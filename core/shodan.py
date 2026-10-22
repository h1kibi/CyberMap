"""Asynchronous Shodan client speaking the same asset contracts as the FOFA engine.

Shodan banners are normalized into the field vocabulary the CLI, REST, MCP and the
exporter already share (`host`, `ip`, `port`, `protocol`, `title`, ...), so Shodan
pages flow through the existing renderers, filters and export paths unchanged.

Documented Shodan billing rules drive the credit accounting here
(https://developer.shodan.io/api):
- a search request costs 1 query credit when the query contains a filter, or when
  results past the first page are requested (1 credit per 100 results);
- `/shodan/host/count` never consumes query credits, so statistics stay free.
"""

from __future__ import annotations

import asyncio
import random
import re
from collections.abc import AsyncIterator, Callable, Sequence
from typing import Any
from urllib.parse import quote

import httpx

from config import settings
from core.cache import PageCache, request_cache_key, resolve_cache
from core.fields import LOCAL_RESULT_FIELDS
from core.models import (
    AssetRecord,
    FofaError,
    FofaErrorCode,
    SearchPage,
    SearchRequest,
    redact_secrets,
    validate_query,
)
from core.ratelimit import RateLimiter, retry_after_seconds

USER_AGENT = "CyberMap/2.0.1"
SEARCH_PAGE_SIZE = 100
DEFAULT_OUTPUT_FIELDS = (
    "host",
    "ip",
    "port",
    "protocol",
    "title",
    "domain",
    "country",
)
# Every field a Shodan match can contribute, in the order users see them.
SHODAN_FIELDS: tuple[str, ...] = (
    "host",
    "ip",
    "port",
    "protocol",
    "title",
    "domain",
    "hostnames",
    "server",
    "status_code",
    "country",
    "country_code",
    "region",
    "city",
    "org",
    "isp",
    "asn",
    "os",
    "product",
    "version",
    "timestamp",
    "vulns",
    "ssl_cn",
    "banner",
)
# Unified field name -> Shodan facet. Any other `token` (for example
# `http.waf`) is passed through verbatim so native facet names keep working.
FACET_ALIASES: dict[str, str] = {
    "asn": "asn",
    "city": "city",
    "country": "country",
    "domain": "domain",
    "isp": "isp",
    "org": "org",
    "os": "os",
    "port": "port",
    "product": "product",
    "protocol": "transport",
    "server": "http.server",
    "ssl_cn": "ssl.cert.subject.cn",
    "title": "http.title",
    "version": "version",
    "vuln": "vuln",
}
_FACET_TOKEN_RE = re.compile(r"[a-z0-9_.]+")
# Shodan charges a query credit for `filter:value` expressions. Bare keywords stay free.
_FILTER_RE = re.compile(r"(?:^|\s)[a-z0-9_.]+\s*:\s*\S", re.IGNORECASE)
_HOST_RE = re.compile(r"[^:/\[\]A-Za-z0-9.\-]")
# FOFA operators that a FOFA-tuned model or a copy-pasted query may leak into Shodan.
_FOFA_SYNTAX_IN_SHODAN = re.compile(
    r"(?:\bapp\s*=|\bdomain\s*=|\bhost\s*=|\bip\s*=|\bport\s*=|\bbody\s*=|\bheader\s*=|\bicp\s*=|\bcert\s*=|"
    r"\borganization\s*=|\bcountry\s*=|\|\||&&)",
    re.IGNORECASE,
)
_QUOTED_SEGMENT = re.compile(r'"[^"]*"')
_FILTER_TOKEN = re.compile(r"(?:^|\s)([a-z][a-z0-9_.]*)\s*:", re.IGNORECASE)
# Filters offered to the planner and documented at https://www.shodan.io/search/filters.
SHODAN_FILTERS = (
    "ip:",
    "net:",
    "hostname:",
    "domain:",
    "org:",
    "isp:",
    "asn:",
    "city:",
    "country:",
    "port:",
    "product:",
    "version:",
    "os:",
    "device:",
    "http.title:",
    "http.server:",
    "http.status:",
    "ssl.cert.subject.cn:",
    "has_ssl:",
    "has_vuln:",
    "vuln:",
)


def shodan_syntax_errors(query: str) -> list[str]:
    """Reject only what is definitely invalid for Shodan, before any credit is spent.

    Filter names are never restricted here or in the agent: Shodan keeps adding filters
    and gates others by plan, so an unknown-but-valid filter must still reach the API.
    `SHODAN_FILTERS` is prompt guidance for the planner, not a gate.
    """
    errors: list[str] = []
    # Quoted values may legitimately contain `filter:` text or `=`, so only the
    # unquoted skeleton is inspected for syntax mistakes.
    skeleton = _QUOTED_SEGMENT.sub(" ", query)
    if _FOFA_SYNTAX_IN_SHODAN.search(skeleton):
        errors.append("Shodan 不支持 app=/domain=/host=/body= 等赋值写法或 &&/|| 运算符，请改用 filter:value")
    return errors


def shodan_request_fields(fields: Sequence[str] | None) -> list[str]:
    """Keep requestable fields, rejecting names Shodan cannot return instead of silently emptying them."""
    requested = [field for field in (fields or []) if field and field not in LOCAL_RESULT_FIELDS]
    unknown = [field for field in requested if field not in SHODAN_FIELDS]
    if unknown:
        raise FofaError(
            FofaErrorCode.INVALID_QUERY,
            f"Shodan 无法返回字段：{', '.join(unknown)}",
            alternatives=list(SHODAN_FIELDS),
        )
    return requested or list(DEFAULT_OUTPUT_FIELDS)


def resolve_facets(fields: Sequence[str], size: int) -> str:
    """Build a Shodan `facets` expression (`country:5,http.title:5`)."""
    top = max(1, min(int(size), 1000))
    resolved: list[str] = []
    for field in fields:
        name = (field or "").strip().lower()
        if not name:
            continue
        facet = FACET_ALIASES.get(name, name)
        if not _FACET_TOKEN_RE.fullmatch(facet):
            raise FofaError(
                FofaErrorCode.INVALID_QUERY,
                f"不是合法的 Shodan facet：{field}",
                alternatives=sorted(FACET_ALIASES),
            )
        resolved.append(f"{facet}:{top}")
    if not resolved:
        raise FofaError(FofaErrorCode.INVALID_QUERY, "统计聚合至少需要一个 facet 字段", alternatives=sorted(FACET_ALIASES))
    return ",".join(dict.fromkeys(resolved))


def favicon_query(icon_hash: int) -> str:
    """Shodan filter for a MurmurHash3 favicon hash."""
    return f"http.favicon.hash:{icon_hash}"


def _nested(source: Any, *path: str) -> Any:
    value = source
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _first(values: Any) -> str:
    for item in values or []:
        if item:
            return str(item)
    return ""


# Ports `_host` renders as URLs; the protocol fallback keeps both functions aligned so a row that
# is a web page for one function is not a bare socket for the other.
WEB_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https"}


def _protocol(match: dict[str, Any]) -> str:
    module = str(_nested(match, "_shodan", "module") or "")
    if module and module not in {"auto", "unknown"}:
        return module
    port = match.get("port")
    if port in WEB_PORTS:
        return WEB_PORTS[port]
    return str(match.get("transport") or "tcp")


def _bracketed(name: str) -> str:
    """IPv6 literals need brackets inside a URL; `https://2001:db8::1:443` cannot be parsed."""
    return f"[{name}]" if name.count(":") >= 2 and not name.startswith("[") else name


def _host(match: dict[str, Any]) -> str:
    protocol = _protocol(match)
    port = match.get("port")
    name = _bracketed(_first(match.get("hostnames")) or str(match.get("ip_str") or ""))
    if not name:
        return ""
    if not protocol.startswith(("http", "https")) and port not in {80, 443, 8080, 8443}:
        return f"{name}:{port}" if port is not None else name
    scheme = "https" if "https" in protocol or port in {443, 8443} else "http"
    return f"{scheme}://{name}:{port}" if port is not None else f"{scheme}://{name}"


def _vulns(match: dict[str, Any]) -> str:
    vulns = match.get("vulns")
    if isinstance(vulns, dict):
        return ", ".join(sorted(str(key) for key in vulns))
    if isinstance(vulns, list):
        return ", ".join(sorted(str(item) for item in vulns))
    return ""


def _hostnames(match: dict[str, Any]) -> str:
    return ", ".join(_as_text_list(match.get("hostnames")))


# Field -> banner extractor. Built once at import time so projecting a large export
# allocates only the result rows, never a closure per record.
_FIELD_EXTRACTORS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "host": _host,
    "ip": lambda match: match.get("ip_str") or "",
    "port": lambda match: match.get("port"),
    "protocol": _protocol,
    # `http.title` only: the top-level `title` key is not part of the documented match
    # schema, and inventing a page title from an undocumented field is worse than blank.
    "title": lambda match: _nested(match, "http", "title") or "",
    # `domains` only: a hostname is not a registrable domain, and the shared consumers
    # (domain statistics, website candidates) treat this column as a registrable domain.
    "domain": lambda match: _first(match.get("domains")),
    "hostnames": _hostnames,
    "server": lambda match: _nested(match, "http", "server") or "",
    "status_code": lambda match: _nested(match, "http", "status"),
    "country": lambda match: _nested(match, "location", "country_name") or "",
    "country_code": lambda match: _nested(match, "location", "country_code") or "",
    "region": lambda match: _nested(match, "location", "region_code") or "",
    "city": lambda match: _nested(match, "location", "city") or "",
    "org": lambda match: match.get("org") or "",
    "isp": lambda match: match.get("isp") or "",
    "asn": lambda match: match.get("asn") or "",
    "os": lambda match: match.get("os") or "",
    "product": lambda match: match.get("product") or "",
    "version": lambda match: match.get("version") or "",
    "timestamp": lambda match: match.get("timestamp") or "",
    "vulns": _vulns,
    "ssl_cn": lambda match: _nested(match, "ssl", "cert", "subject", "CN") or "",
    "banner": lambda match: match.get("data") or "",
}


def map_match(match: dict[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    """Project one Shodan banner onto the requested unified fields."""
    return {field: _FIELD_EXTRACTORS[field](match) for field in fields if field in _FIELD_EXTRACTORS}


def _safe_count(value: Any) -> int:
    """Facet counts are integers; anything unparsable becomes 0 instead of breaking the renderer."""
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _facets_of(data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return only well-formed facet buckets so a malformed payload cannot raise."""
    facets = data.get("facets")
    if not isinstance(facets, dict):
        return {}
    return {
        str(name): [bucket for bucket in buckets if isinstance(bucket, dict)]
        for name, buckets in facets.items()
        if isinstance(buckets, list)
    }


def _as_text_list(value: Any) -> list[str]:
    """Shodan string-list fields are returned as-is; anything else cannot be trusted."""
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item not in (None, "")]


def normalize_host_profile(data: dict[str, Any]) -> dict[str, Any]:
    """Reshape `/shodan/host/{ip}` into the host profile the CLI already renders."""
    entries: dict[int, dict[str, Any]] = {}
    for banner in data.get("data") or []:
        if not isinstance(banner, dict):
            continue
        port = banner.get("port")
        if not isinstance(port, int):
            continue
        entry = entries.setdefault(
            port,
            {
                "port": port,
                "protocol": banner.get("transport") or "tcp",
                "products": [],
                "update_time": banner.get("timestamp") or "",
            },
        )
        label = " ".join(str(item) for item in (banner.get("product"), banner.get("version")) if item)
        label = label or _nested(banner, "http", "server") or _nested(banner, "http", "title") or ""
        if label:
            entry["products"].append({"product": label, "name": label})
    for port in data.get("ports") or []:
        if isinstance(port, int) and port not in entries:
            entries[port] = {"port": port, "protocol": "tcp", "products": [], "update_time": ""}
    vulns = data.get("vulns")
    if isinstance(vulns, dict):
        vuln_list = sorted(str(key) for key in vulns)
    elif isinstance(vulns, list):
        vuln_list = sorted(str(item) for item in vulns)
    else:
        vuln_list = []
    profile = {
        "host": data.get("ip_str") or "",
        "ip": data.get("ip_str") or "",
        "country_name": data.get("country_name") or _nested(data, "location", "country_name") or "",
        "org": data.get("org") or "",
        "asn": data.get("asn") or "",
        "update_time": data.get("last_update") or "",
        "hostnames": _as_text_list(data.get("hostnames")),
        "domains": _as_text_list(data.get("domains")),
        "os": data.get("os") or "",
        "isp": data.get("isp") or "",
        "city": data.get("city") or "",
        "vulns": vuln_list,
        "ports": [entries[port] for port in sorted(entries)],
        "source": "shodan",
    }
    return profile


class ShodanClient:
    """Minimal Shodan client: typed errors, one shared rate limit, documented credit accounting."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        max_retries: int = 3,
        requests_per_second: float | None = None,
        concurrency: int | None = None,
        cache: PageCache | None | bool = True,
    ) -> None:
        self.name = "shodan"
        self.base_url = (base_url or settings.shodan.base_url).rstrip("/")
        self.key = settings.shodan.api_key if api_key is None else api_key
        self.max_retries = max_retries
        self._client = client
        self._owns_client = client is None
        self._configured_rps = (
            requests_per_second or settings.shodan.requests_per_second or settings.system.requests_per_second
        )
        self._limiter = RateLimiter(self._configured_rps)
        self._semaphore = asyncio.Semaphore(concurrency or settings.system.concurrency)
        self.headers = {"User-Agent": USER_AGENT}
        self.plan_info: dict[str, Any] | None = None
        self.cache = (resolve_cache() if cache is True else cache) or None

    async def __aenter__(self) -> ShodanClient:
        await self._get_client()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Shodan authenticates with the `key` query parameter, so the credential is part
            # of every request URI. Keep redirects disabled (the key must never be replayed to
            # a Location target), never call `raise_for_status()` (its message embeds the URL)
            # and never log request URLs or `exc.request.url`.
            self._client = httpx.AsyncClient(
                http2=True, verify=True, timeout=httpx.Timeout(60.0), follow_redirects=False
            )
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _auth_params(self) -> dict[str, str]:
        if not self.key:
            raise FofaError(
                FofaErrorCode.AUTH_FAILED,
                "未配置 SHODAN_API_KEY",
                alternatives=["SHODAN_API_KEY", "cybermap-shodan 钥匙串条目", "settings.yaml 的 shodan.api_key"],
            )
        return {"key": self.key}

    @staticmethod
    def _classify_error(message: str, status_code: int | None = None) -> FofaError:
        lower = message.lower()
        # Quota text outranks the status code on purpose: Shodan reports an exhausted
        # balance in the message body (often with 401/402), and telling the user "your key
        # is invalid" when they simply ran out of credits would be the worse failure.
        if "credit" in lower or "out of queries" in lower:
            return FofaError(FofaErrorCode.QUOTA_EXHAUSTED, message, status_code=status_code)
        if status_code == 429 or "rate limit" in lower or "too many requests" in lower:
            return FofaError(FofaErrorCode.RATE_LIMITED, message, retryable=True, status_code=status_code)
        if status_code == 403 or "access denied" in lower or "upgrade" in lower or "subscription" in lower:
            return FofaError(FofaErrorCode.PERMISSION_DENIED, message, status_code=status_code)
        if status_code == 401 or "invalid api key" in lower or "unauthorized" in lower or "api key" in lower:
            return FofaError(FofaErrorCode.AUTH_FAILED, message, status_code=status_code)
        if status_code is not None and status_code >= 500:
            return FofaError(FofaErrorCode.TRANSPORT_ERROR, message, retryable=True, status_code=status_code)
        if status_code == 400 or "invalid" in lower or "not a valid" in lower:
            return FofaError(FofaErrorCode.INVALID_QUERY, message, status_code=status_code)
        return FofaError(FofaErrorCode.INVALID_RESPONSE, message, status_code=status_code)

    def _scrub(self, text: str) -> str:
        """Never surface upstream text that may echo the credential-bearing request URI."""
        return redact_secrets(text, self.key)

    async def _request(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        client = await self._get_client()
        request_params = {**self._auth_params(), **params}
        last_error: FofaError | None = None
        for attempt in range(self.max_retries + 1):
            try:
                await self._limiter.wait()
                async with self._semaphore:
                    response = await client.get(f"{self.base_url}{path}", params=request_params, headers=self.headers)
                if response.status_code == 429 or response.status_code >= 500:
                    delay = retry_after_seconds(response.headers.get("Retry-After"), 0.5 * (2**attempt))
                    last_error = self._classify_error(
                        self._scrub(response.text[:500]) or "Shodan 请求失败", response.status_code
                    )
                    if attempt < self.max_retries:
                        await asyncio.sleep(delay + random.uniform(0, max(0.05, delay * 0.2)))
                        continue
                    raise last_error
                try:
                    data = response.json()
                except ValueError as exc:
                    # Shodan answers 401/403 with an HTML error page, so the status code
                    # must still drive classification instead of a generic parse failure.
                    if response.is_error:
                        raise self._classify_error(
                            f"Shodan 返回 {response.status_code}（非 JSON 响应）", response.status_code
                        ) from exc
                    raise FofaError(
                        FofaErrorCode.INVALID_RESPONSE, "Shodan 返回了非 JSON 响应", status_code=response.status_code
                    ) from exc
                if response.is_error or (isinstance(data, dict) and data.get("error")):
                    raw = str(data.get("error") or response.text[:500]) if isinstance(data, dict) else response.text[:500]
                    error = self._classify_error(self._scrub(raw), response.status_code)
                    if error.retryable and attempt < self.max_retries:
                        delay = retry_after_seconds(response.headers.get("Retry-After"), 0.5 * (2**attempt))
                        await asyncio.sleep(delay + random.uniform(0, max(0.05, delay * 0.2)))
                        last_error = error
                        continue
                    raise error
                if not isinstance(data, dict):
                    raise FofaError(FofaErrorCode.INVALID_RESPONSE, "Shodan 返回了非对象 JSON 响应")
                return data
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = FofaError(FofaErrorCode.TRANSPORT_ERROR, self._scrub(str(exc)), retryable=True)
                if attempt >= self.max_retries:
                    raise last_error from exc
                await asyncio.sleep(0.5 * (2**attempt) + random.uniform(0, 0.2))
        raise last_error or FofaError(FofaErrorCode.TRANSPORT_ERROR, "Shodan 请求失败")

    @staticmethod
    def page_cost(request: SearchRequest) -> int:
        """Query credits one Shodan page costs: filters and pages past the first are billed."""
        if request.page > 1:
            return 1
        return 1 if _FILTER_RE.search(request.query) else 0

    async def account(self) -> dict[str, Any]:
        """`/api-info` never consumes query credits."""
        data = await self._request("/api-info", {})
        self.plan_info = data
        return data

    async def check_login(self) -> dict[str, Any]:
        return await self.account()

    async def _require_credits(self, request: SearchRequest) -> None:
        if not self.page_cost(request):
            return
        info = self.plan_info or await self.account()
        remaining = info.get("query_credits")
        if isinstance(remaining, int) and remaining == 0:
            raise FofaError(
                FofaErrorCode.QUOTA_EXHAUSTED,
                f"Shodan 查询额度已用尽（plan={info.get('plan') or '-'}）；过滤器查询与第一页之后的翻页都会消耗额度。",
            )

    async def search_page(self, request: SearchRequest) -> SearchPage:
        cache_key = request_cache_key(self.name, request) if self.cache else None
        if cache_key is not None:
            hit = self.cache.get(cache_key)
            if hit is not None:
                return hit
        fields = shodan_request_fields(request.fields)
        errors = validate_query(request.query) + shodan_syntax_errors(request.query)
        if errors:
            # Rejected before the request so a syntax mistake never spends a credit.
            raise FofaError(
                FofaErrorCode.INVALID_QUERY,
                "Shodan 查询语法无效：" + "; ".join(errors),
                alternatives=["product:nginx country:CN", 'http.title:"登录" port:8080', "-country:CN"],
            )
        await self._require_credits(request)
        cost = self.page_cost(request)
        # `minify` truncates the large banner fields, so asking for `banner` switches it off
        # rather than silently returning a truncated value. Vendor sample of a default
        # (minified) search reply keeps http.*, location.* and cpe intact.
        minify = not (request.full or "banner" in fields)
        data = await self._request(
            "/shodan/host/search",
            {
                "query": request.query,
                "page": request.page,
                "minify": str(minify).lower(),
            },
        )
        matches = [item for item in (data.get("matches") or []) if isinstance(item, dict)]
        records = [AssetRecord(values=map_match(match, fields)) for match in matches]
        if len(records) > request.size:
            records = records[: request.size]
        total = data.get("total")
        page = SearchPage(
            records=records,
            fields=list(fields),
            total=total if isinstance(total, int) else None,
            next_cursor=None,
            page=request.page,
            consumed=cost,
            query=request.query,
            metadata={
                "engine": "shodan",
                "matches": len(matches),
                "page_size": SEARCH_PAGE_SIZE,
                "plan": (self.plan_info or {}).get("plan"),
                "query_credits": (self.plan_info or {}).get("query_credits"),
                "minify": minify,
            },
        )
        if cache_key is not None:
            self.cache.put(cache_key, page)
        return page

    async def iter_search(self, request: SearchRequest) -> AsyncIterator[SearchPage]:
        """Walk Shodan's numbered pages, honoring the shared budgets and dedupe contract."""
        seen: set[tuple[Any, ...]] = set()
        emitted = 0
        spent = 0.0
        page_number = request.page
        for _ in range(request.max_pages):
            page = await self.search_page(request.model_copy(update={"page": page_number}))
            raw_count = int(page.metadata.get("matches") or len(page.records))
            if request.dedupe_by:
                filtered: list[AssetRecord] = []
                for record in page.records:
                    key = tuple(record.values.get(field) for field in request.dedupe_by)
                    if key not in seen:
                        seen.add(key)
                        filtered.append(record)
                page.records = filtered
            if emitted + len(page.records) > request.max_records:
                page.records = page.records[: request.max_records - emitted]
            emitted += len(page.records)
            spent += float(page.consumed or 0)
            yield page
            if emitted >= request.max_records or raw_count == 0:
                break
            if request.cost_budget is not None and spent >= request.cost_budget:
                break
            if raw_count < SEARCH_PAGE_SIZE:
                break
            if isinstance(page.total, int) and emitted >= page.total:
                break
            page_number += 1

    @staticmethod
    def _validate_target(host: str) -> str:
        target = host.strip().strip("'\"")
        if not target or "/" in target or "\\" in target or "?" in target or "#" in target or "@" in target:
            raise FofaError(FofaErrorCode.INVALID_QUERY, "主机必须是 IP 地址或域名")
        if _HOST_RE.search(target):
            raise FofaError(FofaErrorCode.INVALID_QUERY, "主机必须是 IP 地址或域名")
        return target

    async def host_profile(self, host: str, *, detail: bool = True) -> dict[str, Any]:
        target = self._validate_target(host)
        data = await self._request(
            f"/shodan/host/{quote(target, safe=':.[]-')}",
            {"minify": str(not detail).lower()},
        )
        return normalize_host_profile(data)

    async def host_search(self, host: str) -> dict[str, Any]:
        return await self.host_profile(host)

    async def stats(self, query: str, fields: list[str], size: int = 5) -> dict[str, Any]:
        """Facet breakdown through `/shodan/host/count`, which spends no query credits."""
        errors = validate_query(query) + shodan_syntax_errors(query)
        if errors:
            raise FofaError(
                FofaErrorCode.INVALID_QUERY,
                "Shodan 查询语法无效：" + "; ".join(errors),
                alternatives=["product:nginx country:CN", 'http.title:"登录"', "-country:CN"],
            )
        facets = resolve_facets(fields, size)
        data = await self._request("/shodan/host/count", {"query": query, "facets": facets})
        aggs = {
            str(name): [{"name": bucket.get("value"), "count": _safe_count(bucket.get("count"))} for bucket in buckets]
            for name, buckets in (_facets_of(data)).items()
        }
        info = self.plan_info or {}
        total = data.get("total")
        return {
            "size": total if isinstance(total, int) else 0,
            "aggs": aggs,
            "source": "shodan",
            "query": query,
            "facets": facets,
            "plan": info.get("plan"),
            "query_credits": info.get("query_credits"),
            "consumed": 0,
        }

    async def count(self, query: str, *, facets: str = "") -> dict[str, Any]:
        params: dict[str, Any] = {"query": query}
        if facets:
            params["facets"] = facets
        return await self._request("/shodan/host/count", params)
