"""DayDayMap cyberspace asset search engine (https://www.daydaymap.com).

Live-verified against the open API with a real key:

- ``POST /api/v1/raymap/search/all`` with an ``api-key`` header;
- body: ``{"page": 1, "page_size": 10, "keyword": "<base64 query>"}`` plus optional
  ``fields`` / ``exclude_fields`` (documented: ``page_size`` up to 10000 per page);
- response: ``{"code": 200, "data": {"list": [...], "page", "page_size", "total", "use_time"}, "msg"}``.

Observed error codes (HTTP 200 carries them in the body): ``2001`` wrong api-key, ``2002`` a field
that is not searchable / not a supported response field, ``2006`` invalid syntax, ``470`` a missing
required parameter. The platform-wide ``/point/point/query`` and ``/raymap/search/syntax/query``
endpoints answer 401/470 for an API key, so this engine has no balance or syntax-catalogue call:
``account()`` is local-only and the syntax rules below are prompt guidance, not a gate.

Syntax is FOFA-like: ``field="value"``, ``&&``, ``||`` and parentheses are verified working;
Shodan-style ``field:value`` and bare words are not accepted. ``icon_md5`` exists as a response
field but is **not searchable**, so favicon reverse search is not available.

The API does not report the points a request consumed, so ``consumed`` stays ``None`` (unknown)
instead of inventing a number and ``cost_budget`` cannot be enforced; pages are still cached so a
re-run spends nothing. ``fields`` is projected onto the native columns the requested unified fields
need, which keeps a 10000-row page from carrying banner/header/cert blobs nobody asked for.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import random
import re
from collections.abc import AsyncIterator, Sequence
from typing import Any
from urllib.parse import urlparse

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
SEARCH_PATH = "/api/v1/raymap/search/all"
# Documented: "查询每页资产条数，最大10000条/页".
MAX_PAGE_SIZE = 10_000
HOST_PROFILE_PAGE_SIZE = 100
# Reverse DNS and SAN lists can be long; the display/export column is a bounded sample.
HOSTNAME_LIMIT = 10

DEFAULT_OUTPUT_FIELDS: tuple[str, ...] = (
    "host",
    "ip",
    "port",
    "protocol",
    "title",
    "hostnames",
    "country",
)

# Response fields the API accepts in `fields` / `exclude_fields` (returned verbatim by the 2002
# error message). Kept for documentation and for anyone extending the mapper.
NATIVE_FIELDS: tuple[str, ...] = (
    "ip",
    "is_ipv6",
    "is_website",
    "port",
    "protocol",
    "country",
    "province",
    "city",
    "asn",
    "asn_org",
    "isp",
    "domain",
    "icp_reg_name",
    "industry",
    "title",
    "banner",
    "header",
    "os",
    "server",
    "lang",
    "device",
    "product",
    "service",
    "tags",
    "cert",
    "cert_selfsigned",
    "time_stamp",
    "device_type",
    "manufacturer",
    "continent",
    "country_code",
    "postal_code",
    "longitude",
    "latitude",
    "ssl",
    "icon_md5",
    "url",
)

# Unified vocabulary this engine can fill, plus the native extras worth exposing. `domain` is
# deliberately absent: DayDayMap's `domain` value is a hostname (e.g. `www.example.com`), and the
# shared consumers treat the `domain` column as a registrable domain, so hostnames go to
# `hostnames` instead of corrupting cross-engine domain statistics.
DAYDAYMAP_FIELDS: tuple[str, ...] = (
    "host",
    "ip",
    "port",
    "protocol",
    "base_protocol",
    "title",
    "hostnames",
    "country",
    "country_code",
    "region",
    "city",
    "org",
    "isp",
    "asn",
    "os",
    "server",
    "status_code",
    "product",
    "timestamp",
    "banner",
    "header",
    "cert",
    "ssl_cn",
    "icp_reg_name",
    "industry",
    "tags",
    "device",
    "device_type",
    "manufacturer",
    "lang",
    "continent",
    "postal_code",
    "latitude",
    "longitude",
    "icon_md5",
    "url",
    "is_website",
    "is_ipv6",
)

_HOST_RE = re.compile(r"[^:/\[\]A-Za-z0-9.\-]")
_TARGET_RE = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
_STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})")
_CN_RE = re.compile(r"CN=([^,]+)")
# Shodan `filter:value` syntax is the mistake models make most often when switching engines.
_SHODAN_STYLE = re.compile(r"(?:^|\s)[A-Za-z][A-Za-z0-9_.]*\s*:\s*\S")
_DNS_PREFIX = "DNS:"


def encode_keyword(query: str) -> str:
    """The API takes the query base64-encoded, not as plain text."""
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


def query_errors(query: str) -> list[str]:
    """Reject only what is definitely invalid before a request (and any points) is spent."""
    text = (query or "").strip()
    errors: list[str] = []
    if not text:
        errors.append("查询语句不能为空")
        return errors
    if text.count('"') % 2:
        errors.append("引号未闭合")
    if text.count("(") != text.count(")"):
        errors.append("括号未配对")
    if "=" not in text and _SHODAN_STYLE.search(text):
        errors.append(
            'DayDayMap 使用 field="value" 语法（例如 title="登录"），不是 Shodan 的 field:value'
        )
    return errors


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _bracketed(name: str) -> str:
    """IPv6 literals need brackets inside a URL."""
    return f"[{name}]" if name.count(":") >= 2 and not name.startswith("[") else name


def _joined(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item not in (None, ""))
    return _text(value)


def _hostnames(row: dict[str, Any]) -> str:
    names: list[str] = []
    domain = _text(row.get("domain")).strip()
    if domain:
        names.append(domain)
    ssl = row.get("ssl") if isinstance(row.get("ssl"), dict) else {}
    for item in ssl.get("alternative_name") or []:
        if isinstance(item, str) and item.upper().startswith(_DNS_PREFIX):
            value = item[len(_DNS_PREFIX):].strip()
            if value:
                names.append(value)
    return ", ".join(list(dict.fromkeys(names))[:HOSTNAME_LIMIT])


def _ssl_cn(row: dict[str, Any]) -> str:
    """Prefer the SAN DNS name; the `cert` blob lists the issuer CN before the subject CN."""
    ssl = row.get("ssl") if isinstance(row.get("ssl"), dict) else {}
    for item in ssl.get("alternative_name") or []:
        if isinstance(item, str) and item.upper().startswith(_DNS_PREFIX):
            value = item[len(_DNS_PREFIX):].strip()
            if value:
                return value
    found = _CN_RE.findall(_text(row.get("cert")))
    return found[-1].strip() if found else ""


def _status_code(row: dict[str, Any]) -> int | None:
    match = _STATUS_RE.match(_text(row.get("header")))
    return int(match.group(1)) if match else None


def _protocol(row: dict[str, Any]) -> str:
    # `service` is the application protocol (http/https/ssh); `protocol` is the transport.
    return (_text(row.get("service")) or _text(row.get("protocol"))).lower()


def _host(row: dict[str, Any]) -> str:
    url = _text(row.get("url")).strip()
    if url:
        return url.rstrip("/")
    ip = _text(row.get("ip"))
    port = row.get("port")
    name = _bracketed(ip)
    return f"{name}:{port}" if name and port is not None else name


# Field -> row extractor. Built once at import time so projecting a page allocates only the
# result rows, never a closure per record.
_FIELD_EXTRACTORS: dict[str, Any] = {
    "host": _host,
    "ip": lambda row: _text(row.get("ip")),
    "port": lambda row: row.get("port"),
    "protocol": _protocol,
    "base_protocol": lambda row: _text(row.get("protocol")),
    "title": lambda row: _text(row.get("title")),
    "hostnames": _hostnames,
    "country": lambda row: _text(row.get("country")),
    "country_code": lambda row: _text(row.get("country_code")),
    "region": lambda row: _text(row.get("province")),
    "city": lambda row: _text(row.get("city")),
    "org": lambda row: _text(row.get("asn_org")),
    "isp": lambda row: _text(row.get("isp")),
    "asn": lambda row: _text(row.get("asn")),
    "os": lambda row: _text(row.get("os")),
    "server": lambda row: _text(row.get("server")),
    "status_code": _status_code,
    "product": lambda row: _joined(row.get("product")),
    "timestamp": lambda row: _text(row.get("time_stamp")),
    "banner": lambda row: _text(row.get("banner")),
    "header": lambda row: _text(row.get("header")),
    "cert": lambda row: _text(row.get("cert")),
    "ssl_cn": _ssl_cn,
    "icp_reg_name": lambda row: _text(row.get("icp_reg_name")),
    "industry": lambda row: _joined(row.get("industry")),
    "tags": lambda row: _joined(row.get("tags")),
    "device": lambda row: _text(row.get("device")),
    "device_type": lambda row: _text(row.get("device_type")),
    "manufacturer": lambda row: _text(row.get("manufacturer")),
    "lang": lambda row: _text(row.get("lang")),
    "continent": lambda row: _text(row.get("continent")),
    "postal_code": lambda row: _text(row.get("postal_code")),
    "latitude": lambda row: row.get("latitude"),
    "longitude": lambda row: row.get("longitude"),
    "icon_md5": lambda row: _text(row.get("icon_md5")),
    "url": lambda row: _text(row.get("url")),
    "is_website": lambda row: row.get("is_website"),
    "is_ipv6": lambda row: row.get("is_ipv6"),
}


# Unified field -> native response columns the extractor needs. Requesting only these keeps a
# 10000-row page from carrying banner/header/cert blobs nobody asked for; the API validates the
# names against its own enumeration, so a wrong dependency would fail loudly with code 2002.
_NATIVE_FOR_UNIFIED: dict[str, tuple[str, ...]] = {
    "host": ("url", "ip", "port"),
    "ip": ("ip",),
    "port": ("port",),
    "protocol": ("service", "protocol"),
    "base_protocol": ("protocol",),
    "title": ("title",),
    "hostnames": ("domain", "ssl"),
    "country": ("country",),
    "country_code": ("country_code",),
    "region": ("province",),
    "city": ("city",),
    "org": ("asn_org",),
    "isp": ("isp",),
    "asn": ("asn",),
    "os": ("os",),
    "server": ("server",),
    "status_code": ("header",),
    "product": ("product",),
    "timestamp": ("time_stamp",),
    "banner": ("banner",),
    "header": ("header",),
    "cert": ("cert",),
    "ssl_cn": ("ssl", "cert"),
    "icp_reg_name": ("icp_reg_name",),
    "industry": ("industry",),
    "tags": ("tags",),
    "device": ("device",),
    "device_type": ("device_type",),
    "manufacturer": ("manufacturer",),
    "lang": ("lang",),
    "continent": ("continent",),
    "postal_code": ("postal_code",),
    "latitude": ("latitude",),
    "longitude": ("longitude",),
    "icon_md5": ("icon_md5",),
    "url": ("url",),
    "is_website": ("is_website",),
    "is_ipv6": ("is_ipv6",),
}


def native_columns(fields: Sequence[str]) -> str:
    """Comma-separated native columns needed to fill the requested unified fields."""
    columns: list[str] = []
    for field in fields:
        for column in _NATIVE_FOR_UNIFIED.get(field, ()):
            if column not in columns:
                columns.append(column)
    return ",".join(columns)


def map_record(row: dict[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    """Project one DayDayMap record onto the requested unified fields."""
    return {field: _FIELD_EXTRACTORS[field](row) for field in fields if field in _FIELD_EXTRACTORS}


def daydaymap_request_fields(fields: Sequence[str]) -> list[str]:
    """Keep the unified fields this engine can fill (and locally computed ones)."""
    requested = [field for field in (fields or []) if field in DAYDAYMAP_FIELDS or field in LOCAL_RESULT_FIELDS]
    return requested or [field for field in DEFAULT_OUTPUT_FIELDS]


def normalize_host_profile(records: Sequence[dict[str, Any]], *, host: str, cached: bool = False) -> dict[str, Any]:
    """Aggregate `ip=` / `domain=` records into the host profile the CLI already renders."""
    entries: dict[Any, dict[str, Any]] = {}
    for values in records:
        port = values.get("port")
        entry = entries.setdefault(
            port,
            {
                "port": port,
                "protocol": values.get("protocol") or "",
                "products": [],
                "update_time": values.get("timestamp") or "",
                "banner": values.get("banner") or "",
                "server": values.get("server") or "",
                "title": values.get("title") or "",
            },
        )
        product = _text(values.get("product"))
        if product:
            for name in (item.strip() for item in product.split(",")):
                if name:
                    entry["products"].append({"product": name, "name": name})
    newest = max((_text(values.get("timestamp")) for values in records), default="")
    first = records[0] if records else {}
    hostnames = list(dict.fromkeys(
        name.strip()
        for values in records
        for name in _text(values.get("hostnames")).split(",")
        if name.strip()
    ))
    profile = {
        "host": host,
        "ip": _text(first.get("ip")) or host,
        "hostnames": hostnames[:HOSTNAME_LIMIT],
        "country_name": _text(first.get("country")),
        "country_code": _text(first.get("country_code")),
        "region": _text(first.get("region")),
        "city": _text(first.get("city")),
        "org": _text(first.get("org")),
        "isp": _text(first.get("isp")),
        "asn": _text(first.get("asn")),
        "os": next((_text(values.get("os")) for values in records if values.get("os")), ""),
        "update_time": newest,
        # DayDayMap has no vulnerability feed on this API.
        "vulns": [],
        "ports": [entries[port] for port in sorted(entries, key=lambda item: (item is None, str(item)))],
        "source": "daydaymap",
        "cached": cached,
    }
    return profile


class DaydaymapClient:
    """DayDayMap API client: typed errors, one shared rate limit, page cache, unknown-point accounting."""

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
        self.name = "daydaymap"
        self.base_url = (base_url or settings.daydaymap.base_url).rstrip("/")
        self.key = settings.daydaymap.api_key if api_key is None else api_key
        self.max_retries = max_retries
        self._client = client
        self._owns_client = client is None
        self._configured_rps = (
            requests_per_second or settings.daydaymap.requests_per_second or settings.system.requests_per_second
        )
        self._limiter = RateLimiter(self._configured_rps)
        self._semaphore = asyncio.Semaphore(concurrency or settings.system.concurrency)
        self.headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        self.cache = (resolve_cache() if cache is True else cache) or None

    async def __aenter__(self) -> DaydaymapClient:
        await self._get_client()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(40.0, connect=10.0),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            )
        return self._client

    def _auth_headers(self) -> dict[str, str]:
        if not self.key:
            raise FofaError(
                FofaErrorCode.AUTH_FAILED,
                "未配置 DayDayMap API Key",
                alternatives=[
                    "export DAYDAYMAP_API_KEY=<personal api key>",
                    "python cybermap.py --save-key daydaymap",
                ],
            )
        return {**self.headers, "api-key": self.key}

    def _scrub(self, text: str) -> str:
        """Never let an upstream message echo the credential-bearing header."""
        return redact_secrets(text, self.key)

    def _classify(self, code: int | None, message: str, status_code: int | None) -> FofaError:
        text = message or ""
        lowered = text.lower()
        if status_code == 401 or code == 2001:
            return FofaError(
                FofaErrorCode.AUTH_FAILED,
                text or "DayDayMap API Key 无效",
                status_code=status_code,
                alternatives=["在个人中心确认 API Key", "export DAYDAYMAP_API_KEY=<key>"],
            )
        if code in (2002, 2006, 470) or status_code == 400:
            return FofaError(
                FofaErrorCode.INVALID_QUERY,
                text or "DayDayMap 查询语法无效",
                status_code=status_code,
                alternatives=['title="登录" && country="中国"', 'cert="example.com"'],
            )
        if status_code == 429 or "频繁" in text or "限流" in text or "too many" in lowered:
            return FofaError(
                FofaErrorCode.RATE_LIMITED, text or "DayDayMap 触发限流", retryable=True, status_code=status_code
            )
        if any(keyword in text for keyword in ("积分", "额度", "余额", "不足", "用完", "超出")):
            return FofaError(FofaErrorCode.QUOTA_EXHAUSTED, text, status_code=status_code)
        if status_code is not None and status_code >= 500:
            return FofaError(FofaErrorCode.TRANSPORT_ERROR, text, retryable=True, status_code=status_code)
        if status_code == 403:
            return FofaError(FofaErrorCode.PERMISSION_DENIED, text, status_code=status_code)
        return FofaError(FofaErrorCode.INVALID_RESPONSE, text or "DayDayMap 返回了未知错误", status_code=status_code)

    async def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        client = await self._get_client()
        last_error: FofaError | None = None
        for attempt in range(self.max_retries + 1):
            try:
                await self._limiter.wait()
                async with self._semaphore:
                    response = await client.post(
                        f"{self.base_url}{SEARCH_PATH}", headers=self._auth_headers(), json=payload
                    )
                if response.status_code == 429 or response.status_code >= 500:
                    delay = retry_after_seconds(response.headers.get("Retry-After"), 0.5 * (2**attempt))
                    last_error = self._classify(
                        None, self._scrub(response.text[:500]) or "DayDayMap 请求失败", response.status_code
                    )
                    if attempt < self.max_retries:
                        await asyncio.sleep(delay + random.uniform(0, max(0.05, delay * 0.2)))
                        continue
                    raise last_error
                try:
                    data = response.json()
                except ValueError as exc:
                    if response.is_error:
                        raise self._classify(
                            None, f"DayDayMap 返回 {response.status_code}（非 JSON 响应）", response.status_code
                        ) from exc
                    raise FofaError(
                        FofaErrorCode.INVALID_RESPONSE, "DayDayMap 返回了非 JSON 响应", status_code=response.status_code
                    ) from exc
                if not isinstance(data, dict):
                    raise FofaError(FofaErrorCode.INVALID_RESPONSE, "DayDayMap 返回了非对象 JSON 响应")
                code = data.get("code")
                if response.is_error or code != 200:
                    error = self._classify(
                        code if isinstance(code, int) else None,
                        self._scrub(_text(data.get("msg")) or f"HTTP {response.status_code}"),
                        response.status_code,
                    )
                    if error.retryable and attempt < self.max_retries:
                        delay = retry_after_seconds(response.headers.get("Retry-After"), 0.5 * (2**attempt))
                        await asyncio.sleep(delay + random.uniform(0, max(0.05, delay * 0.2)))
                        last_error = error
                        continue
                    raise error
                body = data.get("data")
                if not isinstance(body, dict):
                    raise FofaError(FofaErrorCode.INVALID_RESPONSE, "DayDayMap 响应缺少 data 对象")
                return body
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = FofaError(FofaErrorCode.TRANSPORT_ERROR, self._scrub(str(exc)), retryable=True)
                if attempt >= self.max_retries:
                    raise last_error from exc
                await asyncio.sleep(0.5 * (2**attempt) + random.uniform(0, 0.2))
        raise last_error or FofaError(FofaErrorCode.TRANSPORT_ERROR, "DayDayMap 请求失败")

    async def account(self) -> dict[str, Any]:
        """Local capability view: the open API exposes no balance endpoint (the points page needs a login)."""
        configured = bool(self.key)
        return {
            "engine": self.name,
            "plan": "api-key",
            "api_key_configured": configured,
            "balance": None,
            "points": "unknown",
            "note": (
                "DayDayMap 的积分余额只能在官网个人中心查看，开放 API 没有余额接口；"
                "本操作未发起网络请求。"
            ),
            "search_endpoint": f"{self.base_url}{SEARCH_PATH}",
            "page_size_limit": MAX_PAGE_SIZE,
        }

    async def check_login(self) -> dict[str, Any]:
        return await self.account()

    async def search_page(self, request: SearchRequest) -> SearchPage:
        cache_key = request_cache_key(self.name, request) if self.cache else None
        if cache_key is not None:
            hit = self.cache.get(cache_key)
            if hit is not None:
                return hit
        errors = validate_query(request.query) + query_errors(request.query)
        if errors:
            raise FofaError(
                FofaErrorCode.INVALID_QUERY,
                "DayDayMap 查询语法无效：" + "; ".join(errors),
                alternatives=['title="登录" && country="中国"', 'cert="example.com"', 'ip="1.2.3.4"'],
            )
        fields = daydaymap_request_fields(request.fields)
        page_size = max(1, min(int(request.size or 100), MAX_PAGE_SIZE))
        payload: dict[str, Any] = {
            "page": request.page,
            "page_size": page_size,
            "keyword": encode_keyword(request.query),
        }
        # `--full` turns the projection off: the API then returns every native column.
        columns = "" if request.full else native_columns(fields)
        if columns:
            payload["fields"] = columns
        body = await self._request(payload)
        rows = [row for row in (body.get("list") or []) if isinstance(row, dict)]
        records = [AssetRecord(values=map_record(row, fields)) for row in rows]
        total = body.get("total")
        page = SearchPage(
            records=records,
            fields=fields,
            total=total if isinstance(total, int) else None,
            next_cursor=None,
            page=request.page,
            # The API does not report the points a request consumed; unknown is not zero.
            consumed=None,
            query=request.query,
            metadata={
                "engine": self.name,
                "matches": len(rows),
                "page_size": page_size,
                "use_time": body.get("use_time"),
                "points": "unknown",
            },
        )
        if cache_key is not None:
            self.cache.put(cache_key, page)
        return page

    async def iter_search(self, request: SearchRequest) -> AsyncIterator[SearchPage]:
        """Walk numbered pages, honoring the shared record/page budgets and dedupe contract."""
        seen: set[tuple[Any, ...]] = set()
        emitted = 0
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
            yield page
            if emitted >= request.max_records or raw_count == 0:
                break
            page_size = int(page.metadata.get("page_size") or 0)
            if page_size and raw_count < page_size:
                break
            if page.total is not None and page_size and page_number * page_size >= page.total:
                break
            page_number += 1

    @staticmethod
    def _validate_target(host: str) -> str:
        target = (host or "").strip().strip("'\"")
        if "://" in target:
            target = urlparse(target).hostname or ""
        target = target.split("/")[0].strip("[]")
        if not target or _HOST_RE.search(target) or ".." in target:
            raise FofaError(FofaErrorCode.INVALID_QUERY, "主机必须是 IP 地址或域名")
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        if not _TARGET_RE.fullmatch(target):
            raise FofaError(FofaErrorCode.INVALID_QUERY, "主机必须是 IP 地址或域名")
        return target.lower().removeprefix("www.")

    async def host_profile(self, host: str, *, detail: bool = True) -> dict[str, Any]:
        """Aggregate one host's services from an `ip=` / `domain=` search.

        DayDayMap has no host endpoint, so this spends one search request like any other query
        (the API does not report how many points that is) and aggregates the first
        ``HOST_PROFILE_PAGE_SIZE`` records, newest scan times included.
        """
        target = self._validate_target(host)
        is_ip = True
        try:
            ipaddress.ip_address(target)
        except ValueError:
            is_ip = False
        fields = list(DEFAULT_OUTPUT_FIELDS) + (
            [
                "server",
                "org",
                "isp",
                "asn",
                "os",
                "product",
                "status_code",
                "ssl_cn",
                "timestamp",
                "banner",
                "country_code",
                "region",
                "city",
            ]
            if detail
            else []
        )
        page = await self.search_page(
            SearchRequest(
                query=f'ip="{target}"' if is_ip else f'domain="{target}"',
                fields=fields,
                size=HOST_PROFILE_PAGE_SIZE,
                full=detail,
            )
        )
        records = [record.values for record in page.records]
        return normalize_host_profile(records, host=target, cached=bool(page.metadata.get("cached")))

    async def host_search(self, host: str) -> dict[str, Any]:
        return await self.host_profile(host)

    async def stats(self, query: str, fields: list[str], size: int = 5) -> dict[str, Any]:
        raise FofaError(
            FofaErrorCode.UNSUPPORTED,
            "DayDayMap 开放 API 没有按查询聚合的统计接口（/search/count/query 返回的是平台总量，不是本次查询的分布）。",
            alternatives=["用 -e fofa / -e shodan 做统计聚合", "用 -e daydaymap 做普通检索"],
        )
