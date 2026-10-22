"""Censys Platform (v3) engine: host profiles and IP entity lookups.

Live-verified against the Platform API with a Free-plan token:

- ``GET /v3/global/asset/host/{ip}`` costs **1 credit** and returns the full host asset
  (services, endpoints with HTTP/TLS detail, location, ASN, whois, DNS names);
- ``POST /v3/global/search/query`` answers **403** for Free users - "This endpoint requires an
  organization ID for API access. Free users can only access this endpoint through the Platform
  UI" - so this engine never pretends to enumerate assets. List search stays with FOFA/Shodan/Hunter;
- ``GET /v3/accounts/users/credits`` is free and reports ``balance`` + ``resets_at``; the Free
  allowance is 100 credits per month, so every paid call is preflighted against that balance.

Rows use the same unified vocabulary as the other engines, so a Censys page flows through the
existing renderers, exporters and agents unchanged. HTTP detail lives in
``services[].endpoints[].http`` (``html_title``, ``status_code``, ``headers["Server"]``) and TLS
detail in ``services[].endpoints[].tls``; the HTTP shape is live-verified, while the TLS
certificate names are read defensively (``subject_dn`` CN, then ``names``) because the sampled
hosts exposed no TLS endpoints.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
from collections.abc import AsyncIterator, Sequence
from typing import Any

import httpx

from config import settings
from core.cache import CacheKey, PageCache, resolve_cache
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

# Documented credit costs (https://docs.censys.com/docs/platform-credit-system-usage).
HOST_LOOKUP_CREDITS = 1
MONTHLY_FREE_CREDITS = 100
# DNS inventories can run into the hundreds of wildcard PTR names (1.1.1.1 resolves hundreds),
# so the display/export column is a bounded sample; the raw API keeps the full list.
HOSTNAME_LIMIT = 10

# Fields the host mapper can fill. Everything else is either FOFA-only or computed locally.
CENSYS_FIELDS: tuple[str, ...] = (
    "host",
    "ip",
    "port",
    "protocol",
    "base_protocol",
    "title",
    "domain",
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
    "version",
    "timestamp",
    "ssl_cn",
    "banner",
    "vulns",
)
DEFAULT_OUTPUT_FIELDS: tuple[str, ...] = (
    "host",
    "ip",
    "port",
    "protocol",
    "title",
    "domain",
    "country",
    "org",
    "asn",
    "timestamp",
)

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_ENTITY_RE = re.compile(
    r"""^\s*(?:ip|host\.ip)\s*=\s*"?\s*([0-9a-fA-F:.]+?)\s*"?\s*$""",
    re.IGNORECASE,
)


def entity_ip(query: str) -> str | None:
    """Return the IP address when the query is an entity lookup this engine can serve.

    Accepted forms: a bare IP, ``ip="1.2.3.4"`` (FOFA style) and ``host.ip=1.2.3.4`` (CenQL).
    Anything else needs the search API, which the Free plan does not expose.
    """
    candidate = (query or "").strip()
    match = _ENTITY_RE.match(candidate)
    if match:
        candidate = match.group(1)
    try:
        return str(ipaddress.ip_address(candidate.strip("\"'")))
    except ValueError:
        return None


def query_errors(query: str) -> list[str]:
    """Censys-specific query guard: only entity lookups are supported on the Free plan."""
    if entity_ip(query):
        return []
    return [
        'Censys Free 套餐仅支持实体查询（主机画像）：请用 ip="1.2.3.4" 或 -hq 1.2.3.4；列表搜索请改用 FOFA/Shodan/Hunter。',
    ]


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _bracketed(name: str) -> str:
    """IPv6 literals need brackets inside a URL."""
    return f"[{name}]" if name.count(":") >= 2 and not name.startswith("[") else name


def _header(headers: Any, wanted: str) -> str:
    """Censys headers are ``{"Server": {"headers": ["cloudflare"]}}``; match the name case-insensitively."""
    if not isinstance(headers, dict):
        return ""
    for name, value in headers.items():
        if str(name).lower() != wanted.lower():
            continue
        if isinstance(value, dict):
            values = _list(value.get("headers"))
            return _text(values[0]) if values else ""
        return _text(value)
    return ""


def _certificate_cn(tls: Any) -> str:
    certificates = _list((tls or {}).get("certificates")) if isinstance(tls, dict) else []
    for certificate in certificates:
        if not isinstance(certificate, dict):
            continue
        subject = _text(certificate.get("subject_dn"))
        for part in subject.split(","):
            name, _, value = part.strip().partition("=")
            if name.strip().upper() == "CN" and value.strip():
                return value.strip()
        names = _list(certificate.get("names"))
        if names:
            return _text(names[0])
    return ""


def _operating_system(value: Any) -> str:
    if isinstance(value, dict):
        name = _text(value.get("system_name") or value.get("name") or value.get("product"))
        version = _text(value.get("version"))
        return f"{name} {version}".strip()
    return _text(value)


def _hostnames(resource: dict[str, Any]) -> list[str]:
    dns = resource.get("dns") if isinstance(resource.get("dns"), dict) else {}
    names = [*(_list(dns.get("names"))), *(_list((dns.get("reverse_dns") or {}).get("names")))]
    unique = list(dict.fromkeys(_text(name) for name in names if _text(name)))
    return unique[:HOSTNAME_LIMIT]


def _service_row(
    resource: dict[str, Any],
    service: dict[str, Any],
    endpoint: dict[str, Any] | None,
) -> dict[str, Any]:
    """Project one Censys endpoint (or a bare service) onto the unified fields."""
    endpoint = endpoint or {}
    http = endpoint.get("http") if isinstance(endpoint.get("http"), dict) else {}
    tls = endpoint.get("tls") if isinstance(endpoint.get("tls"), dict) else {}
    location = resource.get("location") if isinstance(resource.get("location"), dict) else {}
    asn = resource.get("autonomous_system") if isinstance(resource.get("autonomous_system"), dict) else {}
    whois_org = ((resource.get("whois") or {}).get("organization") if isinstance(resource.get("whois"), dict) else {}) or {}
    host_ip = _text(resource.get("ip")) or _text(endpoint.get("ip")) or _text(service.get("ip"))
    port = endpoint.get("port", service.get("port"))
    protocol = (_text(endpoint.get("endpoint_type") or service.get("protocol"))).lower()
    transport = _text(endpoint.get("transport_protocol") or service.get("transport_protocol"))
    name = _bracketed(_text(endpoint.get("hostname")) or host_ip)
    uri = _text(http.get("uri")).rstrip("/")
    if uri:
        host_value = uri
    elif protocol in {"http", "https"} and name:
        scheme = "https" if protocol == "https" or port in {443, 8443} else "http"
        host_value = f"{scheme}://{name}:{port}" if port is not None else f"{scheme}://{name}"
    elif name:
        host_value = f"{name}:{port}" if port is not None else name
    else:
        host_value = ""
    software = [item for item in _list(service.get("software")) if isinstance(item, dict)]
    products = [_text(item.get("product")) for item in software if _text(item.get("product"))]
    versions = [_text(item.get("version")) for item in software if _text(item.get("version"))]
    asn_number = asn.get("asn")
    return {
        "host": host_value,
        "ip": host_ip,
        "port": port,
        "protocol": protocol,
        "base_protocol": transport,
        "title": _text(http.get("html_title")),
        "domain": "",
        "hostnames": ", ".join(_hostnames(resource)),
        "country": _text(location.get("country")),
        "country_code": _text(location.get("country_code")),
        "region": _text(location.get("province")),
        "city": _text(location.get("city")),
        "org": _text(whois_org.get("name")) or _text(asn.get("name")),
        "isp": _text(asn.get("name")),
        "asn": f"AS{asn_number}" if asn_number not in (None, "") else "",
        "os": _operating_system(resource.get("operating_system")),
        "server": _header(http.get("headers"), "Server"),
        "status_code": http.get("status_code"),
        "product": ", ".join(dict.fromkeys(products)),
        "version": ", ".join(dict.fromkeys(versions)),
        "timestamp": _text(endpoint.get("scan_time") or service.get("scan_time")),
        "ssl_cn": _certificate_cn(tls),
        "banner": _text(service.get("banner")),
        "vulns": "",
    }


def host_rows(resource: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand a host asset into one unified row per endpoint (or one per service)."""
    rows: list[dict[str, Any]] = []
    for service in _list(resource.get("services")):
        if not isinstance(service, dict):
            continue
        endpoints = [item for item in _list(service.get("endpoints")) if isinstance(item, dict)]
        if not endpoints:
            rows.append(_service_row(resource, service, None))
            continue
        for endpoint in endpoints:
            rows.append(_service_row(resource, service, endpoint))
    if not rows and _text(resource.get("ip")):
        # A host with no scanned services is still a paid, meaningful entity (geo/ASN/whois).
        rows.append(_service_row(resource, {}, None))
    return rows


def normalize_host_profile(resource: dict[str, Any]) -> dict[str, Any]:
    """Reshape a host asset into the profile the CLI already renders for FOFA/Shodan/Hunter."""
    location = resource.get("location") if isinstance(resource.get("location"), dict) else {}
    asn = resource.get("autonomous_system") if isinstance(resource.get("autonomous_system"), dict) else {}
    whois_org = ((resource.get("whois") or {}).get("organization") if isinstance(resource.get("whois"), dict) else {}) or {}
    hostnames = _hostnames(resource)
    ports = []
    seen: set[tuple[Any, str]] = set()
    for row in host_rows(resource):
        key = (row["port"], row["protocol"])
        if key in seen:
            continue
        seen.add(key)
        products = [
            {"product": name, "version": row["version"], "category": ""} for name in (row["product"].split(", ") if row["product"] else [])
        ]
        ports.append(
            {
                "port": row["port"],
                "protocol": row["protocol"],
                "products": products,
                "update_time": row["timestamp"],
                "banner": row["banner"],
                "server": row["server"],
                "title": row["title"],
            }
        )
    timestamps = sorted(row["timestamp"] for row in host_rows(resource) if row["timestamp"])
    return {
        "host": _text(resource.get("ip")),
        "ip": _text(resource.get("ip")),
        "domain": "",
        "hostnames": hostnames,
        "country_name": _text(location.get("country")),
        "country_code": _text(location.get("country_code")),
        "region": _text(location.get("province")),
        "city": _text(location.get("city")),
        "org": _text(whois_org.get("name")) or _text(asn.get("name")),
        "isp": _text(asn.get("name")),
        "asn": f"AS{asn['asn']}" if asn.get("asn") not in (None, "") else "",
        "os": _operating_system(resource.get("operating_system")),
        "update_time": timestamps[-1] if timestamps else "",
        "ports": ports,
        "vulns": [],
        "source": "censys",
    }


def _requested(fields: Sequence[str]) -> list[str]:
    """Project the request onto the Censys catalogue: empty columns are worse than a clear error."""
    allowed = [field for field in fields if field in CENSYS_FIELDS]
    denied = [field for field in fields if field and field not in CENSYS_FIELDS and field not in LOCAL_RESULT_FIELDS]
    if not allowed:
        raise FofaError(
            FofaErrorCode.INVALID_QUERY,
            f"Censys 无法返回这些字段：{', '.join(denied) or '（空）'}",
            alternatives=[", ".join(DEFAULT_OUTPUT_FIELDS), ", ".join(CENSYS_FIELDS)],
        )
    return allowed


class CensysClient:
    """Censys Platform client: one paid endpoint (host lookup), documented credits, typed errors."""

    def __init__(
        self,
        *,
        api_token: str | None = None,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        max_retries: int = 3,
        requests_per_second: float | None = None,
        concurrency: int | None = None,
        cache: PageCache | None | bool = True,
    ) -> None:
        self.name = "censys"
        self.base_url = (base_url or settings.censys.base_url).rstrip("/")
        self.key = settings.censys.api_token if api_token is None else api_token
        self.max_retries = max_retries
        self._client = client
        self._owns_client = client is None
        self._configured_rps = requests_per_second or settings.censys.requests_per_second or settings.system.requests_per_second
        self._limiter = RateLimiter(self._configured_rps)
        self._semaphore = asyncio.Semaphore(concurrency or settings.system.concurrency)
        self.headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        self.plan_info: dict[str, Any] | None = None
        self.cache = (resolve_cache() if cache is True else cache) or None

    async def __aenter__(self) -> CensysClient:
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
                timeout=httpx.Timeout(30.0, connect=10.0),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            )
        return self._client

    def _auth_headers(self) -> dict[str, str]:
        if not self.key:
            raise FofaError(
                FofaErrorCode.AUTH_FAILED,
                "未配置 Censys 访问令牌",
                alternatives=[
                    "export CENSYS_API_TOKEN=<personal access token>",
                    "python cybermap.py --save-key censys",
                ],
            )
        return {**self.headers, "Authorization": f"Bearer {self.key}"}

    def _scrub(self, text: str) -> str:
        """Never surface upstream text that may echo the credential-bearing request URI."""
        return redact_secrets(text, self.key)

    def _classify_error(self, message: str, status_code: int | None) -> FofaError:
        lowered = message.lower()
        if status_code == 401:
            return FofaError(FofaErrorCode.AUTH_FAILED, message or "Censys 令牌无效或未激活", status_code=status_code)
        if status_code == 403 and ("organization id" in lowered or "free users" in lowered):
            return FofaError(
                FofaErrorCode.UNSUPPORTED,
                message,
                status_code=status_code,
                alternatives=[
                    "用 -e censys -hq <IP> 查询主机画像（Free 套餐可用）",
                    "列表搜索改用 -e fofa / -e shodan / -e hunter",
                ],
            )
        if status_code == 403:
            return FofaError(FofaErrorCode.PERMISSION_DENIED, message, status_code=status_code)
        if status_code == 404:
            return FofaError(FofaErrorCode.INVALID_QUERY, message or "Censys 未找到该实体", status_code=status_code)
        if status_code == 429:
            return FofaError(FofaErrorCode.RATE_LIMITED, message or "Censys 触发限流", retryable=True, status_code=status_code)
        if status_code == 402 or "credit" in lowered or "quota" in lowered:
            return FofaError(FofaErrorCode.QUOTA_EXHAUSTED, message, status_code=status_code)
        if status_code is not None and status_code >= 500:
            return FofaError(FofaErrorCode.TRANSPORT_ERROR, message, retryable=True, status_code=status_code)
        return FofaError(FofaErrorCode.INVALID_RESPONSE, message, status_code=status_code)

    async def _request(self, path: str) -> dict[str, Any]:
        client = await self._get_client()
        last_error: FofaError | None = None
        for attempt in range(self.max_retries + 1):
            try:
                await self._limiter.wait()
                async with self._semaphore:
                    response = await client.get(f"{self.base_url}{path}", headers=self._auth_headers())
                if response.status_code == 429 or response.status_code >= 500:
                    delay = retry_after_seconds(response.headers.get("Retry-After"), 0.5 * (2**attempt))
                    last_error = self._classify_error(self._scrub(response.text[:500]) or "Censys 请求失败", response.status_code)
                    if attempt < self.max_retries:
                        await asyncio.sleep(delay + random.uniform(0, max(0.05, delay * 0.2)))
                        continue
                    raise last_error
                try:
                    data = response.json()
                except ValueError as exc:
                    if response.is_error:
                        raise self._classify_error(f"Censys 返回 {response.status_code}（非 JSON 响应）", response.status_code) from exc
                    raise FofaError(FofaErrorCode.INVALID_RESPONSE, "Censys 返回了非 JSON 响应", status_code=response.status_code) from exc
                if response.is_error:
                    detail = ""
                    if isinstance(data, dict):
                        detail = _text(data.get("detail") or data.get("title") or data.get("message"))
                    error = self._classify_error(self._scrub(detail or f"HTTP {response.status_code}"), response.status_code)
                    if error.retryable and attempt < self.max_retries:
                        delay = retry_after_seconds(response.headers.get("Retry-After"), 0.5 * (2**attempt))
                        await asyncio.sleep(delay + random.uniform(0, max(0.05, delay * 0.2)))
                        last_error = error
                        continue
                    raise error
                if not isinstance(data, dict):
                    raise FofaError(FofaErrorCode.INVALID_RESPONSE, "Censys 返回了非对象 JSON 响应")
                return data
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = FofaError(FofaErrorCode.TRANSPORT_ERROR, self._scrub(str(exc)), retryable=True)
                if attempt >= self.max_retries:
                    raise last_error from exc
                await asyncio.sleep(0.5 * (2**attempt) + random.uniform(0, 0.2))
        raise last_error or FofaError(FofaErrorCode.TRANSPORT_ERROR, "Censys 请求失败")

    async def account(self) -> dict[str, Any]:
        """Free-user balance; documented as costing no credits."""
        data = await self._request("/v3/accounts/users/credits")
        credit = data.get("result") if isinstance(data.get("result"), dict) else {}
        balance = credit.get("balance")
        self.plan_info = {
            "engine": self.name,
            "plan": "free",
            "balance": balance if isinstance(balance, int) else None,
            "resets_at": _text(credit.get("resets_at")),
            "monthly_credits": MONTHLY_FREE_CREDITS,
        }
        return self.plan_info

    async def check_login(self) -> dict[str, Any]:
        return await self.account()

    async def _require_credits(self, cost: int) -> None:
        info = await self.account()
        balance = info.get("balance")
        if isinstance(balance, int) and balance < cost:
            resets = f"，{info['resets_at']} 重置" if info.get("resets_at") else ""
            raise FofaError(
                FofaErrorCode.QUOTA_EXHAUSTED,
                f"Censys 额度不足：余额 {balance}，本次需要 {cost} 额度（Free 套餐每月 {MONTHLY_FREE_CREDITS}）{resets}。",
                alternatives=["已抓取的页面会缓存并保留，额度重置后可继续", "改用 -e fofa / -e shodan / -e hunter"],
            )

    async def _host(self, ip: str) -> tuple[dict[str, Any], float | None]:
        """Raw host asset plus its cache timestamp (None when just paid for).

        Each lookup costs a credit, so the asset is written to the cache before it is mapped;
        an interrupted run therefore never pays twice for the same host.
        """
        cache_key = CacheKey(self.name, f"host:{ip}", 0, 0, "profile") if self.cache else None
        if cache_key is not None:
            cached = self.cache.get_blob(cache_key)
            if cached is not None:
                return cached[0], cached[1]
        await self._require_credits(HOST_LOOKUP_CREDITS)
        data = await self._request(f"/v3/global/asset/host/{ip}")
        result = data.get("result") if isinstance(data.get("result"), dict) else {}
        resource = result.get("resource") if isinstance(result.get("resource"), dict) else {}
        if not resource:
            raise FofaError(FofaErrorCode.INVALID_RESPONSE, "Censys 未返回主机数据")
        if cache_key is not None:
            self.cache.put_blob(cache_key, resource)
        return resource, None

    async def host_profile(self, host: str, *, detail: bool = True) -> dict[str, Any]:
        ip = entity_ip(host) or entity_ip(f'ip="{host}"')
        if not ip:
            raise FofaError(
                FofaErrorCode.INVALID_QUERY,
                "Censys 主机画像需要明确的 IP 地址",
                alternatives=["-e censys -hq 1.2.3.4"],
            )
        resource, cached_at = await self._host(ip)
        profile = normalize_host_profile(resource)
        profile["cached"] = cached_at is not None
        if cached_at is not None:
            profile["cached_at"] = cached_at
        return profile

    async def search_page(self, request: SearchRequest) -> SearchPage:
        errors = validate_query(request.query) + query_errors(request.query)
        if errors:
            raise FofaError(
                FofaErrorCode.UNSUPPORTED,
                errors[0],
                alternatives=[
                    "-e censys -hq <IP> 查询主机画像",
                    "列表搜索改用 -e fofa / -e shodan / -e hunter",
                ],
            )
        ip = entity_ip(request.query)
        assert ip is not None
        resource, cached_at = await self._host(ip)
        rows = host_rows(resource)
        fields = _requested(request.fields)
        records = [AssetRecord(values={field: row.get(field, "") for field in fields}) for row in rows]
        metadata: dict[str, Any] = {
            "source": "censys",
            "engine": self.name,
            "entities": 1,
            "plans": {"censys": "free"},
            "cached": cached_at is not None,
        }
        if cached_at is not None:
            metadata["cached_at"] = cached_at
        return SearchPage(
            records=records,
            fields=fields,
            total=len(records),
            page=1,
            consumed=0 if cached_at is not None else HOST_LOOKUP_CREDITS,
            query=request.query,
            metadata=metadata,
        )

    async def iter_search(self, request: SearchRequest) -> AsyncIterator[SearchPage]:
        """One host lookup is one page: there is nothing to paginate."""
        timeout = 60.0
        try:
            async with asyncio.timeout(timeout):
                yield await self.search_page(request)
            return
        except TimeoutError:
            raise FofaError(
                FofaErrorCode.TRANSPORT_ERROR,
                f"Censys 页请求超过 {timeout:g} 秒仍未完成",
                retryable=True,
            ) from None
        except FofaError:
            raise
        except httpx.TimeoutException as exc:
            raise FofaError(FofaErrorCode.TRANSPORT_ERROR, str(exc), retryable=True) from exc
        except httpx.NetworkError as exc:
            raise FofaError(FofaErrorCode.TRANSPORT_ERROR, str(exc), retryable=True) from exc

    async def stats(self, query: str, fields: list[str], size: int = 5) -> dict[str, Any]:
        raise FofaError(
            FofaErrorCode.UNSUPPORTED,
            "Censys Free 套餐没有聚合接口（search/aggregate 属于 Starter 及以上），无法产出统计。",
            alternatives=["用 -e censys 查询单台主机画像", "统计请改用 FOFA / Shodan"],
        )
