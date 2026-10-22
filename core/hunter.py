"""Asynchronous Hunter (奇安信鹰图) client speaking the same asset contracts as the other engines.

Every rule below was pinned against the live open API instead of the help pages:

- `GET /openApi/search` takes the query **base64url** encoded (`search=`), 1-based `page`,
  `page_size` (only 1 or a multiple of 10 up to 100 - `2`/`15`/`99` are refused with
  ``页大小不合法``), `is_web` (1 web / 2 non-web / 3 all) and a `fields=` column list
  drawn from the documented export columns; anything else is refused with
  ``字段"x"无效``/``无"x"字段权限``.
- `GET /openApi/userInfo` returns the balance and never consumes credits.
- Failures arrive as HTTP 200 with a body `code` (401 令牌缺失/令牌过期, 400 语法/字段/时间范围),
  so the body code - not the HTTP status - drives classification.
- Credits are decided server-side: every reply carries ``消耗积分：N`` and
  ``今日剩余积分：N``. An identical re-run and any rejected request cost 0 credits, so this
  client reports the returned numbers instead of estimating locally.
- One query can only be paged to 10 000 records (``支持最大查看10000条资产``).
- The open API has no aggregation endpoint, so `stats` is unsupported by design; FOFA and Shodan
  cover the statistics action.
- `web.icon` filters on the favicon **MD5** (verified: the favicon MD5 of a site returned its 617
  indexed assets), not on FOFA/Shodan's MurmurHash3.
"""

from __future__ import annotations

import asyncio
import base64
import random
import re
from collections.abc import AsyncIterator, Callable, Sequence
from typing import Any

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
SEARCH_PAGE_SIZE_DEFAULT = 10
SEARCH_PAGE_SIZE_MAX = 100
# Hunter refuses pages past the 10 000th record of one query, so pagination stops there.
RESULT_WINDOW = 10_000
HOST_PROFILE_PAGE_SIZE = 100
DEFAULT_OUTPUT_FIELDS = (
    "host",
    "ip",
    "port",
    "protocol",
    "title",
    "domain",
    "country",
)
# Documented `fields=` export columns.
NATIVE_FIELDS: tuple[str, ...] = (
    "ip",
    "port",
    "domain",
    "ip_tag",
    "url",
    "web_title",
    "is_risk_protocol",
    "protocol",
    "base_protocol",
    "status_code",
    "os",
    "company",
    "number",
    "icp_exception",
    "country",
    "province",
    "city",
    "is_web",
    "isp",
    "as_org",
    "cert_sha256",
    "ssl_certificate",
    "component",
    "asset_tag",
    "updated_at",
    "header",
    "header_server",
    "banner",
    "whois",
    "body",
    "vul_list",
)
# Every field a Hunter record can contribute, in the order users see them. Names shared with the
# other engines mean the same thing, so a merged export lines up column for column.
HUNTER_FIELDS: tuple[str, ...] = (
    "host",
    "ip",
    "port",
    "protocol",
    "base_protocol",
    "title",
    "domain",
    "server",
    "status_code",
    "country",
    "country_code",
    "region",
    "city",
    "org",
    "as_org",
    "isp",
    "os",
    "product",
    "version",
    "timestamp",
    "vulns",
    "ssl_cn",
    "cert_sha256",
    "banner",
    "header",
    "body",
    "icp",
    "ip_tag",
    "asset_tag",
    "icp_exception",
    "is_risk_protocol",
    "is_web",
)
# Unified field -> native `fields=` columns that must be requested for it.
NATIVE_COLUMNS: dict[str, tuple[str, ...]] = {
    "host": ("url",),
    "ip": ("ip",),
    "port": ("port",),
    "protocol": ("protocol", "base_protocol"),
    "base_protocol": ("base_protocol",),
    "title": ("web_title",),
    "domain": ("domain",),
    "server": ("header_server",),
    "status_code": ("status_code",),
    "country": ("country",),
    "country_code": ("country",),
    "region": ("province",),
    "city": ("city",),
    "org": ("company",),
    "as_org": ("as_org",),
    "isp": ("isp",),
    "os": ("os",),
    "product": ("component",),
    "version": ("component",),
    "timestamp": ("updated_at",),
    "vulns": ("vul_list",),
    "ssl_cn": ("ssl_certificate",),
    "cert_sha256": ("cert_sha256",),
    "banner": ("banner",),
    "header": ("header",),
    "body": ("body",),
    "icp": ("number",),
    "ip_tag": ("ip_tag",),
    "asset_tag": ("asset_tag",),
    "icp_exception": ("icp_exception",),
    "is_risk_protocol": ("is_risk_protocol",),
    "is_web": ("is_web",),
}
# Columns that bloat the reply; requested only for `--full` or an explicit field request.
HEAVY_COLUMNS: tuple[str, ...] = ("banner", "header", "body", "ssl_certificate")
# Shodan-style `filter:value` is the wrong syntax for Hunter, and a model may copy it over.
_COLON_FILTER = re.compile(r"(?:^|\s)[A-Za-z][A-Za-z0-9_.]*\s*:\s*\S")
_QUOTED_SEGMENT = re.compile(r'"[^"]*"')
_PERMISSION_FIELD = re.compile(r"[\"“”]([a-zA-Z_][a-zA-Z0-9_]*)[\"“”]字段权限")
_QUOTA_NUMBER = re.compile(r"(\d+)")
_SSL_COMMON_NAME = re.compile(r"Common\s+Name:\s*([^\s]+)", re.IGNORECASE)
_HOST_RE = re.compile(r"[^:/\[\]A-Za-z0-9.\-]")
# Filters offered to the planner; Hunter rejects unknown keys itself, so this is prompt guidance.
# Filters offered to the planner and documented at https://hunter.qianxin.com; every entry was
# verified against the live API (`number=`, `web.icp=`, `url=`, `asset_tag=` and `is_risk_protocol=`
# are documented elsewhere but the API answers "字段 ... 不支持查询", so they are not advertised).
HUNTER_FILTERS = (
    'ip=""',
    'port=""',
    'protocol=""',
    'base_protocol=""',
    'domain=""',
    'domain.suffix=""',
    'web.title=""',
    'web.body=""',
    'web.icon=""',
    'web.tag=""',
    'web.similar=""',
    'header=""',
    'header.server==""',
    'status_code=""',
    'cert=""',
    'icp=""',
    'app.name=""',
    'app.vendor=""',
    'app.version=""',
    'os=""',
    'company=""',
    'country=""',
    'province=""',
    'city=""',
    'isp=""',
)


def hunter_syntax_errors(query: str) -> list[str]:
    """Reject only what Hunter definitely cannot parse, before any credit can be spent.

    Filter names are never restricted: Hunter validates them server-side (``字段 x 不支持查询``)
    and a rejected request costs no credits, so `HUNTER_FILTERS` stays planner guidance.
    """
    # Quoted values legitimately contain colons (`web.similar="host:443"`), so only the
    # unquoted skeleton is inspected.
    skeleton = _QUOTED_SEGMENT.sub(" ", query)
    if _COLON_FILTER.search(skeleton):
        return ['Hunter 使用 key="value" 语法（例如 web.title="登录"），不支持 filter:value']
    return []


def hunter_request_fields(fields: Sequence[str] | None) -> list[str]:
    """Keep requestable unified fields, rejecting names Hunter cannot return."""
    requested = [field for field in (fields or []) if field and field not in LOCAL_RESULT_FIELDS]
    unknown = [field for field in requested if field not in HUNTER_FIELDS]
    if unknown:
        raise FofaError(
            FofaErrorCode.INVALID_QUERY,
            f"Hunter 无法返回字段：{', '.join(unknown)}",
            alternatives=list(HUNTER_FIELDS),
        )
    return requested or list(DEFAULT_OUTPUT_FIELDS)


def native_columns(fields: Sequence[str], *, full: bool = False) -> list[str]:
    """Render the unified field selection as Hunter's `fields=` column list."""
    columns: list[str] = []
    for field in fields:
        for column in NATIVE_COLUMNS.get(field, ()):
            if column not in columns:
                columns.append(column)
    if full:
        for column in HEAVY_COLUMNS:
            if column not in columns:
                columns.append(column)
    return columns


def legal_page_size(size: int) -> int:
    """Hunter only accepts `page_size` 1 or a multiple of 10 up to 100 (verified live).

    A request is rounded *down* to the nearest legal bucket: Hunter charges per returned record,
    so asking for a larger bucket than the caller wanted would spend more points than requested.
    """
    requested = max(1, min(int(size), SEARCH_PAGE_SIZE_MAX))
    if requested == 1:
        return 1
    bucket = (requested // 10) * 10
    return bucket if bucket >= 10 else 1


def favicon_query(md5: str) -> str:
    """Hunter filters favicons by the MD5 of the icon file (`web.icon="<md5>"`)."""
    return f'web.icon="{md5}"'


# Hunter answers `country` with a Chinese country name and no ISO code, while FOFA answers a code
# and Shodan a name plus a code. The mapping below is what makes `country_code` a column the three
# engines can be filtered and aggregated on together. Names outside it simply leave the code empty
# instead of inventing one.
_HUNTER_COUNTRY_CODES: dict[str, str] = {
    "中国": "CN", "中国香港": "HK", "中国澳门": "MO", "中国台湾": "TW", "台湾": "TW", "香港": "HK", "澳门": "MO",
    "美国": "US", "加拿大": "CA", "墨西哥": "MX", "巴西": "BR", "阿根廷": "AR", "智利": "CL", "哥伦比亚": "CO",
    "秘鲁": "PE", "委内瑞拉": "VE", "厄瓜多尔": "EC",
    "英国": "GB", "爱尔兰": "IE", "法国": "FR", "德国": "DE", "荷兰": "NL", "比利时": "BE", "卢森堡": "LU",
    "瑞士": "CH", "奥地利": "AT", "意大利": "IT", "西班牙": "ES", "葡萄牙": "PT", "希腊": "GR", "波兰": "PL",
    "捷克": "CZ", "斯洛伐克": "SK", "匈牙利": "HU", "罗马尼亚": "RO", "保加利亚": "BG", "乌克兰": "UA",
    "俄罗斯": "RU", "白俄罗斯": "BY", "立陶宛": "LT", "拉脱维亚": "LV", "爱沙尼亚": "EE", "芬兰": "FI",
    "瑞典": "SE", "挪威": "NO", "丹麦": "DK", "冰岛": "IS", "塞尔维亚": "RS", "克罗地亚": "HR", "斯洛文尼亚": "SI",
    "土耳其": "TR", "以色列": "IL", "沙特阿拉伯": "SA", "阿联酋": "AE", "卡塔尔": "QA", "科威特": "KW",
    "伊朗": "IR", "伊拉克": "IQ", "印度": "IN", "巴基斯坦": "PK", "孟加拉国": "BD", "斯里兰卡": "LK",
    "尼泊尔": "NP", "哈萨克斯坦": "KZ", "乌兹别克斯坦": "UZ", "日本": "JP", "韩国": "KR", "朝鲜": "KP",
    "蒙古": "MN", "越南": "VN", "泰国": "TH", "马来西亚": "MY", "新加坡": "SG", "印度尼西亚": "ID",
    "菲律宾": "PH", "柬埔寨": "KH", "缅甸": "MM", "老挝": "LA", "文莱": "BN",
    "澳大利亚": "AU", "新西兰": "NZ", "南非": "ZA", "埃及": "EG", "尼日利亚": "NG", "肯尼亚": "KE",
    "摩洛哥": "MA", "突尼斯": "TN", "阿尔及利亚": "DZ", "加纳": "GH", "坦桑尼亚": "TZ", "埃塞俄比亚": "ET",
}


def country_code_from_name(name: Any) -> str:
    """ISO-3166 alpha-2 code for a Hunter country name, or "" when the name is not mapped."""
    return _HUNTER_COUNTRY_CODES.get(_one_line(name), "")


def parse_points(value: Any) -> int:
    """Read Hunter's ``消耗积分：N`` / ``今日剩余积分：N`` counters."""
    if isinstance(value, int):
        return value
    match = _QUOTA_NUMBER.search(str(value or ""))
    return int(match.group(1)) if match else 0


def _int_or_blank(value: Any) -> int | str:
    text = str(value if value is not None else "").strip()
    if not text or text == "0":
        # Hunter reports `0` for "no HTTP status" (non-web services) and for absent ports.
        return ""
    return int(text) if text.isdigit() else text


def _text(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _one_line(value: Any) -> str:
    """Collapse whitespace: banner-derived product/version strings arrive with CRLF."""
    return " ".join(str(value or "").split())


def _components(match: dict[str, Any]) -> list[tuple[str, str]]:
    value = match.get("component")
    if not isinstance(value, list):
        return []
    components: list[tuple[str, str]] = []
    for item in value:
        if isinstance(item, dict):
            name, version = _one_line(item.get("name")), _one_line(item.get("version"))
        else:
            name, version = _one_line(item), ""
        if name or version:
            components.append((name, version))
    return components


def _bracketed(name: str) -> str:
    """IPv6 literals need brackets inside a URL; `https://2001:db8::1:443` cannot be parsed."""
    return f"[{name}]" if name.count(":") >= 2 and not name.startswith("[") else name


def _host(match: dict[str, Any]) -> str:
    url = _text(match.get("url"))
    if url:
        return url.rstrip("/")
    ip = _text(match.get("ip"))
    if not ip:
        return ""
    port = _int_or_blank(match.get("port"))
    host = _bracketed(ip)
    if port == "":
        return host
    protocol = (_text(match.get("protocol")) or _text(match.get("base_protocol"))).lower()
    if protocol in {"http", "https"} or port in {80, 443, 8080, 8443}:
        scheme = "https" if protocol == "https" or port in {443, 8443} else "http"
        return f"{scheme}://{host}:{port}"
    return f"{host}:{port}"


def _ssl_cn(match: dict[str, Any]) -> str:
    certificate = _text(match.get("ssl_certificate"))
    found = _SSL_COMMON_NAME.search(certificate)
    return found.group(1).strip() if found else ""


def _vulns(match: dict[str, Any]) -> str:
    value = match.get("vul_list")
    if isinstance(value, list):
        return ", ".join(sorted(_one_line(item) for item in value if _one_line(item)))
    return _one_line(value)


# Field -> record extractor. Built once at import time so projecting a large export allocates
# only the result rows.
_FIELD_EXTRACTORS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "host": _host,
    "ip": lambda match: _text(match.get("ip")),
    "port": lambda match: _int_or_blank(match.get("port")),
    "protocol": lambda match: _text(match.get("protocol")) or _text(match.get("base_protocol")),
    "base_protocol": lambda match: _text(match.get("base_protocol")),
    "title": lambda match: _one_line(match.get("web_title")),
    "domain": lambda match: _one_line(match.get("domain")),
    "server": lambda match: _one_line(match.get("header_server")),
    "status_code": lambda match: _int_or_blank(match.get("status_code")),
    "country": lambda match: _one_line(match.get("country")),
    "country_code": lambda match: country_code_from_name(match.get("country")),
    "region": lambda match: _one_line(match.get("province")),
    "city": lambda match: _one_line(match.get("city")),
    "org": lambda match: _one_line(match.get("company")),
    "as_org": lambda match: _one_line(match.get("as_org")),
    "isp": lambda match: _one_line(match.get("isp")),
    "os": lambda match: _one_line(match.get("os")),
    "product": lambda match: ", ".join(name for name, _ in _components(match)),
    "version": lambda match: ", ".join(version for _, version in _components(match) if version),
    "timestamp": lambda match: _one_line(match.get("updated_at")),
    "vulns": _vulns,
    "ssl_cn": _ssl_cn,
    "cert_sha256": lambda match: _one_line(match.get("cert_sha256")),
    "banner": lambda match: _text(match.get("banner")),
    "header": lambda match: _text(match.get("header")),
    "body": lambda match: _text(match.get("body")),
    "icp": lambda match: _one_line(match.get("number")),
    "ip_tag": lambda match: _one_line(match.get("ip_tag")),
    "asset_tag": lambda match: _one_line(match.get("asset_tag")),
    "icp_exception": lambda match: _one_line(match.get("icp_exception")),
    "is_risk_protocol": lambda match: _one_line(match.get("is_risk_protocol")),
    "is_web": lambda match: _one_line(match.get("is_web")),
}


def map_record(match: dict[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    """Project one Hunter record onto the requested unified fields."""
    return {field: _FIELD_EXTRACTORS[field](match) for field in fields if field in _FIELD_EXTRACTORS}


def normalize_host_profile(records: Sequence[dict[str, Any]], *, host: str) -> dict[str, Any]:
    """Aggregate `ip=` search records into the host profile the CLI already renders."""
    entries: dict[int, dict[str, Any]] = {}
    for values in records:
        port = values.get("port")
        if not isinstance(port, int):
            continue
        entry = entries.setdefault(
            port,
            {
                "port": port,
                "protocol": values.get("protocol") or "",
                "products": [],
                "update_time": values.get("timestamp") or "",
            },
        )
        if not entry["protocol"]:
            entry["protocol"] = values.get("protocol") or ""
        label = " ".join(str(item) for item in (values.get("product"), values.get("version")) if item).strip()
        label = label or str(values.get("server") or values.get("title") or "")
        if label:
            entry["products"].append({"product": label, "name": label})
    newest = max((str(item.get("timestamp") or "") for item in records), default="")
    first = records[0] if records else {}
    return {
        "host": host,
        "ip": first.get("ip") or host,
        "country_name": first.get("country") or "",
        "org": first.get("org") or first.get("as_org") or "",
        # Hunter reports no ASN *number*, only the network operator name, so the ASN row stays
        # empty instead of showing an AS number that does not exist.
        "asn": "",
        "as_org": first.get("as_org") or "",
        "update_time": newest,
        "hostnames": [],
        "domains": [first["domain"]] if first.get("domain") else [],
        "os": first.get("os") or "",
        "isp": first.get("isp") or "",
        "city": first.get("city") or "",
        "vulns": [],
        "ports": [entries[port] for port in sorted(entries)],
        "source": "hunter",
    }


class HunterClient:
    """Hunter client: body-code errors, server-reported credit accounting, documented window."""

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
        self.name = "hunter"
        self.base_url = (base_url or settings.hunter.base_url).rstrip("/")
        self.key = settings.hunter.api_key if api_key is None else api_key
        self.max_retries = max_retries
        self._client = client
        self._owns_client = client is None
        self._configured_rps = (
            requests_per_second or settings.hunter.requests_per_second or settings.system.requests_per_second
        )
        self._limiter = RateLimiter(self._configured_rps)
        self._semaphore = asyncio.Semaphore(concurrency or settings.system.concurrency)
        self.cache = (resolve_cache() if cache is True else cache) or None
        self.headers = {"User-Agent": USER_AGENT}
        self.account_info: dict[str, Any] | None = None
        self.remaining_points: int | None = None
        # Fields the account turned out not to own; recorded so a downgrade is never silent.
        self.field_downgrades: list[str] = []

    async def __aenter__(self) -> HunterClient:
        await self._get_client()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Hunter authenticates with the `api-key` query parameter, so the credential is part
            # of every request URI. Keep redirects disabled (the key must never be replayed to a
            # Location target), never call `raise_for_status()` (its message embeds the URL) and
            # never log request URLs.
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
                "未配置 HUNTER_API_KEY",
                alternatives=["HUNTER_API_KEY", "cybermap-hunter 钥匙串条目", "settings.yaml 的 hunter.api_key"],
            )
        return {"api-key": self.key}

    @staticmethod
    def _classify_error(message: str, code: int | None = None) -> FofaError:
        # Balance errors first: Hunter reports an exhausted pool in the message and would
        # otherwise be misread as a syntax or permission problem.
        if "积分不足" in message or "积分不够" in message or "余额不足" in message:
            return FofaError(FofaErrorCode.QUOTA_EXHAUSTED, message, status_code=code)
        if code == 401 or "令牌" in message or "token" in message.lower():
            return FofaError(FofaErrorCode.AUTH_FAILED, message, status_code=code)
        if code == 429 or "频率" in message or "频繁" in message:
            return FofaError(FofaErrorCode.RATE_LIMITED, message, retryable=True, status_code=code)
        if code == 403 or "权限" in message:
            return FofaError(FofaErrorCode.PERMISSION_DENIED, message, status_code=code)
        if code == 400 or any(token in message for token in ("无效", "不支持", "超出", "最大查看", "不能为空")):
            return FofaError(FofaErrorCode.INVALID_QUERY, message, status_code=code)
        if code is not None and code >= 500:
            return FofaError(FofaErrorCode.TRANSPORT_ERROR, message, retryable=True, status_code=code)
        return FofaError(FofaErrorCode.INVALID_RESPONSE, message, status_code=code)

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
                    last_error = self._classify_error(self._scrub(response.text[:500]), response.status_code)
                    if attempt < self.max_retries:
                        delay = retry_after_seconds(response.headers.get("Retry-After"), 0.5 * (2**attempt))
                        await asyncio.sleep(delay + random.uniform(0, max(0.05, delay * 0.2)))
                        continue
                    raise last_error
                try:
                    data = response.json()
                except ValueError as exc:
                    raise FofaError(
                        FofaErrorCode.INVALID_RESPONSE,
                        self._scrub(f"Hunter 返回了非 JSON 响应（HTTP {response.status_code}）"),
                        status_code=response.status_code,
                    ) from exc
                if not isinstance(data, dict):
                    raise FofaError(FofaErrorCode.INVALID_RESPONSE, "Hunter 返回了非对象 JSON 响应")
                code = data.get("code")
                if code == 200:
                    return data
                error = self._classify_error(self._scrub(str(data.get("message") or "Hunter 请求失败")), code)
                if error.retryable and attempt < self.max_retries:
                    last_error = error
                    await asyncio.sleep(0.5 * (2**attempt) + random.uniform(0, 0.2))
                    continue
                raise error
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = FofaError(FofaErrorCode.TRANSPORT_ERROR, self._scrub(str(exc)), retryable=True)
                if attempt >= self.max_retries:
                    raise last_error from exc
                await asyncio.sleep(0.5 * (2**attempt) + random.uniform(0, 0.2))
        raise last_error or FofaError(FofaErrorCode.TRANSPORT_ERROR, "Hunter 请求失败")

    async def account(self) -> dict[str, Any]:
        """`/openApi/userInfo` never consumes credits; it also validates the key early."""
        data = await self._request("/openApi/userInfo", {})
        info = data.get("data")
        self.account_info = dict(info) if isinstance(info, dict) else {}
        remaining = parse_points(self.account_info.get("rest_free_point")) + parse_points(
            self.account_info.get("rest_equity_point")
        )
        self.remaining_points = remaining
        return self.account_info

    async def check_login(self) -> dict[str, Any]:
        return await self.account()

    async def _require_credits(self) -> None:
        """Refuse billed requests with an empty pool instead of letting Hunter error out."""
        if self.remaining_points is None:
            info = self.account_info if self.account_info is not None else await self.account()
            self.remaining_points = parse_points(info.get("rest_free_point")) + parse_points(
                info.get("rest_equity_point")
            )
        if self.remaining_points <= 0:
            raise FofaError(
                FofaErrorCode.QUOTA_EXHAUSTED,
                f"Hunter 可用积分已用尽（账号类型={self._account_type()}）；Hunter 按返回条数扣减积分，"
                "免费额度次日重置，权益积分需在鹰图个人中心补充。",
            )

    def _account_type(self) -> str:
        return str((self.account_info or {}).get("type") or "-")

    def _search_params(self, query: str, page: int, page_size: int, columns: Sequence[str]) -> dict[str, Any]:
        params: dict[str, Any] = {
            "search": base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii"),
            "page": page,
            "page_size": page_size,
            # 3 = web + non-web assets, so SSH/RDP/database banners are mapped as well.
            "is_web": 3,
        }
        if columns:
            params["fields"] = ",".join(columns)
        return params

    async def _search(self, query: str, page: int, page_size: int, columns: Sequence[str]) -> dict[str, Any]:
        """Run one search request, dropping fields the account cannot return.

        Hunter rejects a whole request when one requested column is not entitled
        (``无"body"字段权限``) and a rejected request costs no credits, so the denied column is
        retried without, recorded in `field_downgrades` and reported through the page metadata.
        """
        attempt_columns = list(columns)
        for _ in range(4):
            try:
                return await self._request("/openApi/search", self._search_params(query, page, page_size, attempt_columns))
            except FofaError as exc:
                denied = _PERMISSION_FIELD.search(exc.message)
                if exc.code is not FofaErrorCode.PERMISSION_DENIED or not denied:
                    raise
                column = denied.group(1)
                if column not in attempt_columns:
                    raise
                attempt_columns.remove(column)
                if column not in self.field_downgrades:
                    self.field_downgrades.append(column)
        raise FofaError(FofaErrorCode.PERMISSION_DENIED, "Hunter 当前账号无权导出所请求的字段")

    async def search_page(self, request: SearchRequest) -> SearchPage:
        cache_key = request_cache_key(self.name, request) if self.cache else None
        if cache_key is not None:
            hit = self.cache.get(cache_key)
            if hit is not None:
                return hit
        fields = hunter_request_fields(request.fields)
        errors = validate_query(request.query) + hunter_syntax_errors(request.query)
        if errors:
            # Rejected before the request: Hunter bills per returned record, so a syntax mistake
            # must never reach the API.
            raise FofaError(
                FofaErrorCode.INVALID_QUERY,
                "Hunter 查询语法无效：" + "; ".join(errors),
                alternatives=['web.title="登录" && port="443"', 'domain.suffix="example.com"', 'app.name="nginx"'],
            )
        await self._require_credits()
        page_size = legal_page_size(request.size)
        columns = native_columns(fields, full=request.full)
        data = await self._search(request.query, request.page, page_size, columns)
        payload = data.get("data") if isinstance(data.get("data"), dict) else {}
        rows = [item for item in (payload.get("arr") or []) if isinstance(item, dict)]
        records = [AssetRecord(values=map_record(row, fields)) for row in rows]
        if len(records) > request.size:
            records = records[: request.size]
        consumed = parse_points(payload.get("consume_quota"))
        remaining = parse_points(payload.get("rest_quota"))
        if remaining:
            self.remaining_points = remaining
        total = payload.get("total")
        page = SearchPage(
            records=records,
            fields=list(fields),
            total=total if isinstance(total, int) else None,
            next_cursor=None,
            page=request.page,
            consumed=consumed,
            query=request.query,
            metadata={
                "engine": "hunter",
                "matches": len(rows),
                "page_size": page_size,
                "max_window": RESULT_WINDOW,
                "points_spent": consumed,
                "points_left": remaining,
                "account_type": self._account_type(),
                "downgraded_fields": list(self.field_downgrades),
                "window_exhausted": request.page * page_size >= RESULT_WINDOW,
            },
        )
        if cache_key is not None:
            self.cache.put(cache_key, page)
        return page

    async def iter_search(self, request: SearchRequest) -> AsyncIterator[SearchPage]:
        """Walk Hunter's numbered pages, honoring the shared budgets, window and dedupe contract."""
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
            if raw_count < int(page.metadata.get("page_size") or 0):
                break
            if page.metadata.get("window_exhausted"):
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
        """Aggregate one host's services from an `ip=` search.

        Hunter has no host endpoint, so this spends credits like any other search (FOFA and
        Shodan host lookups are free) - which is why the agent routes host questions to them.
        """
        target = self._validate_target(host)
        fields = list(DEFAULT_OUTPUT_FIELDS) + (
            ["server", "org", "as_org", "isp", "os", "product", "version", "ssl_cn", "timestamp"] if detail else []
        )
        page = await self.search_page(
            SearchRequest(query=f'ip="{target}"', fields=fields, size=HOST_PROFILE_PAGE_SIZE, full=detail)
        )
        return normalize_host_profile([record.values for record in page.records], host=target)

    async def host_search(self, host: str) -> dict[str, Any]:
        return await self.host_profile(host)

    async def stats(self, query: str, fields: list[str], size: int = 5) -> dict[str, Any]:
        """Hunter's open API exposes no aggregation endpoint; FOFA and Shodan own this action."""
        raise FofaError(
            FofaErrorCode.UNSUPPORTED,
            "Hunter 开放 API 不提供聚合统计接口；请改用 FOFA 或 Shodan 的统计接口。",
            alternatives=["-e fofa -cq", "-e shodan -cq", "-e hunter -q"],
        )
