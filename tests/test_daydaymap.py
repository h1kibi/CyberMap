"""DayDayMap engine: FOFA-like syntax, base64 keyword, mapping, points-unknown accounting and cache.

The fixture is a trimmed real response captured with a live API key, so the mapper is tested
against the platform's actual field names and value types.
"""

import base64
import json
from pathlib import Path

import httpx
import pytest

from core.agent_profiles import DaydaymapProfile, agent_profile, daydaymap_fallback_plan
from core.cache import PageCache
from core.daydaymap import (
    DAYDAYMAP_FIELDS,
    DEFAULT_OUTPUT_FIELDS,
    MAX_PAGE_SIZE,
    DaydaymapClient,
    daydaymap_request_fields,
    encode_keyword,
    map_record,
    native_columns,
    normalize_host_profile,
    query_errors,
)
from core.engines import (
    AGENT_ENGINES,
    ENGINE_NAMES,
    default_fields,
    engine_label,
    favicon_query,
    normalize_engine_scope,
    supported_fields,
)
from core.models import FofaError, FofaErrorCode, IconDigest, SearchRequest

FIXTURE = Path(__file__).parent / "fixtures" / "daydaymap_search.json"
_TEST_KEY = "daydaymap-test-key"  # noqa: S105 - fake key for a mocked transport


def _payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _row() -> dict:
    return _payload()["data"]["list"][0]


def _ok(payload: dict | None = None) -> httpx.Response:
    return httpx.Response(200, json=payload or _payload())


def _client(handler, *, cache=None, key: str = _TEST_KEY, retries: int = 0) -> DaydaymapClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return DaydaymapClient(api_key=key, client=http, requests_per_second=1000, cache=cache, max_retries=retries)


def test_keyword_is_base64_encoded():
    assert base64.b64decode(encode_keyword('title="登录"')).decode() == 'title="登录"'


def test_query_errors_catch_local_mistakes_only():
    assert query_errors('title="登录" && country="中国"') == []
    assert query_errors('(domain="a.com" || cert="a.com") && port="443"') == []
    assert "为空" in " ".join(query_errors("   "))
    assert "引号未闭合" in " ".join(query_errors('title="登录'))
    assert "括号未配对" in " ".join(query_errors('(domain="a.com"'))
    shodan_style = query_errors("product:nginx country:CN")
    assert shodan_style and "field:value" in shodan_style[0]
    # `=`-based FOFA-style clauses must never be mistaken for Shodan syntax.
    assert query_errors('header="HTTP/1.1 200"') == []


def test_map_record_projects_the_unified_vocabulary():
    row = _row()
    values = map_record(row, list(DAYDAYMAP_FIELDS))
    url = row["url"]
    assert values["host"] == url.rstrip("/")
    assert values["ip"] == row["ip"]
    assert values["port"] == row["port"]
    # `service` is the application protocol; `protocol` is the transport.
    assert values["protocol"] == row["service"]
    assert values["base_protocol"] == row["protocol"]
    assert values["title"] == row["title"]
    assert values["server"] == row["server"]
    assert values["status_code"] == 200
    assert values["country"] == row["country"]
    assert values["country_code"] == row["country_code"]
    assert values["region"] == row["province"]
    assert values["city"] == row["city"]
    assert values["org"] == row["asn_org"]
    assert values["isp"] == row["isp"]
    assert values["asn"] == row["asn"]
    assert values["timestamp"] == row["time_stamp"]
    assert values["icp_reg_name"] == row["icp_reg_name"]
    assert values["tags"] == ", ".join(row["tags"])
    # `domain` is a hostname, so it lands in hostnames instead of corrupting domain statistics.
    assert row["domain"] in values["hostnames"]
    assert values["ssl_cn"] == row["ssl"]["alternative_name"][0].split(":", 1)[1]
    assert values["product"] == ", ".join(row["product"])
    assert values["url"] == row["url"]
    assert values["is_website"] is True
    assert "domain" not in values


def test_map_record_handles_non_web_rows():
    values = map_record(
        {
            "ip": "45.33.32.156",
            "port": 22,
            "service": "ssh",
            "protocol": "tcp",
            "url": None,
            "is_website": False,
            "server": None,
            "header": None,
            "product": ["Ubuntu", "OpenSSH"],
            "os": "Ubuntu Linux",
        },
        ["host", "protocol", "base_protocol", "status_code", "server", "product", "os"],
    )
    assert values["host"] == "45.33.32.156:22"
    assert values["base_protocol"] == "tcp"
    assert values["status_code"] is None
    assert values["server"] == ""
    assert values["product"] == "Ubuntu, OpenSSH"
    assert values["os"] == "Ubuntu Linux"


def test_native_columns_cover_every_mapped_field():
    assert native_columns(["ip", "port"]) == "ip,port"
    assert native_columns(["host", "status_code"]) == "url,ip,port,header"
    assert native_columns(["ssl_cn"]) == "ssl,cert"
    assert native_columns(["alive_status"]) == ""
    # Every unified field must be able to name its native dependencies, otherwise the column
    # would silently come back empty.
    for field in DAYDAYMAP_FIELDS:
        assert native_columns([field]), field


def test_request_fields_keep_only_what_the_engine_can_fill():
    assert daydaymap_request_fields(["ip", "port", "domain", "vulns"]) == ["ip", "port"]
    assert daydaymap_request_fields([]) == list(DEFAULT_OUTPUT_FIELDS)
    assert daydaymap_request_fields(["adomain", "icp", "version"]) == list(DEFAULT_OUTPUT_FIELDS)


def test_host_profile_aggregates_services():
    row = _row()
    records = [
        map_record(row, list(DEFAULT_OUTPUT_FIELDS)),
        map_record(
            {
                "ip": row["ip"],
                "port": 22,
                "service": "ssh",
                "protocol": "tcp",
                "product": ["OpenSSH"],
                "time_stamp": "2026-09-11T00:00:00.000000+08:00",
                "domain": None,
                "os": "Linux",
                "country": "中国",
                "country_code": "CN",
            },
            list(DEFAULT_OUTPUT_FIELDS) + ["timestamp", "os", "country", "country_code", "product"],
        ),
    ]
    profile = normalize_host_profile(records, host=row["ip"], cached=True)

    assert profile["host"] == row["ip"]
    assert profile["ip"] == row["ip"]
    assert profile["source"] == "daydaymap"
    assert profile["cached"] is True
    assert profile["vulns"] == []
    assert profile["update_time"] == "2026-09-11T00:00:00.000000+08:00"
    ports = {entry["port"]: entry for entry in profile["ports"]}
    assert set(ports) == {443, 22}
    assert ports[22]["products"] == [{"product": "OpenSSH", "name": "OpenSSH"}]
    assert ports[row["port"]]["protocol"] == row["service"]


@pytest.mark.asyncio
async def test_search_sends_the_documented_body_and_maps_the_page():
    calls: list[dict] = []

    def handler(request: httpx.Request):
        body = json.loads(request.content)
        calls.append(
            {
                "path": request.url.path,
                "key": request.headers.get("api-key"),
                "body": body,
            }
        )
        return _ok()

    client = _client(handler)
    request = SearchRequest(query='domain="daydaymap.com"', fields=["host", "ip", "port", "title"], size=2, page=1)
    page = await client.search_page(request)
    await client.aclose()

    assert calls[0]["path"] == "/api/v1/raymap/search/all"
    assert calls[0]["key"] == _TEST_KEY
    body = calls[0]["body"]
    assert body["page"] == 1 and body["page_size"] == 2
    assert base64.b64decode(body["keyword"]).decode() == 'domain="daydaymap.com"'
    # `fields` carries native columns only (never unified-only names like `host`), which the API
    # validates against its own enumeration.
    assert body["fields"] == "url,ip,port,title"
    assert page.fields == ["host", "ip", "port", "title"]
    assert page.total == _payload()["data"]["total"]
    assert page.consumed is None
    assert page.metadata["points"] == "unknown"
    assert page.metadata["page_size"] == 2
    assert len(page.records) == 2


@pytest.mark.asyncio
async def test_full_disables_the_field_projection():
    bodies: list[dict] = []

    def handler(request: httpx.Request):
        bodies.append(json.loads(request.content))
        return _ok()

    client = _client(handler)
    await client.search_page(SearchRequest(query='ip="1.1.1.1"', fields=["ip", "port"]))
    await client.search_page(SearchRequest(query='ip="1.1.1.1"', fields=["ip", "port"], full=True))
    await client.aclose()

    assert bodies[0]["fields"] == "ip,port"
    assert "fields" not in bodies[1]


@pytest.mark.asyncio
async def test_page_size_is_capped_at_the_documented_limit():
    seen: list[int] = []

    def handler(request: httpx.Request):
        seen.append(json.loads(request.content)["page_size"])
        return _ok()

    client = _client(handler)
    await client.search_page(SearchRequest(query='ip="1.1.1.1"', size=MAX_PAGE_SIZE))
    await client.aclose()
    assert seen == [MAX_PAGE_SIZE]


@pytest.mark.asyncio
async def test_error_codes_are_classified():
    cases = [
        ({"code": 2001, "msg": "请检查api-key是否正确", "data": {}}, FofaErrorCode.AUTH_FAILED),
        ({"code": 2002, "msg": "nosuchfield不支持搜索", "data": {}}, FofaErrorCode.INVALID_QUERY),
        ({"code": 2006, "msg": "语法不合法", "data": {}}, FofaErrorCode.INVALID_QUERY),
        ({"code": 470, "msg": "[language]必填项 ", "data": {}}, FofaErrorCode.INVALID_QUERY),
        ({"code": 2003, "msg": "积分不足，无法继续查询", "data": {}}, FofaErrorCode.QUOTA_EXHAUSTED),
    ]
    for payload, expected in cases:
        client = _client(lambda request, payload=payload: httpx.Response(200, json=payload))
        with pytest.raises(FofaError) as error:
            await client.search_page(SearchRequest(query='ip="1.1.1.1"'))
        await client.aclose()
        assert error.value.code is expected, (payload, error.value.code)


@pytest.mark.asyncio
async def test_rate_limit_is_retryable_and_bounded():
    def handler(request: httpx.Request):
        return httpx.Response(429, text="too many requests")

    client = _client(handler, retries=0)
    with pytest.raises(FofaError) as error:
        await client.search_page(SearchRequest(query='ip="1.1.1.1"'))
    await client.aclose()
    assert error.value.code is FofaErrorCode.RATE_LIMITED
    assert error.value.retryable is True


@pytest.mark.asyncio
async def test_missing_key_fails_before_any_request():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        return _ok()

    client = _client(handler, key="")
    with pytest.raises(FofaError) as error:
        await client.search_page(SearchRequest(query='ip="1.1.1.1"'))
    await client.aclose()
    assert calls == []
    assert error.value.code is FofaErrorCode.AUTH_FAILED
    assert any("DAYDAYMAP_API_KEY" in alternative for alternative in error.value.alternatives)


@pytest.mark.asyncio
async def test_invalid_syntax_is_rejected_locally():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        return _ok()

    client = _client(handler)
    with pytest.raises(FofaError) as error:
        await client.search_page(SearchRequest(query="product:nginx country:CN"))
    await client.aclose()
    assert calls == []
    assert error.value.code is FofaErrorCode.INVALID_QUERY


@pytest.mark.asyncio
async def test_cached_page_is_reused_and_marks_unknown_points(tmp_path):
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        return _ok()

    cache = PageCache(tmp_path / "cache.sqlite3")
    client = _client(handler, cache=cache)
    request = SearchRequest(query='domain="daydaymap.com"', fields=["ip", "port"], size=2)
    first = await client.search_page(request)
    second = await client.search_page(request)
    await client.aclose()

    assert len(calls) == 1
    assert first.metadata.get("cached") is not True
    assert second.metadata["cached"] is True
    # A hit spends nothing now, so the cache reports 0 (the original spend was never reported).
    assert second.consumed == 0
    assert second.records[0].values == first.records[0].values


@pytest.mark.asyncio
async def test_host_profile_builds_an_entity_query_and_is_cached(tmp_path):
    queries: list[str] = []

    def handler(request: httpx.Request):
        queries.append(base64.b64decode(json.loads(request.content)["keyword"]).decode())
        return _ok()

    cache = PageCache(tmp_path / "cache.sqlite3")
    client = _client(handler, cache=cache)
    by_ip = await client.host_profile("1.1.1.1")
    by_url = await client.host_profile("https://daydaymap.com/")
    await client.aclose()

    assert queries[0] == 'ip="1.1.1.1"'
    assert queries[1] == 'domain="daydaymap.com"'
    assert by_ip["cached"] is False
    assert by_ip["ip"] == _row()["ip"]
    assert isinstance(by_ip["ports"], list) and by_ip["ports"]
    assert by_url["host"] == "daydaymap.com"


@pytest.mark.asyncio
async def test_host_profile_rejects_unusable_targets():
    client = _client(lambda request: _ok())
    for target in ("", "http://", "bad/target?x=1"):
        with pytest.raises(FofaError) as error:
            await client.host_profile(target)
        assert error.value.code is FofaErrorCode.INVALID_QUERY
    await client.aclose()


@pytest.mark.asyncio
async def test_account_is_local_and_never_calls_the_api():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        return httpx.Response(500)

    client = _client(handler)
    account = await client.account()
    await client.aclose()

    assert calls == []
    assert account["engine"] == "daydaymap"
    assert account["api_key_configured"] is True
    assert account["balance"] is None
    assert account["page_size_limit"] == MAX_PAGE_SIZE


@pytest.mark.asyncio
async def test_stats_explain_the_missing_aggregation_api():
    client = _client(lambda request: _ok())
    with pytest.raises(FofaError) as error:
        await client.stats('domain="a.com"', ["country"], size=5)
    await client.aclose()
    assert error.value.code is FofaErrorCode.UNSUPPORTED


@pytest.mark.asyncio
async def test_iter_search_walks_pages_and_honors_budgets():
    pages: list[int] = []

    def handler(request: httpx.Request):
        page = json.loads(request.content)["page"]
        pages.append(page)
        payload = _payload()
        payload["data"]["page"] = page
        payload["data"]["page_size"] = 2
        payload["data"]["total"] = 5
        if page == 3:
            payload["data"]["list"] = payload["data"]["list"][:1]
        return httpx.Response(200, json=payload)

    client = _client(handler)
    seen_pages = []
    async for page in client.iter_search(
        SearchRequest(query='domain="daydaymap.com"', fields=["ip", "port"], size=2, max_pages=5, max_records=10)
    ):
        seen_pages.append(len(page.records))
    await client.aclose()

    # page 3 is short (1 < 2), so pagination stops there.
    assert pages == [1, 2, 3]
    assert seen_pages == [2, 2, 1]


def test_registry_makes_daydaymap_a_first_class_search_engine():
    assert "daydaymap" in ENGINE_NAMES
    assert "daydaymap" in AGENT_ENGINES
    assert engine_label("all") == "FOFA + Shodan + Hunter + DayDayMap"
    assert normalize_engine_scope("daydaymap") == ("daydaymap",)
    assert supported_fields("daydaymap") == DAYDAYMAP_FIELDS
    assert default_fields("daydaymap") == DEFAULT_OUTPUT_FIELDS


def test_favicon_reverse_lookup_is_rejected_with_alternatives():
    digest = IconDigest(md5="d41d8cd98f00b204e9800998ecf8427e", murmur3=42)
    with pytest.raises(FofaError) as error:
        favicon_query("daydaymap", digest)
    assert error.value.code is FofaErrorCode.UNSUPPORTED
    assert len(error.value.alternatives) == 2


def test_profile_routes_statistics_to_a_normal_search():
    profile = DaydaymapProfile()
    fallback = profile.align_action("stat_query", None, has_queries=False)
    assert fallback is not None and fallback.action == "daydaymap_search" and "统计" in fallback.note
    assert profile.align_action("host_query", "1.1.1.1", has_queries=False) is None
    assert profile.soft_stop(FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "empty")) is not None
    assert profile.soft_stop(FofaError(FofaErrorCode.AUTH_FAILED, "bad key")) is None


def test_profile_fields_fallback_and_hypothesis():
    profile = DaydaymapProfile()
    selection = profile.decide_fields(["ip", "port", "domain", "hostnames", "alive_status"])
    assert selection.allowed == ["ip", "port", "hostnames"]
    assert selection.denied == ["domain"]
    assert profile.request_fields([]) == list(DEFAULT_OUTPUT_FIELDS)
    assert profile.query_errors("product:nginx")
    assert profile.hypothesis_query(["a.com", "b.com"]) == '(domain="a.com" || domain="b.com")'
    assert profile.planning_domains(['domain="WWW.A.com" || cert="b.com"']) == {"a.com"}

    plan = profile.fallback_plan("查 example.com 的资产")
    assert plan["action"] == "daydaymap_search"
    assert plan["queries"][0]["query"] == 'domain="example.com"'
    assert daydaymap_fallback_plan("看 1.2.3.4")["queries"][0]["query"] == 'ip="1.2.3.4"'


def test_agent_profile_dispatches_to_daydaymap():
    class Client:
        name = "daydaymap"

    assert isinstance(agent_profile(Client()), DaydaymapProfile)
