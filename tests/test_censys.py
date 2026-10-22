"""Censys engine: Free-plan entity lookups, unified row mapping, credit accounting and cache.

The fixtures are real Platform API responses captured on a Free token, so the mapper is tested
against the documented shapes rather than against inventions.
"""

import json
from pathlib import Path

import httpx
import pytest

from core.agent_profiles import CensysProfile, agent_profile
from core.cache import CacheKey, PageCache
from core.censys import (
    CENSYS_FIELDS,
    DEFAULT_OUTPUT_FIELDS,
    HOST_LOOKUP_CREDITS,
    CensysClient,
    entity_ip,
    host_rows,
    normalize_host_profile,
    query_errors,
)
from core.engines import (
    AGENT_ENGINES,
    ENGINE_NAMES,
    default_fields,
    favicon_query,
    normalize_engine_scope,
    supported_fields,
)
from core.models import FofaError, FofaErrorCode, IconDigest, SearchRequest

FIXTURE = Path(__file__).parent / "fixtures" / "censys_host_1_1_1_1.json"
_TEST_TOKEN = "censys-test-token"  # noqa: S105 - fake token for a mocked transport
CREDITS = {"result": {"balance": 99, "resets_at": "2026-11-22T00:00:00Z"}}


def _resource() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["result"]["resource"]


def _client(handler, *, cache=None, token: str = _TEST_TOKEN) -> CensysClient:
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(transport=transport)
    return CensysClient(api_token=token, client=http, requests_per_second=1000, cache=cache, max_retries=0)


def test_entity_ip_accepts_only_entity_lookups():
    assert entity_ip("1.1.1.1") == "1.1.1.1"
    assert entity_ip('ip="1.1.1.1"') == "1.1.1.1"
    assert entity_ip("ip=1.1.1.1") == "1.1.1.1"
    assert entity_ip("host.ip=8.8.8.8") == "8.8.8.8"
    assert entity_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"
    for invalid in ("example.com", 'domain="example.com"', "port:443", "", "1.1.1.999"):
        assert entity_ip(invalid) is None


def test_query_errors_explain_the_free_plan_limit():
    assert query_errors('ip="1.1.1.1"') == []
    errors = query_errors('domain="example.com"')
    assert errors and "实体查询" in errors[0] and "FOFA" in errors[0]


def test_host_rows_expand_endpoints_and_map_http_detail():
    resource = _resource()
    rows = host_rows(resource)

    assert len(rows) == len(resource["services"])
    assert {row["ip"] for row in rows} == {"1.1.1.1"}
    web = next(row for row in rows if row["port"] == 80)
    assert web["host"] == "http://1.1.1.1"
    assert web["protocol"] == "http"
    assert web["base_protocol"] == "tcp"
    assert web["title"] == "301 Moved Permanently"
    assert web["status_code"] == 301
    assert web["server"] == "cloudflare"
    assert web["timestamp"] == "2026-10-22T00:40:41Z"
    assert web["country"] == "Australia"
    assert web["country_code"] == "AU"
    assert web["asn"] == "AS13335"
    assert web["isp"].startswith("CLOUDFLARENET")
    assert "waf" in web["product"]
    assert web["ssl_cn"] == ""
    # A DNS service has no HTTP endpoint but still owns a row with its own transport.
    dns = next(row for row in rows if row["port"] == 53)
    assert dns["host"] == "1.1.1.1:53"
    assert dns["protocol"] == "dns"
    assert {row["base_protocol"] for row in rows if row["port"] == 53} <= {"tcp", "udp"}


def test_hostnames_column_is_bounded():
    resource = _resource()
    rows = host_rows(resource)
    hostnames = rows[0]["hostnames"]
    assert hostnames
    assert len(hostnames.split(", ")) <= 10


def test_host_profile_keeps_the_rendered_shape():
    profile = normalize_host_profile(_resource())

    assert profile["host"] == profile["ip"] == "1.1.1.1"
    assert profile["country_name"] == "Australia"
    assert profile["country_code"] == "AU"
    assert profile["asn"] == "AS13335"
    assert profile["source"] == "censys"
    assert profile["vulns"] == []
    assert profile["update_time"] == "2026-10-22T11:36:37Z"
    ports = {entry["port"] for entry in profile["ports"]}
    assert {53, 80, 443} <= ports
    web = next(entry for entry in profile["ports"] if entry["port"] == 80)
    assert web["products"][0]["product"] == "cloudflare_load_balancer"


def test_tls_certificate_names_are_read_defensively():
    from core.censys import _certificate_cn

    assert _certificate_cn({"certificates": [{"subject_dn": "CN=example.com, O=Example"}]}) == "example.com"
    assert _certificate_cn({"certificates": [{"names": ["www.example.com"]}]}) == "www.example.com"
    assert _certificate_cn({}) == ""
    assert _certificate_cn({"certificates": ["garbage"]}) == ""


@pytest.mark.asyncio
async def test_search_page_costs_one_credit_and_reports_the_engine():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path == "/v3/accounts/users/credits":
            return httpx.Response(200, json=CREDITS)
        return httpx.Response(200, json={"result": {"resource": _resource()}})

    client = _client(handler)
    page = await client.search_page(SearchRequest(query='ip="1.1.1.1"', fields=["host", "ip", "port", "title"]))
    await client.aclose()

    assert calls == ["/v3/accounts/users/credits", "/v3/global/asset/host/1.1.1.1"]
    assert page.consumed == HOST_LOOKUP_CREDITS == 1
    assert page.fields == ["host", "ip", "port", "title"]
    assert len(page.records) == len(_resource()["services"])
    assert page.metadata["engine"] == "censys"
    assert page.metadata["cached"] is False
    assert {tuple(record.values) for record in page.records} == {("host", "ip", "port", "title")}


@pytest.mark.asyncio
async def test_unknown_fields_are_dropped_or_rejected_clearly():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path == "/v3/accounts/users/credits":
            return httpx.Response(200, json=CREDITS)
        return httpx.Response(200, json={"result": {"resource": _resource()}})

    client = _client(handler)
    page = await client.search_page(SearchRequest(query='ip="1.1.1.1"', fields=["ip", "port", "icp"]))
    assert page.fields == ["ip", "port"]

    with pytest.raises(FofaError) as error:
        await client.search_page(SearchRequest(query='ip="1.1.1.1"', fields=["icp"]))
    await client.aclose()

    assert error.value.code is FofaErrorCode.INVALID_QUERY
    assert "icp" in error.value.message


@pytest.mark.asyncio
async def test_search_page_rejects_list_queries_before_any_request():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        return httpx.Response(200, json=CREDITS)

    client = _client(handler)
    with pytest.raises(FofaError) as error:
        await client.search_page(SearchRequest(query='domain="example.com"'))
    await client.aclose()

    assert calls == []
    assert error.value.code is FofaErrorCode.UNSUPPORTED
    assert any("-hq" in alternative for alternative in error.value.alternatives)


@pytest.mark.asyncio
async def test_search_is_not_gated_when_credits_are_available():
    """The Free-plan 403 is an entitlement answer, not a quota answer: surface it as UNSUPPORTED."""
    detail = "This endpoint requires an organization ID for API access. Free users can only access this endpoint through the Platform UI."

    def handler(request: httpx.Request):
        if request.url.path == "/v3/accounts/users/credits":
            return httpx.Response(200, json=CREDITS)
        return httpx.Response(403, json={"title": "Forbidden", "status": 403, "detail": detail})

    client = _client(handler)
    with pytest.raises(FofaError) as error:
        await client.search_page(SearchRequest(query='ip="1.1.1.1"'))
    await client.aclose()

    assert error.value.code is FofaErrorCode.UNSUPPORTED
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_zero_balance_stops_before_the_paid_lookup():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"result": {"balance": 0, "resets_at": "2026-11-22T00:00:00Z"}})

    client = _client(handler)
    with pytest.raises(FofaError) as error:
        await client.search_page(SearchRequest(query='ip="1.1.1.1"'))
    await client.aclose()

    assert calls == ["/v3/accounts/users/credits"]
    assert error.value.code is FofaErrorCode.QUOTA_EXHAUSTED
    assert "0" in error.value.message


@pytest.mark.asyncio
async def test_invalid_token_fails_typed_and_leaks_nothing():
    def handler(request: httpx.Request):
        return httpx.Response(401, json={"error": {"code": 401, "message": "Access credentials are invalid"}})

    secret = "censys-super-secret"  # noqa: S105 - fake token for a mocked transport
    client = _client(handler, token=secret)
    with pytest.raises(FofaError) as error:
        await client.account()
    await client.aclose()

    assert error.value.code is FofaErrorCode.AUTH_FAILED
    assert secret not in error.value.message


@pytest.mark.asyncio
async def test_missing_token_fails_before_any_request():
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        return httpx.Response(200, json=CREDITS)

    client = _client(handler, token="")
    with pytest.raises(FofaError) as error:
        await client.account()
    await client.aclose()

    assert calls == []
    assert error.value.code is FofaErrorCode.AUTH_FAILED
    assert any("CENSYS_API_TOKEN" in alternative for alternative in error.value.alternatives)


@pytest.mark.asyncio
async def test_account_reports_balance_and_reset():
    def handler(request: httpx.Request):
        assert request.url.path == "/v3/accounts/users/credits"
        return httpx.Response(200, json=CREDITS)

    client = _client(handler)
    account = await client.account()
    await client.aclose()

    assert account == {
        "engine": "censys",
        "plan": "free",
        "balance": 99,
        "resets_at": "2026-11-22T00:00:00Z",
        "monthly_credits": 100,
    }


@pytest.mark.asyncio
async def test_host_profile_is_cached_and_marked(tmp_path):
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path == "/v3/accounts/users/credits":
            return httpx.Response(200, json=CREDITS)
        return httpx.Response(200, json={"result": {"resource": _resource()}})

    cache = PageCache(tmp_path / "cache.sqlite3")
    client = _client(handler, cache=cache)
    first = await client.host_profile("1.1.1.1")
    second = await client.host_profile('ip="1.1.1.1"')
    await client.aclose()

    assert calls.count("/v3/global/asset/host/1.1.1.1") == 1
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["cached_at"] > 0
    assert second["ip"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_search_page_reuses_the_cached_host(tmp_path):
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path == "/v3/accounts/users/credits":
            return httpx.Response(200, json=CREDITS)
        return httpx.Response(200, json={"result": {"resource": _resource()}})

    cache = PageCache(tmp_path / "cache.sqlite3")
    client = _client(handler, cache=cache)
    request = SearchRequest(query='ip="1.1.1.1"', fields=["ip", "port"])
    first = await client.search_page(request)
    second = await client.search_page(request)
    await client.aclose()

    assert calls.count("/v3/global/asset/host/1.1.1.1") == 1
    assert first.consumed == 1
    assert second.consumed == 0
    assert second.metadata["cached"] is True


@pytest.mark.asyncio
async def test_stats_explain_the_missing_aggregate_api():
    client = _client(lambda request: httpx.Response(200, json=CREDITS))
    with pytest.raises(FofaError) as error:
        await client.stats('domain="example.com"', ["country"], size=5)
    await client.aclose()

    assert error.value.code is FofaErrorCode.UNSUPPORTED
    assert "聚合" in error.value.message


def test_registry_treats_censys_as_a_standalone_engine():
    assert "censys" in ENGINE_NAMES
    assert "censys" not in AGENT_ENGINES
    assert normalize_engine_scope("all") == AGENT_ENGINES
    assert normalize_engine_scope("censys") == ("censys",)
    assert supported_fields("censys") == CENSYS_FIELDS
    assert default_fields("censys") == DEFAULT_OUTPUT_FIELDS


def test_favicon_reverse_lookup_is_rejected_with_alternatives():
    digest = IconDigest(md5="d41d8cd98f00b204e9800998ecf8427e", murmur3=42)
    with pytest.raises(FofaError) as error:
        favicon_query("censys", digest)
    assert error.value.code is FofaErrorCode.UNSUPPORTED
    assert len(error.value.alternatives) == 2


def test_profile_routes_stats_and_icons_to_host_profiles():
    profile = CensysProfile()
    stats = profile.align_action("stat_query", None, has_queries=False)
    icon = profile.align_action("icon_query", "https://example.com/favicon.ico", has_queries=False)

    assert stats is not None and stats.action == "host_query" and "聚合" in stats.note
    assert icon is not None and icon.action == "host_query" and "图标" in icon.note
    assert profile.align_action("host_query", "1.1.1.1", has_queries=False) is None
    assert profile.soft_stop(FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "empty")) is not None
    assert profile.soft_stop(FofaError(FofaErrorCode.AUTH_FAILED, "bad token")) is None


def test_profile_fields_and_fallback_plan():
    profile = CensysProfile()
    selection = profile.decide_fields(["ip", "port", "icp", "alive_status"])
    assert selection.allowed == ["ip", "port"]
    assert selection.denied == ["icp"]
    assert profile.request_fields([]) == list(DEFAULT_OUTPUT_FIELDS)
    assert profile.query_errors('domain="example.com"')

    plan = profile.fallback_plan("看一下 1.2.3.4 暴露了哪些服务")
    assert plan["action"] == "host_query"
    assert plan["target"] == "1.2.3.4"
    assert plan["queries"][0]["query"] == 'ip="1.2.3.4"'

    domain_plan = profile.fallback_plan("查一下 example.com")
    assert domain_plan["queries"] == []
    assert domain_plan["target"] == ""


def test_agent_profile_dispatches_to_censys():
    class Client:
        name = "censys"

    assert isinstance(agent_profile(Client()), CensysProfile)


def test_cache_key_participates_for_host_lookups(tmp_path):
    cache = PageCache(tmp_path / "cache.sqlite3")
    key = CacheKey("censys", "host:1.1.1.1", 0, 0, "profile")
    assert cache.get(key) is None
