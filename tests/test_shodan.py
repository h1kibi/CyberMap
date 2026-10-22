import io
from pathlib import Path

import httpx
import pytest
from rich.console import Console

import cybermap
from config import load_config
from core.agent import AgentAction, AgentRun, AgentState, AssetAgent, _derive_website_candidates
from core.agent_profiles import agent_profile
from core.models import AssetRecord, FofaError, FofaErrorCode, SearchPage, SearchRequest, redact_secrets
from core.shodan import (
    DEFAULT_OUTPUT_FIELDS,
    SEARCH_PAGE_SIZE,
    SHODAN_FIELDS,
    ShodanClient,
    map_match,
    normalize_host_profile,
    resolve_facets,
    shodan_request_fields,
)
from providers.base import ModelResult
from utils import cli_ui

MATCH = {
    "ip_str": "96.93.212.27",
    "port": 443,
    "transport": "tcp",
    "hostnames": ["three.webapplify.net"],
    "domains": ["webapplify.net"],
    "org": "Comcast Business",
    "isp": "Comcast Business",
    "asn": "AS7922",
    "product": "nginx",
    "version": "1.4.2",
    "timestamp": "2021-01-25T21:33:49.154513",
    "location": {"country_name": "United States", "country_code": "US", "city": "Denver", "region_code": "CO"},
    "http": {"title": "400 Bad Request", "server": "nginx/1.4.2", "status": 400},
    "ssl": {"cert": {"subject": {"CN": "webapplify.net"}}},
    "vulns": {"CVE-2021-1234": {}, "CVE-2020-0001": {}},
    "data": "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n",
    "_shodan": {"module": "https"},
}

FIELDS = ["host", "protocol", "ip", "port", "title", "domain", "country"]


def client_for(handler, **kwargs) -> ShodanClient:
    return ShodanClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def plan(action: str = "shodan_search", **overrides) -> dict:
    payload = {
        "action": action,
        "target": "",
        "queries": [{"query": "product:nginx", "purpose": "精确产品指纹", "strategy": "precision"}],
        "stats_fields": [],
        "fields": ["host", "ip", "port", "protocol", "title", "domain", "country"],
        "scan": {"recommended": False, "reason": "未明确要求主动扫描。", "template_ids": [], "severities": []},
    }
    payload.update(overrides)
    return payload


class PlanRouter:
    """Minimal provider router that returns one plan and a summary."""

    def __init__(self, payload: dict | None = None) -> None:
        self.events: list = []
        self.payload = payload or plan()

    async def generate(self, task: str, **_kwargs):
        if task == "planner":
            return ModelResult(text="plan", structured=dict(self.payload), model="m", provider="p")
        return ModelResult(text="## 结论\nok", model="m", provider="p")


def search_handler(payload, seen=None, api_info=None):
    def handler(request: httpx.Request):
        if seen is not None:
            seen.append(request)
        if request.url.path == "/api-info":
            return httpx.Response(200, json=api_info or {"plan": "dev", "query_credits": 100})
        return httpx.Response(200, json=payload) if not callable(payload) else payload(request)

    return handler


def test_match_maps_into_the_shared_asset_field_vocabulary():
    row = map_match(
        MATCH,
        ["host", "ip", "port", "protocol", "title", "domain", "hostnames", "server", "status_code", "ssl_cn", "vulns"],
    )

    assert row["host"] == "https://three.webapplify.net:443"
    assert row["protocol"] == "https"
    assert row["ip"] == "96.93.212.27"
    assert row["port"] == 443
    assert row["title"] == "400 Bad Request"
    assert row["domain"] == "webapplify.net"
    assert row["server"] == "nginx/1.4.2"
    assert row["status_code"] == 400
    assert row["ssl_cn"] == "webapplify.net"
    assert row["vulns"] == "CVE-2020-0001, CVE-2021-1234"


def test_only_requested_fields_are_extracted_so_banners_are_not_read_by_default():
    assert map_match(MATCH, ["ip"]) == {"ip": "96.93.212.27"}


def test_domain_and_title_never_come_from_undocumented_fields():
    banner = {"ip_str": "1.1.1.1", "port": 80, "hostnames": ["www.example.com"], "title": "legacy top-level title"}

    assert map_match(banner, ["domain", "hostnames", "title"]) == {
        "domain": "",
        "hostnames": "www.example.com",
        "title": "",
    }
    assert map_match({**banner, "domains": ["example.com"], "http": {"title": "real"}}, ["domain", "title"]) == {
        "domain": "example.com",
        "title": "real",
    }


def test_non_web_services_keep_a_bare_host_port_target():
    ssh = {"ip_str": "10.0.0.5", "port": 22, "transport": "tcp", "_shodan": {"module": "ssh"}}
    row = map_match(ssh, ["host", "protocol", "port"])

    assert row["host"] == "10.0.0.5:22"
    assert row["protocol"] == "ssh"


@pytest.mark.asyncio
async def test_requesting_banner_switches_off_minification():
    """`banner` is advertised as returnable, so minify must not silently truncate it."""
    seen = []
    async with client_for(search_handler({"matches": [], "total": 0}, seen)) as client:
        await client.search_page(SearchRequest(query="nginx", fields=["host", "banner"]))
        await client.search_page(SearchRequest(query="nginx", fields=["host", "title"]))
        await client.search_page(SearchRequest(query="nginx", fields=["host"], full=True))

    flags = [request.url.params["minify"] for request in seen if request.url.path == "/shodan/host/search"]
    assert flags == ["false", "true", "false"]


@pytest.mark.asyncio
async def test_search_page_uses_documented_parameters_and_flags_full_banner_mode():
    seen = []
    payload = {"matches": [MATCH], "total": 23047224}
    async with client_for(search_handler(payload, seen)) as client:
        page = await client.search_page(SearchRequest(query="product:nginx", fields=FIELDS))
        await client.search_page(SearchRequest(query="product:nginx", fields=FIELDS, full=True))

    assert [request.url.path for request in seen] == ["/api-info", "/shodan/host/search", "/shodan/host/search"]
    searches = [request for request in seen if request.url.path == "/shodan/host/search"]
    assert searches[0].url.params["query"] == "product:nginx"
    assert searches[0].url.params["page"] == "1"
    assert searches[0].url.params["minify"] == "true"
    assert searches[1].url.params["minify"] == "false"
    assert searches[0].url.params["key"] == "test-key"
    assert page.total == 23047224
    assert page.fields == FIELDS
    assert page.records[0].values["host"] == "https://three.webapplify.net:443"
    assert page.metadata["engine"] == "shodan"
    assert page.metadata["matches"] == 1


@pytest.mark.asyncio
async def test_first_page_without_filters_is_free_and_spends_no_plan_lookup():
    seen = []
    async with client_for(search_handler({"matches": [], "total": 0}, seen)) as client:
        page = await client.search_page(SearchRequest(query="nginx", fields=FIELDS))

    assert [request.url.path for request in seen] == ["/shodan/host/search"]
    assert page.consumed == 0


@pytest.mark.asyncio
async def test_filtered_and_paginated_requests_are_billed_once_each():
    seen = []
    async with client_for(search_handler({"matches": [], "total": 0}, seen)) as client:
        assert (await client.search_page(SearchRequest(query="nginx country:DE", fields=FIELDS))).consumed == 1
        assert (await client.search_page(SearchRequest(query="nginx", fields=FIELDS, page=3))).consumed == 1


@pytest.mark.asyncio
async def test_exhausted_credits_stop_billed_requests_before_they_reach_the_search_api():
    seen: list[str] = []

    def handler(request: httpx.Request):
        seen.append(request.url.path)
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 0, "usage_limits": {"query_credits": -1}})
        return httpx.Response(200, json={"matches": [], "total": 0})

    async with client_for(handler) as client:
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query="product:nginx", fields=FIELDS))

    assert captured.value.code is FofaErrorCode.QUOTA_EXHAUSTED
    assert "dev" in captured.value.message
    assert seen == ["/api-info"]

    free_seen: list[str] = []

    def free_handler(request: httpx.Request):
        free_seen.append(request.url.path)
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 0})
        return httpx.Response(200, json={"matches": [MATCH], "total": 1})

    async with client_for(free_handler) as client:
        free_page = await client.search_page(SearchRequest(query="nginx", fields=FIELDS))

    assert free_page.consumed == 0
    assert free_seen == ["/shodan/host/search"]


@pytest.mark.asyncio
async def test_unknown_fields_are_rejected_before_any_network_call():
    async with client_for(lambda _: pytest.fail("an invalid field must not reach the network")) as client:
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query="nginx", fields=["cert"]))

    assert captured.value.code is FofaErrorCode.INVALID_QUERY
    assert "host" in captured.value.alternatives


def test_local_only_columns_are_dropped_and_defaults_apply_for_empty_requests():
    assert shodan_request_fields(["alive_status", "ip"]) == ["ip"]
    assert shodan_request_fields([]) == ["host", "ip", "port", "protocol", "title", "domain", "country"]


@pytest.mark.asyncio
async def test_iteration_stops_on_the_last_short_page_without_extra_requests():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"matches": [MATCH, MATCH], "total": 200})

    async with client_for(handler) as client:
        pages = [page async for page in client.iter_search(SearchRequest(query="nginx", fields=FIELDS, max_pages=5))]

    assert len(pages) == 1
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_iteration_walks_numbered_pages_and_honors_the_record_budget():
    requested_pages: list[str] = []

    def handler(request: httpx.Request):
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 100})
        page = int(request.url.params["page"])
        requested_pages.append(request.url.params["page"])
        matches = [MATCH] * (SEARCH_PAGE_SIZE if page == 1 else 5)
        return httpx.Response(200, json={"matches": matches, "total": 105})

    async with client_for(handler) as client:
        collected = [
            record
            async for page in client.iter_search(SearchRequest(query="nginx", fields=FIELDS, max_pages=5))
            for record in page.records
        ]
        budgeted = [
            record
            async for page in client.iter_search(
                SearchRequest(query="nginx", fields=FIELDS, max_pages=5, max_records=3)
            )
            for record in page.records
        ]

    assert requested_pages == ["1", "2", "1"]
    assert len(collected) == SEARCH_PAGE_SIZE + 5
    assert len(budgeted) == 3


@pytest.mark.asyncio
async def test_iteration_deduplicates_explicit_keys():
    def handler(request: httpx.Request):
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 100})
        page = int(request.url.params["page"])
        matches = [MATCH] * SEARCH_PAGE_SIZE if page == 1 else [MATCH, {"ip_str": "1.1.1.1", "port": 80}]
        return httpx.Response(200, json={"matches": matches, "total": SEARCH_PAGE_SIZE + 1})

    async with client_for(handler) as client:
        hosts = [
            record.values["ip"]
            async for page in client.iter_search(
                SearchRequest(query="nginx", fields=FIELDS, max_pages=5, dedupe_by=["ip"])
            )
            for record in page.records
        ]

    assert hosts == ["96.93.212.27", "1.1.1.1"]


@pytest.mark.asyncio
async def test_authentication_permission_and_quota_errors_are_not_empty_results():
    cases = [
        (401, {"error": "Invalid API key"}, FofaErrorCode.AUTH_FAILED),
        (403, {"error": "Access denied"}, FofaErrorCode.PERMISSION_DENIED),
        (402, {"error": "You are out of query credits"}, FofaErrorCode.QUOTA_EXHAUSTED),
    ]
    for status, payload, expected in cases:
        async with client_for(lambda _request, status=status, payload=payload: httpx.Response(status, json=payload)) as client:
            with pytest.raises(FofaError) as captured:
                await client.search_page(SearchRequest(query="nginx", fields=FIELDS))
            assert captured.value.code is expected


@pytest.mark.asyncio
async def test_quota_text_outranks_an_unauthorized_status():
    """An exhausted balance often arrives as 401/402 with the reason in the body."""
    payload = {"error": "You are out of query credits for this month"}
    async with client_for(lambda _request: httpx.Response(401, json=payload)) as client:
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query="nginx", fields=FIELDS))

    assert captured.value.code is FofaErrorCode.QUOTA_EXHAUSTED
    assert captured.value.status_code == 401


@pytest.mark.asyncio
async def test_html_error_pages_are_classified_by_status_code():
    """Shodan answers 401/403 with an HTML page, not JSON."""
    html = (
        "<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1>"
        "This server could not verify that you are authorized to access the document you requested.</body></html>"
    )
    async with client_for(lambda _request: httpx.Response(401, text=html, headers={"content-type": "text/html"})) as client:
        with pytest.raises(FofaError) as captured:
            await client.account()

    assert captured.value.code is FofaErrorCode.AUTH_FAILED
    assert captured.value.status_code == 401


@pytest.mark.asyncio
async def test_rate_limited_response_is_retried_within_the_same_request():
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"error": "Too many requests"})
        return httpx.Response(200, json={"matches": [MATCH], "total": 1})

    async with client_for(handler) as client:
        page = await client.search_page(SearchRequest(query="nginx", fields=FIELDS))

    assert len(calls) == 2
    assert len(page.records) == 1


@pytest.mark.asyncio
async def test_missing_credentials_fail_before_any_request():
    async with ShodanClient(
        api_key="", client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no key, no request")))
    ) as client:
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query="nginx", fields=FIELDS))

    assert captured.value.code is FofaErrorCode.AUTH_FAILED
    assert captured.value.alternatives


def test_host_profile_normalizes_ports_for_the_existing_renderer():
    profile = normalize_host_profile(
        {
            "ip_str": "8.8.8.8",
            "country_name": "United States",
            "org": "Google",
            "asn": "AS15169",
            "last_update": "2021-01-22T08:49:35.190817",
            "hostnames": ["dns.google"],
            "ports": [53, 443],
            "data": [
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.4.2", "timestamp": "2021-01-22T08:49:35.190817"},
                {"port": 53, "transport": "udp", "timestamp": "2021-01-22T08:49:35.190817"},
            ],
        }
    )

    assert profile["host"] == "8.8.8.8"
    assert profile["country_name"] == "United States"
    assert [item["port"] for item in profile["ports"]] == [53, 443]
    assert profile["ports"][0]["protocol"] == "udp"
    assert profile["ports"][1]["products"] == [{"product": "nginx 1.4.2", "name": "nginx 1.4.2"}]
    assert profile["source"] == "shodan"

    stream = io.StringIO()
    original = cli_ui.console
    cli_ui.console = Console(file=stream, width=120, color_system=None)
    try:
        cli_ui.render_host(profile)
    finally:
        cli_ui.console = original
    assert "nginx 1.4.2" in stream.getvalue()


def test_host_entries_without_banners_still_appear_as_open_ports():
    profile = normalize_host_profile({"ip_str": "1.1.1.1", "ports": [80, 8080], "data": []})

    assert [item["port"] for item in profile["ports"]] == [80, 8080]
    assert profile["ports"][0]["products"] == []


@pytest.mark.asyncio
async def test_host_profile_requests_full_banners_by_default():
    """`detail` defaults to true on every CLI/MCP/REST host path, so minify must stay off."""
    seen = []

    async with client_for(search_handler({"ip_str": "8.8.8.8", "ports": []}, seen)) as client:
        await client.host_profile("8.8.8.8")

    assert seen[0].url.params["minify"] == "false"


@pytest.mark.asyncio
async def test_iteration_stops_when_page_one_holds_the_whole_result_set():
    """A full first page whose total is that page must not trigger another (billed) request."""
    seen = []

    def handler(request: httpx.Request):
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 100})
        seen.append(request.url.params["page"])
        return httpx.Response(200, json={"matches": [MATCH] * SEARCH_PAGE_SIZE, "total": SEARCH_PAGE_SIZE})

    async with client_for(handler) as client:
        pages = [
            page
            async for page in client.iter_search(
                SearchRequest(query='http.title:"login"', fields=FIELDS, size=SEARCH_PAGE_SIZE, max_pages=5)
            )
        ]

    assert seen == ["1"]
    assert sum(page.consumed or 0 for page in pages) == 1


@pytest.mark.asyncio
async def test_agent_failure_panel_names_the_active_engines_credential():
    """A Shodan run must never tell the user to check the FOFA key."""
    stream = io.StringIO()
    original = cli_ui.console
    cli_ui.console = Console(file=stream, width=120, color_system=None)
    run = AgentRun(intent="收集资产", engine="shodan", action=AgentAction.SHODAN_SEARCH, state=AgentState.FAILED)
    run.error = {"code": "auth_failed", "message": "Invalid API key", "status_code": 401}
    try:
        cli_ui.render_agent(run)
    finally:
        cli_ui.console = original

    output = stream.getvalue()
    assert "SHODAN_API_KEY" in output
    assert "FOFA_API_KEY" not in output


@pytest.mark.asyncio
async def test_host_profile_uses_the_minify_flag_and_the_documented_path():
    seen = []

    async with client_for(search_handler({"ip_str": "8.8.8.8", "ports": []}, seen)) as client:
        await client.host_profile("8.8.8.8", detail=False)

    assert seen[0].url.path == "/shodan/host/8.8.8.8"
    assert seen[0].url.params["minify"] == "true"


@pytest.mark.asyncio
async def test_host_profile_rejects_path_or_credential_injection_before_network():
    async with client_for(lambda _: pytest.fail("an invalid target must not reach the network")) as client:
        for target in ("8.8.8.8/../../etc/passwd", "user@host", "host?x=1", "a b c", ""):
            with pytest.raises(FofaError) as captured:
                await client.host_profile(target)
            assert captured.value.code is FofaErrorCode.INVALID_QUERY


@pytest.mark.asyncio
async def test_stats_use_the_free_count_endpoint_and_map_facets_to_aggs():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "matches": [],
                "total": 19590274,
                "facets": {"org": [{"count": 3012386, "value": "Amazon.com"}], "os": [{"count": 601923, "value": "Ubuntu"}]},
            },
        )

    async with client_for(handler) as client:
        data = await client.stats("port:22", ["org", "os"], size=5)

    assert [request.url.path for request in seen] == ["/shodan/host/count"]
    assert seen[0].url.params["facets"] == "org:5,os:5"
    assert data["size"] == 19590274
    assert data["consumed"] == 0
    assert data["aggs"]["org"] == [{"name": "Amazon.com", "count": 3012386}]
    assert data["source"] == "shodan"


def test_facet_aliases_cover_unified_names_and_allow_native_tokens():
    assert resolve_facets(["title", "http.waf"], 3) == "http.title:3,http.waf:3"
    assert resolve_facets(["ssl_cn"], 10) == "ssl.cert.subject.cn:10"

    with pytest.raises(FofaError) as empty:
        resolve_facets([], 5)
    assert empty.value.code is FofaErrorCode.INVALID_QUERY

    with pytest.raises(FofaError) as malformed:
        resolve_facets(["bad facet()"], 5)
    assert malformed.value.code is FofaErrorCode.INVALID_QUERY
    assert "country" in malformed.value.alternatives


def test_engine_selection_reads_configuration_and_environment(tmp_path: Path):
    config_path = tmp_path / "settings.yaml"
    config_path.write_text("search:\n  engine: shodan\n", encoding="utf-8")

    config = load_config(config_path, environ={"SHODAN_API_KEY": "shodan-secret", "APPDATA": str(tmp_path)})
    assert config.search.engine == "shodan"
    assert config.shodan.api_key == "shodan-secret"
    assert config.fofa.api_key == ""

    default = load_config(tmp_path / "missing.yaml", environ={"APPDATA": str(tmp_path)})
    assert default.search.engine == "fofa"
    assert default.shodan.base_url == "https://api.shodan.io"


def test_shodan_account_panel_reports_plan_credits_and_billing_rules():
    stream = io.StringIO()
    original = cli_ui.console
    cli_ui.console = Console(file=stream, width=120, color_system=None)
    try:
        cli_ui.render_shodan_account(
            {"plan": "dev", "query_credits": 100, "scan_credits": 0, "usage_limits": {"query_credits": -1}, "monitored_ips": 5}
        )
    finally:
        cli_ui.console = original

    output = stream.getvalue()
    assert "dev" in output
    assert "不限" in output
    assert "query_credits" not in output
    assert "/shodan/host/count" in output


@pytest.mark.asyncio
async def test_cli_engine_option_routes_account_through_the_shodan_client(monkeypatch):
    captured = {}

    class FakeShodan:
        name = "shodan"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def account(self):
            return {"plan": "dev", "query_credits": 100, "usage_limits": {"query_credits": -1}}

    monkeypatch.setattr(cybermap, "create_engine", lambda name=None: captured.update(engine=name) or FakeShodan())
    monkeypatch.setattr(cybermap, "render_shodan_account", lambda data: captured.update(rendered=data))

    code = await cybermap._main_async(cmd="account", engine="shodan", output_format="table")

    assert code == 0
    assert captured["engine"] == "shodan"
    assert captured["rendered"]["plan"] == "dev"


def test_shodan_profile_teaches_shodan_syntax_and_rejects_fofa_syntax():
    profile = agent_profile(type("C", (), {"name": "shodan"})())
    planner = profile.planner_system()
    reflector = profile.reflector_system()

    assert profile.search_action == "shodan_search"
    assert profile.plan_schema()["properties"]["action"]["enum"][0] == "shodan_search"
    assert "filter:value" in planner
    assert "Never emit FOFA syntax" in planner
    assert "never use && or ||" in planner
    assert "space-separated AND clauses" in reflector

    assert profile.query_errors('app="nginx" && country="CN"') == [
        "Shodan 不支持 app=/domain=/host=/body= 等赋值写法或 &&/|| 运算符，请改用 filter:value"
    ]
    assert profile.query_errors("product:nginx country:CN") == []
    assert profile.query_errors('http.title:"login: admin"') == []
    # Documented filters that are not in the planner catalogue must stay usable, and
    # unknown filters stay the API's business: rejecting them would abort a valid run.
    assert profile.query_errors("tag:ics before:2024-01-01") == []
    assert profile.query_errors("geo:37.7,-122.4,50") == []


def test_shodan_profile_fields_are_limited_to_the_shodan_catalogue():
    profile = agent_profile(type("C", (), {"name": "shodan"})())

    suggested = profile.suggest_fields(["org"], intent="收集目标的组织归属与漏洞")
    assert suggested == list(dict.fromkeys([*DEFAULT_OUTPUT_FIELDS, "org", "isp", "asn", "vulns"]))
    assert set(suggested) <= set(SHODAN_FIELDS)

    selection = profile.decide_fields(["host", "cert", "vulns", "alive_status"])
    assert selection.allowed == ["host", "vulns"]
    assert selection.denied == ["cert"]
    detail, data = profile.denied_fields_step(selection.denied, selection.allowed)
    assert "Shodan" in detail
    assert data == {"denied": ["cert"], "fields": ["host", "vulns"]}
    assert profile.request_fields(["cert"]) == list(DEFAULT_OUTPUT_FIELDS)


def test_shodan_profile_fallback_and_credit_policy():
    profile = agent_profile(type("C", (), {"name": "shodan"})())

    domain_plan = profile.fallback_plan("收集 example.edu 的子域名网站")
    assert [item["query"] for item in domain_plan["queries"]] == ["hostname:example.edu", "domain:example.edu"]
    assert all("=" not in item["query"] for item in domain_plan["queries"])
    ip_plan = profile.fallback_plan("分析 8.8.8.8 的开放端口")
    assert ip_plan["queries"][0]["query"] == "ip:8.8.8.8"
    assert profile.planning_domains(["hostname:a.example.edu,b.example.edu domain:c.example.org"]) == {
        "a.example.edu",
        "b.example.edu",
        "c.example.org",
    }
    assert profile.align_action("host_query", "8.8.8.8", has_queries=False) is None
    assert profile.soft_stop(FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "out of credits"))
    assert profile.soft_stop(FofaError(FofaErrorCode.AUTH_FAILED, "bad key")) is None
    # Quota exhaustion is the one FOFA failure that keeps already-fetched pages (the user asked
    # for partial results to survive a spent quota); every other FOFA error stays fatal.
    fofa_quota_note = agent_profile(None).soft_stop(FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "out of credits"))
    assert fofa_quota_note and "额度已用尽" in fofa_quota_note
    assert agent_profile(None).soft_stop(FofaError(FofaErrorCode.AUTH_FAILED, "bad key")) is None


@pytest.mark.asyncio
async def test_agent_normalizes_a_foreign_search_verb_onto_the_active_engine():
    """A FOFA-tuned planner may still emit `fofa_search`; a Shodan run must not."""
    seen_paths: list[str] = []

    def handler(request: httpx.Request):
        seen_paths.append(request.url.path)
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 100})
        return httpx.Response(200, json={"matches": [MATCH], "total": 1})

    engine = ShodanClient(api_key="test-key", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    run = await AssetAgent(engine, PlanRouter(plan(action="fofa_search"))).run("收集 nginx 资产", max_pages=1)

    assert run.engine == "shodan"
    assert run.action is AgentAction.SHODAN_SEARCH
    assert "/shodan/host/search" in seen_paths
    assert run.result_count == 1


@pytest.mark.asyncio
async def test_exhausted_credits_keep_partial_assets_on_every_engine():
    """Every engine bills per request: an exhausted balance must not discard collected assets."""

    class PartialClient:
        """Implements the engine contract the agent relies on; fails mid-search."""

        def __init__(self, name: str) -> None:
            self.name = name
            self.user_info = {"vip_level": 5}
            self.plan_info: dict = {}
            self.requests: list[SearchRequest] = []

        async def account(self) -> dict:
            self.plan_info = {"plan": "dev", "query_credits": 0}
            return self.plan_info

        async def iter_search(self, request: SearchRequest):
            self.requests.append(request)
            yield SearchPage(
                query=request.query,
                fields=list(request.fields),
                records=[AssetRecord(values={"host": "https://a.example", "ip": "1.1.1.1"})],
            )
            raise FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "out of query credits")

    shodan_client = PartialClient("shodan")
    shodan_run = await AssetAgent(shodan_client, PlanRouter()).run("收集资产", max_pages=1)

    assert shodan_run.error is None
    assert shodan_run.state is AgentState.COMPLETED
    assert shodan_run.result_count == 1
    assert shodan_run.assets[0]["host"] == "https://a.example"
    assert shodan_run.reflection_rounds == 0  # no pointless follow-up queries at zero credits
    assert "额度已用尽" in shodan_run.stop_reason
    assert any("额度已用尽" in step.detail for step in shodan_run.steps)
    assert "额度已用尽" in (shodan_run.summary or "")  # local briefing carries the stop

    # FOFA behaves the same way (the user asked for partial results to survive a spent quota);
    # only non-quota failures stay fatal.
    fofa_client = PartialClient("fofa")
    fofa_run = await AssetAgent(fofa_client, PlanRouter(plan(action="fofa_search"))).run("收集资产", max_pages=1)

    assert fofa_run.error is None
    assert fofa_run.state is AgentState.COMPLETED
    assert fofa_run.result_count == 1
    assert "额度已用尽" in fofa_run.stop_reason
    assert any("额度已用尽" in step.detail for step in fofa_run.steps)


@pytest.mark.asyncio
async def test_fofa_syntax_is_rejected_before_any_network_call():
    """The engine boundary must catch foreign syntax for CLI/REST/MCP callers too, not only the agent."""
    async with client_for(lambda _: pytest.fail("an invalid query must not reach the network")) as client:
        for query in ('app="nginx" && country="CN"', 'domain="example.com"', "product:nginx || port:22"):
            with pytest.raises(FofaError) as captured:
                await client.search_page(SearchRequest(query=query, fields=FIELDS))
            assert captured.value.code is FofaErrorCode.INVALID_QUERY
            assert captured.value.alternatives
        with pytest.raises(FofaError) as stats_error:
            await client.stats('app="nginx"', ["country"])
        assert stats_error.value.code is FofaErrorCode.INVALID_QUERY


@pytest.mark.asyncio
async def test_plan_gated_filters_are_not_blocked_locally():
    """Unknown filters stay the API's business: Shodan adds filters and gates others by plan."""
    seen = []
    async with client_for(search_handler({"matches": [], "total": 0}, seen)) as client:
        await client.search_page(SearchRequest(query="tag:ics", fields=FIELDS))

    assert "/shodan/host/search" in [request.url.path for request in seen]


def test_redact_secrets_removes_credentials_without_over_redacting():
    fake_key = "shodan-credential-fixture"
    assert fake_key not in redact_secrets(f"502 bad gateway for /api-info?key={fake_key}", fake_key)
    assert "[redacted]" in redact_secrets(f"boom: key={fake_key}", fake_key)
    assert redact_secrets("monkey=1 key=value", None) == "monkey=1 key=[redacted]"


@pytest.mark.asyncio
async def test_upstream_error_text_never_echoes_the_credential():
    fake_key = "shodan-credential-fixture"
    body = f"<html><body>bad gateway for https://api.shodan.io/api-info?key={fake_key}</body></html>"
    transport = httpx.MockTransport(lambda _: httpx.Response(502, text=body))
    async with ShodanClient(api_key=fake_key, max_retries=0, client=httpx.AsyncClient(transport=transport)) as client:
        with pytest.raises(FofaError) as captured:
            await client.account()

    assert fake_key not in captured.value.message
    assert "[redacted]" in captured.value.message


@pytest.mark.asyncio
async def test_quota_exhaustion_without_assets_stays_a_failure():
    """An exhausted balance must never be reported as a successful empty search."""

    class EmptyThenQuotaClient:
        name = "shodan"

        def __init__(self) -> None:
            self.plan_info: dict = {}

        async def account(self) -> dict:
            self.plan_info = {"plan": "dev", "query_credits": 0}
            return self.plan_info

        async def iter_search(self, request: SearchRequest):
            yield SearchPage(query=request.query, fields=list(request.fields), records=[])
            raise FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "out of query credits")

    run = await AssetAgent(EmptyThenQuotaClient(), PlanRouter()).run("收集资产", max_pages=1)

    assert run.error is not None
    assert run.error["code"] == "quota_exhausted"
    assert run.state is AgentState.FAILED


def test_shodan_certificate_matches_reach_the_corroborated_tier():
    """Shodan rows carry `ssl_cn` instead of FOFA's `cert.subject.cn`; corroboration must still work."""
    profile = agent_profile(type("C", (), {"name": "shodan"})())
    run = AgentRun(
        intent="收集 example.edu 的网站",
        engine="shodan",
        organization_names=["Example University"],
        domain_hypotheses=["example.edu"],
        fields=["host", "domain", "title", "ssl_cn"],
        assets=[
            {
                "host": "https://portal.example.edu:443",
                "domain": "example.edu",
                "title": "Example University Portal",
                "ssl_cn": "example.edu",
            }
        ],
        asset_confidence=["hypothesis"],
    )

    candidates = _derive_website_candidates(run, profile)

    assert candidates[0].domain == "example.edu"
    assert candidates[0].status == "corroborated"
    assert "shodan_hypothesis" in candidates[0].evidence


def test_fofa_attribution_uses_icp_and_certificate_fields():
    profile = agent_profile(None)
    assert profile.attribution({"cert.subject.cn": "example.edu", "icp": "京ICP备1号"}) == {
        "certificate_cn": "example.edu",
        "icp": "京ICP备1号",
    }


def test_batch_files_render_the_selected_engine_syntax(tmp_path: Path):
    path = tmp_path / "targets.txt"
    path.write_text("1.1.1.1\n2.2.2.2\nexample.com\n", encoding="utf-8")

    assert cybermap._load_batch(str(path), "shodan") == ["ip:1.1.1.1", "ip:2.2.2.2", "domain:example.com"]
    assert cybermap._combine_batch_queries(cybermap._load_batch(str(path), "shodan"), 100, engine="shodan") == [
        "ip:1.1.1.1,2.2.2.2",
        "domain:example.com",
    ]
    assert cybermap._load_batch(str(path), "fofa") == ['ip="1.1.1.1"', 'ip="2.2.2.2"', 'domain="example.com"']
    assert cybermap._combine_batch_queries(cybermap._load_batch(str(path), "fofa"), 100) == [
        '(ip="1.1.1.1" || ip="2.2.2.2")',
        'domain="example.com"',
    ]


@pytest.mark.asyncio
async def test_cli_batch_run_sends_shodan_syntax_to_the_engine(monkeypatch, tmp_path: Path):
    path = tmp_path / "targets.txt"
    path.write_text("1.1.1.1\n2.2.2.2\n", encoding="utf-8")
    queries: list[str] = []

    def handler(request: httpx.Request):
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 100})
        queries.append(request.url.params["query"])
        return httpx.Response(200, json={"matches": [], "total": 0})

    engine = ShodanClient(api_key="test-key", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(cybermap, "create_engine", lambda name=None: engine)

    code = await cybermap._main_async(
        cmd=None,
        engine="shodan",
        query=None,
        bat_query=str(path),
        output_format="json",
        query_fields="host,ip,country",
        pages=1,
        size=100,
        max_records=100,
        full=False,
        dedupe_by=None,
        save=False,
        smart_fields=False,
        check_alive=False,
        key_word=None,
        include=None,
        nuclei=False,
    )

    assert code == 0
    assert queries == ["ip:1.1.1.1,2.2.2.2"]


@pytest.mark.asyncio
async def test_cli_agent_mode_runs_on_shodan_end_to_end(monkeypatch):
    captured = {}
    seen_paths: list[str] = []

    def handler(request: httpx.Request):
        seen_paths.append(request.url.path)
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 100, "usage_limits": {"query_credits": -1}})
        return httpx.Response(200, json={"matches": [MATCH], "total": 1})

    engine = ShodanClient(api_key="test-key", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    class FakeRegistry:
        def __init__(self, *_args, **_kwargs):
            pass

        async def aclose(self):
            return None

    class FakeRouter(PlanRouter):
        def __init__(self, _registry):
            super().__init__(plan(queries=[{"query": "product:nginx country:CN", "purpose": "精确产品指纹", "strategy": "precision"}]))

        async def generate(self, task, **_kwargs):
            if task == "summarizer":
                return ModelResult(text="## 结论\n共发现 1 条资产。", model="test-model", provider="test-provider")
            return await super().generate(task, **_kwargs)

    async def fake_scan_report(run, options, machine):
        captured.update({"run": run, "options": options, "machine": machine})
        return "declined", None

    monkeypatch.setattr(cybermap, "create_engine", lambda name=None: engine)
    monkeypatch.setattr(cybermap, "render_agent", lambda run: captured.update({"rendered": run}))
    monkeypatch.setattr(cybermap, "_agent_scan_and_report", fake_scan_report)
    monkeypatch.setattr("providers.registry.ProviderRegistry", FakeRegistry)
    monkeypatch.setattr("providers.registry.ProviderRouter", FakeRouter)

    code = await cybermap._main_async(
        cmd=None,
        engine="shodan",
        ai_query="收集使用 nginx 的中国资产",
        output_format="table",
        max_records=100,
        pages=1,
        nuclei=False,
        nuclei_ids=(),
        severity=None,
        scan_max_targets=200,
        report=False,
        report_file=None,
        outdir=None,
    )

    run = captured["run"]
    assert code == 0
    assert run.engine == "shodan"
    assert run.action.value == "shodan_search"
    assert run.query == "product:nginx country:CN"
    assert set(run.fields) <= set(SHODAN_FIELDS)
    assert run.assets[0]["host"] == "https://three.webapplify.net:443"
    assert run.error is None
    assert "/shodan/host/search" in seen_paths
    assert "/api-info" in seen_paths


@pytest.mark.asyncio
async def test_cli_shodan_query_runs_end_to_end_into_the_shared_output_path(monkeypatch, capsys):
    def handler(request: httpx.Request):
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"plan": "dev", "query_credits": 100})
        return httpx.Response(200, json={"matches": [MATCH], "total": 1})

    engine = ShodanClient(api_key="test-key", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(cybermap, "create_engine", lambda name=None: engine)

    code = await cybermap._main_async(
        cmd=None,
        engine="shodan",
        query="product:nginx",
        output_format="json",
        query_fields="host,ip,port,protocol,title,country",
        pages=1,
        size=100,
        max_records=100,
        full=False,
        dedupe_by=None,
        save=False,
        smart_fields=False,
        check_alive=False,
        key_word=None,
        include=None,
        nuclei=False,
    )

    output = capsys.readouterr().out
    assert code == 0
    assert "https://three.webapplify.net:443" in output
    assert "United States" in output


def test_ipv6_banners_render_a_parseable_host_and_a_web_protocol():
    """`https://2001:db8::1:443` cannot be parsed, and a bare-IPv6 scan target aborts the plan."""
    from urllib.parse import urlparse

    web = map_match({"ip_str": "2001:db8::1", "port": 443, "transport": "tcp", "_shodan": {"module": "https"}}, ["host", "protocol"])
    assert web["host"] == "https://[2001:db8::1]:443"
    assert urlparse(web["host"]).port == 443

    socket = map_match({"ip_str": "2001:db8::1", "port": 22, "transport": "tcp"}, ["host", "protocol"])
    assert socket["host"] == "[2001:db8::1]:22"
    # A banner Shodan could not classify on a web port stays a web row, so its identity agrees with
    # the hostname-keyed rows FOFA and Hunter produce for the same page.
    assert map_match({"ip_str": "1.2.3.4", "port": 8080, "_shodan": {"module": "auto"}}, ["protocol"]) == {"protocol": "http"}
    assert map_match({"ip_str": "1.2.3.4", "port": 80, "_shodan": {"module": "unknown"}}, ["protocol"]) == {"protocol": "http"}
    assert map_match({"ip_str": "1.2.3.4", "port": 22, "transport": "tcp"}, ["protocol"]) == {"protocol": "tcp"}
