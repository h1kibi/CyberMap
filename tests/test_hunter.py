import base64

import httpx
import pytest

from core import engines
from core.agent_profiles import HunterProfile, ShodanProfile
from core.hunter import (
    DEFAULT_OUTPUT_FIELDS,
    HUNTER_FIELDS,
    HunterClient,
    country_code_from_name,
    hunter_request_fields,
    hunter_syntax_errors,
    legal_page_size,
    map_record,
    normalize_host_profile,
)
from core.models import FofaError, FofaErrorCode, IconDigest, SearchRequest

FIELDS = ["host", "ip", "port", "protocol", "title", "domain", "country"]

ACCOUNT = {
    "code": 200,
    "data": {
        "rest_free_point": 500,
        "day_free_point": 500,
        "type": "个人账号",
        "rest_equity_point": 4000,
        "rest_export_quota": -1,
        "day_export_quota": -1,
        "once_export_quota": 10000,
    },
}

MATCH = {
    "ip": "1.1.1.1",
    "port": "443",
    "url": "https://www.example.com",
    "web_title": "Example 登录",
    "domain": "example.com",
    "protocol": "https",
    "base_protocol": "tcp",
    "status_code": "200",
    "os": "Linux",
    "company": "Example 公司",
    "number": "京ICP备00000000号",
    "country": "中国",
    "province": "北京",
    "city": "北京",
    "isp": "中国电信",
    "as_org": "CHINANET",
    "cert_sha256": "ab12cd34",
    "ssl_certificate": "Version: v3\r\nSignature Algorithm: sha256\nCommon  Name: *.example.com\nIssuer: CN=Example",
    "component": [{"name": "nginx", "version": "1.24.0"}, {"name": "jQuery", "version": ""}],
    "asset_tag": "重点资产",
    "ip_tag": "云主机",
    "icp_exception": "",
    "is_risk_protocol": "false",
    "is_web": "true",
    "updated_at": "2024-05-01 12:00:00",
    "header_server": "nginx/1.24.0",
    "banner": "HTTP/1.1 200 OK\r\nServer: nginx",
    "vul_list": ["CVE-2024-0002", "CVE-2024-0001"],
}

# Non-web service: Hunter reports `0` for "no HTTP status" and the string `"None"` for no component.
NON_WEB = {"ip": "10.0.0.5", "port": "22", "url": "", "protocol": "ssh", "base_protocol": "tcp", "status_code": "0", "component": "None"}

HOST_RECORDS = [
    {
        "ip": "1.1.1.1",
        "port": "80",
        "protocol": "http",
        "base_protocol": "tcp",
        "url": "http://1.1.1.1",
        "web_title": "Example",
        "domain": "example.com",
        "country": "中国",
        "province": "北京",
        "city": "北京",
        "company": "Example 公司",
        "as_org": "CHINANET",
        "isp": "中国电信",
        "os": "",
        "component": [{"name": "nginx", "version": "1.24.0"}],
        "header_server": "nginx/1.24.0",
        "updated_at": "2024-05-01 12:00:00",
    },
    {
        "ip": "1.1.1.1",
        "port": "22",
        "protocol": "ssh",
        "base_protocol": "tcp",
        "url": "",
        "web_title": "",
        "domain": "",
        "country": "中国",
        "province": "北京",
        "city": "北京",
        "company": "Example 公司",
        "as_org": "CHINANET",
        "isp": "中国电信",
        "os": "Linux",
        "component": "None",
        "header_server": "OpenSSH_9.0",
        "updated_at": "2024-04-01 08:00:00",
    },
]


def client_for(handler, **kwargs) -> HunterClient:
    return HunterClient(
        api_key="test-key",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def page_payload(records, *, total=1, consume="消耗积分：1", rest="今日剩余积分：4500"):
    return {"code": 200, "data": {"total": total, "arr": list(records), "consume_quota": consume, "rest_quota": rest}}


def search_handler(payload, seen=None, account=None):
    def handler(request: httpx.Request):
        if seen is not None:
            seen.append(request)
        if request.url.path == "/openApi/userInfo":
            return httpx.Response(200, json=ACCOUNT if account is None else account)
        return httpx.Response(200, json=payload) if not callable(payload) else payload(request)

    return handler


def search_requests(seen):
    return [request for request in seen if request.url.path == "/openApi/search"]


@pytest.mark.asyncio
async def test_search_page_sends_the_documented_parameters_with_a_base64url_query():
    seen = []
    payload = page_payload([MATCH], total=1)
    query = 'web.title="登录"'
    async with client_for(search_handler(payload, seen)) as client:
        page = await client.search_page(
            SearchRequest(query=query, fields=["title", "icp", "timestamp"], size=500)
        )
        await client.search_page(SearchRequest(query=query, fields=FIELDS, size=20, page=2))

    searches = search_requests(seen)
    assert [request.url.path for request in seen] == [
        "/openApi/userInfo",
        "/openApi/search",
        "/openApi/search",
    ]
    assert searches[0].url.params["search"] == base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii")
    assert searches[0].url.params["page"] == "1"
    assert searches[0].url.params["page_size"] == "100"
    assert searches[0].url.params["is_web"] == "3"
    assert searches[0].url.params["api-key"] == "test-key"
    assert set(searches[0].url.params["fields"].split(",")) == {"web_title", "number", "updated_at"}
    assert searches[1].url.params["page"] == "2"
    assert searches[1].url.params["page_size"] == "20"
    assert page.total == 1
    assert page.metadata["engine"] == "hunter"
    assert page.metadata["page_size"] == 100


@pytest.mark.asyncio
async def test_page_size_is_rounded_down_to_a_legal_bucket_on_the_wire_and_in_metadata():
    seen = []
    async with client_for(search_handler(page_payload([MATCH]), seen)) as client:
        tiny = await client.search_page(SearchRequest(query='web.title="登录"', fields=FIELDS, size=5))
        awkward = await client.search_page(SearchRequest(query='web.title="登录"', fields=FIELDS, size=14))

    assert [request.url.params["page_size"] for request in search_requests(seen)] == ["1", "10"]
    assert tiny.metadata["page_size"] == 1
    assert awkward.metadata["page_size"] == 10


def test_legal_page_size_accepts_only_one_or_a_multiple_of_ten_up_to_one_hundred():
    assert legal_page_size(1) == 1
    assert legal_page_size(5) == 1
    assert legal_page_size(14) == 10
    assert legal_page_size(20) == 20
    assert legal_page_size(100) == 100
    assert legal_page_size(150) == 100


def test_full_record_projects_into_the_unified_field_vocabulary():
    row = map_record(MATCH, list(HUNTER_FIELDS))

    assert row["host"] == "https://www.example.com"
    assert row["ip"] == "1.1.1.1"
    assert row["port"] == 443
    assert row["protocol"] == "https"
    assert row["base_protocol"] == "tcp"
    assert row["title"] == "Example 登录"
    assert row["domain"] == "example.com"
    assert row["server"] == "nginx/1.24.0"
    assert row["status_code"] == 200
    assert row["country"] == "中国"
    assert row["region"] == "北京"
    assert row["city"] == "北京"
    assert row["org"] == "Example 公司"
    assert row["as_org"] == "CHINANET"
    assert row["isp"] == "中国电信"
    assert row["os"] == "Linux"
    assert row["product"] == "nginx, jQuery"
    assert row["version"] == "1.24.0"
    assert row["timestamp"] == "2024-05-01 12:00:00"
    assert row["vulns"] == "CVE-2024-0001, CVE-2024-0002"
    assert row["ssl_cn"] == "*.example.com"
    assert row["cert_sha256"] == "ab12cd34"
    assert row["icp"] == "京ICP备00000000号"
    assert row["ip_tag"] == "云主机"
    assert row["asset_tag"] == "重点资产"
    assert row["banner"] == "HTTP/1.1 200 OK\r\nServer: nginx"


def test_a_non_web_service_reports_blank_status_and_no_invented_component():
    row = map_record(NON_WEB, ["host", "port", "protocol", "status_code", "product", "version", "ssl_cn"])

    assert row == {
        "host": "10.0.0.5:22",
        "port": 22,
        "protocol": "ssh",
        "status_code": "",
        "product": "",
        "version": "",
        "ssl_cn": "",
    }


def test_only_requested_fields_are_projected_so_banners_stay_out_of_a_default_export():
    assert map_record(MATCH, ["ip"]) == {"ip": "1.1.1.1"}

    default_row = map_record(MATCH, list(DEFAULT_OUTPUT_FIELDS))
    assert default_row["title"] == "Example 登录"
    assert not {"banner", "header", "body", "ssl_certificate"} & set(default_row)


@pytest.mark.asyncio
async def test_full_mode_adds_the_heavy_columns_while_the_default_never_asks_for_them():
    seen = []
    async with client_for(search_handler(page_payload([MATCH]), seen)) as client:
        await client.search_page(SearchRequest(query='web.title="登录"', fields=["host"]))
        await client.search_page(SearchRequest(query='web.title="登录"', fields=["host"], full=True))

    columns = [set(request.url.params["fields"].split(",")) for request in search_requests(seen)]
    assert columns[0] == {"url"}
    assert columns[1] == {"url", "banner", "header", "body", "ssl_certificate"}

    default_seen = []
    async with client_for(search_handler(page_payload([MATCH]), default_seen)) as client:
        await client.search_page(SearchRequest(query='web.title="登录"', fields=list(DEFAULT_OUTPUT_FIELDS)))

    default_columns = set(search_requests(default_seen)[0].url.params["fields"].split(","))
    assert default_columns == {"url", "ip", "port", "protocol", "base_protocol", "web_title", "domain", "country"}


@pytest.mark.asyncio
async def test_the_reply_reports_the_server_side_credit_spend_and_the_remaining_pool():
    payload = page_payload([MATCH], consume="消耗积分：9", rest="今日剩余积分：4476")
    async with client_for(search_handler(payload)) as client:
        page = await client.search_page(SearchRequest(query='web.title="登录"', fields=FIELDS))

    assert page.consumed == 9
    assert page.metadata["points_spent"] == 9
    assert page.metadata["points_left"] == 4476
    assert page.metadata["account_type"] == "个人账号"
    assert client.remaining_points == 4476


@pytest.mark.asyncio
async def test_an_empty_point_pool_stops_a_billed_search_before_the_search_endpoint():
    seen: list[str] = []

    def handler(request: httpx.Request):
        seen.append(request.url.path)
        if request.url.path == "/openApi/userInfo":
            return httpx.Response(
                200, json={"code": 200, "data": {"rest_free_point": 0, "rest_equity_point": 0, "type": "个人账号"}}
            )
        return httpx.Response(200, json=page_payload([MATCH]))

    async with client_for(handler) as client:
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query='web.title="登录"', fields=FIELDS))

    assert captured.value.code is FofaErrorCode.QUOTA_EXHAUSTED
    assert "个人账号" in captured.value.message
    assert seen == ["/openApi/userInfo"]


@pytest.mark.asyncio
async def test_the_body_code_classifies_upstream_failures():
    cases = [
        (401, "令牌过期", FofaErrorCode.AUTH_FAILED),
        (400, "字段 foo 不支持查询", FofaErrorCode.INVALID_QUERY),
        (400, "积分不足，请充值", FofaErrorCode.QUOTA_EXHAUSTED),
    ]
    for code, message, expected in cases:
        payload = {"code": code, "message": message}
        async with client_for(search_handler(payload)) as client:
            with pytest.raises(FofaError) as captured:
                await client.search_page(SearchRequest(query='web.title="登录"', fields=FIELDS))

        assert captured.value.code is expected
        assert message in captured.value.message


@pytest.mark.asyncio
async def test_missing_credentials_fail_before_any_request():
    async with HunterClient(
        api_key="", client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: pytest.fail("no key, no request")))
    ) as client:
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query='web.title="登录"', fields=FIELDS))

    assert captured.value.code is FofaErrorCode.AUTH_FAILED
    assert "HUNTER_API_KEY" in captured.value.alternatives


@pytest.mark.asyncio
async def test_a_denied_field_is_downgraded_retried_and_reported_instead_of_failing_the_run():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path == "/openApi/userInfo":
            return httpx.Response(200, json=ACCOUNT)
        if "body" in request.url.params["fields"].split(","):
            return httpx.Response(200, json={"code": 400, "message": "无”body“字段权限"})
        return httpx.Response(200, json=page_payload([MATCH]))

    async with client_for(handler) as client:
        page = await client.search_page(SearchRequest(query='web.title="登录"', fields=["host", "body"]))

        assert client.field_downgrades == ["body"]
        assert page.records[0].values["host"] == "https://www.example.com"

    assert [request.url.params["fields"] for request in search_requests(seen)] == ["url,body", "url"]
    assert page.metadata["downgraded_fields"] == ["body"]


@pytest.mark.asyncio
async def test_a_relentless_denial_gives_up_after_a_bounded_number_of_retries():
    seen = []
    heavy = ("banner", "header", "body", "ssl_certificate")

    def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path == "/openApi/userInfo":
            return httpx.Response(200, json=ACCOUNT)
        columns = request.url.params["fields"].split(",")
        denied = next((column for column in heavy if column in columns), None)
        if denied is not None:
            return httpx.Response(200, json={"code": 400, "message": f"无”{denied}“字段权限"})
        return httpx.Response(200, json=page_payload([MATCH]))

    async with client_for(handler) as client:
        with pytest.raises(FofaError) as captured:
            await client.search_page(SearchRequest(query='web.title="登录"', fields=["host"], full=True))

    assert captured.value.code is FofaErrorCode.PERMISSION_DENIED
    assert client.field_downgrades == ["banner", "header", "body", "ssl_certificate"]
    assert len(search_requests(seen)) == 4


@pytest.mark.asyncio
async def test_the_last_page_of_the_result_window_stops_iteration_without_another_request():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path == "/openApi/userInfo":
            return httpx.Response(200, json=ACCOUNT)
        return httpx.Response(200, json=page_payload([MATCH] * 10, total=10000))

    async with client_for(handler) as client:
        pages = [
            page
            async for page in client.iter_search(
                SearchRequest(query='web.title="登录"', fields=FIELDS, page=1000, size=10, max_pages=5)
            )
        ]

    assert len(pages) == 1
    assert pages[0].metadata["max_window"] == 10000
    assert pages[0].metadata["window_exhausted"] is True
    assert len(search_requests(seen)) == 1


@pytest.mark.asyncio
async def test_iteration_honors_the_record_page_and_cost_budgets():
    def handler(consume="消耗积分：1"):
        def handle(request: httpx.Request):
            if request.url.path == "/openApi/userInfo":
                return httpx.Response(200, json=ACCOUNT)
            return httpx.Response(200, json=page_payload([MATCH] * 10, total=10000, consume=consume))

        return handle

    async with client_for(handler()) as client:
        two_pages = [
            page
            async for page in client.iter_search(
                SearchRequest(query='web.title="登录"', fields=FIELDS, size=10, max_pages=2)
            )
        ]
        three_records = [
            record
            async for page in client.iter_search(
                SearchRequest(query='web.title="登录"', fields=FIELDS, size=10, max_pages=5, max_records=3)
            )
            for record in page.records
        ]

    assert len(two_pages) == 2
    assert len(three_records) == 3

    async with client_for(handler(consume="消耗积分：9")) as client:
        budgeted = [
            page
            async for page in client.iter_search(
                SearchRequest(query='web.title="登录"', fields=FIELDS, size=10, max_pages=5, cost_budget=9)
            )
        ]

    assert len(budgeted) == 1


@pytest.mark.asyncio
async def test_bad_fields_and_foreign_syntax_are_rejected_before_any_network_call():
    async with client_for(lambda _: pytest.fail("a locally rejected request must not reach the network")) as client:
        with pytest.raises(FofaError) as unknown_field:
            await client.search_page(SearchRequest(query='web.title="登录"', fields=["cert.subject.cn"]))
        with pytest.raises(FofaError) as foreign_syntax:
            await client.search_page(SearchRequest(query="product:nginx", fields=FIELDS))

    assert unknown_field.value.code is FofaErrorCode.INVALID_QUERY
    assert "host" in unknown_field.value.alternatives
    assert foreign_syntax.value.code is FofaErrorCode.INVALID_QUERY


def test_hunter_syntax_rejects_colon_filters_but_accepts_quoted_colons_and_parens():
    assert hunter_syntax_errors("product:nginx") != []
    assert hunter_syntax_errors('web.similar="a.com:443"') == []
    assert hunter_syntax_errors('web.title="登录" && country="中国"') == []
    assert hunter_syntax_errors('(a="x" || b="y")') == []
    # Unknown filter names stay the API's business: a rejected request costs no credits.
    assert hunter_syntax_errors('made_up_field="x"') == []
    assert hunter_request_fields(["alive_status", "ip"]) == ["ip"]


@pytest.mark.asyncio
async def test_stats_is_unsupported_and_never_touches_the_network():
    async with client_for(lambda _: pytest.fail("hunter has no aggregation endpoint")) as client:
        with pytest.raises(FofaError) as captured:
            await client.stats('web.title="登录"', ["ip"], size=5)

    assert captured.value.code is FofaErrorCode.UNSUPPORTED
    assert captured.value.alternatives == ["-e fofa -cq", "-e shodan -cq", "-e hunter -q"]


@pytest.mark.asyncio
async def test_host_profile_aggregates_an_ip_search_into_the_shared_profile_shape():
    seen = []
    async with client_for(search_handler(page_payload(HOST_RECORDS, total=2), seen)) as client:
        profile = await client.host_profile("1.1.1.1")

    assert [request.url.path for request in seen] == ["/openApi/userInfo", "/openApi/search"]
    assert search_requests(seen)[0].url.params["search"] == base64.urlsafe_b64encode(b'ip="1.1.1.1"').decode("ascii")
    assert search_requests(seen)[0].url.params["page_size"] == "100"
    assert profile["host"] == "1.1.1.1"
    assert profile["ip"] == "1.1.1.1"
    assert profile["country_name"] == "中国"
    assert profile["org"] == "Example 公司"
    assert profile["domains"] == ["example.com"]
    assert profile["source"] == "hunter"
    # Hunter reports no ASN number, only the operator name: the ASN row must stay empty.
    assert profile["asn"] == ""
    assert profile["as_org"] == "CHINANET"
    assert profile["update_time"] == "2024-05-01 12:00:00"
    assert [entry["port"] for entry in profile["ports"]] == [22, 80]
    assert [entry["update_time"] for entry in profile["ports"]] == ["2024-04-01 08:00:00", "2024-05-01 12:00:00"]
    assert all(isinstance(entry["port"], int) for entry in profile["ports"])
    assert profile["ports"][1]["products"] == [{"product": "nginx 1.24.0", "name": "nginx 1.24.0"}]
    assert profile["ports"][0]["products"] == [{"product": "OpenSSH_9.0", "name": "OpenSSH_9.0"}]


def test_normalize_host_profile_keeps_the_newest_observation_time():
    records = [
        {
            "ip": "1.1.1.1",
            "port": 80,
            "protocol": "http",
            "product": "nginx",
            "version": "1.24.0",
            "timestamp": "2024-04-01 08:00:00",
            "as_org": "CHINANET",
        },
        {
            "ip": "1.1.1.1",
            "port": 443,
            "protocol": "https",
            "product": "",
            "version": "",
            "server": "Apache/2.4",
            "timestamp": "2024-05-01 12:00:00",
        },
    ]

    profile = normalize_host_profile(records, host="1.1.1.1")

    assert profile["update_time"] == "2024-05-01 12:00:00"
    assert [entry["update_time"] for entry in profile["ports"]] == ["2024-04-01 08:00:00", "2024-05-01 12:00:00"]
    assert profile["ports"][0]["products"] == [{"product": "nginx 1.24.0", "name": "nginx 1.24.0"}]
    assert profile["ports"][1]["products"] == [{"product": "Apache/2.4", "name": "Apache/2.4"}]
    # Hunter has no ASN number, so the operator name must not be dressed up as one.
    assert profile["asn"] == ""
    assert profile["as_org"] == "CHINANET"


def test_normalize_host_profile_skips_entries_without_a_port():
    profile = normalize_host_profile([{"ip": "1.1.1.1", "port": "", "protocol": ""}], host="1.1.1.1")

    assert profile["ports"] == []
    assert profile["source"] == "hunter"


@pytest.mark.asyncio
async def test_host_profile_rejects_path_credential_or_space_targets_before_network():
    async with client_for(lambda _: pytest.fail("an invalid target must not reach the network")) as client:
        for target in ("1.1.1.1/24", "1.1.1.1?x=1", "user@host", "a b c", ""):
            with pytest.raises(FofaError) as captured:
                await client.host_profile(target)
            assert captured.value.code is FofaErrorCode.INVALID_QUERY


def test_hunter_profile_declares_the_hunter_search_action_and_the_shared_identity_defaults():
    profile = HunterProfile()

    assert profile.engine == "hunter"
    assert profile.search_action == "hunter_search"
    assert set(profile.default_fields) == {"host", "ip", "port", "protocol", "title", "domain", "country"}
    assert set(profile.default_fields) == set(ShodanProfile.default_fields)
    assert set(profile.default_fields) == set(engines.default_fields("fofa"))
    assert profile.plan_schema()["properties"]["action"]["enum"][0] == "hunter_search"


def test_hunter_profile_uses_the_hunter_syntax_rules_and_drops_foreign_fields():
    profile = HunterProfile()

    assert profile.query_errors("product:nginx") == hunter_syntax_errors("product:nginx") != []
    assert profile.query_errors('web.title="登录"') == hunter_syntax_errors('web.title="登录"') == []

    selection = profile.decide_fields(["ip", "cert.subject.cn"])
    assert selection.allowed == ["ip"]
    assert selection.denied == ["cert.subject.cn"]
    assert profile.request_fields(["cert.subject.cn"]) == [
        "host",
        "ip",
        "port",
        "protocol",
        "title",
        "domain",
        "country",
    ]
    assert profile.request_fields(["ip", "as_org"]) == ["ip", "as_org"]
    assert set(HUNTER_FIELDS) >= set(profile.default_fields)


def test_hunter_profile_builds_hunter_hypothesis_queries_and_reads_their_domains():
    profile = HunterProfile()
    query = profile.hypothesis_query(["a.example", "b.example"])

    assert query == '(domain.suffix="a.example" || domain.suffix="b.example")'
    assert profile.planning_domains(['(domain.suffix="a.example" || domain.suffix="b.example")']) == {
        "a.example",
        "b.example",
    }
    assert profile.planning_domains(['domain="WWW.C.example"', 'url="d.example:8443"']) == {"c.example", "d.example"}
    assert profile.planning_domains(['web.title="登录"', 'made_up_field="not.a.domain"']) == set()


def test_hunter_profile_uses_the_md5_favicon_filter_and_downgrades_statistics():
    profile = HunterProfile()

    assert profile.icon_query(IconDigest(md5="ab", murmur3=7)) == 'web.icon="ab"'
    assert engines.favicon_query("hunter", IconDigest(md5="ab", murmur3=7)) == 'web.icon="ab"'

    fallback = profile.align_action("stat_query", None, has_queries=True)
    assert fallback is not None
    assert fallback.action == "hunter_search"
    assert fallback.data == {"fallback": "hunter_search", "engine": "hunter"}
    assert "聚合统计" in fallback.note
    assert profile.align_action("hunter_search", None, has_queries=True) is None
    assert profile.soft_stop(FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "out of credits"))


def test_country_code_is_mapped_from_the_chinese_country_name():
    """Hunter returns 国家名 in Chinese and no ISO code; the merged view needs a code."""
    assert country_code_from_name("美国") == "US"
    assert country_code_from_name("中国") == "CN"
    assert country_code_from_name("拉脱维亚") == "LV"
    assert country_code_from_name("未知星球") == ""


def test_record_projects_country_code_from_the_native_country():
    row = map_record({"country": "美国", "ip": "1.1.1.1"}, ["country", "country_code"])
    assert row == {"country": "美国", "country_code": "US"}


def test_ipv6_records_render_a_parseable_host():
    from urllib.parse import urlparse

    web = map_record({"ip": "2001:db8::1", "port": 443, "protocol": "https"}, ["host"])
    assert web["host"] == "https://[2001:db8::1]:443"
    assert urlparse(web["host"]).port == 443
    assert map_record({"ip": "2001:db8::1", "port": 22, "protocol": "ssh"}, ["host"]) == {"host": "[2001:db8::1]:22"}
