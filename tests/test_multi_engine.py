"""Multi-engine agent: per-engine planning merged into one asset-mapping briefing."""

import pytest
import rich_click as click

import cybermap
from core.agent import AgentAction, AgentState, MultiEngineAgent, _asset_briefing_stats, _asset_identity, asset_endpoint_count
from core.models import AssetRecord, FofaError, FofaErrorCode, SearchPage, SearchRequest
from providers.base import ModelResult


def query_for_engine(system_prompt: str) -> str:
    """Each engine plans in its own syntax, so the fake planner reads the engine off the prompt.

    A colon filter is Shodan-only, FOFA assignments are not Shodan syntax, and Hunter accepts
    neither `product:` nor `app=`; that is exactly why queries are never translated across engines.
    """
    if "DayDayMap" in system_prompt:
        return 'title="nginx"'
    if "Hunter" in system_prompt:
        return 'web.title="nginx"'
    if "Shodan" in system_prompt:
        return "product:nginx"
    return 'app="nginx"'


def plan_payload(query: str = "product:nginx") -> dict:
    return {
        "action": "fofa_search",  # a foreign verb must be normalized onto each engine
        "target": "",
        "queries": [{"query": query, "purpose": "精确产品指纹", "strategy": "precision"}],
        "stats_fields": [],
        "fields": ["host", "ip", "port", "protocol", "title", "domain", "country"],
        "scan": {"recommended": True, "reason": "用户明确要求扫描", "template_ids": [], "severities": ["medium"]},
    }


class PlanRouter:
    def __init__(self, payload: dict | None = None, *, summary: str | None = None) -> None:
        self.events: list = []
        self.payload = payload or plan_payload()
        self.summary = summary
        self.prompts: list[str] = []

    async def generate(self, task: str, **kwargs):
        if task == "planner":
            payload = dict(self.payload)
            payload["queries"] = [
                {**query, "query": query_for_engine(str(kwargs.get("system") or ""))} for query in self.payload["queries"]
            ]
            return ModelResult(text="plan", structured=payload, model="m", provider="p")
        if task == "summarizer":
            self.prompts.append(str(kwargs.get("prompt") or ""))
            if self.summary:
                return ModelResult(text=self.summary, model="m", provider="p")
        return ModelResult(text="## 结论\nok", model="m", provider="p")


class FakeEngine:
    """Minimal engine contract with per-engine rows and an optional failure."""

    def __init__(self, name: str, rows: list[dict], *, error: FofaError | None = None) -> None:
        self.name = name
        self.rows = rows
        self.error = error
        self.user_info = {"username": "tester", "vip_level": 5}
        self.plan_info = {"plan": "edu", "query_credits": 100}
        self.requests: list[SearchRequest] = []
        self.host_calls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def account(self) -> dict:
        return self.plan_info

    async def host_profile(self, host: str, *, detail: bool = True) -> dict:
        self.host_calls.append(host)
        return {"host": host, "ip": host, "ports": [{"port": 443, "protocol": "https", "products": [], "update_time": ""}]}

    async def iter_search(self, request: SearchRequest):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        yield SearchPage(
            query=request.query,
            fields=list(request.fields),
            records=[AssetRecord(values=row) for row in self.rows],
            total=len(self.rows),
        )


def factory(engines: dict[str, FakeEngine]):
    def build(name: str | None = None) -> FakeEngine:
        return engines[str(name)]

    return build


FAKE_SUMMARY = (
    "## 结论\n双引擎结果已合并。\n\n## 高置信资产\n- `a.example`\n\n## 风险与暴露面\n- 443 开放\n\n"
    "## 证据边界与噪声\n- 无\n\n## 覆盖缺口\n- 无\n\n## 处置优先级\n1. 复核\n" + "。" * 400
)


@pytest.mark.asyncio
async def test_engines_are_planned_separately_and_merged_on_shared_identity():
    fofa = FakeEngine("fofa", [{"host": "https://a.example", "ip": "1.1.1.1", "port": 443, "protocol": "https", "icp": "京ICP1"}])
    shodan = FakeEngine(
        "shodan",
        [
            {"host": "https://a.example", "ip": "1.1.1.1", "port": 443, "protocol": "https", "ssl_cn": "a.example"},
            {"host": "1.2.3.4:22", "ip": "1.2.3.4", "port": 22, "protocol": "ssh"},
        ],
    )
    router = PlanRouter(summary=FAKE_SUMMARY)
    run = await MultiEngineAgent(("fofa", "shodan"), router, engine_factory=factory({"fofa": fofa, "shodan": shodan})).run(
        "收集 a.example 资产", max_records=100, smart_fields=False
    )

    assert run.engine == "all"
    assert run.action is AgentAction.MULTI_SEARCH
    assert run.error is None
    # The merged list is deduplicated across engines, so the count is the list length and the
    # cross-engine duplicate (a.example) is not counted twice.
    assert [asset["ip"] for asset in run.assets] == ["1.1.1.1", "1.2.3.4"]
    assert run.result_count == len(run.assets) == 2
    # Merging keeps every column either engine observed, including on the shared row.
    assert run.assets[0]["icp"] == "京ICP1"
    assert run.assets[0]["ssl_cn"] == "a.example"
    # FOFA answers `country` with a code, so its column is merged as `country_code` and stays
    # separate from Shodan's country name: one concept, one column.
    assert set(run.fields) == {"host", "ip", "port", "protocol", "title", "domain", "country", "country_code"}
    assert run.assets[1]["protocol"] == "ssh"
    assert all(query.purpose.startswith("[") for query in run.queries)
    assert {query.purpose.split("]")[0] for query in run.queries} == {"[FOFA", "[Shodan"}
    assert run.scan_recommended is True
    # The ssh row keeps a bare `host:port`: a scheme would make a non-web service look like a URL.
    assert run.scan_targets == ["https://a.example", "1.2.3.4:22"]
    assert fofa.requests and shodan.requests
    # The caller's cap is split across the engines that still have to run, and budget an engine
    # did not use flows to the later engines instead of being wasted. Each engine's share is then
    # split across the queries it runs (here the plan's query plus the bundle's certificate pivot).
    # The share is then rounded up across the engine's own queries (plan + certificate pivot):
    # ceil(50 / 2) and ceil(99 / 2).
    assert fofa.requests[0].max_records == 25
    assert shodan.requests[0].max_records == 50
    assert all(request.max_records <= 50 for request in fofa.requests)
    assert "Per-engine contribution" in next(prompt for prompt in router.prompts if "Per-engine contribution" in prompt)


@pytest.mark.asyncio
async def test_smart_fields_from_both_engines_are_merged():
    """Each engine suggests its own catalogue, so the merged columns are the union."""
    fofa = FakeEngine("fofa", [{"host": "https://a.example", "ip": "1.1.1.1"}])
    shodan = FakeEngine("shodan", [{"host": "https://a.example", "ip": "1.1.1.1"}])
    router = PlanRouter(summary=FAKE_SUMMARY)

    run = await MultiEngineAgent(("fofa", "shodan"), router, engine_factory=factory({"fofa": fofa, "shodan": shodan})).run(
        "收集 a.example 的漏洞与证书信息", max_records=100
    )

    fofa_fields = set(fofa.requests[0].fields)
    shodan_fields = set(shodan.requests[0].fields)
    assert fofa_fields != shodan_fields
    assert {"vulns", "ssl_cn"} <= shodan_fields - fofa_fields  # Shodan-only columns
    assert "cert.subject.cn" in fofa_fields - shodan_fields  # FOFA-only column
    # The merged columns are the union after the documented renames, so FOFA's certificate-name
    # column and Shodan's `ssl_cn` land in one column instead of two half-empty ones.
    # FOFA's own last-seen column is merged as the unified `timestamp` as well.
    expected = (
        set(fofa_fields - {"cert.subject.cn", "country", "lastupdatetime"})
        | shodan_fields
        | {"ssl_cn", "country_code", "timestamp"}
    )
    assert set(run.fields) == expected
    assert "cert.subject.cn" not in run.fields


@pytest.mark.asyncio
async def test_one_engine_failing_keeps_the_other_engines_results():
    fofa = FakeEngine("fofa", [{"host": "https://a.example", "ip": "1.1.1.1"}])
    shodan = FakeEngine("shodan", [], error=FofaError(FofaErrorCode.AUTH_FAILED, "bad key", status_code=401))
    router = PlanRouter(summary=FAKE_SUMMARY)

    run = await MultiEngineAgent(("fofa", "shodan"), router, engine_factory=factory({"fofa": fofa, "shodan": shodan})).run(
        "收集 a.example 资产", max_records=100
    )

    assert run.error is None
    assert run.state is AgentState.COMPLETED
    assert run.engine_errors["shodan"]["code"] == "auth_failed"
    assert any("Shodan 检索失败" in step.detail for step in run.steps)
    assert [asset["ip"] for asset in run.assets] == ["1.1.1.1"]
    merged_prompt = next(prompt for prompt in router.prompts if "Per-engine contribution" in prompt)
    assert "Shodan" in merged_prompt  # the briefing is told which engine is missing


@pytest.mark.asyncio
async def test_all_engines_failing_is_reported_as_a_failure():
    error = FofaError(FofaErrorCode.QUOTA_EXHAUSTED, "out of credits")
    engines = {name: FakeEngine(name, [], error=error) for name in ("fofa", "shodan")}
    run = await MultiEngineAgent(("fofa", "shodan"), PlanRouter(), engine_factory=factory(engines)).run("收集资产")

    assert run.error is not None
    assert run.error["code"] == "quota_exhausted"
    assert run.state is AgentState.FAILED
    assert run.assets == []


def test_multi_engine_label_is_readable():
    from core.engines import MULTI_ENGINE, engine_label, normalize_engine_scope

    assert engine_label(MULTI_ENGINE) == "FOFA + Shodan + Hunter + DayDayMap"
    assert normalize_engine_scope("all") == ("fofa", "shodan", "hunter", "daydaymap")
    assert normalize_engine_scope("hunter") == ("hunter",)
    assert normalize_engine_scope("shodan") == ("shodan",)
    assert normalize_engine_scope(None) == ("fofa",)


@pytest.mark.asyncio
async def test_cli_multi_engine_run_merges_every_engine(monkeypatch):
    fofa = FakeEngine("fofa", [{"host": "https://a.example", "ip": "1.1.1.1", "icp": "京ICP1"}])
    shodan = FakeEngine("shodan", [{"host": "https://b.example", "ip": "2.2.2.2", "ssl_cn": "b.example"}])
    hunter = FakeEngine(
        "hunter", [{"host": "https://c.example", "ip": "3.3.3.3", "port": 443, "protocol": "https", "icp": "京ICP3"}]
    )
    daydaymap = FakeEngine(
        "daydaymap",
        [{"host": "https://d.example", "ip": "4.4.4.4", "port": 443, "protocol": "https", "hostnames": "d.example"}],
    )
    router = PlanRouter(summary=FAKE_SUMMARY)
    captured = {}

    monkeypatch.setattr(
        cybermap,
        "create_engine",
        factory({"fofa": fofa, "shodan": shodan, "hunter": hunter, "daydaymap": daydaymap}),
    )
    monkeypatch.setattr(cybermap, "_make_router", lambda: (type("R", (), {"aclose": lambda self: _noop()})(), router))
    monkeypatch.setattr(cybermap, "render_agent", lambda run: captured.update(run=run))
    monkeypatch.setattr(cybermap, "_agent_scan_and_report", _fake_scan_report)

    code = await cybermap._main_async(
        cmd=None,
        engine="all",
        ai_query="收集示例资产",
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
    assert run.engine == "all"
    assert {asset["ip"] for asset in run.assets} == {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
    assert {step.detail.split("]")[0] for step in run.steps if step.detail.startswith("[")} == {
        "[FOFA",
        "[Shodan",
        "[Hunter",
        "[DayDayMap",
    }
    assert hunter.requests  # every engine really ran, not just listed
    assert daydaymap.requests


async def _noop() -> None:
    return None


async def _fake_scan_report(_run, _options, _machine):
    return "declined", None


@pytest.mark.asyncio
async def test_cli_rejects_multi_engine_for_classic_queries():
    with pytest.raises(click.UsageError) as captured:
        await cybermap._main_async(cmd=None, engine="all", query='app="nginx"', output_format="table")

    assert "all" in str(captured.value)


@pytest.mark.asyncio
async def test_cli_multi_engine_rejects_when_configured_but_only_classic_command_given(monkeypatch):
    monkeypatch.setattr(cybermap.settings.search, "engine", "all", raising=False)

    with pytest.raises(click.UsageError):
        await cybermap._main_async(cmd=None, engine=None, query='app="nginx"', output_format="table")


@pytest.mark.asyncio
async def test_non_list_intent_is_delegated_with_its_payload():
    """A host profile can only be rendered by the engine that produced it, so it is not merged away."""
    fofa = FakeEngine("fofa", [])
    shodan = FakeEngine("shodan", [])
    payload = plan_payload()
    payload.update({"action": "host_query", "target": "8.8.8.8", "queries": []})
    router = PlanRouter(payload)

    run = await MultiEngineAgent(("fofa", "shodan"), router, engine_factory=factory({"fofa": fofa, "shodan": shodan})).run(
        "查看 8.8.8.8 的主机画像", max_records=100
    )

    assert run.action is AgentAction.HOST
    assert run.engine == "fofa"  # the run reports which engine answered
    assert run.result_data["ports"][0]["port"] == 443
    assert run.result_count == 1
    assert fofa.host_calls == ["8.8.8.8"]
    assert shodan.host_calls == []  # the other engines are not asked again
    assert any("不可跨引擎合并" in step.detail for step in run.steps)


@pytest.mark.asyncio
async def test_merge_keeps_columns_when_evidence_ranks_are_equal():
    """Same-rank rows must still union their columns: a merge may not drop what an engine saw."""
    fofa = FakeEngine("fofa", [{"host": "https://a.example", "ip": "1.1.1.1", "port": 443, "protocol": "https", "icp": "京ICP1"}])
    shodan = FakeEngine(
        "shodan",
        [{"host": "https://a.example", "ip": "1.1.1.1", "port": 443, "protocol": "https", "vulns": "CVE-2021-44228"}],
    )

    run = await MultiEngineAgent(
        ("fofa", "shodan"), PlanRouter(summary=FAKE_SUMMARY), engine_factory=factory({"fofa": fofa, "shodan": shodan})
    ).run("收集 a.example 资产", max_records=100, smart_fields=False)

    assert len(run.assets) == 1
    # Both engines observed this asset at the same evidence rank; the merged row still has to
    # carry every column either of them returned.
    assert run.assets[0]["icp"] == "京ICP1"
    assert run.assets[0]["vulns"] == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_cli_multi_engine_rejects_batch_and_icon_sources_before_building_queries(tmp_path):
    """`-e all` merges engine-specific syntax, so classic query sources must fail with the real reason."""
    batch = tmp_path / "clues.txt"
    batch.write_text("1.1.1.1\n", encoding="utf-8")

    for options in ({"bat_query": str(batch)}, {"icon_file": str(tmp_path / "missing.png")}):
        with pytest.raises(click.UsageError) as captured:
            await cybermap._main_async(cmd=None, engine="all", output_format="table", **options)
        message = str(captured.value)
        assert "all" in message
        assert "未知的搜索引擎" not in message


@pytest.mark.asyncio
async def test_cli_multi_engine_account_lists_every_engine(monkeypatch):
    """`-e all account` is the one classic action the merged scope must keep supporting."""
    from core.engines import AGENT_ENGINES

    engines = {name: FakeEngine(name, []) for name in AGENT_ENGINES}
    captured = {}
    monkeypatch.setattr(cybermap, "create_engine", factory(engines))
    monkeypatch.setattr(cybermap, "_emit_json", lambda payload, _format: captured.update(payload=payload))

    code = await cybermap._main_async(cmd="account", engine="all", output_format="json")

    assert code == 0
    assert set(captured["payload"]) == set(AGENT_ENGINES)
    assert all(engines[name].plan_info == captured["payload"][name] for name in engines)


@pytest.mark.asyncio
async def test_one_vhost_from_three_engines_merges_into_one_row():
    """Measured reality: the engines render the same endpoint as `45.33.32.156` / `http://host:80`
    / `http://host`, and Shodan reports `tcp` where the others report `ssh`."""
    fofa = FakeEngine("fofa", [{"host": "scanme.nmap.org", "ip": "45.33.32.156", "port": 80, "protocol": "http", "icp": "X"}])
    shodan = FakeEngine(
        "shodan",
        [
            {"host": "http://scanme.nmap.org:80", "ip": "45.33.32.156", "port": 80, "protocol": "http", "server": "Apache"},
            {"host": "scanme.nmap.org:22", "ip": "45.33.32.156", "port": 22, "protocol": "tcp", "vulns": "CVE-1"},
        ],
    )
    hunter = FakeEngine(
        "hunter",
        [
            {"host": "http://scanme.nmap.org", "ip": "45.33.32.156", "port": 80, "protocol": "http", "org": "ACME"},
            {"host": "45.33.32.156:22", "ip": "45.33.32.156", "port": 22, "protocol": "ssh", "product": "OpenSSH"},
        ],
    )

    run = await MultiEngineAgent(
        ("fofa", "shodan", "hunter"),
        PlanRouter(summary=FAKE_SUMMARY),
        engine_factory=factory({"fofa": fofa, "shodan": shodan, "hunter": hunter}),
    ).run("收集 scanme.nmap.org 资产", max_records=100, smart_fields=False)

    assert len(run.assets) == 2  # one web vhost + one socket, not five rows
    assert run.result_count == 2
    rows = {int(asset["port"]): asset for asset in run.assets}
    assert rows[80]["icp"] == "X" and rows[80]["server"] == "Apache" and rows[80]["org"] == "ACME"
    # Shodan named the service by hostname and said `tcp`; Hunter named it by address and said
    # `ssh`. Same socket, so both rows merge into the address-keyed asset.
    assert rows[22]["host"] in {"45.33.32.156:22", "scanme.nmap.org:22"}
    assert rows[22]["vulns"] == "CVE-1" and rows[22]["product"] == "OpenSSH"


@pytest.mark.asyncio
async def test_distinct_virtual_hosts_on_one_endpoint_stay_distinct():
    """Several vhosts share 45.33.32.156:80 and are separate assets; only the endpoint rolls up."""
    fofa = FakeEngine(
        "fofa",
        [
            {"host": "scanme.nmap.org", "ip": "45.33.32.156", "port": 80, "protocol": "http"},
            {"host": "scanme.org", "ip": "45.33.32.156", "port": 80, "protocol": "http"},
            {"host": "http://scanme.org", "ip": "45.33.32.156", "port": 80, "protocol": "http"},  # same vhost
        ],
    )
    run = await MultiEngineAgent(
        ("fofa",), PlanRouter(summary=FAKE_SUMMARY), engine_factory=factory({"fofa": fofa})
    ).run("收集 scanme 资产", max_records=100, smart_fields=False)

    assert len(run.assets) == 2  # two vhosts, the third row is the same one again
    assert asset_endpoint_count(run.assets) == 1
    stats = _asset_briefing_stats(run)
    assert stats["unique_endpoints"] == 1
    assert stats["top_endpoints"] == [{"name": "45.33.32.156:80", "count": 2}]


@pytest.mark.asyncio
async def test_briefing_country_uses_one_iso_code_per_country():
    """FOFA answers a code, Shodan a name plus a code and Hunter a Chinese name."""
    fofa = FakeEngine("fofa", [{"host": "a.example", "ip": "1.1.1.1", "port": 80, "protocol": "http", "country": "US"}])
    shodan = FakeEngine(
        "shodan",
        [{"host": "b.example", "ip": "2.2.2.2", "port": 80, "protocol": "http", "country": "United States", "country_code": "US"}],
    )
    hunter = FakeEngine(
        "hunter",
        [{"host": "c.example", "ip": "3.3.3.3", "port": 80, "protocol": "http", "country": "美国", "country_code": "US"}],
    )

    run = await MultiEngineAgent(
        ("fofa", "shodan", "hunter"),
        PlanRouter(summary=FAKE_SUMMARY),
        engine_factory=factory({"fofa": fofa, "shodan": shodan, "hunter": hunter}),
    ).run("收集资产", max_records=100, smart_fields=False)

    assert _asset_briefing_stats(run)["top_countries"] == [{"name": "US", "count": 3}]


def test_asset_identity_normalizes_engine_specific_forms():
    """The identity contract itself: one service must key the same from every engine."""
    engine_forms = [
        {"host": "45.33.32.156", "ip": "45.33.32.156", "port": 80, "protocol": "http"},
        {"host": "scanme.nmap.org", "ip": "45.33.32.156", "port": 80, "protocol": "http"},
        {"host": "http://scanme.nmap.org", "ip": "45.33.32.156", "port": 80, "protocol": "http"},
        {"host": "http://scanme.nmap.org:80", "ip": "45.33.32.156", "port": 80, "protocol": "http"},
        {"host": "scanme.nmap.org.", "ip": "45.33.32.156", "port": "80", "protocol": "HTTP"},
    ]
    assert len({_asset_identity(row) for row in engine_forms[1:]}) == 1  # same vhost
    assert _asset_identity(engine_forms[0]) != _asset_identity(engine_forms[1])  # IP row vs vhost row
    # Non-web rows key on the address, so a hostname alias cannot split one socket in two.
    assert _asset_identity({"host": "a.example", "ip": "1.1.1.1", "port": 22, "protocol": "ssh"}) == _asset_identity(
        {"host": "1.1.1.1", "ip": "1.1.1.1", "port": 22, "protocol": "tcp"}
    )
    assert _asset_identity({"host": "a.example", "port": 443, "protocol": "https"}) != _asset_identity(
        {"host": "a.example", "port": 443, "protocol": "http"}
    )
    assert _asset_identity({"host": "[2001:db8::1]:443", "port": 443, "protocol": "https"})[1] == "2001:db8::1"


@pytest.mark.asyncio
async def test_cross_engine_corroboration_is_counted():
    """An asset two engines independently indexed is stronger evidence than one query's hit."""
    shared = {"host": "https://a.example", "ip": "1.1.1.1", "port": 443, "protocol": "https"}
    fofa = FakeEngine("fofa", [dict(shared), {"host": "https://b.example", "ip": "2.2.2.2", "port": 443, "protocol": "https"}])
    shodan = FakeEngine("shodan", [dict(shared)])

    run = await MultiEngineAgent(
        ("fofa", "shodan"), PlanRouter(summary=FAKE_SUMMARY), engine_factory=factory({"fofa": fofa, "shodan": shodan})
    ).run("收集 a.example 资产", max_records=100, smart_fields=False)

    assert run.result_count == 2
    assert run.corroboration == {"multi_engine": 1, "single_engine": 1}


def test_ipv6_hosts_keep_their_full_address_in_the_identity():
    """A bare IPv6 literal must not lose its last group to the host:port port-stripping rule."""
    from core.agent import _asset_identity, _normalize_host

    assert _normalize_host("2001:db8::1") == "2001:db8::1"
    assert _normalize_host("[2001:db8::1]:443") == "2001:db8::1"
    assert _normalize_host("example.com:443") == "example.com"
    # Two distinct addresses stay distinct, and both spellings of one address agree.
    assert _asset_identity({"host": "2001:db8::2", "port": 443, "protocol": "https"}) != _asset_identity(
        {"host": "2001:db8::3", "port": 443, "protocol": "https"}
    )
    assert _asset_identity({"host": "2001:db8::1", "port": 443, "protocol": "https"}) == _asset_identity(
        {"host": "[2001:db8::1]:443", "port": 443, "protocol": "https"}
    )


@pytest.mark.asyncio
async def test_merge_keeps_a_later_engines_value_when_the_first_engine_is_blank():
    """Engine clients emit "" for missing fields, so an empty stored value must not win."""
    fofa = FakeEngine("fofa", [{"host": "https://a.example", "ip": "1.1.1.1", "port": 443, "protocol": "https", "title": ""}])
    shodan = FakeEngine(
        "shodan",
        [
            {
                "host": "https://a.example",
                "ip": "1.1.1.1",
                "port": 443,
                "protocol": "https",
                "title": "Welcome",
                "org": "ACME University",
                "ssl_cn": "a.example",
            }
        ],
    )

    run = await MultiEngineAgent(
        ("fofa", "shodan"), PlanRouter(summary=FAKE_SUMMARY), engine_factory=factory({"fofa": fofa, "shodan": shodan})
    ).run("收集 a.example 资产", max_records=100, smart_fields=False)

    assert len(run.assets) == 1
    assert run.assets[0]["title"] == "Welcome"
    assert run.assets[0]["org"] == "ACME University"
    assert run.assets[0]["ssl_cn"] == "a.example"
