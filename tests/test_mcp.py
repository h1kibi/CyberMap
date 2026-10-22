import pytest
from mcp import Client

import mcp_server
from mcp_server import mcp


@pytest.mark.asyncio
async def test_mcp_v2_structured_schema_and_annotations():
    async with Client(mcp) as client:
        tools = await client.list_tools()
        by_name = {tool.name: tool for tool in tools.tools}
        assert "fofa_search" in by_name
        assert "fofa_syntax" in by_name
        assert "fofa_rules" in by_name
        assert "fofa_fields" in by_name
        assert "fofa_account" in by_name
        assert "fofa_icon_search" in by_name
        assert "shodan_search" in by_name
        assert "shodan_host_profile" in by_name
        assert "shodan_stats" in by_name
        assert "shodan_account" in by_name
        assert "hunter_search" in by_name
        assert "hunter_host_profile" in by_name
        assert "hunter_account" in by_name
        # Hunter has no aggregation endpoint, so no such tool may be published.
        assert "hunter_stats" not in by_name
        assert by_name["shodan_search"].output_schema["type"] == "object"
        assert by_name["shodan_search"].annotations.read_only_hint is True
        assert "engine" in by_name["fofa_agent_run"].input_schema["properties"]
        assert by_name["fofa_search"].output_schema["type"] == "object"
        assert by_name["fofa_search"].annotations.read_only_hint is True
        assert by_name["nuclei_execute"].annotations.destructive_hint is True
        result = await client.call_tool("fofa_validate_query", {"query": 'app="nginx"'})
        assert result.structured_content["data"]["valid"] is True
        invalid = await client.call_tool("shodan_validate_query", {"query": 'app="nginx" && country="CN"'})
        assert invalid.structured_content["data"]["valid"] is False
        assert invalid.structured_content["data"]["errors"]
        valid = await client.call_tool("shodan_validate_query", {"query": "product:nginx country:CN"})
        assert valid.structured_content["data"]["valid"] is True
        shodan_syntax = await client.call_tool("hunter_validate_query", {"query": "product:nginx"})
        assert shodan_syntax.structured_content["data"]["valid"] is False
        hunter_syntax = await client.call_tool("hunter_validate_query", {"query": 'web.title="登录" && country="中国"'})
        assert hunter_syntax.structured_content["data"]["valid"] is True
        assert result.content
        syntax = await client.call_tool("fofa_syntax", {})
        assert syntax.structured_content["data"]["source"] == "https://fofa.info/api/introd"
        fields = await client.call_tool("fofa_fields", {})
        assert fields.structured_content["data"]["memberships"]
        rules = await client.call_tool("fofa_rules", {"keyword": "ThinkPHP"})
        assert rules.structured_content["data"]["count"] >= 1
        resources = await client.list_resources()
        uris = {str(resource.uri) for resource in resources.resources}
        assert "cybermap://shodan/account" in uris
        assert "cybermap://hunter/account" in uris


@pytest.mark.asyncio
async def test_shodan_search_tool_forwards_paging_and_reports_credits(monkeypatch):
    from core.models import AssetRecord, SearchPage

    captured = {}

    class FakeShodan:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def search_page(self, request):
            captured["request"] = request
            return SearchPage(
                query=request.query,
                records=[AssetRecord(values={"ip": "1.1.1.1"})],
                fields=list(request.fields),
                page=request.page,
                total=5,
                consumed=1,
            )

    monkeypatch.setattr(mcp_server, "ShodanClient", FakeShodan)
    async with Client(mcp) as client:
        result = await client.call_tool("shodan_search", {"query": "product:nginx", "fields": ["ip"], "page": 3})

    assert captured["request"].page == 3
    assert captured["request"].query == "product:nginx"
    assert list(captured["request"].fields) == ["ip"]
    assert result.structured_content["consumed"] == 1
    assert result.structured_content["total"] == 5
    assert result.structured_content["next_cursor"] is None
    assert "page=4" in result.structured_content["summary"]


@pytest.mark.asyncio
async def test_agent_tool_merges_every_engine(monkeypatch):
    from core.agent import AgentRun, AgentState

    captured = {}

    class FakeMulti:
        def __init__(self, engines, _router, *, engine_factory=None):
            captured["engines"] = engines
            captured["factory"] = engine_factory

        async def run(self, intent, **_kwargs):
            return AgentRun(intent=intent, engine="all", state=AgentState.COMPLETED, summary="all")

    class FakeRegistry:
        def __init__(self, *_args, **_kwargs):
            pass

        async def aclose(self):
            return None

    class FakeRouter:
        def __init__(self, _registry):
            self.events = []

    monkeypatch.setattr(mcp_server, "MultiEngineAgent", FakeMulti)
    monkeypatch.setattr(mcp_server, "ProviderRegistry", FakeRegistry)
    monkeypatch.setattr(mcp_server, "ProviderRouter", FakeRouter)

    async with Client(mcp) as client:
        result = await client.call_tool("fofa_agent_run", {"intent": "收集资产", "engine": "all"})

    from core.engines import AGENT_ENGINES

    assert captured["engines"] == AGENT_ENGINES
    assert "daydaymap" in captured["engines"]
    assert result.structured_content["data"]["engine"] == "all"
    async with captured["factory"]("hunter") as client_for_hunter:
        assert client_for_hunter.name == "hunter"


@pytest.mark.asyncio
async def test_agent_tool_runs_against_the_requested_engine(monkeypatch):
    from core.agent import AgentRun, AgentState

    captured = {}

    class FakeEngine:
        name = "shodan"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

    class FakeAgent:
        def __init__(self, client, _router):
            captured["client"] = client

        async def run(self, intent, **_kwargs):
            return AgentRun(intent=intent, engine="shodan", state=AgentState.COMPLETED, summary="ok")

    class FakeRegistry:
        def __init__(self, *_args, **_kwargs):
            pass

        async def aclose(self):
            return None

    class FakeRouter:
        def __init__(self, _registry):
            self.events = []

    monkeypatch.setattr(mcp_server, "create_engine", lambda name=None: captured.update(engine=name) or FakeEngine())
    monkeypatch.setattr(mcp_server, "AssetAgent", FakeAgent)
    monkeypatch.setattr(mcp_server, "ProviderRegistry", FakeRegistry)
    monkeypatch.setattr(mcp_server, "ProviderRouter", FakeRouter)

    async with Client(mcp) as client:
        result = await client.call_tool("fofa_agent_run", {"intent": "收集资产", "engine": "shodan"})

    assert captured["engine"] == "shodan"
    assert captured["client"].name == "shodan"
    assert result.structured_content["data"]["engine"] == "shodan"
