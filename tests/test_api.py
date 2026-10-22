from fastapi.testclient import TestClient

from core.models import SearchPage
from service import api
from service.api import app


def test_openapi_and_fields_endpoint():
    with TestClient(app) as client:
        openapi = client.get("/openapi.json")
        assert openapi.status_code == 200
        assert openapi.json()["info"]["version"] == "2.0.1"
        response = client.get("/v1/fields")
        assert response.status_code == 200
        assert "host" in response.json()["base"]
        assert "longitude" in response.json()["base"]
        assert "status_code" in response.json()["compat"]
        assert "fid" in response.json()["tiers"]["enterprise"]
        assert response.json()["membership_source"] == "https://fofa.info/api"
        education = next(item for item in response.json()["memberships"] if item["vip_level"] == 22)
        assert education["field_tier"] == "personal"
        assert education["stats_api"] is False


def test_shodan_routes_are_published():
    with TestClient(app) as client:
        paths = client.get("/openapi.json").json()["paths"]

    assert "/v1/shodan/account" in paths
    assert "/v1/shodan/search" in paths
    assert "/v1/shodan/hosts/{host}" in paths
    assert "/v1/shodan/stats" in paths


def test_hunter_routes_are_published():
    with TestClient(app) as client:
        paths = client.get("/openapi.json").json()["paths"]

    assert "/v1/hunter/account" in paths
    assert "/v1/hunter/search" in paths
    assert "/v1/hunter/hosts/{host}" in paths
    # Hunter's open API has no aggregation endpoint, so no stats route may be published.
    assert "/v1/hunter/stats" not in paths


def test_agent_run_route_uses_the_selected_engine(monkeypatch):
    from core.agent import AgentRun, AgentState

    captured = {}

    class FakeEngine:
        name = "shodan"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

    class FakeRegistry:
        def __init__(self, *_args, **_kwargs):
            pass

        async def aclose(self):
            return None

    class FakeRouter:
        def __init__(self, _registry):
            self.events = []

    class FakeAgent:
        def __init__(self, client, _router):
            captured["client"] = client

        async def run(self, intent, **_kwargs):
            return AgentRun(intent=intent, engine="shodan", state=AgentState.COMPLETED)

    monkeypatch.setattr(api, "create_engine", lambda name=None: captured.update(engine=name) or FakeEngine())
    monkeypatch.setattr(api, "AssetAgent", FakeAgent)
    monkeypatch.setattr(api, "ProviderRegistry", FakeRegistry)
    monkeypatch.setattr(api, "ProviderRouter", FakeRouter)

    with TestClient(app) as client:
        response = client.post("/v1/agent/runs", json={"intent": "收集资产", "engine": "shodan"})

    assert response.status_code == 200
    assert captured["engine"] == "shodan"
    assert response.json()["run"]["engine"] == "shodan"


def test_agent_run_route_merges_every_engine(monkeypatch):
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

    monkeypatch.setattr(api, "MultiEngineAgent", FakeMulti)
    monkeypatch.setattr(api, "ProviderRegistry", FakeRegistry)
    monkeypatch.setattr(api, "ProviderRouter", FakeRouter)

    with TestClient(app) as client:
        response = client.post("/v1/agent/runs", json={"intent": "收集资产", "engine": "all"})

    assert response.status_code == 200
    from core.engines import AGENT_ENGINES

    assert captured["engines"] == AGENT_ENGINES
    assert "daydaymap" in captured["engines"]
    assert response.json()["run"]["engine"] == "all"
    # The route must hand the production factory over, not a stub: build one engine through it.
    # Construction is enough (the HTTP client is created lazily), so no event loop is needed here.
    assert captured["factory"]("hunter").name == "hunter"


def test_shodan_search_route_uses_the_shodan_client_and_rejects_cursors(monkeypatch):
    captured = {}

    class FakeShodan:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def search_page(self, request):
            captured["request"] = request
            return SearchPage(records=[], fields=request.fields, query=request.query, page=request.page)

    monkeypatch.setattr(api, "ShodanClient", FakeShodan)
    with TestClient(app) as client:
        response = client.post("/v1/shodan/search", json={"query": "product:nginx", "fields": ["ip", "port"], "page": 2})
        rejected = client.post("/v1/shodan/search", json={"query": "product:nginx", "fields": ["ip"], "cursor": "opaque"})

    assert response.status_code == 200
    assert captured["request"].page == 2
    assert captured["request"].query == "product:nginx"
    assert rejected.status_code == 422
    assert "cursor" in rejected.json()["detail"]


def test_unauthenticated_service_is_loopback_only(monkeypatch):
    """The env var describes the intended bind address; the arriving connection is what counts."""
    monkeypatch.delenv("CYBERMAP_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("CYBERMAP_BIND_HOST", raising=False)

    with TestClient(app) as local:
        assert local.get("/v1/fields").status_code == 200
    with TestClient(app, client=("203.0.113.9", 51000)) as remote:
        assert remote.get("/v1/fields").status_code == 503
        assert remote.get("/v1/account").status_code == 503
    # A configured token works from anywhere.
    monkeypatch.setenv("CYBERMAP_SERVICE_TOKEN", "s3cret")
    with TestClient(app, client=("203.0.113.9", 51000)) as remote_token:
        assert remote_token.get("/v1/fields", headers={"Authorization": "Bearer s3cret"}).status_code == 200
