"""Optional real-provider smoke tests; never enabled in normal CI."""

from __future__ import annotations

import os

import pytest

from config import settings
from core.agent import AgentState, AssetAgent
from core.censys import CensysClient
from core.client import FofaClient
from core.daydaymap import DaydaymapClient
from core.models import SearchRequest
from providers.registry import ProviderRegistry, ProviderRouter

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.getenv("CYBERMAP_RUN_LIVE_TESTS") != "true", reason="real API smoke tests are opt-in"),
]


@pytest.mark.asyncio
async def test_live_fofa_account_and_one_record_search():
    async with FofaClient(max_retries=1, requests_per_second=10) as client:
        account = await client.account()
        assert account
        page = await client.search_page(
            SearchRequest(
                query='domain="harvard.edu"',
                fields=["host", "status_code"],
                size=1,
                max_records=1,
                max_pages=1,
                continuous=True,
            )
        )
    assert page.fields == ["host", "status_code"]
    assert len(page.records) <= 1


@pytest.mark.asyncio
async def test_live_daydaymap_one_page():
    """One real query; the API reports no points, so the assertion is on the mapped shape."""
    async with DaydaymapClient(max_retries=1, requests_per_second=5) as client:
        page = await client.search_page(
            SearchRequest(query='cert="daydaymap.com"', fields=["host", "ip", "port", "title"], size=2)
        )
    assert page.fields == ["host", "ip", "port", "title"]
    assert page.records
    assert all(record.values.get("ip") for record in page.records)
    assert page.consumed is None


@pytest.mark.asyncio
async def test_live_censys_balance_and_one_host_profile(monkeypatch):
    """Free balance is free; the host profile costs 1 credit unless the page cache already has it."""
    # The opt-in smoke run uses the user's real configuration, so keep the cache enabled.
    monkeypatch.setenv("CYBERMAP_CACHE_TTL_HOURS", "24")
    async with CensysClient(max_retries=1, requests_per_second=10) as client:
        account = await client.account()
        assert isinstance(account["balance"], int)
        profile = await client.host_profile("1.1.1.1")
    assert profile["ip"] == "1.1.1.1"
    assert profile["source"] == "censys"
    assert isinstance(profile["ports"], list) and profile["ports"]
    assert profile["cached"] in {True, False}


@pytest.mark.asyncio
async def test_live_model_and_agent_without_scan():
    registry = ProviderRegistry(settings, execution_mode="interactive")
    try:
        async with FofaClient(max_retries=1, requests_per_second=10) as client:
            run = await AssetAgent(client, ProviderRouter(registry)).run(
                "查找美国哈佛大学公开网站资产，不要扫描",
                max_records=1,
                max_pages=1,
            )
    finally:
        await registry.aclose()
    assert run.state is AgentState.COMPLETED, run.error
    assert run.error is None
    assert run.result_count <= 1
    assert run.summary
    assert run.scan_requested_by_user is False
    assert run.scan_artifact is None
