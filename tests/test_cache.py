"""Page cache: paid pages are reused, keys never collide, expiry and the kill switch behave.

The suite-wide ``settings.cache.enabled`` is False (tests/conftest.py); these tests pass an
explicit ``PageCache`` so nothing depends on the ambient configuration.
"""

import sqlite3
import time

import httpx
import pytest

from core.cache import CacheKey, PageCache, disable_cache, request_cache_key, resolve_cache
from core.client import FofaClient
from core.models import AssetRecord, SearchPage, SearchRequest
from core.shodan import ShodanClient

FOFA_PAGE = {"results": [["https://a.example"]], "fields": "host", "size": 1, "consumed_fpoint": 1}
SHODAN_MATCH = {
    "ip_str": "45.33.32.156",
    "port": 22,
    "transport": "tcp",
    "hostnames": ["scanme.nmap.org"],
    "product": "OpenSSH",
    "timestamp": "2024-01-01T00:00:00",
    "location": {"country_name": "United States", "country_code": "US"},
    "http": {},
}


def _page(query: str = 'app="nginx"', consumed: int = 1) -> SearchPage:
    return SearchPage(
        records=[AssetRecord(values={"host": "https://a.example"})],
        fields=["host"],
        total=1,
        page=1,
        consumed=consumed,
        query=query,
        metadata={"engine": "fofa"},
    )


def test_roundtrip_marks_hits_and_zeroes_consumed(tmp_path):
    cache = PageCache(tmp_path / "cache.sqlite3")
    key = CacheKey("fofa", 'app="nginx"', 1, 100, "x")

    assert cache.get(key) is None
    cache.put(key, _page())
    hit = cache.get(key)

    assert hit is not None
    assert hit.consumed == 0
    assert hit.metadata["cached"] is True
    assert hit.metadata["cached_at"] > 0
    assert hit.records[0].values == {"host": "https://a.example"}


def test_keys_are_request_specific(tmp_path):
    cache = PageCache(tmp_path / "cache.sqlite3")
    base = CacheKey("shodan", "product:nginx", 1, 100, "")
    cache.put(base, _page(query="product:nginx"))

    assert cache.get(base) is not None
    for different in (
        CacheKey("shodan", "product:nginx", 2, 100, ""),
        CacheKey("shodan", "product:apache", 1, 100, ""),
        CacheKey("shodan", "product:nginx", 1, 50, ""),
        CacheKey("shodan", "product:nginx", 1, 100, "|host,ip|0|"),
        CacheKey("hunter", "product:nginx", 1, 100, ""),
    ):
        assert cache.get(different) is None


def test_request_key_separates_page_fields_and_cursor():
    page = SearchRequest(query="q", fields=["host"], page=3)
    same = SearchRequest(query="q", fields=["host"], page=3)
    other_page = SearchRequest(query="q", fields=["host"], page=4)
    other_fields = SearchRequest(query="q", fields=["host", "ip"], page=3)
    cursor = SearchRequest(query="q", fields=["host"], cursor="abc")

    assert request_cache_key("fofa", page) == request_cache_key("fofa", same)
    assert request_cache_key("fofa", page) != request_cache_key("fofa", other_page)
    assert request_cache_key("fofa", page) != request_cache_key("fofa", other_fields)
    assert request_cache_key("fofa", page) != request_cache_key("fofa", cursor)


def test_expired_entries_are_dropped(tmp_path):
    path = tmp_path / "cache.sqlite3"
    cache = PageCache(path)
    key = CacheKey("fofa", "q", 1, 10, "")
    cache.put(key, _page(query="q"))
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE page_cache SET expires_at = ?", (time.time() - 1,))

    assert cache.get(key) is None
    assert cache.stats()["entries"] == 0


def test_clear_and_stats(tmp_path):
    cache = PageCache(tmp_path / "cache.sqlite3")
    for index in range(3):
        cache.put(CacheKey("fofa", f"q{index}", 1, 10, ""), _page(query=f"q{index}"))

    assert cache.stats()["entries"] == 3
    assert cache.clear() == 3
    assert cache.stats()["entries"] == 0


def test_resolve_cache_respects_the_enabled_switch(tmp_path, monkeypatch):
    from config import settings

    monkeypatch.setattr(settings.cache, "path", str(tmp_path / "resolved.sqlite3"))
    monkeypatch.setattr(settings.cache, "enabled", True)
    assert resolve_cache() is not None

    monkeypatch.setattr(settings.cache, "enabled", False)
    assert resolve_cache() is None
    disable_cache()
    assert resolve_cache() is None


def test_a_broken_payload_is_a_miss_not_a_crash(tmp_path):
    path = tmp_path / "cache.sqlite3"
    cache = PageCache(path)
    key = CacheKey("fofa", "q", 1, 10, "")
    cache.put(key, _page(query="q"))
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE page_cache SET payload = ?", ("{not json",))

    assert cache.get(key) is None
    assert cache.stats()["entries"] == 0


@pytest.mark.asyncio
async def test_fofa_reuses_a_cached_page_without_calling_the_api(tmp_path):
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request):
        calls.append(request)
        return httpx.Response(200, json=FOFA_PAGE)

    cache = PageCache(tmp_path / "cache.sqlite3")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=1000, cache=cache)
        request = SearchRequest(query='app="nginx"', fields=["host"], page=1)
        first = await client.search_page(request)
        second = await client.search_page(request)
        third = await client.search_page(request.model_copy(update={"page": 2}))

    assert len(calls) == 2  # page 1 fetched once, page 2 fetched once
    assert first.consumed == 1
    assert second.consumed == 0
    assert second.metadata["cached"] is True
    assert third.consumed == 1
    assert not third.metadata.get("cached")


@pytest.mark.asyncio
async def test_fofa_cache_is_disabled_when_no_cache_is_passed(tmp_path):
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request):
        calls.append(request)
        return httpx.Response(200, json=FOFA_PAGE)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = FofaClient(api_key="test", client=http, requests_per_second=1000, cache=None)
        request = SearchRequest(query='app="nginx"', fields=["host"], page=1)
        await client.search_page(request)
        await client.search_page(request)

    assert len(calls) == 2
    assert client.cache is None


@pytest.mark.asyncio
async def test_shodan_cache_hit_skips_credit_preflight(tmp_path):
    calls: list[str] = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path == "/shodan/host/search":
            return httpx.Response(200, json={"matches": [SHODAN_MATCH], "total": 1})
        return httpx.Response(200, json={"plan": "dev", "query_credits": 100})

    cache = PageCache(tmp_path / "cache.sqlite3")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = ShodanClient(api_key="k", client=http, requests_per_second=1000, cache=cache)
        request = SearchRequest(query="product:OpenSSH", fields=["ip", "port"], page=1)
        first = await client.search_page(request)
        # An exhausted balance must not turn a cached page into a quota error.
        client.plan_info = {"plan": "dev", "query_credits": 0}
        second = await client.search_page(request)

    assert calls.count("/shodan/host/search") == 1
    assert first.consumed == 1
    assert second.consumed == 0
    assert second.metadata["cached"] is True
