"""Asset search engine selection shared by the CLI, REST and MCP entry points.

Every engine exposes the same asset contracts (`SearchRequest` -> `SearchPage`), so
surfaces stay engine-agnostic and only the engine-specific syntax lives behind the
registry. Executable code lives in `core/client.py` (FOFA), `core/shodan.py` and
`core/hunter.py`; per-engine agent knowledge lives in `core/agent_profiles.py`.

The three engines are complementary on purpose:

- FOFA owns fingerprinting and ICP filing lookups (free account/stats APIs);
- Shodan owns service banners, CVE lists and dated history;
- Hunter owns Chinese-language asset metadata (components, asset tags, filing exceptions)
  and MD5-favicon pivoting, but has no aggregation endpoint and bills per returned record.
- DayDayMap owns Chinese fingerprint/ICP-oriented metadata, FOFA-like syntax and a very large
  per-page limit (10000), with no balance or aggregation endpoint on the open API;
- Censys (Platform v3) owns deep host profiles: services, endpoints with HTTP/TLS detail,
  whois/ASN/DNS. Its Free plan exposes entity lookups only, so it joins host-profile runs and
  IP entity lookups but not the agent's list-search fan-out.

A merged run therefore keeps one column per concept: `merge_aliases` renames the few
engine-native names that mean something the unified vocabulary already names.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol

from core.cache import PageCache
from core.models import FofaError, FofaErrorCode, IconDigest, SearchPage, SearchRequest

ENGINE_NAMES: tuple[str, ...] = ("fofa", "shodan", "hunter", "daydaymap", "censys")
ENGINE_LABELS = {
    "fofa": "FOFA",
    "shodan": "Shodan",
    "hunter": "Hunter",
    "daydaymap": "DayDayMap",
    "censys": "Censys",
}
# List-search engines the agent can fan out over. Censys Free has no search API (403
# "requires an organization ID"), so it is selectable for host profiles/IP lookups only.
AGENT_ENGINES: tuple[str, ...] = ("fofa", "shodan", "hunter", "daydaymap")
# Agent-only scope: run every agent engine and merge the results into one briefing.
MULTI_ENGINE = "all"
# Engine-native response field -> unified name, applied when engines are merged so one concept
# keeps one column. Shodan and Hunter already answer in unified names.
MERGE_ALIASES: dict[str, dict[str, str]] = {
    "fofa": {"country": "country_code", "cert.subject.cn": "ssl_cn", "lastupdatetime": "timestamp"},
    "shodan": {},
    "hunter": {},
    "daydaymap": {},
    "censys": {},
}
# Engine-native "last time this engine confirmed the asset" column. FOFA exposes it as
# `lastupdatetime` (professional tier and above), Shodan as the banner `timestamp` and Hunter as
# `updated_at`; all three are mapped onto the unified `timestamp`.
TIMESTAMP_FIELDS: dict[str, str] = {
    "fofa": "lastupdatetime",
    "shodan": "timestamp",
    "hunter": "timestamp",
    "daydaymap": "timestamp",
    "censys": "timestamp",
}


def normalize_engine_scope(name: str | None) -> tuple[str, ...]:
    """Return the engines to run: one for classic queries, all for an agent fan-out."""
    scope = (name or "fofa").strip().lower()
    if scope == MULTI_ENGINE:
        return AGENT_ENGINES
    return (normalize_engine(scope),)


class AssetSearchEngine(Protocol):
    name: str

    async def __aenter__(self) -> AssetSearchEngine: ...

    async def __aexit__(self, *_: object) -> None: ...

    async def aclose(self) -> None: ...

    async def search_page(self, request: SearchRequest) -> SearchPage: ...

    def iter_search(self, request: SearchRequest) -> AsyncIterator[SearchPage]: ...

    async def host_profile(self, host: str, *, detail: bool = True) -> dict[str, Any]: ...

    async def account(self) -> dict[str, Any]: ...

    async def stats(self, query: str, fields: list[str], size: int = 5) -> dict[str, Any]: ...


def normalize_engine(name: str | None) -> str:
    engine = (name or "fofa").strip().lower()
    if engine not in ENGINE_NAMES:
        raise FofaError(
            FofaErrorCode.INVALID_QUERY,
            f"未知的搜索引擎：{name}",
            alternatives=list(ENGINE_NAMES),
        )
    return engine


def create_engine(name: str | None = None, *, cache: PageCache | None | bool = True) -> AssetSearchEngine:
    """Build a fresh engine client; callers own its lifecycle (`async with`).

    `cache=True` resolves the configured page cache, `None`/`False` disables it.
    """
    engine = normalize_engine(name)
    if engine == "shodan":
        from core.shodan import ShodanClient

        return ShodanClient(cache=cache)
    if engine == "hunter":
        from core.hunter import HunterClient

        return HunterClient(cache=cache)
    if engine == "daydaymap":
        from core.daydaymap import DaydaymapClient

        return DaydaymapClient(cache=cache)
    if engine == "censys":
        from core.censys import CensysClient

        return CensysClient(cache=cache)
    from core.client import FofaClient

    return FofaClient(cache=cache)


def engine_label(name: str | None) -> str:
    """Human label for a single engine or the merged multi-engine scope."""
    scope = (name or "fofa").strip().lower()
    if scope in ENGINE_LABELS:
        return ENGINE_LABELS[scope]
    if scope == MULTI_ENGINE:
        return " + ".join(ENGINE_LABELS[engine] for engine in AGENT_ENGINES)
    return ENGINE_LABELS[normalize_engine(scope)]


def merge_aliases(engine: str) -> dict[str, str]:
    """Field renames applied to one engine's rows before a merged run stores them."""
    return MERGE_ALIASES.get(normalize_engine(engine), {})


def timestamp_field(engine: str) -> str:
    """Engine-native column holding the last time the engine confirmed the asset."""
    return TIMESTAMP_FIELDS[normalize_engine(engine)]


def supported_fields(engine: str) -> tuple[str, ...] | None:
    """Fields an engine can return; `None` means it filters internally (FOFA does).

    This lets a configured field list belonging to the default engine be adapted instead of
    aborting a run on an engine that cannot return those columns.
    """
    resolved = normalize_engine(engine)
    if resolved == "shodan":
        from core.shodan import SHODAN_FIELDS

        return SHODAN_FIELDS
    if resolved == "hunter":
        from core.hunter import HUNTER_FIELDS

        return HUNTER_FIELDS
    if resolved == "daydaymap":
        from core.daydaymap import DAYDAYMAP_FIELDS

        return DAYDAYMAP_FIELDS
    if resolved == "censys":
        from core.censys import CENSYS_FIELDS

        return CENSYS_FIELDS
    return None


def default_fields(engine: str) -> tuple[str, ...]:
    """Fields an engine returns when nothing else is configured."""
    resolved = normalize_engine(engine)
    if resolved == "shodan":
        from core.shodan import DEFAULT_OUTPUT_FIELDS as shodan_defaults

        return shodan_defaults
    if resolved == "hunter":
        from core.hunter import DEFAULT_OUTPUT_FIELDS as hunter_defaults

        return hunter_defaults
    if resolved == "daydaymap":
        from core.daydaymap import DEFAULT_OUTPUT_FIELDS as daydaymap_defaults

        return daydaymap_defaults
    if resolved == "censys":
        from core.censys import DEFAULT_OUTPUT_FIELDS as censys_defaults

        return censys_defaults
    # FOFA keeps the configured field list (its client filters unsupported columns itself); this
    # is only the fallback, matching the SearchConfig default.
    return ("host", "protocol", "ip", "port", "title", "domain", "country")


def favicon_query(engine: str, digest: IconDigest) -> str:
    """MurmurHash3 favicon filter (FOFA/Shodan) or MD5 filter (Hunter) in native syntax."""
    resolved = normalize_engine(engine)
    if resolved == "shodan":
        from core.shodan import favicon_query as shodan_favicon_query

        return shodan_favicon_query(digest.murmur3)
    if resolved == "hunter":
        from core.hunter import favicon_query as hunter_favicon_query

        return hunter_favicon_query(digest.md5)
    if resolved == "daydaymap":
        raise FofaError(
            FofaErrorCode.UNSUPPORTED,
            "DayDayMap 的 icon_md5 字段不支持搜索，无法做图标反查；请使用 FOFA、Shodan 或 Hunter。",
            alternatives=["-e fofa --icon <URL 或文件>", "-e hunter --icon <URL 或文件>"],
        )
    if resolved == "censys":
        raise FofaError(
            FofaErrorCode.UNSUPPORTED,
            "Censys 不提供图标指纹过滤；图标反查请使用 FOFA、Shodan 或 Hunter。",
            alternatives=["-e fofa --icon <URL 或文件>", "-e shodan --icon <URL 或文件>"],
        )
    return f'icon_hash="{digest.murmur3}"'
