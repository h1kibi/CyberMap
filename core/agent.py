"""Recoverable deterministic workflow agent; the LLM plans and summarizes only."""

from __future__ import annotations

import inspect
import json
import re
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence
from enum import Enum
from typing import Any, Literal

from opentelemetry import trace
from pydantic import BaseModel, Field

from core.agent_profiles import (
    ORGANIZATION_INTENT_PATTERN,
    AgentProfile,
    agent_profile,
    briefing_system,
    intent_context,
    user_authorized_scan,
)
from core.engines import MULTI_ENGINE, AssetSearchEngine, create_engine, engine_label, merge_aliases
from core.hosting import hosting_provider
from core.models import FofaError, SearchPage, SearchRequest, validate_query
from core.playbooks import collection_steps, derived_pivots
from core.rules import match_intent_rules
from core.scans import align_scan_severities, default_nuclei_template_ids, nuclei_id_allowlist
from providers.base import ProviderError
from providers.registry import ProviderRouter
from utils.logger import logger


class AgentState(str, Enum):
    INTENT = "intent_parsing"
    VALIDATE = "query_validation"
    EXECUTE = "execute"
    EVALUATE = "evaluate"
    REFLECT = "reflect"
    REPAIR = "query_repair"
    SUMMARIZE = "summarize"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentAction(str, Enum):
    SEARCH = "fofa_search"
    SHODAN_SEARCH = "shodan_search"
    HUNTER_SEARCH = "hunter_search"
    DAYDAYMAP_SEARCH = "daydaymap_search"
    MULTI_SEARCH = "all_search"
    HOST = "host_query"
    STATS = "stat_query"
    ICON = "icon_query"


# List-search actions are engine-specific; every other stage treats them identically.
SEARCH_ACTIONS = frozenset(
    {
        AgentAction.SEARCH,
        AgentAction.SHODAN_SEARCH,
        AgentAction.HUNTER_SEARCH,
        AgentAction.DAYDAYMAP_SEARCH,
        AgentAction.MULTI_SEARCH,
    }
)


class AgentStep(BaseModel):
    state: AgentState
    detail: str
    data: dict[str, Any] = Field(default_factory=dict)


class AgentQuery(BaseModel):
    query: str
    purpose: str = ""
    strategy: str = "balanced"
    source: str = "planner"
    available_count: int | None = None
    result_count: int = 0
    new_assets: int = 0
    pages: int = 0


class WebsiteCandidate(BaseModel):
    """A website surfaced by the active search engine, with explicit attribution confidence."""

    domain: str
    url: str
    status: Literal["corroborated", "observed", "candidate"]
    confidence: Literal["high", "medium", "low"]
    evidence: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)


class AgentRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    intent: str
    engine: str = "fofa"
    action: AgentAction = AgentAction.SEARCH
    target: str | None = None
    stats_fields: list[str] = Field(default_factory=list)
    result_data: dict[str, Any] = Field(default_factory=dict)
    state: AgentState = AgentState.INTENT
    steps: list[AgentStep] = Field(default_factory=list)
    query: str | None = None
    queries: list[AgentQuery] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    result_count: int = 0
    assets: list[dict[str, Any]] = Field(default_factory=list)
    assets_truncated: bool = False
    asset_confidence: list[str] = Field(default_factory=list)
    evidence_counts: dict[str, int] = Field(default_factory=dict)
    organization_names: list[str] = Field(default_factory=list)
    domain_hypotheses: list[str] = Field(default_factory=list)
    website_candidates: list[WebsiteCandidate] = Field(default_factory=list)
    reflection_rounds: int = 0
    reflection_notes: list[str] = Field(default_factory=list)
    stop_reason: str = ""
    engine_errors: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # Freshness filter outcome: rows dropped as stale and rows kept without a timestamp.
    age_filter: dict[str, int] = Field(default_factory=dict)
    # How many merged assets were seen by more than one engine (cross-engine corroboration).
    corroboration: dict[str, int] = Field(default_factory=dict)
    summary: str | None = None
    scan_requested_by_user: bool = False
    scan_recommended: bool = False
    scan_reason: str = ""
    scan_template_ids: list[str] = Field(default_factory=list)
    scan_severities: list[str] = Field(default_factory=lambda: ["medium", "high", "critical"])
    scan_targets: list[str] = Field(default_factory=list)
    scan_artifact: str | None = None
    report_artifact: str | None = None
    error: dict[str, Any] | None = None
    route_events: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def scan_ready(self) -> bool:
        return bool(
            self.scan_requested_by_user and self.scan_recommended and self.scan_targets and self.scan_template_ids and self.error is None
        )


AgentProgressCallback = Callable[[AgentRun, AgentStep], None]
AgentPageCallback = Callable[[AgentRun, SearchPage, int], None | Awaitable[None]]
# Human-facing Agent runs keep every returned asset for small/medium result sets.
# Only larger runs are capped so terminal, JSON and report payloads stay bounded.
ASSET_PREVIEW_LIMIT = 500
MAX_QUERY_VARIANTS = 8
INITIAL_QUERY_VARIANTS = 5
MAX_REFLECTION_ROUNDS = 2
MAX_REFLECTION_ADDITIONS = 2
EVIDENCE_RANK = {"recall": 1, "hypothesis": 2, "balanced": 3, "precision": 4}


def _record_step(
    run: AgentRun,
    state: AgentState,
    detail: str,
    *,
    data: dict[str, Any] | None = None,
    on_progress: AgentProgressCallback | None = None,
) -> None:
    run.state = state
    step = AgentStep(state=state, detail=detail, data=data or {})
    run.steps.append(step)
    if on_progress:
        # Presentation observers must never be able to abort an engine run.
        try:
            on_progress(run, step)
        except Exception as exc:
            logger.warning(f"Agent progress observer failed: {exc}")


def _record_page(
    run: AgentRun,
    page: SearchPage,
    page_number: int,
    *,
    strategy: str,
) -> None:
    run.result_count += len(page.records)
    for record in page.records:
        if len(run.assets) < ASSET_PREVIEW_LIMIT:
            run.assets.append(record.values)
            run.asset_confidence.append(strategy)
            continue
        weakest_rank = min(EVIDENCE_RANK.get(value, 1) for value in run.asset_confidence)
        if EVIDENCE_RANK.get(strategy, 1) <= weakest_rank:
            continue
        # Replace the latest weakest candidate so later high-quality strategies
        # cannot be hidden merely because a broad recall query arrived first.
        replace_at = max(
            index
            for index, value in enumerate(run.asset_confidence)
            if EVIDENCE_RANK.get(value, 1) == weakest_rank
        )
        run.assets[replace_at] = record.values
        run.asset_confidence[replace_at] = strategy
    if run.result_count > len(run.assets):
        run.assets_truncated = True


async def _notify_page(
    on_page: AgentPageCallback | None,
    run: AgentRun,
    page: SearchPage,
    page_number: int,
) -> None:
    if not on_page:
        return
    try:
        result = on_page(run, page, page_number)
        if inspect.isawaitable(result):
            await result
    except Exception as exc:
        logger.warning(f"Agent page observer failed: {exc}")


ENTITY_RESOLUTION_SCHEMA = {
    "type": "object",
    "properties": {
        "organization_names": {"type": "array", "maxItems": 6, "items": {"type": "string"}},
        "domains": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "properties": {"domain": {"type": "string"}, "reason": {"type": "string"}},
                "required": ["domain", "reason"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["organization_names", "domains"],
    "additionalProperties": False,
}

QUERY_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "fields": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["query", "fields"],
    "additionalProperties": False,
}

REFLECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "observation": {"type": "string"},
        "coverage_sufficient": {"type": "boolean"},
        "queries": {
            "type": "array",
            "maxItems": MAX_REFLECTION_ADDITIONS,
            "items": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "purpose": {"type": "string"},
                    "strategy": {"type": "string", "enum": ["precision", "balanced", "recall"]},
                },
                "required": ["query", "purpose", "strategy"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["observation", "coverage_sufficient", "queries"],
    "additionalProperties": False,
}

SAFE_TEMPLATE_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
WEBSITE_INTENT_PATTERN = re.compile(
    r"(?:网站|官网|域名|站点|子域名|资产|暴露面|websites?|domains?|sites?|subdomains?|assets?|recon|attack surface)",
    re.IGNORECASE,
)


def _scan_template_ids_for_intent(intent: str, suggested: list[str]) -> list[str]:
    """Apply the bounded default profile unless the user named exact template IDs."""
    allowlist = nuclei_id_allowlist()
    normalized = list(dict.fromkeys(item for item in suggested if item in allowlist))
    lowered = intent.lower()
    explicit = [item for item in allowlist if item.lower() in lowered]
    if explicit:
        return [item for item in default_nuclei_template_ids() if item in explicit] + sorted(
            item for item in explicit if item not in default_nuclei_template_ids()
        )
    return list(dict.fromkeys([*default_nuclei_template_ids(), *normalized]))[:100]


def _scan_target(values: dict[str, Any]) -> str | None:
    host = str(values.get("host") or "").strip()
    if host.startswith(("http://", "https://")):
        return host
    if not host:
        ip = values.get("ip")
        if not ip:
            return None
        port = values.get("port")
        host = f"{ip}:{port}" if port else str(ip)
    protocol = str(values.get("protocol") or "http").lower()
    family = _protocol_family(protocol)
    if family == "other":
        # SSH/RDP/database ports are not HTTP: asserting a scheme would feed Nuclei a URL it can
        # never match, while a bare `host:port` lets it probe http(s) itself and lets network
        # templates match. Verified against the local Nuclei build: bare `127.0.0.1:12345` is
        # accepted and probed.
        return host
    scheme = "https" if family == "https" or str(values.get("port")) in {"443", "8443"} else "http"
    return f"{scheme}://{host}"


def _query_candidates(plan: dict[str, Any], *, source: str, limit: int) -> list[AgentQuery]:
    raw_candidates = plan.get("queries") if isinstance(plan.get("queries"), list) else []
    if not raw_candidates and plan.get("query"):
        raw_candidates = [{"query": plan["query"], "purpose": "主查询"}]
    candidates: list[AgentQuery] = []
    seen: set[str] = set()
    for item in raw_candidates:
        if not isinstance(item, dict):
            continue
        query = str(item.get("query") or "").strip()
        if not query or query in seen:
            continue
        seen.add(query)
        candidates.append(
            AgentQuery(
                query=query,
                purpose=str(item.get("purpose") or "补充资产维度"),
                strategy=str(item.get("strategy") or "balanced"),
                source=source,
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


def _inject_derived_pivots(
    run: AgentRun,
    profile: AgentProfile,
    *,
    on_progress: AgentProgressCallback | None = None,
) -> list[AgentQuery]:
    """Add pivots derived from what the first batch found (filing, certificate, netblock, domain).

    The planner works from the user's wording only; a run's own results carry new seeds, and they
    are the cheapest recall available. Everything stays bounded (`MAX_DERIVED_PIVOTS`) and labelled
    `source="pivot"` with the tier the pivot deserves, and rows sitting on a hosting/CDN provider
    are not used as seeds.
    """
    existing = [item.query for item in run.queries]
    steps = derived_pivots(profile.engine, run.assets, existing=existing)
    if not steps:
        return []
    added = [
        AgentQuery(query=step.query, purpose=step.purpose, strategy=step.strategy, source="pivot")
        for step in steps
    ]
    run.queries.extend(added)
    _record_step(
        run,
        AgentState.INTENT,
        f"已按首轮结果派生 {len(added)} 条补充枢轴（备案号 / 证书 / 网段 / 域名）",
        data={"queries": [item.query for item in added], "pivots": [item.purpose for item in added]},
        on_progress=on_progress,
    )
    return added


def _inject_playbook_queries(
    run: AgentRun,
    profile: AgentProfile,
    intent: str,
    *,
    on_progress: AgentProgressCallback | None = None,
) -> None:
    """Add the bounded, engine-native pivots the bundle knows for the user's own signals.

    `min_evidence` and the query budget still apply, so an injected pivot competes for the same
    record budget as the planner's own strategies, and every added query carries
    `source="playbook"` with the evidence tier it deserves.
    """
    context = intent_context(intent)
    matched = match_intent_rules(intent, limit=1)
    steps = collection_steps(
        profile.engine,
        domain=context.domain,
        product=matched[0].name if matched else None,
        organization=context.organization,
        existing=[item.query for item in run.queries],
    )
    if not steps:
        return
    run.queries.extend(
        AgentQuery(query=step.query, purpose=step.purpose, strategy=step.strategy, source="playbook") for step in steps
    )
    _record_step(
        run,
        AgentState.INTENT,
        f"已按内置信息收集剧本补充 {len(steps)} 条定向查询",
        data={"queries": [step.query for step in steps], "pivots": [step.purpose for step in steps]},
        on_progress=on_progress,
    )


def _merge_library_queries(
    profile: AgentProfile,
    intent: str,
    queries: list[AgentQuery],
    *,
    limit: int,
) -> list[AgentQuery]:
    """Prepend bundled library fingerprints (FOFA app=) when the user named a known product."""
    matched = profile.library_queries(intent, limit=min(3, limit))
    if not matched:
        return queries
    existing = " ".join(item.query for item in queries).lower()
    extras = [
        AgentQuery(
            query=str(item["query"]),
            purpose=str(item["purpose"]),
            strategy=str(item["strategy"]),
            source=str(item.get("source") or "library"),
        )
        for item in matched
        if str(item["query"]).lower() not in existing
    ]
    if not extras:
        return queries
    merged: list[AgentQuery] = []
    seen: set[str] = set()
    for item in extras + queries:
        key = item.query.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        if len(merged) >= limit:
            break
    return merged


def _domain_hypothesis_insert_at(queries: list[AgentQuery]) -> int:
    """Official-domain hypotheses should run before broad name or body recall."""
    for index, item in enumerate(queries):
        if item.strategy == "recall" or "结构化规划降级" in item.purpose:
            return index
    return len(queries)


def _is_list_action(action: AgentAction) -> bool:
    """List search and stats actions both carry query strings; both engines behave identically here."""
    return action in SEARCH_ACTIONS or action is AgentAction.STATS


def _domain_hypothesis_candidate(plan: dict[str, Any], profile: AgentProfile) -> AgentQuery | None:
    raw_items = plan.get("domains") if isinstance(plan.get("domains"), list) else []
    domains: list[str] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip().lower()
        domain = re.sub(r"^https?://", "", domain).split("/", 1)[0].split(":", 1)[0].removeprefix("www.")
        if re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
            domains.append(domain)
    domains = list(dict.fromkeys(domains))[:6]
    if not domains:
        return None
    return AgentQuery(
        query=profile.hypothesis_query(domains),
        purpose="验证可能的官网域名：" + ", ".join(domains),
        strategy="hypothesis",
        source="entity_resolution",
    )


def _normalized_domain(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    text = re.sub(r"^https?://", "", text).split("/", 1)[0].split(":", 1)[0]
    text = text.removeprefix("*.").removeprefix("www.").rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", text):
        return None
    return text


def _website_identity_terms(run: AgentRun) -> list[str]:
    source = " ".join([run.intent, *run.organization_names]).lower()
    generic = {
        "studio",
        "workroom",
        "website",
        "websites",
        "domain",
        "domains",
        "site",
        "工作室",
        "网站",
        "官网",
        "域名",
    }
    terms = [item for item in re.findall(r"[a-z][a-z0-9_-]{2,}|[\u4e00-\u9fff]{2,}", source) if item not in generic]
    return list(dict.fromkeys(terms))[:12]


def _derive_website_candidates(run: AgentRun, profile: AgentProfile) -> list[WebsiteCandidate]:
    """Turn noisy asset rows into a stable, evidence-labelled website inventory."""
    if not WEBSITE_INTENT_PATTERN.search(run.intent):
        return []
    terms = _website_identity_terms(run)
    hypotheses = set(run.domain_hypotheses)
    grouped: dict[str, dict[str, Any]] = {}
    for asset, strategy in zip(run.assets, run.asset_confidence, strict=False):
        host = str(asset.get("host") or "").strip()
        signals = profile.attribution(asset)
        domain = _normalized_domain(asset.get("domain"))
        cert_domain = _normalized_domain(signals.get("certificate_cn"))
        host_domain = _normalized_domain(host)
        domain = domain or cert_domain or host_domain
        if not domain:
            continue
        searchable = " ".join(
            str(asset.get(field) or "").lower()
            for field in ("host", "domain", "title", "org", "icp", "cert.subject.org", "cert.subject.cn")
        )
        name_match = any(term in searchable for term in terms)
        if domain not in hypotheses and not name_match:
            continue
        entry = grouped.setdefault(
            domain,
            {
                "hosts": [],
                "strategies": set(),
                "brand_domain": any(term in domain for term in terms),
                "title_match": False,
                "icp": False,
                "certificate": False,
            },
        )
        if host and host not in entry["hosts"]:
            entry["hosts"].append(host)
        entry["strategies"].add(strategy)
        title = str(asset.get("title") or "").lower()
        entry["title_match"] = entry["title_match"] or any(term in title for term in terms)
        entry["icp"] = entry["icp"] or bool(str(signals.get("icp") or "").strip())
        entry["certificate"] = entry["certificate"] or cert_domain == domain

    candidates: list[WebsiteCandidate] = []
    for domain, entry in grouped.items():
        evidence: list[str] = []
        if domain in hypotheses:
            evidence.append("entity_resolution")
        if entry["title_match"]:
            evidence.append("name_in_title")
        if entry["icp"]:
            evidence.append("icp_observed")
        if entry["certificate"]:
            evidence.append("certificate_observed")
        evidence.extend(
            profile.evidence_key(item) for item in sorted(entry["strategies"], key=lambda item: -EVIDENCE_RANK.get(item, 1))
        )
        if entry["icp"] and (entry["brand_domain"] or entry["title_match"]):
            status, confidence = "corroborated", "high"
        elif domain in hypotheses and entry["title_match"] and entry["certificate"]:
            status, confidence = "corroborated", "high"
        elif domain in hypotheses:
            status, confidence = "observed", "medium"
        else:
            status, confidence = "candidate", "low"
        hosts = entry["hosts"][:8]
        preferred = next(
            (
                item
                for item in hosts
                if item.startswith("https://")
                and (_normalized_domain(item) == domain or str(_normalized_domain(item) or "").endswith(f".{domain}"))
            ),
            None,
        )
        if not preferred:
            preferred = next(
                (
                    item
                    for item in hosts
                    if item.startswith("http://")
                    and (_normalized_domain(item) == domain or str(_normalized_domain(item) or "").endswith(f".{domain}"))
                ),
                None,
            )
        if not preferred:
            preferred = next((item for item in hosts if item.startswith("https://")), None)
        url = preferred or f"https://{domain}"
        candidates.append(
            WebsiteCandidate(
                domain=domain,
                url=url,
                status=status,
                confidence=confidence,
                evidence=list(dict.fromkeys(evidence)),
                hosts=hosts,
            )
        )
    rank = {"corroborated": 0, "observed": 1, "candidate": 2}
    return sorted(candidates, key=lambda item: (rank[item.status], item.domain))[:100]


_SCHEME_PREFIX = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_PORT_SUFFIX = re.compile(r":\d+$")


def _normalize_host(value: str) -> str:
    """Strip scheme, userinfo, port, path and trailing dot so engines agree on one hostname.

    Measured on one endpoint (45.33.32.156:80): FOFA returned `45.33.32.156`, Shodan
    `http://scanme.nmap.org:80` and Hunter `http://scanme.nmap.org`. The raw string was part of
    the asset identity, so the same service was counted once per engine.
    """
    host = _SCHEME_PREFIX.sub("", str(value or "").strip()).split("/", 1)[0]
    host = host.split("@", 1)[-1].strip().lower()
    if host.startswith("["):  # IPv6 literal: [2001:db8::1]:443
        host = host.split("]", 1)[0].lstrip("[")
    elif host.count(":") == 1:
        # `host:port`. A bare IPv6 literal has more than one colon and no port to strip - without
        # this guard `2001:db8::2` and `2001:db8::3` both collapsed to `2001:db8:` and one of the
        # two assets was silently dropped as a duplicate.
        host = _PORT_SUFFIX.sub("", host)
    return host.rstrip(".")


def _protocol_family(value: str) -> str:
    """Fold the engines' protocol vocabularies into http / https / other.

    Shodan reports `tcp` where FOFA and Hunter report `ssh` (measured on port 22) and
    `https-simple-new` where they report `https`, so the raw value cannot key an identity.
    """
    text = str(value or "").strip().lower()
    if "https" in text:
        return "https"
    if "http" in text:
        return "http"
    return "other"


def _asset_identity(values: dict[str, Any]) -> tuple[str, ...]:
    """Stable identity shared by every engine: one virtual host, or one socket.

    Web rows are virtual hosts, so the hostname is what distinguishes sites sharing an IP:port.
    Non-web rows are sockets (a hostname is only a DNS alias of the same service), and the engines
    disagree on whether they name them by hostname or by address - measured: Shodan returned
    `scanme.nmap.org:22` while FOFA and Hunter returned `45.33.32.156:22` - so the address wins
    there. The protocol is folded to a family because Shodan says `tcp` where they say `ssh`.
    """
    host = _normalize_host(str(values.get("host") or ""))
    ip = str(values.get("ip") or "").strip().lower()
    family = _protocol_family(str(values.get("protocol") or ""))
    name = (ip or host) if family == "other" else (host or ip)
    if not name:
        return ("record", repr(sorted((str(key), str(value)) for key, value in values.items())))
    return ("asset", name, str(values.get("port") or "").strip(), family)


def _endpoint_key(values: dict[str, Any]) -> tuple[str, ...]:
    """Rollup key for the endpoint behind a row: several virtual hosts share one IP:port."""
    ip = str(values.get("ip") or "").strip().lower()
    if not ip:
        return _asset_identity(values)
    return ("endpoint", ip, str(values.get("port") or "").strip(), _protocol_family(str(values.get("protocol") or "")))


def asset_endpoint_count(assets: list[dict[str, Any]]) -> int:
    """Distinct endpoints (ip:port:protocol family) behind a list of asset rows."""
    return len({_endpoint_key(asset) for asset in assets})


def _endpoint_label(values: dict[str, Any]) -> str:
    ip = str(values.get("ip") or "").strip()
    port = str(values.get("port") or "").strip()
    return f"{ip}:{port}" if ip and port else ip or port


def _compact_asset_sample(assets: list[dict[str, Any]], limit: int = 30) -> list[dict[str, str]]:
    """Compact rows for prompts, spread across the ranked list instead of only its head.

    Assets arrive ranked by evidence, so a large result set would otherwise reach the model as a
    biased slice of its highest-confidence rows.
    """
    if len(assets) > limit:
        step = len(assets) / limit
        picked = [assets[min(int(index * step), len(assets) - 1)] for index in range(limit)]
    else:
        picked = list(assets)
    useful_fields = (
        "host",
        "domain",
        "ip",
        "port",
        "protocol",
        "title",
        "org",
        "icp",
        "product",
        "server",
        "country",
        "cert.subject.org",
        "cert.subject.cn",
        "cert.issuer.org",
    )
    sample: list[dict[str, str]] = []
    for asset in picked:
        compact = {
            field: str(asset[field]).replace("\r", " ").replace("\n", " ")[:240]
            for field in useful_fields
            if asset.get(field) not in (None, "", [], {})
        }
        if compact:
            sample.append(compact)
    return sample


def _top_counts(values: list[str], *, limit: int = 8) -> list[dict[str, Any]]:
    counter = Counter(value for value in values if value)
    return [{"name": name, "count": count} for name, count in counter.most_common(limit)]


def _briefing_country(values: dict[str, Any]) -> str:
    """Canonical country for cross-engine aggregation: the ISO code when one is known.

    FOFA answers `country` with a code, Shodan with an English name plus `country_code` and Hunter
    with a Chinese name: reading the name column directly mixed 美国 / United States / US in one
    ranking, so the aggregated view prefers the code.
    """
    code = str(values.get("country_code") or "").strip().upper()
    return code or str(values.get("country") or "").strip()


def _asset_briefing_stats(run: AgentRun) -> dict[str, Any]:
    assets = run.assets
    hosting_providers = [hosting_provider(asset) for asset in assets]
    truncated = [
        {
            "purpose": item.purpose,
            "available": item.available_count,
            "pulled": item.result_count,
        }
        for item in run.queries
        if item.available_count is not None and item.result_count < item.available_count
    ]
    return {
        "unique_assets": run.result_count,
        "unique_endpoints": asset_endpoint_count(assets),
        "previewed": len(assets),
        "evidence": dict(run.evidence_counts),
        "unique_domains": len({str(asset.get("domain") or "").strip() for asset in assets if asset.get("domain")}),
        "unique_ips": len({str(asset.get("ip") or "").strip() for asset in assets if asset.get("ip")}),
        "top_endpoints": _top_counts([_endpoint_label(asset) for asset in assets]),
        "top_domains": _top_counts([str(asset.get("domain") or "").strip() for asset in assets]),
        "top_titles": _top_counts(
            [re.sub(r"\s+", " ", str(asset.get("title") or "")).strip()[:80] for asset in assets]
        ),
        "top_orgs": _top_counts([str(asset.get("org") or "").strip() for asset in assets]),
        "top_products": _top_counts([str(asset.get("product") or "").strip()[:100] for asset in assets]),
        "top_servers": _top_counts([str(asset.get("server") or "").strip()[:100] for asset in assets]),
        "top_countries": _top_counts([_briefing_country(asset) for asset in assets]),
        "top_ports": _top_counts([str(asset.get("port") or "").strip() for asset in assets]),
        "top_protocols": _top_counts([str(asset.get("protocol") or "").strip().lower() for asset in assets]),
        "alive": _top_counts(
            [str(asset.get("alive_status")) for asset in assets if asset.get("alive_status") not in (None, "")]
        ),
        "age_filter": dict(run.age_filter),
        "preview_limit": ASSET_PREVIEW_LIMIT,
        "corroboration": dict(run.corroboration),
        "hosting": _top_counts(hosting_providers),
        "hosting_rows": sum(1 for provider in hosting_providers if provider),
        "truncated_queries": truncated,
    }


def _assets_with_evidence(run: AgentRun, *strategies: str, limit: int = 12) -> list[dict[str, str]]:
    picked: list[dict[str, Any]] = []
    for asset, evidence in zip(run.assets, run.asset_confidence, strict=False):
        if evidence in strategies:
            picked.append(asset)
        if len(picked) >= limit:
            break
    return _compact_asset_sample(picked, limit=limit)


def _search_summary_prompt(run: AgentRun, intent: str) -> str:
    return (
        f"User intent: {intent}\n"
        f"Structured website candidates: {[item.model_dump() for item in run.website_candidates]}\n"
        f"Inventory stats: {json.dumps(_asset_briefing_stats(run), ensure_ascii=False)}\n"
        f"Sample coverage: the two samples below are capped at 15 rows each out of {run.result_count} "
        "deduplicated rows, while Inventory stats covers all of them; treat the samples as illustrative "
        "and the stats as the distribution\n"
        f"Higher-confidence sample: {_assets_with_evidence(run, 'precision', 'balanced', 'hypothesis', limit=15)}\n"
        f"Recall/candidate sample: {_assets_with_evidence(run, 'recall', limit=15)}\n"
        f"Planned scan follow-up: requested={run.scan_requested_by_user}, recommended={run.scan_recommended}, "
        f"targets={len(run.scan_targets)}, template_ids={run.scan_template_ids}, severities={run.scan_severities}"
        + (f"\nSearch stopped early: {run.stop_reason}" if run.stop_reason else "")
    )


def _briefing_join(items: list[dict[str, Any]], *, limit: int = 5, wrap: bool = False) -> str:
    parts: list[str] = []
    for item in items[:limit]:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        label = f"`{name}`" if wrap else name
        count = item.get("count")
        parts.append(f"{label} ×{count}" if count not in (None, "") else label)
    return "、".join(parts)


def _local_search_summary(run: AgentRun) -> str:
    stats = _asset_briefing_stats(run)
    evidence = stats["evidence"]
    high = sum(int(evidence.get(key, 0) or 0) for key in ("precision", "balanced", "hypothesis"))
    recall = int(evidence.get("recall", 0) or 0)
    domains = _briefing_join(stats["top_domains"], wrap=True) or "无"
    titles = _briefing_join(stats["top_titles"]) or "无"
    ports = _briefing_join(stats["top_ports"]) or "无"
    protocols = _briefing_join(stats["top_protocols"]) or "无"
    products = _briefing_join(stats["top_products"]) or "未识别"
    servers = _briefing_join(stats["top_servers"]) or "未识别"
    countries = _briefing_join(stats["top_countries"]) or "未返回"
    endpoints = stats["unique_endpoints"]
    top_endpoints = _briefing_join(stats["top_endpoints"], wrap=True) or "无"
    fanout = (
        f"；其中 {stats['unique_assets'] - endpoints} 条是同一 IP:端口 上的其它虚拟主机"
        if endpoints and endpoints < stats["unique_assets"]
        else ""
    )
    alive = _briefing_join(stats["alive"]) or "未探测"
    hosting_rows = int(stats.get("hosting_rows") or 0)
    hosting = _briefing_join(stats.get("hosting") or []) or "无"
    corroborated_rows = int((stats.get("corroboration") or {}).get("multi_engine") or 0)
    corroboration = f"，其中 {corroborated_rows} 条被 ≥2 个引擎同时观测到（交叉印证）" if corroborated_rows else ""
    truncated = stats["truncated_queries"]
    corroborated = "、".join(
        f"`{item.domain}`" for item in run.website_candidates if item.status == "corroborated"
    ) or "无"
    candidates = "、".join(
        f"`{item.domain}`（{item.status}）" for item in run.website_candidates if item.status != "corroborated"
    ) or "无"
    if run.stop_reason:
        next_step = f"检索提前结束：{run.stop_reason}"
    elif truncated:
        first = truncated[0]
        next_step = (
            f"部分查询仍有余量未拉全（例如 {first['purpose']} {first['pulled']}/{first['available']}），"
            "可提高页数后再复核。"
        )
    else:
        next_step = "先复核高置信域名与证书/组织命中，再处理名称/正文候选。"
    return (
        "## 结论\n"
        f"共识别去重资产 {stats['unique_assets']} 条"
        + (f"（受每引擎 {stats['preview_limit']} 条预览上限限制，实际命中更多）" if run.assets_truncated else "")
        + f"，落在 {endpoints} 个独立端点（IP:端口）上{fanout}，"
        f"覆盖 {stats['unique_domains']} 个域名和 {stats['unique_ips']} 个 IP{corroboration}；"
        f"高置信约 {high} 条，名称/正文召回候选 {recall} 条。"
        "当前结果适合作为暴露面清单，但组织归属和漏洞结论仍需独立验证。\n\n"
        "## 高置信资产\n"
        f"- **交叉印证网站**：{corroborated}\n"
        f"- **主要域名**：{domains}\n\n"
        "## 风险与暴露面\n"
        f"- **端口与协议**：端口 {ports}；协议 {protocols}\n"
        f"- **端点分布**：{top_endpoints}（记录 {stats['unique_assets']} 条 / 端点 {endpoints} 个）\n"
        f"- **产品与服务器**：产品 {products}；服务器 {servers}\n"
        f"- **可达性与地域**：存活状态 {alive}；地域 {countries}\n\n"
        "## 证据边界与噪声\n"
        f"- **待确认网站**：{candidates}\n"
        + (
            f"- **托管/CDN 归属**：{hosting_rows} 条落在托管或 CDN 网络（{hosting}），其证书、备案与组织字段属于服务商，"
            "不能当作目标自身的归属证据，也不应作为派生枢轴的种子\n"
            if hosting_rows
            else ""
        )
        +
        f"- **高频标题**：{titles}；标题或正文命中不等同于组织归属\n"
        f"- **召回候选**：{recall} 条仍需官网内容、备案、证书或权威来源交叉验证\n\n"
        "## 覆盖缺口\n"
        f"- **查询完整性**：{next_step}\n"
        f"- **终端样本**：当前保留 {stats['previewed']} / {stats['unique_assets']} 条用于分析，"
        "大规模结果需结合导出文件复核\n\n"
        "## 处置优先级\n"
        "1. 先核验交叉印证网站及其证书、备案和官网跳转关系，固化真实资产边界。\n"
        "2. 按非标准端口、可达性和产品指纹排序复核，确认服务用途与是否应对公网开放。\n"
        "3. 对名称/正文候选逐项排除第三方引用、停放页和共享基础设施，避免扩大扫描范围。\n"
        "4. 扫描前再次核对目标、模板及严重级别审批范围，并对命中结果进行人工验证。\n"
    )


def _local_generic_summary(run: AgentRun) -> str:
    if run.action is AgentAction.HOST:
        target = f"`{run.target}`" if run.target else "该主机"
        return f"## 结论\n已获取 {target} 的主机画像。模型未返回可读总结，请直接查看上方端口与产品数据。\n"
    if run.action is AgentAction.STATS:
        query = f"`{run.query}`" if run.query else "该统计查询"
        return f"## 结论\n统计查询 {query} 已返回，总量 {run.result_count}。模型未返回可读总结，请查看聚合分布。\n"
    return _local_search_summary(run)


def _asset_briefing_has_sufficient_quality(text: str) -> bool:
    required = (
        "## 结论",
        "## 高置信资产",
        "## 风险与暴露面",
        "## 证据边界与噪声",
        "## 覆盖缺口",
        "## 处置优先级",
    )
    substantive_lines = [line for line in text.splitlines() if line.lstrip().startswith(("- ", "1. ", "2. ", "3. "))]
    return len(text) >= 320 and all(heading in text for heading in required) and len(substantive_lines) >= 8


def _apply_generated_summary(
    run: AgentRun,
    text: str | None,
    *,
    fallback: str,
    require_asset_briefing: bool = False,
) -> None:
    cleaned = (text or "").strip()
    if cleaned and (not require_asset_briefing or _asset_briefing_has_sufficient_quality(cleaned)):
        run.summary = cleaned
        return
    logger.warning("模型未返回达到质量门槛的总结，已改用本地结构化资产简报。")
    run.summary = fallback


def _align_action_to_profile(
    run: AgentRun,
    profile: AgentProfile,
    *,
    on_progress: AgentProgressCallback | None = None,
) -> None:
    """Apply engine capability downgrades before the selected action executes."""
    fallback = profile.align_action(run.action.value, run.target, has_queries=bool(run.queries))
    if fallback is None:
        return
    if fallback.queries and not run.queries:
        run.queries = [
            AgentQuery(
                query=str(item["query"]),
                purpose=str(item["purpose"]),
                strategy=str(item["strategy"]),
                source=str(item.get("source") or "capability"),
            )
            for item in fallback.queries
        ]
    run.action = AgentAction(fallback.action)
    _record_step(run, AgentState.INTENT, fallback.note, data=fallback.data, on_progress=on_progress)


class AssetAgent:
    def __init__(self, client: AssetSearchEngine, router: ProviderRouter) -> None:
        self.client = client
        self.router = router
        self.profile = agent_profile(client)

    def _action_for(self, plan: dict[str, Any]) -> AgentAction:
        """Map planner output onto this engine's verbs; unknown or foreign verbs fall back to list search."""
        try:
            action = AgentAction(str(plan.get("action") or "").strip())
        except ValueError:
            return AgentAction(self.profile.search_action)
        if action in SEARCH_ACTIONS:
            return AgentAction(self.profile.search_action)
        return action

    async def _execute_routed_action(
        self,
        run: AgentRun,
        intent: str,
        *,
        on_progress: AgentProgressCallback | None,
    ) -> bool:
        """Execute non-list actions selected by the planner; return whether the run is complete."""
        if run.action is AgentAction.ICON:
            if not run.target:
                raise ValueError("icon_query 需要明确的 URL 目标")
            from utils.helpers import IconHashCalculator

            _record_step(run, AgentState.EXECUTE, f"正在安全获取 {run.target} 的网站图标", on_progress=on_progress)
            icon_hash = await IconHashCalculator.hash_url(run.target)
            if icon_hash is None:
                raise ValueError("无法获取网站图标或计算哈希")
            icon_query = self.profile.icon_query(icon_hash)
            run.queries = [
                AgentQuery(query=icon_query, purpose="使用目标网站图标的 MurmurHash3 反查同类资产", strategy="balanced")
            ]
            run.query = icon_query
            _record_step(
                run,
                AgentState.INTENT,
                f"已将图标反查动作转换为可审计的 {self.profile.label} 查询策略",
                data={"target": run.target, "query": icon_query},
                on_progress=on_progress,
            )
            return False

        if run.action is AgentAction.HOST:
            if not run.target:
                raise ValueError("host_query 需要明确的 IP 地址或主机目标")
            _record_step(run, AgentState.EXECUTE, f"正在查询主机聚合画像：{run.target}", on_progress=on_progress)
            data = await self.client.host_profile(run.target)
            run.result_data = data
            run.result_count = 1
            _record_step(
                run,
                AgentState.EVALUATE,
                f"主机画像已返回，共 {len(data.get('ports') or [])} 个端口条目",
                data={"target": run.target, "ports": len(data.get("ports") or [])},
                on_progress=on_progress,
            )
            _record_step(run, AgentState.SUMMARIZE, "正在生成单体资产暴露面解读", on_progress=on_progress)
            summary = await self.router.generate(
                "summarizer",
                system=self.profile.host_summary_system(),
                prompt=(
                    f"User intent: {intent}\nTarget: {run.target}\n"
                    f"{self.profile.label} Host data: {json.dumps(data, ensure_ascii=False, default=str)[:12000]}"
                ),
            )
            _apply_generated_summary(run, summary.text, fallback=_local_generic_summary(run))
            _record_step(run, AgentState.COMPLETED, "主机画像任务已完成", on_progress=on_progress)
            return True

        if run.action is AgentAction.STATS:
            if not run.queries:
                raise ValueError(f"stat_query 需要一条 {self.profile.label} 查询语句")
            run.query = run.queries[0].query
            errors = validate_query(run.query) + self.profile.query_errors(run.query)
            if errors:
                raise ValueError("统计查询语法无效：" + "; ".join(errors))
            run.stats_fields = list(
                dict.fromkeys(field for field in run.stats_fields if field in self.profile.stats_fields)
            ) or list(self.profile.default_stats_fields)
            _record_step(
                run,
                AgentState.EXECUTE,
                f"正在执行统计聚合：{', '.join(run.stats_fields)}",
                data={"query": run.query, "fields": run.stats_fields},
                on_progress=on_progress,
            )
            data = await self.client.stats(run.query, run.stats_fields)
            run.result_data = data
            run.result_count = int(data.get("size") or 0)
            _record_step(
                run,
                AgentState.EVALUATE,
                f"统计聚合完成，{self.profile.label} 总量 {run.result_count:,} 条",
                data={"query": run.query, "fields": run.stats_fields, "size": run.result_count},
                on_progress=on_progress,
            )
            _record_step(run, AgentState.SUMMARIZE, "正在生成统计分布解读", on_progress=on_progress)
            summary = await self.router.generate(
                "summarizer",
                system=self.profile.stats_summary_system(),
                prompt=(
                    f"User intent: {intent}\nQuery: {run.query}\nDimensions: {run.stats_fields}\n"
                    f"{self.profile.label} statistics: {json.dumps(data, ensure_ascii=False, default=str)[:12000]}"
                ),
            )
            _apply_generated_summary(run, summary.text, fallback=_local_generic_summary(run))
            _record_step(run, AgentState.COMPLETED, "统计聚合任务已完成", on_progress=on_progress)
            return True

        return False

    async def run(
        self,
        intent: str,
        *,
        max_records: int = 1000,
        max_pages: int = 10,
        fields: list[str] | None = None,
        smart_fields: bool = True,
        min_evidence: str | None = None,
        ensure_timestamp: bool = False,
        on_progress: AgentProgressCallback | None = None,
        on_page: AgentPageCallback | None = None,
    ) -> AgentRun:
        run = AgentRun(intent=intent, engine=self.profile.engine)
        # Rows whose strategy ranks below the caller's floor are dropped while collecting, so the
        # asset list, the counts, the scan targets and the briefing all describe the same set.
        min_rank = EVIDENCE_RANK.get(str(min_evidence or "").lower(), 0)
        span = trace.get_tracer("cybermap.agent").start_span("cybermap.agent.run")
        span.set_attribute("cybermap.agent.run_id", run.id)
        span.set_attribute("cybermap.agent.engine", run.engine)

        def finish() -> AgentRun:
            run.route_events = [event.model_dump(mode="json") for event in self.router.events]
            span.set_attribute("cybermap.agent.action", run.action.value)
            span.set_attribute("cybermap.agent.state", run.state.value)
            span.set_attribute("cybermap.agent.result_count", run.result_count)
            if run.error:
                span.set_attribute("error.type", str(run.error.get("code", "agent_error")))
            span.end()
            return run

        try:
            _record_step(
                run,
                AgentState.INTENT,
                f"正在识别任务类型并制定 {self.profile.label} 执行策略",
                on_progress=on_progress,
            )
            run.scan_requested_by_user = user_authorized_scan(intent)
            await self.profile.prepare()
            try:
                library_hint = self.profile.library_hint(intent)
                planner_prompt = self.profile.planner_context(
                    intent,
                    smart_fields=smart_fields,
                    requested_fields=fields,
                )
                if library_hint:
                    planner_prompt = f"{planner_prompt}\n{library_hint}"
                plan_result = await self.router.generate(
                    "planner",
                    system=self.profile.planner_system(),
                    prompt=planner_prompt,
                    schema=self.profile.plan_schema(),
                )
                plan = plan_result.structured if isinstance(plan_result.structured, dict) else {}
            except ProviderError as exc:
                if exc.code != "model_structured_output_error":
                    raise
                plan = self.profile.fallback_plan(intent)
                _record_step(
                    run,
                    AgentState.INTENT,
                    "规划模型返回格式异常，已自动切换为保守查询方案",
                    data={"error": exc.code, "query": plan["queries"][0]["query"]},
                    on_progress=on_progress,
                )
            run.action = self._action_for(plan)
            run.target = str(plan.get("target") or "").strip() or None
            run.stats_fields = [str(item) for item in plan.get("stats_fields", [])]
            run.queries = _query_candidates(plan, source="planner", limit=INITIAL_QUERY_VARIANTS)
            if _is_list_action(run.action):
                merged = _merge_library_queries(self.profile, intent, run.queries, limit=INITIAL_QUERY_VARIANTS)
                if [item.query for item in merged] != [item.query for item in run.queries]:
                    run.queries = merged
                    _record_step(
                        run,
                        AgentState.INTENT,
                        "已按内置规则库补齐精确 app= 指纹",
                        data={"queries": [item.query for item in merged if item.source == "library"]},
                        on_progress=on_progress,
                    )
                _inject_playbook_queries(run, self.profile, intent, on_progress=on_progress)
            explicit_domain = bool(
                re.search(r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,63}(?:/|\b)", intent, re.IGNORECASE)
            )
            generic_domain_scopes = {
                "ac.cn",
                "com.cn",
                "edu.cn",
                "gov.cn",
                "net.cn",
                "org.cn",
            }
            planned_domains = self.profile.planning_domains([item.query for item in run.queries])
            run.domain_hypotheses = sorted(planned_domains - generic_domain_scopes)
            planned_domain = bool(planned_domains - generic_domain_scopes)
            should_resolve_domain = (
                run.action in SEARCH_ACTIONS
                and not explicit_domain
                and not planned_domain
                and bool(ORGANIZATION_INTENT_PATTERN.search(intent))
            )
            if should_resolve_domain:
                _record_step(
                    run,
                    AgentState.INTENT,
                    "正在将机构名称解析为待验证的官网域名线索",
                    on_progress=on_progress,
                )
                try:
                    resolution_result = await self.router.generate(
                        "entity_resolver",
                        system=(
                            f"Resolve a named organization for defensive {self.profile.label} asset discovery. Return its common and "
                            "official name "
                            "variants, plus three to six plausible website domains. Prefer a domain known from reliable general "
                            "knowledge when available. Otherwise derive strong acronym/name stems and test realistic suffixes such as "
                            ".cn, .edu.cn and .com.cn. A province or administrative prefix may be absent from the common name. Every "
                            f"domain is an untrusted hypothesis to be checked in {self.profile.label}, not proof of ownership. Do not "
                            "fabricate ICP "
                            "numbers, IP addresses or ownership claims. Return structured data only."
                        ),
                        prompt=f"Organization request: {intent}",
                        schema=ENTITY_RESOLUTION_SCHEMA,
                    )
                    resolution = (
                        resolution_result.structured if isinstance(resolution_result.structured, dict) else {}
                    )
                    run.organization_names = [
                        str(item).strip()
                        for item in resolution.get("organization_names", [])
                        if str(item).strip()
                    ][:6]
                    run.domain_hypotheses = list(
                        dict.fromkeys(
                            domain
                            for item in resolution.get("domains", [])
                            if isinstance(item, dict)
                            for domain in [_normalized_domain(item.get("domain"))]
                            if domain
                        )
                    )[:6]
                    hypothesis = _domain_hypothesis_candidate(resolution, self.profile)
                    if hypothesis:
                        insert_at = _domain_hypothesis_insert_at(run.queries)
                        run.queries.insert(insert_at, hypothesis)
                        run.queries = run.queries[:INITIAL_QUERY_VARIANTS]
                        _record_step(
                            run,
                            AgentState.INTENT,
                            f"已生成官网域名候选，将先在 {self.profile.label} 中验证后再展示",
                            data={
                                "organization_names": resolution.get("organization_names", []),
                                "query": hypothesis.query,
                            },
                            on_progress=on_progress,
                        )
                except ProviderError as exc:
                    # Entity resolution improves recall but must never make an otherwise
                    # valid workflow fail when a provider cannot satisfy its schema.
                    logger.warning(f"Organization domain resolution skipped: {exc}")
                    _record_step(
                        run,
                        AgentState.INTENT,
                        f"官网域名线索解析暂不可用，继续执行名称与证书等 {self.profile.label} 查询",
                        on_progress=on_progress,
                    )
            if _is_list_action(run.action) and not run.queries:
                raise ValueError(f"模型未生成任何 {self.profile.label} 查询候选")
            _align_action_to_profile(run, self.profile, on_progress=on_progress)
            run.query = run.queries[0].query if run.queries else None
            _record_step(
                run,
                AgentState.INTENT,
                f"已选择动作 {run.action.value}",
                data={"action": run.action.value, "target": run.target, "stats_fields": run.stats_fields},
                on_progress=on_progress,
            )
            if await self._execute_routed_action(run, intent, on_progress=on_progress):
                return finish()
            if not run.queries:
                raise ValueError(f"所选动作未生成 {self.profile.label} 查询语句")
            run.fields = [str(item) for item in plan.get("fields", [])]
            if fields:
                run.fields = list(dict.fromkeys(str(item).strip() for item in fields if str(item).strip()))
            elif smart_fields:
                run.fields = self.profile.suggest_fields(run.fields, intent=intent)
            else:
                run.fields = run.fields or list(self.profile.default_fields)
            scan = plan.get("scan") if isinstance(plan.get("scan"), dict) else {}
            run.scan_recommended = bool(scan.get("recommended", False))
            run.scan_reason = str(scan.get("reason", ""))
            run.scan_template_ids = list(
                dict.fromkeys(str(item) for item in scan.get("template_ids", []) if SAFE_TEMPLATE_ID_PATTERN.fullmatch(str(item)))
            )[:100]
            allowed_template_ids = nuclei_id_allowlist()
            run.scan_template_ids = [item for item in run.scan_template_ids if item in allowed_template_ids]
            if run.scan_recommended:
                run.scan_template_ids = _scan_template_ids_for_intent(intent, run.scan_template_ids)
            severities = [
                str(item).lower()
                for item in scan.get("severities", [])
                if str(item).lower() in {"info", "low", "medium", "high", "critical"}
            ]
            if severities:
                run.scan_severities = list(dict.fromkeys(severities))
            if run.scan_template_ids:
                run.scan_severities = align_scan_severities(run.scan_template_ids, run.scan_severities)
            if run.scan_requested_by_user or run.scan_recommended:
                run.fields = list(dict.fromkeys([*run.fields, "host", "protocol", "ip", "port", "title"]))
            if ensure_timestamp:
                # The caller filters by age, so the engine's own last-seen column is required; it
                # still passes the same deny check as any other requested field.
                run.fields = list(dict.fromkeys([*run.fields, self.profile.timestamp_field]))
            selection = self.profile.decide_fields(run.fields)
            run.fields = selection.allowed or list(self.profile.default_fields)

            _record_step(
                run,
                AgentState.INTENT,
                f"已生成 {len(run.queries)} 个初始查询策略",
                data={"queries": [item.model_dump() for item in run.queries], "fields": run.fields},
                on_progress=on_progress,
            )
            if selection.denied:
                detail, data = self.profile.denied_fields_step(selection.denied, run.fields)
                _record_step(run, AgentState.VALIDATE, detail, data=data, on_progress=on_progress)
            elif smart_fields and not fields:
                detail, data = self.profile.smart_fields_step(run.fields)
                _record_step(run, AgentState.INTENT, detail, data=data, on_progress=on_progress)

            for index, candidate in enumerate(run.queries, start=1):
                errors = validate_query(candidate.query) + self.profile.query_errors(candidate.query)
                if errors:
                    _record_step(
                        run,
                        AgentState.VALIDATE,
                        f"查询策略 {index} 语法存在问题，正在修复",
                        data={"query": candidate.query, "errors": errors},
                        on_progress=on_progress,
                    )
                    repair = await self.router.generate(
                        "query_repair",
                        system=self.profile.repair_system(),
                        prompt=f"Intent: {intent}\nQuery: {candidate.query}\nErrors: {errors}",
                        schema=QUERY_SCHEMA,
                    )
                    repaired = repair.structured if isinstance(repair.structured, dict) else {}
                    candidate.query = str(repaired.get("query", ""))
                    run.fields = [str(item) for item in repaired.get("fields", run.fields)]
                    remaining = validate_query(candidate.query) + self.profile.query_errors(candidate.query)
                    if remaining:
                        raise ValueError(f"模型无法生成有效的 {self.profile.label} 查询：" + "; ".join(remaining))
                _record_step(
                    run,
                    AgentState.VALIDATE,
                    f"查询策略 {index}/{len(run.queries)} 语法校验通过",
                    data={"query": candidate.query, "purpose": candidate.purpose},
                    on_progress=on_progress,
                )
            run.query = run.queries[0].query

            page_number = 0
            seen_assets: set[tuple[str, ...]] = set()
            evidence_by_asset: dict[tuple[str, ...], str] = {}
            stopped: dict[str, str] = {}

            async def execute_queries(candidates: list[AgentQuery]) -> None:
                nonlocal page_number
                for batch_index, candidate in enumerate(candidates):
                    remaining_budget = max_records - run.result_count
                    if remaining_budget <= 0:
                        break
                    # Share the *remaining* global budget across only the strategies
                    # that are actually about to run. Empty/low-hit strategies thus
                    # return their unused capacity to later, broader strategies.
                    remaining_candidates = len(candidates) - batch_index
                    query_budget = max(1, (remaining_budget + remaining_candidates - 1) // remaining_candidates)
                    if candidate.strategy == "recall":
                        query_budget = min(query_budget, 200)
                    query_number = run.queries.index(candidate) + 1
                    _record_step(
                        run,
                        AgentState.EXECUTE,
                        f"正在执行查询策略 {query_number}/{len(run.queries)}：{candidate.purpose}",
                        data={"query": candidate.query, "budget": query_budget},
                        on_progress=on_progress,
                    )
                    request = SearchRequest(
                        query=candidate.query,
                        fields=self.profile.request_fields(run.fields),
                        max_records=query_budget,
                        max_pages=max_pages,
                    )
                    try:
                        async for page in self.client.iter_search(request):
                            page_number += 1
                            candidate.pages += 1
                            raw_records = list(page.records)
                            if page.total is not None:
                                candidate.available_count = max(candidate.available_count or 0, page.total)
                            candidate.result_count += len(raw_records)
                            unique_records = []
                            for record in raw_records:
                                identity = _asset_identity(record.values)
                                if min_rank and EVIDENCE_RANK.get(candidate.strategy, 1) < min_rank:
                                    continue
                                previous_evidence = evidence_by_asset.get(identity)
                                if previous_evidence is None or EVIDENCE_RANK.get(candidate.strategy, 1) > EVIDENCE_RANK.get(
                                    previous_evidence, 1
                                ):
                                    evidence_by_asset[identity] = candidate.strategy
                                if identity in seen_assets:
                                    continue
                                seen_assets.add(identity)
                                unique_records.append(record)
                            page.records = unique_records
                            await _notify_page(on_page, run, page, page_number)
                            candidate.new_assets += len(page.records)
                            _record_page(run, page, page_number, strategy=candidate.strategy)
                            _record_step(
                                run,
                                AgentState.EXECUTE,
                                (
                                    f"策略 {query_number} 第 {candidate.pages} 页：返回 {len(raw_records)} 条，"
                                    f"新增 {len(page.records)} 条，累计去重资产 {run.result_count} 条"
                                ),
                                data={
                                    "query": candidate.query,
                                    "page": candidate.pages,
                                    "raw_records": len(raw_records),
                                    "new_assets": len(page.records),
                                    "records": run.result_count,
                                },
                                on_progress=on_progress,
                            )
                            if run.scan_requested_by_user or run.scan_recommended:
                                for record in page.records:
                                    target = _scan_target(record.values)
                                    if target and target not in run.scan_targets and len(run.scan_targets) < 10_000:
                                        run.scan_targets.append(target)
                    except FofaError as exc:
                        # Engine-declared soft stops keep the assets already collected and
                        # continue to the summary instead of discarding the whole run. With
                        # nothing collected the stop stays fatal, otherwise an exhausted
                        # balance would be reported as "no assets found".
                        note = self.profile.soft_stop(exc)
                        if note is None or run.result_count == 0:
                            raise
                        stopped["note"] = note
                        run.stop_reason = note
                        _record_step(run, AgentState.EVALUATE, note, data=exc.as_dict(), on_progress=on_progress)
                        return

            initial_queries = list(run.queries)
            await execute_queries(initial_queries)
            _record_step(
                run,
                AgentState.EVALUATE,
                f"首轮 {len(initial_queries)} 个查询完成，共发现 {run.result_count} 条去重资产",
                data={"records": run.result_count, "queries": [item.model_dump() for item in initial_queries]},
                on_progress=on_progress,
            )
            count_before_pivots = run.result_count
            derived_queries = _inject_derived_pivots(run, self.profile, on_progress=on_progress)
            if derived_queries:
                await execute_queries(derived_queries)
                _record_step(
                    run,
                    AgentState.EVALUATE,
                    f"派生枢轴补充 {run.result_count - count_before_pivots} 条去重资产",
                    data={
                        "new_assets": run.result_count - count_before_pivots,
                        "records": run.result_count,
                        "queries": [item.query for item in derived_queries],
                    },
                    on_progress=on_progress,
                )

            for reflection_round in range(1, MAX_REFLECTION_ROUNDS + 1):
                if stopped or len(run.queries) >= MAX_QUERY_VARIANTS or run.result_count >= max_records:
                    break
                _record_step(
                    run,
                    AgentState.REFLECT,
                    f"正在进行第 {reflection_round}/{MAX_REFLECTION_ROUNDS} 轮结果驱动反思",
                    on_progress=on_progress,
                )
                run.reflection_rounds = reflection_round
                try:
                    reflection = await self.router.generate(
                        "reflector",
                        system=self.profile.reflector_system(),
                        prompt=(
                            f"User intent: {intent}\n"
                            f"Reflection round: {reflection_round}/{MAX_REFLECTION_ROUNDS}\n"
                            f"Executed strategy metrics: {[item.model_dump() for item in run.queries]}\n"
                            f"Unique asset count: {run.result_count}\n"
                            f"Compact asset sample: {_compact_asset_sample(run.assets)}"
                        ),
                        schema=REFLECTION_SCHEMA,
                    )
                except ProviderError as exc:
                    note = f"第 {reflection_round} 轮反思不可用：{exc}；保留已完成查询结果并继续生成总结。"
                    run.reflection_notes.append(note)
                    _record_step(
                        run,
                        AgentState.REFLECT,
                        f"第 {reflection_round} 轮反思降级，保留 {run.result_count} 条已发现资产",
                        data={"error": exc.code, "message": str(exc)},
                        on_progress=on_progress,
                    )
                    break
                reflected = reflection.structured if isinstance(reflection.structured, dict) else {}
                observation = str(reflected.get("observation") or "").strip()
                if observation:
                    run.reflection_notes.append(observation)
                coverage_sufficient = bool(reflected.get("coverage_sufficient", False))
                existing_queries = {item.query for item in run.queries}
                remaining_slots = min(MAX_REFLECTION_ADDITIONS, MAX_QUERY_VARIANTS - len(run.queries))
                additions = [
                    item
                    for item in _query_candidates(
                        reflected,
                        source=f"reflection_{reflection_round}",
                        limit=remaining_slots,
                    )
                    if item.query not in existing_queries
                ]
                valid_additions: list[AgentQuery] = []
                for item in additions:
                    errors = validate_query(item.query) + self.profile.query_errors(item.query)
                    if errors:
                        repair = await self.router.generate(
                            "query_repair",
                            system=self.profile.repair_system(reflection=True),
                            prompt=f"Intent: {intent}\nQuery: {item.query}\nErrors: {errors}",
                            schema=QUERY_SCHEMA,
                        )
                        repaired = repair.structured if isinstance(repair.structured, dict) else {}
                        item.query = str(repaired.get("query") or "")
                    if item.query not in existing_queries and not (
                        validate_query(item.query) + self.profile.query_errors(item.query)
                    ):
                        existing_queries.add(item.query)
                        valid_additions.append(item)
                additions = valid_additions
                run.queries.extend(additions)
                _record_step(
                    run,
                    AgentState.REFLECT,
                    f"第 {reflection_round} 轮反思完成，新增 {len(additions)} 个混合查询策略",
                    data={
                        "observation": observation,
                        "coverage_sufficient": coverage_sufficient,
                        "queries": [item.model_dump() for item in additions],
                    },
                    on_progress=on_progress,
                )
                if not additions:
                    break
                count_before = run.result_count
                await execute_queries(additions)
                round_new_assets = run.result_count - count_before
                _record_step(
                    run,
                    AgentState.EVALUATE,
                    f"第 {reflection_round} 轮补充查询新增 {round_new_assets} 条去重资产",
                    data={"new_assets": round_new_assets, "records": run.result_count},
                    on_progress=on_progress,
                )
                # Stop when a round learned nothing and the run already had results. A round that
                # added assets keeps the loop alive (that is what reflection is for), and an empty
                # run gets its correction round - measured before this change: any run that had
                # found an asset already stopped after round 1, so the second round never applied.
                if coverage_sufficient or (round_new_assets == 0 and count_before > 0):
                    break

            run.asset_confidence = [evidence_by_asset.get(_asset_identity(asset), "recall") for asset in run.assets]
            ranked_assets = sorted(
                zip(run.assets, run.asset_confidence, strict=True),
                key=lambda item: EVIDENCE_RANK.get(item[1], 1),
                reverse=True,
            )
            run.assets = [asset for asset, _confidence in ranked_assets]
            run.asset_confidence = [confidence for _asset, confidence in ranked_assets]
            run.evidence_counts = {
                strategy: sum(1 for value in evidence_by_asset.values() if value == strategy)
                for strategy in ("precision", "balanced", "hypothesis", "recall")
                if any(value == strategy for value in evidence_by_asset.values())
            }
            run.website_candidates = _derive_website_candidates(run, self.profile)
            if run.website_candidates:
                _record_step(
                    run,
                    AgentState.EVALUATE,
                    f"已整理 {len(run.website_candidates)} 个带证据等级的网站候选",
                    data={"websites": [item.model_dump() for item in run.website_candidates]},
                    on_progress=on_progress,
                )

            _record_step(
                run,
                AgentState.EVALUATE,
                f"全部 {len(run.queries)} 个查询策略执行完成，共发现 {run.result_count} 条去重资产"
                if not stopped
                else f"检索提前结束（{stopped['note']}）——已发现 {run.result_count} 条去重资产",
                data={"records": run.result_count, "queries": [item.model_dump() for item in run.queries]},
                on_progress=on_progress,
            )
            if run.result_count == 0:
                run.scan_recommended = False
                run.scan_reason = "未发现可供扫描的资产，已取消初始扫描建议。"
                run.scan_template_ids = []
                run.scan_targets = []

            _record_step(run, AgentState.SUMMARIZE, "正在基于资产样本生成总结", on_progress=on_progress)
            summary = await self.router.generate(
                "summarizer",
                system=self.profile.summarizer_system(),
                prompt=_search_summary_prompt(run, intent),
            )
            _apply_generated_summary(
                run,
                summary.text,
                fallback=_local_search_summary(run),
                require_asset_briefing=True,
            )
            _record_step(run, AgentState.COMPLETED, "侦察任务已完成", on_progress=on_progress)
        except FofaError as exc:
            # Exact engine errors stop the workflow and never trigger query reflection.
            run.error = exc.as_dict()
            _record_step(run, AgentState.FAILED, f"{self.profile.label} 查询失败", data=run.error, on_progress=on_progress)
        except ProviderError as exc:
            run.error = {
                "code": exc.code,
                "message": str(exc),
                "retryable": exc.retryable,
                "hint": exc.hint,
                "status_code": exc.status_code,
            }
            _record_step(run, AgentState.FAILED, "AI 模型调用失败", data=run.error, on_progress=on_progress)
        except Exception as exc:
            run.error = {"code": "agent_error", "message": str(exc), "retryable": False}
            _record_step(run, AgentState.FAILED, "智能体执行失败", data=run.error, on_progress=on_progress)
        return finish()


_CANDIDATE_RANK = {"corroborated": 3, "observed": 2, "candidate": 1}


def _mirror_steps(engine: str, merged: AgentRun, on_progress: AgentProgressCallback | None) -> AgentProgressCallback:
    """Show each engine's steps inside the merged run so the live view keeps progressing."""
    label = engine_label(engine)

    def mirror(_run: AgentRun, step: AgentStep) -> None:
        _record_step(merged, step.state, f"[{label}] {step.detail}", data=dict(step.data), on_progress=on_progress)

    return mirror


def _adopt_engine_run(merged: AgentRun, engine: str, engine_run: AgentRun) -> AgentRun:
    """Carry one engine's non-list payload (host profile, statistics, favicon) through unchanged.

    The merged run keeps the mirrored steps and any engine failures as the audit trail, while the
    payload, action and state come from the engine that actually produced them.
    """
    for field in (
        "action",
        "target",
        "stats_fields",
        "result_data",
        "state",
        "query",
        "queries",
        "fields",
        "assets",
        "asset_confidence",
        "website_candidates",
        "evidence_counts",
        "result_count",
        "assets_truncated",
        "scan_requested_by_user",
        "scan_recommended",
        "scan_reason",
        "scan_template_ids",
        "scan_severities",
        "scan_targets",
        "stop_reason",
        "organization_names",
        "domain_hypotheses",
        "summary",
    ):
        setattr(merged, field, getattr(engine_run, field))
    merged.engine = engine
    return merged


def _merge_runs(merged: AgentRun, per_engine: list[tuple[str, AgentRun]]) -> None:
    """Merge per-engine runs on the shared asset identity, keeping the strongest evidence."""
    fields: list[str] = []
    assets: list[dict[str, Any]] = []
    confidences: list[str] = []
    positions: dict[tuple[str, ...], int] = {}
    candidates: dict[str, WebsiteCandidate] = {}
    templates: list[str] = []
    severities: list[str] = []
    targets: list[str] = []
    reasons: list[str] = []
    stops: list[str] = []
    organizations: list[str] = []
    hypotheses: list[str] = []
    seen_by_engine: dict[tuple[str, ...], set[str]] = {}
    for engine, run in per_engine:
        label = engine_label(engine)
        # Rename the few engine-native columns that already have a unified name, so one concept
        # keeps one column when records from different engines describe the same asset.
        aliases = merge_aliases(engine)
        for field in run.fields:
            name = aliases.get(field, field)
            if name not in fields:
                fields.append(name)
        for asset, confidence in zip(run.assets, run.asset_confidence, strict=False):
            incoming = {aliases.get(key, key): value for key, value in asset.items()}
            identity = _asset_identity(incoming)
            seen_by_engine.setdefault(identity, set()).add(engine)
            position = positions.get(identity)
            if position is None:
                positions[identity] = len(assets)
                assets.append(incoming)
                confidences.append(confidence or "recall")
                continue
            kept = assets[position]
            if EVIDENCE_RANK.get(confidence, 1) > EVIDENCE_RANK.get(confidences[position], 1):
                # Stronger evidence wins, but columns it lacks are still filled in from the
                # weaker row: a merge must never drop what an engine actually observed.
                assets[position] = {**kept, **{key: value for key, value in incoming.items() if value not in (None, "")}}
                confidences[position] = confidence
            else:
                # The stored row keeps its columns, but an empty value must not erase what the
                # incoming row actually observed (the stronger-evidence branch filters too).
                assets[position] = {
                    **incoming,
                    **{key: value for key, value in kept.items() if value not in (None, "")},
                }
        for candidate in run.website_candidates:
            existing = candidates.get(candidate.domain)
            if existing is None:
                candidates[candidate.domain] = candidate.model_copy(deep=True)
                continue
            strongest = existing if _CANDIDATE_RANK.get(existing.status, 0) >= _CANDIDATE_RANK.get(candidate.status, 0) else candidate
            candidates[candidate.domain] = existing.model_copy(
                update={
                    "status": strongest.status,
                    "confidence": strongest.confidence,
                    "evidence": list(dict.fromkeys([*existing.evidence, *candidate.evidence])),
                    "hosts": list(dict.fromkeys([*existing.hosts, *candidate.hosts]))[:8],
                }
            )
        merged.queries.extend(item.model_copy(update={"purpose": f"[{label}] {item.purpose}"}) for item in run.queries)
        merged.reflection_notes.extend(f"[{label}] {note}" for note in run.reflection_notes)
        for template in run.scan_template_ids:
            if template not in templates:
                templates.append(template)
        for severity in run.scan_severities:
            if severity not in severities:
                severities.append(severity)
        for target in run.scan_targets:
            if target not in targets and len(targets) < 10_000:
                targets.append(target)
        if run.scan_recommended and run.scan_reason and run.scan_reason not in reasons:
            reasons.append(f"{label}：{run.scan_reason}")
        if run.stop_reason:
            stops.append(f"{label}：{run.stop_reason}")
        for name in run.organization_names:
            if name not in organizations:
                organizations.append(name)
        for hypothesis in run.domain_hypotheses:
            if hypothesis not in hypotheses:
                hypotheses.append(hypothesis)
    merged.assets = assets
    merged.asset_confidence = confidences
    merged.fields = fields or list(dict.fromkeys(key for asset in assets for key in asset))
    merged.website_candidates = sorted(candidates.values(), key=lambda item: (item.status, item.domain))
    merged.evidence_counts = {
        strategy: sum(1 for value in confidences if value == strategy)
        for strategy in EVIDENCE_RANK
        if any(value == strategy for value in confidences)
    }
    # The merged list is deduplicated across engines, so the count must be the list length:
    # summing per-engine counts would report one asset twice as "去重结果".
    merged.result_count = len(assets)
    # Cross-engine corroboration: an asset two engines independently indexed is much stronger
    # evidence than one engine's single query.
    merged.corroboration = {
        "multi_engine": sum(1 for names in seen_by_engine.values() if len(names) > 1),
        "single_engine": sum(1 for names in seen_by_engine.values() if len(names) == 1),
    }
    merged.assets_truncated = any(run.assets_truncated for _, run in per_engine)
    for _, run in per_engine:
        for key, value in run.age_filter.items():
            merged.age_filter[key] = merged.age_filter.get(key, 0) + value
    merged.scan_template_ids = templates
    merged.scan_severities = align_scan_severities(templates, severities) if templates else severities
    merged.scan_targets = targets
    merged.scan_recommended = any(run.scan_recommended for _, run in per_engine)
    merged.scan_reason = " ".join(reasons) if reasons else "未明确要求主动扫描。"
    merged.stop_reason = "；".join(stops)
    merged.organization_names = organizations
    merged.domain_hypotheses = hypotheses
    merged.query = merged.queries[0].query if merged.queries else None


def _multi_summary_prompt(merged: AgentRun, intent: str, per_engine: list[tuple[str, AgentRun]]) -> str:
    breakdown = [
        {
            "engine": engine_label(engine),
            "records": run.result_count,
            "queries": len(run.queries),
            "stop_reason": run.stop_reason,
        }
        for engine, run in per_engine
    ]
    failures = {engine_label(engine): error.get("message") or error.get("code") for engine, error in merged.engine_errors.items()}
    return (
        f"{_search_summary_prompt(merged, intent)}\n"
        f"Per-engine contribution: {json.dumps(breakdown, ensure_ascii=False)}\n"
        + (f"Engines that failed: {json.dumps(failures, ensure_ascii=False)}\n" if failures else "")
        + "Attribute findings to the engine that produced them when it matters, and name any engine whose results are missing."
    )


class MultiEngineAgent:
    """Run the workflow once per engine and merge the runs into one asset-mapping briefing.

    Each engine plans with its own syntax rules (queries are never translated across engines),
    then the runs are merged on the shared asset identity, so one briefing covers FOFA's
    fingerprint/filing view, Shodan's service/CVE view and Hunter's component/filing metadata.
    A single engine failing keeps the other engines' results and records the failure instead of
    discarding the run. Non-list intents (host profile, statistics, favicon) are delegated to the
    first engine that accepts them, because only that engine's payload can be rendered.
    """

    def __init__(
        self,
        engines: Sequence[str],
        router: ProviderRouter,
        *,
        engine_factory: Callable[[str], AssetSearchEngine] = create_engine,
    ) -> None:
        self.engines = tuple(engines)
        self.router = router
        self._engine_factory = engine_factory

    async def run(
        self,
        intent: str,
        *,
        max_records: int = 1000,
        max_pages: int = 10,
        fields: list[str] | None = None,
        smart_fields: bool = True,
        min_evidence: str | None = None,
        ensure_timestamp: bool = False,
        on_progress: AgentProgressCallback | None = None,
        on_page: AgentPageCallback | None = None,
    ) -> AgentRun:
        run = AgentRun(intent=intent, engine=MULTI_ENGINE, action=AgentAction.MULTI_SEARCH)
        remaining = max(1, max_records)
        engines_left = len(self.engines)
        completed: list[tuple[str, AgentRun]] = []
        for engine in self.engines:
            label = engine_label(engine)
            # Split the caller's budget across the engines that have not run yet, so the merged
            # result stays inside max_records instead of multiplying it by the engine count.
            budget = max(1, remaining // max(1, engines_left))
            engines_left -= 1
            _record_step(
                run,
                AgentState.INTENT,
                f"正在用 {label} 独立规划与检索（本引擎预算 {budget:,} 条）",
                data={"engine": engine, "budget": budget},
                on_progress=on_progress,
            )
            try:
                async with self._engine_factory(engine) as client:
                    engine_run = await AssetAgent(client, self.router).run(
                        intent,
                        max_records=budget,
                        max_pages=max_pages,
                        fields=fields,
                        smart_fields=smart_fields,
                        min_evidence=min_evidence,
                        ensure_timestamp=ensure_timestamp,
                        on_progress=_mirror_steps(engine, run, on_progress),
                        on_page=on_page,
                    )
            except FofaError as exc:
                run.engine_errors[engine] = exc.as_dict()
                _record_step(run, AgentState.FAILED, f"{label} 检索失败：{exc.message}", data=exc.as_dict(), on_progress=on_progress)
                continue
            if engine_run.error:
                run.engine_errors[engine] = dict(engine_run.error)
                _record_step(
                    run,
                    AgentState.FAILED,
                    f"{label} 检索失败：{engine_run.error.get('message') or engine_run.error.get('code')}",
                    data=engine_run.error,
                    on_progress=on_progress,
                )
                continue
            if engine_run.action not in SEARCH_ACTIONS:
                # A host profile, statistics or favicon payload can only be rendered by the engine
                # that produced it, so the intent is delegated instead of merged and discarded.
                _record_step(
                    run,
                    AgentState.INTENT,
                    f"{label} 将意图判定为 {engine_run.action.value}；该动作不可跨引擎合并，已由 {label} 单独完成",
                    data={"engine": engine, "action": engine_run.action.value},
                    on_progress=on_progress,
                )
                return self._finish(_adopt_engine_run(run, engine, engine_run))
            completed.append((engine, engine_run))
            _record_step(
                run,
                AgentState.EVALUATE,
                f"{label} 完成：{engine_run.result_count:,} 条去重资产，{len(engine_run.queries)} 个查询策略",
                data={"engine": engine, "records": engine_run.result_count, "queries": len(engine_run.queries)},
                on_progress=on_progress,
            )
            remaining = max(1, remaining - engine_run.result_count)
        if not completed:
            run.error = dict(next(iter(run.engine_errors.values()), {"code": "agent_error", "message": "所有引擎均失败"}))
            _record_step(run, AgentState.FAILED, "所有引擎均失败，未生成资产测绘结果", data=run.error, on_progress=on_progress)
            return self._finish(run)
        _merge_runs(run, completed)
        if len(run.assets) > max_records:
            # The per-engine budgets are computed from the engines still to run, so a late engine
            # can still overshoot the caller's cap; the merged list is trimmed to honour it.
            run.assets = run.assets[:max_records]
            run.asset_confidence = run.asset_confidence[:max_records]
            run.result_count = len(run.assets)
            run.assets_truncated = True
        _record_step(
            run,
            AgentState.EVALUATE,
            f"合并完成：{len(run.assets):,} 条去重资产，覆盖 {len(run.fields)} 个字段",
            data={"engines": [engine for engine, _ in completed], "assets": len(run.assets), "fields": run.fields},
            on_progress=on_progress,
        )
        _record_step(run, AgentState.SUMMARIZE, "正在合并多路证据生成资产测绘简报", on_progress=on_progress)
        summary = await self.router.generate(
            "summarizer",
            system=briefing_system(engine_label(MULTI_ENGINE)),
            prompt=_multi_summary_prompt(run, intent, completed),
        )
        _apply_generated_summary(run, summary.text, fallback=_local_search_summary(run), require_asset_briefing=True)
        _record_step(run, AgentState.COMPLETED, "多引擎资产测绘完成", on_progress=on_progress)
        return self._finish(run)

    def _finish(self, run: AgentRun) -> AgentRun:
        run.route_events = [event.model_dump(mode="json") for event in self.router.events]
        return run
