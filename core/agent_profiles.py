"""Engine-specific knowledge for the reconnaissance agent.

`core/agent.py` owns the recoverable workflow (plan -> execute -> reflect -> summarize).
Everything that differs between engines lives here: planner/reflector/repair prompts,
query syntax rules, deterministic fallback plans, return-field catalogues, capability
downgrades and credit policy. Adding an engine therefore cannot silently inherit another
engine's syntax or membership assumptions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from core.censys import CENSYS_FIELDS as CENSYS_FIELD_CATALOG
from core.censys import DEFAULT_OUTPUT_FIELDS as CENSYS_DEFAULT_FIELDS
from core.censys import query_errors as censys_query_errors
from core.daydaymap import DAYDAYMAP_FIELDS
from core.daydaymap import DEFAULT_OUTPUT_FIELDS as DAYDAYMAP_DEFAULT_FIELDS
from core.daydaymap import query_errors as daydaymap_query_errors
from core.engines import TIMESTAMP_FIELDS, normalize_engine
from core.engines import favicon_query as engine_favicon_query
from core.fields import (
    LOCAL_RESULT_FIELDS,
    STATS_FIELDS,
    account_tier,
    available_fields,
    decide_fields,
    fofa_request_fields,
    merge_return_fields,
)
from core.hunter import DEFAULT_OUTPUT_FIELDS as HUNTER_DEFAULT_FIELDS
from core.hunter import HUNTER_FIELDS, HUNTER_FILTERS, hunter_syntax_errors
from core.membership import host_fallback_query, membership_from_account, planner_capabilities_prompt
from core.models import FofaError, FofaErrorCode, IconDigest
from core.rules import match_intent_rules, rules_hint_for_prompt
from core.scans import default_nuclei_template_ids
from core.shodan import (
    DEFAULT_OUTPUT_FIELDS,
    FACET_ALIASES,
    SHODAN_FIELDS,
    SHODAN_FILTERS,
    shodan_syntax_errors,
)

SEARCH_ACTION_FOFA = "fofa_search"
SEARCH_ACTION_SHODAN = "shodan_search"
SEARCH_ACTION_HUNTER = "hunter_search"
SEARCH_ACTION_DAYDAYMAP = "daydaymap_search"
SEARCH_ACTION_CENSYS = "censys_search"
HOST_ACTION = "host_query"
STATS_ACTION = "stat_query"
ICON_ACTION = "icon_query"

SHODAN_FIELD_LIMIT = 14
SHODAN_FALLBACK_FIELDS = ("host", "ip", "port", "protocol", "title", "domain")
_SHODAN_DOMAIN_CLAUSE = re.compile(r"(?:hostname|domain|ssl\.cert\.subject\.cn)\s*:\s*([^\s]+)", re.IGNORECASE)
# Unified field name -> intent keywords that justify asking Shodan for it.
_SHODAN_FIELD_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("组织", "公司", "机构", "归属", "运营商", "org", "organization", "company", "isp"), ("org", "isp", "asn")),
    (("端口", "服务", "协议", "port", "service", "protocol"), ("protocol", "server", "status_code")),
    (
        ("产品", "版本", "中间件", "数据库", "设备", "cms", "oa", "vpn", "product", "version", "device"),
        ("product", "version", "os"),
    ),
    (("漏洞", "cve", "vuln"), ("vulns",)),
    (("证书", "ssl", "tls", "cert"), ("ssl_cn",)),
    (("banner", "横幅", "正文", "页面内容", "body", "content"), ("banner",)),
    (("城市", "地域", "位置", "city", "region", "location"), ("city", "region")),
    (("时间", "更新", "timestamp", "updated"), ("timestamp",)),
)

# Hunter metadata worth pulling in only when the intent asks for it (they are China-specific
# columns the other engines do not have).
_HUNTER_FIELD_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("备案", "icp", "资质", "归属"), ("icp", "icp_exception")),
    (("组件", "中间件", "产品", "版本", "component", "app"), ("product", "version", "server")),
    (("标签", "指纹", "tag"), ("asset_tag", "ip_tag")),
    (("组织", "公司", "机构", "运营商", "org", "company", "isp"), ("org", "as_org", "isp")),
    (("端口", "服务", "协议", "port", "protocol"), ("base_protocol", "status_code")),
    (("证书", "ssl", "tls", "cert"), ("ssl_cn", "cert_sha256")),
    (("区域", "地域", "省市", "city", "region", "province"), ("region", "city")),
    (("banner", "横幅", "页面内容", "正文", "body"), ("banner", "body")),
    (("时间", "更新", "timestamp", "updated"), ("timestamp",)),
)
HUNTER_FIELD_LIMIT = 14
HUNTER_FALLBACK_FIELDS = ("host", "ip", "port", "protocol", "title", "domain")

DAYDAYMAP_FIELD_LIMIT = 14
DAYDAYMAP_FALLBACK_FIELDS = ("host", "ip", "port", "protocol", "title", "hostnames")
CENSYS_FIELD_LIMIT = 14
CENSYS_FALLBACK_FIELDS = ("host", "ip", "port", "protocol", "title")
_IP_IN_INTENT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DAYDAYMAP_DOMAIN_CLAUSE = re.compile(r'domain\s*=\s*"([^"]+)"', re.IGNORECASE)
_DAYDAYMAP_FIELD_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("服务", "service", "端口", "port", "组件", "产品", "product", "指纹"), ("product", "server", "status_code")),
    (("证书", "tls", "ssl", "https"), ("ssl_cn", "cert")),
    (("备案", "icp", "主体", "单位", "公司"), ("icp_reg_name", "org")),
    (("地理", "位置", "城市", "省份", "国家", "region", "country"), ("country", "country_code", "region", "city")),
    (("标签", "资产类型", "行业", "tag", "industry"), ("tags", "industry")),
    (("标题", "title", "状态码", "header"), ("title", "status_code", "header")),
)
_CENSYS_FIELD_HINTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("服务", "service", "端口", "port", "组件", "产品", "product", "指纹"), ("product", "version", "banner")),
    (("证书", "tls", "ssl", "https"), ("ssl_cn",)),
    (("地理", "位置", "城市", "省份", "国家", "region", "country"), ("country", "country_code", "region", "city")),
    (("组织", "归属", "asn", "whois", "运营商"), ("org", "isp", "asn", "hostnames")),
    (("标题", "title", "状态码", "服务端", "server"), ("status_code", "server", "title")),
)
# Clauses that carry a registrable domain in Hunter syntax (verified: `domain.suffix=` and
# `domain=` are both accepted).
_HUNTER_DOMAIN_CLAUSE = re.compile(r"\b(?:domain|domain\.suffix|url)\s*=\s*[\"“”]([^\"“”\s]+)[\"“”]", re.IGNORECASE)

SCAN_AUTHORIZATION_PATTERN = re.compile(r"(?:扫描|漏洞检测|漏洞扫描|nuclei|scan(?:ning)?)", re.IGNORECASE)
SCAN_DENIAL_PATTERN = re.compile(
    r"(?:不要|不需要|无需|禁止|拒绝|不进行|请勿|勿).{0,8}(?:扫描|漏洞检测|漏洞扫描|nuclei)"
    r"|(?:no|do\s+not|don't|without)\s+(?:nuclei\s+)?scan(?:ning)?",
    re.IGNORECASE,
)
ORGANIZATION_SUFFIX_PATTERN = (
    "公司|集团|大学|学院|学校|研究院|研究所|实验室|工作室|医院|协会|政府|委员会|中心|银行"
)
EN_ORGANIZATION_SUFFIX_PATTERN = (
    "university|college|company|corporation|institute|laboratory|studio|school|"
    "hospital|association|government|bank"
)
ORGANIZATION_INTENT_PATTERN = re.compile(
    rf"(?:{ORGANIZATION_SUFFIX_PATTERN})|(?:{EN_ORGANIZATION_SUFFIX_PATTERN})\b",
    re.IGNORECASE,
)
CN_ORGANIZATION_NAME_PATTERN = re.compile(
    rf"(?:[A-Za-z][A-Za-z0-9._&'-]*|[\u4e00-\u9fff]|\d+){{1,40}}(?:{ORGANIZATION_SUFFIX_PATTERN})"
)
EN_ORGANIZATION_NAME_PATTERN = re.compile(
    rf"\b((?:[A-Za-z][A-Za-z0-9.&']+\s+)+(?:{EN_ORGANIZATION_SUFFIX_PATTERN}))\b",
    re.IGNORECASE,
)
FALLBACK_NOISE_PATTERN = re.compile(
    r"(?:请|麻烦|帮我|帮忙|我要|需要|尽可能|尽量|查询|查找|搜索|收集|发现|分析|看看|一下|"
    r"的?子域名网站|的?子域名|子域名|的?官网(?:网站)?|官网|的?网站|网站|的?域名|域名|"
    r"的?站点|站点|的?主机名?|主机|的?网页|网页|"
    r"的?全网资产|的?公开资产|相关资产|资产清单|的?资产|相关|"
    r"并且|并|然后|进行|执行|漏洞检测|漏洞扫描|扫描一下|扫描)"
    r"|\b(?:please|help\s+me|find|search|collect|discover|"
    r"subdomains?|websites?|website|domains?|hosts?|assets?|and|scan(?:ning)?|them)\b",
    re.IGNORECASE,
)


def user_authorized_scan(intent: str) -> bool:
    return not SCAN_DENIAL_PATTERN.search(intent) and bool(SCAN_AUTHORIZATION_PATTERN.search(intent))


def _query_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ").strip()


def _organization_core_name(text: str) -> str | None:
    english = EN_ORGANIZATION_NAME_PATTERN.search(text)
    if english:
        return english.group(1).strip()
    chinese = CN_ORGANIZATION_NAME_PATTERN.search(text)
    if chinese:
        return chinese.group(0).strip()
    return None


def _fallback_search_term(intent: str) -> str:
    quoted = re.search(r"[“‘'\"]([^”’'\"]{2,100})[”’'\"]", intent)
    if quoted:
        return quoted.group(1).strip()
    cleaned = FALLBACK_NOISE_PATTERN.sub(" ", intent)
    cleaned = re.sub(r"[，。！？、,:：;；()（）\[\]{}]+", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    organization = _organization_core_name(cleaned) or _organization_core_name(intent)
    if organization:
        return organization[:100]
    parts = [part.strip() for part in cleaned.split() if len(part.strip()) >= 2]
    return max(parts, key=len)[:100] if parts else intent.strip()[:100]


def fofa_fallback_plan(intent: str) -> dict[str, Any]:
    """Produce a conservative executable FOFA search when planner JSON is unusable."""
    domain_match = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:/|\b)", intent, re.IGNORECASE)
    ip_match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", intent)
    if domain_match:
        domain = _query_literal(domain_match.group(1).lower().removeprefix("www."))
        query = f'(domain="{domain}" || host="{domain}")'
        purpose = f"结构化规划降级：按用户提供的域名 {domain} 检索"
        strategy = "precision"
    elif ip_match:
        ip = _query_literal(ip_match.group(0))
        query = f'ip="{ip}"'
        purpose = f"结构化规划降级：按用户提供的 IP {ip} 检索"
        strategy = "precision"
    else:
        library = match_intent_rules(intent, limit=3)
        if library:
            return {
                "action": SEARCH_ACTION_FOFA,
                "target": "",
                "queries": [
                    {
                        "query": rule.query,
                        "purpose": f"规则库精确指纹：{rule.name}",
                        "strategy": "precision",
                    }
                    for rule in library
                ],
                "stats_fields": [],
                "fields": ["host", "ip", "port", "protocol", "title", "domain"],
                "scan": _scan_section(intent),
            }
        term = _query_literal(_fallback_search_term(intent))
        clauses = [f'title="{term}"', f'body="{term}"']
        if ORGANIZATION_INTENT_PATTERN.search(term):
            clauses.insert(0, f'org="{term}"')
        query = "(" + " || ".join(clauses) + ")"
        purpose = f"结构化规划降级：围绕用户核心名称“{term}”进行保守召回"
        strategy = "recall"
    return {
        "action": SEARCH_ACTION_FOFA,
        "target": "",
        "queries": [{"query": query, "purpose": purpose, "strategy": strategy}],
        "stats_fields": [],
        "fields": ["host", "ip", "port", "protocol", "title", "domain"],
        "scan": _scan_section(intent),
    }


def shodan_fallback_plan(intent: str) -> dict[str, Any]:
    """Produce a conservative executable Shodan search when planner JSON is unusable."""
    domain_match = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:/|\b)", intent, re.IGNORECASE)
    ip_match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", intent)
    queries: list[dict[str, Any]] = []
    if domain_match:
        domain = _query_literal(domain_match.group(1).lower().removeprefix("www."))
        queries = [
            {
                "query": f"hostname:{domain}",
                "purpose": f"结构化规划降级：按用户提供的域名 {domain} 检索主机名",
                "strategy": "precision",
            },
            {
                "query": f"domain:{domain}",
                "purpose": f"结构化规划降级：按注册域 {domain} 补充检索",
                "strategy": "balanced",
            },
        ]
    elif ip_match:
        ip = _query_literal(ip_match.group(0))
        queries = [{"query": f"ip:{ip}", "purpose": f"结构化规划降级：按用户提供的 IP {ip} 检索", "strategy": "precision"}]
    else:
        term = _query_literal(_fallback_search_term(intent))
        if ORGANIZATION_INTENT_PATTERN.search(term):
            queries.append(
                {"query": f'org:"{term}"', "purpose": f"结构化规划降级：按组织名“{term}”检索", "strategy": "balanced"}
            )
        queries.append(
            {
                "query": f'http.title:"{term}"',
                "purpose": f"结构化规划降级：围绕用户核心名称“{term}”进行保守召回",
                "strategy": "recall",
            }
        )
    return {
        "action": SEARCH_ACTION_SHODAN,
        "target": "",
        "queries": queries,
        "stats_fields": [],
        "fields": list(SHODAN_FALLBACK_FIELDS),
        "scan": _scan_section(intent),
    }


def hunter_fallback_plan(intent: str) -> dict[str, Any]:
    """Produce a conservative executable Hunter search when planner JSON is unusable."""
    domain_match = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:/|\b)", intent, re.IGNORECASE)
    ip_match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", intent)
    queries: list[dict[str, Any]] = []
    if domain_match:
        domain = _query_literal(domain_match.group(1).lower().removeprefix("www."))
        queries = [
            {
                "query": f'domain.suffix="{domain}"',
                "purpose": f"结构化规划降级：按主域 {domain} 检索",
                "strategy": "precision",
            },
            {
                "query": f'domain="{domain}"',
                "purpose": f"结构化规划降级：按域名包含 {domain} 补充检索",
                "strategy": "balanced",
            },
        ]
    elif ip_match:
        ip = _query_literal(ip_match.group(0))
        queries = [{"query": f'ip="{ip}"', "purpose": f"结构化规划降级：按用户提供的 IP {ip} 检索", "strategy": "precision"}]
    else:
        term = _query_literal(_fallback_search_term(intent))
        if ORGANIZATION_INTENT_PATTERN.search(term):
            queries.append(
                {"query": f'company="{term}"', "purpose": f"结构化规划降级：按单位名“{term}”检索", "strategy": "balanced"}
            )
        queries.append(
            {
                "query": f'web.title="{term}"',
                "purpose": f"结构化规划降级：围绕用户核心名称“{term}”进行保守召回",
                "strategy": "recall",
            }
        )
    return {
        "action": SEARCH_ACTION_HUNTER,
        "target": "",
        "queries": queries,
        "stats_fields": [],
        "fields": list(HUNTER_FALLBACK_FIELDS),
        "scan": _scan_section(intent),
    }


def _scan_section(intent: str) -> dict[str, Any]:
    authorized = user_authorized_scan(intent)
    return {
        "recommended": authorized,
        "reason": "用户明确提出扫描需求；先完成只读资产发现，再展示边界并请求确认。"
        if authorized
        else "未明确要求主动扫描。",
        "template_ids": default_nuclei_template_ids() if authorized else [],
        "severities": ["medium", "high", "critical"],
    }


def plan_schema(search_action: str) -> dict[str, Any]:
    """Planner output contract; the search action carries the engine's own verb."""
    return {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": [search_action, HOST_ACTION, STATS_ACTION, ICON_ACTION]},
            "target": {"type": "string"},
            "queries": {
                "type": "array",
                "minItems": 0,
                "maxItems": 5,
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
            "stats_fields": {"type": "array", "items": {"type": "string"}},
            "fields": {"type": "array", "items": {"type": "string"}},
            "scan": {
                "type": "object",
                "properties": {
                    "recommended": {"type": "boolean"},
                    "reason": {"type": "string"},
                    "template_ids": {"type": "array", "items": {"type": "string"}},
                    "severities": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    },
                },
                "required": ["recommended", "reason", "template_ids", "severities"],
                "additionalProperties": False,
            },
        },
        "required": ["action", "target", "queries", "stats_fields", "fields", "scan"],
        "additionalProperties": False,
    }


def briefing_system(label: str) -> str:
    """Shared defensive-briefing contract; only the engine name changes."""
    return (
        "You write a high-value defensive asset briefing in Simplified Chinese. The reader already saw the query-strategy table "
        f"and the asset list; do not recount how many {label} queries ran, do not explain balanced/recall/precision as a method, "
        "and do not narrate available_count, pagination, reflection rounds or intermediate totals. "
        "Start immediately with ## 结论. Do not write chain-of-thought, hidden reasoning, or a preamble. "
        "Synthesize concrete evidence, concentrations, anomalies, attribution limits, coverage gaps and prioritized actions; every claim "
        "must be traceable to the supplied data. Avoid generic security advice and do not pad the answer. Keep the briefing between 350 "
        "and 900 Chinese characters when data is non-empty. "
        "Output GitHub-flavored Markdown in this exact skeleton, with a blank line between sections:\n"
        "## 结论\n"
        "2-3 sentences stating the asset picture, confidence split and most important exposure signal.\n\n"
        "## 高置信资产\n"
        "- **资产簇**：`host`（`ip`），说明归属证据和用途\n\n"
        "## 风险与暴露面\n"
        "- **端口/技术/可达性信号**：具体数据，以及为什么值得关注；不要把暴露直接写成漏洞\n\n"
        "## 证据边界与噪声\n"
        "- **候选簇**：具体误报或归属不确定性及依据\n\n"
        "## 覆盖缺口\n"
        "- **数据缺口**：分页截断、字段缺失、不可达或仍待交叉验证的范围\n\n"
        "## 处置优先级\n"
        "1. 基于具体资产和证据的验证动作、目的与预期结果\n"
        "Rules: use `##` headings only, never numbered section titles; each bullet is one short line; "
        "write 2-5 substantive bullets in each applicable evidence section and 3-5 ordered actions; "
        "wrap hosts, IPs and domains in backticks; bold the cluster label; at most 5 bullets per section; "
        "at most 3 hosts per bullet, then write 等 N 个; do not dump comma-separated subdomain lists. "
        "Do not invent domains or products absent from the data. Treat Structured website candidates as the authoritative attribution "
        "boundary: list every corroborated website in the high-confidence section, never promote observed/candidate entries to confirmed "
        "or high-confidence, and do not omit a corroborated website merely because it appears late in the asset sample."
    )


# Registrable scopes that are too generic to pivot on (a certificate filter on "edu.cn" would
# return every Chinese university).
GENERIC_DOMAIN_SCOPES = frozenset({"ac.cn", "com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn"})


@dataclass(frozen=True)
class IntentContext:
    """Pivots the user's wording states explicitly, so playbooks never invent a target."""

    domain: str | None = None
    organization: str | None = None


def intent_context(intent: str) -> IntentContext:
    """Extract an explicit registrable domain and organization name from the intent."""
    match = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:/|\b)", intent, re.IGNORECASE)
    domain = match.group(1).lower().removeprefix("www.") if match else None
    if domain in GENERIC_DOMAIN_SCOPES:
        domain = None
    # Strip the request verbs before naming an organization: `_organization_core_name` matches from
    # the start of the string, so "收集某某大学" would otherwise become the filter `org="收集某某大学"`
    # and return nothing.
    cleaned = re.sub(r"\s+", " ", FALLBACK_NOISE_PATTERN.sub(" ", intent)).strip()
    organization = _organization_core_name(cleaned)
    if organization is None and ORGANIZATION_INTENT_PATTERN.search(intent):
        organization = _organization_core_name(intent)
    return IntentContext(domain=domain, organization=organization)


@dataclass(frozen=True)
class ActionFallback:
    """A capability-driven action replacement, always with an auditable note."""

    action: str
    note: str
    queries: list[dict[str, Any]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FieldSelection:
    allowed: list[str]
    denied: list[str]


class AgentProfile(Protocol):
    engine: str
    label: str
    search_action: str
    timestamp_field: str
    default_fields: tuple[str, ...]
    stats_fields: tuple[str, ...]
    default_stats_fields: tuple[str, ...]

    async def prepare(self) -> None: ...

    def plan_schema(self) -> dict[str, Any]: ...

    def planner_system(self) -> str: ...

    def planner_context(self, intent: str, *, smart_fields: bool, requested_fields: list[str] | None) -> str: ...

    def reflector_system(self) -> str: ...

    def repair_system(self, *, reflection: bool = False) -> str: ...

    def summarizer_system(self) -> str: ...

    def host_summary_system(self) -> str: ...

    def stats_summary_system(self) -> str: ...

    def library_hint(self, intent: str) -> str: ...

    def library_queries(self, intent: str, limit: int) -> list[dict[str, Any]]: ...

    def query_errors(self, query: str) -> list[str]: ...

    def fallback_plan(self, intent: str) -> dict[str, Any]: ...

    def align_action(self, action: str, target: str | None, *, has_queries: bool) -> ActionFallback | None: ...

    def hypothesis_query(self, domains: list[str]) -> str: ...

    def evidence_key(self, strategy: str) -> str: ...

    def attribution(self, asset: dict[str, Any]) -> dict[str, Any]: ...

    def planning_domains(self, queries: list[str]) -> set[str]: ...

    def suggest_fields(self, requested: list[str], *, intent: str) -> list[str]: ...

    def decide_fields(self, requested: list[str]) -> FieldSelection: ...

    def denied_fields_step(self, denied: list[str], fields: list[str]) -> tuple[str, dict[str, Any]]: ...

    def smart_fields_step(self, fields: list[str]) -> tuple[str, dict[str, Any]]: ...

    def request_fields(self, fields: list[str]) -> list[str]: ...

    def icon_query(self, icon_hash: int) -> str: ...

    def soft_stop(self, error: FofaError) -> str | None: ...


class FofaProfile:
    """Every FOFA-specific decision the agent used to hard-code."""

    engine = "fofa"
    label = "FOFA"
    search_action = SEARCH_ACTION_FOFA
    # Last time this engine confirmed the asset, used by the freshness filter.
    timestamp_field = TIMESTAMP_FIELDS["fofa"]
    default_fields = ("host", "ip", "port", "protocol", "title")
    stats_fields = tuple(sorted(STATS_FIELDS))
    default_stats_fields = ("country", "port")

    def __init__(self, client: Any = None) -> None:
        """A client is optional: prompts, syntax rules and field catalogues need no connection."""
        self.client = client

    # -- capability discovery -------------------------------------------------
    def _user_info(self) -> dict[str, Any]:
        return getattr(self.client, "user_info", None) or {}

    def _vip_level(self) -> Any:
        user_info = self._user_info()
        return user_info.get("vip_level", user_info.get("level", "unknown"))

    def _tier(self) -> str | None:
        return account_tier(self._vip_level())

    async def prepare(self) -> None:
        return None

    # -- prompt material ------------------------------------------------------
    def plan_schema(self) -> dict[str, Any]:
        return plan_schema(self.search_action)

    def planner_system(self) -> str:
        return (
            "You are a FOFA action router and query strategist. Select exactly one action: fofa_search for an asset list; "
            "host_query only for a single explicit IP/host profile; stat_query for counts, distributions, rankings or trends; "
            "or icon_query for reverse-searching an explicit website favicon. Put the explicit host/URL in target for host/icon "
            "actions, use an empty target for other actions, and select only supported aggregate dimensions for stat_query. "
            "For fofa_search, translate defensive asset-discovery intent into one to five high-quality, "
            "complementary read-only query strategies. A strategy may be a focused single clause or an advanced composite "
            "expression using parentheses, || and &&. Optimize the portfolio for coverage, precision and API efficiency: combine "
            "aliases or equivalent ownership signals in one query when that saves requests without adding noise; keep queries "
            "separate when they represent different precision/recall tradeoffs or need independent result evaluation. Include at "
            "least one balanced or recall-oriented strategy for organization discovery. Use domain, host, org, certificate "
            "subject, "
            "ICP, title, header or body only when semantically appropriate. Search syntax fields such as body= are independent of "
            "returned result fields. Do not invent a domain, ICP number, company alias or geography; organization-to-domain "
            "resolution is performed separately. Avoid an unbounded body/header organization-name query when it is likely to "
            "swamp the "
            "portfolio with third-party mentions; constrain it when a safe country, asset type or ownership signal is available. "
            "Keep every query "
            "within "
            "the exact organization, geography and authorization scope requested by the user. Avoid redundant queries whose result "
            "sets are predictably subsumed by another strategy. "
            "Also assess whether a bounded Nuclei follow-up would be useful. A scan recommendation is only a plan: "
            "never execute it. Use only template IDs made of letters, digits, dot, underscore or hyphen; "
            "For a general scan, the application will add its bounded multi-template web-baseline profile; "
            "use template_ids only for justified product-specific additions or exact IDs named by the user. "
            "Never emit shell arguments. Select returned fields from the allowed membership catalogue supplied in the user prompt; "
            "match the field count to the task and do not request body/header/banner unless the user asked for page content. "
            "When the user names a known product, OA, VPN, middleware, database, camera, CMS or ops panel, prefer the bundled "
            "FOFA library app= queries supplied in the user prompt. Use those query strings verbatim as precision strategies "
            "and do not invent app= names."
        )

    def planner_context(self, intent: str, *, smart_fields: bool, requested_fields: list[str] | None) -> str:
        tier = self._tier()
        context = f"User intent: {intent}\n{planner_capabilities_prompt(self._vip_level())}"
        if requested_fields:
            return context
        if smart_fields:
            context += (
                f"\nFOFA membership tier: {tier or 'registered'}"
                f"\nAllowed return fields: {', '.join(sorted(available_fields(tier)))}"
                f"\nSuggested return fields: {', '.join(merge_return_fields([], account_tier_name=tier, intent=intent))}"
            )
        return context

    def reflector_system(self) -> str:
        return (
            "You are the result-reflection stage of a FOFA asset-discovery agent. Evaluate each executed strategy using "
            "its raw hit count and deduplicated additions, then propose zero to two efficient complementary strategies. "
            "A strategy may be a single clause or an advanced composite expression with parentheses, || and &&. Never "
            "mechanically split every field into a separate query. Combine equivalent aliases/signals when that improves "
            "API efficiency; separate precision and recall strategies when their noise profiles differ. When all results "
            "are zero, use a correction ladder: first remove only unsupported or overly strict conditions, then try a "
            "balanced composite across semantically valid ownership/content fields, and finally a bounded recall query "
            "using the strongest user-provided identifier. Do not invent domains, ICP numbers, aliases, parent companies "
            "or geographies without evidence. When results exist, derive follow-ups only from concrete sample signals "
            "such as domains returned by FOFA, certificate subjects, organization names, ICP values, products or titles. "
            "A strategy labeled hypothesis proves only that a candidate domain is indexed by FOFA; it does not confirm "
            "ownership. You may pivot from its observed IP/certificate to find related candidates, but must not call the "
            "domain confirmed or official without independent ownership evidence. Do not "
            "repeat or submit a query predictably subsumed by one already executed. Never expand the user's organization, "
            "geography or authorization scope. Mark coverage sufficient only when the user's goal has meaningful nonzero "
            "coverage or no safe evidence-based strategy remains."
        )

    def repair_system(self, *, reflection: bool = False) -> str:
        if reflection:
            return (
                "Repair only the syntax of this reflected FOFA query. Preserve every organization and geography "
                "scope constraint and do not broaden the query."
            )
        return "Repair only the syntax of a FOFA query. Preserve every organization and geography scope constraint."

    def summarizer_system(self) -> str:
        return briefing_system(self.label)

    def host_summary_system(self) -> str:
        return (
            "Summarize this FOFA Host profile as a defensive exposure overview. Distinguish observed ports/products from "
            "inference, do not claim a vulnerability without validation, and include data freshness limitations."
        )

    def stats_summary_system(self) -> str:
        return (
            "Summarize FOFA aggregate statistics. Separate observed counts from interpretation, mention the query and "
            "dimensions, identify concentration or anomalies, and do not infer vulnerabilities from aggregate data."
        )

    def library_hint(self, intent: str) -> str:
        return rules_hint_for_prompt(intent)

    def library_queries(self, intent: str, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "query": rule.query,
                "purpose": f"规则库精确指纹：{rule.name}",
                "strategy": "precision",
                "source": "library",
            }
            for rule in match_intent_rules(intent, limit=min(3, limit))
        ]

    # -- syntax ---------------------------------------------------------------
    def query_errors(self, query: str) -> list[str]:
        return []

    def fallback_plan(self, intent: str) -> dict[str, Any]:
        return fofa_fallback_plan(intent)

    # -- capabilities ---------------------------------------------------------
    def align_action(self, action: str, target: str | None, *, has_queries: bool) -> ActionFallback | None:
        membership = membership_from_account(self._user_info())
        if membership is None:
            return None
        if action == STATS_ACTION and not membership.stats_api:
            return ActionFallback(
                action=self.search_action,
                note=f"{membership.name} 无统计聚合 API，已改为普通检索",
                data={"vip_level": membership.vip_level, "fallback": self.search_action},
            )
        if action == HOST_ACTION and not membership.host_api:
            queries: list[dict[str, Any]] = []
            if target and not has_queries:
                queries = [
                    {
                        "query": host_fallback_query(target),
                        "purpose": f"{membership.name} 无主机聚合，改用检索",
                        "strategy": "balanced",
                        "source": "membership",
                    }
                ]
            return ActionFallback(
                action=self.search_action,
                note=f"{membership.name} 无主机聚合 API，已改为普通检索",
                queries=queries,
                data={"vip_level": membership.vip_level, "target": target, "fallback": self.search_action},
            )
        return None

    def hypothesis_query(self, domains: list[str]) -> str:
        return "(" + " || ".join(f'domain="{domain}" || host="{domain}"' for domain in domains) + ")"

    def evidence_key(self, strategy: str) -> str:
        return f"{self.engine}_{strategy}"

    def attribution(self, asset: dict[str, Any]) -> dict[str, Any]:
        """Ownership signals a FOFA row can carry: certificate CN and ICP filing."""
        return {"certificate_cn": asset.get("cert.subject.cn"), "icp": asset.get("icp")}

    def planning_domains(self, queries: list[str]) -> set[str]:
        return {
            value.lower().removeprefix("www.")
            for query in queries
            for value in re.findall(r'\b(?:domain|host)\s*=\s*"([^" ]+\.[a-z]{2,63})"', query, re.IGNORECASE)
        }

    # -- fields ---------------------------------------------------------------
    def suggest_fields(self, requested: list[str], *, intent: str) -> list[str]:
        return merge_return_fields(requested, account_tier_name=self._tier(), intent=intent)

    def decide_fields(self, requested: list[str]) -> FieldSelection:
        decision = decide_fields(requested, self._tier())
        return FieldSelection(allowed=decision.allowed, denied=decision.denied)

    def denied_fields_step(self, denied: list[str], fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            "已按 FOFA 会员权限调整返回字段；查询语法中的高级检索字段不受影响",
            {"denied": denied, "fields": fields},
        )

    def smart_fields_step(self, fields: list[str]) -> tuple[str, dict[str, Any]]:
        tier = self._tier()
        return (
            f"已按账号等级（{tier or '未知'}）和任务智能选择 {len(fields)} 个返回字段",
            {"tier": tier, "fields": fields},
        )

    def request_fields(self, fields: list[str]) -> list[str]:
        return fofa_request_fields(fields) or fields

    def icon_query(self, digest: IconDigest) -> str:
        return engine_favicon_query(self.engine, digest)

    def soft_stop(self, error: FofaError) -> str | None:
        """Only an exhausted quota keeps the partial set; every other FOFA error stays fatal."""
        if error.code is FofaErrorCode.QUOTA_EXHAUSTED:
            return "FOFA 查询额度已用尽，已保留已获取的结果并停止继续检索。"
        return None


class ShodanProfile:
    """Shodan decisions: `filter:value` syntax, facets, credits, no membership tiers."""

    engine = "shodan"
    label = "Shodan"
    search_action = SEARCH_ACTION_SHODAN
    # Last time this engine confirmed the asset, used by the freshness filter.
    timestamp_field = TIMESTAMP_FIELDS["shodan"]
    default_fields = DEFAULT_OUTPUT_FIELDS
    stats_fields = tuple(sorted(FACET_ALIASES))
    default_stats_fields = ("country", "port")

    def __init__(self, client: Any = None) -> None:
        """A client is optional: prompts, syntax rules and field catalogues need no connection."""
        self.client = client

    # -- capability discovery -------------------------------------------------
    def _plan(self) -> dict[str, Any]:
        return getattr(self.client, "plan_info", None) or {}

    async def prepare(self) -> None:
        """`/api-info` is free: it validates the key and reveals the credit balance early."""
        if not self._plan():
            await self.client.account()

    # -- prompt material ------------------------------------------------------
    def plan_schema(self) -> dict[str, Any]:
        return plan_schema(self.search_action)

    def planner_system(self) -> str:
        return (
            "You are a Shodan action router and query strategist. Select exactly one action: shodan_search for an asset list; "
            "host_query only for a single explicit IP or host profile; stat_query for counts, distributions or rankings through "
            "Shodan facets; or icon_query for reverse-searching an explicit website favicon. Put the explicit host/URL in target "
            "for host/icon actions, use an empty target for other actions, and select only supported facets for stat_query. "
            "For shodan_search, translate defensive asset-discovery intent into one to five high-quality, complementary read-only "
            "query strategies. Shodan syntax is `filter:value`; space-separated clauses are ANDed, and a comma-separated value list "
            "inside one filter is ORed, for example `product:MySQL,PostgreSQL port:>1024,<6000`. Exclude noise with a leading "
            "minus, for example `-country:CN`. Never emit FOFA syntax: no app=, "
            "domain=, host=, ip=, port=, body=, header=, cert= or org= assignments, and never use && or ||. Always quote values "
            "that contain spaces. Shodan searches only the banner `data` property by default, so prefer explicit filters over bare "
            "words. "
            "Optimize the portfolio for coverage, precision and API efficiency: combine alias values inside one filter when that "
            "saves requests without adding noise, and keep queries separate when they represent different precision/recall "
            "tradeoffs. Include at least one balanced or recall-oriented strategy for organization discovery. Do not invent a "
            "domain, organization name, product name or geography; organization-to-domain resolution is performed separately. "
            "Keep every query within the exact organization, geography and authorization scope requested by the user. Avoid "
            "redundant queries whose result sets are predictably subsumed by another strategy. "
            "Also assess whether a bounded Nuclei follow-up would be useful. A scan recommendation is only a plan: never execute "
            "it. Use only template IDs made of letters, digits, dot, underscore or hyphen; for a general scan the application adds "
            "its bounded multi-template web-baseline profile, so use template_ids only for justified product-specific additions or "
            "exact IDs named by the user. Never emit shell arguments. "
            "Select returned fields only from the allowed Shodan catalogue supplied in the user prompt; match the field count to "
            "the task and do not request banner unless the user asked for page content or banner detail. "
            "Billing: a query that contains any filter costs one query credit and every page after the first costs one more, so "
            "prefer fewer precise queries over many low-value ones."
        )

    def planner_context(self, intent: str, *, smart_fields: bool, requested_fields: list[str] | None) -> str:
        plan = self._plan()
        credits = plan.get("query_credits")
        credits_label = "不限" if isinstance(credits, int) and credits < 0 else (credits if credits is not None else "未知")
        context = (
            f"User intent: {intent}"
            f"\nShodan plan: {plan.get('plan') or '未知'}"
            f"\nShodan query credits left: {credits_label}"
            f"\nShodan billing: any query containing filter:value costs 1 query credit and every page after the first costs 1 "
            "more; stat_query (/shodan/host/count) and account lookups are free."
            f"\nAllowed filters: {', '.join(SHODAN_FILTERS)}"
        )
        if requested_fields:
            return context
        if smart_fields:
            context += (
                f"\nAllowed return fields: {', '.join(SHODAN_FIELDS)}"
                f"\nSuggested return fields: {', '.join(self.suggest_fields([], intent=intent))}"
            )
        return context

    def reflector_system(self) -> str:
        return (
            "You are the result-reflection stage of a Shodan asset-discovery agent. Evaluate each executed strategy using its "
            "raw hit count and deduplicated additions, then propose zero to two efficient complementary strategies. Shodan syntax "
            "is `filter:value` with space-separated AND clauses and comma-separated OR values inside one filter; never use && or || "
            "and never emit FOFA assignments such as app=, domain= or body=. Never mechanically split every field into a separate "
            "query. When all results are zero, use a correction ladder: first drop unsupported or overly strict filters, then try a "
            "balanced combination of valid ownership filters (org:, isp:, net:, hostname:, domain:) and content filters "
            "(http.title:, product:), and finally a bounded recall query using the strongest user-provided identifier. Do not "
            "invent domains, organization names, aliases or geographies without evidence. When results exist, derive follow-ups "
            "only from concrete sample signals such as hostnames, domains, organizations, products or titles returned by Shodan. A "
            "strategy labeled hypothesis proves only that a candidate hostname is indexed by Shodan; it does not confirm ownership, "
            "and you may pivot from its observed IP, netblock or certificate to related candidates but must not call it official "
            "without independent evidence. Do not repeat or submit a query predictably subsumed by one already executed, and never "
            "expand the user's organization, geography or authorization scope. Remember that every filtered query and every page "
            "after the first spends a query credit, so prefer the highest-value complement. Mark coverage sufficient only when the "
            "user's goal has meaningful nonzero coverage or no safe evidence-based strategy remains."
        )

    def repair_system(self, *, reflection: bool = False) -> str:
        if reflection:
            return (
                "Repair only the syntax of this reflected Shodan query. Use Shodan `filter:value` syntax with space-separated AND "
                "clauses and comma-separated OR values, remove any FOFA-only assignments or ||/&& operators, preserve every "
                "organization and geography scope constraint, and do not broaden the query."
            )
        return (
            "Repair only the syntax of a Shodan query. Use Shodan `filter:value` syntax with space-separated AND clauses and "
            "comma-separated OR values, remove any FOFA-only assignments or ||/&& operators, and preserve every organization and "
            "geography scope constraint."
        )

    def summarizer_system(self) -> str:
        return briefing_system(self.label)

    def host_summary_system(self) -> str:
        return (
            "Summarize this Shodan Host profile as a defensive exposure overview. Distinguish observed ports/products from "
            "inference, do not claim a vulnerability without validation, and include data freshness limitations."
        )

    def stats_summary_system(self) -> str:
        return (
            "Summarize Shodan aggregate statistics. Separate observed counts from interpretation, mention the query and "
            "dimensions, identify concentration or anomalies, and do not infer vulnerabilities from aggregate data."
        )

    def library_hint(self, intent: str) -> str:
        return ""

    def library_queries(self, intent: str, limit: int) -> list[dict[str, Any]]:
        return []

    # -- syntax ---------------------------------------------------------------
    def query_errors(self, query: str) -> list[str]:
        # Only definitely-invalid syntax; the filter catalogue below is prompt guidance, and
        # rejecting a valid-but-unlisted filter would abort an otherwise good run.
        return shodan_syntax_errors(query)

    def fallback_plan(self, intent: str) -> dict[str, Any]:
        return shodan_fallback_plan(intent)

    # -- capabilities ---------------------------------------------------------
    def align_action(self, action: str, target: str | None, *, has_queries: bool) -> ActionFallback | None:
        """Shodan has no vip-level tiers; the client reports plan limits as explicit errors instead."""
        return None

    def hypothesis_query(self, domains: list[str]) -> str:
        # Shodan ORs comma-separated values inside a single filter, so hosts share one clause.
        return f"hostname:{','.join(domains)}"

    def evidence_key(self, strategy: str) -> str:
        return f"{self.engine}_{strategy}"

    def attribution(self, asset: dict[str, Any]) -> dict[str, Any]:
        """Shodan has no ICP filing field, so certificate CN carries the ownership signal."""
        return {"certificate_cn": asset.get("ssl_cn"), "icp": ""}

    def planning_domains(self, queries: list[str]) -> set[str]:
        domains: set[str] = set()
        for query in queries:
            for clause in _SHODAN_DOMAIN_CLAUSE.findall(query):
                for token in clause.split(","):
                    value = token.strip().strip("\"'").lower().removeprefix("www.").removeprefix("*.")
                    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", value):
                        domains.add(value)
        return domains

    # -- fields ---------------------------------------------------------------
    def suggest_fields(self, requested: list[str], *, intent: str) -> list[str]:
        """Core identity columns first, then intent-relevant extras.

        Shodan returns whole banners and bills per request, so field count is only a
        readability/export-width budget rather than a quota concern.
        """
        selected = [field for field in requested if field in SHODAN_FIELDS]
        haystack = intent.lower()
        for keywords, extras in _SHODAN_FIELD_HINTS:
            if any(keyword in haystack for keyword in keywords):
                selected.extend(extras)
        selected = list(dict.fromkeys([*DEFAULT_OUTPUT_FIELDS, *selected]))
        return selected[:SHODAN_FIELD_LIMIT]

    def decide_fields(self, requested: list[str]) -> FieldSelection:
        allowed = [field for field in requested if field in SHODAN_FIELDS]
        denied = [field for field in requested if field not in SHODAN_FIELDS and field not in LOCAL_RESULT_FIELDS]
        return FieldSelection(allowed=allowed, denied=denied)

    def denied_fields_step(self, denied: list[str], fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            "已按 Shodan 字段目录调整返回字段；被拒绝的字段不会进入查询",
            {"denied": denied, "fields": fields},
        )

    def smart_fields_step(self, fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            f"已按 Shodan 字段目录和任务智能选择 {len(fields)} 个返回字段",
            {"fields": fields},
        )

    def request_fields(self, fields: list[str]) -> list[str]:
        allowed = [field for field in fields if field in SHODAN_FIELDS]
        return allowed or list(DEFAULT_OUTPUT_FIELDS)

    def icon_query(self, digest: IconDigest) -> str:
        return engine_favicon_query(self.engine, digest)

    def soft_stop(self, error: FofaError) -> str | None:
        """Shodan credits are billed per page, so an exhausted balance keeps the partial result set."""
        if error.code is FofaErrorCode.QUOTA_EXHAUSTED:
            return "Shodan 查询额度已用尽，已保留已获取的结果并停止继续检索。"
        return None


class HunterProfile:
    """Hunter decisions: `key="value"` syntax, MD5 favicons, per-record credits, no aggregation API."""

    engine = "hunter"
    label = "Hunter"
    search_action = SEARCH_ACTION_HUNTER
    # Last time this engine confirmed the asset, used by the freshness filter.
    timestamp_field = TIMESTAMP_FIELDS["hunter"]
    default_fields = HUNTER_DEFAULT_FIELDS
    # Hunter's open API exposes no aggregation endpoint, so no dimensions are offered.
    stats_fields: tuple[str, ...] = ()
    default_stats_fields: tuple[str, ...] = ()

    def __init__(self, client: Any = None) -> None:
        """A client is optional: prompts, syntax rules and field catalogues need no connection."""
        self.client = client

    # -- capability discovery -------------------------------------------------
    def _plan(self) -> dict[str, Any]:
        return getattr(self.client, "account_info", None) or {}

    async def prepare(self) -> None:
        """`/openApi/userInfo` is free: it validates the key and reveals the credit pool early."""
        if not self._plan():
            await self.client.account()

    def _points_label(self) -> str:
        plan = self._plan()
        free = plan.get("rest_free_point")
        equity = plan.get("rest_equity_point")
        if free is None and equity is None:
            return "未知"
        total = (free if isinstance(free, int) else 0) + (equity if isinstance(equity, int) else 0)
        return f"{total}（含免费 {free if free is not None else '-'}、权益 {equity if equity is not None else '-'}）"

    # -- prompt material ------------------------------------------------------
    def plan_schema(self) -> dict[str, Any]:
        return plan_schema(self.search_action)

    def planner_system(self) -> str:
        return (
            "You are a Hunter (奇安信鹰图) action router and query strategist. Select exactly one action: "
            "hunter_search for an asset list; host_query only for a single explicit IP or host profile "
            "(Hunter aggregates it from an `ip=` search, which spends credits); or icon_query for "
            "reverse-searching an explicit website favicon. Statistics are not available on Hunter, so never select "
            "stat_query. Put the explicit host/URL in target for host/icon actions and use an empty target for search. "
            "For hunter_search, translate defensive asset-discovery intent into one to five high-quality, complementary "
            "read-only query strategies. Hunter syntax is `key=\"value\"` with the operators `&&`, `||` and `!=`, for "
            "example `web.title=\"登录\" && country=\"中国\"` or `domain.suffix=\"example.com\"`. Prefer "
            "`web.title=`, `web.body=`, `header.server==`, `domain.suffix=`, `app.name=`, `app.vendor=`, "
            "`app.version=`, `web.tag=`, `cert=`, `company=`, `number=` and `web.icon=<md5>`. Always quote values. "
            "Never use Shodan's `filter:value` form and never use a bare `key:value`; Hunter field names are validated "
            "server-side, so only use filters you are sure exist. "
            "Optimize the portfolio for coverage and precision. Include at least one balanced or recall-oriented "
            "strategy for organization discovery. Do not invent a domain, organization name, product name or geography; "
            "organization-to-domain resolution is performed separately. Keep every query within the exact organization, "
            "geography and authorization scope requested by the user, and avoid queries predictably subsumed by another "
            "strategy. "
            "Also assess whether a bounded Nuclei follow-up would be useful. A scan recommendation is only a plan: never "
            "execute it. Use only template IDs made of letters, digits, dot, underscore or hyphen; for a general scan the "
            "application adds its bounded multi-template web-baseline profile, so use template_ids only for justified "
            "product-specific additions or exact IDs named by the user. Never emit shell arguments. "
            "Select returned fields only from the allowed Hunter catalogue supplied in the user prompt; match the field "
            "count to the task and do not request banner, header or body unless the user asked for page content. "
            "Billing: Hunter deducts credits per returned record (a repeated identical query costs nothing), and one query "
            "can only be paged to 10,000 records, so prefer fewer precise queries over many low-value ones."
        )

    def planner_context(self, intent: str, *, smart_fields: bool, requested_fields: list[str] | None) -> str:
        context = (
            f"User intent: {intent}"
            f"\nHunter account type: {self._plan().get('type') or '未知'}"
            f"\nHunter points left: {self._points_label()}"
            "\nHunter billing: credits are deducted per returned record; a repeated identical query and any rejected "
            "request cost 0, and one query can only be paged to 10,000 records."
            "\nHunter operators: && (and), || (or), != (not); values must be quoted."
            f"\nSupported filters: {', '.join(HUNTER_FILTERS)}"
        )
        if requested_fields:
            return context
        if smart_fields:
            context += (
                f"\nAllowed return fields: {', '.join(HUNTER_FIELDS)}"
                f"\nSuggested return fields: {', '.join(self.suggest_fields([], intent=intent))}"
            )
        return context

    def reflector_system(self) -> str:
        return (
            "You are the result-reflection stage of a Hunter (奇安信鹰图) asset-discovery agent. Evaluate each executed "
            "strategy using its raw hit count and deduplicated additions, then propose zero to two efficient complementary "
            "strategies. Hunter syntax is `key=\"value\"` combined with `&&`, `||` and `!=`; never emit Shodan's "
            "`filter:value` form and never emit FOFA-only operators such as `&&` inside a value. Never mechanically split "
            "every field into a separate query. When all results are zero, use a correction ladder: first drop overly "
            "strict or unsupported filters, then try a balanced combination of ownership filters (`company=`, `number=`, "
            "`domain.suffix=`, `cert=`) and content filters (`web.title=`, `web.body=`, `app.name=`), and finally a bounded "
            "recall query using the strongest user-provided identifier. Do not invent domains, organization names, aliases "
            "or geographies without evidence. When results exist, derive follow-ups only from concrete sample signals such "
            "as domains, titles, components, asset tags or certificate names returned by Hunter. A strategy labeled "
            "hypothesis proves only that a candidate hostname is indexed by Hunter; it does not confirm ownership. Do not "
            "repeat or submit a query predictably subsumed by one already executed, and never expand the user's "
            "organization, geography or authorization scope. Credits are spent per returned record, so prefer the "
            "highest-value complement. Mark coverage sufficient only when the user's goal has meaningful nonzero coverage "
            "or no safe evidence-based strategy remains."
        )

    def repair_system(self, *, reflection: bool = False) -> str:
        stage = "this reflected Hunter query" if reflection else "a Hunter query"
        return (
            f"Repair only the syntax of {stage}. Use Hunter's `key=\"value\"` syntax with `&&`, `||` and `!=` operators, "
            "quote every value, replace any Shodan `filter:value` clause with the equivalent Hunter filter (for example "
            "`product:nginx` becomes `app.name=\"nginx\"` and `country:CN` becomes `country=\"中国\"`), and preserve every "
            "organization and geography scope constraint without broadening the query."
        )

    def summarizer_system(self) -> str:
        return briefing_system(self.label)

    def host_summary_system(self) -> str:
        return (
            "Summarize this Hunter host profile as a defensive exposure overview. Distinguish observed ports and "
            "components from inference, do not claim a vulnerability without validation, mention that the profile was "
            "aggregated from an `ip=` search that spends Hunter credits, and include data freshness limitations."
        )

    def stats_summary_system(self) -> str:
        # Hunter has no aggregation endpoint; the action is downgraded in `align_action` before this
        # prompt could ever be used, so this only satisfies the profile contract.
        return "Hunter 开放 API 不提供聚合统计，统计结论必须由 FOFA 或 Shodan 的统计接口产出。"

    def library_hint(self, intent: str) -> str:
        # The bundled rule library is FOFA syntax and queries are never translated across engines.
        return ""

    def library_queries(self, intent: str, limit: int) -> list[dict[str, Any]]:
        return []

    # -- syntax ---------------------------------------------------------------
    def query_errors(self, query: str) -> list[str]:
        # Hunter validates filter names server-side and a rejected request costs no credits, so only
        # definitely-wrong syntax (Shodan-style colons) is rejected locally.
        return hunter_syntax_errors(query)

    def fallback_plan(self, intent: str) -> dict[str, Any]:
        return hunter_fallback_plan(intent)

    # -- capabilities ---------------------------------------------------------
    def align_action(self, action: str, target: str | None, *, has_queries: bool) -> ActionFallback | None:
        if action == STATS_ACTION:
            # FOFA and Shodan own the statistics action; Hunter has no aggregation endpoint at all.
            return ActionFallback(
                action=self.search_action,
                note="Hunter 开放 API 无聚合统计接口，已改为普通检索（需要统计分布请改用 FOFA 或 Shodan）",
                data={"fallback": self.search_action, "engine": self.engine},
            )
        return None

    def hypothesis_query(self, domains: list[str]) -> str:
        # Hunter accepts parentheses, `||` and `domain.suffix=` (all verified against the live API).
        return "(" + " || ".join(f'domain.suffix="{domain}"' for domain in domains) + ")"

    def evidence_key(self, strategy: str) -> str:
        return f"{self.engine}_{strategy}"

    def attribution(self, asset: dict[str, Any]) -> dict[str, Any]:
        """Hunter carries its own filing number (`number`) and certificate CN, like FOFA's ICP view."""
        return {"certificate_cn": asset.get("ssl_cn"), "icp": asset.get("icp")}

    def planning_domains(self, queries: list[str]) -> set[str]:
        domains: set[str] = set()
        for query in queries:
            for value in _HUNTER_DOMAIN_CLAUSE.findall(query):
                candidate = value.strip().strip("\"'").lower().removeprefix("www.").removeprefix("*.")
                candidate = re.sub(r":\d+$", "", candidate)
                if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", candidate):
                    domains.add(candidate)
        return domains

    # -- fields ---------------------------------------------------------------
    def suggest_fields(self, requested: list[str], *, intent: str) -> list[str]:
        """Identity columns first, then Hunter metadata the intent justifies.

        Hunter bills per returned record rather than per field, so field count is only a
        readability/export-width budget.
        """
        selected = [field for field in requested if field in HUNTER_FIELDS]
        haystack = intent.lower()
        for keywords, extras in _HUNTER_FIELD_HINTS:
            if any(keyword in haystack for keyword in keywords):
                selected.extend(extras)
        selected = list(dict.fromkeys([*HUNTER_DEFAULT_FIELDS, *selected]))
        return selected[:HUNTER_FIELD_LIMIT]

    def decide_fields(self, requested: list[str]) -> FieldSelection:
        allowed = [field for field in requested if field in HUNTER_FIELDS]
        denied = [field for field in requested if field not in HUNTER_FIELDS and field not in LOCAL_RESULT_FIELDS]
        return FieldSelection(allowed=allowed, denied=denied)

    def denied_fields_step(self, denied: list[str], fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            "已按 Hunter 字段目录调整返回字段；被拒绝的字段不会进入查询",
            {"denied": denied, "fields": fields},
        )

    def smart_fields_step(self, fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            f"已按 Hunter 字段目录和任务智能选择 {len(fields)} 个返回字段",
            {"fields": fields},
        )

    def request_fields(self, fields: list[str]) -> list[str]:
        allowed = [field for field in fields if field in HUNTER_FIELDS]
        return allowed or list(HUNTER_DEFAULT_FIELDS)

    def icon_query(self, digest: IconDigest) -> str:
        return engine_favicon_query(self.engine, digest)

    def soft_stop(self, error: FofaError) -> str | None:
        """Hunter bills per returned record, so an exhausted pool keeps the partial result set."""
        if error.code is FofaErrorCode.QUOTA_EXHAUSTED:
            return "Hunter 积分已用尽，已保留已获取的结果并停止继续检索。"
        return None


def daydaymap_fallback_plan(intent: str) -> dict[str, Any]:
    """Produce a conservative executable DayDayMap search when planner JSON is unusable."""
    domain_match = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:/|\b)", intent, re.IGNORECASE)
    ip_match = _IP_IN_INTENT.search(intent)
    queries: list[dict[str, Any]] = []
    if domain_match:
        domain = _query_literal(domain_match.group(1).lower().removeprefix("www."))
        queries = [
            {
                "query": f'domain="{domain}"',
                "purpose": f"结构化规划降级：按主机名 {domain} 检索",
                "strategy": "precision",
            },
            {
                "query": f'cert="{domain}"',
                "purpose": f"结构化规划降级：按证书记载的 {domain} 补充检索",
                "strategy": "balanced",
            },
        ]
    elif ip_match:
        ip = _query_literal(ip_match.group(0))
        queries = [{"query": f'ip="{ip}"', "purpose": f"结构化规划降级：按用户提供的 IP {ip} 检索", "strategy": "precision"}]
    else:
        term = _query_literal(_fallback_search_term(intent))
        if ORGANIZATION_INTENT_PATTERN.search(term):
            queries.append(
                {
                    "query": f'icp_reg_name="{term}"',
                    "purpose": f"结构化规划降级：按备案主体“{term}”检索",
                    "strategy": "balanced",
                }
            )
        queries.append(
            {
                "query": f'title="{term}"',
                "purpose": f"结构化规划降级：围绕用户核心名称“{term}”进行保守召回",
                "strategy": "recall",
            }
        )
    return {
        "action": SEARCH_ACTION_DAYDAYMAP,
        "target": "",
        "queries": queries,
        "stats_fields": [],
        "fields": list(DAYDAYMAP_FALLBACK_FIELDS),
        "scan": _scan_section(intent),
    }


class DaydaymapProfile:
    """DayDayMap decisions: FOFA-like `field="value"` syntax, no stats, no balance endpoint."""

    engine = "daydaymap"
    label = "DayDayMap"
    search_action = SEARCH_ACTION_DAYDAYMAP
    timestamp_field = TIMESTAMP_FIELDS["daydaymap"]
    default_fields = DAYDAYMAP_DEFAULT_FIELDS
    # No per-query aggregation endpoint on the open API (the count endpoint returns platform totals).
    stats_fields: tuple[str, ...] = ()
    default_stats_fields: tuple[str, ...] = ()

    def __init__(self, client: Any = None) -> None:
        self.client = client

    async def prepare(self) -> None:
        """No free balance/capability endpoint exists; the first query validates the key."""
        return None

    def plan_schema(self) -> dict[str, Any]:
        return plan_schema(self.search_action)

    def planner_system(self) -> str:
        return (
            "You are a DayDayMap action router and query strategist. Select exactly one action: daydaymap_search for an "
            "asset list; host_query only when the user supplied a single explicit IP or host; icon_query is not supported "
            "by DayDayMap, and stat_query has no aggregation endpoint, so prefer daydaymap_search for those intents. "
            "DayDayMap syntax is `field=\"value\"`, the same family as FOFA: multiple clauses are ANDed with `&&`, OR is "
            "written with `||`, and parentheses group expressions, for example "
            '`(domain="example.com" || cert="example.com") && country="中国"`. Never emit Shodan syntax: '
            "no `field:value`, no bare words, no `-field:value`. Always quote values that contain spaces or non-ASCII text. "
            "Searchable fields seen in production include ip, port, protocol, service, domain, title, header, banner, cert, "
            "product, server, os, country, province, city, isp, asn, asn_org, icp_reg_name, industry, tags, time_stamp and "
            "url; a field the platform does not search is rejected with a clear error, so prefer the listed fields. "
            "For daydaymap_search, translate defensive asset-discovery intent into one to five complementary read-only "
            "strategies. Optimize for coverage, precision and request efficiency: combine alias values inside one "
            "expression when that saves requests without adding noise. Do not invent a domain, organization name, product "
            "name, ICP number or geography; organization-to-domain resolution is performed separately. Keep every query "
            "within the exact organization, geography and authorization scope requested by the user. Avoid redundant "
            "queries whose result sets are predictably subsumed by another strategy. "
            "Also assess whether a bounded Nuclei follow-up would be useful. A scan recommendation is only a plan: never "
            "execute it. Use only template IDs made of letters, digits, dot, underscore or hyphen; never emit shell "
            "arguments. Select returned fields only from the allowed DayDayMap catalogue supplied in the user prompt. "
            "The API does not expose the points a request consumed, so prefer fewer, higher-value queries."
        )

    def planner_context(self, intent: str, *, smart_fields: bool, requested_fields: list[str] | None) -> str:
        context = (
            f"User intent: {intent}"
            "\nDayDayMap billing: the open API does not return the points consumed and exposes no balance endpoint, "
            "so avoid speculative queries."
            "\nAccepted syntax: field=\"value\" with && (AND), || (OR) and parentheses."
        )
        if requested_fields:
            return context
        if smart_fields:
            context += (
                f"\nAllowed return fields: {', '.join(DAYDAYMAP_FIELDS)}"
                f"\nSuggested return fields: {', '.join(self.suggest_fields([], intent=intent))}"
            )
        return context

    def reflector_system(self) -> str:
        return (
            "You are the result-reflection stage of a DayDayMap asset-discovery agent. Evaluate each executed strategy "
            "using its raw hit count and deduplicated additions, then propose zero to two efficient complementary "
            "strategies in DayDayMap syntax (`field=\"value\"`, `&&`, `||`, parentheses). Never use Shodan-style "
            "`field:value`. When all results are zero, first drop unsupported or overly strict fields, then try a "
            "balanced certificate/title combination, and finally a bounded recall query on the strongest user-provided "
            "identifier. Do not invent domains, organization names, ICP entities or geographies. When results exist, "
            "derive follow-ups only from concrete sample signals such as hostnames, certificate names, products or "
            "titles returned by DayDayMap. Never expand the user's organization, geography or authorization scope. "
            "Mark coverage sufficient only when the user's goal has meaningful nonzero coverage or no safe "
            "evidence-based strategy remains."
        )

    def repair_system(self, *, reflection: bool = False) -> str:
        return (
            "Repair only the syntax of this DayDayMap query. Use `field=\"value\"` clauses joined by `&&` or `||` "
            "with balanced parentheses, remove any Shodan-style `field:value`, and preserve every organization and "
            "geography scope constraint."
        )

    def summarizer_system(self) -> str:
        return briefing_system(self.label)

    def host_summary_system(self) -> str:
        return (
            "Summarize this DayDayMap host profile as a defensive exposure overview. Distinguish observed services, "
            "products and certificate names from inference, do not claim a vulnerability without validation, mention "
            "that the profile was aggregated from an `ip=`/`domain=` search that spends points, and include data "
            "freshness limitations."
        )

    def stats_summary_system(self) -> str:
        # No aggregation endpoint; `align_action` downgrades statistics before this could run.
        return "DayDayMap 开放 API 没有按查询聚合的统计接口，统计结论必须由 FOFA 或 Shodan 的统计接口产出。"

    def library_hint(self, intent: str) -> str:
        # The bundled rule library is FOFA `app=` syntax and is not translated across engines.
        return ""

    def library_queries(self, intent: str, limit: int) -> list[dict[str, Any]]:
        return []

    # -- syntax ---------------------------------------------------------------
    def query_errors(self, query: str) -> list[str]:
        return daydaymap_query_errors(query)

    def fallback_plan(self, intent: str) -> dict[str, Any]:
        return daydaymap_fallback_plan(intent)

    # -- capabilities ---------------------------------------------------------
    def align_action(self, action: str, target: str | None, *, has_queries: bool) -> ActionFallback | None:
        if action == STATS_ACTION:
            return ActionFallback(
                action=self.search_action,
                note="DayDayMap 开放 API 没有按查询聚合的统计接口，已改为普通检索（统计请改用 FOFA 或 Shodan）",
                data={"fallback": self.search_action, "engine": self.engine},
            )
        return None

    def hypothesis_query(self, domains: list[str]) -> str:
        return "(" + " || ".join(f'domain="{domain}"' for domain in domains) + ")"

    def evidence_key(self, strategy: str) -> str:
        return f"{self.engine}_{strategy}"

    def attribution(self, asset: dict[str, Any]) -> dict[str, Any]:
        """No filing number on this API (`icp_reg_name` is an entity name), certificate CN carries the signal."""
        return {"certificate_cn": asset.get("ssl_cn"), "icp": ""}

    def planning_domains(self, queries: list[str]) -> set[str]:
        domains: set[str] = set()
        for query in queries:
            for value in _DAYDAYMAP_DOMAIN_CLAUSE.findall(query):
                candidate = value.strip().strip("\"'").lower().removeprefix("www.").removeprefix("*.")
                if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", candidate):
                    domains.add(candidate)
        return domains

    # -- fields ---------------------------------------------------------------
    def suggest_fields(self, requested: list[str], *, intent: str) -> list[str]:
        selected = [field for field in requested if field in DAYDAYMAP_FIELDS]
        haystack = intent.lower()
        for keywords, extras in _DAYDAYMAP_FIELD_HINTS:
            if any(keyword in haystack for keyword in keywords):
                selected.extend(extras)
        selected = list(dict.fromkeys([*DAYDAYMAP_DEFAULT_FIELDS, *selected]))
        return selected[:DAYDAYMAP_FIELD_LIMIT]

    def decide_fields(self, requested: list[str]) -> FieldSelection:
        allowed = [field for field in requested if field in DAYDAYMAP_FIELDS]
        denied = [field for field in requested if field not in DAYDAYMAP_FIELDS and field not in LOCAL_RESULT_FIELDS]
        return FieldSelection(allowed=allowed, denied=denied)

    def denied_fields_step(self, denied: list[str], fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            "已按 DayDayMap 字段目录调整返回字段；被拒绝的字段不会进入查询",
            {"denied": denied, "fields": fields},
        )

    def smart_fields_step(self, fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            f"已按 DayDayMap 字段目录和任务智能选择 {len(fields)} 个返回字段",
            {"fields": fields},
        )

    def request_fields(self, fields: list[str]) -> list[str]:
        allowed = [field for field in fields if field in DAYDAYMAP_FIELDS]
        return allowed or list(DAYDAYMAP_DEFAULT_FIELDS)

    def icon_query(self, digest: IconDigest) -> str:
        return engine_favicon_query(self.engine, digest)

    def soft_stop(self, error: FofaError) -> str | None:
        """DayDayMap points are the only metered resource here, so a spent balance keeps fetched pages."""
        if error.code is FofaErrorCode.QUOTA_EXHAUSTED:
            return "DayDayMap 积分不足，已保留已获取的结果并停止继续检索（已抓取的页面有缓存）。"
        return None


def censys_fallback_plan(intent: str) -> dict[str, Any]:
    """Censys Free only serves entity lookups, so a detected IP becomes a host profile."""
    ip_match = _IP_IN_INTENT.search(intent)
    ip = _query_literal(ip_match.group(0)) if ip_match else ""
    queries: list[dict[str, Any]] = []
    if ip:
        queries = [
            {
                "query": f'ip="{ip}"',
                "purpose": f"结构化规划降级：查询用户提供的 IP {ip} 的主机画像",
                "strategy": "precision",
            }
        ]
    return {
        "action": HOST_ACTION if ip else SEARCH_ACTION_CENSYS,
        "target": ip,
        "queries": queries,
        "stats_fields": [],
        "fields": list(CENSYS_FALLBACK_FIELDS),
        "scan": _scan_section(intent),
    }


class CensysProfile:
    """Censys decisions: entity lookups only, one credit per host, no search or aggregation API.

    The Free plan accepts `GET /v3/global/asset/host/{ip}` (1 credit) and rejects
    `/v3/global/search/query` with 403, so this profile routes to host profiles and never
    pretends to enumerate assets.
    """

    engine = "censys"
    label = "Censys"
    search_action = SEARCH_ACTION_CENSYS
    timestamp_field = TIMESTAMP_FIELDS["censys"]
    default_fields = CENSYS_DEFAULT_FIELDS
    # No aggregation endpoint on the Free plan: stats are downgraded before they can run.
    stats_fields: tuple[str, ...] = ()
    default_stats_fields: tuple[str, ...] = ()

    def __init__(self, client: Any = None) -> None:
        self.client = client

    # -- capability discovery -------------------------------------------------
    def _plan(self) -> dict[str, Any]:
        return getattr(self.client, "plan_info", None) or {}

    async def prepare(self) -> None:
        """The Free balance endpoint costs no credits: validate the token and learn the budget."""
        if not self._plan():
            await self.client.account()

    # -- prompt material ------------------------------------------------------
    def plan_schema(self) -> dict[str, Any]:
        return plan_schema(self.search_action)

    def planner_system(self) -> str:
        return (
            "You are a Censys action router for the Censys Platform API (v3). Censys on a Free plan only serves entity "
            "lookups: one host by IP, one certificate or one web property. It has no search API and no aggregation API. "
            "Select host_query for any single explicit IP address, and put that IP in target. Select censys_search only "
            "when the user explicitly supplied an IP to look up; then emit exactly one query of the form ip=\"1.2.3.4\". "
            "Never invent domains, organizations, products or geographies, never emit FOFA or Shodan syntax, and never "
            "promise enumeration or statistics - list search belongs to FOFA, Shodan and Hunter. "
            "If the intent contains no explicit IP, return zero queries so the run stops with a clear message instead of "
            "spending credits on a guess. "
            "Also assess whether a bounded Nuclei follow-up would be useful. A scan recommendation is only a plan: never "
            "execute it. Use only template IDs made of letters, digits, dot, underscore or hyphen; never emit shell "
            "arguments. "
            "Select returned fields only from the allowed Censys catalogue supplied in the user prompt. Billing: every "
            "host lookup costs one credit and the Free plan includes 100 credits per month."
        )

    def planner_context(self, intent: str, *, smart_fields: bool, requested_fields: list[str] | None) -> str:
        plan = self._plan()
        balance = plan.get("balance")
        context = (
            f"User intent: {intent}"
            f"\nCensys plan: {plan.get('plan') or 'free'}"
            f"\nCensys credits left: {balance if balance is not None else '未知'}"
            f"\nCensys billing: each host lookup costs 1 credit; search/aggregate are not available on the Free plan."
            "\nAccepted search form: ip=\"1.2.3.4\" (host_query takes the same IP as target)."
        )
        if requested_fields:
            return context
        if smart_fields:
            context += (
                f"\nAllowed return fields: {', '.join(CENSYS_FIELD_CATALOG)}"
                f"\nSuggested return fields: {', '.join(self.suggest_fields([], intent=intent))}"
            )
        return context

    def reflector_system(self) -> str:
        return (
            "You are the result-reflection stage of a Censys host-profile run. A host lookup returns every service of "
            "one IP, so there is nothing to broaden: propose no new strategy, never expand the scope, and never suggest "
            "a Censys search query (the Free plan has no search API). Mark coverage sufficient."
        )

    def repair_system(self, *, reflection: bool = False) -> str:
        return (
            "Repair only the syntax of this Censys entity lookup. The only accepted form is ip=\"1.2.3.4\"; never "
            "widen it into a search query, and never invent another IP."
        )

    def summarizer_system(self) -> str:
        return briefing_system(self.label)

    def host_summary_system(self) -> str:
        return (
            "Summarize this Censys host profile as a defensive exposure overview. Distinguish observed services, "
            "products and certificate subjects from inference, do not claim a vulnerability without validation, and "
            "mention the scan time as the freshness limit."
        )

    def stats_summary_system(self) -> str:
        # No aggregation endpoint on the Free plan; `align_action` downgrades stats before this runs.
        return "Censys Free 套餐没有聚合接口，统计结论必须由 FOFA 或 Shodan 的统计接口产出。"

    def library_hint(self, intent: str) -> str:
        return ""

    def library_queries(self, intent: str, limit: int) -> list[dict[str, Any]]:
        return []

    # -- syntax ---------------------------------------------------------------
    def query_errors(self, query: str) -> list[str]:
        return censys_query_errors(query)

    def fallback_plan(self, intent: str) -> dict[str, Any]:
        return censys_fallback_plan(intent)

    # -- capabilities ---------------------------------------------------------
    def align_action(self, action: str, target: str | None, *, has_queries: bool) -> ActionFallback | None:
        if action == STATS_ACTION:
            # FOFA and Shodan own statistics; Censys Free has neither search nor aggregate.
            return ActionFallback(
                action=HOST_ACTION,
                note="Censys Free 套餐没有聚合统计接口，已改为按 IP 查询主机画像（统计请改用 FOFA 或 Shodan）",
                data={"fallback": HOST_ACTION, "engine": self.engine},
            )
        if action == ICON_ACTION:
            return ActionFallback(
                action=HOST_ACTION,
                note="Censys 不提供图标反查，已改为按 IP 查询主机画像（图标反查请改用 FOFA、Shodan 或 Hunter）",
                data={"fallback": HOST_ACTION, "engine": self.engine},
            )
        return None

    def hypothesis_query(self, domains: list[str]) -> str:
        # Censys cannot search by domain: no hypothesis pivot exists on this plan.
        return ""

    def evidence_key(self, strategy: str) -> str:
        return f"{self.engine}_{strategy}"

    def attribution(self, asset: dict[str, Any]) -> dict[str, Any]:
        """No ICP filing; the certificate subject CN carries the ownership signal."""
        return {"certificate_cn": asset.get("ssl_cn"), "icp": ""}

    def planning_domains(self, queries: list[str]) -> set[str]:
        return set()

    # -- fields ---------------------------------------------------------------
    def suggest_fields(self, requested: list[str], *, intent: str) -> list[str]:
        selected = [field for field in requested if field in CENSYS_FIELD_CATALOG]
        haystack = intent.lower()
        for keywords, extras in _CENSYS_FIELD_HINTS:
            if any(keyword in haystack for keyword in keywords):
                selected.extend(extras)
        selected = list(dict.fromkeys([*CENSYS_DEFAULT_FIELDS, *selected]))
        return selected[:CENSYS_FIELD_LIMIT]

    def decide_fields(self, requested: list[str]) -> FieldSelection:
        allowed = [field for field in requested if field in CENSYS_FIELD_CATALOG]
        denied = [field for field in requested if field not in CENSYS_FIELD_CATALOG and field not in LOCAL_RESULT_FIELDS]
        return FieldSelection(allowed=allowed, denied=denied)

    def denied_fields_step(self, denied: list[str], fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            "已按 Censys 字段目录调整返回字段；被拒绝的字段不会进入查询",
            {"denied": denied, "fields": fields},
        )

    def smart_fields_step(self, fields: list[str]) -> tuple[str, dict[str, Any]]:
        return (
            f"已按 Censys 字段目录和任务智能选择 {len(fields)} 个返回字段",
            {"fields": fields},
        )

    def request_fields(self, fields: list[str]) -> list[str]:
        allowed = [field for field in fields if field in CENSYS_FIELD_CATALOG]
        return allowed or list(CENSYS_DEFAULT_FIELDS)

    def icon_query(self, digest: IconDigest) -> str:
        return engine_favicon_query(self.engine, digest)

    def soft_stop(self, error: FofaError) -> str | None:
        """Free credits are monthly, so an exhausted balance keeps every page already fetched."""
        if error.code is FofaErrorCode.QUOTA_EXHAUSTED:
            return "Censys 额度已用尽，已保留已获取的结果并停止继续检索；额度重置后可继续（已抓取的页面有缓存）。"
        return None


def agent_profile(client: Any = None) -> AgentProfile:
    """Build the profile from the client actually in use (None selects the FOFA default)."""
    engine = normalize_engine(getattr(client, "name", "fofa"))
    if engine == "shodan":
        return ShodanProfile(client)
    if engine == "hunter":
        return HunterProfile(client)
    if engine == "daydaymap":
        return DaydaymapProfile(client)
    if engine == "censys":
        return CensysProfile(client)
    return FofaProfile(client)
