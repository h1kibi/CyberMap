"""CyberMap MCP 2.0 server (stdio by default, authenticated Streamable HTTP optionally)."""

from __future__ import annotations

import argparse
import asyncio
import hmac
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from config import settings
from core.agent import AssetAgent, MultiEngineAgent, validate_query
from core.agent_profiles import DaydaymapProfile, HunterProfile, ShodanProfile
from core.censys import DEFAULT_OUTPUT_FIELDS as CENSYS_DEFAULT_FIELDS
from core.censys import CensysClient
from core.client import FofaClient
from core.daydaymap import DEFAULT_OUTPUT_FIELDS as DAYDAYMAP_DEFAULT_FIELDS
from core.daydaymap import DaydaymapClient
from core.engines import create_engine, normalize_engine_scope
from core.exporter import export_pages
from core.fields import field_catalog
from core.hunter import DEFAULT_OUTPUT_FIELDS as HUNTER_DEFAULT_FIELDS
from core.hunter import HunterClient
from core.models import ExportRequest, FofaError, SearchRequest
from core.scanner import NucleiScanner
from core.scans import ScanApproval, ScanPlanRequest
from core.shodan import DEFAULT_OUTPUT_FIELDS as SHODAN_DEFAULT_FIELDS
from core.shodan import ShodanClient
from providers.registry import ProviderRegistry, ProviderRouter
from service.store import JobStore

try:
    from mcp.server.auth.provider import AccessToken
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.mcpserver import Context, MCPServer
except ImportError as exc:  # clear migration failure instead of corrupting stdio
    raise RuntimeError("CyberMap 2.0.1 requires mcp>=2,<3; install the 2.0.1 dependencies") from exc


READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
LOCAL_READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
WRITE_SAFE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
SCAN_EXECUTE = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}

MCP_INSTRUCTIONS = (
    "CyberMap searches internet assets via FOFA, Shodan, Hunter (奇安信鹰图), DayDayMap and Censys. "
    "When the user names a product, OA, VPN, middleware, database, camera, CMS or ops panel, "
    "call fofa_rules first (no FOFA quota) and use the returned query values verbatim in fofa_search or fofa_stats. "
    "Never invent app= names. An empty keyword lists the bundled catalog. "
    "Host aggregation and stats APIs depend on FOFA vip_level; call fofa_account and fofa_fields first "
    "(the equivalent Resources are available on hosts that support them). "
    "Registered users have no host API; personal/education accounts have no stats API. "
    "For Shodan use the shodan_* tools with Shodan syntax (product:nginx country:US) and numbered pages: "
    "a query containing filter:value or a page past the first costs 1 Shodan query credit, "
    "while shodan_stats (/shodan/host/count) and shodan_account (/api-info) are free. "
    "For Hunter use the hunter_* tools with Hunter syntax (web.title=\"登录\" && country=\"中国\"): Hunter bills per "
    "returned record, exposes no aggregation endpoint, pages at most to 10,000 records per query, and its "
    "hunter_account (/openApi/userInfo) call is free. "
    "For DayDayMap use the daydaymap_* tools with FOFA-like syntax (title=\"登录\" && country=\"中国\"): the open API "
    "has no balance or aggregation endpoint and does not report the points a request consumed. "
    "Censys on a Free token serves host lookups by IP only (censys_host_profile); it has no search API. "
    "Set engine to shodan, hunter, daydaymap or censys in fofa_export to export those results. "
    "fofa_agent_run with engine=\"all\" plans on every engine separately and merges them into one briefing; "
    "an engine that fails keeps the other engines' results and is reported per engine, and non-list intents "
    "(host profile, statistics, favicon) are delegated to a single engine. "
    "Validate queries before spending quota: fofa_validate_query checks FOFA syntax, shodan_validate_query checks Shodan syntax, "
    "hunter_validate_query checks Hunter syntax, daydaymap_validate_query checks DayDayMap syntax. "
    "Never plan Nuclei scans without an explicit authorized scope."
)


class _TokenVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        service_token = os.getenv("CYBERMAP_SERVICE_TOKEN", "")
        if service_token and hmac.compare_digest(token, service_token):
            return AccessToken(
                token=token,
                client_id="cybermap-static-token",
                scopes=["cybermap"],
                expires_at=None,
                resource=os.getenv("CYBERMAP_MCP_RESOURCE_URL"),
            )
        public_key = os.getenv("CYBERMAP_JWT_PUBLIC_KEY", "")
        issuer = os.getenv("CYBERMAP_JWT_ISSUER", "")
        if not public_key or not issuer:
            return None
        try:
            import jwt

            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256", "ES256"],
                issuer=issuer,
                audience=os.getenv("CYBERMAP_JWT_AUDIENCE", "cybermap"),
            )
        except Exception:
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("sub") or "jwt-client"),
            subject=claims.get("sub"),
            scopes=str(claims.get("scope", "cybermap")).split(),
            expires_at=int(claims["exp"]) if claims.get("exp") else None,
            resource=os.getenv("CYBERMAP_MCP_RESOURCE_URL"),
            claims=claims,
        )


def _build_mcp() -> MCPServer:
    issuer = os.getenv("CYBERMAP_MCP_ISSUER_URL")
    resource = os.getenv("CYBERMAP_MCP_RESOURCE_URL")
    if issuer and resource:
        return MCPServer(
            "cybermap_mcp",
            version="2.0.1",
            instructions=MCP_INSTRUCTIONS,
            auth=AuthSettings(issuer_url=issuer, resource_server_url=resource, required_scopes=[]),
            token_verifier=_TokenVerifier(),
        )
    return MCPServer("cybermap_mcp", version="2.0.1", instructions=MCP_INSTRUCTIONS)


mcp = _build_mcp()
store = JobStore(os.getenv("CYBERMAP_DATABASE_URL", "sqlite:///./cybermap.sqlite3"))


class SearchToolResult(BaseModel):
    summary: str
    query: str
    fields: list[str]
    records: list[dict[str, Any]]
    total: int | None = None
    next_cursor: str | None = None
    consumed: int | float | None = None


class GenericResult(BaseModel):
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)


@mcp.tool(name="fofa_validate_query", annotations=LOCAL_READ)
async def fofa_validate_query(query: str) -> GenericResult:
    """Perform local syntax checks without spending FOFA quota."""
    errors = validate_query(query)
    return GenericResult(
        summary="query is valid" if not errors else "query is invalid", data={"valid": not errors, "query": query, "errors": errors}
    )


@mcp.tool(name="shodan_validate_query", annotations=LOCAL_READ)
async def shodan_validate_query(query: str) -> GenericResult:
    """Validate a Shodan query locally (shodan_syntax_errors + catalogue) without spending credits."""
    errors = validate_query(query) + ShodanProfile().query_errors(query)
    return GenericResult(
        summary="query is valid" if not errors else "query is invalid",
        data={"valid": not errors, "query": query, "errors": errors, "engine": "shodan"},
    )


@mcp.tool(name="hunter_validate_query", annotations=LOCAL_READ)
async def hunter_validate_query(query: str) -> GenericResult:
    """Validate a Hunter query locally (Shodan-style colons are rejected) without spending points."""
    errors = validate_query(query) + HunterProfile().query_errors(query)
    return GenericResult(
        summary="query is valid" if not errors else "query is invalid",
        data={"valid": not errors, "query": query, "errors": errors, "engine": "hunter"},
    )


@mcp.tool(name="daydaymap_validate_query", annotations=LOCAL_READ)
async def daydaymap_validate_query(query: str) -> GenericResult:
    """Validate a DayDayMap query locally (`field="value"`, `&&`, `||`, parentheses) without spending points."""
    errors = validate_query(query) + DaydaymapProfile().query_errors(query)
    return GenericResult(
        summary="query is valid" if not errors else "query is invalid",
        data={"valid": not errors, "query": query, "errors": errors, "engine": "daydaymap"},
    )


@mcp.tool(name="fofa_fields", annotations=LOCAL_READ)
async def fofa_fields() -> GenericResult:
    """Return the versioned FOFA field and membership capability catalogue without using quota."""
    catalog = field_catalog()
    return GenericResult(summary="FOFA field and membership catalogue", data=catalog)


@mcp.tool(name="fofa_account", annotations=READ_ONLY)
async def fofa_account() -> GenericResult:
    """Return the current FOFA account tier, API capabilities and quota information."""
    async with FofaClient() as client:
        data = await client.account()
    return GenericResult(summary="FOFA account capabilities loaded", data=data)


async def _search(request: SearchRequest) -> SearchToolResult:
    async with FofaClient() as client:
        page = await client.search_page(request)
    return SearchToolResult(
        summary=f"FOFA returned {len(page.records)} records; use next_cursor for continuation or fofa_export for large results.",
        query=page.query,
        fields=page.fields,
        records=[record.values for record in page.records],
        total=page.total,
        next_cursor=page.next_cursor,
        consumed=page.consumed,
    )


@mcp.tool(name="fofa_search", annotations=READ_ONLY)
async def fofa_search(query: str, fields: list[str] | None = None, size: int = 100, full: bool = False) -> SearchToolResult:
    """Run one read-only FOFA search page. If the user named a product/OA/VPN, call fofa_rules first and paste its query verbatim."""
    return await _search(SearchRequest(query=query, fields=fields or settings.search.fields.split(","), size=size, full=full))


@mcp.tool(name="fofa_search_next", annotations=READ_ONLY)
async def fofa_search_next(query: str, cursor: str, fields: list[str], size: int = 100, full: bool = False) -> SearchToolResult:
    """Continue a FOFA search using the opaque cursor returned by fofa_search."""
    return await _search(SearchRequest(query=query, cursor=cursor, continuous=True, fields=fields, size=size, full=full))


@mcp.tool(name="fofa_icon_search", annotations=READ_ONLY)
async def fofa_icon_search(
    url: str,
    fields: list[str] | None = None,
    size: int = 100,
    full: bool = False,
) -> SearchToolResult:
    """Fetch a public website favicon safely, calculate its digests, and search matching FOFA assets."""
    from core.engines import favicon_query
    from utils.helpers import IconHashCalculator

    digest = await IconHashCalculator.hash_url(url)
    if digest is None:
        raise ValueError("unable to fetch a favicon or calculate its hash")
    query = favicon_query("fofa", digest)
    return await _search(SearchRequest(query=query, fields=fields or settings.search.fields.split(","), size=size, full=full))


@mcp.tool(name="shodan_search", annotations=READ_ONLY)
async def shodan_search(
    query: str,
    fields: list[str] | None = None,
    size: int = 100,
    page: int = 1,
    full: bool = False,
) -> SearchToolResult:
    """One read-only Shodan search page (100 matches per page). Use Shodan syntax such as `product:nginx country:US`."""
    async with ShodanClient() as client:
        page = await client.search_page(
            SearchRequest(
                query=query,
                # The configured fields belong to the default engine; each engine falls back to
                # its own catalogue instead of inheriting FOFA-only column names.
                fields=fields or list(SHODAN_DEFAULT_FIELDS),
                size=size,
                page=page,
                full=full,
            )
        )
    return SearchToolResult(
        summary=(
            f"Shodan returned {len(page.records)} records; continue with page={(page.page or 1) + 1} "
            "(each page holds 100 matches and pages past the first consume 1 query credit). "
            "Use fofa_export with engine=shodan for large result sets."
        ),
        query=page.query,
        fields=page.fields,
        records=[record.values for record in page.records],
        total=page.total,
        next_cursor=None,
        consumed=page.consumed,
    )


@mcp.tool(name="shodan_host_profile", annotations=READ_ONLY)
async def shodan_host_profile(host: str, detail: bool = True) -> GenericResult:
    """Return every service Shodan has seen on one IP or domain, with open ports and banners."""
    async with ShodanClient() as client:
        data = await client.host_profile(host, detail=detail)
    return GenericResult(summary=f"Shodan host profile loaded for {host}", data=data)


@mcp.tool(name="shodan_stats", annotations=READ_ONLY)
async def shodan_stats(query: str, fields: list[str], size: int = 5) -> GenericResult:
    """Facet breakdown for a Shodan query; size is Top-N (default 5). Uses /shodan/host/count, which is free."""
    async with ShodanClient() as client:
        data = await client.stats(query, fields, size=size)
    return GenericResult(summary=f"Shodan statistics loaded for {query}", data=data)


@mcp.tool(name="shodan_account", annotations=READ_ONLY)
async def shodan_account() -> GenericResult:
    """Return the Shodan plan, remaining query/scan credits and monthly limits without spending credits."""
    async with ShodanClient() as client:
        data = await client.account()
    return GenericResult(summary="Shodan account capabilities loaded", data=data)


@mcp.tool(name="hunter_search", annotations=READ_ONLY)
async def hunter_search(
    query: str,
    fields: list[str] | None = None,
    size: int = 10,
    page: int = 1,
    full: bool = False,
) -> SearchToolResult:
    """One read-only Hunter (奇安信鹰图) search page. Hunter syntax: `web.title="登录" && country="中国"`."""
    async with HunterClient() as client:
        page_result = await client.search_page(
            SearchRequest(
                query=query,
                fields=fields or list(HUNTER_DEFAULT_FIELDS),
                size=size,
                page=page,
                full=full,
            )
        )
    return SearchToolResult(
        summary=(
            f"Hunter returned {len(page_result.records)} records; continue with page={(page_result.page or 1) + 1}. "
            "Hunter bills credits per returned record, a repeated identical query is free, and one query only pages "
            "to 10,000 records. Use fofa_export with engine=hunter for large result sets."
        ),
        query=page_result.query,
        fields=page_result.fields,
        records=[record.values for record in page_result.records],
        total=page_result.total,
        next_cursor=None,
        consumed=page_result.consumed,
    )


@mcp.tool(name="daydaymap_search", annotations=READ_ONLY)
async def daydaymap_search(
    query: str,
    fields: list[str] | None = None,
    size: int = 100,
    page: int = 1,
) -> SearchToolResult:
    """One read-only DayDayMap page. Syntax: `title="登录" && country="中国"` (FOFA-like, not `field:value`)."""
    async with DaydaymapClient() as client:
        page_result = await client.search_page(
            SearchRequest(
                query=query,
                fields=fields or list(DAYDAYMAP_DEFAULT_FIELDS),
                size=size,
                page=page,
            )
        )
    cached = page_result.metadata.get("cached")
    return SearchToolResult(
        summary=(
            f"DayDayMap returned {len(page_result.records)} records; continue with page={(page_result.page or 1) + 1}. "
            f"{'Cached page: no points spent. ' if cached else ''}"
            "The API does not report the points consumed, and it has no balance or aggregation endpoint. "
            "Use fofa_export with engine=daydaymap for large result sets."
        ),
        query=page_result.query,
        fields=page_result.fields,
        records=[record.values for record in page_result.records],
        total=page_result.total,
        next_cursor=None,
        consumed=page_result.consumed,
    )


@mcp.tool(name="daydaymap_host_profile", annotations=READ_ONLY)
async def daydaymap_host_profile(host: str, detail: bool = True) -> GenericResult:
    """Aggregate every service DayDayMap indexed for one IP or host (`ip=`/`domain=` search; spends points)."""
    async with DaydaymapClient() as client:
        data = await client.host_profile(host, detail=detail)
    return GenericResult(
        summary=(
            f"DayDayMap host profile loaded for {host}"
            f"{' (cached, no points spent)' if data.get('cached') else ' (aggregated from a search that spends points)'}"
        ),
        data=data,
    )


@mcp.tool(name="daydaymap_account", annotations=READ_ONLY)
async def daydaymap_account() -> GenericResult:
    """Return the local DayDayMap capability view (the open API has no balance endpoint)."""
    async with DaydaymapClient() as client:
        data = await client.account()
    return GenericResult(summary="DayDayMap capability view loaded", data=data)


@mcp.tool(name="censys_search", annotations=READ_ONLY)
async def censys_search(query: str, fields: list[str] | None = None, size: int = 100) -> SearchToolResult:
    """Look up ONE host by IP (`ip="1.2.3.4"`). Censys Free has no list-search API; each lookup costs 1 credit."""
    async with CensysClient() as client:
        page = await client.search_page(
            SearchRequest(
                query=query,
                fields=fields or list(CENSYS_DEFAULT_FIELDS),
                size=size,
            )
        )
    note = "（缓存命中，未消耗额度）" if page.metadata.get("cached") else "（1 额度）"
    return SearchToolResult(
        summary=(
            f"Censys returned {len(page.records)} service rows for one host{note}. "
            "Censys Free only serves entity lookups; use fofa_search/shodan_search/hunter_search/daydaymap_search "
            "for enumeration. "
            "Use censys_host_profile for the rendered profile."
        ),
        query=page.query,
        fields=page.fields,
        records=[record.values for record in page.records],
        total=page.total,
        next_cursor=None,
        consumed=page.consumed,
    )


@mcp.tool(name="censys_host_profile", annotations=READ_ONLY)
async def censys_host_profile(host: str, detail: bool = True) -> GenericResult:
    """Every service, endpoint, HTTP/TLS detail, whois and DNS name Censys holds for one IP (1 credit, cached)."""
    async with CensysClient() as client:
        data = await client.host_profile(host, detail=detail)
    suffix = " (cached, 0 credits)" if data.get("cached") else " (1 credit)"
    return GenericResult(summary=f"Censys host profile loaded for {host}{suffix}", data=data)


@mcp.tool(name="censys_account", annotations=READ_ONLY)
async def censys_account() -> GenericResult:
    """Censys Free monthly credit balance and reset time; this endpoint spends no credits."""
    async with CensysClient() as client:
        data = await client.account()
    return GenericResult(summary="Censys account capabilities loaded", data=data)


@mcp.tool(name="hunter_host_profile", annotations=READ_ONLY)
async def hunter_host_profile(host: str, detail: bool = True) -> GenericResult:
    """Aggregate every service Hunter has indexed for one IP or domain (spends Hunter credits)."""
    async with HunterClient() as client:
        data = await client.host_profile(host, detail=detail)
    return GenericResult(
        summary=f"Hunter host profile loaded for {host} (aggregated from an `ip=` search that spends credits)",
        data=data,
    )


@mcp.tool(name="hunter_account", annotations=READ_ONLY)
async def hunter_account() -> GenericResult:
    """Return the Hunter account type and remaining free/equity points without spending points."""
    async with HunterClient() as client:
        data = await client.account()
    return GenericResult(summary="Hunter account capabilities loaded", data=data)


@mcp.tool(name="fofa_host_profile", annotations=READ_ONLY)
async def fofa_host_profile(host: str, detail: bool = True) -> GenericResult:
    """Get FOFA Host aggregation for one IP or DNS name. Registered users have no Host API."""
    async with FofaClient() as client:
        data = await client.host_profile(host, detail=detail)
    return GenericResult(summary=f"Host profile loaded for {host}", data=data)


@mcp.tool(name="fofa_stats", annotations=READ_ONLY)
async def fofa_stats(query: str, fields: list[str], size: int = 5) -> GenericResult:
    """Get FOFA stats. Personal/education accounts have no stats API. size is Top-N (default 5)."""
    async with FofaClient() as client:
        data = await client.stats(query, fields, size=size)
    return GenericResult(summary=f"Statistics loaded for {query}", data=data)


@mcp.tool(name="fofa_syntax", annotations=LOCAL_READ)
async def fofa_syntax() -> GenericResult:
    """Return official FOFA query operators and syntax fields from the API appendix."""
    from core.syntax import syntax_catalog

    catalog = syntax_catalog()
    return GenericResult(summary="FOFA official query syntax", data=catalog)


@mcp.tool(name="fofa_rules", annotations=LOCAL_READ)
async def fofa_rules(keyword: str = "") -> GenericResult:
    """Search bundled official app= names; call before product searches and use returned queries verbatim."""
    from core.rules import rules_catalog

    catalog = rules_catalog(keyword)
    return GenericResult(summary=f"{catalog['count']} of {catalog['total']} FOFA library rules matched", data=catalog)


async def _export(job_id: str, request: ExportRequest) -> None:
    store.update(job_id, status="running")
    try:
        path = Path(settings.system.output_dir).resolve() / Path(request.filename or f"{job_id}.{request.format}").name
        async with create_engine(request.engine) as client:
            artifact, count = await export_pages(client.iter_search(request.search), path, request.format)
        store.update(job_id, status="completed", result={"records": count}, artifact_path=str(artifact.resolve()))
    except FofaError as exc:
        store.update(job_id, status="failed", error=exc.as_dict())
    except Exception as exc:
        store.update(job_id, status="failed", error={"code": "export_error", "message": str(exc)})


@mcp.tool(name="fofa_export", annotations=WRITE_SAFE)
async def fofa_export(request: ExportRequest) -> GenericResult:
    """Start a bounded export job (engine=fofa|shodan|hunter|daydaymap|censys); retrieve status and artifact through MCP resources."""
    job = store.create("export", request.model_dump(mode="json"))
    asyncio.create_task(_export(job["id"], request))
    return GenericResult(summary=f"Export job {job['id']} started", data=job)


@mcp.tool(name="fofa_job_status", annotations=LOCAL_READ)
async def fofa_job_status(job_id: str) -> GenericResult:
    """Read local export, agent or scan job state."""
    job = store.get(job_id)
    return GenericResult(summary=f"Job {job_id} is {job['status']}", data=job)


@mcp.tool(name="fofa_agent_run", annotations=READ_ONLY)
async def fofa_agent_run(
    intent: str,
    max_records: int = 1000,
    max_pages: int = 10,
    engine: str = "fofa",
    min_evidence: str | None = None,
    ctx: Context | None = None,
) -> GenericResult:
    """Run planning with bundled app= fingerprints (fofa), Shodan filters (shodan), Hunter filters
    (hunter), or every engine merged (all); never scan.
    """
    if min_evidence and min_evidence not in {"recall", "hypothesis", "balanced", "precision"}:
        raise ValueError("min_evidence must be one of recall, hypothesis, balanced, precision")
    job = store.create(
        "agent",
        {"intent": intent, "max_records": max_records, "max_pages": max_pages, "engine": engine, "min_evidence": min_evidence},
    )
    store.update(job["id"], status="running")
    if ctx:
        await ctx.report_progress(0, 3, "planning")
    registry = ProviderRegistry(settings, execution_mode="service")
    router = ProviderRouter(registry)
    engines = normalize_engine_scope(engine)
    if len(engines) > 1:
        run = await MultiEngineAgent(engines, router, engine_factory=create_engine).run(
            intent, max_records=max_records, max_pages=max_pages, min_evidence=min_evidence
        )
    else:
        async with create_engine(engines[0]) as client:
            run = await AssetAgent(client, router).run(
                intent, max_records=max_records, max_pages=max_pages, min_evidence=min_evidence
            )
    await registry.aclose()
    status = "completed" if run.error is None else "failed"
    store.update(job["id"], status=status, result=run.model_dump(mode="json"), error=run.error)
    if ctx:
        await ctx.report_progress(3, 3, "complete")
    data = run.model_dump(mode="json")
    data["job_id"] = job["id"]
    return GenericResult(summary=run.summary or f"Agent run {run.state}", data=data)


@mcp.tool(name="nuclei_plan", annotations=WRITE_SAFE)
async def nuclei_plan(request: ScanPlanRequest) -> GenericResult:
    """Create an exact, expiring Nuclei plan and one-time approval token. Scanning must be enabled."""
    if os.getenv("CYBERMAP_ENABLE_SCANNING", "false").lower() != "true":
        raise ValueError("active scanning is disabled")
    job, token = ScanApproval(store, allow_private=settings.system.allow_private_network).create(request)
    return GenericResult(
        summary="Review target/template/severity scope before calling nuclei_execute", data={"plan": job, "approval_token": token}
    )


@mcp.tool(name="nuclei_execute", annotations=SCAN_EXECUTE)
async def nuclei_execute(plan_id: str, approval_token: str) -> GenericResult:
    """Consume a scope-bound approval exactly once and execute that exact plan."""
    if os.getenv("CYBERMAP_ENABLE_SCANNING", "false").lower() != "true":
        raise ValueError("active scanning is disabled")
    job = ScanApproval(store, allow_private=settings.system.allow_private_network).consume(plan_id, approval_token)
    store.update(plan_id, status="running")
    try:
        scan = await NucleiScanner().run_plan(
            ScanPlanRequest.model_validate(job["payload"]),
            Path(settings.system.output_dir).resolve() / f"scan-{plan_id}",
        )
        job = store.update(
            plan_id,
            status="completed",
            artifact_path=str(scan.artifact.resolve()),
            result=scan.to_job_payload(),
        )
    except Exception as exc:
        store.update(plan_id, status="failed", error={"code": "scan_error", "message": str(exc)})
        raise
    return GenericResult(summary=scan.headline(), data=job)


@mcp.resource("cybermap://fields")
def fields_resource() -> dict[str, Any]:
    """Current versioned FOFA field catalogue."""
    return field_catalog()


@mcp.resource("cybermap://rules")
def rules_resource() -> dict[str, Any]:
    """Bundled FOFA app= fingerprint library (official names from fofa.info/library)."""
    from core.rules import rules_catalog

    return rules_catalog()


@mcp.resource("cybermap://account")
async def account_resource() -> dict[str, Any]:
    """Current FOFA account capability and usage data."""
    async with FofaClient() as client:
        return await client.account()


@mcp.resource("cybermap://shodan/account")
async def shodan_account_resource() -> dict[str, Any]:
    """Current Shodan plan, remaining query/scan credits and monthly limits."""
    async with ShodanClient() as client:
        return await client.account()


@mcp.resource("cybermap://daydaymap/account")
async def daydaymap_account_resource() -> dict[str, Any]:
    """Local DayDayMap capability view (no API balance endpoint exists)."""
    async with DaydaymapClient() as client:
        return await client.account()


@mcp.resource("cybermap://censys/account")
async def censys_account_resource() -> dict[str, Any]:
    """Current Censys Free credit balance and reset time."""
    async with CensysClient() as client:
        return await client.account()


@mcp.resource("cybermap://hunter/account")
async def hunter_account_resource() -> dict[str, Any]:
    """Current Hunter account type and remaining free/equity points."""
    async with HunterClient() as client:
        return await client.account()


@mcp.resource("cybermap://jobs/{job_id}")
def job_resource(job_id: str) -> dict[str, Any]:
    """Job metadata; artifact_path points to large local results."""
    return store.get(job_id)


def _loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def run_server() -> None:
    parser = argparse.ArgumentParser(description="CyberMap MCP 2.0 服务")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio", help="传输方式")
    parser.add_argument("--host", default=os.getenv("CYBERMAP_BIND_HOST", "127.0.0.1"), help="HTTP 绑定地址")
    parser.add_argument("--port", type=int, default=int(os.getenv("CYBERMAP_MCP_PORT", "8001")), help="HTTP 端口")
    args = parser.parse_args()
    if args.transport == "streamable-http" and not _loopback(args.host):
        if not (
            (os.getenv("CYBERMAP_SERVICE_TOKEN") or os.getenv("CYBERMAP_JWT_PUBLIC_KEY"))
            and os.getenv("CYBERMAP_MCP_ISSUER_URL")
            and os.getenv("CYBERMAP_MCP_RESOURCE_URL")
        ):
            parser.error("非回环 Streamable HTTP 需要令牌校验器，以及 CYBERMAP_MCP_ISSUER_URL 和 CYBERMAP_MCP_RESOURCE_URL")
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            stateless_http=True,
            json_response=True,
        )


if __name__ == "__main__":
    run_server()
