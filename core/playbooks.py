"""Information-gathering playbooks: one intent, rendered in every engine's native syntax.

Why this exists: `core/rules.py` bundles hundreds of FOFA `app=` fingerprints, which only benefit
a FOFA run, and a planner model both misses pivots and invents filters. Each playbook step below
encodes a collection intent that matters and renders it per engine. Everything was verified against
the live APIs:

- certificate pivot - FOFA `cert="qianxin.com"` (1600 hits), Shodan `ssl.cert.subject.cn:qianxin.com`
  (146), Hunter `cert="qianxin.com"` (1555): the one pivot whose wording agrees across engines.
- web product pivot - FOFA `app="P"` (bundled library), Hunter `app.name="P"` (164263 hits for
  ThinkPHP) and Shodan **`http.title:"P"`** (792 hits): Shodan's `product:"ThinkPHP"` returns 0
  because `product` describes the service banner, not a web framework.
- organization pivot - the raw user string is used as-is. FOFA stores Chinese organization names
  (`org="奇安信"` returns 0 where the Latin spelling hits) and Shodan stores Latin ones
  (`org:"Qianxin"` returns 3), so a machine-translated filter would silently return nothing.

Steps are bounded by `MAX_PLAYBOOK_QUERIES` (injected queries cost quota on Shodan and Hunter),
labelled with the evidence strategy they deserve, and marked `source="playbook"` so a run stays
auditable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from core.engines import normalize_engine

# Injected queries cost quota on paid engines, so a single run never adds more than this many.
MAX_PLAYBOOK_QUERIES = 2


@dataclass(frozen=True)
class CollectionStep:
    """One deterministic collection query with the evidence strategy it deserves."""

    query: str
    purpose: str
    strategy: str


def certificate_step(engine: str, domain: str) -> CollectionStep:
    """Assets whose TLS certificate names the given domain."""
    resolved = normalize_engine(engine)
    if resolved == "shodan":
        query = f"ssl.cert.subject.cn:{domain}"
    else:
        query = f'cert="{domain}"'
    return CollectionStep(
        query=query,
        purpose=f"证书枢轴：找出证书中出现 {domain} 的资产（同证书常被同一主体复用）",
        # Certificate reuse across tenants is common, so this is supporting evidence, not proof.
        strategy="balanced",
    )


def product_step(engine: str, product: str) -> CollectionStep:
    """Assets running a named product/component, in the engine's own fingerprint vocabulary."""
    resolved = normalize_engine(engine)
    if resolved == "shodan":
        # `product:` is service-level (ThinkPHP -> 0 hits); the product name shows up in titles.
        query = f'http.title:"{product}"'
        strategy = "balanced"
    elif resolved == "hunter":
        query = f'app.name="{product}"'
        strategy = "precision"
    else:
        query = f'app="{product}"'
        strategy = "precision"
    return CollectionStep(
        query=query,
        purpose=f"产品指纹枢轴：按组件名 {product} 检索同源资产",
        strategy=strategy,
    )


_CJK = re.compile(r"[\u4e00-\u9fff]")
_LATIN = re.compile(r"[A-Za-z]")


def organization_step(engine: str, organization: str) -> CollectionStep | None:
    """Assets attributed to an organization, spelled exactly as the user wrote it.

    The spelling is never translated, and a name without Latin characters is not sent to engines
    that index Latin organization names - measured: Shodan `org:"北京大学"` returns 0 where
    `org:"Peking University"` returns 181, and FOFA `org="北京大学"`/`org="清华大学"`/`org="奇安信"`
    all return 0. Hunter indexes Chinese company names (`company="北京大学"` returns 4758), so it
    keeps the pivot. The planner may still try its own spelling if it knows one.
    """
    resolved = normalize_engine(engine)
    if resolved != "hunter" and _CJK.search(organization) and not _LATIN.search(organization):
        return None
    if resolved == "shodan":
        query = f'org:"{organization}"'
    elif resolved == "hunter":
        query = f'company="{organization}"'
    else:
        query = f'org="{organization}"'
    return CollectionStep(
        query=query,
        purpose=f"组织枢轴：按组织名“{organization}”检索（各引擎语言不同，按原样提交）",
        strategy="balanced",
    )


_STEP_FILTER = re.compile(r'^(?P<field>[a-z0-9_.]+)\s*(?:=|:)\s*"?(?P<value>[^"]+?)"?$', re.IGNORECASE)


def _already_planned(step_query: str, planned_queries: Iterable[str]) -> bool:
    """Is this pivot already covered by a planned query?

    A textual comparison is not enough: measured on the planner's own output, the query
    `(org="Example University" || cert.subject.org="Example University") && country="US"` already
    covers the pivot `org="Example University"`, so injecting it again would spend quota (and a
    Shodan credit) on a duplicate. The filter name and value must both appear in the same planned
    query for the pivot to count as covered.
    """
    match = _STEP_FILTER.match(step_query.strip())
    if match is None:
        return False
    field = match.group("field").lower()
    value = match.group("value").strip().lower()
    return any(field in query.lower() and value in query.lower() for query in planned_queries)


def collection_steps(
    engine: str,
    *,
    domain: str | None = None,
    product: str | None = None,
    organization: str | None = None,
    existing: Iterable[str] = (),
    limit: int = MAX_PLAYBOOK_QUERIES,
) -> list[CollectionStep]:
    """Render the applicable pivots for one engine, deduplicated against already-planned queries.

    A certificate pivot outranks a product or organization pivot when several apply: it usually
    returns the widest set of assets that are independently attributable to the same subject.
    """
    planned = list(existing)
    candidates: list[CollectionStep] = []
    if domain:
        candidates.append(certificate_step(engine, domain))
    if product:
        candidates.append(product_step(engine, product))
    if organization:
        organization_pivot = organization_step(engine, organization)
        if organization_pivot is not None:
            candidates.append(organization_pivot)
    picked: list[CollectionStep] = []
    for step in candidates:
        if step.query.strip().lower() in {item.strip().lower() for item in planned}:
            continue
        if _already_planned(step.query, planned):
            continue
        planned.append(step.query)
        picked.append(step)
        if len(picked) >= max(1, limit):
            break
    return picked


# Derived pivots are wider than the intent's own signals (a /24 holds unrelated tenants), so a run
# never adds more than this many, and nothing derived is labelled "precision".
MAX_DERIVED_PIVOTS = 3
_BARE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Reserved names (RFC 6761/6762) plus single-label hosts: pivoting on them cannot find anything.
_RESERVED_SUFFIXES = (".local", ".internal", ".localhost", ".invalid", ".test", ".example", ".home", ".lan")


def _bare_domain(value: object) -> str:
    from core.agent_profiles import GENERIC_DOMAIN_SCOPES

    text = str(value or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text).split("/", 1)[0].split(":", 1)[0].removeprefix("www.")
    text = text.rstrip(".")
    if not _BARE_DOMAIN.fullmatch(text) or text in GENERIC_DOMAIN_SCOPES:
        return ""
    if text.endswith(_RESERVED_SUFFIXES):
        return ""
    return text


def _netblock(value: object) -> str:
    """The /24 a public IPv4 address belongs to, or "" when it is not usable as a seed."""
    import ipaddress

    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    if address.version != 4 or not address.is_global:
        return ""
    return str(ipaddress.ip_network(f"{address}/24", strict=False))


def derived_pivots(
    engine: str,
    assets: list[dict],
    *,
    existing: Iterable[str] = (),
    limit: int = MAX_DERIVED_PIVOTS,
) -> list[CollectionStep]:
    """Pivots derived from what the run already found, ordered by recall value per query.

    - filing number (`icp`, FOFA/Hunter): every domain filed by the same subject - the strongest
      Chinese-organization lever, and unavailable on Shodan (it has no filing field);
    - certificate name (`ssl_cn`): other assets sharing that certificate;
    - a newly seen registrable domain (`domain`): its own surface, most likely the same target;
    - the /24 of a discovered address: siblings on the same netblock. Widest and least specific of
      the four (one measured /24 held 2140 rows across unrelated tenants), so it is used last.

    Rows that sit on a hosting/CDN provider are skipped as seeds: their certificate, filing and
    organization fields describe the provider, so pivoting on them would pull in unrelated tenants.
    """
    from core.hosting import hosting_provider

    resolved = normalize_engine(engine)
    planned = list(existing)
    seeds: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for asset in assets:
        if hosting_provider(asset):
            continue
        signals = (
            ("icp", str(asset.get("icp") or "").strip()),
            ("cert", _bare_domain(asset.get("ssl_cn")) or _bare_domain(asset.get("cert.subject.cn"))),
            ("net", _netblock(asset.get("ip"))),
            ("domain", _bare_domain(asset.get("domain"))),
        )
        for kind, value in signals:
            if value and (kind, value) not in seen:
                seen.add((kind, value))
                seeds.append((kind, value))
    order = {"icp": 0, "cert": 1, "domain": 2, "net": 3}
    seeds.sort(key=lambda item: order[item[0]])

    steps: list[CollectionStep] = []
    for kind, value in seeds:
        step = _derived_step(resolved, kind, value)
        if step is None:
            continue
        if step.query.strip().lower() in {item.strip().lower() for item in planned}:
            continue
        if _already_planned(step.query, planned):
            continue
        planned.append(step.query)
        steps.append(step)
        if len(steps) >= max(1, limit):
            break
    return steps


def _derived_step(engine: str, kind: str, value: str) -> CollectionStep | None:
    if kind == "icp":
        if engine == "shodan":  # Shodan exposes no filing field.
            return None
        purpose = f"备案号枢轴：查出 {value} 登记的同主体资产"
        query = f'icp="{value}"'
        strategy = "balanced"
    elif kind == "cert":
        step = certificate_step(engine, value)
        purpose = f"证书枢轴（派生）：{value} 的同证书资产"
        query, strategy = step.query, step.strategy
    elif kind == "net":
        purpose = f"网段枢轴（派生）：{value} 内的相邻资产，需按归属复核"
        query = f"net:{value}" if engine == "shodan" else f'ip="{value}"'
        strategy = "recall"
    elif kind == "domain":
        purpose = f"域名枢轴（派生）：{value} 的资产面"
        if engine == "shodan":
            query = f"hostname:{value}"
        elif engine == "hunter":
            query = f'domain.suffix="{value}"'
        else:
            query = f'domain="{value}"'
        strategy = "balanced"
    else:  # pragma: no cover - guarded by the caller's kind set
        return None
    return CollectionStep(query=query, purpose=purpose, strategy=strategy)
