"""Information-gathering playbooks: one intent, rendered in every engine's native syntax.

Every query string asserted here was verified against the live APIs (see the module docstring of
`core/playbooks.py`), so these tests pin the *cross-engine vocabulary* rather than an internal
helper: FOFA `cert=` → Shodan `ssl.cert.subject.cn:` → Hunter `cert=`, and the fact that Shodan's
web-product pivot is `http.title:` (its `product:` field returns 0 for ThinkPHP).
"""

import pytest

from core.agent_profiles import intent_context
from core.hosting import hosting_provider
from core.playbooks import (
    MAX_DERIVED_PIVOTS,
    MAX_PLAYBOOK_QUERIES,
    collection_steps,
    derived_pivots,
)


def test_certificate_pivot_is_rendered_per_engine():
    (step,) = collection_steps("fofa", domain="qianxin.com")
    assert (step.query, step.strategy) == ('cert="qianxin.com"', "balanced")

    (step,) = collection_steps("shodan", domain="qianxin.com")
    assert step.query == "ssl.cert.subject.cn:qianxin.com"

    (step,) = collection_steps("hunter", domain="qianxin.com")
    assert step.query == 'cert="qianxin.com"'


def test_product_pivot_uses_the_engine_own_vocabulary():
    assert collection_steps("fofa", product="ThinkPHP")[0].query == 'app="ThinkPHP"'
    assert collection_steps("hunter", product="ThinkPHP")[0].query == 'app.name="ThinkPHP"'
    # Shodan's `product:"ThinkPHP"` matches nothing (verified: 0 vs 792 hits for http.title).
    assert collection_steps("shodan", product="ThinkPHP")[0].query == 'http.title:"ThinkPHP"'


def test_organization_pivot_keeps_the_user_spelling():
    """The name is never translated, so a Latin org name reaches every engine unchanged."""
    assert collection_steps("fofa", organization="Example University")[0].query == 'org="Example University"'
    assert collection_steps("shodan", organization="Peking University")[0].query == 'org:"Peking University"'
    assert collection_steps("hunter", organization="Peking University")[0].query == 'company="Peking University"'


def test_a_chinese_org_name_is_not_sent_to_engines_that_index_latin_names():
    """Measured: Shodan `org:"北京大学"` = 0 (Latin spelling = 181) and FOFA `org="北京大学"` = 0,
    while Hunter `company="北京大学"` = 4758, so a guaranteed-empty pivot is not injected."""
    assert collection_steps("fofa", organization="北京大学") == []
    assert collection_steps("shodan", organization="北京大学") == []
    assert collection_steps("hunter", organization="北京大学")[0].query == 'company="北京大学"'
    # A mixed name still carries Latin characters, so it stays applicable.
    assert collection_steps("shodan", organization="北京大学 Peking University")[0].query == (
        'org:"北京大学 Peking University"'
    )


def test_pivots_already_covered_by_the_plan_are_not_injected():
    planned = ['(org="Example University" || cert.subject.org="Example University") && country="US"']
    assert collection_steps("fofa", organization="Example University", existing=planned) == []
    planned_cert = ['(domain="example.edu" || cert="example.edu") && country="US"']
    assert collection_steps("fofa", domain="example.edu", existing=planned_cert) == []


def test_certificate_pivot_outranks_other_pivots_and_the_budget_is_bounded():
    steps = collection_steps(
        "fofa",
        domain="example.edu",
        product="ThinkPHP",
        organization="Example University",
        existing=['body="Example University"'],
    )
    # The certificate pivot usually returns the widest independently attributable set, and injected
    # queries cost quota, so the bundle never adds more than its documented budget.
    assert [step.query for step in steps] == ['cert="example.edu"', 'app="ThinkPHP"']
    assert len(steps) <= MAX_PLAYBOOK_QUERIES


def test_intent_context_extracts_only_explicit_signals():
    context = intent_context("收集 example.com 域名下使用 nginx 的资产清单")
    assert context.domain == "example.com"
    assert context.organization is None

    # The request verbs must not leak into the filter: `org="收集某某大学"` would match nothing.
    assert intent_context("收集某某大学的对外资产").organization == "某某大学"
    assert intent_context("查一下北京大学的官网").organization == "北京大学"
    # Generic scopes are not pivots: a certificate filter on edu.cn would match every university.
    assert intent_context("帮我看看 edu.cn 的资产") == intent_context("帮我看看 edu.cn 的资产")
    assert intent_context("帮我看看 edu.cn 的资产").domain is None
    assert intent_context("看看 https://www.example.com/admin").domain == "example.com"


@pytest.mark.parametrize("engine", ["fofa", "shodan", "hunter"])
def test_steps_never_render_empty_values(engine):
    assert collection_steps(engine, domain=None, product="", organization=None) == []


def test_derived_pivots_render_from_what_the_run_found():
    assets = [{"ip": "45.33.32.156", "domain": "example.com", "ssl_cn": "www.example.com", "icp": "京ICP证030173号"}]

    assert [step.query for step in derived_pivots("fofa", assets)] == [
        'icp="京ICP证030173号"',
        'cert="example.com"',
        'domain="example.com"',
    ]
    # Shodan has no filing field, so the strongest Chinese lever simply does not exist there.
    assert [step.query for step in derived_pivots("shodan", assets)] == [
        "ssl.cert.subject.cn:example.com",
        "hostname:example.com",
        "net:45.33.32.0/24",
    ]
    assert [step.query for step in derived_pivots("hunter", assets)][0] == 'icp="京ICP证030173号"'


def test_derived_pivots_skip_hosting_rows_and_private_networks():
    """A CDN/cloud edge carries the provider's certificate and filing, not the target's."""
    assets = [
        {"ip": "104.20.23.154", "domain": "example.com", "org": "Cloudflare, Inc.", "icp": "京ICP证030173号"},
        {"ip": "10.0.0.7", "domain": "intranet.local"},
    ]
    assert derived_pivots("fofa", assets) == []


def test_derived_pivots_are_bounded_and_respect_planned_queries():
    assets = [{"ip": f"45.33.{index}.10", "domain": f"site{index}.example.com"} for index in range(4)]
    assert len(derived_pivots("fofa", assets)) == MAX_DERIVED_PIVOTS
    planned = ['ip="45.33.0.0/24"', 'domain="site0.example.com"']
    # Domains rank above netblocks, and a seed the plan already covers is skipped.
    assert [step.query for step in derived_pivots("fofa", assets, existing=planned)] == [
        'domain="site1.example.com"',
        'domain="site2.example.com"',
        'domain="site3.example.com"',
    ]


def test_derived_pivot_strategies_never_claim_precision():
    assets = [{"ip": "45.33.32.156", "domain": "example.com", "icp": "京ICP证030173号"}]
    # A pivot is inherently indirect: it is scored as balanced evidence or a wide recall net.
    assert {step.strategy for step in derived_pivots("fofa", assets)} == {"balanced", "recall"}


def test_hosting_provider_recognizes_network_owners_only():
    assert hosting_provider({"org": "Cloudflare, Inc."}) == "Cloudflare"
    assert hosting_provider({"isp": "阿里云"}) == "阿里云"
    assert hosting_provider({"as_org": "AKAMAI-AS"}) == "AKAMAI"
    assert hosting_provider({"server": "cloudflare"}) == "cloudflare"
    # A page title is not ownership evidence.
    assert hosting_provider({"title": "cloud storage dashboard"}) == ""
    assert hosting_provider({"org": "Peking University"}) == ""
