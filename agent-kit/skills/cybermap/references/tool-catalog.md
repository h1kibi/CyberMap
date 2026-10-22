# CyberMap tool catalog

## MCP tools

| Tool | Purpose | Side effect |
|---|---|---|
| `fofa_validate_query` | Validate FOFA syntax locally | None; no quota use |
| `shodan_validate_query` | Validate Shodan syntax locally | None; no query credits |
| `hunter_validate_query` | Validate Hunter syntax locally (Shodan-style `filter:value` is rejected) | None; no Hunter points |
| `fofa_fields` | Read field tiers and membership capability matrix | None; no quota use |
| `fofa_account` | Read current account tier, permissions and quota | FOFA quota/read |
| `fofa_search` | Fetch one structured result page | FOFA quota/read |
| `fofa_search_next` | Continue with an opaque cursor | FOFA quota/read |
| `fofa_icon_search` | Fetch a public favicon, calculate its FOFA hash and search it (the same fetch also yields the Hunter MD5) | Public HTTP + engine quota/read |
| `fofa_host_profile` | Load one host aggregation | FOFA quota/read; requires Host API membership |
| `fofa_stats` | Aggregate by supported dimensions | FOFA quota/read; requires stats API membership |
| `shodan_search` | Fetch one Shodan page (100 matches per page, `page=` numbering) | Shodan query credits: filters and pages past the first cost 1 each |
| `shodan_host_profile` | Load every service Shodan saw on one IP or domain | Shodan read |
| `shodan_stats` | Facet Top-N via `/shodan/host/count` | None; no query credits |
| `shodan_account` | Read plan, remaining query/scan credits and monthly limits | None; no query credits |
| `hunter_search` | Fetch one Hunter page (`page=` numbering, `size` defaults to 10; Hunter accepts only 1 or a multiple of 10 up to 100, so a requested size is rounded down) | Hunter credits per returned record; an identical re-run and any rejected request cost 0 |
| `hunter_host_profile` | Aggregate every service Hunter saw on one IP or domain | Hunter credits; aggregated from an `ip="x"` search |
| `hunter_account` | Read Hunter account type, remaining free/equity points and export quotas | None; `/openApi/userInfo` spends nothing |
| `daydaymap_validate_query` | Validate DayDayMap syntax locally (`field="value"`, `&&`, `||`, parentheses) | None; no points |
| `daydaymap_search` | Fetch one DayDayMap page (`page=` numbering, `page_size` up to 10000) | Platform points; the API does not report how many |
| `daydaymap_host_profile` | Aggregate every service DayDayMap indexed for one IP or host | One `ip=`/`domain=` search (points not reported) |
| `daydaymap_account` | Local capability view (no API balance endpoint exists) | None; no request at all |
| `censys_search` | Look up ONE host by IP (`ip="1.2.3.4"`): the Free plan has no list-search API | Censys credits: 1 per host lookup, 0 on a cache hit |
| `censys_host_profile` | Every service, endpoint, HTTP/TLS detail, whois, ASN and DNS name for one IP | Censys credits: 1 per lookup (cached 24h) |
| `censys_account` | Read the Free credit balance and reset time | None; `/v3/accounts/users/credits` spends nothing |
| `fofa_syntax` | Official FOFA query operators and fields | None |
| `fofa_rules` | Search bundled FOFA library `app=` names. Call **before** `fofa_search` when the user names a product/OA/VPN. Use returned queries verbatim. | None |
| `fofa_export` | Start a bounded background export; set `engine` to `fofa`, `shodan`, `hunter`, `daydaymap` or `censys` | Writes a local artifact |
| `fofa_job_status` | Read export, agent, or scan job state | None |
| `fofa_agent_run` | Run the optional planning workflow without active scanning (`engine=fofa\|shodan\|hunter\|all`; `all` plans every engine separately and merges the runs; `min_evidence=recall\|hypothesis\|balanced\|precision` drops rows found only by weaker strategies); organization website runs include evidence-labelled `website_candidates` | Engine/model quota/read |
| `nuclei_plan` | Create an expiring, exact active-scan plan | Requires scanning enabled and authorization |
| `nuclei_execute` | Consume one approval token and execute the exact plan | Destructive/open-world |

There is no `hunter_stats`: Hunter's open API exposes no aggregation endpoint, so statistics stay a FOFA/Shodan capability and a statistics intent on Hunter is downgraded to a search.
There is no `daydaymap_stats`: the open API has no per-query aggregation endpoint (its count endpoint returns platform-wide totals), so a statistics intent is downgraded to a normal search. DayDayMap's `consumed` is `null` because the API does not report the points a request used.

There is no `censys_stats` either: Censys Free answers 403 for `/v3/global/search/query` and does not expose `/v3/global/search/aggregate`, so a statistics intent on Censys is downgraded to a host profile. Censys is deliberately excluded from `fofa_agent_run(engine="all")` for the same reason; select `censys_host_profile` for an explicit IP instead. Every engine's fetched pages are cached in SQLite as they arrive, so a re-run of the same request spends nothing; `--no-cache` forces a fresh request and `--cache-clear` empties the cache.

## MCP resources

- `cybermap://fields`: versioned FOFA field catalogue and vip_level API matrix (`https://fofa.info/api`).
- `cybermap://rules`: bundled FOFA `app=` fingerprint library.
- `cybermap://account`: account capabilities and usage.
- `cybermap://shodan/account`: Shodan plan, remaining query/scan credits and monthly limits.
- `cybermap://hunter/account`: Hunter account type and remaining free/equity points.
- `cybermap://jobs/{job_id}`: job metadata and artifact path.

DeepSeek Harness currently bridges MCP Tools only; MCP Resources and Prompts are unavailable there. Other hosts may expose resources through host-specific wrapper tools.

## Engine differences

| | FOFA | Shodan | Hunter (奇安信鹰图) |
|---|---|---|---|
| Syntax | `app="nginx" && country="CN"` | `product:nginx country:CN` | `web.title="登录" && country="中国"` |
| Pagination | opaque cursor | `page=` number, 100 matches per page | `page=` number, `size` 1 or a multiple of 10 up to 100 (rounded down) |
| Statistics | stats API (membership) | facet via `/shodan/host/count` | not available |
| Host profile | free, needs Host API | free-ish, plan dependent | costs credits (`ip=` search) |
| Favicon pivoting | MurmurHash3 `icon_hash` | MurmurHash3 `http.favicon.hash` | MD5 `web.icon="<md5>"` |
| Cost | FOFA quota | 1 query credit per filtered query/page past the first | credits per returned record |

Merged runs (`engine="all"`, agent only) are deduplicated on a normalized identity - scheme/port/path/trailing dot stripped, `protocol` folded to http/https/other, web assets keyed by virtual host and non-web services by `IP:port` - country aggregated only by `country_code` (Hunter reports a Chinese country name, so the code is mapped), and every count reported as rows *and* distinct endpoints. They also keep the other engines' results when one engine fails (reported per engine) and delegate non-list intents (host profile, statistics, favicon) to the first engine that accepts them.

## Common query patterns

```text
domain="example.com"
cert="example.com"
app="nginx" && country="CN"
ip="192.0.2.1"
icon_hash="123456789"
```

Shodan uses `filter:value` syntax instead, and never `app=`:

```text
product:nginx country:CN
http.title:"后台登录" port:8080
org:"Example University" os:Windows
http.favicon.hash:123456789
```

Hunter uses `key="value"` with the operators `&&`, `||` and `!=`, never Shodan's `filter:value`, and always quotes values:

```text
web.title="登录" && country="中国"
domain.suffix="example.com"
app.name="nginx"
header.server=="nginx"
web.icon="<md5>"
```

One Hunter query only pages to 10,000 records, and its favicon filter uses the icon MD5 (`web.icon="<md5>"`), not FOFA/Shodan's MurmurHash3; a single `fofa_icon_search` fetch yields both hashes.

Useful Hunter filters (the API-verified set): `ip`, `port`, `protocol`, `base_protocol`, `domain`, `domain.suffix`, `web.title`, `web.body`, `web.icon`, `web.tag`, `web.similar`, `header`, `header.server==`, `status_code`, `cert`, `icp`, `app.name`, `app.vendor`, `app.version`, `os`, `company`, `country`, `province`, `city`, `isp`.

Every `fofa_agent_run` list search also gets the bundle's deterministic pivots for the signals the intent states itself (certificate, product and organization, rendered in the active engine's own syntax and labelled `source=playbook`, at most two per run, run after the planner's own queries, and never duplicating a planned query). After the first batch the run additionally derives up to three pivots from its own results (filing number `icp=` where the engine has one, certificate name, newly seen registrable domain, then the /24 netblock), labelled `source=pivot` and never scored as precision; rows sitting on a hosting/CDN provider are not used as seeds. Merged runs report `corroboration.multi_engine` (assets two engines independently indexed).

## Engine syntax

```text
FOFA:   app="nginx" && country="CN"          cursor pagination, FOFA quota
Shodan: product:nginx country:CN             page= pagination, 1 query credit per filtered query/page
Hunter: web.title="登录" && country="中国"   page= pagination, credits per returned record
```

Hunter uses `key="value"` with `&&`, `||` and `!=` and never Shodan's `filter:value`; its `page_size` accepts only 1 or
a multiple of 10 up to 100 and a requested size is rounded down. Hunter has no aggregation endpoint (there is no
`hunter_stats`) and its host profile is aggregated from an `ip="x"` search, so it spends credits.
