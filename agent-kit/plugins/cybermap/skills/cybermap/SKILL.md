---
name: cybermap
description: Use CyberMap to validate FOFA, Shodan, Hunter (奇安信鹰图), DayDayMap and Censys syntax, search and profile internet assets, aggregate statistics, export bounded results, and manage authorized scan plans through its MCP tools. Trigger for FOFA queries, external attack-surface discovery, host intelligence, favicon searches, asset inventory, exposure analysis, or FOFA result exports.
---

# CyberMap

Use the CyberMap MCP server for evidence-based asset research. Prefer the MCP tools over shell commands when they are available.

One contract (`SearchRequest` / `SearchPage` / `AssetRecord`) backs five engines: FOFA, Shodan, Hunter (奇安信鹰图), DayDayMap and Censys. Only the query syntax, the billing rules and the available endpoints differ (Censys on a Free token serves host lookups by IP only; DayDayMap has no aggregation endpoint).

## Engine syntax

| Engine | Selector | Query syntax | Cost |
|---|---|---|---|
| FOFA | `fofa` (default) | `app="nginx" && country="CN"` | FOFA quota per request |
| Shodan | `shodan` | `product:nginx country:CN` (`filter:value`) | 1 query credit per filtered query and per page after the first |
| Hunter | `hunter` | `web.title="登录" && country="中国"` (`key="value"`, operators `&&`, `\|\|`, `!=`) | credits deducted per returned record |
| DayDayMap | `daydaymap` | `title="登录" && country="中国"` (FOFA-like `field="value"`, `\|\|`, parentheses) | points are deducted by the platform and **not reported**; no balance endpoint |
| Censys | `censys` | `ip="1.2.3.4"` (host lookup only) | 1 credit per host lookup; the Free plan has no search/aggregate API |
| Merged | `all` | each engine plans in its own syntax; never translated across engines | every platform bills separately |

`all` replaces the old two-engine scope: it merges FOFA, Shodan and Hunter, is only reachable through `fofa_agent_run(engine="all")` (or `-e all -ai` on the CLI), and merged output renames FOFA `country` to `country_code`, merges FOFA `cert.subject.cn` into `ssl_cn`, and is deduplicated on a normalized identity - scheme/port/path/trailing dot stripped, `protocol` folded to http/https/other, web assets keyed by virtual host and non-web services by `IP:port` - country aggregated only by `country_code` (Hunter reports a Chinese country name, so the code is mapped), and every count reported as rows *and* distinct endpoints.

## Workflow

1. Clarify the target, ownership or authorization boundary, desired fields, time range, and result limit when these materially affect the request. Call `fofa_account` and `fofa_fields` when membership-dependent capabilities matter; these tools work even in hosts that do not expose MCP Resources.
2. If the user names a product, OA, VPN, middleware, database, camera, CMS, or ops panel, call `fofa_rules` **before** `fofa_search`. Use the returned `query` values verbatim. Do not invent `app=` names. An empty keyword lists the bundled catalog (no FOFA quota).
3. Call the engine's validator before spending quota: `fofa_validate_query`, `shodan_validate_query` or `hunter_validate_query` (`censys_search` validates locally and rejects non-IP queries before any request). Repair invalid syntax before searching.
4. Call `fofa_search` for the first bounded page. Use the smallest useful field set and size.
5. Use `fofa_search_next` only when more records are needed, passing its opaque cursor unchanged.
6. Use `fofa_host_profile` only when `fofa_account` shows Host aggregation (not registered users). Use `fofa_stats` only when the account has the stats API (professional / business / enterprise). Personal, ordinary, and education accounts should use `fofa_search` instead of stats.
7. For Shodan targets call `shodan_account` first, then `shodan_search` with Shodan syntax (`product:nginx country:CN`) and numbered pages. `shodan_stats` (`/shodan/host/count`) and `shodan_account` (`/api-info`) spend no query credits; a query containing `filter:value` and every page past the first cost 1 query credit each.
8. For Hunter targets call `hunter_account` first (free, `/openApi/userInfo`), then `hunter_search` with Hunter syntax (`web.title="登录" && country="中国"`) and numbered pages (`page=`; `size` defaults to 10). Hunter only accepts `page_size` 1 or a multiple of 10 up to 100, so a requested `size` is rounded **down** to the nearest legal bucket (`5` → 1, `14` → 10, `150` → 100) — rounding up would spend more credits than the user asked for, because Hunter bills credits per returned record. An identical re-run and any rejected request cost 0, and one query only pages to 10,000 records. Hunter exposes **no** aggregation endpoint: there is no `hunter_stats`, so run statistics on FOFA or Shodan and treat a statistics intent as a plain search. `hunter_host_profile` is aggregated from an `ip="x"` search, so unlike the FOFA/Shodan host lookups it spends credits. Permission-gated columns (`body`, `whois`, `vul_list` on a personal account) are dropped with a visible note and retried once.
9. For Censys targets call `censys_account` first (free), then `censys_host_profile <ip>` or `censys_search 'ip="1.2.3.4"'`. Each host lookup costs 1 credit and is cached for 24h; the Free plan returns 403 for any list search, so never plan Censys enumeration, and use `censys_search` only when the user supplied an IP. There is no `censys_stats`.
9b. For DayDayMap targets call `daydaymap_account` (local, no request), then `daydaymap_search` with FOFA-like syntax (`title="登录" && country="中国"`, `||`, parentheses). Its `domain` value is a hostname and lives in `hostnames`; there is no `daydaymap_stats`, `icon_md5` is not searchable, and the API does not report the points consumed, so prefer few high-value queries.
10. Use `fofa_export` for large or reusable result sets (set `engine` to `fofa`, `shodan`, `hunter`, `daydaymap` or `censys`), then poll `fofa_job_status`. Return the artifact path instead of pasting large tables.
11. Use `fofa_icon_search` for an explicit public website favicon (FOFA and Shodan search the MurmurHash3, Hunter searches the favicon MD5 as `web.icon="<md5>"`; one fetch yields both). Prefer `fofa_agent_run` for open-ended Chinese/English discovery intents (`engine="fofa"` by default, `"shodan"` for Shodan, `"hunter"` for Hunter, `"all"` to plan every engine separately and merge them); for organization website discovery, return its structured `website_candidates` first, preserving `corroborated`, `observed`, and `candidate` status instead of flattening them into confirmed ownership.
12. State that FOFA, Shodan or Hunter observations and even cross-consistent title/certificate/ICP clues indicate exposed or corroborated candidates, not legal ownership or vulnerability, unless separately verified.

## Safety

- Treat searches, profiles, and statistics as passive intelligence collection, but still respect the user's scope and applicable rules.
- Never call `nuclei_plan` unless the user explicitly asks for active scanning and identifies an authorized scope.
- Review every target, template, and severity in the plan before asking for approval.
- Call `nuclei_execute` only after explicit approval for that exact plan. Never broaden or reuse an approval token.
- Do not interpret authentication, quota, timeout, or provider errors as an empty FOFA, Shodan or Hunter result. Shodan `query_credits` exhaustion and Hunter point exhaustion are reported as `quota_exhausted`, never as "no assets".
- Never place `FOFA_API_KEY`, `SHODAN_API_KEY`, `HUNTER_API_KEY`, provider keys, bearer tokens, or approval tokens in reports or committed files.

## Host Fallback

If the host cannot expose MCP tools, use CyberMap's machine-readable CLI only for passive operations, for example `cybermap -q 'domain="example.com"' --output-format json --no-save`, `cybermap --engine shodan -q 'product:nginx country:CN' --output-format json --no-save`, `cybermap --engine hunter -q 'web.title="登录"' --output-format json --no-save`, or `cybermap --rule 致远OA --output-format json --no-save`. Do not use the CLI to bypass host approval controls.

Read [references/tool-catalog.md](references/tool-catalog.md) when exact tool selection, pagination, resources, or host capability differences matter.
