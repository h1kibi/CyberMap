# Migrating to CyberMap

CyberMap is the renamed continuation of FofaMap 2.0.1 (a 二开/fork). Everything below is a rename
of project-scoped identifiers; engine names (`fofa`, `shodan`, `hunter`, `daydaymap`, `censys`) and
their MCP tools (`fofa_search`, `shodan_search`, ...) are unchanged.

| Item | FofaMap | CyberMap |
|---|---|---|
| CLI / module | `fofamap`, `fofamap.py` | `cybermap`, `cybermap.py` |
| Entry points | `fofamap`, `fofamap-api`, `fofamap-mcp` | `cybermap`, `cybermap-api`, `cybermap-mcp` |
| Environment prefix | `FOFAMAP_*` (config, token, ports, JWT, cache, ...) | `CYBERMAP_*` |
| Keyring services | `fofamap`, `fofamap-shodan`, `fofamap-hunter`, `fofamap-censys`, `fofamap-daydaymap`, `fofamap-provider` | `cybermap`, `cybermap-shodan`, `cybermap-hunter`, `cybermap-censys`, `cybermap-daydaymap`, `cybermap-provider` |
| Per-user config dir | `%APPDATA%/FofaMap`, `~/Library/Application Support/FofaMap`, `~/.config/fofamap` | `%APPDATA%/CyberMap`, `~/Library/Application Support/CyberMap`, `~/.config/cybermap` |
| Jobs DB / cache | `fofamap.sqlite3`, `fofamap-cache.sqlite3`, table `fofamap_jobs` | `cybermap.sqlite3`, `cybermap-cache.sqlite3`, table `cybermap_jobs` |
| MCP server name / resources | `fofamap_mcp`, `fofamap://...` | `cybermap_mcp`, `cybermap://...` |
| JWT scope / audience | `fofamap` | `cybermap` |
| Integration markers | `.fofamap-managed.json`, `# >>> fofamap managed integration >>>` | `.cybermap-managed.json`, `# >>> cybermap managed integration >>>` |

Migration steps:

1. Re-enter engine keys or copy them to the new keyring services:
   `keyring get fofamap-shodan SHODAN_API_KEY` → `keyring set cybermap-shodan SHODAN_API_KEY`.
   `FOFA_*`, `SHODAN_API_KEY`, `HUNTER_API_KEY`, `CENSYS_API_TOKEN` and `DAYDAYMAP_API_KEY` environment
   variable names are unchanged (they name providers, not the project).
2. Rename `FOFAMAP_*` environment variables to `CYBERMAP_*` (service token, bind host/port, JWT
   settings, database URL, cache settings, scanning switches, live-test switch).
3. Move `fofamap.sqlite3` → `cybermap.sqlite3` (rename the `fofamap_jobs` table to `cybermap_jobs`,
   or start a fresh job database) and `fofamap-cache.sqlite3` → `cybermap-cache.sqlite3` if you want
   to keep cached pages.
4. Re-run `cybermap --install-integration` (or `--force`) for MCP hosts: the MCP server key is now
   `cybermap`, so old `fofamap` entries in host configs are stale. The integration installer refuses
   to touch unmanaged entries and writes `.cybermap-managed.json` markers.
5. `search.engine` values and the `-e` choices are unchanged except for the added engines.

# Migrating from FofaMap 2.0 to 2.0.1

## Credentials and configuration

Copy `config/settings.example.yaml` to `config/settings.yaml`, or run `cybermap init`. Environment variables, Keyring and container secrets remain preferred. If Keyring is unavailable, the wizard can write FOFA and model keys to the local YAML only after explicit confirmation; the default path is gitignored. On macOS/Linux it applies `0600` permissions. Windows relies on the current user directory ACL and the wizard warns that Keyring or environment variables are safer. `FOFA_KEY` remains a temporary compatibility alias; `FOFA_EMAIL` is optional for current key-only FOFA endpoints. A missing YAML file is valid.

Keys found in YAML still load with a warning. Any key that was ever committed must be rotated; a newly confirmed local-only key may remain only while the file stays private and untracked.

## CLI

The frequently used 2.0 aliases remain:

```bash
cybermap -q 'app="nginx"' -f host,ip,port,status_code -p 3
cybermap -hq 8.8.8.8
cybermap -cq 'app="redis"' -f country,port
cybermap -ai '统计中国公开的 Redis 服务分布'
```

Running `cybermap` without arguments restores the full interactive wizard. Passing a classic option without its value, such as `cybermap --query`, prompts for the value instead of failing. Human-readable Rich tables and automatic XLSX export are the defaults; raw JSON is opt-in through `--output-format json` or `jsonl`.

The CLI is a standalone product entry point: ordinary search, Host, stats, icon and batch modes do not start MCP/REST and do not require a model provider. MCP remains a parallel integration entry point backed by the same typed FOFA core.

`-n/--nuclei` creates a bounded plan after search and can run it only after showing the exact targets, template IDs and severities and receiving interactive approval. MCP/REST use the equivalent independent `nuclei_plan` then `nuclei_execute` flow.

The old internal `core.ai`, `core.handler`, and duplicate `core.core.FofaClient` implementations are removed. `core.core.FofaClient` remains a re-export, but other internal Python APIs are not compatibility guarantees.

## MCP

2.0.1 requires `mcp>=2,<3` and uses `MCPServer`. The SDK negotiates older supported protocol revisions with clients. Update installation before importing `mcp_server.py`.

```bash
cybermap-mcp                         # stdio
cybermap-mcp --transport streamable-http --host 127.0.0.1 --port 8001
```

## Agent/model configuration

Providers are profiles, not branches in Agent code. Choose `openai_responses`, `openai_chat`, `anthropic_messages`, or `ollama_native`, then set any current or future model ID. Cross-provider fallback is off until explicitly configured.
