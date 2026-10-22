# 🗺️ CyberMap

**多引擎网络空间资产测绘工具**：一个命令行、一个 MCP Server、一套 Agent Skill 与 REST 接口，共用同一份检索契约，把 **FOFA / Shodan / Hunter（奇安信鹰图）/ DayDayMap / Censys** 的资产发现、画像、统计与导出串成可追溯的工作流，并在**显式人工审批**后才执行 Nuclei 扫描。

[![CI](https://github.com/h1kibi/CyberMap/actions/workflows/ci.yml/badge.svg?branch=main&style=flat-square)](https://github.com/h1kibi/CyberMap/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white&style=flat-square)](#安装)
[![License](https://img.shields.io/badge/License-Apache_2.0-2563EB?style=flat-square)](LICENSE)

## 与 FofaMap 的关系

CyberMap 是 [FofaMap](https://github.com/asaotomo/FofaMap) **2.0.1 的二开（fork）项目**，不是 FofaMap 官方发行版，也不代表上游立场。

- **保留**：上游的 `SearchRequest` / `SearchPage` / `AssetRecord` 引擎契约、Agent 的“规划 → 执行 → 反思 → 总结”工作流、MCP / Skill / REST 三层入口、Nuclei 计划与一次性审批令牌的边界、字段目录与密钥安全设计（环境变量 → 系统钥匙串 → 显式确认的本地 YAML）、Apache-2.0 许可证与上游署名。
- **新增**：Shodan、Hunter、DayDayMap、Censys 四个引擎；跨引擎合并与证据分级；**分页缓存**（每页到手即落盘，中断后重跑不重复扣额度）；全引擎额度耗尽时保留已抓取结果；Censys 主机画像、DayDayMap 主机画像与批量语法适配。
- **更名**：命令 `fofamap` → `cybermap`，模块 `fofamap.py` → `cybermap.py`，环境变量前缀 `FOFAMAP_*` → `CYBERMAP_*`，钥匙串服务 `fofamap-*` → `cybermap-*`，MCP server `cybermap_mcp`，资源 `cybermap://...`。完整对照见 [MIGRATION.md](MIGRATION.md)。
- **引擎名与工具名保持不变**（`fofa`、`shodan_search`、`fofa_export` 等），因为它们描述的是数据源而不是本项目。

## 功能特性

| 能力 | 说明 |
|---|---|
| 五引擎检索 | `-e fofa / shodan / hunter / daydaymap / censys`；`-e all` 为 AI 多引擎各自规划后合并 |
| 统一分页与导出 | 各引擎原生分页 → 统一页对象；XLSX / CSV / JSONL，流式大结果导出 |
| 分页缓存 | SQLite 按键（引擎、查询、页码/游标、字段、`full`）缓存；命中不扣额度；`--no-cache` / `--cache-clear` |
| 额度保护 | 任一引擎额度耗尽时保留已抓取结果并说明原因；Censys 付费调用前先读免费余额 |
| 主机画像 | FOFA Host、Shodan Host、Hunter `ip=` 聚合、DayDayMap `ip=`/`domain=` 聚合、Censys 主机 endpoint 详情 |
| 统计聚合 | FOFA / Shodan 提供 `-cq`；Hunter、DayDayMap、Censys 无按查询聚合接口，会明确报 `unsupported` |
| 图标反查 | FOFA / Shodan（MurmurHash3）、Hunter（MD5）；DayDayMap / Censys 不支持 |
| AI 侦察 | `-ai` 自然语言规划、证据分级、结果反思、Markdown 报告；多引擎合并去重 |
| MCP / Skill | stdio 与 Streamable HTTP；一条命令接入 Cursor / Codex / Claude Code / LM Studio 等 |
| REST | FastAPI：检索、画像、统计、导出、Agent、扫描计划与审批 |
| 主动扫描 | 默认关闭；展示精确目标/模板/级别并请求一次性审批；`CYBERMAP_ENABLE_SCANNING=true` 才开放 |

## 安装

需要 Python 3.10+（推荐 3.11+）。

```bash
git clone https://github.com/h1kibi/CyberMap.git
cd CyberMap
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e .
# 或只装运行依赖：pip install -r requirements.txt
cybermap --version
```

## 快速开始

```bash
# 1) 初始化（密钥优先写入系统钥匙串；可用环境变量替代）
cybermap init

# 2) FOFA 检索（官方服务地址 https://fofa.info）
export FOFA_API_KEY='你的 FOFA Key'
export FOFA_EMAIL='你的 FOFA 邮箱'
cybermap -q 'app="nginx" && country="CN"' -f host,ip,port,title -p 2

# 3) 其它引擎
cybermap -e shodan    -q 'product:nginx country:CN' -p 2
cybermap -e hunter    -q 'web.title="登录" && country="中国"'
cybermap -e daydaymap -q 'cert="example.com" && country="中国"' -f ip,port,title,ssl_cn
cybermap -e censys    -hq 1.1.1.1          # Free 套餐：仅按 IP 查询主机画像

# 4) 主机画像 / 统计
cybermap -hq 8.8.8.8
cybermap -cq 'app="redis"' -f country,port --size 10

# 5) AI 侦察（多引擎合并）
cybermap -e all -ai '收集某高校的对外资产'

# 6) MCP / 集成
cybermap-mcp                              # stdio
cybermap-mcp --transport streamable-http --host 127.0.0.1 --port 8001
cybermap integrate --agent cursor         # 安装 MCP/Skill 到本机宿主
```

> `fofa.base_url` 默认是官方 **`https://fofa.info`**。如有自建代理或镜像，可在**本地** `config/settings.yaml` 中覆盖（该文件已被 Git 忽略，不会被提交）；本项目不内置任何镜像地址。

## 引擎与语法

| 引擎 | `-e` | 语法示例 | 计费与边界 |
|---|---|---|---|
| FOFA | `fofa` | `app="nginx" && country="CN"` | 按 F 点/额度；Host、统计接口取决于会员等级 |
| Shodan | `shodan` | `product:nginx country:CN` | 含过滤器的查询、首页之后的翻页各 1 query credit |
| Hunter | `hunter` | `web.title="登录" && country="中国"` | 按返回条数扣积分；无聚合接口 |
| DayDayMap | `daydaymap` | `title="登录" && country="中国"` | 开放 API 不返回本次积分消耗，无余额/统计/图标接口 |
| Censys | `censys` | `ip="1.2.3.4"`（实体查询） | Free 套餐仅主机画像 1 credit/次，无 search/aggregate |

引擎密钥读取顺序一致：环境变量 → 系统钥匙串 → 已明确确认的本地 YAML。

| 引擎 | 环境变量 | 钥匙串服务 / 用户名 |
|---|---|---|
| FOFA | `FOFA_API_KEY`（可选 `FOFA_EMAIL`） | `cybermap` / 邮箱（无邮箱时 `default`） |
| Shodan | `SHODAN_API_KEY` | `cybermap-shodan` / `SHODAN_API_KEY` |
| Hunter | `HUNTER_API_KEY` | `cybermap-hunter` / `HUNTER_API_KEY` |
| DayDayMap | `DAYDAYMAP_API_KEY` | `cybermap-daydaymap` / `DAYDAYMAP_API_KEY` |
| Censys | `CENSYS_API_TOKEN` | `cybermap-censys` / `CENSYS_API_TOKEN` |

## 分页缓存与额度保护

每个引擎都按请求计费，中断（Ctrl-C、崩溃、宿主被杀、Agent 超时）以前会丢掉已付费的页。CyberMap 在**每页到达时立即写入 SQLite**，重跑同一请求直接复用：

```bash
cybermap -e shodan -q 'product:nginx country:CN' -p 3
cybermap -e shodan -q 'product:nginx country:CN' -p 3              # 命中缓存，页面下方提示“缓存命中 N 页”
cybermap -e shodan -q 'product:nginx country:CN' -p 3 --no-cache   # 强制重新请求
cybermap -e shodan -q 'product:nginx country:CN' -p 3 --cache-clear
```

```yaml
cache:
  enabled: true          # 也可用 --no-cache 或 CYBERMAP_DISABLE_CACHE=true
  ttl_hours: 24
  max_entries: 5000
  path: ""               # 留空 = 当前目录 cybermap-cache.sqlite3；也可用 CYBERMAP_CACHE_PATH
```

缓存只存引擎响应（不含密钥）；命中页返回 `consumed=0` 与 `metadata.cached=true`，并保留原始抓取时间。

## MCP / REST / Agent

- **MCP server**：`cybermap_mcp`；工具按引擎分组（`fofa_search`、`shodan_search`、`hunter_search`、`daydaymap_search`、`censys_search`、各引擎的 `*_host_profile` / `*_account` / `*_validate_query`、`fofa_stats` / `shodan_stats`、`fofa_export`、`fofa_agent_run`、`nuclei_plan` / `nuclei_execute`）；资源 `cybermap://fields`、`cybermap://rules`、`cybermap://account`、各引擎账号与 `cybermap://jobs/{id}`。
- **REST**：`cybermap-api`，如 `POST /v1/search`、`POST /v1/shodan/search`、`GET /v1/daydaymap/hosts/{host}`、`POST /v1/agent/runs`、`POST /v1/exports`。非回环绑定需要 `CYBERMAP_SERVICE_TOKEN`。
- **Agent**：`-ai` 或 `fofa_agent_run`；`engine="all"` 让 FOFA/Shodan/Hunter/DayDayMap 各自规划并合并（Censys 免费套餐无列表检索，不参与合并）。
- 宿主接入详见 [docs/AGENT_INTEGRATIONS.md](docs/AGENT_INTEGRATIONS.md)。

## Nuclei 扫描审批

只读检索默认；主动扫描需要 `CYBERMAP_ENABLE_SCANNING=true`，且每次执行都展示目标、模板 ID 与严重级别并请求一次性令牌。`-batch` 不会绕过审批。

## 配置与安全

- 模板：`config/settings.example.yaml` → 复制为 `config/settings.yaml`（已 Git 忽略）。
- 环境变量前缀：`CYBERMAP_*`（服务令牌、绑定地址/端口、数据库 URL、JWT、MCP 资源、缓存、扫描开关等），完整清单见 [.env.example](.env.example)。
- 密钥不写入日志：请求 URL 中的密钥、响应回显、上游错误页都会被脱敏；`httpx` 日志固定为 WARNING。
- 仅供**获得授权**的资产排查使用。详见 [SECURITY.md](SECURITY.md)。

## 目录结构

```text
cybermap.py          # CLI 入口（click）
mcp_server.py        # MCP server 入口
service/             # FastAPI 服务（检索/导出/Agent/扫描审批）
core/                # 引擎客户端（client/shodan/hunter/daydaymap/censys）、Agent、缓存、导出、扫描
config/              # 配置加载（环境变量 / 钥匙串 / YAML）
providers/           # 模型提供商适配（OpenAI/DeepSeek/Anthropic/Ollama/LM Studio）
utils/               # 终端渲染、哈希、存活检测、日志
agent-kit/           # Skill 与跨宿主插件清单
tests/               # pytest（含可选的 live smoke）
```

## 更多文档

- 更名与迁移对照：[MIGRATION.md](MIGRATION.md)
- 宿主接入：[docs/AGENT_INTEGRATIONS.md](docs/AGENT_INTEGRATIONS.md)
- 安全策略：[SECURITY.md](SECURITY.md)
- FOFA 查询语法与字段细节：参考 [FofaMap 上游文档](https://github.com/asaotomo/FofaMap)

## 许可证与致谢

- Apache-2.0，见 [LICENSE](LICENSE)。
- 基于 [FofaMap](https://github.com/asaotomo/FofaMap) 2.0.1（Hx0 Team）二开，保留其版权与许可证声明。
- 数据来自 FOFA、Shodan、奇安信鹰图 Hunter、DayDayMap、Censys 各平台，请遵守对应服务条款与配额规则。
