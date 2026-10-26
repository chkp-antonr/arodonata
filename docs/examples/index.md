# Arodonata v2 Examples

Progressive runnable scripts demonstrating `ArodonataClient` usage from basic cache-backed queries to advanced multi-user session overlays, declarative Policy-as-Code (`CPCRUD`), auditable change reports, OpenTelemetry tracing, and embedded MCP servers.

## Catalog Overview

| Script | Doc Page | Topic | Mutates Lab? |
| --- | --- | --- | --- |
| `01_basic_queries.py` | [01 — Basic Queries](01-basic-queries.md) | Discovers domains (`get_domains`) and queries cached hosts, networks, and services (`get_hosts`, `get_networks`, `get_services`) | No |
| `02_search_and_query.py` | [02 — Search & Structured Query](02-search-and-query.md) | Multi-term object search with recursive group memberships (`search_objects`), progressive disclosure (`describe_objects`), structured cross-domain aggregation (`query_objects`), and cache freshness (`get_cache_status`) | No |
| `03_gateway_relationships.py` | [03 — Gateway & VSX Topology](03-gateway-relationships.md) | Gateway, cluster, and VSX asset topology (`get_gateways`) linking cluster members and virtual systems via `parent_uid` and `member_uids` | No |
| `04_smart_refresh.py` | [04 — Smart & Streaming Refresh](04-smart-refresh.md) | Paired streaming (`stream_refresh_*`) and batch (`refresh_*`) cache synchronization across assets, objects, services, and rulebases — **run this first to warm a persistent DB** | No |
| `05_rulebase_queries.py` | [05 — Rulebase Queries](05-rulebase-queries.md) | Policy package discovery (`get_policy_packages`), hierarchical SmartConsole numbering (`get_package_rulebase`), reverse UID lookup (`locate_rules`), and local rule filtering (`filter_rulebase`) | No |
| `06_session_basics.py` | [06 — Session Lifecycle Basics](06-session-basics.md) | Low-level session lifecycle: capture baseline (`show-last-published-session`), `create_dedicated_session`, `add-host`, `publish`, and `revert-to-revision` | Yes (auto-reverted via `_session_guard.py`) |
| `07_context_and_overlay.py` | [07 — Contexts & Session Overlay](07-context-and-overlay.md) | Dynamic `auth_context`, `user_context`, and `write_session` with `SessionOverlay` read-your-own-writes isolation (discards on exit without publishing) | No (discards uncommitted session) |
| `08_cpcrud_operations.py` | [08 — CPCRUD Operations](08-cpcrud-operations.md) | Declarative Policy-as-Code (`client.cpcrud.validate`, `plan`, `apply`) applying `crud_example.yaml` twice to prove idempotency — see [CPCRUD User Guide](../user-guide/cpcrud.md) | Yes (auto-reverted via `_session_guard.py`) |
| `09_cpcrud_inverse.py` | [09 — CPCRUD Inverse Rollback](09-cpcrud-inverse.md) | Compensating rollback workflow: `plan` -> `apply` -> `inverse(plan, report)` -> `plan` -> `apply` | Yes (auto-reverted via `_session_guard.py`) |
| `10_change_report_evidence.py` | [10 — Change Report Evidence](10-change-report-evidence.md) | Auditable `ChangeReport` evidence: live unpublished numbering via `OwnedSession` vs published cached numbering rendered to HTML, Markdown, and JSON | Yes (auto-reverted via `_session_guard.py`) |
| `11_otel_tracing.py` | [11 — OpenTelemetry Tracing](11-otel-tracing.md) | Provider-agnostic OpenTelemetry instrumentation (`arlogi.otel.setup_tracing`) with a per-span timing breakdown from exported JSONL traces | No |
| `12_mcp_embedded.py` | [12 — Embedded FastAPI MCP](12-mcp-embedded.md) | Embedding Arodonata's MCP server (`create_mcp_server`, `create_asgi_app`) inside a FastAPI application with custom tools | No |
| `_session_guard.py` | — | Crash-safe baseline snapshot/restore context manager (`guarded_session`) and standalone CLI tool for manual testing | Helper / CLI |

## Setup & Execution

```bash
# 1. Install dependencies (including dev/example dependencies)
uv sync --all-extras

# 2. Configure environment files (.env.lib / .env.test / .env.secrets)
cp .env.example .env.lib

# 3. Warm the cache first (when using a persistent SQLite or PostgreSQL DATABASE_URL)
uv run examples/04_smart_refresh.py

# 4. Run read-only query, search, topology, rulebase, and overlay examples
uv run examples/01_basic_queries.py
uv run examples/02_search_and_query.py
uv run examples/03_gateway_relationships.py
uv run examples/05_rulebase_queries.py
uv run examples/07_context_and_overlay.py
uv run examples/11_otel_tracing.py

# 5. Run mutating lab examples (automatically snapshot and revert Domain4/Domain5 baseline)
ARODONATA_LAB=home uv run examples/06_session_basics.py
ARODONATA_LAB=home uv run examples/08_cpcrud_operations.py
ARODONATA_LAB=home uv run examples/09_cpcrud_inverse.py
ARODONATA_LAB=home uv run examples/10_change_report_evidence.py

# 6. Run the embedded FastAPI + MCP server on http://127.0.0.1:8000/mcp
uv run examples/12_mcp_embedded.py
```

## Crash-Safe Manual Testing with `_session_guard.py`

When experimenting manually in SmartConsole or with ad-hoc scripts against a lab domain:

```bash
# 1st invocation: snapshots and saves the current last-published session to examples/_tmp/session_guard_state.json
ARODONATA_LAB=home uv run examples/_session_guard.py 192.168.5.140 Domain4

# ... perform manual changes/publishes in Domain4 ...

# 2nd invocation: discards open sessions, reverts Domain4 to the saved baseline, and removes the state file
ARODONATA_LAB=home uv run examples/_session_guard.py 192.168.5.140 Domain4
```
