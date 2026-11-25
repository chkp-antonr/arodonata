# Arodonata v2 — Concepts, Architecture & User Guide

This document is the consolidated narrative guide to **Arodonata v2 (`2.6.7`)**: hexagonal architecture, the 17 `arodonata_*` SQLModel cache tables, incremental sync, isolated write sessions with `SessionOverlay`, the declarative `CPCRUD` engine, auditable change reports, mock/replay testing, Check Point API & operational quirks, and the consolidated Model Context Protocol (MCP) server.


---

## Overview & Quickstart

*(source: `docs/index.md`)*

# Arodonata v2

**Arodonata v2 (`2.0.0`)** is an async-first Python 3.13+ library, declarative Policy-as-Code (`CPCRUD`) engine, auditable change report generator, and Streamable-HTTP Model Context Protocol (MCP) server for Check Point Security Management and Multi-Domain Security Management (MDSM).

> **Looking for Arodonata v1 (`1.16.0`)?**
> Legacy v1 remains frozen in this repository on branch [`master_v1`](https://github.com/chkp-antonr/arodonata/tree/master_v1) and tag [`v1.16.0`](https://github.com/chkp-antonr/arodonata/releases/tag/v1.16.0). All new projects and downstream integrations should target **Arodonata v2**.

## Quickstart

```python
import asyncio
from arodonata import ArodonataClient


async def main() -> None:
    # Reads ARODONATA_* / MGMT_* environment variables and initializes SQLite/PostgreSQL cache
    async with ArodonataClient() as client:
        domains = await client.get_domains()
        print(f"Discovered {len(domains)} domains: {[d.name for d in domains]}")

        # Smart cache-first read across hosts in Domain4
        hosts = await client.get_hosts(domain="Domain4", cache_mode="smart")
        print(f"Domain4 has {len(hosts)} cached hosts")

        # Multi-term search with recursive parent group resolution
        search = await client.search_objects("10.1.10.50, *.internal.corp", max_depth=2)
        for obj in search.objects:
            print(f"Matched {obj.type} {obj.name} ({obj.uid}) in {obj.domain_name}")


asyncio.run(main())
```

## Core Capability Matrix

| Capability | Primary Entry Point | Description |
| --- | --- | --- |
| **Unified Async Facade** | `ArodonataClient` | Single composition root wiring transport, SQL cache, distributed locks, rulebase numbering, CPCRUD, and change reports |
| **Database-Backed Cache** | `DatabaseManager`, `SqlCacheAdapter` | 17 `arodonata_*`-prefixed SQLModel tables on PostgreSQL (`asyncpg`) or SQLite (`aiosqlite`) with SHA-256 auto-migration and cross-process locks |
| **Smart & Incremental Sync** | `refresh_objects`, `stream_refresh_*` | Four cache modes (`cache`, `smart`, `smart-fast`, `force`) with `show-changes` incremental diffs and parallel per-MDS-member execution |
| **Search & Aggregation** | `search_objects`, `query_objects` | IP/CIDR/range/wildcard/exact search with recursive group membership traversal and SQL-free cross-domain aggregation (`list`, `count`, `describe`) |
| **Rulebase Introspection** | `get_package_rulebase`, `filter_rulebase` | Normalized 6-table rulebase cache with exact SmartConsole hierarchical numbering (`1`, `2.1`, `3`), reverse UID lookup (`locate_rules`), and local filtering |
| **Session Isolation & Overlay** | `client.write_session(...)` | Shared read-only `arodonata_sid_cache` sessions vs isolated `WriteSession` with `contextvars`-scoped `SessionOverlay` (read-your-own-writes before publish) |
| **Declarative CPCRUD** | `client.cpcrud` (`CPCRUDService`) | Offline JSON Schema validation, `HybridStateReader`, two-axis conflict policies (`on_name_conflict` × `on_ip_conflict`), staleness guard (`DomainStamp`), and rollback (`inverse`) |
| **Auditable Change Reports** | `build_change_report` | Collects object and rule diffs across sessions or date ranges (`SessionScope`, `RangeScope`) and renders self-contained HTML, Markdown, and JSON |
| **Consolidated MCP Server** | `arodonata-mcp`, `create_mcp_server` | Streamable-HTTP MCP server exposing 13 cache-aligned core tools + 5 tamper-proof HMAC-signed CPCRUD tools for AI agents and FastAPI host apps |
| **Observability & Security** | `@traced`, `redact_sid`, `TrustPolicy` | Provider-agnostic OpenTelemetry spans (`arlogi[otel]`), TOFU/pinned TLS fingerprint verification, and automatic `sid`/secret redaction everywhere |

## Documentation Map

- **Getting Started**: [Installation & Overview](getting-started/index.md), [Your First Script](getting-started/first-script.md), and [CPCRUD Quickstart](getting-started/cpcrud.md).
- **Downstream Integration Contract**: [Capabilities & Integration Guide (`CAPABILITIES.md`)](CAPABILITIES.md) — mandatory reading for host applications (e.g., FPCR v2).
- **Architecture Deep Dives**:
  - [Architecture Overview](architecture/index.md) & [Hexagonal Ports & Adapters](architecture/ports-and-adapters.md)
  - [Database Schema Reference (17 `arodonata_*` Tables)](architecture/database-schema.md)
  - [Caching, Incremental Sync & Search](architecture/caching-and-sync.md)
  - [Sessions, MDSM & `SessionOverlay`](architecture/sessions-and-mdm.md)
  - [CPCRUD Engine Internals](architecture/cpcrud.md)
- **User Guides & MCP**:
  - [Declarative CPCRUD Operations](user-guide/cpcrud.md)
  - [Auditable Change Reports](user-guide/change-report.md)
  - [Enterprise Replay Mock Server](guides/enterprise-replay-mock-server.md)
  - [Mock Testing Scenarios & Rule Creation Guide](guides/mock-testing-scenarios.md)
  - [Model Context Protocol (MCP) Server & Consolidated Tool Surface](mcp/index.md)
- **Configuration**: [Environment Variables & Settings](configuration/index.md), [Multi-Server Topology](configuration/multi-server.md), and [TLS Verification (`pinned` / `tofu` / `lab-memory`)](configuration/tls-verification.md).
- **Examples (`01`..`12`)**: [Runnable Examples Catalog](examples/index.md).
- **Development**: [Testing & Quality Gates (`./pytest.sh`)](development/testing.md) and [Changelog](CHANGELOG.md).


---

## Getting Started — Installation & Setup

*(source: `docs/getting-started/index.md`)*

# Getting Started

Arodonata v2 requires **Python 3.13+** and uses asynchronous I/O (`asyncio`, `aiohttp`, `SQLAlchemy 2.0+` async engine) across all operations.

## Installation

Install `arodonata` using `uv` (recommended) or `pip`:

```bash
# Core SDK (includes SQLite cache via aiosqlite, CPCRUD, rulebase, and change reports)
uv add arodonata

# Recommended: install with all optional extras (PostgreSQL asyncpg, MCP server, OpenTelemetry)
uv add "arodonata[all]"
```

### Optional Extras

You can install individual extras depending on your deployment environment:

| Extra | Command | Installed Packages | Purpose |
| --- | --- | --- | --- |
| `postgres` | `uv add "arodonata[postgres]"` | `asyncpg>=0.30.0` | PostgreSQL database cache & distributed locks |
| `mcp` | `uv add "arodonata[mcp]"` | `mcp>=1.2.0`, `starlette`, `uvicorn` | Standalone `arodonata-mcp` CLI and embeddable ASGI MCP server |
| `otel` | `uv add "arodonata[otel]"` | `arlogi[otel]>=0.1.0` | OpenTelemetry span export and structured trace correlation |
| `all` | `uv add "arodonata[all]"` | All of the above | Full production feature set |

## Minimal Environment Configuration

Arodonata never loads `.env` files implicitly on import; your application (or CLI) loads environment variables explicitly (for example via `python-dotenv` or container orchestration) or passes typed arguments to `ArodonataSettings`.

Create a `.env` file for a single management server or MDSM server:

```ini
# Management server topology
ARODONATA_MGMT_NAMES=mdsm-prod
ARODONATA_MGMT_SERVERS=192.0.2.10:443
ARODONATA_API_KEYS=your-checkpoint-api-key

# Persistent cache (SQLite file or PostgreSQL URL)
ARODONATA_DATABASE_URL=sqlite+aiosqlite:///./arodonata_cache.db
# Or PostgreSQL:
# ARODONATA_DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/arodonata

# TLS certificate verification mode: pinned | tofu | lab-memory
ARODONATA_TLS_TRUST=tofu
```

## Next Steps

1. **[Your First Script](first-script.md)** — Initialize `ArodonataClient`, query cached domains/objects/gateways, and use `WriteSession` with `SessionOverlay`.
2. **[CPCRUD Quickstart](cpcrud.md)** — Validate, plan, apply, and roll back declarative YAML/JSON policy templates.
3. **[MCP Server Guide](../mcp/index.md)** — Run `arodonata-mcp` or mount the consolidated MCP tool surface inside FastAPI.


---

## Getting Started — Your First Script

*(source: `docs/getting-started/first-script.md`)*

# Your First Script

Every interaction in Arodonata v2 goes through [`ArodonataClient`](../architecture/ports-and-adapters.md). It manages the database schema, connection pools, session lifecycle, rate limiting, and domain cache synchronization.

## 1. Read-Only Queries & Smart Caching

When you enter `async with ArodonataClient() as client:`, Arodonata automatically:

1. Verifies and migrates the 17 `arodonata_*` tables in your SQLite or PostgreSQL database (`DatabaseManager.initialize()`).
2. Schedules non-blocking cleanup of any orphaned idle Arodonata read sessions (`changes == 0` and `locks == 0`).
3. Disposes owned connections cleanly on exit (preserving persistent `arodonata_sid_cache` rows across CLI runs when using a file-backed SQLite or PostgreSQL database).

```python
import asyncio
from dotenv import load_dotenv
from arodonata import ArodonataClient


async def main() -> None:
    load_dotenv(".env")

    async with ArodonataClient() as client:
        # 1. Discover domains on all configured management servers
        domains = await client.get_domains(include_global=True)
        for dom in domains:
            print(f"{dom.mgmt_name} / {dom.name} (active IP: {dom.active_ip}, global: {dom.is_global})")

        # 2. Fetch hosts, networks, and services using smart cache synchronization
        hosts = await client.get_hosts(domain="Domain4", cache_mode="smart")
        networks = await client.get_networks(domain="Domain4", cache_mode="smart")
        services = await client.get_services(domain="Domain4", types=["tcp", "udp"], cache_mode="smart")

        print(f"Loaded {len(hosts)} hosts, {len(networks)} networks, {len(services)} services")

        # 3. Inspect gateways, clusters, and VSX topology (with human-readable asset_id & parent_asset_id)
        gateways = await client.get_gateways(domain="Domain4", cache_mode="smart")
        for gw in gateways:
            print(
                f"Asset: {gw.asset_id} ({gw.type}) IP={gw.ipv4_address} "
                f"parent={gw.parent_asset_id} members={gw.member_asset_ids}"
            )


if __name__ == "__main__":
    asyncio.run(main())
```

## 2. Understanding `cache_mode`

All read and refresh methods accept a `CacheMode`:

- `"cache"`: Read strictly from the local SQL database (`0` network calls).
- `"smart"` (default): Probes `show-last-published-session` when the domain TTL (`cache_ttl`, default `300s`) expires; reloads from the API only if a newer publish occurred.
- `"smart-fast"`: Like `"smart"`, but fetches only incremental deltas via `show-changes` (preferring `from-session` over UTC `from-date`), falling back to a full type reload if changes exceed `max_incremental_changes` (`500`).
- `"force"`: Unconditionally reloads the requested scope from the Check Point API and atomically updates the SQL cache.

## 3. Isolated Writes & Read-Your-Own-Writes (`SessionOverlay`)

Never mutate objects on the shared read-only session. Instead, open an isolated `client.write_session(mgmt_name, domain)` or call high-level mutation helpers (`add_object`, `set_object`, `delete_object`):

```python
async with ArodonataClient() as client:
    mgmt = client.settings.mgmt_names[0]

    # Opens a dedicated Check Point session outside arodonata_sid_cache
    async with client.write_session(mgmt, "Domain4", publish_on_exit=False) as ws:
        await client.add_object(
            mgmt,
            "host",
            {"name": "h-temp-app", "ipv4-address": "198.51.100.42"},
            domain="Domain4",
        )

        # SessionOverlay automatically merges uncommitted creates/updates/deletes into cache reads!
        found = await client.find_object(mgmt, "Domain4", "h-temp-app")
        assert found is not None and found.ipv4_address == "198.51.100.42"

        # Explicitly discard so nothing is published to Domain4
        await client.api_call(mgmt, "discard", {}, domain="Domain4", sid=ws.sid, server_ip=ws.server_ip)
        ws.discarded = True
```


---

## Getting Started — CPCRUD Quickstart

*(source: `docs/getting-started/cpcrud.md`)*

# CPCRUD Quickstart

`client.cpcrud` (`CPCRUDService`) is Arodonata's declarative Policy-as-Code engine. It takes a YAML or JSON template describing desired objects, services, groups, sections, and rules, computes an idempotent execution plan against cached + live state, applies changes in an isolated session per domain, and can generate a compensating rollback template (`inverse`).

## 1. Define a Declarative Template

```yaml
version: 1
mgmt_name: "mdsm-prod"
domain: "Domain4"
on_name_conflict: "update"
on_ip_conflict: "reuse"

objects:
  - type: "host"
    name: "web-srv-01"
    ipv4-address: "198.51.100.10"
    comments: "Managed by Arodonata CPCRUD"
    color: "dark green"

services:
  - type: "service-tcp"
    name: "tcp-8443"
    port: "8443"

groups:
  - type: "group"
    name: "grp-web-servers"
    members:
      - "web-srv-01"

rules:
  - type: "access-rule"
    layer: "Standard Network"
    position: "bottom"
    name: "allow-web-8443"
    source: ["Any"]
    destination: ["grp-web-servers"]
    service: ["tcp-8443"]
    rule_action: "Accept"
    track: "Log"
```

## 2. Validate, Plan, Apply, and Roll Back

```python
import asyncio
from pathlib import Path
from arodonata import ArodonataClient


async def main() -> None:
    template_text = Path("examples/crud_example.yaml").read_text(encoding="utf-8")

    async with ArodonataClient() as client:
        # Step 1: Offline JSON Schema validation (zero network or DB calls)
        errors = client.cpcrud.validate(template_text)
        if errors:
            raise ValueError(f"Invalid template: {errors}")

        # Step 2: Plan (captures DomainStamp and resolves diffs via HybridStateReader)
        plan = await client.cpcrud.plan(template_text)
        for action in plan.actions:
            print(f"[{action.outcome}] {action.object_type} {action.name} -> {action.command}")

        # Step 3: Apply (verifies DomainStamp hasn't drifted, executes in isolated WriteSession, publishes)
        report = await client.cpcrud.apply(plan)
        print(f"Applied: success={report.success}, published={report.published}")

        # Step 4: Generate a compensating rollback template from (plan, report)
        rollback_template = client.cpcrud.inverse(plan, report)
        rollback_plan = await client.cpcrud.plan(rollback_template)
        rollback_report = await client.cpcrud.apply(rollback_plan)
        print(f"Rolled back: success={rollback_report.success}")


if __name__ == "__main__":
    asyncio.run(main())
```

## 3. Staged Sessions (Human-in-the-Loop Approval)

When integrating into approval workflows (or MCP agent workflows), pass `no_publish=True, keep_session=True` to `apply()`. This leaves the Check Point session open and returns `StagedSessionInfo` (`session_uid`) in `report.staged_sessions`.

Later, once approved or rejected, finalize the session by its `session_uid`:

```python
# Approve and publish (adopts via take-over-session, publishes, logs out, and invalidates domain cache)
await client.publish_staged_session("mdsm-prod", "Domain4", session_uid=staged.session_uid)

# Or reject and discard cleanly
await client.discard_staged_session("mdsm-prod", "Domain4", session_uid=staged.session_uid)
```


---

## Capabilities & Downstream Integration Guide

*(source: `docs/CAPABILITIES.md`)*

# Arodonata v2: Capabilities & Downstream Integration Guide

**Version:** 2.0.0 · **Status:** Canonical Architecture Specification · **Date:** October 2026

## 1. Executive Summary & Architectural Role

**Arodonata v2** is an async-first Python 3.13+ platform library, hexagonal SDK, Policy-as-Code (`CPCRUD`) engine, auditable change report generator, and Streamable-HTTP MCP server for Check Point Security Management and Multi-Domain Security Management (MDSM).

In the enterprise automation ecosystem (such as **FPCR v2**, web portals, CLIs, and AI agent platforms), **Arodonata acts as the single authoritative engine for all Check Point interactions**:

- Native `aiohttp` transport, post-handshake SHA-256 certificate verification (`pinned`, `tofu`, `lab-memory`), per-MDS-member rate limiting, and `70s` login throttle recovery (`LoginGate`).
- Database-backed caching across **17 `arodonata_*`-prefixed SQLModel tables** (PostgreSQL `asyncpg` and SQLite `aiosqlite`) with SHA-256 schema hash auto-migration, naive UTC timestamp uniformity (`tzinfo=None`), and distributed locks (`arodonata_distributed_locks`).
- Incremental (`show-changes`) and full synchronization across domains, objects, services, assets (gateways/clusters/VSX), and rulebases with typed streaming progress events (`SyncProgressEvent`).
- Isolated write sessions (`WriteSession`) with `contextvars`-bound `SessionOverlay` for read-your-own-writes isolation prior to `publish`.
- Declarative Policy-as-Code (`CPCRUDService`): offline JSON Schema validation, `HybridStateReader`, two-axis conflict policies (`NameConflictPolicy` × `IpConflictPolicy`), pre-publish staleness verification (`DomainStamp`), staged session handoff (`take-over-session`), compensating rollback generation (`inverse`), and full lifecycle support for network objects, services, `application-site` custom URL/regex objects, groups, and rules.
- Normalized 6-table rulebase cache with exact SmartConsole hierarchical rule numbering (`1`, `2.1`, `3`), reverse UID lookup (`locate_rules`), and local rulebase filtering (`filter_rulebase`, including `output_format="cpcrud"`).
- Auditable change evidence collection and offline multi-format rendering (`HTML`, `Markdown`, `JSON`).
- Consolidated Model Context Protocol (`arodonata.mcp`) server with 13 cache-aligned core tools and 5 tamper-proof HMAC-signed CPCRUD tools.

### Core Architectural Principle for Downstream Consumers

> **"Delegate, Never Duplicate"**
> Downstream applications MUST NOT implement custom Check Point HTTP callers, bespoke SQL cache tables for Check Point objects/rules, manual `sid` session pools, custom rulebase numbering parsers, or ad-hoc object naming algorithms. Consumer applications act strictly as business workflow orchestrators, state machines, user interfaces, and authorization/audit coordinators.

---

## 2. Capability Catalog & Consumer Contracts

| Capability Area | Canonical Arodonata v2 Module | Primary Classes / Functions | Configuration Source |
| --- | --- | --- | --- |
| **Unified Facade** | `arodonata` / `arodonata.client` | `ArodonataClient`, `ArodonataSettings` | `ARODONATA_*` / `MGMT_*` env vars |
| **Storage & Locks** | `arodonata.adapters.storage` | `DatabaseManager`, `SqlCacheAdapter`, `SqlLockAdapter`, `ARODONATA_TABLE_NAMES` | `ARODONATA_DATABASE_URL` |
| **Transport & Sessions** | `arodonata.adapters.checkpoint` | `AMgmtClient`, `TrustPolicy`, `RateLimiter`, `LoginGate`, `TaskWaiter` | `ARODONATA_TLS_TRUST`, `ARODONATA_CONCURRENT_LIMIT` |
| **Contexts & Overlays** | `arodonata.core.context` | `WriteSession`, `SessionOverlay`, `AuthContext`, `UserContext` | Python `contextvars` |
| **Sync, Search & Query** | `arodonata.core.services` | `DomainSyncCoordinator`, `ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `SearchService` | `CacheMode` (`cache`, `smart`, `smart-fast`, `force`) |
| **Rulebase & Numbering** | `arodonata.rulebase` | `CachedRulebaseSource`, `RulebaseRefreshService`, `fetch_paged_rulebase`, `rule_to_cpcrud_operation` | `RuleFormat` (`markdown`, `model_friendly`, `raw`, `cpcrud`) |
| **Declarative CPCRUD** | `arodonata.cpcrud` | `CPCRUDService`, `Plan`, `ApplyReport`, `NamingPrefixes`, `StagedSessionInfo` | `checkpoint_ops_schema.json` |
| **Evidence & Reports** | `arodonata.reports` | `collect_change_report`, `render_change_report`, `build_change_report` | `SessionScope`, `RangeScope`, `RenderOptions` |
| **MCP Integration** | `arodonata.mcp` | `create_mcp_server`, `create_asgi_app`, `ArodonataMCPSettings` | `ARODONATA_MCP_*` env vars |

---

## 3. Deep-Dive: Host Application Integration Patterns

### 3.1 Shared `AsyncEngine` & Namespace Coexistence

Host applications (such as FastAPI backends using SQLAlchemy/SQLModel) can pass their existing `AsyncEngine` directly to `ArodonataClient(engine=host_engine)`.

- **Non-Destructive Ownership (`owns_engine=False`)**: When an external `AsyncEngine` is passed, `await client.close()` closes Arodonata's HTTP transport and background tasks **without** disposing the host application's `AsyncEngine`.
- **Strict Table Namespace Isolation (`arodonata_*`)**: All 17 Arodonata tables are prefixed with `arodonata_` (`ARODONATA_TABLE_NAMES`). `DatabaseManager.initialize()` inspects and migrates only `arodonata_*` tables, completely ignoring any host application tables registered in `SQLModel.metadata` (even if the host app has tables named `assets`, `domains`, or `distributed_locks`).
- **Naive UTC Timestamp Uniformity**: All Arodonata models and database columns use naive UTC (`DateTime(timezone=False)`, `tzinfo=None` via `to_naive_utc()` and `utc_now()`), eliminating `asyncpg` offset-naive vs offset-aware `DataError` crashes on PostgreSQL.

```python
from sqlalchemy.ext.asyncio import create_async_engine
from arodonata import ArodonataClient, ArodonataSettings

engine = create_async_engine("postgresql+asyncpg://app:secret@db:5432/fpcr")
settings = ArodonataSettings()

client = ArodonataClient(settings, engine=engine)
await client.initialize()
# ... serve requests ...
await client.close()  # Leaves `engine` open for the host application
```

### 3.2 Streaming Synchronization to Web UIs (SSE)

Every batch refresh method (`refresh_objects`, `refresh_services`, `refresh_assets`, `refresh_rulebases`) and CPCRUD execution (`cpcrud.apply`) has a paired async generator (`stream_refresh_*`, `cpcrud.stream_apply`, `stream_publish_staged_session`) yielding typed domain events (`SyncProgressEvent`, `CPCRUDEvent`).

To stream progress over HTTP Server-Sent Events (SSE), convert domain events at the HTTP boundary using `arodonata.adapters.sse.to_sse_event`:

```python
from arodonata.adapters.sse import to_sse_event

async for event in client.stream_refresh_objects(domains=["Domain4"], mode="smart-fast"):
    sse = to_sse_event(event)
    yield sse.encode()  # "event: ...\ndata: {...}\n\n"
```

### 3.3 Exact Search, Human-Readable Composite IDs, Cross-Domain Structured Queries, and Rule-to-CPCRUD Export

1. **Human-Readable Composite Identifiers (`object_id`, `service_id`, `asset_id`) & Dual Topology Links**:
   - Every cached entity carries both a collision-safe UID primary key (`id = "{mgmt_name}:{domain_name}:{uid}"`) and an indexed human-readable composite identifier (`object_id`, `service_id`, or `asset_id = "{mgmt_name}:{domain_name}:{name}"`).
   - Gateway, cluster, and VSX assets (`Asset` / `arodonata_assets`) expose both UID and human-readable parent/child links (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, `virtual_system_asset_ids`), automatically resolving cross-domain VSX-to-Virtual-System relationships across domains on the same management server.
   - `find_object()`, `get_group_members()`, `search_objects()`, and `query_objects()` accept raw UIDs, object names, or composite identifiers (e.g., `"mds:Domain4:hWebHost"` or `"mds:VSX:VSX-Cluster-01"`).
2. **Exact vs Substring Search**: Pass `exact_match=True` to `await client.search_objects(".example.com", exact_match=True)` when validating whether an exact FQDN or object name exists without matching subdomains (`sub.example.com`). Each `GroupMembershipNode` in `SearchResult.memberships` includes `id`, `object_id`, `parent_uids`, and `parent_object_ids`.
3. **Cross-Domain Structured Queries (`query_objects`)**: Use `await client.query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` to build dashboard summaries or filter across domains (`scope_origin="local" | "global" | "all"`, plus `object_id`, `service_id`, `asset_id`, `parent_id`, `parent_asset_id`) without writing raw SQL against cache tables.
4. **Exporting Existing Rules to CPCRUD (`output_format="cpcrud"`)**: Use `await client.filter_rulebase(mgmt, domain, layer="Standard Network", filter_query="10.1.10.50", output_format="cpcrud")` or `rule_to_cpcrud_operation(rule)` to convert cached rules directly into schema-valid CPCRUD rule dicts for modification or migration.

### 3.4 Staged CPCRUD Sessions for Approval Workflows

When a workflow requires peer review before publishing to Check Point:

```python
# Phase 1: Stage changes in a dedicated Check Point session without publishing
plan = await client.cpcrud.plan(template)
report = await client.cpcrud.apply(plan, no_publish=True, keep_session=True)
staged_uid = report.staged_sessions[0].session_uid

# Phase 2a: Collect a rich HTML/Markdown ChangeReport from the unpublished session!
evidence = await client.build_change_report(
    [{"mgmt_name": mgmt, "domain": "Domain4", "session_uids": [staged_uid]}],
    formats=["html", "markdown"],
)

# Phase 2b: After human approval, adopt via take-over-session and publish (or discard)
await client.publish_staged_session(mgmt, "Domain4", session_uid=staged_uid)
# Or on rejection:
# await client.discard_staged_session(mgmt, "Domain4", session_uid=staged_uid)
```

### 3.5 Universal Check Point Script Repository Facade

`ArodonataClient` exposes application-agnostic Script Repository management and execution via `ScriptRepositoryService` (`client.script_service`):

- **Read-only inspection (`sid_cache`)**: `get_repository_script`, `list_repository_scripts`, and `check_repository_script(..., expected_body=...)` inspect scripts without opening write sessions or calling `publish`.
- **Idempotent provisioning (`WriteSession`)**: `ensure_repository_script` normalizes line endings (`\r\n` -> `\n`), short-circuits with `action="unchanged"` and zero publishes when the script body (and any explicitly supplied `comments`/`color`/`tags`) already matches, and otherwise creates/updates inside an isolated `WriteSession` (or reuses an active matching `WriteSession`) without polluting `SessionOverlay`.
- **Execution (`script-type="repository"`)**: `run_repository_script(mgmt_name, script_name_or_uid, targets, *, domain=None, args=None, ...)` forwards caller `args` verbatim (`str`) or space-joined (`Sequence[str]`) over a dedicated non-read-only session (without `publish` or `discard`) and Base64-decodes per-target `show-task` results into `RepositoryScriptExecutionOutcome`, mapping missing scripts or insufficient permissions to `RepositoryScriptNotFoundError` / `RepositoryScriptPermissionError`.
- **Route collection consumer**: `TopologyService.collect_gateway_routes()` consumes this layer when `cprid_script_mode` is `"repository"` or `"auto"`, defaulting to `"inline"` for backward compatibility and providing `check_route_collection_script` / `ensure_route_collection_script`.


---

## Architecture — Overview

*(source: `docs/architecture/index.md`)*

# Architecture Overview

Arodonata v2 is built on a strict **Hexagonal (Ports & Adapters)** architecture designed for high-concurrency asynchronous execution, multi-worker database safety, and zero-leak security hygiene.

## System Context & Component Diagram

```mermaid
flowchart TB
    subgraph Consumers["Downstream Consumers & AI Agents"]
        SDK["Python Applications & FPCR v2"]
        CLI["arodonata-mcp CLI / FastAPI Host"]
        LLM["LLM / MCP Clients"]
    end

    subgraph Facade["Composition Root & Facades"]
        Client["ArodonataClient"]
        MCP["arodonata.mcp Server & Tools"]
    end

    subgraph Core["Hexagonal Core (core, rulebase, cpcrud, reports, api_reference)"]
        Services["Domain, Object, Service, Asset & Search Services"]
        Coord["DomainSyncCoordinator"]
        Topology["TopologyService & ScriptRepositoryService"]
        Rulebase["CachedRulebaseSource & RulebaseRefreshService"]
        CPCRUD["CPCRUDService (Expressions, Validator, Planner, Differ, Executor, Inverse)"]
        Reports["ChangeReport Collector & Renderer"]
        ApiRef["ApiReferenceEngine (Bundled Offline Index)"]
        Ports["Protocols: ApiPort | CachePort | LockPort | AuthProvider | GatewayCliPort"]
    end

    subgraph Adapters["Infrastructure Adapters (adapters & testing)"]
        CP["AMgmtClient (ApiTransport, TrustPolicy, RateLimiter, LoginCoordinator, SessionCleaner, TaskWaiter)"]
        DB["SqlCacheAdapter & SqlLockAdapter (DatabaseManager)"]
        GWCLI["GatewayCliPort SSH Adapter / FileReplayApiMock & FileReplayCliMock"]
        SSE["SSE Boundary Adapter (SSEEvent)"]
    end

    subgraph External["External Systems"]
        MDSM["Check Point SMS / MDSM Clusters (HTTPS Web API)"]
        Gateways["Check Point Gateways / VSX (SSH / cprid run-script)"]
        SQL[("PostgreSQL (asyncpg) / SQLite (aiosqlite)\n17 arodonata_* Tables")]
    end

    SDK --> Client
    LLM --> MCP
    CLI --> MCP
    MCP --> Client
    Client --> Services
    Client --> Coord
    Client --> Topology
    Client --> Rulebase
    Client --> CPCRUD
    Client --> Reports
    Client --> ApiRef
    Services --> Ports
    Coord --> Ports
    Topology --> Ports
    Rulebase --> Ports
    CPCRUD --> Ports
    Reports --> Ports
    Ports -.-> CP
    Ports -.-> DB
    Ports -.-> GWCLI
    Client -.-> SSE
    CP --> MDSM
    CP --> Gateways
    GWCLI --> Gateways
    DB --> SQL
```

## Key Architectural Invariants

1. **Pure Core Domain (`arodonata.core`, `arodonata.rulebase`, `arodonata.cpcrud`, `arodonata.reports`, `arodonata.api_reference`)**:
   - Business logic depends exclusively on typed Python `Protocol` interfaces (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`, `GatewayCliPort`).
   - Core modules never import `aiohttp`, `asyncpg`, `aiosqlite`, or HTTP transport primitives directly.
2. **Database-First Synchronization & Multi-Worker Coordination**:
   - All cached state lives in **17 `arodonata_*` SQLModel tables** ([Database Schema Reference](database-schema.md)).
   - Schema initialization is serialized across worker processes (`pg_advisory_xact_lock` on PostgreSQL, `BEGIN IMMEDIATE` on SQLite) and tracked by SHA-256 metadata digest in `arodonata_schema_version`.
   - `arodonata_distributed_locks` coordinates cross-process critical sections with automatic background heartbeat renewal across domain syncs, domain list discovery, `LoginGate` serialization, and distributed `RateLimiter` slots.
3. **Strict Read vs Write Session Separation**:
   - Read operations share a persistent, credential-bound read-only session in `arodonata_sid_cache` (system domain keyed as `"System Data"`). Mutating commands (`add-*`, `set-*`, `delete-*`, `publish`, `discard`, `run-script`) are rejected on the shared session.
   - Write operations open an isolated `WriteSession` (`create_dedicated_session`) with an in-memory `SessionOverlay` bound via `contextvars` so callers immediately read their own uncommitted object/service writes before `publish`. CPCRUD also supports staged sessions (`no_publish=True, keep_session=True`, finalized via `publish_staged_session` / `discard_staged_session`), while `ScriptRepositoryService` executes scripts inside dedicated non-read-only sessions without `publish`/`discard`.
4. **Defense-in-Depth Security Hygiene**:
   - Session tokens (`sid`), API keys, and passwords are redacted (`"***REDACTED***"`) in all `repr()`, logs, OpenTelemetry span attributes, exception messages, and MCP tool outputs (`redact_sid(..., known_sids=...)`).
   - TLS certificates are verified post-handshake and pre-request against SHA-256 DER fingerprints (`pinned`, `tofu`, or `lab-memory`).
5. **Provider-Agnostic Observability**:
   - Functions decorated with `@traced` (`arodonata.core.telemetry`) emit OpenTelemetry spans via `opentelemetry-api` (`arlogi.otel.traced`) without ever owning or overriding the host application's global `TracerProvider`.

## Subsystems & Package Map

| Package | Responsibility |
| --- | --- |
| `arodonata.client` & `arodonata.core` | Composition root (`ArodonataClient`), typed settings/contexts, error hierarchy, five core protocols, domain/object/service/asset/search/topology/script services, and background warm-up |
| `arodonata.rulebase` | Normalized policy package, inline layer, section, SmartConsole numbering, local filtering (`RulebaseRefreshService`, `CachedRulebaseSource`), and CPCRUD export |
| `arodonata.cpcrud` | Declarative Policy-as-Code engine: shorthand expression parser, draft-07 schema validator, `HybridStateReader`, differ, cleanup-aware planner, executor (retries + staged sessions), and inverse rollback builder |
| `arodonata.reports` | Auditable `ChangeReport` collector (session/range scopes + offline `build_change_report_from_plan`), live rule placement numbering, and self-contained HTML/Markdown/JSON renderer |
| `arodonata.api_reference` | Offline bundled `cp_api_index.json.gz` engine (`ApiReferenceEngine`) supporting version-filtered command search, payload schema description, and offline validation |
| `arodonata.mcp` | Streamable-HTTP MCP server (`arodonata-mcp` CLI + `ArodonataASGIApp`), static bearer / JWT / host auth, DNS-rebinding & Origin guards, HMAC-signed CPCRUD plans, and read/topology/API tools |
| `arodonata.testing` | Enterprise replay dataset generator, stateful in-process emulator (`FileReplayApiMock`, `FileReplayCliMock`), and standalone HTTPS mock server (`CheckPointReplayHttpServer`) |


---

## Architecture — Hexagonal Ports & Adapters

*(source: `docs/architecture/ports-and-adapters.md`)*

# Hexagonal Ports & Adapters

Arodonata v2 isolates all Check Point Management API, gateway CLI execution, and SQL database details behind five core `Protocol` interfaces defined in `src/arodonata/core/ports/__init__.py`.

## Core Protocols (`arodonata.core.ports`)

### 1. `ApiPort`

Defines the asynchronous contract for communicating with Check Point Management and MDSM servers:

- `api_call(mgmt_name, command, payload=None, *, domain=None, sid=None, server_ip=None, wait_for_task=True, timeout=None) -> ApiCallResult`
- `api_query(mgmt_name, command, *, domain=None, details_level="standard", payload=None, sid=None, server_ip=None, limit=300) -> ApiQueryResult`
- `create_dedicated_session(mgmt_name, domain=None, *, auth=None, session_name=None, session_description=None) -> tuple[str, str]`
- `logout_sid(mgmt_name, sid, *, server_ip=None) -> Awaitable[bool]`
- `close(*, logout=None) -> None` (when `logout=None`, auto-logs out active sessions only if the client owns an auto-created ephemeral `:memory:` SQLite engine)

**Default Adapter**: `AMgmtClient` (`src/arodonata/adapters/checkpoint/client.py`), backed by:

- `ApiTransport` (`transport.py`): Native `aiohttp` client with `allow_redirects=False`, `trust_env=False`, post-handshake and pre-request SHA-256 certificate verification (`TrustPolicy` / `TrustStore` in `tls.py`), and phase-tagged `TransportError` (`phase="connect" | "post-send"`) / `ApiTimeoutError` (`phase="connect" | "read"`) carrying `request_sent: bool` so mutating calls are never re-sent after bytes leave the socket.
- `VerifiedConnectionPool`: Reuses verified keep-alive connections (`<= 10s` idle, `< 95` requests) for idempotent `show-*` commands under shared scope AND for non-boundary commands within scoped dedicated sessions (`s:<sha256_prefix>`), while `NON_POOLABLE_SESSION_COMMANDS` (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`) bypass pooling.
- `LoginCoordinator` & `SessionCleaner` (`sessions.py`): Credential-bound read-only session cache lookup, isolated `WriteSession` management, coalesced keepalive sweeps, and startup cleanup of orphaned Arodonata sessions.
- `RateLimiter` & `LoginGate` (`rate_limiter.py`): Enforces `concurrent_limit` per MDS member IP and a `70.0s` cooldown window on login throttling (`err_too_many_requests`).
- `paginate_objects` (`pager.py`) & `TaskWaiter` (`task_waiter.py`): Continuity-verified pagination (`limit=300`, clamped to `500`, `±10` boundary overlap recovery and single restart on `total` shift) plus exponential-backoff `show-task` polling (`2s..10s` up to `task_timeout`).

### 2. `CachePort`

Defines the contract for reading and persisting cached Check Point topology, sessions, objects, services, assets, gateway topology intervals, annotations, rulebases, and sync states:

- **Domain topology**: `get_domains()`, `get_domain()`, `upsert_domains()`
- **Shared sessions**: `get_sid()`, `upsert_sid()`, `evict_sid()`, `list_sids()`
- **Sync state**: `get_sync_state()`, `list_sync_states()`, `upsert_sync_state()`
- **Objects & Services**: `get_objects()`, `get_object_by_uid()`, `replace_domain_objects()`, `upsert_objects()`, `delete_objects_by_uids()`, `get_services()`, `get_service_by_uid()`, `replace_domain_services()`, `upsert_services()`, `delete_services_by_uids()`
- **Assets**: `get_assets()`, `replace_domain_assets()`, `upsert_assets()`
- **Gateway topology & annotations**: `get_gateway_topology()`, `replace_domain_topology()`, `upsert_gateway_topology()`, `get_topology_annotations()`, `upsert_topology_annotations()`, `delete_topology_annotations()`
- **Rulebase snapshots & slices**: `replace_domain_rulebase()`, `replace_domain_package_catalog()`, `upsert_domain_rulebase_layers()`, `get_domain_rulebase()`, `get_domain_rulebase_packages()`

*(Note: Cross-domain filtering and aggregation methods `describe_objects()` and `query_objects()` live in `SearchService` and `ArodonataClient`, built on top of `CachePort`.)*

**Default Adapter**: `SqlCacheAdapter` (`src/arodonata/adapters/storage/cache_adapter.py`), which executes atomic transactions, deduplicates primary keys before batched writes (`_BATCH_ROWS = 500`), and runs dialect-specific `ON CONFLICT DO UPDATE` upserts on PostgreSQL and SQLite.

### 3. `LockPort`

Coordinates distributed cross-process critical sections (per-domain cache refreshes, `LoginGate` serialization, and cross-worker `RateLimiter` slots):

- `acquire(lock_key, *, ttl_seconds=60.0, owner_id=None, wait_timeout=None, poll_interval=0.05) -> bool`
- `renew(lock_key, *, ttl_seconds=60.0, owner_id=None) -> bool`
- `release(lock_key, *, owner_id=None) -> bool`
- `lock(lock_key, *, ttl_seconds=60.0, owner_id=None, wait_timeout=None, poll_interval=0.05) -> AbstractAsyncContextManager[str]` (yields `owner_id`; raises `LockAcquisitionError` on contention/timeout)

**Default Adapter**: `SqlLockAdapter` (aliased as `DatabaseLockManager`, `src/arodonata/adapters/storage/lock_adapter.py`) backed by `arodonata_distributed_locks`, evaluating expiration against the database server's UTC clock.

### 4. `AuthProvider`

Optional pluggable protocol for resolving runtime credentials dynamically per `(mgmt_name, domain)` and receiving failure notifications when `auth_mode="dynamic"` is used without an explicit `auth_context`:

- `get_credentials(mgmt_name, domain=None, *, user=None) -> AuthContext`
- `on_auth_failed(mgmt_name, auth, exc) -> None`

### 5. `GatewayCliPort` (& `GatewayCliCallable`)

Optional protocol for executing shell/clish diagnostics on Check Point gateways and VSX Virtual Systems (e.g., via SSH):

- `execute_command(target: GatewayCliTarget, command: str, *, timeout: float = 30.0) -> GatewayCliResult | str`
- `GatewayCliCallable = Callable[[GatewayCliTarget, str], Awaitable[GatewayCliResult | str]]`

Injected via `ArodonataClient(..., gateway_cli=...)` or `client.set_gateway_cli(...)` for `TopologyService.collect_gateway_routes()`. When unavailable or failing, route collection falls back to Check Point `cprid` via `AMgmtClient` (`run-script` one-time or repository scripts managed by `ScriptRepositoryService`).

## Boundary, Storage & Testing Adapters

- **`DatabaseManager`** (`src/arodonata/adapters/storage/database.py`): Manages async SQLAlchemy engines (`asyncpg` / `aiosqlite`), cross-worker schema locks, and SHA-256 schema hash auto-migration restricted to `ARODONATA_TABLE_NAMES`.
- **`SSEAdapter`** (`src/arodonata/adapters/sse/__init__.py`): Converts core `DomainEvent` streams (`SyncProgressEvent`, `CPCRUDEvent`) into SID-redacted `SSEEvent` frames via `to_sse_event()` and `stream_as_sse()`.
- **Replay & Test Doubles (`arodonata.testing`)**: `FileReplayApiMock`, `FileReplayCliMock`, and `CheckPointReplayHttpServer` implement `ApiPort` and `GatewayCliPort` against realistic MDSM/VSX fixture datasets with stateful session overlays and call auditing.

## Dependency Injection in Tests & Custom Hosts

Because `ArodonataClient` accepts custom `api: ApiPort`, `cache: CachePort`, `lock_port: LockPort`, `auth_provider: AuthProvider`, and `gateway_cli: GatewayCliPort | GatewayCliCallable` instances in its constructor, unit tests and downstream applications can inject in-memory fakes or custom adapters without monkeypatching internal classes:

```python
client = ArodonataClient(
    settings,
    api=custom_api_port,
    cache=custom_cache_port,
    lock_port=custom_lock_port,
    auth_provider=custom_auth_provider,
    gateway_cli=custom_gateway_cli,
)
```


---

## Architecture — Database Schema (17 Tables)

*(source: `docs/architecture/database-schema.md`)*

# Database Schema Reference (17 `arodonata_*` Tables)

Arodonata v2 persists all cached topology, shared sessions, distributed locks, objects, services, gateway/VSX assets, gateway topology intervals, administrator topology annotations, and normalized policy rulebases across **17 SQLModel tables** defined in `src/arodonata/adapters/storage/tables.py` (`ARODONATA_TABLE_NAMES`).

Both **PostgreSQL (`postgresql+asyncpg://`)** and **SQLite (`sqlite+aiosqlite://`)** are first-class supported backends.

---

## 1. Host Application Coexistence & Auto-Migration Design

Arodonata v2 is engineered to share a single database and `SQLModel.metadata` registry safely with host applications (such as **FPCR v2**):

1. **Strict `arodonata_` Table Namespace (`ARODONATA_TABLE_NAMES`)**:
   - Every table owned by Arodonata is prefixed with `arodonata_` (all 17 tables in `ARODONATA_TABLE_NAMES`).
   - `DatabaseManager.initialize()` inspects and migrates **only** tables in `ARODONATA_TABLE_NAMES`. Any host application tables in the same database or `SQLModel.metadata` (such as a host app's own `assets`, `domains`, or `sid_cache` table) are never touched, altered, or dropped.
2. **SHA-256 Schema Hash Auto-Migration (`arodonata_schema_version`)**:
   - `DatabaseManager` computes a deterministic SHA-256 digest (`compute_schema_hash()`) over the table names, column names, SQL types, primary keys, nullability, and indexes of all 17 `arodonata_*` tables.
   - If the current `schema_hash` is already recorded in `arodonata_schema_version` and all 17 tables exist, startup skips column inspection and completes rapidly.
   - When the schema evolves, `_is_table_schema_incompatible()` checks for breaking structural drift: primary key mismatch, orphaned `NOT NULL` columns lacking defaults, legacy timezone-aware `TIMESTAMPTZ` columns, coarse column type family changes, or tightened/newly added `NOT NULL` columns without defaults. Compatible additions use savepoint-protected (`begin_nested()`) `ALTER TABLE` statements; incompatible cache tables are dropped and recreated before recording the new `schema_hash`.
3. **Cross-Worker Migration Serialization**:
   - Multi-worker Uvicorn/Gunicorn startups are serialized using `SELECT pg_advisory_xact_lock(...)` on PostgreSQL and `BEGIN IMMEDIATE` on SQLite, with a double-check of `arodonata_schema_version` after acquiring the lock.
4. **Legacy v1 Table Fingerprint Cleanup**:
   - If upgrading an existing database from Arodonata v1, `DatabaseManager` drops legacy unprefixed `domains` or `sid_cache` tables **only** if they contain positive v1 column fingerprints (`mdm_dmn` or `mgmt_dmn_key`), guaranteeing zero risk to unprefixed host tables.
5. **Naive UTC Timestamp Uniformity (`DateTime(timezone=False)`)**:
   - Every timestamp column in Arodonata uses `Column(DateTime(timezone=False))` normalized via `to_naive_utc()` (`tzinfo=None` in UTC), preventing `asyncpg` offset-naive vs offset-aware errors on PostgreSQL.
6. **UID Primary Keys (`id`) + Human-Readable Composite Identifiers (`object_id`, `service_id`, `asset_id`)**:
   - Check Point permits distinct objects in the same domain (or visible from `Global`) to share the same `name` across different object classes (e.g., built-in objects named `email`) while having distinct `uid` values, and allows existing objects to be renamed across publishes.
   - Therefore, `arodonata_objects`, `arodonata_services`, and `arodonata_assets` retain a UID-based primary key `id = "{mgmt_name}:{domain_name}:{uid}"` (preventing primary-key collisions and orphaned rows on rename during `smart-fast` incremental sync) while simultaneously exposing an indexed, non-unique human-readable composite identifier:
     - `CPObject.object_id` (`arodonata_objects.object_id`): `"{mgmt_name}:{domain_name}:{name}"`
     - `CPService.service_id` (`arodonata_services.service_id`): `"{mgmt_name}:{domain_name}:{name}"`
     - `Asset.asset_id` (`arodonata_assets.asset_id`): `"{mgmt_name}:{domain_name}:{name}"`
   - Rich `application-site` properties (`primary_category`, `url_list`, `urls_defined_as_regular_expression`, `description`) are stored in `arodonata_objects.raw_data` and hydrated onto `CPObject` on read.
   - In addition, `arodonata_assets` maintains dual UID and human-readable parent/child topology links (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`), supporting both intra-domain clusters and **cross-domain VSX topology** (where a physical VSX gateway/cluster resides in an infrastructure domain like `VSX` and its Virtual Systems reside in tenant domains like `Domain4`).

---

## 2. Entity-Relationship Diagram (17 Tables)

```mermaid
erDiagram
    arodonata_schema_version {
        string schema_hash PK
        datetime applied_at
    }
    arodonata_distributed_locks {
        string lock_key PK
        string owner_id "INDEX"
        datetime acquired_at
        datetime expires_at "INDEX"
    }
    arodonata_domains {
        string id PK "mgmt_name:name"
        string mgmt_name "INDEX"
        string uid "INDEX"
        string name "INDEX"
        string domain_type
        string active_ip
        string active_mds_ip "INDEX"
        boolean is_global "INDEX"
        datetime updated_at
    }
    arodonata_sid_cache {
        string id PK "mgmt_name:domain_name:auth_identity"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string sid "REDACTED in repr"
        string server_ip
        string session_uid
        string auth_identity
        datetime created_at
        datetime last_used_at
        datetime expires_at
    }
    arodonata_domain_sync_state {
        string id PK "mgmt_name:domain_name:scope:item_type"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string scope "INDEX: domains|objects|services|assets|rulebase|topology"
        string item_type "INDEX: host|network|*|..."
        datetime last_published_at
        string last_session_uid
        datetime synced_at
        string status "idle|syncing|ok|failed"
        int object_count
        string last_error
    }
    arodonata_objects {
        string id PK "mgmt_name:domain_name:uid"
        string object_id "INDEX: mgmt_name:domain_name:name"
        string uid "INDEX"
        string name "INDEX"
        string type "INDEX: host|network|address-range|group|dns-domain|application-site"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string original_domain "INDEX"
        string ipv4_address "INDEX"
        string subnet4 "INDEX"
        int mask_length4
        string fqdn "INDEX"
        json members
    }
    arodonata_services {
        string id PK "mgmt_name:domain_name:uid"
        string service_id "INDEX: mgmt_name:domain_name:name"
        string uid "INDEX"
        string name "INDEX"
        string type "INDEX: service-tcp|service-udp|service-icmp|service-group|..."
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string original_domain "INDEX"
        string port "INDEX"
        string protocol "INDEX"
        json members
    }
    arodonata_assets {
        string id PK "mgmt_name:domain_name:uid"
        string asset_id "INDEX: mgmt_name:domain_name:name"
        string uid "INDEX"
        string name "INDEX"
        string type "INDEX: simple-gateway|CpmiGatewayCluster|vsx-gateway|..."
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string ipv4_address "INDEX"
        string parent_uid "INDEX"
        string parent_id "INDEX: mgmt_name:parent_domain:parent_uid"
        string parent_asset_id "INDEX: mgmt_name:parent_domain:parent_name"
        json member_uids
        json member_asset_ids
        json virtual_system_uids
        json virtual_system_asset_ids
        json interfaces
        json network_security_blades
    }
    arodonata_gateway_topology {
        string id PK "mgmt_name:domain_name:gw_uid:iface:src_type:cidr"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string gateway_id "INDEX"
        string gateway_asset_id "INDEX"
        string gateway_uid "INDEX"
        string gateway_name "INDEX"
        string interface_name "INDEX"
        string topology_zone "INDEX"
        string source_type "INDEX"
        bigint ip_first_int "INDEX"
        bigint ip_last_int "INDEX"
        int prefix_len
    }
    arodonata_topology_annotations {
        string id PK "mgmt_name:domain_name:gw_uid:iface:cidr"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string gateway_uid "INDEX"
        string gateway_name "INDEX"
        string interface_name "INDEX"
        string cidr_or_range "INDEX"
        boolean trust_static_topology
        string disposition "INDEX"
        string zone
        string site
        json custom_metadata
    }
    arodonata_rulebase_package_layer {
        string id PK "mgmt_name:domain_name:package_uid:rulebase_type:layer_uid"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string package_uid "INDEX"
        string package_name "INDEX"
        string rulebase_type "INDEX: access|https|threat|nat"
        string layer_uid "INDEX"
        string layer_name "INDEX"
        int position
    }
    arodonata_rulebase_layer {
        string id PK "mgmt_name:domain_name:uid"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string uid "INDEX"
        string name "INDEX"
        string rulebase_type "INDEX: access|https|threat"
        string parent_layer_uid "INDEX"
        string parent_rule_uid "INDEX"
        string implicit_cleanup_action
    }
    arodonata_rulebase_section {
        string id PK "mgmt_name:domain_name:layer_uid:uid"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string layer_uid "INDEX"
        string layer_name "INDEX"
        string rulebase_type "INDEX"
        string uid "INDEX"
        string name "INDEX"
        int position
        json rule_uids
    }
    arodonata_rulebase_access {
        string id PK "mgmt_name:domain_name:layer_uid:uid"
        string layer_uid "INDEX"
        string section_uid "INDEX"
        string uid "INDEX"
        string name "INDEX"
        int position
        string rule_number
        boolean enabled
        string action
        string inline_layer_uid
        json source
        json destination
        json service
    }
    arodonata_rulebase_nat {
        string id PK "mgmt_name:domain_name:package_uid:uid"
        string package_uid "INDEX"
        string section_uid "INDEX"
        string uid "INDEX"
        string name "INDEX"
        int position
        string rule_number
        string method
        string original_source
        string translated_source
    }
    arodonata_rulebase_https {
        string id PK "mgmt_name:domain_name:layer_uid:uid"
        string layer_uid "INDEX"
        string section_uid "INDEX"
        string uid "INDEX"
        string name "INDEX"
        int position
        string rule_number
        string action
        json site_category
    }
    arodonata_rulebase_threat {
        string id PK "mgmt_name:domain_name:layer_uid:uid"
        string layer_uid "INDEX"
        string section_uid "INDEX"
        string uid "INDEX"
        string name "INDEX"
        int position
        string rule_number
        string action
        json protected_scope
    }

    arodonata_domains ||--o{ arodonata_domain_sync_state : "tracks sync per scope/item_type"
    arodonata_domains ||--o{ arodonata_objects : "contains"
    arodonata_domains ||--o{ arodonata_services : "contains"
    arodonata_domains ||--o{ arodonata_assets : "contains"
    arodonata_domains ||--o{ arodonata_gateway_topology : "contains"
    arodonata_domains ||--o{ arodonata_topology_annotations : "contains"
    arodonata_assets ||--o{ arodonata_gateway_topology : "exposes interface intervals"
    arodonata_domains ||--o{ arodonata_rulebase_package_layer : "contains"
    arodonata_rulebase_package_layer }o--|| arodonata_rulebase_layer : "orders layer"
    arodonata_rulebase_layer ||--o{ arodonata_rulebase_section : "divides into sections"
    arodonata_rulebase_layer ||--o{ arodonata_rulebase_access : "contains access rules"
    arodonata_rulebase_layer ||--o{ arodonata_rulebase_https : "contains https rules"
    arodonata_rulebase_layer ||--o{ arodonata_rulebase_threat : "contains threat rules"
    arodonata_rulebase_package_layer ||--o{ arodonata_rulebase_nat : "contains nat rules"
```

---

## 3. Detailed Table Catalog

### 3.1 Infrastructure, Sessions & Synchronization Tables

#### 1. `arodonata_schema_version` (`SchemaVersionRecord`)

Tracks applied SQLModel metadata SHA-256 hashes so workers skip redundant table migration inspections.

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `schema_hash` | `str` | `PK` | 64-char SHA-256 hex digest of the 17 `arodonata_*` table schemas |
| `applied_at` | `datetime` | `NOT NULL` | Naive UTC timestamp when the schema version was applied |

#### 2. `arodonata_distributed_locks` (`DistributedLockRecord`)

Coordinates cross-process critical sections (per-domain cache refreshes, `LoginGate` serialization, and distributed `RateLimiter` slots).

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `lock_key` | `str` | `PK` | Resource identifier (e.g., `sync:mdsm-prod:Domain4:objects`) |
| `owner_id` | `str` | `INDEX` | Unique holder token (`uuid4`) verified on `renew()` and `release()` |
| `acquired_at` | `datetime` | `NOT NULL` | Naive UTC acquisition timestamp |
| `expires_at` | `datetime` | `INDEX, NOT NULL` | Naive UTC expiration timestamp (periodically extended by background heartbeat) |

#### 3. `arodonata_sid_cache` (`SIDCacheRecord`)

Persistent shared read-only Check Point session store. Strictly omits `sid` from `__repr__` and `__str__`.

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | Composite key `"{mgmt_name}:{domain_name}:{auth_identity}"` (or `"{mgmt_name}:{domain_name}"` when `auth_identity` is `None`) |
| `mgmt_name` | `str` | `INDEX` | Management server logical name |
| `domain_name` | `str` | `INDEX` | Normalized domain name (`"System Data"` / `SYSTEM_DOMAIN_KEY` for SMS or MDS system domain) |
| `sid` | `str` | `repr=False` | Check Point session token (redacted in all representations) |
| `server_ip` | `str` | `NOT NULL` | Active CMA or MDS IP where this session resides |
| `session_uid` | `str \| None` | — | Check Point session UID from `login` response |
| `auth_identity` | `str \| None` | — | Non-secret `AuthContext.identity_key` (`"{principal}:{24-char-hmac-sha256}"`) bound to the credential |
| `created_at` | `datetime` | `NOT NULL` | Naive UTC creation timestamp |
| `last_used_at` | `datetime` | `NOT NULL` | Naive UTC last API call timestamp |
| `expires_at` | `datetime \| None` | — | Naive UTC local expiry (`last_used_at + session_expire_seconds`) |

#### 4. `arodonata_domain_sync_state` (`DomainSyncStateRecord`)

Unified synchronization state tracker per `(mgmt_name, domain_name, scope, item_type)`. Updated atomically inside the same database transaction as cache data writes.

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | Composite key `"{mgmt_name}:{domain_name}:{scope}:{item_type}"` |
| `mgmt_name` | `str` | `INDEX` | Management server logical name |
| `domain_name` | `str` | `INDEX` | Domain name |
| `scope` | `str` | `INDEX` | `"domains"`, `"objects"`, `"services"`, `"assets"`, `"rulebase"`, or `"topology"` |
| `item_type` | `str` | `INDEX` | Specific type (e.g., `"host"`, `"service-tcp"`) or `"*"` for whole-scope syncs |
| `last_published_at` | `datetime \| None` | — | Domain's `show-last-published-session` timestamp (`None` if never published) |
| `last_session_uid` | `str \| None` | — | Last published Check Point session UID (used for `show-changes from-session` and `HybridStateReader`) |
| `synced_at` | `datetime \| None` | — | Naive UTC timestamp of the last successful sync |
| `status` | `str` | — | `"idle"`, `"syncing"`, `"ok"`, or `"failed"` |
| `object_count` | `int` | — | Count of cached rows for this `(scope, item_type)` slice |
| `last_error` | `str \| None` | — | Sanitized (`redact_sid`) error message if the last sync failed |

---

### 3.2 Topology, Objects, Services & Assets Tables

#### 5. `arodonata_domains` (`DomainRecord`)

Cached MDSM/SMS domain topology discovered via `show-domains` (plus synthesized `Global` domain on MDSM).

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | `"{mgmt_name}:{name}"` |
| `mgmt_name` | `str` | `INDEX` | Management server logical name |
| `uid` | `str` | `INDEX` | Check Point domain UID |
| `name` | `str` | `INDEX` | Domain name (e.g., `"Domain4"`, `"Global"`, `"System Data"`) |
| `domain_type` | `str` | — | `"domain"`, `"global"` / `"global-domain"` / `"global domain"`, or `"smc-user"` |
| `active_ip` | `str \| None` | — | Active CMA IPv4/IPv6 address |
| `active_mds_ip` | `str \| None` | `INDEX` | Hosting MDS member IP (used to group per-MDS-member sync concurrency) |
| `standby_ips` | `list[str]` (JSON) | `NOT NULL` | Standby CMA IPs for automatic failover |
| `servers` | `list[dict]` (JSON) | `NOT NULL` | Full CMA server entries from Check Point API |
| `is_global` | `bool` | `INDEX` | `True` for the MDSM `Global` domain |
| `raw_data` | `dict` (JSON) | `NOT NULL` | Full sanitized API payload |
| `updated_at` | `datetime` | `NOT NULL` | Naive UTC update timestamp |

#### 6. `arodonata_objects` (`CPObjectRecord`)

Cached network objects (`host`, `network`, `address-range`, `group`, `dns-domain`, `application-site`, etc.).

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | `"{mgmt_name}:{domain_name}:{uid}"` |
| `object_id` | `str` | `INDEX` | Human-readable composite key `"{mgmt_name}:{domain_name}:{name}"` |
| `uid` | `str` | `INDEX` | Check Point object UID |
| `name` | `str` | `INDEX` | Object name |
| `type` | `str` | `INDEX` | Canonical object type (`"host"`, `"network"`, `"address-range"`, `"group"`, `"dns-domain"`, `"application-site"`) |
| `mgmt_name`, `domain_name` | `str` | `INDEX` | Server and domain context |
| `original_domain` | `str \| None` | `INDEX` | Owning domain reported by Check Point (`domain.name` inside `raw_data`, distinguishing local vs `Global` objects) |
| `ipv4_address`, `ipv6_address` | `str \| None` | `INDEX` (`ipv4`) | Host IPv4 / IPv6 address |
| `subnet4`, `mask_length4`, `subnet_mask` | `str / int` | `INDEX` (`subnet4`) | Network CIDR subnet and mask |
| `ipv4_address_first`, `ipv4_address_last` | `str \| None` | — | Address range bounds |
| `fqdn`, `is_sub_domain` | `str / bool` | `INDEX` (`fqdn`) | DNS domain FQDN and subdomain flag |
| `members` | `list[str]` (JSON) | `NOT NULL` | Member UIDs for `group` objects |
| `comments`, `color`, `tags`, `nat_settings` | `str / JSON` | `NOT NULL` (`comments`, `tags`, `nat_settings`) | Metadata, tag names, and automatic NAT settings |
| `raw_data`, `updated_at` | `JSON / datetime` | `NOT NULL` | Full API payload (hydrating `application-site` URLs/categories) and naive UTC timestamp |

#### 7. `arodonata_services` (`CPServiceRecord`)

Dedicated cache table for service objects (`service-tcp`, `service-udp`, `service-icmp`, `service-group`, and on-demand `service-other`, `service-sctp`, `service-dce-rpc`, `service-rpc`, `service-icmp6`, `service-citrix-tcp`, `service-compound-tcp`, `service-gtp`).

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | `"{mgmt_name}:{domain_name}:{uid}"` |
| `service_id` | `str` | `INDEX` | Human-readable composite key `"{mgmt_name}:{domain_name}:{name}"` |
| `uid`, `name`, `type` | `str` | `INDEX` | Service UID, name, and canonical type |
| `mgmt_name`, `domain_name`, `original_domain` | `str` | `INDEX` | Server, domain, and owning domain |
| `port`, `protocol` | `str \| None` | `INDEX` | Port/range string (e.g., `"443"`, `"8080-8090"`) and protocol |
| `icmp_type`, `icmp_code` | `int \| None` | — | ICMP type and code |
| `members` | `list[str]` (JSON) | `NOT NULL` | Member service UIDs for `service-group` |
| `session_timeout`, `match_for_any` | `int / bool` | — | Service session timeout and `match-for-any` flag |
| `comments`, `tags`, `raw_data`, `updated_at` | `str / JSON / datetime` | `NOT NULL` | Metadata, tag names, raw payload, and naive UTC timestamp (`color` is nullable) |

#### 8. `arodonata_assets` (`AssetRecord`)

Cached gateways, clusters, cluster members, VSX gateways/clusters/virtual systems, and management servers, enriched with parent/child topology links by `ClusterRelationshipManager` and `VSXRelationshipManager`.

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | `"{mgmt_name}:{domain_name}:{uid}"` |
| `asset_id` | `str` | `INDEX` | Human-readable composite key `"{mgmt_name}:{domain_name}:{name}"` |
| `uid`, `name`, `type` | `str` | `INDEX` | Asset UID, name, and type (`simple-gateway`, `CpmiGatewayCluster`, `CpmiClusterMember`, `vsx-gateway`, `vsx-cluster-netobj`, `virtual-system`, etc.) |
| `mgmt_name`, `domain_name` | `str` | `INDEX` | Server and domain context |
| `ipv4_address`, `ipv6_address` | `str \| None` | `INDEX` (`ipv4`) | Management IPv4 / IPv6 address |
| `version`, `os_name`, `hardware`, `sic_status` | `str \| None` | — | Check Point version (e.g. `"R82"`), Gaia OS, appliance model, and SIC trust status |
| `parent_uid`, `parent_name` | `str \| None` | `INDEX` (`parent_uid`) | Parent cluster or VSX container UID and name |
| `parent_id`, `parent_asset_id` | `str \| None` | `INDEX` | Parent composite UID key (`"{mgmt_name}:{parent_domain}:{parent_uid}"`) and human-readable key (`"{mgmt_name}:{parent_domain}:{parent_name}"`) |
| `member_uids`, `member_asset_ids` | `list[str]` (JSON) | `NOT NULL` | Child cluster member UIDs and human-readable `asset_id` values |
| `virtual_system_uids`, `virtual_system_asset_ids` | `list[str]` (JSON) | `NOT NULL` | Child VSX virtual system UIDs and human-readable `asset_id` values |
| `interfaces` | `list[dict]` (JSON) | `NOT NULL` | Normalized network interfaces (`name`, `ipv4-address`, `ipv4-network-mask`, `topology`) |
| `network_security_blades` | `dict` (JSON) | `NOT NULL` | Enabled software blades (`firewall`, `ips`, `url-filtering`, `anti-bot`, etc.) |
| `comments`, `raw_data`, `updated_at` | `str / JSON / datetime` | `NOT NULL` | Metadata, raw payload, and naive UTC timestamp (`color` is nullable) |

---

### 3.3 Normalized Rulebase Cache Tables (SmartConsole-in-SQL)

Arodonata v2 normalizes policy packages, layers, section headers, and rules across **7 dedicated tables** so SmartConsole hierarchical rule numbers (`1`, `2.1`, `3`), inline layers, and Global domain placeholders can be queried and filtered locally in milliseconds without hitting the Check Point API.

#### 9. `arodonata_rulebase_package_layer` (`RulebasePackageLayerRecord`)

Links each policy package (`package_uid`, `package_name`) to its ordered access, HTTPS, threat, and NAT layers (`layer_uid`, `layer_name`, `rulebase_type`, `position`).

#### 10. `arodonata_rulebase_layer` (`RulebaseLayerRecord`)

Stores every access, HTTPS, and threat layer (`uid`, `name`, `rulebase_type`), including inline layers (`parent_layer_uid`, `parent_rule_uid`), `is_global`, `shared`, and `implicit_cleanup_action` (`"Drop"` or `"Accept"`).

#### 11. `arodonata_rulebase_section` (`RulebaseSectionRecord`)

Stores rulebase section headers (`layer_uid`, `uid`, `name`, `position`, `from_rule`, `to_rule`, and ordered `rule_uids` list) stitched cleanly across 100-rule API pagination boundaries.

#### 12. `arodonata_rulebase_access` (`AccessRuleRecord`)

Stores access-control rules (`layer_uid`, `section_uid`, `uid`, `name`, `position`, `rule_number`, `enabled`, `action`, `inline_layer_uid`, `inline_layer_name`, `placeholder_domain_layer_uid`, `source`, `destination`, `service`, `source_negate`, `destination_negate`, `service_negate`, `track`, `install_on`, `comments`, `raw_data`).

#### 13. `arodonata_rulebase_nat` (`NatRuleRecord`)

Stores NAT rules (`package_uid`, `package_name`, `section_uid`, `uid`, `name`, `position`, `rule_number`, `enabled`, `method`, `auto_generated`, `original_source`, `original_destination`, `original_service`, `translated_source`, `translated_destination`, `translated_service`, `install_on`, `comments`, `raw_data`).

#### 14. `arodonata_rulebase_https` (`HttpsRuleRecord`)

Stores HTTPS inspection rules (`layer_uid`, `section_uid`, `uid`, `name`, `position`, `rule_number`, `enabled`, `action`, `inline_layer_uid`, `source`, `destination`, `service`, `site_category`, `certificate`, `track`, `install_on`, `comments`, `raw_data`).

#### 15. `arodonata_rulebase_threat` (`ThreatRuleRecord`)

Stores Threat Prevention rules (`layer_uid`, `section_uid`, `uid`, `name`, `position`, `rule_number`, `enabled`, `action`, `protected_scope`, `source`, `destination`, `service`, `track`, `install_on`, `comments`, `raw_data`).

---

### 3.4 Gateway Topology & Annotation Tables

#### 16. `arodonata_gateway_topology` (`GatewayTopologyRecord`)

Stores pre-expanded 64-bit integer IPv4 topology intervals (`[ip_first_int..ip_last_int]`) behind gateway and Virtual System interfaces from static topology extraction, VPN encryption domains, VSX provisioning routes, and live CLI routing tables (21 columns, 11 indexes).

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | Composite key `"{mgmt_name}:{domain_name}:{gateway_uid}:{interface_name}:{source_type}:{cidr_or_range}"` |
| `mgmt_name`, `domain_name` | `str` | `INDEX` | Server and domain context |
| `gateway_id`, `gateway_asset_id` | `str` | `INDEX` | Gateway UID key (`"{mgmt_name}:{domain_name}:{gateway_uid}"`) and human-readable key (`"{mgmt_name}:{domain_name}:{gateway_name}"`) |
| `gateway_uid`, `gateway_name` | `str` | `INDEX` | Enforcing gateway/cluster/VS UID and name |
| `gateway_type` | `str` | `NOT NULL` | Gateway asset type (default `"simple-gateway"`) |
| `interface_name` | `str` | `INDEX` | Gateway interface name (`eth0`, `bond0.10`, `wrp128`) |
| `interface_ipv4`, `interface_mask_length` | `str \| int \| None` | — | Primary IPv4 and mask prefix length of the interface |
| `topology_zone` | `str` | `INDEX` | `"internal"`, `"external"`, or `"dmz"` |
| `leads_to_dmz` | `bool` | `NOT NULL` | Whether Check Point marks this interface as leading to a DMZ |
| `anti_spoofing_mode` | `str` | `NOT NULL` | `"prevent"`, `"detect"`, `"off"`, or `"unknown"` |
| `source_type` | `str` | `INDEX` | `"interface_connected"`, `"interface_specific"`, `"external_interface"`, `"vpn_domain"`, `"vs_static_route"`, `"gaia_static_route"`, `"bgp_route"`, `"ospf_route"`, `"kernel_route"`, or `"manual"` |
| `source_ref`, `cidr_or_range` | `str` | `NOT NULL` | Backing Check Point group/object/route reference and CIDR or IP range string |
| `ip_first_int`, `ip_last_int` | `int` (`BigInteger`) | `INDEX, NOT NULL` | Unsigned 32-bit IPv4 start/end stored as 64-bit integer for portable SQL interval queries |
| `prefix_len` | `int` | `NOT NULL` | Effective prefix specificity (`/0`..`/32`) for longest-prefix matching |
| `updated_at` | `datetime` | `NOT NULL` | Naive UTC update timestamp |

#### 17. `arodonata_topology_annotations` (`TopologyAnnotationRecord`)

Stores persistent administrator overrides (`ignore`, `standby_dynamic`), static-topology trust hints, and IPAM site/zone metadata preserved across full `force` topology refreshes (15 columns, 7 indexes).

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | Composite annotation key scoped by server, domain, gateway, interface, and CIDR |
| `mgmt_name`, `domain_name` | `str` | `INDEX` | Server and domain context |
| `gateway_uid`, `gateway_name` | `str` | `INDEX` | Target gateway UID and optional name |
| `interface_name` | `str` | `INDEX` | Target interface name or `"*"` wildcard |
| `cidr_or_range` | `str` | `INDEX` | Target CIDR/IP range or `"*"` wildcard |
| `trust_static_topology` | `bool \| None` | — | Optional confidence override trusting static topology over live routing conflicts |
| `disposition` | `str \| None` | `INDEX` | Optional `"ignore"` (suppresses interface from matching) or `"standby_dynamic"` |
| `topology_zone` | `str \| None` | — | Optional zone override (`"internal"`, `"external"`, `"dmz"`) |
| `zone`, `site`, `comment` | `str` | `NOT NULL` | Organizational zone/site metadata and administrator note |
| `custom_metadata` | `dict` (JSON) | `NOT NULL` | Extensible JSON metadata exported alongside prefixes (`export_topology_prefixes()`) |
| `updated_at` | `datetime` | `NOT NULL` | Naive UTC update timestamp |


---

## Architecture — Caching, Incremental Sync & Search

*(source: `docs/architecture/caching-and-sync.md`)*

# Caching, Incremental Synchronization & Search

Arodonata v2 coordinates multi-domain synchronization through `DomainSyncCoordinator` (`src/arodonata/core/services/sync_coordinator.py`) and exposes four cache freshness modes (`CacheMode`).

## 1. The Four `CacheMode` Policies

| Mode | Staleness Probe (`show-last-published-session`) | Data Fetch Strategy | Typical Use Case |
| --- | --- | --- | --- |
| `"cache"` | Never | Local SQLite/PostgreSQL query only (`0` API calls) | High-speed rulebase filtering, offline analysis, MCP `query_objects` |
| `"smart"` (default) | Only when `synced_at` is older than `cache_ttl` (or after `invalidate_domain`) | Full atomic type-slice reload if `(last_published_at, last_session_uid)` changed | Default SDK reads (`get_hosts`, `get_services`, `get_gateways`) |
| `"smart-fast"` | Same as `"smart"` | Queries `show-changes` (`from-session` or UTC `from-date`), deletes removed UIDs, re-fetches added/modified UIDs via `show-object`, and applies dialect `ON CONFLICT` upserts; falls back to full reload if changes `> max_incremental_changes` (`500`) | Rapid refresh after small publishes across large domains |
| `"force"` | Always probes current publish head | Unconditional atomic reload of all requested types | Initial cache build or forced recovery |

## 2. Synchronization Pipeline & Safeguards

```mermaid
sequenceDiagram
    participant Caller as Caller / ArodonataClient
    participant Coord as DomainSyncCoordinator
    participant Lock as SqlLockAdapter (arodonata_distributed_locks)
    participant API as AMgmtClient (Check Point API)
    participant Cache as SqlCacheAdapter (PostgreSQL / SQLite)

    Caller->>Coord: ensure(scope="objects", mode="smart-fast")
    Coord->>Cache: list_sync_states(mgmt, domain, scope)
    alt Within cache_ttl and not invalidated
        Coord-->>Caller: Return cached data immediately (0 API calls)
    else In-process single-flight already active
        Coord-->>Caller: Coalesce and await shared result
    else Expired TTL or invalidated
        Coord->>Lock: acquire("sync:mgmt:domain:objects") + start heartbeat task
        Coord->>API: show-session (verify changes == 0, locks == 0, published == 0)
        Coord->>API: show-last-published-session
        alt (last_published_at, last_session_uid) unchanged
            Coord->>Cache: Update synced_at timestamp
        else Published head advanced
            alt mode == "smart-fast" and baseline exists
                Coord->>API: show-changes(from-session=last_session_uid) + show-object per changed UID
                Coord->>Cache: Atomic transaction: delete_objects_by_uids + upsert_objects + upsert_sync_state
            else mode == "smart" or "force" or >500 changes
                Coord->>API: Continuity-verified paginated show-hosts / show-networks / ...
                Coord->>Cache: Atomic transaction: replace_domain_objects + upsert_sync_state
            end
        end
        Coord->>Lock: Cancel heartbeat + release lock
        Coord-->>Caller: RefreshOutcome
    end
```

### Critical Invariants

- **Dirty Shared Session Refusal (`DirtySessionError`)**: Before syncing any domain into the shared cache, `DomainSyncCoordinator` verifies via `show-session` that `locks == 0`, `changes == 0`, and `number-of-published-changes == 0` (failing closed if `show-session` fails). Uncommitted changes are never written into shared SQL tables.
- **Process-Wide Concurrency & Single-Flight Coalescing (`_ProcessSyncRegistry`)**: Coordinators sharing a database engine share event-loop-bound per-MDS-member semaphores and an `_InFlightDomainSync` registry so concurrent coroutines syncing the same domain coalesce without duplicate API probes or lock contention. Default `domain_sync_concurrency` is `min(2, max(1, concurrent_limit - 1))` unless overridden via `ARODONATA_DOMAIN_SYNC_CONCURRENCY`, and re-entrant nested `ensure` calls reuse `_HELD_MDS_PERMITS` without deadlocking.
- **Lock Contention vs Genuine Failure**: If another worker holds the per-domain lock (`LockAcquisitionError`), the coordinator skips redundant work without marking `arodonata_domain_sync_state.status = "failed"`. Genuine API or credential errors record a sanitized (`redact_sid`) error in `last_error` while preserving previously cached rows.

## 3. Search, Structured Queries & Recursive Group Membership (`SearchService`)

`await client.search_objects(query, ..., exact_match=False, max_depth=2)` classifies each comma-separated term via `classify_search_term()` into `"ipv4"`, `"cidr"`, `"range"`, `"wildcard"`, `"uid"`, or `"name"` and searches across `arodonata_objects` (plus `arodonata_assets` including interface IPv4s when asset types are specified, and any active `WriteSession` overlay):

1. **IPv4 Address (`10.1.10.50`)**: Matches hosts with that IPv4 address, networks whose CIDR subnet contains the IP, and address ranges whose `[first..last]` bounds include the IP.
2. **CIDR Subnet (`10.1.10.0/24`)**: Matches networks with that subnet/mask and hosts/subnets contained within it (with containment excluded when `exact_match=True`).
3. **IPv4 Range (`10.1.10.1-10.1.10.20`)**: Matches overlapping `address-range` objects and contained hosts.
4. **Wildcard Pattern (`*.corp.example`, `web-*`)**: Evaluates case-insensitive anchored `fnmatchcase` across `name`, `uid`, `object_id`, `id`, `fqdn`, `ipv4_address`, `subnet4`, and `comments`.
5. **UUID Identifier (`<uid>`)**: Matches `CPObject.uid` or composite `id` directly.
6. **Exact or Substring Name (`exact_match=True` vs `False`)**:
   - When `exact_match=False` (default), matches case-insensitive substrings in `name`, `fqdn`, `object_id`, `id`, and `comments`.
   - When `exact_match=True`, matches only exact case-insensitive `name`, `fqdn`, `object_id`, `id`, or `uid` (e.g., searching `".example.com"` with `exact_match=True` matches `.example.com` without matching `sub.example.com`).
7. **Recursive Group Resolution (`max_depth`)**: Traverses `group.members` upward up to `max_depth` levels, returning `SearchResult(query=..., matches=[...], memberships=...)` where each `GroupMembershipNode` carries `id`, `object_id`, `uid`, `name`, `mgmt_name`, `domain_name`, `depth`, `parent_uids`, and `parent_object_ids`.

`SearchService` also provides:

- `describe_objects()` and `query_objects()` for cross-domain SQL-backed filtering (`scope_origin="local"|"global"|"all"`, `ip_subnet`, `port`, `protocol`, `tags`), `group_by` aggregation with CPMI type aliases, and `aggregate="count" | "list" | "describe"`.
- `get_cache_status()` inspecting `arodonata_domain_sync_state` per `(mgmt_name, domain_name, scope, item_type)`.
- `get_group_members()` / `resolve_group_with_members()` resolving recursive group, service-group, cluster, and cross-domain VSX members while raising `AmbiguousObjectError` if an unqualified name matches multiple cached domains.

## 4. Cross-Domain Asset Topology & Composite Identifiers

During `refresh_assets` / `stream_refresh_assets`, `AssetRefreshService` runs `ClusterRelationshipManager` and `VSXRelationshipManager` across cached domain assets:

- **Intra-Domain Cluster Members**: Links each cluster (`CpmiGatewayCluster`, `vsx-cluster-netobj`) and its members (`CpmiClusterMember`, `vsx-cluster-member`) with both UID references (`parent_uid`, `member_uids`) and composite identifiers (`parent_id`, `parent_asset_id`, `member_asset_ids`).
- **Cross-Domain VSX Virtual Systems**: Reconciles VSX relationships across all domains on the same `mgmt_name` (including `CpmiVsxSlotObj` / `CpmiVsSlotObj` interface and route inheritance), populating `parent_id` (`"mds:VSX:<vsx-uid>"`), `parent_asset_id` (`"mds:VSX:<vsx-name>"`), `virtual_system_uids`, and `virtual_system_asset_ids` (`["mds:Domain4:<vs-name>"]`).

## 5. Explicit Background Cache Warm-Up

`client.start_object_cache_warmup(...)` starts non-blocking background cache warming coalesced across callers via `_WarmupFlightKey` (`(mgmt_name, domains, types, include_global, include_services, mode == "force")`). `get_domains()` never triggers implicit warm-up, while `client.get_warmup_status()` reports SID-redacted per-server progress (`WarmupStatusEntry`). On `client.close()`, active warm-up tasks are cancelled cleanly.

## 6. Gateway Topology & Live Route Sync (`TopologyService`)

`TopologyService` combines Check Point static interface/VPN/VS-route extraction with live CLI routing diagnostics:

- **Targeted On-Demand Extraction**: Expands interface specific-network groups on demand via targeted `show-object` / `show-group` lookups rather than downloading every host/network object in a domain.
- **Live Route Collection**: Executes route collection scripts bounded by `route_collect_concurrency` (default `min(4, max(1, concurrent_limit // 2))`) and serialized per VSX physical chassis node, trying `GatewayCliPort` (SSH) first and falling back to Check Point `cprid` `run-script` (via `ScriptRepositoryService` in `"auto"` or `"repository"` mode, or inline bash).
- **Reconciliation, Confidence & Matching**: Persists 64-bit IPv4 intervals into `arodonata_gateway_topology`, honors persistent `arodonata_topology_annotations` (`ignore`, `standby_dynamic`, `trust_static_topology`), computes `ConfidenceDelta` scores using `TopologyConfidenceWeights` and policy rule evidence, and exposes `reconcile_gateway_topology()`, `get_topology_diagnostics()`, `find_affected_gateways()`, and `export_topology_prefixes()`.

## 7. Rulebase Snapshots & Selective Package Refresh

`RulebaseRefreshService` and `CachedRulebaseSource` maintain normalized SmartConsole-compatible rulebase caches across the 7 `arodonata_rulebase_*` tables:

- `refresh_policy_packages()` populates the lightweight `arodonata_rulebase_package_layer` catalog without downloading all rule rows.
- `refresh_package_rulebase()` atomically updates only the target package's layers, inline layers, sections, and NAT package rows (`upsert_domain_rulebase_layers`) without overwriting other packages in the domain.
- `RulebasePager` stitches sections split across 100-rule pagination boundaries and probes trailing empty sections; `CachedRulebaseSource` supports offline hierarchical numbering (`1`, `2.1`, `3`), `locate_rules()`, and `filter_rulebase()` (`output_format="objects" | "markdown" | "model_friendly" | "cpcrud"`).


---

## Architecture — Sessions, MDSM & SessionOverlay

*(source: `docs/architecture/sessions-and-mdm.md`)*

# Sessions, MDSM & `SessionOverlay`

Check Point Management servers tie every uncommitted change and object lock to a session identifier (`sid`). Sharing a single `sid` across concurrent tasks or mutating on a read session leads to accidental publishes of another user's changes or deadlocked objects.

Arodonata v2 enforces a strict architectural separation between **shared read-only sessions** and **isolated write sessions**.

## 1. Shared Read-Only Sessions (`arodonata_sid_cache`)

- **Credential-Bound Pooling (`C4`)**: All read commands (`show-*`, `where-used`, `verify-policy`) use a pooled session stored in `arodonata_sid_cache` keyed by `"{mgmt_name}:{domain_name}:{auth_identity}"`, where `domain_name` normalizes `None` to `SYSTEM_DOMAIN_KEY` (`"System Data"`) and `auth_identity` is the non-secret HMAC-SHA256 `AuthContext.identity_key` (`"{principal}:{digest}"`). Distinct users or API keys in multi-tenant hosts never collide or share a `sid`.
- **Hard Read-Only Guard**: `AMgmtClient` checks `is_readonly_command(command)` before using a cached `sid`. Attempting to run `add-*`, `set-*`, `delete-*`, `publish`, `discard`, or `run-script` on the shared session raises `SessionStateError` immediately.
- **Persistent Reuse Across Invocations**: When configured with PostgreSQL or file-backed SQLite, `await client.close()` leaves valid `arodonata_sid_cache` sessions alive so subsequent worker invocations reuse existing logins without triggering Check Point's login rate limiter (auto-logout on close runs only when `logout=True` or on an owned ephemeral `:memory:` SQLite DB).
- **Startup & Max-Sessions `SessionCleaner`**: `SessionCleaner` (`src/arodonata/adapters/checkpoint/sessions.py`) inspects open Web API sessions where `application == "arodonata"` or `session-name` starts with `"arodonata"` with `changes == 0` and `locks == 0`. It discards orphaned sessions via **`discard {"uid": target_uid}`** (never `logout`, which cannot close foreign UIDs) while leaving `SmartConsole`, third-party, and dirty sessions untouched. Startup cleanup is also invoked on max-sessions errors and skips cleanly in cold `"dynamic"` mode with no active auth.

## 2. Isolated `WriteSession` & `SessionOverlay`

Whenever you open `async with client.write_session(mgmt_name, domain) as ws:`, Arodonata:

1. Calls `create_dedicated_session()` to open a fresh Check Point session outside `arodonata_sid_cache` (applying `session_name` / `session_description` from `UserContext` if set).
2. Binds the `WriteSession` and its `SessionOverlay` to Python's `contextvars` for the current async task tree.
3. Intercepts every `add-<type>`, `set-<type>`, and `delete-<type>` call for cacheable objects and services and records them via `ws.overlay.record_object_upsert()`, `record_object_delete()`, `record_service_upsert()`, and `record_service_delete()`. Non-object/non-service commands (`NON_OVERLAY_MUTATION_TARGETS` such as rules, sections, layers, packages, domains, and repository scripts) bypass `SessionOverlay`.
4. Automatically merges `ws.overlay` (`apply_to_objects()`, `apply_to_services()`) into cached read helpers (`get_hosts`, `get_objects`, `get_services`, `find_object`, `search_objects`, `get_group_members`) called within the same async context.
5. On normal block exit (`publish_on_exit=True`), executes `publish`, waits for the task to complete, clears the overlay, invalidates the domain cache so the next read fetches the new published revision, and logs out the dedicated `sid`.
6. On any `BaseException` (including `asyncio.CancelledError`), shields `discard` and `logout_sid()` via `asyncio.shield` so no locks remain orphaned on Check Point.

```mermaid
sequenceDiagram
    participant App as Application Task
    participant Client as ArodonataClient
    participant Overlay as SessionOverlay (contextvars)
    participant CP as Check Point API
    participant SQL as SQL Cache (arodonata_objects)

    App->>Client: async with client.write_session(mgmt, "Domain4") as ws:
    Client->>CP: login (dedicated session) -> sid_write
    App->>Client: add_object(mgmt, "host", {"name": "h1", "ipv4-address": "10.0.0.1"}, domain="Domain4")
    Client->>CP: add-host (sid=sid_write)
    Client->>Overlay: record_object_upsert(CPObject("h1"))
    App->>Client: get_hosts(mgmt, "Domain4")
    Client->>SQL: SELECT * FROM arodonata_objects (committed state)
    Client->>Overlay: apply_to_objects(committed_hosts) -> includes uncommitted "h1"
    Client-->>App: [..., CPObject("h1")]
    App->>Client: exit write_session block
    Client->>CP: publish (sid=sid_write) + wait_for_task
    Client->>Overlay: clear() + invalidate_domain(mgmt, "Domain4")
    Client->>CP: logout (sid=sid_write)
```

## 3. Authentication Modes & Context Propagation

`ArodonataSettings` resolves credentials across three mutually validated modes (`api_key`, `credential`, and `dynamic`):

- **`client.auth_context(AuthContext(...))`**: Scopes per-request credentials (`api_key` or `username`/`password` + optional `user_id`) via `contextvars` for multi-tenant APIs/MCP hosts.
- **`AuthProvider`**: Optional dynamic credential callback queried when no static or context-bound credential is present; notifies `on_auth_failed()` and fast-fails evicted identities across retries.
- **`client.user_context(UserContext(...))`**: Propagates operator `user_id`, `username`, `session_name`, `session_description`, and `client_id` metadata onto dedicated Check Point write sessions.

## 4. MDSM Discovery, Failover & Login Throttling Recovery

- **Domain & Active CMA Failover**: `DomainService` caches `show-domains` (falling back to `details-level="standard"` if RBAC rejects `full` while preserving cached CMA IPs) with a `1h` TTL (`domain_list_ttl`). If a read-only call hits a stale standby CMA IP, `LoginCoordinator` clears cached SIDs and re-resolves active CMA IPs via `DomainService` / `show-global-domain`. Coalesced background keepalive sweeps (`RateLimiter.run_coalesced_keepalive`) keep long-lived sessions valid and evict expired SIDs immediately (`"object not found"` / revision reverts).
- **Login Throttling Recovery (`LoginGate`)**: Check Point R81.20 / R82 Management servers enforce a strict login rate limit returning HTTP `400` / `429` (`err_too_many_requests` / `"Too many login attempts"`). `LoginGate` (`src/arodonata/adapters/checkpoint/rate_limiter.py`) serializes login attempts per MDS member IP with inter-login spacing and opens a shared `login_throttle_window` (`70.0s` default) cooldown gate up to `login_max_wait` (`900.0s`), while genuine auth failures (`InvalidCredentialsError`, e.g. `"Authentication to server failed."`) fail fast with zero retries.

## 5. Staged CPCRUD Sessions & Repository Script Execution

- **CPCRUD Staged Sessions**: `cpcrud.apply(plan, no_publish=True, keep_session=True)` retains the uncommitted write session cleanly and records `StagedSessionInfo` (`sid` redacted). Later calls to `publish_staged_session()` or `discard_staged_session()` validate session provenance and adopt the session via `take-over-session` (with `switch-session` fallback).
- **`ScriptRepositoryService` Execution**: `run_repository_script()` runs `run-script` inside a dedicated non-read-only session (not `arodonata_sid_cache`) and closes cleanly without calling `publish` or `discard`.


---

## Architecture — CPCRUD Engine Internals

*(source: `docs/architecture/cpcrud.md`)*

# CPCRUD Engine Architecture

`arodonata.cpcrud` (`src/arodonata/cpcrud/`) implements a deterministic, two-phase (`plan` → `apply`) Policy-as-Code engine for Check Point Security Management and MDSM.

## Architecture & Data Flow

```mermaid
flowchart LR
    Expr["Shorthand Expressions\n(expressions.py)"] -.-> Tpl["YAML / JSON Template"]
    Tpl --> Val["Validator & Semantic Checks\n(checkpoint_ops_schema.json)"]
    Val --> Plan["Planner & Differ"]
    Stamp["show-last-published-session\n(DomainStamp)"] --> Plan
    Reader["HybridStateReader\n(SQL Cache + show-objects / API Fallback\n+ Virtual Intra-Plan Overlay)"] --> Plan
    Plan --> SignedPlan["Plan\n(PlannedActions + DomainStamps\n+ Name Resolutions)"]
    SignedPlan --> DryReport["build_change_report_from_plan\n(Offline Dry-Run Report)"]
    SignedPlan --> Exec["Executor\n(Pre-Apply Stamp Check + WriteSession\n+ Retry Folding + Publish or Stage)"]
    Exec --> Report["ApplyReport\n(ActionResults + StagedSessionInfo)"]
    Exec -.-> Staged["publish_staged_session /\ndiscard_staged_session"]
    SignedPlan & Report --> Inv["Inverse Builder\n(build_inverse_template)"]
```

## Core Components

### 1. Offline Schema & Semantic Validator (`validator.py`)

`CPCRUDService.validate()` validates YAML strings or Python dictionaries against `src/arodonata/cpcrud/checkpoint_ops_schema.json` (or `cpcrud_schema_path`, JSON Schema Draft-07) with zero network or database calls. Beyond JSON Schema, semantic checks enforce strict `(object_type, operation)` command allowlisting, reject `add` operations on `application-site` missing both `url-list` and `application-signature`, and validate incremental `{add, remove}` delta mappings.

### 2. `DomainStamp` & `HybridStateReader` (`state_reader.py`)

Before inspecting any objects or rules, `Planner` queries `show-last-published-session` for each target domain and records a `DomainStamp(mgmt_name, domain, last_session_uid, last_published_at)`.

`HybridStateReader` serves object, service, and rule lookups using a tiered strategy:

- **Cache Hit (Fast Path)**: If `arodonata_domain_sync_state` for `(mgmt_name, domain, scope, item_type)` matches the planner's `DomainStamp` (`last_published_at` and `last_session_uid`), lookups (`host`, `network`, `address-range`, `group`, `dns-domain`, `application-site`, `service-tcp`, `service-udp`, `service-icmp`, etc.) resolve directly from `arodonata_objects` and `arodonata_services` in local SQL.
- **Targeted Cold-Cache API Lookup**: When local cache is cold or stale, `HybridStateReader` first issues targeted `show-objects` queries (`filter` + `ip-only=True`)—with `application-site` value-matching using normalized `url-list` keys (`normalize_app_site_url_key`)—before falling back to full paginated `api_query` (`show-hosts`, `show-services-tcp`, etc.) only when necessary (e.g., `generic_err_command_not_recognized` or ICMP type/code lookups).
- **Intra-Plan Virtual State Overlay**: Each `plan()` call instantiates a fresh `HybridStateReader` whose virtual overlay tracks objects, services, and groups planned earlier in the same template so downstream groups and rules see newly planned members immediately.
- **Fail-Closed Lookup Errors**: Transport or API errors during state lookup raise `StateLookupError` and produce `Outcome.ERROR` (plus `Outcome.SKIPPED_DEPENDENCY` on dependent groups/rules) rather than falsely assuming an object is missing and planning a duplicate `CREATE`.

### 3. Two-Axis Conflict Resolution (`differ.py` & `planner.py`)

When planning an object or service:

- **`on_name_conflict: "update" | "error"`**:
  - If an object with the same `name` exists with identical desired fields → `Outcome.UNCHANGED` (`no-op`).
  - If fields differ and `on_name_conflict="update"` → `Outcome.UPDATE` with field-level `FieldChange` diffs.
  - If fields differ and `on_name_conflict="error"` → `Outcome.ERROR`.
- **`on_ip_conflict: "reuse" | "create_new" | "error"`**:
  - Evaluated when no object has the requested `name`, but an existing object in the domain already owns the same IPv4/IPv6 value, CIDR subnet, IP range, port/ICMP tuple, DNS FQDN, or `application-site` URL set:
  - `"reuse"` (default): Plans `Outcome.REUSE` and records `requested_name -> existing_name` in `Plan.name_resolutions`, automatically rewriting references in subsequent groups and rules.
  - `"create_new"`: Generates a convention name via `NamingPrefixes` (`Host_<ip>`, `Net_<subnet>_<mask>`, `IPR_<first>-<last>` or compressed same-`/24`, `TCP_<port>`, `UDP_<port>`, `ICMP_<type>[_<code>]`, `grp<name><suffix>`, `Site_[marker]<domain>`) and plans `Outcome.CREATE` (or reuses if that canonical name already exists).
  - `"error"`: Plans `Outcome.ERROR` and skips dependent actions.

### 4. Rule Identity & Cleanup-Aware Positioning (`rule_identity.py` & `position_helper.py`)

- **Access, HTTPS, and Threat Rules**: Matched by `uid`, `name`, or traffic tuple (`source`, `destination`, `service`, `action`).
- **NAT Rules**: Matched by `uid`, `name`, or original/translated traffic tuple, normalizing Check Point's built-in `"Original"` (`NAT_ORIGINAL_OBJECT_UID`) and `"Any"` (`NAT_ANY_OBJECT_UID`) sentinel UIDs so re-planning an applied NAT rule is idempotent (`Outcome.UNCHANGED`).
- **Cleanup Rule Anchoring**: `is_cleanup_rule()` identifies any rule with `"cleanup"` in its name or any trailing `Any / Any / Any` rule at the end of a layer or section. When `position: "bottom"` or `{"bottom": "<section>"}` is requested alongside a trailing cleanup rule, `position_helper` automatically anchors the new rule `{"above": "<cleanup_rule_uid>"}` so traffic rules are never placed below the cleanup drop rule.

### 5. Dedicated-Session `Executor` & Compensating Rollback (`executor.py`, `inverse.py`)

When `await client.cpcrud.apply(plan, force=False)` runs:

1. **Pre-Session Staleness Check**: Re-queries `show-last-published-session` and compares against `plan.domain_stamps`. If another admin published changes after `plan()` was created and `force=False`, execution aborts with `Outcome.PLAN_STALE` before opening a write session.
2. **Pre-Publish Drift Re-Verification**: Before calling `publish`, `Executor` re-checks `show-last-published-session`; if concurrent changes published during execution (`force=False`), it discards the session cleanly and reports `Outcome.PLAN_STALE`.
3. **Bounded Retries (`retry_remaining`)**: `Executor.stream_apply` can re-run failed actions up to `retry_remaining` times, advancing `DomainStamp` only for domains published by the executor and folding retry results into a cumulative `ApplyReport`.
4. **Compensating Rollback (`inverse.py`)**: `client.cpcrud.inverse(plan, report=None)` supports both post-apply rollback (`Outcome.CREATE`, `Outcome.UPDATE`, `Outcome.DELETE` using `prior_state`, requiring a concrete `target_uid` on `CREATE`) and pre-apply dry-run inversion, emitting a schema-valid reverse template in reverse dependency order (rules → sections → groups → services/objects).

### 6. Shorthand Expression Parser (`expressions.py`)

`arodonata.cpcrud.expressions` parses concise operator strings into normalized Check Point object/service dictionaries using `NamingPrefixes`: `parse_object_expression()`, `parse_service_expression()`, `parse_group_expression()`, `expand_group_expression()`, `parse_app_site_expression()`, `parse_range_token()`, `normalize_wildcard_domain()`, and `wildcard_domain_to_cp_regex_urls()` (covering hosts, CIDRs, short IP ranges like `10.1.1.1-9`, `tcp/udp/icmp` tokens, DNS sub-domains, wildcard `application-site` regex URLs, and nested group trees).

### 7. Incremental Group & Rule Cell Deltas (`DiffSafetyError`)

`differ.py` supports incremental `{add, remove}` dictionaries on `group.members`, `service-group.members`, `application-site.url-list`, and rule cells (`source`, `destination`, `service`, `install-on`, `protected-scope`, `site-category`), raising `DiffSafetyError` to prevent unsafe mutations (adding `'Any'`, narrowing an existing `'Any'` cell without explicitly removing `'Any'`, or emptying a rule cell or `url-list` without `application-signature`). Missing named targets under `"set"` or incremental delta updates fail closed as `Outcome.ERROR`.

### 8. Staged Sessions & Offline Dry-Run `ChangeReport`

- **Staged Sessions**: Calling `apply(plan, no_publish=True, keep_session=True)` leaves the dedicated write session uncommitted for external inspection (`ApplyReport.staged_sessions` with `StagedSessionInfo`, `sid` redacted), emits `StagedSessionEvent`, and supports later provenance-verified adoption (`take-over-session` / `switch-session`) via `publish_staged_session()` and `discard_staged_session()`.
- **Offline Plan Reports**: `build_change_report_from_plan(plan)` (`arodonata.reports.plan_report`) converts any `Plan` directly into a `ChangeReport` renderable via `render_change_report()` (`html`, `markdown`, `json`) without live API calls.


---

## MCP Server & Consolidated Tool Surface

*(source: `docs/mcp/index.md`)*

# Model Context Protocol (MCP) Server & Consolidated Tool Surface

Arodonata v2 includes a production-hardened **Streamable-HTTP Model Context Protocol (MCP) server** (`arodonata[mcp]`) that can run either as a standalone CLI (`arodonata-mcp`) or embedded as an ASGI sub-application (`create_mcp_server`, `create_asgi_app`) inside a FastAPI or Starlette host.

---

## 1. Consolidated Tool Surface Optimization (v2 Architecture)

In Arodonata v2, the MCP tool surface was redesigned and consolidated into **13 cache-aligned core tools** (plus **5 opt-in tamper-proof CPCRUD tools** when `ARODONATA_MCP_CPCRUD=true`).

### Why We Consolidated the MCP Tools

Early MCP servers often expose dozens of 1-to-1 wrappers over raw Check Point API endpoints (`show-hosts`, `show-networks`, `show-access-layers`, `show-packages`, etc.). That causes three major problems for LLM agents:

1. **Tool Selection Ambiguity & Context Bloat**: Too many overlapping tool schemas consume thousands of prompt tokens and cause models to pick the wrong endpoint.
2. **Unbounded Output Overflow**: Raw Check Point API calls or unanchored substring searches on large enterprise domains return thousands of objects and blow up the LLM context window.
3. **N+1 API Round-Trips**: Answering questions like *"How many hosts and networks exist per domain?"* or *"What packages and layers exist in Domain4?"* previously required dozens of sequential tool calls.

Arodonata v2 solves all three problems with **progressive disclosure**, **multi-table unified lookup**, **SQL-free cached aggregation**, and **hybrid cache/live execution**:

| Tool Category | Tool Name | Optimization & Key Capabilities |
| --- | --- | --- |
| **Collection Listing** | `list_domains` | Lists discovered domains (`arodonata_domains`) with `active_ip`, `active_mds_ip`, `standby_ips`, `is_global`, `source`, and `cache_age_seconds` |
| **Collection Listing** | `list_objects` | Lists cached network objects (`host`, `network`, `address-range`, `group`, `dns-domain`) with `id`, `object_id`, pagination (`from`, `to`, `total`), and type normalization |
| **Collection Listing** | `list_services` | Lists cached services (`arodonata_services` with `id` and `service_id`), accepting both short (`"tcp"`, `"udp"`, `"icmp"`, `"group"`) and canonical (`"service-tcp"`, etc.) `types` filters |
| **Collection Listing** | `list_assets` | Lists cached gateways, clusters, cluster members, VSX gateways/virtual systems, and management servers (`arodonata_assets` with `id`, `asset_id`, `parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`), with optional `parent` UID/name/`asset_id` filtering |
| **Multi-Table Entity Lookup** | `show_object` | Searches across **`arodonata_objects`**, **`arodonata_services`**, **`arodonata_assets`** (including gateway `interfaces`, `network_security_blades`, `member_uids`, `member_asset_ids`, `virtual_system_asset_ids`), and **`arodonata_rulebase_layer` / `package_layer`** by UID, exact name, or composite ID (`object_id`/`service_id`/`asset_id`) using **3-tier matching** (`exact`, strict `wildcard` via `fnmatchcase`, and paginated `substring_candidates` fallback) |
| **Structured Analytics** | `query_objects` | Executes cross-domain filtering (`name_pattern`, `ip_subnet`, `port`, `protocol`, `tags`, `scope_origin="all"\|"local"\|"global"`, `object_id`, `service_id`, `asset_id`, `parent_id`, `parent_asset_id`), `group_by`, and aggregation (`aggregate="list"\|"count"\|"describe"`) over cached SQL tables in a single tool call |
| **Cache Management** | `cache_control` | Unified cache inspection (`action="status"`, returning per-domain/per-type freshness from `arodonata_domain_sync_state`) and scoped refresh (`action="refresh"`, `scope="domains"\|"objects"\|"services"\|"assets"\|"rulebase"`) |
| **Search & Membership** | `search_objects` | Multi-term IP/CIDR/range/wildcard/UID/composite-ID/name search with `exact_match: bool = False` and recursive parent group resolution (`max_depth`, including `object_id` and `parent_object_ids`) |
| **Search & Membership** | `get_group_members` | Expands direct or recursive members of a network `group`, `service-group`, gateway cluster (`member_uids` / `member_asset_ids`), or VSX container (`virtual_system_uids` / `virtual_system_asset_ids`, including cross-domain Virtual Systems) by UID, name, or composite ID |
| **Policy & Rulebase** | `show_rulebase` | **Catalog + Rulebase Hybrid**: when `package` and `layer` are omitted (or unmatched), returns the domain's cached packages and layers catalog! When specified, evaluates `filter` locally against cached rules/objects/services (`markdown`, `model_friendly`, `raw`, `cpcrud`) or switches to live API when `show_hits` / `cache_mode="live"` is used |
| **Policy & Rulebase** | `locate_rules` | Resolves rule UIDs or layer UIDs into exact SmartConsole hierarchical rule numbers (`1`, `2.1`) and package/layer paths across a domain |
| **Audit & Compliance** | `change_report` | Collects and renders auditable session change reports (`SessionScope` or `RangeScope`) in `markdown`, `json`, or `html` with full `sid` redaction |
| **Escape Hatch** | `api_call` | Executes direct Check Point Web API commands (`where-used`, `show-sessions`, `verify-policy`). Enforces a strict read-only command allowlist when `ARODONATA_MCP_ALLOW_WRITE_API=false`, and isolates allowed write calls in a dedicated session |
| **Opt-in CPCRUD** | `cpcrud_validate` | Offline JSON Schema validation of declarative CPCRUD templates (`ARODONATA_MCP_CPCRUD=true`) |
| **Opt-in CPCRUD** | `cpcrud_plan` | Generates a deterministic CPCRUD `Plan` signed with an in-memory **HMAC-SHA256** key (`plan_signature` + `plan_id`) |
| **Opt-in CPCRUD** | `cpcrud_apply` | Verifies the `plan_id` or HMAC `plan_signature` (rejecting model-forged or modified plans), executes inside an isolated `WriteSession`, and supports staging (`no_publish=True, keep_session=True`) |
| **Opt-in CPCRUD** | `cpcrud_inverse` | Generates a compensating rollback template from a verified `Plan` and `ApplyReport` |
| **Opt-in CPCRUD** | `cpcrud_staged_session` | Adopts a staged session (`session_uid`) via `take-over-session` and either publishes (`action="publish"`, invalidating domain cache) or discards (`action="discard"`) cleanly |

---

## 2. Deep-Dive into Key Tool Behaviors

### 2.1 Three-Tier Matching in `show_object`

When an LLM calls `show_object(uid_or_name=..., mgmt_name=..., domain=..., obj_type=None, limit=20, offset=0)`:

1. **Tier 1 — Exact Match (`match_type="exact"`)**:
   - If `uid_or_name` contains no `*` or `?` wildcards and matches an exact UID or case-insensitive name in `arodonata_objects`, `arodonata_services`, `arodonata_assets`, or `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer`, `show_object` returns that single entity with full details (including gateway `interfaces`, `network_security_blades`, `member_uids`, and `virtual_system_uids`).
2. **Tier 2 — Strict Explicit Wildcard (`match_type="wildcard"`)**:
   - If `uid_or_name` contains `*` or `?` (e.g. `"web-*-prod"` or `"*.example.com"`), it evaluates anchored `fnmatchcase` strictly against the pattern without adding implicit leading/trailing wildcards. If `total == 1`, it returns the full object; if `total > 1`, it returns a paginated candidate slice (`limit` default `20`, max `500`).
3. **Tier 3 — Paginated Substring Candidate Fallback (`match_type="substring_candidates"`)**:
   - If `uid_or_name` has no wildcard and no exact match exists in cache, instead of failing with a bare `"not found"` error or dumping thousands of objects, `show_object` searches for case-insensitive substring matches across cached names and returns up to `limit` (`20`) compact candidate summaries (`uid`, `name`, `type`, `domain_name`, `summary`) with `from`, `to`, and `total` so the LLM can pick the exact object on the next turn.

### 2.2 Progressive Disclosure via `query_objects` & `show_rulebase`

- **Schema & Inventory Discovery (`query_objects(aggregate="describe")`)**:
  - Calling `query_objects(mgmt_name="mdsm-prod", aggregate="describe")` returns all available domains, per-type object/service/asset counts, and the exact list of filterable and groupable fields (`domain_name`, `type`, `original_domain`, `color`, `protocol`, `port`, etc.).
- **Cross-Domain Counting (`query_objects(aggregate="count", group_by=["domain_name", "type"])`)**:
  - Counts objects and services across all domains in a single SQL query, supporting `scope_origin="local"` (domain-owned only) vs `"global"` (`original_domain == "Global"`).
- **Guided Rulebase Discovery (`show_rulebase`)**:
  - Calling `show_rulebase(mgmt_name="mdsm-prod", domain="Domain4")` **without** `package` or `layer` (or with a misspelled layer name) automatically returns `"mode": "catalog"` containing all cached `packages` (`arodonata_rulebase_package_layer`) and `layers` (`arodonata_rulebase_layer`, including inline layers and `implicit_cleanup_action`).

### 2.3 Pre-Login Domain Validation & Actionable `ToolFailure`

Every domain-scoped MCP tool validates `domain` against the cached `arodonata_domains` table (triggering a single domain-list refresh on cache miss) **before** attempting any Check Point login. If an invalid domain name is passed, the tool returns an actionable error listing the valid domain names on that server instead of triggering unnecessary failed logins.

---

## 3. Running & Embedding the MCP Server

### 3.1 Standalone CLI (`arodonata-mcp`)

```bash
# Start with static bearer token authentication (default)
export ARODONATA_MCP_AUTH_MODE=static
export ARODONATA_MCP_TOKEN_VARS=TEAM_ALPHA_MCP_TOKEN
export TEAM_ALPHA_MCP_TOKEN="a-very-long-random-secret-token-at-least-32-chars"

uv run arodonata-mcp --host 127.0.0.1 --port 8000 --path /mcp
```

### 3.2 Embedding in FastAPI / Starlette (`create_mcp_server` & `create_asgi_app`)

See [`examples/12_mcp_embedded.py`](../examples/12-mcp-embedded.md) for a complete runnable example mounting Arodonata's MCP server inside a FastAPI application with custom host-level tools:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from arodonata import ArodonataClient, ArodonataMCPSettings, create_asgi_app, create_mcp_server

client = ArodonataClient()
mcp_settings = ArodonataMCPSettings(auth_mode="host", path="/mcp")
mcp_server = create_mcp_server(client, mcp_settings=mcp_settings)
mcp_asgi = create_asgi_app(client, mcp_settings=mcp_settings, server=mcp_server)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with client, mcp_asgi.lifespan(app):
        yield


app = FastAPI(lifespan=lifespan)
app.mount("/mcp", mcp_asgi)
```

---

## 4. MCP Configuration & Security Reference (`ArodonataMCPSettings`)

| Env Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `ARODONATA_MCP_HOST` | `str` | `"127.0.0.1"` | Bind address for standalone `arodonata-mcp` |
| `ARODONATA_MCP_PORT` | `int` | `8000` | Bind TCP port (`1..65535`) |
| `ARODONATA_MCP_PATH` | `str` | `"/mcp"` | Streamable-HTTP mount path |
| `ARODONATA_MCP_AUTH_MODE` | `"static" \| "host" \| "jwt" \| "none"` | `"static"` | Authentication mode (`"host"` and `"jwt"` are for embedded ASGI mode only; standalone CLI exits with code `2` if used) |
| `ARODONATA_MCP_TOKEN_VARS` | `list[str]` (CSV) | `[]` | Env var names holding bearer tokens (`>= 32` chars); each var name becomes `client_id` in `UserContext` |
| `ARODONATA_MCP_TOKENS` | `list[str]` (CSV) | `[]` | Direct `"client_id=secret"`, `"client_id:secret"`, or bare base64 token secrets (`>= 32` chars; safe with trailing `=` base64 padding) |
| `ARODONATA_MCP_ENABLE_DNS_REBINDING_PROTECTION` | `bool` | `True` | Enforces `Host` (`HTTP 421`) and `Origin` (`HTTP 403`) header allowlists |
| `ARODONATA_MCP_ALLOWED_HOSTS` | `list[str]` (CSV) | `127.0.0.1:*,localhost:*,[::1]:*` | Permitted `Host` headers (validates numeric ports on wildcard `:port` patterns) |
| `ARODONATA_MCP_ALLOWED_ORIGINS` | `list[str]` (CSV) | `http(s)://localhost:*`, `127.0.0.1:*` | Permitted browser `Origin` headers |
| `ARODONATA_MCP_ALLOW_WRITE_API` | `bool` | `False` | When `False`, `api_call` permits only the explicit read-only allowlist (`show-*`, `where-used`, `verify-policy`); when `True`, mutating calls run in an isolated dedicated session |
| `ARODONATA_MCP_CPCRUD` | `bool` | `False` | Registers the 5 tamper-proof HMAC-signed CPCRUD tools (`cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_staged_session`) |
| `ARODONATA_MCP_ALLOW_INSECURE_UNAUTHENTICATED` | `bool` | `False` | Explicit opt-in required to pair `ARODONATA_MCP_AUTH_MODE=none` with non-loopback `host`, disabled DNS rebinding protection, wildcard or non-loopback allowlist entries, `allow_write_api=true`, or `cpcrud=true` (emits a `SECURITY WARNING`) |
| `ARODONATA_MCP_TOOL_RATE_LIMIT_PER_MINUTE` | `int` | `120` | Sliding-window per-caller (`client_id[:user_id]`) tool invocation limit per minute across all MCP tools (`0` disables enforcement) |
| `ARODONATA_MCP_LIVE_TOOL_RATE_LIMIT_PER_MINUTE` | `int` | `30` | Stricter per-caller sliding-window limit per minute for live/mutating tools, cold/stale `smart` syncs, domain-miss refreshes, and `show_object` live fallbacks (`0` disables enforcement) |
| `ARODONATA_MCP_JSON_RESPONSE` | `bool` | `False` | Return JSON responses instead of SSE streams on Streamable-HTTP POST |
| `ARODONATA_MCP_STATELESS_HTTP` | `bool` | `False` | Enable stateless Streamable-HTTP mode per request (recommended when serving multiple identities over one `auth_mode="host"` endpoint) |
| `ARODONATA_MCP_SERVER_NAME` | `str` | `"arodonata-mcp"` | Server identifier reported in MCP initialization |

### 4.1 Security, Multi-Tenant Isolation & Quota Semantics

- **Service-Account Server-Wide Visibility Trust Boundary**: The MCP server authenticates callers at the HTTP/ASGI boundary (`client_id[:user_id]`), while backend Check Point queries execute using the `ArodonataClient` service account's configured `mgmt_names` and domain permissions. Do not expose a single shared MCP endpoint to mutually untrusted tenants expecting per-domain Check Point RBAC partitioning; run separate service-account-scoped MCP instances or enforce domain filtering in an enclosing host gateway.
- **Embedded `auth_mode="host"` Middleware**: When embedding via `create_asgi_app(..., auth_mode="host")`, the enclosing host ASGI middleware MUST bind `UserContext` on every incoming HTTP request. For multi-tenant hosts handling varying caller identities over one Streamable-HTTP mount, configure `stateless_http=True` so each request executes with its own `UserContext` rather than inheriting the opening session's context.
- **Per-Caller CPCRUD Isolation**: `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`, and `cpcrud_staged_session` scope HMAC signatures, `plan_store`, `last_report`, and `staged_session_store` strictly by resolved caller identity (`client_id[:user_id]`). If `staged_session_store` exceeds `MAX_STORED_PLANS`, same-caller sessions are evicted before other callers' entries, cleanly discarded, and logged out with a SID-redacted `WARNING`.
- **Smart-Sync Live Quotas**: Cached reads served from fresh warm cache (`cache_mode="cache"` or `cache_mode="smart"` within `cache_ttl`) consume only `tool_rate_limit_per_minute`, while cold/stale `smart` syncs, domain-list cache misses, multi-scope/composite-ID syncs, proportional domain/scope fan-out (`cache_control`, `change_report`), and `show_object` live fallbacks charge `live_tool_rate_limit_per_minute`.


---

## User Guide — Declarative CPCRUD Operations

*(source: `docs/user-guide/cpcrud.md`)*

# CPCRUD — Declarative Policy-as-Code Engine (`client.cpcrud`)

`client.cpcrud` (`CPCRUDService`) provides a deterministic, two-phase (`plan` -> `apply`) Policy-as-Code CRUD engine for Check Point Security Management and MDSM servers with offline JSON Schema validation, two-axis conflict resolution, staleness guards, and compensating rollback templates (`inverse`).

## Quick Start

```bash
ARODONATA_LAB=home uv run examples/08_cpcrud_operations.py
ARODONATA_LAB=home uv run examples/09_cpcrud_inverse.py
```

- `08_cpcrud_operations.py` validates `examples/crud_example.yaml` offline, plans and applies it twice in `Domain4`, and verifies that Run 2 produces `unchanged` outcomes with zero `create` actions.
- `09_cpcrud_inverse.py` plans and applies a template, generates a compensating rollback template via `client.cpcrud.inverse(plan, report)`, and applies the rollback.

## Template Structure

Templates are validated offline against `src/arodonata/cpcrud/checkpoint_ops_schema.json` using `client.cpcrud.validate(template)` (zero network or database calls):

```yaml
version: 1
mgmt_name: "10.192.15.140"
domain: "Domain4"
on_name_conflict: "update"
on_ip_conflict: "reuse"

objects:
  - type: "host"
    name: "cpcrud-example-host-1"
    ipv4-address: "198.51.100.10"
    comments: "CPCRUD example host"
    color: "dark green"

  - type: "network"
    name: "cpcrud-example-net-1"
    subnet4: "198.51.100.0"
    mask-length4: 24

services:
  - type: "service-tcp"
    name: "cpcrud-example-tcp-8443"
    port: "8443"

groups:
  - type: "group"
    name: "cpcrud-example-group"
    members:
      - "cpcrud-example-host-1"
      - "cpcrud-example-net-1"

rules:
  - type: "access-rule"
    layer: "FPCR_UAT_Active Network"
    position: "bottom"
    name: "cpcrud-example-access-rule"
    source: ["cpcrud-example-host-1"]
    destination: ["Any"]
    service: ["cpcrud-example-tcp-8443"]
    rule_action: "Drop"
```

Multi-domain templates can also group operations under `targets:` (or `domains:`), where each item specifies its own `mgmt_name`, `domain`, and `objects` / `services` / `groups` / `rules` / `operations`.

## Two-Axis Conflict Policies

### `on_name_conflict`

Controls what happens when an object with the requested `name` already exists with different attributes:

| Value | Behavior |
| --- | --- |
| `update` (default) | Plans `Outcome.UPDATE` (`set-<type>`) with a field-level diff |
| `error` | Plans `Outcome.ERROR` and skips dependent groups/rules (`Outcome.SKIPPED_DEPENDENCY`) |

### `on_ip_conflict`

Controls what happens when no object has the requested `name`, but another object already owns the same IPv4/subnet/range or service port:

| Value | Behavior |
| --- | --- |
| `reuse` (default) | Plans `Outcome.REUSE` and maps `requested_name -> resolved_name` in `Plan.name_resolutions` so downstream groups and rules reference the existing object |
| `create_new` | Plans `Outcome.CREATE` using convention-compliant `NamingPrefixes` (`Host_<ip>`, `Net_<subnet>_<mask>`, `IPR_<first>-<last>`, `TCP_<port>`, `UDP_<port>`) |
| `error` | Plans `Outcome.ERROR` and skips dependent actions |

## Staleness Protection & Execution Options

1. **Pre-Lookup `DomainStamp`**: `client.cpcrud.plan(template)` captures `show-last-published-session` (`last_session_uid`, `last_published_at`) for every target domain BEFORE reading state.
2. **Staleness Guard on `apply()`**: `await client.cpcrud.apply(plan, force=False)` re-verifies each domain's published head before opening a write session. If another administrator published changes since `plan()`, `apply(force=False)` aborts that domain with `Outcome.PLAN_STALE`. Pass `force=True` to override.
3. **Staged Sessions (`no_publish=True, keep_session=True`)**: Leaves the dedicated write session open on the server and returns `StagedSessionInfo` in `ApplyReport.staged_sessions` (with `.sid` redacted in `repr()` and logs).
4. **Automatic Retries (`retry_remaining=N`)**: Retries failed or locked actions up to `N` additional passes.

## Compensating Rollback (`inverse`)

Always pass the original `Plan` (captured before `apply`) and the resulting `ApplyReport` to `client.cpcrud.inverse(plan, report)`:

```python
plan = await client.cpcrud.plan(template)
report = await client.cpcrud.apply(plan)

inverse_template = client.cpcrud.inverse(plan, report)
inv_plan = await client.cpcrud.plan(inverse_template)
inv_report = await client.cpcrud.apply(inv_plan)
```

---

## User Guide — Auditable Change Reports

*(source: `docs/user-guide/change-report.md`)*

# Auditable Change Reports (`arodonata.reports`)

Arodonata v2 provides a read-only change evidence collector and offline multi-format renderer (`HTML`, `Markdown`, `JSON`) in `src/arodonata/reports/` and on `ArodonataClient`.

It is designed for change-management tickets, compliance audits, and human-in-the-loop review of both **unpublished staged sessions** and **historical published sessions**.

## 1. Scopes: `SessionScope` vs `RangeScope`

You can collect change reports across one or more management servers and domains in a single call by passing `SessionScope` or `RangeScope` items:

```python
from datetime import datetime, UTC
from arodonata import ArodonataClient, RangeScope, RenderOptions, SessionScope

async with ArodonataClient() as client:
    # Option A: Inspect specific session UIDs (published or currently open)
    scope_sessions = SessionScope(
        mgmt_name="mdsm-prod",
        domain="Domain4",
        session_uids=["4a8b9c10-..."],
    )

    # Option B: Inspect all published sessions within a UTC time window or session range
    scope_range = RangeScope(
        mgmt_name="mdsm-prod",
        domain="Domain4",
        from_date=datetime(2026, 10, 25, 0, 0, tzinfo=UTC),
        to_date=datetime(2026, 10, 26, 0, 0, tzinfo=UTC),
    )

    bundle = await client.build_change_report(
        [scope_sessions, scope_range],
        formats=["html", "markdown", "json"],
        options=RenderOptions(
            title="Firewall Change Evidence — Ticket CHG-10492",
            include_object_changes=True,
            include_field_diffs=True,
            include_warnings=True,
        ),
    )

    # Save rendered outputs
    Path("report.html").write_bytes(bundle.html)
    Path("report.md").write_text(bundle.markdown, encoding="utf-8")
    Path("report.json").write_text(bundle.json_text, encoding="utf-8")
```

## 2. Unpublished Live Numbering vs Published Cached Numbering

A key capability in Arodonata v2 is accurate SmartConsole rule numbering (`1`, `2.1`, `3`) even for **uncommitted rules inside an open `WriteSession` or staged CPCRUD session**:

1. **Live Unpublished Session (`OwnedSession`)**:
   - When you pass `owned_sessions=[OwnedSession(mgmt_name=..., domain=..., session_uid=..., sid=ws.sid, server_ip=ws.server_ip)]` in `RenderOptions`, the collector reads the rulebase directly through that unpublished `sid` (strictly read-only `show-*` calls) so newly added or moved rules receive their exact post-change SmartConsole rule numbers before `publish`!
   - The `OwnedSession.sid` is never stored in `ChangeReport` and is redacted in `__repr__` and all rendered outputs.
2. **Published Session Fallback**:
   - For already-published sessions (or when no `OwnedSession` is provided), the collector resolves rule numbers and layer locations from the cached rulebase snapshot (`arodonata_rulebase_*`), complemented by bounded (`MAX_UID_LOOKUPS = 200`) live `show-object` UID resolution for referenced objects.


---

## Configuration — Environment & Settings

*(source: `docs/configuration/index.md`)*

# Configuration Overview

Arodonata v2 uses `ArodonataSettings` (`src/arodonata/core/config.py`) built on `pydantic-settings` for type-safe configuration resolution.

## Core Design Principles

1. **No Implicit `.env` Loading**: `ArodonataSettings` reads from explicit constructor keyword arguments and `os.environ` (`env_file=None`). Host applications and CLIs control when `.env` files are loaded.
2. **Automatic Secret Redaction**: `api_key`, `api_keys`, `password`, and `database_url` passwords are automatically masked (`"***REDACTED***"`) in `__repr__()`, `__str__()`, `model_dump()`, and `model_dump_json()`.
3. **Dual Alias Support**: Every setting supports both prefixed `ARODONATA_*` environment variables and legacy `MGMT_*` / unprefixed aliases.

## `ArodonataSettings` Reference

### Server Topology & Authentication

| Field | Env Variable(s) | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `mgmt_names` | `ARODONATA_MGMT_NAMES`, `MGMT_NAMES` | `list[str]` (CSV/JSON) | `[]` | Logical names of management servers (positional match with `mgmt_servers`) |
| `mgmt_servers` | `ARODONATA_MGMT_SERVERS`, `MGMT_SERVERS` | `list[str]` (CSV/JSON) | `[]` | Target `host`, `host:port`, or `[ipv6]:port` addresses |
| `api_keys` | `ARODONATA_API_KEYS`, `API_KEYS` | `list[str]` (CSV/JSON) | `[]` | Positional API keys for each server in `mgmt_servers` |
| `api_key_vars` | `ARODONATA_API_KEY_VARS`, `API_KEY_VARS` | `list[str]` (CSV/JSON) | `[]` | Names of environment variables holding each server's API key |
| `mgmt_name` | `ARODONATA_MGMT_NAME`, `MGMT_NAME` | `str \| None` | `None` | Single-server logical name convenience fallback |
| `mgmt_ip` | `ARODONATA_MGMT_IP`, `MGMT_IP` | `str \| None` | `None` | Single-server IP/hostname convenience fallback |
| `mgmt_port` | `ARODONATA_MGMT_PORT`, `MGMT_PORT` | `int` | `443` | Default HTTPS port when omitted in `mgmt_servers` |
| `api_key` | `ARODONATA_API_KEY`, `MGMT_API_KEY` | `str \| None` | `None` | Single-server API key fallback |
| `username` | `ARODONATA_USERNAME`, `MGMT_USER`, `MGMT_USERNAME` | `str \| None` | `None` | Administrator username for `"credential"` auth mode |
| `password` | `ARODONATA_PASSWORD`, `MGMT_PASSWORD` | `str \| None` | `None` | Administrator password for `"credential"` auth mode |
| `auth_mode` | `ARODONATA_AUTH_MODE` | `"api_key" \| "credential" \| "dynamic"` | Auto-inferred | Inferred from configured keys/credentials (`dynamic` when neither is static) |

### Timeouts, Concurrency & Rate Limiting

| Field | Env Variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `connect_timeout` | `ARODONATA_CONNECT_TIMEOUT` | `float` | `30.0` | TCP/TLS handshake timeout in seconds |
| `api_timeout` | `ARODONATA_API_TIMEOUT` | `float` | `120.0` | Per-request Management API timeout budget in seconds |
| `login_timeout` | `ARODONATA_LOGIN_TIMEOUT` | `float` | `120.0` | Timeout budget for `login` requests in seconds |
| `task_timeout` | `ARODONATA_TASK_TIMEOUT` | `float` | `900.0` | Maximum polling duration (`TaskWaiter`) for async tasks (`publish`, `show-changes`, `revert-to-revision`) |
| `rate_limit_slot_timeout` | `ARODONATA_RATE_LIMIT_SLOT_TIMEOUT` | `float` | `90.0` | Maximum wait time to acquire a per-MDS-member concurrency slot |
| `session_timeout` | `ARODONATA_SESSION_TIMEOUT` | `int` | `600` | Check Point server-side `session-timeout` requested on `login` (seconds) |
| `session_expire_seconds` | `ARODONATA_SESSION_EXPIRE_SECONDS` | `int` | `540` | Local TTL in `arodonata_sid_cache` before proactive keepalive/re-login |
| `concurrent_limit` | `ARODONATA_CONCURRENT_LIMIT` | `int` (`1..20`) | `4` | Max concurrent API requests per MDS member IP (`domain_sync_concurrency = max(1, concurrent_limit - 1)`) |
| `login_throttle_window` | `ARODONATA_LOGIN_THROTTLE_WINDOW` | `float` | `70.0` | Cooldown window (seconds) enforced by `LoginGate` when Check Point throttles logins |
| `login_max_wait` | `ARODONATA_LOGIN_MAX_WAIT` | `float` | `900.0` | Maximum total wait time across throttled login retries |

### Storage, Cache & Telemetry

| Field | Env Variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `database_url` | `ARODONATA_DATABASE_URL` | `str` | `"sqlite+aiosqlite:///:memory:"` | SQLAlchemy async database URL (`sqlite+aiosqlite:///...` or `postgresql+asyncpg://...`) |
| `sqlite_busy_timeout_ms` | `ARODONATA_SQLITE_BUSY_TIMEOUT_MS` | `int` | `30000` | SQLite `PRAGMA busy_timeout` in milliseconds (WAL mode enabled automatically on file DBs) |
| `cache_ttl` | `ARODONATA_CACHE_TTL` | `int` | `300` | Freshness window (seconds) before `"smart"` / `"smart-fast"` probes `show-last-published-session` |
| `domain_list_ttl` | `ARODONATA_DOMAIN_LIST_TTL` | `int` | `3600` | TTL (seconds) for cached MDSM `show-domains` topology (`arodonata_domains`) |
| `max_incremental_changes` | `ARODONATA_MAX_INCREMENTAL_CHANGES` | `int` | `500` | Threshold of `show-changes` entries above which `"smart-fast"` falls back to full type reload |
| `tls_trust` | `ARODONATA_TLS_TRUST` | `"pinned" \| "tofu" \| "lab-memory"` | `"tofu"` | TLS peer certificate verification mode |
| `tls_known_hosts_path` | `ARODONATA_TLS_KNOWN_HOSTS_PATH` | `str` | `~/.config/arodonata/tls_known_hosts.json` | Path to persistent `0600` JSON trust store |
| `tls_fingerprints` | `ARODONATA_TLS_FINGERPRINTS` | `str` | `""` | Comma-separated pinned SHA-256 certificate fingerprints (`host:port=SHA256:...` or bare hex) |
| `cpcrud_schema_path` | `ARODONATA_CPCRUD_SCHEMA_PATH` | `str \| None` | `None` | Optional path override for `checkpoint_ops_schema.json` |
| `trace_modules` | `ARODONATA_TRACE_MODULES` | `str` | `""` | OpenTelemetry module span gating rules (e.g. `"+arodonata.core,-arodonata.adapters.storage"`) |
| `cprid_script_mode` | `ARODONATA_CPRID_SCRIPT_MODE` | `"inline" \| "repository" \| "auto"` | `"inline"` | Execution mode for Management API `cprid` `run-script` route collection |
| `cprid_repository_script_name` | `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME` | `str` | `"arodonata-collect-routes-v1"` | Default Check Point Script Repository entry used in `"repository"` and `"auto"` modes |


---

## Configuration — Multi-Server Topology & Auth

*(source: `docs/configuration/multi-server.md`)*

# Multi-Server Topology & Authentication Modes

Arodonata v2 natively manages multiple Check Point Security Management Servers (SMS) and Multi-Domain Security Management (MDSM) clusters within a single `ArodonataClient` instance.

## 1. Positional Multi-Server Configuration

Configure multiple servers by providing comma-separated lists (or JSON arrays) in `ARODONATA_MGMT_NAMES` and `ARODONATA_MGMT_SERVERS`:

```ini
ARODONATA_MGMT_NAMES=mdsm-eu,mdsm-us,sms-dmz
ARODONATA_MGMT_SERVERS=10.10.1.10:443,10.20.1.10:443,[2001:db8::10]:443
ARODONATA_API_KEY_VARS=MDSM_EU_KEY,MDSM_US_KEY,SMS_DMZ_KEY

MDSM_EU_KEY=secret-api-key-eu
MDSM_US_KEY=secret-api-key-us
SMS_DMZ_KEY=secret-api-key-dmz
```

### Indirect Secret References (`ARODONATA_API_KEY_VARS`)

Using `ARODONATA_API_KEY_VARS` is recommended for production deployments so each server's secret key resides in its own dedicated secret environment variable rather than a combined comma-separated string.

## 2. Authentication Modes (`AuthMode`)

`ArodonataSettings` automatically determines `auth_mode` using strict precedence:

1. **`"api_key"` Mode**: Active when `api_keys`, `api_key`, or `api_key_vars` are provided. Counts of `mgmt_names`, `mgmt_servers`, and `api_keys` must match exactly.
2. **`"credential"` Mode**: Active when `username` and `password` are provided (and no explicit `api_keys` are set).
3. **`"dynamic"` Mode**: Active when no static credentials or API keys are configured in `ArodonataSettings`. Callers supply per-request credentials at runtime via `with client.auth_context(username=..., password=...):` or an injected `AuthProvider` port.

## 3. Runtime Credential & Attribution Contexts

In multi-tenant web backends (such as FPCR v2), a single long-lived `ArodonataClient` can execute operations under the logged-in administrator's identity using Python `contextvars`:

```python
with (
    client.auth_context(api_key=user_api_key),
    client.user_context(
        user_id="u-1042",
        username="alice@corp.example",
        session_name="fpcr-ticket-9812",
        session_description="Automated firewall rule provisioning",
    ),
):
    async with client.write_session("mdsm-eu", "Domain4") as ws:
        await client.add_object("mdsm-eu", "host", {"name": "h-srv-99", "ipv4-address": "10.10.99.1"}, domain="Domain4")
```

- **Credential Isolation in `arodonata_sid_cache`**: Shared read-only session keys incorporate an HMAC-SHA256 digest of the active credential (`auth_identity`), ensuring two different dynamic credentials never share a cached `sid`.


---

## Configuration — TLS Certificate Verification

*(source: `docs/configuration/tls-verification.md`)*

# TLS Certificate Verification (`TrustPolicy` & `TrustStore`)

Check Point Management and MDSM servers frequently use self-signed or internal CA certificates, and MDSM standby/member CMA IPs often present a certificate issued to the primary MDS hostname. Standard hostname-based TLS verification breaks on CMA IP routing, while disabling TLS verification (`verify_ssl=False`) exposes automation to man-in-the-middle attacks.

Arodonata v2 solves this with **post-handshake, pre-request SHA-256 DER certificate fingerprint verification** (`src/arodonata/adapters/checkpoint/tls.py`).

## How Verification Works

1. Before sending any HTTP request headers or Check Point credentials (`api-key` / `password` / `X-chkp-sid`) over an `aiohttp` connection, `ApiTransport` inspects the peer's raw DER certificate from `transport.get_extra_info("ssl_object").getpeercert(binary_form=True)`.
2. It computes the uppercase SHA-256 hex digest and validates it against `TrustPolicy` **before a single byte of HTTP payload leaves the socket**.
3. If the certificate does not match, the connection is aborted immediately with `CertificateMismatchError` or `UnknownServerCertificateError`.

## Trust Modes (`ARODONATA_TLS_TRUST`)

| Mode | Behavior | Recommended Use |
| --- | --- | --- |
| `"pinned"` | Strictly requires the server's SHA-256 fingerprint to exist in `ARODONATA_TLS_FINGERPRINTS` or `tls_known_hosts.json`. Rejects unknown certificates with `UnknownServerCertificateError`. | **Production** |
| `"tofu"` (default) | **Trust On First Use**: pins the certificate fingerprint to `~/.config/arodonata/tls_known_hosts.json` (with `0600` permissions and `fcntl.flock` cross-process locking) on first contact, and raises `CertificateMismatchError` if it ever changes. | **Staging / CLI / Standard Deployments** |
| `"lab-memory"` | Stores TOFU pins in memory for the lifetime of the process without writing to disk. Refuses to activate unless `ARODONATA_LAB` is set or explicitly configured for tests. | **CI / Ephemeral Lab Tests** |

## Cross-IP MDSM Member Recognition

On Multi-Domain servers, `show-domains` discovers domain CMA IPs and active MDS member IPs (`active_mds_ip`) that share the same physical server certificate as the primary `mgmt_ip`.

When `TrustPolicy` connects to an MDSM member IP whose certificate SHA-256 fingerprint matches an already-trusted entry in the same management cluster, it automatically recognizes and records that `(host, port)` endpoint without failing.

## Configuring Pinned Fingerprints

You can supply pinned fingerprints via environment variable:

```ini
ARODONATA_TLS_TRUST=pinned
# Host-scoped or global comma-separated SHA-256 fingerprints:
ARODONATA_TLS_FINGERPRINTS="10.10.1.10:443=SHA256:A1B2C3...,10.20.1.10:443=SHA256:D4E5F6..."
```


---

## Development — Testing & Quality Gates

*(source: `docs/development/testing.md`)*

# Testing & Quality Gates

Arodonata v2 enforces strict offline unit test coverage, static typing, linting, OpenSpec specification validation, and a 7-bucket live Check Point MDSM integration suite.

## 1. Unified Test Runner (`./pytest.sh`)

All test execution goes through `./pytest.sh`:

```bash
# Fast offline unit tests (mandatory pre-PR quality gate; zero network access)
./pytest.sh
./pytest.sh unit

# Pass extra pytest arguments (e.g. -k or specific test file)
./pytest.sh unit tests/unit/test_mcp_server.py
```

### Live Check Point MDSM/SMS Integration Buckets (`b1`..`b7`)

Live integration tests require `.env.test`, `.env.secrets`, and an optional lab overlay `.env.lab.<ARODONATA_LAB>` (e.g., `ARODONATA_LAB=home`). They acquire a non-blocking process-wide lock (`tests/integration/run_lock.py`), probe server readiness (`lab_ready.py`), and automatically snapshot and restore mutated domains via `revert-to-revision` (`cp_revision.py`).

| Command | Bucket | Scope |
| --- | --- | --- |
| `./pytest.sh int-1` | `bucket_1` | Authentication, session lifecycle, rate limiter, cached reads, search, rulebase reads, change reports |
| `./pytest.sh int-2` | `bucket_2` | Cache build, streaming sync events (`SyncProgressEvent`), live CPCRUD (`plan` / `apply` / `inverse`) |
| `./pytest.sh int-3` | `bucket_3` | `WriteSession` + `SessionOverlay`, `publish`, `discard`, `revert-to-revision`, and `70s` login throttle recovery |
| `./pytest.sh int-4` | `bucket_4` | Multi-domain isolation (`Domain4` vs `Domain5` vs `Global`) and `CacheMode` matrix (`cache`, `smart`, `smart-fast`, `force`) |
| `./pytest.sh int-5` | `bucket_5` | Full rebuilds, 120-rule layer pagination stitching, publish matrix, and session change reports |
| `./pytest.sh int-6` | `bucket_6` | Bounded soak loop (repeated `publish` → `smart-fast` → `revert` stability cycles) |
| `./pytest.sh int-7` | `bucket_7` | Live MCP server and consolidated tool surface verification |
| `./pytest.sh int-full` | `b1..b7` | Full sequential integration suite |

## 2. Mandatory Pre-Commit / Pre-PR Quality Gates

```bash
# 1. Python lint and formatting
uv run ruff check .
uv run ruff format --check .

# 2. Strict MyPy type checking (Python 3.13)
uv run mypy src

# 3. Offline unit test suite
./pytest.sh unit

# 4. Markdown linting
npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix

# 5. OpenSpec specification validation
openspec validate --specs --no-interactive
```


---

## Guides — Enterprise Replay Mock Server

*(source: `docs/guides/enterprise-replay-mock-server.md`)*

# Enterprise Raw-Replay Dataset & Standalone HTTPS Mock Server

`arodonata.testing` provides a deterministic, enterprise-scale raw Check Point Management API and Gateway CLI fixture dataset (`tests/fixtures/enterprise_raw_dataset/`), in-memory replay adapters (`FileReplayApiMock`, `FileReplayCliMock`), and a standalone/embeddable HTTPS server (`CheckPointReplayHttpServer`).

This allows downstream applications such as **MMP** and **FPCR** to point `ArodonataClient` at `localhost:443` (or any custom `host:port`) and receive 10 MDSM domains, 315 policy-enforcing gateways, 2,950+ objects (including 7-level nested groups), 1,050+ access rules, 120 NAT rules, and live gateway CLI routes via real HTTPS without requiring physical Check Point appliances or waiting for artificial rate limits / login throttling.

> **Practical Test Scenarios**: Looking for concrete source/destination IP flows across multiple gateways, pre-existing object/service reuse examples for `Evidence` verification, and planted topology discrepancies in **FPCR v2**? See [Mock Testing Scenarios & Rule Creation Guide](mock-testing-scenarios.md).

## 1. Enterprise Dataset Overview (`tests/fixtures/enterprise_raw_dataset/`)

Generated deterministically with `DEFAULT_SEED = 20261108` (`DATASET_VERSION = "1.2.0"`) via `ensure_enterprise_raw_dataset()`:

- **Domains (10 total)**: 9 user domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`.
- **Gateways & Assets (341 total assets / 315 policy-enforcing gateways, 325 CLI routing targets)**:
  - Simple gateways (`simple-gateway`), clusters (`simple-cluster` / `CpmiGatewayCluster` with `cluster-member` nodes), VSX physical chassis (`vsx-cluster` / `CpmiVsxNetobj` / `CpmiVsxSlotObj`), and VSX Virtual Systems (`virtual-system` / `CpmiVsNetobj` / `CpmiVsSlotObj`) distributed heterogeneously across every user domain (`Branch` through `Partner_DMZ`), including 15+ cross-domain VSX Virtual Systems.
  - Covers all Check Point interface topology representations (`interfaces`, `interfaces_installed`, `leads-to-internet`, `leads-to-specific-network`, `anti-spoofing-settings`, `routes_installed`).
- **Network & Service Objects (2,951 network objects, 210 services)**:
  - Hosts, networks, address ranges, DNS domains, and nested object groups up to 7 levels deep (`G_L1_*` through `G_L7_*`).
- **Policy Packages & Rulebases (1,050 access rules, 120 NAT rules)**:
  - Ordered access layers, sections, inline layers, `Global` placeholder rules, and NAT rulebases across all domains.
- **Raw Gateway CLI Routing Outputs (`cli/` & `tasks/`)**:
  - `vsx stat -l`, `ip -4 route show`, and `clish -c "show route"` covering `kernel`/`C`, `static`/`S`, `bgp`/`B`, `ospf`/`O`, `routed`/`R`, `I` IS-IS, ECMP, and cluster member drift.
  - Base64-encoded `run-script` / `show-task` payloads (`tasks/<node>__vs_<vsid>.json`) for `cprid` fallback testing.

## 2. Running the Standalone HTTPS Mock Server for MMP / FPCR

Start the HTTPS mock server from the command line:

```bash
# Run on localhost:8443 (unprivileged)
uv run python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443

# Or bind to port 443 for applications configured with default HTTPS port
sudo uv run python -m arodonata.testing.mock_server --host 127.0.0.1 --port 443
```

When started, the server automatically:

1. Generates a self-signed RSA-2048 TLS certificate and prints its SHA-256 fingerprint (`SHA256:...`).
2. Tracks `X-chkp-sid -> domain` mappings created during `POST /web_api/login` (`{"domain": "..."}`) so subsequent domain-scoped `POST /web_api/<command>` calls are routed to the right CMA domain dataset.
3. Rewrites CMA and MDS `ipv4-address` entries in `/web_api/show-domains`, `/web_api/show-global-domain`, and `/web_api/show-mdss` to the mock server's bound host (`127.0.0.1` / `localhost`), so multi-domain `ArodonataClient` connections stay on the local mock server.

### Connecting `ArodonataClient` (or MMP / FPCR) to the Mock Server

```python
from arodonata import ArodonataClient, ArodonataSettings

settings = ArodonataSettings(
    database_url="sqlite+aiosqlite:////tmp/arodonata_mock.sqlite",
    mgmt_name="mds",
    mgmt_ip="127.0.0.1",
    mgmt_port=8443,
    api_key="mock-key",
    tls_trust="tofu",
    tls_known_hosts_path="/tmp/mock_known_hosts",
)

async with ArodonataClient(settings=settings) as client:
    domains = await client.get_domains(mgmt_name="mds", include_global=True)
    await client.topology_service.refresh_topology(mgmt_name="mds", collect_routes=True)
    hops = await client.topology_service.find_affected_gateways(
        sources=["10.11.1.25"],
        destinations=["10.220.77.50"],
        mgmt_name="mds",
        cache_mode="cache",
    )
```

## 3. Using `FileReplayApiMock` and `FileReplayCliMock` in Automated Tests

For fast, zero-socket unit and scale tests, inject `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) directly into `ArodonataClient`:

```python
from arodonata import ArodonataClient, ArodonataSettings
from arodonata.testing import FileReplayApiMock, FileReplayCliMock

cli_mock = FileReplayCliMock()
api_mock = FileReplayApiMock(cli_mock=cli_mock)
settings = ArodonataSettings(
    database_url="sqlite+aiosqlite:///:memory:",
    mgmt_name="mds",
    mgmt_ip="127.0.0.1",
    mgmt_port=8443,
    api_key="mock-key",
)

async with ArodonataClient(settings=settings, api=api_mock, gateway_cli=cli_mock) as client:
    await client.topology_service.refresh_topology(mgmt_name="mds", collect_routes=True)
```

## Stateful Session Isolation, CRUD, and MDSM Emulation

Both `FileReplayApiMock` and `CheckPointReplayHttpServer` emulate stateful Check Point Management & MDSM behavior on top of the loaded dataset:

- **Per-`sid` Staging Overlays & Session Lifecycle**: Sessions opened via `login`, `/web_api/login`, or `create_dedicated_session` receive an isolated copy-on-write staging overlay and acquire per-object UID locks on modification. Supports `read-only` sessions, `set-session`, `take-over-session` (including disconnecting the prior active SID), `switch-session`, `discard`, `logout` / `logout_sid`, `publish` (with conflict-checked rebase fallback and post-publish work-session rotation), `show-session`, `show-sessions`, `show-last-published-session`, and `show-changes`.
- **Stateful Object, Service, Group & Rule CRUD**: Supports `show-*` / `add-*` / `set-*` / `delete-*` for `host`, `network`, `address-range`, `dns-domain`, `application-site`, `group`, `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, `service-other`, `service-group`, `access-rule`, `access-section`, `access-layer` (including inline layers), `https-rule`, `threat-rule`, `nat-rule`, `nat-section`, plus `show-https-rulebase`, `show-threat-rulebase`, `verify-policy`, `install-policy`, `show-unused-objects`, and `delete-unused-objects`.
- **Referential Integrity & Consistency**: Enforces Check Point deletion blocking (`generic_err_object_cannot_be_deleted` with `blocking-errors`) whenever an object or group is referenced by groups, Access rules, or NAT rules, and keeps `where-used`, `show-objects`, `show-object`, and `objects-dictionary` synchronized after every change.
- **MDSM `Global` Read/Write Protection**: `Global` objects and groups are visible across local user domains (`show-object`, `show-objects`, `where-used`, `show-access-rulebase`), while local-domain `set-*` / `delete-*` calls targeting `Global` entities are rejected with `generic_err_object_read_only`. Also supports `show-global-assignments`, `show-global-assignment`, `assign-global-assignment`, and `assign-global-policy`.
- **Stateful Script Repository & `run-script` Permissions**: Supports per-domain `add-repository-script`, `show-repository-script`, `show-repository-scripts`, `set-repository-script`, and `delete-repository-script` (isolated in uncommitted `WorkSession` overlays until `publish`), `script-type="repository"` execution with positional `args`, `read-only` session rejection, and configurable `allow_one_time_script` / `allow_repository_script` / `manage_repository_scripts` permission toggles.

## Fast Snapshot/Restore, Test Control Endpoints, and Call-Log Assertions

### In-Memory Snapshot & Reset (`ReplayStateSnapshot`)

Use `snapshot_state()` and `restore_state(snapshot)` on either `FileReplayApiMock` or `CheckPointReplayHttpServer` to isolate multi-step E2E scenarios in milliseconds without regenerating disk fixtures (capturing domain data, sessions, locks, tasks, global assignments, and `FileReplayCliMock` overrides), or call `reset()` to return to the baseline fixture state.

### Opt-In HTTP Test-Control Endpoints (`--enable-test-control`)

Programmatic `CheckPointReplayHttpServer(..., enable_test_control=True)` (default `False` in both the constructor and CLI; opt-in via `--enable-test-control`, optionally with `--test-control-token`) requires authentication on all control endpoints via either `X-Arodonata-Test-Token: <server.test_control_token>` or an active `X-chkp-sid` header, and exposes:

- `POST /__testing__/reset`: Resets all server state back to dataset baseline.
- `POST /__testing__/snapshot`: Saves a named snapshot (`{"name": "..."}`, defaults to `"default"`).
- `POST /__testing__/restore`: Restores a named snapshot (`{"name": "..."}`, defaults to `"default"`).
- `GET /__testing__/call-log`: Returns the SID-redacted `api_mock.call_log`.

### SID-Safe `call_log` & Assertion Helpers

`FileReplayApiMock.call_log` redacts raw SIDs, passwords, and API keys while recording non-secret `mgmt_name`, `domain`, `command`, `is_mutating`, `sid_ref`, `session_uid`, `read_only_session`, `payload`, `payload_summary`, `status_code`, `success`, and `error_code`. Built-in helpers:

- `get_calls(domain=..., command=..., mutating_only=...)`
- `assert_no_global_mutations()`
- `assert_no_full_object_scans(...)`
- `assert_command_called(command, domain=..., times=...)`
- `assert_command_not_called(command, domain=...)`


---

## Guides — Mock Testing Scenarios

*(source: `docs/guides/mock-testing-scenarios.md`)*

# Mock Testing Scenarios & Rule Creation Guide

Practical scenarios for testing multi-gateway rule provisioning, pre-existing object/service reuse in change evidence, and static-vs-route topology discrepancy audits against the deterministic `arodonata` enterprise replay dataset (`DATASET_VERSION = "1.2.0"`, `DEFAULT_SEED = 20261108`) and **FPCR v2**.

> **Reference Server Guide**: For standalone HTTPS mock server options, in-memory snapshots (`ReplayStateSnapshot`), and `/__testing__/*` endpoints, see [Enterprise Raw-Replay Dataset & Standalone HTTPS Mock Server](enterprise-replay-mock-server.md).

## 1. Quick Start

### Standalone `arodonata` HTTPS Mock Server

```bash
uv run python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443
```

### Full FPCR v2 Mock Environment

From the `FPCR_v2` repository root, launch the isolated `fpcr_mock` PostgreSQL database, background `arodonata.testing.mock_server` (`https://127.0.0.1:8443/web_api`, `ARODONATA_MOCK_CLI=true`), and FastAPI + React WebUI:

```bash
./run_fa_mock.sh
```

- **WebUI**: `http://localhost:8080`
- **API Docs**: `http://localhost:8080/docs`
- **Credentials**: Sign in as `admin`, `eng1`..`eng4`, or `AntonR` with any non-empty password. To test Four-Eyes approval end-to-end, stage the change as `eng1` and approve/publish as `eng2`.

## 2. Multi-Gateway Traffic Flows (Source -> Destination Examples)

Use these IP pairs to exercise multi-domain, multi-gateway path prediction in `ArodonataClient.topology_service.find_affected_gateways(...)` and **FPCR v2** (`Predict Gateways` / `fan_out_multi_gateway`).

| Scenario | Source(s) | Destination(s) | `arodonata` Gateways Matched | `FPCR_v2` Prediction Behavior |
| --- | --- | --- | --- | --- |
| **Flow A: 9-Hop Cross-Domain Chain** (`Branch` -> `DB_Seg`) | `10.11.1.10`, `10.11.1.0/24`, `10.11.1.100-10.11.1.199`, or `10.11.1.77` | `10.220.77.0/24` or `10.220.77.88` | **10 gateways** static-only / **11** with routes across **8 domains** | **Primary (4 leaf domains / 5 gateways)**: `Branch`, `Regional`, `DC_Pod`, `DB_Seg`. **Superseded supernets (4 transit domains, expandable in UI)**: `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`. |
| **Flow B: Direct `/16` Transit Core Flow** (no `/24` leaf overlap) | `10.11.200.10` | `10.220.200.50` | **5 gateways** static-only / **6** with routes across `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine` | **Primary**: `WAN_Core`, `Perimeter`, `Transit` (plus `DC_Spine` when routes are loaded), because no narrower `/24` leaf supersedes the `/16` transit networks. |
| **Flow C: Branch to Partner Extranet** (`Branch` -> `Partner_DMZ`) | `10.11.1.10` (or `10.12.1.25` VoIP with routes) | `172.30.1.50` | **9 gateways** across `Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `Partner_DMZ` (or **4 gateways** for `10.12.1.25` with routes) | **Primary**: `Branch`, `Regional`, `Partner_DMZ` (plus `lpm-matryoshka-gw` / `/16` transit entries shown under superseded/broad exclusions). |

### Hop-by-Hop Breakdown of Flow A (`10.11.1.x` -> `10.220.77.x`)

1. **`Branch`** -> `br-spb-gw-01` (`Branch_Standard_Pkg` / `Branch_Standard_Pkg Network`): `eth1` (`10.11.1.0/24`, internal) -> `eth0` (external).
2. **`Regional`** -> `reg-nw-cluster` (`Regional_Hub_Pkg` / `Regional_Hub_Pkg Network`): `eth1` (7-level nested group `G_Reg_NW_L1_Root` -> ... -> `G_Reg_NW_L7_Leaf`) -> `eth0`.
3. **`WAN_Core`** -> `wan-core-ecmp-a`, `wan-core-ecmp-b` (active ECMP), and `wan-core-bgp-standby` (`WAN_Core_Transit_Pkg` / `WAN_Core_Transit_Pkg Network`): `/16` transit `10.11.0.0/16` -> `10.220.0.0/16`.
4. **`Perimeter`** -> `perim-edge-cluster` (`Perimeter_Edge_Pkg` / `Perimeter_Edge_Pkg Network`): Global groups `G_Global_Branch_Supernet` -> `G_Global_DC_Supernet`.
5. **`Transit`** -> `ix-transit-gw-01` (`Transit_Interconnect_Pkg` / `Transit_Interconnect_Pkg Network`): `eth1` (`N_Transit_West_10_11`) -> `eth2` (`N_Transit_East_10_220`).
6. **`DC_Spine`** -> `dc-vsx-spine-vs01` (`DC_Spine_VS_Pkg` / `DC_Spine_VS_Pkg Network`): VSX `vsid=1` on `dc-vsx-chassis-01` (matched when `vs_static_route` / CLI routes are present).
7. **`DC_Pod`** -> `dc-vs-tier1-web` (`vsid=11`) and `dc-vs-tier2-app` (dynamic `vsid=12` resolved via `vsx stat -l`) (`DC_Pod_Tier_Pkg` / `DC_Pod_Tier_Pkg Network`).
8. **`DB_Seg`** -> `db-seg-internal-fw-01` (`DB_Vault_Seg_Pkg` / `DB_Vault_Seg_Pkg Network`): internal-only firewall (`eth1` `G_DB_Allowed_Clients` -> `eth2` `10.220.77.0/24`).

> **Tip**: In **FPCR v2** `Predict Gateways`, Flow A selects the narrow `/24` leaf domains (`Branch`, `Regional`, `DC_Pod`, `DB_Seg`) as **Primary** targets and places the `/16` transit core domains (`WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`) in the expandable **Superseded / Excluded** panel (`min_internal_prefix_len=16`). Check those transit entries in the Target Proposal modal or use Flow B (`10.11.200.10` -> `10.220.200.50`) to target core gateways directly.

## 3. Reusing Pre-Existing Objects & Services in Rules & `Evidence`

With `on_ip_conflict="reuse"` (default in both `arodonata.cpcrud` and **FPCR v2**), the planner matches candidate IPs, subnets, address ranges, and services against existing local-domain and `Global` objects. When a match exists under another name, the rule references the **pre-existing Check Point object name**, and the `Object Changes` section in `Evidence` records **only newly created (`NEW`) objects**.

### Pre-Existing Dataset Objects vs Unused Values

| Object Type | Raw Value / Token | Outcome (`on_ip_conflict="reuse"`) | Resolved Object Name in Rule (`Evidence`) | Scope / Notes |
| --- | --- | --- | --- | --- |
| **Host** | `10.11.1.10` | `reuse` | `H_Branch_001_Server` | `Branch` (`10.11.<b>.10` -> `H_Branch_<b:03d>_Server`, `b=1..140`) |
| **Host** | `10.121.0.2` | `reuse` | `H_Branch_AppNode_001` | `Branch` (`10.<120+d_idx>.0.2` -> `H_<Domain>_AppNode_001` for `d_idx=1..9`) |
| **Host** | `10.253.0.1` | `reuse` | `H_Global_DNS_001` | `Global` (`10.253.0.1..80` -> `H_Global_DNS_001..080`, visible in all domains) |
| **Host (new)** | `10.11.1.77` or `10.220.77.88` | `create` | `Host_10.11.1.77` / `Host_10.220.77.88` | Not in dataset; appears as `NEW` in `Object Changes` |
| **Network** | `10.11.1.0/24` | `reuse` | `N_Branch_001_LAN` (`Branch`) / `N_Reg_Branch_001_LAN` (`Regional`) | Domain-specific `/24` LAN network |
| **Network** | `10.220.77.0/24` | `reuse` in `DC_Pod` / `create` in `Branch` | `N_DC_DB_Vault_Sub` (`DC_Pod`) / `Net_10.220.77.0_24` (`Branch`) | Demonstrates cross-domain contrast in a single multi-domain RITM |
| **Network** | `10.11.0.0/16` | `reuse` | `N_Global_All_Branches` (`Global`) / `N_WAN_Branch_Agg` (`WAN_Core`) | Also `N_Transit_West_10_11` in `Transit` |
| **Address Range** | `10.11.1.100-10.11.1.199` | `reuse` | `R_Branch_001_DHCP` | `Branch` (`b=1..30`) |
| **Address Range** | `10.161.1.10-10.161.1.50` | `reuse` | `R_Branch_Pool_001` | `Branch`; pattern `10.<160+d_idx>.<1..20>.10-50` -> `R_<Domain>_Pool_001..020` (e.g. `10.167.1.10-10.167.1.50` in `DC_Pod`, `10.168.1.10-10.168.1.50` in `DB_Seg`) |
| **Address Range (new)** | `10.11.1.210-10.11.1.220` | `create` | `IPR_10.11.1.210-10.11.1.220` | Not in dataset; appears as `NEW` in `Object Changes` |
| **Service (ICMP)** | `ICMP/8` (`icmp-type: 8`) | `reuse` | `ICMP_Branch_Echo` / `ICMP_<Domain>_Echo` | Resolves raw `ICMP/8` by ICMP type to the domain's pre-existing object name |
| **Service (TCP/UDP)** | `SVC_Branch_TCP_5432`, `SVC_Branch_UDP_53`, `G_Web_Services` | `unchanged` (by name) or `reuse` (by port when requested name differs from `TCP_<port>`) | `SVC_Branch_TCP_5432` / `SVC_<Domain>_TCP_<port>` | Pre-seeded TCP ports: `22, 53, 80, 443, 1521, 3306, 5432, 6379, 8080, 8443, 9092, 9200`; UDP: `53, 123, 161, 500, 514, 1812, 4500`. Note: `Global` also defines `TCP_<port>` and `UDP_<port>`, so raw `TCP/5432` matches `TCP_5432` as `unchanged` (still zero `NEW` objects in `Object Changes`). |
| **Service (new)** | `TCP/15432` | `create` | `TCP_15432` | Not in dataset; appears as `NEW` in `Object Changes` |

### Mixed Rule Example (FPCR v2 Rule Editor)

Enter the following in an **FPCR v2** RITM rule and run **Predict Gateways** -> **Try & Verify**:

- **Source**: `10.11.1.10, 10.121.0.2, 10.11.1.0/24, 10.11.1.100-10.11.1.199, 10.161.1.10-10.161.1.50, 10.11.1.77`
- **Destination**: `10.253.0.1, 10.220.77.0/24, 10.220.77.88`
- **Service**: `ICMP/8, SVC_Branch_TCP_5432, TCP/15432`
- **Action / Track**: `Accept` / `Log`

### Mixed Rule Example (Direct `arodonata.cpcrud` Script + Evidence Output)

```python
import asyncio
import tempfile
from pathlib import Path
from arodonata import ArodonataClient, ArodonataSettings
from arodonata.reports import RenderOptions, SessionScope
from arodonata.testing import FileReplayApiMock, FileReplayCliMock, ensure_enterprise_raw_dataset


async def main() -> None:
    dataset_dir = ensure_enterprise_raw_dataset()
    cli_mock = FileReplayCliMock(dataset_dir)
    api_mock = FileReplayApiMock(dataset_dir, cli_mock=cli_mock)

    with tempfile.TemporaryDirectory() as tmp:
        settings = ArodonataSettings(
            database_url=f"sqlite+aiosqlite:///{Path(tmp) / 'mock.sqlite'}",
            mgmt_name="mds",
            mgmt_ip="127.0.0.1",
            mgmt_port=8443,
            api_key="mock-key",
        )
        async with ArodonataClient(settings=settings, api=api_mock, gateway_cli=cli_mock) as client:
            template = {
                "mgmt_name": "mds",
                "domains": [
                    {
                        "domain": "Branch",
                        "operations": [
                            {"operation": "add", "type": "host", "name": "Host_10.11.1.10", "ipv4-address": "10.11.1.10"},
                            {"operation": "add", "type": "host", "name": "Host_10.121.0.2", "ipv4-address": "10.121.0.2"},
                            {"operation": "add", "type": "network", "name": "Net_10.11.1.0_24", "subnet4": "10.11.1.0", "mask-length4": 24},
                            {
                                "operation": "add",
                                "type": "address-range",
                                "name": "IPR_10.11.1.100-10.11.1.199",
                                "ipv4-address-first": "10.11.1.100",
                                "ipv4-address-last": "10.11.1.199",
                            },
                            {
                                "operation": "add",
                                "type": "address-range",
                                "name": "IPR_10.161.1.10-10.161.1.50",
                                "ipv4-address-first": "10.161.1.10",
                                "ipv4-address-last": "10.161.1.50",
                            },
                            {"operation": "add", "type": "host", "name": "Host_10.11.1.77", "ipv4-address": "10.11.1.77"},
                            {"operation": "add", "type": "host", "name": "Host_10.253.0.1", "ipv4-address": "10.253.0.1"},
                            {"operation": "add", "type": "network", "name": "Net_10.220.77.0_24", "subnet4": "10.220.77.0", "mask-length4": 24},
                            {"operation": "add", "type": "host", "name": "Host_10.220.77.88", "ipv4-address": "10.220.77.88"},
                            {"operation": "add", "type": "service-icmp", "name": "ICMP_8", "icmp-type": 8},
                            {"operation": "add", "type": "service-tcp", "name": "Svc_PG_5432", "port": "5432"},
                            {"operation": "add", "type": "service-tcp", "name": "TCP_15432", "port": "15432"},
                            {
                                "operation": "add",
                                "type": "access-rule",
                                "layer": "Branch_Standard_Pkg Network",
                                "position": "top",
                                "name": "RITM0099001_Branch_to_Vault",
                                "enabled": True,
                                "source": [
                                    "Host_10.11.1.10",
                                    "Host_10.121.0.2",
                                    "Net_10.11.1.0_24",
                                    "IPR_10.11.1.100-10.11.1.199",
                                    "IPR_10.161.1.10-10.161.1.50",
                                    "Host_10.11.1.77",
                                ],
                                "destination": ["Host_10.253.0.1", "Net_10.220.77.0_24", "Host_10.220.77.88"],
                                "service": ["ICMP_8", "Svc_PG_5432", "TCP_15432"],
                                "rule_action": "Accept",
                                "track": {"type": "Log"},
                            },
                        ],
                    }
                ],
            }
            plan = await client.cpcrud.plan(template, on_ip_conflict="reuse")
            await client.cpcrud.apply(plan, no_publish=False, session_name="RITM0099001")
            last_pub = await client.api_call("mds", "show-last-published-session", {}, domain="Branch")
            chg = await client.collect_change_report(
                [SessionScope(mgmt_name="mds", domain="Branch", session_uids=[last_pub.data["uid"]])]
            )
            print(client.render_change_report(chg, formats=["markdown"], options=RenderOptions(title="Evidence: RITM0099001")).markdown)


asyncio.run(main())
```

How to verify object reuse in the resulting **Evidence** report:

- **Rule Changes table** displays the pre-existing object names in `Source`, `Destination`, and `Service` (`H_Branch_001_Server`, `H_Branch_AppNode_001`, `N_Branch_001_LAN`, `R_Branch_001_DHCP`, `R_Branch_Pool_001`, `H_Global_DNS_001`, `ICMP_Branch_Echo`, `SVC_Branch_TCP_5432`) alongside newly created objects (`Host_10.11.1.77`, `Net_10.220.77.0_24`, `Host_10.220.77.88`, `TCP_15432`).
- **Object Changes table** lists **only** the 4 `NEW` objects (`Host_10.11.1.77`, `Host_10.220.77.88`, `Net_10.220.77.0_24`, `TCP_15432`); reused hosts, networks, ranges, and services are absent from `Object Changes`.

## 4. Inspecting Topology Discrepancies in FPCR v2

### Where to View Discrepancies

1. **WebUI (`Topology Audit & Routes` — `http://localhost:8080/topology-audit`)**:
   - Open **Topology Audit & Routes** in the left navigation sidebar.
   - Views are cache-first on navigation: click **Refresh Static Topology** (if needed) and **Collect Live Routes (cprid)** in the top toolbar to pull simulated `ip -4 route show` / `clish -c "show route"` data from `FileReplayCliMock` and run reconciliation.
   - Inspect the four tabs:
     - **Static Diagnostics & Interfaces**: SmartConsole interface config, Anti-Spoofing mode, static health warnings (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `one_arm_topology`), and expandable `[+]` static vs live intervals per interface.
     - **Route vs Static Discrepancies**: Discrepancies grouped by `Domain` -> `Gateway` -> `Interface` (`stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, `resolved_by_routing`), with **Fix / Remediate** and **Add Exception** actions.
     - **Known Networks & Subnets**: Unified `(domain, gateway, interface, CIDR)` pairing table across static and live entries.
     - **Exceptions**: Saved `TopologyAnnotation` suppressions (`confirmed`, `standby_dynamic`, `ignore`, `manual`).
   - Use **Export CSV** (unified or 6 table presets) or **Export JSON** above the tabs to download the full reconciliation bundle.
2. **CLI (`fpcr domains reconcile`, run from `FPCR_v2`)**:

   ```bash
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile --collect-routes
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile -d Partner_DMZ -g partner-b2b-cluster --collect-routes
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile -d Transit -g anomaly-audit-gw --collect-routes
   FPCR_ENV_FILE=.env.mock uv run fpcr domains reconcile -d WAN_Core -g wan-core-bgp-standby --collect-routes
   ```

3. **REST API (`FPCR_v2`)**:
   - `GET /api/v1/domains/topology/reconcile?domain=Partner_DMZ&cache_mode=cache` (read cached report)
   - `POST /api/v1/domains/topology/reconcile` with `{"domain": "Partner_DMZ", "collect_routes": true}` (trigger live route collection and reconciliation)

### Planted Discrepancies & Diagnostics in the Mock Dataset

Across 315 policy-enforcing gateways, full reconciliation surfaces **13 static diagnostics** and **164 route-vs-static discrepancies**:

| Domain | Gateway | Interface | Code / Discrepancy Type | What It Demonstrates |
| --- | --- | --- | --- | --- |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth1` | `stale_in_topology` | `172.30.2.0/24` in SmartConsole static group, absent in live routes |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth1` | `interface_mismatch` | `172.30.3.0/24` declared on `eth1`, routed via `eth2` in live CLI |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth1` | `missing_in_topology` | `172.30.5.0/24` (OSPF) & `172.30.10.0/24` (connected) missing from SmartConsole |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth2` | `cluster_member_drift` | `172.30.6.0/24` (BGP) present only on `partner-b2b-1a`, missing on `partner-b2b-1b` |
| `Partner_DMZ` | `partner-b2b-cluster` | `eth2` | `resolved_by_routing` | `172.30.4.0/24`, `172.30.6.0/24`, `172.30.20.0/24` on `network defined by routing` |
| `Partner_DMZ` | `partner-onearm-gw-01..10` | `eth0` | `one_arm_topology` (diagnostic) | Single-interface layout relying on external fabric/PBR |
| `Transit` | `anomaly-audit-gw` | `eth0` / `eth5` | `default_route_mismatch` | `eth0` marked external, but live `0.0.0.0/0` egresses via internal `eth5` |
| `Transit` | `anomaly-audit-gw` | `eth2` / `eth3` / `eth4` | `anti_spoofing_detect_or_off`, `not_defined`, `routing_defined_without_routes` | Anti-Spoofing in `detect`, undefined topology, and dynamic routing without routes |
| `Transit` | `ix-transit-gw-02..11` | `eth1` | `missing_in_topology` | `10.81.2.0/24`..`10.81.11.0/24` (`clish` RIP routes) missing from static topology |
| `WAN_Core` | `wan-core-bgp-standby` | `eth2` | `stale_in_topology` | `10.220.0.0/16` static on `eth2`, absent from standby BGP routing table |
| `DC_Spine` | `dc-vsx-spine-vs01` | `wrp0` / `eth1.100` | `stale_in_topology` / `missing_in_topology` | `192.168.250.0/30` stale on `wrp0`; `10.220.0.0/16` BGP missing on `eth1.100` |
| `DC_Pod` | `dc-vs-tier1-web` | `eth2.11` | `missing_in_topology` | Connected `10.216.11.0/24` missing when `eth2.11` uses `specific` network |
| `DB_Seg` | `db-seg-internal-fw-01` | `eth1` | `missing_in_topology` | Connected `10.210.1.0/24` missing when `eth1` uses `specific` group |
| `Branch` | `br-spb-gw-01`, `br-reg-gw-002..140` | `eth2` | `resolved_by_routing` | `10.12.1.0/24`..`10.12.140.0/24` OSPF VoIP subnets resolved via CLI routes |


---

## Troubleshooting — Check Point API Quirks

*(source: `docs/troubleshooting/checkpoint-api-quirks.md`)*

# Check Point Management API Quirks & SDK Mitigations

Real-world Check Point Management API versions (`R80.x`, `R81.x`, `R82.x`, Management API `v1.9`–`v2.2`) exhibit undocumented or subtle server behaviors that directly shape Arodonata v2's transport, session, caching, CPCRUD, and testing architecture.

## 1. Session Lifecycle & Login Throttling

- **Login Rate-Limit Window (`70s`)**: Check Point Management servers enforce per-source login throttling (roughly once per `60s`+ window). `LoginCoordinator` tracks shared cooldown gates per server IP (`login_throttle_window=70.0`, bounded by `login_max_wait=900.0`) so concurrent tasks back off together instead of hammering the server (`REQ-SESS-006`).
- **Gated Login Exception vs. General No-Resend**: General `/web_api/<command>` calls NEVER resend after request bytes leave the socket (`request_sent=True`) to avoid duplicating non-idempotent mutations (`REQ-TRANS-007`). Login attempts inside `LoginCoordinator` are an explicit single-retry exception alongside cooldown backoff.
- **Dirty `logout` Preserves Object Locks**: Calling `logout` on a Check Point session with uncommitted changes does **not** roll back or release locks—it transitions the session to `"disconnected"` while retaining object locks. Always call `discard` (or `publish`) before `logout` (`REQ-SESS-003`, `SCN-ITEST-010-2`).
- **`take-over-session` Ownership & `application` Quirk**: Check Point exposes no pre-flight flag showing whether an external Web API SID is actively mid-request. For non-disruptive staged adoption (`force_disconnect=False`), `CPCRUDService` omits `disconnect-active-session` from `take-over-session` so active sessions are not terminated, and accepts empty `application == ""` alongside `"web_api"` and `"arodonata"` in `show-session` (`SCN-CPCRUD-011-4`).
- **Targeted `session_uid` + `take-over-session` Discard Rules**: Never sweep-discard arbitrary sessions on a shared Management Server or MDSM. Always record the workflow's exact `session_uid`, inspect its state with `show-session(uid=session_uid)`, adopt it via `take-over-session(uid=session_uid)` (omitting `disconnect-active-session` unless forced disconnect is explicitly approved), call `discard`, and then `logout` cleanly so unrelated administrators' pending changes and locks remain untouched.
- **`verify-policy` & `install-policy` Non-Publish Write-Session Requirements**: Policy verification (`verify-policy`) and installation (`install-policy`) require a write-capable (non-`read-only`) session with **zero uncommitted changes** (`changes == 0`). Always run them after `publish` finishes (and task polling completes) or from a clean write session. Both commands return asynchronous `task-id` values that must be polled via `show-task` (inspecting per-target `tasks[].task-details[]`), and callers must ensure session identifiers (`sid`) and credentials never appear in logs or reports.
- **Unauthenticated Readiness Probe**: `show-api-versions` called with `sid=None` responds either with `success=True` or `generic_err_missing_required_header`, allowing readiness probes without consuming login rate-limit slots (`SCN-ITEST-004-2`).

## 2. Clean-Session Gate, Incremental Sync & Pagination

- **Fail-Closed Dirty Session Check (`show-session`)**: Before syncing shared cache tables (`arodonata_objects`, `arodonata_services`, `arodonata_rulebase_*`), `DomainSyncCoordinator` verifies the read session has `changes == 0` via `show-session` so uncommitted session state never leaks into the shared cache (`REQ-CACHE-005`, `REQ-RULE-001`).
- **`show-changes` Time & Payload Differences**:
  - Prefer `from-session` over `from-date` (when date fallback is needed, Check Point requires UTC `Z`-suffixed ISO-8601 timestamps).
  - R82+ servers may wrap changed objects inside `{"new-object": ...}` and `{"old-object": ...}` inside `changes[]` buckets (with `added-objects`, `modified-objects`, `deleted-objects`, etc. directly under `changes[i]`, without an intermediate `.operations` object).
  - Bare deleted or modified object UIDs in `show-changes` can be backfilled from pre-change snapshots or `objects-dictionary` (`REQ-REPORT-002`).
- **Task-Based Query Commands**: Commands such as `show-changes`, `show-logs`, and `show-gateways-and-servers-task` return a `task-id` rather than direct inline items and must be polled via `show-task` (`tasks[].task-details[]`) across pagination offsets (`REQ-TRANS-006`).
- **Boundary-Swap Duplicate UIDs on Pagination**: Check Point object listings sorted with equal keys can swap two objects across page boundaries. `AMgmtClient.api_query()` detects duplicate UIDs at page seams and re-reads a small boundary window instead of restarting full scans, restarting once if `total` drifts (`REQ-TRANS-006`).

## 3. Object Listings, Services & Sentinels

- **Multi-Version `show-objects` Fallback**: Older or restricted Management API versions may return `generic_err_command_not_recognized` for universal `show-objects`. CPCRUD cold-cache lookups automatically fall back to type-scoped endpoints (`show-hosts`, `show-networks`, `show-address-ranges`, `show-services-*`) (`REQ-CPCRUD-004`).
- **Built-In ICMP Names & Non-Numeric Matching**: Built-in ICMP services such as `echo-request` cannot be found by numeric `filter="8"` queries on `show-objects`; Arodonata queries single-page `show-services-icmp` / `show-services-icmp6` directly (`REQ-CPCRUD-005`).
- **`Any` and NAT `Original` Sentinels**: Access rules start empty cells at `"Any"` (`97aeb369-9aea-11d5-bd16-0090272ccb30`), which Check Point strips automatically as soon as concrete members are added and restores when the last member is removed. NAT rules additionally normalize `"Original"` (`85c0f50f-6d8a-4528-88ab-5fb11d8fe16c`) (`REQ-CPCRUD-008`, `REQ-RULE-005`).
- **Zero-Mask Host Rules**: Gateway interfaces with `/32` (`255.255.255.255`) or unmasked points and VSX `CpmiVsxSlotObj` / `CpmiVsSlotObj` cross-domain Virtual System bindings require querying generic objects (`show-generic-objects`) beyond standard gateway listings (`REQ-CACHE-010`, `REQ-TOPO-001`).
- **`show-networks` Mask-Length Post-Filtering**: `show-networks` `filter` performs substring text matching against object names and IP strings rather than CIDR prefix-length matching (for example, `filter="10.1.0.0"` returns both `/16` and `/24` networks). Callers MUST post-filter results on exact `subnet4` and `mask-length4` (`CPObject.subnet4`, `CPObject.mask_length4`) instead of relying on server-side `filter`.
- **`dns-domain` Leading-Dot Requirement**: Check Point Management API requires `dns-domain` object names to start with a leading dot (for example, `.example.com`). Creating or looking up `example.com` without the leading dot fails or misses the object; Arodonata preserves `.example.com` in `CPObject.name` while populating `CPObject.fqdn = "example.com"`.
- **`nat-rule` Package Scoping**: NAT rulebase commands (`show-nat-rulebase`, `add-nat-rule`, `set-nat-rule`, `delete-nat-rule`) are scoped strictly by policy `package` (not by access `layer`), and apply `"Original"` / `"Any"` sentinel normalization across `original-*` and `translated-*` columns (`REQ-CPCRUD-008`, `REQ-RULE-005`).

## 4. MDSM Global Domain & Failover Semantics

- **Global Domain Routing**: Sessions to the `"Global"` MDS domain route to the active server returned by `show-global-domain` rather than treating `"Global"` as a regular CMA (`SCN-SESS-001-3`).
- **Global Read Visibility vs. Write Protection**: Local domain rulebases can reference `Global` objects (resolved in `objects-dictionary` with `domain.domain-type == "global domain"`), while local bulk listings (`show-hosts`, `show-networks`, etc.) remain domain-scoped and local CMA writes targeting `Global` entities fail with `generic_err_object_read_only` (`REQ-ITEST-014`).
- **MDSM Global vs. Local `"Network"` Layer Collisions**: Domains with an assigned Global Policy often expose two access layers both named `"Network"`—one owned by `Global` (`domain.domain-type == "global domain"`) and one owned by the local CMA. Never target `"Network"` ambiguously by bare name on such domains; disambiguate explicitly by layer `uid` or `domain.domain-type` (Arodonata raises `AmbiguousLayerName` when a bare name collides).
- **`show-global-assignments` Safeguards**:
  - Newly provisioned or unassigned local domains may return `"never_assigned"` or empty assignment lists instead of a normal assignment record—treat `"never_assigned"` as a valid unassigned baseline rather than a hard error.
  - Normalize status strings defensively across whitespace, hyphens, and case (for example, `"up to date"` vs. `"up-to-date"`, `"in progress"`, `"assigned"`).
  - Global policy assignment operations (`assign-global-assignment`, `reassign-global-assignments`) can span many CMAs on large MDSMs; budget up to `15` minutes (`900s`) for `show-task` polling before timing out.
- **Wildcard & Cross-Domain Lookups on MDS**: Unqualified lookups (`domain=None`) keep multi-domain MDS caches strictly local (`cache_mode="cache"`) to prevent costly accidental whole-MDS login storms (`REQ-CLIENT-006`, `REQ-CACHE-014`).


---

## Troubleshooting — Check Point Operations & CLI Quirks

*(source: `docs/troubleshooting/checkpoint-ops-quirks.md`)*

# Check Point Operational Automation & CLI Quirks

Operational rules and field-proven edge cases for building Check Point automation scripts on top of Arodonata v2, Gaia OS (`clish`, `python3`, `cpinfo`, `cplp`, `autoupdatercli`), Central Deployment Tool (CDT), and `arlogi`.

## 1. Asset, ClusterXL, VSX & Platform Boundaries

- **Native `Asset` Resolution vs. Platform/Role Classification**:
  - Arodonata's `Asset` model natively resolves ClusterXL (`CLUSTER_PARENT_TYPES` / `CLUSTER_MEMBER_TYPES`) and VSX (`VSX_PARENT_TYPES` / `VSX_CHILD_TYPES`) parent-child graphs, populating `parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`.
  - Deeper vendor/platform role classification (such as Maestro `MHO`/`SMO`/`SGM` roles, `MDS` vs. `MLM` management roles, or hardware family categorization) is **not** built into `Asset`; inspect `Asset.type`, `Asset.hardware`, `Asset.os_name`, and `Asset.raw_data` explicitly rather than assuming built-in role enums.
- **Documented API Types vs. `Cpmi*` Generic Objects**: Standard `show-gateways-and-servers` responses can surface simplified documented types (`simple-gateway`, `simple-cluster`, `cluster-member`), whereas `show-generic-objects` and VSX queries expose internal `Cpmi*` classes (`CpmiGatewayCluster`, `CpmiClusterMember`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, `CpmiVsSlotObj`). Always handle both sets when inspecting `Asset.type`.
- **Cluster Member Hardware Inheritance**: Cluster member objects returned by Check Point APIs frequently omit `hardware` or appliance model fields on the member itself; inherit missing hardware metadata from the parent cluster (`Asset.parent_uid`) when generating physical inventory reports.
- **Policy Targets vs. Physical Execution Targets**: Policy installation (`install-policy`) targets logical cluster or Virtual System objects, whereas on-box CLI execution (`run-script`), hotfix checks, and upgrades target physical gateways or individual cluster members (`member_uids`). Never pass a logical cluster or VS object directly to per-blade OS commands expecting a physical host response.
- **MDS Active Server vs. Single-Domain SMS**:
  - On MDSM, `DomainInfo.active_ip` resolves from `servers[].active == True` (`parse_domain_entry`); standby MDS/CMA IPs remain in `DomainInfo.standby_ips`.
  - Single-domain SmartCenter (SMS) deployments report domain `""` or `"SMC User"` in `show-domains` / session payloads; pass `domain=None` (or the configured SMS domain label) consistently.
- **Zero-Asset Failed-Scope Guard**: Never treat an empty `get_assets()` result after a failed or partially failed `refresh_assets()` (`RefreshOutcome.failed_domains` non-empty) as "zero gateways exist"—abort or report the failed domain scope before making inventory or cleanup decisions.
- **Maestro & Quantum Spark Platform Nuances**:
  - **Check Point Maestro**: Single Management Objects (`SMO`) and Security Group Members (`SGM`) use `gclish` and `asg_cp2blades` for multi-blade operations; non-interactive scripts invoked over `run-script` or SSH must source `/etc/profile.d/CP.sh` (or `$CPDIR/tmp/.CPprofile.sh`) so Check Point environment variables (`$CPDIR`, `$FWDIR`) are defined.
  - **Quantum Spark / SMB (`Gaia Embedded`)**: Runs BusyBox POSIX `sh` with a restricted CLI and **no `python3`**; any script targeting SMB appliances must avoid bashisms, GNU-only flags, and Python dependencies.

## 2. On-Box Execution (`run-script`, `ScriptRepositoryService`, Gaia `python3`, `clish`)

- **Gaia Stdlib `python3` vs. Gaia Embedded `sh`**:
  - Standard Gaia (`R81.x` / `R82+`) ships a system `python3` interpreter (`~3.9` / `$CPDIR/Python/bin/python3`) containing only Python's standard library (no third-party PyPI packages). Using stdlib `python3` (`json`, `re`, `subprocess`, `xml.etree.ElementTree`) inside `run-script` or CDT helpers avoids brittle `awk`/`sed` quoting bugs when parsing structured outputs.
  - Reserve pure POSIX `sh` for minimal bootstrap wrappers or Quantum Spark (`Gaia Embedded`) targets where `python3` is absent.
- **`ScriptRepositoryService` Mechanics**:
  - Prefer `script-type="repository"` via `ScriptRepositoryService.ensure_repository_script()` and `ScriptRepositoryService.run_repository_script()` (or `ArodonataClient`'s repository script facade methods) over one-time inline scripts in restricted RBAC environments.
  - Execution sessions used by `ScriptRepositoryService` operate cleanly without requiring a destructive `publish` of policy changes; keep repository script registration (`add-repository-script` / `set-repository-script`) separated from read-only target execution when possible.
  - Check Point encodes `run-script` output inside Base64 `responseMessage` fields (and R82+ `show-repository-script` encodes script contents in `script-body`); Arodonata's `decode_base64_task_message()` and `ScriptRepositoryService` handle this decoding automatically.
  - Omit `"args"` completely from `run-script` payloads when arguments are empty—sending `args=""` triggers RBAC permission errors on accounts that lack one-time-script execution privileges.
- **`clish` Automation Rules**:
  - Execute configuration commands line-by-line via `clish -c "<cmd>" < /dev/null` (redirecting stdin from `/dev/null` prevents `clish` from hanging on interactive prompts or consuming heredoc input).
  - Always run `clish -c "lock database override" < /dev/null` before mutating commands: treat `CLICMD0201` (already locked by the current context) as benign, but **abort immediately** on `CLINFR0771` (database locked by another active administrator/session).
  - Issue a single trailing `clish -c "save config" < /dev/null` after all `set`/`add`/`delete` commands succeed rather than saving after every line.
  - Watch for Gaia `R81.x` vs. `R82+` `clish` grammar differences (for example, NTP server syntax errors returning `CLINFR0329` and stricter multi-line MOTD/banner quoting on R82+).
  - **Never** run `clish -c "show route"` on gateways carrying large BGP/OSPF routing tables (`>10,000` routes)—`clish` serialization can stall management CPU (`confd`); use kernel `ip route` / `vtysh` or Arodonata's `TopologyService` (`collect_gateway_routes`) instead.

## 3. Software Inventory, Hotfixes & Central Deployment Tool (CDT, `sk111158`)

- **Single-Pass `cpinfo -y all`**: Run `cpinfo -y all` once and parse both `[FW1]` (major release and `Jumbo_Take`) and `[CPUpdates]` (installed hotfix bundles and Takes-less individual hotfixes) from that single output. Never invoke `cpinfo -y FW1` and `cpinfo -y CPUpdates` separately, as each invocation duplicates heavy package inspection overhead.
- **`cplp list` Live Patch Inventory**:
  - Invoke `/opt/cplp/bin/cplp list --json` (or `cplp list` with plain-text fallback when older builds lack `--json`).
  - Account for Check Point's `14`-day live patch retention/lifetime metadata when tracking temporary hotfixes that are not persisted across full Jumbo Hotfix Accumulator (JHA) upgrades.
- **`autoupdatercli show` Quirks**:
  - Parse `"repository-packages"` defensively: Check Point emits the literal string `"empty"` when no packages are present instead of an empty JSON array `[]`.
  - Parse boolean-looking fields defensively: Check Point frequently emits string literals `"true"` and `"false"` rather than JSON booleans.
- **CDT (`sk111158`) XML & CSV Constraints**:
  - Ensure all CDT pre/post/custom helper scripts carry `0700` executable permissions (`chmod 0700`) and Unix LF line endings (strip CRLF `\r\n` -> `\n` before bundling, as Windows line endings break `/bin/sh` shebangs on Gaia).
  - CDT `<execute_script>` XML elements are **non-parameterized**: pass configuration variations via distinct helper wrappers or environment/config files staged alongside the package rather than expecting parameterized XML attributes.
  - Interpret CDT script exit codes accurately: `0` means success with no reboot required, `222` means success requiring a gateway reboot/continuation step, and any other non-zero code signals failure.

## 4. Standalone CLI Lifecycle (`arodonata` SQLite Cache + `arlogi`)

- **Ephemeral `:memory:` vs. Persistent SQLite Cache**:
  - For single-shot read/check CLI scripts, omit `engine` (`engine=None`, defaulting to `sqlite+aiosqlite:///:memory:`) and wrap `ArodonataClient` in `async with` (which calls `await client.close(logout=True)` cleanly).
  - For multi-step human-in-the-loop CLI workflows (`plan` -> review -> `apply`), configure a file-backed SQLite URL (`ARODONATA_DATABASE_URL="sqlite+aiosqlite:///./state/arodonata_cache.db"`) so warm cache tables survive across invocations.
  - Never hold open SQLite write transactions across `api_call()` network I/O (`ArodonataClient` and `SqlCacheAdapter` keep DB reads/writes short and outside HTTP awaits to avoid `database is locked` contention).
- **Idiomatic `arlogi` CLI Logging**:
  - Initialize logging once at CLI startup with `arlogi.setup_logging(level="INFO", json_file_name="logs/cli.jsonl", json_file_only=False)` so human-readable logs appear on stderr/stdout while structured JSONL records are written to disk, and obtain module loggers via `arlogi.get_logger(__name__)`.
  - Pass structured metadata via keyword arguments (`logger.info("sync completed", domain=domain, count=total)`) and **never** pass `sid`, `api_key`, `password`, or raw auth headers in log messages or `extra` kwargs.


---

## Project Changelog (v2.6.7)

*(source: `docs/CHANGELOG.md`)*

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v2.6.7 (2026-11-25)

### Feat

- **topology,scripts**: zero-arg VSX repository route script and R82 parity (#101)

### Fix

- **wave-8**: remediate policy-layer, topology, asset, and emulator audit findings (#104)
- **security,cache,mcp**: wave 7 security hardening, cache integrity, and review remediation (#103)

### Refactor

- **wave-9**: unify sync/session/cpcrud pipelines, optimize hot paths, and remediate audit findings (#105)
- **testing**: decompose replay mock, CRUD engine, and dataset generator (#102)
- **cpcrud,rulebase,reports**: decompose domain engines, fix virtual overlay coherency, and unify rulebase BFS (#100)
- **mcp,security,specs**: decompose mcp/tools, harden fail-closed policy, add per-client quotas, and fix IPv6/split-brain (#99)
- **client,adapters,tls,sessions**: decompose client/adapters, fix SessionCleaner/TOFU concurrency, and harden TLS auditability (#98)
- **topology**: decompose topology_service and route_collector into topology package with SID redaction (#97)
- **core,ports,cpcrud,rulebase,testing**: unify core primitives, ISP CachePort, sentinels, and hexagonal boundaries (#96)

### Security

- **cpcrud,reports,rulebase,search**: Redacted leaked SIDs and credentials via `redact_sid(..., known_sids=...)` across `ActionResult`, `CPCRUDEvent`, `check_current_domain_head`, `_executor_pass`, and recursive `FieldDiff` (`is_sensitive_key`) / `ChangeReport` / `reports/collector` sanitization (`DA-001`, `DA-009`), escaped `[` / `]`, `![img](...)`, backticks, newlines, and Markdown table pipes in `render_safe_inline_markdown_md`, `_esc_md`, `_esc_md_code`, and `format_rules_markdown` (`DA-010`, `DA-015`), enforced an explicit `ALLOWED_QUERY_GROUP_BY_FIELDS` allowlist in `query_objects` (`DA-011`), and propagated `ServerIdentityError` in `resolve_implicit_domain_mode` (`DA-013`).
- **transport,ssrf,storage,tls**: Tightened `validate_explicit_server_ip()` to require `.issubset()` across all resolved DNS answers and return canonical pinned IPs without host re-resolution (`DA-001`), defaulted `RateLimitTimeoutError` to `phase="connect"` / `request_sent=False`, canonicalized `ConnectionPool` IPv4/IPv6/DNS keys, enforced bounded `max_response_bytes` (`67_108_864` default) streaming reads and valid TCP port bounds (`1..65535`), refused symlinked/group-writable `TrustStore` files and parent dirs while preserving `0444`/`0644` `uid=0` Kubernetes ConfigMap mounts (`VVAH-CLAUDE-05`), and created new file-backed SQLite parent directories (`0700`) and files (`0600`).
- **sessions,cleaner,scripts,routes**: Enforced fail-closed `SessionCleaner` cleanup without seeding read-write SIDs into `arodonata_sid_cache` (`DA-042`), respected explicit `SIDCacheEntry.expires_at` in `is_sid_entry_fresh()`, normalized `domain_name=normalize_domain_key(...)` unconditionally in `get_write_session()` (`DA-003`), passed `cached.domain_name` in `keepalive_sid` eviction, caught `Exception` (not `BaseException`) in `logout_sid()`, and enforced SID redaction across `ScriptTargetExecutionResult`, `RepositoryScriptExecutionOutcome`, `GatewayCliResult`, `route_executor`, and all `ScriptRepositoryService.run_repository_script()` session exception branches (`DA-011`, `VVAH-SID-01`).
- **mcp,cpcrud**: Rejected present-but-blank `Origin` headers (`origin_matches_allowed`), bound `plan_id` into `_sign_plan()`, blocked cross-caller `plan_id` overwrites, prioritized same-caller `staged_session_store` eviction (`VVAH-MCP-CPCRUD-01`), registered per-call extra dedicated SIDs via `_ACTIVE_MCP_EXTRA_SIDS` + shielded `logout_sid` + `TaskPollError(..., known_sids=...)` + `json_tool_result(..., known_sids=...)` (`DA-037`), and documented the service-account / server-wide domain visibility trust boundary in `docs/mcp/index.md`.
- **tls,sessions,testing**: Failed closed with `ValidationError` when an explicit hostname resolves to zero DNS A/AAAA records (`REQ-SESS-010`), enforced unconditional startup stale-session inspection despite cached read-only System Data SIDs (`REQ-SESS-011`), preserved hostname-bound `TrustPolicy` pinned and TOFU fingerprint verification (`identity_host` / `tls_identity_host`) across canonical IP pinning and pooled socket reuse (`REQ-SESS-012`), and aligned `FileReplayApiMock` command-name validation with `AMgmtClient` (`REQ-ITEST-007`).

### Added

- **topology,scripts,specs**: Added zero-argument self-detecting VSX route collection bundle script (`build_route_collection_repository_script()`) emitting multi-VS bundles (`===ARODONATA_VSX_BUNDLE_START===` ... `===ARODONATA_VSX_BUNDLE_END===`) with per-VS error isolation (`===ARODONATA_VS_ERROR...===`), bundle parser and slice extractor (`parse_vsx_bundle_output()`, `extract_vs_slice_from_bundle()`, `VsxBundleSlice`), and per-physical-node zero-argument CPRID bundle coalescing (`(mgmt_name, node_key)`) traced to `REQ-TOPO-008` (`SCN-TOPO-008-4`).
- **scripts,models,specs**: Added safe Base64 `"script-body"` decoding in `RepositoryScript.from_cp_dict()` with shared `_try_decode_base64_text()` heuristic, giving explicit precedence to `"script-body-base64"` over `"script-body"` and eliminating Check Point R82 false-positive outdated script drift traced to `REQ-CLIENT-010` (`SCN-CLIENT-010-4`).
- **testing,emulator,specs**: Added Check Point R82 parity in `FileReplayApiMock` (`encode_repository_script_body_base64=True`), rejection of non-empty `"args"` on repository scripts when `allow_one_time_script=False` (`HTTP 400 err_validation_failed`), synthetic zero-argument VSX bundle generation on VSX chassis nodes, and field-order-independent `list_virtual_systems()` parsing traced to `REQ-TOPO-018` (`SCN-TOPO-018-2`).
- **sessions,rate_limiter,specs**: Added principal identity logging (`username`, `user-name`, or non-secret static identifier) on login throttle cooldown events in `LoginGate` and `LoginCoordinator` traced to `REQ-SESS-006` (`SCN-SESS-006-1`).
- **mcp,security,specs**: Added `MCPToolQuotaManager` (`src/arodonata/mcp/quota.py`, `QuotaDecision`) wired into `mcp_tool_guard` (`src/arodonata/mcp/errors.py`) enforcing independent per-`client_id` sliding-window quotas (`tool_rate_limit_per_minute=120`, `live_tool_rate_limit_per_minute=30`, defaulting unauthenticated callers to `"anonymous"`, emitting `arlogi` `WARNING` logs and `arodonata.mcp_rate_limited` / `arodonata.mcp_client_id` span attributes, and returning structured `rate_limit_exceeded` JSON `ToolFailure` responses; closes SAST #6), unified `ArodonataMCPSettings.validate_security_policy()` with `allow_insecure_unauthenticated` opt-in (`ARODONATA_MCP_ALLOW_INSECURE_UNAUTHENTICATED` / `--allow-insecure-unauthenticated`), `LOOPBACK_HOSTS` / `is_loopback_host()`, `REQ-MCP-012` (`SCN-MCP-012-1`) and `SCN-MCP-001-6`..`7` in `openspec/specs/mcp-server/spec.md`, and `"mcp"` hexagonal import-boundary enforcement (`arodonata.adapters`, `arodonata.testing`) in `tests/unit/test_architecture_boundaries.py` (`SCN-CLIENT-018-1`).
- **openspec,tests**: Added `REQ-TOPO-020` (`SCN-TOPO-020-1`..`3`) in `openspec/specs/gateway-topology/spec.md` and comprehensive regression coverage in `tests/unit/test_topology_compat_and_security.py` specifying shim compatibility, boundary SID redaction, and fail-fast `ServerIdentityError` propagation across live route collection and targeted topology refresh.
- **core,ports,specs**: Added `arodonata.core.models.sentinels` (canonical Check Point built-in UIDs, token sets, and sentinel normalizers), `arodonata.core.primitives` (`UUID_RE`, `is_uuid`, `format_composite_id`, `parse_composite_id`, `normalize_str_sequence`, `MAX_IPV4_INT`, `mask_to_prefix_len`, `prefix_len_to_mask`, `effective_range_prefix_len`, `object_ipv4_bounds`, `parse_cidr_or_range_bounds`), `RulebaseRefreshPort`, and AST architectural boundary tests in `tests/unit/test_architecture_boundaries.py` traced to `REQ-CLIENT-018` (`SCN-CLIENT-018-1`..`3`).
- **ports**: Decomposed `CachePort` into eight `@runtime_checkable` Interface Segregation sub-protocols (`DomainCachePort`, `SidCachePort`, `SyncStatePort`, `ObjectCachePort`, `ServiceCachePort`, `AssetCachePort`, `TopologyCachePort`, `RulebaseCachePort`) and narrowed all core, checkpoint, CPCRUD, rulebase, and report cache consumers to the exact sub-protocols they use while preserving `CachePort` as the composite protocol.

### Changed

- **wave-9,architecture,performance**: Precomputed `_RulebaseFilterIndex` once per `filter_numbered_rulebase` call (`REQ-RULE-008`), replaced quadratic per-object emulator scans with single-pass `collect_referenced_uids()` (`REQ-ITEST-020`), unified canonical object summaries in `src/arodonata/reports/_object_summary.py` (`REQ-REPORT-007`), extracted shared typed cache sync/overlay engine `_typed_cache_sync.py` (`REQ-CACHE-018`), decomposed `search_service.py` into acyclic `core/services/search/` and extracted `_asset_linking.py` + `_domain_discovery.py` (`REQ-CACHE-018`, `REQ-SESS-013`), unified canonical `parse_domain_entry` / `parse_domain_dict` in `core/models/domains.py` and shared `open_api_write_session` lifecycle in `core/context.py` alongside `details-level="standard"` MDS fallback (`REQ-SESS-013`), and consolidated `_HybridStateReaderBase` (fixing `get_service_by_name` exact-name guard), `_DomainPlanState` single-pass step caching, `_run_on_adopted_staged_session`, `_copy_prior_fields`, and split per-type `differ.py` helpers (`REQ-CPCRUD-016`).
- **cpcrud,rulebase,reports**: Decomposed all 6 oversized domain-engine modules into cohesive, acyclic submodules (`<= 677` LOC each) while preserving exact backward-compatible imports, `arlogi.get_logger(...)` channel names, and `@traced` span parity (`cpcrud`: `state_reader.py` → `_state_reader_common.py`, `_state_reader_objects.py`, `_state_reader_services.py`; `planner.py` → `_planner_helpers.py`, `_planner_diff.py`, `_planner_entity_steps.py`, `_planner_rule_steps.py`; `executor.py` → `_executor_helpers.py`, `_executor_pass.py`, `_executor_staged.py`; `rulebase`: `refresh.py` → `collector.py`; `reports`: `collector.py` → `_collector_diffs.py`, `_collector_changes.py`; `renderer.py` → `_renderer_formatting.py`, `_renderer_html.py`, `_renderer_markdown.py`), unified `collect_package_rulebase_slice` and `collect_domain_rulebase_snapshot` over shared `_traverse_rulebase_layers` BFS traversal and `_fetch_nat_package_rules` with single-pass `_extract_package_layers_and_seeds`, and unified group/member payload metadata helpers (`_append_common_create_metadata`, `parse_existing_member_entries`).
- **testing,emulator**: Decomposed `replay_mock.py` (3,737 LOC), `_emulator_crud.py` (2,581 LOC), and `dataset_generator.py` (2,817 LOC) into cohesive, acyclic `_replay_*`, `_emulator_*`, and `_dataset_*` submodules (`<= 626` LOC each), consolidated shared projection, pagination, object-inlining, and rulebase-slicing helpers in `_emulator_projection` (`project_replay_details_level`, `project_details_level`, `paginate_items`, `inline_rule_objects`, `slice_rulebase_with_sections`), preserved all public and backward-compatible re-exports (`FileReplayApiMock`, `FileReplayCliMock`, `ReplayStateSnapshot`, `ensure_enterprise_raw_dataset`, `generate_enterprise_raw_dataset`, `_normalize_subnet_fields`), and verified byte-for-byte deterministic dataset parity.
- **mcp,core,client**: Decomposed monolithic `src/arodonata/mcp/tools.py` (2,457 LOC) into the cohesive, acyclic `src/arodonata/mcp/tools/` package (`__init__`, `_common`, `_show_object`, `objects`, `lookup`, `topology`, `rulebase`, `admin`, `cpcrud`) with every file `<= 477` LOC, full legacy helper/constant re-exports, deduplicated `RULEBASE_TYPE_TO_COMMAND` and live collection fetching, and zero `client._*` private accesses or `arodonata.adapters` imports; moved `READONLY_EXACT_COMMANDS`, `is_readonly_command`, `validate_command_name`, and `format_host_attr_for_url` into `arodonata.core.primitives` (preserving exact identity re-exports in `arodonata.adapters.checkpoint.*`); and exposed `build_validated_trust_policy` / `TrustPolicy` via `arodonata.client` plus public `resolve_api_version`, `ensure_and_load_snapshot`, and `resolve_implicit_domain_mode` methods.
- **client,search,config,boundaries**: Replaced monolithic `src/arodonata/client.py` with the cohesive, acyclic `src/arodonata/client/` package (`_base`, `warmup`, `lifecycle`, `inventory`, `rulebase_reports`, `topology`, `__init__`), moved `find_object` resolution into `SearchService.find_object()` with cache fallbacks when optional sub-services are omitted and concurrent cross-domain Pass-1/Pass-2 cache lookups, consolidated repeated database initialization checks into `_ensure_initialized()`, removed the dead `_CaptureExplicitAuthMode` validator from `ArodonataSettings` and unused internal facade aliases, added `"adapters"` hexagonal import-boundary enforcement in `tests/unit/test_architecture_boundaries.py` (`SCN-CLIENT-018-1`), and preserved exact 61 `@traced` spans, service properties, and shared `logger` identity.
- **adapters,storage,checkpoint**: Decomposed `cache_adapter.py` into `src/arodonata/adapters/storage/cache/` (`_base`, `mappers`, `rulebase_mappers`, `control`, `inventory`, `topology`, `rulebase`, `__init__`) with unified dialect upserts and removed 5 unused `*_to_record` helpers; split `sessions.py` (`response_classifiers`, `target_resolver`, `session_cleaner`, `session_credentials`, `sessions`) and `transport.py` (`connection_pool`, `connector`, `transport`) with `PolicyBoundSSLContext` validation and clean `LoginCoordinator` helper boundaries.
- **topology,services**: Decomposed `topology_service.py` and `route_collector.py` into the cohesive, acyclic `src/arodonata/core/services/topology/` package (`_shared`, `normalizer`, `objects`, `scoring`, `policy_rules`, `extractor`, `flow_matching`, `policy_matcher`, `diagnostics`, `reconciler`, `refresh`, `route_scripts`, `route_parsers`, `route_executor`, `route_collection`, `service`) while keeping `topology_service.py` and `route_collector.py` as import-compatible re-export shims for `__all__`, public helpers, formerly re-exported route helpers on `topology_service`, and exact shared `logger` identity supporting method-level monkeypatching (`topology_service.logger.warning`), removing internal `collect_gateway_routes` from `arodonata.core.services.topology.__all__`, and emitting structured `WARNING` logs alongside `DomainSyncFailedEvent` when targeted gateway topology refresh fails.
- **core,cpcrud,rulebase,mcp,testing**: Moved `parse_cp_publish_timestamp` to `core.models.common`, `SERVICE_COMMAND_TYPES` / `NON_OVERLAY_MUTATION_TARGETS` / `update_overlay_from_command` to `core.context`, and `PolicyPackageInfo` / `extract_policy_packages` to `core.models.rulebase` with 100% backward-compatible re-exports; eliminated hexagonal violations across `core`, `cpcrud`, and `rulebase`; decoupled `TopologyService` via `RulebaseRefreshPort` DI (logging a warning when omitted during cold package refresh); and migrated duplicate UUID/CSV/IPv4 helpers and `dataset_generator.py` sentinel literals to the unified core modules.

### Fixed

- **wave-9-deep-audit**: Remediated 34 Wave-9 deep-audit findings across CPCRUD (`StagedSessionInfo.baseline_readable` fail-closed publish guard + `allow_stale` propagation, single cancellation-safe `asyncio.shield(logout_sid)` cleanup, `_resolve_domain_name` `None` fallback, `groups` diffing, non-blank rule item safety, unset `install-on` normalization, clean `checkpoint_ops_schema.json`), Rulebase (`_service_matches_term` strict `proto/port` and `svc.type` matching, cycle-safe `_expand_parent_identifiers`), Sessions/MDSM (`WriteSession` exception preservation + shielded `logout_sid`, bounded stall-safe MDS pagination in `_domain_discovery.py`, `cached_domains` preservation in `validate_explicit_server_ip`, `ServerIdentityError`/`TaskError` propagation in script/route execution), Cache/Search (`SessionOverlay.apply_to_single_object` / `apply_to_single_service` isolation, empty/foreign `types` early short-circuits, `vsx-reconcile` `wait_timeout=15.0` and non-fatal `LockAcquisitionError` handling, `VSXRelationshipManager.enrich` `vsx_ref` fallback, lazy single-domain freshness checks in `find_object`, `exact_match=True` IP-range containment, shared `resolve_query_scopes` skipping `objects` on `port`/`protocol` queries, preserved `SearchService.__module__ == "arodonata.core.services.search_service"`), Emulator (`groups` filter `seed_uids`, gateway detail `leads-to-specific-network` name resolution, `delete-unused-objects` cross-session lock preflight), and documentation sync (`README.md`, `build_notebooklm_docs.py` covering 13 examples / 12 OpenSpec specs / 33 HTML pages).
- **cpcrud,reports,rulebase,topology,assets,testing**: Remediated Wave 8 policy-layer audit findings (`REQ-CPCRUD-014`, `REQ-CPCRUD-015`, `REQ-REPORT-006`, `REQ-RULE-007`, `REQ-TOPO-021`, `REQ-CACHE-017`, `REQ-ITEST-019`) across CPCRUD (`track` wire encoding per rulebase, fail-closed rule actions, `install-on` anti-Any and empty-list guards, `is_cleanup_rule` fix, offline `validate()` parity, `planned:` UID stripping in `inverse()`, staged session `logout_sid` shielding and domain-head staleness checks), Change Reports (fail-closed `RangeScope` UIDs, `OwnedSession` `sid=None` fallback, nested `old_rule_number` and dotted `rule_number` preservation, order-only `FieldDiff` suppression, inline Markdown/`_esc_md` sanitization), Rulebase (paginated `show-*-layers`, advancing zero-rule pages, `< total_reported` truncation error, empty/name-keyed `LayerPrefixLocation`), Topology (`ServerIdentityError` propagation, full-domain `routes` sync state, `(mgmt_name, domain_name, node_key)` VSX coalescing, list `next-hop` unwrapping, spaced `_VS_ERROR_RE`, `manual` export parity), Assets (`(mgmt_name, uid)` VSX keying, per-management distributed lock, `cache`/no-op skip), and `FileReplayApiMock` (per-rulebase `track` wire validation, failed `set` rollback, `read_only` `switch-session`/`discard` guards, lazy in-memory baseline snapshots).
- **cache,sync,rulebase,mcp**: Preserved in-flight domain/wildcard invalidations across `probe_domain_staleness` (`REQ-CACHE-015`) and slice sync handlers (`REQ-CACHE-016` — stamping `DomainSyncState.synced_at` at `probe.probe_started_at` and guarding `stream_ensure` / live route `_record_slice_synced` on `invalidation_at_start`), honored `cache_ttl` on single-package `refresh_package_rulebase` once slice invalidation is satisfied (`REQ-RULE-003`), kept `cache_mode="cache"` domain pre-validation free of live refreshes and quota charges (`REQ-MCP-013`), capped implicit all-domain `cache_control(action="refresh")` at `live_tool_rate_limit_per_minute` on empty live buckets while rejecting oversize explicit fan-out calls upfront with zero leaked slots (`REQ-MCP-014`), and reported `max(...)` `cache_age_seconds` across touched scopes in `query_objects` and `search_objects` (`REQ-MCP-015`).
- **cache,sync,search,models**: Replaced destructive `.discard()` domain invalidation with timestamped + monotonic-sequence slice tracking in `DomainSyncCoordinator` and `DomainListRefreshTracker.invalidate(None)`, wired `WriteSession` publish invalidation for externally injected `AMgmtClient` (`DA-002`), committed `smart-fast` incremental diffs atomically via `apply_object_diff()` / `apply_service_diff()` after `show-object` hydration (`DA-004`), normalized service type aliases/casing across SQL and `SessionOverlay` (`DA-025`), preserved `mask-length4 == 0` (`0.0.0.0/0`, `DA-023`), scoped `SessionOverlay` merges across `ObjectService`, `ServiceCacheService`, and `SearchService` (`DA-024`), fixed `SearchService.find_object()` non-default `obj_type` sync and single-pass `force` refresh (`DA-005`), preserved multi-domain `Global` UID memberships (`DA-030`), prevented non-group `CPObject`/`CPService` shadowing and cross-domain `parent_name` cluster leaks (`DA-031`), and clamped `query_objects` `limit` (`1..1000`), `offset >= 0`, and `group_by` pagination (`VVAH-SEARCH-01`).
- **mcp,quota,apiref,docs**: Honored `cache_mode="cache"` and MDS downgrades in `show_object` (`DA-044`), enforced multi-scope/composite-ID live quota and proportional bounded fan-out (`cache_control`, `change_report`, `DA-016`, `VVAH-MCP-QUOTA-01`), validated explicit domains when `mgmt_name` is omitted (`DA-045`), validated `valid_values` on `list[enum]` payloads (`DA-055`) and capped deduplicated `describe_command` batches at `<= 50` (`VVAH-APIREF-01`), and synchronized docs/specs (`arodonata_distributed_locks`, `17` tables, `SSEEvent.encode()`).
- **testing,emulator**: Remediated Wave 6 audit findings across `src/arodonata/testing/`: fixed NAT rule lock preflight when `package` is omitted (`str(None) == "None"` bypass), preserved constructor `fail_ssh_nodes` defaults across `reset()`, rotated all active SID bindings on `discard` by `uid` and rejected mutations on non-open sessions, separated `project_replay_details_level()` (`REPLAY_STANDARD_SUMMARY_KEYS` excluding `"groups"`) from deterministic `project_details_level()` (`CRUD_STANDARD_KEEP_KEYS` ordered tuple), restored `min_limit=0` pagination behavior across `_paginate_list` and `handle_show_repository_scripts` (now reusing `paginate_items()`), enforced MDS/Global domain binding on `assign-global-policy` / `assign-global-assignment`, and routed both live writes and `run-script` tasks through `mock._apply_domain_mutation()` and `mock._next_task_id()`.
- **topology,executor,coalescing**: Fixed `execute_gateway_cli()` in repository mode to return extracted per-target Virtual System slices with attached `bundle_stdout` (instead of raw chassis bundles), fail closed on missing bundle markers (`vsx_bundle_missing`) or truncated bundles (`vsx_bundle_truncated`), preserve run failure status without discarding error messages, and isolate coalesced leader cancellations via non-cancellation exceptions to protect sibling followers across independent gateways.
- **tls,platform**: Added Windows cross-process file locking via `msvcrt.locking(lock_fd, msvcrt.LK_LOCK, 1)` in `TrustStore._save_atomic()` and non-blocking `msvcrt` locks in `IntegrationRunLock`, resolving Windows platform compatibility and file contention races.
- **cpcrud,rulebase,reports**: Fixed intra-plan virtual overlay coherency in `Planner` and `HybridStateReader` so `group` and `service-group` `Outcome.UPDATE` paths record updated models (`members`, `comments`, `color`, `tags`, `new-name`, `raw_data`) in the virtual overlay, object/service updates, `DELETE` tombstones, fresh-cache `dns-domain` leading-dot lookups, and `res_map`/`Plan.name_resolutions` stay coherent across subsequent template steps (including clearing stale rename aliases upon re-creation and pruning deleted targets), same-template `CREATE -> UPDATE` / `CREATE -> DELETE` link `depends_on` and emit valid `"name"` wire identifiers instead of synthetic `"planned:"` UIDs (`REQ-CPCRUD-003` / `SCN-CPCRUD-003-6`), `Executor._stream_single_pass` routes head-freshness checks and invalidation through `Executor._check_current_domain_head` / `Executor._invalidate_domain`, `_traverse_rulebase_layers` backfills `parent_layer_uid`/`parent_rule_uid` onto queued pre-seeded inline/domain layers (`SCN-RULE-001-2`), and `_discover_target_sessions` applies `redact_sid()` / `sanitize_mapping()` across session listing errors and `RawResponse` payloads.
- **mcp,security,server**: Enforced `ArodonataMCPSettings.validate_security_policy()` across all three MCP entry points (`arodonata-mcp` CLI, `create_mcp_server()`, and `create_asgi_app()`), failing closed on wildcard `allowed_hosts`/`allowed_origins` while DNS rebinding protection is active and on unsafe `auth_mode="none"` configurations (non-loopback `host`, disabled DNS rebinding protection, non-loopback `allowed_hosts`/`allowed_origins`, wildcards, `allow_write_api`, or `cpcrud`) unless `allow_insecure_unauthenticated=True` is explicitly set (closing SAST #1, #2, and #5), bracketed IPv6 literals (`::1`, `::`, `fe80::1`) in `AuthSettings.issuer_url` via `format_host_attr_for_url()`, eliminated split-brain drift in `create_asgi_app(mcp_server=...)` (allowing matching `settings` parity while rejecting conflicts and `trust_policy` overrides), ensured CLI exits cleanly with code `2` on factory errors with single `SECURITY WARNING` emission and managed client disposal, fixed `collect_known_sids()` to inspect active dedicated SIDs via `ArodonataClient.get_active_dedicated_sids()` and retained closed dedicated SIDs for `api_call` redaction, isolated per-caller (`client_id[:user_id]`) CPCRUD plan signatures / stores / staged sessions with automatic discard+logout on eviction, charged cold/stale `smart` syncs, domain-miss refreshes, and live fallbacks to `live` quota once per call via `MCPToolQuotaManager.check_and_consume_live_only()`, mapped invalid ISO-8601 dates in `change_report` to actionable `ToolFailure`, protected structured `ToolFailure` core JSON keys, and restored forwarding `_ensure_and_load_snapshot` / `_resolve_implicit_domain_mode` wrappers on `CachedRulebaseSource` and `SearchService`.
- **tls,security**: Bound `FingerprintTCPConnector` `SSLContext` creation explicitly to validated `TrustPolicy` via `PolicyBoundSSLContext` (`TrustPolicy.create_ssl_context()`, `create_verified_ssl_context()`, and upfront `TrustPolicy` validation in `FingerprintTCPConnector`, removing unreferenced `_DEFAULT_CHECKPOINT_SSL_CONTEXT`), prevented failed concurrent TOFU merges or disk write errors in `TrustStore.record()` / `_save_atomic()` from poisoning in-memory `_entries`, added structured `arlogi` `WARNING` audit logs on first-contact TOFU and `lab-memory` acceptance (`event="tls_tofu_first_contact"`) plus `ERROR`/`WARNING` logs on certificate mismatch/rejection/missing cert, and recorded `arodonata.tls_decision` span attributes (including `"stored_match"` for legacy known-hosts entries) via `span_attrs()` (`SCN-TRANS-002-6`, closing SAST #3 and #4).
- **sessions,client**: Prevented unbounded recursion in `LoginCoordinator` max-sessions recovery (`allow_max_sessions_cleanup=False` on `SessionCleaner` logins plus per-management `_cleaning_max_sessions` guard), preserved live fresh cached SIDs across all principals and domains regardless of `seed_system_sid` while logging out (`logout_sid`) and evicting only the active principal's expired cached SIDs, and eliminated the duplicate `invalidate_domain()` call when publishing via `ArodonataClient.api_call()`.
- **topology,scripts,security**: Enforced regex-based `redact_sid()` at Pydantic model boundaries (`GatewayCliResult`, `GatewayRouteCollectionStatus`, `DomainSyncState.last_error`, `RefreshOutcome.failed_domains`, `SyncProgressEvent.error`, `DomainSyncFailedEvent`, `ScriptTargetExecutionResult`, and `RepositoryScriptExecutionOutcome`), threaded `known_sids` through `ScriptRepositoryService.run_repository_script()` (covering internally opened `arodonata-run-repo-script` sessions as well as injected getters), scrubbed SSH-only and `_vs_error=` `GatewayCliResult` paths, scrubbed targeted refresh `WARNING` logs, propagated fatal `ServerIdentityError` fail-fast (with `asyncio.TaskGroup` sibling cancellation and clean dedicated-session logout, without downgrading domain `routes` sync states) across both targeted gateway topology refresh (`_stream_targeted_gateway_refresh`) and live route collection (`execute_gateway_cli`, `collect_gateway_routes`, `AutoScriptModeResolver`), and restored legacy `cprid` fallback error formatting when an injected `gateway_cli` callback returns `None`.
- **testing,sentinels**: Resolved UID `6c488338-8eec-4103-ad21-cd461ac2c476` misclassification in the replay emulator by removing `DROP_UID_ALT` and mapping it canonically to `Policy Targets` (`type="Global"`), matching Check Point Management API semantics (`6c488338-8eec-4103-ad21-cd461ac2c473` remains `Drop`), and switched `_normalize_action` / `_normalize_track` to validate strictly against `ACTION_UID_TO_NAME` / `TRACK_UID_TO_NAME`.
- **cpcrud,primitives**: Implemented single-pass contiguous netmask validation in `mask_to_prefix_len` (supporting integral floats such as `24.0` and explicit `allow_hostmask` / `allow_prefix_int` flags) and added `strict=True` validation in `normalize_mask_length` for desired CPCRUD network specs so invalid `mask_length4` or `subnet_mask` values raise `ValidationError` instead of being silently dropped.

## v2.6.6 (2026-11-19)

### Fix

- **core,cpcrud,mcp,reports,specs**: adopt traceable OpenSpec schema, resolve Phase 1b audit findings, and achieve 100% spec coverage (#94)

### Added

- **openspec,tests**: Forked minimal `arodonata` OpenSpec schema (`openspec/schemas/arodonata/`) enforcing `REQ-<DOM>-<NNN>` and `SCN-<DOM>-<NNN>-<K>` scenario traceability across all 12 domain specifications (`132` requirements, `284` scenarios), registered `@pytest.mark.spec(...)` in `pyproject.toml`, added `scripts/check_spec_traceability.py` with `tests/unit/test_check_spec_traceability.py` and `.github/workflows/specs.yml`, and achieved 100% scenario test coverage (`0` untested baseline scenarios) via `tests/spec/`.
- **reports**: Added symmetric per-object `Field Diffs` Markdown column support alongside rule `Field Diffs` in `render_change_report()`.
- **docs**: Synchronized `docs/architecture/` documentation with `v2.6.5`, added `docs/examples/13-gateway-topology-matching.md`, and documented Check Point Management Web API quirks and workarounds in `docs/troubleshooting/checkpoint-api-quirks.md`.

### Fixed

- **security,sessions,telemetry**: Validated explicit `server_ip` via `resolve_target_ips()` and enforced resolved MDS rate-limit slots in `LoginCoordinator.logout_sid()` and cache-hit `get_readonly_session()` (`FC-01`), and added recursive `sanitize_mapping` / sequence / `bytes` redaction in `core/telemetry.py` (`span_attrs`, `_coerce_span_value`) so credentials and session tokens never leak into OpenTelemetry spans (`FC-02`).
- **client,mcp,search,cpcrud,topology,testing**: Determined ephemeral database cleanup on close from the actual SQLAlchemy engine URL in `ArodonataClient.close()` and `AMgmtClient.close()` (`FC-03`), auto-upgraded cold `list_domains(cache_mode="cache")` (`FC-04`), normalized mixed-case canonical `group_by` fields in `SearchService.query_objects()` (`FC-05`), diffed existing auto-named entities under `on_ip_conflict="create_new"` in `Planner` (`FC-06`), completed audit findings `FC-07`–`FC-12` (including synthetic `show-task` log status codes in `FileReplayApiMock`), and removed the dead `live_compat` configuration flag.

## v2.6.5 (2026-11-18)

### Feat

- **scripts,topology,testing**: add Check Point Script Repository service, route modes, and emulator (#92)
- **cpcrud,reports,config**: add incremental rule/URL diffs, naming profiles, and dry-run plan reports (#91)

### Added

- **config,cpcrud**: Extended `NamingPrefixes` (`src/arodonata/core/config.py`, re-exported in `arodonata.cpcrud.models`) with `range_separator`, `compress_range_same_subnet`, `group_suffix`, `app_site`, `app_site_wildcard_marker`, `format_group()`, and `format_app_site()`, and wired `ArodonataSettings.cpcrud_naming_prefixes` (`ARODONATA_CPCRUD_*` and fallback `CPCRUD_*` environment variables without implicit `.env` loading) as the default profile in `CPCRUDService` and `Planner`.
- **cpcrud**: Added `arodonata.cpcrud.expressions` (`parse_object_expression`, `parse_range_token`, `parse_app_site_expression`, `parse_service_expression`, `parse_group_expression`, `expand_group_expression`, `normalize_wildcard_domain`, `wildcard_domain_to_cp_regex_urls`) for pure shorthand parsing of hosts, CIDRs, compressed same-`/24` ranges, `.domain` DNS objects, `*domain`/`*.domain` Check Point regex `application-site` specs, services, and recursive nested inline groups.
- **cpcrud,testing**: Added `{"add": [...], "remove": [...]}` incremental patch support in `checkpoint_ops_schema.json`, `FieldChange` (`added_items`, `removed_items`), `differ.py` (`application-site.url-list` and Access/HTTPS/Threat/NAT rule cells `source`, `destination`, `service`, `protected-scope`, `site-category`, `install-on`), `Planner` (`depends_on` ordering, UID dereferencing in `_build_prior_rule_state`, case-folded non-regex `url-list` value reuse via `normalize_app_site_url_key`), `inverse.py` rule rename rollback, and `FileReplayApiMock` (`_emulator_crud.py`, `_emulator_changes.py`).
- **reports,client**: Added offline Dry-Run `ChangeReport` synthesis via `build_change_report_from_plan()` (`src/arodonata/reports/plan_report.py`, re-exported via `arodonata.reports`, `arodonata`, and `ArodonataClient.build_change_report_from_plan`) for pre-session HTML, Markdown, and JSON previews via `render_change_report()`.
- **scripts,client**: Added application-agnostic Check Point Script Repository support via `ScriptRepositoryService` (`src/arodonata/core/services/script_service.py`), models and normalized body helpers (`CpridScriptMode`, `RepositoryScript`, `RepositoryScriptStatus`, `EnsureRepositoryScriptResult`, `ScriptTargetExecutionResult`, `RepositoryScriptExecutionOutcome` in `arodonata.core.models.scripts`), typed SID-redacted exceptions and shared classifiers (`RepositoryScriptError`, `RepositoryScriptNotFoundError`, `RepositoryScriptPermissionError`, `is_script_permission_error`, `is_unsupported_script_command_error` in `arodonata.core.errors`), and `@traced` `ArodonataClient` methods (`get_repository_script`, `list_repository_scripts`, `check_repository_script`, `ensure_repository_script`, `delete_repository_script`, `run_repository_script`) with `"repository-script"`, `"api-key"`, `"md-permissions-profile"`, and `"domain-permissions-profile"` excluded from `SessionOverlay` (`NON_OVERLAY_MUTATION_TARGETS`).
- **config,topology,testing**: Added `ArodonataSettings.cprid_script_mode` (`"inline" | "repository" | "auto"`, default `"inline"`, env `ARODONATA_CPRID_SCRIPT_MODE`) and `cprid_repository_script_name` (`ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME`, default `"arodonata-collect-routes-v1"`), canonical parameterized bash route-collection script (`build_route_collection_repository_script()`, `format_route_collection_repository_args()`), single-flight `AutoScriptModeResolver` `"auto"` probing without semaphore starvation, `check_route_collection_script()` / `ensure_route_collection_script()` helpers, fail-closed `GatewayRouteCollectionStatus.error_code` reporting, stateful per-domain `repository-script` CRUD and permission emulation in `FileReplayApiMock`, and gated live lifecycle integration test `tests/integration/b3/test_repository_scripts_live.py`.

### Fixed

- **cpcrud**: Enforced fail-closed `Outcome.ERROR` / `DiffSafetyError` invariants preventing unsafe `"Any"` widening (blocking removals that empty rule cells or `application-site.url-list` without `application-signature`, requiring explicit `"Any"` removal when narrowing `"Any"` cells while stripping `"Any"` from Check Point wire `remove`, blocking incremental `{"add": ["Any"]}`, rejecting `set`/`update` targeting missing entities, rejecting unmatched rules carrying `{add, remove}` cell deltas under any verb, and preserving `rule_number` positional renames under `strict_name`).
- **context,scripts**: Consolidated `SYSTEM_DOMAIN_KEY`, `normalize_domain_key()`, and shared `open_api_write_session()` in `arodonata.core.context` so `ScriptRepositoryService`, `DomainService`, `LoginCoordinator`, and `ArodonataClient.write_session()` share identical `"System Data"` scoping without cross-domain `WriteSession` bleed on `domain=None`, and restored lenient UTF-8 / control-character Base64 task decoding (`decode_base64_task_message`).

## v2.6.4 (2026-11-16)

### Feat

- **testing**: expand replay dataset v1.2.0 with heterogeneous domain gateways (#88)
- **testing,cpcrud**: add replay policy verification, inline layers, and staged session discard (#87)

### Added

- **testing**: Upgraded `dataset_generator.py` and `tests/fixtures/enterprise_raw_dataset/` to `DATASET_VERSION = "1.2.0"` (`341` total domain assets, `315` policy-enforcing gateways, `325` CLI routing targets), adding `+7` standalone `simple-gateway` appliances, `+7` `CpmiGatewayCluster` HA clusters (`14` cluster members), `+4` `CpmiVsxNetobj` VSX chassis hosts, and `+25` local and cross-domain `CpmiVsNetobj` Virtual Systems with unique per-domain gateway/interface IPs and Virtual System internal `/24` subnets and complete `CpmiVsxSlotObj` / `CpmiVsSlotObj` coverage across all VSX chassis hosts so every user MDSM domain (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) exercises heterogeneous appliance, cluster, Virtual System, and cross-domain VSX topologies.
- **testing**: Extended `FileReplayApiMock` (`_emulator_crud.py`, `_emulator_models.py`, `replay_mock.py`) with `verify-policy` and `install-policy` task simulation, `access-layer` / inline-layer CRUD (`add-access-layer`, `set-access-layer`, `delete-access-layer`, `show-access-layer`), and `show-https-rulebase` / `show-threat-rulebase` (`https-rule`, `threat-rule`) CRUD and `where-used` resolution (#87).

### Fixed

- **cpcrud,client**: Propagated `ArodonataClient.logout_sid()` notifications through `CPCRUDService.notify_sid_logged_out()` and `Executor.notify_sid_logged_out()` so `StagedSessionInfo.clear_sid()` clears logged-out SIDs while preserving session provenance for external `publish` or `discard` adoption (#87).

## v2.6.3 (2026-11-14)

### Feat

- **testing,cpcrud**: add stateful Check Point replay emulator and MDSM session lifecycle (#85)

### Added

- **testing**: Extended `FileReplayApiMock` and `CheckPointReplayHttpServer` (`src/arodonata/testing/_emulator_models.py`, `_emulator_crud.py`, `_emulator_changes.py`, `replay_mock.py`, `mock_server.py`) into a stateful Check Point Management and MDSM replay emulator supporting per-`sid` staging overlays, read-your-own-writes isolation, read-only session enforcement, cross-session object locking (`generic_err_object_locked`), `set-session`, `take-over-session`, `switch-session`, `publish`, `discard`, `logout`, and structured `show-changes` deltas.
- **testing**: Implemented stateful CRUD, bidirectional group membership maintenance, Check Point uniqueness checks, and referential integrity validation (`generic_err_object_cannot_be_deleted`) across hosts, networks, address ranges, DNS domains, application sites, groups, TCP/UDP/ICMP/ICMPv6/other services, service groups, `show-unused-objects` / `delete-unused-objects`, and Access/NAT rules and sections with automatic `rule-number`, section bounds, `objects-dictionary`, and `where-used` recomputation.
- **testing**: Added MDSM `Global` domain visibility for local reads, local write protection (`generic_err_object_read_only`), and `assign-global-assignment` / `assign-global-policy` task emulation, and upgraded `dataset_generator.py` to `DATASET_VERSION = "1.1.0"` with `mds/show-global-assignments.json` and deterministic `Global` references in Access rule `#104`.
- **testing**: Added fast in-memory state management (`ReplayStateSnapshot`, `snapshot_state()`, `restore_state()`, `reset()`), SID-redacted `call_log` records, and test assertion helpers (`get_calls()`, `assert_no_global_mutations()`, `assert_no_full_object_scans()`, `assert_command_called()`, `assert_command_not_called()`), plus comprehensive E2E test suites and updated documentation in `docs/guides/enterprise-replay-mock-server.md`.

### Fixed

- **cpcrud**: Updated `Executor._extract_published_session_uid()` and shared `_resolve_session_uid()` in `src/arodonata/cpcrud/executor.py` to extract published session UIDs from `show-task` `task-details[].revision` and `publishResponse` payloads without redundant pre-publish `show-session` round-trips.

### Security

- **testing**: Gated `CheckPointReplayHttpServer` `/__testing__/*` control endpoints behind opt-in `enable_test_control=False` (`--enable-test-control`) and `X-Arodonata-Test-Token` / active `X-chkp-sid` authentication, enforced domain session pinning on `FileReplayApiMock`, and verified zero raw SID or credential leakage across `call_log` entries and OpenTelemetry spans.

## v2.6.2 (2026-11-14)

### Fix

- **search,mcp,testing**: normalize Cpmi asset aliases, group_by aliases, and replay where-used (#83)

### Added

- **models,testing**: Added `ASSET_TYPE_EQUIVALENTS`, `QUERY_GROUP_BY_ALIASES`, `expand_asset_type()`, and `expand_asset_types()` in `arodonata.core.models`, and implemented `where-used` (direct and indirect groups, access control rules, NAT rules via `show-packages`, and `System Data` package metadata) plus `use-object-dictionary=False` inline object dictionary expansion and layer/package UID lookup in `arodonata.testing.replay_mock.FileReplayApiMock`.

### Fixed

- **search,assets,mcp**: Expanded `Cpmi*` internal Check Point asset type aliases (`CpmiGatewayPlain` <-> `simple-gateway`, `CpmiGatewayCluster` <-> `simple-cluster`, `CpmiClusterMember` / `CpmiVsxClusterMember` <-> `cluster-member` / `vsx-cluster-member`, `CpmiVsxNetobj` / `CpmiVsxClusterNetobj` <-> `vsx-gateway` / `vsx-cluster`, `CpmiVsNetobj` / `CpmiVsClusterNetobj` <-> `virtual-system` / `vs-netobj`, `CpmiHostCkp` <-> `checkpoint-host`) across `SqlCacheAdapter.get_assets()`, `AssetRefreshService.get_assets()`, `SearchService.search_objects()`, `SearchService.query_objects()`, and MCP `list_assets`, and mapped `query_objects` `group_by` aliases (`domain` -> `domain_name`, `mgmt` / `server` / `management` -> `mgmt_name`, `object_type` / `asset_type` / `service_type` -> `type`, `orig_domain` -> `original_domain`) so grouped results preserve domain/server metadata and emit both requested alias keys and canonical column keys.

## v2.6.1 (2026-11-13)

### Fix

- **transport,sessions**: pool dedicated-session keep-alive sockets and harden lifecycle (#81)

### Changed

- **transport,sessions**: Reuse fingerprint-verified keep-alive HTTPS connections across sequential non-boundary commands within dedicated sessions (`WriteSession` / explicit `sid`) via non-reversible SHA-256 `session_scope`, while isolating shared read-only `show-*` pooling and enforcing `Connection: close` on session-boundary and un-scoped mutating commands.
- **transport**: Use a pre-built lightweight TLS 1.2+ `SSLContext` without disk CA bundle loads for fingerprint-verified Check Point connections.

### Fixed

- **transport**: Prevent `aiohttp.ServerDisconnectedError` (`0`-byte EOF) caused by stale idle pooled sockets and Check Point `httpd2` `MaxKeepAliveRequests` (`100`) exhaustion by evicting matching idle sockets before non-pooled or fresh session handshakes, rotating pooled sockets at `95` requests in `FingerprintTCPConnector`, and closing session-scoped sockets on `logout_sid`.

## v2.6.0 (2026-11-13)

### Feat

- **sync,rulebase,topology,cpcrud**: add lightweight package catalog, targeted lookups, and unreachable server resilience (#79)

### Added

- Lightweight Policy Package Catalog & Targeted Single-Package Rulebase Synchronization (`RulebaseRefreshService`, `CachedRulebaseSource`, `CachePort`, `SqlCacheAdapter`, `ArodonataClient`):
  - Added `RulebaseRefreshService.refresh_policy_packages()` and `ArodonataClient.refresh_policy_packages()` (`scope="rulebase"`, `item_type="packages"`), synchronizing `PolicyPackageInfo` metadata via `show-packages` and `CachePort.replace_domain_rulebase_packages()` without downloading NAT, HTTPS, threat-prevention, or access rulebases when `get_policy_packages(..., cache_mode="smart")` runs on a cold domain.
  - Added `RulebaseRefreshService.refresh_package_rulebase()` and `ArodonataClient.refresh_package_rulebase()` (`scope="rulebase"`, `item_type="package:<rulebase_type>:<package_uid>"`), synchronizing only the target package's catalog metadata, ordered layers for the requested `rulebase_type`, Global placeholder expansions, and referenced inline sub-layers via `CachePort.upsert_domain_rulebase_layers()` without stamping `item_type="*"` or fetching sibling packages, while keeping `locate_rules()` gated on a full `item_type="*"` domain snapshot.
- Single-Flight Background Cache Warm-Up Status & Static Topology Candidate Filtering (`ArodonataClient`, `WarmupStatusEntry`, `TopologyService`, `STATIC_TOPOLOGY_SOURCES`):
  - Coalesced concurrent `ArodonataClient.start_object_cache_warmup()` calls by `(mgmt_name, domains, types, include_global, include_services, force)`, suppressed unretrieved `asyncio.Task` exception warnings for fire-and-forget callers with SID-redacted structured warning logs, and added `ArodonataClient.get_warmup_status()` returning `WarmupStatusEntry` (`running`, `completed`, `failed`, `cancelled`).
  - Added `STATIC_TOPOLOGY_SOURCES`, `source_types: Sequence[TopologySourceType] | None = None`, and `include_annotations: bool = True` parameters to `TopologyService.find_affected_gateways()` and `ArodonataClient.find_affected_gateways()` so callers can restrict candidate matching to static SmartConsole topology intervals without mutating cached route or annotation rows.
- Check Point `show-objects` Replay Support (`FileReplayApiMock`): Implemented `show-objects` (`type`, `filter`, `ip-only`, `details-level`, `limit`, `offset`) across `objects_raw.json`, `services_raw.json`, and `gateways_and_servers.json` in `arodonata.testing.replay_mock.FileReplayApiMock`.

### Changed

- Replaced full-domain `DEFAULT_OBJECT_TYPES` (`show-hosts`, `show-dns-domains`) refreshes during cold `TopologyService.refresh_topology()` and `stream_refresh_topology()` with targeted on-demand `show-objects` / `show-group` / `show-object` resolution across the target domain and `"Global"` persisted via `CachePort.upsert_objects()` without stamping whole-domain `"objects"` sync slices, while re-validating cached groups/objects whenever `"objects"` sync states lag behind a newer domain `publish` (`src/arodonata/core/services/topology_service.py`).
- Switched cold-cache CPCRUD value-conflict lookups (`find_host_by_ip`, `find_network_by_subnet`, `find_range_by_bounds`, `find_tcp_udp_service` in `HybridStateReader`) to targeted `show-objects` queries with exact attribute verification, intra-plan virtual overlays, and `generic_err_command_not_recognized` fallback instead of paginating full-domain `show-hosts`, `show-networks`, or `show-services-tcp` / `show-services-udp`, while retaining single-page `show-services-icmp` / `show-services-icmp6` listing for `find_icmp_service` (`src/arodonata/cpcrud/state_reader.py`).

### Fixed

- Hardened multi-server (`mgmt_name=None`) domain discovery and scoped synchronization against unreachable management servers (`DomainService.get_domains()`, `DomainSyncCoordinator`, `LoginCoordinator`): caught transport/authentication errors during `show-domains` discovery and pagination without redundant RBAC `details-level="standard"` retries on transport failure or pointless MDS self-failover, continued syncing reachable management servers while recording unreachable servers in `RefreshOutcome.failed_domains`, and suppressed unrelated server failures when all explicit `domains` resolved on reachable servers.
- Refined `SearchService.search_objects()` and `ObjectService` so `exact_match=True` excludes wider containing supernets on IPv4/CIDR queries, mixed `types=["host", "network", "gateway"]` filters strip non-object types before `ObjectService` API calls while refreshing and matching gateway/VSX assets from `arodonata_assets`, and asset-only `search_objects(..., max_depth > 0)` still loads group hierarchy nodes (`src/arodonata/core/services/search_service.py`, `src/arodonata/core/services/object_service.py`).
- Updated MCP listing/search and `query_objects(..., aggregate="describe")` cold-cache handling (`src/arodonata/mcp/tools.py`) to report `cache_age_seconds: null` when no `synced_at` timestamp exists, search across all configured `mgmt_names` when `mgmt_name` is omitted, and auto-upgrade `cache_mode="cache"` to `"smart"` whenever a scope has `0` sync state stamps (including when `arodonata_objects` holds only partial topology-hydrated rows).

## v2.5.0 (2026-11-11)

### Feat

- **testing,topology**: add enterprise raw-replay scale suite and HTTPS mock server (#76)
- **topology**: add policy/NAT topology inference, VPN domain extraction, and policy reconciliation (#75)
- **topology**: add route collection, reconciliation, annotations, and confidence scoring (#73)

### Fix

- **sync,topology**: batch Core cache writes, serialize VSX route CLI, and harden single-flight locks (#77)
- **sessions**: fail fast on unreachable login transport and suppress startup cleanup tracebacks (#74)

### Added

- Gateway Topology Diagnostics, Live Route Collection via SSH Dependency Injection & `cprid` Fallback, Static-vs-Route Reconciliation, Persistent Administrator Annotations, IPAM Prefix Export, and Evidence Delta Confidence Scoring (`arodonata.core.models.topology`, `arodonata.core.services.route_collector`, `arodonata.core.services.topology_service`, `arodonata.adapters.storage`, `ArodonataClient`, `arodonata.mcp.tools`):
  - **Static Topology Health Diagnostics (`get_topology_diagnostics()`)**: Detects incomplete or untrustworthy SmartConsole interface topology settings (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`, `no_interfaces`) while treating internal-only segmentation gateways as valid (zero warnings) and classifying single-interface or external-only service-graph gateways (e.g., Cisco ACI) as `one_arm_topology` (`severity="info"`).
  - **Live OS/Clish Route Collection (`collect_gateway_routes()`, `GatewayCliPort`, `GatewayCliCallable`)**: Collects live IPv4 routing tables (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`, and `0.0.0.0/0` default routes) across simple gateways, cluster members (detecting cross-member route drift), and VSX Virtual Systems (via `vsenv` context switching on the physical VSX parent, `$FWDIR` `CTX%05d` verification, and dynamic `vsx stat -l` VSID lookup), invoking an injected SSH bash callback first and falling back to Check Point Management API `run-script` (`cprid` via `TaskWaiter`).
  - **Targeted Per-Gateway Refresh**: `refresh_topology(..., gateways=..., collect_routes=...)`, `stream_refresh_topology(..., gateways=..., collect_routes=...)`, and `CachePort.replace_domain_topology(..., gateway_uids=..., source_types=..., active_gateway_uids=...)` refresh and replace cached topology/route rows for specific gateways without re-downloading or deleting other gateways in the domain while pruning orphaned live routes on full domain refresh.
  - **Static vs. Live Route Reconciliation (`reconcile_gateway_topology()`)**: Compares SmartConsole static topology intervals against live CLI-collected routing intervals and across cluster members to report `TopologyReconciliationReport` discrepancies (`stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, `resolved_by_routing`).
  - **Persistent Administrator Annotations & IPAM Export (`arodonata_topology_annotations`, `upsert_topology_annotations()`, `get_topology_annotations()`, `delete_topology_annotations()`, `export_topology_prefixes()`)**: Persists administrator dispositions (`confirmed`, `standby_dynamic`, `ignore`, `manual`), `trust_static_topology` overrides, and IPAM metadata (`zone`, `site`, `comment`, `custom_metadata`) across topology resyncs and exports consolidated prefix inventories.
  - **Evidence Delta Confidence Scoring (`TopologyConfidenceWeights`, `ConfidenceDelta`)**: Computes endpoint and flow `confidence` (`0.0..1.0`), `is_standby_path`, and `confidence_factors` on `TrafficFlowMatch` and `AffectedGatewayCandidate` (with `min_confidence` and `include_standby` filters on `find_affected_gateways()` and MCP `locate_gateways`).
  - **Stage 2 Policy & NAT Topology Inference, VPN Encryption Domain Extraction, and Policy-vs-Topology Reconciliation**:
    - Extracts gateway and cluster `vpn-domain` (`encryption-domain`) references (honoring `vpn-domain-type`), recursively expands referenced network/group objects into `arodonata_gateway_topology` (`source_type="vpn_domain"`), and applies `vpn_encryption_domain` (`+0.45`) in confidence scoring.
    - Evaluates cached installed Access Control (`arodonata_rulebase_access_rule`) and NAT (`arodonata_rulebase_nat_rule` `original` and `translated`) rules in `find_affected_gateways(..., include_policy_inferred: bool = True)` and MCP `locate_gateways(..., include_policy_inferred: bool = True)`, awarding `+policy_rule_evidence` (`+0.25`) to cross-interface L3 candidates and discovering one-arm (e.g., Cisco ACI service-graph) and incomplete-topology gateways with `match_type="policy_inferred"`.
    - Adds `check_policy: bool = False` to `reconcile_gateway_topology()` (`TopologyService` and `ArodonataClient`) to detect `policy_topology_mismatch` discrepancies when enabled Access or NAT rules explicitly targeting a gateway via `install_on` have no explicit source or destination intervals overlapping that gateway's internal topology or routes.
- Enterprise Raw-Replay Topology Scale Suite, File-Backed Check Point API/CLI Replay Doubles, and Standalone HTTPS Mock Server for Downstream Applications (`arodonata.testing`, `tests/fixtures/enterprise_raw_dataset/`, `tests/unit/test_topology_raw_replay_scale.py`, `docs/guides/enterprise-replay-mock-server.md`):
  - **Deterministic Enterprise Raw Dataset & Generator (`ensure_enterprise_raw_dataset()`, `generate_enterprise_raw_dataset()`)**: Fixed-seed (`20261108`) generator producing raw Check Point Management API JSON files and gateway CLI routing outputs across 9 MDSM user domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global` (284 total assets / 276 policy-enforcing gateways, 2,951 network objects with 7-level nested groups, 210 services, 1,050 access rules, 120 NAT rules, and 279 CLI routing targets).
  - **File-Backed Replay Adapters (`FileReplayApiMock`, `FileReplayCliMock`)**: Full `ApiPort` and `GatewayCliPort` implementations reading raw fixtures from disk with pagination (`limit`, `offset`, `from`, `to`, `total`), `details-level` (`uid`, `standard`, `full`), `uid`/`name` and `class-name` filtering, `run-script` + `show-task` Base64 task execution, VSX `vsenv` / `vsx stat -l` / `CTX%05d` bash validation, per-domain/per-command/per-node call counters, and in-memory mutation helpers for targeted refresh testing.
  - **Standalone & Embeddable Check Point HTTPS Mock Server (`CheckPointReplayHttpServer`, `python -m arodonata.testing.mock_server`)**: `aiohttp.web` HTTPS server serving `POST /web_api/{command}` with auto-generated self-signed TLS certificates, `/web_api/login` credential validation, domain-bound `X-chkp-sid` session tracking, and dynamic CMA/MDS `ipv4-address` host rewriting in `/web_api/show-domains` so external applications (MMP, FPCR) can point `ArodonataClient` at `localhost:<port>` (`8443` or `443`) without hardware appliances or artificial rate limits.
  - **Smart Route Collection Caching & Per-Domain `cprid` Session Reuse (`TopologyService`, `execute_gateway_cli`)**: `refresh_topology(..., collect_routes=True, mode="smart")` now skips redundant SSH/`cprid` route collection for unchanged domains whose `DomainSyncState(scope="topology", item_type="routes", status="ok")` is within `cache_ttl` (while retrying domains with partial gateway failures), and `collect_gateway_routes()` reuses at most one dedicated `run-script` session per `(mgmt_name, domain_name)`.
- Configurable Domain Sync & Route Collection Concurrency Knobs and Lightweight Rulebase Package Queries (`ArodonataSettings`, `CachePort.get_domain_rulebase_packages`, `SqlCacheAdapter`, `CachedRulebaseSource`):
  - Added `domain_sync_concurrency` (`ARODONATA_DOMAIN_SYNC_CONCURRENCY`, auto-default `min(2, max(1, concurrent_limit - 1))`), `route_collect_concurrency` (`ARODONATA_ROUTE_COLLECT_CONCURRENCY`, auto-default `min(4, max(1, concurrent_limit // 2))`), and `max_routes_per_gateway` (`ARODONATA_MAX_ROUTES_PER_GATEWAY`, default `50000`) on `ArodonataSettings`.
  - Added `CachePort.get_domain_rulebase_packages()` (`SqlCacheAdapter.get_domain_rulebase_packages`) to load `package_layers` and distinct NAT package metadata without reading full rule tables during topology extraction, route collection, and `CachedRulebaseSource.get_policy_packages()`.

### Changed

- Replaced per-row SQLModel ORM `session.add()` writes across `SqlCacheAdapter.replace_domain_objects()`, `replace_domain_services()`, `replace_domain_assets()`, `replace_domain_topology()`, and all seven `replace_domain_rulebase()` tables with chunked SQLAlchemy Core multi-row `INSERT` batches (`_insert_rows_batched`, `_BATCH_ROWS = 500`) and direct `_*_to_row` dictionary builders to eliminate ORM identity-map memory spikes on large Check Point domains (`src/arodonata/adapters/storage/cache_adapter.py`).
- Moved cross-domain VSX parent/child reconciliation (`AssetRefreshService._reconcile_cross_domain_vsx`) from per-domain sync handlers to once per refresh run with a `finally:` fallback so early `stream_refresh_assets()` disconnects or mid-run exceptions still reconcile committed domains (`src/arodonata/core/services/asset_service.py`).

### Fixed

- Shared per-MDS domain sync semaphores and `(mgmt_name, domain_name, scope)` single-flight coalescing process-wide across coordinators attached to the same database engine (weakly keyed per `AbstractEventLoop`), while reusing the caller's active MDS permit via `ContextVar` on nested re-entrant `DomainSyncCoordinator.ensure()` calls so empty-cache asset lookups inside `TopologyService._sync_domain_topology()` cannot deadlock (`src/arodonata/core/services/sync_coordinator.py`).
- Serialized gateway CLI/`cprid` route collection per physical `node_uid` before acquiring the per-management concurrency slot so multiple VSX Virtual Systems sharing one `VS0` chassis execute sequentially without starving independent gateways, coalesced identical concurrent `refresh_topology()` and `collect_gateway_routes()` calls while preserving waiter `CancelledError` (`asyncio.timeout`), capped collected routes in a single `ip -4 route show` `awk` pass (skipping `clish -c "show route"` above `10,000` kernel routes), and emitted truncation warnings strictly when routes are dropped beyond `max_routes_per_gateway` (`src/arodonata/core/services/topology_service.py`, `src/arodonata/core/services/route_collector.py`).
- Failed fast on unreachable management login transport errors without redundant retries and suppressed noisy startup session-cleanup tracebacks (`src/arodonata/adapters/checkpoint/sessions.py`).

## v2.4.1 (2026-11-05)

### Added

- Streaming gateway topology refresh progress (`TopologyService.stream_refresh_topology()` and `ArodonataClient.stream_refresh_topology()`), yielding `DomainSyncProgressEvent` items across `"assets"`, `"objects"`, and `"topology"` phases along with per-gateway `gateway-topology` progress events carrying `gateway_uid`, `gateway_name`, `gateway_type`, `installed_access_policy`, and `interval_count` (`src/arodonata/core/services/topology_service.py`, `src/arodonata/client.py`).

### Fixed

- Resolved each gateway's single active policy package (`installed_access_policy` and single-element `policy_packages`) in `TopologyService._resolve_gateway_installed_policy()` by explicit `policy.access-policy-name` (when `access-policy-installed` is truthy), latest installation timestamp across `installation-targets-revision` / `access-policy-installation-date`, single-package `installation-targets` membership, or single-package domain fallback rather than assigning all domain packages to every gateway in multi-package domains (`src/arodonata/core/services/topology_service.py`, `src/arodonata/core/models/topology.py`).
- Parsed Check Point `"leads-to-specific-network"` interface topology dictionaries (with inline `subnet4`/`mask-length4` fallback) in `_normalize_interface()` and CPMI `destination`/`nextHop`/`interfaceName` static route objects in `_parse_route_destination()` / `_parse_route_nexthop_and_interface()` (`src/arodonata/core/services/topology_service.py`).
- Evicted cached read-only session SIDs (`arodonata_sid_cache`) immediately upon `ApiTimeoutError` or `TransportError` in `AMgmtClient.api_call()`, and allowed `DomainSyncCoordinator.probe_domain_staleness()` to recover transiently failed sync state rows (`status="failed"` with matching `last_published_at` / `last_session_uid` and `object_count > 0`) back to `status="ok"` without forcing a full domain re-download (`src/arodonata/adapters/checkpoint/client.py`, `src/arodonata/core/services/sync_coordinator.py`).

### Fix

- **topology**: resolve single installed gateway policy, stream refresh progress, and parse leads-to-specific-network (#71)
- **sync,sessions**: evict cached SID on transport/read timeout and recover transient failed sync states (#70)

## v2.4.0 (2026-11-04)

### Feat

- **topology,sync**: add matched endpoints on gateway candidates and structured sync/session logging (#68)

### Added

- Per-gateway filtered `matched_sources` and `matched_destinations` on `AffectedGatewayCandidate` (`arodonata.core.models.topology`, `arodonata.core.services.topology_service`, `ArodonataClient.find_affected_gateways`, and MCP `locate_gateways`): `TopologyService.find_affected_gateways()` now populates `matched_sources: list[str]` and `matched_destinations: list[str]` on each returned `AffectedGatewayCandidate` with the deduplicated caller query strings from that gateway's cross-interface `matched_flows` (`src_interface != dst_interface` and not `external == external`), strictly preserving the caller's input order from `sources` and `destinations`.
- Structured `arlogi` operational logging and RBAC `show-domains` fallback (`arodonata.core.services.sync_coordinator`, `arodonata.core.services.domain_service`, `arodonata.adapters.checkpoint.rate_limiter`, `arodonata.adapters.checkpoint.sessions`): `DomainSyncCoordinator` emits structured `DEBUG` logs on sync start, per-domain progress, and completion and `WARNING` logs on domain sync failure; `DomainService` emits structured `DEBUG`/`WARNING` logs during domain discovery and retries `show-domains` with `details-level="standard"` when `details-level="full"` is rejected by Check Point RBAC while preserving previously cached CMA `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`; and `LoginGate`, `LoginCoordinator`, and `SessionCleaner` emit structured `WARNING` logs on login throttle/read-timeout cooldowns and `DEBUG` logs on active CMA IP failover resolution, max-sessions cleanup triggers, and stale session discards.

## v2.3.0 (2026-11-03)

### Feat

- **topology**: add gateway interface topology cache and candidate matching (#65)
- **cpcrud,cache**: support Check Point application-site objects and access-rule negate flags (#62)
- **api-reference,mcp**: bundle multi-version API schema index and unified api_reference tool (#61)

### Fix

- **audit**: remediate findings R1-R10 from audit 2611022007 (#64)
- **cpcrud**: allow same-creator WEB_API staged session adoption and discard adopt helper session (#63)
- **reports**: log system_objects_filtered at DEBUG instead of emitting ReportWarning (#60)

### Added

- Gateway Interface Topology Cache & Candidate Policy-Enforcing Gateway Matching (`arodonata.core.models.topology`, `arodonata.core.services.topology_service`, `arodonata.core.services.asset_service`, `arodonata.adapters.storage`, `ArodonataClient`, `arodonata.mcp.tools`, `examples/13_gateway_topology_matching.py`): SQL-backed `arodonata_gateway_topology` table (`GatewayTopologyRecord` / `GatewayTopologyEntry` with 64-bit integer IPv4 bounds `ip_first_int` / `ip_last_int`), cross-domain VSX slot reconciliation (`CpmiVsxSlotObj` and `CpmiVsSlotObj` linking tenant `CpmiVsNetobj` Virtual Systems via `targetCustomer` to their physical VSX parent gateway/cluster and merging `interfaces_installed` and `routes_installed`), `TopologyService` (`refresh_topology()`, `stream_refresh_topology()`, `get_gateway_topology()`, `summarize_gateway_interfaces()`, and `find_affected_gateways()`), `ArodonataClient` facade methods, and MCP `locate_gateways` tool and `cache_control(scope="topology")` support — resolving IPv4 addresses, CIDRs, ranges, and domain-scoped Check Point object/group names across connected subnets, recursive `specific-network` groups, VS static routes, and external interfaces while excluding physical cluster members, VS0 chassis, non-firewall hosts, `external_to_external` transits, and same-interface (`src_interface == dst_interface`) flows.
- Check Point `application-site` (`application-site`, `application-site-category`, `application-site-group`) support across `ServiceCacheService`, `HybridStateReader`, `SearchService`, `CachedRulebaseSource`, `CPCRUD`, and MCP tools (`arodonata.core.services.service_cache_service`, `arodonata.cpcrud`, `arodonata.rulebase`, `arodonata.mcp.tools`), plus `source-negate`, `destination-negate`, and `service-negate` boolean flags on CPCRUD `access-rule` operations (`checkpoint_ops_schema.json`, `Planner`, `Differ`, `Executor`, `inverse()`).
- Bundled multi-version Check Point API Reference & Offline Payload Validation Engine (`arodonata.api_reference`, `ArodonataClient`, `arodonata.mcp.tools`): packaged `cp_api_index.json.gz` (~395 KB compressed, covering 1,161 Management `v1.9`..`v2.2` and Gaia `v2.0.1` commands, 724 shared nested objects, and 430 enums) with lazy in-memory `ApiReferenceEngine` (`get_api_reference()`, `search_api_commands()`, `describe_api_command()` for single or batch command names with dynamic version filtering, and `validate_api_payload()` checking unknown/version-unsupported commands and fields, required parameters, mutually exclusive `field_alternatives`, types, and enum `valid_values`), `ArodonataClient` facade helpers with automatic `api_version` inference per `mgmt_name`, and the unified MCP `api_reference(action="search" | "describe" | "validate")` tool and `lookup_api_command` prompt.

### Changed

- Replaced the user-facing `system_objects_filtered` `ReportWarning` in `collect_change_report()` with a structured `DEBUG`-level log entry via `arlogi` (`src/arodonata/reports/collector.py`, `openspec/specs/change-reports/spec.md`) so routine filtering of background Check Point `"System"` maintenance objects does not clutter rendered HTML/Markdown evidence reports.

### Fixed

- CPCRUD staged-session cross-process adoption provenance and detached `arodonata-cpcrud-adopt` helper session cleanup (`arodonata.cpcrud.executor`, `arodonata.cpcrud.service`, `arodonata.client`): `Executor._adopt_staged_session()` now inspects `show-session {}` on the fresh helper session before takeover to obtain both `initial_uid` and the authenticated administrator's `user-name`, permits adopting custom-named `WEB_API` staged sessions (such as MMP `[ant]-MMP_Rules-...`) owned by the same administrator after a process restart or across workers/CLI while still refusing human `SmartConsole` GUI sessions and other administrators' sessions by default, accepts optional `expected_session_name: str | None = None` (`403 session_name_mismatch` on mismatch) and `allow_foreign: bool = False` across `publish_staged_session()`, `stream_publish_staged_session()`, and `discard_staged_session()`, and immediately calls `discard {"uid": initial_uid}` after `take-over-session` / `switch-session` so no empty `arodonata-cpcrud-adopt` helper session remains open on Check Point.

## v2.2.0 (2026-10-31)

### Feat

- **reports**: synthesize snapshot field diffs and style HTML evidence like SmartConsole (#58)

### Added

- Snapshot-based `FieldDiff` synthesis, pre-change bare-UID resolution, `"System"` maintenance noise filtering, and SmartConsole-styled inline diff rendering (`arodonata.reports`, `arodonata.mcp.tools`): `collect_change_report()` now synthesizes `FieldDiff` entries (`old_value`, `new_value`, `added_items`, `removed_items`) directly from `old-object` and `new-object` snapshots whenever explicit `field-changes` are absent or partial (avoiding false-positive rule diffs when an unchanged referenced group has internal member edits), recursively harvests `{uid, name}` dictionaries across `old-object` and `new-object` and resolves bare UUIDs appearing only in `old-object` or `track` (such as removed `group.members` or `track.type`) via `CachePort` and bounded `show-object` lookups, populates structured `ObjectChangeEntry.summary_fields` and enriched `ObjectChangeEntry.summary` (`ipv6-address`, `subnet4/mask-length4`, `subnet6/mask-length6`, `address-range` bounds, `members`, `comments`), and excludes non-deleted background Check Point `"System"` maintenance non-rule objects by default (`RenderOptions.include_system_objects: bool = False`, also exposed on the `change_report` MCP tool) while emitting a `system_objects_filtered` `ReportWarning` (`details={"filtered_count": ...}`) and preserving `ChangeReport.raw_responses`; `apply_session_rule_placement()` groups rules by `(package, rulebase_type, layer)` before sorting in ascending SmartConsole order; and `render_change_report()` renders SmartConsole-styled HTML tables (dark-blue `#253245` headers, full-width pale-yellow `#eee8aa` access section banner rows `▾ <section_name> (<section_range>)`, shaded `No.` column, `Track` column in both HTML and Markdown, and `Accept`/`Drop` action indicators) with inline cell-level removed/added/before-after diffs (including composite `subnet4=net/mask` and `range=first-last` diffs) in both HTML and Markdown.

## v2.1.1 (2026-10-30)

### Fix

- **reports**: support post-publish OwnedSession placement, cold-cache fallback, and cross-domain lookups (#56)

### Security

- Explicit `server_ip` trust validation and MCP staged-session boundary hardening (`arodonata.adapters.checkpoint.sessions`, `arodonata.cpcrud.executor`, `arodonata.mcp.tools`): `LoginCoordinator.resolve_target_ips()` and `LoginCoordinator.create_dedicated_session()` now verify that any caller-supplied `server_ip` belongs to the configured management host or cached `DomainInfo` IPs (`active_ip`, `active_mds_ip`, `standby_ips`, `servers`) before opening a socket, raising `ValidationError` on untrusted destinations; and MCP `cpcrud_staged_session` resolves target domain endpoints internally rather than accepting an unverified `server_ip` argument.

### Fixed

- Post-publish `OwnedSession` live rulebase numbering, object-only session placement short-circuit, cold-cache live published rulebase fallback, and bare `layer_uid` resolution (`arodonata.reports`): `apply_session_rule_placement()` now accepts a clean post-publish `OwnedSession` (`state == "published"` or `published_at is not None` with `changes == 0`, `locks == 0`, `number-of-published-changes == 0`, and matching domain) to read the published rulebase live via `sid` without emitting `owned_session_not_used` and best-effort warm `CachePort.replace_domain_rulebase()` alongside `arodonata_domain_sync_state` (`numbering_source = "live_published"`, `numbering_basis = "Numbering read live after publish at <time> UTC"` derived from `session_report.publish_time`, skipping cache overwrite if a concurrent refresh advanced `arodonata_domain_sync_state`); short-circuits immediately when `session_report.rule_changes` is empty (`numbering_source = "not_applicable"`, `numbering_basis = ""`) while omitting `.basis-banner` and `- **Numbering Basis**:` in HTML and Markdown renderers; falls back to a single-fetch read-only `collect_domain_rulebase_snapshot()` + cache warm when the local SQL rulebase cache is cold (`numbering_source = "live_published"`, `numbering_basis = "Numbering read live from published rulebase at <time> UTC"`); and resolves bare UUID `layer` references on rule changes via cache and bounded `show-object` lookups into top-level `RuleChangeEntry.layer_name`.
- Cross-domain cache-first `domain=None` lookups and ambiguity detection (`arodonata.core.errors`, `arodonata.client`, `arodonata.core.services.search_service`, `arodonata.mcp.tools`): `ArodonataClient.find_object()`, `SearchService.get_group_members()`, and MCP `show_object` / `get_group_members` now enforce `cache_mode="cache"` and `include_global=True` when `domain` is omitted (preventing multi-domain network refresh storms), reject blank/whitespace targets with `ValidationError`, raise `AmbiguousObjectError` in the Python SDK when multiple domains match, and return `match_type="ambiguous"` with candidate objects in MCP tools.
- `LoginGate` inter-login spacing without distributed lock starvation, post-revert read-only session recovery, and CPCRUD staged session takeover cleanup (`arodonata.adapters.checkpoint.rate_limiter`, `arodonata.adapters.checkpoint.sessions`, `arodonata.adapters.checkpoint.client`, `arodonata.cpcrud.executor`): `LoginGate.acquire()` now releases the cross-process `login_gate:{mds_ip}` distributed lock immediately after recording `mark_login_attempt` and sleeps `login_attempt_spacing` outside the distributed lock; `is_session_expired_result()` classifies `show-session` (without `uid`) returning `generic_err_object_not_found` after `revert-to-revision` as an expired session so `AMgmtClient.api_call()` automatically evicts the wiped SID and re-authenticates; and `Executor._adopt_staged_session()` passes `{"uid": session_uid, "disconnect-active-session": True}` to `take-over-session` with fallback to `switch-session` (`{"uid": session_uid}`) while logging out the initial dedicated session on exit.

## v2.1.0 (2026-10-26)

### Feat

- **cache,docs**: add human-readable composite IDs and v2 documentation (#53)

### Fix

- **docs**: fix pymdownx.snippets syntax across example pages (#54)

### Added

- Human-readable composite identifiers (`object_id`, `service_id`, `asset_id`) and dual UID/human-readable topology links (`arodonata.core.models`, `arodonata.adapters.storage`, `arodonata.core.services`, `arodonata.client`, `arodonata.mcp`): non-unique indexed `object_id = "{mgmt_name}:{domain_name}:{name}"` on `CPObject` / `CPObjectRecord` (`arodonata_objects`), `service_id = "{mgmt_name}:{domain_name}:{name}"` on `CPService` / `CPServiceRecord` (`arodonata_services`), and `asset_id = "{mgmt_name}:{domain_name}:{name}"` on `Asset` / `AssetRecord` (`arodonata_assets`) alongside UID primary keys `id = "{mgmt_name}:{domain_name}:{uid}"`; `id`, `object_id`, and `parent_object_ids` on `GroupMembershipNode` in `SearchResult.memberships`; `parent_id`, `parent_asset_id`, `member_asset_ids`, and `virtual_system_asset_ids` on `Asset` / `AssetRecord` with cross-domain VSX gateway/cluster to Virtual System reconciliation across domains on the same management server; and composite identifier support across `find_object()`, `get_group_members()`, `search_objects()`, `query_objects()`, and MCP tools (`show_object`, `list_assets`, `get_group_members`, `query_objects`).
- Complete MkDocs Material documentation site (`docs/`, `mkdocs.yml`, `.github/workflows/docs.yml`), portable standalone HTML guide (`docs/_html/arodonata-v2-docs.html`), and NotebookLM knowledge bundles (`docs-notebooklm/01..04.md`).

## v2.0.0 (2026-10-26)

### Feat

- **mcp**: consolidate MCP tool surface into cache-aligned catalog (#9)
- **sdk**: live integration tests (b1..b7), SDK examples (01..12), and host-app integration hardening (#8)
- **mcp**: implement Streamable-HTTP MCP server, CLI, security guards, and tool surface (Milestone 6) (#7)
- **cpcrud**: implement declarative Policy-as-Code CPCRUD engine (#6)
- **rulebase,reports**: implement rulebase introspection, numbering, and change reports (#5)
- **sync**: implement core sync/search services and ArodonataClient facade (#4)
- **checkpoint**: implement native aiohttp transport, TLS verification, and session lifecycle (#3)
- **core,storage**: implement milestone 1 core foundation and sql storage adapters (#2)

### Security

- Comprehensive security and specification conformance remediation (`audit-remediation-261025` across `arodonata.adapters`, `arodonata.core`, `arodonata.cpcrud`, `arodonata.rulebase`, and `arodonata.mcp`): strict Web API command-name validation (`^[a-z0-9]+(-[a-z0-9]+)*$`), disabled HTTP redirects (`allow_redirects=False`) and ambient proxies (`trust_env=False`), and phase-classified `TransportError` (`connect` vs `post-send`) preventing post-write request resends on failover; cross-process `fcntl.flock` locking, `0600` permission enforcement, and IPv6 `[host]:port` key normalization in `TrustStore`; full secret and `database_url` password masking across `ArodonataSettings`/`ArodonataMCPSettings` and recursive secret/SID redaction across nested collections and exception chains; `arodonata_` prefix on all 15 SQLModel tables with positive v1 column fingerprint checks (`mdm_dmn`, `mgmt_dmn_key`), cross-worker serialized migration locks (`pg_advisory_xact_lock` / `BEGIN IMMEDIATE`), atomic single-transaction cache + sync-state commits, dialect `ON CONFLICT` upserts, and owner-verified distributed lock renewal heartbeats; HMAC-SHA256 credential-bound `arodonata_sid_cache` keys, `LoginGate` self-deadlock elimination and inter-login spacing, Arodonata-only `SessionCleaner` filtering (`changes == 0` and `locks == 0`), and strict prohibition of mutating commands on the shared read-only `arodonata_sid_cache` session; CPCRUD `(object_type, operation)` command allowlisting, per-plan `HybridStateReader` isolation, pre-publish head drift re-verification, and report-verified `inverse()` generation; and MCP read-only command allowlisting, HMAC-SHA256 signed `cpcrud_plan` verification in `cpcrud_apply`/`cpcrud_inverse`, `cpcrud_staged_session` tool, base64-safe 32-char minimum static token parsing with SHA-256 `hmac.compare_digest`, and fail-closed `jwt` authentication.

### Added

- Consolidated cache-aligned MCP tool surface (`arodonata.mcp`, `arodonata.core.services`, `arodonata.client`): 13 base tools (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object` with 3-tier exact/anchored-wildcard/substring matching across objects, services, assets, and rulebase layers, `search_objects`, `get_group_members` expanding network groups, service groups, and cluster/VSX child assets, `query_objects` with `aggregate="list" | "count" | "describe"`, `show_rulebase`, `locate_rules`, `change_report`, `cache_control`, and `api_call`) plus 5 opt-in CPCRUD tools (`cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_staged_session`) and multi-table `ArodonataClient.find_object`.
- Host application integration hardening (`arodonata.adapters.storage`, `arodonata.core.services`, `arodonata.cpcrud`, `arodonata.rulebase`): `to_naive_utc()` helper and uniform naive UTC timestamps (`DateTime(timezone=False)`, `tzinfo=None`) across all database tables, domain models, and Check Point timestamp parsers; `ARODONATA_TABLE_NAMES` namespace isolation and `arodonata_assets` table rename (preventing collision with host application `assets` tables and ignoring non-Arodonata tables in `SQLModel.metadata`); savepoint-wrapped (`begin_nested()`) multi-worker schema evolution with automatic `DROP` + `CREATE` recovery for incompatible legacy v1 cache tables (`domains`, `sid_cache`, `arodonata_schema_version`); `exact_match: bool = False` in `SearchService.search_objects()`, `ArodonataClient.search_objects()`, and MCP `search_objects`; staged session finalization (`publish_staged_session`, `stream_publish_staged_session`, `discard_staged_session`) on `CPCRUDService` and `ArodonataClient` via `take-over-session` (`uid=session_uid`); and `rule_to_cpcrud_operation()` with `output_format="cpcrud"` support in `filter_rulebase()` for exporting cached rules into schema-valid CPCRUD operations.
- Live Check Point MDSM/SMS integration test harness (`tests/integration/`, `openspec/specs/integration-testing-and-examples/spec.md`), `./pytest.sh` test runner (`unit`, `int-1`..`int-7`, `int-full` with `-v` enabled by default), and 12 progressive runnable SDK examples (`examples/01..12`, `examples/_session_guard.py`, `examples/crud_example.yaml`, `examples/README.md`, `examples/README_CRUD.md`): layered lab environment loader (`tests/integration/lab_env.py` supporting `ARODONATA_LAB=<profile>`), non-blocking process-wide `fcntl.flock` run lock (`tests/integration/run_lock.py`), live API readiness probe (`tests/integration/lab_ready.py`), crash-safe domain revision snapshot and `revert-to-revision` baseline recovery (`tests/integration/cp_revision.py` and `restore_baseline.py`), standalone diagnostic utilities (`probe_lab_domains.py`, `probe_login_throttle.py`, `lab_build.py`), 60 live integration tests across 7 buckets (`b1` auth/sessions/reads/search/rate-limiting, `b2` cache build & CPCRUD live operations, `b3` publish/revert & 70s login throttle recovery, `b4` cache mode matrix & multi-domain isolation, `b5` full rebuild/120-rule pagination/rulebase session refresh/publish matrix/change reports, `b6` bounded soak loop, `b7` MCP server & tools), top-level re-exports (`Asset`, `CPObject`, `CPService`, `DomainInfo`, `RefreshOutcome`, `SearchResult`), `ArodonataClient.cleanup_server_sessions()`, and `otel` optional dependency group (`arodonata[otel]`).
- Streamable-HTTP MCP server and standalone CLI (`arodonata.mcp`, `arodonata[mcp]`, `arodonata-mcp`): `ArodonataMCPSettings` (`ARODONATA_MCP_*` configuration with secret-safe `__repr__` and standalone startup validation refusing `auth_mode="host"` or `"jwt"` and missing `pinned` TLS trust material with exit code `2`), `create_mcp_server` and `create_asgi_app` (`ArodonataASGIApp` for Starlette/FastAPI embedding), `StaticTokenVerifier` and `MCPBearerAuthMiddleware` (constant-time `hmac.compare_digest` verification across `ARODONATA_MCP_TOKEN_VARS` mapping variable names to `client_id` in logs and `UserContext` without logging token values), `MCPOriginHostGuardMiddleware` (DNS rebinding protection returning HTTP `421` for unlisted `Host` and HTTP `403` for unlisted `Origin`), pre-login `domain` validation against the cached `arodonata_domains` table (with single domain-list refresh on miss) and `InvalidCredentialsError` translation into actionable `ToolFailure` messages listing known domains, and MCP prompt templates (`audit_session_changes`, `locate_ip_in_policy`, `plan_declarative_change`).
- Declarative Policy-as-Code CPCRUD engine (`arodonata.cpcrud`) wired into `ArodonataClient` (`client.cpcrud`): offline JSON Schema Draft-07 template validator (`CPCRUDService.validate` / `validate_template` over `checkpoint_ops_schema.json` with zero network or database calls), `HybridStateReader` (isolated per-plan state reader serving objects from `arodonata_objects` and services from `arodonata_services` strictly when `arodonata_domain_sync_state` for `(scope, item_type)` matches the planner's `DomainStamp` `last_published_at` and `last_session_uid`, with transparent live API fallback and intra-plan virtual state overlay), `Planner` and `Differ` (pre-lookup `DomainStamp` capture, two-axis conflict resolution `NameConflictPolicy` x `IpConflictPolicy` with `NamingPrefixes` auto-naming, `Outcome.ERROR` and `Outcome.SKIPPED_DEPENDENCY` on lookup failures instead of false `CREATE`, rule identity matching by key or traffic tuple with Check Point NAT `"Original"` / `"Any"` sentinel normalization, and cleanup-rule-aware `"bottom"` placement anchoring `{"above": "<cleanup_rule_uid>"}`), dedicated-session `Executor` (`apply` and `stream_apply` with `Outcome.PLAN_STALE` safeguard, per-domain `WriteSession` + `SessionOverlay` updates, `no_publish=True, keep_session=True` staging with `StagedSessionInfo`/`StagedSessionEvent` and SID redaction, post-publish `invalidate_domain`, and `retry_remaining` folding), and compensating rollback generator (`CPCRUDService.inverse` / `build_inverse_template`).
- Rulebase introspection, SmartConsole hierarchical numbering (`arodonata.rulebase`), and auditable session change reports (`arodonata.reports`) wired into `ArodonataClient`: section-stitching rulebase pager (`fetch_paged_rulebase` merging split `rulebase-section` headers across 100-rule pages and recovering empty trailing sections), `RulebaseRefreshService` (`refresh_rulebases` / `stream_refresh_rulebases` with dirty-session refusal, full package/NAT/access/HTTPS/threat/inline/Global placeholder traversal, and atomic `replace_domain_rulebase` replacement), `CachedRulebaseSource` (`get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`, automatic domain resolution with `AmbiguousLayerName`, and local `filter_rulebase` evaluation over cached rules/objects/services), and change report pipeline (`collect_change_report` with `SessionScope`/`RangeScope` UTC validation, deduplication, `ReportWarning` partial-failure tracking, bounded 200-UID `show-object` lookup, read-only live `OwnedSession` rule numbering with full SID redaction and cached snapshot fallback, and offline `render_change_report` / `build_change_report` for self-contained HTML, Markdown, and versioned JSON).
- Core synchronization, search services (`arodonata.core.services`), and unified `ArodonataClient` facade (`arodonata.client`): `DomainService` and `DomainListRefreshTracker` (MDSM `show-domains` discovery, `Global` domain synthesis, `include_global` filtering, active/standby failover IP re-resolution, and 1-hour TTL), `DomainSyncCoordinator` (parallel domain traversal per `active_mds_ip` at `max(1, concurrent_limit - 1)`, per-domain distributed locks, dirty-session checks via `show-session`, `(last_published_at, last_session_uid)` staleness comparison in `arodonata_domain_sync_state`, and probe `InvalidCredentialsError` failure handling), `ObjectService` (paired `refresh_objects` / `stream_refresh_objects`, `CacheMode` `"cache" | "smart" | "smart-fast" | "force"`, `"smart-fast"` incremental diff via `show-changes` with fallback on `> max_incremental_changes`, default `("host", "network", "address-range", "group", "dns-domain")`, and type-scoped replacement), `ServiceCacheService` (`arodonata_services` with default `("service-tcp", "service-udp", "service-icmp", "service-group")` and selective on-demand `types=[...]`), `AssetRefreshService` (`ClusterRelationshipManager` and `VSXRelationshipManager` via encapsulated `generic-object` queries), `SearchService` (`search_objects` with IP/CIDR/range/wildcard/UID/name classification and recursive group traversal up to `max_depth`, `describe_objects`, `query_objects`, and `get_cache_status`), and `ArodonataClient` (typed getters, `WriteSession` overlay merging, `write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`, `start_object_cache_warmup`, and `invalidate_domain`).
- Check Point native `asyncio` transport and session adapter (`arodonata.adapters.checkpoint`): `TrustStore` and `TrustPolicy` (`pinned`, `tofu`, `lab-memory` with atomic `0600` `tls_known_hosts.json` persistence and cross-IP MDS member certificate recognition), `ApiTransport` over `aiohttp` (post-handshake pre-request SHA-256 fingerprint verification, separate `connect_timeout`/`read_timeout` `ApiTimeoutError` phases, no automatic re-send after socket write, and `VerifiedConnectionPool` reusing keep-alive sockets up to 10s idle strictly for `show-*` commands), `TaskWaiter` (exponential backoff `2s..10s` polling under `task_timeout` tolerating up to 5 transient poll errors), continuity-verified object pager (`pager.py` with `±10` boundary swap window recovery and single restart on discontinuity), per-MDS-member `RateLimiter` (database slot locks + FIFO waiter queue + coalesced keepalive sweeps) and `LoginGate` (`70s` throttle recovery and fast-fail `InvalidCredentialsError`), `LoginCoordinator`, `SessionCleaner`, context-bound `WriteSession` (`SessionOverlay` updates, auto-`publish` / `discard`), and `AMgmtClient` implementing `ApiPort`.
- Core foundation (`arodonata.core`) and SQL storage adapter (`arodonata.adapters.storage`): `ArodonataSettings`, exception hierarchy with SID/secret redaction, `@traced` and `span_attrs` instrumentation, typed domain progress events (`SyncProgressEvent`, `CPCRUDEvent`), `contextvars`-bound `AuthContext`, `UserContext`, and `WriteSession` with `SessionOverlay`, Pydantic v2 domain models, hexagonal protocols (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`), `DatabaseManager` (SQLite + PostgreSQL with SHA-256 schema hash auto-migration via `arodonata_schema_version`), `SqlLockAdapter`, `SqlCacheAdapter`, and SSE boundary adapter (`arodonata.adapters.sse`).

### Changed

- Revised all OpenSpec capability specifications for Arodonata v2 clean-slate hexagonal architecture: native `aiohttp` transport (replacing `cpapi`), `SqlCacheAdapter` (replacing `PostgresCacheAdapter`/`CacheRepository`), canonical `CacheMode` names (`cache`, `smart`, `smart-fast`, `force`), paired coroutine and `stream_*` domain event APIs (removing `SSEEvent` from core), and unified `ArodonataClient` facade (replacing `arodonata.helpers`).

### Fixed

- Check Point R82 live compatibility and persistent cache/session reuse fixes: `ArodonataClient` and `AMgmtClient` now honor `settings.database_url` when `engine=None`, auto-create parent directories for file-backed SQLite URLs, preserve `arodonata_sid_cache` entries on `close()` for persistent databases, and skip redundant startup `SessionCleaner` logins when a valid system-domain SID is already cached; `LoginCoordinator` classifies generic R82 `"Authentication to server failed."` (`err_login_failed`) as non-retryable `InvalidCredentialsError`; `DomainSyncCoordinator` and `ObjectService` extract `"iso-8601"` from dict-formatted `publish-time` and unwrap task-based `show-changes` `operations` arrays; `Collector` passes `view-published-sessions=True` for published session discovery; and `Planner._find_existing_nat_rule` resolves inline object/service names to UIDs for idempotent NAT rule re-planning.