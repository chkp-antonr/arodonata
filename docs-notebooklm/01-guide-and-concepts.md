# Arodonata v2 — Concepts, Architecture & User Guide

This document is the consolidated narrative guide to **Arodonata v2 (`2.0.0`)**: hexagonal architecture, the 15 `arodonata_*` SQLModel cache tables, incremental sync, isolated write sessions with `SessionOverlay`, the declarative `CPCRUD` engine, auditable change reports, and the consolidated Model Context Protocol (MCP) server.


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
| **Database-Backed Cache** | `DatabaseManager`, `SqlCacheAdapter` | 15 `arodonata_*`-prefixed SQLModel tables on PostgreSQL (`asyncpg`) or SQLite (`aiosqlite`) with SHA-256 auto-migration and cross-process locks |
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
  - [Database Schema Reference (15 `arodonata_*` Tables)](architecture/database-schema.md)
  - [Caching, Incremental Sync & Search](architecture/caching-and-sync.md)
  - [Sessions, MDSM & `SessionOverlay`](architecture/sessions-and-mdm.md)
  - [CPCRUD Engine Internals](architecture/cpcrud.md)
- **User Guides & MCP**:
  - [Declarative CPCRUD Operations](user-guide/cpcrud.md)
  - [Auditable Change Reports](user-guide/change-report.md)
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

1. Verifies and migrates the 15 `arodonata_*` tables in your SQLite or PostgreSQL database (`DatabaseManager.initialize()`).
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
- Database-backed caching across **15 `arodonata_*`-prefixed SQLModel tables** (PostgreSQL `asyncpg` and SQLite `aiosqlite`) with SHA-256 schema hash auto-migration, naive UTC timestamp uniformity (`tzinfo=None`), and distributed locks (`arodonata_distributed_locks`).
- Incremental (`show-changes`) and full synchronization across domains, objects, services, assets (gateways/clusters/VSX), and rulebases with typed streaming progress events (`SyncProgressEvent`).
- Isolated write sessions (`WriteSession`) with `contextvars`-bound `SessionOverlay` for read-your-own-writes isolation prior to `publish`.
- Declarative Policy-as-Code (`CPCRUDService`): offline JSON Schema validation, `HybridStateReader`, two-axis conflict policies (`NameConflictPolicy` × `IpConflictPolicy`), pre-publish staleness verification (`DomainStamp`), staged session handoff (`take-over-session`), and compensating rollback generation (`inverse`).
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
- **Strict Table Namespace Isolation (`arodonata_*`)**: All 15 Arodonata tables are prefixed with `arodonata_` (`ARODONATA_TABLE_NAMES`). `DatabaseManager.initialize()` inspects and migrates only `arodonata_*` tables, completely ignoring any host application tables registered in `SQLModel.metadata` (even if the host app has tables named `assets`, `domains`, or `distributed_locks`).
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

    subgraph Core["Hexagonal Core (src/arodonata/core, rulebase, cpcrud, reports)"]
        Services["Domain, Object, Service, Asset & Search Services"]
        Coord["DomainSyncCoordinator"]
        Rulebase["CachedRulebaseSource & RulebaseRefreshService"]
        CPCRUD["CPCRUDService (Validator, Planner, Differ, Executor, Inverse)"]
        Reports["ChangeReport Collector & Renderer"]
        Ports["Protocols: ApiPort | CachePort | LockPort | AuthProvider"]
    end

    subgraph Adapters["Infrastructure Adapters (src/arodonata/adapters)"]
        CP["AMgmtClient (ApiTransport, TrustPolicy, RateLimiter, LoginGate, TaskWaiter)"]
        DB["SqlCacheAdapter & SqlLockAdapter (DatabaseManager)"]
        SSE["SSE Boundary Adapter (SSEEvent)"]
    end

    subgraph External["External Systems"]
        MDSM["Check Point SMS / MDSM Clusters (HTTPS Web API)"]
        SQL[("PostgreSQL (asyncpg) / SQLite (aiosqlite)\n15 arodonata_* Tables")]
    end

    SDK --> Client
    LLM --> MCP
    CLI --> MCP
    MCP --> Client
    Client --> Services
    Client --> Coord
    Client --> Rulebase
    Client --> CPCRUD
    Client --> Reports
    Services --> Ports
    Coord --> Ports
    Rulebase --> Ports
    CPCRUD --> Ports
    Reports --> Ports
    Ports -.-> CP
    Ports -.-> DB
    Client -.-> SSE
    CP --> MDSM
    DB --> SQL
```

## Key Architectural Invariants

1. **Pure Core Domain (`arodonata.core`, `arodonata.rulebase`, `arodonata.cpcrud`, `arodonata.reports`)**:
   - Business logic depends exclusively on typed Python `Protocol` interfaces (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`).
   - Core modules never import `aiohttp`, `asyncpg`, `aiosqlite`, or HTTP transport primitives directly.
2. **Database-First Synchronization & Multi-Worker Coordination**:
   - All cached state lives in **15 `arodonata_*` SQLModel tables** ([Database Schema Reference](database-schema.md)).
   - Schema initialization is serialized across worker processes (`pg_advisory_xact_lock` on PostgreSQL, `BEGIN IMMEDIATE` on SQLite) and tracked by SHA-256 metadata digest in `arodonata_schema_version`.
   - Domain synchronization acquires database-backed distributed locks (`arodonata_distributed_locks`) with automatic background TTL heartbeat renewal.
3. **Strict Read vs Write Session Separation**:
   - Read operations share a persistent, credential-bound read-only session in `arodonata_sid_cache`. Mutating commands (`add-*`, `set-*`, `delete-*`, `publish`, `discard`) are strictly rejected on the shared session.
   - Write operations open an isolated `WriteSession` (`create_dedicated_session`) with an in-memory `SessionOverlay` bound via `contextvars` so callers immediately read their own uncommitted writes before `publish`.
4. **Defense-in-Depth Security Hygiene**:
   - Session tokens (`sid`), API keys, and passwords are redacted (`"***REDACTED***"`) in all `repr()`, logs, OpenTelemetry span attributes, exception messages, and MCP tool outputs (`redact_sid(..., known_sids=...)`).
   - TLS certificates are verified post-handshake and pre-request against SHA-256 DER fingerprints (`pinned`, `tofu`, or `lab-memory`).
5. **Provider-Agnostic Observability**:
   - Functions decorated with `@traced` (`arodonata.core.telemetry`) emit OpenTelemetry spans via `opentelemetry-api` (`arlogi.otel.traced`) without ever owning or overriding the host application's global `TracerProvider`.


---

## Architecture — Hexagonal Ports & Adapters

*(source: `docs/architecture/ports-and-adapters.md`)*

# Hexagonal Ports & Adapters

Arodonata v2 isolates all Check Point Management API and SQL database details behind four core `Protocol` interfaces defined in `src/arodonata/core/ports/__init__.py`.

## Core Protocols (`arodonata.core.ports`)

### 1. `ApiPort`

Defines the asynchronous contract for communicating with Check Point Management and MDSM servers:

- `api_call(mgmt_name, command, payload, *, domain=None, sid=None, server_ip=None, wait_for_task=True, timeout=None) -> ApiCallResult`
- `api_query(mgmt_name, command, *, domain=None, details_level="standard", payload=None, sid=None, server_ip=None, limit=500) -> ApiQueryResult`
- `create_dedicated_session(mgmt_name, domain=None, *, auth=None, session_name=None, session_description=None) -> tuple[str, str]`
- `logout_sid(mgmt_name, sid, *, server_ip=None) -> bool`
- `close(*, logout=False) -> None`

**Default Adapter**: `AMgmtClient` (`src/arodonata/adapters/checkpoint/client.py`), backed by:

- `ApiTransport`: Native `aiohttp` client with `allow_redirects=False`, `trust_env=False`, post-handshake SHA-256 certificate verification, and phase-tagged `TransportError` (`phase="connect"` vs `"post-send"` so mutating calls are never re-sent after bytes leave the socket).
- `VerifiedConnectionPool`: Reuses verified keep-alive connections (up to `10s` idle) strictly for idempotent `show-*` commands.
- `RateLimiter` & `LoginGate`: Enforces `concurrent_limit` per MDS member IP and a `70s` cooldown window on login throttling (`err_too_many_requests`).
- `TaskWaiter`: Polls asynchronous Check Point `task-id` responses with exponential backoff (`2s..10s`) up to `task_timeout`.

### 2. `CachePort`

Defines the contract for reading and persisting cached Check Point topology, objects, services, assets, rulebases, sessions, and sync states:

- Domain topology: `get_domains()`, `replace_domains()`
- Shared sessions: `get_cached_sid()`, `upsert_cached_sid()`, `delete_cached_sid()`, `list_cached_sids()`
- Sync state: `get_sync_state()`, `list_sync_states()`, `upsert_sync_state()`
- Objects & Services: `get_objects()`, `get_object_by_uid()`, `replace_domain_objects()`, `apply_incremental_objects()`, `get_services()`, `get_service_by_uid()`, `replace_domain_services()`, `apply_incremental_services()`
- Assets: `get_assets()`, `replace_domain_assets()`
- Rulebase snapshots: `get_domain_rulebase()`, `replace_domain_rulebase()`
- Structured aggregation: `describe_objects()`, `query_objects()`

**Default Adapter**: `SqlCacheAdapter` (`src/arodonata/adapters/storage/cache_adapter.py`), which executes atomic transactions and dialect-specific `ON CONFLICT DO UPDATE` upserts on PostgreSQL and SQLite.

### 3. `LockPort`

Coordinates distributed cross-process critical sections (per-domain cache refreshes, login serialization, and cross-worker rate-limit slots):

- `acquire(lock_key, *, ttl_seconds=60.0, timeout_seconds=30.0, poll_interval=0.25) -> str` (returns `owner_id`)
- `renew(lock_key, owner_id, *, ttl_seconds=60.0) -> bool`
- `release(lock_key, owner_id) -> bool`
- `lock(lock_key, *, ttl_seconds=60.0, timeout_seconds=30.0) -> AsyncIterator[str]`

**Default Adapter**: `SqlLockAdapter` (`src/arodonata/adapters/storage/lock_adapter.py`) backed by the `arodonata_distributed_locks` table, evaluating expiration against the database server's UTC clock.

### 4. `AuthProvider`

Optional pluggable protocol for resolving credentials dynamically per `(mgmt_name, domain)` when `auth_mode="dynamic"` is used without an explicit `auth_context`.

## Dependency Injection in Tests & Custom Hosts

Because `ArodonataClient` accepts custom `api: ApiPort`, `cache: CachePort`, and `lock_port: LockPort` instances in its constructor, unit tests and downstream applications can inject in-memory fakes or custom adapters without monkeypatching internal classes:

```python
client = ArodonataClient(
    settings,
    api=custom_api_port,
    cache=custom_cache_port,
    lock_port=custom_lock_port,
)
```


---

## Architecture — Database Schema (15 Tables)

*(source: `docs/architecture/database-schema.md`)*

# Database Schema Reference (15 `arodonata_*` Tables)

Arodonata v2 persists all cached topology, shared sessions, distributed locks, objects, services, gateway/VSX assets, and normalized policy rulebases across **15 SQLModel tables** defined in `src/arodonata/adapters/storage/tables.py` (`ARODONATA_TABLE_NAMES`).

Both **PostgreSQL (`postgresql+asyncpg://`)** and **SQLite (`sqlite+aiosqlite://`)** are first-class supported backends.

---

## 1. Host Application Coexistence & Auto-Migration Design

Arodonata v2 is engineered to share a single database and `SQLModel.metadata` registry safely with host applications (such as **FPCR v2**):

1. **Strict `arodonata_` Table Namespace (`ARODONATA_TABLE_NAMES`)**:
   - Every table owned by Arodonata is prefixed with `arodonata_` (including `arodonata_assets`, `arodonata_domains`, `arodonata_distributed_locks`, `arodonata_sid_cache`, `arodonata_domain_sync_state`).
   - `DatabaseManager.initialize()` inspects and migrates **only** tables in `ARODONATA_TABLE_NAMES`. Any host application tables in the same database or `SQLModel.metadata` (such as a host app's own `assets` or `domains` table) are never touched, altered, or dropped.
2. **SHA-256 Schema Hash Auto-Migration (`arodonata_schema_version`)**:
   - `DatabaseManager` computes a deterministic SHA-256 digest (`compute_schema_hash()`) over the table names, column names, SQL types, primary keys, nullability, and indexes of all 15 `arodonata_*` tables.
   - If the current `schema_hash` is already recorded in `arodonata_schema_version` and all 15 tables exist, startup skips column inspection and completes in `< 2ms`.
   - When the schema evolves, `DatabaseManager` adds missing columns/indexes via savepoint-protected (`begin_nested()`) `ALTER TABLE` statements—or drops and recreates ephemeral `arodonata_*` cache tables if primary keys or `NOT NULL` constraints changed—and records the new `schema_hash`.
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
   - In addition, `arodonata_assets` maintains dual UID and human-readable parent/child topology links (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`), supporting both intra-domain clusters and **cross-domain VSX topology** (where a physical VSX gateway/cluster resides in an infrastructure domain like `VSX` and its Virtual Systems reside in tenant domains like `Domain4`).

---

## 2. Entity-Relationship Diagram (15 Tables)

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
        string id PK "mgmt_name:domain_name:auth_hash"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string sid "REDACTED in repr"
        string server_ip
        string session_uid
        string auth_identity
        datetime last_used_at
        datetime expires_at
    }
    arodonata_domain_sync_state {
        string id PK "mgmt_name:domain_name:scope:item_type"
        string mgmt_name "INDEX"
        string domain_name "INDEX"
        string scope "INDEX: domains|objects|services|assets|rulebase"
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
        string type "INDEX: host|network|address-range|group|dns-domain"
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
| `schema_hash` | `str` | `PK` | 64-char SHA-256 hex digest of the 15 `arodonata_*` table schemas |
| `applied_at` | `datetime` | `NOT NULL` | Naive UTC timestamp when the schema version was applied |

#### 2. `arodonata_distributed_locks` (`DistributedLockRecord`)

Coordinates cross-process critical sections (per-domain cache refreshes, login coordination, rate-limit slots).

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
| `id` | `str` | `PK` | Composite key `"{mgmt_name}:{domain_name}:{auth_identity_hash}"` |
| `mgmt_name` | `str` | `INDEX` | Management server logical name |
| `domain_name` | `str` | `INDEX` | Normalized domain name (`"default"` for SMS / MDS system domain) |
| `sid` | `str` | `repr=False` | Check Point session token (redacted in all representations) |
| `server_ip` | `str` | `NOT NULL` | Active CMA or MDS IP where this session resides |
| `session_uid` | `str \| None` | — | Check Point session UID from `login` response |
| `auth_identity` | `str \| None` | — | Non-secret HMAC-SHA256 fingerprint of the credential that opened the session |
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
| `scope` | `str` | `INDEX` | `"domains"`, `"objects"`, `"services"`, `"assets"`, or `"rulebase"` |
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
| `name` | `str` | `INDEX` | Domain name (e.g., `"Domain4"`, `"Global"`, `"default"`) |
| `domain_type` | `str` | — | `"domain"`, `"global domain"`, or `"smc-user"` |
| `active_ip` | `str \| None` | — | Active CMA IPv4/IPv6 address |
| `active_mds_ip` | `str \| None` | `INDEX` | Hosting MDS member IP (used to group per-MDS-member sync concurrency) |
| `standby_ips` | `list[str]` (JSON) | `NOT NULL` | Standby CMA IPs for automatic failover |
| `servers` | `list[dict]` (JSON) | `NOT NULL` | Full CMA server entries from Check Point API |
| `is_global` | `bool` | `INDEX` | `True` for the MDSM `Global` domain |
| `raw_data` | `dict` (JSON) | `NOT NULL` | Full sanitized API payload |
| `updated_at` | `datetime` | `NOT NULL` | Naive UTC update timestamp |

#### 6. `arodonata_objects` (`CPObjectRecord`)

Cached network objects (`host`, `network`, `address-range`, `group`, `dns-domain`, etc.).

| Column | Type | Key / Index | Description |
| --- | --- | --- | --- |
| `id` | `str` | `PK` | `"{mgmt_name}:{domain_name}:{uid}"` |
| `object_id` | `str` | `INDEX` | Human-readable composite key `"{mgmt_name}:{domain_name}:{name}"` |
| `uid` | `str` | `INDEX` | Check Point object UID |
| `name` | `str` | `INDEX` | Object name |
| `type` | `str` | `INDEX` | Canonical object type (`"host"`, `"network"`, `"address-range"`, `"group"`, `"dns-domain"`) |
| `mgmt_name`, `domain_name` | `str` | `INDEX` | Server and domain context |
| `original_domain` | `str \| None` | `INDEX` | Owning domain reported by Check Point (`domain.name` inside `raw_data`, distinguishing local vs `Global` objects) |
| `ipv4_address`, `ipv6_address` | `str \| None` | `INDEX` (`ipv4`) | Host IPv4 / IPv6 address |
| `subnet4`, `mask_length4`, `subnet_mask` | `str / int` | `INDEX` (`subnet4`) | Network CIDR subnet and mask |
| `ipv4_address_first`, `ipv4_address_last` | `str \| None` | — | Address range bounds |
| `fqdn`, `is_sub_domain` | `str / bool` | `INDEX` (`fqdn`) | DNS domain FQDN and subdomain flag |
| `members` | `list[str]` (JSON) | `NOT NULL` | Member UIDs for `group` objects |
| `comments`, `color`, `tags`, `nat_settings` | `str / JSON` | — | Metadata, tag names, and automatic NAT settings |
| `raw_data`, `updated_at` | `JSON / datetime` | `NOT NULL` | Full API payload and naive UTC timestamp |

#### 7. `arodonata_services` (`CPServiceRecord`)

Dedicated cache table for service objects (`service-tcp`, `service-udp`, `service-icmp`, `service-group`, and on-demand `service-other`, `service-sctp`, `service-dce-rpc`, `service-rpc`, `service-icmp6`, `service-citrix-tcp`, `service-compound-tcp`).

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
| `comments`, `color`, `tags`, `raw_data`, `updated_at` | `str / JSON / datetime` | — | Metadata, raw payload, and naive UTC timestamp |

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
| `comments`, `color`, `raw_data`, `updated_at` | `str / JSON / datetime` | — | Metadata, raw payload, and naive UTC timestamp |

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

## Architecture — Caching, Incremental Sync & Search

*(source: `docs/architecture/caching-and-sync.md`)*

# Caching, Incremental Synchronization & Search

Arodonata v2 coordinates multi-domain synchronization through `DomainSyncCoordinator` (`src/arodonata/core/services/sync_coordinator.py`) and exposes four cache freshness modes (`CacheMode`).

## 1. The Four `CacheMode` Policies

| Mode | Staleness Probe (`show-last-published-session`) | Data Fetch Strategy | Typical Use Case |
| --- | --- | --- | --- |
| `"cache"` | Never | Local SQLite/PostgreSQL query only (`0` API calls) | High-speed rulebase filtering, offline analysis, MCP `query_objects` |
| `"smart"` (default) | Only when `synced_at` is older than `cache_ttl` (or after `invalidate_domain`) | Full atomic type-slice reload if `(last_published_at, last_session_uid)` changed | Default SDK reads (`get_hosts`, `get_services`, `get_gateways`) |
| `"smart-fast"` | Same as `"smart"` | Queries `show-changes` (`from-session` or UTC `from-date`) and applies dialect `ON CONFLICT` upserts/deletes; falls back to full reload if changes `> max_incremental_changes` (`500`) | Rapid refresh after small publishes across large domains |
| `"force"` | Always probes current publish head | Unconditional atomic reload of all requested types | Initial cache build (`04_smart_refresh.py`) or forced recovery |

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
    else Expired TTL or invalidated
        Coord->>Lock: acquire("sync:mgmt:domain:objects") + start heartbeat task
        Coord->>API: show-session (verify shared session has 0 uncommitted changes)
        Coord->>API: show-last-published-session
        alt (last_published_at, last_session_uid) unchanged
            Coord->>Cache: Update synced_at timestamp
        else Published head advanced
            alt mode == "smart-fast" and baseline exists
                Coord->>API: show-changes(from-session=last_session_uid)
                Coord->>Cache: Atomic transaction: apply_incremental_objects + upsert_sync_state
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

- **Dirty Shared Session Refusal (`DirtySessionError`)**: Before syncing any domain into the shared cache, `DomainSyncCoordinator` verifies via `show-session` that the session has `changes == 0`. It never caches uncommitted objects into the shared SQL tables.
- **Per-MDS-Member Concurrency**: Domains hosted on the same `active_mds_ip` are refreshed concurrently via `asyncio.TaskGroup` up to `max(1, concurrent_limit - 1)` at a time, leaving at least one rate-limiter slot free for interactive API calls.
- **Lock Contention vs Genuine Failure**: If another worker holds the per-domain lock (`LockAcquisitionError`), the coordinator skips redundant work without marking `arodonata_domain_sync_state.status = "failed"`. Genuine API or credential errors record a sanitized (`redact_sid`) error in `last_error` while preserving previously cached rows.

## 3. Search & Recursive Group Membership (`SearchService`)

`await client.search_objects(query, ..., exact_match=False, max_depth=2)` classifies each comma-separated term in `query` and searches across `arodonata_objects` (plus any active `WriteSession` overlay):

1. **IPv4 Address (`10.1.10.50`)**: Matches hosts with that IPv4 address, networks whose CIDR subnet contains the IP, and address ranges whose `[first..last]` bounds include the IP.
2. **CIDR Subnet (`10.1.10.0/24`)**: Matches networks with that subnet/mask and hosts/subnets contained within it.
3. **IPv4 Range (`10.1.10.1-10.1.10.20`)**: Matches overlapping `address-range` objects and contained hosts.
4. **Wildcard Pattern (`*.corp.example`, `web-*`)**: Evaluates case-insensitive anchored `fnmatchcase` across object names and `fqdn` fields.
5. **Composite Identifier (`mds:Domain4:hWebHost` or `mds:Domain4:<uid>`)**: Matches `CPObject.object_id` or `CPObject.id` directly (case-insensitively on `object_id`).
6. **Exact or Substring Name (`exact_match=True` vs `False`)**:
   - When `exact_match=False` (default), matches case-insensitive substrings in `name`, `fqdn`, `object_id`, and `comments`.
   - When `exact_match=True`, matches only exact case-insensitive `name`, `fqdn`, `object_id`, or `id` (e.g., searching `".example.com"` with `exact_match=True` matches `.example.com` without matching `sub.example.com`).
7. **Recursive Group Resolution (`max_depth`)**: Automatically traverses `group.members` upward up to `max_depth` levels, returning both `SearchResult.objects` and `SearchResult.memberships` (`object_uid -> list[GroupMembershipNode]`, where each `GroupMembershipNode` carries `uid`, `name`, `type`, `domain`, `id`, `object_id`, `depth`, `parent_uids`, and `parent_object_ids`).

## 4. Cross-Domain Asset Topology & Composite Identifiers

During `refresh_assets` / `stream_refresh_assets`, `AssetRefreshService` runs `ClusterRelationshipManager` and `VSXRelationshipManager` across cached domain assets:

- **Intra-Domain Cluster Members**: Links each cluster (`CpmiGatewayCluster`, `vsx-cluster-netobj`) and its members (`CpmiClusterMember`, `vsx-cluster-member`) with both UID references (`parent_uid`, `member_uids`) and composite identifiers (`parent_id`, `parent_asset_id`, `member_asset_ids`).
- **Cross-Domain VSX Virtual Systems**: On Multi-Domain Security Management (MDSM), a physical VSX gateway or cluster typically lives in an infrastructure domain (e.g., `"VSX"`) while its Virtual Systems (`virtual-system`) reside in tenant domains (e.g., `"Domain4"`). `AssetRefreshService` reconciles VSX relationships across all domains on the same `mgmt_name`, populating `parent_id` (`"mds:VSX:<vsx-uid>"`), `parent_asset_id` (`"mds:VSX:<vsx-name>"`), `virtual_system_uids`, and `virtual_system_asset_ids` (`["mds:Domain4:<vs-name>"]`).


---

## Architecture — Sessions, MDSM & SessionOverlay

*(source: `docs/architecture/sessions-and-mdm.md`)*

# Sessions, MDSM & `SessionOverlay`

Check Point Management servers tie every uncommitted change and object lock to a session identifier (`sid`). Sharing a single `sid` across concurrent tasks or mutating on a read session leads to accidental publishes of another user's changes or deadlocked objects.

Arodonata v2 enforces a strict architectural separation between **shared read-only sessions** and **isolated write sessions**.

## 1. Shared Read-Only Sessions (`arodonata_sid_cache`)

- All read commands (`show-*`, `where-used`, `verify-policy`) use a pooled session cached in the `arodonata_sid_cache` table per `(mgmt_name, domain_name, auth_identity_hash)`.
- **Hard Read-Only Guard**: `AMgmtClient` checks `is_readonly_command(command)` before using a cached `sid`. Attempting to run `add-*`, `set-*`, `delete-*`, `publish`, or `discard` on the shared session raises `SessionStateError` immediately.
- **Persistent Reuse Across CLI Invocations**: When `ARODONATA_DATABASE_URL` points to a file-backed SQLite or PostgreSQL database, `await client.close()` leaves valid `arodonata_sid_cache` sessions alive so subsequent CLI commands or worker processes reuse the existing login without triggering Check Point's login rate limiter.
- **Startup `SessionCleaner`**: On initialization, `SessionCleaner` inspects open sessions created by Arodonata (`application="arodonata"`) and logs out only orphaned idle sessions that have `changes == 0` and `locks == 0`.

## 2. Isolated `WriteSession` & `SessionOverlay`

Whenever you open `async with client.write_session(mgmt_name, domain) as ws:`, Arodonata:

1. Calls `create_dedicated_session()` to open a fresh Check Point session outside `arodonata_sid_cache`.
2. Binds the `WriteSession` and its `SessionOverlay` to Python's `contextvars` for the current async task tree.
3. Intercepts every `add-<type>`, `set-<type>`, and `delete-<type>` call inside that `with` block and records the created, modified, or deleted object/service in `ws.overlay`.
4. Automatically merges `ws.overlay` into all cached read helpers (`get_hosts`, `get_objects`, `get_services`, `find_object`, `search_objects`, `get_group_members`) called within the same async context!
5. On normal block exit (`publish_on_exit=True`), executes `publish`, waits for the task to complete, clears the overlay, invalidates the domain cache so the next read fetches the new published revision, and logs out the dedicated `sid`.
6. On exception, automatically executes `discard` (shielded via `asyncio.shield`) and logs out cleanly so no locks remain orphaned on the Check Point server.

```mermaid
sequenceDiagram
    participant App as Application Task
    participant Client as ArodonataClient
    participant Overlay as SessionOverlay (contextvars)
    participant CP as Check Point API
    participant SQL as SQL Cache (arodonata_objects)

    App->>Client: async with client.write_session(mgmt, "Domain4") as ws:
    Client->>CP: login (dedicated session) -> sid_write
    App->>Client: add_object(mgmt, "host", {"name": "h1", "ipv4-address": "10.0.0.1"})
    Client->>CP: add-host (sid=sid_write)
    Client->>Overlay: record_upsert(CPObject("h1"))
    App->>Client: get_hosts(mgmt, "Domain4")
    Client->>SQL: SELECT * FROM arodonata_objects (committed state)
    Client->>Overlay: apply_objects(committed_hosts) -> includes uncommitted "h1"!
    Client-->>App: [..., CPObject("h1")]
    App->>Client: exit write_session block
    Client->>CP: publish (sid=sid_write) + wait_for_task
    Client->>Overlay: clear() + invalidate_domain(mgmt, "Domain4")
    Client->>CP: logout (sid=sid_write)
```

## 3. Login Throttling Recovery (`LoginGate`)

Check Point R81.20 / R82 Management servers enforce a strict login rate limit; exceeding it returns HTTP `400` / `429` (`err_too_many_requests` / `"Too many login attempts"`).

- `LoginGate` (`src/arodonata/adapters/checkpoint/rate_limiter.py`) serializes login attempts per MDS member IP with inter-login spacing and, upon detecting a throttle response, opens a `login_throttle_window` (`70.0s` default) cooldown gate across all waiting tasks up to `login_max_wait` (`900.0s`).
- Genuine authentication failures (`InvalidCredentialsError`, including Check Point R82 `"Authentication to server failed."` / `err_login_failed`) fail fast immediately without waiting or retrying.


---

## Architecture — CPCRUD Engine Internals

*(source: `docs/architecture/cpcrud.md`)*

# CPCRUD Engine Architecture

`arodonata.cpcrud` (`src/arodonata/cpcrud/`) implements a deterministic, two-phase (`plan` → `apply`) Policy-as-Code engine for Check Point Security Management and MDSM.

## Architecture & Data Flow

```mermaid
flowchart LR
    Tpl["YAML / JSON Template"] --> Val["Validator\n(checkpoint_ops_schema.json)"]
    Val --> Plan["Planner & Differ"]
    Stamp["show-last-published-session\n(DomainStamp)"] --> Plan
    Reader["HybridStateReader\n(SQL Cache + Live API Fallback\n+ Virtual Intra-Plan Overlay)"] --> Plan
    Plan --> SignedPlan["Plan\n(PlannedActions + DomainStamps\n+ Name Resolutions)"]
    SignedPlan --> Exec["Executor\n(Pre-Apply Stamp Check + WriteSession\n+ Retry Folding + Publish/Stage)"]
    Exec --> Report["ApplyReport\n(ActionResults + StagedSessionInfo)"]
    SignedPlan & Report --> Inv["Inverse Builder\n(build_inverse_template)"]
```

## Core Components

### 1. Offline Schema Validator (`validator.py`)

Validates YAML strings or Python dictionaries against `src/arodonata/cpcrud/checkpoint_ops_schema.json` (JSON Schema Draft-07) with zero network or database calls. Checks structural requirements, object/service/group/section/rule types, conflict policies, and strict `(object_type, operation)` command allowlisting.

### 2. `DomainStamp` & `HybridStateReader` (`state_reader.py`)

Before inspecting any objects or rules, `Planner` queries `show-last-published-session` for each target domain and records a `DomainStamp(mgmt_name, domain, last_session_uid, last_published_at)`.

`HybridStateReader` then serves object and service lookups using a two-tier strategy:

- **Cache Hit (Fast Path)**: If `arodonata_domain_sync_state` for `(mgmt_name, domain, scope, item_type)` matches the planner's `DomainStamp` (`last_published_at` and `last_session_uid`), lookups (`host`, `network`, `address-range`, `group`, `dns-domain`, `service-tcp`, `service-udp`, etc.) are resolved directly from `arodonata_objects` and `arodonata_services` in local SQL.
- **Live API Fallback**: If the domain cache is absent or older than the `DomainStamp`, `HybridStateReader` falls back transparently to live Check Point API queries.
- **Intra-Plan Virtual State Overlay**: Each `plan()` call instantiates a fresh `HybridStateReader` whose virtual overlay tracks objects, services, and groups planned earlier in the same template so downstream groups and rules see newly planned members immediately.
- **Fail-Closed Lookup Errors**: Transport or API errors during state lookup raise `StateLookupError` and produce `Outcome.ERROR` (plus `Outcome.SKIPPED_DEPENDENCY` on dependent groups/rules) rather than falsely assuming an object is missing and planning a duplicate `CREATE`.

### 3. Two-Axis Conflict Resolution (`differ.py` & `planner.py`)

When planning an object or service:

- **`on_name_conflict: "update" | "error"`**:
  - If an object with the same `name` exists with identical desired fields → `Outcome.UNCHANGED` (`no-op`).
  - If fields differ and `on_name_conflict="update"` → `Outcome.UPDATE` with field-level `FieldChange` diffs.
  - If fields differ and `on_name_conflict="error"` → `Outcome.ERROR`.
- **`on_ip_conflict: "reuse" | "create_new" | "error"`**:
  - Evaluated when no object has the requested `name`, but an existing object in the domain already owns the same IPv4 address, CIDR subnet, IP range, or TCP/UDP port:
  - `"reuse"` (default): Plans `Outcome.REUSE` and records `requested_name -> existing_name` in `Plan.name_resolutions`, automatically rewriting references in subsequent groups and rules.
  - `"create_new"`: Generates a canonical convention name via `NamingPrefixes` (`Host_<ip>`, `Net_<subnet>_<mask>`, `IPR_<first>-<last>`, `TCP_<port>`, `UDP_<port>`) and plans `Outcome.CREATE` (or reuses if that canonical name already exists).
  - `"error"`: Plans `Outcome.ERROR` and skips dependent actions.

### 4. Rule Identity & Cleanup-Aware Positioning (`rule_identity.py` & `position_helper.py`)

- **Access, HTTPS, and Threat Rules**: Matched by `uid`, `name`, or traffic tuple (`source`, `destination`, `service`, `action`).
- **NAT Rules**: Matched by `uid`, `name`, or original/translated traffic tuple, normalizing Check Point's built-in `"Original"` (`NAT_ORIGINAL_OBJECT_UID`) and `"Any"` (`NAT_ANY_OBJECT_UID`) sentinel UIDs so re-planning an applied NAT rule is 100% idempotent (`Outcome.UNCHANGED`).
- **Cleanup Rule Anchoring**: When `position: "bottom"` is requested on an access layer whose bottom rule is an explicit Check Point cleanup rule (`name="Cleanup rule"` or `action="Drop"` with `Any/Any/Any`), `position_helper` automatically anchors the new rule `{"above": "<cleanup_rule_uid>"}` so traffic rules are never placed below the cleanup drop rule.

### 5. Dedicated-Session `Executor` & Staleness Guard (`executor.py`)

When `await client.cpcrud.apply(plan, force=False)` runs:

1. **Pre-Session Staleness Check**: Re-queries `show-last-published-session` and compares against `plan.domain_stamps`. If another admin published changes after `plan()` was created and `force=False`, execution aborts with `Outcome.PLAN_STALE` before opening a write session.
2. **Pre-Publish Drift Re-Verification**: Before calling `publish` at the end of a domain's action batch, `Executor` re-checks `show-last-published-session` a second time; if concurrent changes were published while actions were running and `force=False`, it discards the session and reports `Outcome.PLAN_STALE`.
3. **Compensating Rollback (`inverse.py`)**: `client.cpcrud.inverse(plan, report)` inspects only actions that actually succeeded (`Outcome.CREATED`, `Outcome.UPDATED`, `Outcome.DELETED`) in `ApplyReport` and generates a schema-valid reverse template (`delete` for `CREATED`, `set` with `before` values for `UPDATED`, `add` with `before_snapshot` for `DELETED`) in reverse dependency order (rules → sections → groups → services/objects).


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
| `ARODONATA_MCP_JSON_RESPONSE` | `bool` | `False` | Return JSON responses instead of SSE streams on Streamable-HTTP POST |
| `ARODONATA_MCP_STATELESS_HTTP` | `bool` | `False` | Enable stateless Streamable-HTTP mode per request |
| `ARODONATA_MCP_SERVER_NAME` | `str` | `"arodonata-mcp"` | Server identifier reported in MCP initialization |


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

## Project Changelog (v2.0.0)

*(source: `docs/CHANGELOG.md`)*

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Human-readable composite identifiers (`object_id`, `service_id`, `asset_id`) and dual UID/human-readable topology links (`arodonata.core.models`, `arodonata.adapters.storage`, `arodonata.core.services`, `arodonata.client`, `arodonata.mcp`): non-unique indexed `object_id = "{mgmt_name}:{domain_name}:{name}"` on `CPObject` / `CPObjectRecord` (`arodonata_objects`), `service_id = "{mgmt_name}:{domain_name}:{name}"` on `CPService` / `CPServiceRecord` (`arodonata_services`), and `asset_id = "{mgmt_name}:{domain_name}:{name}"` on `Asset` / `AssetRecord` (`arodonata_assets`) alongside UID primary keys `id = "{mgmt_name}:{domain_name}:{uid}"`; `id`, `object_id`, and `parent_object_ids` on `GroupMembershipNode` in `SearchResult.memberships`; `parent_id`, `parent_asset_id`, `member_asset_ids`, and `virtual_system_asset_ids` on `Asset` / `AssetRecord` with cross-domain VSX gateway/cluster to Virtual System reconciliation across domains on the same management server; and composite identifier support across `find_object()`, `get_group_members()`, `search_objects()`, `query_objects()`, and MCP tools (`show_object`, `list_assets`, `get_group_members`, `query_objects`).
- Bilingual (English and Russian) documentation architecture (`docs/`, `mkdocs.yml`, `.github/workflows/docs.yml`) and NotebookLM monolithic knowledge bundles (`docs-notebooklm/arodonata_v2_bundle_Part1..Part3.md`).

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