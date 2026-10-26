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
