# Arodonata v2 — Capabilities, DB Schema, MCP Surface & Canonical OpenSpec Specifications

This bundle combines the Downstream Integration Guide (`docs/CAPABILITIES.md`), the complete 17-table SQLModel database schema (`docs/architecture/database-schema.md` + `src/arodonata/adapters/storage/tables.py`), the consolidated MCP Server specification (`docs/mcp/index.md`), and all 13 canonical OpenSpec capability specifications (`openspec/specs/*/spec.md`).


---

## Part 1: Downstream Integration Guide (`docs/CAPABILITIES.md`)

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

## Part 2: 17-Table Database Schema (`docs/architecture/database-schema.md`)

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
        json management_blades
        string asset_role "INDEX"
        string platform_family "INDEX"
        boolean is_policy_target "INDEX"
        boolean is_execution_target "INDEX"
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
| `management_blades` | `dict \| None` (JSON) | — | Enabled management blades (`multi-domain-server`, `network-policy-management`, `logging-and-status`, etc.); nullable for in-place `ALTER TABLE` evolution |
| `asset_role` | `str \| None` | `INDEX` | Normalized vendor-neutral role (`gateway`, `cluster`, `cluster_member`, `vsx_gateway`, `vsx_cluster`, `vsx_cluster_member`, `virtual_system`, `management_server`, `mds`, `log_server`, `interoperable_device`, `unknown`); legacy `NULL` rows auto-classify on read |
| `platform_family` | `str \| None` | `INDEX` | Normalized vendor platform (`gaia`, `gaia_embedded`, `maestro`, `cloudguard`, `open_server`, `unknown`); legacy `NULL` rows auto-classify on read |
| `is_policy_target` | `bool \| None` | `INDEX` | `True` for policy-enforcing targets (`gateway`, `cluster`, `virtual_system`); legacy `NULL` rows auto-classify on read |
| `is_execution_target` | `bool \| None` | `INDEX` | `True` for OS-backed CLI/upgrade hosts (`gateway`, `cluster_member`, `vsx_gateway`, `vsx_cluster_member`, `management_server`, `mds`, `log_server`); legacy `NULL` rows auto-classify on read |
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

### Canonical SQLModel Table Definitions (`src/arodonata/adapters/storage/tables.py`)

```python
"""SQLModel table definitions for Arodonata v2 persistence (`SQLite` and `PostgreSQL`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Column, DateTime
from sqlmodel import Field, SQLModel

from arodonata.core.errors import REDACTED_PLACEHOLDER
from arodonata.core.models.common import to_naive_utc, utc_now


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Normalize a datetime loaded from or written to SQLite/PostgreSQL to naive UTC (tzinfo=None)."""
    return to_naive_utc(dt)


class SchemaVersionRecord(SQLModel, table=True):
    """Tracks applied SQLModel metadata SHA-256 hashes to skip redundant migration checks."""

    __tablename__ = "arodonata_schema_version"

    schema_hash: str = Field(primary_key=True)
    applied_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class DistributedLockRecord(SQLModel, table=True):
    """Cross-process distributed lock row with expiration timestamp in `arodonata_distributed_locks`."""

    __tablename__ = "arodonata_distributed_locks"

    lock_key: str = Field(primary_key=True)
    owner_id: str = Field(index=True)
    acquired_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=False), nullable=False, index=True),
    )


class DomainRecord(SQLModel, table=True):
    """Cached Check Point domain metadata in `arodonata_domains`."""

    __tablename__ = "arodonata_domains"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    domain_type: str = Field(default="domain")
    active_ip: str | None = Field(default=None)
    active_mds_ip: str | None = Field(default=None, index=True)
    standby_ips: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    servers: list[dict[str, Any]] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    is_global: bool = Field(default=False, index=True)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class SIDCacheRecord(SQLModel, table=True):
    """Persistent shared read-only session cache row in `arodonata_sid_cache`.

    Strictly omits `sid` from `__repr__` and `__str__`.
    """

    __tablename__ = "arodonata_sid_cache"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    sid: str = Field(repr=False)
    server_ip: str
    tls_identity_host: str | None = Field(default=None)
    session_uid: str | None = Field(default=None)
    auth_identity: str | None = Field(default=None)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )
    last_used_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=False), nullable=True),
    )

    def __repr__(self) -> str:
        return (
            f"SIDCacheRecord(id={self.id!r}, mgmt_name={self.mgmt_name!r}, "
            f"domain_name={self.domain_name!r}, server_ip={self.server_ip!r}, "
            f"sid={REDACTED_PLACEHOLDER!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class DomainSyncStateRecord(SQLModel, table=True):
    """Unified per-`(mgmt_name, domain_name, scope, item_type)` synchronization state in `arodonata_domain_sync_state`."""

    __tablename__ = "arodonata_domain_sync_state"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    scope: str = Field(index=True)
    item_type: str = Field(default="*", index=True)
    last_published_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=False), nullable=True),
    )
    last_session_uid: str | None = Field(default=None)
    synced_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=False), nullable=True),
    )
    status: str = Field(default="idle")
    object_count: int = Field(default=0)
    last_error: str | None = Field(default=None)


class CPObjectRecord(SQLModel, table=True):
    """Cached network object row in `arodonata_objects`."""

    __tablename__ = "arodonata_objects"

    id: str = Field(primary_key=True)
    object_id: str = Field(default="", index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    type: str = Field(index=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    original_domain: str | None = Field(default=None, index=True)
    ipv4_address: str | None = Field(default=None, index=True)
    ipv6_address: str | None = Field(default=None)
    subnet4: str | None = Field(default=None, index=True)
    mask_length4: int | None = Field(default=None)
    subnet_mask: str | None = Field(default=None)
    ipv4_address_first: str | None = Field(default=None)
    ipv4_address_last: str | None = Field(default=None)
    fqdn: str | None = Field(default=None, index=True)
    is_sub_domain: bool | None = Field(default=None)
    members: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    color: str | None = Field(default=None)
    tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    nat_settings: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class CPServiceRecord(SQLModel, table=True):
    """Cached service object row in `arodonata_services`."""

    __tablename__ = "arodonata_services"

    id: str = Field(primary_key=True)
    service_id: str = Field(default="", index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    type: str = Field(index=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    original_domain: str | None = Field(default=None, index=True)
    port: str | None = Field(default=None, index=True)
    protocol: str | None = Field(default=None, index=True)
    icmp_type: int | None = Field(default=None)
    icmp_code: int | None = Field(default=None)
    members: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    session_timeout: int | None = Field(default=None)
    match_for_any: bool | None = Field(default=None)
    comments: str = Field(default="")
    color: str | None = Field(default=None)
    tags: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class AssetRecord(SQLModel, table=True):
    """Cached gateway, cluster, cluster member, VSX, or management server asset row in `arodonata_assets`."""

    __tablename__ = "arodonata_assets"

    id: str = Field(primary_key=True)
    asset_id: str = Field(default="", index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    type: str = Field(index=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    ipv4_address: str | None = Field(default=None, index=True)
    ipv6_address: str | None = Field(default=None)
    version: str | None = Field(default=None)
    os_name: str | None = Field(default=None)
    hardware: str | None = Field(default=None)
    sic_status: str | None = Field(default=None)
    parent_uid: str | None = Field(default=None, index=True)
    parent_name: str | None = Field(default=None)
    parent_id: str | None = Field(default=None, index=True)
    parent_asset_id: str | None = Field(default=None, index=True)
    member_uids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    member_asset_ids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    virtual_system_uids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    virtual_system_asset_ids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    interfaces: list[dict[str, Any]] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    network_security_blades: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    management_blades: dict[str, Any] | None = Field(
        default=None,
        sa_column=Column(JSON, nullable=True),
    )
    asset_role: str | None = Field(default=None, index=True)
    platform_family: str | None = Field(default=None, index=True)
    is_policy_target: bool | None = Field(default=None, index=True)
    is_execution_target: bool | None = Field(default=None, index=True)
    comments: str = Field(default="")
    color: str | None = Field(default=None)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class RulebasePackageLayerRecord(SQLModel, table=True):
    """Cached policy package to ordered layer/NAT linkage in `arodonata_rulebase_package_layer`."""

    __tablename__ = "arodonata_rulebase_package_layer"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    package_uid: str = Field(index=True)
    package_name: str = Field(index=True)
    rulebase_type: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    position: int = Field(default=0)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class RulebaseLayerRecord(SQLModel, table=True):
    """Cached rulebase layer row in `arodonata_rulebase_layer`."""

    __tablename__ = "arodonata_rulebase_layer"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    rulebase_type: str = Field(index=True)
    parent_layer_uid: str | None = Field(default=None, index=True)
    parent_rule_uid: str | None = Field(default=None, index=True)
    is_global: bool = Field(default=False)
    shared: bool = Field(default=False)
    implicit_cleanup_action: str | None = Field(default=None)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class RulebaseSectionRecord(SQLModel, table=True):
    """Cached rulebase section header row in `arodonata_rulebase_section`."""

    __tablename__ = "arodonata_rulebase_section"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    rulebase_type: str = Field(index=True)
    uid: str = Field(index=True)
    name: str = Field(index=True)
    position: int = Field(default=0)
    from_rule: int | None = Field(default=None)
    to_rule: int | None = Field(default=None)
    rule_uids: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class AccessRuleRecord(SQLModel, table=True):
    """Cached access-control rule row in `arodonata_rulebase_access`."""

    __tablename__ = "arodonata_rulebase_access"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="access-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    action: str | None = Field(default=None)
    inline_layer_uid: str | None = Field(default=None)
    inline_layer_name: str | None = Field(default=None)
    placeholder_domain_layer_uid: str | None = Field(default=None)
    source: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    destination: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    service: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    source_negate: bool = Field(default=False)
    destination_negate: bool = Field(default=False)
    service_negate: bool = Field(default=False)
    track: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class NatRuleRecord(SQLModel, table=True):
    """Cached NAT rule row in `arodonata_rulebase_nat`."""

    __tablename__ = "arodonata_rulebase_nat"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    package_uid: str = Field(index=True)
    package_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="nat-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    method: str | None = Field(default=None)
    auto_generated: bool = Field(default=False)
    original_source: str | None = Field(default=None)
    original_destination: str | None = Field(default=None)
    original_service: str | None = Field(default=None)
    translated_source: str | None = Field(default=None)
    translated_destination: str | None = Field(default=None)
    translated_service: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class HttpsRuleRecord(SQLModel, table=True):
    """Cached HTTPS inspection rule row in `arodonata_rulebase_https`."""

    __tablename__ = "arodonata_rulebase_https"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="https-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    action: str | None = Field(default=None)
    inline_layer_uid: str | None = Field(default=None)
    source: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    destination: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    service: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    site_category: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    certificate: str | None = Field(default=None)
    track: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class ThreatRuleRecord(SQLModel, table=True):
    """Cached Threat Prevention rule row in `arodonata_rulebase_threat`."""

    __tablename__ = "arodonata_rulebase_threat"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    layer_uid: str = Field(index=True)
    layer_name: str = Field(index=True)
    section_uid: str | None = Field(default=None, index=True)
    section_name: str | None = Field(default=None)
    uid: str = Field(index=True)
    name: str = Field(default="", index=True)
    rule_type: str = Field(default="threat-rule")
    position: int = Field(default=0)
    rule_number: str | None = Field(default=None)
    enabled: bool = Field(default=True)
    action: str | None = Field(default=None)
    protected_scope: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    source: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    destination: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    service: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    track: str | None = Field(default=None)
    install_on: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON, nullable=False),
    )
    comments: str = Field(default="")
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class GatewayTopologyRecord(SQLModel, table=True):
    """Cached pre-expanded IPv4 topology interval behind a gateway interface in `arodonata_gateway_topology`."""

    __tablename__ = "arodonata_gateway_topology"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    gateway_id: str = Field(default="", index=True)
    gateway_asset_id: str = Field(default="", index=True)
    gateway_uid: str = Field(index=True)
    gateway_name: str = Field(index=True)
    gateway_type: str = Field(default="simple-gateway")
    interface_name: str = Field(index=True)
    interface_ipv4: str | None = Field(default=None)
    interface_mask_length: int | None = Field(default=None)
    topology_zone: str = Field(default="internal", index=True)
    leads_to_dmz: bool = Field(default=False)
    anti_spoofing_mode: str = Field(default="unknown")
    source_type: str = Field(default="interface_connected", index=True)
    source_ref: str = Field(default="")
    cidr_or_range: str = Field(default="")
    ip_first_int: int = Field(
        sa_column=Column(BigInteger, nullable=False, index=True),
    )
    ip_last_int: int = Field(
        sa_column=Column(BigInteger, nullable=False, index=True),
    )
    prefix_len: int = Field(default=32)
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


class TopologyAnnotationRecord(SQLModel, table=True):
    """Persistent administrator override, standby route marker, or IPAM metadata in `arodonata_topology_annotations`."""

    __tablename__ = "arodonata_topology_annotations"

    id: str = Field(primary_key=True)
    mgmt_name: str = Field(index=True)
    domain_name: str = Field(index=True)
    gateway_uid: str = Field(index=True)
    gateway_name: str = Field(default="", index=True)
    interface_name: str = Field(default="*", index=True)
    cidr_or_range: str = Field(default="*", index=True)
    trust_static_topology: bool | None = Field(default=None)
    disposition: str | None = Field(default=None, index=True)
    topology_zone: str | None = Field(default=None)
    zone: str = Field(default="")
    site: str = Field(default="")
    comment: str = Field(default="")
    custom_metadata: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON, nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=False), nullable=False),
    )


ARODONATA_TABLE_NAMES: frozenset[str] = frozenset(
    {
        SchemaVersionRecord.__tablename__,
        DistributedLockRecord.__tablename__,
        DomainRecord.__tablename__,
        SIDCacheRecord.__tablename__,
        DomainSyncStateRecord.__tablename__,
        CPObjectRecord.__tablename__,
        CPServiceRecord.__tablename__,
        AssetRecord.__tablename__,
        RulebasePackageLayerRecord.__tablename__,
        RulebaseLayerRecord.__tablename__,
        RulebaseSectionRecord.__tablename__,
        AccessRuleRecord.__tablename__,
        NatRuleRecord.__tablename__,
        HttpsRuleRecord.__tablename__,
        ThreatRuleRecord.__tablename__,
        GatewayTopologyRecord.__tablename__,
        TopologyAnnotationRecord.__tablename__,
    }
)
```

---

## Part 3: Consolidated MCP Server & Tools (`docs/mcp/index.md`)

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

## Part 4: Canonical OpenSpec System Specifications (`openspec/specs/`)


---

### OpenSpec Capability: `ai-builder` (`openspec/specs/ai-builder/spec.md`)

# ai-builder Specification

## Purpose

Defines packaging isolation, consolidated Check Point quirk knowledge bundles, compact SDK quick-reference generation, and multi-agent skill/playbook contracts for authoring lightweight Check Point automation scripts on top of Arodonata and `arlogi`.

## Requirements

### Requirement: Python Distribution Packaging Isolation

**ID**: REQ-AIBUILD-001\
**Intent**: Keep `uv add arodonata` and `pip install arodonata` lightweight and free of repository-hosted AI skill packs or large LLM bundles.\
**Non-goals**: Publishing `plugins/arodonata-aibuilder` as an importable Python runtime module inside `arodonata`.

Both wheel and source distribution (`sdist`) builds of the `arodonata` package MUST exclude repository-hosted `plugins/` directories and `docs-notebooklm/` knowledge bundles so installing `arodonata` distributes strictly the Python SDK artifacts.

#### Scenario: SCN-AIBUILD-001-1 — Wheel and sdist exclude AI builder plugins and NotebookLM bundles

- **GIVEN** the repository contains `docs-notebooklm/` bundles and `plugins/` skill directories
- **WHEN** wheel and source distribution package targets are inspected or built from `pyproject.toml`
- **THEN** wheel packages SHALL include only `src/arodonata`
- **AND** source distributions SHALL exclude `plugins/` and `docs-notebooklm/`

### Requirement: Check Point API and Operational Quirks Knowledge Bundle

**ID**: REQ-AIBUILD-002\
**Intent**: Ensure LLM context bundles and documentation sites carry authoritative Check Point API and operational automation pitfalls in one synchronized build.\
**Non-goals**: Modifying runtime `ArodonataClient` transport or asset classification logic.

The documentation bundle build MUST include Check Point Management API quirks, Check Point operational automation quirks (gateway/cluster/VSX boundaries, Gaia `python3` vs. Gaia Embedded `sh` execution, `cpinfo`/`cplp`/CPUSE collection, CDT workflows, MDSM Global/Local rules, and CLI SQLite + `arlogi` usage), and all tracked runnable examples without embedding live secrets or session identifiers.

#### Scenario: SCN-AIBUILD-002-1 — Generated guide bundle includes API and operational quirks

- **GIVEN** `docs/troubleshooting/checkpoint-api-quirks.md` and `docs/troubleshooting/checkpoint-ops-quirks.md` exist in the documentation tree
- **WHEN** the documentation bundle build executes
- **THEN** `docs-notebooklm/01-guide-and-concepts.md` and the portable HTML staging directory SHALL include both quirk documents with resolved snippets
- **AND** MkDocs navigation SHALL expose both troubleshooting guides without broken links

#### Scenario: SCN-AIBUILD-002-2 — Generated examples bundle includes all tracked runnable examples

- **GIVEN** tracked example guides exist in `docs/examples/` (including `01` through `13`)
- **WHEN** the documentation bundle build executes
- **THEN** `docs-notebooklm/03-examples-and-recipes.md` SHALL embed every tracked example guide in deterministic order

### Requirement: Deterministic Agent SDK Quick-Reference Generation

**ID**: REQ-AIBUILD-003\
**Intent**: Provide AI coding agents with a compact, up-to-date signature cheat sheet extracted from the actual `arodonata` codebase so generated scripts never hallucinate SDK methods or model fields.\
**Non-goals**: Replacing the full multi-thousand-line `docs-notebooklm/02-api-reference.md` reference.

The documentation bundle build MUST generate a deterministic, compact Markdown SDK quick-reference summarizing current `arodonata.__version__`, public `ArodonataClient` and `ScriptRepositoryService` signatures, key fields of `Asset`, `CPObject`, and `CPService`, `CPCRUDService` and `ApiReferenceEngine` entry points, `arodonata.testing` replay helpers, and idiomatic `arlogi` CLI logging setup.

#### Scenario: SCN-AIBUILD-003-1 — SDK quick-reference matches public package exports and signatures

- **GIVEN** the current `arodonata` source tree in `src/arodonata`
- **WHEN** the documentation bundle build generates the compact SDK quick-reference
- **THEN** the output Markdown SHALL match `arodonata.__version__` and include verified signatures and model fields for `ArodonataClient`, `Asset`, `CPObject`, `CPService`, `ScriptRepositoryService`, `CPCRUDService`, and `ApiReferenceEngine`
- **AND** re-running the generator without source edits SHALL produce byte-identical output

#### Scenario: SCN-AIBUILD-003-2 — Valid default-factory rendering and complete arodonata.testing method coverage

- **GIVEN** Pydantic fields using `lambda` `default_factory` expressions (including `ArodonataSettings.tls_known_hosts_path`) and public methods on `FileReplayApiMock` and `CheckPointReplayHttpServer`
- **WHEN** the documentation bundle build generates `docs-notebooklm/05-sdk-quickref.md`
- **THEN** lambda-backed defaults SHALL render valid Python expressions without invalid `lambda: ...()` syntax
- **AND** `FileReplayApiMock` and `CheckPointReplayHttpServer` sections SHALL include all public methods and properties without `[:8]` truncation


---

### OpenSpec Capability: `api-reference` (`openspec/specs/api-reference/spec.md`)

# Check Point API Reference Engine Specification

## Purpose

Defines the bundled multi-version Check Point API schema index (`cp_api_index.json.gz`, covering Management API `v1.9` through `v2.2` and Gaia API `v2.0.1`), lazy in-memory `ApiReferenceEngine`, two-step command discovery (`search_commands` and `describe_command` with dynamic version filtering), and offline request payload validation (`validate_payload`).

## Requirements

### Requirement: Bundled Multi-Version API Schema Index and Lazy Loading

**ID**: REQ-APIREF-001\
**Intent**: Provide offline access to multi-version Check Point API schemas without startup overhead or network dependencies.\
**Non-goals**: Inferring default management server versions from client topology (handled by `ArodonataClient`, `REQ-CLIENT-014`).

`arodonata.api_reference` SHALL package the compressed multi-version Check Point API schema bundle (`cp_api_index.json.gz`, covering Management API `v1.9`, `v2`, `v2.1`, `v2.2` and Gaia API `v2.0.1`) inside the installed distribution, load and decompress it lazily in memory via zero-argument `get_api_reference()` / `ApiReferenceEngine.default()` (or custom index files via `ApiReferenceEngine.from_path(path)`), and perform zero network or database calls.

#### Scenario: SCN-APIREF-001-1 — Default bundled index loads lazily without network or database access

- **GIVEN** an offline process with no `ArodonataClient` or database configured
- **WHEN** `get_api_reference()` or `ApiReferenceEngine.default()` is called
- **THEN** it SHALL decompress the bundled `cp_api_index.json.gz` into memory once and cache the singleton instance for subsequent calls
- **AND** it SHALL expose `meta` (`versions`, `latest`, `commands_count`, `shared_objects_count`, `enums_count`)
- **AND** it SHALL perform zero network or database calls

### Requirement: Version-Aware Command Search

**ID**: REQ-APIREF-002\
**Intent**: Allow callers and agents to discover relevant Check Point API commands quickly without loading full schemas.\
**Non-goals**: Returning full per-command field definitions and nested object schemas (`REQ-APIREF-003`).

`ApiReferenceEngine.search_commands` (and top-level helper `search_api_commands`) SHALL provide ranked lightweight command summaries filtered by `version`, `category`, `crud_type`, and `api_family`.

#### Scenario: SCN-APIREF-002-1 — Step 1 search filters by API version, CRUD type, and category

- **WHEN** `search_commands("export-access-rulebase", version="v1.9")` and `search_commands("export-access-rulebase", version="v2.2")` are called
- **THEN** the `v1.9` search SHALL exclude commands introduced after `v1.9`
- **AND** the `v2.2` search SHALL return the matching command summary with `added_in`, `supported_versions`, and `short_description`

### Requirement: Version-Filtered Command Schema Inspection

**ID**: REQ-APIREF-003\
**Intent**: Expose accurate, version-scoped request schemas and examples on demand for one or more commands.\
**Non-goals**: Ranking or searching commands by keyword (`REQ-APIREF-002`) or validating user payloads (`REQ-APIREF-004`).

`ApiReferenceEngine.describe_command` (and top-level helper `describe_api_command`) SHALL accept one or more command names and return resolved schemas (`fields`, `field_alternatives`, `nested_objects`, `enums`, `example`) dynamically filtered to the target API version for `"management"` commands while preserving fields for non-management (`"gaia"`/`"cme"`) commands.

#### Scenario: SCN-APIREF-003-1 — Step 2 describe dynamically filters fields and nested objects by target version

- **WHEN** `describe_command("add-interface", version="v1.9")` and `describe_command("add-interface", version="v2.2")` are called
- **THEN** the `v1.9` schema SHALL include `v1.9`-only fields (such as `gateway-owner` and `anti-spoofing-enabled`) and omit `v2+`-only fields
- **AND** the `v2.2` schema SHALL include only fields and nested objects valid in `v2.2`

#### Scenario: SCN-APIREF-003-2 — Batch describe accepts multiple command names in a single call

- **WHEN** `describe_command(["add-host", "set-host"], version="v2.2")` is called with a list of command names
- **THEN** it SHALL return resolved command descriptions for each requested command
- **AND** it SHALL report any unknown or version-unsupported command names clearly

#### Scenario: SCN-APIREF-003-3 — Gaia and CME commands preserve fields and validate payloads under default v2.2 and v2.0.1

- **GIVEN** bundled `"gaia"` and `"cme"` commands (such as `gaia-show-interface`, `cme-azure`, `cme-management`)
- **WHEN** `describe_command()` or `validate_payload()` is called with default `version="v2.2"` or `version="v2.0.1"`
- **THEN** non-management commands SHALL retain their `fields` and nested objects without management-version stripping and validate valid payloads as `valid=True`

### Requirement: Offline Request Payload Validation Against Versioned Schema

**ID**: REQ-APIREF-004\
**Intent**: Catch invalid commands, missing required parameters, and incompatible fields offline before sending requests.\
**Non-goals**: CPCRUD declarative template schema validation (`REQ-CPCRUD-001`) or server-side semantic checks.

`ApiReferenceEngine.validate_payload(command, payload, *, version="v2.2")` (and `validate_api_payload`) SHALL validate a candidate request `payload` dictionary offline against the command's schema for `version`, reporting structured validation errors for unknown or version-unsupported commands and fields, missing `required` fields, unsatisfied or conflicting `field_alternatives`, invalid types, and enum `valid_values` mismatches.

#### Scenario: SCN-APIREF-004-1 — Payload validation catches missing required fields and version-unsupported parameters

- **WHEN** `validate_payload("add-host", {"color": "invalid-color"}, version="v2.2")` is called
- **THEN** it SHALL return `valid=False` with zero network or database calls
- **AND** the errors SHALL identify missing required fields (`name` and `ip-address` / `ipv4-address` / `ipv6-address`) and the invalid enum value for `color`


---

### OpenSpec Capability: `cache-and-sync` (`openspec/specs/cache-and-sync/spec.md`)

# Cache, Synchronization, and Search Specification

## Purpose

Defines the database-backed cache and distributed locking layer (`CachePort`, `LockPort`, `arodonata_*` tables) with schema hash auto-migration (`arodonata_schema_version`), selective object, service, asset, and topology synchronization (`ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `TopologyService`, `DomainSyncCoordinator`), cross-domain VSX enrichment, and recursive object/group search (`SearchService`).

## Requirements

### Requirement: Schema Hash Auto-Migration and Multi-Backend Persistence

**ID**: REQ-CACHE-001\
**Intent**: Initialize and evolve Arodonata SQL tables safely across concurrent workers sharing a host PostgreSQL or SQLite database.\
**Non-goals**: Cache synchronization policies (`REQ-CACHE-004`, `REQ-CACHE-005`) or distributed work locks (`REQ-CACHE-003`).

The SQL persistence layer SHALL support PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`), prefix all Arodonata tables with `arodonata_` (`ARODONATA_TABLE_NAMES`), serialize migration across workers (`pg_advisory_xact_lock` / `BEGIN IMMEDIATE`) with double-checked `schema_hash` and table verification, and drop legacy unprefixed v1 tables ONLY when a positive v1 column fingerprint (`mdm_dmn` or `mgmt_dmn_key`) exists.

#### Scenario: SCN-CACHE-001-1 — Unchanged schema hash skips table inspection

- **GIVEN** the cross-worker initialization lock (`pg_advisory_xact_lock` or `BEGIN IMMEDIATE`) is acquired
- **WHEN** `arodonata_schema_version` already contains the current `schema_hash` and all tables in `ARODONATA_TABLE_NAMES` exist
- **THEN** schema initialization SHALL skip per-table column/index migration inspection and mark the cache initialized immediately
- **AND** if any table in `ARODONATA_TABLE_NAMES` was dropped out-of-band, it SHALL re-run table creation even when `schema_hash` matched

#### Scenario: SCN-CACHE-001-2 — Schema evolution applies missing columns and records new hash

- **GIVEN** a database shared with host application tables (`SQLModel.metadata`) where Arodonata's schema hash is absent from `arodonata_schema_version`
- **WHEN** database initialization runs inside the serialized migration lock
- **THEN** it SHALL inspect only `arodonata_*` tables in `ARODONATA_TABLE_NAMES`, create new Arodonata tables with naive UTC timestamp columns, and apply missing columns/indexes (or recreate `arodonata_*` tables when column types or `NOT NULL` constraints change)
- **AND** it SHALL insert the new `schema_hash` row into `arodonata_schema_version`

#### Scenario: SCN-CACHE-001-3 — Legacy v1 cache table with incompatible primary key is dropped and recreated

- **GIVEN** an incompatible `arodonata_*` table or a legacy v1 table (`domains` / `sid_cache`) matching `mdm_dmn` or `mgmt_dmn_key`
- **AND** an unprefixed host table (`domains`, `sid_cache`, `distributed_locks`, `domain_sync_state`) lacking that v1 fingerprint
- **WHEN** database initialization runs
- **THEN** it SHALL drop only positively fingerprinted legacy v1 tables and recreate incompatible `arodonata_*` tables
- **AND** it SHALL leave unprefixed host tables completely untouched

#### Scenario: SCN-CACHE-001-4 — Local SQLite cache directory and database file enforce owner-only permissions

- **WHEN** `DatabaseManager` initializes a file-backed local SQLite cache database (`sqlite+aiosqlite:///...`, non-memory)
- **THEN** its parent directory SHALL be created with mode `0700` and the database file SHALL enforce owner-only read/write permissions (`0600`) to protect cached `arodonata_sid_cache` rows at rest

### Requirement: Human-Readable Composite Identifiers Across Cached Entities

**ID**: REQ-CACHE-002\
**Intent**: Allow duplicate-named Check Point entities to coexist cleanly under UID primary keys while exposing human-readable lookup keys.\
**Non-goals**: Resolving cross-domain ambiguity at query time (`REQ-CACHE-014`).

`CPObject` (`arodonata_objects`), `CPService` (`arodonata_services`), and `Asset` (`arodonata_assets`) SHALL keep `id = "{mgmt_name}:{domain_name}:{uid}"` as primary key while persisting non-unique indexed human-readable keys (`object_id`, `service_id`, `asset_id` formatted as `"{mgmt_name}:{domain_name}:{name}"`) and dual UID/human-readable links on `GroupMembershipNode`.

#### Scenario: SCN-CACHE-002-1 — Duplicate-named objects with distinct UIDs coexist with identical human-readable IDs

- **GIVEN** a domain containing two Check Point objects or services with the same `name` (such as `email`) and distinct `uid` values
- **WHEN** both entities are cached
- **THEN** both rows SHALL be stored without collision under distinct `id` primary keys (`"{mgmt_name}:{domain_name}:{uid}"`)
- **AND** both rows SHALL expose the same indexed `object_id` or `service_id` (`"{mgmt_name}:{domain_name}:{name}"`)

#### Scenario: SCN-CACHE-002-2 — Object rename during incremental sync updates object_id in place

- **GIVEN** a cached Check Point object renamed on the management server
- **WHEN** `"smart-fast"` (`show-changes`) or a full refresh synchronizes the domain
- **THEN** the existing row keyed by `id = "{mgmt_name}:{domain_name}:{uid}"` SHALL update in place with the new `name` and recomputed `object_id = "{mgmt_name}:{domain_name}:{new_name}"`
- **AND** no orphaned row under the old name SHALL remain

#### Scenario: SCN-CACHE-002-3 — Group membership traversal includes human-readable group composite IDs

- **WHEN** `SearchService.search_objects()` resolves containing parent groups for matched objects
- **THEN** each `GroupMembershipNode` in `SearchResult.memberships` SHALL populate `id` (`"{mgmt_name}:{domain_name}:{uid}"`), `object_id` (`"{mgmt_name}:{domain_name}:{name}"`), `parent_uids`, and `parent_object_ids`

### Requirement: Database-Backed Distributed Locks

**ID**: REQ-CACHE-003\
**Intent**: Serialize critical domain sync operations across processes without stale locks outliving crashed workers.\
**Non-goals**: Per-MDS-member API concurrency semaphores (`REQ-SESS-007`).

`LockPort` SHALL coordinate cross-process critical sections using `arodonata_distributed_locks` with explicit lock expiration (`expires_at`) evaluated against the database server's UTC clock, owner-verified lock renewal (`renew` / heartbeat) and `release`, and retry resilience against transient database serialization/deadlock errors.

#### Scenario: SCN-CACHE-003-1 — Expired lock reclamation

- **GIVEN** a `lock_key` row in `arodonata_distributed_locks` whose `expires_at` is in the past according to the database server's UTC clock
- **WHEN** a worker acquires `lock_key`
- **THEN** the lock adapter SHALL atomically reclaim the expired lock for the new `owner_id`
- **AND** `release(lock_key, owner_id)` SHALL delete the row ONLY when `owner_id` matches the active holder

#### Scenario: SCN-CACHE-003-2 — Active sync renews distributed lock before TTL expiration

- **GIVEN** a long-running domain object, service, asset, or rulebase refresh holding a lock in `arodonata_distributed_locks`
- **WHEN** synchronization remains active across renewal intervals
- **THEN** `DomainSyncCoordinator` SHALL periodically renew `expires_at` via a background heartbeat so active syncs never lose their lock mid-flight

### Requirement: Concurrent Multi-Domain Sync Coordination and Failure Isolation

**ID**: REQ-CACHE-004\
**Intent**: Maximize multi-domain refresh throughput per MDS without overwhelming endpoints, duplicating in-flight syncs, or masking real failures.\
**Non-goals**: Type-specific object, service, asset, or rulebase refresh logic (`REQ-CACHE-005`..`REQ-CACHE-012`).

`DomainSyncCoordinator` SHALL refresh domains concurrently per MDS member (`active_mds_ip`, up to `settings.domain_sync_concurrency`) via `asyncio.TaskGroup` while coalescing concurrent same-scope syncs, emit structured `arlogi` progress logs (`DEBUG` on start/completion/skip/batch; `WARNING` on failure), record `sid`-redacted errors without falsely failing `LockAcquisitionError`, and avoid implicit warm-up on `get_domains()`.

#### Scenario: SCN-CACHE-004-1 — Parallel domain refresh per MDS member and background first-use warm-up

- **GIVEN** multiple domains hosted across one or more MDS members
- **WHEN** `DomainSyncCoordinator.ensure()` refreshes domains and `get_domains()` runs
- **THEN** domains SHALL refresh concurrently up to `settings.domain_sync_concurrency` (default `min(2, max(1, concurrent_limit - 1))`) per `active_mds_ip`, reusing the caller's active MDS permit on re-entrant coordinator calls
- **AND** concurrent in-process syncs for the same `(mgmt_name, domain_name, scope)` SHALL coalesce, writes SHALL batch safely, and a fatal `ServerIdentityError` SHALL cancel sibling tasks immediately
- **AND** `get_domains()` SHALL return domains without implicitly triggering background object-cache warm-up (`start_object_cache_warmup` is invoked explicitly)

#### Scenario: SCN-CACHE-004-2 — Refresh failure visibility, unreachable server resilience, and InvalidCredentialsError handling

- **GIVEN** a domain staleness probe or refresh failing with an API/auth error (`InvalidCredentialsError`, etc.), a server failing `get_domains()` during `mgmt_name=None` refresh, or a domain hitting `LockAcquisitionError`
- **WHEN** a multi-domain or multi-server refresh executes
- **THEN** genuine errors (including failed server domain discovery) SHALL be recorded in `RefreshOutcome.failed_domains`, `arodonata_domain_sync_state.last_error`, and `DomainSyncFailedEvent` (`WARNING` log) with `sid`s redacted
- **AND** previously cached objects SHALL remain intact and synchronization SHALL continue on all reachable servers
- **AND** `LockAcquisitionError` SHALL NOT overwrite `arodonata_domain_sync_state.status` as `"failed"` or emit a false failure event

#### Scenario: SCN-CACHE-004-3 — Domain and wildcard invalidation persists across scopes until each scope refreshes

- **GIVEN** `invalidate_domain(mgmt_name, domain)` or `invalidate_domain(mgmt_name, None)` (wildcard) is invoked within `cache_ttl`
- **WHEN** only one scope or domain (`"objects"`, `"services"`, `"assets"`, `"rulebase"`, or `"topology"`) subsequently runs a `"smart"` or `"smart-fast"` sync
- **THEN** only slices whose `synced_at` is newer than the invalidation timestamp SHALL be treated as fresh, preserving invalidation for every other invalidated domain and scope until each refreshes

### Requirement: Object Cache Refresh Modes and Incremental Sync

**ID**: REQ-CACHE-005\
**Intent**: Synchronize network objects accurately using head-stamp comparisons and incremental diffs without leaving partial state on error.\
**Non-goals**: On-demand `application-site` objects (`REQ-CACHE-006`) or service tables (`REQ-CACHE-007`).

`ObjectService` SHALL support four `CacheMode` values (`"cache"`, `"smart"`, `"smart-fast"`, and `"force"`), default to syncing `("host", "network", "address-range", "group", "dns-domain")` into `arodonata_objects`, track revision state per `(mgmt_name, domain_name, scope, item_type)` in `arodonata_domain_sync_state` within the same atomic transaction using dialect `ON CONFLICT` upserts, and expose `refresh_objects` and `stream_refresh_objects`.

#### Scenario: SCN-CACHE-005-1 — Smart/Check refresh reloads only stale domains atomically and handles never-published domains

- **GIVEN** domains with differing `show-last-published-session` timestamps/UIDs or never-published domains (`last_published_at=None`)
- **WHEN** `await client.refresh_objects(mode="smart")` or a read helper with `cache_mode="smart"` runs
- **THEN** the coordinator SHALL compare `show-last-published-session` (`last_published_at` and `last_session_uid`, preserving `None` for never-published domains) against `arodonata_domain_sync_state`
- **AND** it SHALL verify the shared session is clean (failing closed if `show-session` fails) and reload only missing or stale `item_type` slices and sync-state rows in one atomic transaction under a renewed domain lock
- **AND** it SHALL emit `DomainSyncStartedEvent`, `DomainSyncCompletedEvent`, `DomainSyncSkippedEvent`, and `SyncCompletedEvent` alongside `DEBUG` progress logs

#### Scenario: SCN-CACHE-005-2 — Incremental refresh applies show-changes diff or falls back safely

- **GIVEN** stale `item_type` rows with a known baseline in `arodonata_domain_sync_state`
- **WHEN** `await client.refresh_objects(mode="smart-fast")` or a read helper with `cache_mode="smart-fast"` runs
- **THEN** the service SHALL query `show-changes` preferring `from-session` (`last_session_uid`) over UTC `Z`-suffixed `from-date`, unwrap `new-object`/`old-object`, delete removed objects, upsert changes via `ON CONFLICT`, and update sync state atomically
- **AND** if changes exceed `max_incremental_changes` (default `500`) or any error occurs, it SHALL fall back automatically to an atomic type-scoped reload

### Requirement: On-Demand Application-Site Object Model and Synchronization

**ID**: REQ-CACHE-006\
**Intent**: Cache Check Point `application-site` URL lists and regex flags on demand without bloating default network-object syncs.\
**Non-goals**: Declarative CPCRUD `application-site` planning and patching (`REQ-CPCRUD-006`, `REQ-CPCRUD-007`).

`CPObject` and `ObjectService` SHALL support Check Point `application-site` objects on demand via `show-application-sites` (bulk sync) and universal `show-object` (single-UID incremental sync), while `HybridStateReader` queries `show-application-site`, hydrating `primary_category`, `url_list`, and `urls_defined_as_regular_expression`.

#### Scenario: SCN-CACHE-006-1 — CPObject hydrates application-site URL list and regex flag from Check Point dict and DB cache

- **GIVEN** a Check Point `application-site` payload containing `primary-category`, `url-list`, and `urls-defined-as-regular-expression`
- **WHEN** `CPObject.from_cp_dict()` or `CachePort` hydrates the object
- **THEN** `CPObject` SHALL expose `type == "application-site"`, `primary_category`, `url_list` as `list[str]`, and `urls_defined_as_regular_expression` as `bool | None`

#### Scenario: SCN-CACHE-006-2 — On-demand refresh and incremental update of application-site objects

- **WHEN** `refresh_objects(types=["application-site"])`, `get_objects(types=["application-site"])`, or incremental `smart-fast` refresh runs
- **THEN** `ObjectService` SHALL use `show-application-sites` for full reload and `show-object` for single-UID incremental `smart-fast` updates
- **AND** it SHALL persist rows in `arodonata_objects` with `item_type="application-site"` in `arodonata_domain_sync_state` and return hydrated `CPObject` entries

### Requirement: Dedicated Service Cache Table and Selective Refresh

**ID**: REQ-CACHE-007\
**Intent**: Keep service synchronization modular and avoid overwriting cached service slices during targeted refreshes.\
**Non-goals**: Network object caching (`REQ-CACHE-005`) or gateway topology extraction (`REQ-CACHE-011`).

`ServiceCacheService` and `CachePort` SHALL persist service objects in `arodonata_services` (`CPService`), tracking `(mgmt_name, domain_name, "services", item_type)` in `arodonata_domain_sync_state` atomically (preferring `from-session` over UTC `Z`-suffixed `from-date` in `"smart-fast"` mode), refreshing `("service-tcp", "service-udp", "service-icmp", "service-group")` by default and other types on demand via `types`.

#### Scenario: SCN-CACHE-007-1 — Default service refresh loads core variable service types

- **WHEN** `await client.refresh_services(mode="smart")` runs without an explicit `types` list
- **THEN** the service SHALL synchronize `service-tcp`, `service-udp`, `service-icmp`, and `service-group` rows into `arodonata_services`
- **AND** it SHALL record each type's `last_published_at`, `last_session_uid`, and `synced_at` in `arodonata_domain_sync_state` in the same atomic transaction

#### Scenario: SCN-CACHE-007-2 — Explicit service types sync on demand without wiping other cached service types

- **GIVEN** a domain with `service-tcp` already cached in `arodonata_services`
- **WHEN** `await client.refresh_services(types=["service-other"])` is called
- **THEN** only `service-other` rows SHALL be fetched and replaced in `arodonata_services` (preserving existing `service-tcp` rows)
- **AND** `arodonata_domain_sync_state` SHALL record the sync state for `item_type="service-other"`

### Requirement: Asset and Gateway Cache Synchronization

**ID**: REQ-CACHE-008\
**Intent**: Cache gateway, cluster, VSX, and management assets safely in `arodonata_assets` with real-time progress streaming.\
**Non-goals**: Parent-child relationship enrichment across domains (`REQ-CACHE-009`, `REQ-CACHE-010`).

`AssetRefreshService` (`refresh_assets`, `stream_refresh_assets`) and `CachePort` SHALL persist gateways, clusters, cluster members, VSX gateways/clusters (via encapsulated `generic-object` topology queries), and management servers in `arodonata_assets` concurrently via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`) with UID primary keys (`id`) and indexed composite identifiers (`asset_id`).

#### Scenario: SCN-CACHE-008-1 — Concurrent domain asset collection with interleaved SSE events

- **WHEN** `stream_refresh_assets()` runs across multiple servers and domains
- **THEN** it SHALL collect domains concurrently per MDS member (`settings.domain_sync_concurrency`) and persist rows in `arodonata_assets` (avoiding collision with host `assets` tables)
- **AND** it SHALL emit typed `SyncProgressEvent` items (convertible to SSE events) tagged with `mgmt_name` and `domain`
- **AND** it SHALL link cluster members and VSX virtual systems (`parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`) and update `arodonata_domain_sync_state` (`scope="assets"`, `item_type="*"`)

### Requirement: Cluster and Cross-Domain VSX Parent-Child Topology Enrichment

**ID**: REQ-CACHE-009\
**Intent**: Reconcile parent-child links across clusters and cross-domain VSX Virtual Systems on the same management server.\
**Non-goals**: VSX slot object metadata retrieval (`REQ-CACHE-010`).

`ClusterRelationshipManager` and `VSXRelationshipManager` SHALL enrich cached `arodonata_assets` rows with bidirectional parent-child topology attributes (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`), including cross-domain VSX parent/child links on the same `mgmt_name`.

#### Scenario: SCN-CACHE-009-1 — Cluster members and VSX virtual systems link bidirectionally to parent containers

- **WHEN** `ClusterRelationshipManager` and `VSXRelationshipManager` enrich gateway, cluster, cluster-member, VSX, and virtual-system assets on `mgmt_name`
- **THEN** child assets SHALL populate `parent_uid`, `parent_name`, `parent_id` (`"{mgmt_name}:{parent_domain}:{parent_uid}"`), and `parent_asset_id` (`"{mgmt_name}:{parent_domain}:{parent_name}"`)
- **AND** parent cluster or VSX containers SHALL list all child `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids` across domains on `mgmt_name`

#### Scenario: SCN-CACHE-009-2 — Cross-domain VSX gateway and Virtual System topology reconciliation

- **GIVEN** a VSX gateway (`vsx_gateway` or `vsx_cluster`) cached in domain `"VSX"` and its Virtual System (`virtual_system`) cached in `"Domain4"` on `"mds"`
- **WHEN** asset relationship reconciliation runs across `mgmt_name`
- **THEN** the Virtual System SHALL populate `parent_uid`, `parent_name`, `parent_id` (`"mds:VSX:<vsx-uid>"`), and `parent_asset_id` (`"mds:VSX:<vsx-name>"`)
- **AND** the parent VSX asset SHALL populate `virtual_system_uids` and `virtual_system_asset_ids` (`["mds:Domain4:<vs-name>"]`)

### Requirement: VSX Slot Generic Object Enrichment for Cross-Domain Virtual Systems

**ID**: REQ-CACHE-010\
**Intent**: Recover missing VSX parent links and slot route/interface metadata stored in Check Point VSX slot generic objects.\
**Non-goals**: Translating slot routes into `GatewayTopologyEntry` intervals (`REQ-TOPO-006`).

`VSXRelationshipManager` SHALL query `com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj` (`vsid == 0`) and `com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj` (`vsid > 0`) alongside `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, and `CpmiVsClusterNetobj`, linking cross-domain Virtual Systems via `targetCustomer` and `vsxGateway` and preserving slot `interfaces`, `interfaces_installed`, `routes`, and `routes_installed`.

#### Scenario: SCN-CACHE-010-1 — VSX slot objects in the VSX domain link a Virtual System in a tenant domain and attach VS routes

- **GIVEN** a VSX domain storing `CpmiVsxSlotObj` (`vsid=0`, `vsxGateway="vsx-uid"`) and `CpmiVsSlotObj` (`vsid=1`, `name="VS_Tenant"`, `targetCustomer="TenantDomain"`, `vsxGateway="vsx-uid"`, `routes=[...]`)
- **AND** `"VS_Tenant"` (`CpmiVsNetobj`) in `"TenantDomain"` lacking a direct `vsx-gateway` field
- **WHEN** `VSXRelationshipManager` reconciles VSX relationships on `"mds1"`
- **THEN** it SHALL link `"mds1:TenantDomain:VS_Tenant"` to parent `"mds1:VSXDomain:<vsx-name>"`
- **AND** it SHALL merge the slot's `routes` and `interfaces` metadata onto `"VS_Tenant"`'s `raw_data`

### Requirement: Gateway Interface Topology Persistence and Coordinator Synchronization

**ID**: REQ-CACHE-011\
**Intent**: Store normalized gateway IPv4 intervals persistently and refresh them safely under domain sync coordination.\
**Non-goals**: Detailed interface extraction, route collection, and candidate matching logic (`REQ-TOPO-001`..`REQ-TOPO-018`).

`CachePort` and the SQL persistence layer SHALL persist normalized gateway topology intervals in `arodonata_gateway_topology` (registered in `ARODONATA_TABLE_NAMES`), and `TopologyService` (`refresh_topology`, `stream_refresh_topology`) SHALL synchronize domain topology under `DomainSyncCoordinator` (`scope="topology"`, `item_type="*"`) with atomic per-domain replacement (`replace_domain_topology`).

#### Scenario: SCN-CACHE-011-1 — Atomic domain topology replacement and sync state recording

- **WHEN** `await client.refresh_topology(mgmt_name="mds1", domains=["Domain4"], mode="force")` completes
- **THEN** `TopologyService` SHALL ensure domain assets and network objects are fresh and compute all `GatewayTopologyEntry` rows for `"Domain4"`
- **AND** it SHALL atomically replace existing `"Domain4"` rows in `arodonata_gateway_topology` alongside `arodonata_domain_sync_state` (`scope="topology"`, `item_type="*"`)
- **AND** `SearchService.get_cache_status()` SHALL expose `"topology"` freshness

### Requirement: Exclusive Coordinator-Synchronized Rulebase Cache Writes

**ID**: REQ-CACHE-012\
**Intent**: Prevent read-only report consumers from overwriting newer rulebase snapshots outside distributed lock and sync-state coordination.\
**Non-goals**: Rulebase package/layer fetching and numbering semantics (`REQ-RULE-001`..`REQ-RULE-004`).

Shared `arodonata_rulebase_*` cache tables SHALL be written exclusively under `DomainSyncCoordinator` per-domain distributed locks after `verify_session_clean` succeeds and within an atomic transaction that updates `arodonata_domain_sync_state` (`scope="rulebase"`, `item_type="*"`); read-only consumers (including `arodonata.reports`) SHALL NEVER invoke `CachePort.replace_domain_rulebase` directly out-of-band.

#### Scenario: SCN-CACHE-012-1 — Concurrent report generation cannot overwrite a newer stamped rulebase snapshot

- **GIVEN** `refresh_rulebases` updating `arodonata_rulebase_*` and `arodonata_domain_sync_state` concurrently with `collect_change_report`
- **WHEN** `collect_change_report` performs rule placement numbering
- **THEN** `collect_change_report` SHALL NOT perform unlocked `replace_domain_rulebase` writes that could clobber the newer stamped rulebase snapshot

### Requirement: Cache-First Object Search with Recursive Group Membership Resolution

**ID**: REQ-CACHE-013\
**Intent**: Search cached objects, assets, and active write overlays cleanly across IP, CIDR, range, wildcard, and exact selectors with parent group chains.\
**Non-goals**: Cross-domain ambiguity errors when looking up a single named container (`REQ-CACHE-014`).

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4, CIDR, address range, wildcard, UID, composite ID, or name), support `exact_match: bool = False`, query cached objects with active `WriteSession` `contextvars` overlays across target servers/domains, and resolve parent group memberships up to `max_depth` (default 2) into `SearchResult` with dual UID and composite group links.

#### Scenario: SCN-CACHE-013-1 — Search resolves direct matches and containing groups with human-readable composite IDs

- **WHEN** `await client.search_objects("10.1.10.50", max_depth=2)` or `await client.search_objects("mds:General:hWebHost", max_depth=2)` is called
- **THEN** it SHALL return a `SearchResult` containing matching objects (reflecting any uncommitted `WriteSession` overlay in the current context)
- **AND** `SearchResult.memberships` SHALL contain direct and transitive parent `GroupMembershipNode` entries with `id`, `object_id`, `parent_uids`, and `parent_object_ids`

#### Scenario: SCN-CACHE-013-2 — Exact-match search avoids partial name matches and wider supernets

- **GIVEN** a domain containing `.example.com`, `sub.example.com`, and a wider `10.0.0.0/8` supernet alongside `10.192.13.0/24`
- **WHEN** `search_objects(".example.com", exact_match=True)` or `search_objects("10.192.13.0/24, 192.168.1.10", exact_match=True)` is called
- **THEN** name search SHALL match only `.example.com` without matching `sub.example.com` (while wildcard terms `*.example.com` use anchored `fnmatchcase`)
- **AND** IPv4/CIDR search SHALL match only exact hosts/subnets or narrower contained subnets, excluding wider containing supernets such as `10.0.0.0/8`

#### Scenario: SCN-CACHE-013-3 — Mixed object and gateway type filters partition cleanly between objects and assets

- **WHEN** `await client.search_objects(query, types=["host", "network", "gateway"], cache_mode="smart")` is called
- **THEN** `ObjectService` SHALL strip asset/service types (`"gateway"`, etc.) before calling Check Point `show-*` object endpoints so `arodonata_objects` refreshes without `"Requested API type: not found"`
- **AND** `SearchService.search_objects()` SHALL refresh and match gateway/cluster/VSX assets (primary `ipv4_address` and interface IPs) from `arodonata_assets`

### Requirement: Cross-Domain Group Member Resolution with Ambiguity Detection

**ID**: REQ-CACHE-014\
**Intent**: Prevent non-deterministic group member expansion when an unqualified group name exists in multiple cached domains.\
**Non-goals**: Multi-domain search queries (`REQ-CACHE-013`) or MCP response envelope formatting (`REQ-MCP-003`).

`SearchService.get_group_members()` SHALL reject blank `group_name_or_uid` inputs with `ValidationError`, and when `domain` is `None` (not a `mgmt:domain:name` composite ID) SHALL enforce `cache_mode="cache"` (`include_global=True`) on multi-domain MDS (`> 1` non-global cached domains) while permitting single-domain SMC or cold caches to probe `show-domains` when `cache_mode != "cache"`, raising `AmbiguousObjectError` if multiple domains match.

#### Scenario: SCN-CACHE-014-1 — Cross-domain group member lookup enforces MDS cache-only guard without whole-MDS sync

- **GIVEN** a multi-domain MDS cache where `"SharedGroup"` exists in two distinct domains under `mgmt_name`
- **WHEN** `SearchService.get_group_members(mgmt_name, None, "SharedGroup")` is called
- **THEN** it SHALL execute zero remote domain refreshes (`cache_mode="cache"`, while single-domain SMC or cold caches MAY probe `show-domains` when `cache_mode != "cache"`)
- **AND** it SHALL raise `AmbiguousObjectError` enumerating the matching domains and composite identifiers

### Requirement: In-Flight Sync Probe Invalidation Preservation

**ID**: REQ-CACHE-015\
**Intent**: Prevent concurrent publish or explicit domain invalidations from being lost when an in-flight smart staleness probe or sync completes.\
**Non-goals**: Multi-scope wildcard invalidation storage semantics (`REQ-CACHE-004`).

Domain and wildcard invalidations recorded via `invalidate_domain()` while a staleness probe or slice refresh is in flight SHALL survive probe or sync completion so pre-invalidation cache states are never marked fresh for remaining `cache_ttl` windows.

#### Scenario: SCN-CACHE-015-1 — Domain invalidation during in-flight smart probe survives probe completion

- **GIVEN** a domain cache whose synced head matches the initial `show-last-published-session` probe response
- **WHEN** `WriteSession` publish or `invalidate_domain(mgmt_name, domain)` executes after the staleness probe started (under advancing or frozen clocks) and the earlier probe later receives the pre-publish response
- **THEN** probe completion SHALL NOT stamp `synced_at` or record an invalidation sequence ahead of the in-flight invalidation
- **AND** subsequent `"smart"` or `"smart-fast"` reads within `cache_ttl` SHALL still treat the domain slice as invalidated

### Requirement: Start-Epoch Slice Timestamping and Mid-Sync Invalidation Preservation

**ID**: REQ-CACHE-016\
**Intent**: Prevent domain or wildcard invalidations arriving while a slice refresh is executing from being masked by post-sync completion timestamps.\
**Non-goals**: Fresh-slice staleness probe invalidation preservation (`REQ-CACHE-015`) or multi-scope invalidation storage (`REQ-CACHE-004`).

When `ArodonataClient` synchronizes cached domain slices (`objects`, `services`, `assets`, `rulebase`, or `topology`), persisted `DomainSyncState.synced_at` timestamps SHALL record the pre-probe synchronization start time rather than completion time, and any `WriteSession` publish or `invalidate_domain()` call occurring during probe, lock acquisition, or slice execution SHALL preserve invalidation on subsequent `"smart"` and `"smart-fast"` reads.

#### Scenario: SCN-CACHE-016-1 — Mid-handler domain invalidation survives slice sync completion under advancing and frozen clocks

- **GIVEN** an in-flight `ArodonataClient` domain slice synchronization (`refresh_objects`, `refresh_services`, `refresh_assets`, `refresh_rulebases`, `refresh_package_rulebase`, or `refresh_topology`) whose staleness probe started at `T0`
- **WHEN** `WriteSession` publish or `invalidate_domain(mgmt_name, domain)` runs at `T1` while slice fetching or lock acquisition is still in progress (`T0 <= T1 <= T2` under advancing or frozen clocks) and the slice completes at `T2`
- **THEN** persisted `DomainSyncState.synced_at` SHALL reflect `T0` rather than `T2` and sequence watermarks SHALL NOT advance past the `T1` invalidation
- **AND** a subsequent `"smart"` or `"smart-fast"` read within `cache_ttl` SHALL treat the domain slice as invalidated instead of skipping server re-verification

### Requirement: Lock-Serialized Per-Management Cross-Domain VSX Reconciliation

**ID**: REQ-CACHE-017\
**Intent**: Prevent unlocked cross-domain VSX asset overwrites, unintended writes during `cache` mode, and bare-UID collisions across multiple management servers.\
**Non-goals**: Single-domain asset synchronization (`REQ-CACHE-008`) or cluster enrichment (`REQ-CACHE-009`).

`AssetRefreshService` SHALL skip cross-domain VSX reconciliation when `mode == "cache"` or no domains were written, partition asset lookups by `(mgmt_name, uid)` to avoid cross-management UID collisions, and serialize cross-domain VSX updates under a per-management distributed lock.

#### Scenario: SCN-CACHE-017-1 — Cross-domain VSX reconciliation skips cache mode and serializes per management server

- **GIVEN** multi-management cached assets with overlapping UIDs across `mgmt_name`s or concurrent `refresh_assets()` calls
- **WHEN** `get_assets(cache_mode="cache")` or `refresh_assets()` executes
- **THEN** `mode == "cache"` (and no-op refreshes) SHALL perform zero cross-domain asset writes
- **AND** active refreshes SHALL key assets by `(mgmt_name, uid)` and serialize cross-domain VSX updates under a per-management distributed lock

### Requirement: Unified Typed Cache Sync Pipeline, Modular Search Package, and Shared VSX Linking

**ID**: REQ-CACHE-018\
**Intent**: Eliminate behavioral drift between duplicated object/service sync pipelines and improve modularity across `SearchService` and `VSXRelationshipManager` while preserving full backward compatibility.\
**Non-goals**: Cache SQL schema layout (`REQ-CACHE-001`) or cross-domain VSX distributed locking (`REQ-CACHE-017`).

`ObjectService` and `ServiceCacheService` SHALL share a unified typed sync/overlay pipeline, `SearchService` SHALL delegate through `arodonata.core.services.search` with full `search_service` import and `@traced` compatibility, and `AssetRefreshService` SHALL share cluster and VSX linking helpers.

#### Scenario: SCN-CACHE-018-1 — Unified typed cache sync and overlay pipeline keeps object and service parity

- **GIVEN** concurrent or sequential incremental (`smart-fast`), full (`force`), and `WriteSession`-overlay reads on `ObjectService` and `ServiceCacheService`
- **WHEN** `refresh_objects()`, `refresh_services()`, `get_objects()`, or `get_services()` executes
- **THEN** both services SHALL share identical incremental fallback, sync-progress emission, and `WriteSession` overlay semantics without type-normalization drift

#### Scenario: SCN-CACHE-018-2 — Decomposed search package and shared asset linking preserve public APIs and telemetry

- **GIVEN** imports from `arodonata.core.services.search_service` and VSX/cluster assets spanning single-domain and cross-domain enrichment
- **WHEN** callers invoke `SearchService` methods, `classify_search_term()`, `VSXRelationshipManager.enrich()`, and `reconcile_cross_domain()`
- **THEN** all exported symbols, `@traced` span names/qualnames, and hexagonal AST layer boundaries SHALL remain preserved
- **AND** cluster, local VSX, and cross-domain VSX parent-child links and slot metadata SHALL reconcile consistently without duplicated link loops

### Requirement: Vendor-Neutral Asset Role and Platform Classification

**ID**: REQ-CACHE-019\
**Intent**: Expose vendor-neutral Asset role, platform, and target flags.\
**Non-goals**: Customer hostname rules or live SSH probing.

`Asset` SHALL expose `management_blades`, `asset_role`, `platform_family`, `is_policy_target`, and `is_execution_target` from API metadata; asset enrichment SHALL inherit parent cluster fields and isolate VSX links; and asset/search/MCP queries SHALL normalize `"mds"`/`"CpmiMds"` and support role/platform filtering consistently.

#### Scenario: SCN-CACHE-019-1 — Vendor-neutral role classification across gateways, clusters, VSX, management, and log servers

- **GIVEN** raw Check Point asset payloads for standalone gateways (`simple-gateway`, `CpmiGatewayPlain`), clusters (`simple-cluster`, `CpmiGatewayCluster`), cluster members (`cluster-member`, `CpmiClusterMember`), VSX hosts/clusters/members/virtual systems, `mds`, `checkpoint-host` / `CpmiHostCkp` servers with `management-blades` or `network-security-blades`, and `interoperable-device`
- **WHEN** `Asset.from_cp_dict()` or `classify_asset_role()` classifies each asset
- **THEN** `asset_role` SHALL resolve deterministically across `"gateway"`, `"cluster"`, `"cluster_member"`, `"vsx_gateway"`, `"vsx_cluster"`, `"vsx_cluster_member"`, `"virtual_system"`, `"management_server"`, `"mds"`, `"log_server"`, `"interoperable_device"`, and `"unknown"`
- **AND** `is_policy_target` SHALL match `is_policy_enforcing_gateway()` (`True` only for `"gateway"`, `"cluster"`, and `"virtual_system"`, preserving `CpmiHostCkp` with `firewall=True` as `"gateway"`), while `is_execution_target` SHALL be `True` only for OS-backed execution hosts (`"gateway"`, `"cluster_member"`, `"vsx_gateway"`, `"vsx_cluster_member"`, `"management_server"`, `"mds"`, `"log_server"`)

#### Scenario: SCN-CACHE-019-2 — Vendor-neutral platform family classification across Gaia, Gaia Embedded, Maestro, CloudGuard, and Open Server

- **GIVEN** Check Point asset payloads with vendor `os-name`, `hardware`, or `raw_data` platform metadata (and ignoring arbitrary `name`, `comments`, or `tags`)
- **WHEN** `Asset.from_cp_dict()` or `classify_asset_platform()` classifies `platform_family`
- **THEN** it SHALL classify `"gaia_embedded"` before generic `"gaia"`, `"maestro"` (`MHO`/`SMO`/`SGM`/`Orchestrator`/`Scalable Platform`), `"cloudguard"` (CloudGuard/AWS/Azure/GCP/VMSS), `"open_server"`, `"gaia"`, or `"unknown"` strictly from vendor attributes

#### Scenario: SCN-CACHE-019-3 — Cluster member metadata inheritance and re-classification during ClusterRelationshipManager enrichment

- **GIVEN** a parent cluster (`simple-cluster`, `CpmiGatewayCluster`, `vsx-cluster`, or `CpmiVsxClusterNetobj`) carrying `hardware`, `os_name`, and `version`, and linked child members missing one or more of those fields
- **WHEN** `ClusterRelationshipManager.enrich()` enriches the assets
- **THEN** each linked member SHALL inherit missing `hardware`, `os_name`, and `version` from its parent cluster without overwriting non-empty member values
- **AND** `ClusterRelationshipManager` SHALL recompute member `asset_role` (promoting `"cluster_member"` under a VSX cluster parent to `"vsx_cluster_member"`), `platform_family`, `is_policy_target`, and `is_execution_target`

#### Scenario: SCN-CACHE-019-4 — Cache persistence, in-place schema migration, and role/platform filtering and grouping

- **GIVEN** an existing `arodonata_assets` cache table (including legacy rows with `NULL` classification columns) and newly synced assets
- **WHEN** `DatabaseManager.initialize()` evolves the schema, `Asset` rows are round-tripped through `arodonata_assets`, and callers invoke `get_assets()`, `get_gateways()`, `query_objects()`, `describe_objects()`, MCP `list_assets()`, or MCP `query_objects()`
- **THEN** missing classification columns SHALL migrate in place without wiping cached rows and legacy `NULL` rows SHALL auto-classify on hydration
- **AND** `get_assets()`, `get_gateways()`, and MCP `list_assets()` SHALL support `roles` and `platforms` filtering, while `query_objects()` and `describe_objects()` SHALL support filtering (`roles`, `platforms`, `is_policy_target`, `is_execution_target`) and `group_by` across `asset_role`, `platform_family`, `is_policy_target`, and `is_execution_target` (including `"role"` and `"platform"` aliases)

#### Scenario: SCN-CACHE-019-5 — Canonical MDS asset routing, VSX member/self-link isolation, and MCP query_objects asset-scope parity

- **GIVEN** `"mds"` / `"CpmiMds"` assets, `vsx_cluster_member`/`vs_netobj` underscore aliases, VSX/cluster parent-child link candidates (parent lists, slot objects, pass-2 cluster links), and MCP `query_objects` calls grouping by `role`/`asset_role`/`platform`/`platform_family`/`is_policy_target`/`is_execution_target` with `types=None`
- **WHEN** callers normalize aliases, query, look up, search, enrich VSX/cluster relationships, or invoke MCP `query_objects`
- **THEN** every `ASSET_TYPE_EQUIVALENTS` alias (including `vsx_cluster_member` and `vs_netobj`) and `"mds"`/`"CpmiMds"` SHALL normalize and route cleanly to `scope="assets"`, and VSX/cluster enrichment SHALL exclude cluster members, VSX parents, Virtual Systems (from cluster members), and self-links across parent lists, slots, and cross-domain links
- **AND** MCP `query_objects` SHALL pass normalized `group_by` and asset classification filters to scope resolution so live quota, cold-cache auto-upgrade, and `cache_age_seconds` evaluate against `scope="assets"`

### Requirement: Single-Flight Coalescing Freshness Integrity and Hardened SQLite Cache Permissions

**ID**: REQ-CACHE-020\
**Intent**: Prevent stale or offline single-flight operations from suppressing concurrent smart refreshes and ensure existing SQLite cache files reject symlinks and enforce owner-only permissions.\
**Non-goals**: Base domain sync lock heartbeats (`REQ-CACHE-004`) or schema hash auto-migration (`REQ-CACHE-001`).

`DomainSyncCoordinator` SHALL prevent `mode="cache"`, looser-TTL skips, and mid-flight-invalidated flights from suppressing concurrent `mode="smart"` waiters or mislabeling fresh slices as `"failed"`, and `DatabaseManager` SHALL reject SQLite symlinks and tighten pre-existing SQLite cache files to `0o600`.

#### Scenario: SCN-CACHE-020-1 — Single-flight coalescing preserves mid-flight invalidations, mode="cache" isolation, and fresh sibling slices

- **GIVEN** concurrent `DomainSyncCoordinator.stream_ensure()` callers across `mode="cache"`, `mode="smart"` with differing `cache_ttl` values, or mid-flight `invalidate_domain()` calls
- **WHEN** a `mode="cache"` or TTL-skipped leader completes, an invalidation arrives mid-flight, or one stale item type fails while sibling item types already passed
- **THEN** waiters requiring server verification or observing newer invalidations SHALL NOT skip syncing, and sibling `fresh_types` SHALL retain `status="ok"`

#### Scenario: SCN-CACHE-020-2 — DatabaseManager rejects SQLite symlinks and enforces 0o600 on pre-existing cache files

- **GIVEN** a pre-existing SQLite cache path that is a symlink (including a dangling symlink) or an owner-owned regular file with `0644` permissions
- **WHEN** `DatabaseManager.initialize()` opens the SQLite engine
- **THEN** symlinks and non-regular files SHALL fail closed before SQLite opens them, and pre-existing regular files with group/other permission bits SHALL be tightened to `0o600`


---

### OpenSpec Capability: `change-reports` (`openspec/specs/change-reports/spec.md`)

# Auditable Session Change Report Specification

## Purpose

Defines read-only collection (`collect_change_report`), rulebase placement numbering (`apply_session_rule_placement`), dry-run CPCRUD plan conversion (`build_change_report_from_plan`), and multi-format rendering (`render_change_report`, `build_change_report`) of Check Point policy session change evidence (`ChangeReport`) across explicit session UIDs (`SessionScope`) and published session/date ranges (`RangeScope`).

## Requirements

### Requirement: Scope Validation and Read-Only Change Collection

**ID**: REQ-REPORT-001\
**Intent**: Collect auditable Check Point session change evidence safely in read-only mode while bounding UID resolution calls and validating scopes.\
**Non-goals**: Synthesizing field diffs or filtering background `"System"` maintenance noise (`REQ-REPORT-002`).

`collect_change_report(api, cache, scopes, ...)` SHALL validate `SessionScope` and `RangeScope` inputs strictly (raising `pydantic.ValidationError` or `ChangeReportInputError` on invalid bounds or naive datetimes), bind unkeyed `OwnedSession` only to single-session scopes, query `show-changes` strictly read-only without mutating `CachePort` tables, deduplicate sessions, and record partial failures as `ReportWarning` entries.

#### Scenario: SCN-REPORT-001-1 — Single-session change collection via to-session query and container filtering

- **GIVEN** a `SessionScope` requesting changes for explicit `session_uids`
- **WHEN** `collect_change_report` queries Check Point `show-changes`
- **THEN** it SHALL pass `{"to-session": s_uid, "details-level": "full"}` (omitting `from-session: s_uid` because `from-session` is exclusive in Check Point)
- **AND** it SHALL filter returned `changes[]` containers to the matching `session-uid`
- **AND** it SHALL classify `modified-objects` entries containing `new-object` without `old-object` as `"added"`

#### Scenario: SCN-REPORT-001-2 — Timezone-aware date range conversion and exact publish-time filtering

- **GIVEN** a `RangeScope` with timezone-aware `from_date` and/or `to_date`
- **WHEN** `collect_change_report` queries published sessions in the range
- **THEN** it SHALL convert bounds to the server's UTC offset and widen the server query window safely (or omit server date parameters when `from_session` is also given)
- **AND** it SHALL filter returned sessions by exact UTC publish timestamp

#### Scenario: SCN-REPORT-001-3 — Reference UID name resolution with bounded show-object lookups

- **GIVEN** `show-changes` returning bare UIDs in `new-object` or `old-object` snapshots (including removed `group.members`, removed rule cell references, `layer`, or NAT fields) not yet named
- **WHEN** `collect_change_report` resolves referenced object names
- **THEN** it SHALL recursively index nested `{uid, name}` dictionaries across `old-object` and `new-object`
- **AND** it SHALL resolve up to `200` (`MAX_UID_LOOKUPS`) distinct remaining bare UIDs per report via cache first and read-only `show-object` calls second
- **AND** it SHALL substitute resolved names into rule fields, object summaries, `FieldDiff` values (`old_value`, `new_value`, `added_items`, `removed_items`), and `RuleChangeEntry.layer_name` (when `layer_uid` resolves)
- **AND** it SHALL emit a `names_unresolved` `ReportWarning` if the lookup cap is exceeded or a lookup fails

#### Scenario: SCN-REPORT-001-4 — Multi-session scope does not bind an unkeyed OwnedSession across multiple sessions

- **GIVEN** a `SessionScope` listing multiple UIDs in `session_uids` with an unkeyed `OwnedSession` (`session_uid` empty/`None`), or an `OwnedSession` whose `mgmt_name`/`domain` disagrees with the scope
- **WHEN** `SessionScope.resolve_owned_session` resolves the owned session for a target session
- **THEN** it SHALL NOT match that unkeyed or mismatched `OwnedSession` to arbitrary sessions in the scope

### Requirement: Snapshot-Based Field Diff Synthesis and System Noise Filtering

**ID**: REQ-REPORT-002\
**Intent**: Provide accurate rule and object diffs from `show-changes` snapshots while hiding noisy `"System"` maintenance records by default.\
**Non-goals**: Live or cached rulebase numbering (`REQ-REPORT-003`) or output format rendering (`REQ-REPORT-005`).

When collecting modified rules and objects from `show-changes`, the collector SHALL synthesize `FieldDiff` entries (`old_value`, `new_value`, `added_items`, `removed_items`) from `old-object` and `new-object` snapshots for any changed tracked fields not already covered by explicit `field-changes`, enrich object summaries, and omit background `"System"` maintenance non-rule objects unless `RenderOptions.include_system_objects` is `True`.

#### Scenario: SCN-REPORT-002-1 — Rule list cell partial removal and sole-member Any replacement

- **GIVEN** `show-changes` returning a modified rule with `old-object` and `new-object` snapshots and no explicit `field-changes`
- **WHEN** items are removed from a multi-item list field (`source`, `destination`, `service`), or a sole remaining member is replaced with `Any` alongside disabling the rule
- **THEN** `RuleChangeEntry.field_diffs` SHALL populate `removed_items` (and `Any` in `added_items` when replaced by `Any`) plus scalar diffs (`enabled`, `comments`)
- **AND** it SHALL NOT report false-positive cell diffs when an unchanged referenced group has internal member edits

#### Scenario: SCN-REPORT-002-2 — Explicit field-changes merge cleanly with snapshot diffs

- **GIVEN** a `modified-objects` entry providing explicit `field-changes` for a subset of modified fields alongside `old-object` and `new-object` snapshots with additional changed fields
- **WHEN** the collector builds `field_diffs`
- **THEN** it SHALL preserve explicit `field-changes` entries and append synthesized `FieldDiff` entries only for changed tracked fields absent from `field-changes`

#### Scenario: SCN-REPORT-002-3 — Non-rule object member diffs and enriched object summaries

- **GIVEN** `show-changes` returning modified, added, or deleted non-rule objects (`group`, `host`, `network`, `address-range`, `service-*`)
- **WHEN** the collector processes those entries
- **THEN** it SHALL compute `FieldDiff` entries (`added_items`/`removed_items` for `members`, and before/after values for `comments` and address/service attributes)
- **AND** it SHALL populate `ObjectChangeEntry.summary_fields` and `summary` with IPv4/IPv6 addresses, CIDR subnets, ranges, service ports/protocols, resolved `members`, and `comments`

#### Scenario: SCN-REPORT-002-4 — Background Check Point System maintenance objects excluded by default

- **GIVEN** a non-`"System"` user session whose `show-changes` includes non-deleted (`added`/`modified`) non-rule objects with post-change `meta-info.last-modifier == "System"`
- **AND** internal records such as `IpsProtectionUserSettings`, `cp-trusted-ca-certificate`, or `TrustedCaPackageConf`
- **WHEN** the collector builds `SessionChangeReport.object_changes`
- **THEN** it SHALL exclude those `"System"` non-rule entries by default without emitting a `ReportWarning` (logging the filtered count at `DEBUG`)
- **AND** it SHALL never exclude `deleted` objects or filter by `old-object.meta-info.last-modifier`, and SHALL include them when `RenderOptions.include_system_objects` is `True`
- **AND** it SHALL preserve the complete sanitized `show-changes` payload in `ChangeReport.raw_responses`

### Requirement: Owned Session Live Numbering and Cached Snapshot Fallback

**ID**: REQ-REPORT-003\
**Intent**: Attach SmartConsole-accurate rule numbers to change reports without ever leaking SIDs or performing unsafe cache writes.\
**Non-goals**: Coordinator-managed rulebase cache synchronization (`REQ-CACHE-012`, `REQ-CLIENT-013`).

The change report builder SHALL number added, modified, moved, and deleted rules according to SmartConsole hierarchy using a verified `OwnedSession` in-memory snapshot, the domain's cached rulebase snapshot, or a coordinator-delegated / in-memory published rulebase fallback when the cache is cold, skipping placement for object-only sessions and NEVER calling `CachePort.replace_domain_rulebase` directly from `arodonata.reports`.

#### Scenario: SCN-REPORT-003-1 — Object-only session skips rulebase placement and omits numbering banner

- **GIVEN** a `SessionChangeReport` containing zero `rule_changes`
- **WHEN** `apply_session_rule_placement` runs
- **THEN** it SHALL return immediately without calling `show-session`, `collect_domain_rulebase_snapshot`, or `CachePort.get_domain_rulebase`
- **AND** it SHALL set `numbering_source = "not_applicable"` and `numbering_basis = ""`, and HTML/Markdown output SHALL omit the numbering basis banner/line

#### Scenario: SCN-REPORT-003-2 — Read-only live numbering via OwnedSession with strict SID hygiene

- **GIVEN** a `SessionScope` supplying an `OwnedSession` matching an unpublished session with rule changes
- **WHEN** `apply_session_rule_placement` verifies ownership and domain via `show-session`
- **THEN** it SHALL read `show-packages` and `show-*-rulebase` strictly read-only into memory without publishing, discarding, logging out, or calling `CachePort` writes
- **AND** it SHALL label the session `"Numbering read live in the owned session at <time> UTC"` (`numbering_source = "owned_session"`)
- **AND** it SHALL NEVER include or log the `sid` in `ChangeReport`, `RawResponse`, HTML, JSON, Markdown, or `repr()`

#### Scenario: SCN-REPORT-003-3 — Post-publish live numbering via clean OwnedSession before logout

- **GIVEN** a `SessionScope` supplying an `OwnedSession` bound to an already-published session (`session_uid` or single-session scope, matching `mgmt_name`/`domain`)
- **AND** `show-session` confirms a non-discarded session on the expected domain with `changes == 0`, `locks == 0`, and `number-of-published-changes == 0`
- **WHEN** `apply_session_rule_placement` numbers the session's rules
- **THEN** it SHALL read the published rulebase live in memory without calling `CachePort.replace_domain_rulebase` or emitting `owned_session_not_used`
- **AND** it SHALL set `numbering_source = "live_published"` and basis `"Numbering read live after publish at <time> UTC"`

#### Scenario: SCN-REPORT-003-4 — Graceful fallback when OwnedSession is already published or expired

- **GIVEN** an `OwnedSession` that fails `show-session`, is `discarded`, targets a different domain, omits `changes`/`locks`, reports non-zero activity on a post-publish session, or mismatches an unpublished UID
- **WHEN** `apply_session_rule_placement` runs
- **THEN** it SHALL record an `owned_session_not_used` or `owned_session_error` warning
- **AND** it SHALL fall back to numbering from the domain's cached rulebase snapshot (or cold-cache fallback)

#### Scenario: SCN-REPORT-003-5 — Cold-cache on-demand live published rulebase fallback

- **GIVEN** a session with rule changes where no usable `OwnedSession` handled numbering and `CachePort.get_domain_rulebase` is empty
- **WHEN** invoked via `ArodonataClient`
- **THEN** `ArodonataClient` SHALL delegate cache warming to `RulebaseRefreshService` / `DomainSyncCoordinator` (enforcing distributed locks and `DomainSyncState` stamps) before reading cache
- **AND** when called standalone without coordinator warming (no `refresh_rulebase_fn` executed), it SHALL attempt read-only in-memory `collect_domain_rulebase_snapshot` without writing to `CachePort` or double-fetching after coordinator sync
- **AND** that live fallback SHALL set `numbering_source = "live_published"` and basis `"Numbering read live from published rulebase at <time> UTC"`
- **AND** only if live collection fails or is empty SHALL it fall back to `"Numbering from cached rulebase snapshot (unavailable)"` (`numbering_source = "unnumbered"`)

### Requirement: Offline Dry-Run ChangeReport Synthesis from CPCRUD Plan

**ID**: REQ-REPORT-004\
**Intent**: Allow operators to preview and archive dry-run CPCRUD plans in the exact same evidence report format as live sessions.\
**Non-goals**: Live `show-changes` collection (`REQ-REPORT-001`) or executing a `Plan` (`REQ-CPCRUD-010`).

`arodonata.reports` SHALL provide `build_change_report_from_plan(plan, ...)` to convert a CPCRUD `Plan` offline into a `ChangeReport` compatible with `render_change_report()`, capturing object, group, and rule creates, deletes, and field-level add/remove diffs without opening Check Point sessions.

#### Scenario: SCN-REPORT-004-1 — Dry-run ChangeReport renders HTML and JSON offline with added and removed item diffs

- **GIVEN** a multi-action `Plan` containing object creates (`Outcome.CREATE`), group member deltas (`Outcome.UPDATE` with `add`/`remove`), and incremental rule cell diffs (`Outcome.UPDATE` on `source`/`destination`/`service`)
- **WHEN** `build_change_report_from_plan(plan)` converts the plan and `render_change_report(report, formats=["html", "json"])` renders it
- **THEN** `build_change_report_from_plan` SHALL produce a valid `ChangeReport` with zero Check Point API calls
- **AND** it SHALL populate `ObjectChangeEntry.field_diffs` and `RuleChangeEntry.field_diffs` (`added_items` and `removed_items`)
- **AND** `render_change_report` SHALL emit self-contained SmartConsole-styled HTML and round-trippable JSON containing no `sid`s or errors

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

**ID**: REQ-REPORT-005\
**Intent**: Render portable, XSS-safe HTML, JSON, and Markdown change reports offline with complete SmartConsole visual fidelity.\
**Non-goals**: Querying live Check Point APIs during rendering (`REQ-REPORT-001`).

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: SCN-REPORT-005-1 — Self-contained HTML evidence output

- **GIVEN** a `ChangeReport` with rule changes, section context, object changes, and field diffs
- **WHEN** `render_change_report(report, formats=["html"], options=...)` (or `formats=["md"]`) runs
- **THEN** it SHALL return a `RenderedReportBundle` (normalizing `"md"` to `"markdown"`) whose `.html` attribute contains a self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, and zero external network assets
- **AND** the HTML SHALL render SmartConsole-styled dark-blue headers (`#253245`), yellow section banner rows (`<tr class="section-row">` on `#eee8aa` with `▾ <section_name> (<section_range>)`), and shaded `.col-num` rule cells
- **AND** it SHALL display change badges (`NEW`, `DELETED`, `MODIFIED`, `MOVED`), disabled `✗` markers, and `Accept`/`Drop` action indicators
- **AND** it SHALL show inline `- <name>` / `+ <name>` / `before → after` cell diffs, plus `Field Diffs` tables when `RenderOptions.include_field_diffs=True`
- **AND** all Check Point object/rule strings SHALL be HTML-escaped while safe inline markdown in `title` and `header_fields` is rendered

#### Scenario: SCN-REPORT-005-2 — Inline diff markers in Markdown rule and object tables

- **GIVEN** a `ChangeReport` containing modified rules or objects with `field_diffs`
- **WHEN** `render_change_report(report, formats=["markdown"], ...)` runs
- **THEN** it SHALL render removed items (`[-<name>]`), added/replacement items (`[+<name>]`), and scalar `before -> after` transitions inline in `Rule Changes` (including `Track`) and `Object Changes` cells
- **AND** when `RenderOptions.include_field_diffs=True`, it SHALL emit detailed Markdown `Field Diffs` tables for both rule changes and object changes symmetrically to HTML
- **AND** it SHALL escape pipe characters, newlines, and raw HTML tags in Check Point strings

#### Scenario: SCN-REPORT-005-3 — Round-trip JSON serialization with format_version check

- **GIVEN** a `ChangeReport` serialized to `"json"`
- **WHEN** it is reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access
- **AND** it SHALL reject JSON payloads whose `format_version` is newer than supported by the installed library

### Requirement: Fail-Closed Range Bounds, Safe Inline Markup, and Accurate Placement/Diff Reporting

**ID**: REQ-REPORT-006\
**Intent**: Prevent unbounded session history leaks, HTML/Markdown injection via inline markup or CR/CRLF splits, false `MOVED` flags, and spurious empty field diffs in change reports.\
**Non-goals**: Base scope validation (`REQ-REPORT-001`) or offline plan synthesis (`REQ-REPORT-004`).

`ChangeReportService` SHALL return empty matches with a `ReportWarning` when `RangeScope.from_session` or `to_session` UID is absent, verify `OwnedSession` liveness/domain with shared read-only fallback (`sid=None`), prefix nested `old_rule_number` values accurately, omit empty `FieldDiff`s for reordered unordered lists, preserve dotted `rule_number` strings in dry-run plan reports, and sanitize inline Markdown links, backtick spans, and CR/CRLF characters.

#### Scenario: SCN-REPORT-006-1 — Missing RangeScope UID fails closed and OwnedSession falls back cleanly

- **GIVEN** a `RangeScope` referencing a nonexistent `from_session` or `to_session` UID, OR an expired/wrong-domain `OwnedSession`
- **WHEN** `ArodonataClient.get_change_report()` collects session changes
- **THEN** a missing `RangeScope` UID SHALL return zero matched sessions with a `ReportWarning` instead of falling back to full domain history
- **AND** an unusable `OwnedSession` SHALL fall back to the shared read-only session (`sid=None`) with a warning while preserving report evidence

#### Scenario: SCN-REPORT-006-2 — Nested rule placement, order-only list diffs, and dotted plan rule numbers remain accurate

- **GIVEN** modified rules inside inline or Global-placeholder layers, unordered list fields whose items were only reordered, or dry-run `plan_report` actions with dotted `rule_number` strings (e.g., `"2.1"`)
- **WHEN** change reports or dry-run plan reports are synthesized
- **THEN** nested in-place edits SHALL NOT be falsely flagged as `MOVED` and deleted rules SHALL preserve layer prefixes
- **AND** reordered unordered Check Point list fields SHALL produce zero empty `FieldDiff`s and dotted `rule_number` strings SHALL be preserved

#### Scenario: SCN-REPORT-006-3 — Inline Markdown links, multiline code spans, and CR/CRLF comments are safely escaped

- **GIVEN** Check Point object names, comments, or descriptions containing multiline backtick code spans, unsafe `href` characters/schemes, or `\r`/`\r\n` line breaks
- **WHEN** `render_safe_inline_markdown_md` or Markdown/HTML report renderers format evidence
- **THEN** multiline inline tokens, unsafe `href` targets, and raw HTML tags SHALL be neutralized and `\r`/`\n` normalized so table rows and headings cannot be broken or injected

### Requirement: Canonical Object Summary Schema Across Diffs, Plans, and Renderers

**ID**: REQ-REPORT-007\
**Intent**: Prevent modified-object detail tables and dry-run plan reports from dropping Check Point attributes due to diverged duplicate summary formatters.\
**Non-goals**: Base report layout structure (`REQ-REPORT-002`) or inline Markdown escaping rules (`REQ-REPORT-006`).

`ChangeReportService` and dry-run `plan_report` synthesis SHALL use a single canonical object summary field registry across summary construction, summary token splitting, and HTML/Markdown cell rendering so `ip-protocol`, `icmp-type`, `icmp-code`, `primary-category`, `urls-defined-as-regular-expression`, `url-list`, `description`, `subnet6`, `mask-length6`, and `ipv6-address-first/last` are preserved uniformly on created, modified, deleted, and planned objects.

#### Scenario: SCN-REPORT-007-1 — Unified object summary formatter preserves protocol, ICMP, URL, description, and IPv6 fields

- **GIVEN** modified or planned `service-icmp`, `service-other`, `application-site`, `network`, or `address-range` objects carrying `icmp-type`/`icmp-code`, `ip-protocol`, `primary-category`, `urls-defined-as-regular-expression`, `url-list`, `description`, or IPv6 subnet/range fields
- **WHEN** `build_change_report()`, `build_plan_report()`, `render_change_report()`, or `format_plan_report()` renders object summaries and `Details` cells
- **THEN** all present canonical attributes SHALL be emitted in plain summaries, dry-run plan summaries, and both HTML and Markdown modified-object `Details` cells without silent field loss
- **AND** `_SUMMARY_SPLIT_RE` token parsing SHALL recognize every emitted canonical key consistently across collectors and renderers

### Requirement: Fail-Closed Timestamp Bounds, Validated Owned-Session Forwarding, and Nested Markdown Escaping

**ID**: REQ-REPORT-008\
**Intent**: Prevent unparsed bound sessions from leaking full domain history, avoid reusing invalidated `OwnedSession` instances or unredacted `known_names`, and block nested Markdown links/images inside bold/italic spans.\
**Non-goals**: Dry-run plan report field summaries (`REQ-REPORT-007`).

`collect_change_report()` SHALL fail closed when a requested `from_session`/`to_session` lacks a parseable timestamp, omit invalidated `OwnedSession` instances from downstream resolution/placement, redact substituted `known_names`, and neutralize nested Markdown links and images inside `**bold**` and `*italic*` spans.

#### Scenario: SCN-REPORT-008-1 — Unparsed range bounds fail closed, invalidated OwnedSession stops propagating, and known_names are redacted

- **GIVEN** a `RangeScope(from_session=...)` whose bound session exists without a parseable timestamp, or a `SessionScope` whose `OwnedSession` fails `show-session`/`show-changes` while `show-object` resolves a name containing a SID
- **WHEN** `collect_change_report()` filters sessions, resolves bare UIDs, and runs rule placement
- **THEN** the unparsed range bound SHALL fail closed with a warning and empty session set instead of returning full domain history
- **AND** invalidated `OwnedSession` instances SHALL NOT be forwarded to bare-UID lookup/placement, and substituted names SHALL pass `redact_sid(..., known_sids=...)`

#### Scenario: SCN-REPORT-008-2 — render_safe_inline_markdown_md blocks nested javascript: links and external images inside bold/italic spans

- **GIVEN** Markdown `title` or `header_fields` strings containing `**[label](javascript:alert(1))**` or `*![beacon](https://example.invalid/x.png)*`
- **WHEN** `render_safe_inline_markdown_md()` renders the Markdown report
- **THEN** nested `[` and `]` characters inside `**...**` and `*...*` spans SHALL be escaped so no active Markdown links or external image beacons are emitted

### Requirement: RangeScope Target Session Date Omission, Warning Schema Parity, and Single-Warning OwnedSession Context

**ID**: REQ-REPORT-009\
**Intent**: Ensure `to_session`-bounded ranges omit server-side date filters symmetrically with `from_session`, keep `WarningCode` aligned with emitted codes, and centralize `OwnedSession` invalidation cleanly.\
**Non-goals**: Unparsed timestamp fail-closed behavior (`REQ-REPORT-008`) or inline Markdown escaping (`REQ-REPORT-008`).

`RangeScope` SHALL omit server date bounds whenever `to_session` is specified, `WarningCode` SHALL include `"range_session_not_found"`, and `_OwnedSessionContext` SHALL track and disable failing `OwnedSession` credentials cleanly with a single warning.

#### Scenario: SCN-REPORT-009-1 — RangeScope to_session server-date omission, range_session_not_found schema parity, and single-disable OwnedSession context

- **GIVEN** a `RangeScope(to_session=..., from_date=..., to_date=...)` alongside a `SessionScope` whose `OwnedSession` fails on initial `show-session`
- **WHEN** `collect_change_report()` discovers target sessions and collects metadata/changes/UIDs
- **THEN** `show-sessions` SHALL omit `from` and `to` date parameters when `to_session` is set, `WarningCode` SHALL validate `"range_session_not_found"`, and `_OwnedSessionContext` SHALL disable the failing `OwnedSession` once with a single warning so subsequent calls never reuse it


---

### OpenSpec Capability: `client-and-facade` (`openspec/specs/client-and-facade/spec.md`)

# Client Facade, Ports/Adapters, and Telemetry Specification

## Purpose

Defines the primary composition root and unified developer facade (`ArodonataClient`), hexagonal architectural ports (`ApiPort`, `CachePort` composed of `DomainCachePort`, `SidCachePort`, `SyncStatePort`, `ObjectCachePort`, `ServiceCachePort`, `AssetCachePort`, `TopologyCachePort`, and `RulebaseCachePort`, plus `LockPort`, `AuthProvider`, `GatewayCliPort`, and `RulebaseRefreshPort`), adapters (`AMgmtClient`), shared core primitives and sentinel UIDs, `contextvars`-aware session and object mutation methods, gateway topology and repository script facades, change-report and API-reference integration, and provider-agnostic OpenTelemetry instrumentation (`@traced`, `span_attrs`).

## Requirements

### Requirement: Hexagonal Composition Root and Lifecycle Management

**ID**: REQ-CLIENT-001\
**Intent**: Provide a single client entry point that owns default SQLite lifecycle, drains background tasks, and cleans up sessions deterministically.\
**Non-goals**: Underlying SQL schema migration (`REQ-CACHE-001`) or transport TLS pinning (`REQ-TRANS-002`).

`ArodonataClient` SHALL serve as the unified composition root wiring `ApiPort` (`AMgmtClient`), `CachePort`, and `LockPort` into core domain services, defaulting `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) and cleaning up sessions, background tasks, and owned engines deterministically on `close()` / `__aexit__()`.

#### Scenario: SCN-CLIENT-001-1 — Context manager initializes database and drains or cancels background work on close

- **WHEN** `async with ArodonataClient(...) as client:` enters and exits
- **THEN** `__aenter__` SHALL initialize the cache schema (and schedule startup session cleanup if static credentials are present)
- **AND** `__aexit__` (`close()`) SHALL cancel running background warm-up tasks immediately, drain startup cleanup tasks up to the grace period, and close `AMgmtClient`
- **AND** it SHALL dispose of the SQLAlchemy engine ONLY if `client` auto-created it from `engine=None`

#### Scenario: SCN-CLIENT-001-2 — Automatic logout policy on client close

- **WHEN** `client.close(logout=None)` is called
- **THEN** the client SHALL automatically log out active Check Point sessions when it auto-created an in-memory engine (`engine=None`)
- **AND** it SHALL preserve cached read-only sessions in the database when an external persistent engine was supplied

### Requirement: Single-Flight Background Object and Service Cache Warm-Up

**ID**: REQ-CLIENT-002\
**Intent**: Warm domain object and service caches asynchronously without spawning duplicate tasks or leaking unhandled task exceptions.\
**Non-goals**: Foreground synchronous/streaming refresh coordination (`REQ-CACHE-004`, `REQ-CACHE-005`).

`ArodonataClient.start_object_cache_warmup()` SHALL coalesce concurrent in-flight background warm-up calls sharing the same 6-tuple flight key `(mgmt_name, domains, types, include_global, include_services, mode == "force")` (so `"force"` runs never coalesce with `"smart"`), handle failures with `sid`-redacted structured logging without unretrieved asyncio task warnings, and expose status via `get_warmup_status()`.

#### Scenario: SCN-CLIENT-002-1 — Concurrent warm-up calls for the same domain coalesce into one task

- **GIVEN** an in-flight warm-up task started for `(mgmt_name="mds1", domains=["Corp"], include_services=True)`
- **WHEN** `client.start_object_cache_warmup(mgmt_name="mds1", domains=["Corp"], include_services=True)` is called again while the first task is running
- **THEN** it SHALL return the existing in-flight task rather than spawning duplicate concurrent refreshes
- **AND** `client.get_warmup_status(mgmt_name="mds1")` SHALL report `"Corp"` as `"running"` until completion

#### Scenario: SCN-CLIENT-002-2 — Fire-and-forget warm-up failure logs redacted warning without unretrieved exception

- **GIVEN** a caller schedules `client.start_object_cache_warmup(mgmt_name="mds1", domains=["UnreachableCMA"])` without awaiting the returned `asyncio.Task`
- **WHEN** the background refresh raises an error
- **THEN** the client SHALL record the `sid`-redacted failure in `get_warmup_status()` and emit a structured `WARNING` log
- **AND** garbage collection SHALL produce zero `"Task exception was never retrieved"` warnings

### Requirement: Typed Read Facade and Domain Invalidation

**ID**: REQ-CLIENT-003\
**Intent**: Expose typed Pydantic v2 getters honoring `WriteSession` overlays and immediate cache invalidation after publish.\
**Non-goals**: Low-level Check Point pagination (`REQ-TRANS-006`) or search query classification (`REQ-CACHE-013`).

`ArodonataClient` SHALL expose typed getters (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_objects`, `get_services`, `get_object_by_uid`) with `cache_mode`/`cache_ttl`, snapshot rulebase getters (`get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules`), apply `WriteSession` overlays, and invalidate domain freshness on publish.

#### Scenario: SCN-CLIENT-003-1 — Read helpers reflect active WriteSession overlay via contextvars

- **WHEN** `await client.get_hosts(mgmt_name, domain)` or `await client.get_services(mgmt_name, domain)` runs inside `async with client.write_session(mgmt_name, domain):`
- **THEN** the returned list SHALL include objects created or updated in that `WriteSession` and exclude deleted objects
- **AND** shared database cache rows SHALL remain unmodified until `publish`

#### Scenario: SCN-CLIENT-003-2 — Publish via api_call invalidates domain freshness memos

- **WHEN** a `WriteSession` publishes or `await client.api_call(mgmt_name, "publish", domain=domain)` succeeds
- **THEN** `client.invalidate_domain(mgmt_name, domain)` SHALL be invoked automatically so the next `"smart"` or `"smart-fast"` read re-checks the domain head even within `cache_ttl`

### Requirement: Policy Package Catalog and Targeted Package Rulebase Facade Methods

**ID**: REQ-CLIENT-004\
**Intent**: Give SDK consumers fast targeted package and single-package rulebase access without full-domain scans.\
**Non-goals**: Cross-package full-domain `locate_rules` indexing (`REQ-RULE-003`, `REQ-RULE-004`).

`ArodonataClient` SHALL expose traced async facade methods `refresh_policy_packages(...)` and `refresh_package_rulebase(...)` in addition to `get_policy_packages(...)` and `get_package_rulebase(...)`, enabling targeted catalog and single-package rulebase queries without full-domain rulebase or bulk host scans.

#### Scenario: SCN-CLIENT-004-1 — Consumer refreshes policy packages and single package access sections via facade

- **WHEN** a consumer calls `await client.get_policy_packages("mds1", "Corp", cache_mode="smart")` and `await client.get_package_rulebase("mds1", "Corp", "Corp_Pkg", rulebase_type="access", cache_mode="smart")`
- **THEN** `ArodonataClient` SHALL return the domain's `PolicyPackageInfo` catalog and the numbered `PackageRulebase` for `"Corp_Pkg"`
- **AND** it SHALL execute zero full-domain NAT/HTTPS/Threat rulebase syncs or full-domain `show-hosts` downloads

### Requirement: Entity Lookup, Group Expansion, and Composite Identifier Resolution

**ID**: REQ-CLIENT-005\
**Intent**: Allow consumers to locate and expand objects, services, groups, and cluster/VSX assets uniformly by UID, name, or composite ID.\
**Non-goals**: Cross-domain disambiguation when `domain=None` (`REQ-CLIENT-006`).

`ArodonataClient.find_object()`, `ArodonataClient.get_group_members()`, `SearchService.search_objects()`, and `SearchService.query_objects()` SHALL resolve entities across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` by raw `name`/`uid`, UID composite `id` (`"{mgmt_name}:{domain_name}:{uid}"`), or human-readable composite IDs (`object_id`, `service_id`, `asset_id` formatted as `"{mgmt_name}:{domain_name}:{name}"`).

#### Scenario: SCN-CLIENT-005-1 — find_object and get_group_members resolve across objects, services, and assets by UID, name, or composite ID

- **WHEN** `await client.find_object(mgmt_name, domain, name_or_uid)` or `await client.get_group_members(mgmt_name, domain, group_name_or_uid)` is called
- **AND** the target is a raw UID, object name, or composite ID (`"mds:General:hWebHost"`, `"mds:General:Cluster01"`, `"mds:VSX:VSX-Cluster-01"`)
- **THEN** `find_object` SHALL look up the target across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` returning `CPObject | CPService | Asset | None` with composite IDs populated
- **AND** `get_group_members` SHALL expand direct and recursive members of a network group, `service-group`, or cluster/VSX parent asset (including cross-domain Virtual Systems) from cache

#### Scenario: SCN-CLIENT-005-2 — Structured query_objects and describe_objects expose composite ID fields

- **WHEN** `await client.describe_objects()` or `await client.query_objects(...)` is called
- **THEN** `describe_objects()` SHALL list `id`, `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id` among filterable fields
- **AND** `query_objects()` SHALL include those composite fields on returned items

### Requirement: Cache-Only Cross-Domain Entity Lookup and Ambiguity Refusal

**ID**: REQ-CLIENT-006\
**Intent**: Keep unqualified cross-domain lookups fast, strictly local to cache, and safe against multi-domain name collisions.\
**Non-goals**: Explicit-domain lookups (`REQ-CLIENT-005`).

`ArodonataClient.find_object()` and `ArodonataClient.get_group_members()` SHALL require a non-empty target (`ValidationError` on blank input); when `domain` is `None` (not a `mgmt:domain:key` composite ID), multi-domain MDS (`> 1` non-global cached domains) SHALL run strictly cache-only (`cache_mode="cache"`, `include_global=True`) while single-domain SMC or cold caches MAY probe `show-domains` when `cache_mode != "cache"`, raising `AmbiguousObjectError` on multi-domain collisions.

#### Scenario: SCN-CLIENT-006-1 — Blank target identifier rejected immediately

- **WHEN** `client.find_object(mgmt_name, domain, "")` or `client.get_group_members(mgmt_name, domain, "   ")` is called
- **THEN** the method SHALL raise `ValidationError` immediately without scanning cached or remote domains

#### Scenario: SCN-CLIENT-006-2 — Cross-domain lookup enforces MDS cache-only guard with Global visibility and raises AmbiguousObjectError on multi-domain collision

- **WHEN** `await client.find_object(mgmt_name, None, name_or_uid)` or `await client.get_group_members(mgmt_name, None, group_name_or_uid)` runs without a domain
- **THEN** on multi-domain MDS (`> 1` non-global cached domains), it SHALL search cached tables including `"Global"` (`cache_mode="cache"`) with zero remote logins or syncs (while single-domain SMC or cold caches MAY probe `show-domains` when `cache_mode != "cache"`)
- **AND** it SHALL return the match if unique to one domain, or raise `AmbiguousObjectError` listing candidate domains and composite IDs if multiple domains match

### Requirement: Context-Aware Write Sessions and Isolated Object Mutation Helpers

**ID**: REQ-CLIENT-007\
**Intent**: Guarantee atomic, isolated write sessions with read-your-own-writes overlays and automatic rollback on cancellation or error.\
**Non-goals**: Declarative multi-action CPCRUD plans (`REQ-CPCRUD-010`, `REQ-CPCRUD-011`).

`ArodonataClient` SHALL provide `contextvars`-aware session and mutation helpers (`write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`), auto-wrapping standalone mutations in an isolated write session, stripping secret fields from `SessionOverlay`, and redacting secrets in `ApiCallResult`.

#### Scenario: SCN-CLIENT-007-1 — Context manager write_session publishes on success and discards on exception

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_auth)` is entered
- **THEN** it SHALL open an isolated write session bound to `contextvars` so nested mutations and reads share its SID and `SessionOverlay`
- **AND** secret request keys (`one-time-password`, `shared-secret`, `password`, `api-key`) SHALL be stripped from cached `raw_data`
- **AND** clean exit SHALL auto-publish (discarding before logout if `publish` returns `success=False`), and any unhandled `BaseException` (including `asyncio.CancelledError`) SHALL shield `discard` and `logout_sid`

#### Scenario: SCN-CLIENT-007-2 — Standalone object mutation helpers never dirty the shared read-only SID cache

- **WHEN** `await client.add_object(...)`, `await client.set_object(...)`, or `await client.delete_object(...)` runs outside `write_session()` without an explicit `sid`
- **THEN** it SHALL execute inside a dedicated isolated session (never using the shared `arodonata_sid_cache` session)
- **AND** `ApiCallResult.__repr__()` SHALL redact `sid` and secret payload fields

### Requirement: Gateway Topology Synchronization, Route Collection, Reconciliation, and Annotation Facade

**ID**: REQ-CLIENT-008\
**Intent**: Expose gateway topology, live SSH/CPRID route collection, diagnostics, reconciliation, and IPAM exports directly on `ArodonataClient`.\
**Non-goals**: Detailed topology extraction and LPM matching rules (`REQ-TOPO-001`..`REQ-TOPO-018`).

`ArodonataClient` SHALL accept optional `gateway_cli` (`GatewayCliPort` or async callback), expose `topology_service`, and provide traced async methods (`refresh_topology`, `stream_refresh_topology`, `collect_gateway_routes`, `get_gateway_topology`, `get_topology_diagnostics`, `reconcile_gateway_topology`, `upsert_topology_annotations`, `get_topology_annotations`, `delete_topology_annotations`, `export_topology_prefixes`).

#### Scenario: SCN-CLIENT-008-1 — Host application injects SSH callback and reconciles gateway routes via ArodonataClient

- **GIVEN** `ArodonataClient(settings, gateway_cli=ssh_exec_fn)`
- **WHEN** the host calls `collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateways=["gw-01"])` and `reconcile_gateway_topology(mgmt_name="mds1", domain="Corp", gateways=["gw-01"], check_policy=True)`
- **THEN** `ArodonataClient` SHALL invoke `ssh_exec_fn` for `"gw-01"` and persist parsed routes into `arodonata_gateway_topology`
- **AND** it SHALL return a `TopologyReconciliationReport` detailing discrepancies across SmartConsole topology, live routes, and gateway-targeted policy rules

#### Scenario: SCN-CLIENT-008-2 — Pipelined collection in one domain runs concurrently with script provisioning in another domain

- **WHEN** `collect_gateway_routes(mgmt_name="mds1", domain="DomainA", cprid_script_mode="repository")` runs concurrently with `ensure_route_collection_script("mds1", "DomainB")`
- **THEN** both operations SHALL maintain isolated session contexts without `WriteSession` `contextvars` bleed or cross-domain lock blocking

#### Scenario: SCN-CLIENT-008-3 — Topology facade methods forward targeting, script override, annotation, and export parameters

- **WHEN** callers invoke `refresh_topology(..., gateways=..., collect_routes=...)`, `stream_refresh_topology(...)`, or `collect_gateway_routes(..., cprid_script_mode=..., repository_script_name=..., repository_script_args_fn=...)`
- **AND** callers invoke `get_gateway_topology(...)`, `get_topology_diagnostics(...)`, `reconcile_gateway_topology(..., check_policy=...)`, annotation helpers, or `export_topology_prefixes(...)`
- **THEN** `ArodonataClient` SHALL trace and forward all parameters to `topology_service` (`TopologyService`) and return the corresponding typed Pydantic models

### Requirement: Affected Gateway Candidate Discovery Facade

**ID**: REQ-CLIENT-009\
**Intent**: Provide a clean, traced client method for finding affected Check Point gateways and policy packages for traffic flows.\
**Non-goals**: Underlying LPM, confidence-delta, and policy-inference matching algorithms (`REQ-TOPO-011`..`REQ-TOPO-014`).

`ArodonataClient` SHALL expose traced async `find_affected_gateways(sources, destinations, ..., min_confidence=..., include_standby=..., include_policy_inferred=..., source_types=..., include_annotations=...)` delegating to `topology_service` and returning ranked `AffectedGatewayCandidate` Pydantic models.

#### Scenario: SCN-CLIENT-009-1 — Consumer resolves affected gateways and policy packages via ArodonataClient

- **WHEN** `await client.find_affected_gateways(sources=["10.1.1.10"], destinations=["10.2.2.20"], mgmt_name="mds1", include_policy_inferred=True, cache_mode="smart")` is called
- **THEN** `ArodonataClient` SHALL synchronize topology according to `cache_mode`
- **AND** it SHALL return ranked `AffectedGatewayCandidate` models with `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `installed_access_policy`, `policy_packages`, and `access_layers`
- **AND** each candidate SHALL populate `confidence`, `is_standby_path`, `confidence_factors`, `warnings`, and `matched_flows`

#### Scenario: SCN-CLIENT-009-2 — Consumer filters affected gateway candidates to static topology sources without annotations

- **WHEN** `await client.find_affected_gateways(sources, destinations, mgmt_name="mds1", source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)` is called
- **THEN** `ArodonataClient` SHALL return the static-only `AffectedGatewayCandidate` list without triggering full-domain NAT/HTTPS/Threat rulebase syncs or full-domain `show-hosts` downloads

### Requirement: Script Repository Read, Check, Ensure, and Delete Facade

**ID**: REQ-CLIENT-010\
**Intent**: Manage Check Point repository scripts idempotently across read-only checks and isolated write provisioning.\
**Non-goals**: Executing repository scripts against gateway targets (`REQ-CLIENT-012`) or route-script defaults (`REQ-CLIENT-011`).

`ArodonataClient` SHALL expose traced async methods `get_repository_script`, `list_repository_scripts`, `check_repository_script`, `ensure_repository_script`, and `delete_repository_script`—decoding plaintext or Base64 `"script-body"` payloads—using shared read-only sessions for reads/checks and isolated write sessions (omitting `"repository-script"` from `SessionOverlay`) only when creation, modification, or deletion is required.

#### Scenario: SCN-CLIENT-010-1 — Read-only script check and zero-write fast path in ensure_repository_script

- **GIVEN** `"arodonata-collect-routes-v1"` already exists in `"Corp"` with matching normalized line endings (`\r\n` -> `\n`, stripped trailing whitespace) and matching explicit metadata (`comments`, `color`, `tags`)
- **WHEN** `check_repository_script` or `ensure_repository_script(mgmt_name, "arodonata-collect-routes-v1", expected_body, domain="Corp")` runs
- **THEN** the inspection SHALL run strictly read-only over cached read-only sessions without opening a `WriteSession` or calling `publish`
- **AND** `ensure_repository_script` SHALL return `EnsureRepositoryScriptResult(action="unchanged")`

#### Scenario: SCN-CLIENT-010-2 — Missing or outdated script created or updated without SessionOverlay pollution

- **GIVEN** a repository script that is absent, differs in body, or has mismatched explicit `comments`/`color`/`tags`
- **WHEN** `ensure_repository_script(mgmt_name, script_name, script_body, domain="Corp")` runs standalone or inside an active `WriteSession`
- **THEN** standalone calls SHALL open an isolated `WriteSession`, execute `add-repository-script` or `set-repository-script`, publish and invalidate `"Corp"`, and return `action="created"` or `"updated"`
- **AND** active `WriteSession` calls SHALL reuse the caller's session without auto-publishing or polluting `SessionOverlay` object caches

#### Scenario: SCN-CLIENT-010-3 — Permission error during script check or provisioning raises RepositoryScriptPermissionError

- **GIVEN** an administrator lacking `manage-repository-scripts: write` or `publish-sessions` privileges
- **WHEN** `ensure_repository_script` or `delete_repository_script` is invoked
- **THEN** `ArodonataClient` SHALL discard any uncommitted session cleanly
- **AND** it SHALL raise `RepositoryScriptPermissionError` carrying `mgmt_name`, `domain_name`, `script_ref`, and `operation` without exposing `sid` or credentials

#### Scenario: SCN-CLIENT-010-4 — Base64-encoded script-body from Check Point R82 show-repository-script decodes cleanly without false outdated drift

- **GIVEN** Check Point `show-repository-script` returns Base64-encoded script text inside the `"script-body"` field (rather than `"script-body-base64"`) for an up-to-date repository script
- **WHEN** `get_repository_script`, `check_repository_script`, or `ensure_repository_script` inspects that script
- **THEN** `RepositoryScript.script_body` SHALL decode the Base64 payload to UTF-8 text without corrupting plaintext scripts
- **AND** `check_repository_script` SHALL report `matches_expected=True` and `ensure_repository_script` SHALL return `action="unchanged"` without opening a `WriteSession`

### Requirement: Route-Collection Repository Script Convenience Helpers

**ID**: REQ-CLIENT-011\
**Intent**: Standardize checking and provisioning the canonical route-collection script using configured settings defaults.\
**Non-goals**: Arbitrary custom script provisioning (`REQ-CLIENT-010`) or execution (`REQ-CLIENT-012`).

`ArodonataClient` SHALL expose `check_route_collection_script` and `ensure_route_collection_script` helpers wrapping `check_repository_script` and `ensure_repository_script` with `settings.cprid_repository_script_name` (or an explicit `script_name` override) and the canonical route-collection repository script body.

#### Scenario: SCN-CLIENT-011-1 — Host application checks and provisions the canonical route-collection script

- **WHEN** a host application calls `await client.check_route_collection_script("mds1", "Corp")` followed by `await client.ensure_route_collection_script("mds1", "Corp")`
- **THEN** `ArodonataClient` SHALL check and provision the canonical route-collection script body in `"Corp"` using `settings.cprid_repository_script_name` (default `"arodonata-collect-routes-v1"`)

### Requirement: Universal Application-Agnostic Repository Script Execution Facade

**ID**: REQ-CLIENT-012\
**Intent**: Allow downstream applications to run any pre-approved Check Point repository script via `run-script` with non-read-only sessions.\
**Non-goals**: Route-collection fallback policies (`REQ-TOPO-008`) or inline one-time script execution.

`ArodonataClient` SHALL expose traced async `run_repository_script(mgmt_name, script_name_or_uid, targets, *, domain=None, args=None, comments=None, timeout=None, script_timeout=None)` sending `run-script` with `script-type="repository"` and caller-supplied `args` verbatim (`str`) or space-joined (`Sequence[str]`) over a dedicated non-read-only session (or active `WriteSession`) without `publish` or `discard`.

#### Scenario: SCN-CLIENT-012-1 — Universal execution forwards application script name, targets, and args verbatim

- **WHEN** `await client.run_repository_script("mds1", "app-custom-diag", ["gw-01", "gw-02"], domain="Corp", args=["--mode", "fast"])` (or `args="--mode fast"`) is called
- **THEN** `ArodonataClient` SHALL invoke `run-script` with `{"script-name": "app-custom-diag", "script-type": "repository", "targets": ["gw-01", "gw-02"], "args": "--mode fast"}` (omitting `"script"` and `"script-base64"`, or passing `"uid"` for UUID targets)
- **AND** it SHALL poll `show-task`, Base64-decode per-target outputs into `RepositoryScriptExecutionOutcome`, and inject zero route-collection or VSX logic

#### Scenario: SCN-CLIENT-012-2 — Execution outside WriteSession uses a non-read-only session without publish or discard

- **WHEN** `run_repository_script` runs outside an active `WriteSession`
- **THEN** it SHALL authenticate a dedicated non-read-only session (`read_only=False`), execute `run-script` and `show-task`, and log out cleanly without calling `publish` or `discard`
- **AND** it SHALL never reuse the shared read-only `arodonata_sid_cache` session

#### Scenario: SCN-CLIENT-012-3 — Missing script or read-only session denial maps to typed script exceptions

- **WHEN** Check Point rejects `run-script` because the script is absent or because the caller lacks `run-repository-script` (or authenticated with `read-only: true`)
- **THEN** `run_repository_script` SHALL raise `RepositoryScriptNotFoundError` or `RepositoryScriptPermissionError` respectively without falling back to inline `"one time"` script execution

### Requirement: Coordinator-Delegated Cold-Cache Rulebase Warming in Client Change Reports

**ID**: REQ-CLIENT-013\
**Intent**: Route cold-cache rulebase warming during `ArodonataClient` change reports through `DomainSyncCoordinator` locks and sync stamps.\
**Non-goals**: Standalone `collect_change_report()` in-memory fallback (`REQ-REPORT-003`).

`ArodonataClient.collect_change_report()` and `ArodonataClient.build_change_report()` SHALL wire cold-cache rulebase placement fallback through `ArodonataClient.refresh_rulebases(..., mode="smart")` so any rulebase cache population triggered during report generation obeys `DomainSyncCoordinator` distributed locks, dirty-session checks, and `DomainSyncState` stamps.

#### Scenario: SCN-CLIENT-013-1 — Cold-cache report collection via ArodonataClient warms rulebase through coordinator

- **GIVEN** a session with rule changes on a domain whose `arodonata_rulebase_*` cache is empty and no `OwnedSession` handled placement
- **WHEN** `await client.collect_change_report(scopes)` runs
- **THEN** `ArodonataClient` SHALL invoke `refresh_rulebases(mgmt_name=mgmt_name, domains=[domain_name], mode="smart")` via `DomainSyncCoordinator` rather than performing an unlocked direct `replace_domain_rulebase` write

### Requirement: Client Facade API Reference Introspection with Management Version Inference

**ID**: REQ-CLIENT-014\
**Intent**: Infer target Check Point API versions automatically from configured management servers during API schema discovery and validation.\
**Non-goals**: Underlying offline API reference index behavior (`REQ-APIREF-001`..`REQ-APIREF-004`).

`ArodonataClient` SHALL expose `api_reference` (`ApiReferenceEngine`) and convenience methods `search_api_commands(...)`, `describe_api_command(...)`, and `validate_api_payload(...)`, automatically inferring target API `version` when `version=None` from `mgmt_name` (or the sole configured server's `api_version`), falling back to the index's `latest` version (`"v2.2"`).

#### Scenario: SCN-CLIENT-014-1 — Client facade infers target API version from configured management server

- **GIVEN** an `ArodonataClient` where `"corp-mds"` is configured with `api_version="1.9"`
- **WHEN** `client.describe_api_command("add-interface", mgmt_name="corp-mds")` is called with `version=None`
- **THEN** `ArodonataClient` SHALL resolve `version="v1.9"` automatically from `"corp-mds"` settings and return the `v1.9`-filtered schema for `add-interface`

### Requirement: Provider-Agnostic OpenTelemetry Instrumentation and Secret Redaction

**ID**: REQ-CLIENT-015\
**Intent**: Provide host-controlled OpenTelemetry tracing across client operations while ensuring secrets and SIDs never enter telemetry spans.\
**Non-goals**: `ARODONATA_TRACE_MODULES` settings parsing (`REQ-CONFIG-007`).

All major client, transport, login, lock, cache, and CPCRUD entry points SHALL be decorated with `@traced` and attach `arodonata.*`-namespaced span attributes (`span_attrs`) while recursively sanitizing mappings, nested lists/tuples, and chained exception causes (`__cause__` and `__context__`) so credentials, API keys, or unredacted session SIDs are never recorded.

#### Scenario: SCN-CLIENT-015-1 — Span attributes omit None values and never expose secrets

- **WHEN** `span_attrs(**attrs)` runs inside a `@traced` operation or an exception with a chained `__cause__` / `__context__` is recorded on a span
- **THEN** non-`None` attributes SHALL be recorded under `arodonata.<key>` with recursive secret and `sid` redaction across mappings, lists, and chained exception messages
- **AND** `@traced` and `span_attrs` SHALL operate as a zero-overhead no-op when no `TracerProvider` is configured by the host application

### Requirement: Domain Events and Framework-Agnostic SSE Stream Adapter

**ID**: REQ-CLIENT-016\
**Intent**: Convert internal async `DomainEvent` generators (`SyncProgressEvent`, `CPCRUDEvent`, `StagedSessionEvent`) into standards-compliant Server-Sent Events cleanly.\
**Non-goals**: HTTP framework routing (Starlette/FastAPI `StreamingResponse` wiring belongs to host applications).

`arodonata.core.events` and `arodonata.adapters.sse` SHALL define typed Pydantic v2 `DomainEvent` subclasses (`SyncProgressEvent`, `CPCRUDEvent`, `StagedSessionEvent`) and convert async event streams via `to_sse_event()` and `stream_as_sse()` into `SSEEvent` payloads formatted as `event:` / `data:` / `id:` wire strings.

#### Scenario: SCN-CLIENT-016-1 — Domain events serialize to SSEEvent and wire-formatted SSE chunks

- **WHEN** `to_sse_event(event)` or `stream_as_sse(events)` processes `SyncProgressEvent`, `CPCRUDEvent`, or `StagedSessionEvent` instances
- **THEN** `to_sse_event()` SHALL map `event.event_type` to `SSEEvent.event` and serialize `model_dump(mode="json")` into `SSEEvent.data`
- **AND** `SSEEvent.encode()` / `stream_as_sse()` SHALL emit wire-format `event:` / `data:` chunks terminated by blank lines without owning HTTP server state

### Requirement: Extended Client Lifecycle, Streaming, Staged Session, and Service Properties Facade

**ID**: REQ-CLIENT-017\
**Intent**: Document and verify the full `ArodonataClient` facade surface so consumers rely on stable top-level methods and service accessors.\
**Non-goals**: Detailed semantics of underlying services covered in domain specs.

`ArodonataClient` SHALL expose full lifecycle, context, streaming, search, rulebase, reporting, staged-session, CLI, and API-reference methods alongside typed service properties (`db`, `cache`, `lock_port`, `api`, `amgmt`, `cpcrud`, `topology_service`, `script_service`, `api_reference`) delegating cleanly to their backing ports and domain services.

#### Scenario: SCN-CLIENT-017-1 — ArodonataClient exposes full public method and service-accessor contract

- **WHEN** a caller initializes `ArodonataClient` and inspects its service properties (`db`, `cache`, `lock_port`, `api`, `amgmt`, `cpcrud`, `topology_service`, `script_service`, `api_reference`)
- **AND** invokes `initialize()`, `user_context()`, `create_dedicated_session()`, `logout_sid()`, `invalidate_domain()`, `refresh_*`/`stream_refresh_*`, `search_objects()`, `get_cache_status()`, `get_layer_rulebase()`, `locate_rules()`, `filter_rulebase()`, `build_change_report_from_plan()`, `render_change_report()`, `publish_staged_session()`, `stream_publish_staged_session()`, `discard_staged_session()`, `set_gateway_cli()`, and `ensure_api_reference()`
- **THEN** all facade methods and service accessors SHALL resolve cleanly and delegate to their backing ports and services

### Requirement: Hexagonal Layer Boundaries, Segregated Cache Ports, and Shared Core Primitives

**ID**: REQ-CLIENT-018\
**Intent**: Enforce strict hexagonal import isolation, Interface Segregation on `CachePort`, and DRY core primitives and Check Point sentinel definitions.\
**Non-goals**: Behavioral changes to Management API pagination or cache schema migrations.

Hexagonal layers (`core`, `adapters`, `cpcrud`, `rulebase`, `reports`, `mcp`) SHALL obey AST-verified import boundaries, `CachePort` SHALL compose eight `@runtime_checkable` ISP sub-protocols matched to service consumers alongside `RulebaseRefreshPort`, and `arodonata.core.primitives` / `arodonata.core.models.sentinels` SHALL provide shared primitives and Check Point sentinel UIDs with backward-compatible re-exports.

#### Scenario: SCN-CLIENT-018-1 — Hexagonal layer import boundaries are enforced via AST across core, adapters, cpcrud, rulebase, reports, and mcp

- **WHEN** an AST boundary scan inspects every import statement (including relative, lazy, and `TYPE_CHECKING` imports) in `core`, `adapters`, `cpcrud`, `rulebase`, `reports`, and `mcp`
- **THEN** `core` SHALL have zero imports from `arodonata.adapters`, `arodonata.client`, `arodonata.mcp`, `arodonata.cpcrud`, `arodonata.reports`, `arodonata.rulebase`, `arodonata.testing`, `cpapi`, `aiohttp`, `sqlalchemy`, `sqlmodel`, `asyncpg`, or `aiosqlite`
- **AND** `adapters` SHALL not import `arodonata.client`, `arodonata.mcp`, `arodonata.cpcrud`, `arodonata.reports`, `arodonata.rulebase`, or `arodonata.testing`
- **AND** `cpcrud` SHALL not import `arodonata.adapters` or `arodonata.client`, `rulebase` SHALL not import `arodonata.cpcrud`, `arodonata.adapters`, or `arodonata.client`, `reports` SHALL not import `arodonata.adapters`, `arodonata.client`, `arodonata.mcp`, or `arodonata.testing`, and `mcp` SHALL not import `arodonata.adapters` or `arodonata.testing`

#### Scenario: SCN-CLIENT-018-2 — CachePort composes eight runtime-checkable ISP sub-protocols and RulebaseRefreshPort decouples TopologyService

- **WHEN** `SqlCacheAdapter`, `RulebaseRefreshService`, and narrowed service consumers (such as `AssetRefreshService`) are inspected at runtime
- **THEN** `SqlCacheAdapter` SHALL satisfy all eight `@runtime_checkable` sub-protocols (`DomainCachePort`, `SidCachePort`, `SyncStatePort`, `ObjectCachePort`, `ServiceCachePort`, `AssetCachePort`, `TopologyCachePort`, `RulebaseCachePort`) and `CachePort`
- **AND** `RulebaseRefreshService` SHALL satisfy `RulebaseRefreshPort`, consumers narrowed to a sub-protocol SHALL accept minimal sub-port doubles, and `TopologyService` constructed without `rulebase_refresh` SHALL log a warning and return cold package snapshots without failing

#### Scenario: SCN-CLIENT-018-3 — Canonical Check Point sentinels and core primitives resolve UID c476 as Policy Targets and preserve strict mask validation

- **WHEN** callers evaluate `arodonata.core.models.sentinels`, `arodonata.core.primitives`, legacy re-export paths, and strict CPCRUD `normalize_mask_length(..., strict=True)`
- **THEN** UID `6c488338-8eec-4103-ad21-cd461ac2c476` SHALL map strictly to `Policy Targets` (`type="Global"`) rather than `Drop`, and all moved helpers (`parse_cp_publish_timestamp`, `update_overlay_from_command`, `extract_policy_packages`, `PolicyPackageInfo`, sentinel normalizers) SHALL retain object identity at legacy import paths
- **AND** `mask_to_prefix_len` SHALL validate contiguous netmasks (accepting integral floats such as `24.0` and hostmasks only with `allow_hostmask=True`), while desired CPCRUD specs with invalid `mask_length4` or `subnet_mask` SHALL raise `ValidationError`

### Requirement: SSE Control Field Sanitization Against Frame Injection

**ID**: REQ-CLIENT-019\
**Intent**: Prevent CR/LF/NUL injection and SID leakage in SSE wire `id:` and `event:` headers.\
**Non-goals**: Multiline JSON `data:` payload serialization (`REQ-CLIENT-016`).

`SSEEvent.encode()` SHALL strip CR, LF, and NUL control characters from `id` and `event` header fields and apply SID redaction to `event` before formatting SSE wire frames.

#### Scenario: SCN-CLIENT-019-1 — SSEEvent.encode strips newlines/NUL from id and event and redacts SIDs in event

- **GIVEN** an `SSEEvent` or `to_sse_event(..., event_id=...)` input whose `id` or `event` contains `\r`, `\n`, `\x00`, or an embedded SID pattern
- **WHEN** `encode()` formats the SSE wire frame
- **THEN** the emitted frame SHALL contain zero injected `data:`/`event:` lines and SHALL scrub any SID pattern from both `id:` and `event:` headers

### Requirement: Extended Secret Redaction, Shielded Write-Session Cancellation, and Script Unsupported Error Handling

**ID**: REQ-CLIENT-020\
**Intent**: Prevent secret leakage in key-value and DB URL diagnostics, guarantee clean discard on write-session cancellation or pre-send publish failure, rollback standalone mutations cleanly, and surface unsupported script-repository responses explicitly.\
**Non-goals**: SSE wire frame formatting (`REQ-CLIENT-019`) or CLI logging configuration (`REQ-AIBUILD-003`).

`redact_sid()` SHALL mask key=value secrets and URL passwords, write-session lifecycle helpers SHALL shield discard/logout while propagating `CancelledError`/`ServerIdentityError`, standalone `_mutate_object()` SHALL discard on failure, and `ScriptRepositoryService` SHALL scrub active SIDs and map unsupported script responses cleanly.

#### Scenario: SCN-CLIENT-020-1 — Extended key-value/URL secret redaction, shielded write-session cancellation/discard, and standalone mutation rollback

- **GIVEN** text containing `password=...`/`api_key=...`/`secret=...` or `scheme://user:pass@host` URLs, a write session experiencing `CancelledError` or pre-send `publish` `TransportError`, or a standalone `_mutate_object()` failure
- **WHEN** `redact_sid()`, `run_write_session_lifecycle()`, or `_mutate_object()` executes
- **THEN** key-value and URL credentials SHALL be redacted consistently, cancellations and identity errors SHALL propagate after shielded discard/logout, and failed `_mutate_object()` calls SHALL execute `discard` without leaving dirty server state

#### Scenario: SCN-CLIENT-020-2 — Unsupported repository-script classification and active write-session SID scrubbing

- **GIVEN** a Check Point server returning an unsupported repository-script error on `show-repository-scripts` / `show-repository-script`, or an active `WriteSession` whose SID appears in `ScriptRepositoryService` errors or `RepositoryScriptStatus.error`
- **WHEN** `get_repository_script()`, `list_repository_scripts()`, `check_repository_script()`, `ensure_repository_script()`, or route script execution runs
- **THEN** unsupported errors SHALL map to `RepositoryScriptUnsupportedError`, `RouteCollectionService` SHALL handle fallback cleanly, and active `WriteSession` SIDs SHALL be scrubbed everywhere including `RepositoryScriptStatus.error`


---

### OpenSpec Capability: `configuration` (`openspec/specs/configuration/spec.md`)

# Configuration and Settings Specification

## Purpose

Defines explicit, type-safe configuration resolution for Arodonata (`ArodonataSettings`) and its MCP server (`ArodonataMCPSettings`), supporting static API-key multi-server topologies, static credential authentication, and dynamic/deferred authentication without ever reading `.env` files implicitly inside the library.

## Requirements

### Requirement: Explicit Settings Precedence Without Implicit Dotenv Loading

**ID**: REQ-CONFIG-001\
**Intent**: Keep library configuration deterministic and predictable across working directories without hidden `.env` side effects.\
**Non-goals**: Standalone test harness `.env.test` loading (`REQ-ITEST-003`) or MCP token validation (`REQ-MCP-001`).

`ArodonataSettings` SHALL resolve configuration from explicit constructor keyword arguments over `os.environ` without reading `.env` files automatically, compute derived concurrency and route-limit defaults, and anchor default `tls_known_hosts_path` to `~/.config/arodonata/tls_known_hosts.json` rather than the working directory.

#### Scenario: SCN-CONFIG-001-1 — Constructor keyword overrides environment variable

- **GIVEN** `ARODONATA_CONCURRENT_LIMIT=4` is set in `os.environ`
- **WHEN** `ArodonataSettings` is instantiated with `concurrent_limit=8` (and without `domain_sync_concurrency`, `route_collect_concurrency`, or `max_routes_per_gateway` overrides)
- **THEN** `settings.concurrent_limit` SHALL equal `8`
- **AND** default `domain_sync_concurrency` SHALL be capped at `min(2, max(1, concurrent_limit - 1)) == 2` unless overridden via constructor or `ARODONATA_DOMAIN_SYNC_CONCURRENCY`
- **AND** default `route_collect_concurrency` SHALL be capped at `min(4, max(1, concurrent_limit // 2)) == 4` unless overridden via constructor or `ARODONATA_ROUTE_COLLECT_CONCURRENCY`
- **AND** default `max_routes_per_gateway` SHALL equal `50000` unless overridden via constructor or `ARODONATA_MAX_ROUTES_PER_GATEWAY`

#### Scenario: SCN-CONFIG-001-2 — Environment variable populates field by default

- **GIVEN** `ARODONATA_SESSION_TIMEOUT=900` is present in `os.environ`
- **WHEN** `ArodonataSettings()` is instantiated without keyword arguments
- **THEN** `settings.session_timeout` SHALL equal `900`

#### Scenario: SCN-CONFIG-001-3 — Default TLS known-hosts path is independent of working directory

- **GIVEN** different process working directories (`os.getcwd()`)
- **WHEN** `ArodonataSettings()` is instantiated without an explicit `tls_known_hosts_path`
- **THEN** `tls_known_hosts_path` SHALL resolve to the same absolute user-scoped path (`~/.config/arodonata/tls_known_hosts.json`) so changing `os.getcwd()` never resets TOFU trust state

### Requirement: Positional Multi-Server Topology Configuration

**ID**: REQ-CONFIG-002\
**Intent**: Support multi-server and MDSM topologies consistently via positional lists across both library and CLI entry points.\
**Non-goals**: Runtime CMA failover resolution (`REQ-SESS-001`).

The system SHALL support configuring multiple Check Point management servers via comma-separated `mgmt_names` and `mgmt_servers`, optionally paired by position with `api_keys` (or `API_KEY_VARS`), using a single consistent precedence order (`api_keys` keyword/env over `API_KEY_VARS`) across both library and CLI entry points.

#### Scenario: SCN-CONFIG-002-1 — Valid positional server and API key resolution via API_KEY_VARS

- **GIVEN** `MGMT_NAMES="mds1,sms2"`, `MGMT_SERVERS="10.0.0.1,10.0.0.2"`, `API_KEY_VARS="KEY_MDS1,KEY_MDS2"`, `KEY_MDS1="secret1"`, and `KEY_MDS2="secret2"`
- **WHEN** `ArodonataSettings()` resolves the multi-server registry
- **THEN** `mgmt_names` SHALL resolve to `["mds1", "sms2"]` and `mgmt_servers` to `["10.0.0.1", "10.0.0.2"]`
- **AND** `"mds1"` SHALL pair with `"secret1"` and `"sms2"` SHALL pair with `"secret2"`

#### Scenario: SCN-CONFIG-002-2 — Precedence of API_KEYS vs API_KEY_VARS in library vs MCP CLI

- **GIVEN** both `API_KEYS` and `API_KEY_VARS` are present in the environment
- **WHEN** configuration is loaded in library or MCP CLI mode
- **THEN** `ArodonataSettings` SHALL consistently prioritize explicit `API_KEYS` over `API_KEY_VARS` in both modes

#### Scenario: SCN-CONFIG-002-3 — Mismatched server and key counts

- **GIVEN** static API keys whose count disagrees with the number of entries in `mgmt_names` and `mgmt_servers`
- **WHEN** `ArodonataSettings` validates the server registry
- **THEN** validation SHALL raise `ConfigurationError` describing the count mismatch

### Requirement: Authentication Mode and Default Engine Resolution

**ID**: REQ-CONFIG-003\
**Intent**: Support static API keys, static credentials, and deferred dynamic auth uniformly with an auto-owned SQLite default when no engine is supplied.\
**Non-goals**: Runtime session caching and credential eviction (`REQ-SESS-002`, `REQ-SESS-003`).

The system SHALL resolve `auth_mode` to `"api_key"`, `"credential"`, or `"dynamic"` (deferred credentials when servers are configured without static keys or passwords), and SHALL default `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) across all authentication modes.

#### Scenario: SCN-CONFIG-003-1 — Credential mode requires management server IP or topology

- **GIVEN** `username` and `password` without `mgmt_ip` or `mgmt_servers`
- **WHEN** settings initialization validates server endpoints
- **THEN** initialization SHALL raise `MissingConfigurationError` stating that a target management server address is required

#### Scenario: SCN-CONFIG-003-2 — Omitted engine auto-creates in-memory SQLite in any authentication mode

- **GIVEN** `"api_key"`, `"credential"`, or `"dynamic"` authentication mode
- **WHEN** `AMgmtClient` or `ArodonataClient` is initialized with `engine=None`
- **THEN** the client SHALL create and own an in-memory `sqlite+aiosqlite:///:memory:` engine
- **AND** `client.close()` SHALL dispose of that auto-created engine

#### Scenario: SCN-CONFIG-003-3 — Dynamic mode initializes cleanly without static credentials

- **GIVEN** `MGMT_NAMES="mds1"` and `MGMT_SERVERS="10.0.0.1"` without `api_keys` or `username`/`password`
- **WHEN** `ArodonataSettings()` initializes
- **THEN** `auth_mode` SHALL resolve to `"dynamic"` without raising `MissingConfigurationError`, deferring credentials to runtime `AuthContext` or `AuthProvider`

### Requirement: Separate Operational Timeout Budgets

**ID**: REQ-CONFIG-004\
**Intent**: Isolate connect, standard RPC, login, task-poll, and rate-limiter wait budgets so slow operations do not starve fast calls.\
**Non-goals**: Transport resend prohibition and phase classification (`REQ-TRANS-007`).

The configuration SHALL maintain distinct timeout settings for TCP/TLS connection establishment (`connect_timeout`, default 30s), standard API calls (`api_timeout`, default 120s), login attempts (`login_timeout`, default 120s), long-running server tasks (`task_timeout`, default 900s), and rate-limiter slot acquisition (`rate_limit_slot_timeout`, default 90s).

#### Scenario: SCN-CONFIG-004-1 — Default read timeout calculation on transport socket

- **GIVEN** an HTTP transport configured from `ArodonataSettings`
- **WHEN** TCP/TLS connects and executes calls with or without an explicit per-call budget
- **THEN** the TCP/TLS connect and handshake timeout SHALL equal `connect_timeout`
- **AND** calls with an explicit per-call budget SHALL use `budget + 5` seconds as the socket read timeout
- **AND** calls without an explicit per-call budget (such as `show-task` polls) SHALL use `max(api_timeout, login_timeout) + 5` seconds

### Requirement: CPRID Repository Script Execution Configuration

**ID**: REQ-CONFIG-005\
**Intent**: Configure repository-script execution mode and script naming cleanly while keeping inline execution as the backward-compatible default.\
**Non-goals**: Script provisioning and execution behavior on management servers (`REQ-CLIENT-010`, `REQ-TOPO-008`).

`ArodonataSettings` SHALL resolve `cprid_script_mode` (`"inline" | "repository" | "auto"`, default `"inline"`, env alias `ARODONATA_CPRID_SCRIPT_MODE`) and `cprid_repository_script_name` (default `"arodonata-collect-routes-v1"`, env alias `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME`, rejecting blank strings) from constructor arguments and `os.environ` without implicitly loading `.env` files.

#### Scenario: SCN-CONFIG-005-1 — Default mode preserves backward-compatible inline execution

- **WHEN** `ArodonataSettings()` is instantiated without `cprid_script_mode` or `cprid_repository_script_name` overrides
- **THEN** `cprid_script_mode` SHALL equal `"inline"`
- **AND** `cprid_repository_script_name` SHALL equal `"arodonata-collect-routes-v1"`

#### Scenario: SCN-CONFIG-005-2 — Constructor and environment overrides resolve repository mode settings

- **GIVEN** `ARODONATA_CPRID_SCRIPT_MODE="repository"` and `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME="custom-routes-script"` in `os.environ`
- **WHEN** `ArodonataSettings()` loads from env or receives `ArodonataSettings(cprid_script_mode="auto", cprid_repository_script_name="corp-routes")`
- **THEN** explicit constructor arguments SHALL override `os.environ` without reading `.env` files from disk

#### Scenario: SCN-CONFIG-005-3 — Invalid mode or blank repository script name rejected on settings initialization

- **WHEN** `ArodonataSettings` receives an unsupported `cprid_script_mode` (e.g., `"ssh-only"`) or a blank/whitespace-only `cprid_repository_script_name`
- **THEN** settings validation SHALL fail immediately with `pydantic.ValidationError`

### Requirement: Environment-Backed CPCRUD Naming Profile Configuration

**ID**: REQ-CONFIG-006\
**Intent**: Allow operators to standardize CPCRUD auto-naming prefixes and suffixes via environment variables without passing overrides on every call.\
**Non-goals**: Shorthand parsing and conflict resolution logic (`REQ-CPCRUD-002`, `REQ-CPCRUD-003`).

`ArodonataSettings` SHALL resolve a default `cpcrud_naming_prefixes` profile from explicit constructor arguments and `ARODONATA_CPCRUD_*` (falling back to `CPCRUD_*`) environment variables without loading `.env` files implicitly, covering host, network, range, group, service, and application-site formatting options.

#### Scenario: SCN-CONFIG-006-1 — Environment variables populate CPCRUD naming profile defaults

- **GIVEN** `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"`, `ARODONATA_CPCRUD_RANGE_SEPARATOR="_"`, and `ARODONATA_CPCRUD_RANGE_COMPRESS_OCTETS="true"` in `os.environ`
- **AND** `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_GROUP=""`, `ARODONATA_CPCRUD_AUTO_NAME_SUFFIX_GROUP="_Grp"`, `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_APP_SITE="Site_"`, and `ARODONATA_CPCRUD_APP_SITE_WILDCARD_MARKER="_"` in `os.environ`
- **WHEN** `ArodonataSettings()` is instantiated
- **THEN** `settings.cpcrud_naming_prefixes` SHALL reflect those configured prefixes, suffixes, range separator, compression flag, and wildcard marker without reading `.env` files

#### Scenario: SCN-CONFIG-006-2 — Secondary CPCRUD environment aliases are accepted when ARODONATA_CPCRUD variables are absent

- **GIVEN** `CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"` and `CPCRUD_RANGE_COMPRESS_OCTETS="true"` in `os.environ` without `ARODONATA_CPCRUD_*` counterparts
- **WHEN** `ArodonataSettings()` is instantiated
- **THEN** `cpcrud_naming_prefixes` SHALL resolve those `CPCRUD_*` values as fallback defaults while prioritizing `ARODONATA_CPCRUD_*` and explicit constructor arguments

#### Scenario: SCN-CONFIG-006-3 — CPCRUDService planning uses ArodonataSettings naming profile by default

- **GIVEN** an `ArodonataClient` configured with `settings.cpcrud_naming_prefixes`
- **WHEN** `client.cpcrud.plan(template)` runs without an explicit `naming_prefixes` argument or template `naming_prefixes` block
- **THEN** `CPCRUDService.plan()` SHALL apply `settings.cpcrud_naming_prefixes` when auto-naming newly created objects and services

### Requirement: OpenTelemetry Module Span Gating Configuration

**ID**: REQ-CONFIG-007\
**Intent**: Allow selective OpenTelemetry span filtering by module prefix without clobbering a host application's existing telemetry configuration.\
**Non-goals**: Span attribute sanitization and secret redaction (`REQ-CLIENT-015`).

The system SHALL support hierarchical dotted-prefix span gating via `ARODONATA_TRACE_MODULES` (`trace_modules`) without owning or resetting the host application's global `TracerProvider` unless rules are explicitly configured.

#### Scenario: SCN-CONFIG-007-1 — Empty trace_modules preserves host tracing rules

- **WHEN** `ArodonataClient` is initialized with `trace_modules=""` (the default)
- **THEN** it SHALL preserve and never overwrite any existing process-global trace gating configuration set by the host application

#### Scenario: SCN-CONFIG-007-2 — Explicit trace_modules applies longest-prefix rules

- **WHEN** `ARODONATA_TRACE_MODULES="arodonata:on,arodonata.api.client:off"` is configured
- **THEN** `trace_modules_rules` SHALL parse into `{"arodonata": True, "arodonata.api.client": False}` and apply to `@traced` spans

### Requirement: Secret and Database Credential Masking in Settings Representations

**ID**: REQ-CONFIG-008\
**Intent**: Prevent accidental credential leakage when settings objects are logged, printed, or serialized.\
**Non-goals**: Runtime `sid` redaction in call results, spans, and reports (`REQ-CLIENT-015`, `REQ-CPCRUD-011`).

`ArodonataSettings` (and `ArodonataMCPSettings.tokens`) SHALL mask all secret fields (`password`, `api_key`, `api_keys`, `tokens`, and `database_url` credentials) across `repr()`, `str()`, `model_dump()`, and `model_dump_json()` unless an explicit secret getter is invoked internally.

#### Scenario: SCN-CONFIG-008-1 — Secrets and database URL passwords masked in repr and serialization

- **GIVEN** an `ArodonataSettings` instance configured with `password`, `api_keys`, or `database_url="postgresql+asyncpg://user:secretpass@db.internal:5432/app"` (or `ArodonataMCPSettings` with `tokens`)
- **WHEN** `repr(settings)`, `str(settings)`, `settings.model_dump()`, or `settings.model_dump_json()` is called
- **THEN** all passwords, API keys, MCP tokens, and the password component of `database_url` SHALL be masked (`"***"`)

### Requirement: Operational Timeout, Cache TTL, and Sync Tuning Configuration

**ID**: REQ-CONFIG-009\
**Intent**: Expose typed, validated settings fields for multi-server API versions, ports, session TTLs, login throttling, cache windows, SQLite busy timeouts, CPCRUD schema path overrides, and topology confidence weights.\
**Non-goals**: Core required `mgmt_names`/`mgmt_servers` parsing (`REQ-CONFIG-001`) or timeout calculation rules (`REQ-CONFIG-004`).

`ArodonataSettings` SHALL expose and validate `api_versions`, `api_version`, `mgmt_port` (`1..65535`), `max_response_bytes` (`>= 1024`, default `67108864`), `max_query_pages` (`>= 1`, default `5000`), `max_query_objects` (`>= 1`, default `1000000`), `session_expire_seconds`, `login_throttle_window`, `login_max_wait`, `domain_list_ttl`, `max_incremental_changes`, `sqlite_busy_timeout_ms`, `cpcrud_schema_path`, and `topology_confidence_weights` with safe defaults and per-server resolution.

#### Scenario: SCN-CONFIG-009-1 — Operational and per-server version settings resolve with validated defaults and overrides

- **WHEN** `ArodonataSettings` is constructed with defaults or overrides (including `mgmt_port <= 0` / `> 65535`, `max_response_bytes < 1024`, `api_versions`, `api_version`, `session_expire_seconds`, `login_throttle_window`, `login_max_wait`, `domain_list_ttl`, `max_incremental_changes`, `sqlite_busy_timeout_ms`, `cpcrud_schema_path`, and `topology_confidence_weights`)
- **THEN** all fields SHALL enforce their Pydantic numeric bounds (`mgmt_port` within `1..65535`, `max_response_bytes >= 1024`) and per-server `api_versions` resolution SHALL fall back to `api_version` when a server entry is omitted

#### Scenario: SCN-CONFIG-009-2 — Pagination page and object caps bound api_query and rulebase paging

- **WHEN** `AMgmtClient.api_query()` exceeds `max_query_pages` or `max_query_objects`, OR `fetch_paged_rulebase()` exceeds `MAX_RULEBASE_OBJECTS`
- **THEN** `api_query()` SHALL return `ApiQueryResult(success=False, code="paging_limit_exceeded")` before unbounded accumulation, and rulebase paging SHALL stop cleanly at the configured object cap


---

### OpenSpec Capability: `cpcrud` (`openspec/specs/cpcrud/spec.md`)

# CPCRUD Declarative Policy-as-Code Engine Specification

## Purpose

Defines the declarative, idempotent Check Point Policy-as-Code CRUD service (`CPCRUDService`, `ArodonataClient.cpcrud`) and shorthand expression helpers for offline template validation, conflict-aware planning (`Plan`), dedicated-session execution and session staging (`ApplyReport`), and compensating rollback template generation across Security Management and MDSM domains.

## Requirements

### Requirement: Offline Template Schema Validation

**ID**: REQ-CPCRUD-001\
**Intent**: Reject malformed templates on the client before opening sessions or touching cache.\
**Non-goals**: Semantic or state-level conflicts (handled during planning, not schema validation).

`CPCRUDService.validate()` SHALL validate YAML/JSON templates against `checkpoint_ops_schema.json` (or `cpcrud_schema_path`) without making network or database calls.

#### Scenario: SCN-CPCRUD-001-1 — Invalid template returns errors offline

- **GIVEN** a template violating `checkpoint_ops_schema.json`
- **WHEN** `validate(template)` is called
- **THEN** it SHALL return a non-empty list of human-readable validation error strings
- **AND** perform zero API or database calls

### Requirement: Shorthand Object, Range, Domain, and Wildcard Application Expression Parsing

**ID**: REQ-CPCRUD-002\
**Intent**: Allow concise IP, address-range, DNS-domain, service, group, and wildcard-domain expressions with configurable naming conventions.\
**Non-goals**: Resolving live Check Point object conflicts or server-side existence (handled during planning).

`arodonata.cpcrud` SHALL parse shorthand host, network, full or compressed-octet address-range, DNS-domain, service, inline group, and wildcard application expressions (`*domain` and `*.domain`) into canonical CPCRUD specifications using `NamingPrefixes` for newly created object names while preserving legacy defaults.

#### Scenario: SCN-CPCRUD-002-1 — Compressed same-subnet IPv4 address-range naming and shorthand range input

- **GIVEN** `NamingPrefixes` configured with `address_range="Range_"`, `range_separator="_"`, and `compress_range_same_subnet=True`
- **WHEN** an expression or range object specifies `10.1.1.1` through `10.1.1.9` (including shorthand `10.1.1.1-9`) or a cross-`/24` range `10.1.1.1` through `10.1.2.9`
- **THEN** range parsing SHALL resolve bounds `("10.1.1.1", "10.1.1.9")` for `10.1.1.1-9`
- **AND** `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"Range_10.1.1.1_9"`
- **AND** `format_address_range("10.1.1.1", "10.1.2.9")` across distinct `/24` prefixes SHALL return `"Range_10.1.1.1_10.1.2.9"`

#### Scenario: SCN-CPCRUD-002-2 — Legacy default NamingPrefixes behavior remains backward compatible

- **GIVEN** `NamingPrefixes()` instantiated with default arguments
- **WHEN** default object names are formatted
- **THEN** `format_host("10.1.1.1")` SHALL return `"Host_10.1.1.1"`
- **AND** `format_network("10.1.1.0", 24)` SHALL return `"Net_10.1.1.0_24"`
- **AND** `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"IPR_10.1.1.1-10.1.1.9"`
- **AND** `format_group("WebServers")` SHALL return `"grpWebServers"`

#### Scenario: SCN-CPCRUD-002-3 — Wildcard application expressions normalize both leading-star and star-dot syntax

- **GIVEN** `NamingPrefixes(app_site="Site_", app_site_wildcard_marker="_")`
- **WHEN** an operator supplies `*chinacloudapi.cn` or `*.chinacloudapi.cn`
- **THEN** `format_app_site("chinacloudapi.cn", is_wildcard=True)` SHALL return `"Site__chinacloudapi.cn"` containing no `*` character
- **AND** the parsed `application-site` specification SHALL emit `primary-category: "Custom_Application_Site"`, `urls-defined-as-regular-expression: true`, and `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]`

#### Scenario: SCN-CPCRUD-002-4 — Group suffix and DNS domain shorthand expressions

- **GIVEN** `NamingPrefixes(group="", group_suffix="_Grp")`
- **WHEN** `format_group("AppAccess")` formats a group name or `.abc.com` is parsed as an object expression
- **THEN** `format_group("AppAccess")` SHALL return `"AppAccess_Grp"` without duplicating the suffix if already ending in `"_Grp"`
- **AND** `.abc.com` SHALL parse as `type: "dns-domain"`, `name: ".abc.com"`, and `is_sub_domain: true`

### Requirement: Two-Axis Conflict Resolution and Idempotent Planning

**ID**: REQ-CPCRUD-003\
**Intent**: Produce deterministic, side-effect-free execution plans that resolve name and value conflicts safely and fail closed on state-read errors.\
**Non-goals**: Opening write sessions or mutating Check Point state (handled during plan execution).

`CPCRUDService.plan()` SHALL record a `sid`-redacted `DomainStamp` per domain before state lookups, inspect domain state via an isolated per-run cache-first view gated by domain head freshness while maintaining intra-plan virtual overlay coherency across creations, updates, renames, and deletions, enforce the CPCRUD `type` allowlist and unique operation `id`s, evaluate `NameConflictPolicy` and `IpConflictPolicy`, compute `FieldChange` diffs, and return a deterministic `Plan`.

#### Scenario: SCN-CPCRUD-003-1 — Re-planning an already-applied template yields UNCHANGED or REUSE

- **GIVEN** a target domain where all desired objects, services, and rules already exist with matching attributes
- **WHEN** `CPCRUDService.plan(template)` runs against that domain
- **THEN** every `PlannedAction` SHALL have `Outcome.UNCHANGED` or `Outcome.REUSE`
- **AND** executing the resulting `Plan` in `apply()` SHALL require zero API write operations

#### Scenario: SCN-CPCRUD-003-2 — Value conflict with create_new auto-names object using NamingPrefixes

- **GIVEN** `on_ip_conflict="create_new"` is active
- **WHEN** a host, network, address-range, or service operation encounters an IP, subnet, range, or port/protocol match under a different name
- **THEN** `CPCRUDService.plan()` SHALL generate a convention-compliant name using `NamingPrefixes` (`Host_`, `Net_`, `IPR_`, `TCP_`, `UDP_`, `ICMP_` by default)

#### Scenario: SCN-CPCRUD-003-3 — Failed state lookup produces ERROR action rather than false CREATE

- **GIVEN** a domain where `show-last-published-session` fails, or a cache or API lookup (`dns-domain` leading-dot retry, name/IP lookup, service listing, rulebase read, or `where-used`) fails or returns `paging_inconsistent`
- **WHEN** `CPCRUDService.plan(template)` evaluates operations in that domain
- **THEN** it SHALL NOT treat the failure as "not found"
- **AND** it SHALL plan an `Outcome.ERROR` action (`lookup failed, nothing planned (re-plan to retry): ...`) with `sid`-redacted details
- **AND** it SHALL execute zero writes for that action and mark dependent actions as `skipped_dependency`

#### Scenario: SCN-CPCRUD-003-4 — Cache-first object and service lookups gated by exact domain head stamp

- **GIVEN** a target domain whose head `DomainStamp` (`last_published_at` and `last_session_uid`) was read at the start of `CPCRUDService.plan()`
- **WHEN** `plan()` looks up a `host`, `network`, `address-range`, `dns-domain`, `group`, or service
- **THEN** it SHALL read from the cached object or service store ONLY while the domain's stored sync state for that specific `(scope, item_type)` matches `DomainStamp.last_published_at` and `DomainStamp.last_session_uid`
- **AND** it SHALL fall back to live API queries otherwise

#### Scenario: SCN-CPCRUD-003-5 — Duplicate template operation IDs or unknown object types rejected

- **GIVEN** a template containing two operations with the same `id` or an `object_type` outside the canonical CPCRUD allowlist
- **WHEN** `CPCRUDService.plan(template)` runs
- **THEN** it SHALL raise `ValidationError` (or record a validation failure) rather than silently overwriting action results or constructing arbitrary `show-<type>` / `add-<type>` commands

#### Scenario: SCN-CPCRUD-003-6 — Intra-plan virtual overlay coherency across same-template updates, renames, and deletions

- **GIVEN** a template containing multiple sequential operations targeting the same `group`, `service-group`, network object (`host`, `network`, `application-site`, `dns-domain`), or service (`service-tcp`, `service-icmp`)
- **WHEN** an earlier step updates attributes, members, or name (`new-name`) or deletes an entity, and a subsequent step in the same `plan()` run looks up, modifies, deletes, or checks value conflicts against that entity or its prior/new values
- **THEN** `Planner` and `HybridStateReader` SHALL reflect the post-update model (including `group` and `service-group` members/metadata, object/service values, and renamed names) or deletion tombstone in the virtual overlay
- **AND** same-template updates or deletions of an earlier `CREATE` SHALL emit valid wire `"name"` identifiers instead of synthetic `"planned:"` UIDs
- **AND** a `set` targeting a virtually deleted entity SHALL fail closed with `Outcome.ERROR`, while a repeat identical update SHALL yield `Outcome.UNCHANGED`

### Requirement: Targeted Cold-Cache Value Conflict Lookups via show-objects

**ID**: REQ-CPCRUD-004\
**Intent**: Avoid expensive full-domain object and service pagination when planning against empty or stale domain caches.\
**Non-goals**: Cold-cache ICMP service value lookups (`REQ-CPCRUD-005`) or background cache synchronization.

When a domain's object or service cache slice is absent or stale during `CPCRUDService.plan()`, value-conflict lookups for `host`, `network`, `address-range`, `service-tcp`, and `service-udp` operations SHALL query `show-objects` (`type`, `filter`, `ip-only`) with exact attribute verification and intra-plan overlays instead of paginating `show-hosts`, `show-networks`, `show-services-tcp`, or `show-services-udp`.

#### Scenario: SCN-CPCRUD-004-1 — Cold-cache host and TCP service conflict checks avoid full domain listing

- **GIVEN** a target domain whose object and service cache slices are empty
- **WHEN** `CPCRUDService.plan()` evaluates `add` or `present` operations for a `host` (`10.20.30.40`) and a `service-tcp` (`port: "8443"`)
- **THEN** it SHALL query `show-objects` (`type="host"`, `filter="10.20.30.40"`, `ip-only=True`) and `show-objects` (`type="service-tcp"`, `filter="8443"`)
- **AND** it SHALL filter returned candidates by exact IP/port/protocol equality while merging intra-plan virtual additions and deletions
- **AND** it SHALL execute zero full-domain `show-hosts` or `show-services-tcp` queries

#### Scenario: SCN-CPCRUD-004-2 — Substring filter candidates are verified by exact value match

- **GIVEN** `show-objects` (`type="service-tcp"`, `filter="80"`) returns both `TCP_80` (`port="80"`) and `TCP_8080` (`port="8080"`)
- **AND** `show-objects` (`type="network"`, `filter="10.10.0.0"`, `ip-only=True`) returns both `10.10.0.0/24` and `10.10.0.0/16`
- **WHEN** `CPCRUDService.plan()` evaluates a value-conflict lookup for TCP port `"80"` or subnet `10.10.0.0/24`
- **THEN** it SHALL match only the candidate with exact `(port="80", protocol)` or exact `(subnet4="10.10.0.0", mask_length4=24)` equality

#### Scenario: SCN-CPCRUD-004-3 — Graceful fallback when custom ApiPort adapter does not implement show-objects

- **GIVEN** a cold-cache value lookup during `CPCRUDService.plan()`
- **WHEN** a custom or legacy `ApiPort` adapter returns `generic_err_command_not_recognized` for `show-objects`, or returns `paging_inconsistent` or a transport/API failure
- **THEN** `generic_err_command_not_recognized` SHALL fall back to type-scoped `show-hosts` / `show-networks` / `show-address-ranges` / `show-services-*` listing
- **AND** genuine API failures or `paging_inconsistent` errors SHALL still fail closed as `Outcome.ERROR` (`StateLookupError`)

### Requirement: Single-Page Cold-Cache ICMP Service Value Lookups

**ID**: REQ-CPCRUD-005\
**Intent**: Match built-in and custom ICMP services reliably on cold cache where `show-objects` text filters miss non-numeric names such as `echo-request`.\
**Non-goals**: Host, network, address-range, TCP, or UDP cold-cache lookups via `show-objects` (`REQ-CPCRUD-004`).

When a domain's service cache slice is absent or stale during `CPCRUDService.plan()`, ICMP value-conflict lookups SHALL query single-page `show-services-icmp` and `show-services-icmp6` listings (memoized per domain) instead of numeric text filtering on `show-objects`.

#### Scenario: SCN-CPCRUD-005-1 — Cold-cache ICMP lookup matches built-in services without numeric text filter

- **GIVEN** a target domain on cold cache where built-in `echo-request` does not contain `"8"` in its name
- **WHEN** `CPCRUDService.plan()` evaluates `add` or `present` for a `service-icmp` (`icmp-type: 8`, `icmp-code: 0`)
- **THEN** it SHALL query `show-services-icmp` (memoized per domain within the `plan()` run)
- **AND** it SHALL match `echo-request` by exact `(icmp_type, icmp_code)` equality

### Requirement: Declarative Lifecycle Support for Check Point Application-Site Objects

**ID**: REQ-CPCRUD-006\
**Intent**: Manage custom Check Point `application-site` objects end-to-end across validation, planning, rule references, and rollback.\
**Non-goals**: Incremental `url-list` add/remove patching and cross-name URL-list reuse (`REQ-CPCRUD-007`).

`CPCRUDService` SHALL validate, read, diff, plan (`add-application-site`, `set-application-site`, `delete-application-site`), and generate compensating `inverse()` rollback operations for Check Point `application-site` objects declared in `objects`, `services`, or `operations` sections, including `url-list` and `urls-defined-as-regular-expression` fields.

#### Scenario: SCN-CPCRUD-006-1 — Schema and semantic validation of application-site operations

- **GIVEN** an `application-site` operation in `objects`, `services`, or `operations` with `name`, `primary-category` (or `primary_category`), `url-list` (or `url_list`), and `urls-defined-as-regular-expression` (or `urls_defined_as_regular_expression`)
- **WHEN** `CPCRUDService.validate()` or `CPCRUDService.plan()` evaluates `application-site` operations
- **THEN** static validation SHALL succeed when `url-list` or `application-signature` is present, and reject `action="add"` operations omitting both
- **AND** static validation SHALL allow `present` metadata updates through, while `CPCRUDService.plan()` SHALL reject absent `present` targets that omit both `url-list` and `application-signature`

#### Scenario: SCN-CPCRUD-006-2 — Planning creation of a new regex application-site object

- **GIVEN** an absent `application-site` (`name: "Site_baidu.com"`, `primary-category: "Custom_Application_Site"`, `url-list: ["\\/baidu\\.com", "\\.baidu\\.com"]`, `urls-defined-as-regular-expression: true`)
- **WHEN** `CPCRUDService.plan()` evaluates a `present` or `add` operation for that object
- **THEN** it SHALL produce a `PlannedAction` with `Outcome.CREATE` and command `"add-application-site"`
- **AND** the action payload SHALL contain `"name"`, `"primary-category"`, `"url-list"`, and `"urls-defined-as-regular-expression": true`
- **AND** it SHALL register the resolved name for downstream `access-rule` `service` references

#### Scenario: SCN-CPCRUD-006-3 — Existing application-site with identical URL list and regex flag is planned as UNCHANGED

- **GIVEN** an `application-site` whose target name already exists in the domain with the same `primary-category`, the same set of URLs in `url-list`, and the same `urls-defined-as-regular-expression` boolean
- **WHEN** `CPCRUDService.plan()` evaluates the operation
- **THEN** it SHALL produce `Outcome.UNCHANGED` requiring zero write calls during `apply()`

#### Scenario: SCN-CPCRUD-006-4 — Existing application-site with different URL list respects NameConflictPolicy

- **GIVEN** an `application-site` whose target name already exists in the domain with a different `url-list` or `urls-defined-as-regular-expression` value
- **WHEN** `CPCRUDService.plan()` evaluates the operation under `on_name_conflict="error"` or `on_name_conflict="update"`
- **THEN** it SHALL produce `Outcome.ERROR` reporting `differs on [url-list]` when `on_name_conflict="error"`
- **AND** it SHALL produce `Outcome.UPDATE` with command `"set-application-site"` when `on_name_conflict="update"`

#### Scenario: SCN-CPCRUD-006-5 — Inverse rollback template restores or deletes application-site objects

- **GIVEN** a `Plan` (and optional `ApplyReport`) containing `CREATE`, `UPDATE`, or `DELETE` actions on `application-site` objects
- **WHEN** `CPCRUDService.inverse()` is called
- **THEN** it SHALL generate the corresponding compensating `delete`, `set`, or `add` `application-site` operation preserving `primary-category`, `url-list`, `urls-defined-as-regular-expression`, and `description`
- **AND** it SHALL order those operations after any dependent `access-rule` rollbacks

### Requirement: Incremental URL-List Updates and Value Reuse for Application-Site Objects

**ID**: REQ-CPCRUD-007\
**Intent**: Support safe partial `url-list` updates without clobbering concurrent entries and reuse existing `application-site` objects matching by URL set.\
**Non-goals**: Full-object creation, replacement, and deletion lifecycles for `application-site` (`REQ-CPCRUD-006`).

`CPCRUDService.plan()` SHALL accept `{"add": [...], "remove": [...]}` deltas on `application-site` `url-list` fields, compute idempotent `set-application-site` diffs, reject removals that leave `url-list` empty without `application-signature` (`DiffSafetyError` / `Outcome.ERROR`), and reuse pre-existing `application-site` objects matching by normalized URL list regardless of name.

#### Scenario: SCN-CPCRUD-007-1 — Adding and removing regex entries on an existing application-site

- **GIVEN** an existing `application-site` `"Site__chinacloudapi.cn"` containing `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]`
- **WHEN** `CPCRUDService.plan()` evaluates an update with `url-list: {"add": ["\\.partner\\.cn"], "remove": ["\\/chinacloudapi\\.cn"]}`
- **THEN** it SHALL produce `Outcome.UPDATE` (`set-application-site`) carrying the merged post-delta `url-list` (`["\\.chinacloudapi\\.cn", "\\.partner\\.cn"]`)
- **AND** it SHALL record a `FieldChange` capturing the prior and updated URL lists

#### Scenario: SCN-CPCRUD-007-2 — Removing the last URL from an application-site without an application signature fails closed

- **GIVEN** an existing `application-site` that lacks `application-signature`
- **WHEN** `CPCRUDService.plan()` evaluates a `url-list: {"remove": [...]}` delta that removes every remaining URL entry
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) explaining that an `application-site` cannot have an empty `url-list` without an `application-signature`

#### Scenario: SCN-CPCRUD-007-3 — Legacy-named application-site with identical URL list is reused on value conflict

- **GIVEN** `on_ip_conflict="reuse"` is active and an existing `application-site` `"Custom_ChinaCloud"` already holds `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]` with matching regex flag
- **WHEN** `CPCRUDService.plan()` evaluates `"Site__chinacloudapi.cn"` with that identical `url-list` and regex flag
- **THEN** it SHALL produce `Outcome.REUSE` resolving `"Site__chinacloudapi.cn"` to `"Custom_ChinaCloud"` without renaming or duplicating the existing object

### Requirement: Rule Identity Matching, Cleanup-Aware Positioning, and NAT Sentinels

**ID**: REQ-CPCRUD-008\
**Intent**: Match existing policy and NAT rules idempotently and prevent `"bottom"` insertions from landing below terminal cleanup rules.\
**Non-goals**: Incremental list-cell `add`/`remove` patching and anti-`"Any"`-widening guards (`REQ-CPCRUD-009`).

`CPCRUDService.plan()` SHALL resolve access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`) or by traffic tuple, support cleanup-rule-aware `"bottom"` positioning, and normalize Check Point NAT `"Original"` and `"Any"` sentinel UIDs (`NAT_ORIGINAL_OBJECT_UID`, `NAT_ANY_OBJECT_UID`).

#### Scenario: SCN-CPCRUD-008-1 — Cleanup-aware bottom rule placement

- **GIVEN** a rulebase layer or section whose last rule is an `Any / Any / Any` cleanup rule
- **WHEN** `CPCRUDService.plan()` evaluates a new rule with `position="bottom"` or `position={"bottom": "<section>"}`
- **THEN** it SHALL anchor the new rule at `{"above": "<cleanup_rule_uid>"}` instead of placing it after the cleanup rule

#### Scenario: SCN-CPCRUD-008-2 — NAT rule traffic matching with Original sentinel normalization

- **GIVEN** a live NAT rulebase where Check Point dereferences untranslated fields to the `"Original"` sentinel UID (`NAT_ORIGINAL_OBJECT_UID`)
- **WHEN** a NAT rule with empty or `"Original"` `translated-*` fields is planned against that rulebase
- **THEN** `CPCRUDService.plan()` SHALL match `NAT_ORIGINAL_OBJECT_UID` as equivalent to no translation so re-applying the template reports `Outcome.UNCHANGED` rather than creating a duplicate rule

### Requirement: Incremental List-Cell Patching and Anti-Any-Widening Guards for Policy Rules

**ID**: REQ-CPCRUD-009\
**Intent**: Enable targeted member additions and removals on policy rule cells while preventing accidental rule widening to `"Any"` or silent rule creation.\
**Non-goals**: Rule position anchoring and NAT `"Original"` sentinel normalization (`REQ-CPCRUD-008`).

`CPCRUDService` SHALL support `{"add": [...], "remove": [...]}` deltas on list-valued policy rule fields (`source`, `destination`, `service`, `protected-scope`, `site-category`, `install-on`), enforce target existence on `set`/`update` and delta operations, block unsafe `"Any"` widening or collision (`DiffSafetyError` / `Outcome.ERROR`), generate `inverse()` rollbacks, and replicate these behaviors in `FileReplayApiMock`.

#### Scenario: SCN-CPCRUD-009-1 — Adding and removing sources, destinations, and services in an existing access rule

- **GIVEN** `"Host_10.1.1.1"` is created earlier in the same template and an `access-rule` exists in the target layer
- **WHEN** `CPCRUDService.plan()` evaluates `operation: "set"` with `uid` (or `name`/`rule_number`), `source: {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}`, and `service: {"add": ["TCP_8443"]}`
- **THEN** it SHALL plan `Outcome.UPDATE` (`set-access-rule`) with `depends_on` referencing the `"Host_10.1.1.1"` create action
- **AND** the wire payload SHALL carry incremental `{"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}` on `source` and `{"add": ["TCP_8443"]}` on `service`
- **AND** `CPCRUDService.inverse()` (`build_inverse_template()`) SHALL generate a compensating `set-access-rule` restoring the dereferenced `prior_state`

#### Scenario: SCN-CPCRUD-009-2 — Removing all remaining objects from a rule traffic or install cell is rejected to prevent Any widening

- **GIVEN** an existing policy rule with members in `source`, `destination`, `service`, `protected-scope`, `site-category`, or `install-on`
- **WHEN** `CPCRUDService.plan()` evaluates an incremental `{"remove": [...]}` patch that would leave that cell empty
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) refusing to empty the cell so Check Point cannot implicitly widen the rule to `"Any"`

#### Scenario: SCN-CPCRUD-009-3 — Adding specific objects to a rule cell currently set to Any requires explicit removal of Any

- **GIVEN** an existing policy rule with `source: ["Any"]`
- **WHEN** `CPCRUDService.plan()` evaluates `source: {"add": ["Host_10.1.1.1"]}` without `"Any"` in `remove`
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) requiring `"Any"` to be removed explicitly when narrowing a rule cell
- **AND** when `"Any"` IS explicitly listed in `remove`, `FieldChange.removed_items` SHALL record `["Any"]` while stripping `"Any"` from the Check Point wire `remove` array

#### Scenario: SCN-CPCRUD-009-4 — Adding Any via an incremental rule delta is rejected

- **GIVEN** an existing policy rule
- **WHEN** `CPCRUDService.plan()` evaluates an incremental `{"add": ["Any"]}` delta on a list-valued policy rule cell
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) refusing to add `"Any"` incrementally

#### Scenario: SCN-CPCRUD-009-5 — Unmatched rule with incremental cell deltas fails closed under any verb

- **GIVEN** no existing rule matches the target selector in the domain layer
- **WHEN** `CPCRUDService.plan()` evaluates a policy rule carrying `{"add": ...}` or `{"remove": ...}` cell deltas under `operation: "present"`, omitted `operation`, or `operation: "set"`
- **THEN** it SHALL emit `Outcome.ERROR` instead of falling back to `Outcome.CREATE` with `"Any"` traffic cells

#### Scenario: SCN-CPCRUD-009-6 — Explicit set or update operation targeting a missing rule, group, object, or service fails closed

- **GIVEN** a target rule, group, service, or object that does not exist in the domain
- **WHEN** `CPCRUDService.plan()` evaluates an operation with `operation: "set"` or `operation: "update"`
- **THEN** it SHALL emit `Outcome.ERROR` reporting that the target does not exist rather than creating a new rule or object

#### Scenario: SCN-CPCRUD-009-7 — FileReplayApiMock applies incremental url-list and rule cell updates faithfully

- **GIVEN** an active work session in `FileReplayApiMock`
- **WHEN** `FileReplayApiMock` processes `set-application-site` or `set-*-rule` with `{"add": [...], "remove": [...]}` patches or list replacements
- **THEN** subsequent reads and `show-changes` inside the emulator SHALL reflect the updated URL list or dereferenced rule traffic members accurately

### Requirement: Dedicated-Session Plan Execution and Stale-Plan Safeguards

**ID**: REQ-CPCRUD-010\
**Intent**: Execute planned writes atomically per domain only while the domain head matches the planned snapshot and guarantee session cleanup on failure.\
**Non-goals**: Retaining unpublished sessions for external approval or adopting staged sessions (`REQ-CPCRUD-011`).

`CPCRUDService.apply()` and `stream_apply()` SHALL execute only allowlisted `(object_type, operation)` commands in an isolated `WriteSession` per domain (defaulting omitted session names to `arodonata-cpcrud*`), re-verify the `DomainStamp` head before each pass and pre-`publish`, shield `discard` before `logout` on any `BaseException`, and invalidate domain caches post-`publish`.

#### Scenario: SCN-CPCRUD-010-1 — Stale plan abort when domain published after planning

- **GIVEN** a `Plan` recording a `DomainStamp` for a target domain
- **WHEN** `apply(plan, force=False)` or `stream_apply(plan, force=False)` runs on the initial pass, on any `retry_remaining` pass, or pre-`publish`
- **AND** the domain's `show-last-published-session` UID or `last_published_at` differs from `DomainStamp` (including `None -> published` or unreadable head)
- **THEN** `CPCRUDService` SHALL mark all remaining actions in that domain as `Outcome.PLAN_STALE`
- **AND** it SHALL discard any uncommitted write session if staleness is detected pre-`publish`
- **AND** it SHALL publish zero writes in that domain

#### Scenario: SCN-CPCRUD-010-2 — Forged or unlisted action command rejected before execution

- **GIVEN** a `Plan` containing a `PlannedAction` whose `(object_type, operation)` is outside the canonical CPCRUD command allowlist or whose `command` field disagrees with that allowlist
- **WHEN** `apply(plan)` or `stream_apply(plan)` is called
- **THEN** `CPCRUDService` SHALL raise `ValidationError` before opening a session or sending any Web API call

#### Scenario: SCN-CPCRUD-010-3 — Unhandled exception, cancellation, or publish failure discards uncommitted session before logout

- **GIVEN** an open domain write session during `apply()` or `stream_apply()` (unless `no_publish=True` and `keep_session=True` completed cleanly or recorded the staged session prior to error)
- **WHEN** an unhandled exception, `asyncio.CancelledError`, or `publish` transport/task failure occurs
- **THEN** `CPCRUDService` SHALL shield `discard` followed by `logout_sid` in `finally` so no uncommitted changes or object locks remain orphaned on the management server
- **AND** when `keep_session=True` is active, any opened staged session SHALL be recorded as soon as the session is created

#### Scenario: SCN-CPCRUD-010-4 — Post-publish domain cache invalidation and retry_remaining folding

- **GIVEN** `apply()` publishes changes in a domain or runs additional passes when `retry_remaining > 0`
- **WHEN** a domain `publish` succeeds or retry passes execute remaining failed actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called after `publish` so subsequent reads re-synchronize the domain
- **AND** each `retry_remaining` pass SHALL re-verify domain head freshness (never forcing `force=True` automatically) and fold its `ApplyReport` into the cumulative `ApplyReport`

### Requirement: Non-Disruptive Staged Session Retention, Adoption, Publish, and Discard

**ID**: REQ-CPCRUD-011\
**Intent**: Support external review and delayed commit/rollback of staged Web API sessions without disrupting SmartConsole or foreign administrator sessions.\
**Non-goals**: Immediate single-pass `apply()` publication (`REQ-CPCRUD-010`) or compensating template generation (`REQ-CPCRUD-012`).

`CPCRUDService` and `ArodonataClient` SHALL support `no_publish=True, keep_session=True` session staging (`arodonata-cpcrud-staged`) and `publish_staged_session`, `stream_publish_staged_session`, and `discard_staged_session` adoption only after `show-session` provenance verification, defaulting to non-disruptive `take-over-session` and disconnecting active sessions only under explicit `force_disconnect=True`.

#### Scenario: SCN-CPCRUD-011-1 — Keep-session staging mode preserves unpublished session for external workflow

- **GIVEN** an executable `Plan`
- **WHEN** `apply(plan, no_publish=True, keep_session=True)` or `stream_apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** `CPCRUDService` SHALL assign a default `arodonata-cpcrud-staged` session name when none was supplied
- **AND** it SHALL leave the dedicated write session open without publishing
- **AND** it SHALL record `StagedSessionInfo` (`sid`, `server_ip`, `session_uid`, `session_name`, `sid` redacted in `repr()`/logs) in `ApplyReport.staged_sessions` and the internal `Executor._staged_sessions` LRU registry (256 entries) upon creation
- **AND** `stream_apply()` SHALL emit a `StagedSessionEvent`

#### Scenario: SCN-CPCRUD-011-2 — Staged session publication adopts ownership via take-over-session and invalidates domain cache

- **GIVEN** a previously staged open Web API session identified by `session_uid`
- **WHEN** `await client.publish_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` or `client.stream_publish_staged_session(...)` is called
- **THEN** the service SHALL reuse a caller-supplied `sid` directly when `show-session {}` confirms `uid == session_uid` in an open state
- **AND** otherwise it SHALL open a dedicated `arodonata-cpcrud-adopt` helper session and read `show-session {}` (`initial_uid`, `current_user`)
- **AND** it SHALL verify via `show-session {"uid": session_uid}` that the target session is open and eligible (`keep_session=True` registry, `arodonata*` name, `expected_session_name`, or same-user `WEB_API` when `allow_foreign=False`)
- **AND** when adopting via helper session, it SHALL issue `take-over-session` (`{"uid": session_uid}`) omitting `disconnect-active-session` unless `force_disconnect=True`
- **AND** it SHALL fall back to `switch-session` only after provenance verification passes, reporting both errors if both fail
- **AND** it SHALL immediately discard the detached helper session via `discard {"uid": initial_uid}` so no empty helper session remains open
- **AND** it SHALL execute `publish` while polling task progress, log out cleanly, and call `client.invalidate_domain(mgmt_name, domain)`

#### Scenario: SCN-CPCRUD-011-3 — Staged session discard adopts ownership via take-over-session before discarding

- **GIVEN** an open or orphaned staged session identified by `session_uid`
- **WHEN** `await client.discard_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` is called
- **THEN** the service SHALL reuse an active matching `sid` when `show-session {}` confirms `uid == session_uid`, or verify open Web API / Arodonata provenance via an `arodonata-cpcrud-adopt` helper session
- **AND** when adopting via helper session, it SHALL issue non-disruptive `take-over-session` (`disconnect-active-session` omitted/`False` unless `force_disconnect=True`)
- **AND** it SHALL fall back to `switch-session` only after provenance verification passes, reporting both errors if both fail
- **AND** it SHALL discard the detached `arodonata-cpcrud-adopt` helper session via `discard {"uid": initial_uid}`
- **AND** it SHALL execute `discard` on the adopted session and log out cleanly

#### Scenario: SCN-CPCRUD-011-4 — Foreign, active SmartConsole, or already-finalized session UID refused during staged adoption

- **GIVEN** a `session_uid` belonging to a SmartConsole session, another user's Web API session (`allow_foreign=False`), a mismatched `expected_session_name`, an already published/discarded session, or an active session when `force_disconnect=False`
- **WHEN** `publish_staged_session`, `stream_publish_staged_session`, or `discard_staged_session` is called
- **THEN** the service SHALL refuse foreign, SmartConsole (`application` outside `""`/`"web_api"`/`"arodonata"`), or finalized sessions before issuing `take-over-session` or `switch-session`
- **AND** when `force_disconnect=False`, `take-over-session` SHALL omit `disconnect-active-session` so an active holder is never forcibly disconnected
- **AND** it SHALL log out any fresh helper session cleanly and return a failed `ApiCallResult` (or failure event)

### Requirement: Compensating Rollback Template Generation

**ID**: REQ-CPCRUD-012\
**Intent**: Build safe, schema-valid rollback templates that invert only confirmed mutations using concrete server UIDs and captured prior state.\
**Non-goals**: Executing the generated rollback template against Check Point (performed via a separate `plan()` and `apply()` run).

`CPCRUDService.inverse(plan, report)` (and `build_inverse_template()`) SHALL build a schema-valid compensating template from `Plan` and `ApplyReport`, inverting only actions that actually succeeded when `report` is supplied, targeting created objects by the concrete `uid` returned in `ApplyReport` (refusing unsafe delete-by-name for unexecuted `planned:` UIDs), and restoring all mutated fields present in `PlannedAction.prior_state`.

#### Scenario: SCN-CPCRUD-012-1 — Inverse template restores deleted and updated objects and removes created ones

- **GIVEN** a `Plan` and an `ApplyReport` from an apply pass where some actions succeeded and others failed or were skipped/stale
- **WHEN** `CPCRUDService.inverse(plan, report)` is called
- **THEN** it SHALL return a dictionary valid against `checkpoint_ops_schema.json` containing compensating operations ONLY for actions that succeeded in `report`
- **AND** it SHALL delete `CREATE` actions strictly by the concrete `uid` recorded in `report` (skipping any `CREATE` that lacks a real created UID)
- **AND** it SHALL restore all prior field values from `prior_state` for `UPDATE` actions and re-create `DELETE` actions from `prior_state`

### Requirement: Public CPCRUDService Options and Package Helper Exports

**ID**: REQ-CPCRUD-013\
**Intent**: Expose configurable conflict policies, naming overrides, schema path overrides, and pure helper primitives cleanly across `CPCRUDService` and `arodonata.cpcrud`.\
**Non-goals**: Internal multi-action plan execution semantics (`REQ-CPCRUD-010`, `REQ-CPCRUD-011`).

`CPCRUDService` SHALL support `schema_path=` on `validate()` and `on_name_conflict=`, `on_ip_conflict=`, `naming_prefixes=`, and `validate_schema=` on `plan()`, while `arodonata.cpcrud` SHALL export typed models (`Plan`, `PlannedAction`, `ApplyReport`, `ActionResult`, `StagedSessionInfo`, `NamingPrefixes`), enums (`Outcome`, conflict policies), and pure helper primitives.

#### Scenario: SCN-CPCRUD-013-1 — CPCRUDService.validate and plan accept explicit schema, policy, and naming overrides

- **WHEN** callers invoke `CPCRUDService.validate(template, schema_path=...)` and `CPCRUDService.plan(template, on_name_conflict=..., on_ip_conflict=..., naming_prefixes=..., validate_schema=False)`
- **THEN** `validate()` SHALL validate against the explicit `schema_path` offline
- **AND** `plan()` SHALL honor the per-call conflict policies, naming prefixes, and `validate_schema` toggle

### Requirement: Per-Rulebase Track Wire Encoding, Fail-Closed Defaults, and Validation Parity

**ID**: REQ-CPCRUD-014\
**Intent**: Ensure CPCRUD schema validation, planning, and rollback match Check Point Web API wire formats, fail-closed rule defaults, and anti-widening invariants across all rulebase types.\
**Non-goals**: Base shorthand expression parsing (`REQ-CPCRUD-002`) or rule list-cell patch syntax (`REQ-CPCRUD-009`).

`CPCRUDService` SHALL encode `track` as a settings object (`{"type": ...}`) for `access` rules and a plain string for `https`/`threat` rules, default omitted rule actions fail-closed (`"Drop"` for `access`, `"Inspect"` for `https`, `"Optimized"` for `threat`), reject empty list replacements (`[]`, `""`, `[""]`) and `default_any` coercion on `install-on`, and infer omitted `type` with `operation > state > action` precedence and `check_where_used` schema support during `validate()`.

#### Scenario: SCN-CPCRUD-014-1 — Access vs HTTPS/Threat track wire encoding and sub-field diffs

- **GIVEN** an existing `access`, `https`, or `threat` rule in Check Point
- **WHEN** `CPCRUDService.plan()` and `execute()` create, update, or roll back rules with `track` settings (including `accounting`, `per-session`, `per-connection`, `alert`, or `enable-firewall-session` on `access` rules)
- **THEN** `access` rule payloads SHALL encode `track` as a `TrackSettingsForRequest` object and detect sub-field diffs while `https` and `threat` payloads SHALL encode `track` as a plain string
- **AND** compensating rollback templates SHALL preserve the prior `track` object or string wire representation

#### Scenario: SCN-CPCRUD-014-2 — Fail-closed rule defaults, install-on anti-Any guard, and empty-list rejection

- **GIVEN** a CPCRUD rule operation omitting `rule_action`/`action`, omitting `install-on`, or attempting an empty list replacement (`[]`, `""`, `[""]`)
- **WHEN** `CPCRUDService.validate()` or `plan()` evaluates the rule operation
- **THEN** omitted rule actions SHALL resolve fail-closed to `"Drop"` (`access`), `"Inspect"` (`https`), or `"Optimized"` (`threat`) identically across planning and unnamed-rule traffic matching
- **AND** `install-on` SHALL NOT default to `"Any"`, empty list replacements SHALL fail with `ValidationError` / `DiffSafetyError`, and `is_cleanup_rule` SHALL require `Any`/`Any`/`Any` traffic even when `"cleanup"` appears in the rule name

#### Scenario: SCN-CPCRUD-014-3 — Offline validation parity, multi-target state continuity, and NAT/resolved-object parity

- **GIVEN** a multi-target CPCRUD template with omitted `type` on rules/groups, `check_where_used: true`, or NAT/access rules carrying `_resolved_objects`
- **WHEN** `CPCRUDService.validate()` and `plan()` execute across multiple targets referencing the same domain
- **THEN** `validate()` SHALL infer default types, apply `operation > state > action` precedence, and accept `check_where_used`
- **AND** `plan()` SHALL preserve failure propagation, name resolutions, and `depends_on` edges across targets on the same domain while passing resolved object dictionaries to NAT and traffic-tuple helpers

### Requirement: Hardened Staged Session Lifecycle, Provenance, and Placeholder-Free Rollback

**ID**: REQ-CPCRUD-015\
**Intent**: Prevent dedicated session leaks, stale staged publishes, synthetic UID leaks in rollback templates, and dead provenance checks in staged CPCRUD workflows.\
**Non-goals**: Base staged session registry persistence (`REQ-CPCRUD-011`) or compensating rollback ordering (`REQ-CPCRUD-012`).

`CPCRUDService` SHALL shield staged-session `logout_sid` cleanup under cancellation and `ServerIdentityError`, verify domain-head freshness before publishing staged sessions, align `arodonata*` session provenance checks with `REQ-CPCRUD-011`, strip synthetic `planned:` UIDs from rollback `UPDATE` operations, and restore parent-group memberships and `service-group` rollbacks accurately.

#### Scenario: SCN-CPCRUD-015-1 — Staged session cleanup shields cancellation and verifies head staleness before publish

- **GIVEN** an active or adopted staged `CPCRUDService` session (`publish_staged_session`, `discard_staged_session`, or `execute(..., keep_session=True)`)
- **WHEN** `asyncio.CancelledError` or `ServerIdentityError` interrupts registration, adoption, publish, or discard, OR the domain published head changed since staging
- **THEN** temporary/owned sessions SHALL be logged out via shielded `logout_sid` cleanup without leaking open Check Point sessions
- **AND** `publish_staged_session` SHALL reject stale domain heads when `allow_stale=False` and enforce consistent `arodonata*` provenance rules

#### Scenario: SCN-CPCRUD-015-2 — Rollback templates strip synthetic planned UIDs and invert group/service-group mutations

- **GIVEN** a CPCRUD plan that creates and subsequently updates an entity in the same run (`planned:<type>:<name>`), modifies group memberships, or modifies a `service-group`
- **WHEN** `CPCRUDService.inverse()` generates a compensating rollback template
- **THEN** rollback `UPDATE` operations SHALL omit synthetic `planned:` UIDs rather than emitting placeholder identifiers
- **AND** group and `service-group` rollbacks SHALL restore prior parent-group memberships and route `service-group` inversions to the group inverter

### Requirement: Unified CPCRUD State-Reader Lookups, Single-Pass Planning, and Split Differ/Executor/Inverse Helpers

**ID**: REQ-CPCRUD-016\
**Intent**: Eliminate behavioral drift across mirrored CPCRUD object/service lookup mixins, duplicated staged-session finalizers, repeated inverse helpers, duplicated step collection, and high-branching diff functions.\
**Non-goals**: Base CPCRUD expression evaluation (`REQ-CPCRUD-002`) or staged session registry persistence (`REQ-CPCRUD-011`).

`HybridStateReader` SHALL consolidate cache/overlay/live lookup helpers in `_HybridStateReaderBase` (with exact service-name checks), `Planner.decide` SHALL cache target steps in `_DomainPlanState`, `differ.py` SHALL delegate to per-type diff helpers, and `Executor`/`inverse.py` SHALL share staged-session and prior-field helpers.

#### Scenario: SCN-CPCRUD-016-1 — Unified state reader enforces exact service name match and shared staged/inverse helpers preserve semantics

- **GIVEN** a `HybridStateReader` service lookup where cache returns a mismatched service name, an adopted staged session interrupted by error or cancellation, or an inverse rollback over prior fields
- **WHEN** `get_service_by_name()`, `stream_publish_staged_session()`, `discard_staged_session()`, or `CPCRUDService.inverse()` executes
- **THEN** `get_service_by_name()` SHALL reject mismatched service names identically to `get_object_by_name()`
- **AND** adopted staged operations SHALL shield `logout_sid` cleanup through one shared runner, and `inverse()` SHALL copy prior fields uniformly via shared helpers

#### Scenario: SCN-CPCRUD-016-2 — Single-pass planner step collection and split object/rule differs maintain exact plan parity

- **GIVEN** a multi-target CPCRUD template modifying hosts, networks, ranges, application sites, NAT rules, and policy rules
- **WHEN** `Planner.decide()`, `compute_object_diff()`, and `compute_rule_diff()` compute actions
- **THEN** `_collect_ordered_steps` SHALL be evaluated at most once per target during `Planner.decide()` with per-domain state stored in `_DomainPlanState`
- **AND** per-type object and rule diff helpers SHALL produce identical actions and field diffs across every entity and rulebase type

### Requirement: Fail-Closed Staged Publishing, Active Where-Used Enforcement, Empty-List Inverse Rollback, and Unified Entity Planning

**ID**: REQ-CPCRUD-017\
**Intent**: Prevent stale staged publishes after LRU eviction or restart, enforce `check_where_used` across all entity deletions, restore newly added groups/tags on rollback, and honor `check_domain_head` consistently.\
**Non-goals**: Base CPCRUD shorthand parsing (`REQ-CPCRUD-002`) or HMAC MCP plan signing (`REQ-MCP-009`).

`Executor` SHALL fail closed on `publish_staged_session(..., allow_stale=False)` when no verified baseline stamp is present, honor `check_domain_head` across all passes, enforce non-empty `check_where_used` usage across objects, services, and groups via unified entity planning, and emit `groups: []` / `tags: []` in `inverse()` when newly added.

#### Scenario: SCN-CPCRUD-017-1 — Fail-closed allow_stale=False staged publishing and consistent check_domain_head dispatch

- **GIVEN** a staged session whose entry was evicted from `Executor._staged_sessions` or adopted post-restart, or an `Executor(check_domain_head=custom_cb)` instance
- **WHEN** `stream_publish_staged_session(..., allow_stale=False)` runs without an explicit baseline stamp, or `apply()` / `stream_apply()` runs retry passes
- **THEN** `stream_publish_staged_session` SHALL fail closed when no verified baseline stamp is available (while accepting explicit baseline stamps forwarded from `stored_staged`)
- **AND** `apply()` and `stream_apply()` SHALL invoke `check_domain_head` consistently across all domain-head verification paths

#### Scenario: SCN-CPCRUD-017-2 — check_where_used blocks referenced objects, services, and groups via unified entity planner

- **GIVEN** a CPCRUD `delete` step with `check_where_used: true` on an object (`host`), service (`service-tcp`), `group`, or `service-group` that has active `used-directly`/`used-indirectly` references outside deleted plan entities
- **WHEN** `CPCRUDService.plan()` executes via the consolidated entity planner
- **THEN** `plan()` SHALL emit `Outcome.ERROR` and block deletion rather than discarding `where-used` usage data

#### Scenario: SCN-CPCRUD-017-3 — inverse() restores empty groups and tags on previously ungrouped/untagged entities

- **GIVEN** an existing host, service, `group`, or `service-group` with `groups=[]` and `tags=[]` that was updated to add parent `groups` or `tags`
- **WHEN** `CPCRUDService.inverse(plan, report)` generates a compensating rollback template
- **THEN** the rollback `set-*` operations SHALL emit `groups: []` and `tags: []` whenever those fields were mutated from empty prior state

### Requirement: Strict Operation IDs, Virtual Rule Overlay Integrity, Protocol Zero Fidelity, and Concurrent/Owner-Fair Execution

**ID**: REQ-CPCRUD-018\
**Intent**: Reject blank or duplicate template IDs via unified verb normalization, prevent intra-plan virtual rule traffic collisions, preserve `ip_protocol=0` and access inline layers, restore empty description/additional-categories fields, and make concurrent executor/registry state race-free and owner-fair.\
**Non-goals**: Staged baseline verification (`REQ-CPCRUD-017`) or schema path settings (`REQ-CONFIG-009`).

CPCRUD SHALL reject blank/duplicate IDs via shared verb parsing, preserve `ip_protocol=0`, dereference `AccessRuleEntry` inline layers, isolate planned virtual rule traffic matching, restore empty `description`/`additional-categories` on rolling back `UPDATE`s, return per-call `ApplyReport`s, and evict staged sessions owner-fairly.

#### Scenario: SCN-CPCRUD-018-1 — Non-blank unique operation IDs, intra-plan virtual rule overlays, IP protocol zero, inline-layer deref, and empty-field inverse rollback

- **GIVEN** templates with blank or duplicate `id` fields, virtual rules created then chained in one plan (`explicit id` or distinct-named bottom rules), a service with `ip_protocol=0` (`HOPOPT`), an `AccessRuleEntry` with `inline-layer`, or an `UPDATE` adding `description`/`additional-categories` from empty prior state
- **WHEN** validation, planning, diffing, or `inverse()` runs
- **THEN** validator and planner SHALL reject blank/duplicate IDs via shared verb normalization, planner SHALL update virtual rule overlays without colliding differently named rules across traffic tuples, differ SHALL preserve `0` protocols and access inline layers, and inverse SHALL emit empty `""`/`[]` restoration values

#### Scenario: SCN-CPCRUD-018-2 — Race-free concurrent Executor.apply reports and owner-fair staged session registry eviction

- **GIVEN** concurrent `Executor.apply()` coroutines on one `Executor` instance, or a full 256-entry staged session registry holding single-session peers alongside a greedy multi-session owner
- **WHEN** concurrent applies execute or a new owner stages a 257th session
- **THEN** each `Executor.apply()` call SHALL return its own isolated `ApplyReport` from the completion event without shared-attribute races, and staged registry eviction SHALL discard the new or greedy multi-session owner's oldest SID while preserving single-session peers


---

### OpenSpec Capability: `gateway-topology` (`openspec/specs/gateway-topology/spec.md`)

# Gateway Topology and Candidate Matching Specification

## Purpose

Defines Check Point gateway interface topology extraction (`TopologyService`), static and live CLI route resolution into `arodonata_gateway_topology`, health diagnostics and live-route reconciliation (`get_topology_diagnostics`, `reconcile_gateway_topology`), persistent administrator annotations (`arodonata_topology_annotations`), delta-based confidence scoring, and affected gateway / policy package candidate matching (`find_affected_gateways`) across simple gateways, clusters, and VSX Virtual Systems.

## Requirements

### Requirement: Extensible Multi-Source Topology Schema

**ID**: REQ-TOPO-001\
**Intent**: Allow static API definitions, VPN domains, live CLI routes, and manual prefixes to coexist safely without clobbering unrelated sources on refresh.\
**Non-goals**: Extracting individual interface or route sources (`REQ-TOPO-003`..`REQ-TOPO-007`).

Each persisted `GatewayTopologyEntry` in `arodonata_gateway_topology` SHALL carry a `source_type` discriminator (covering static API definitions, VPN encryption domains, live CLI routes, and manual entries) and `anti_spoofing_mode` metadata so distinct topology sources coexist without overwriting unrelated categories during refresh.

#### Scenario: SCN-TOPO-001-1 — Multiple topology sources coexist per gateway interface

- **GIVEN** an interface storing static intervals (`"interface_connected"`, `"interface_specific"`, `"external_interface"`), `"vpn_domain"`, `"vs_static_route"`, or `"manual"` entries
- **AND** CLI-collected route intervals (`"connected_route"`, `"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, `"ospf_route"`)
- **WHEN** `refresh_topology(collect_routes=False)` refreshes static topology
- **THEN** `arodonata_gateway_topology` SHALL preserve and query all intervals for `(gateway_uid, interface_name)` with each interval's `source_type`, `source_ref`, and `anti_spoofing_mode`
- **AND** existing CLI-collected route and `"manual"` entries SHALL remain intact

### Requirement: Policy-Enforcing Gateway Target Selection

**ID**: REQ-TOPO-002\
**Intent**: Index topology strictly for policy-enforcing gateways, clusters, and Virtual Systems rather than cluster members or physical VSX hosts.\
**Non-goals**: Routing CLI target expansion to cluster members and VSX hosts (`REQ-TOPO-007`).

`TopologyService` SHALL index topology only for policy-enforcing gateway assets (`simple-gateway`, `simple-cluster`, `CpmiGatewayCluster`, `virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`), skipping cluster members (`cluster-member`, `CpmiClusterMember`, `CpmiVsxClusterMember`), physical VSX hosts (`vsx-gateway`, `vsx-cluster`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`), and management servers (`checkpoint-host`, `mds`).

#### Scenario: SCN-TOPO-002-1 — Cluster topology is derived from the cluster object while members and VSX hosts are skipped

- **GIVEN** a domain containing a `CpmiGatewayCluster`, its `cluster-member` nodes, a `CpmiVsxNetobj` physical host (`VS0`), and a `CpmiVsNetobj` Virtual System
- **WHEN** `refresh_topology` processes the domain
- **THEN** `TopologyService` SHALL build topology entries only for the `CpmiGatewayCluster` and the `CpmiVsNetobj` Virtual System
- **AND** it SHALL emit zero topology rows for `cluster-member` or `CpmiVsxNetobj` assets

### Requirement: Static Interface Topology Extraction and Detail Fallback

**ID**: REQ-TOPO-003\
**Intent**: Extract normalized IPv4 intervals and Anti-Spoofing modes from Check Point gateway interface definitions with on-demand detail fallback.\
**Non-goals**: Specific-group object resolution without bulk scans (`REQ-TOPO-004`) or VPN domain expansion (`REQ-TOPO-005`).

`TopologyService` SHALL normalize interface definitions across `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, and `show-generic-object` payloads, extracting Anti-Spoofing (`"prevent"`, `"detect"`, `"off"`, `"unknown"`), connected subnets (`"network defined by the interface ip and net mask"`), `"external"` interfaces (`leads-to-internet: true`), and logging a warning on unresolvable route-based or undefined interfaces.

#### Scenario: SCN-TOPO-003-1 — Connected subnet and specific group behind interfaces expand into IPv4 intervals

- **GIVEN** a gateway with `eth0` (`leads-to-internet: true`) and `eth1` (`10.10.1.1/24`, `"network defined by the interface ip and net mask"`)
- **AND** `eth2` configured with `"specific"` group `"G_App_Subnets"` (`10.20.1.5`, `10.20.2.0/24`, nested `10.20.3.10-10.20.3.20`) and Anti-Spoofing `"prevent"`
- **WHEN** `TopologyService` extracts interface topology
- **THEN** it SHALL persist `"external"` (`source_type="external_interface"`, `0.0.0.0/0`) for `eth0` and `10.10.1.0/24` (`source_type="interface_connected"`) for `eth1`
- **AND** it SHALL persist three expanded intervals (`10.20.1.5/32`, `10.20.2.0/24`, `10.20.3.10-10.20.3.20`) with `source_type="interface_specific"` and `anti_spoofing_mode="prevent"` for `eth2`

#### Scenario: SCN-TOPO-003-2 — Interface with routing-defined or undefined topology logs a warning and is skipped

- **WHEN** a non-external gateway interface has `ip-address-behind-this-interface` set to `"network defined by routing"` (without static route records) or `"not defined"`
- **THEN** `TopologyService` SHALL emit a structured warning log identifying the gateway, domain, interface name, and topology setting
- **AND** it SHALL skip static interval creation for that interface

#### Scenario: SCN-TOPO-003-3 — On-demand detail fallback when gateway summary lacks interface topology

- **GIVEN** a policy-enforcing gateway or cluster in `arodonata_assets` whose `show-gateways-and-servers` summary lacks `interfaces` or topology settings
- **WHEN** `TopologyService` extracts topology for that asset
- **THEN** it SHALL query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` (`details-level="full"`) for that UID before extracting intervals

### Requirement: On-Demand Specific Group Expansion Without Bulk Object Scans

**ID**: REQ-TOPO-004\
**Intent**: Keep cold topology refreshes fast in large domains by resolving referenced groups and objects on demand without downloading all hosts.\
**Non-goals**: Full domain object cache synchronization (`REQ-CACHE-005`).

`TopologyService` SHALL recursively resolve `"specific"` network and group objects behind gateway interfaces across the domain and `"Global"` using fresh cached objects or targeted single-object/group API lookups, without triggering bulk default-object-type refreshes (`show-hosts`, `show-dns-domains`) or falsely stamping whole-domain object slices as synced.

#### Scenario: SCN-TOPO-004-1 — Cold topology refresh resolves specific and VPN domain references on demand without bulk show-hosts

- **GIVEN** a cold database on domains holding thousands of `host` and `dns-domain` objects where gateways reference a `"specific"` or `vpn-domain` group `"G_App_Subnets"`
- **WHEN** `refresh_topology` or `stream_refresh_topology` runs
- **THEN** it SHALL synchronize gateway assets and resolve `"G_App_Subnets"` and transitive member UIDs via targeted object/group lookups
- **AND** it SHALL persist resolved objects without marking whole-domain `"host"` or `"group"` slices as fully synced
- **AND** it SHALL execute zero full-domain `show-hosts` or `show-dns-domains` paginated queries

### Requirement: VPN Encryption Domain Topology Extraction

**ID**: REQ-TOPO-005\
**Intent**: Include Check Point gateway VPN encryption domains in topology intervals and candidate confidence scoring.\
**Non-goals**: Specific interface behind-IP topology (`REQ-TOPO-003`) or evidence-delta weights (`REQ-TOPO-013`).

During topology extraction, the system SHALL extract each policy-enforcing gateway or cluster `vpn-domain` (`encryption-domain`) reference, recursively expand the referenced network or group object from cached domain and `"Global"` objects into IPv4 intervals with `source_type="vpn_domain"`, and apply the `vpn_encryption_domain` confidence delta when matching endpoints against those intervals.

#### Scenario: SCN-TOPO-005-1 — Gateway encryption domain group expands into vpn_domain intervals and contributes vpn_encryption_domain confidence

- **GIVEN** a gateway or cluster whose `vpn-domain` (`encryption-domain`) references group `"G_VPN_Encryption_Domain"` (`10.77.1.0/24`, `10.77.2.0/24`)
- **WHEN** `refresh_topology` extracts topology and `find_affected_gateways` matches an endpoint in `10.77.1.0/24`
- **THEN** `arodonata_gateway_topology` SHALL persist `10.77.1.0/24` and `10.77.2.0/24` with `source_type="vpn_domain"`
- **AND** `confidence_factors` on the match SHALL include the `vpn_encryption_domain` (`+0.45`) delta

### Requirement: VSX Virtual System Static Route Topology Resolution

**ID**: REQ-TOPO-006\
**Intent**: Map Check Point Management API VSX static routes onto the corresponding Virtual System interface intervals.\
**Non-goals**: VSX slot relationship linking (`REQ-CACHE-010`) or live CLI route collection (`REQ-TOPO-007`).

For VSX Virtual Systems (`virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`), `TopologyService` SHALL extract static routes from Check Point Management API generic objects (`CpmiVsSlotObj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj` via `routes`, `routes_installed`, or `routing_table`) and associate each routed destination network with the corresponding VS interface (`source_type="vs_static_route"`).

#### Scenario: SCN-TOPO-006-1 — VS static route next-hop IP resolves to the matching VS connected interface

- **GIVEN** a Virtual System with `wrp128` (`192.168.100.2/30`), `eth1.50` (`10.50.0.1/24`), static route `172.16.80.0/24` via `10.50.0.254`, and default route `0.0.0.0/0` via `192.168.100.1`
- **WHEN** `TopologyService` resolves VS static routes
- **THEN** it SHALL bind `172.16.80.0/24` to `eth1.50` with `source_type="vs_static_route"` and `topology_zone="internal"`
- **AND** it SHALL mark `wrp128` as an `"external"` interface (`source_type="vs_static_route"`, `0.0.0.0/0`)

### Requirement: Live Gateway Route Collection via SSH Dependency Injection and CPRID Fallback

**ID**: REQ-TOPO-007\
**Intent**: Collect live gateway routing tables safely via injected SSH or `cprid` fallback with VSX context checks and route-scale protection.\
**Non-goals**: CPRID script mode selection (`REQ-TOPO-008`) or targeted gateway filtering (`REQ-TOPO-009`).

`TopologyService.collect_gateway_routes()` SHALL collect live IPv4 routing tables (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`, and `0.0.0.0/0` default routes) via an injected `GatewayCliPort` (or async SSH bash callback) first, falling back to Management API `run-script` (`cprid` with `show-task` polling) when absent or failing under `fallback_to_cprid=True`.

#### Scenario: SCN-TOPO-007-1 — Cluster and VSX Virtual System route collection via SSH DI and vsenv context switching

- **WHEN** `collect_gateway_routes()` runs for a `CpmiGatewayCluster` (two `cluster-member` nodes) and a VSX `CpmiVsNetobj` (`vsid=3` on `VSX-GW-01`)
- **THEN** it SHALL resolve the cluster to its `cluster-member` targets and the Virtual System to `VSX-GW-01` (`vsid=3`)
- **AND** the executed script SHALL switch context via `vsenv "$vsid" >/dev/null 2>&1 </dev/null`, verify `$FWDIR` contains `CTX00003`, and run `ip -4 route show </dev/null`
- **AND** parsed route intervals SHALL be persisted in `arodonata_gateway_topology`

#### Scenario: SCN-TOPO-007-2 — Automatic fallback from SSH callback to Management API run-script

- **GIVEN** an injected SSH `gateway_cli` callback that raises a connection error for a remote gateway while `fallback_to_cprid=True`
- **WHEN** `collect_gateway_routes()` runs
- **THEN** `TopologyService` SHALL run the route collection script via Management API `run-script`, poll `show-task`, Base64-decode `task-details[].responseMessage`, and parse the routes

#### Scenario: SCN-TOPO-007-3 — Per-physical-node VSX serialization, MDS concurrency cap, and single-flight route collection

- **WHEN** `collect_gateway_routes()` runs across multiple Virtual Systems sharing `VS0` alongside independent gateways, or when identical calls overlap concurrently
- **THEN** CLI/`cprid` execution SHALL be serialized per physical `node_uid` on `VS0` without blocking independent gateways up to `route_collect_concurrency`
- **AND** identical concurrent calls SHALL coalesce into a single in-flight collection

#### Scenario: SCN-TOPO-007-4 — Large routing table cap and clish bypass protect gateways holding BGP full-view tables

- **WHEN** `collect_gateway_routes()` runs on a gateway exceeding `max_routes_per_gateway` (or `10000` kernel routes for `clish`)
- **THEN** the collection script SHALL skip `clish -c "show route"` when kernel routes exceed `10000` lines
- **AND** collected routes SHALL be truncated at `max_routes_per_gateway` with a warning recorded in `GatewayRouteCollectionStatus.warnings`

### Requirement: CPRID Script Execution Modes for Route Collection

**ID**: REQ-TOPO-008\
**Intent**: Support pre-approved repository scripts, inline scripts, and automatic fallback when collecting gateway routes via `run-script`.\
**Non-goals**: General-purpose application repository scripts (`REQ-CLIENT-012`) or `ArodonataSettings` validation (`REQ-CONFIG-005`).

`collect_gateway_routes()`, `refresh_topology()`, `stream_refresh_topology()`, and `reconcile_gateway_topology()` SHALL honor `cprid_script_mode` (`"inline" | "repository" | "auto"`), `repository_script_name`, and `repository_script_args_fn` overrides, defaulting `"repository"` mode to zero-argument canonical execution with self-detecting multi-VS VSX bundling and per-node coalescing.

#### Scenario: SCN-TOPO-008-1 — Repository mode executes canonical pre-approved script across standalone, cluster, and VSX gateways

- **GIVEN** an account holding `run-repository-script` without `run-one-time-script`
- **WHEN** `collect_gateway_routes(..., cprid_script_mode="repository")` runs across standalone, cluster, and VSX (`vsid=3`, `vs_name="VS_DMZ"`) targets with `repository_script_args_fn=None`
- **THEN** `TopologyService` SHALL send `run-script` with `script-type="repository"`, `script-name=settings.cprid_repository_script_name`, and omitted `"args"` (plus zero `"script"`/`"script-base64"` fields) so least-privilege repository profiles succeed without `"Insufficient permissions to run this script with arguments."`
- **AND** it SHALL parse Gaia/Clish/VSX route markers identically to inline mode, or fail closed with `error_code="repository_script_not_found"` or `"repository_script_permission_denied"`

#### Scenario: SCN-TOPO-008-2 — Host application overrides repository script name and positional arguments builder

- **WHEN** `collect_gateway_routes(..., cprid_script_mode="repository", repository_script_name="corp-routes-v2", repository_script_args_fn=custom_fn)` runs
- **THEN** `TopologyService` SHALL invoke `"corp-routes-v2"` with `"script-type": "repository"` and pass `custom_fn(target, max_routes)` as `"args"`

#### Scenario: SCN-TOPO-008-3 — Auto mode falls back per domain on missing repository script while preserving strict repository errors

- **GIVEN** `"DomainA"` having `arodonata-collect-routes-v1` and `"DomainB"` lacking it
- **WHEN** `collect_gateway_routes(..., cprid_script_mode="auto")` runs vs `cprid_script_mode="repository"`
- **THEN** in `"auto"` mode, `"DomainA"` SHALL use `"script-type": "repository"` and `"DomainB"` SHALL fall back per domain to inline `"one time"` execution (cached per flight)
- **AND** in `"repository"` mode, `"DomainB"` SHALL fail with `error_code="repository_script_not_found"` without sending an inline script

#### Scenario: SCN-TOPO-008-4 — Zero-argument VSX self-detection bundle coalesces per physical VSX node and isolates per-VS errors

- **GIVEN** a VSX gateway or cluster hosting multiple L3 Virtual Systems (and optionally an L2 Virtual Switch or a failing VS context) collected in `"repository"` mode with `repository_script_args_fn=None`
- **WHEN** the canonical zero-argument route-collection script runs once per physical VSX node
- **THEN** the script SHALL auto-detect VSX via `vsx stat -l </dev/null`, iterate L3 Virtual Systems/Virtual Routers (`VSID > 0`, skipping Virtual Switches) with `vsenv` and `CTX%05d` verification, isolate single-VS errors via `===ARODONATA_VS_ERROR ...===`, and emit `===ARODONATA_VSX_BUNDLE_START===` / `===ARODONATA_VS_START vsid=<id> name=<name>===` ... `===ARODONATA_VS_END===` / `===ARODONATA_VSX_BUNDLE_END===`
- **AND** `collect_gateway_routes()` SHALL coalesce sibling Virtual Systems sharing `(mgmt_name, domain_name, node_key)` onto one `run-script` call per physical node per run, extract each VS slice by `vsid` (or `vs_name` fallback), enforce `max_routes_per_gateway`, and preserve backward-compatible single-context execution when explicit positional arguments are supplied

### Requirement: Targeted Per-Gateway Topology and Route Refresh

**ID**: REQ-TOPO-009\
**Intent**: Allow incremental refresh of a single modified gateway without re-querying or deleting untouched gateways in large domains.\
**Non-goals**: Whole-domain topology sync-state stamping (`REQ-CACHE-011`).

`TopologyService.refresh_topology()` and `TopologyService.collect_gateway_routes()` SHALL accept an optional `gateways: Sequence[str] | None` filter (matching gateway UID, name, `id`, or `asset_id`) that refreshes and replaces cached topology and route intervals strictly for the specified gateways without re-querying or deleting cached topology rows for other gateways in the domain.

#### Scenario: SCN-TOPO-009-1 — Refreshing a single modified gateway in a large domain preserves other gateways

- **WHEN** `refresh_topology(mgmt_name="mds1", domains=["Corp"], gateways=["gw-branch-42"], collect_routes=True, mode="force")` runs
- **THEN** `TopologyService` SHALL query Management API gateway details and collect live routes ONLY for `"gw-branch-42"`
- **AND** it SHALL atomically replace only `"gw-branch-42"` rows in `arodonata_gateway_topology` while leaving all other gateways in `"Corp"` untouched

### Requirement: Persistent Administrator Topology Annotations and IPAM Prefix Export

**ID**: REQ-TOPO-010\
**Intent**: Preserve operator overrides and IPAM metadata across topology refreshes and allow exporting the annotated prefix inventory.\
**Non-goals**: Confidence delta scoring formulas (`REQ-TOPO-013`).

The cache layer SHALL persist `TopologyAnnotation` records in `arodonata_topology_annotations` across topology refreshes, supporting gateway/interface `trust_static_topology` overrides, prefix dispositions (`"confirmed"`, `"standby_dynamic"`, `"ignore"`, `"manual"`), and IPAM fields (`zone`, `site`, `comment`, `custom_metadata`), while `TopologyService.export_topology_prefixes()` exports the annotated prefix inventory.

#### Scenario: SCN-TOPO-010-1 — Annotations survive topology refresh and enrich IPAM prefix export

- **GIVEN** a `TopologyAnnotation` marking `10.90.0.0/24` on `gw1:eth1` as `disposition="standby_dynamic"`, `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and `10.99.0.0/24` as `disposition="ignore"`
- **WHEN** `refresh_topology(mode="force")` and `export_topology_prefixes()` execute
- **THEN** both annotations SHALL survive `refresh_topology` intact and `10.99.0.0/24` SHALL be excluded from active candidate matching
- **AND** `export_topology_prefixes()` SHALL include `10.90.0.0/24` with `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and `disposition="standby_dynamic"`

### Requirement: Affected Gateway LPM Candidate Matching and Exclusion

**ID**: REQ-TOPO-011\
**Intent**: Identify gateways whose interfaces traverse source-to-destination traffic via LPM while eliminating same-interface and external-only false positives.\
**Non-goals**: Package metadata attachment (`REQ-TOPO-012`) or policy-rule inference (`REQ-TOPO-014`).

`TopologyService.find_affected_gateways()` SHALL match `sources` and `destinations` against internal intervals first (longest-prefix match) and external interfaces second (`0.0.0.0/0`), excluding any gateway where pairs share one interface (`src_interface == dst_interface`), both hit `external`, or confidence falls below `min_confidence`.

#### Scenario: SCN-TOPO-011-1 — Traffic between two internal interfaces or between internal and external interfaces matches

- **GIVEN** Gateway A (`10.10.1.0/24` on `eth1`, `external` on `eth0`, `"Perimeter_Pkg"` in `"Corp"`) and Gateway C (`192.168.1.0/24` on `eth1`, `external` on `eth0`)
- **AND** Gateway B (`10.10.1.0/24` on `bond0.10`, `8.8.8.0/24` on `bond0.20`, `"Core_Pkg"` in `"DC"`)
- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["8.8.8.8"])` runs
- **THEN** it SHALL return Gateway B (`match_type="internal_to_internal"`, `bond0.10 -> bond0.20`, domain `"DC"`, package `"Core_Pkg"`)
- **AND** it SHALL return Gateway A (`match_type="internal_to_external"`, `eth1 -> eth0`, domain `"Corp"`, package `"Perimeter_Pkg"`) with `matched_sources=["10.10.1.25"]` and `matched_destinations=["8.8.8.8"]`
- **AND** it SHALL exclude Gateway C because both endpoints fall back to Gateway C's `eth0` (`external == external`)

#### Scenario: SCN-TOPO-011-2 — Traffic where both source and destination sit behind the same internal interface is excluded

- **WHEN** `find_affected_gateways(sources=["10.10.1.10"], destinations=["10.10.1.99"])` runs against a gateway where both addresses match `10.10.1.0/24` on `eth1`
- **THEN** that gateway SHALL be excluded because `src_interface == dst_interface == "eth1"`

### Requirement: Affected Gateway Candidate Package Enrichment, Source Filtering, and Input Ordering

**ID**: REQ-TOPO-012\
**Intent**: Give callers deterministic input-ordered flow matches, linked policy packages/layers, and control over evaluated interval sources.\
**Non-goals**: LPM exclusion logic (`REQ-TOPO-011`) or confidence-delta math (`REQ-TOPO-013`).

`TopologyService.find_affected_gateways()` SHALL honor `source_types` and `include_annotations` filters, attach domain, `installed_access_policy`, `policy_packages`, `access_layers`, and `matched_flows`, and populate `matched_sources` and `matched_destinations` per gateway in the caller's input order.

#### Scenario: SCN-TOPO-012-1 — Multi-gateway and transit topology filters matched_sources and matched_destinations per gateway in input order

- **GIVEN** multiple `sources` and `destinations` traversing a 4-gateway topology including `GW3` acting as a multi-interface transit gateway and `GW4` behind `GW3`
- **WHEN** `find_affected_gateways(sources, destinations)` runs
- **THEN** each returned `AffectedGatewayCandidate` SHALL list only the unique `source_query` and `destination_query` strings from its cross-interface `matched_flows` in exact caller input order
- **AND** any gateway where all pairs resolve to `src_interface == dst_interface` or `external == external` SHALL be excluded

#### Scenario: SCN-TOPO-012-2 — Policy package resolution combines asset policy metadata and rulebase installation targets

- **GIVEN** an affected gateway with `raw_data["policy"]["access-policy-name"] = "Standard_Policy"` or an entry in cached `PolicyPackageInfo.raw_data["installation-targets"]`
- **WHEN** `find_affected_gateways()` builds the candidate
- **THEN** it SHALL populate `installed_access_policy` and `policy_packages=[installed_policy]` (assigning the single active installed policy) alongside ordered `access_layers` when cached

#### Scenario: SCN-TOPO-012-3 — Static-only source_types and disabled annotations filter out live route and manual intervals

- **GIVEN** a cache containing static interface intervals, live `bgp_route` entries, and `manual` annotations
- **WHEN** `find_affected_gateways(sources, destinations, source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)` runs
- **THEN** matching SHALL evaluate strictly intervals matching `source_types` and ignore `TopologyAnnotation` overrides without mutating cached rows

### Requirement: Extensible Evidence Delta Confidence Scoring

**ID**: REQ-TOPO-013\
**Intent**: Quantify path reliability transparently using configurable signed evidence deltas and conflict penalties.\
**Non-goals**: Policy rule inference evidence (`REQ-TOPO-014`).

`TopologyService` SHALL compute endpoint and flow confidence in `[0.0, 1.0]` by summing configurable signed evidence deltas (`TopologyConfidenceWeights` for positive route, static topology, annotation, and policy/VPN/bridge hooks, minus conflict penalties) and attaching `confidence`, `is_standby_path`, and `confidence_factors` (`list[ConfidenceDelta]`) to each `TrafficFlowMatch` and `AffectedGatewayCandidate`.

#### Scenario: SCN-TOPO-013-1 — Delta confidence reflects route agreement, detect-only anti-spoofing, conflicts, and standby annotations

- **WHEN** `find_affected_gateways()` evaluates (a) matching live route + `Prevent` topology, (b) live route on `eth1` conflicting with static topology on `eth2`, and (c) static topology annotated as `standby_dynamic`
- **THEN** case (a) SHALL clamp to `confidence=1.0`
- **AND** case (b) SHALL yield a high penalized confidence that increases when static topology has `trust_static_topology=False`
- **AND** case (c) SHALL set `is_standby_path=True` with `admin_standby_dynamic` recorded in `confidence_factors`

### Requirement: Policy and NAT Rule Topology Inference and Confidence Evidence

**ID**: REQ-TOPO-014\
**Intent**: Reinforce gateway candidates using installed Access/NAT rules and discover one-arm gateways when `include_policy_inferred=True`.\
**Non-goals**: Interface-only LPM matching (`REQ-TOPO-011`).

`find_affected_gateways()` SHALL evaluate enabled, non-negated, non-`Any` Access/NAT rules in each gateway's installed policy package (`install_on`-aware), awarding `+policy_rule_evidence` in `confidence_factors` to cross-interface L3 candidates and returning one-arm or incomplete-topology gateways whose installed rules explicitly cover `sources` and `destinations` as `match_type="policy_inferred"` when `include_policy_inferred=True`.

#### Scenario: SCN-TOPO-014-1 — Cross-interface L3 gateway receives policy_rule_evidence bonus from matching Access or NAT rules

- **GIVEN** a multi-interface L3 gateway whose installed policy contains an enabled non-`Any` Access or NAT rule (`original` or `translated` traffic) covering `10.10.1.25` and `10.20.2.50` for that gateway or `"Policy Targets"`
- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["10.20.2.50"])` matches that gateway
- **THEN** `confidence_factors` on the matched flow and candidate SHALL include `ConfidenceDelta(code="policy_rule_evidence", delta=0.25, ...)`

#### Scenario: SCN-TOPO-014-2 — One-arm Cisco ACI service-graph gateway is discovered via installed EPG policy while unrelated one-arm gateways are excluded

- **GIVEN** 10 single-interface `external` one-arm gateways (`corp-aci-onearm-01`..`10`) where only `corp-aci-onearm-03` has an installed rule permitting or translating `10.160.10.0/24` to `10.160.20.0/24`
- **WHEN** `find_affected_gateways(sources=["10.160.10.15"], destinations=["10.160.20.25"], include_policy_inferred=...)` runs
- **THEN** with `include_policy_inferred=True`, it SHALL return only `corp-aci-onearm-03` (`match_type="policy_inferred"`, `policy_rule_evidence` in `confidence_factors`) and exclude the other 9 one-arm gateways
- **AND** with `include_policy_inferred=False`, it SHALL exclude all 10 one-arm gateways

### Requirement: Static Topology Health Diagnostics and One-Arm Classification

**ID**: REQ-TOPO-015\
**Intent**: Audit static gateway topology completeness without raising false warnings on valid internal-only firewalls or one-arm gateways.\
**Non-goals**: Live CLI routing reconciliation (`REQ-TOPO-016`).

`TopologyService.get_topology_diagnostics()` SHALL inspect policy-enforcing gateways and interfaces for completeness and trust (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`, `no_interfaces`), treating internal-only gateways as valid and classifying single-interface or external-only gateways as `one_arm_topology` (`severity="info"`).

#### Scenario: SCN-TOPO-015-1 — Diagnostics report incomplete interfaces and Detect-mode anti-spoofing without false positives on internal-only or one-arm gateways

- **GIVEN** Gateway 1 (`eth1` `not defined`, `eth2` `network defined by routing` without routes, `eth3` `specific` with Anti-Spoofing `Detect`)
- **AND** internal-only Gateway 2 (`eth1` and `eth2`) plus single-interface `one_arm` Gateway 3
- **WHEN** `get_topology_diagnostics()` runs
- **THEN** it SHALL emit warnings for Gateway 1 (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`)
- **AND** it SHALL emit zero warnings for internal-only Gateway 2 and report Gateway 3 as `code="one_arm_topology"` with `severity="info"`

### Requirement: Static Topology vs Live Routing Reconciliation and Cluster Drift Detection

**ID**: REQ-TOPO-016\
**Intent**: Detect anti-spoofing staleness, interface mismatches, cluster member routing drift, and policy-vs-topology gaps automatically.\
**Non-goals**: Static completeness checks without routing comparison (`REQ-TOPO-015`).

`TopologyService.reconcile_gateway_topology()` SHALL compare SmartConsole static topology against live CLI routes, across cluster members, and optionally against gateway-targeted policy rules (`check_policy=True`), returning a `TopologyReconciliationReport` of typed discrepancies while honoring `TopologyAnnotation` dispositions.

#### Scenario: SCN-TOPO-016-1 — Reconciliation detects stale anti-spoofing subnets, interface mismatches, and cluster member drift

- **GIVEN** Cluster A with static `10.50.0.0/24` and `10.60.0.0/24` on `eth1`, `10.70.0.0/24` on `eth2`, live routes showing `10.50.0.0/24` on `eth1`, `10.60.0.0/24` absent, `10.70.0.0/24` on `eth1`, and `10.80.0.0/24` on `eth1` on `member-1` only
- **WHEN** `reconcile_gateway_topology()` evaluates Cluster A
- **THEN** it SHALL report `stale_in_topology` for `10.60.0.0/24`, `interface_mismatch` for `10.70.0.0/24`, and `missing_in_topology` plus `cluster_member_drift` for `10.80.0.0/24`
- **AND** it SHALL classify `default_route_mismatch` and `resolved_by_routing` where applicable, and suppress `stale_in_topology` when `10.60.0.0/24` is annotated `standby_dynamic`

#### Scenario: SCN-TOPO-016-2 — Policy reconciliation flags gateway-targeted rules whose explicit networks are absent from gateway topology and routes

- **GIVEN** a gateway with internal topology `10.10.0.0/16` and an enabled Access or NAT rule targeting that gateway in `install_on` with explicit `source=192.168.50.0/24` and `destination=192.168.60.0/24` outside all internal intervals
- **WHEN** `reconcile_gateway_topology(..., check_policy=True)` runs
- **THEN** it SHALL emit a `TopologyDiscrepancy` with `discrepancy_type="policy_topology_mismatch"` naming the gateway, rule, and unmatched networks

### Requirement: Enterprise Raw-Replay Scale Verification for Multi-Hop, ECMP, LPM, and Batch Topology Queries

**ID**: REQ-TOPO-017\
**Intent**: Verify topology synchronization, diagnostics, reconciliation, and batch LPM candidate matching at enterprise MDSM scale.\
**Non-goals**: Raw dataset fixture generation rules (`REQ-ITEST-006`).

`TopologyService` SHALL accurately synchronize, diagnose, reconcile, and resolve 7–10-hop cross-domain transit chains, parallel ECMP paths, standby BGP paths, nested `/8`–`/32` longest-prefix-match (LPM) hierarchies, and `20x20+` batch source/destination matrices when driven end-to-end from raw Check Point Management API and gateway CLI routing fixtures.

#### Scenario: SCN-TOPO-017-1 — Cold raw-replay sync, smart-cache reuse, anomaly reconciliation, and administrator annotations

- **GIVEN** the enterprise raw dataset loaded via `FileReplayApiMock` and `FileReplayCliMock`
- **WHEN** cold `refresh_topology(..., collect_routes=True)` runs, followed by `"smart"` / `"cache"` re-runs, diagnostics, reconciliation, `upsert_topology_annotations()`, and `export_topology_prefixes()`
- **THEN** cold sync SHALL populate `CachePort` from raw payloads, and subsequent `"smart"`/`"cache"` runs SHALL make zero `show-gateways-and-servers` or SSH calls while `show-last-published-session` is unchanged
- **AND** diagnostics SHALL detect `not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, and `one_arm_topology` with zero false warnings on internal-only gateways
- **AND** reconciliation SHALL detect `stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `cluster_member_drift`, and `default_route_mismatch`
- **AND** annotations (`standby_dynamic`, `ignore`, `manual`, `confirmed`, `trust_static_topology=False`, `zone`, `site`, `comment`) SHALL govern candidate matching and IPAM export

#### Scenario: SCN-TOPO-017-2 — Deep 7 to 10 hop inter-domain transit chain, ECMP, standby BGP, LPM matryoshka, and 20x20 batch matrix

- **WHEN** `find_affected_gateways()` evaluates a 7–10 hop ECMP/standby-BGP flow (`include_standby=True` vs `False`), nested `/8`–`/32` prefixes, and a `20+ x 20+` batch with nested groups and ranges
- **THEN** it SHALL return all active hops (including both ECMP legs) while filtering standby BGP hops via `include_standby`
- **AND** it SHALL select the exact most-specific interface at every `/8`–`/32` matryoshka level via LPM
- **AND** it SHALL complete the `20+ x 20+` batch from cache within the CI latency budget (< 5.0s) while preserving exact caller input order in `matched_sources` and `matched_destinations`

#### Scenario: SCN-TOPO-017-3 — Targeted single-gateway refresh after raw API and CLI mutation queries only the target gateway

- **GIVEN** a modified raw API/CLI fixture adding a new routed subnet on `target_gateway`
- **WHEN** `refresh_topology(gateways=[target_gateway], collect_routes=True)` runs
- **THEN** replay call counters SHALL confirm only `target_gateway` was queried via Management API and SSH CLI
- **AND** `find_affected_gateways()` SHALL immediately reflect the updated routing graph

### Requirement: Stateful Script Repository and Repository-Mode Run-Script Emulation in FileReplayApiMock

**ID**: REQ-TOPO-018\
**Intent**: Enable offline end-to-end testing of repository-script provisioning, session isolation, and permission enforcement.\
**Non-goals**: General replay CRUD and session emulation (`REQ-ITEST-009`..`REQ-ITEST-014`).

`FileReplayApiMock` SHALL support per-domain repository script CRUD (isolated in uncommitted write sessions until `publish`), reject non-empty `"args"` on repository `run-script` unless `allow_one_time_script=True`, emit zero-argument VSX bundles or parameterized outputs, and optionally encode `"script-body"` as Base64.

#### Scenario: SCN-TOPO-018-1 — End-to-end provisioning and restricted-permission repository execution in FileReplayApiMock

- **GIVEN** `arodonata-collect-routes-v1` provisioned via `ensure_route_collection_script` (invisible to other sessions until `publish`) and `FileReplayApiMock(allow_one_time_script=False, allow_repository_script=True)`
- **WHEN** `collect_gateway_routes(cprid_script_mode="repository")` vs `cprid_script_mode="inline"` runs across cluster and VSX replay fixtures
- **THEN** `"repository"` mode SHALL succeed without `"args"` using `script-type="repository"`, whereas `"inline"` mode SHALL fail with `error_code="repository_script_permission_denied"`

#### Scenario: SCN-TOPO-018-2 — FileReplayApiMock rejects non-empty repository args without one-time permission and emulates R82 Base64 script-body

- **GIVEN** `FileReplayApiMock(allow_one_time_script=False, allow_repository_script=True, encode_repository_script_body_base64=True)`
- **WHEN** callers invoke `run-script` (`script-type="repository"`) with non-empty `"args"` vs omitted `"args"` on a VSX host, and inspect `show-repository-script`
- **THEN** non-empty `"args"` SHALL return HTTP `400` (`err_validation_failed`, `"Insufficient permissions to run this script with arguments."`), omitted `"args"` SHALL succeed emitting the zero-arg VSX bundle, and `show-repository-script` SHALL return Base64-encoded `"script-body"` decoded cleanly by `check_repository_script`

### Requirement: Interface Topology Aggregation and Cached Policy Metadata Enrichment

**ID**: REQ-TOPO-019\
**Intent**: Provide summarized per-interface topology views and enrich cached `get_gateway_topology()` rows with installed policy package metadata.\
**Non-goals**: Flow matching and confidence scoring (`REQ-TOPO-011`..`REQ-TOPO-014`).

`TopologyService.summarize_gateway_interfaces()` SHALL aggregate `GatewayTopologyEntry` rows into `GatewayInterfaceSummary` models preserving zones, anti-spoofing modes, source types, and CIDRs/ranges, while `TopologyService.get_gateway_topology()` SHALL enrich returned entries with `installed_access_policy` and `policy_packages` from cached assets and policy packages.

#### Scenario: SCN-TOPO-019-1 — Interface summary aggregation and get_gateway_topology policy enrichment

- **WHEN** `TopologyService.summarize_gateway_interfaces(entries)` or `client.get_gateway_topology(mgmt_name, domain)` runs on cached topology entries and rulebase/asset snapshots
- **THEN** `summarize_gateway_interfaces` SHALL group rows by `(mgmt_name, domain_name, gateway_uid, interface_name)` and aggregate `topology_zone`, `source_types`, and `cidrs_and_ranges`
- **AND** `get_gateway_topology` SHALL populate `installed_access_policy` and `policy_packages` on each enriched `GatewayTopologyEntry`

### Requirement: Modular Topology Package Compatibility, Boundary SID Redaction, and Fail-Fast TLS Identity Propagation

**ID**: REQ-TOPO-020\
**Intent**: Guarantee backward-compatible shim re-exports and logger method hooking for the modular `arodonata.core.services.topology` package, enforce SID redaction at model and service boundaries, and fail fast on `ServerIdentityError` across live route collection and targeted refresh.\
**Non-goals**: Internal submodule file naming beyond public `topology` / shim compatibility (`REQ-CLIENT-018`).

`arodonata.core.services.topology_service` and `arodonata.core.services.route_collector` SHALL serve as backward-compatible re-export shims for `arodonata.core.services.topology` with shared `logger` identity while omitting internal `collect_gateway_routes` from `topology.__all__`; model boundaries, `ScriptRepositoryService`, live route collection, and targeted refresh SHALL redact SIDs; and `ServerIdentityError` SHALL propagate fail-fast while preserving `None` SSH fallback error parity.

#### Scenario: SCN-TOPO-020-1 — Shims preserve exact re-export identity and logger method interception while omitting internal orchestration exports

- **WHEN** callers import `TopologyService`, shared helpers, normalizers, or route-collection utilities from `arodonata.core.services.topology_service` or `arodonata.core.services.route_collector` and monkeypatch `topology_service.logger.warning`
- **THEN** imported symbols SHALL reference the exact canonical objects in `arodonata.core.services.topology`, warnings emitted by topology submodules SHALL be intercepted by the patched `logger.warning`, and `arodonata.core.services.topology.__all__` SHALL omit internal `collect_gateway_routes`

#### Scenario: SCN-TOPO-020-2 — Boundary models, ScriptRepositoryService, route collection, and targeted refresh scrub patterned and dedicated SIDs

- **GIVEN** exceptions, API error payloads, task outputs, or `gateway_cli` return values containing `X-chkp-sid`, JSON `"sid"`, `Authorization: Bearer`, or bare dedicated `arodonata-route-collect` / `arodonata-run-repo-script` SID tokens across direct SSH (`fallback_to_cprid=False`), `_vs_error=` stdout, repository mode without `cprid_session_getter`, `collect_gateway_routes`, or targeted `stream_refresh_topology(gateways=...)`
- **THEN** all resulting `GatewayCliResult`, `GatewayRouteCollectionStatus`, `DomainSyncState`, `DomainSyncFailedEvent`, `SyncCompletedEvent`, `RefreshOutcome`, `ScriptTargetExecutionResult`, `RepositoryScriptExecutionOutcome`, and `WARNING` log messages SHALL scrub every SID token with `***REDACTED***`

#### Scenario: SCN-TOPO-020-3 — Fatal ServerIdentityError propagates fail-fast across route collection and targeted refresh with SSH None fallback parity

- **GIVEN** a `ServerIdentityError` raised during SSH execution, inline or repository `cprid`, `AutoScriptModeResolver` probing, multi-gateway `collect_gateway_routes`, or multi-domain targeted `stream_refresh_topology(gateways=...)` / `refresh_topology(gateways=...)`
- **THEN** `ServerIdentityError` SHALL propagate immediately, cancel sibling route-collection tasks, preserve domain `routes` sync states (no `"failed"` downgrade), skip unvisited domains in targeted refresh without emitting `DomainSyncFailedEvent`, log out any opened dedicated sessions, and omit spurious SSH error prefixes when `gateway_cli` returns `None` during `cprid` fallback

### Requirement: Domain-Scoped Route Sync Atomicity, VSX Coalescing Isolation, and Manual Prefix Parity

**ID**: REQ-TOPO-021\
**Intent**: Prevent premature whole-domain route freshness stamps, cross-domain VSX coalescing collisions, dropped list next-hops, and swallowed `ServerIdentityError` during topology operations.\
**Non-goals**: Base VSX bundle parsing (`REQ-TOPO-008`) or LPM candidate matching (`REQ-TOPO-011`).

`TopologyService` SHALL propagate `ServerIdentityError` in group enrichment, defer domain-level `("topology", "routes")` sync state until full-domain route collection completes, key repository VSX coalescing by `(mgmt_name, domain_name, node_key)` while preserving upstream errors, unwrap list-valued Gaia/CPMI `next-hop` objects, match space-containing VS names on error markers, and include `disposition="manual"` prefixes in `export_topology_prefixes(include_ignored=True)`.

#### Scenario: SCN-TOPO-021-1 — Full-domain route sync state, VSX domain coalescing, and fail-fast TLS identity propagation

- **GIVEN** a targeted `gateways=[...]` or partial multi-gateway route collection, concurrent VSX domains sharing a chassis, or a `ServerIdentityError` during group enrichment
- **WHEN** `collect_gateway_routes()` or `refresh_topology()` executes
- **THEN** targeted or aborted per-gateway runs SHALL NOT stamp whole-domain `("topology", "routes")` `status="ok"` prematurely
- **AND** repository VSX coalescing SHALL isolate by `(mgmt_name, domain_name, node_key)`, preserve upstream command errors instead of overwriting with `vsx_bundle_missing`, publish `auto`-probed bundles, and propagate `ServerIdentityError`

#### Scenario: SCN-TOPO-021-2 — List-valued next-hops, space-containing VS error markers, and manual prefix export

- **GIVEN** a Gaia/CPMI static route with a list-valued `next-hop`, a VS error marker whose name contains spaces, or `disposition="manual"` topology annotations
- **WHEN** topology normalization, VSX bundle parsing, or `export_topology_prefixes(include_ignored=True)` runs
- **THEN** list-valued `next-hop` entries SHALL be unwrapped, space-containing VS error markers SHALL populate `VsxBundleSlice.error`, and `export_topology_prefixes(include_ignored=True)` SHALL retain all `manual` prefixes and manual-only gateways

### Requirement: Isolated VSX Coalescing, Accurate LPM/Export Scoring, Atomic Route Streaming, and Scrubbed Topology Errors

**ID**: REQ-TOPO-022\
**Intent**: Ensure VSX coalesced execution isolates per-VS errors, topology streaming orders completion events accurately, LPM/export/VSID matching covers nested/manual/spaced targets, and topology/script errors scrub bare SIDs.\
**Non-goals**: Base VSX repository bundle parsing (`REQ-TOPO-008`) or LPM penalty weights (`REQ-TOPO-010`).

Topology and script services SHALL isolate per-VS bundle slice errors during VSX coalescing, hold `SyncCompletedEvent` until route collection completes, match annotations strictly on LPM `best_entry`, filter manual gateways across all canonical identifiers, resolve spaced VS names in `awk`, and scrub bare SIDs across write/topology error paths.

#### Scenario: SCN-TOPO-022-1 — Coalescing leader VS slice failure does not fail healthy sibling Virtual Systems

- **GIVEN** a physical VSX node hosting an alphabetically first broken Virtual System (`vs_context_error` or `vs_not_found_in_bundle`) alongside healthy sibling Virtual Systems
- **WHEN** `collect_gateway_routes()` runs in `"repository"` or `"auto"` mode
- **THEN** healthy sibling Virtual Systems SHALL still extract and persist their route slices while only the broken Virtual System records its error

#### Scenario: SCN-TOPO-022-2 — Streamed topology refresh, LPM annotation lookup, manual gateway export, and spaced VSID resolution

- **GIVEN** `stream_refresh_topology(collect_routes=True)`, overlapping interface subnets (`10.0.0.0/8` `standby_dynamic` + `10.10.1.0/24`), manual-only annotation gateways, or space-containing VS names without numeric `vsid`
- **WHEN** topology refresh streams, flows score, prefixes export by gateway name/composite ID, or inline/SSH route scripts run `vsx stat -l`
- **THEN** `SyncCompletedEvent` SHALL be yielded only after route collection completes, `_score_interface_group` SHALL match annotations for LPM `best_entry`, `export_topology_prefixes` SHALL match manual gateways by name/UID/composite ID, and `awk` SHALL resolve spaced VS names

#### Scenario: SCN-TOPO-022-3 — ScriptRepositoryService write paths and targeted topology refresh scrub bare SIDs and map permission errors

- **GIVEN** an active or isolated `WriteSession` in `ensure_repository_script` / `delete_repository_script`, or an exception during targeted topology refresh or lazy package loading
- **WHEN** a `SessionError`, `AuthenticationError`, or generic `Exception` embeds a bare session SID
- **THEN** `ScriptRepositoryService` SHALL map permission errors to `RepositoryScriptPermissionError` consistently and all error/log/event outputs SHALL scrub bare cached and active SIDs via `known_sids`

### Requirement: WriteSession Cache Isolation, Server-Scoped CLI Targets, Canonical Annotations, and Zero-Prefix Routes

**ID**: REQ-TOPO-023\
**Intent**: Prevent uncommitted `WriteSession` overlays from leaking into persistent SQL topology caches, enforce clean-session checks on targeted gateway refreshes, avoid cross-management CLI target leakage, match all canonical annotation IDs, and preserve `/0` default routes.\
**Non-goals**: Coalescing leader error isolation (`REQ-TOPO-022`) or LPM penalty scoring (`REQ-TOPO-010`).

`TopologyService` SHALL skip SQL persistence during active `WriteSession` resolution, enforce clean sessions on targeted refresh, scope CLI target resolution to `gateway_asset.mgmt_name`, match all four canonical IDs in annotations, and preserve zero-length route prefixes.

#### Scenario: SCN-TOPO-023-1 — WriteSession SQL cache isolation, server-scoped CLI targets, canonical annotation IDs, and zero-prefix route normalization

- **GIVEN** an active `WriteSession` during on-demand topology object resolution, a targeted gateway refresh, multi-MDS cluster/VSX assets during `resolve_gateway_cli_targets()`, topology annotations using UID or composite IDs, or a static route with `mask-length: 0`
- **WHEN** topology resolution, targeted refresh, annotation lookup, or normalizer route parsing runs
- **THEN** on-demand object/global resolutions SHALL NOT write to persistent SQL tables under an active `WriteSession`, targeted refresh SHALL call `verify_session_clean()`, CLI targets SHALL be scoped to `gateway_asset.mgmt_name`, annotations SHALL match all 4 canonical keys, and `mask-length: 0` SHALL normalize to prefix `/0`


---

### OpenSpec Capability: `integration-testing-and-examples` (`openspec/specs/integration-testing-and-examples/spec.md`)

# Integration Testing and Examples Specification

## Purpose

Defines the live Check Point integration testing harness (`tests/integration/b1..b7`), the `./pytest.sh` runner separating the mandatory zero-network unit test gate (`tests/unit/`) from bucketed live-environment integration suites, the lab safety net (exclusive run lock, unauthenticated API readiness gate, and automatic revision baseline snapshot/restore), the deterministic enterprise raw dataset and stateful API/CLI replay emulator (`FileReplayApiMock`, `FileReplayCliMock`, `CheckPointReplayHttpServer`), and the runnable SDK usage examples (`examples/`).

## Requirements

### Requirement: Unit and Integration Test Separation and Runner

**ID**: REQ-ITEST-001\
**Intent**: Keep default unit testing fast and network-free while organizing live lab tests into rate-limit-safe buckets.\
**Non-goals**: Automatic pytest directory marker attachment (`REQ-ITEST-002`).

The repository SHALL separate fast, zero-network unit tests (`tests/unit/`) from live Check Point integration tests (`tests/integration/b1..b7`) and provide an executable `./pytest.sh` runner at the repository root.

#### Scenario: SCN-ITEST-001-1 — Default test invocation executes only fast unit tests

- **WHEN** `./pytest.sh`, `./pytest.sh unit`, or bare `uv run pytest` is executed
- **THEN** pytest SHALL run only unit tests (`-m "not integration"`) with verbose names (`-v`) and zero network access, excluding `tests/integration/`

#### Scenario: SCN-ITEST-001-2 — Single integration bucket runs in an isolated session with short tracebacks

- **WHEN** `./pytest.sh int-<N>` (`N` in `1..7`) is executed
- **THEN** it SHALL invoke `pytest` on `tests/integration/b<N>` with `-v`, live CLI info logging (`-o log_cli=true --log-cli-level=INFO`), `--durations=15`, and `--tb=short` so frame-local secrets never print on failure

#### Scenario: SCN-ITEST-001-3 — Full integration suite runs all buckets sequentially with throttle pauses

- **WHEN** `./pytest.sh int-full` is executed
- **THEN** it SHALL run buckets `b1` through `b7` sequentially in separate `pytest` sessions, pausing `BUCKET_PAUSE_SECONDS` (default `90s`) between buckets
- **AND** it SHALL continue past failed buckets and exit non-zero if any bucket failed

#### Scenario: SCN-ITEST-001-4 — Unknown integration target is rejected before pytest collection

- **WHEN** `./pytest.sh int-unknown` is executed with an invalid `int-*` target
- **THEN** `./pytest.sh` SHALL exit with code `2` and print valid bucket targets (`int-1`..`int-7`, `int-full`) without invoking `pytest`

### Requirement: Automatic Directory-Based Integration Markers

**ID**: REQ-ITEST-002\
**Intent**: Ensure every integration test receives its bucket and integration markers automatically based on file location.\
**Non-goals**: Test runner invocation options (`REQ-ITEST-001`).

Integration tests under `tests/integration/` SHALL automatically receive `integration` and `bucket_<N>` pytest markers from their directory path during collection without manual per-test marker declarations.

#### Scenario: SCN-ITEST-002-1 — Collection hook applies integration and bucket markers

- **WHEN** `pytest` collects test items located under `tests/integration/b<N>/`
- **THEN** the collection hook SHALL attach `pytest.mark.integration` and `pytest.mark.bucket_<N>` to each item and sort collected items by bucket number

### Requirement: Multi-Profile Lab Environment Loader

**ID**: REQ-ITEST-003\
**Intent**: Allow live integration suites and lab diagnostic scripts to switch target labs cleanly via env profiles.\
**Non-goals**: Library `ArodonataSettings` explicit env resolution (`REQ-CONFIG-001`).

The integration harness and diagnostic scripts SHALL load lab configuration deterministically from `.env.test`, `.env.secrets`, and an optional `.env.lab.<ARODONATA_LAB>` profile override.

#### Scenario: SCN-ITEST-003-1 — Default lab environment loads when ARODONATA_LAB is unset

- **WHEN** `load_lab_env()` is called without `ARODONATA_LAB` set
- **THEN** it SHALL load `.env.test` with `override=False` (preserving caller env vars), followed by `.env.secrets` with `override=True`, and return `None`

#### Scenario: SCN-ITEST-003-2 — Named lab profile layers overrides and expands secret references

- **GIVEN** `ARODONATA_LAB=<profile>` where `.env.lab.<profile>` exists
- **WHEN** `load_lab_env()` runs
- **THEN** it SHALL load `.env.lab.<profile>` after `.env.test` and `.env.secrets`, expanding `${VAR}` secret references and returning `<profile>`

#### Scenario: SCN-ITEST-003-3 — Missing selected lab profile fails fast

- **GIVEN** `ARODONATA_LAB=<profile>` where `.env.lab.<profile>` does not exist
- **WHEN** `load_lab_env()` runs
- **THEN** it SHALL raise `LabProfileMissing` rather than silently falling back to `.env.test`

### Requirement: Exclusive Integration Run Lock and Lab Readiness Gate

**ID**: REQ-ITEST-004\
**Intent**: Prevent parallel integration runs from colliding on a live lab and verify API readiness without wasting login rate-limit slots.\
**Non-goals**: Domain revision baseline capture and restore (`REQ-ITEST-005`).

Each integration session SHALL acquire a non-blocking exclusive OS file lock (`_tmp/integration.lock`) and verify that the target Check Point API server is responsive before touching the SQLite cache database or logging in.

#### Scenario: SCN-ITEST-004-1 — Concurrent integration run fails fast on lock contention

- **GIVEN** another process holding `_tmp/integration.lock`
- **WHEN** a new integration session starts
- **THEN** `IntegrationRunLock.acquire()` SHALL raise `IntegrationRunLocked` naming the holding PID and start timestamp, exiting with return code `3`

#### Scenario: SCN-ITEST-004-2 — Readiness gate probes API server without spending login allowance

- **WHEN** the `lab_ready` fixture probes `API_MGMT` via `show-api-versions` (`sid=None`) up to `ARODONATA_TEST_READY_WAIT` seconds
- **THEN** `generic_err_missing_required_header` or `success=True` SHALL count as ready without consuming a login rate-limit slot
- **AND** expiring the readiness budget SHALL abort with return code `4`

### Requirement: Automatic Revision Baseline Snapshot and Teardown Revert

**ID**: REQ-ITEST-005\
**Intent**: Protect live lab domains by reverting any published mutations automatically on test session teardown.\
**Non-goals**: In-memory replay mock state snapshots (`REQ-ITEST-015`).

Integration sessions SHALL snapshot the last published revision via `show-sessions` (`view-published-sessions=True`) for `TEST_DOMAIN_A` and `TEST_DOMAIN_B` before running tests and revert any drifted domain on teardown if any `cp_mutates`-marked test executed.

#### Scenario: SCN-ITEST-005-1 — Baseline snapshot persisted before tests and restored after mutations

- **GIVEN** `TEST_DOMAIN_A` or `TEST_DOMAIN_B` configured and at least one `@pytest.mark.cp_mutates` test executed
- **WHEN** the integration session starts and tears down
- **THEN** it SHALL write `_tmp/cp_baseline/baseline-<UTC>.json` before the first test
- **AND** on teardown it SHALL discard open sessions holding locks/changes and run `revert-to-revision` (`timeout=900s`) for any domain whose head UID drifted from baseline

#### Scenario: SCN-ITEST-005-2 — Baseline snapshot failure aborts the session before running tests

- **WHEN** capturing the initial baseline snapshot of `TEST_DOMAIN_A` or `TEST_DOMAIN_B` fails
- **THEN** the session fixture SHALL abort immediately with return code `5` rather than executing mutating tests without recovery

### Requirement: Deterministic Enterprise Raw Dataset and Generator

**ID**: REQ-ITEST-006\
**Intent**: Supply a reproducible, multi-domain Check Point enterprise dataset for offline scale, topology, and replay verification.\
**Non-goals**: Replay mock runtime query execution (`REQ-ITEST-007`).

The testing harness SHALL provide a deterministic (fixed-seed) generator (`ensure_enterprise_raw_dataset()`) and raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) containing Check Point Management API JSON payloads and gateway CLI routing outputs for an enterprise MDSM topology.

#### Scenario: SCN-ITEST-006-1 — Raw dataset covers multi-domain API payloads and gateway CLI outputs

- **WHEN** the enterprise raw dataset is generated or loaded from `tests/fixtures/enterprise_raw_dataset/`
- **THEN** it SHALL provide domain/session JSON fixtures (`show-domains`, `show-global-assignments`, `show-sessions`, `show-last-published-session`, `show-session`)
- **AND** it SHALL provide gateway JSON fixtures (`show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects`)
- **AND** it SHALL provide object/service JSON fixtures (`show-hosts`, `show-networks`, `show-address-ranges`, `show-groups` nested 6–7 levels deep, `show-services-*`)
- **AND** it SHALL provide rulebase JSON fixtures (`show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`)
- **AND** it SHALL provide raw CLI stdout fixtures (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, Base64 `run-script`/`show-task`) across `9` user MDSM domains plus `Global`

#### Scenario: SCN-ITEST-006-2 — Raw dataset includes deterministic Global object and group usage in local domain rules without breaking scale invariants

- **WHEN** `ensure_enterprise_raw_dataset()` materializes `tests/fixtures/enterprise_raw_dataset/`
- **THEN** local domains SHALL reference `Global` entities (`H_Global_DNS_001`, `G_Global_Branch_Supernet`, `G_Global_DC_Supernet`, `TCP_53`, `UDP_53`) in rule #104 (`uid-arule-<domain>-0104`) and provide `mds/show-global-assignments.json`
- **AND** the dataset SHALL preserve `10` domains, `341` cached assets, `315` gateways (with `simple-gateway`, HA cluster, and `CpmiVsNetobj` Virtual Systems per user domain plus `>= 15` cross-domain Virtual Systems), and `325` CLI routing targets
- **AND** it SHALL preserve unique per-domain gateway/interface IPs and Virtual System internal `/24` subnets plus complete `CpmiVsxSlotObj` / `CpmiVsSlotObj` entries
- **AND** it SHALL preserve `105` access rules in `3` sections per domain, `12` NAT rules per domain, `< 250` topology-cached objects, and unmodified rule #1 fixtures

### Requirement: File-Backed Check Point API and Gateway CLI Replay Doubles

**ID**: REQ-ITEST-007\
**Intent**: Emulate Check Point `ApiPort` pagination/queries and `GatewayCliPort` VSX context checks deterministically offline.\
**Non-goals**: Standalone HTTPS HTTP server wrapper (`REQ-ITEST-008`) or write overlays (`REQ-ITEST-009`).

The testing package SHALL provide `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) backed by the disk raw dataset, validating commands against `^[a-z0-9]+(-[a-z0-9]+)*$` (optional `/web_api/` or `web_api/` prefix) and emulating pagination, `details-level`, filters, `use-object-dictionary=False` inlining, `where-used`, `run-script` + `show-task`, VSX CLI checks, per-`sid` writes, and redacted call logs.

#### Scenario: SCN-ITEST-007-1 — Paginated API queries and VSX CLI context validation execute against raw fixture files

- **WHEN** `ArodonataClient` queries `FileReplayApiMock` (`limit`/`offset`, `uid`/`name`/`class-name`, `where-used`, `show-*-rulebase` with `use-object-dictionary=True | False`) and invokes `FileReplayCliMock` (or `run-script` + `show-task`)
- **THEN** `FileReplayApiMock` SHALL return continuity-valid slices (`from`, `to`, `total`), resolve direct/indirect `where-used`, and inline `objects-dictionary` when `use-object-dictionary=False`
- **AND** `FileReplayApiMock` SHALL return Base64 `show-task` payloads and record per-command call counters
- **AND** `FileReplayCliMock` SHALL verify `vsenv` / `vsx stat -l` and `CTX%05d` `$FWDIR` guards before returning the raw CLI stdout for the target node and VSID

#### Scenario: SCN-ITEST-007-2 — Stateless read calls without SID continue reading published domain state

- **WHEN** read-only `FileReplayApiMock.api_call(...)` or `api_query(...)` is called with `sid=None`
- **THEN** `FileReplayApiMock` SHALL serve responses from the domain's published snapshot without failing authentication

#### Scenario: SCN-ITEST-007-3 — Replay mock enforces strict command-name validation parity with AMgmtClient

- **WHEN** `FileReplayApiMock.api_call(...)` or `api_query(...)` receives a malformed command (e.g., `"/show-hosts"`, `" show-hosts "`, `"SHOW-HOSTS"`, `"show-hosts/../publish"`, `"show-hosts?x=1"`) vs valid `"web_api/show-access-rulebase"` or `"/web_api/login"`
- **THEN** malformed commands SHALL raise `ValidationError` before mutating state or recording a valid command call, matching `AMgmtClient` validation
- **AND** valid `"web_api/"` / `"/web_api/"` prefixed commands SHALL normalize cleanly to the canonical lowercase hyphenated command name

### Requirement: Standalone Check Point Web API HTTPS Mock Server for Downstream Applications

**ID**: REQ-ITEST-008\
**Intent**: Allow downstream services and tests to run full real-HTTPS Check Point read/write workflows locally without a live lab.\
**Non-goals**: In-memory replay state isolation semantics (`REQ-ITEST-009`..`REQ-ITEST-014`).

The testing package SHALL provide an embeddable and CLI-runnable HTTPS server (`python -m arodonata.testing.mock_server`) sharing unified session, async task, and mutation state with `FileReplayApiMock`, serving `/web_api/{cmd}` with host-rewritten `show-domains`, `X-chkp-sid` session enforcement, and fast state reset controls so downstream applications can run full read and write workflows against `localhost:<port>`.

#### Scenario: SCN-ITEST-008-1 — Downstream application connects over HTTPS to localhost and syncs multi-domain dataset

- **GIVEN** `CheckPointReplayHttpServer` listening on `localhost:<port>`
- **WHEN** a client connects via real `AMgmtClient` TLS transport and logs in via `/web_api/login`
- **THEN** `/web_api/login` SHALL issue domain-bound `X-chkp-sid` tokens and `/web_api/show-domains` SHALL rewrite server `ipv4-address` fields to the bound host
- **AND** `/web_api/{cmd}` endpoints (`show-gateways-and-servers`, `show-hosts`, `show-groups`, `show-packages`, `show-access-rulebase`, `run-script`, `show-task`) SHALL return paginated raw domain datasets without rate-limit delays

#### Scenario: SCN-ITEST-008-2 — Downstream application executes stateful write workflows and resets state via CheckPointReplayHttpServer

- **WHEN** an HTTPS client logs in, runs mutating `/web_api/{cmd}` calls, and polls `/web_api/show-task` for async tasks (`publish`, `show-changes`, `verify-policy`, `install-policy`, `assign-global-assignment`, `assign-global-policy`, `run-script`)
- **AND** the client subsequently resets server state between test scenarios
- **THEN** `/web_api/{cmd}` SHALL enforce HTTP `401` (`generic_err_missing_required_header` or `generic_err_invalid_session_id`) on missing or invalid `X-chkp-sid`
- **AND** committed writes SHALL appear immediately across subsequent requests, and `snapshot_state()`, `restore_state()`, `reset()`, or opt-in `/__testing__/*` endpoints SHALL restore clean state

### Requirement: Per-Session Staging Overlay and Read-Your-Own-Writes Isolation

**ID**: REQ-ITEST-009\
**Intent**: Emulate Check Point's copy-on-write work-session isolation, read-only guards, and cross-session object locks faithfully.\
**Non-goals**: Publish, discard, and adoption lifecycle transitions (`REQ-ITEST-010`).

`FileReplayApiMock` and `CheckPointReplayHttpServer` MUST isolate uncommitted write operations inside a copy-on-write per-`sid` staging overlay (`login`, `create_dedicated_session`, `/web_api/login`) until `publish`, while enforcing Check Point `"read-only": true` restrictions and cross-session object locks.

#### Scenario: SCN-ITEST-009-1 — Uncommitted mutations are visible to the mutating SID and isolated from other sessions

- **GIVEN** Session A (`sid_a`) mutating objects, groups, or rules without calling `publish`
- **WHEN** Session A (`sid_a`) and Session B (`sid_b`, a read-only session, or `sid=None`) read from that domain
- **THEN** reads with `sid_a` SHALL reflect all uncommitted mutations, while reads with `sid_b`, `"read-only": true`, or `sid=None` SHALL see only the last published domain state

#### Scenario: SCN-ITEST-009-2 — Read-only sessions and object locks reject conflicting write commands

- **WHEN** a `"read-only": true` session sends a write command, OR Session B edits or deletes a UID currently modified or deleted in uncommitted Session A
- **THEN** the emulator SHALL reject the read-only write with HTTP `400` (`err_validation_failed`)
- **AND** it SHALL reject Session B's conflicting edit with HTTP `400` (`generic_err_object_locked`)

### Requirement: Session Lifecycle, Adoption, Discard, and Change History Emulation

**ID**: REQ-ITEST-010\
**Intent**: Emulate Check Point session commit, discard, takeover, rotation, and `show-changes` history for end-to-end testing.\
**Non-goals**: Per-session staging overlay isolation (`REQ-ITEST-009`).

The emulator SHALL support `login`, `logout` / `logout_sid`, `set-session`, `take-over-session`, `switch-session`, `publish`, `discard`, `show-session`, `show-sessions`, `show-last-published-session`, and `show-changes` with atomic publish commits, post-publish work-session rotation, rollback on discard or logout without publish, and structured change deltas.

#### Scenario: SCN-ITEST-010-1 — Publish commits overlay atomically, rotates active work session, and records change history

- **WHEN** a write session calls `publish` (`{}` or `{"uid": <session_uid>}`)
- **THEN** the emulator SHALL apply the overlay atomically, update `show-last-published-session`, prepend the revision (`published-changes`, `number-of-published-changes`) to `show-sessions`, and record `show-changes` deltas
- **AND** it SHALL return a completed `tasks` response (`wait_for_task=True`) or pollable `task-id` (`wait_for_task=False`) and rotate `sid` to a fresh `"open"` session (`changes=0`, `locks=0`, `number-of-published-changes=0`, no `publish-time`)

#### Scenario: SCN-ITEST-010-2 — Discard, logout without publish, set-session, take-over-session, and switch-session manage uncommitted state

- **WHEN** a client executes `set-session`, `take-over-session` (`uid`, optional `disconnect-active-session`), `switch-session` (`uid`), `discard` (`{}` or `{"uid": <target_session_uid>}`), or `logout`/`logout_sid` before `publish`
- **THEN** `set-session` SHALL persist `name` and `description` in `show-session`, and session adoption SHALL transfer the overlay (invalidating disconnected active SIDs with HTTP `401` `generic_err_invalid_session_id`)
- **AND** `discard` (or clean `logout`) SHALL roll back uncommitted changes and release locks immediately, whereas `logout` on a dirty uncommitted session SHALL transition the session to `"disconnected"` while preserving object locks for Check Point parity

#### Scenario: SCN-ITEST-010-3 — Querying show-changes returns structured deltas for staged and published sessions

- **WHEN** `show-changes` queries a published session (`to-session`, optional `from-session`, `from-date`, `to-date`) or an uncommitted staged session
- **THEN** the emulator SHALL return `changes[]` items carrying `added-objects`, `modified-objects`, `deleted-objects`, `added-rules`, `modified-rules`, and `deleted-rules` directly (without an `.operations` wrapper)
- **AND** each bucket entry SHALL carry `old-object`, `new-object`, `field-changes`, `layer`, `package`, `rule-number`, and `old-rule-number` metadata
- **AND** it SHALL return a completed task (`wait_for_task=True`) or pollable `task-id` (`wait_for_task=False`)

### Requirement: Stateful Object, Service, and Group CRUD Operations

**ID**: REQ-ITEST-011\
**Intent**: Emulate Check Point CRUD semantics, validation errors, and unused-object cleanup across objects, services, and groups.\
**Non-goals**: Deletion blocking when references remain (`REQ-ITEST-012`) or rulebase CRUD (`REQ-ITEST-013`).

The emulator SHALL support `add-*`, `set-*`, `delete-*`, and singular `show-*` commands for `host`, `network`, `address-range`, `dns-domain`, `application-site`, `group`, `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, `service-other`, and `service-group`, plus `show-unused-objects` and `delete-unused-objects`.

#### Scenario: SCN-ITEST-011-1 — CRUD lifecycle for network objects, services, and groups

- **WHEN** a write session creates, renames (`new-name`), updates (`set-*`, `members` full or `add`/`remove`, `groups`, `set-if-exists`), and deletes supported objects, services, or groups
- **THEN** the emulator SHALL enforce name uniqueness (`ignore-warnings` for value warnings), keep bidirectional group memberships consistent, and return `generic_err_object_not_found` for unknown UIDs or names

#### Scenario: SCN-ITEST-011-2 — Unused object discovery and cleanup via show-unused-objects and delete-unused-objects

- **WHEN** `show-unused-objects` or `delete-unused-objects` runs (with optional object or group filters)
- **THEN** `show-unused-objects` SHALL return domain objects with zero references in groups, Access/NAT rules, or gateway interfaces
- **AND** `delete-unused-objects` SHALL delete only unreferenced local objects into the active staging overlay while leaving referenced and `Global` objects intact

### Requirement: Referential Integrity Enforcement on Object and Service Deletion

**ID**: REQ-ITEST-012\
**Intent**: Reproduce Check Point server-side deletion rejections accurately for decommission and rollback testing.\
**Non-goals**: Non-referenced object CRUD (`REQ-ITEST-011`).

The emulator MUST reject `delete-*` on any object, service, or group that is still referenced within the effective domain by any group, Access rule (enabled or disabled), NAT rule, or gateway interface topology.

#### Scenario: SCN-ITEST-012-1 — Deleting a referenced object, service, or group fails with Check Point validation error

- **WHEN** a write session calls `delete-host`, `delete-network`, `delete-address-range`, `delete-dns-domain`, `delete-application-site`, `delete-group`, or `delete-service-*`
- **AND** the target entity is still referenced by a group, Access rule, NAT rule, or gateway topology
- **THEN** the emulator SHALL reject the deletion with HTTP `400` and `generic_err_object_cannot_be_deleted` (with `blocking-errors` identifying referencers, compatible with `err_validation_failed`)
- **AND** the target entity SHALL remain intact

#### Scenario: SCN-ITEST-012-2 — Deleting an object succeeds after removing all group and rule references

- **WHEN** a workflow removes the target object from referencing groups (`set-group` with `members.remove`), removes it from multi-member rule cells or disables/deletes sole-member rules, and then calls `delete-*`
- **THEN** `delete-*` SHALL succeed once zero staged references remain in the session overlay

### Requirement: Access, HTTPS, Threat, and NAT Rulebase CRUD and Consistency

**ID**: REQ-ITEST-013\
**Intent**: Keep rule numbers, section bounds, `objects-dictionary`, `where-used`, and `show-objects` consistent across staged rulebase edits.\
**Non-goals**: MDSM `Global` domain write protection (`REQ-ITEST-014`).

The emulator SHALL support Access, HTTPS, Threat-prevention, and NAT rulebase, rule, and section CRUD, read-only `show-{access,https,threat}-layer(s)` with `inline-layer` references, and `verify-policy`/`install-policy` task simulation, automatically recomputing sequential rule numbers, section ranges, live `objects-dictionary`, `show-objects`, `show-object`, and `where-used`.

#### Scenario: SCN-ITEST-013-1 — Access rule, section, and read-only inline-layer reads maintain rule-numbers, section bounds, and objects-dictionary

- **WHEN** a write session executes Access rule/section CRUD or `show-{access,https,threat}-layer(s)` (including `inline-layer` references), toggles `enabled`, or patches rule cells via list replacement or `{"add": ..., "remove": ...}`
- **AND** rules are positioned via `position` / `new-position` (`"top"`, `"bottom"`, 1-based `rule-number`, `{"top": section}`, `{"bottom": section}`, `{"above": ref}`, `{"below": ref}`)
- **THEN** the emulator SHALL strip `"Any"` (`97aeb369-9aea-11d5-bd16-0090272ccb30`) on member addition, revert emptied cells to `"Any"`, and recompute sequential 1-based `rule-number`, section `from`/`to`, and layer `total`
- **AND** `show-access-rule`, `show-access-rulebase`, and `show-{access,https,threat}-layer(s)` SHALL reflect live `objects-dictionary` entries (or inline dicts for `use-object-dictionary=False`) and layer metadata, resolving built-in sentinels consistently with `arodonata.core.models.sentinels` (`6c488338-8eec-4103-ad21-cd461ac2c476` as `Policy Targets` / `Global` and `6c488338-8eec-4103-ad21-cd461ac2c473` as `Drop`)

#### Scenario: SCN-ITEST-013-2 — HTTPS, Threat-prevention, and NAT rulebase CRUD and policy verification/install tasks

- **WHEN** a write session runs `show-https-rulebase`, `show-threat-rulebase`, `https-rule`/`threat-rule` CRUD, or `verify-policy`/`install-policy`
- **AND** NAT rules/sections run with `"Original"`, `"Any"`, sentinel UIDs (`85c0f50f-6d8a-4528-88ab-5fb11d8fe16c` / `97aeb369-9aea-11d5-bd16-0090272ccb30`), names, or UIDs
- **THEN** the emulator SHALL store normalized sentinel/object UIDs, recompute rule numbers, section `from`/`to` bounds, and `objects-dictionary`
- **AND** it SHALL return updated `show-nat-rule` / `show-*-rulebase` data and Check Point task responses for `verify-policy` and `install-policy`

#### Scenario: SCN-ITEST-013-3 — Post-mutation reads stay consistent across where-used, show-objects, show-object, and inline rulebases

- **WHEN** any group membership or Access/NAT rule cell is mutated in a session overlay or published into domain state
- **THEN** subsequent `where-used` (direct and indirect), `show-objects`, `show-object`, singular `show-*`, and `show-*-rulebase` (`use-object-dictionary=True | False`) calls SHALL immediately reflect the updated references

### Requirement: MDSM Global Domain Visibility, Write Protection, and Policy Assignment

**ID**: REQ-ITEST-014\
**Intent**: Emulate MDSM `Global` object read visibility from local domains, local write refusal, and global policy assignments.\
**Non-goals**: Standalone single-domain object CRUD (`REQ-ITEST-011`).

In MDSM mode, `Global` domain entities SHALL be readable from local domain sessions and visible in rule references, whereas attempts to modify or delete `Global` objects or rules from a local domain session MUST fail with a realistic Check Point read-only / domain-ownership error, and `assign-global-assignment` / `assign-global-policy` SHALL be supported.

#### Scenario: SCN-ITEST-014-1 — Local domain queries resolve Global objects while bulk domain syncs remain domain-scoped

- **WHEN** a local domain (`Branch`, `Perimeter`) queries `show-object`, `show-objects`, singular `show-*`, `where-used`, or `show-*-rulebase` referencing `Global` entities
- **THEN** lookups and `objects-dictionary` SHALL resolve `Global` entities tagged with `"domain": {"uid": "uid-dom-global", "name": "Global", "domain-type": "global domain"}`
- **AND** bulk sync endpoints (`show-hosts`, `show-networks`, `show-groups`, `show-services-*`) SHALL remain scoped strictly to the queried local domain

#### Scenario: SCN-ITEST-014-2 — Local domain sessions cannot modify or delete Global objects or Global rules

- **WHEN** a write session opened on a local domain invokes `set-*` or `delete-*` on a `Global` object, service, group, or Global rule/layer
- **THEN** the emulator SHALL reject the mutation with HTTP `400` (`generic_err_object_read_only` / `err_validation_failed`) without modifying `Global` state
- **AND** a write session opened directly on `"Global"` MAY mutate unreferenced `Global` objects while still enforcing cross-domain referential integrity on deletion

#### Scenario: SCN-ITEST-014-3 — Global policy assignment emulates Check Point task execution and assignment metadata

- **WHEN** a client executes `assign-global-assignment` (or `assign-global-policy`) and `show-global-assignment` / `show-global-assignments`
- **THEN** the emulator SHALL update global assignment metadata for the specified `global-domains` and `dependent-domains`
- **AND** it SHALL return `{"tasks": [...]}` (`wait_for_task=True`) or pollable `task-id` metadata (`wait_for_task=False`)

### Requirement: Fast In-Memory State Snapshot, Restore, and Reset

**ID**: REQ-ITEST-015\
**Intent**: Reset emulator state between test cases in milliseconds without touching disk fixtures.\
**Non-goals**: Live lab revision revert (`REQ-ITEST-005`).

`FileReplayApiMock` and `CheckPointReplayHttpServer` SHALL provide fast in-memory state snapshot, restore, and reset primitives so test suites roll back all domain mutations, active sessions, tasks, and attached CLI overrides between scenarios without re-reading or regenerating disk fixtures.

#### Scenario: SCN-ITEST-015-1 — Snapshot, restore, and reset roll back emulator and CLI state in milliseconds

- **WHEN** a test captures `snap = api_mock.snapshot_state()` (or `/__testing__/snapshot`), mutates domain state or `FileReplayCliMock` overrides, and calls `restore_state(snap)` or `reset()` (or `/__testing__/restore` / `/__testing__/reset`)
- **THEN** all published domain data, MDSM assignments, session bindings, work sessions, `show-changes` history, dynamic tasks, and CLI overrides SHALL revert cleanly in memory with zero disk I/O

### Requirement: SID-Redacted Call Auditing and OpenTelemetry Span Hygiene

**ID**: REQ-ITEST-016\
**Intent**: Give tests structured SID-redacted call logs, scan/global-safety assertions, and end-to-end OTel hygiene verification.\
**Non-goals**: Core telemetry attribute decorator implementation (`REQ-CLIENT-015`).

The emulator SHALL record `sid`-redacted call audit entries (`call_log`), expose test assertion helpers, and propagate provider-agnostic OpenTelemetry spans (`@traced`) without owning a global `TracerProvider` or leaking credentials or raw session IDs.

#### Scenario: SCN-ITEST-016-1 — Enriched call_log and assertion helpers verify domain safety and query efficiency

- **WHEN** tests run workflows against `FileReplayApiMock` or `CheckPointReplayHttpServer` and inspect `call_log` or `get_calls(...)`
- **AND** tests invoke `assert_no_global_mutations()`, `assert_no_full_object_scans()`, `assert_command_called(...)`, or `assert_command_not_called(...)`
- **THEN** every `call_log` entry SHALL record `mgmt_name`, `domain`, `command`, `is_mutating`, `sid_ref` (`"sid#..."`), `session_uid`, `read_only_session`, sanitized `payload`, `payload_summary`, `status_code`, `success`, and `error_code`
- **AND** `call_log` entries SHALL contain zero raw `sid`, `api-key`, or `password` values
- **AND** assertion helpers SHALL raise descriptive failures on any unexpected `Global` mutation or any full-table `show-hosts`, `show-networks`, `show-address-ranges`, or `show-groups` call regardless of pagination flags

#### Scenario: SCN-ITEST-016-2 — OpenTelemetry spans propagate over FileReplayApiMock and CheckPointReplayHttpServer without SID leakage

- **GIVEN** an external host test attaching `InMemorySpanExporter` to its own `TracerProvider`
- **WHEN** `ArodonataClient` runs E2E write, publish, and diff workflows over both `FileReplayApiMock` and `CheckPointReplayHttpServer`
- **THEN** `@traced` spans SHALL record expected span names, `arodonata.*` attributes, and statuses without configuring any global `TracerProvider`
- **AND** zero occurrences of raw `sid`, `X-chkp-sid`, `api-key`, or `password` strings SHALL appear across all span names, attributes, events, and status descriptions

### Requirement: Progressive Runnable SDK Examples Catalog

**ID**: REQ-ITEST-017\
**Intent**: Document every major SDK capability with executable, lab-safe examples including authenticated ASGI MCP embedding.\
**Non-goals**: Core library runtime features covered in feature specs.

The repository SHALL provide a runnable `examples/` catalog demonstrating Arodonata v2 capabilities from basic cached queries to advanced multi-tenant contexts, CPCRUD, change reports, OpenTelemetry tracing, and ASGI MCP embedding, ensuring that embedded MCP examples enforce host or bearer authentication when write tools (`cpcrud=True` or `allow_write_api=True`) are enabled.

#### Scenario: SCN-ITEST-017-1 — Examples cover core and advanced v2 workflows with crash-safe lab guard

- **WHEN** a developer inspects or executes scripts in `examples/`
- **THEN** scripts `01`–`07` SHALL cover basic queries (`01`), search/query (`02`), gateway/VSX relationships (`03`), streaming sync (`04`), rulebases/numbering (`05`), session lifecycle (`06`), and contexts/`SessionOverlay` (`07`)
- **AND** scripts `08`–`13` SHALL cover CPCRUD apply (`08`) and inverse (`09`), change reports (`10`), OTel tracing (`11`), authenticated FastAPI MCP embedding (`12`), and gateway topology/candidate matching (`13`)
- **AND** all mutating examples SHALL wrap execution in `guarded_session` so target lab domains restore automatically on exit

### Requirement: Emulator Repository-Script CRUD and Permission Toggles

**ID**: REQ-ITEST-018\
**Intent**: Emulate Check Point repository-script lifecycle CRUD and session/permission enforcement offline cleanly alongside gateway route-collection scenarios.\
**Non-goals**: Gateway CPRID route-collection execution covered in `REQ-TOPO-018`.

`FileReplayApiMock` and `CheckPointReplayHttpServer` SHALL implement per-domain `add-repository-script`, `show-repository-script`, `show-repository-scripts`, `set-repository-script`, and `delete-repository-script` inside uncommitted staging overlays until `publish`, honoring `allow_one_time_script`, `allow_repository_script`, and `manage_repository_scripts` permission flags.

#### Scenario: SCN-ITEST-018-1 — Emulator enforces repository-script CRUD isolation and permission toggles

- **WHEN** callers run `add/set/delete/show-repository-script(s)` or configure `allow_one_time_script`, `allow_repository_script`, or `manage_repository_scripts` on `FileReplayApiMock`
- **THEN** uncommitted script edits SHALL remain isolated to the writing session until `publish`
- **AND** disabling `manage_repository_scripts` or `allow_repository_script` SHALL reject restricted operations with Check Point permission errors

### Requirement: Replay Emulator Mutation Atomicity, Read-Only Session Guards, and Zero-Disk Reset

**ID**: REQ-ITEST-019\
**Intent**: Ensure the replay mock enforces Check Point `track` wire formats, rolls back failed entity/section mutations, blocks read-only `switch-session` aliasing, and resets strictly in memory.\
**Non-goals**: Base replay CRUD (`REQ-ITEST-011`, `REQ-ITEST-013`) or initial dataset generation (`REQ-ITEST-006`).

`FileReplayApiMock` SHALL enforce per-rulebase `track` wire types (`access` object vs `https`/`threat` string), roll back in-memory overlay mutations on failed entity/section `add`/`set` calls, reject `switch-session`/`set-session`/`discard`/writes on `read_only` bindings while rotating aliased SIDs, and capture clean domain baselines in memory before first mutation so `restore_state()` and `reset()` perform zero disk I/O.

#### Scenario: SCN-ITEST-019-1 — Replay emulator validates track wire types, rolls back failed mutations, and blocks read-only switch-session

- **GIVEN** a `FileReplayApiMock` instance with clean disk fixtures and active read-only and read-write sessions
- **WHEN** a caller sends invalid `track` wire types, triggers a validation error in entity/section `add`/`set`, invokes `switch-session` on a read-only session, or calls `restore_state()`/`reset()` after domain mutations
- **THEN** invalid `track` wire types and read-only `switch-session` calls SHALL be rejected with `err_validation_failed` (rotating any aliased SIDs on valid switches)
- **AND** failed entity/section mutations SHALL leave overlay state unchanged, and `restore_state()`/`reset()` SHALL execute zero disk fixture reads

### Requirement: Single-Pass Reference Collection for Unused Emulator Objects

**ID**: REQ-ITEST-020\
**Intent**: Eliminate quadratic per-object full rulebase and gateway scans in `find_unused_objects` and `delete_unused_objects` while preserving exact cascading fixed-point deletion semantics.\
**Non-goals**: Single-entity `collect_blocking_references` error detail formatting for direct `delete-*` calls (`REQ-ITEST-011`).

`FileReplayApiMock` unused-object inspection and cleanup (`find_unused_objects` and `delete_unused_objects`) SHALL compute referenced UIDs in a single pass per iteration via `collect_referenced_uids()` using O(1) membership lookups instead of scanning all rulebases and gateways for each candidate object.

#### Scenario: SCN-ITEST-020-1 — Unused object lookup and cascading deletion use single-pass reference sets cleanly

- **GIVEN** a mock domain containing referenced objects, nested group chains (`GroupA -> GroupB -> HostX`), rule/gateway references, and unreferenced objects
- **WHEN** `show-unused-objects` (`find_unused_objects`) and `delete-unused-objects` (`delete_unused_objects`) execute
- **THEN** `find_unused_objects()` SHALL scan rulebases and groups once via `collect_referenced_uids()` and return every truly unreferenced local object
- **AND** `delete_unused_objects()` SHALL preserve multi-pass cascading cleanup (removing parent groups first, then newly unreferenced child objects) using one single-pass reference scan per fixed-point iteration

### Requirement: Atomic Emulator Rollback, Aliased SID Rotation, Read-Only Disconnect Guard, and Zero-Disk Mutation Baselines

**ID**: REQ-ITEST-021\
**Intent**: Ensure failed section/group CRUD calls leave overlays clean, `switch-session` isolates aliased SIDs and read-only sessions cannot disconnect peers, and direct-mutation helpers keep `reset()`/`restore_state()` free of disk reads.\
**Non-goals**: Base replay fixture loading (`REQ-ITEST-008`) or rule CRUD semantics (`REQ-ITEST-012`).

`FileReplayApiMock` SHALL roll back failed section `set` and group `add`/`set` mutations atomically (including sibling reverse `groups` links), rotate aliased SIDs on valid `switch-session`, reject read-only `disconnect` calls targeting other sessions, and capture clean baselines before direct domain mutations.

#### Scenario: SCN-ITEST-021-1 — Atomic rollback on failed section set and cross-field group add/set mutations

- **GIVEN** a `FileReplayApiMock` write session executing `set-*-section` with an invalid `new-position` or `add-group`/`set-group` with valid `members` and invalid `groups`
- **WHEN** the command fails validation
- **THEN** original section order/name and all sibling entity `groups` lists in the overlay SHALL remain completely unchanged

#### Scenario: SCN-ITEST-021-2 — Switch-session SID rotation, read-only disconnect rejection, and zero-disk direct-mutation baseline capture

- **GIVEN** two active SIDs aliased onto the same work session, a read-only session invoking `disconnect` on another session UID, or direct `assign-global-assignment` / `update_gateway_interfaces` / `bump_published_session` mutations
- **WHEN** `switch-session`, read-only `disconnect`, or `reset()` / `restore_state()` runs
- **THEN** `switch-session` SHALL rotate other active SIDs onto fresh work sessions, read-only `disconnect` on foreign sessions SHALL fail with HTTP 400, and `reset()` / `restore_state()` SHALL perform zero disk fixture reads


---

### OpenSpec Capability: `mcp-server` (`openspec/specs/mcp-server/spec.md`)

# Model Context Protocol (MCP) Server Specification

## Purpose

Defines the Streamable-HTTP Model Context Protocol server (`arodonata-mcp` CLI and `arodonata.mcp` embeddable ASGI application under `arodonata[mcp]`), authentication and security guards, tool surface (native, cached, structured query/aggregation, rulebase, change report, API reference, and opt-in CPCRUD tools), and prompt templates.

## Requirements

### Requirement: Standalone CLI and Embeddable ASGI Server Modes

**ID**: REQ-MCP-001\
**Intent**: Expose Arodonata securely over Streamable-HTTP MCP in both standalone and embedded ASGI deployments with unified fail-closed security policy, IPv6 support, and Host/Origin checks.\
**Non-goals**: Tool-level domain validation, per-client tool rate limiting (`REQ-MCP-012`), and write-API allowlisting (`REQ-MCP-010`).

The `arodonata.mcp` package SHALL provide `arodonata-mcp`, `create_mcp_server`, and `create_asgi_app`, enforcing unified fail-closed `validate_security_policy()` across all entry points (rejecting wildcards under DNS rebinding protection and unsafe `auth_mode="none"` unless opted in), IPv6 `issuer_url` bracketing, constant-time SHA-256 bearer auth, and `create_asgi_app(mcp_server=...)` parity.

#### Scenario: SCN-MCP-001-1 — Standalone startup validates TLS trust store and auth mode

- **WHEN** `arodonata-mcp` starts up
- **THEN** it SHALL verify the TLS trust store configuration before serving traffic
- **AND** it SHALL exit with code `2` and a clear error if `ARODONATA_MCP_AUTH_MODE=host` or `jwt` (without a verifier) or an invalid ASGI configuration is encountered
- **AND** it SHALL fail closed with exit code `2` when `auth_mode="none"` is paired with non-loopback `--host` (`0.0.0.0`), disabled DNS rebinding protection, non-loopback `allowed_hosts`/`allowed_origins`, or `ALLOWED_HOSTS=*` unless `allow_insecure_unauthenticated=True` (emitting `SECURITY WARNING` once and closing the owned client cleanly)

#### Scenario: SCN-MCP-001-2 — Static bearer token authentication maps token variable name to client_id

- **GIVEN** `ARODONATA_MCP_AUTH_MODE=static` with `ARODONATA_MCP_TOKEN_VARS="TEAM_A_TOKEN,TEAM_B_TOKEN"` or `ARODONATA_MCP_TOKENS` (`c2Vj...=` or `team_a=c2Vj...==`)
- **WHEN** static tokens are parsed and verified
- **THEN** the parser SHALL split on the first `=` or `:` ONLY when the prefix matches `^[A-Za-z_][A-Za-z0-9_-]*$` and the secret is `>= 32` chars (keeping unprefixed base64 whole under a non-secret `client_id` like `token_1`)
- **AND** any secret shorter than 32 characters SHALL raise `ConfigurationError`
- **AND** token comparison SHALL use constant-time SHA-256 digest matching without exposing any secret prefix in `client_id` or `repr()`

#### Scenario: SCN-MCP-001-3 — Embedded JWT mode without token_verifier fails closed on startup

- **WHEN** `create_mcp_server` or `create_asgi_app` is called with `auth_mode="jwt"` and `token_verifier=None`
- **THEN** initialization SHALL raise `ConfigurationError` immediately rather than falling back to unauthenticated access

#### Scenario: SCN-MCP-001-4 — Host authentication mode in embedded ASGI applications

- **WHEN** `create_mcp_server` is called with `auth_mode="host"` for embedding inside an authenticating ASGI host
- **THEN** Arodonata SHALL disable its internal token verifier and rely on the enclosing ASGI host middleware for request authentication

#### Scenario: SCN-MCP-001-5 — DNS rebinding and Origin header protection

- **WHEN** a request arrives with a `Host` header not in `allowed_hosts` (including malformed ports on `host:*` like `localhost:abc`) or a browser `Origin` header not in `allowed_origins`
- **THEN** the server SHALL reject an unlisted or malformed-port `Host` with HTTP `421` and an unlisted `Origin` with HTTP `403`

#### Scenario: SCN-MCP-001-6 — Unified fail-closed security policy rejects unsafe unauthenticated and wildcard configurations across all entry points

- **WHEN** `run_cli`, `create_mcp_server`, or `create_asgi_app` evaluates `validate_security_policy()` on wildcard entries in `allowed_hosts`/`allowed_origins` with `enable_dns_rebinding_protection=True` OR on `auth_mode="none"` paired with non-loopback `host`, disabled DNS rebinding protection, wildcard or non-loopback `allowed_hosts`/`allowed_origins`, `allow_write_api=True`, or `cpcrud=True`
- **THEN** all three entry points SHALL fail closed with `ConfigurationError` (or exit code `2` in CLI) unless `allow_insecure_unauthenticated=True` is explicitly configured for unsafe `auth_mode="none"` (while always permitting loopback read-only `auth_mode="none"` with DNS rebinding protection)

#### Scenario: SCN-MCP-001-7 — IPv6 issuer URL bracketing and create_asgi_app parity prevent split-brain drift

- **WHEN** `create_mcp_server` is constructed with an IPv6 `host` (`"::1"`, `"::"`, `"fe80::1"`) under `auth_mode="static"` or `"jwt"`, OR `create_asgi_app(mcp_server=srv, ...)` is called with an injected server
- **THEN** `AuthSettings.issuer_url` SHALL bracket IPv6 literals cleanly without `ValidationError`
- **AND** `create_asgi_app(mcp_server=srv, ...)` SHALL enforce `validate_security_policy()` on the effective settings and raise `ConfigurationError` whenever runtime overrides (`allow_write_api`, `cpcrud`, `auth_mode`, `client`, conflicting `settings`, `trust_policy`, `token_verifier`, `quota_manager`) conflict with `srv` (while accepting identical `settings`)

### Requirement: Cache-Aligned Tool Surface, Envelopes, and Single-Entity Lookup

**ID**: REQ-MCP-002\
**Intent**: Provide uniform paginated JSON envelopes with cold-cache upgrades and predictable exact/ambiguous/wildcard/substring `show_object` resolution.\
**Non-goals**: Structured SQL-backed aggregation (`REQ-MCP-004`) or cross-domain `get_group_members` (`REQ-MCP-003`).

The MCP server SHALL expose a cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `locate_gateways`, `api_reference`, `change_report`, `api_call`, and opt-in CPCRUD tools) returning consistent cache-backed JSON envelopes and multi-domain `show_object` resolution.

#### Scenario: SCN-MCP-002-1 — List and search tool response envelope includes source, accurate cache age, and cold-cache auto-upgrade

- **WHEN** `list_domains`, `list_objects`, `list_services`, `list_assets`, `search_objects`, or `query_objects` executes
- **THEN** the JSON text response SHALL return `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds` (`null` when no `synced_at` timestamp exists rather than `0.0`), and sliced `objects`
- **AND** when `cache_mode="cache"` runs on an uninitialized scope (`0` sync states for that scope, or `0` cached domain rows for `domains`), it SHALL auto-upgrade to `"smart"`
- **AND** when `mgmt_name` is omitted in `search_objects`, the search SHALL span all configured `mgmt_names` rather than only `mgmt_names[0]`

#### Scenario: SCN-MCP-002-2 — Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0)` runs across `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and cached rulebase layers (`cache_mode="cache"`, including `"Global"` when `domain` is omitted)
- **THEN** an exact non-wildcard match in one domain SHALL return that entity with `match_type="exact"` and full details
- **AND** an exact non-wildcard match across multiple domains when `domain` is omitted SHALL return `match_type="ambiguous"` with `object=None` and candidate `objects`
- **AND** an explicit `*` or `?` wildcard query SHALL evaluate `fnmatchcase` (`match_type="wildcard"`), returning the full object when `total == 1` or a paginated slice when `total > 1`
- **AND** a non-wildcard query with no exact match SHALL return up to `limit` compact case-insensitive substring candidates (`match_type="substring_candidates"`)

### Requirement: Cache-Only Cross-Domain Group Lookup and Ambiguity Reporting in MCP

**ID**: REQ-MCP-003\
**Intent**: Avoid expensive multi-domain logins when MCP clients inspect a group name without specifying a domain.\
**Non-goals**: Underlying `SearchService` group ambiguity rules (`REQ-CACHE-014`).

When `get_group_members` is called without `domain` (and `group_name_or_uid` is not a `mgmt:domain:name` composite ID), the MCP server SHALL resolve the target group across cached domains including `"Global"` using `cache_mode="cache"` without triggering whole-MDS logins, and SHALL return a structured `match_type="ambiguous"` candidate response when matching groups exist in more than one domain.

#### Scenario: SCN-MCP-003-1 — Cross-domain MCP get_group_members reports ambiguity without whole-MDS sync

- **GIVEN** a cache where `"SharedAdmins"` exists in multiple cached domains
- **WHEN** `get_group_members(group_name_or_uid="SharedAdmins")` is invoked without `domain`
- **THEN** the tool SHALL perform zero remote domain refreshes
- **AND** it SHALL return `match_type="ambiguous"` with candidate domain and composite-ID entries for caller disambiguation

### Requirement: Structured Object Querying, Aggregation, and Type/Field Alias Normalization

**ID**: REQ-MCP-004\
**Intent**: Give MCP agents fast parameterized filtering, counting, and schema discovery with consistent field and `Cpmi*` asset aliases.\
**Non-goals**: Single-entity text search (`REQ-MCP-002`).

`query_objects` (`aggregate="list" | "count" | "describe"`) SHALL support parameterized filtering, grouping, and counting across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` without raw SQL, normalizing `group_by` field aliases and expanding short asset type aliases to Check Point `Cpmi*` classes case-insensitively across `list_assets`, `search_objects`, and `query_objects`.

#### Scenario: SCN-MCP-004-1 — Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` (or with `group_by=["domain", "type"]` and `types=["cluster", "vsx", "vs"]`) is called
- **THEN** the tool SHALL run a parameterized cached query distinguishing domain-owned vs `Global` objects via `original_domain`
- **AND** it SHALL return grouped counts in one response, populating both requested alias keys and canonical keys when an alias is used

#### Scenario: SCN-MCP-004-2 — Progressive-disclosure schema description via query_objects

- **WHEN** `query_objects(mgmt_name=..., domain=..., aggregate="describe")` is called (defaulting to `cache_mode="smart"`)
- **THEN** if the target `scope="objects"` has `0` sync states (even if partial topology objects exist) and `cache_mode != "cache"`, it SHALL warm `arodonata_objects` first
- **AND** it SHALL return available domains, management servers, per-type object/service/asset counts, and filterable/groupable field lists

#### Scenario: SCN-MCP-004-3 — Field and asset type aliases normalize consistently across query and search tools

- **WHEN** callers supply `group_by` aliases (`domain` -> `domain_name`, `mgmt`/`server`/`management` -> `mgmt_name`, `object_type`/`asset_type`/`service_type` -> `type`, `orig_domain` -> `original_domain`)
- **AND** callers pass short asset types (`gateway`, `cluster`, `member`, `vsx`, `vs`, `server`) to `list_assets`, `search_objects`, or `query_objects`
- **THEN** the server SHALL normalize field names case-insensitively across `list_assets`, `search_objects`, and `query_objects`
- **AND** it SHALL expand short types to Check Point `Cpmi*` classes (`CpmiGatewayPlain`, `CpmiGatewayCluster`, `CpmiClusterMember`, `CpmiVsxClusterMember`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`, `CpmiHostCkp`)

### Requirement: Unified Cache Status and Scoped Refresh Control Tool

**ID**: REQ-MCP-005\
**Intent**: Give MCP agents visibility into cache freshness and controlled refresh execution across all scopes.\
**Non-goals**: Background warm-up coalescing in Python client code (`REQ-CLIENT-002`).

The `arodonata[mcp]` server SHALL expose `cache_control` (`action="status" | "refresh"`) reporting per-domain and per-`item_type` freshness (`last_published_at`, `last_session_uid`, `synced_at`, `cache_age_seconds`) from `arodonata_domain_sync_state` and triggering scoped synchronization across `"domains"`, `"objects"`, `"services"`, `"assets"`, `"rulebase"`, and `"topology"` (with `gateways` and `collect_routes`).

#### Scenario: SCN-MCP-005-1 — Cache status inspection and refresh across core and topology scopes

- **WHEN** `cache_control(mgmt_name=..., action="status")` or `cache_control(mgmt_name=..., domain=..., action="refresh", scope="objects" | "topology", gateways=..., collect_routes=...)` is called
- **THEN** `action="status"` SHALL return per-domain and per-`item_type` status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across all six scopes
- **AND** `action="refresh"` SHALL synchronize the requested scope (forwarding `gateways` and `collect_routes` for `"topology"`), returning `RefreshOutcome` (or `{"scope": "domains", "mgmt_name": ..., "refreshed_count": ..., "domains": [...]}` for `scope="domains"`)

### Requirement: Rulebase Inspection and Local Filtering Tool

**ID**: REQ-MCP-006\
**Intent**: Allow MCP agents to inspect package catalogs and filter SmartConsole rulebases offline while falling back to live API for live-only flags.\
**Non-goals**: Underlying hierarchical rule numbering (`REQ-RULE-004`).

`show_rulebase` SHALL inspect cached rulebase catalogs (`arodonata_rulebase_package_layer`, `arodonata_rulebase_layer`) and evaluate local filters against fresh snapshots (`markdown`, `model_friendly`, `raw`, or `cpcrud` format), switching to live Management API queries when `cache_mode="live"` or live-only parameters are requested.

#### Scenario: SCN-MCP-006-1 — Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_rulebase(mgmt_name=..., domain=..., rulebase_type="access" | "nat" | "https" | "threat", ...)` is called
- **THEN** when `package` and `layer` are omitted (or the requested target is not in cache), it SHALL return the domain's cached `packages` and `layers` (including inline layers, parent links, and `implicit_cleanup_action`)
- **AND** when a valid `package` or `layer` has a fresh snapshot without live-only flags, it SHALL filter locally in `markdown`, `model_friendly`, `raw`, or `cpcrud` format
- **AND** `cache_mode="live"` or live-only flags (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`, `hits_settings`, `dereference_group_members`, `show_membership`) SHALL query the live rulebase API
- **AND** live queries SHALL call `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase`

### Requirement: Affected Gateway Discovery Tool

**ID**: REQ-MCP-007\
**Intent**: Expose Check Point affected-gateway and policy-package flow matching directly as an MCP tool.\
**Non-goals**: Internal LPM and evidence-delta confidence math (`REQ-TOPO-011`..`REQ-TOPO-014`).

The `arodonata[mcp]` server SHALL expose `locate_gateways(sources, destinations, mgmt_name=..., domain=..., min_confidence=..., include_standby=..., include_policy_inferred=..., cache_mode="smart")` returning affected Check Point gateways, domains, policy packages, matched interfaces, delta-based `confidence` scores, `confidence_factors`, `is_standby_path` flags, and `topology_warnings`.

#### Scenario: SCN-MCP-007-1 — MCP client locates candidate gateways and policy packages for a traffic flow

- **WHEN** an MCP client invokes `locate_gateways(sources=["10.10.1.5"], destinations=["172.16.20.10"], mgmt_name="mds1", include_policy_inferred=True)`
- **THEN** the tool SHALL return affected gateways (both cross-interface L3 matches and `policy_inferred` matches when enabled)
- **AND** each candidate SHALL include `domain_name`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, and `confidence_factors`
- **AND** each candidate SHALL include per-flow `(src_interface -> dst_interface)` matches, `include_policy_inferred`, and `topology_warnings`

### Requirement: Unified Progressive-Disclosure MCP API Reference Tool

**ID**: REQ-MCP-008\
**Intent**: Keep LLM agent context lean by consolidating Check Point API command search, schema inspection, and payload validation into one tool.\
**Non-goals**: Direct Web API execution (`REQ-MCP-010`).

The `arodonata[mcp]` server SHALL expose a consolidated `api_reference` tool (`action="search" | "describe" | "validate"`, inferring `version` from `mgmt_name` when omitted) so clients can search commands, inspect version-filtered parameters, nested objects, and examples, and validate payloads offline before calling `api_call`.

#### Scenario: SCN-MCP-008-1 — Two-step MCP discovery and payload validation via api_reference tool

- **WHEN** an MCP client calls `api_reference` for `action="search"` (`query="host"`, `crud_type="add"`), `action="describe"` (`command="add-host"`, `version="v2.2"`), and `action="validate"` (`"add-host"`, `{"name": "web-01", "ip-address": "192.0.2.10"}`)
- **THEN** `action="search"` SHALL return compact matching summaries, `action="describe"` SHALL return the `v2.2` field schema, `field_alternatives`, `nested_objects`, and example, and `action="validate"` SHALL return `valid=True` with `errors=[]`

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

**ID**: REQ-MCP-009\
**Intent**: Prevent LLM-tampered plans or cross-caller/foreign session takeovers when write-capable CPCRUD tools are enabled on the MCP server.\
**Non-goals**: Direct Python SDK staged-session adoption options (`REQ-CPCRUD-011`).

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify caller-bound HMAC plans in `cpcrud_apply`/`cpcrud_inverse`, omit `force`/`validate_schema`/`server_ip`, cap `retry_remaining` (`<= 3`), isolate `plan_store`, `last_report`, and `staged_session_store` by resolved caller identity (`client_id[:user_id]`), and discard+logout evicted staged sessions on capacity overflow.

#### Scenario: SCN-MCP-009-1 — Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` receives an unknown `plan_id` or a `plan` whose signature fails or whose `command` / `object_type` / `payload` was altered after `cpcrud_plan`
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: SCN-MCP-009-2 — Staged CPCRUD session published or discarded via dedicated MCP tools

- **GIVEN** a session staged by `cpcrud_apply(..., no_publish=True, keep_session=True)` and registered under `(mgmt_name, domain_key, session_uid)` in this server process
- **WHEN** `cpcrud_staged_session(session_uid=..., action="publish" | "discard", mgmt_name=..., domain=...)` is called
- **THEN** the tool SHALL verify `session_uid` is in this server's staged registry and adopt it non-disruptively without exposing `server_ip` or `force_disconnect`
- **AND** it SHALL publish (invalidating the domain cache) or discard uncommitted changes, remove the registry entry, and log out cleanly

#### Scenario: SCN-MCP-009-3 — Unregistered or foreign session UID rejected by cpcrud_staged_session

- **WHEN** `cpcrud_staged_session` is called with a `session_uid` not created by `cpcrud_apply(..., no_publish=True, keep_session=True)` in this MCP server instance (such as a human administrator's SmartConsole UID)
- **THEN** `cpcrud_staged_session` SHALL raise `ToolFailure` immediately without opening a Check Point session or calling `take-over-session`, `switch-session`, `publish`, or `discard`

#### Scenario: SCN-MCP-009-4 — CPCRUD plans, ApplyReports, and staged sessions isolate per caller and discard cleanly on eviction

- **GIVEN** two authenticated MCP callers (`TEAM_A` and `TEAM_B`) sharing one server instance
- **WHEN** `TEAM_A` creates a CPCRUD `plan`, `ApplyReport`, or staged session, and `TEAM_B` attempts to reference `TEAM_A`'s `plan_id`, replay `TEAM_A`'s signed `plan`, read `TEAM_A`'s `last_report` in `cpcrud_inverse`, or publish/discard `TEAM_A`'s `session_uid`, OR when `staged_session_store` exceeds `MAX_STORED_PLANS`
- **THEN** all cross-caller plan and staged-session accesses SHALL fail before executing Check Point API calls
- **AND** capacity eviction of an oldest staged session SHALL discard uncommitted changes, log out its session cleanly, and emit a SID-redacted `WARNING` audit log

### Requirement: Domain Pre-Validation, Write API Guardrails, and SID-Redacted Tool Failures

**ID**: REQ-MCP-010\
**Intent**: Give callers actionable domain-validation errors, block unauthorized `api_call` writes, and keep `sid`s out of all MCP failures.\
**Non-goals**: Transport-level command-name validation (`REQ-TRANS-001`) or ASGI auth (`REQ-MCP-001`).

MCP tools SHALL pre-validate explicit `domain` arguments against `arodonata_domains`, return actionable `ToolFailure` responses on unknown domains or `InvalidCredentialsError`, restrict `api_call` to a read-only allowlist unless `ARODONATA_MCP_ALLOW_WRITE_API=true` (running allowed writes in isolated dedicated sessions), and redact active `sid` values and secrets from all error messages.

#### Scenario: SCN-MCP-010-1 — Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** a tool is called with a `domain` absent from `arodonata_domains` (after one domain-list refresh) or login raises `InvalidCredentialsError`
- **THEN** the server SHALL log the `ToolFailure` at `WARNING` without arguments or secrets
- **AND** it SHALL return an actionable error listing known domains on that management server rather than `"internal error: InvalidCredentialsError"`

#### Scenario: SCN-MCP-010-2 — Write API protection and SID masking on error

- **WHEN** `api_call` is invoked with `ARODONATA_MCP_ALLOW_WRITE_API=false`, or with a write command while `ARODONATA_MCP_ALLOW_WRITE_API=true`, or when an error contains an active or just-closed dedicated session SID (including `LoginCoordinator.active_dedicated_sids`)
- **THEN** with `ALLOW_WRITE_API=false`, `api_call` SHALL permit ONLY explicit read-only allowlisted commands (rejecting traversal, writes, `publish`, `discard`, `logout`, and unlisted commands)
- **AND** with `ALLOW_WRITE_API=true`, mutating `api_call` calls SHALL run in an isolated dedicated session (never shared `arodonata_sid_cache`) with bounded `timeout`
- **AND** any active or dedicated `sid` collected via `ArodonataClient.get_active_dedicated_sids()` or tracked by `api_call` SHALL be redacted before logging or returning to the MCP client

### Requirement: Built-In MCP Domain Prompt Templates

**ID**: REQ-MCP-011\
**Intent**: Provide reusable workflow prompts guiding LLM clients to combine Arodonata read, topology, change-report, and API-reference tools effectively.\
**Non-goals**: Underlying MCP tool execution (`REQ-MCP-002`..`REQ-MCP-010`).

The `arodonata[mcp]` server (`arodonata.mcp.prompts`) SHALL register four reusable MCP prompt templates (`audit_access_rulebase`, `investigate_ip_exposure`, `summarize_recent_changes`, `lookup_api_command`) returning structured user-role guidance tailored to optional domain, package, IP, and command arguments.

#### Scenario: SCN-MCP-011-1 — MCP server registers all four domain workflow prompts with argument substitution

- **WHEN** `register_prompts(mcp)` registers prompt templates on a server (via `create_mcp_server`)
- **THEN** `audit_access_rulebase`, `investigate_ip_exposure`, `summarize_recent_changes`, and `lookup_api_command` SHALL be registered and callable
- **AND** invoking each prompt with domain, package, IP, or command arguments SHALL interpolate those parameters into workflow instructions without touching the network or database

### Requirement: Per-Client MCP Tool Rate Limiting and Quota Isolation

**ID**: REQ-MCP-012\
**Intent**: Protect management servers and cache databases from abusive tool bursts with independent per-caller sliding-window throttling.\
**Non-goals**: HTTP transport DNS rebinding protection (`REQ-MCP-001`).

The `arodonata.mcp` server SHALL enforce per-caller (`client_id[:user_id]` or `"anonymous"`) sliding-window quotas via `MCPToolQuotaManager` inside `mcp_tool_guard` and deferred live-sync checks (charging both explicit live calls and cold/stale `smart` syncs against `live` quota while keeping warm cache hits on `general` quota), returning protected `rate_limit_exceeded` JSON `ToolFailure` responses without secret leakage.

#### Scenario: SCN-MCP-012-1 — Independent per-client tool throttling emits audit warning, span attrs, and structured rejection without secret leakage

- **WHEN** a caller (`client_id` from `UserContext` or `"anonymous"`) invokes MCP tools exceeding `tool_rate_limit_per_minute` or `live_tool_rate_limit_per_minute`
- **THEN** `mcp_tool_guard` SHALL reject only the exhausted caller (leaving other clients unaffected) with `is_error=True` and JSON `error_code="rate_limit_exceeded"` + positive `retry_after_seconds`
- **AND** live-bucket rejections SHALL NOT consume general quota, quotas SHALL recover cleanly after sliding-window expiry, `0` SHALL disable enforcement, and `arlogi` `WARNING` logs + `arodonata.mcp_rate_limited` span attributes SHALL never expose bearer tokens or SIDs

#### Scenario: SCN-MCP-012-2 — Composite caller identity isolation and deferred smart-sync live quota enforcement

- **WHEN** distinct `user_id` principals share one OAuth `client_id`, OR read tools execute in `cache_mode="smart"` across cold/stale syncs vs warm cached hits, OR domain pre-validation / `show_object` triggers a live fallback call
- **THEN** quota accounting SHALL isolate `client_id:user_id` pairs independently, charge cold/stale syncs, domain-miss refreshes, and `show_object` live fallbacks to `live` quota once per invocation, and keep warm `smart`/`cache` hits strictly on the `general` quota

### Requirement: Cache-Only Domain Pre-Validation Without Live Refresh or Quota Charge

**ID**: REQ-MCP-013\
**Intent**: Keep MCP tool calls using `cache_mode="cache"` (or `mode="cache"`) free of forced live domain discovery calls and live quota charges during domain pre-validation.\
**Non-goals**: Smart-mode domain-miss refresh fallback (`REQ-MCP-010`) or rate-limit bucket accounting (`REQ-MCP-012`).

When an MCP tool is invoked with `cache_mode="cache"` or `cache_control(action="refresh", mode="cache")` (with or without explicit `mgmt_name`), domain pre-validation and refresh routing SHALL inspect cached `arodonata_domains` rows only without invoking live `show-domains` refreshes or consuming `live` quota slots.

#### Scenario: SCN-MCP-013-1 — Cache-only multi-server and single-server domain pre-validation performs zero live calls or quota charges

- **GIVEN** single- or multi-management MCP configuration where one or more servers have an empty `arodonata_domains` cache while another server has cached domains and initialized objects
- **WHEN** `locate_gateways(..., cache_mode="cache")`, `cache_control(action="refresh", mode="cache", ...)`, or `query_objects(..., cache_mode="cache", domains=[...])` runs domain pre-validation and tool execution (with or without `mgmt_name`)
- **THEN** the invocation SHALL execute zero live `get_domains(cache_mode="force")` or `show-domains` API calls and charge zero `live` quota slots
- **AND** when cached domains are present for the evaluated server(s) and do not contain the requested domain, pre-validation SHALL fail with `ToolFailure` listing the cached known domains

### Requirement: Bounded Multi-Domain Fan-Out Quota Charging and Slot Rollback

**ID**: REQ-MCP-014\
**Intent**: Allow a single full-MDS `cache_control` refresh per idle window at default rate limits while rejecting oversize explicit fan-out calls cleanly without leaking quota slots.\
**Non-goals**: Base per-caller sliding-window rate-limit enforcement (`REQ-MCP-012`) or offline domain pre-validation (`REQ-MCP-013`).

When `live_tool_rate_limit_per_minute > 0`, implicit all-domain `cache_control(action="refresh")` (`domain=None`, `domains=None`) SHALL cap single-call live cost at `live_tool_rate_limit_per_minute` on an empty live bucket, while explicit `cache_control(domains=...)` or `change_report(scopes=...)` requests exceeding `live_tool_rate_limit_per_minute` SHALL fail upfront with `error_code="rate_limit_exceeded"`, zero consumed quota slots, and batching guidance.

#### Scenario: SCN-MCP-014-1 — Implicit all-domain cache_control refresh succeeds once per idle window when domain count exceeds live_tool_rate_limit_per_minute

- **GIVEN** a management server with more cached domains (e.g., `40`) than `live_tool_rate_limit_per_minute` (e.g., `30`) and an empty caller `live` quota bucket
- **WHEN** the caller invokes `cache_control(action="refresh", scope="objects")` with `domain=None` and `domains=None`
- **THEN** single-call live quota consumption SHALL cap at `live_tool_rate_limit_per_minute` so the refresh executes once on the idle bucket
- **AND** any second live tool call within the same 60-second window SHALL be rejected with `error_code="rate_limit_exceeded"`

#### Scenario: SCN-MCP-014-2 — Explicit multi-domain or multi-scope fan-out exceeding per-minute live limit rejects upfront without leaking general or live slots

- **GIVEN** `live_tool_rate_limit_per_minute` set to `L > 0`
- **WHEN** a caller invokes `cache_control(action="refresh", domains=[...])` or `change_report(scopes=[...])` with explicit fan-out count `C > L` (or a multi-unit fan-out exceeding remaining live slots)
- **THEN** the server SHALL reject the call with `is_error=True`, `error_code="rate_limit_exceeded"`, and actionable guidance to pass batches of `<= L` items when `C > L` (with `retry_after_seconds=0.0` rather than a misleading retry timer)
- **AND** neither `general` nor `live` quota slots SHALL remain consumed by the rejected invocation

### Requirement: Stalest-Scope Cache Age Reporting Across Multi-Scope Queries

**ID**: REQ-MCP-015\
**Intent**: Prevent multi-scope MCP queries from understating data staleness when combined scopes were synchronized at different times.\
**Non-goals**: Single-scope `list_*` envelope pagination (`REQ-MCP-002`).

When `query_objects` or `search_objects` evaluates cached entities across multiple cache scopes (`objects`, `services`, `assets`), the returned `cache_age_seconds` envelope field SHALL report the maximum (`max`) age across all touched scopes that have a persisted `synced_at` timestamp (or `null` when none are synchronized).

#### Scenario: SCN-MCP-015-1 — Multi-scope query_objects and search_objects report maximum cache_age_seconds across touched scopes

- **GIVEN** `objects` synchronized `7200` seconds ago and `services` (or `assets`) synchronized `120` seconds ago on the same domain
- **WHEN** `query_objects(types=["host", "service-tcp"], cache_mode="cache")` or `search_objects(query="gw", types=["host", "gateway"], cache_mode="cache")` executes
- **THEN** the response envelope `cache_age_seconds` SHALL reflect the stalest touched scope (`>= 7200` seconds) rather than only the first or last scope evaluated

### Requirement: Pre-Validation Fan-Out Quota Ordering, Unified Multi-MDS Scoping, Stalest Cache Age, and Guardrail Hardening

**ID**: REQ-MCP-016\
**Intent**: Enforce explicit fan-out quota before live domain discovery, unify multi-MDS scope resolution, report true stalest cache ages, harden error guards and staged SID/plan isolation, and fix typed `show_object` and `show_rulebase` bounds.\
**Non-goals**: `REQ-MCP-004` `group_by` asset routing in `query_objects` (tracked separately).

MCP tools SHALL charge explicit fan-out quotas before live domain pre-validation, unify multi-MDS scope validation across `search_objects` and siblings, report `min(synced_at)` stalest ages, guard error-handler cache lookups, protect staged SIDs and `plan_store`, handle typed UUID/`Cpmi*` `show_object` calls, and clamp cached `show_rulebase` paging.

#### Scenario: SCN-MCP-016-1 — Upfront fan-out quota rejection, unified multi-MDS scoping, and stalest cache_age_seconds

- **GIVEN** an oversize `cache_control(domains=...)` / `change_report(scopes=...)` fan-out, a multi-MDS `search_objects(mgmt_name=None, domain=...)` call, or multi-type/multi-domain caches with differing `synced_at` ages
- **WHEN** the MCP tool validates quota, resolves management scope, or computes `cache_age_seconds`
- **THEN** oversize fan-out SHALL fail quota checks BEFORE executing live `show-domains` pre-validation (probing failing servers at most once per call)
- **AND** `search_objects` SHALL span all configured servers when `mgmt_name` is omitted, and `cache_age_seconds` SHALL report the stalest (`min(synced_at)`) age across touched scopes, domains, and item types

#### Scenario: SCN-MCP-016-2 — Defensive error-guard lookups, staged SID redaction, and owner-fair plan_store eviction

- **GIVEN** an uninitialized cache DB during offline `api_reference` `ValidationError`, an exception during `cpcrud_staged_session`, or >256 `cpcrud_plan` calls by a second caller
- **WHEN** `mcp_tool_guard` handles the error or `cpcrud` tools manage staged SIDs and stored plans
- **THEN** `mcp_tool_guard` SHALL never leak unhandled `OperationalError` (and offline `api_reference` errors SHALL skip domain cache queries)
- **AND** `cpcrud_staged_session` SHALL register `stored_staged.sid` before execution, and `plan_store` SHALL evict same-owner entries first before cross-caller entries

#### Scenario: SCN-MCP-016-3 — Typed UUID live show_object lookups, Cpmi*/underscore type normalization, and clamped cached show_rulebase

- **GIVEN** a typed UUID `show_object(uid_or_name=<uuid>, obj_type='host')`, `obj_type='CpmiGatewayCluster'` / `'simple_gateway'`, or cached `show_rulebase(offset=-2, limit=100000)`
- **WHEN** `show_object` or `show_rulebase` executes
- **THEN** `live_show_object` SHALL send `uid` rather than `name` for UUIDs and `validate_show_object_type` SHALL normalize `Cpmi*`/underscore aliases safely
- **AND** cached `show_rulebase` SHALL clamp `offset >= 0` and `1 <= limit <= 500`

### Requirement: Accurate Tool Naming Hints, Multi-Domain Cold Upgrade, Asset Classification MCP Filters, and Peer-Safe Staged Registry

**ID**: REQ-MCP-017\
**Intent**: Keep MCP error hints accurate to consolidated tool names, evaluate multi-domain `domains` cold-cache upgrades reliably, expose asset role/platform filtering on MCP tools alongside shared list helpers, and prevent third-caller staged session exhaustion of peer callers.\
**Non-goals**: Initial MCP quota enforcement (`REQ-MCP-016`) or HMAC plan verification (`REQ-MCP-009`).

MCP error hints SHALL reference `list_domains` rather than `show_domains`, `_upgrade_uninitialized_cache_mode()` SHALL evaluate multi-domain `domains` scopes, `list_assets`/`query_objects` SHALL expose role/platform classification filters alongside shared typed-list execution, and `staged_session_store` SHALL protect single-session peers.

#### Scenario: SCN-MCP-017-1 — Accurate list_domains guidance, multi-domain cold-cache upgrade, asset role/platform MCP filters, and owner-fair staged session capacity

- **GIVEN** empty cached domain errors, a multi-domain `domains` list containing an uncached domain under `cache_mode="cache"`, `list_objects`/`list_services`/`list_assets`/`query_objects` classification queries, or a saturated `staged_session_store`
- **WHEN** `format_invalid_credentials_failure()`, `_upgrade_uninitialized_cache_mode()`, object/asset tools, or `_store_staged_session()` executes
- **THEN** credential errors SHALL instruct callers to run `list_domains`, `_upgrade_uninitialized_cache_mode()` SHALL upgrade when any requested domain is cold, `list_assets` and `query_objects` SHALL filter by `roles`/`platforms` (and target flags on `query_objects`), and `_store_staged_session()` SHALL evict greedy multi-slot owners first or discard and fail cleanly rather than evicting single-session peers


---

### OpenSpec Capability: `rulebase-and-numbering` (`openspec/specs/rulebase-and-numbering/spec.md`)

# Rulebase Introspection, Caching, and Numbering Specification

## Purpose

Defines multi-domain rulebase snapshot caching (`RulebaseRefreshService`, `DomainSyncCoordinator`), continuity-verified rulebase pagination (`fetch_paged_rulebase`), SmartConsole-accurate hierarchical rule numbering (`CachedRulebaseSource`, `number_package_rulebase`, `number_layer_rulebase`), and package/layer introspection APIs (`get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`, `filter_rulebase`).

## Requirements

### Requirement: Session-Aware Atomic Rulebase Snapshot Refresh

**ID**: REQ-RULE-001\
**Intent**: Keep cached domain rulebases internally consistent and protected against dirty-session reads or partial writes.\
**Non-goals**: Lightweight package-only or single-package synchronization slices (`REQ-RULE-002`, `REQ-RULE-003`).

`RulebaseRefreshService` (`refresh_rulebases`, `stream_refresh_rulebases`) SHALL refresh a domain's `arodonata_rulebase_*` snapshot and `arodonata_domain_sync_state` (`scope="rulebase"`) in one atomic transaction under a per-domain distributed lock with heartbeat renewal, tracking freshness via the last published session UID and preserving `last_published_at=None` for never-published domains.

#### Scenario: SCN-RULE-001-1 — Refusal to refresh when shared session is dirty

- **GIVEN** a domain whose shared API session holds unpublished changes or locks (`number-of-published-changes` / `locks` non-zero) or where `show-session` fails
- **WHEN** `refresh_rulebases` runs for that domain
- **THEN** the refresh SHALL refuse to proceed (failing closed on `show-session` error) and preserve any existing cached rulebase snapshot
- **AND** `arodonata_domain_sync_state.status` (`scope="rulebase"`) SHALL be recorded as `"failed"` with `sid`-redacted `last_error`

#### Scenario: SCN-RULE-001-2 — Complete traversal of packages, ordered layers, inline layers, and global placeholders

- **GIVEN** a clean domain session under a renewed per-domain distributed lock
- **WHEN** `refresh_rulebases` fetches the domain's rulebases
- **THEN** it SHALL fetch `show-packages`, the NAT rulebase of every package with `nat-policy`, and every access, HTTPS, and threat layer reachable from packages, layer listings, or inline-layer references
- **AND** for any global layer containing a domain `place-holder`, it SHALL query the global layer with `package` context to resolve the parent rule and nested domain layer
- **AND** it SHALL replace the domain's rows across `arodonata_rulebase_*` and update `arodonata_domain_sync_state` in a single atomic transaction

#### Scenario: SCN-RULE-001-3 — Rulebase pager merges split sections across page boundaries

- **GIVEN** Check Point `show-*-rulebase` pagination in chunks of up to 100 rules where a `rulebase-section` header repeats across consecutive pages
- **WHEN** `fetch_paged_rulebase()` fetches the rulebase
- **THEN** it SHALL merge the split section into a single section entry containing all of its rules in order
- **AND** it SHALL recover empty trailing sections

### Requirement: Lightweight Policy Package Catalog Synchronization

**ID**: REQ-RULE-002\
**Intent**: Allow fast listing of policy packages without downloading full domain rulebases.\
**Non-goals**: Synchronizing rulebase layers or rules (`REQ-RULE-001`, `REQ-RULE-003`).

The rulebase service SHALL synchronize and return policy package metadata (`get_policy_packages`, `refresh_policy_packages`) using a package-only synchronization slice (`scope="rulebase"`, `item_type="packages"`) when the full domain rulebase snapshot (`item_type="*"`) is not yet fresh, querying `show-packages` without downloading NAT, HTTPS, threat-prevention, or access rulebases.

#### Scenario: SCN-RULE-002-1 — Cold-cache get_policy_packages queries show-packages without fetching rulebases

- **GIVEN** a domain whose `scope="rulebase"` cache has neither a fresh `"*"` snapshot nor a fresh `"packages"` slice
- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs
- **THEN** the system SHALL verify the shared session is clean under the domain lock and fetch `show-packages`
- **AND** it SHALL atomically replace package-catalog metadata and update `item_type="packages"` sync state without stamping `item_type="*"`
- **AND** it SHALL execute zero `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase` calls

#### Scenario: SCN-RULE-002-2 — Fresh full rulebase snapshot satisfies get_policy_packages from cache

- **GIVEN** a domain whose full `scope="rulebase"`, `item_type="*"` snapshot already matches the domain's published session head
- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs
- **THEN** the system SHALL return the cached `PolicyPackageInfo` list without issuing `show-packages` again

### Requirement: Targeted Single-Package Rulebase Synchronization

**ID**: REQ-RULE-003\
**Intent**: Avoid downloading unrelated policy packages and rulebases when inspecting one target package.\
**Non-goals**: Cross-package full-domain `locate_rules` indexing (`REQ-RULE-001`, `REQ-RULE-004`).

When `get_package_rulebase` or `refresh_package_rulebase` runs with `cache_mode != "cache"` without a fresh `item_type="*"` snapshot, it SHALL evaluate slice-scoped invalidation (`scope="rulebase"`, `item_type="package:<rulebase_type>:<package_uid>"`, `synced_at`), honor `cache_ttl` once synced, and sync only the target package catalog and reachable layers.

#### Scenario: SCN-RULE-003-1 — Cold-cache access rulebase read for one package skips NAT, HTTPS, Threat, and sibling packages

- **GIVEN** a domain containing multiple policy packages, NAT policies, HTTPS layers, threat layers, and standalone layers
- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package="Branch_Pkg", rulebase_type="access", cache_mode="smart")` runs
- **THEN** the system SHALL fetch only package metadata, the ordered access layers of `"Branch_Pkg"`, any Global placeholder expansion in `"Branch_Pkg"` context, and referenced inline access sub-layers
- **AND** it SHALL persist those layers and record `item_type="package:access:<package_uid>"` without stamping `item_type="*"`
- **AND** it SHALL return SmartConsole-numbered sections and rules identical to a full domain snapshot

#### Scenario: SCN-RULE-003-2 — Locate rules still requires or triggers full domain rulebase snapshot

- **GIVEN** a domain where only a targeted `item_type="package:access:<package_uid>"` slice is cached
- **WHEN** `locate_rules(mgmt_name, domain_name, ...)` or `refresh_rulebases(...)` runs
- **THEN** the system SHALL treat `item_type="*"` as unsynced until a full domain rulebase snapshot completes so cross-package rule location never omits sibling packages

#### Scenario: SCN-RULE-003-3 — Single-package rulebase refresh honors cache_ttl once domain invalidation is satisfied

- **GIVEN** a domain previously marked invalidated via `invalidate_domain(mgmt_name, domain)` followed by a completed `refresh_package_rulebase(..., package="Branch_Pkg", rulebase_type="access")`
- **WHEN** a subsequent `refresh_package_rulebase` runs within `cache_ttl` in `"smart"` or `"smart-fast"` mode for that same package slice
- **THEN** invalidation checking SHALL compare the target `(scope="rulebase", item_type="package:access:<package_uid>")` `synced_at` timestamp instead of treating domain invalidation as permanent
- **AND** the refresh SHALL honor `cache_ttl` and skip remote rulebase probes until `cache_ttl` expires or a newer invalidation occurs

### Requirement: SmartConsole-Identical Hierarchical Rule Numbering

**ID**: REQ-RULE-004\
**Intent**: Produce SmartConsole-exact rule numbers and cross-package positions from cached snapshots.\
**Non-goals**: Fetching rulebases from Check Point (`REQ-RULE-001`..`REQ-RULE-003`) or filtering rules (`REQ-RULE-005`).

`arodonata.rulebase` (`CachedRulebaseSource`, `number_package_rulebase`, `number_layer_rulebase`) SHALL compute hierarchical rule and section numbers (`1`, `2`, `2.1`, `2.2.1`, section ranges `2.1-2.2`, or `No Rules`) dynamically from the domain's cached rulebase snapshot so that numbers match SmartConsole display both in package context (`get_package_rulebase`) and standalone layer context (`get_layer_rulebase`).

#### Scenario: SCN-RULE-004-1 — Package rulebase numbering expands global placeholders and inline layers

- **GIVEN** a policy package whose rulebase includes a Global layer with a `place-holder` and rules calling inline layers
- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package, rulebase_type="access")` is called
- **THEN** the returned `PackageRulebase` SHALL number top-level rules sequentially (`1`, `2`, ...)
- **AND** it SHALL expand the domain layer under the global placeholder's parent rule with dotted numbers (`2.1`, `2.2`, ...)
- **AND** it SHALL expand inline layers beneath their calling rule (`2.2.1`, ...)

#### Scenario: SCN-RULE-004-2 — Locate rules across all packages and layers of a domain

- **WHEN** `locate_rules(mgmt_name, domain_name, rule_uids=[...], layer_uids=[...])` is called
- **THEN** it SHALL return `RuleLocations` mapping each rule UID to all of its SmartConsole positions across packages and layers
- **AND** it SHALL map each layer UID to its numbering prefixes (`""`, `"2."`, `"2.2."`) along with `snapshot_session_uid`, `snapshot_published_at`, and sync status

#### Scenario: SCN-RULE-004-3 — Automatic domain resolution and ambiguity error for domainless calls

- **WHEN** `get_package_rulebase` or `get_layer_rulebase` is called with `domain_name=None` or `""`
- **THEN** the client SHALL resolve the unique cached domain containing that package or layer (or the sole cached domain on an SMS)
- **AND** if multiple cached domains contain a matching name or UID, it SHALL raise `AmbiguousLayerName` listing all `(domain, uid)` candidates

### Requirement: Local Rulebase Filtering and CPCRUD Rule Export

**ID**: REQ-RULE-005\
**Intent**: Search cached rulebases offline with transitive group expansion and export matched rules directly into CPCRUD templates.\
**Non-goals**: Planning or applying CPCRUD rule mutations against Check Point (`REQ-CPCRUD-008`, `REQ-CPCRUD-009`).

`filter_rulebase()` and `rule_to_cpcrud_operation()` SHALL evaluate search/filter queries locally against cached rulebases (`PackageRulebase` or `NumberedLayerRulebase`) with transitive object/service group expansion and convert matched access, NAT, HTTPS, and threat-prevention rules into schema-valid `cpcrud` operation dictionaries (`output_format="cpcrud"`).

#### Scenario: SCN-RULE-005-1 — Convert matched access and NAT rules into valid CPCRUD operations

- **WHEN** `rule_to_cpcrud_operation(rule)` or `filter_rulebase(..., output_format="cpcrud")` is called on a cached `AccessRuleEntry`, `NatRuleEntry`, `HttpsRuleEntry`, or `ThreatRuleEntry`
- **THEN** it SHALL return a flat operation dictionary (`operation`, `type`, `layer` or `package`, `uid`, `name`, `source`/`destination`/`service` or NAT `original-*`/`translated-*` keys) compatible with `CPCRUDService.validate({"operations": [...]})`
- **AND** it SHALL normalize Check Point NAT `"Original"` and `"Any"` sentinel UIDs

### Requirement: Public Rulebase Numbering and Formatting Helper Exports

**ID**: REQ-RULE-006\
**Intent**: Export pure rulebase filtering, SmartConsole formatting, policy-package extraction, and standalone snapshot helpers cleanly under `arodonata.rulebase`.\
**Non-goals**: Coordinator-synchronized database persistence (`REQ-RULE-002`, `REQ-RULE-003`).

`arodonata.rulebase` SHALL export `filter_numbered_rulebase`, `format_rules_markdown`, `format_rules_model_friendly`, `extract_policy_packages`, and `collect_domain_rulebase_snapshot` alongside model and numbering primitives so downstream tools and custom adapters can format and inspect snapshots offline.

#### Scenario: SCN-RULE-006-1 — Public rulebase formatting and package extraction helpers work standalone on snapshot objects

- **WHEN** callers invoke `extract_policy_packages()`, `filter_numbered_rulebase()`, `format_rules_markdown()`, `format_rules_model_friendly()`, or `collect_domain_rulebase_snapshot()` from `arodonata.rulebase`
- **THEN** `extract_policy_packages` SHALL extract `PolicyPackageInfo` entries from a domain snapshot
- **AND** `filter_numbered_rulebase`, `format_rules_markdown`, and `format_rules_model_friendly` SHALL render filtered rules deterministically offline

### Requirement: Complete Layer Pagination, Advancing Zero-Rule Pages, and Prefix Continuity

**ID**: REQ-RULE-007\
**Intent**: Prevent silent rulebase snapshot truncation from unpaginated layer listings, zero-rule advancing pages, or missing post-fetch completeness checks.\
**Non-goals**: Base SmartConsole hierarchical numbering (`REQ-RULE-004`) or local filtering (`REQ-RULE-005`).

Rulebase synchronization SHALL paginate `show-access-layers`, `show-https-layers`, and `show-threat-layers` via `api_query`, continue rulebase paging across zero-rule advancing pages (`to > offset`), fail closed if collected rule count is less than `total_reported` before committing `status="ok"`, unify synthetic fallback UIDs, and record layer prefixes for empty or name-keyed layers.

#### Scenario: SCN-RULE-007-1 — Paginated layer discovery and zero-rule advancing pages never truncate snapshots

- **GIVEN** a domain with more than 50 standalone layers OR a rulebase page where `data["to"] > offset` returns zero rules (e.g., empty sections) before `total_reported`
- **WHEN** `refresh_rulebases()` or `fetch_paged_rulebase()` executes
- **THEN** layer discovery SHALL paginate all layers via `api_query` and rulebase paging SHALL continue across zero-rule advancing pages without the `' blade'` typo or diverging fallback UIDs
- **AND** if upstream pagination stops short of `total_reported`, rulebase refresh SHALL raise an error and record `status="failed"` rather than committing a truncated snapshot as `"ok"`

#### Scenario: SCN-RULE-007-2 — Empty inline/placeholder layers and layer-name lookups preserve prefix locations

- **GIVEN** an inline layer or Global-placeholder-embedded domain layer with zero child rules, OR a `show-changes` entry keyed by layer name instead of UID
- **WHEN** SmartConsole rulebase numbering and placement resolve layer prefixes
- **THEN** `LayerPrefixLocation` entries SHALL still be recorded for empty inline/placeholder layers and indexed under requested layer-name keys

### Requirement: Precomputed Group and Pattern Index for Rulebase Filtering

**ID**: REQ-RULE-008\
**Intent**: Eliminate quadratic `O(R * T * (|O| + |S|))` group-graph rebuilding and IP/CIDR re-parsing on the event loop during local rulebase filtering.\
**Non-goals**: Remote Check Point server-side rulebase search or SmartConsole rule numbering rules (`REQ-RULE-004`).

`filter_numbered_rulebase` SHALL precompute query IP/CIDR tokens, object and service `reverse_parents` membership graphs, and per-token matching identifier sets once per invocation and reuse them across all evaluated rules while preserving identical match results for both `filter_numbered_rulebase` and direct `rule_matches_filter` callers.

#### Scenario: SCN-RULE-008-1 — Precomputed rulebase filter index preserves exact match parity in linear group-graph time

- **GIVEN** a numbered rulebase with nested object/service groups and IP/CIDR or name filter tokens
- **WHEN** `filter_numbered_rulebase()` evaluates all rules alongside direct `rule_matches_filter()` calls on individual rules
- **THEN** `filter_numbered_rulebase()` SHALL build the object and service membership graphs at most once rather than per rule
- **AND** matched rule UIDs and ordering SHALL match direct `rule_matches_filter()` evaluation identically across nested group, IP, CIDR, range, and wildcard tokens

### Requirement: Fail-Closed Rulebase Snapshot Collection, Bounded Drift-Safe Paging, and Empty Embedded Layer Prefix Continuity

**ID**: REQ-RULE-009\
**Intent**: Prevent rulebase collection from committing truncated 50-item fallbacks as `"ok"`, bound pagination against infinite loops and `total` drift, unify fallback UIDs, and preserve package prefixes for empty embedded layers.\
**Non-goals**: Hierarchical SmartConsole rule numbering syntax (`REQ-RULE-004`).

Rulebase snapshot collection SHALL fail closed on `paging_inconsistent` and non-RBAC errors without 50-item unpaginated fallbacks, bound `fetch_paged_rulebase` against infinite loops and `total` drift, emit consistent synthetic fallback UIDs, and preserve package prefixes for empty Global-placeholder and unnamed inline layers.

#### Scenario: SCN-RULE-009-1 — Fail-closed paging_inconsistent handling, bounded pagination, and total drift detection

- **GIVEN** a domain with >50 packages/layers encountering `paging_inconsistent` or API errors, or a layer page stream with omitted `total`, repeated UIDs, or mid-fetch `total` growth
- **WHEN** `collect_domain_rulebase_snapshot()` or `fetch_paged_rulebase()` executes
- **THEN** `collect_domain_rulebase_snapshot()` SHALL raise rather than committing truncated/empty 50-item fallback caches as `status="ok"`
- **AND** `fetch_paged_rulebase()` SHALL enforce `max_pages` and zero-new-rule bounds and fail or restart on mid-fetch `total` discontinuities

#### Scenario: SCN-RULE-009-2 — Unified synthetic fallback rule UIDs and empty Global-placeholder / inline layer prefixes

- **GIVEN** a section mixing real-UID and missing-UID rules or a package referencing an empty Global-placeholder domain layer or unnamed empty inline layer
- **WHEN** `fetch_paged_rulebase()` parses rules/sections or `locate_rules_in_snapshot()` indexes layer prefixes
- **THEN** `sec.rule_uids` SHALL match parsed rule UIDs identically across rulebase types, and `locate_rules_in_snapshot()` SHALL emit the package prefix (`"2."`) without duplicate standalone `prefix=""` entries


---

### OpenSpec Capability: `sessions-and-mdm` (`openspec/specs/sessions-and-mdm/spec.md`)

# Sessions, Multi-Domain Resolution, and Concurrency Specification

## Purpose

Defines the lifecycle of Check Point API sessions (`AMgmtClient`, `SIDCacheEntry`, `arodonata_sid_cache`), hybrid and dynamic authentication with `contextvars`-bound `WriteSession` overlays (`SessionOverlay`, `AuthContext`, `AuthProvider`), per-MDS-member login serialization and request concurrency limiting, and Multi-Domain Security Management (MDSM) domain/server discovery (`DomainService`).

## Requirements

### Requirement: Multi-Domain Discovery, Failover IP Resolution, and Global Domain Visibility

**ID**: REQ-SESS-001\
**Intent**: Discover and cache MDS domains reliably with RBAC fallback, failover server tracking, and opt-in `Global` visibility.\
**Non-goals**: Validating explicit caller-supplied IP addresses (`REQ-SESS-008`) or read-only SID caching (`REQ-SESS-003`).

`DomainService` and `AMgmtClient` SHALL discover and cache MDS domains (`show-domains`, `show-mdss`, `show-global-domain`), track each domain's `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`, support opt-in `include_global`, periodically refresh cached domains when their 1-hour TTL expires, and log `DEBUG` discovery and `WARNING` failure messages.

#### Scenario: SCN-SESS-001-1 — Opt-in Global domain visibility

- **WHEN** `get_domains(include_global=False)` (default) vs `get_domains(include_global=True)` is called
- **THEN** the `Global` domain row SHALL be excluded when `include_global=False` and included when `include_global=True`

#### Scenario: SCN-SESS-001-2 — Periodic TTL-based domain list refresh

- **WHEN** `get_domains` or smart cache refresh runs while `arodonata_domains` is empty, the 1-hour domain-list TTL expired, or `mode="force"` is set
- **THEN** `show-domains` SHALL refresh domains, retrying with `details-level="standard"` if `details-level="full"` is denied by RBAC while preserving cached `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`
- **AND** discovery start and completion SHALL log `DEBUG` messages, and discovery failure SHALL log `WARNING` with the server error code and message

#### Scenario: SCN-SESS-001-3 — Cold-cache CMA IP resolution and active domain server failover re-resolution

- **WHEN** a customer or `Global` domain login runs before `arodonata_domains` is cached or when a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** the client SHALL query the MDS system domain (`show-domains`, `show-mdss`, `show-global-domain`), cache `active_ip` and `active_mds_ip` in `arodonata_domains`, and log a `DEBUG` message before authenticating

### Requirement: Hybrid and Dynamic Authentication with Context-Bound WriteSession Overlay

**ID**: REQ-SESS-002\
**Intent**: Support per-request dynamic credentials and isolated `contextvars` write overlays without exposing secrets or dirtying shared caches.\
**Non-goals**: Shared read-only SID caching (`REQ-SESS-003`).

The system SHALL support hybrid authentication (shared read-only credentials with per-admin write credentials) and dynamic authentication via `contextvars` (`AuthContext` / `AuthProvider`), and SHALL bind isolated `WriteSession` instances in `contextvars` with an in-memory `SessionOverlay` so read operations within that session reflect uncommitted creations, updates, and deletions.

#### Scenario: SCN-SESS-002-1 — WriteSession opens under administrator credentials and isolates uncommitted state

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_creds):` executes `add_host`, `set_host`, or `delete_host` followed by `get_hosts()`
- **THEN** the session SHALL authenticate under `admin_creds` and record mutations in `SessionOverlay` via `contextvars`
- **AND** `get_hosts()` SHALL return created/updated hosts and exclude deleted hosts without mutating shared database cache rows until `publish`

#### Scenario: SCN-SESS-002-2 — Dynamic authentication resolves credentials from AuthContext and evicts stale admin password

- **GIVEN** `"dynamic"` mode without static startup credentials where credentials come from `client.auth_context(...)` or `AuthProvider`
- **WHEN** a subsequent login using those credentials fails with `InvalidCredentialsError` (e.g., after a password change)
- **THEN** the client SHALL immediately evict those credentials and notify `AuthProvider` without retrying

### Requirement: Identity-Scoped Read-Only SID Caching and Dedicated Write Sessions

**ID**: REQ-SESS-003\
**Intent**: Prevent cross-principal SID reuse and ensure mutating commands never execute on shared read-only sessions.\
**Non-goals**: Startup cleanup of abandoned Arodonata sessions (`REQ-SESS-004`).

The system SHALL authenticate shared `arodonata_sid_cache` sessions with `"read-only": true`, key rows by `f"{mgmt_name}:{domain_key}:{auth_identity}"` (excluding `SIDCacheEntry.sid` from model dumps and defaulting `SIDCacheEntry.id` to include `auth_identity`), evict only the affected `auth_identity` row on expiry, failover, keepalive failure, or logout failure, and refuse mutating commands on `arodonata_sid_cache`.

#### Scenario: SCN-SESS-003-1 — Reuse of unexpired cached session scoped by authentication identity

- **WHEN** a read-only API call targets `(mgmt_name, domain)` under resolved credentials (`auth_identity`)
- **THEN** new `arodonata_sid_cache` sessions SHALL authenticate with `"read-only": true` and reuse only an unexpired row matching exact `f"{mgmt_name}:{domain_key}:{auth_identity}"`
- **AND** `SIDCacheEntry.model_dump()` / `model_dump_json()` SHALL omit raw `sid`, and another principal's cached SID SHALL NEVER be matched or overwritten

#### Scenario: SCN-SESS-003-2 — Transparent re-login on session expiration error

- **WHEN** a read-only call using a cached SID hits session expiration/CMA failover, a keepalive returns `success=False`, or `logout_all` fails to log out a cached SID
- **THEN** only that specific `(mgmt_name, domain_key, auth_identity)` row SHALL be evicted from `arodonata_sid_cache` (preserving other principals' SIDs)
- **AND** active read-only API calls SHALL acquire a fresh session and retry once

#### Scenario: SCN-SESS-003-3 — Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called
- **THEN** `AMgmtClient` SHALL authenticate a fresh read-write session (`"read-only"` omitted/`False`) with retry/backoff resilience and return `(sid, server_ip)` without storing it in `arodonata_sid_cache`
- **AND** the session SHALL remain tracked for cleanup until `logout_sid()` succeeds, shielding `discard` and `logout_sid()` against any `BaseException` (including `asyncio.CancelledError`)

#### Scenario: SCN-SESS-003-4 — Mutating commands refused on shared cached SID path

- **WHEN** `AMgmtClient.api_call` receives a mutating command (`add-*`, `set-*`, `delete-*`, `publish`, `discard`, `install-policy`, `run-script`, etc.) without an explicit `sid` or active `WriteSession` in `contextvars`
- **THEN** `AMgmtClient` SHALL refuse to run it on the shared `arodonata_sid_cache` session by raising `SessionStateError`

### Requirement: Stale Session Cleanup Without Read-Write Cache Seeding

**ID**: REQ-SESS-004\
**Intent**: Reclaim abandoned Arodonata API sessions fail-closed without ever touching human/dirty sessions or placing read-write SIDs into shared read-only caches.\
**Non-goals**: Read-only SID cache scoping (`REQ-SESS-003`).

The session manager SHALL clean up stale or abandoned Arodonata-owned sessions on startup (when static credentials exist) and on max-sessions refusal, restricting `discard` to Arodonata sessions (`application == "arodonata"` or `arodonata` prefix) with `changes == 0` and `locks == 0`, and SHALL log out its read-write cleanup session without seeding `arodonata_sid_cache`.

#### Scenario: SCN-SESS-004-1 — Startup cleanup logs out read-write probe session without seeding shared read-only SID cache

- **GIVEN** static credentials on client entry
- **WHEN** startup session cleanup runs `show-sessions` and discards stale Arodonata sessions using its temporary read-write cleanup session
- **THEN** `SessionCleaner` SHALL close that temporary read-write session via `logout_sid` on completion or error
- **AND** it SHALL NEVER insert a read-write SID into `arodonata_sid_cache` (so subsequent read-only calls acquire fresh `"read-only": true` sessions under `REQ-SESS-003`)

#### Scenario: SCN-SESS-004-2 — Foreign administrator sessions and sessions with unpublished changes are never discarded

- **WHEN** stale-session cleanup inspects `show-sessions` and sees sessions belonging to human administrators, other tools, or sessions with non-zero `changes` or `locks`
- **THEN** cleanup SHALL skip those sessions and NEVER issue `discard` or `take-over-session` against them

#### Scenario: SCN-SESS-004-3 — Cold startup in dynamic auth mode skips network cleanup

- **WHEN** `ArodonataClient` enters its context manager in `"dynamic"` auth mode before any administrator credentials are supplied
- **THEN** startup session cleanup SHALL be skipped without raising an authentication error

### Requirement: Per-MDS-Member Login Serialization and Deadlock-Free Failover

**ID**: REQ-SESS-005\
**Intent**: Serialize login bursts per MDS member to respect Check Point login pacing while avoiding self-deadlock on nested CMA failover lookups.\
**Non-goals**: Login throttle cooldown windows and fast credential rejection (`REQ-SESS-006`).

The client SHALL serialize logins per hosting MDS member (`active_mds_ip`, falling back to configured server IP) with minimum inter-login spacing and `wait_timeout`-bounded `asyncio.Lock` acquisition, while executing CMA failover IP refreshes and retry sleeps outside the gate so nested system-domain logins never deadlock.

#### Scenario: SCN-SESS-005-1 — Cold-cache CMA failover during login does not deadlock login serialization

- **GIVEN** a customer-domain login on `mds_ip` encountering a transport/failover error while the system-domain SID is not yet cached
- **WHEN** failover recovery triggers a nested system-domain login to refresh the domain's active IP on `mds_ip`
- **THEN** `AMgmtClient` SHALL release the per-`mds_ip` login serialization lock before refreshing the domain IP so the nested system-domain login completes without self-deadlock

### Requirement: Login Throttle Cooldown and Fast Credential Rejection

**ID**: REQ-SESS-006\
**Intent**: Coordinate login throttle cooldowns across queued callers while failing fast on wrong credentials or locked accounts.\
**Non-goals**: Per-MDS login lock release during CMA failover (`REQ-SESS-005`).

The client SHALL enforce a shared per-MDS throttle cooldown inside the login gate with a `WARNING` log on login throttling or read-phase timeout, retry within `login_max_wait`, and raise `InvalidCredentialsError` immediately without retrying when credentials are rejected or an administrator account is locked.

#### Scenario: SCN-SESS-006-1 — Throttled login waits out Check Point throttle window

- **WHEN** a login attempt is rejected for Check Point login throttling or times out during the read phase
- **THEN** the per-MDS login gate SHALL record the cooldown (`login_throttle_window`, default `70s`, or exponential read-timeout backoff) and log a `WARNING` with server IP, non-secret administrator principal (resolved from credentials or Check Point login response `'user-name'`, falling back to `'api_key'`), and cooldown duration
- **AND** queued callers SHALL wait out the cooldown, and the caller SHALL release the gate before sleeping and retrying within `login_max_wait` (default `900s`)

#### Scenario: SCN-SESS-006-2 — Credential rejection or locked account fails fast with InvalidCredentialsError

- **WHEN** Check Point rejects login (`Authentication to server failed` or `Administrator account is locked`) rather than reporting a transient lock (`Database revision is in progress`)
- **THEN** login SHALL raise `InvalidCredentialsError` (subclass of `AuthenticationError`) immediately without exhausting transient retry loops

### Requirement: Per-MDS-Member Concurrency Semaphore

**ID**: REQ-SESS-007\
**Intent**: Bound concurrent API requests per MDS safely using FIFO fairness, shielded cleanup, and coalesced keepalive sweeps.\
**Non-goals**: Login serialization and throttle windows (`REQ-SESS-005`, `REQ-SESS-006`).

The client SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using database-backed slot locks (with TTL `>= max(api_timeout, login_timeout) + 60s`) and FIFO in-process waiter queues, suppressing database `Exception` errors during shielded DB lock release while always releasing the local FIFO slot and propagating `asyncio.CancelledError`.

#### Scenario: SCN-SESS-007-1 — Fair waiter wakeup on slot release

- **GIVEN** all `concurrent_limit` slots for an MDS member are occupied and multiple coroutines are queued in arrival order
- **WHEN** an active slot holder exits (including when DB lock release raises an `Exception` or `asyncio.CancelledError` occurs)
- **THEN** DB lock cleanup SHALL be shielded (`suppress(Exception)`), the local FIFO slot SHALL ALWAYS release in `finally` to wake the longest-waiting coroutine, and `asyncio.CancelledError` SHALL propagate

#### Scenario: SCN-SESS-007-2 — Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity (including if an awaiting caller is cancelled)
- **THEN** overlapping keepalive sweeps SHALL coalesce under `asyncio.shield` so at most one sweep runs at a time without starving active caller slots or aborting sibling waiters

### Requirement: Untrusted Explicit Server IP Rejection

**ID**: REQ-SESS-008\
**Intent**: Prevent SSRF or credential/SID exfiltration to arbitrary IP addresses passed via `explicit_server_ip`.\
**Non-goals**: Pre-request TLS certificate fingerprint verification (`REQ-TRANS-002`).

`AMgmtClient` (across `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, and `logout_sid`) SHALL validate any caller-supplied `explicit_server_ip` against `mgmt_name`'s configured endpoint hosts and cached/discovered MDS and domain server addresses, rejecting untrusted IPs with `ValidationError` before connecting.

#### Scenario: SCN-SESS-008-1 — Untrusted explicit_server_ip rejected before connection or SID transmission

- **WHEN** `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid` receives an `explicit_server_ip` absent from `mgmt_name`'s configured endpoints and cached/discovered MDS or domain server IPs
- **THEN** the client SHALL raise `ValidationError` before opening a TLS connection, learning a TOFU certificate, or transmitting `X-chkp-sid`

### Requirement: Contextual User Attribution Propagation

**ID**: REQ-SESS-009\
**Intent**: Attribute dedicated Web API work sessions to downstream application users and metadata via `contextvars` without mixing identity across concurrent tasks.\
**Non-goals**: Authentication credentials passed via `AuthContext` (`REQ-CONFIG-003`).

`arodonata.core.context` (`UserContext`) and `ArodonataClient.user_context()` SHALL bind caller attribution metadata (`session_name`, `session_description`, `user_id`, `username`) to `contextvars`, applying `session_name` and `session_description` automatically to dedicated write sessions while preserving clean outer context on exit.

#### Scenario: SCN-SESS-009-1 — UserContext attributes dedicated sessions safely via contextvars

- **WHEN** `create_dedicated_session` or `write_session` runs inside `async with` / `with client.user_context(session_name="change-42", session_description="ticket", username="alice"):` without explicit session metadata overrides
- **THEN** the opened session SHALL receive `session_name` and `session_description` from the active `UserContext` (`login` / `set-session`)
- **AND** exiting the `user_context` block SHALL restore the previous `UserContext` without mutating concurrent tasks

### Requirement: Fail-Closed DNS Pinning for Unresolvable Explicit Hostnames

**ID**: REQ-SESS-010\
**Intent**: Prevent unpinned hostname forwarding to transport when DNS resolution returns no answers during explicit server validation.\
**Non-goals**: Subset validation when DNS resolves or explicit IP literals (`REQ-SESS-008`).

When `AMgmtClient` validates an explicit non-IP hostname `server_ip` whose DNS lookup yields zero A/AAAA answers, validation SHALL fail closed with `ValidationError` before any connection attempt rather than forwarding an unresolved hostname to transport.

#### Scenario: SCN-SESS-010-1 — Unresolvable explicit hostname raises ValidationError before transport connect

- **GIVEN** a management endpoint configured with a hostname (`mgmt.example.com`) whose DNS resolution returns zero A/AAAA records during validation
- **WHEN** `AMgmtClient` (`api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid`) receives `explicit_server_ip="mgmt.example.com"`
- **THEN** validation SHALL raise `ValidationError` before opening a TLS connection or transmitting `X-chkp-sid`
- **AND** callers SHALL never receive an unpinned raw hostname for transport connect-time re-resolution

### Requirement: Unconditional Startup Stale-Session Inspection

**ID**: REQ-SESS-011\
**Intent**: Guarantee startup stale-session cleanup always inspects and discards abandoned Arodonata sessions even when a previous run left an unexpired read-only System Data SID in cache.\
**Non-goals**: Read-only SID cache reuse (`REQ-SESS-003`) or RW cleanup logout/filtering rules (`REQ-SESS-004`).

On startup cleanup when static credentials exist, `AMgmtClient` and `SessionCleaner` SHALL open a temporary read-write session, inspect `show-sessions`, discard eligible abandoned Arodonata-owned sessions, and log out via `logout_sid` without short-circuiting on cached read-only System Data SIDs.

#### Scenario: SCN-SESS-011-1 — Startup cleanup inspects and discards abandoned sessions despite cached read-only System Data SID

- **GIVEN** static credentials and an unexpired read-only System Data `SIDCacheEntry` persisted in `arodonata_sid_cache` alongside an abandoned Arodonata-owned session (`changes == 0`, `locks == 0`) on the server
- **WHEN** startup session cleanup runs (`run_startup_cleanup()` or `schedule_startup_cleanup()`)
- **THEN** cleanup SHALL NOT return early on the cached read-only SID and SHALL query `show-sessions`, discard eligible abandoned sessions, and close its temporary read-write session via `logout_sid`
- **AND** the pre-existing fresh cached read-only System Data SID SHALL remain preserved in `arodonata_sid_cache`

### Requirement: Hostname-Bound TLS Fingerprint Enforcement Across Canonical IP Pinning

**ID**: REQ-SESS-012\
**Intent**: Prevent TOFU first-contact bypass or cross-host pin substitution when an explicit hostname is resolved and connected via its pinned canonical IP literal.\
**Non-goals**: Unresolvable hostname rejection (`REQ-SESS-010`) or DNS-rebinding subset validation (`REQ-SESS-008`).

When an explicit `server_ip` hostname is resolved and pinned to a canonical trusted IP literal before connecting, TLS certificate fingerprint verification (`TrustPolicy` in `"pinned"`, `"tofu"`, and `"lab-memory"` modes) SHALL also enforce any certificate fingerprint pinned or previously persisted under that hostname (`<hostname>:<port>`), rejecting mismatched peer certificates with `CertificateMismatchError` before transmitting any HTTP request or `X-chkp-sid`.

#### Scenario: SCN-SESS-012-1 — Hostname-pinned and TOFU-learned TLS fingerprints remain enforced when connecting to a resolved canonical IP

- **GIVEN** a management endpoint with a certificate fingerprint pinned in `ARODONATA_TLS_FINGERPRINTS` or previously persisted in `tls_known_hosts.json` under `mgmt.example.com:443` while `mgmt.example.com` resolves to trusted IP `10.0.0.50`
- **WHEN** `AMgmtClient` executes an API call, read-only login, keepalive, or logout with `server_ip="mgmt.example.com"` and `10.0.0.50:443` presents either the expected fingerprint or a different certificate (including another server's pinned fingerprint or an unknown MITM certificate in `"tofu"` mode)
- **THEN** the connection SHALL dial `10.0.0.50:443` directly without connect-time DNS re-resolution and succeed when `10.0.0.50:443` presents `mgmt.example.com:443`'s fingerprint
- **AND** any certificate mismatch against `mgmt.example.com:443`'s pinned or TOFU-stored fingerprint SHALL raise `CertificateMismatchError` before sending HTTP headers or `X-chkp-sid`

### Requirement: Canonical Domain Discovery, Shared WriteSession Lifecycle, and Decomposed Session Execution

**ID**: REQ-SESS-013\
**Intent**: Eliminate diverged domain parsers, missing RBAC fallback in MDS discovery, duplicated `WriteSession` teardown logic, and monolithic session/route execution paths.\
**Non-goals**: Login throttle backoff semantics (`REQ-SESS-006`) or base VSX repository bundle parsing (`REQ-TOPO-008`).

`arodonata` SHALL use one canonical domain parser for `parse_domain_entry` and `parse_domain_dict`, support `details-level="standard"` RBAC fallback in `fetch_domain_topology_from_mds`, share a `WriteSession` teardown helper, and decompose `run_repository_script` and `_collect_gateway_routes_impl` into focused helpers.

#### Scenario: SCN-SESS-013-1 — Canonical domain parser identity, MDS standard RBAC fallback, and shared WriteSession lifecycle

- **GIVEN** raw MDS domain payloads parsed via `parse_domain_entry` or `parse_domain_dict`, an MDS returning permission denial on `details-level="full"`, or `WriteSession` exits (clean vs exception) across `open_api_write_session` and `AMgmtClient.write_session`
- **WHEN** domains are discovered or write sessions are opened and closed
- **THEN** `sessions.parse_domain_entry` and `response_classifiers.parse_domain_entry` SHALL preserve object identity and parse identically to `parse_domain_dict`
- **AND** `fetch_domain_topology_from_mds` SHALL fall back to `details-level="standard"` preserving cached CMA IPs, and both `WriteSession` entrypoints SHALL enforce identical publish/discard/logout semantics

#### Scenario: SCN-SESS-013-2 — Decomposed run_repository_script and route collection preserve SID redaction and coalescing

- **GIVEN** `ScriptRepositoryService.run_repository_script()` across session modes or `collect_gateway_routes()` across VSX coalesced nodes
- **WHEN** repository scripts run (with normal completion, validation failure, or session errors) or multi-gateway route collection executes
- **THEN** every session exception branch and task output SHALL scrub SIDs uniformly and close dedicated sessions cleanly
- **AND** coalescing execution, per-gateway persistence, and post-TaskGroup domain sync-state finalization SHALL run via isolated composable helpers

### Requirement: Lifecycle TLS Identity Binding, Discovery Retry Integrity, and Session Secret Hardening

**ID**: REQ-SESS-014\
**Intent**: Preserve hostname-bound TLS pins across the full session lifecycle, prevent failed domain discovery from suppressing retries, enforce target-MDS throttling and typed lock-timeout errors, and mask secrets on model serialization.\
**Non-goals**: Base rate-limit sizing (`REQ-SESS-007`) or initial TOFU enrollment policy (`REQ-TRANS-002`).

`ArodonataClient` SHALL preserve hostname TLS pin binding across cached/dedicated sessions and expired-SID retries, gate `domain_list_ttl` on `status == "ok"`, translate distributed login-gate lock timeouts to `AuthenticationError`, throttle stale-session cleanup on the target MDS member, and mask secrets in `AuthContext` and `ServerEndpointConfig` `model_dump()` outputs.

#### Scenario: SCN-SESS-014-1 — Hostname-bound TLS pinning persists across first-contact TOFU, keepalive/logout sweeps, and expired-SID retries

- **GIVEN** a hostname endpoint (`mgmt.example.com`) verified via `TrustPolicy` in `tofu` or `pinned` mode
- **WHEN** first-contact TOFU records fingerprints, cached or dedicated sessions run `keepalive` / `logout` / non-system `api_call()`, or an expired read-only SID retries
- **THEN** `TrustPolicy` SHALL bind both `(resolved_ip, port)` and `(hostname, port)`, and session operations SHALL preserve `tls_identity_host` and target IP pinning end-to-end

#### Scenario: SCN-SESS-014-2 — Failed domain discovery does not suppress subsequent smart refreshes for domain_list_ttl

- **GIVEN** a management server whose cached domain list exceeded `domain_list_ttl` and whose `show-domains` call fails transiently (`status="failed"`)
- **WHEN** a caller (including a restarted process or sibling worker) invokes `get_domains(cache_mode="smart")` shortly thereafter
- **THEN** `DomainService` SHALL treat `status != "ok"` sync state as stale and re-attempt live domain discovery instead of suppressing retries for `domain_list_ttl`

#### Scenario: SCN-SESS-014-3 — Distributed LoginGate timeout raises AuthenticationError and SessionCleaner throttles target MDS member

- **GIVEN** a contended distributed `login_gate:<mds_ip>` lock or a multi-MDS domain hosted on a secondary MDS member
- **WHEN** `LoginGate.acquire()` times out on `LockPort` or `SessionCleaner` runs `show-sessions` / `discard` for that domain
- **THEN** `LoginGate.acquire()` SHALL raise `AuthenticationError` rather than `LockAcquisitionError`
- **AND** `SessionCleaner` SHALL acquire `RateLimiter` slots against the target domain's resolved `mds_ip` (while expired-SID retries in `api_call` also refresh `mds_ip`)

#### Scenario: SCN-SESS-014-4 — AuthContext and ServerEndpointConfig mask password and api_key on model_dump and clean obsolete login residue

- **GIVEN** `AuthContext` or `ServerEndpointConfig` instances populated with `password` or `api_key`
- **WHEN** `.model_dump()` or `.model_dump_json()` is called directly or through an enclosing Pydantic model
- **THEN** `password` and `api_key` SHALL be emitted as `REDACTED_PLACEHOLDER` (never plaintext), while `LoginCoordinator` omits dead startup-seeding methods and racy `_inflight_logins` state

### Requirement: SessionCleaner Identity Fail-Fast, Keepalive Isolation, and Single-Resolution Read-Only Target Lookup

**ID**: REQ-SESS-015\
**Intent**: Prevent silent swallowing of TLS identity errors in background session cleanup, isolate dedicated SIDs from `auth_identity=None` keepalive sweeps, and eliminate redundant DNS resolution.\
**Non-goals**: Base rate-limiting rules (`REQ-SESS-007`) or startup cleanup SID exclusion (`REQ-SESS-004`).

`SessionCleaner` SHALL propagate `ServerIdentityError` immediately, `LoginCoordinator.keepalive_sid()` SHALL avoid `auth_identity=None` fallbacks and route dedicated SIDs safely, `target_resolver` SHALL guard `evict_sid` when `expired_identity is None`, and `get_readonly_session()` SHALL pass prevalidated host targets without repeating DNS resolution.

#### Scenario: SCN-SESS-015-1 — SessionCleaner identity propagation, dedicated keepalive isolation, and single-DNS read-only login

- **GIVEN** a TLS `ServerIdentityError` inside `SessionCleaner`, a `keepalive_sid()` sweep across explicit dedicated SIDs or credential errors, or an explicit hostname target in `get_readonly_session()`
- **WHEN** cleanup, keepalive maintenance, or read-only session acquisition runs
- **THEN** `SessionCleaner` SHALL re-raise `ServerIdentityError`, `keepalive_sid()` SHALL return `False` on credential failure without evicting unrelated `auth_identity=None` caches, and `get_readonly_session()` SHALL resolve explicit hostnames once per call


---

### OpenSpec Capability: `transport-and-tls` (`openspec/specs/transport-and-tls/spec.md`)

# Transport, TLS Identity Verification, and Task Polling Specification

## Purpose

Defines the native `asyncio` Check Point Management API HTTPS transport (`AMgmtClient`), pre-request SHA-256 certificate fingerprint identity verification and TOFU persistence, verified keep-alive connection pooling, socket-level connect and read timeout handling without unsafe retries, asynchronous `show-task` polling, and continuity-verified pagination (`api_query`).

## Requirements

### Requirement: Strict Web API Command Name Validation

**ID**: REQ-TRANS-001\
**Intent**: Block path traversal, query injection, and malformed API commands on the client before opening connections, logging in, or touching pools.\
**Non-goals**: Payload schema validation against Check Point API reference (`REQ-APIREF-004`).

`AMgmtClient` transport and `api_call` execution SHALL validate every Check Point Web API command string against `^[a-z0-9]+(-[a-z0-9]+)*$` before `is_readonly_command()` classification, login, or request URL construction, rejecting whitespace, slashes, traversal, percent-encoding, and uppercase characters.

#### Scenario: SCN-TRANS-001-1 — Path traversal or malformed command rejected before network I/O

- **WHEN** `AMgmtClient.api_call` or transport execution receives a command violating `^[a-z0-9]+(-[a-z0-9]+)*$` (such as `"show-hosts/../publish"`, `"show-x/%2e%2e/publish"`, `"../../gaia_api/v1.7/run-script"`, `"show-hosts?x=1"`, `" show-hosts "`, or `"SHOW-HOSTS"`)
- **THEN** the client SHALL raise `ValidationError` immediately before `is_readonly_command()` classification, session login, connection acquisition, or sending any network bytes

### Requirement: Pre-Request TLS Certificate Fingerprint Verification

**ID**: REQ-TRANS-002\
**Intent**: Pin and verify management server TLS identities after handshake and prior to sending any secrets, headers, or payloads.\
**Non-goals**: TOFU known-hosts file locking and IPv6 key syntax (`REQ-TRANS-003`).

The transport SHALL verify the server certificate SHA-256 fingerprint at `host:port` immediately after the TLS handshake and BEFORE sending HTTP headers, credentials, API keys, or payloads across `"pinned"`, `"tofu"`, and `ARODONATA_LAB`-gated `"lab-memory"` modes, bind `SSLContext` creation to `TrustPolicy`, log TOFU first-contact warnings and `arodonata.tls_decision` spans, forbid proxies (`trust_env=False`), and never retry `ServerIdentityError`.

#### Scenario: SCN-TRANS-002-1 — Untrusted certificate refused in pinned mode

- **GIVEN** `tls_trust="pinned"` where the server at `host:port` presents a certificate whose SHA-256 fingerprint is absent from both the trust store and `ARODONATA_TLS_FINGERPRINTS`
- **WHEN** a connection is established
- **THEN** the connection SHALL close before any request bytes are sent
- **AND** `UnknownServerCertificateError` (or `CertificateMismatchError` if another fingerprint was pinned) SHALL be raised with `"No request was sent."` in the message

#### Scenario: SCN-TRANS-002-2 — Known MDS member fingerprint accepted on a new domain IP

- **GIVEN** a domain server IP presenting a certificate whose SHA-256 fingerprint is already trusted for another address in the trust store or `ARODONATA_TLS_FINGERPRINTS`
- **WHEN** the transport connects to that domain IP
- **THEN** the certificate SHALL be accepted (and recorded as `known-identity` in `"tofu"` mode)

#### Scenario: SCN-TRANS-002-3 — Lab-memory mode restricted to lab environment

- **WHEN** `tls_trust="lab-memory"` is configured without `ARODONATA_LAB` set in the environment
- **THEN** trust configuration initialization SHALL raise `ConfigurationError`

#### Scenario: SCN-TRANS-002-4 — Proxy connections and unverified sender seams rejected

- **WHEN** proxy environment variables (`HTTPS_PROXY`, `ALL_PROXY`) are present, a proxy connection is attempted, or a custom sender seam lacks peer certificate verification outside explicit unit test fixtures
- **THEN** the transport SHALL ignore ambient proxy variables (`trust_env=False`), refuse proxy connections before sending request bytes, and never bypass pre-request certificate verification

#### Scenario: SCN-TRANS-002-5 — Identity errors are never retried

- **WHEN** a connection raises `ServerIdentityError` (`CertificateMismatchError`, `UnknownServerCertificateError`, or `TrustStoreError`)
- **THEN** login, keepalive, and task-wait loops SHALL propagate the error immediately without retrying

#### Scenario: SCN-TRANS-002-6 — First-contact TOFU and lab-memory trust emit audit warning, record tls_decision span attribute, and bind SSLContext to TrustPolicy

- **WHEN** `TrustPolicy.verify_der()` / `verify_fingerprint()` trusts a server on first contact (`"tofu"` or `"lab-memory"`), matches a stored or pinned certificate, or rejects an untrusted/mismatched/missing certificate, OR when `TrustPolicy.create_ssl_context()` / `create_verified_ssl_context()` creates a client `SSLContext`
- **THEN** first-contact `"tofu"` and `"lab-memory"` acceptance SHALL emit a structured `WARNING` audit log (`event="tls_tofu_first_contact"`, `host`, `port`, `fingerprint`, `mode`) without secrets or SIDs
- **AND** OpenTelemetry spans SHALL record `arodonata.tls_decision` (`"pinned_match"`, `"tofu_match"`, `"stored_match"`, `"tofu_first_contact"`, `"lab_memory_first_contact"`, `"known_identity_match"`, `"lab_memory_match"`, `"mismatch"`, `"unpinned_rejected"`, or `"missing_cert"`)
- **AND** `TrustPolicy.create_ssl_context()` / `create_verified_ssl_context(policy)` SHALL return a `PolicyBoundSSLContext` enforcing TLS 1.2+, `OP_NO_COMPRESSION`, and HTTP/1.1 ALPN bound to the validated `TrustPolicy`, while `FingerprintTCPConnector` SHALL reject invalid `TrustPolicy` objects with `ConfigurationError`

### Requirement: Atomic Cross-Process Known-Hosts Persistence and IPv6 Key Normalization

**ID**: REQ-TRANS-003\
**Intent**: Prevent multi-worker TOFU known-hosts file corruption, enforce owner-only directory/file security, and support IPv6 literal endpoints reliably.\
**Non-goals**: TLS trust mode policy enforcement (`REQ-TRANS-002`).

TLS trust-store persistence SHALL create parent directories with `0700`, reject symlinked trust stores (`S_ISLNK`) and non-sticky group/world-writable parent directories before network I/O, write `tls_known_hosts.json` (`0600`) under cross-process locking atomically, and normalize RFC-compliant IPv6 `[host]:port` keys.

#### Scenario: SCN-TRANS-003-1 — First contact learned in TOFU mode

- **GIVEN** `tls_trust="tofu"` and `host:port` absent from `tls_known_hosts.json`
- **WHEN** the first TLS handshake completes
- **THEN** the SHA-256 fingerprint SHALL be persisted atomically to `tls_known_hosts.json` (mode `0600`) under an exclusive OS lock after re-reading and merging on-disk entries
- **AND** a subsequent connection to `host:port` presenting a different fingerprint SHALL raise `CertificateMismatchError`

#### Scenario: SCN-TRANS-003-2 — IPv6 host and port keys parsed without ambiguity

- **WHEN** a management server or domain endpoint uses an IPv6 literal (`[2001:db8::1]:443` or `2001:db8::1`)
- **THEN** both `tls_known_hosts.json` and `ARODONATA_TLS_FINGERPRINTS` SHALL normalize and match `[ipv6]:port` without splitting on internal colons

#### Scenario: SCN-TRANS-003-3 — Symlinked trust store or unsafe parent directory permissions rejected before network I/O

- **WHEN** `tls_known_hosts.json` or its lock target is a symlink, its parent directory has unsafe group/world write bits without a sticky bit, OR an owner-managed `euid` store in `"tofu"` mode has group/world read bits (`S_IRGRP | S_IROTH`) vs a `uid=0` read-only mounted `ConfigMap` (`0444`/`0644`)
- **THEN** `TrustStore` SHALL raise `TrustStoreError` for symlinks and unsafe writable dirs before API requests, create new parent dirs with mode `0700`, emit a `WARNING` for over-readable `euid` `tofu` stores, and preserve compatibility with `uid=0` read-only mounts

### Requirement: Verified Connection Pooling for Read-Only and Session-Scoped Commands

**ID**: REQ-TRANS-004\
**Intent**: Reduce TLS handshake overhead across sequential read-only and dedicated-session commands without leaking SIDs or missing host-key eviction.\
**Non-goals**: Socket timeout classification (`REQ-TRANS-007`) or task polling (`REQ-TRANS-005`).

The HTTPS transport SHALL pool fingerprint-verified keep-alive connections keyed by canonicalized `(host, port)` (lowercase DNS, uncompressed-agnostic RFC-5952 IPv6) for up to 10s idle and `< 95` requests, closing matching canonical idle sockets on `close_host`/`close_scope` and non-pooled commands without exposing raw `sid`s.

#### Scenario: SCN-TRANS-004-1 — Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and below 95 requests on that socket
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: SCN-TRANS-004-2 — Mutating commands and idle connections bypass reuse

- **WHEN** a session-boundary command (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`), an un-scoped non-`show-*` command, `close_host`/`close_scope` with mixed-case hostname or equivalent IPv6 spelling (`"2001:0db8::1"` / `"[2001:db8::1]"`), or a call after `> 10s` idle runs
- **THEN** the transport SHALL canonicalize the host key, close all matching idle pooled sockets before connecting, send `Connection: close`, and open a fresh TLS-verified connection

#### Scenario: SCN-TRANS-004-3 — Sequential commands within a dedicated session reuse session-scoped keep-alive connection

- **WHEN** non-boundary commands (`show-session`, `add-*`, `set-*`, `delete-*`, `show-task`) run with a dedicated `session_scope` on the same `(server_ip, port)` within 10s and `< 95` requests
- **THEN** they SHALL reuse the pooled connection isolated to that `session_scope` without setting `Connection: close`, while keeping shared read-only calls and distinct `session_scope`s isolated

#### Scenario: SCN-TRANS-004-4 — Pooled socket rotates cleanly before server max-keepalive request limit

- **WHEN** a pooled socket reaches 95 HTTP requests or signals closure (`should_close`)
- **THEN** the transport SHALL close that socket on release instead of re-pooling it so the next request opens a fresh verified connection before the server's 100-request keep-alive limit

### Requirement: Self-Managed Asynchronous Task Polling

**ID**: REQ-TRANS-005\
**Intent**: Handle long-running Check Point async operations reliably without blocking event loops or misclassifying partial task failures as success.\
**Non-goals**: Paging over task-based query results (`REQ-TRANS-006`).

`AMgmtClient` SHALL execute Check Point Web API commands asynchronously without blocking worker threads and poll any returned `task-id` / `tasks` entries via `show-task` using exponential backoff (`2s` up to `10s`) under the separate `task_timeout` budget.

#### Scenario: SCN-TRANS-005-1 — Successful task completion returns final show-task response

- **WHEN** an API command (`publish`, `install-policy`, `revert-to-revision`, `assign-global-assignment`, etc.) returns a task identifier
- **THEN** `AMgmtClient` SHALL poll `show-task` until all tasks reach terminal state and return `success=True` only when every task's status is in the explicit success allowlist (`succeeded`)

#### Scenario: SCN-TRANS-005-2 — Failed or partially succeeded task returns success=False without raising

- **WHEN** a polled server task finishes with `failed` or `partially succeeded`
- **THEN** `api_call` SHALL return `ApiCallResult(success=False, ...)` with the raw `show-task` payload and error message rather than raising an exception

#### Scenario: SCN-TRANS-005-3 — Tolerance of transient poll failures

- **WHEN** individual `show-task` polls fail or time out transiently fewer than 5 consecutive times within `task_timeout`
- **THEN** polling SHALL continue until completion, or raise `TaskPollError` on 5 consecutive poll failures or `TaskTimeoutError` (`TimeoutError` subclass) if `task_timeout` expires

### Requirement: Continuity-Verified Object Listing Pagination

**ID**: REQ-TRANS-006\
**Intent**: Guarantee gap-free and duplicate-free multi-page Check Point object listings even under concurrent SmartConsole mutations.\
**Non-goals**: Rulebase section-merge pagination (`REQ-RULE-001`).

`AMgmtClient.api_query()` SHALL page object listings in chunks (default 300, max 500), acquiring and releasing a per-MDS concurrency slot per page so short API calls can interleave between pages, and verifying `from`, `to`, `total`, and object UID uniqueness across pages.

#### Scenario: SCN-TRANS-006-1 — Boundary swap duplicate UID recovery

- **WHEN** Check Point reorders two equal-name objects across a page boundary, producing a duplicate UID on the new page
- **THEN** `api_query` SHALL drop the duplicate and re-read a small boundary window (up to 10 objects on each side) in one request to recover the displaced object without restarting the full listing

#### Scenario: SCN-TRANS-006-2 — Total count change or continuity break triggers single restart

- **WHEN** `total` changes mid-listing, `from`/`to` continuity breaks, or the distinct UID count disagrees with `total`
- **THEN** `api_query` SHALL restart once from the initial offset, and if the second pass also fails continuity checks, return a failed `ApiQueryResult` with `code="paging_inconsistent"` instead of silent gaps or duplicates

#### Scenario: SCN-TRANS-006-3 — Task-based query commands paged through show-task polling

- **WHEN** `api_query` executes a task-based query command (such as `show-changes` or `show-logs`)
- **THEN** each page SHALL run via `api_call` (`show-task` polling unpacking `tasks[].task-details[]`) until `to >= total`, failing the entire query if any page fails or stops advancing

### Requirement: Socket-Level Connect and Read Timeouts Without Automatic Resend

**ID**: REQ-TRANS-007\
**Intent**: Enforce unambiguous failure semantics and never double-execute non-idempotent Check Point commands after bytes leave the socket.\
**Non-goals**: Timeout budget settings resolution (`REQ-CONFIG-004`).

`AMgmtClient` HTTPS transport SHALL enforce connect/read timeouts and `max_response_bytes` response-body limits, disable redirects (`allow_redirects=False`), classify `TransportError` (`phase="connect"` / `request_sent=False` before wire send, including `RateLimitTimeoutError`, vs `"read"` / `"post-send"` with `request_sent=True`), and never resend after `request_sent=True`.

#### Scenario: SCN-TRANS-007-1 — Socket connect or handshake timeout

- **WHEN** TCP connect or TLS handshake exceeds `connect_timeout`, OR local MDS concurrency slot acquisition raises `RateLimitTimeoutError` before any network I/O
- **THEN** TCP/TLS timeouts SHALL raise `ApiTimeoutError` (`TimeoutError` subclass) with `phase="connect"`, `request_sent=False`, and target `host`/`port`, and `RateLimitTimeoutError` SHALL set `request_sent=False` so callers know no bytes were transmitted

#### Scenario: SCN-TRANS-007-2 — Socket read timeout

- **WHEN** waiting for the server's HTTP response exceeds the call's read timeout
- **THEN** the transport SHALL raise `ApiTimeoutError` with `phase="read"`, `request_sent=True`, naming the server and command and warning that the command may still have executed

#### Scenario: SCN-TRANS-007-3 — Connection reset or broken pipe after request transmission never resends

- **WHEN** the peer resets or closes the connection (`ConnectionResetError`, `BrokenPipeError`, `ServerDisconnectedError`, or post-connect `ClientOSError`) after request bytes were written
- **THEN** the transport SHALL raise `TransportError` with `phase="post-send"` (`request_sent=True`), and neither the transport nor CMA failover recovery SHALL resend the request

#### Scenario: SCN-TRANS-007-4 — HTTP redirects are never followed

- **WHEN** the server responds with any `3xx` redirect status (`301`, `302`, `303`, `307`, `308`)
- **THEN** the transport SHALL NOT follow the redirect (`allow_redirects=False`), SHALL NOT transmit `X-chkp-sid` or request bodies to `Location`, and SHALL fail the call immediately

#### Scenario: SCN-TRANS-007-5 — Oversized HTTP response body rejected before unbounded memory buffering

- **WHEN** a server sends a response whose `Content-Length` header or streamed byte count exceeds `ArodonataSettings.max_response_bytes`
- **THEN** `ApiTransport` SHALL abort reading at `max_response_bytes + 1` bytes, close the socket without pooling, raise `TransportError` with `phase="read"` (`request_sent=True`), and never automatically resend the request
