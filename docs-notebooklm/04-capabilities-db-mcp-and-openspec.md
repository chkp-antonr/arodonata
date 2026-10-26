# Arodonata v2 — Capabilities, DB Schema, MCP Surface & Canonical OpenSpec Specifications

This bundle combines the Downstream Integration Guide (`docs/CAPABILITIES.md`), the complete 15-table SQLModel database schema (`docs/architecture/database-schema.md` + `src/arodonata/adapters/storage/tables.py`), the consolidated MCP Server specification (`docs/mcp/index.md`), and all 10 canonical OpenSpec capability specifications (`openspec/specs/*/spec.md`).


---

## Part 1: Downstream Integration Guide (`docs/CAPABILITIES.md`)

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

## Part 2: 15-Table Database Schema (`docs/architecture/database-schema.md`)

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

### Canonical SQLModel Table Definitions (`src/arodonata/adapters/storage/tables.py`)

```python
"""SQLModel table definitions for Arodonata v2 persistence (`SQLite` and `PostgreSQL`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime
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
| `ARODONATA_MCP_JSON_RESPONSE` | `bool` | `False` | Return JSON responses instead of SSE streams on Streamable-HTTP POST |
| `ARODONATA_MCP_STATELESS_HTTP` | `bool` | `False` | Enable stateless Streamable-HTTP mode per request |
| `ARODONATA_MCP_SERVER_NAME` | `str` | `"arodonata-mcp"` | Server identifier reported in MCP initialization |


---

## Part 4: Canonical OpenSpec System Specifications (`openspec/specs/`)


---

### OpenSpec Capability: `cache-and-sync` (`openspec/specs/cache-and-sync/spec.md`)

# Cache, Synchronization, and Search Specification

## Purpose

Defines the database-backed cache layer (`DatabaseManager`, `SqlCacheAdapter`, `SqlLockAdapter`), schema hash auto-migration (`arodonata_schema_version`), distributed locks (`distributed_locks`), selective object and service synchronization (`ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `DomainSyncCoordinator`), and recursive object/group search (`SearchService`).

## Requirements

### Requirement: Schema Hash Auto-Migration and Multi-Backend Persistence

`DatabaseManager.initialize()` SHALL support PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`), prefix all Arodonata tables with `arodonata_` (`ARODONATA_TABLE_NAMES`), serialize schema migration across workers (`pg_advisory_xact_lock` on PostgreSQL, `BEGIN IMMEDIATE` on SQLite) with double-checked `schema_hash` and table-existence verification, and drop legacy unprefixed v1 tables ONLY when a positive v1 column fingerprint (`mdm_dmn` or `mgmt_dmn_key`) is present.

#### Scenario: Unchanged schema hash skips table inspection

- **WHEN** `DatabaseManager.initialize()` runs and, after acquiring the cross-worker initialization lock (`pg_advisory_xact_lock` or `BEGIN IMMEDIATE`), a row with the current `schema_hash` already exists in `arodonata_schema_version` and all tables in `ARODONATA_TABLE_NAMES` exist
- **THEN** the database manager SHALL skip per-table column/index migration inspection and mark the database initialized immediately; if any table in `ARODONATA_TABLE_NAMES` was dropped out-of-band, it SHALL re-run table creation even when `schema_hash` matched

#### Scenario: Schema evolution applies missing columns and records new hash

- **WHEN** the Arodonata SQLModel metadata changes (producing a new `schema_hash` not in `arodonata_schema_version`) on a database shared with host application tables in `SQLModel.metadata`
- **THEN** `DatabaseManager.initialize()` SHALL inspect only `arodonata_*` tables in `ARODONATA_TABLE_NAMES`, create any new Arodonata tables with naive UTC timestamp columns, add any missing columns/indexes (or recreate `arodonata_*` cache tables if column types or `NOT NULL` constraints changed) safely inside the serialized migration lock, and insert the new `schema_hash` row into `arodonata_schema_version`

#### Scenario: Legacy v1 cache table with incompatible primary key is dropped and recreated

- **WHEN** `DatabaseManager.initialize()` encounters an existing Arodonata table (such as `arodonata_*` with an incompatible schema or a legacy v1 `domains` / `sid_cache` table positively matching the v1 column fingerprint `mdm_dmn` or `mgmt_dmn_key`), or encounters an unprefixed host table (`domains`, `sid_cache`, `distributed_locks`, `domain_sync_state`) without the v1 column fingerprint
- **THEN** `DatabaseManager.initialize()` SHALL drop only positively fingerprinted legacy v1 tables and recreate incompatible `arodonata_*` tables while leaving unprefixed host tables completely untouched (neither dropping nor altering them)

### Requirement: Database-Backed Distributed Locks

`DatabaseLockManager` (`SqlLockAdapter`) SHALL coordinate cross-process critical sections using the `arodonata_distributed_locks` table with explicit lock expiration (`expires_at`) evaluated against the database server's UTC clock, owner-verified lock renewal (`renew` / heartbeat) and `release`, and retry resilience against transient database serialization/deadlock errors.

#### Scenario: Expired lock reclamation

- **WHEN** a worker requests a `lock_key` whose existing row in `arodonata_distributed_locks` has `expires_at` in the past according to the database server's current UTC timestamp
- **THEN** `DatabaseLockManager` SHALL atomically reclaim the expired lock for the new `owner_id`, and `release(lock_key, owner_id)` SHALL delete the row ONLY when `owner_id` matches the active holder

#### Scenario: Active sync renews distributed lock before TTL expiration

- **WHEN** a domain object, service, asset, or rulebase refresh holds a per-domain lock in `arodonata_distributed_locks`
- **THEN** the coordinator SHALL periodically renew `expires_at` via a background heartbeat while the refresh is active so long-running domain syncs never expire mid-flight

### Requirement: Object Cache Refresh Modes and Incremental Sync

`ObjectService` and `DomainSyncCoordinator` SHALL support four `CacheMode` values (`"cache"`, `"smart"`, `"smart-fast"`, and `"force"`), default to syncing `("host", "network", "address-range", "group", "dns-domain")` into `arodonata_objects`, track revision state per `(mgmt_name, domain_name, scope, item_type)` in `arodonata_domain_sync_state` within the same atomic transaction as data writes using dialect `ON CONFLICT` upserts, and expose `refresh_objects` and `stream_refresh_objects`.

#### Scenario: Smart/Check refresh reloads only stale domains atomically and handles never-published domains

- **WHEN** `await client.refresh_objects(mode="smart")` or a read helper with `cache_mode="smart"` runs
- **THEN** the coordinator SHALL compare each domain's `show-last-published-session` publish timestamp (`last_published_at`) and UID (`last_session_uid`, when timestamps match) against the requested `item_type` rows in `arodonata_domain_sync_state` (preserving `last_published_at=None` for never-published domains rather than fabricating `now`), verify the shared session is clean (failing closed if `show-session` fails), and reload only missing or stale `item_type` slices and their `arodonata_domain_sync_state` rows in a single atomic transaction under a renewed per-domain distributed lock

#### Scenario: Incremental refresh applies show-changes diff or falls back safely

- **WHEN** `await client.refresh_objects(mode="smart-fast")` or a read helper with `cache_mode="smart-fast"` detects stale `item_type` rows with a known baseline in `arodonata_domain_sync_state`
- **THEN** the service SHALL query `show-changes` preferring `from-session` (`last_session_uid`) over `from-date` (formatting `from-date` as an explicit UTC ISO-8601 string with `Z` suffix when used), unwrap `new-object` / `old-object` change entries, delete removed objects, upsert added/modified objects via dialect `ON CONFLICT`, and update `arodonata_domain_sync_state` atomically; if changes exceed `max_incremental_changes` (default 500) or any error occurs, it SHALL fall back automatically to an atomic type-scoped reload

#### Scenario: Refresh failure visibility and InvalidCredentialsError handling

- **WHEN** a domain's staleness probe or refresh fails with an API/authentication error (`InvalidCredentialsError`, etc.) versus encountering `LockAcquisitionError` because another worker is actively refreshing that domain
- **THEN** genuine errors SHALL be recorded in `RefreshOutcome.failed_domains`, `arodonata_domain_sync_state.last_error`, and `DomainSyncFailedEvent` with `redact_sid(..., known_sids=...)` applied while keeping previously cached objects intact, whereas `LockAcquisitionError` SHALL NOT overwrite `arodonata_domain_sync_state.status` as `"failed"` or emit a false failure event over the active worker's sync

#### Scenario: Parallel domain refresh per MDS member and background first-use warm-up

- **WHEN** `DomainSyncCoordinator.ensure()` refreshes multiple domains
- **THEN** domains SHALL be refreshed concurrently via `asyncio.TaskGroup` at up to `max(1, concurrent_limit - 1)` domains at once per MDS member (`active_mds_ip`, cancelling sibling tasks immediately if a fatal `ServerIdentityError` occurs), while `get_domains()` SHALL return the domain list without implicitly starting background object-cache warm-up (warm-up is invoked explicitly via `start_object_cache_warmup`)

### Requirement: Dedicated Service Cache Table and Selective Refresh

`ServiceCacheService` and `SqlCacheAdapter` SHALL persist service objects in `arodonata_services` (`CPService`) tracked per `(mgmt_name, domain_name, "services", item_type)` in `arodonata_domain_sync_state` in a single atomic transaction (preferring `from-session` over UTC `Z`-suffixed `from-date` in `"smart-fast"` mode), refreshing `("service-tcp", "service-udp", "service-icmp", "service-group")` by default and fetching other types only when requested in `types`.

#### Scenario: Default service refresh loads core variable service types

- **WHEN** `await client.refresh_services(mode="smart")` runs without an explicit `types` list
- **THEN** the service SHALL synchronize `service-tcp`, `service-udp`, `service-icmp`, and `service-group` rows into `arodonata_services` and record each type's `last_published_at`, `last_session_uid`, and `synced_at` in `arodonata_domain_sync_state` within the same atomic database transaction

#### Scenario: Explicit service types sync on demand without wiping other cached service types

- **WHEN** `await client.refresh_services(types=["service-other"])` is called on a domain that already has `service-tcp` cached
- **THEN** only `service-other` rows SHALL be fetched and replaced in `arodonata_services` (preserving existing `service-tcp` rows), and `arodonata_domain_sync_state` SHALL record the sync state for `item_type="service-other"`

### Requirement: Asset and Gateway Cache with Cluster and VSX Relationships

`AssetRefreshService` (`refresh_assets`, `stream_refresh_assets`) and `SqlCacheAdapter` SHALL persist gateways, clusters, cluster members, VSX gateways/clusters (via encapsulated `generic-object` topology queries), and management servers in the `arodonata_assets` table across domains concurrently via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`) with both UID primary keys (`id`) and indexed human-readable composite identifiers (`asset_id`), and enrich parent-child relationships (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, `virtual_system_asset_ids`) via `ClusterRelationshipManager` and `VSXRelationshipManager`, including cross-domain VSX parent/child links on the same management server.

#### Scenario: Concurrent domain asset collection with interleaved SSE events

- **WHEN** `stream_refresh_assets()` runs across multiple servers and domains
- **THEN** it SHALL collect domains concurrently per MDS member (`max(1, concurrent_limit - 1)`), persist rows in `arodonata_assets` (avoiding collision with host application `assets` tables), emit typed `SyncProgressEvent` items (convertible to `SSEEvent` via `adapters.sse`) tagged with `mgmt_name` and `domain`, link cluster members and VSX virtual systems to their parent asset UIDs and composite IDs (`parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`), and update `domain_sync_state` (`scope="assets"`, `item_type="*"`)

#### Scenario: Cross-domain VSX gateway and Virtual System topology reconciliation

- **WHEN** a VSX gateway (`vsx_gateway` or `vsx_cluster`) is cached in one domain (e.g., `"VSX"`) and its Virtual System (`virtual_system`) is cached in another domain (e.g., `"Domain4"`) on the same management server (`mgmt_name`)
- **THEN** asset relationship reconciliation SHALL populate the Virtual System's `parent_uid`, `parent_name`, `parent_id` (`"mds:VSX:<vsx-uid>"`), and `parent_asset_id` (`"mds:VSX:<vsx-name>"`), and populate the parent VSX asset's `virtual_system_uids` and `virtual_system_asset_ids` (`["mds:Domain4:<vs-name>"]`)

### Requirement: Human-Readable Composite Identifiers and Dual Topology Links

`CPObject` (`arodonata_objects`), `CPService` (`arodonata_services`), and `Asset` (`arodonata_assets`) SHALL keep `id = "{mgmt_name}:{domain_name}:{uid}"` as primary key while persisting non-unique indexed human-readable keys (`object_id`, `service_id`, `asset_id` formatted as `"{mgmt_name}:{domain_name}:{name}"`) and dual UID/human-readable parent-child links on `Asset` and `GroupMembershipNode`.

#### Scenario: Duplicate-named objects with distinct UIDs coexist with identical human-readable IDs

- **WHEN** a domain contains two Check Point objects or services with the same `name` (such as `email`) and different `uid` values
- **THEN** both rows SHALL be stored without collision under their distinct `id` primary keys (`"{mgmt_name}:{domain_name}:{uid}"`) while both expose the same indexed `object_id` or `service_id` (`"{mgmt_name}:{domain_name}:{name}"`)

#### Scenario: Object rename during incremental sync updates object_id in place

- **WHEN** an existing Check Point object is renamed and synchronized via `"smart-fast"` (`show-changes`) or full refresh
- **THEN** the existing database row identified by `id = "{mgmt_name}:{domain_name}:{uid}"` SHALL be updated in place with the new `name` and recomputed `object_id = "{mgmt_name}:{domain_name}:{new_name}"` without leaving an orphaned row under the old name

#### Scenario: Cluster and cross-domain VSX assets populate both UID and human-readable parent/child links

- **WHEN** `ClusterRelationshipManager` and `VSXRelationshipManager` enrich gateway, cluster, cluster-member, VSX, and virtual-system assets (including a virtual system in a tenant domain hosted on a VSX gateway/cluster in another domain on the same `mgmt_name`)
- **THEN** child assets SHALL populate `parent_uid`, `parent_name`, `parent_id` (`"{mgmt_name}:{parent_domain}:{parent_uid}"`), and `parent_asset_id` (`"{mgmt_name}:{parent_domain}:{parent_name}"`), and parent cluster/VSX assets SHALL populate `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`

#### Scenario: Group membership traversal includes human-readable group composite IDs

- **WHEN** `search_objects()` resolves containing parent groups for matched objects
- **THEN** each `GroupMembershipNode` in `SearchResult.memberships` SHALL include `id` (`"{mgmt_name}:{domain_name}:{uid}"`), `object_id` (`"{mgmt_name}:{domain_name}:{name}"`), `parent_uids`, and `parent_object_ids`

### Requirement: Cache-First Object Search with Recursive Group Membership Resolution

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4 address, CIDR subnet, address range, wildcard pattern, UID, human-readable composite identifier `object_id` / `id`, or object name), support `exact_match: bool = False` for case-insensitive exact name/FQDN matching, query cached objects (including any active `WriteSession` overlay in `contextvars`) across target servers and domains, and traverse parent group memberships up to `max_depth` (default 2), returning a typed `SearchResult` whose `GroupMembershipNode` entries include `id`, `object_id`, `parent_uids`, and `parent_object_ids`.

#### Scenario: Search resolves direct matches and containing groups with human-readable composite IDs

- **WHEN** `await client.search_objects("10.1.10.50", max_depth=2)` or `await client.search_objects("mds:General:hWebHost", max_depth=2)` is called
- **THEN** it SHALL return a `SearchResult` containing both the matching host/network objects (reflecting any uncommitted `WriteSession` overlay in the current context) and the hierarchy of groups (`memberships`) that directly or transitively contain those objects, with each `GroupMembershipNode` populated with `id`, `object_id`, `parent_uids`, and `parent_object_ids`

#### Scenario: Exact-match name search avoids partial substring matches

- **WHEN** `await client.search_objects(".example.com", exact_match=True)` is called on a domain containing `.example.com` and `sub.example.com`
- **THEN** it SHALL return only `.example.com` (and its parent groups) without matching `sub.example.com`, while wildcard terms (`*.example.com`) continue to match via anchored `fnmatchcase`


---

### OpenSpec Capability: `change-reports` (`openspec/specs/change-reports/spec.md`)

# Auditable Session Change Report Specification

## Purpose

Defines read-only collection (`collect_change_report`), rulebase placement numbering (`placement.py`), and multi-format rendering (`render_change_report`, `build_change_report`) of Check Point policy session change evidence (`ChangeReport`) across explicit session UIDs (`SessionScope`) and published session/date ranges (`RangeScope`).

## Requirements

### Requirement: Scope Validation and Read-Only Change Collection

`collect_change_report(client, scopes, ...)` SHALL validate `SessionScope` and `RangeScope` inputs strictly (raising `pydantic.ValidationError` or `ChangeReportInputError` on invalid bounds or naive datetimes), query `show-changes` read-only across target management servers and domains, deduplicate sessions named by multiple scopes, and record partial runtime failures as structured `ReportWarning` entries rather than aborting the whole report.

#### Scenario: Single-session change collection via to-session query and container filtering

- **WHEN** a `SessionScope` requests changes for explicit `session_uids`
- **THEN** the collector SHALL call `show-changes` with `{"to-session": s_uid, "details-level": "full"}` (omitting `from-session: s_uid` because `from-session` is exclusive in Check Point `show-changes`), filter the returned `changes[]` containers to the matching `session-uid`, and classify `modified-objects` entries that contain `new-object` without `old-object` as `"added"`

#### Scenario: Timezone-aware date range conversion and exact publish-time filtering

- **WHEN** a `RangeScope` includes timezone-aware `from_date` and/or `to_date`
- **THEN** the collector SHALL convert the bounds to the server's UTC offset, widen the server query window safely (or omit server date parameters when `from_session` is also given), and filter returned sessions by exact UTC publish timestamp

#### Scenario: Reference UID name resolution with bounded show-object lookups

- **WHEN** `show-changes` returns bare UIDs for group members or NAT fields not already named in the session's own change entries
- **THEN** the collector SHALL resolve up to 200 distinct UIDs per report via read-only `show-object` calls and emit a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails

### Requirement: Owned Session Live Numbering and Cached Snapshot Fallback

The change report builder SHALL number added, modified, moved, and deleted rules according to SmartConsole hierarchy using either a caller-supplied unpublished `OwnedSession` (`sid`, `server_ip`) or the domain's cached rulebase snapshot, labeling each session with its exact numbering basis.

#### Scenario: Read-only live numbering via OwnedSession with strict SID hygiene

- **WHEN** a `SessionScope` supplies an `OwnedSession` matching an unpublished session in the scope
- **THEN** the collector SHALL verify ownership via `show-session`, read `show-packages` and `show-*-rulebase` using that SID strictly read-only (never publishing, discarding, or logging out), label the session `"Numbering read live in the owned session at <time> UTC"`, and NEVER include or log the SID in `ChangeReport`, `RawResponse`, HTML, JSON, Markdown, or `repr()`

#### Scenario: Graceful fallback when OwnedSession is already published or expired

- **WHEN** a supplied `OwnedSession` no longer corresponds to an unpublished session or its SID fails
- **THEN** the collector SHALL record an `owned_session_not_used` or `owned_session_error` warning and fall back to numbering from the rulebase cache

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: Self-contained HTML evidence output

- **WHEN** `"html"` is requested in `formats`
- **THEN** `render_change_report` SHALL produce a single self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, zero external network assets, visual change indicators (`NEW`, `DELETED`, yellow field diffs, moved rule badges, disabled `✗` markers), and per-rule field diff detail tables

#### Scenario: Round-trip JSON serialization with format_version check

- **WHEN** a `ChangeReport` is serialized to `"json"` and reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access, and reject JSON files whose `format_version` is newer than supported by the installed library


---

### OpenSpec Capability: `client-and-facade` (`openspec/specs/client-and-facade/spec.md`)

# Client Facade, Ports/Adapters, and Telemetry Specification

## Purpose

Defines the primary composition root and unified developer facade (`ArodonataClient`), hexagonal architectural ports (`ApiPort`, `CachePort`, `LockPort`) and adapters (`AMgmtClient`, `SqlCacheAdapter`, `SqlLockAdapter`), `contextvars`-aware session and object mutation methods, and OpenTelemetry instrumentation (`telemetry.py`).

## Requirements

### Requirement: Hexagonal Composition Root and Lifecycle Management

`ArodonataClient` SHALL serve as the unified composition root wiring `ApiPort` (`AMgmtClient`), `CachePort` (`SqlCacheAdapter`), and `LockPort` (`SqlLockAdapter`) into core domain services, defaulting `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) and cleaning up sessions, background tasks, and owned engines deterministically on `close()` / `__aexit__()`.

#### Scenario: Context manager initializes database and drains or cancels background work on close

- **WHEN** `async with ArodonataClient(...) as client:` enters and exits
- **THEN** `__aenter__` SHALL initialize the database schema (and schedule startup session cleanup if static credentials are present), and `__aexit__` (`close()`) SHALL cancel any running background warm-up tasks immediately, drain startup cleanup tasks up to the grace period, close `AMgmtClient`, and dispose of the SQLAlchemy engine ONLY if `client` auto-created it (`_owns_engine == True`)

#### Scenario: Automatic logout policy on client close

- **WHEN** `client.close(logout=None)` is called
- **THEN** the client SHALL automatically log out active Check Point sessions if it auto-created an in-memory database (`_owns_engine == True`), and preserve cached read-only sessions in the database if an external persistent engine was provided

### Requirement: Typed Read Facade and Domain Invalidation

`ArodonataClient` SHALL expose typed async read methods returning Pydantic v2 models (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_services`, `get_object_by_uid`, `get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules`) with `cache_mode` and `cache_ttl` overrides, overlay uncommitted `WriteSession` changes from `contextvars`, and invalidate domain freshness memos on publish (`invalidate_domain`).

#### Scenario: Read helpers reflect active WriteSession overlay via contextvars

- **WHEN** `await client.get_hosts(mgmt_name, domain)` or `await client.get_services(mgmt_name, domain)` is called inside an active `async with client.write_session(mgmt_name, domain):` block
- **THEN** the returned list SHALL include objects created or updated in that `WriteSession` and exclude objects deleted in that `WriteSession` without mutating the shared database rows

#### Scenario: Publish via api_call invalidates domain freshness memos

- **WHEN** a `WriteSession` publishes or `await client.api_call(mgmt_name, "publish", domain=domain)` succeeds
- **THEN** `client.invalidate_domain(mgmt_name, domain)` SHALL be invoked automatically so the next `"smart"` or `"smart-fast"` read re-checks the domain's published session head even within `cache_ttl`

### Requirement: User-Aware Domain Helper Functions

`ArodonataClient` SHALL provide session and object mutation/lookup methods (`write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`) propagating `WriteSession`, `AuthContext`, and `UserContext` via `contextvars`, resolving `find_object` across cached `arodonata_objects` (`CPObject`), `arodonata_services` (`CPService`), and `arodonata_assets` (`Asset`) by UID, name, or composite identifier (`object_id`, `service_id`, `asset_id`, `id`), expanding `get_group_members` across network groups (`arodonata_objects`), service groups (`arodonata_services`), and cluster/VSX containers (`arodonata_assets`, including cross-domain Virtual Systems), auto-wrapping standalone object mutations in an isolated write session, stripping secret request fields from `SessionOverlay`, and masking secrets in `ApiCallResult`.

#### Scenario: Context manager write_session publishes on success and discards on exception

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_auth)` is entered
- **THEN** it SHALL open an isolated write session, bind it to `contextvars` so nested mutations and reads use its SID and `SessionOverlay` (with secret request keys such as `one-time-password`, `shared-secret`, `password`, and `api-key` stripped from cached `raw_data`), auto-publish on clean exit (or discard before logout if `publish` returns `success=False`), and automatically shield `discard` and `logout_sid` on any unhandled `BaseException` (including `asyncio.CancelledError`)

#### Scenario: Standalone object mutation helpers never dirty the shared read-only SID cache

- **WHEN** `await client.add_object(...)`, `await client.set_object(...)`, or `await client.delete_object(...)` is called outside an active `async with client.write_session(...)` block and without an explicit `sid`
- **THEN** the helper SHALL execute inside a dedicated isolated session (never using the shared `arodonata_sid_cache` session) and `ApiCallResult.__repr__()` SHALL redact `sid` and secret payload fields

#### Scenario: find_object and get_group_members resolve across objects, services, and assets by UID, name, or composite ID

- **WHEN** `await client.find_object(mgmt_name, domain, name_or_uid)` or `await client.get_group_members(mgmt_name, domain, group_name_or_uid)` is called with a raw UID, object name, or composite identifier (`object_id`, `service_id`, `asset_id`, or `id`, such as `"mds:General:hWebHost"` or `"mds:VSX:VSX-Cluster-01"`)
- **THEN** `find_object` SHALL look up the target across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` (returning `CPObject | CPService | Asset | None` with `object_id` / `service_id` / `asset_id` populated), and `get_group_members` SHALL expand direct and recursive members of a network group (`CPObject`), a `service-group` (`CPService`), or a cluster/VSX parent asset (`Asset` via `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`, including cross-domain Virtual Systems) from cache

### Requirement: Composite Identifier Resolution in Facade and Search Helpers

`ArodonataClient.find_object()`, `ArodonataClient.get_group_members()`, `SearchService.search_objects()`, and `SearchService.query_objects()` SHALL accept and filter by composite human-readable identifiers (`object_id`, `service_id`, `asset_id` formatted as `"{mgmt_name}:{domain_name}:{name}"`) or composite UID keys (`id` formatted as `"{mgmt_name}:{domain_name}:{uid}"`) in addition to raw `name` or `uid`.

#### Scenario: find_object and get_group_members resolve composite human-readable IDs

- **WHEN** `await client.find_object(mgmt_name, domain, "mds:General:hWebHost")` or `await client.get_group_members(mgmt_name, domain, "mds:General:Cluster01")` is called with a composite `object_id`, `service_id`, `asset_id`, or `id`
- **THEN** the helper SHALL match the corresponding `CPObject`, `CPService`, or `Asset` (or expand its members/child assets) identically to passing the raw `name` or `uid`

#### Scenario: Structured query_objects and describe_objects expose composite ID fields

- **WHEN** `await client.describe_objects()` or `await client.query_objects(...)` is called
- **THEN** `describe_objects()` SHALL list `id`, `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id` among filterable fields, and `query_objects()` SHALL include the composite fields on returned items

### Requirement: Provider-Agnostic OpenTelemetry Instrumentation and Secret Redaction

All major client, transport, login, lock, cache, and CPCRUD entry points SHALL be decorated with `@traced` and attach `arodonata.*`-namespaced span attributes (`span_attrs`) while recursively sanitizing mappings, nested lists/tuples, and chained exception causes (`__cause__` and `__context__`) so credentials, API keys, or unredacted session SIDs are never recorded.

#### Scenario: Span attributes omit None values and never expose secrets

- **WHEN** `span_attrs(**attrs)` is called inside a traced operation or an exception with a chained `__cause__` / `__context__` is recorded on a span
- **THEN** non-`None` attributes SHALL be set on the current OpenTelemetry span under the `arodonata.<key>` namespace with recursive secret/SID redaction applied to mappings, lists, and chained exception messages, operating as a zero-overhead no-op when no `TracerProvider` is configured by the host application


---

### OpenSpec Capability: `configuration` (`openspec/specs/configuration/spec.md`)

# Configuration and Settings Specification

## Purpose

Defines explicit, type-safe configuration resolution for Arodonata (`ArodonataSettings`) and its MCP server (`ArodonataMCPSettings`), supporting static API-key multi-server topologies, static credential authentication, and dynamic/deferred authentication without ever reading `.env` files implicitly inside the library.

## Requirements

### Requirement: Explicit Settings Resolution Without Implicit File Loading

The library SHALL resolve configuration from explicit constructor keyword arguments and `os.environ` via `ArodonataSettings` without reading `.env` files automatically, anchor default `tls_known_hosts_path` to `~/.config/arodonata/tls_known_hosts.json` rather than the working directory, and mask all secret fields (`password`, `api_key`, `api_keys`, `mcp_tokens`, and `database_url` credentials) across `repr()`, `str()`, `model_dump()`, and `model_dump_json()`.

#### Scenario: Constructor keyword overrides environment variable

- **WHEN** `ArodonataSettings` is instantiated with a constructor keyword argument (e.g., `concurrent_limit=8`) while `ARODONATA_CONCURRENT_LIMIT=4` is set in `os.environ`
- **THEN** the resulting settings instance SHALL use `concurrent_limit == 8`

#### Scenario: Environment variable populates field by default

- **WHEN** `ArodonataSettings()` is instantiated without keyword arguments and `ARODONATA_SESSION_TIMEOUT=900` is present in `os.environ`
- **THEN** `settings.session_timeout` SHALL equal `900`

#### Scenario: Secrets and database URL passwords masked in repr and serialization

- **WHEN** `repr(settings)`, `settings.model_dump()`, or `settings.model_dump_json()` is called on an `ArodonataSettings` instance configured with `password`, `api_keys`, or `database_url="postgresql+asyncpg://user:secretpass@db.internal:5432/app"`
- **THEN** all passwords, API keys, and the password component of `database_url` SHALL be masked (`"***"`) unless an explicit secret getter is invoked internally

#### Scenario: Default TLS known-hosts path is independent of working directory

- **WHEN** `ArodonataSettings()` is instantiated without an explicit `tls_known_hosts_path` across different working directories
- **THEN** `tls_known_hosts_path` SHALL resolve to the same absolute user-scoped path (`~/.config/arodonata/tls_known_hosts.json`) so changing `os.getcwd()` never resets TOFU trust state

### Requirement: Positional Multi-Server Topology Configuration

The system SHALL support configuring multiple Check Point management servers via comma-separated `mgmt_names` and `mgmt_servers`, optionally paired by position with `api_keys` (or `API_KEY_VARS`), using a single consistent precedence order (`api_keys` keyword/env over `API_KEY_VARS`) across both library and CLI entry points.

#### Scenario: Valid positional server and API key resolution via API_KEY_VARS

- **WHEN** `MGMT_NAMES="mds1,sms2"`, `MGMT_SERVERS="10.0.0.1,10.0.0.2"`, and `API_KEY_VARS="KEY_MDS1,KEY_MDS2"` are set along with `KEY_MDS1="secret1"` and `KEY_MDS2="secret2"`
- **THEN** `ArodonataSettings` SHALL resolve `mgmt_names` to `["mds1", "sms2"]`, `mgmt_servers` to `["10.0.0.1", "10.0.0.2"]`, and pair `"mds1"` with `"secret1"` and `"sms2"` with `"secret2"`

#### Scenario: Precedence of API_KEYS vs API_KEY_VARS in library vs MCP CLI

- **WHEN** both `API_KEYS` and `API_KEY_VARS` are present in the environment
- **THEN** `ArodonataSettings` SHALL consistently prioritize explicit `API_KEYS` over `API_KEY_VARS` in both library and CLI modes

#### Scenario: Mismatched server and key counts

- **WHEN** static API keys are configured and the number of entries in `mgmt_names`, `mgmt_servers`, and resolved API keys do not match
- **THEN** server registry validation SHALL raise `ConfigurationError` describing the count mismatch

### Requirement: Authentication Mode and Default Engine Resolution

The system SHALL resolve `auth_mode` to `"api_key"`, `"credential"`, or `"dynamic"` (deferred credentials when servers are configured without static keys or passwords), and SHALL default `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) across all authentication modes.

#### Scenario: Credential mode requires management server IP or topology

- **WHEN** `username` and `password` are provided without `mgmt_ip` or `mgmt_servers`
- **THEN** initialization SHALL raise `MissingConfigurationError` stating that a target management server address is required

#### Scenario: Omitted engine auto-creates in-memory SQLite in any authentication mode

- **WHEN** `AMgmtClient` or `ArodonataClient` is initialized with `engine=None` in `"api_key"`, `"credential"`, or `"dynamic"` mode
- **THEN** the client SHALL automatically create and own an in-memory `sqlite+aiosqlite:///:memory:` engine and dispose of it upon `client.close()`

#### Scenario: Dynamic mode initializes cleanly without static credentials

- **WHEN** `MGMT_NAMES="mds1"` and `MGMT_SERVERS="10.0.0.1"` are configured without `api_keys` or `username`/`password`
- **THEN** `ArodonataSettings` SHALL resolve `auth_mode == "dynamic"` without raising `MissingConfigurationError`, deferring credential resolution to runtime `AuthContext` or `AuthProvider`

### Requirement: Separate Operational Timeout Budgets

The configuration SHALL maintain distinct timeout settings for TCP/TLS connection establishment (`connect_timeout`, default 30s), standard API calls (`api_timeout`, default 120s), login attempts (`login_timeout`, default 120s), long-running server tasks (`task_timeout`, default 900s), and rate-limiter slot acquisition (`rate_limit_slot_timeout`, default 90s).

#### Scenario: Default read timeout calculation on transport socket

- **WHEN** `ApiTransport` is configured from `ArodonataSettings`
- **THEN** the socket connect/handshake timeout SHALL be `connect_timeout`, a call with an explicit budget SHALL use `budget + 5` seconds as its socket read timeout, and calls without an explicit per-call budget (such as `show-task` polls) SHALL use `max(api_timeout, login_timeout) + 5` seconds

### Requirement: OpenTelemetry Module Span Gating Configuration

The system SHALL support hierarchical dotted-prefix span gating via `ARODONATA_TRACE_MODULES` (`trace_modules`) without owning or resetting the host application's global `TracerProvider` unless rules are explicitly configured.

#### Scenario: Empty trace_modules preserves host tracing rules

- **WHEN** `ArodonataClient` is initialized with `trace_modules=""` (the default)
- **THEN** it SHALL NOT call `set_trace_modules({})` or overwrite any existing process-global trace gating configuration set by the host application

#### Scenario: Explicit trace_modules applies longest-prefix rules

- **WHEN** `ARODONATA_TRACE_MODULES="arodonata:on,arodonata.api.client:off"` is configured
- **THEN** `trace_modules_rules` SHALL parse into `{"arodonata": True, "arodonata.api.client": False}` and apply to `@traced` spans


---

### OpenSpec Capability: `cpcrud` (`openspec/specs/cpcrud/spec.md`)

# CPCRUD Declarative Policy-as-Code Engine Specification

## Purpose

Defines the declarative, idempotent Check Point CRUD engine (`CPCRUDService`, `Planner`, `HybridStateReader`, `Executor`, `Differ`, `build_inverse_template`) for validating, planning, applying, and rolling back security object, service, and rulebase changes across management servers and domains.

## Requirements

### Requirement: Offline JSON Schema Validation

`CPCRUDService.validate()` SHALL validate YAML/JSON templates against `checkpoint_ops_schema.json` (or `cpcrud_schema_path` override) using `jsonschema.Draft7Validator` without making any network or database calls.

#### Scenario: Invalid template returns structured schema errors

- **WHEN** `validate(template)` is called with a template violating `checkpoint_ops_schema.json`
- **THEN** it SHALL return a non-empty list of human-readable validation error strings and perform zero API calls

### Requirement: Two-Axis Conflict Resolution and Idempotent Planning

`CPCRUDService.plan()` (`Planner.decide`) SHALL inspect state via an isolated `HybridStateReader` per run (using `arodonata_objects` and `arodonata_services` when `arodonata_domain_sync_state` matches the domain head), validate template `type` values against the CPCRUD allowlist, reject duplicate operation `id` values, evaluate `NameConflictPolicy` and `IpConflictPolicy`, compute field diffs (`differ.py`), and produce a `Plan` with SID-redacted `DomainStamp` records read before domain lookups.

#### Scenario: Re-planning an already-applied template yields UNCHANGED or REUSE

- **WHEN** `plan(template)` runs against a domain where all desired objects, services, and rules already exist with matching attributes
- **THEN** every planned action SHALL have `Outcome.UNCHANGED` or `Outcome.REUSE` and require zero API write operations during `apply()`

#### Scenario: IP conflict with create_new auto-names object using NamingPrefixes

- **WHEN** a host or network operation encounters an IP/subnet match under a different name and `on_ip_conflict="create_new"` is active
- **THEN** the planner SHALL generate a convention-compliant name using `NamingPrefixes` (`Host_`, `Net_`, `IPR_`, `TCP_`, `UDP_`, `ICMP_`)

#### Scenario: Failed state lookup produces ERROR action rather than false CREATE

- **WHEN** an API or cache lookup (including `dns-domain` leading-dot retry, name lookup, IP lookup, service port listing, rulebase read, or `where-used`) fails or returns `paging_inconsistent`, or when a domain's `show-last-published-session` head cannot be read
- **THEN** the planner SHALL NOT treat the failure as "not found"; it SHALL plan an `Outcome.ERROR` action (`lookup failed, nothing planned (re-plan to retry): ...`) with SID-redacted error details that writes nothing and marks dependent actions as `skipped_dependency`

#### Scenario: Cache-first object lookups gated by exact domain head stamp

- **WHEN** `HybridStateReader` looks up a host, network, address range, dns-domain, group, or service during `plan()`
- **THEN** it SHALL read from `arodonata_objects` or `arodonata_services` ONLY while the domain's stored `arodonata_domain_sync_state` row for that specific `(scope, item_type)` matches the head `last_published_at` and `last_session_uid` read by the planner at the start of `plan()`, falling back to live API queries otherwise

#### Scenario: Duplicate template operation IDs or unknown object types rejected

- **WHEN** `plan(template)` encounters two operations with the same `id` or an `object_type` outside the canonical CPCRUD type registry
- **THEN** `plan()` SHALL raise `ValidationError` (or record a validation failure) rather than silently overwriting action results or constructing arbitrary `show-<type>` / `add-<type>` commands

### Requirement: Rule Identity Matching, Cleanup-Aware Positioning, and NAT Sentinels

The planner and position helper SHALL resolve access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`) or by traffic tuple, support cleanup-rule-aware `"bottom"` positioning, and normalize Check Point NAT `"Original"` and `"Any"` sentinel UIDs (`NAT_ORIGINAL_OBJECT_UID`, `NAT_ANY_OBJECT_UID`).

#### Scenario: Cleanup-aware bottom rule placement

- **WHEN** a rule operation specifies `position="bottom"` or `position={"bottom": "<section>"}` and the last rule in that layer or section is an `Any / Any / Any` cleanup rule
- **THEN** `position_helper` SHALL anchor the new rule at `{"above": "<cleanup_rule_uid>"}` instead of placing it after the cleanup rule

#### Scenario: NAT rule traffic matching with Original sentinel normalization

- **WHEN** a NAT rule with empty/Original `translated-*` fields is planned against a live NAT rulebase
- **THEN** `rule_identity` and `differ` SHALL match Check Point's dereferenced `"Original"` sentinel UID (`NAT_ORIGINAL_OBJECT_UID`) as equivalent to no translation so re-applying the template reports `Outcome.UNCHANGED` rather than creating a duplicate rule

### Requirement: Dedicated-Session Execution, Stale Plan Safeguard, and Session Staging

`CPCRUDService` SHALL provide `apply` and `stream_apply`, deriving Web API commands strictly from an allowlist of `(object_type, operation)` pairs, executing actions in an isolated `WriteSession` per `(mgmt_name, domain_name)`, verifying the domain head has not drifted before each pass and immediately before `publish`, shielding `discard` before `logout` on any unhandled `BaseException`, and providing `publish_staged_session` and `discard_staged_session`.

#### Scenario: Stale plan abort when domain published after planning

- **WHEN** `apply(plan, force=False)` runs (on the initial pass, on any `retry_remaining` pass, or immediately before issuing `publish`) and a target domain's current `show-last-published-session` UID or `last_published_at` differs from the `DomainStamp` recorded in `plan` (including when `stamp.last_session_uid is None` and the domain now has a published session, or when the head cannot be read)
- **THEN** the executor SHALL mark all remaining actions in that domain as `Outcome.PLAN_STALE` (or discard the uncommitted session if detected pre-publish) and publish no writes in that domain

#### Scenario: Forged or unlisted action command rejected before execution

- **WHEN** `apply(plan)` receives a `PlannedAction` whose `object_type` and `operation` do not map to the canonical CPCRUD command allowlist or whose `command` field disagrees with the allowlisted command for `(object_type, operation)`
- **THEN** the executor SHALL reject the action with `ValidationError` before opening a session or sending any Web API call

#### Scenario: Unhandled exception, cancellation, or publish failure discards uncommitted session before logout

- **WHEN** an exception, `asyncio.CancelledError`, or `publish` transport/task failure occurs while executing a domain in `apply()` or `stream_apply()` (unless `no_publish=True and keep_session=True` completed cleanly or recorded the staged session prior to error)
- **THEN** the executor SHALL shield `discard` followed by `logout_sid` in `finally` so no uncommitted changes or object locks remain orphaned on the management server, and record any staged session opened under `keep_session=True` as soon as the session is created

#### Scenario: Keep-session staging mode preserves unpublished session for external workflow

- **WHEN** `apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** the executor SHALL leave the dedicated write session open without publishing, record its details (`sid`, `server_ip`, `session_uid`, `session_name`) in `ApplyReport.staged_sessions` immediately upon session creation, and emit a `StagedSessionEvent` (`CPCRUDEvent`) in `stream_apply()`

#### Scenario: Staged session publication adopts ownership via take-over-session and invalidates domain cache

- **WHEN** `await client.publish_staged_session(mgmt_name, domain, session_uid=session_uid)` or `client.stream_publish_staged_session(...)` is called for a previously staged session
- **THEN** the service SHALL adopt ownership of `session_uid` via `take-over-session` (`uid=session_uid`), execute `publish` (`payload={}`) while polling task progress, log out the session, and call `client.invalidate_domain(mgmt_name, domain)`

#### Scenario: Staged session discard adopts ownership via take-over-session before discarding

- **WHEN** `await client.discard_staged_session(mgmt_name, domain, session_uid=session_uid)` is called for an open or orphaned staged session
- **THEN** the service SHALL issue `take-over-session` (`uid=session_uid`) prior to `discard` so foreign locks or session ownership divergence do not prevent clean session termination

#### Scenario: Post-publish domain cache invalidation and retry_remaining folding

- **WHEN** `apply()` publishes changes in a domain or `retry_remaining > 0` re-runs failed/remaining actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called so subsequent smart reads re-sync the domain, and retry passes SHALL re-verify domain head freshness (never forcing `force=True` automatically) and fold their `ApplyReport` into the cumulative report

### Requirement: Compensating Rollback Template Generation

`CPCRUDService.inverse(plan, report)` SHALL build a schema-valid compensating template from `Plan` and `ApplyReport`, inverting only actions that actually succeeded when `report` is supplied, targeting created objects by the real `uid` returned in `ApplyReport` (refusing unsafe delete-by-name for unexecuted `planned:` UIDs), and restoring all mutated fields present in `PlannedAction.prior_state`.

#### Scenario: Inverse template restores deleted and updated objects and removes created ones

- **WHEN** `inverse(plan, report)` is called after an apply pass where some actions succeeded and others failed or were skipped/stale
- **THEN** it SHALL produce a dictionary valid against `checkpoint_ops_schema.json` that includes compensating operations ONLY for actions that succeeded in `report`, deletes `CREATE` actions using the concrete `uid` recorded in `report` (skipping any `CREATE` that lacks a real created UID), restores all prior field values from `prior_state` for `UPDATE` actions, and re-creates `DELETE` actions from `prior_state`


---

### OpenSpec Capability: `integration-testing-and-examples` (`openspec/specs/integration-testing-and-examples/spec.md`)

# Integration Testing and Examples Specification

## Purpose

Defines the live Check Point integration testing harness (`tests/integration/b1..b7`), the `./pytest.sh` runner separating the mandatory zero-network unit test gate (`tests/unit/`) from bucketed live-environment integration suites, the lab safety net (exclusive run lock, unauthenticated API readiness gate, and automatic revision baseline snapshot/restore), and the runnable SDK usage examples (`examples/`).

## Requirements

### Requirement: Unit and Integration Test Separation and Runner

The repository SHALL separate fast, zero-network unit tests (`tests/unit/`) from live Check Point integration tests (`tests/integration/b1..b7`) and provide an executable `./pytest.sh` runner at the repository root.

#### Scenario: Default test invocation executes only fast unit tests

- **WHEN** `./pytest.sh`, `./pytest.sh unit`, or bare `uv run pytest` is executed
- **THEN** pytest SHALL run only unit tests (`-m "not integration"`) with verbose test names (`-v`) by default, excluding `tests/integration/`, with zero network access required so it acts as a fast mandatory pre-PR quality gate

#### Scenario: Single integration bucket runs in an isolated session with short tracebacks

- **WHEN** `./pytest.sh int-<N>` (`N` in `1..7`) is executed
- **THEN** it SHALL launch an isolated `pytest` session targeting `tests/integration/b<N>` with verbose output (`-v`), live CLI info logging (`-o log_cli=true --log-cli-level=INFO`), `--durations=15`, and `--tb=short` so frame-local credentials or API keys are never printed on failure

#### Scenario: Full integration suite runs all buckets sequentially with throttle pauses

- **WHEN** `./pytest.sh int-full` is executed
- **THEN** it SHALL execute buckets `b1` through `b7` in separate sequential `pytest` sessions, pausing `BUCKET_PAUSE_SECONDS` (default `90` seconds) between buckets to clear Check Point's per-IP login rate-limit window, continuing past failed buckets, and exiting non-zero if any bucket failed

#### Scenario: Unknown integration target is rejected before pytest collection

- **WHEN** `./pytest.sh int-unknown` is executed with an invalid `int-*` target
- **THEN** `./pytest.sh` SHALL exit with code `2` and print valid bucket targets (`int-1`..`int-7`, `int-full`) instead of passing the invalid argument to `pytest`

### Requirement: Automatic Directory-Based Integration Markers

Integration tests under `tests/integration/` SHALL automatically receive `integration` and `bucket_<N>` pytest markers from their directory path during collection without manual per-test marker declarations.

#### Scenario: Collection hook applies integration and bucket markers

- **WHEN** `pytest` collects test items located under `tests/integration/b<N>/`
- **THEN** the collection hook SHALL automatically attach `pytest.mark.integration` and `pytest.mark.bucket_<N>` to each item and sort collected integration items by bucket number

### Requirement: Multi-Profile Lab Environment Loader

The integration harness and diagnostic scripts SHALL load lab configuration deterministically from `.env.test`, `.env.secrets`, and an optional `.env.lab.<ARODONATA_LAB>` profile override.

#### Scenario: Default lab environment loads when ARODONATA_LAB is unset

- **WHEN** `load_lab_env()` is called without `ARODONATA_LAB` set
- **THEN** it SHALL load `.env.test` followed by `.env.secrets` with `override=True` and return `None` as the active profile name

#### Scenario: Named lab profile layers overrides and expands secret references

- **WHEN** `ARODONATA_LAB=<profile>` is set and `.env.lab.<profile>` exists
- **THEN** `load_lab_env()` SHALL load `.env.lab.<profile>` after `.env.test` and `.env.secrets`, expanding `${VAR}` secret references and returning `<profile>`

#### Scenario: Missing selected lab profile fails fast

- **WHEN** `ARODONATA_LAB=<profile>` is set but `.env.lab.<profile>` does not exist
- **THEN** `load_lab_env()` SHALL raise `LabProfileMissing` rather than silently falling back to `.env.test`

### Requirement: Exclusive Integration Run Lock and Lab Readiness Gate

Each integration session SHALL acquire a non-blocking exclusive OS file lock (`_tmp/integration.lock`) and verify that the target Check Point API server is responsive before touching the SQLite cache database or logging in.

#### Scenario: Concurrent integration run fails fast on lock contention

- **WHEN** an integration session starts while another process holds `_tmp/integration.lock`
- **THEN** `IntegrationRunLock.acquire()` SHALL raise `IntegrationRunLocked` naming the holding PID and start timestamp, and the session SHALL exit immediately with return code `3`

#### Scenario: Readiness gate probes API server without spending login allowance

- **WHEN** the `lab_ready` session fixture runs against `API_MGMT`
- **THEN** it SHALL poll `show-api-versions` without a session header (`sid=None`) up to `ARODONATA_TEST_READY_WAIT` seconds, treating a Check Point JSON error code (`generic_err_missing_required_header`) or `success=True` as proof the API server is awake without consuming any per-minute login rate-limit slot, or abort with return code `4` if the budget expires

### Requirement: Automatic Revision Baseline Snapshot and Teardown Revert

Integration sessions SHALL snapshot the last published revision (`show-last-published-session`) of `TEST_DOMAIN_A` and `TEST_DOMAIN_B` before running tests and revert any drifted domain on teardown if any `cp_mutates`-marked test executed.

#### Scenario: Baseline snapshot persisted before tests and restored after mutations

- **WHEN** an integration session runs with `TEST_DOMAIN_A` or `TEST_DOMAIN_B` configured and at least one `@pytest.mark.cp_mutates` test executes
- **THEN** the harness SHALL write `_tmp/cp_baseline/baseline-<UTC>.json` before the first test, and on session teardown SHALL discard open sessions holding locks/changes and execute `revert-to-revision` (`timeout=900s`) for any snapshotted domain whose `show-last-published-session` UID drifted from the baseline

#### Scenario: Baseline snapshot failure aborts the session before running tests

- **WHEN** capturing the initial baseline snapshot of `TEST_DOMAIN_A` or `TEST_DOMAIN_B` fails
- **THEN** the session fixture SHALL abort the entire pytest run immediately with return code `5` rather than executing mutating tests without a recovery baseline

### Requirement: Progressive Runnable SDK Examples Catalog

The repository SHALL provide a runnable `examples/` catalog demonstrating Arodonata v2 capabilities from basic cached queries to advanced multi-tenant contexts, CPCRUD, change reports, OpenTelemetry tracing, and ASGI MCP embedding, ensuring that embedded MCP examples enforce host or bearer authentication when write tools (`cpcrud=True` or `live_compat=True`) are enabled.

#### Scenario: Examples cover core and advanced v2 workflows with crash-safe lab guard

- **WHEN** a developer inspects or executes scripts in `examples/`
- **THEN** the catalog SHALL include runnable scripts for basic domain/object/service queries (`01`), search and structured queries (`02`), gateway/cluster/VSX relationships (`03`), streaming cache refresh (`04`), rulebase queries and numbering (`05`), session lifecycle (`06`), `auth_context`/`user_context` and `SessionOverlay` read-your-own-writes (`07`), CPCRUD idempotent apply (`08`) and compensating inverse (`09`), change report evidence (`10`), OpenTelemetry tracing with module gating (`11`), and FastAPI MCP embedding (`12`, configured with explicit bearer/host authentication middleware protecting write-capable MCP routes), with all mutating examples wrapped in `guarded_session` so target lab domains are automatically restored on exit


---

### OpenSpec Capability: `mcp-server` (`openspec/specs/mcp-server/spec.md`)

# Model Context Protocol (MCP) Server Specification

## Purpose

Defines the Streamable-HTTP Model Context Protocol server (`arodonata-mcp` CLI and `arodonata.mcp` embeddable ASGI application under `arodonata[mcp]`), authentication and security guards, tool surface (native, cached, structured query/aggregation, rulebase, change report, live compatibility, and opt-in CPCRUD tools), and prompt templates.

## Requirements

### Requirement: Standalone CLI and Embeddable ASGI Server Modes

The `arodonata.mcp` package SHALL provide a standalone CLI (`arodonata-mcp`) and ASGI factories (`create_mcp_server`, `create_asgi_app`), enforcing fail-closed auth in `"static"` and `"jwt"` modes, parsing `client_id=secret` token entries ONLY when the prefix matches `^[A-Za-z_][A-Za-z0-9_-]*$` with a 32-character minimum secret length, comparing SHA-256 digests via `hmac.compare_digest`, and validating numeric ports on wildcard `Host` patterns.

#### Scenario: Standalone startup validates TLS trust store and auth mode

- **WHEN** `arodonata-mcp` starts up
- **THEN** it SHALL verify the TLS trust store configuration and refuse `ARODONATA_MCP_AUTH_MODE=host` or `jwt` (without a verifier) with exit code `2` and a clear configuration error message, and refuse or emit a prominent security warning when `auth_mode="none"` is combined with non-loopback `--host` (`0.0.0.0`) or `ALLOWED_HOSTS=*`

#### Scenario: Static bearer token authentication maps token variable name to client_id

- **WHEN** `ARODONATA_MCP_AUTH_MODE=static` is configured with `ARODONATA_MCP_TOKEN_VARS="TEAM_A_TOKEN,TEAM_B_TOKEN"` or `ARODONATA_MCP_TOKENS` containing a base64 token with trailing `=` padding (e.g., `c2VjcmV0dG9rZW4xMjM0NTY3ODkwMTIzNDU2Nzg5MDEy==`) or an explicit `team_a=c2VjcmV0dG9rZW4xMjM0NTY3ODkwMTIzNDU2Nzg5MDEy==`
- **THEN** the parser SHALL split on the first `=` or `:` ONLY when the prefix matches `^[A-Za-z_][A-Za-z0-9_-]*$` and the secret is at least 32 characters (keeping raw unprefixed base64 tokens whole under a generated non-secret `client_id` such as `token_1`), reject any token secret shorter than 32 characters with `ConfigurationError`, compare SHA-256 digests via `hmac.compare_digest`, and NEVER log or expose any prefix of the secret in `client_id` or `repr()`

#### Scenario: Embedded JWT mode without token_verifier fails closed on startup

- **WHEN** `create_mcp_server` or `create_asgi_app` is called with `auth_mode="jwt"` and `token_verifier=None`
- **THEN** initialization SHALL raise `ConfigurationError` immediately rather than falling back to unauthenticated access

#### Scenario: Host authentication mode in embedded ASGI applications

- **WHEN** `create_mcp_server` is called with `auth_mode="host"` for embedding inside an authenticating ASGI host
- **THEN** Arodonata SHALL disable its internal token verifier and rely on the enclosing ASGI host middleware for request authentication

#### Scenario: DNS rebinding and Origin header protection

- **WHEN** a request arrives with a `Host` header not in `allowed_hosts` (including malformed ports on `host:*` entries such as `localhost:abc`) or a browser `Origin` header not in `allowed_origins`
- **THEN** the server SHALL reject an unlisted or malformed-port `Host` with HTTP `421` and an unlisted `Origin` with HTTP `403`

### Requirement: Structured Object Aggregation and Cache Status Tools

The `arodonata[mcp]` server SHALL expose a structured query and schema-introspection tool (`query_objects` supporting `aggregate="list" | "count" | "describe"`) for cross-domain filtering, grouping, and counting over `arodonata_objects`, `arodonata_services`, and `arodonata_assets` without raw SQL, along with a unified `cache_control` tool (`action="status" | "refresh"`) reporting freshness per domain and scope from `domain_sync_state` or triggering scoped synchronization.

#### Scenario: Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` is called
- **THEN** the tool SHALL execute a parameterized query over the cached tables (distinguishing domain-owned vs Global objects via `original_domain`) and return the grouped counts in a single response

#### Scenario: Progressive-disclosure schema description via query_objects

- **WHEN** `query_objects(mgmt_name=..., domain=..., aggregate="describe")` is called
- **THEN** it SHALL return available domains, management servers, per-type object/service/asset counts, and the list of filterable and groupable fields from the cached tables

#### Scenario: Cache status inspection across scopes

- **WHEN** `cache_control(mgmt_name=..., action="status")` or `cache_control(mgmt_name=..., domain=..., action="refresh", scope="objects")` is called
- **THEN** `action="status"` SHALL return per-domain and per-`item_type` sync status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`, and `action="refresh"` SHALL synchronize the requested scope (`"domains"`, `"objects"`, `"services"`, `"assets"`, or `"rulebase"`) and return the `RefreshOutcome`

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose a consolidated cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `change_report`, `api_call`, and opt-in CPCRUD tools), pre-validating `domain` names against `arodonata_domains` before login, normalizing short and canonical `types`/`obj_type` values, resolving `show_object` across `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` with strict explicit wildcard matching and paginated substring candidate fallback, returning the domain's package and layer catalog in `show_rulebase` when `package`/`layer` is omitted or unmatched, enforcing a read-only command allowlist in `api_call` when `ARODONATA_MCP_ALLOW_WRITE_API=false`, isolating allowed write `api_call` invocations in a dedicated session, and passing `known_sids` into error redaction.

#### Scenario: List tool response envelope includes source and cache age

- **WHEN** a collection listing tool (`list_domains`, `list_objects`, `list_services`, or `list_assets`) returns a page of objects (including with short or canonical `types` filters such as `types=["tcp", "udp"]` on `list_services` or `parent="..."` on `list_assets`)
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds`, and `objects` sliced by `limit` and `offset`

#### Scenario: Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0)` is called
- **THEN** it SHALL search `arodonata_objects`, `arodonata_services`, `arodonata_assets` (returning cached gateway/cluster `interfaces`, `network_security_blades`, `member_uids`, and `virtual_system_uids`), and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer`:
  - if `uid_or_name` contains no `*` or `?` and matches an exact UID or name, it SHALL return that single entity with `match_type="exact"` and full details;
  - if `uid_or_name` contains an explicit wildcard (`*` or `?`), it SHALL evaluate `fnmatchcase` strictly against the pattern without adding implicit leading or trailing wildcards (`match_type="wildcard"`), returning the full object when `total == 1` or a paginated candidate slice (`limit` default `20`, max `500`) when `total > 1`;
  - if `uid_or_name` contains no wildcard and has no exact match in cache, it SHALL search for case-insensitive substring matches across cached names (`match_type="substring_candidates"`) and return up to `limit` (default `20`, max `500`) compact candidate summaries with `from`, `to`, and `total` so the caller can refine the next query without overflowing context

#### Scenario: Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_rulebase(mgmt_name=..., domain=..., rulebase_type="access" | "nat" | "https" | "threat", ...)` is called
- **THEN**:
  - when neither `package` nor `layer` (`name`/`uid`) is provided (or when the requested target name is not found in the domain's cached snapshot), it SHALL return the domain's cached `packages` (`arodonata_rulebase_package_layer`) and `layers` (`arodonata_rulebase_layer`, including inline layers, parent links, and `implicit_cleanup_action`) rather than an unguided error;
  - when a valid `package` or `layer` is provided on a domain with a fresh rulebase snapshot and without live-only parameters (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`, `hits_settings`, `dereference_group_members`, `show_membership`), it SHALL evaluate any `filter` locally against the cached rulebase and cached objects/services in `markdown`, `model_friendly`, `raw`, or `cpcrud` format;
  - when live-only parameters or `cache_mode="live"` are requested, it SHALL execute a live Management API query (`show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase`)

#### Scenario: Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** a tool is called with a `domain` not present in the `arodonata_domains` table (after a single domain-list refresh) or login raises `InvalidCredentialsError`
- **THEN** the server SHALL log the `ToolFailure` at WARNING (without arguments or secrets) and return an actionable error listing known domains on that management server rather than `"internal error: InvalidCredentialsError"`

#### Scenario: Write API protection and SID masking on error

- **WHEN** `api_call` is invoked while `ARODONATA_MCP_ALLOW_WRITE_API=false`, or invoked with a write command while `ARODONATA_MCP_ALLOW_WRITE_API=true`, or when an error message contains an active session SID
- **THEN** when `ALLOW_WRITE_API=false`, `api_call` SHALL permit ONLY commands in the explicit read-only command allowlist (rejecting path traversal, mutating commands, `publish`, `discard`, `logout`, and unlisted commands); when `ALLOW_WRITE_API=true`, mutating `api_call` invocations SHALL execute inside an isolated dedicated session (never the shared `arodonata_sid_cache` session) with bounded `timeout`; and any error text SHALL be sanitized via `redact_sid(..., known_sids=...)`

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was generated by `cpcrud_plan` (via server-side `plan_id` storage or HMAC-SHA256 signature verification), omit `force` and `validate_schema` from MCP tools, cap `retry_remaining` (`<= 3`), and expose a unified `cpcrud_staged_session(session_uid, action="publish" | "discard", ...)` tool.

#### Scenario: Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` is called with an unknown `plan_id` or a `plan` payload that was not issued/signed by this server's `cpcrud_plan` tool (or whose `command` / `object_type` / `payload` was altered)
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: Staged CPCRUD session published or discarded via dedicated MCP tools

- **WHEN** `cpcrud_apply(..., no_publish=True, keep_session=True)` stages changes in a dedicated session and the caller subsequently invokes `cpcrud_staged_session(session_uid=..., action="publish" | "discard", mgmt_name=..., domain=...)`
- **THEN** the tool SHALL adopt the staged session via `take-over-session` and either publish (invalidating the domain cache) or discard uncommitted changes and log out cleanly so no locks remain orphaned


---

### OpenSpec Capability: `rulebase-and-numbering` (`openspec/specs/rulebase-and-numbering/spec.md`)

# Rulebase Introspection, Caching, and Numbering Specification

## Purpose

Defines multi-domain rulebase snapshot caching (`RulebaseRefreshService`, `DomainSyncCoordinator`), rulebase pagination (`rulebase/pager.py`), SmartConsole-accurate hierarchical rule numbering (`rulebase/numbering.py`, `CachedRulebaseSource`), and package/layer introspection APIs (`get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`).

## Requirements

### Requirement: Session-Aware Atomic Rulebase Snapshot Refresh

`RulebaseRefreshService` (`refresh_rulebases`, `stream_refresh_rulebases`) SHALL refresh a domain's rulebase snapshot (`arodonata_rulebase_*` tables) and `arodonata_domain_sync_state` (`scope="rulebase"`) in a single atomic database transaction protected by a per-domain distributed lock with periodic heartbeat renewal, tracking freshness against the domain's last published session UID and preserving `last_published_at=None` for never-published domains.

#### Scenario: Refusal to refresh when shared session is dirty

- **WHEN** `refresh_rulebases` runs for a domain whose shared API session currently holds unpublished changes or object locks (`number-of-published-changes` / `locks` non-zero) or where `show-session` fails
- **THEN** the refresh for that domain SHALL refuse to proceed (failing closed on `show-session` error), preserve any existing cached rulebase snapshot, and mark `arodonata_domain_sync_state.status = "failed"` (`scope="rulebase"`) with SID-redacted `last_error`

#### Scenario: Complete traversal of packages, ordered layers, inline layers, and global placeholders

- **WHEN** `refresh_rulebases` reads a clean domain
- **THEN** it SHALL fetch `show-packages`, the NAT rulebase of every package with `nat-policy`, every access/HTTPS/threat layer reachable from packages, layer listings, or inline-layer rule references, and for any global layer containing a domain `place-holder`, query the global layer with `package` context to resolve the parent rule and nested domain layer, replacing the domain's snapshot rows across `arodonata_rulebase_*` AND updating `arodonata_domain_sync_state` inside a single atomic database transaction under a renewed domain lock

#### Scenario: Rulebase pager merges split sections across page boundaries

- **WHEN** `rulebase/pager.py` pages `show-*-rulebase` in chunks of up to 100 rules and Check Point repeats a `rulebase-section` header across two consecutive pages
- **THEN** the pager SHALL merge the split section into a single section entry containing all of its rules in order and recover empty trailing sections

### Requirement: SmartConsole-Identical Hierarchical Rule Numbering

`arodonata.rulebase.numbering` and `CachedRulebaseSource` SHALL compute hierarchical rule and section numbers (`1`, `2`, `2.1`, `2.2.1`, section ranges `2.1-2.2`, or `No Rules`) dynamically from the domain's cached rulebase snapshot so that numbers match SmartConsole display both in package context (`get_package_rulebase`) and standalone layer context (`get_layer_rulebase`).

#### Scenario: Package rulebase numbering expands global placeholders and inline layers

- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package, rulebase_type="access")` is called for a package that includes a Global layer with a `place-holder` and rules calling inline layers
- **THEN** the returned `PackageRulebase` SHALL number top-level rules sequentially (`1`, `2`, ...), expand the domain layer under the global placeholder's parent rule with dotted numbers (`2.1`, `2.2`, ...), and expand inline layers beneath their calling rule (`2.2.1`, ...)

#### Scenario: Locate rules across all packages and layers of a domain

- **WHEN** `locate_rules(mgmt_name, domain_name, rule_uids=[...], layer_uids=[...])` is called
- **THEN** it SHALL return `RuleLocations` mapping each rule UID to all of its SmartConsole positions across packages/layers and each layer UID to its numbering prefixes (`""`, `"2."`, `"2.2."`), along with `snapshot_session_uid`, `snapshot_published_at`, and sync status

#### Scenario: Automatic domain resolution and ambiguity error for domainless calls

- **WHEN** `get_package_rulebase` or `get_layer_rulebase` is called with `domain_name=None` or `""`
- **THEN** the client SHALL resolve the unique cached domain containing that package or layer (or the single cached domain on an SMS); if multiple cached domains contain a matching name/UID, it SHALL raise `AmbiguousLayerName` listing all `(domain, uid)` candidates

### Requirement: Local Rulebase Filtering and CPCRUD Rule Export

`filter_rulebase()` and `rule_to_cpcrud_operation()` SHALL evaluate search/filter queries locally against cached rulebases (`PackageRulebase` or `NumberedLayerRulebase`) with transitive object/service group expansion and convert matched access, NAT, HTTPS, and threat-prevention rules into schema-valid `cpcrud` operation dictionaries (`format="cpcrud"`).

#### Scenario: Convert matched access and NAT rules into valid CPCRUD operations

- **WHEN** `rule_to_cpcrud_operation(rule)` or `filter_rulebase(..., format="cpcrud")` is called on a cached `AccessRuleEntry`, `NatRuleEntry`, `HttpsRuleEntry`, or `ThreatRuleEntry`
- **THEN** it SHALL return an operation dictionary (`operation`, `type`, `layer` or `package`, `key`, `data`) that passes `CPCRUDService.validate()` and normalizes Check Point NAT `"Original"` / `"Any"` sentinel UIDs


---

### OpenSpec Capability: `sessions-and-mdm` (`openspec/specs/sessions-and-mdm/spec.md`)

# Sessions, Multi-Domain Resolution, and Concurrency Specification

## Purpose

Defines the lifecycle of Check Point API sessions (`LoginCoordinator`, `SessionCleaner`, `SIDCache`), hybrid and dynamic authentication with `contextvars`-bound `WriteSession` overlays (`SessionOverlay`), per-MDS-member login gating and request concurrency limiting (`LoginGate`, `RateLimiter`), and Multi-Domain Security Management (MDSM) domain/server resolution (`DomainService`, `DomainListRefreshTracker`).

## Requirements

### Requirement: Persistent SID Caching and Auto-Recovery

The system SHALL persist shared read-only session identifiers (`sid`) in `arodonata_sid_cache` keyed by `f"{mgmt_name}:{domain_key}:{auth_identity}"` (where `auth_identity` is an HMAC-SHA256 credential digest), re-authenticate when a cached session expires, evict a cached SID when `keepalive` returns `success=False`, and reject or isolate mutating commands so they never use `arodonata_sid_cache`.

#### Scenario: Reuse of unexpired cached session scoped by authentication identity

- **WHEN** a read-only API call targets `(mgmt_name, domain)` under resolved credentials (`auth_identity`) and a cached SID exists in `arodonata_sid_cache` with the exact `f"{mgmt_name}:{domain_key}:{auth_identity}"` key whose age is less than `session_expire_seconds`
- **THEN** `LoginCoordinator` SHALL reuse that SID without performing a new login call, whereas a call with a different password, different API key, or `auth_identity=None` SHALL NEVER match or overwrite that cached SID

#### Scenario: Transparent re-login on session expiration error

- **WHEN** a read-only API call using a cached SID receives a session expiration error or a background `keepalive` returns `success=False`
- **THEN** the client SHALL immediately evict only that specific `(mgmt_name, domain_key, auth_identity)` row from `arodonata_sid_cache` and, for active read-only API calls, acquire a fresh session via `LoginCoordinator` and retry the call once transparently

#### Scenario: Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called for isolated write workflows
- **THEN** `LoginCoordinator` SHALL authenticate a fresh session with retry/backoff resilience, return `(sid, server_ip)` without storing the SID in `arodonata_sid_cache`, keep the SID registered in `_active_dedicated_sids` until `logout_sid()` succeeds, and shield `discard`/`logout_sid()` against `asyncio.CancelledError` (`BaseException`)

#### Scenario: Mutating commands refused on shared cached SID path

- **WHEN** `AMgmtClient.api_call` is invoked with a non-read-only command (`add-*`, `set-*`, `delete-*`, `publish`, `discard`, `install-policy`, `run-script`, etc.) without an explicit `sid` or active `WriteSession` in `contextvars`
- **THEN** `AMgmtClient` SHALL refuse to execute the command on the shared `arodonata_sid_cache` session (raising `SessionStateError` unless called via high-level `ArodonataClient` helpers that open an isolated dedicated session)

### Requirement: Hybrid and Dynamic Authentication with Context-Bound WriteSession Overlay

The system SHALL support hybrid authentication (shared read-only credentials with per-admin write credentials) and dynamic authentication via `contextvars` (`AuthContext` / `AuthProvider`), and SHALL bind isolated `WriteSession` instances in `contextvars` with an in-memory `SessionOverlay` so read operations within that session reflect uncommitted creations, updates, and deletions.

#### Scenario: WriteSession opens under administrator credentials and isolates uncommitted state

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_creds):` executes `add_host`, `set_host`, or `delete_host` followed by `get_hosts()`
- **THEN** the session SHALL authenticate under `admin_creds`, record the mutated objects in the session's `SessionOverlay` via `contextvars`, and return `get_hosts()` with created/updated hosts included and deleted hosts excluded without modifying the shared database cache until `publish`

#### Scenario: Dynamic authentication resolves credentials from AuthContext and evicts stale admin password

- **WHEN** the client runs in `"dynamic"` mode without static startup credentials and an admin request provides credentials via `client.auth_context(...)` or `AuthProvider`
- **THEN** `LoginCoordinator` SHALL use those credentials to establish sessions, and if a subsequent login fails with `InvalidCredentialsError` (e.g., after a password change), it SHALL immediately evict those credentials and notify `AuthProvider` without retrying

### Requirement: Per-MDS-Member Login Gate and Throttle Recovery

The system SHALL serialize and rate-limit logins per hosting MDS member (`active_mds_ip`, falling back to configured server IP) via `LoginGate`, enforcing a minimum inter-login spacing and shared throttle cooldown inside the gate, bounding local `asyncio.Lock` acquisition by `wait_timeout`, and executing CMA failover IP refreshes (`refresh_domain_active_ip`) and retry backoff sleeps outside the gate so recursive system-domain logins on the same MDS IP never deadlock.

#### Scenario: Throttled login waits out Check Point throttle window

- **WHEN** a login attempt is rejected due to Check Point login throttling or times out during the read phase
- **THEN** `LoginGate` SHALL record the per-MDS cooldown window (`login_throttle_window`, default 70s, or exponential read-timeout backoff) so subsequent queued callers respect the cooldown before sending another `login`, and `LoginCoordinator` SHALL release the gate before sleeping and retrying within `login_max_wait` (default 900s)

#### Scenario: Cold-cache CMA failover during login does not deadlock LoginGate

- **WHEN** a login to a customer domain on `mds_ip` encounters a transport or failover error and triggers `refresh_domain_active_ip()` while the system domain SID is not yet cached (requiring a system domain login to the same `mds_ip`)
- **THEN** `LoginCoordinator` SHALL release the `LoginGate` for `mds_ip` before invoking `refresh_domain_active_ip()` so the nested system-domain login acquires `LoginGate(mds_ip)` cleanly without self-deadlock

#### Scenario: Credential rejection or locked account fails fast with InvalidCredentialsError

- **WHEN** the Check Point server rejects login credentials (`Authentication to server failed` or `Administrator account is locked`) rather than reporting a transient revision/lock condition (`Database revision is in progress`)
- **THEN** `LoginCoordinator` SHALL raise `InvalidCredentialsError` (a subclass of `AuthenticationError`) without exhausting transient retry loops

### Requirement: Per-MDS-Member Concurrency Semaphore

The `RateLimiter` SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using database-backed slot locks (with TTL `>= max(api_timeout, login_timeout) + 60s`) and FIFO in-process waiter queues, guaranteeing local FIFO slot release in `finally` even if database lock release raises an error or is cancelled.

#### Scenario: Fair waiter wakeup on slot release

- **WHEN** all `concurrent_limit` slots for an MDS member are occupied, multiple coroutines are waiting, and the active slot holder exits (even if the database lock release raises an exception or `asyncio.CancelledError`)
- **THEN** `RateLimiter` SHALL always release the local FIFO slot in `finally` (shielding DB lock cleanup) and wake the longest-waiting coroutine in arrival order within the client, or raise a timeout error if no slot becomes free within `rate_limit_slot_timeout`

#### Scenario: Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity (including when one awaiting caller is cancelled)
- **THEN** overlapping keepalive sweeps SHALL be coalesced and protected via `asyncio.shield` so at most one sweep runs at a time without starving active caller slots or aborting sibling waiters

### Requirement: Stale Session Cleanup and Startup Session Seed

`SessionCleaner` SHALL clean up stale or abandoned Arodonata-owned API sessions on configured management servers on startup (when static credentials are available) and upon max-sessions refusal, strictly restricting `discard` to sessions created by Arodonata (`application == "arodonata"` or `arodonata` session-name prefix) that have `changes == 0` and `locks == 0`.

#### Scenario: Startup cleanup seeds system domain SID when cache is empty

- **WHEN** `schedule_startup_cleanup()` runs on client entry with static credentials and no cached SID or in-flight login exists for a server's system domain
- **THEN** the session opened by `SessionCleaner` to inspect/discard stale sessions SHALL be retained in `arodonata_sid_cache` for subsequent read calls rather than logged out

#### Scenario: Foreign administrator sessions and sessions with unpublished changes are never discarded

- **WHEN** `SessionCleaner` inspects `show-sessions` and encounters sessions belonging to human administrators, other tools, or sessions with non-zero `changes` or `locks`
- **THEN** `SessionCleaner` SHALL skip those sessions and NEVER issue `discard` or `take-over-session` against them

#### Scenario: Cold startup in dynamic auth mode skips network cleanup

- **WHEN** `ArodonataClient` enters its context manager in `"dynamic"` auth mode before any administrator credentials have been supplied
- **THEN** startup session cleanup SHALL be skipped without raising an authentication error

### Requirement: Multi-Domain Discovery, Failover IP Resolution, and Global Domain Support

`DomainService` SHALL discover and cache all domains on MDS servers (`show-domains`), synthesize an explicit `Global` domain row (`show-global-domain`), and track each domain's `active_ip`, `active_mds_ip`, and standby servers.

#### Scenario: Opt-in Global domain visibility

- **WHEN** `get_domains(include_global=False)` (the default) is called
- **THEN** the `Global` domain row SHALL be excluded from the returned list; when `include_global=True`, the `Global` domain row SHALL be included

#### Scenario: Periodic domain list refresh via DomainListRefreshTracker

- **WHEN** `get_domains` or smart cache refresh runs
- **THEN** the domain list (`show-domains`) SHALL be re-fetched from the management server when the `domains` table is empty, when the 1-hour domain-list TTL has elapsed, or when `mode="force"` is requested

#### Scenario: Cold-cache CMA IP resolution and active domain server failover re-resolution

- **WHEN** a customer or `Global` domain login runs before `domains` is cached (cold cache) or when a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** `LoginCoordinator` SHALL query the MDS system domain (`show-domains`, `show-mdss`, and `show-global-domain`) to resolve and cache the domain's `active_ip` (CMA IP) and `active_mds_ip` in the `domains` table before authenticating against the domain


---

### OpenSpec Capability: `transport-and-tls` (`openspec/specs/transport-and-tls/spec.md`)

# Transport, TLS Identity Verification, and Task Polling Specification

## Purpose

Defines the native `asyncio` Check Point Management API transport (`ApiTransport` over `aiohttp`), SHA-256 certificate fingerprint identity verification (`TrustPolicy` and `TrustStore`), verified read-only connection pooling (`VerifiedConnectionPool`), socket-level timeout enforcement, transport-owned asynchronous task polling (`TaskWaiter`), and continuity-verified pagination (`pager.py`).

## Requirements

### Requirement: Pre-Request TLS Certificate Fingerprint Verification

The transport SHALL verify the SHA-256 fingerprint of the server certificate presented at `host:port` immediately after the TLS handshake and BEFORE sending any HTTP headers, credentials, API keys, or command payloads, and SHALL protect `TrustStore` persistence with cross-process file locking, atomic read-merge-write, `0600` permission checks, and RFC-compliant IPv6 `[host]:port` address keys while forbidding unverified HTTP proxies (`trust_env=False`).

#### Scenario: Untrusted certificate refused in pinned mode

- **WHEN** `tls_trust="pinned"` and the server at `host:port` presents a certificate whose SHA-256 fingerprint is neither in the trust store nor in `ARODONATA_TLS_FINGERPRINTS`
- **THEN** the connection SHALL be closed before any request bytes are sent and `UnknownServerCertificateError` (or `CertificateMismatchError` if another fingerprint was pinned for that address) SHALL be raised with `"No request was sent."` in the message

#### Scenario: First contact learned in TOFU mode

- **WHEN** `tls_trust="tofu"` and `host:port` has no entry in the trust store
- **THEN** the presented certificate's SHA-256 fingerprint SHALL be persisted atomically to the trust store (`tls_known_hosts.json` with mode `0600`) under an exclusive OS file lock after re-reading and merging on-disk entries so concurrent workers never clobber learned fingerprints, and subsequent connections to `host:port` presenting a different fingerprint SHALL raise `CertificateMismatchError`

#### Scenario: Known MDS member fingerprint accepted on a new domain IP

- **WHEN** a domain server IP presents a certificate whose SHA-256 fingerprint is already trusted for another address (either in the trust store or in `ARODONATA_TLS_FINGERPRINTS`)
- **THEN** the certificate SHALL be accepted for the new address (and recorded as `known-identity` in `tofu` mode)

#### Scenario: Lab-memory mode restricted to lab environment

- **WHEN** `tls_trust="lab-memory"` is configured without `ARODONATA_LAB` set in the environment
- **THEN** `TrustPolicy` initialization SHALL raise `ConfigurationError`

#### Scenario: Identity errors are never retried

- **WHEN** a connection raises `ServerIdentityError` (`CertificateMismatchError`, `UnknownServerCertificateError`, or `TrustStoreError`)
- **THEN** login, keepalive, and task-wait loops SHALL NOT retry the request and SHALL propagate the error immediately

#### Scenario: IPv6 host and port keys parsed without ambiguity

- **WHEN** a management server or domain endpoint uses an IPv6 literal (`[2001:db8::1]:443` or `2001:db8::1`)
- **THEN** `TrustStore` and `ARODONATA_TLS_FINGERPRINTS` SHALL normalize and match the canonical `[ipv6]:port` key without splitting on internal colons

#### Scenario: Proxy connections and unverified sender seams rejected

- **WHEN** environment proxy variables (`HTTPS_PROXY`, `ALL_PROXY`) are present or `_create_proxy_connection` is invoked on the connector, or `ApiTransport` is given a `request_sender` without `peer_cert_getter` outside explicit unit test fixtures
- **THEN** the transport SHALL ignore ambient proxy variables (`trust_env=False`), refuse proxy connections before sending any request bytes, and never skip pre-request certificate verification

### Requirement: Socket-Level Connect and Read Timeouts Without Automatic Resend

The native `aiohttp` transport SHALL enforce explicit TCP/TLS connect (`connect_timeout`) and socket read timeouts on every Check Point Web API (`/web_api/<command>`) connection, disable HTTP redirects (`allow_redirects=False`), classify every `TransportError` with an execution phase (`phase="connect"` with `request_sent=False` vs `phase="post-send"` with `request_sent=True`), and NEVER automatically re-send a request after bytes have been written to the socket.

#### Scenario: Socket connect or handshake timeout

- **WHEN** TCP connection or TLS handshake exceeds `connect_timeout`
- **THEN** the transport SHALL raise `ApiTimeoutError` (a subclass of `TimeoutError`) with `phase="connect"`, `request_sent=False`, and the target `host` and `port`

#### Scenario: Socket read timeout

- **WHEN** waiting for the server's HTTP response exceeds the call's read timeout
- **THEN** the transport SHALL raise `ApiTimeoutError` with `phase="read"`, `request_sent=True`, naming the server and command, and warning that the command may still have run on the server

#### Scenario: Connection reset or broken pipe after request transmission never resends

- **WHEN** the peer resets or closes the connection (`ConnectionResetError`, `BrokenPipeError`, `ServerDisconnectedError`, or post-connect `ClientOSError`) after HTTP request bytes were written
- **THEN** the transport SHALL raise `TransportError` with `phase="post-send"` (`request_sent=True`), and neither `ApiTransport` nor `AMgmtClient` CMA failover recovery SHALL re-execute the request

#### Scenario: HTTP redirects are never followed

- **WHEN** the target server responds with any `3xx` redirect status (`301`, `302`, `303`, `307`, `308`)
- **THEN** the transport SHALL NOT follow the redirect (`allow_redirects=False`), SHALL NOT transmit `X-chkp-sid` or request bodies to the `Location` target, and SHALL fail the call immediately

### Requirement: Verified Connection Pooling for Read-Only Commands

`ApiTransport` SHALL pool and reuse fingerprint-verified keep-alive HTTPS connections (`VerifiedConnectionPool`) per `(server_ip, port)` for up to 10 seconds idle exclusively for read-only `show-*` commands, reaping expired idle sockets and bounding per-protocol fingerprint tracking without memory growth while always establishing a fresh connection for login, logout, keepalive, publish, discard, and mutating commands.

#### Scenario: Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and the pooled socket remains open
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: Mutating commands and idle connections bypass reuse

- **WHEN** a non-`show-*` command is executed or a pooled connection has been idle for more than 10 seconds
- **THEN** `ApiTransport` SHALL close any expired pooled socket, evict closed protocol fingerprint entries, and open a fresh TLS-verified connection

### Requirement: Self-Managed Asynchronous Task Polling

The native `aiohttp` transport SHALL execute Check Point Web API commands asynchronously without blocking worker threads and poll any returned `task-id` / `tasks` entries via `TaskWaiter` using exponential backoff (`2s` up to `10s`) under the separate `task_timeout` budget.

#### Scenario: Successful task completion returns final show-task response

- **WHEN** an API command (such as `publish`, `install-policy`, `revert-to-revision`, or `assign-global-assignment`) returns a task identifier
- **THEN** `TaskWaiter` SHALL poll `show-task` until all tasks reach a terminal state and return the final `show-task` payload with `success=True` only when every task's status is in the explicit success allowlist (`succeeded`)

#### Scenario: Failed or partially succeeded task returns success=False without raising

- **WHEN** a polled server task finishes with `failed` or `partially succeeded`
- **THEN** `api_call` SHALL return `ApiCallResult(success=False, ...)` containing the raw `show-task` data and error message rather than raising an exception

#### Scenario: Tolerance of transient poll failures

- **WHEN** individual `show-task` poll calls fail or time out transiently fewer than 5 consecutive times within `task_timeout`
- **THEN** `TaskWaiter` SHALL continue polling until the task completes or 5 consecutive poll errors occur (raising `TaskPollError`) or `task_timeout` expires (raising `TaskTimeoutError`, a subclass of `TimeoutError`)

### Requirement: Continuity-Verified Object Listing Pagination

The `api_query` pager (`pager.py`) SHALL page object listings in chunks (default 300, max 500), acquiring and releasing a `RateLimiter` slot per page so short API calls can interleave between pages, and verifying `from`, `to`, `total`, and object UID uniqueness across pages.

#### Scenario: Boundary swap duplicate UID recovery

- **WHEN** Check Point reorders two objects with equal names across a page boundary, causing a duplicate UID on the new page
- **THEN** the pager SHALL drop the duplicate and re-read a small window (up to 10 objects on each side of the boundary) in a single request to recover the displaced object without restarting the entire listing

#### Scenario: Total count change or continuity break triggers single restart

- **WHEN** `total` changes mid-listing, `from`/`to` continuity breaks, or the final distinct object count does not match `total`
- **THEN** the pager SHALL restart the listing once from the caller's initial offset, and if the second pass also fails continuity checks, return a failed result with `code="paging_inconsistent"` instead of returning silent gaps or duplicates

#### Scenario: Task-based query commands paged through TaskWaiter

- **WHEN** `api_query` is called with a command in `TASK_QUERY_COMMANDS`
- **THEN** each page SHALL be executed via `api_call` (awaited by `TaskWaiter` and unpacked from `tasks[].task-details[]`) until `to >= total`, failing the entire query if any page fails or fails to advance

### Requirement: Strict Web API Command Name Validation

`ApiTransport.execute` SHALL validate every Check Point Web API command string against `^[a-z0-9]+(-[a-z0-9]+)*$` before constructing the request URL, rejecting path traversal sequences, slashes, percent-encoding, whitespace, and uppercase characters.

#### Scenario: Path traversal or malformed command rejected before network I/O

- **WHEN** `ApiTransport.execute` is called with a command that does not match `^[a-z0-9]+(-[a-z0-9]+)*$` (such as `"show-hosts/../publish"`, `"show-x/%2e%2e/publish"`, `"../../gaia_api/v1.7/run-script"`, `"show-hosts?x=1"`, or `"SHOW-HOSTS"`)
- **THEN** the transport SHALL raise `ValidationError` before acquiring a connection or sending any network bytes
