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
| `ARODONATA_MCP_JSON_RESPONSE` | `bool` | `False` | Return JSON responses instead of SSE streams on Streamable-HTTP POST |
| `ARODONATA_MCP_STATELESS_HTTP` | `bool` | `False` | Enable stateless Streamable-HTTP mode per request |
| `ARODONATA_MCP_SERVER_NAME` | `str` | `"arodonata-mcp"` | Server identifier reported in MCP initialization |


---

## Part 4: Canonical OpenSpec System Specifications (`openspec/specs/`)


---

### OpenSpec Capability: `api-reference` (`openspec/specs/api-reference/spec.md`)

# api-reference Specification

## Purpose

Defines the bundled multi-version Check Point API schema index (`cp_api_index.json.gz`, covering Management API `v1.9` through `v2.2` and Gaia API `v2.0.1`), lazy in-memory `ApiReferenceEngine`, two-step command discovery (`search_commands` and `describe_command` with dynamic version filtering), and offline request payload validation (`validate_payload`).

## Requirements

### Requirement: Bundled Multi-Version API Schema Index and Lazy Loading

`arodonata.api_reference` SHALL package the compressed multi-version Check Point API schema bundle (`cp_api_index.json.gz`, covering Management API `v1.9`, `v2`, `v2.1`, `v2.2` and Gaia API `v2.0.1`) inside the installed distribution, load and decompress it lazily in memory on first query (with optional custom `index_path` override), and perform zero network or database calls.

#### Scenario: Default bundled index loads lazily without network or database access

- **WHEN** `get_api_reference()` or `ApiReferenceEngine.default()` is called in an offline process with no `ArodonataClient` or database configured
- **THEN** it SHALL decompress the bundled `cp_api_index.json.gz` into memory once, cache the singleton instance for subsequent calls, and expose `meta` (`versions`, `latest`, `commands_count`, `shared_objects_count`, `enums_count`)

### Requirement: Two-Step Version-Aware Command Discovery (Search and Describe)

`ApiReferenceEngine` (and top-level helpers `search_api_commands` / `describe_api_command`) SHALL provide a two-step lookup contract: `search_commands` returning ranked lightweight command summaries filtered by version, category, `crud_type`, and `api_family`, and `describe_command` accepting one or more command names and returning resolved schemas (`fields`, `field_alternatives`, `nested_objects`, `enums`, `example`) dynamically filtered to the target API version.

#### Scenario: Step 1 search filters by API version, CRUD type, and category

- **WHEN** `search_commands("export-access-rulebase", version="v1.9")` and `search_commands("export-access-rulebase", version="v2.2")` are called
- **THEN** the `v1.9` search SHALL exclude commands added after `v1.9`, while the `v2.2` search SHALL return the matching command summary with `added_in`, `supported_versions`, and `short_description`

#### Scenario: Step 2 describe dynamically filters fields and nested objects by target version

- **WHEN** `describe_command("add-interface", version="v1.9")` and `describe_command("add-interface", version="v2.2")` are called
- **THEN** the `v1.9` schema SHALL include `v1.9`-only fields (such as `gateway-owner` and `anti-spoofing-enabled`) and omit `v2+`-only fields, while the `v2.2` schema SHALL include only fields and nested objects valid in `v2.2`

#### Scenario: Batch describe accepts multiple command names in a single call

- **WHEN** `describe_command(["add-host", "set-host"], version="v2.2")` is called with a list of command names
- **THEN** it SHALL return a mapping or list of resolved command descriptions for each requested command (and report any unknown or version-unsupported command names clearly)

### Requirement: Offline Request Payload Validation Against Versioned Schema

`ApiReferenceEngine.validate_payload(command, payload, *, version="v2.2")` (and `validate_api_payload`) SHALL validate a candidate request `payload` dictionary offline against the command's schema for `version`, reporting structured validation errors for unknown or version-unsupported commands and fields, missing `required` fields, unsatisfied or conflicting `field_alternatives`, invalid types, and enum `valid_values` mismatches.

#### Scenario: Payload validation catches missing required fields and version-unsupported parameters

- **WHEN** `validate_payload("add-host", {"color": "invalid-color"}, version="v2.2")` is called
- **THEN** it SHALL return `valid=False` with actionable errors identifying missing required fields (`name` and `ip-address` / `ipv4-address` / `ipv6-address`) and the invalid enum value for `color`


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

`ObjectService` and `DomainSyncCoordinator` SHALL support four `CacheMode` values (`"cache"`, `"smart"`, `"smart-fast"`, and `"force"`), default to syncing `("host", "network", "address-range", "group", "dns-domain")` into `arodonata_objects`, track revision state per `(mgmt_name, domain_name, scope, item_type)` in `arodonata_domain_sync_state` within the same atomic transaction as data writes using dialect `ON CONFLICT` upserts, expose `refresh_objects` and `stream_refresh_objects`, and emit structured `arlogi` log messages for domain sync progress (`DEBUG` on domain sync start, completion, skip, and batch summary; `WARNING` on domain sync failure).

#### Scenario: Smart/Check refresh reloads only stale domains atomically and handles never-published domains

- **WHEN** `await client.refresh_objects(mode="smart")` or a read helper with `cache_mode="smart"` runs
- **THEN** the coordinator SHALL compare each domain's `show-last-published-session` publish timestamp (`last_published_at`) and UID (`last_session_uid`, when timestamps match) against the requested `item_type` rows in `arodonata_domain_sync_state` (preserving `last_published_at=None` for never-published domains rather than fabricating `now`), verify the shared session is clean (failing closed if `show-session` fails), reload only missing or stale `item_type` slices and their `arodonata_domain_sync_state` rows in a single atomic transaction under a renewed per-domain distributed lock, and log `DEBUG` entries for domain sync progress (`DomainSyncStartedEvent`, `DomainSyncCompletedEvent`, `DomainSyncSkippedEvent`, and `SyncCompletedEvent`)

#### Scenario: Incremental refresh applies show-changes diff or falls back safely

- **WHEN** `await client.refresh_objects(mode="smart-fast")` or a read helper with `cache_mode="smart-fast"` detects stale `item_type` rows with a known baseline in `arodonata_domain_sync_state`
- **THEN** the service SHALL query `show-changes` preferring `from-session` (`last_session_uid`) over `from-date` (formatting `from-date` as an explicit UTC ISO-8601 string with `Z` suffix when used), unwrap `new-object` / `old-object` change entries, delete removed objects, upsert added/modified objects via dialect `ON CONFLICT`, and update `arodonata_domain_sync_state` atomically; if changes exceed `max_incremental_changes` (default 500) or any error occurs, it SHALL fall back automatically to an atomic type-scoped reload

#### Scenario: Refresh failure visibility, unreachable server resilience, and InvalidCredentialsError handling

- **WHEN** a domain's staleness probe or refresh fails with an API/authentication error (`InvalidCredentialsError`, etc.), when one management server in a multi-server refresh (`mgmt_name=None`) fails during domain discovery (`get_domains`), or when a domain encounters `LockAcquisitionError` because another worker is actively refreshing that domain
- **THEN** genuine errors (including a server whose domain discovery failed) SHALL be recorded in `RefreshOutcome.failed_domains`, `arodonata_domain_sync_state.last_error` (where applicable), and `DomainSyncFailedEvent` (logged at `WARNING` level) with `redact_sid(..., known_sids=...)` applied while keeping previously cached objects intact and continuing synchronization on all reachable servers, whereas `LockAcquisitionError` SHALL NOT overwrite `arodonata_domain_sync_state.status` as `"failed"` or emit a false failure event over the active worker's sync

#### Scenario: Parallel domain refresh per MDS member and background first-use warm-up

- **WHEN** `DomainSyncCoordinator.ensure()` refreshes multiple domains
- **THEN** domains SHALL be refreshed concurrently via `asyncio.TaskGroup` at up to `settings.domain_sync_concurrency` (default `min(2, max(1, concurrent_limit - 1))`) domains at once per MDS member (`active_mds_ip`, shared process-wide across coordinators attached to the same database engine while reusing the caller's active MDS permit on nested re-entrant coordinator calls, coalescing concurrent in-process syncs of the same `(mgmt_name, domain_name, scope)`, writing cached rows in bounded Core batches, and cancelling sibling tasks immediately if a fatal `ServerIdentityError` occurs), while `get_domains()` SHALL return the domain list without implicitly starting background object-cache warm-up (warm-up is invoked explicitly via `start_object_cache_warmup`)

### Requirement: Dedicated Service Cache Table and Selective Refresh

`ServiceCacheService` and `SqlCacheAdapter` SHALL persist service objects in `arodonata_services` (`CPService`) tracked per `(mgmt_name, domain_name, "services", item_type)` in `arodonata_domain_sync_state` in a single atomic transaction (preferring `from-session` over UTC `Z`-suffixed `from-date` in `"smart-fast"` mode), refreshing `("service-tcp", "service-udp", "service-icmp", "service-group")` by default and fetching other types only when requested in `types`.

#### Scenario: Default service refresh loads core variable service types

- **WHEN** `await client.refresh_services(mode="smart")` runs without an explicit `types` list
- **THEN** the service SHALL synchronize `service-tcp`, `service-udp`, `service-icmp`, and `service-group` rows into `arodonata_services` and record each type's `last_published_at`, `last_session_uid`, and `synced_at` in `arodonata_domain_sync_state` within the same atomic database transaction

#### Scenario: Explicit service types sync on demand without wiping other cached service types

- **WHEN** `await client.refresh_services(types=["service-other"])` is called on a domain that already has `service-tcp` cached
- **THEN** only `service-other` rows SHALL be fetched and replaced in `arodonata_services` (preserving existing `service-tcp` rows), and `arodonata_domain_sync_state` SHALL record the sync state for `item_type="service-other"`

### Requirement: Asset and Gateway Cache with Cluster and VSX Relationships

`AssetRefreshService` (`refresh_assets`, `stream_refresh_assets`) and `SqlCacheAdapter` SHALL persist gateways, clusters, cluster members, VSX gateways/clusters (via encapsulated `generic-object` topology queries), and management servers in `arodonata_assets` concurrently across domains via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`) with UID primary keys (`id`) and indexed composite identifiers (`asset_id`).

#### Scenario: Concurrent domain asset collection with interleaved SSE events

- **WHEN** `stream_refresh_assets()` runs across multiple servers and domains
- **THEN** it SHALL collect domains concurrently per MDS member (`settings.domain_sync_concurrency`, default `min(2, max(1, concurrent_limit - 1))`), persist rows in `arodonata_assets` (avoiding collision with host application `assets` tables), emit typed `SyncProgressEvent` items (convertible to `SSEEvent` via `adapters.sse`) tagged with `mgmt_name` and `domain`, link cluster members and VSX virtual systems to their parent asset UIDs and composite IDs (`parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`), and update `domain_sync_state` (`scope="assets"`, `item_type="*"`)

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

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4, CIDR, address range, wildcard, UID, composite ID, or name), support `exact_match: bool = False`, query cached objects with active `WriteSession` `contextvars` overlays across target servers/domains, and resolve parent group memberships up to `max_depth` (default 2) into `SearchResult` with dual UID and composite group links.

#### Scenario: Search resolves direct matches and containing groups with human-readable composite IDs

- **WHEN** `await client.search_objects("10.1.10.50", max_depth=2)` or `await client.search_objects("mds:General:hWebHost", max_depth=2)` is called
- **THEN** it SHALL return a `SearchResult` containing both the matching host/network objects (reflecting any uncommitted `WriteSession` overlay in the current context) and the hierarchy of groups (`memberships`) that directly or transitively contain those objects, with each `GroupMembershipNode` populated with `id`, `object_id`, `parent_uids`, and `parent_object_ids`

#### Scenario: Exact-match search avoids partial name matches and wider supernets

- **WHEN** `await client.search_objects(".example.com", exact_match=True)` is called on a domain containing `.example.com` and `sub.example.com`, or `await client.search_objects("10.192.13.0/24, 192.168.1.10", exact_match=True)` is called on a domain also containing a wider supernet (`10.0.0.0/8`)
- **THEN** name search SHALL return only `.example.com` without matching `sub.example.com` (while wildcard terms `*.example.com` continue to match via anchored `fnmatchcase`), and IPv4/CIDR search SHALL match only exact hosts/subnets (or narrower subnets contained within a CIDR query) while excluding wider containing supernets such as `10.0.0.0/8`

#### Scenario: Mixed object and gateway type filters partition cleanly between objects and assets

- **WHEN** `await client.search_objects(query, types=["host", "network", "gateway"], cache_mode="smart")` is called
- **THEN** `ObjectService` SHALL strip asset/service types (`"gateway"`, etc.) before calling Check Point `show-*` object endpoints so `arodonata_objects` refreshes cleanly without `Requested API type: not found`, and `SearchService.search_objects()` SHALL additionally refresh and match gateway/cluster/VSX assets (both primary `ipv4_address` and interface IPv4 addresses) from `arodonata_assets`

### Requirement: Cluster and Cross-Domain VSX Parent-Child Topology Enrichment

`ClusterRelationshipManager` and `VSXRelationshipManager` SHALL enrich cached `arodonata_assets` rows with bidirectional parent-child topology attributes (`parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`), including cross-domain VSX parent/child links on the same management server.

#### Scenario: Cluster members and VSX virtual systems link bidirectionally to parent containers

- **WHEN** asset refresh reconciles cluster members and VSX virtual systems on `mgmt_name`
- **THEN** each child member or virtual system SHALL reference its parent's UID and composite `asset_id`, and each parent cluster or VSX container SHALL list all child UIDs and composite `asset_id`s across domains on `mgmt_name`

### Requirement: Exclusive Coordinator-Synchronized Rulebase Cache Writes

Shared `arodonata_rulebase_*` cache tables SHALL be written exclusively under `DomainSyncCoordinator` per-domain distributed locks after `verify_session_clean` succeeds and within an atomic transaction that updates `arodonata_domain_sync_state` (`scope="rulebase"`, `item_type="*"`); read-only consumers (including `arodonata.reports`) SHALL NEVER invoke `CachePort.replace_domain_rulebase` directly out-of-band.

#### Scenario: Concurrent report generation cannot overwrite a newer stamped rulebase snapshot

- **WHEN** `refresh_rulebases` updates `arodonata_rulebase_*` and `arodonata_domain_sync_state` while a concurrent `collect_change_report` call numbers rule changes
- **THEN** `collect_change_report` SHALL NOT perform unlocked `replace_domain_rulebase` writes that could replace the newer cached rulebase under a fresh `DomainSyncState` stamp

### Requirement: Cross-Domain Group Member Resolution with Ambiguity Detection

`SearchService.get_group_members()` SHALL reject empty or whitespace-only `group_name_or_uid` inputs with `ValidationError`, and when `domain` is `None` (and not encoded in a `mgmt:domain:name` composite ID) SHALL resolve the target container across cached domains including `"Global"` using `cache_mode="cache"`, raising `AmbiguousObjectError` if matching containers exist in more than one domain.

#### Scenario: Cross-domain group member lookup detects multi-domain name collision without whole-MDS sync

- **WHEN** `SearchService.get_group_members(mgmt_name, None, "SharedGroup")` runs against a cache where `"SharedGroup"` exists in two distinct domains
- **THEN** it SHALL execute zero remote domain refreshes (`cache_mode="cache"`) and raise `AmbiguousObjectError` enumerating the matching domains and composite identifiers

### Requirement: On-Demand Application-Site Object Model and Synchronization

`CPObject` and `ObjectService` SHALL support Check Point `application-site` objects on demand via `show-application-site` and `show-application-sites`, hydrating `primary_category`, `url_list`, and `urls_defined_as_regular_expression` fields from Check Point API responses and cached `raw_data`.

#### Scenario: CPObject hydrates application-site URL list and regex flag from Check Point dict and DB cache

- **WHEN** `CPObject.from_cp_dict()` or `SqlCacheAdapter` hydrates a Check Point `application-site` payload containing `primary-category`, `url-list`, and `urls-defined-as-regular-expression`
- **THEN** the resulting `CPObject` instance SHALL expose `type == "application-site"`, `primary_category`, `url_list` as `list[str]`, and `urls_defined_as_regular_expression` as `bool | None`

#### Scenario: On-demand refresh and query of application-site objects

- **WHEN** `refresh_objects(types=["application-site"])` or `get_objects(types=["application-site"])` is invoked
- **THEN** `ObjectService` SHALL query Check Point using `show-application-sites` (and `show-application-site` for single-item lookups), persist the rows in `arodonata_objects` with `item_type="application-site"` in `arodonata_domain_sync_state`, and return the hydrated `CPObject` entries

### Requirement: Gateway Interface Topology Persistence and Coordinator Synchronization

`SqlCacheAdapter` and `DatabaseManager` SHALL persist normalized gateway topology intervals in `arodonata_gateway_topology` (registered in `ARODONATA_TABLE_NAMES`), and `TopologyService` (`refresh_topology`, `stream_refresh_topology`) SHALL synchronize domain topology under `DomainSyncCoordinator` (`scope="topology"`, `item_type="*"`) with atomic per-domain replacement (`replace_domain_topology`).

#### Scenario: Atomic domain topology replacement and sync state recording

- **WHEN** `await client.refresh_topology(mgmt_name="mds1", domains=["Domain4"], mode="force")` completes
- **THEN** `TopologyService` SHALL ensure domain assets and network objects are fresh, compute all `GatewayTopologyEntry` rows for `"Domain4"`, atomically replace existing `"Domain4"` rows in `arodonata_gateway_topology` alongside the updated `arodonata_domain_sync_state` row (`scope="topology"`, `item_type="*"`), and expose `"topology"` freshness in `SearchService.get_cache_status()`

### Requirement: VSX Slot Generic Object Enrichment for Cross-Domain Virtual Systems

`VSXRelationshipManager` SHALL query `com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj` (`vsid == 0`) and `com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj` (`vsid > 0`) in addition to `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, and `CpmiVsClusterNetobj`, linking cross-domain Virtual Systems via `targetCustomer` and `vsxGateway` and preserving slot `interfaces`, `interfaces_installed`, `routes`, and `routes_installed` on the Virtual System asset.

#### Scenario: VSX slot objects in the VSX domain link a Virtual System in a tenant domain and attach VS routes

- **WHEN** a VSX gateway's domain stores a `CpmiVsxSlotObj` (`vsid=0`, `vsxGateway="vsx-uid"`) and a `CpmiVsSlotObj` (`vsid=1`, `name="VS_Tenant"`, `targetCustomer="TenantDomain"`, `vsxGateway="vsx-uid"`, `routes=[...]`), while the `CpmiVsNetobj` asset `"VS_Tenant"` lives in `"TenantDomain"` without a direct `vsx-gateway` field
- **THEN** `VSXRelationshipManager` SHALL link `" mds1:TenantDomain:VS_Tenant"` to parent `"mds1:VSXDomain:<vsx-name>"` and merge the slot's `routes` and `interfaces` metadata onto the `"VS_Tenant"` asset's `raw_data`


---

### OpenSpec Capability: `change-reports` (`openspec/specs/change-reports/spec.md`)

# Auditable Session Change Report Specification

## Purpose

Defines read-only collection (`collect_change_report`), rulebase placement numbering (`placement.py`), and multi-format rendering (`render_change_report`, `build_change_report`) of Check Point policy session change evidence (`ChangeReport`) across explicit session UIDs (`SessionScope`) and published session/date ranges (`RangeScope`).

## Requirements

### Requirement: Scope Validation and Read-Only Change Collection

`collect_change_report(api, cache, scopes, ...)` SHALL validate `SessionScope` and `RangeScope` inputs strictly (raising `pydantic.ValidationError` or `ChangeReportInputError` on invalid bounds or naive datetimes), bind unkeyed `OwnedSession` instances only to single-session scopes, query `show-changes` strictly read-only without directly mutating `CachePort` tables, deduplicate sessions, and record partial runtime failures as `ReportWarning` entries.

#### Scenario: Single-session change collection via to-session query and container filtering

- **WHEN** a `SessionScope` requests changes for explicit `session_uids`
- **THEN** the collector SHALL call `show-changes` with `{"to-session": s_uid, "details-level": "full"}` (omitting `from-session: s_uid` because `from-session` is exclusive in Check Point `show-changes`), filter the returned `changes[]` containers to the matching `session-uid`, and classify `modified-objects` entries that contain `new-object` without `old-object` as `"added"`

#### Scenario: Timezone-aware date range conversion and exact publish-time filtering

- **WHEN** a `RangeScope` includes timezone-aware `from_date` and/or `to_date`
- **THEN** the collector SHALL convert the bounds to the server's UTC offset, widen the server query window safely (or omit server date parameters when `from_session` is also given), and filter returned sessions by exact UTC publish timestamp

#### Scenario: Reference UID name resolution with bounded show-object lookups

- **WHEN** `show-changes` returns bare UIDs in either `new-object` or `old-object` snapshots (including removed `group.members` UUIDs, removed rule cell references, rule layers `layer`, or NAT fields) not already named in the session's own change entries or nested `{uid, name}` dictionaries
- **THEN** the collector SHALL recursively index nested `{uid, name}` dictionaries across `old-object` and `new-object`, resolve up to 200 distinct remaining bare UIDs per report (checking local cache first, then read-only `show-object` calls), substitute resolved names into rule fields, object summaries, and `FieldDiff` values (`old_value`, `new_value`, `added_items`, `removed_items`), populate `RuleChangeEntry.layer_name` when `layer_uid` resolves to a named layer, and emit a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails

#### Scenario: Multi-session scope does not bind an unkeyed OwnedSession across multiple sessions

- **WHEN** a `SessionScope` lists more than one UID in `session_uids` and supplies a bare `OwnedSession` whose `session_uid` is `None` or empty (or an `OwnedSession` whose explicit `mgmt_name` or `domain` disagrees with the scope)
- **THEN** `SessionScope.resolve_owned_session` SHALL NOT match that unkeyed or mismatched `OwnedSession` to arbitrary sessions in the scope

### Requirement: Owned Session Live Numbering and Cached Snapshot Fallback

The change report builder SHALL number added, modified, moved, and deleted rules according to SmartConsole hierarchy using a verified `OwnedSession` in-memory snapshot, the domain's cached rulebase snapshot, or a coordinator-delegated / in-memory published rulebase fallback when the cache is cold, skipping placement for object-only sessions and NEVER calling `CachePort.replace_domain_rulebase` directly from `arodonata.reports`.

#### Scenario: Object-only session skips rulebase placement and omits numbering banner

- **WHEN** a collected `SessionChangeReport` contains zero `rule_changes`
- **THEN** `apply_session_rule_placement` SHALL return immediately without calling `show-session`, `collect_domain_rulebase_snapshot`, or `CachePort.get_domain_rulebase`, setting `numbering_source = "not_applicable"` and `numbering_basis = ""`, and HTML/Markdown rendering SHALL omit the numbering basis banner/line for that session

#### Scenario: Read-only live numbering via OwnedSession with strict SID hygiene

- **WHEN** a `SessionScope` supplies an `OwnedSession` matching an unpublished session with rule changes in the scope
- **THEN** the collector SHALL verify ownership and matching domain via `show-session`, read `show-packages` and `show-*-rulebase` using that SID strictly read-only into memory (never publishing, discarding, logging out, or writing to `CachePort`), label the session `"Numbering read live in the owned session at <time> UTC"` (`numbering_source = "owned_session"`), and NEVER include or log the SID in `ChangeReport`, `RawResponse`, HTML, JSON, Markdown, or `repr()`

#### Scenario: Post-publish live numbering via clean OwnedSession before logout

- **WHEN** a `SessionScope` supplies an `OwnedSession` bound to an already-published session with rule changes (matching `OwnedSession.session_uid == session_uid` or a single-session scope, and matching `mgmt_name`/`domain` when set) and `show-session` on that SID confirms a non-discarded session on the expected domain with `changes` present and `0`, `locks` present and `0`, and `number-of-published-changes == 0`
- **THEN** the collector SHALL read the published rulebase snapshot live through that SID, number the session's rules strictly in-memory without calling `CachePort.replace_domain_rulebase` and without emitting `owned_session_not_used`, and label the session `"Numbering read live after publish at <time> UTC"` (`numbering_source = "live_published"`)

#### Scenario: Graceful fallback when OwnedSession is already published or expired

- **WHEN** a supplied `OwnedSession` fails `show-session`, is `discarded`, reports a different domain than the target session, omits `changes` or `locks`, reports non-zero `changes`, `locks`, or `number-of-published-changes` on a rotated post-publish session, or does not match an unpublished target session's UID
- **THEN** the collector SHALL record an `owned_session_not_used` or `owned_session_error` warning and fall back to numbering from the domain's cached rulebase snapshot (or cold-cache fallback)

#### Scenario: Cold-cache on-demand live published rulebase fallback

- **WHEN** a session has rule changes, no usable `OwnedSession` handled numbering, and `CachePort.get_domain_rulebase` contains no cached rules or layers for `(mgmt_name, domain_name)`
- **THEN** when invoked via `ArodonataClient`, the collector SHALL delegate warming to `RulebaseRefreshService` / `DomainSyncCoordinator` (enforcing per-domain distributed lock, dirty-session refusal, and atomic `DomainSyncState` stamping) and read the resulting cached snapshot; if invoked standalone without a coordinator or if warming does not populate the cache, it SHALL attempt a read-only in-memory `collect_domain_rulebase_snapshot` (`numbering_source = "live_published"`, basis `"Numbering read live from published rulebase at <time> UTC"`) without writing to `CachePort`, falling back to `"Numbering from cached rulebase snapshot (unavailable)"` (`numbering_source = "unnumbered"`) only when live collection fails or is empty

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: Self-contained HTML evidence output

- **WHEN** `"html"` is requested in `formats`
- **THEN** `render_change_report` SHALL produce a single self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, zero external network assets, SmartConsole-styled dark-blue table headers (`#253245` with white text), full-width pale-yellow access section banner rows (`<tr class="section-row">` on `#eee8aa` background displaying `▾ <section_name> (<section_range>)` and layer context), shaded gray `No.` rule-number cells (`.col-num`), visual change indicators (`NEW`, `DELETED`, `MODIFIED`, `MOVED` badges, disabled `✗` markers, and `Accept`/`Drop` action indicators), inline cell-level diff annotations inside `Rule Changes` and `Object Changes` rows showing removed items (`- <name>` struck-through), added/replacement items (`+ <name>`), and scalar `before → after` transitions, and optional per-rule/per-object `Field Diffs` detail tables when `RenderOptions.include_field_diffs` is `True`

#### Scenario: Inline diff markers in Markdown rule and object tables

- **WHEN** `"markdown"` is requested in `formats` for a report containing modified rules or modified objects with `field_diffs`
- **THEN** `render_change_report` SHALL render removed items (`[-<name>]`), added/replacement items (`[+<name>]`), and scalar `before -> after` transitions inline inside the Markdown `Rule Changes` (including the `Track` column) and `Object Changes` table cells while escaping pipe characters, newlines, and raw HTML tags

#### Scenario: Round-trip JSON serialization with format_version check

- **WHEN** a `ChangeReport` is serialized to `"json"` and reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access, and reject JSON files whose `format_version` is newer than supported by the installed library

### Requirement: Snapshot-Based Field Diff Synthesis and System Noise Filtering

When collecting modified rules and objects from `show-changes`, the collector SHALL synthesize `FieldDiff` entries (`old_value`, `new_value`, `added_items`, `removed_items`) from `old-object` and `new-object` snapshots for any changed tracked fields not already covered by explicit `field-changes`, enrich object summaries, and omit background `"System"` maintenance non-rule objects unless `RenderOptions.include_system_objects` is `True`.

#### Scenario: Rule list cell partial removal and sole-member Any replacement

- **WHEN** `show-changes` returns a modified rule with `old-object` and `new-object` snapshots and no explicit `field-changes` (either removing one or more objects from a multi-item list field such as `source`, `destination`, or `service`, or replacing the sole remaining object with `Any` and disabling the rule)
- **THEN** the collector SHALL populate `RuleChangeEntry.field_diffs` with the removed object names in `removed_items` (and `Any` in `added_items` when replaced by `Any`), record scalar diffs such as `enabled` and `comments`, and NOT report false-positive cell diffs when an unchanged referenced group has internal member edits

#### Scenario: Explicit field-changes merge cleanly with snapshot diffs

- **WHEN** a `modified-objects` entry provides explicit `field-changes` covering a subset of modified fields alongside `old-object` and `new-object` snapshots with additional changed fields
- **THEN** the collector SHALL preserve the explicit `field-changes` entries and append synthesized `FieldDiff` entries only for changed tracked fields not already present in `field-changes`

#### Scenario: Non-rule object member diffs and enriched object summaries

- **WHEN** `show-changes` returns modified, added, or deleted non-rule objects (including `group`, `host`, `network`, `address-range`, and `service-*`)
- **THEN** the collector SHALL compute `FieldDiff` entries (including `added_items` and `removed_items` for `members`, and before/after values for `comments` and address/service attributes) and populate structured `ObjectChangeEntry.summary_fields` and formatted `ObjectChangeEntry.summary` with IPv4/IPv6 addresses, CIDR subnets, address-range bounds, service ports/protocols, resolved `members`, and `comments`

#### Scenario: Background Check Point System maintenance objects excluded by default

- **WHEN** `show-changes` for a non-`"System"` user session includes non-deleted (`added` or `modified`) non-rule objects whose post-change `meta-info.last-modifier` is `"System"` (or nameless/typeless internal `"System"` records such as `IpsProtectionUserSettings`, `cp-trusted-ca-certificate`, or `TrustedCaPackageConf`)
- **THEN** the collector SHALL exclude those `"System"` non-rule entries from `SessionChangeReport.object_changes` by default (never excluding `deleted` objects and never inspecting `old-object.meta-info.last-modifier`, and including them when `RenderOptions.include_system_objects` is `True`), log the filtered count at `DEBUG` level without emitting a user-facing `ReportWarning`, and preserve the complete sanitized `show-changes` payload in `ChangeReport.raw_responses`

### Requirement: Offline Dry-Run ChangeReport Synthesis from CPCRUD Plan

`arodonata.reports` SHALL provide `build_change_report_from_plan(plan, ...)` to convert a CPCRUD `Plan` offline into a `ChangeReport` compatible with `render_change_report()`, capturing object, group, and rule creates, deletes, and field-level add/remove diffs without opening Check Point sessions.

#### Scenario: Dry-run ChangeReport renders HTML and JSON offline with added and removed item diffs

- **WHEN** a caller passes a multi-action `Plan` containing object creates (`Outcome.CREATE`), group member deltas (`Outcome.UPDATE` with `add`/`remove`), and incremental rule cell diffs (`Outcome.UPDATE` on `source`/`destination`/`service`) to `build_change_report_from_plan(plan)` and renders it via `render_change_report(report, formats=["html", "json"])`
- **THEN** `build_change_report_from_plan` SHALL produce a valid `ChangeReport` with zero Check Point API calls, populate `ObjectChangeEntry.field_diffs` and `RuleChangeEntry.field_diffs` (`added_items` and `removed_items`), and render self-contained SmartConsole-styled HTML and round-trippable JSON containing no SIDs or errors


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

`ArodonataClient` SHALL provide `contextvars`-aware session, mutation, and lookup helpers (`write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`), auto-wrapping standalone object mutations in an isolated write session, stripping secret request fields from `SessionOverlay`, and redacting secrets in `ApiCallResult`.

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

### Requirement: Cache-Only Cross-Domain Entity Lookup and Ambiguity Refusal

`ArodonataClient.find_object()` and `ArodonataClient.get_group_members()` SHALL require a non-empty target identifier (`ValidationError` on empty/blank input), and when `domain` is `None` (and cannot be extracted from a `mgmt:domain:key` composite ID) SHALL query strictly from local cache (`cache_mode="cache"`, `include_global=True`) and raise `AmbiguousObjectError` if more than one domain matches.

#### Scenario: Blank target identifier rejected immediately

- **WHEN** `client.find_object(mgmt_name, domain, "")` or `client.get_group_members(mgmt_name, domain, "   ")` is called with an empty or whitespace-only target string
- **THEN** the method SHALL raise `ValidationError` immediately without scanning cached or remote domains

#### Scenario: Cross-domain lookup runs cache-only with Global visibility and raises AmbiguousObjectError on multi-domain collision

- **WHEN** `await client.find_object(mgmt_name, None, name_or_uid)` or `await client.get_group_members(mgmt_name, None, group_name_or_uid)` is called without a domain
- **THEN** it SHALL search cached `arodonata_objects`, `arodonata_services`, and `arodonata_assets` across all cached domains including `"Global"` using `cache_mode="cache"` (triggering zero live domain logins or whole-MDS syncs), return the match when unique to a single domain, and raise `AmbiguousObjectError` listing the candidate domains and composite IDs when multiple domains match

### Requirement: Coordinator-Delegated Cold-Cache Rulebase Warming in Client Change Reports

`ArodonataClient.collect_change_report()` and `ArodonataClient.build_change_report()` SHALL wire cold-cache rulebase placement fallback through `ArodonataClient.refresh_rulebases(..., mode="smart")` so any rulebase cache population triggered during report generation obeys `DomainSyncCoordinator` distributed locks, dirty-session checks, and `DomainSyncState` stamps.

#### Scenario: Cold-cache report collection via ArodonataClient warms rulebase through coordinator

- **WHEN** `await client.collect_change_report(scopes)` processes a session with rule changes on a domain whose `arodonata_rulebase_*` cache is empty and no `OwnedSession` handled placement
- **THEN** `ArodonataClient` SHALL invoke `refresh_rulebases(mgmt_name=mgmt_name, domains=[domain_name], mode="smart")` via `DomainSyncCoordinator` rather than performing an unlocked direct `replace_domain_rulebase` write

### Requirement: Client Facade API Reference Introspection with Management Version Inference

`ArodonataClient` SHALL expose `api_reference` (`ApiReferenceEngine`) and convenience methods `search_api_commands(...)`, `describe_api_command(...)`, and `validate_api_payload(...)` that automatically infer the default target API `version` from the configured management server's `api_version` when `version=None` (using `mgmt_name` or the sole configured management server, and falling back to the index's `latest` version `"v2.2"` when no server version is configured).

#### Scenario: Client facade infers target API version from configured management server

- **WHEN** `client.describe_api_command("add-interface", mgmt_name="corp-mds")` is called with `version=None` on a client where `"corp-mds"` is configured with `api_version="1.9"`
- **THEN** `ArodonataClient` SHALL resolve `version="v1.9"` automatically from `"corp-mds"` settings and return the `v1.9`-filtered schema for `add-interface`

### Requirement: Gateway Topology and Candidate Discovery Facade Methods

`ArodonataClient` SHALL accept an optional `gateway_cli` (`GatewayCliPort` or async command callback) for SSH command execution on gateways, expose `topology_service` (`TopologyService`), and provide traced async facade methods `refresh_topology(..., gateways=..., collect_routes=...)`, `stream_refresh_topology(..., gateways=..., collect_routes=...)`, `collect_gateway_routes(...)`, `get_gateway_topology(...)`, `get_topology_diagnostics(...)`, `reconcile_gateway_topology(..., check_policy=...)`, `upsert_topology_annotations(...)`, `get_topology_annotations(...)`, `delete_topology_annotations(...)`, `export_topology_prefixes(...)`, and `find_affected_gateways(sources, destinations, ..., min_confidence=..., include_standby=..., include_policy_inferred=...)` returning typed Pydantic models.

#### Scenario: Consumer resolves affected gateways and policy packages via ArodonataClient

- **WHEN** a downstream consumer calls `await client.find_affected_gateways(sources=["10.1.1.10"], destinations=["10.2.2.20"], mgmt_name="mds1", include_policy_inferred=True, cache_mode="smart")`
- **THEN** `ArodonataClient` SHALL ensure the topology cache is synchronized according to `cache_mode` and return a ranked list of `AffectedGatewayCandidate` instances containing `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, `confidence_factors`, `warnings`, and `matched_flows` (including `policy_inferred` matches when enabled)

#### Scenario: Host application injects SSH callback and reconciles gateway routes via ArodonataClient

- **WHEN** a host application initializes `ArodonataClient(settings, gateway_cli=ssh_exec_fn)` and calls `await client.collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateways=["gw-01"])` followed by `await client.reconcile_gateway_topology(mgmt_name="mds1", domain="Corp", gateways=["gw-01"], check_policy=True)`
- **THEN** `ArodonataClient` SHALL invoke `ssh_exec_fn` for `"gw-01"`, persist the parsed route intervals into `arodonata_gateway_topology`, and return a `TopologyReconciliationReport` detailing any discrepancies between SmartConsole topology, live routes, and gateway-targeted policy rules

### Requirement: Single-Flight Background Object and Service Cache Warm-Up

`ArodonataClient.start_object_cache_warmup()` SHALL coalesce concurrent in-flight background warm-up calls sharing the same `(mgmt_name, domains, types, include_global, include_services)` scope, handle background failures with SID-redacted structured logging without emitting unretrieved asyncio task warnings for fire-and-forget callers, and expose active/recent warm-up state via `get_warmup_status()`.

#### Scenario: Concurrent warm-up calls for the same domain coalesce into one task

- **WHEN** a host application invokes `client.start_object_cache_warmup(mgmt_name="mds1", domains=["Corp"], include_services=True)` multiple times while the initial warm-up task for `"Corp"` is still running
- **THEN** `start_object_cache_warmup` SHALL return the existing in-flight task rather than spawning duplicate concurrent `refresh_objects` / `refresh_services` runs, and `client.get_warmup_status(mgmt_name="mds1")` SHALL report `"Corp"` as `"running"` until completion

#### Scenario: Fire-and-forget warm-up failure logs redacted warning without unretrieved exception

- **WHEN** a caller schedules `client.start_object_cache_warmup(mgmt_name="mds1", domains=["UnreachableCMA"])` without awaiting the returned `asyncio.Task` and the background refresh raises an error
- **THEN** the client SHALL record the SID-redacted failure in `get_warmup_status()` and emit a structured warning log without producing an `"Task exception was never retrieved"` warning on garbage collection

### Requirement: Lightweight Package Catalog and Targeted Package Rulebase Facade Methods

`ArodonataClient` SHALL expose traced async facade methods `refresh_policy_packages(...)` and `refresh_package_rulebase(...)` in addition to `get_policy_packages(...)` and `get_package_rulebase(...)`, and SHALL forward `source_types` and `include_annotations` filtering parameters on `find_affected_gateways(...)`.

#### Scenario: Consumer refreshes single package access sections and static gateway candidates via facade

- **WHEN** a consumer calls `await client.get_policy_packages("mds1", "Corp", cache_mode="smart")`, `await client.get_package_rulebase("mds1", "Corp", "Corp_Pkg", rulebase_type="access", cache_mode="smart")`, and `await client.find_affected_gateways(sources, destinations, mgmt_name="mds1", source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)`
- **THEN** `ArodonataClient` SHALL return the domain's `PolicyPackageInfo` catalog, the numbered `PackageRulebase` for `"Corp_Pkg"`, and the static-only `AffectedGatewayCandidate` list without triggering full-domain NAT/HTTPS/Threat rulebase syncs or full-domain `show-hosts` downloads


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
- **THEN** the resulting settings instance SHALL use `concurrent_limit == 8`, cap default `domain_sync_concurrency` at `min(2, max(1, concurrent_limit - 1)) == 2` unless overridden via `domain_sync_concurrency` or `ARODONATA_DOMAIN_SYNC_CONCURRENCY`, cap default `route_collect_concurrency` at `min(4, max(1, concurrent_limit // 2)) == 4` unless overridden via `route_collect_concurrency` or `ARODONATA_ROUTE_COLLECT_CONCURRENCY`, and default `max_routes_per_gateway` to `50000` unless overridden via `max_routes_per_gateway` or `ARODONATA_MAX_ROUTES_PER_GATEWAY`

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

### Requirement: Environment-Backed CPCRUD Naming Profile Configuration

`ArodonataSettings` SHALL resolve a default `cpcrud_naming_prefixes` profile from explicit constructor arguments and `ARODONATA_CPCRUD_*` (falling back to `CPCRUD_*`) environment variables without loading `.env` files implicitly, covering host, network, range, group, service, and application-site formatting options.

#### Scenario: Environment variables populate CPCRUD naming profile defaults

- **WHEN** `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"`, `ARODONATA_CPCRUD_RANGE_SEPARATOR="_"`, `ARODONATA_CPCRUD_RANGE_COMPRESS_OCTETS="true"`, `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_GROUP=""`, `ARODONATA_CPCRUD_AUTO_NAME_SUFFIX_GROUP="_Grp"`, `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_APP_SITE="Site_"`, and `ARODONATA_CPCRUD_APP_SITE_WILDCARD_MARKER="_"` are set in `os.environ`
- **THEN** `ArodonataSettings().cpcrud_naming_prefixes` SHALL reflect those configured prefixes, suffixes, range separator, compression flag, and wildcard marker without reading `.env` files from disk

#### Scenario: Secondary CPCRUD environment aliases are accepted when ARODONATA_CPCRUD variables are absent

- **WHEN** `CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"` and `CPCRUD_RANGE_COMPRESS_OCTETS="true"` are present without `ARODONATA_CPCRUD_*` counterparts
- **THEN** `ArodonataSettings().cpcrud_naming_prefixes` SHALL resolve those `CPCRUD_*` values as fallback defaults while prioritizing `ARODONATA_CPCRUD_*` and explicit constructor arguments

#### Scenario: CPCRUDService planning uses ArodonataSettings naming profile by default

- **WHEN** a caller invokes `client.cpcrud.plan(template)` without supplying an explicit `naming_prefixes` argument or template `naming_prefixes` block
- **THEN** the planner SHALL apply `settings.cpcrud_naming_prefixes` when auto-naming newly created objects and services


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

`CPCRUDService` SHALL execute `apply` and `stream_apply` using allowlisted `(object_type, operation)` commands in an isolated `WriteSession` per domain (defaulting omitted session names to `arodonata-cpcrud*`), re-verify the domain head before each pass and pre-`publish`, shield `discard` before `logout` on any `BaseException`, and adopt staged sessions only after `show-session` provenance verification with non-disruptive takeover by default.

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
- **THEN** the executor SHALL assign a default `arodonata-cpcrud-staged` session name when none was supplied, leave the dedicated write session open without publishing, record its details (`sid`, `server_ip`, `session_uid`, `session_name`) in `ApplyReport.staged_sessions` and the client's staged-session registry immediately upon creation, and emit a `StagedSessionEvent` in `stream_apply()`

#### Scenario: Staged session publication adopts ownership via take-over-session and invalidates domain cache

- **WHEN** `await client.publish_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` or `client.stream_publish_staged_session(...)` is called for a previously staged session
- **THEN** the service SHALL reuse a caller-supplied `sid` directly when `show-session {}` confirms `uid == session_uid` in an open state, or otherwise open a dedicated helper session (`arodonata-cpcrud-adopt`), inspect `show-session {}` to record the helper session's `initial_uid` and `current_user`, verify via `show-session {"uid": session_uid}` that the target session is open and eligible for Web API adoption (recorded by `keep_session=True`, carrying an `arodonata*` session name, matching `expected_session_name`, or created via `WEB_API` by the same administrator when `allow_foreign=False`), issue `take-over-session` (`{"uid": session_uid}` without `disconnect-active-session` unless explicit library-only `force_disconnect=True` is passed, falling back to `switch-session` only after provenance verification passes and reporting both errors if both fail), immediately discard the detached initial helper session via `discard {"uid": initial_uid}` so no empty `arodonata-cpcrud-adopt` session remains open on Check Point, execute `publish` while polling task progress, log out cleanly, and call `client.invalidate_domain(mgmt_name, domain)`

#### Scenario: Staged session discard adopts ownership via take-over-session before discarding

- **WHEN** `await client.discard_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` is called for an open or orphaned staged session
- **THEN** the service SHALL verify open Web API / Arodonata provenance via `show-session` (or reuse an active matching `sid` directly), adopt ownership via non-disruptive `take-over-session` (with `disconnect-active-session` omitted/`False` unless explicit library-only `force_disconnect=True` is passed, and provenance-gated `switch-session` fallback reporting both errors on failure), discard the detached initial `arodonata-cpcrud-adopt` helper session via `discard {"uid": initial_uid}`, execute `discard` on the adopted session, and log out cleanly

#### Scenario: Foreign, active SmartConsole, or already-finalized session UID refused during staged adoption

- **WHEN** `publish_staged_session`, `stream_publish_staged_session`, or `discard_staged_session` is called with a `session_uid` belonging to a human SmartConsole session, another administrator's Web API session (when `allow_foreign=False`), a session whose name mismatches `expected_session_name`, an already `published`/`discarded` session, or an actively connected session while `force_disconnect=False`
- **THEN** the service SHALL refuse adoption before issuing disruptive `take-over-session` or `switch-session`, log out any fresh helper session it opened, and return a failed `ApiCallResult` (or failure event) without disconnecting the active administrator or publishing/discarding their work

#### Scenario: Post-publish domain cache invalidation and retry_remaining folding

- **WHEN** `apply()` publishes changes in a domain or `retry_remaining > 0` re-runs failed/remaining actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called so subsequent smart reads re-sync the domain, and retry passes SHALL re-verify domain head freshness (never forcing `force=True` automatically) and fold their `ApplyReport` into the cumulative report

### Requirement: Compensating Rollback Template Generation

`CPCRUDService.inverse(plan, report)` SHALL build a schema-valid compensating template from `Plan` and `ApplyReport`, inverting only actions that actually succeeded when `report` is supplied, targeting created objects by the real `uid` returned in `ApplyReport` (refusing unsafe delete-by-name for unexecuted `planned:` UIDs), and restoring all mutated fields present in `PlannedAction.prior_state`.

#### Scenario: Inverse template restores deleted and updated objects and removes created ones

- **WHEN** `inverse(plan, report)` is called after an apply pass where some actions succeeded and others failed or were skipped/stale
- **THEN** it SHALL produce a dictionary valid against `checkpoint_ops_schema.json` that includes compensating operations ONLY for actions that succeeded in `report`, deletes `CREATE` actions using the concrete `uid` recorded in `report` (skipping any `CREATE` that lacks a real created UID), restores all prior field values from `prior_state` for `UPDATE` actions, and re-creates `DELETE` actions from `prior_state`

### Requirement: Declarative Lifecycle Support for Check Point Application-Site Objects

`CPCRUDService` SHALL validate, read, diff, plan (`add-application-site`, `set-application-site`, `delete-application-site`), and generate compensating rollback operations for Check Point `application-site` objects declared in `objects`, `services`, or `operations` sections, including URL lists and regular-expression flags.

#### Scenario: Schema and semantic validation of application-site operations

- **WHEN** `CPCRUDService.validate()` is called on a template containing an `application-site` operation in `objects`, `services`, or `operations` with `name`, `primary-category` (or `primary_category`), `url-list` (or `url_list`), and `urls-defined-as-regular-expression` (or `urls_defined_as_regular_expression`)
- **THEN** validation SHALL succeed with zero errors, and SHALL reject `present`/`add` `application-site` operations that omit both `url-list` and `application-signature`

#### Scenario: Planning creation of a new regex application-site object

- **WHEN** `CPCRUDService.plan()` evaluates a `present` or `add` operation for an `application-site` (e.g., `name: "Site_baidu.com"`, `primary-category: "Custom_Application_Site"`, `url-list: ["\\/baidu\\.com", "\\.baidu\\.com"]`, `urls-defined-as-regular-expression: true`) that does not exist in the target domain
- **THEN** the planner SHALL produce a `PlannedAction` with `Outcome.CREATE`, command `"add-application-site"`, and payload containing `"name"`, `"primary-category"`, `"url-list"`, and `"urls-defined-as-regular-expression": true`, and SHALL register the resolved name for downstream `access-rule` `service` references

#### Scenario: Existing application-site with identical URL list and regex flag is planned as UNCHANGED

- **WHEN** `CPCRUDService.plan()` evaluates an `application-site` operation whose target name already exists in the domain with the same `primary-category`, the same set of URLs in `url-list`, and the same `urls-defined-as-regular-expression` boolean
- **THEN** the planner SHALL produce `Outcome.UNCHANGED` requiring zero write calls during `apply()`

#### Scenario: Existing application-site with different URL list respects NameConflictPolicy

- **WHEN** `CPCRUDService.plan()` evaluates an `application-site` operation whose target name already exists in the domain with a different `url-list` or `urls-defined-as-regular-expression` value
- **THEN** the planner SHALL produce `Outcome.ERROR` reporting `differs on [url-list]` when `on_name_conflict="error"`, or `Outcome.UPDATE` with command `"set-application-site"` when `on_name_conflict="update"`

#### Scenario: Inverse rollback template restores or deletes application-site objects

- **WHEN** `CPCRUDService.inverse()` is called for a plan/report containing `CREATE`, `UPDATE`, or `DELETE` actions on `application-site` objects
- **THEN** it SHALL generate the corresponding compensating `delete`, `set`, or `add` `application-site` operation preserving `primary-category`, `url-list`, `urls-defined-as-regular-expression`, and `description`, ordered after any dependent `access-rule` rollbacks

### Requirement: Targeted Cold-Cache Value Conflict Lookups During Planning

When a domain's object or service cache slice is not stamped fresh during `CPCRUDService.plan()`, value-conflict lookups for hosts, networks, address ranges, and TCP/UDP services SHALL query `show-objects` (`type`, `filter`, `ip-only`) with exact attribute verification and intra-plan overlays instead of paginating `show-hosts`, `show-networks`, or `show-services-tcp` / `show-services-udp`, while ICMP value lookups SHALL use single-page `show-services-icmp` / `show-services-icmp6` listing.

#### Scenario: Cold-cache ICMP lookup matches built-in services without numeric text filter

- **WHEN** `CPCRUDService.plan()` evaluates `add` / `present` for a `service-icmp` (`icmp-type: 8`, `icmp-code: 0`) on cold cache where built-in `echo-request` does not contain `"8"` in its name
- **THEN** the planner SHALL query `show-services-icmp` (memoized per domain) and match `echo-request` by exact `(icmp_type, icmp_code)` equality

#### Scenario: Cold-cache host and TCP service conflict checks avoid full domain listing

- **WHEN** `CPCRUDService.plan()` evaluates `add` / `present` operations for a `host` (`10.20.30.40`) and a `service-tcp` (`port: "8443"`) in a domain whose `arodonata_objects` and `arodonata_services` caches are empty
- **THEN** the planner SHALL query `show-objects` (`type="host"`, `filter="10.20.30.40"`, `ip-only=True`) and `show-objects` (`type="service-tcp"`, `filter="8443"`), filter returned candidates by exact IP/port/protocol equality while merging intra-plan virtual additions/deletions, and execute zero full-domain `show-hosts` or `show-services-tcp` queries

#### Scenario: Substring filter candidates are verified by exact value match

- **WHEN** Check Point `show-objects` (`type="service-tcp"`, `filter="80"`) returns both `TCP_80` (`port="80"`) and `TCP_8080` (`port="8080"`), or `show-objects` (`type="network"`, `filter="10.10.0.0"`, `ip-only=True`) returns both `10.10.0.0/24` and `10.10.0.0/16`
- **THEN** the planner SHALL match only the candidate with exact `(port="80", protocol)` or exact `(subnet4="10.10.0.0", mask_length4=24)` equality

#### Scenario: Graceful fallback when custom ApiPort adapter does not implement show-objects

- **WHEN** a custom or legacy `ApiPort` adapter returns `generic_err_command_not_recognized` for `show-objects` during a cold-cache value lookup, or returns `paging_inconsistent` / transport failure
- **THEN** `generic_err_command_not_recognized` SHALL fall back to type-scoped `show-hosts` / `show-services-*` listing, whereas genuine API or `paging_inconsistent` errors SHALL still fail closed as `Outcome.ERROR` (`StateLookupError`)

### Requirement: Shorthand Object, Range, Domain, and Wildcard Application Expression Parsing

`arodonata.cpcrud` SHALL parse shorthand host, network, full or compressed-octet address-range, DNS-domain, service, inline group, and wildcard application expressions (`*domain` and `*.domain`) into canonical CPCRUD specifications using `NamingPrefixes` for newly created object names while preserving legacy defaults.

#### Scenario: Compressed same-subnet IPv4 address-range naming and shorthand range input

- **WHEN** `NamingPrefixes` has `address_range="Range_"`, `range_separator="_"`, and `compress_range_same_subnet=True`, and an expression or range object specifies `10.1.1.1` through `10.1.1.9` (including shorthand `10.1.1.1-9`)
- **THEN** the parser SHALL resolve bounds `("10.1.1.1", "10.1.1.9")` and `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"Range_10.1.1.1_9"`, while ranges across distinct `/24` prefixes (such as `10.1.1.1` to `10.1.2.9`) SHALL format as `"Range_10.1.1.1_10.1.2.9"`

#### Scenario: Legacy default NamingPrefixes behavior remains backward compatible

- **WHEN** `NamingPrefixes()` is instantiated with default arguments
- **THEN** `format_host("10.1.1.1")` SHALL return `"Host_10.1.1.1"`, `format_network("10.1.1.0", 24)` SHALL return `"Net_10.1.1.0_24"`, `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"IPR_10.1.1.1-10.1.1.9"`, and `format_group("WebServers")` SHALL return `"grpWebServers"`

#### Scenario: Wildcard application expressions normalize both leading-star and star-dot syntax

- **WHEN** an operator supplies `*chinacloudapi.cn` or `*.chinacloudapi.cn` with `NamingPrefixes(app_site="Site_", app_site_wildcard_marker="_")`
- **THEN** `format_app_site("chinacloudapi.cn", is_wildcard=True)` SHALL return `"Site__chinacloudapi.cn"` (containing no `*` character) and the parsed `application-site` spec SHALL emit `primary-category: "Custom_Application_Site"`, `urls-defined-as-regular-expression: true`, and `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]`

#### Scenario: Group suffix and DNS domain shorthand expressions

- **WHEN** `NamingPrefixes(group="", group_suffix="_Grp")` formats group `"AppAccess"` or the parser evaluates `.abc.com`
- **THEN** `format_group("AppAccess")` SHALL return `"AppAccess_Grp"` (avoiding double suffix if already ending in `_Grp`), and `.abc.com` SHALL parse as `type: "dns-domain"`, `name: ".abc.com"`, and `is_sub_domain: true`

### Requirement: Incremental URL-List Updates and Value Reuse for Application-Site Objects

`CPCRUDService` SHALL accept `{"add": [...], "remove": [...]}` deltas on `application-site` `url-list` fields, compute idempotent `set-application-site` diffs, block removals that empty `url-list` without `application-signature`, and reuse pre-existing `application-site` objects matching by normalized URL list regardless of name.

#### Scenario: Adding and removing regex entries on an existing application-site

- **WHEN** `plan()` evaluates an `application-site` update for `"Site__chinacloudapi.cn"` currently containing `["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]` with `url-list: {"add": ["\\.partner\\.cn"], "remove": ["\\/chinacloudapi\\.cn"]}`
- **THEN** `Planner` SHALL produce `Outcome.UPDATE` (`set-application-site`) carrying the merged post-delta `url-list` (`["\\.chinacloudapi\\.cn", "\\.partner\\.cn"]`) and a `FieldChange` recording the prior and updated lists

#### Scenario: Removing the last URL from an application-site without an application signature fails closed

- **WHEN** `plan()` evaluates a `url-list: {"remove": [...]}` operation that removes every remaining entry from an `application-site` that lacks `application-signature`
- **THEN** `Planner` SHALL emit `Outcome.ERROR` explaining that an `application-site` cannot have an empty `url-list` without an `application-signature`

#### Scenario: Legacy-named application-site with identical URL list is reused on value conflict

- **WHEN** `on_ip_conflict="reuse"` is active and `plan()` evaluates `"Site__chinacloudapi.cn"` with `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]` while an existing object `"Custom_ChinaCloud"` already holds that identical URL list and regex flag
- **THEN** `Planner` SHALL produce `Outcome.REUSE` resolving `"Site__chinacloudapi.cn"` to `"Custom_ChinaCloud"` without renaming or duplicating the existing object

### Requirement: Incremental List-Cell Patching and Anti-Any-Widening Guards for Policy Rules

`CPCRUDService` SHALL support `{"add": [...], "remove": [...]}` mutations on list-valued policy rule fields (`source`, `destination`, `service`, `protected-scope`, `site-category`, `install-on`), enforce strict existence on `set`/`update`, block unsafe `"Any"` widening or collision, support `inverse()` rollback, and replicate these behaviors in `FileReplayApiMock`.

#### Scenario: Adding and removing sources, destinations, and services in an existing access rule

- **WHEN** `plan()` evaluates an `access-rule` with `operation: "set"`, `uid` (or `name`/`rule_number`), `source: {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}`, and `service: {"add": ["TCP_8443"]}` where `"Host_10.1.1.1"` is created earlier in the same template
- **THEN** `Planner` SHALL plan `Outcome.UPDATE` (`set-access-rule`) with `depends_on` referencing the `"Host_10.1.1.1"` create action and incremental wire payloads (`{"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}` on `source` and `{"add": ["TCP_8443"]}` on `service`), and `build_inverse_template()` SHALL generate a compensating `set-access-rule` restoring the dereferenced `prior_state`

#### Scenario: Removing all remaining objects from a rule traffic or install cell is rejected to prevent Any widening

- **WHEN** `plan()` evaluates an incremental `{"remove": [...]}` patch on `source`, `destination`, `service`, `protected-scope`, `site-category`, or `install-on` that would leave the resulting list empty
- **THEN** `Planner` SHALL emit `Outcome.ERROR` refusing to empty the cell (preventing Check Point from implicitly widening the rule to `"Any"`)

#### Scenario: Adding specific objects to a rule cell currently set to Any requires explicit removal of Any

- **WHEN** an existing rule has `source: ["Any"]` and `plan()` evaluates `source: {"add": ["Host_10.1.1.1"]}` without `"Any"` in `remove`
- **THEN** `Planner` SHALL emit `Outcome.ERROR` informing the caller that `"Any"` must be removed explicitly when narrowing a rule cell (and when `"Any"` IS explicitly listed in `remove`, `FieldChange.removed_items` SHALL record `["Any"]` while stripping `"Any"` from the Check Point wire `remove` array)

#### Scenario: Adding Any via an incremental rule delta is rejected

- **WHEN** `plan()` evaluates an incremental `{"add": ["Any"]}` delta on a policy rule list cell
- **THEN** `Planner` SHALL emit `Outcome.ERROR` refusing to add `"Any"` incrementally

#### Scenario: Unmatched rule with incremental cell deltas fails closed under any verb

- **WHEN** `plan()` evaluates a policy rule with `{"add": ...}` or `{"remove": ...}` cell deltas under `operation: "present"` (or omitted `operation` / `"set"`) and no existing rule matches
- **THEN** `Planner` SHALL emit `Outcome.ERROR` instead of falling back to `Outcome.CREATE` with `"Any"` traffic cells

#### Scenario: Explicit set or update operation targeting a missing rule, group, object, or service fails closed

- **WHEN** `plan()` evaluates an operation with `operation: "set"` or `operation: "update"` whose target rule, group, service, or object does not exist in the domain
- **THEN** `Planner` SHALL emit `Outcome.ERROR` reporting that the target does not exist rather than creating a new rule or object

#### Scenario: FileReplayApiMock applies incremental url-list and rule cell updates faithfully

- **WHEN** `FileReplayApiMock` processes `set-application-site` or `set-*-rule` with `{"add": [...], "remove": [...]}` patches or list replacements inside a work session
- **THEN** subsequent reads and `show-changes` inside the emulator SHALL reflect the updated URL list or dereferenced rule traffic members accurately


---

### OpenSpec Capability: `gateway-topology` (`openspec/specs/gateway-topology/spec.md`)

# Gateway Topology and Candidate Matching Specification

## Purpose

Defines Check Point gateway interface topology extraction (`TopologyService`), static and API-based subnet/group/route resolution into `arodonata_gateway_topology`, and affected gateway / policy package candidate matching (`find_affected_gateways`, `locate_gateways`) for traffic flows across simple gateways, clusters, and VSX Virtual Systems.

## Requirements

### Requirement: Policy-Enforcing Gateway Target Selection

`TopologyService` SHALL extract and index interface topology only for policy-enforcing gateway assets (`simple-gateway`, `simple-cluster`, `CpmiGatewayCluster`, `virtual-system`, `CpmiVsNetobj`, and `CpmiVsClusterNetobj`), skipping cluster members (`cluster-member`, `CpmiClusterMember`, `CpmiVsxClusterMember`), physical VSX containers (`vsx-gateway`, `vsx-cluster`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`), and management servers (`checkpoint-host`, `mds`).

#### Scenario: Cluster topology is derived from the cluster object while members and VSX hosts are skipped

- **WHEN** `refresh_topology` processes a domain containing a `CpmiGatewayCluster`, its `cluster-member` nodes, a `CpmiVsxNetobj` physical host (`VS0`), and a `CpmiVsNetobj` Virtual System
- **THEN** `TopologyService` SHALL build topology entries only for the `CpmiGatewayCluster` and the `CpmiVsNetobj` Virtual System, emitting zero topology rows for `cluster-member` or `CpmiVsxNetobj` assets

### Requirement: Static Interface Topology Extraction and Group Expansion

`TopologyService` SHALL normalize interface definitions across `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, and `show-generic-object` payloads, extracting Anti-Spoofing enforcement mode (`"prevent"`, `"detect"`, `"off"`, or `"unknown"`), expanding connected subnets (`"network defined by the interface ip and net mask"`), recursively resolving `"specific"` network/group objects from fresh cached objects or via targeted single-object/group API lookups across the domain and `"Global"` without refreshing full `DEFAULT_OBJECT_TYPES` (`show-hosts`, `show-dns-domains`), recording `"external"` interfaces (`leads-to-internet: true`), and logging a warning on unresolvable route-based interfaces.

#### Scenario: Connected subnet and specific group behind interfaces expand into IPv4 intervals

- **WHEN** a gateway has `eth0` configured with `leads-to-internet: true`, `eth1` (`10.10.1.1/24`) configured with `"network defined by the interface ip and net mask"`, and `eth2` configured with `"specific"` referencing group `"G_App_Subnets"` (which contains a host `10.20.1.5`, a subnet `10.20.2.0/24`, and a nested group with range `10.20.3.10-10.20.3.20`) and Anti-Spoofing action `"prevent"`
- **THEN** `TopologyService` SHALL persist an `"external"` entry (`source_type="external_interface"`, `0.0.0.0/0`) for `eth0`, a connected interval (`10.10.1.0/24`, `source_type="interface_connected"`) for `eth1`, and three expanded intervals (`10.20.1.5/32`, `10.20.2.0/24`, `10.20.3.10-10.20.3.20`, `source_type="interface_specific"`, `anti_spoofing_mode="prevent"`) for `eth2`

#### Scenario: Cold topology refresh resolves specific and VPN domain references on demand without bulk show-hosts

- **WHEN** `refresh_topology` or `stream_refresh_topology` runs on a cold database across domains containing thousands of `host` and `dns-domain` objects, where gateways use connected/external interfaces and a `"specific"` or `vpn-domain` group `"G_App_Subnets"`
- **THEN** the refresh SHALL synchronize gateway assets and resolve `"G_App_Subnets"` and its transitive member UIDs via targeted object/group lookups (persisting resolved objects without marking whole-domain `"host"` or `"group"` slices as fully synced), and SHALL perform zero full-domain `show-hosts` or `show-dns-domains` paginated queries

#### Scenario: Interface with routing-defined or undefined topology logs a warning and is skipped

- **WHEN** a non-external gateway interface has `ip-address-behind-this-interface` set to `"network defined by routing"` (without static route records) or `"not defined"`
- **THEN** `TopologyService` SHALL emit a structured warning log identifying the gateway, domain, interface name, and topology setting, and skip static interval creation for that interface

#### Scenario: On-demand detail fallback when gateway summary lacks interface topology

- **WHEN** a policy-enforcing gateway or cluster in `arodonata_assets` has an empty `interfaces` list or lacks topology settings in its `show-gateways-and-servers` summary
- **THEN** `TopologyService` SHALL query `show-simple-gateway`, `show-simple-cluster`, or `show-generic-object` (`details-level="full"`) for that asset UID to retrieve its complete interface list and topology settings before extracting intervals

### Requirement: VSX Virtual System Static Route Topology Resolution

For VSX Virtual Systems (`virtual-system`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`), `TopologyService` SHALL extract static routes from Check Point Management API generic objects (`CpmiVsSlotObj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj` via `routes`, `routes_installed`, or `routing_table`) and associate each routed destination network with the corresponding VS interface (`source_type="vs_static_route"`).

#### Scenario: VS static route next-hop IP resolves to the matching VS connected interface

- **WHEN** a Virtual System has interface `wrp128` (`192.168.100.2/30`), interface `eth1.50` (`10.50.0.1/24`), a static route for `172.16.80.0/24` with next-hop `10.50.0.254`, and a default route `0.0.0.0/0` with next-hop `192.168.100.1`
- **THEN** `TopologyService` SHALL bind `172.16.80.0/24` to interface `eth1.50` with `source_type="vs_static_route"` and `topology_zone="internal"`, and mark `wrp128` as an `"external"` interface (`source_type="vs_static_route"`, `0.0.0.0/0`)

### Requirement: Extensible Multi-Source Topology Schema

Each persisted `GatewayTopologyEntry` in `arodonata_gateway_topology` SHALL carry a `source_type` discriminator (`"interface_connected"`, `"interface_specific"`, `"vs_static_route"`, `"vpn_domain"`, `"external_interface"`, `"connected_route"`, `"gaia_static_route"`, `"clish_route"`, `"bgp_route"`, `"ospf_route"`, or `"manual"`) and `anti_spoofing_mode` metadata so static Management API definitions, live CLI-collected routing tables, and manual entries coexist without overwriting unrelated source categories during refresh.

#### Scenario: Multiple topology sources coexist per gateway interface

- **WHEN** an interface has both a connected or specific subnet (`source_type="interface_connected"` or `"interface_specific"`), VPN encryption domain intervals (`source_type="vpn_domain"`), and routed subnets (`source_type="vs_static_route"` or `"bgp_route"`), and `refresh_topology(collect_routes=False)` subsequently refreshes static topology
- **THEN** `arodonata_gateway_topology` SHALL store and query all intervals for that `(gateway_uid, interface_name)` while preserving each interval's `source_type`, `source_ref`, and existing CLI-collected route entries

### Requirement: Affected Gateway and Policy Package Candidate Matching

`TopologyService.find_affected_gateways()` SHALL resolve `sources` and `destinations` against each gateway's internal intervals first (longest-prefix match) and external interface second (`0.0.0.0/0` fallback), optionally filter evaluated intervals by `source_types` and toggle `TopologyAnnotation` overrides via `include_annotations`, compute delta-based `confidence` scores (`0.0..1.0`) with `confidence_factors` and `is_standby_path` flags, exclude any gateway where `Source` and `Destination` resolve to the same interface (`src_interface == dst_interface`), both fall back to `external`, or fall below `min_confidence`, and return affected gateways with their domain, policy packages, `matched_flows`, and input-ordered `matched_sources` and `matched_destinations`.

#### Scenario: Traffic between two internal interfaces or between internal and external interfaces matches

- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["8.8.8.8"])` runs against Gateway A (`10.10.1.0/24` on `eth1`, `external` on `eth0`, policy `"Perimeter_Pkg"` in domain `"Corp"`), Gateway B (`10.10.1.0/24` on `bond0.10`, `8.8.8.0/24` on `bond0.20`, policy `"Core_Pkg"` in domain `"DC"`), and Gateway C (`192.168.1.0/24` on `eth1`, `external` on `eth0`)
- **THEN** it SHALL return Gateway B (`match_type="internal_to_internal"`, `bond0.10 -> bond0.20`, domain `"DC"`, package `"Core_Pkg"`, `matched_sources=["10.10.1.25"]`, `matched_destinations=["8.8.8.8"]`) and Gateway A (`match_type="internal_to_external"`, `eth1 -> eth0`, domain `"Corp"`, package `"Perimeter_Pkg"`, `matched_sources=["10.10.1.25"]`, `matched_destinations=["8.8.8.8"]`), and exclude Gateway C because both `10.10.1.25` and `8.8.8.8` fall back to Gateway C's `eth0` (`external == external`)

#### Scenario: Traffic where both source and destination sit behind the same internal interface is excluded

- **WHEN** `find_affected_gateways(sources=["10.10.1.10"], destinations=["10.10.1.99"])` runs against a gateway where both addresses match `10.10.1.0/24` on `eth1`
- **THEN** that gateway SHALL be excluded from the returned candidates because `src_interface == dst_interface == "eth1"`

#### Scenario: Multi-gateway and transit topology filters matched_sources and matched_destinations per gateway in input order

- **WHEN** `find_affected_gateways(sources, destinations)` runs with multiple sources and destinations across a 4-gateway topology (`GW1` and `GW2` serving distinct source branches, `GW3` acting as a transit gateway with upstream branch networks on one interface, its own local subnets on another interface, and downstream networks on a third interface, plus `GW4` behind `GW3`)
- **THEN** each returned `AffectedGatewayCandidate` SHALL populate `matched_sources` and `matched_destinations` with only the unique `source_query` and `destination_query` strings present in that gateway's cross-interface `matched_flows`, strictly preserving the caller's input order from `sources` and `destinations`, and excluding any gateway where all pairs resolve to the same interface (`src_interface == dst_interface`) or `external == external`

#### Scenario: Policy package resolution combines asset policy metadata and rulebase installation targets

- **WHEN** an affected gateway has `raw_data["policy"]["access-policy-name"] = "Standard_Policy"` and/or is listed in `installation-targets` of a cached `PolicyPackageInfo` in `arodonata_rulebase_package_layer`
- **THEN** the returned `AffectedGatewayCandidate` SHALL populate `installed_access_policy="Standard_Policy"`, `policy_packages` with all matching package names, and `access_layers` with the ordered access layer names when the domain's rulebase package catalog or snapshot is cached

#### Scenario: Static-only source_types and disabled annotations filter out live route and manual intervals

- **WHEN** `find_affected_gateways(sources, destinations, source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)` runs on a cache containing static interface topology, live `bgp_route` entries, and `manual` annotations
- **THEN** candidate matching SHALL evaluate strictly the intervals matching `source_types` and ignore `TopologyAnnotation` overrides without mutating cached rows

### Requirement: Static Topology Health Diagnostics and One-Arm Classification

`TopologyService.get_topology_diagnostics()` SHALL inspect policy-enforcing gateways and interfaces to report completeness and trust diagnostics (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`, `no_interfaces`), while treating internal-only gateways as valid and classifying single-interface or external-only gateways as `one_arm_topology` (`severity="info"`).

#### Scenario: Diagnostics report incomplete interfaces and Detect-mode anti-spoofing without false positives on internal-only or one-arm gateways

- **WHEN** `get_topology_diagnostics()` evaluates Gateway 1 (`eth1` with `not defined`, `eth2` with `network defined by routing` and no cached routes, `eth3` with `specific` group and Anti-Spoofing set to `Detect`), Gateway 2 (an internal segmentation firewall with `eth1` and `eth2` internal subnets and no `external` interface), and Gateway 3 (a single-interface `one_arm` gateway)
- **THEN** it SHALL emit warning diagnostics for Gateway 1's `eth1` (`not_defined`), `eth2` (`routing_defined_without_routes`), and `eth3` (`anti_spoofing_detect_or_off`), emit zero warnings for Gateway 2, and report Gateway 3 with `code="one_arm_topology"` at `severity="info"`

### Requirement: Live Gateway Route Collection via SSH Dependency Injection and CPRID Fallback

`TopologyService.collect_gateway_routes()` SHALL collect live IPv4 routing tables (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`, and `0.0.0.0/0` default routes) by invoking an injected `GatewayCliPort` (or async SSH callback in bash) first, and falling back to Check Point Management API `run-script` (`cprid` via `TaskWaiter`) when no SSH executor is provided or when SSH execution fails and `fallback_to_cprid=True`.

#### Scenario: Cluster and VSX Virtual System route collection via SSH DI and vsenv context switching

- **WHEN** `collect_gateway_routes()` runs for a `CpmiGatewayCluster` (with two `cluster-member` nodes) and a VSX `CpmiVsNetobj` (`vsid=3` hosted on physical parent `VSX-GW-01`)
- **THEN** it SHALL resolve the cluster to its `cluster-member` node targets and resolve the Virtual System to `VSX-GW-01` (`vsid=3`), executing a bash script that switches context via `vsenv "$vsid" >/dev/null 2>&1 </dev/null`, verifies `$FWDIR` contains `CTX00003`, and runs `ip -4 route show </dev/null` to persist normalized route intervals in `arodonata_gateway_topology`

#### Scenario: Automatic fallback from SSH callback to Management API run-script

- **WHEN** a host application provides an SSH `gateway_cli` callback that raises a connection error for a remote branch gateway while `fallback_to_cprid=True`
- **THEN** `TopologyService` SHALL execute the route collection script on that gateway via Management API `run-script`, wait for the task via `TaskWaiter`, decode the Base64 output from `task-details[].responseMessage`, and parse the resulting routes

#### Scenario: Per-physical-node VSX serialization, MDS concurrency cap, and single-flight route collection

- **WHEN** `collect_gateway_routes()` runs across multiple VSX Virtual Systems sharing one physical VSX host (`VS0`) alongside independent gateways, or when two callers invoke `collect_gateway_routes()` concurrently with identical scope
- **THEN** `TopologyService` SHALL serialize CLI/`cprid` execution per physical `node_uid` so at most one command runs at a time on `VS0` without blocking independent gateways up to `route_collect_concurrency`, and coalesce identical concurrent calls into a single in-flight collection

#### Scenario: Large routing table cap and clish bypass protect gateways holding BGP full-view tables

- **WHEN** `collect_gateway_routes()` runs on a gateway whose routing table exceeds `max_routes_per_gateway` (or `10000` kernel routes for `clish`)
- **THEN** the collection script SHALL skip `clish -c "show route"` when kernel routes exceed `10000` lines, truncate collected routes at `max_routes_per_gateway`, and record a truncation warning in `GatewayRouteCollectionStatus.warnings`

### Requirement: Targeted Per-Gateway Topology and Route Refresh

`TopologyService.refresh_topology()` and `TopologyService.collect_gateway_routes()` SHALL accept an optional `gateways: Sequence[str] | None` filter (matching gateway UID, name, `id`, or `asset_id`) that refreshes and replaces cached topology and route intervals strictly for the specified gateways without re-querying or deleting cached topology rows for other gateways in the domain.

#### Scenario: Refreshing a single modified gateway in a large domain preserves other gateways

- **WHEN** an administrator updates topology or routing on `"gw-branch-42"` and calls `refresh_topology(mgmt_name="mds1", domains=["Corp"], gateways=["gw-branch-42"], collect_routes=True, mode="force")`
- **THEN** `TopologyService` SHALL query Management API gateway details and collect live routes only for `"gw-branch-42"`, atomically replacing only `"gw-branch-42"` rows in `arodonata_gateway_topology` while leaving all other gateways in `"Corp"` untouched

### Requirement: Static Topology vs Live Routing Reconciliation and Cluster Drift Detection

`TopologyService.reconcile_gateway_topology()` SHALL compare SmartConsole static topology intervals against live CLI-collected routing intervals, across cluster members, and optionally against gateway-targeted policy rules (`check_policy=True`), returning a `TopologyReconciliationReport` classifying discrepancies (`stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, `resolved_by_routing`, `policy_topology_mismatch`) while honoring `TopologyAnnotation` dispositions.

#### Scenario: Reconciliation detects stale anti-spoofing subnets, interface mismatches, and cluster member drift

- **WHEN** SmartConsole static topology on Cluster A declares `10.50.0.0/24` and `10.60.0.0/24` behind `eth1` and `10.70.0.0/24` behind `eth2`, while live routing tables show `10.50.0.0/24` routed via `eth1`, `10.60.0.0/24` absent from all interfaces, `10.70.0.0/24` routed via `eth1` (instead of `eth2`), and `10.80.0.0/24` routed via `eth1` on `member-1` only (absent on `member-2`)
- **THEN** `reconcile_gateway_topology()` SHALL report `stale_in_topology` for `10.60.0.0/24` on `eth1`, `interface_mismatch` for `10.70.0.0/24`, `missing_in_topology` and `cluster_member_drift` for `10.80.0.0/24` on `eth1`, and suppress `stale_in_topology` if `10.60.0.0/24` is annotated with `disposition="standby_dynamic"`

#### Scenario: Policy reconciliation flags gateway-targeted rules whose explicit networks are absent from gateway topology and routes

- **WHEN** `reconcile_gateway_topology(..., check_policy=True)` evaluates a gateway with internal topology `10.10.0.0/16` and an enabled Access or NAT rule explicitly targeting that gateway in `install_on` whose explicit (non-`Any`) `source` (`192.168.50.0/24`) and `destination` (`192.168.60.0/24`) both fall outside all internal topology and route intervals of that gateway
- **THEN** `reconcile_gateway_topology()` SHALL emit a `TopologyDiscrepancy` with `discrepancy_type="policy_topology_mismatch"` identifying the gateway, rule, and unmatched networks

### Requirement: Persistent Administrator Topology Annotations and IPAM Prefix Export

The cache layer SHALL persist `TopologyAnnotation` records in `arodonata_topology_annotations` across topology refreshes, supporting gateway/interface-level `trust_static_topology` overrides, prefix-level dispositions (`"confirmed"`, `"standby_dynamic"`, `"ignore"`, `"manual"`), and IPAM enrichment fields (`zone`, `site`, `comment`, `custom_metadata`), and `TopologyService.export_topology_prefixes()` SHALL export the annotated prefix inventory.

#### Scenario: Annotations survive topology refresh and enrich IPAM prefix export

- **WHEN** an administrator saves a `TopologyAnnotation` marking `10.90.0.0/24` on `gw1:eth1` as `disposition="standby_dynamic"`, `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and marks `10.99.0.0/24` as `disposition="ignore"`, followed by `refresh_topology(mode="force")` and `export_topology_prefixes()`
- **THEN** the annotations SHALL remain intact after `refresh_topology`, `10.99.0.0/24` SHALL be excluded from active candidate matching, and `export_topology_prefixes()` SHALL include `10.90.0.0/24` with `zone="DMZ-Partner"`, `site="Branch-SPB"`, `comment="Backup BGP path"`, and `disposition="standby_dynamic"`

### Requirement: Extensible Evidence Delta Confidence Scoring

`TopologyService` SHALL compute endpoint and flow confidence in `[0.0, 1.0]` by summing configurable signed evidence deltas (`TopologyConfidenceWeights` for positive route, static topology, annotation, and policy/VPN/bridge hooks, minus conflict penalties) and attaching `confidence`, `is_standby_path`, and `confidence_factors` (`list[ConfidenceDelta]`) to each `TrafficFlowMatch` and `AffectedGatewayCandidate`.

#### Scenario: Delta confidence reflects route agreement, detect-only anti-spoofing, conflicts, and standby annotations

- **WHEN** `find_affected_gateways()` evaluates flows across interfaces with (a) matching live route + SmartConsole `Prevent` topology, (b) live route on `eth1` conflicting with mismatched SmartConsole static topology on `eth2`, and (c) a subnet present only in SmartConsole topology and annotated as `standby_dynamic`
- **THEN** case (a) SHALL clamp to `confidence=1.0`, case (b) SHALL yield a high but penalized confidence (rising when static topology is marked `trust_static_topology=False`), and case (c) SHALL set `is_standby_path=True` with the `admin_standby_dynamic` delta recorded in `confidence_factors`

### Requirement: VPN Encryption Domain Topology Extraction

During topology extraction, the system SHALL extract each policy-enforcing gateway or cluster `vpn-domain` (`encryption-domain`) reference, recursively expand the referenced network or group object from cached domain and `"Global"` objects into IPv4 intervals with `source_type="vpn_domain"`, and apply the `vpn_encryption_domain` confidence delta when matching endpoints against those intervals.

#### Scenario: Gateway encryption domain group expands into vpn_domain intervals and contributes vpn_encryption_domain confidence

- **WHEN** a gateway or cluster defines `vpn-domain` (or `encryption-domain`) referencing group `"G_VPN_Encryption_Domain"` containing `10.77.1.0/24` and `10.77.2.0/24`, and `refresh_topology` extracts its topology
- **THEN** `arodonata_gateway_topology` SHALL persist `10.77.1.0/24` and `10.77.2.0/24` with `source_type="vpn_domain"`, and `find_affected_gateways` matching an endpoint inside `10.77.1.0/24` SHALL include the `vpn_encryption_domain` (`+0.45`) delta in `confidence_factors`

### Requirement: Policy and NAT Rule Topology Inference and Confidence Evidence

`find_affected_gateways()` SHALL evaluate enabled, non-negated, non-`Any` Access Control and NAT rules in each gateway's installed policy package (honoring `install_on` targets), awarding `+policy_rule_evidence` in `confidence_factors` to cross-interface L3 candidates and, when `include_policy_inferred=True`, returning one-arm or incomplete-topology gateways whose installed rules explicitly cover the queried `sources` and `destinations` with `match_type="policy_inferred"`.

#### Scenario: Cross-interface L3 gateway receives policy_rule_evidence bonus from matching Access or NAT rules

- **WHEN** `find_affected_gateways(sources=["10.10.1.25"], destinations=["10.20.2.50"])` matches a multi-interface L3 gateway whose installed policy package contains an enabled, non-`Any` Access rule or NAT rule (`original` or `translated` source/destination) covering `10.10.1.25` and `10.20.2.50` and targeting that gateway (or `"Policy Targets"`)
- **THEN** the matched flow and `AffectedGatewayCandidate` SHALL include `ConfidenceDelta(code="policy_rule_evidence", delta=0.25, ...)` in `confidence_factors`

#### Scenario: One-arm Cisco ACI service-graph gateway is discovered via installed EPG policy while unrelated one-arm gateways are excluded

- **WHEN** a domain contains 10 one-arm Cisco ACI service-graph gateways (`corp-aci-onearm-01` .. `corp-aci-onearm-10`, each having only a single `external` interface) and only `corp-aci-onearm-03` has an installed policy rule explicitly permitting or translating traffic between `10.160.10.0/24` (EPG-Web) and `10.160.20.0/24` (EPG-App)
- **THEN** `find_affected_gateways(sources=["10.160.10.15"], destinations=["10.160.20.25"], include_policy_inferred=True)` SHALL return `corp-aci-onearm-03` with `match_type="policy_inferred"` and `policy_rule_evidence` in `confidence_factors`, while excluding the remaining 9 one-arm gateways (`corp-aci-onearm-01..02`, `04..10`), and `find_affected_gateways(..., include_policy_inferred=False)` SHALL exclude all 10 one-arm gateways

### Requirement: Enterprise Raw-Replay Scale Verification for Multi-Hop, ECMP, LPM, and Batch Topology Queries

`TopologyService` SHALL accurately synchronize, diagnose, reconcile, and resolve 7–10-hop cross-domain transit chains, parallel ECMP paths, standby BGP paths, nested `/8`–`/32` longest-prefix-match (LPM) hierarchies, and `20x20+` batch source/destination matrices when driven end-to-end from raw Check Point Management API and gateway CLI routing fixtures.

#### Scenario: Cold raw-replay sync, smart-cache reuse, anomaly reconciliation, and administrator annotations

- **WHEN** `refresh_topology(..., collect_routes=True)` executes cold against the multi-domain enterprise raw dataset, followed by a `cache_mode="smart"` / `"cache"` re-run, `get_topology_diagnostics()`, `reconcile_gateway_topology()`, `upsert_topology_annotations()`, and `export_topology_prefixes()`
- **THEN** the cold sync SHALL populate `SqlCacheAdapter` from raw API/CLI payloads, the subsequent `smart` and `cache` runs SHALL perform zero `show-gateways-and-servers` or SSH calls while `show-last-published-session` is unchanged, diagnostics and reconciliation SHALL detect all planted anomalies (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `one_arm_topology`, `stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `cluster_member_drift`, `default_route_mismatch`) with zero false warnings on internal-only gateways, and administrator annotations (`standby_dynamic`, `ignore`, `manual`, `confirmed`, `trust_static_topology=False`, `zone`, `site`, `comment`) SHALL govern candidate matching and IPAM prefix export

#### Scenario: Deep 7 to 10 hop inter-domain transit chain, ECMP, standby BGP, LPM matryoshka, and 20x20 batch matrix

- **WHEN** `find_affected_gateways()` evaluates (a) a cross-domain flow traversing 7–10 hops (`Branch -> Regional -> WAN_Core -> Perimeter -> Transit -> DC_Spine -> VS Tier-1 -> VS Tier-2 -> DB_Seg`) with parallel ECMP hops and standby BGP gateways (`include_standby=True` vs `False`), (b) packets targeting nested prefixes (`/8`, `/12`, `/16`, `/22`, `/24`, `/28`, `/32`) distributed across distinct interfaces of a single gateway, and (c) a `20+ x 20+` batch of sources and destinations (including nested groups and address ranges)
- **THEN** it SHALL return all active hops (including both ECMP legs) while filtering standby BGP hops according to `include_standby`, select the exact most-specific interface at every `/8`–`/32` matryoshka level via LPM, and complete the `20+ x 20+` batch query in sub-second time from cache while strictly preserving the caller's input order in `matched_sources` and `matched_destinations`

#### Scenario: Targeted single-gateway refresh after raw API and CLI mutation queries only the target gateway

- **WHEN** the raw API/CLI fixture for a single gateway is modified to add a new routed subnet and `refresh_topology(gateways=[target_gateway], collect_routes=True)` is invoked
- **THEN** the replay call counters SHALL confirm that only `target_gateway` was queried via Management API and SSH CLI, and `find_affected_gateways()` SHALL immediately reflect the updated routing graph


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
- **THEN** the catalog SHALL include runnable scripts for basic domain/object/service queries (`01`), search and structured queries (`02`), gateway/cluster/VSX relationships (`03`), streaming cache refresh (`04`), rulebase queries and numbering (`05`), session lifecycle (`06`), `auth_context`/`user_context` and `SessionOverlay` read-your-own-writes (`07`), CPCRUD idempotent apply (`08`) and compensating inverse (`09`), change report evidence (`10`), OpenTelemetry tracing with module gating (`11`), FastAPI MCP embedding (`12`, configured with explicit bearer/host authentication middleware protecting write-capable MCP routes), and gateway interface topology caching and affected gateway candidate matching (`13`), with all mutating examples wrapped in `guarded_session` so target lab domains are automatically restored on exit

### Requirement: Deterministic Enterprise Raw Dataset and Generator

The testing harness SHALL provide a deterministic (fixed-seed) generator and raw fixture dataset (`tests/fixtures/enterprise_raw_dataset/`) containing Check Point Management API JSON payloads (including MDSM global assignments, deterministic `Global` object/group usage in local rules, heterogeneous standalone gateway, HA cluster, Virtual System, and cross-domain VSX distributions across every user domain, unique per-domain gateway/interface IPs and Virtual System internal subnets, and complete `CpmiVsxSlotObj`/`CpmiVsSlotObj` metadata) and gateway CLI routing outputs for an enterprise MDSM topology.

#### Scenario: Raw dataset covers multi-domain API payloads and gateway CLI outputs

- **WHEN** the enterprise raw dataset is generated or loaded from `tests/fixtures/enterprise_raw_dataset/`
- **THEN** it SHALL provide deterministic raw Check Point API JSON files (`show-domains`, `show-global-assignments`, `show-sessions`, `show-last-published-session`, `show-session`, `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects`, `show-hosts`, `show-networks`, `show-address-ranges`, `show-groups` nested 6–7 levels deep, `show-services-*`, `show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`) and raw CLI stdout files (`vsx stat -l`, `ip -4 route show`, `clish -c "show route"`, and Base64 `run-script`/`show-task` payloads) across 9 user MDSM domains plus `Global`

#### Scenario: Raw dataset includes deterministic Global object and group usage in local domain rules without breaking scale invariants

- **WHEN** `ensure_enterprise_raw_dataset()` materializes `tests/fixtures/enterprise_raw_dataset/`
- **THEN** local user domains SHALL deterministically reference `Global` objects, services, and groups (such as `H_Global_DNS_001`, `G_Global_Branch_Supernet`, `G_Global_DC_Supernet`, `TCP_53`, and `UDP_53`) inside existing Access rule #104 (`uid-arule-<domain>-0104`) and expose `mds/show-global-assignments.json` while preserving existing scale invariants (`10` domains, `341` cached assets, `315` gateways with `simple-gateway`, cluster, and `CpmiVsNetobj` Virtual System assets in every user domain plus at least `15` cross-domain Virtual Systems, `325` CLI routing targets, unique per-domain gateway and interface IPv4 addresses and Virtual System internal `/24` subnets, complete `CpmiVsxSlotObj` and `CpmiVsSlotObj` entries across VSX chassis hosts, `105` access rules in `3` sections per domain, `12` NAT rules per domain, fewer than `250` topology-cached objects, and unmodified rule #1 fixtures)

### Requirement: File-Backed Check Point API and Gateway CLI Replay Doubles

The testing package SHALL provide `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) backed by the raw dataset on disk, emulating Check Point pagination (`limit`/`offset`/`from`/`to`/`total`), `details-level`, `uid`/`name`/`class-name` filtering, rulebase slicing with `use-object-dictionary=False` inlining, `where-used` dependency resolution, `run-script` + `show-task`, VSX CLI validation, stateful per-`sid` mutations, and redacted call auditing.

#### Scenario: Paginated API queries and VSX CLI context validation execute against raw fixture files

- **WHEN** `ArodonataClient` queries `FileReplayApiMock` with `limit`/`offset`, `uid`/`name`/`class-name` filters, `where-used`, or `show-access-rulebase` / `show-nat-rulebase` (`use-object-dictionary=True | False`), and executes route collection scripts against `FileReplayCliMock` (or `run-script` + `show-task` fallback)
- **THEN** `FileReplayApiMock` SHALL return continuity-valid slices (`from`, `to`, `total`), resolve `where-used` direct and indirect group/access-rule/NAT-rule references (and inline `objects-dictionary` dicts when `use-object-dictionary=False`), and return Base64-encoded `show-task` responses from the raw dataset while recording per-command call counters, and `FileReplayCliMock` SHALL verify `vsenv` / `vsx stat -l` and `CTX%05d` `$FWDIR` guards before returning the raw CLI stdout for the target node and VSID

#### Scenario: Stateless read calls without SID continue reading published domain state

- **WHEN** a caller invokes read-only `FileReplayApiMock.api_call(...)` or `api_query(...)` with `sid=None`
- **THEN** `FileReplayApiMock` SHALL continue serving responses from the domain's published snapshot without failing authentication, ensuring existing unit and topology scale tests remain backward-compatible

### Requirement: Standalone Check Point Web API HTTPS Mock Server for Downstream Applications

The testing package SHALL provide an embeddable and CLI-runnable HTTPS server (`python -m arodonata.testing.mock_server`) sharing unified session, async task, and mutation state with `FileReplayApiMock`, serving `/web_api/{cmd}` with host-rewritten `show-domains`, `X-chkp-sid` session enforcement, and fast state reset controls so downstream applications can run full read and write workflows against `localhost:<port>`.

#### Scenario: Downstream application connects over HTTPS to localhost and syncs multi-domain dataset

- **WHEN** `CheckPointReplayHttpServer` is started on `localhost:<port>` (e.g., `localhost:443` or an ephemeral test port) and a client connects via real `AMgmtClient` / `ApiTransport`
- **THEN** `/web_api/login` SHALL issue domain-bound session tokens (`X-chkp-sid`), `/web_api/show-domains` SHALL rewrite active CMA/MDS server `ipv4-address` fields to the server's bound host, and subsequent `/web_api/{cmd}` requests (`show-gateways-and-servers`, `show-hosts`, `show-groups`, `show-packages`, `show-access-rulebase`, `run-script`, `show-task`, etc.) SHALL return the corresponding domain's paginated raw dataset without artificial rate limiting or login delays

#### Scenario: Downstream application executes stateful write workflows and resets state via CheckPointReplayHttpServer

- **WHEN** an HTTPS client authenticates via `/web_api/login`, executes mutating `/web_api/{cmd}` calls, polls `/web_api/show-task` for asynchronous commands (`publish`, `show-changes`, `verify-policy`, `install-policy`, `assign-global-assignment`, `assign-global-policy`, `run-script`), and subsequently resets server state between test scenarios
- **THEN** `/web_api/{cmd}` SHALL enforce HTTP `401` (`generic_err_missing_required_header` or `generic_err_invalid_session_id`) on missing or invalidated `X-chkp-sid` headers, reflect committed changes immediately across subsequent HTTPS requests, and restore clean state via `snapshot_state()`, `restore_state()`, `reset()`, or opt-in `/__testing__/*` endpoints

### Requirement: Per-Session Staging Overlay and Read-Your-Own-Writes Isolation

`FileReplayApiMock` and `CheckPointReplayHttpServer` MUST isolate uncommitted write operations inside a copy-on-write per-`sid` staging overlay (`login`, `create_dedicated_session`, `/web_api/login`) until `publish`, while enforcing Check Point `"read-only": true` restrictions and cross-session object locks.

#### Scenario: Uncommitted mutations are visible to the mutating SID and isolated from other sessions

- **WHEN** Session A (`sid_a`) creates, modifies, or deletes objects, groups, or rules without calling `publish`, and both Session A and Session B (`sid_b`, a read-only session, or `sid=None`) read from the same domain
- **THEN** reads using `sid_a` SHALL reflect all uncommitted mutations in Session A's staging overlay, while reads using `sid_b`, a `"read-only": true` session, or `sid=None` SHALL observe only the last published domain state

#### Scenario: Read-only sessions and object locks reject conflicting write commands

- **WHEN** a client sends a mutating command using a `"read-only": true` session SID, OR Session B attempts to modify or delete an existing object or rule UID currently modified or deleted by open uncommitted Session A
- **THEN** the emulator SHALL reject the read-only write with HTTP `400` (`err_validation_failed`) and reject the conflicting edit with HTTP `400` (`generic_err_object_locked`)

### Requirement: Session Lifecycle, Adoption, Discard, and Change History Emulation

The emulator SHALL support `login`, `logout` / `logout_sid`, `set-session`, `take-over-session`, `switch-session`, `publish`, `discard`, `show-session`, `show-sessions`, `show-last-published-session`, and `show-changes` with atomic publish commits, post-publish work-session rotation, rollback on discard or logout without publish, and structured change deltas.

#### Scenario: Publish commits overlay atomically, rotates active work session, and records change history

- **WHEN** a write session calls `publish` (`{}` or `{"uid": <session_uid>}`)
- **THEN** the emulator SHALL atomically apply the session's overlay into published domain state, update `show-last-published-session` and prepend the published revision (including `published-changes` and `number-of-published-changes`) to `show-sessions`, record structured deltas for `show-changes`, return a completed `tasks` response when `wait_for_task=True` or a pollable `task-id` when `wait_for_task=False`, and bind `sid` to a fresh `"open"` work session (`changes=0`, `locks=0`, `number-of-published-changes=0`, no `publish-time`)

#### Scenario: Discard, logout without publish, set-session, take-over-session, and switch-session manage uncommitted state

- **WHEN** a client updates session metadata via `set-session`, adopts or switches an open session via `take-over-session` (`uid`, optional `disconnect-active-session`) or `switch-session` (`uid`), or invokes `discard` (`{}` or `{"uid": <target_session_uid>}`) or `logout` / `logout_sid` before `publish`
- **THEN** `set-session` SHALL persist session `name` and `description` in `show-session`, session adoption SHALL transfer the staging overlay and invalidate disconnected active SIDs with HTTP `401` (`generic_err_invalid_session_id`), and `discard` or `logout` SHALL roll back all uncommitted overlay changes and release session object locks

#### Scenario: Querying show-changes returns structured deltas for staged and published sessions

- **WHEN** a client invokes `show-changes` targeting a published session (`to-session`, optional `from-session`, `from-date`, `to-date`) or an uncommitted staged session
- **THEN** the emulator SHALL return Check Point `changes[].operations` buckets (`added-objects`, `modified-objects`, `deleted-objects`, `added-rules`, `modified-rules`, `deleted-rules`) with `old-object`, `new-object`, `field-changes`, `layer`, `package`, `rule-number`, and `old-rule-number` metadata, wrapped as a completed task when `wait_for_task=True` or a `task-id` for `show-task` when `wait_for_task=False`

### Requirement: Stateful Object, Service, and Group CRUD Operations

The emulator SHALL support `add-*`, `set-*`, `delete-*`, and singular `show-*` commands for `host`, `network`, `address-range`, `dns-domain`, `application-site`, `group`, `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, `service-other`, and `service-group`, plus `show-unused-objects` and `delete-unused-objects`.

#### Scenario: CRUD lifecycle for network objects, services, and groups

- **WHEN** a write session creates, renames (`new-name`), updates (`set-*` including `members` full replacement or `{"add": ..., "remove": ...}`, `groups` updates, and `set-if-exists`), and deletes supported network objects, services, or groups
- **THEN** the emulator SHALL enforce Check Point uniqueness validation (`ignore-warnings` awareness for duplicate values, error on duplicate names), maintain bidirectional group membership consistency across staged reads, and return Check Point `generic_err_object_not_found` for unknown UIDs or names

#### Scenario: Unused object discovery and cleanup via show-unused-objects and delete-unused-objects

- **WHEN** a client calls `show-unused-objects` or a write session calls `delete-unused-objects` (with optional object or group filters)
- **THEN** `show-unused-objects` SHALL return domain objects with zero references in groups, Access rules, NAT rules, or gateway interfaces, and `delete-unused-objects` SHALL remove only unreferenced local objects into the active staging overlay while leaving referenced or `Global` objects untouched

### Requirement: Referential Integrity Enforcement on Object and Service Deletion

The emulator MUST reject `delete-*` on any object, service, or group that is still referenced within the effective domain by any group, Access rule (enabled or disabled), NAT rule, or gateway interface topology.

#### Scenario: Deleting a referenced object, service, or group fails with Check Point validation error

- **WHEN** a write session calls `delete-host`, `delete-network`, `delete-address-range`, `delete-dns-domain`, `delete-application-site`, `delete-group`, or `delete-service-*` for an entity still referenced by a group, Access rule, NAT rule, or gateway topology
- **THEN** the emulator SHALL reject the deletion with HTTP `400` and Check Point error code `generic_err_object_cannot_be_deleted` (including `blocking-errors` identifying the referencing entities, compatible with `err_validation_failed` checks) and leave the target entity intact

#### Scenario: Deleting an object succeeds after removing all group and rule references

- **WHEN** a Decommission workflow first removes the target object from referencing groups (`set-group` with `members.remove`), removes it from multi-member rule cells or disables/deletes sole-member rules (`set-*-rule` / `delete-*-rule`), and then invokes `delete-*`
- **THEN** `delete-*` SHALL succeed because zero staged references remain in the session overlay

### Requirement: Access and NAT Rulebase CRUD, Positioning, and Automatic Consistency

The emulator SHALL support `show-access-rule`, `add-access-rule`, `set-access-rule`, `delete-access-rule`, `add-access-section`, `set-access-section`, `delete-access-section`, `show-access-layer`, `add-access-layer`, `set-access-layer`, `delete-access-layer` (including inline layers), `show-https-rulebase`, `show-threat-rulebase`, `https-rule` / `threat-rule` CRUD, `show-nat-rule`, `add-nat-rule`, `set-nat-rule`, `delete-nat-rule`, `add-nat-section`, `set-nat-section`, `delete-nat-section`, and `verify-policy` / `install-policy` task simulation, automatically recomputing rule numbers, section ranges, live `objects-dictionary`, `show-objects`, `show-object`, and `where-used`.

#### Scenario: Access rule and section CRUD maintains rule-numbers, section bounds, and objects-dictionary

- **WHEN** a write session adds, edits, reorders (`position` / `new-position` with `"top"`, `"bottom"`, 1-based integer `rule-number`, `{"top": section}`, `{"bottom": section}`, `{"above": ref}`, `{"below": ref}`), enables/disables, or deletes Access rules or sections, or mutates rule cells via full replacement or `{"add": ..., "remove": ...}`
- **THEN** the emulator SHALL strip `"Any"` (`97aeb369-9aea-11d5-bd16-0090272ccb30`) when concrete members are added, revert emptied cells to `"Any"`, recompute sequential 1-based `rule-number` values and section `from`/`to` bounds (plus layer `total`), and return live `objects-dictionary` entries (or inline dicts for `use-object-dictionary=False`) on subsequent `show-access-rule` and `show-access-rulebase` reads

#### Scenario: NAT rule CRUD normalizes Original and Any sentinels and updates NAT rule numbers

- **WHEN** a write session creates, updates, repositions, or deletes NAT rules or sections in a package using `"Original"`, `"Any"`, sentinel UIDs (`85c0f50f-6d8a-4528-88ab-5fb11d8fe16c`, `97aeb369-9aea-11d5-bd16-0090272ccb30`), object names, or object UIDs
- **THEN** the emulator SHALL normalize and store sentinel/object UIDs cleanly, recompute sequential NAT `rule-number` values, section `from`/`to` bounds, and package `objects-dictionary`, and serve updated rules via `show-nat-rule` and `show-nat-rulebase`

#### Scenario: Post-mutation reads stay consistent across where-used, show-objects, show-object, and inline rulebases

- **WHEN** any group membership or Access/NAT rule cell is mutated in a session overlay or published into domain state
- **THEN** subsequent calls to `where-used` (direct and indirect), `show-objects`, `show-object`, singular `show-*`, and `show-*-rulebase` (`use-object-dictionary=True | False`) with visibility into that state SHALL immediately reflect added, renamed, re-bound, or removed references

### Requirement: MDSM Global Domain Visibility, Write Protection, and Policy Assignment

In MDSM mode, `Global` domain entities SHALL be readable from local domain sessions and visible in rule references, whereas attempts to modify or delete `Global` objects or rules from a local domain session MUST fail with a realistic Check Point read-only / domain-ownership error, and `assign-global-assignment` / `assign-global-policy` SHALL be supported.

#### Scenario: Local domain queries resolve Global objects while bulk domain syncs remain domain-scoped

- **WHEN** a client queries `show-object`, `show-objects`, singular `show-*`, `where-used`, or `show-*-rulebase` in a local domain (such as `Branch` or `Perimeter`) that references `Global` objects, services, or groups
- **THEN** those lookups and `objects-dictionary` entries SHALL resolve the `Global` entities tagged with `"domain": {"uid": "uid-dom-global", "name": "Global", "domain-type": "global domain"}`, while bulk per-domain sync endpoints (`show-hosts`, `show-networks`, `show-groups`, `show-services-*`) remain scoped to the queried domain

#### Scenario: Local domain sessions cannot modify or delete Global objects or Global rules

- **WHEN** a write session opened on a local domain invokes `set-*` or `delete-*` targeting a `Global`-owned object, service, group, or Global rule/layer (by UID or name)
- **THEN** the emulator SHALL reject the mutation with HTTP `400` (`generic_err_object_read_only` / `err_validation_failed`) without altering `Global` state, whereas a write session opened directly on the `Global` domain MAY mutate unreferenced `Global` objects (while still enforcing cross-domain referential integrity on deletion)

#### Scenario: Global policy assignment emulates Check Point task execution and assignment metadata

- **WHEN** a client executes `assign-global-assignment` (or `assign-global-policy`) and `show-global-assignment` / `show-global-assignments`
- **THEN** the emulator SHALL update global assignment metadata for the specified `global-domains` and `dependent-domains` and return a Check Point task response (`{"tasks": [...]}` for `wait_for_task=True` or pollable `{"task-id": ...}` / `{"tasks": [{"task-id": ...}]}` for `wait_for_task=False`)

### Requirement: Fast In-Memory State Snapshot, Restore, and Reset

`FileReplayApiMock` and `CheckPointReplayHttpServer` SHALL provide fast in-memory state snapshot, restore, and reset primitives so test suites roll back all domain mutations, active sessions, tasks, and attached CLI overrides between scenarios without re-reading or regenerating disk fixtures.

#### Scenario: Snapshot, restore, and reset roll back emulator and CLI state in milliseconds

- **WHEN** a test captures `snap = api_mock.snapshot_state()` (or via `CheckPointReplayHttpServer` method or `/__testing__/snapshot`), mutates or publishes domain state, modifies attached `FileReplayCliMock` overrides, and calls `api_mock.restore_state(snap)` or `reset()` (or `/__testing__/restore` / `/__testing__/reset`)
- **THEN** all published domain data, MDSM assignments, session bindings, work sessions, `show-changes` history, dynamic tasks, and attached CLI overrides SHALL revert cleanly in memory without disk I/O or dataset regeneration

### Requirement: SID-Redacted Call Auditing and OpenTelemetry Span Hygiene

The emulator SHALL record SID-redacted call audit entries (`call_log`), expose test assertion helpers, and emit provider-agnostic OpenTelemetry spans (`arodonata.core.telemetry`) without owning a global `TracerProvider` or leaking credentials or raw session IDs.

#### Scenario: Enriched call_log and assertion helpers verify domain safety and query efficiency

- **WHEN** tests run E2E workflows against `FileReplayApiMock` or `CheckPointReplayHttpServer` and inspect `call_log`, `get_calls(...)`, or invoke `assert_no_global_mutations()`, `assert_no_full_object_scans()`, `assert_command_called(...)`, or `assert_command_not_called(...)`
- **THEN** every `call_log` entry SHALL contain `mgmt_name`, `domain`, `command`, `is_mutating`, a deterministic non-secret `sid_ref` (`"sid#..."`), `session_uid`, `read_only_session`, sanitized `payload`, `payload_summary`, `status_code`, `success`, and `error_code` with zero raw `sid`, `api-key`, or `password` values, and assertion helpers SHALL raise descriptive failures if unexpected `Global` mutations or unpaginated bulk `show-hosts` / `show-networks` scans occur

#### Scenario: OpenTelemetry spans propagate over FileReplayApiMock and CheckPointReplayHttpServer without SID leakage

- **WHEN** an external host test configures `InMemorySpanExporter` on its own `TracerProvider` and runs `ArodonataClient` E2E write/publish/diff workflows over both `FileReplayApiMock` and `CheckPointReplayHttpServer`
- **THEN** Arodonata and replay spans SHALL record expected span names, `arodonata.*` attributes, and success/error statuses without initializing any global `TracerProvider` and with zero occurrences of raw `sid`, `X-chkp-sid`, `api-key`, or `password` strings across all span names, attributes, events, and status descriptions


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

The `arodonata[mcp]` server SHALL expose a structured query and schema-introspection tool (`query_objects` supporting `aggregate="list" | "count" | "describe"`) for cross-domain filtering, grouping, and counting over `arodonata_objects`, `arodonata_services`, and `arodonata_assets` without raw SQL, along with a unified `cache_control` tool (`action="status" | "refresh"`) reporting freshness per domain and scope from `domain_sync_state` or triggering scoped synchronization. It SHALL normalize `group_by` field aliases (`domain` -> `domain_name`, `mgmt` / `server` / `management` -> `mgmt_name`, `object_type` / `asset_type` / `service_type` -> `type`, `orig_domain` -> `original_domain`) and expand asset type aliases (`gateway`, `cluster`, `member`, `vsx`, `vs`, `server`) to include Check Point `Cpmi*` classes (`CpmiGatewayPlain`, `CpmiGatewayCluster`, `CpmiClusterMember`, `CpmiVsxClusterMember`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`, `CpmiHostCkp`) with case-insensitive matching.

#### Scenario: Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` is called (or with `group_by=["domain", "type"]` and asset aliases such as `types=["cluster", "vsx", "vs"]`)
- **THEN** the tool SHALL execute a parameterized query over the cached tables (distinguishing domain-owned vs Global objects via `original_domain`), resolve `group_by` aliases and `Cpmi*` asset classes case-insensitively, and return the grouped counts in a single response (populating both requested alias keys and canonical keys when an alias is used)

#### Scenario: Progressive-disclosure schema description via query_objects

- **WHEN** `query_objects(mgmt_name=..., domain=..., aggregate="describe")` is called (defaulting to `cache_mode="smart"`)
- **THEN** if the object cache for the target scope has not been synchronized (`0` `scope="objects"` sync states, even if partial on-demand topology objects exist), it SHALL warm `arodonata_objects` first when `cache_mode != "cache"`, and return available domains, management servers, per-type object/service/asset counts, and the list of filterable and groupable fields from the cached tables

#### Scenario: Cache status inspection across scopes

- **WHEN** `cache_control(mgmt_name=..., action="status")` or `cache_control(mgmt_name=..., domain=..., action="refresh", scope="objects")` is called
- **THEN** `action="status"` SHALL return per-domain and per-`item_type` sync status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`, and `action="refresh"` SHALL synchronize the requested scope (`"domains"`, `"objects"`, `"services"`, `"assets"`, or `"rulebase"`) and return the `RefreshOutcome`

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose a consolidated cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `change_report`, `api_call`, and opt-in CPCRUD tools), pre-validating explicit `domain` names against `arodonata_domains` and normalizing short and canonical object/service/asset types (including case-insensitive `Cpmi*` equivalence expansion across `list_assets`, `search_objects`, and `query_objects`).

#### Scenario: List and search tool response envelope includes source, accurate cache age, and cold-cache auto-upgrade

- **WHEN** a collection listing or search tool (`list_domains`, `list_objects`, `list_services`, `list_assets`, `search_objects`, or `query_objects`) executes
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds` (`null` when no `synced_at` timestamp exists in `arodonata_domain_sync_state` rather than `0.0`), and `objects` sliced by `limit` and `offset`; when `cache_mode="cache"` is passed on an uninitialized scope (`0` sync states for that scope, or `0` cached domain rows for `domains`), the tool SHALL automatically upgrade to `"smart"` so cold caches are populated on first query; and when `mgmt_name` is omitted in `search_objects`, the search SHALL span all configured `mgmt_names` rather than only `mgmt_names[0]`

#### Scenario: Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0)` is called
- **THEN** it SHALL search `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` (using `cache_mode="cache"` and including `"Global"` whenever `domain` is omitted):
  - if `uid_or_name` contains no `*` or `?` and matches in exactly one domain, it SHALL return that single entity with `match_type="exact"` and full details;
  - if `domain` is omitted and `uid_or_name` matches exact entities in more than one domain, it SHALL return `match_type="ambiguous"` with `object=None` and `objects` listing the matching candidates across domains so the caller can disambiguate;
  - if `uid_or_name` contains an explicit wildcard (`*` or `?`), it SHALL evaluate `fnmatchcase` strictly (`match_type="wildcard"`), returning the full object when `total == 1` or a paginated candidate slice when `total > 1`;
  - if `uid_or_name` contains no wildcard and has no exact match in cache, it SHALL return up to `limit` compact case-insensitive substring candidates (`match_type="substring_candidates"`)

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

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was issued/signed by `cpcrud_plan`, omit `force`, `validate_schema`, and `server_ip` from MCP CPCRUD tools, cap `retry_remaining` (`<= 3`), and restrict `cpcrud_staged_session(session_uid, action="publish" | "discard", ...)` exclusively to session UIDs staged by `cpcrud_apply(keep_session=True)` in this server process.

#### Scenario: Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` is called with an unknown `plan_id` or a `plan` payload that was not issued/signed by this server's `cpcrud_plan` tool (or whose `command` / `object_type` / `payload` was altered)
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: Staged CPCRUD session published or discarded via dedicated MCP tools

- **WHEN** `cpcrud_apply(..., no_publish=True, keep_session=True)` stages changes in a dedicated session (recording `(mgmt_name, domain_key, session_uid)` in the server's staged-session registry) and the caller subsequently invokes `cpcrud_staged_session(session_uid=..., action="publish" | "discard", mgmt_name=..., domain=...)`
- **THEN** the tool SHALL verify `session_uid` is registered in this MCP server's staged-session store, adopt the session non-disruptively without exposing `server_ip` or `force_disconnect`, publish (invalidating the domain cache) or discard uncommitted changes, remove the completed entry from the staged store, and log out cleanly

#### Scenario: Unregistered or foreign session UID rejected by cpcrud_staged_session

- **WHEN** `cpcrud_staged_session` is called with a `session_uid` that was not created by `cpcrud_apply(..., no_publish=True, keep_session=True)` in this MCP server instance (for example, a SmartConsole administrator's session UID discovered via `show-sessions`)
- **THEN** `cpcrud_staged_session` SHALL raise `ToolFailure` immediately without opening a Check Point session or calling `take-over-session`, `switch-session`, `publish`, or `discard`

### Requirement: Cache-Only Cross-Domain Group Lookup and Ambiguity Reporting in MCP

When `get_group_members` is called without `domain` (and `group_name_or_uid` is not a `mgmt:domain:name` composite ID), the MCP server SHALL resolve the target group across cached domains including `"Global"` using `cache_mode="cache"` without triggering whole-MDS logins, and SHALL return a structured `match_type="ambiguous"` candidate response when matching groups exist in more than one domain.

#### Scenario: Cross-domain MCP get_group_members reports ambiguity without whole-MDS sync

- **WHEN** `get_group_members(group_name_or_uid="SharedAdmins")` is invoked without `domain` and `"SharedAdmins"` exists in multiple cached domains
- **THEN** the tool SHALL perform zero remote domain refreshes and return `match_type="ambiguous"` with the candidate domain/composite-ID list so the caller can re-query with an explicit `domain` or `mgmt:domain:name`

### Requirement: Unified Progressive-Disclosure MCP API Reference Tool

The `arodonata[mcp]` server SHALL expose a single consolidated `api_reference` tool supporting `action="search" | "describe" | "validate"` (with automatic `version` inference from `mgmt_name` when `version` is omitted), enabling MCP clients and agents to search Check Point commands (`action="search"`), inspect version-filtered command parameters, nested objects, and examples (`action="describe"`), and validate candidate request payloads offline before calling `api_call` (`action="validate"`).

#### Scenario: Two-step MCP discovery and payload validation via api_reference tool

- **WHEN** an MCP client calls `api_reference(action="search", query="host", crud_type="add")`, then `api_reference(action="describe", command="add-host", version="v2.2")`, and finally `api_reference(action="validate", command="add-host", payload={"name": "web-01", "ip-address": "192.0.2.10"})`
- **THEN** `action="search"` SHALL return compact matching command summaries, `action="describe"` SHALL return the full `v2.2` field schema, `field_alternatives`, `nested_objects`, and canonical example for `add-host`, and `action="validate"` SHALL return `valid=True` with `errors=[]`

### Requirement: MCP Gateway Topology Control and Affected Gateway Discovery Tool

The `arodonata[mcp]` server SHALL support `scope="topology"` (with optional `gateways` and `collect_routes` parameters) in `cache_control(action="status" | "refresh", ...)` and expose `locate_gateways(sources, destinations, mgmt_name=..., domain=..., min_confidence=..., include_standby=..., include_policy_inferred=..., cache_mode="smart")` returning affected Check Point gateways, domains, policy packages, matched interfaces, delta-based `confidence` scores, `confidence_factors`, `is_standby_path` flags, and `topology_warnings`.

#### Scenario: MCP client locates candidate gateways and policy packages for a traffic flow

- **WHEN** an MCP client invokes `locate_gateways(sources=["10.10.1.5"], destinations=["172.16.20.10"], mgmt_name="mds1", include_policy_inferred=True)`
- **THEN** the tool SHALL return a structured JSON envelope listing the affected gateways (both cross-interface L3 matches and `policy_inferred` one-arm or incomplete-topology matches when enabled), along with each gateway's `domain_name`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, `confidence_factors`, per-flow `(src_interface -> dst_interface)` match details, `include_policy_inferred`, and any domain `topology_warnings`


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

### Requirement: Lightweight Policy Package Catalog Synchronization

The rulebase service SHALL synchronize and return policy package metadata (`get_policy_packages`, `refresh_policy_packages`) using a package-only synchronization slice (`scope="rulebase"`, `item_type="packages"`) when the full domain rulebase snapshot (`item_type="*"`) is not yet fresh, querying `show-packages` without downloading NAT, HTTPS, threat-prevention, or access rulebases.

#### Scenario: Cold-cache get_policy_packages queries show-packages without fetching rulebases

- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs on a domain whose `scope="rulebase"` cache has neither a fresh `"*"` snapshot nor a fresh `"packages"` slice
- **THEN** the system SHALL verify the shared session is clean under the domain lock, fetch `show-packages`, atomically replace the domain's package-catalog metadata and update `item_type="packages"` sync state without marking `item_type="*"` as synced, and perform zero `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase` calls

#### Scenario: Fresh full rulebase snapshot satisfies get_policy_packages from cache

- **WHEN** `get_policy_packages(mgmt_name, domain_name, cache_mode="smart")` runs on a domain whose full `scope="rulebase"`, `item_type="*"` snapshot already matches the domain's published session head
- **THEN** the system SHALL return the cached `PolicyPackageInfo` list without issuing `show-packages` again

### Requirement: Targeted Single-Package Rulebase Synchronization

When `get_package_rulebase` (or `refresh_package_rulebase`) runs with `cache_mode != "cache"` on a domain lacking a fresh full `item_type="*"` snapshot, the system SHALL synchronize only the target package's catalog entry and the layers reachable for the requested `(package, rulebase_type)` slice (`item_type="package:<rulebase_type>:<package_uid>"`), skipping unrelated packages, standalone unused layers, and other rulebase types.

#### Scenario: Cold-cache access rulebase read for one package skips NAT, HTTPS, Threat, and sibling packages

- **WHEN** `get_package_rulebase(mgmt_name, domain_name, package="Branch_Pkg", rulebase_type="access", cache_mode="smart")` runs in a domain containing multiple policy packages, NAT policies, HTTPS layers, threat layers, and standalone layers
- **THEN** the system SHALL fetch only package metadata, the ordered access layers of `"Branch_Pkg"`, any Global placeholder access expansion in `"Branch_Pkg"` context, and any inline access sub-layers referenced by rules in `"Branch_Pkg"`, persist those layers and record `item_type="package:access:<package_uid>"` without stamping `item_type="*"`, and return SmartConsole-numbered sections and rules identical to a full domain snapshot

#### Scenario: Locate rules still requires or triggers full domain rulebase snapshot

- **WHEN** `locate_rules(mgmt_name, domain_name, ...)` or `refresh_rulebases(...)` runs after a targeted single-package sync populated `item_type="package:access:<package_uid>"`
- **THEN** the system SHALL treat `item_type="*"` as unsynced until a full domain rulebase snapshot completes, ensuring cross-package rule location never omits unsynced sibling packages


---

### OpenSpec Capability: `sessions-and-mdm` (`openspec/specs/sessions-and-mdm/spec.md`)

# Sessions, Multi-Domain Resolution, and Concurrency Specification

## Purpose

Defines the lifecycle of Check Point API sessions (`LoginCoordinator`, `SessionCleaner`, `SIDCache`), hybrid and dynamic authentication with `contextvars`-bound `WriteSession` overlays (`SessionOverlay`), per-MDS-member login gating and request concurrency limiting (`LoginGate`, `RateLimiter`), and Multi-Domain Security Management (MDSM) domain/server resolution (`DomainService`, `DomainListRefreshTracker`).

## Requirements

### Requirement: Persistent SID Caching and Auto-Recovery

The system SHALL authenticate shared `arodonata_sid_cache` sessions with `"read-only": true`, key rows by `f"{mgmt_name}:{domain_key}:{auth_identity}"` (excluding `SIDCacheEntry.sid` from model dumps and defaulting `SIDCacheEntry.id` to include `auth_identity`), evict only the affected `auth_identity` row on expiry, failover, keepalive failure, or logout failure, and refuse mutating commands on `arodonata_sid_cache`.

#### Scenario: Reuse of unexpired cached session scoped by authentication identity

- **WHEN** a read-only API call targets `(mgmt_name, domain)` under resolved credentials (`auth_identity`)
- **THEN** `LoginCoordinator` SHALL authenticate new `arodonata_sid_cache` sessions with `"read-only": true`, reuse an unexpired row matching exact `f"{mgmt_name}:{domain_key}:{auth_identity}"`, omit raw `sid` from `SIDCacheEntry.model_dump()` / `model_dump_json()`, and NEVER match or overwrite another principal's cached SID

#### Scenario: Transparent re-login on session expiration error

- **WHEN** a read-only API call using a cached SID encounters session expiration or CMA failover, a background `keepalive` returns `success=False`, or `logout_all` evicts an unloggable cached SID
- **THEN** the client SHALL evict ONLY that specific `(mgmt_name, domain_key, auth_identity)` row from `arodonata_sid_cache` (leaving other administrators' cached SIDs for the same domain intact) and, for active read-only API calls, acquire a fresh session via `LoginCoordinator` and retry once

#### Scenario: Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called for isolated write workflows
- **THEN** `LoginCoordinator` SHALL authenticate a fresh read-write session (`"read-only"` omitted/`False`) with retry/backoff resilience, return `(sid, server_ip)` without storing the SID in `arodonata_sid_cache`, keep the SID registered in `_active_dedicated_sids` until `logout_sid()` succeeds, and shield `discard`/`logout_sid()` against `asyncio.CancelledError` (`BaseException`)

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

The system SHALL serialize and rate-limit logins per hosting MDS member (`active_mds_ip`, falling back to configured server IP) via `LoginGate`, enforcing a minimum inter-login spacing and shared throttle cooldown inside the gate, logging a `WARNING` when entering a login throttle cooldown, bounding local `asyncio.Lock` acquisition by `wait_timeout`, and executing CMA failover IP refreshes (`refresh_domain_active_ip`) and retry backoff sleeps outside the gate so recursive system-domain logins on the same MDS IP never deadlock.

#### Scenario: Throttled login waits out Check Point throttle window

- **WHEN** a login attempt is rejected due to Check Point login throttling or times out during the read phase
- **THEN** `LoginGate` SHALL record the per-MDS cooldown window (`login_throttle_window`, default 70s, or exponential read-timeout backoff) and log a `WARNING` message with the server IP and cooldown duration so subsequent queued callers respect the cooldown before sending another `login`, and `LoginCoordinator` SHALL release the gate before sleeping and retrying within `login_max_wait` (default 900s)

#### Scenario: Cold-cache CMA failover during login does not deadlock LoginGate

- **WHEN** a login to a customer domain on `mds_ip` encounters a transport or failover error and triggers `refresh_domain_active_ip()` while the system domain SID is not yet cached (requiring a system domain login to the same `mds_ip`)
- **THEN** `LoginCoordinator` SHALL release the `LoginGate` for `mds_ip` before invoking `refresh_domain_active_ip()` so the nested system-domain login acquires `LoginGate(mds_ip)` cleanly without self-deadlock

#### Scenario: Credential rejection or locked account fails fast with InvalidCredentialsError

- **WHEN** the Check Point server rejects login credentials (`Authentication to server failed` or `Administrator account is locked`) rather than reporting a transient revision/lock condition (`Database revision is in progress`)
- **THEN** `LoginCoordinator` SHALL raise `InvalidCredentialsError` (a subclass of `AuthenticationError`) without exhausting transient retry loops

### Requirement: Per-MDS-Member Concurrency Semaphore

The `RateLimiter` SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using database-backed slot locks (with TTL `>= max(api_timeout, login_timeout) + 60s`) and FIFO in-process waiter queues, suppressing database `Exception` errors during shielded DB lock release while always releasing the local FIFO slot and propagating `asyncio.CancelledError`.

#### Scenario: Fair waiter wakeup on slot release

- **WHEN** all `concurrent_limit` slots for an MDS member are occupied, multiple coroutines are waiting, and the active slot holder exits (including when DB lock release raises an `Exception` or the task receives `asyncio.CancelledError`)
- **THEN** `RateLimiter` SHALL shield DB lock cleanup (`suppress(Exception)`), ALWAYS release the local FIFO slot in `finally` to wake the longest-waiting coroutine in arrival order, and re-raise `asyncio.CancelledError` if cancellation occurred rather than swallowing it

#### Scenario: Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity (including when one awaiting caller is cancelled)
- **THEN** overlapping keepalive sweeps SHALL be coalesced and protected via `asyncio.shield` so at most one sweep runs at a time without starving active caller slots or aborting sibling waiters

### Requirement: Stale Session Cleanup and Startup Session Seed

`SessionCleaner` SHALL clean up stale or abandoned Arodonata-owned API sessions on configured management servers on startup (when static credentials are available) and upon max-sessions refusal, logging `DEBUG` entries when discarding stale Arodonata sessions, and strictly restricting `discard` to sessions created by Arodonata (`application == "arodonata"` or `arodonata` session-name prefix) that have `changes == 0` and `locks == 0`.

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

`DomainService` and `LoginCoordinator` SHALL discover and cache domains on MDS servers (`show-domains`, `show-mdss`, `show-global-domain`), log `DEBUG` messages when discovering/caching domains and resolving active domain CMA/MDS IPs, track each domain's `active_ip`, `active_mds_ip`, and standby servers, and validate any caller-supplied `explicit_server_ip` against configured endpoint hosts and discovered MDS/domain server addresses for `mgmt_name`.

#### Scenario: Opt-in Global domain visibility

- **WHEN** `get_domains(include_global=False)` (the default) is called
- **THEN** the `Global` domain row SHALL be excluded from the returned list; when `include_global=True`, the `Global` domain row SHALL be included

#### Scenario: Periodic domain list refresh via DomainListRefreshTracker

- **WHEN** `get_domains` or smart cache refresh runs
- **THEN** the domain list (`show-domains`) SHALL be re-fetched from the management server when the `domains` table is empty, when the 1-hour domain-list TTL has elapsed, or when `mode="force"` is requested, retrying with `details-level="standard"` if `details-level="full"` is rejected by Check Point RBAC (preserving any previously cached `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`), logging `DEBUG` messages at discovery start and after caching the discovered domain records, and logging a `WARNING` with the server error code and message if discovery fails

#### Scenario: Cold-cache CMA IP resolution and active domain server failover re-resolution

- **WHEN** a customer or `Global` domain login runs before `domains` is cached (cold cache) or when a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** `LoginCoordinator` SHALL query the MDS system domain (`show-domains`, `show-mdss`, and `show-global-domain`) to resolve and cache the domain's `active_ip` (CMA IP) and `active_mds_ip` in the `domains` table and log a `DEBUG` entry before authenticating against the domain

#### Scenario: Untrusted explicit_server_ip rejected before connection or SID transmission

- **WHEN** `resolve_target_ips` (via `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid`) receives an `explicit_server_ip` that does not match `mgmt_name`'s configured endpoint host or any cached domain `active_ip`, `active_mds_ip`, or `standby_ips` / MDS member IP for `mgmt_name`
- **THEN** `LoginCoordinator` SHALL reject the target with `ValidationError` before opening a TLS connection, learning a TOFU certificate, or transmitting `X-chkp-sid`


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

`ApiTransport` SHALL pool fingerprint-verified keep-alive HTTPS connections (`VerifiedConnectionPool`) for up to 10 seconds idle and fewer than 95 requests per socket across read-only `show-*` commands and non-boundary dedicated-session commands (`session_scope`), closing idle sockets before non-pooled commands and never exposing raw SIDs in pool keys or `repr()`.

#### Scenario: Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and the pooled socket remains open below 95 requests
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: Mutating commands and idle connections bypass reuse

- **WHEN** a session-boundary command (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`), an un-scoped non-`show-*` command, or a command after a >10s idle gap executes
- **THEN** `ApiTransport` SHALL close matching idle pooled sockets before initiating a new handshake, evict closed protocol tracking entries, send `Connection: close`, and open a fresh TLS-verified connection

#### Scenario: Sequential commands within a dedicated session reuse session-scoped keep-alive connection

- **WHEN** non-boundary commands (such as `show-session`, `add-*`, `set-*`, `delete-*`, or `show-task`) run with a dedicated `session_scope` on the same `(server_ip, port)` within 10 seconds and fewer than 95 requests
- **THEN** they SHALL reuse the pooled verified connection isolated to that `session_scope` (without setting `Connection: close`), while concurrent shared read-only calls or distinct `session_scope` values remain isolated

#### Scenario: Pooled socket rotates cleanly before server max-keepalive request limit

- **WHEN** a pooled socket reaches 95 HTTP requests in `FingerprintTCPConnector` or reports `should_close`
- **THEN** the transport SHALL close that socket on release instead of re-pooling it, so the next request opens a fresh TLS-verified connection before hitting the server's 100-request keep-alive limit

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
