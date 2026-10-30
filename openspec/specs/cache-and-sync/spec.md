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

`AssetRefreshService` (`refresh_assets`, `stream_refresh_assets`) and `SqlCacheAdapter` SHALL persist gateways, clusters, cluster members, VSX gateways/clusters (via encapsulated `generic-object` topology queries), and management servers in `arodonata_assets` concurrently across domains via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`) with UID primary keys (`id`) and indexed composite identifiers (`asset_id`).

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

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4, CIDR, address range, wildcard, UID, composite ID, or name), support `exact_match: bool = False`, query cached objects with active `WriteSession` `contextvars` overlays across target servers/domains, and resolve parent group memberships up to `max_depth` (default 2) into `SearchResult` with dual UID and composite group links.

#### Scenario: Search resolves direct matches and containing groups with human-readable composite IDs

- **WHEN** `await client.search_objects("10.1.10.50", max_depth=2)` or `await client.search_objects("mds:General:hWebHost", max_depth=2)` is called
- **THEN** it SHALL return a `SearchResult` containing both the matching host/network objects (reflecting any uncommitted `WriteSession` overlay in the current context) and the hierarchy of groups (`memberships`) that directly or transitively contain those objects, with each `GroupMembershipNode` populated with `id`, `object_id`, `parent_uids`, and `parent_object_ids`

#### Scenario: Exact-match name search avoids partial substring matches

- **WHEN** `await client.search_objects(".example.com", exact_match=True)` is called on a domain containing `.example.com` and `sub.example.com`
- **THEN** it SHALL return only `.example.com` (and its parent groups) without matching `sub.example.com`, while wildcard terms (`*.example.com`) continue to match via anchored `fnmatchcase`

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
