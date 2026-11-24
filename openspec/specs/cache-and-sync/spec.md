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
