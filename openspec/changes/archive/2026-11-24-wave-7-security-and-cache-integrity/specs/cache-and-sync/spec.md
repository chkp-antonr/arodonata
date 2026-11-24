# Spec Delta

## MODIFIED Requirements

### Requirement: Schema Hash Auto-Migration and Multi-Backend Persistence

**ID**: REQ-CACHE-001\
**Intent**: Initialize and evolve Arodonata SQL tables safely across concurrent workers sharing a host PostgreSQL or SQLite database with owner-only local cache file permissions.\
**Non-goals**: Cache synchronization policies (`REQ-CACHE-004`, `REQ-CACHE-005`) or distributed work locks (`REQ-CACHE-003`).

The SQL persistence layer SHALL support PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`), enforce `0700` parent directories and `0600` file modes on newly created local file-backed SQLite DBs, prefix Arodonata tables with `arodonata_` (`ARODONATA_TABLE_NAMES`), serialize migration (`pg_advisory_xact_lock` / `BEGIN IMMEDIATE`), and drop legacy v1 tables ONLY with a v1 fingerprint (`mdm_dmn` or `mgmt_dmn_key`).

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

### Requirement: Concurrent Multi-Domain Sync Coordination and Failure Isolation

**ID**: REQ-CACHE-004\
**Intent**: Maximize multi-domain refresh throughput per MDS without overwhelming endpoints, duplicating in-flight syncs, losing invalidations across scopes, or masking real failures.\
**Non-goals**: Type-specific object, service, asset, or rulebase refresh logic (`REQ-CACHE-005`..`REQ-CACHE-012`).

`DomainSyncCoordinator` SHALL refresh domains concurrently per MDS (`settings.domain_sync_concurrency`) via `asyncio.TaskGroup`, retain domain and wildcard (`"*"`) invalidation timestamps per `(scope, item_type)` so partial syncs never clear unsynced scopes, emit `arlogi` progress logs (`sid`-redacted), avoid false `LockAcquisitionError` failures, and skip implicit warm-up on `get_domains()`.

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
**Intent**: Synchronize network objects accurately using head-stamp comparisons and atomic incremental diffs without leaving partial state on error.\
**Non-goals**: On-demand `application-site` objects (`REQ-CACHE-006`) or service tables (`REQ-CACHE-007`).

`ObjectService` SHALL support four `CacheMode` values (`"cache"`, `"smart"`, `"smart-fast"`, `"force"`), sync `("host", "network", "address-range", "group", "dns-domain")` by default into `arodonata_objects`, hydrate `smart-fast` `show-object` calls before DB transaction entry so deletes/upserts/sync-state commit atomically, and expose `refresh_objects` / `stream_refresh_objects`.

#### Scenario: SCN-CACHE-005-1 — Smart/Check refresh reloads only stale domains atomically and handles never-published domains

- **GIVEN** domains with differing `show-last-published-session` timestamps/UIDs or never-published domains (`last_published_at=None`)
- **WHEN** `await client.refresh_objects(mode="smart")` or a read helper with `cache_mode="smart"` runs
- **THEN** the coordinator SHALL compare `show-last-published-session` (`last_published_at` and `last_session_uid`, preserving `None` for never-published domains) against `arodonata_domain_sync_state`
- **AND** it SHALL verify the shared session is clean (failing closed if `show-session` fails) and reload only missing or stale `item_type` slices and sync-state rows in one atomic transaction under a renewed domain lock
- **AND** it SHALL emit `DomainSyncStartedEvent`, `DomainSyncCompletedEvent`, `DomainSyncSkippedEvent`, and `SyncCompletedEvent` alongside `DEBUG` progress logs

#### Scenario: SCN-CACHE-005-2 — Incremental refresh applies show-changes diff or falls back safely

- **GIVEN** stale `item_type` rows with a known baseline in `arodonata_domain_sync_state`
- **WHEN** `await client.refresh_objects(mode="smart-fast")` or a read helper with `cache_mode="smart-fast"` runs
- **THEN** the service SHALL query `show-changes` (`from-session` preferred over UTC `Z`-suffixed `from-date`), hydrate all modified UIDs via `show-object` before opening the DB write transaction, and commit deletions, `ON CONFLICT` upserts, and sync state in one atomic transaction
- **AND** if changes exceed `max_incremental_changes` (default `500`) or any hydration/API error occurs before commit, ZERO partial deletions or sync-state changes SHALL persist and it SHALL fall back to an atomic type-scoped reload

### Requirement: On-Demand Application-Site Object Model and Synchronization

**ID**: REQ-CACHE-006\
**Intent**: Cache Check Point `application-site` URL lists and regex flags on demand without bloating default network-object syncs.\
**Non-goals**: Declarative CPCRUD `application-site` planning and patching (`REQ-CPCRUD-006`, `REQ-CPCRUD-007`).

`CPObject` and `ObjectService` SHALL support `application-site` objects on demand via `show-application-sites` (bulk), `show-object` (single-UID incremental), and `SearchService.find_object(..., obj_type="application-site")` (smart/force sync without redundant reload), while `HybridStateReader` queries `show-application-site`.

#### Scenario: SCN-CACHE-006-1 — CPObject hydrates application-site URL list and regex flag from Check Point dict and DB cache

- **GIVEN** a Check Point `application-site` payload containing `primary-category`, `url-list`, and `urls-defined-as-regular-expression`
- **WHEN** `CPObject.from_cp_dict()` or `CachePort` hydrates the object
- **THEN** `CPObject` SHALL expose `type == "application-site"`, `primary_category`, `url_list` as `list[str]`, and `urls_defined_as_regular_expression` as `bool | None`

#### Scenario: SCN-CACHE-006-2 — On-demand refresh and incremental update of application-site objects

- **WHEN** `refresh_objects(types=["application-site"])`, `get_objects(types=["application-site"])`, `find_object(mgmt_name, domain, name, obj_type="application-site", cache_mode="smart" | "force")`, or incremental `smart-fast` refresh runs
- **THEN** `ObjectService` SHALL use `show-application-sites` for full reload and `show-object` for single-UID incremental `smart-fast` updates
- **AND** `find_object` with explicit `obj_type="application-site"` SHALL sync that non-default type once in `smart`/`smart-fast` or `force` mode and persist `item_type="application-site"` in `arodonata_domain_sync_state`

### Requirement: Dedicated Service Cache Table and Selective Refresh

**ID**: REQ-CACHE-007\
**Intent**: Keep service synchronization modular, normalize service type aliases consistently, and commit incremental service updates atomically.\
**Non-goals**: Network object caching (`REQ-CACHE-005`) or gateway topology extraction (`REQ-CACHE-011`).

`ServiceCacheService` and `CachePort` SHALL normalize service type aliases/casing across SQL and `SessionOverlay` queries, persist rows in `arodonata_services` (`CPService`), hydrate `smart-fast` `show-object` calls before DB transaction commit per `(mgmt_name, domain_name, "services", item_type)`, and sync `("service-tcp", "service-udp", "service-icmp", "service-group")` by default plus other types on demand.

#### Scenario: SCN-CACHE-007-1 — Default service refresh loads core variable service types

- **WHEN** `await client.refresh_services(mode="smart")` runs without an explicit `types` list
- **THEN** the service SHALL synchronize `service-tcp`, `service-udp`, `service-icmp`, and `service-group` rows into `arodonata_services`
- **AND** it SHALL record each type's `last_published_at`, `last_session_uid`, and `synced_at` in `arodonata_domain_sync_state` in the same atomic transaction

#### Scenario: SCN-CACHE-007-2 — Explicit service types sync on demand without wiping other cached service types

- **GIVEN** a domain with `service-tcp` already cached in `arodonata_services`
- **WHEN** `await client.refresh_services(types=["service-other"])`, mixed-case/aliased `get_services(types=["TCP"])` / `find_object(..., obj_type="service-other")`, or `smart-fast` incremental service refresh runs
- **THEN** service type aliases/casing SHALL normalize uniformly across SQL queries and `SessionOverlay` lookups without wiping unrelated `item_type` slices
- **AND** `smart-fast` service hydration SHALL execute before DB write transaction entry so deletes, upserts, and `arodonata_domain_sync_state` commit atomically

### Requirement: Cache-First Object Search with Recursive Group Membership Resolution

**ID**: REQ-CACHE-013\
**Intent**: Search cached objects, assets, and active write overlays cleanly across IP, CIDR (`0.0.0.0/0` inclusive), range, wildcard, and exact selectors without cross-domain overlay leaks or lost `Global` group chains.\
**Non-goals**: Cross-domain ambiguity errors when looking up a single named container (`REQ-CACHE-014`).

`SearchService.search_objects()` SHALL classify terms (`0.0.0.0/0` preserving `mask-length4 == 0`), isolate `WriteSession` `SessionOverlay` entries by matching `(mgmt_name, target_domains)` and `include_global`, preserve multi-domain `Global` UID group memberships without overwriting distinct domains, and resolve recursive parent groups into `SearchResult`.

#### Scenario: SCN-CACHE-013-1 — Search resolves direct matches and containing groups with human-readable composite IDs

- **GIVEN** a `Global` UID shared across multiple domains or an active `WriteSession` overlay on `"Corp"`
- **WHEN** `await client.search_objects("10.1.10.50", domains=["Sales"], max_depth=2)` or `await client.search_objects("mds:General:hWebHost", max_depth=2)` runs
- **THEN** `search_objects` SHALL include overlays only for matching `(mgmt_name, target_domains)` / `include_global` (never leaking excluded-domain or `Global` overlays)
- **AND** `SearchResult.memberships` SHALL preserve per-domain membership chains for shared `Global` UIDs (keyed by composite or per-domain identity rather than silently overwriting earlier domains)

#### Scenario: SCN-CACHE-013-2 — Exact-match search avoids partial name matches and wider supernets

- **GIVEN** a domain containing `.example.com`, `sub.example.com`, `net_any` (`0.0.0.0` with `mask-length4 == 0`), and `10.0.0.0/8` alongside `10.192.13.0/24`
- **WHEN** `search_objects(".example.com", exact_match=True)`, `search_objects("10.192.13.0/24, 192.168.1.10", exact_match=True)`, or `CPObject.from_cp_dict()` on `mask-length4: 0` runs
- **THEN** `CPObject.from_cp_dict()` SHALL preserve `mask_length4 == 0` (`0.0.0.0/0`, never coalescing to `/32`), exact name search SHALL match `.example.com` only, and exact IP/CIDR search SHALL exclude wider containing supernets

#### Scenario: SCN-CACHE-013-3 — Mixed object and gateway type filters partition cleanly between objects and assets

- **WHEN** `await client.search_objects(query, types=["host", "network", "gateway"], cache_mode="smart")` is called
- **THEN** `ObjectService` SHALL strip asset/service types (`"gateway"`, etc.) before calling Check Point `show-*` object endpoints so `arodonata_objects` refreshes without `"Requested API type: not found"`
- **AND** `SearchService.search_objects()` SHALL refresh and match gateway/cluster/VSX assets (primary `ipv4_address` and interface IPs) from `arodonata_assets`

### Requirement: Cross-Domain Group Member Resolution with Ambiguity Detection

**ID**: REQ-CACHE-014\
**Intent**: Prevent non-deterministic group expansion, cross-domain cluster member leaks, and non-group name collisions across cached domains.\
**Non-goals**: Multi-domain search queries (`REQ-CACHE-013`) or MCP response envelope formatting (`REQ-MCP-003`).

`SearchService.get_group_members()` / `resolve_group_with_members()` SHALL reject blank inputs, enforce `cache_mode="cache"` (`include_global=True`) on multi-domain MDS when `domain` is `None`, isolate cluster members by `(mgmt_name, domain_name)`, prevent non-group `CPObject` collisions from shadowing `service-group`/cluster containers, and raise `AmbiguousObjectError` on multi-domain ties.

#### Scenario: SCN-CACHE-014-1 — Cross-domain group member lookup enforces MDS cache-only guard without whole-MDS sync

- **GIVEN** a multi-domain MDS cache where `"SharedGroup"` exists in two domains, OR two clusters named `"ClusterA"` in distinct domains with `parent_name="ClusterA"` members, OR a non-group host/network sharing a name with a `service-group` or cluster
- **WHEN** `SearchService.get_group_members(mgmt_name, None, "SharedGroup")` or `SearchService.get_group_members(mgmt_name, "Corp", "ClusterA")` runs
- **THEN** unqualified multi-domain lookup SHALL execute zero remote refreshes (`cache_mode="cache"`) and raise `AmbiguousObjectError` enumerating matching domains
- **AND** cluster member resolution SHALL filter strictly by `(mgmt_name, domain_name)` (never leaking wrong-domain members by `parent_name`), and non-group `CPObject` matches SHALL NOT shadow expandable `service-group` or cluster assets
