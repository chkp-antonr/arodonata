# Cache, Synchronization, and Search Specification

## Purpose

Defines the database-backed cache layer (`DatabaseManager`, `CacheRepository`, `PostgresCacheAdapter`), schema hash auto-migration (`arodonata_schema_version`), distributed locks (`DatabaseLockManager`), object and asset synchronization (`ObjectService`, `AssetRefreshService`, `CacheRefreshCoordinator`), and recursive object/group search (`SearchService`).

## Requirements

### Requirement: Schema Hash Auto-Migration and Multi-Backend Persistence

`DatabaseManager.initialize()` SHALL support both PostgreSQL (`asyncpg`) and SQLite (`aiosqlite`, with a 30s busy timeout by default) and compute a deterministic SHA-256 hash (`compute_schema_hash`) over the registered SQLModel metadata to skip redundant per-table schema migration checks when the hash is already recorded in `arodonata_schema_version`.

#### Scenario: Unchanged schema hash skips table inspection

- **WHEN** `DatabaseManager.initialize()` runs and a row with the current `schema_hash` already exists in `arodonata_schema_version`
- **THEN** the database manager SHALL skip per-table column/index migration inspection and mark the database initialized immediately

#### Scenario: Schema evolution applies missing columns and records new hash

- **WHEN** the SQLModel metadata changes (producing a new `schema_hash` not in `arodonata_schema_version`)
- **THEN** `DatabaseManager.initialize()` SHALL create any new tables, add any missing columns/indexes safely, and insert the new `schema_hash` row into `arodonata_schema_version`

### Requirement: Database-Backed Distributed Locks

`DatabaseLockManager` SHALL coordinate cross-process critical sections using the `distributed_locks` table with explicit lock expiration (`expires_at`) so crashed processes do not hold locks indefinitely.

#### Scenario: Expired lock reclamation

- **WHEN** a worker requests a `lock_key` whose existing row in `distributed_locks` has `expires_at` in the past
- **THEN** `DatabaseLockManager` SHALL atomically reclaim the expired lock for the new `owner_id`

### Requirement: Object Cache Refresh Modes and Incremental Sync

`ObjectService` and `CacheRefreshCoordinator` SHALL support four refresh modes (`skip`/`cache`, `check`/`smart`, `incremental`/`smart-fast`, and `force`) across cached object types (hosts, networks, address ranges, and groups), streaming progress as `SSEEvent` items.

#### Scenario: Smart/Check refresh reloads only stale domains atomically

- **WHEN** `refresh_objects(mode="check")` or a read helper with `cache_mode="smart"` runs
- **THEN** the service SHALL compare each domain's `show-last-published-session` UID against `last_published_sessions`, skip fresh domains, and reload stale domains using a single atomic collect-then-swap transaction (`replace_domain_objects`) per domain

#### Scenario: Incremental refresh applies show-changes diff or falls back safely

- **WHEN** `refresh_objects(mode="incremental")` or a read helper with `cache_mode="smart-fast"` detects a stale domain with a known baseline session
- **THEN** the service SHALL query `show-changes` from the stored baseline session, delete removed objects directly, re-fetch added/modified objects in full (`show-object` with `details-level="full"`), and update the baseline to the pre-diff head session; if changes exceed `max_incremental_changes` (default 500) or any anomaly/error occurs, it SHALL fall back automatically to a full atomic domain reload

#### Scenario: Refresh failure visibility and InvalidCredentialsError handling

- **WHEN** a domain's staleness probe fails with `InvalidCredentialsError` (unlike transient network blips which fail open as not-stale)
- **THEN** the probe SHALL report the domain as stale so the reload path records the domain in `RefreshOutcome.failed_domains` and emits a `domain_failed` `SSEEvent`, while keeping the domain's previously cached objects intact

#### Scenario: Parallel domain refresh per MDS member and background first-use warm-up

- **WHEN** `CacheRefreshCoordinator.ensure()` refreshes multiple domains or `get_domains()` encounters an empty object cache with `warm_object_cache_on_first_use=True`
- **THEN** domains SHALL be refreshed concurrently at up to `max(1, concurrent_limit - 1)` domains at once per MDS member (with MDS members running in parallel), and `get_domains()` SHALL return the domain list immediately while warming the object cache in a cancellable background task tracked via `object_cache_warm_up(mgmt_name)`

### Requirement: Asset and Gateway Cache with Cluster and VSX Relationships

`AssetRefreshService` (`build_refresh_assets_cache`, `refresh_domain_assets`) SHALL collect gateways, clusters, cluster members, VSX gateways/clusters, and management servers across domains concurrently (`asset_refresh_concurrency`, default 4) and enrich parent-child relationships via `ClusterRelationshipManager` and `VSXRelationshipManager`.

#### Scenario: Concurrent domain asset collection with interleaved SSE events

- **WHEN** `build_refresh_assets_cache()` runs across multiple servers and domains
- **THEN** it SHALL collect up to `asset_refresh_concurrency` domains concurrently, emitting `SSEEvent` items tagged with `mgmt_name` and `domain`, and linking cluster members and VSX virtual systems to their parent cluster/VSX asset IDs

### Requirement: Cache-First Object Search with Recursive Group Membership Resolution

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4 address, CIDR subnet, wildcard pattern, UID, or object name), query cached objects across target servers and domains, and traverse parent group memberships up to `max_depth` (default 2).

#### Scenario: Search resolves direct matches and containing groups

- **WHEN** `search_objects("10.1.10.50", max_depth=2)` is called
- **THEN** it SHALL yield `SSEEvent` progress and per-domain result events containing both the matching host/network objects and the hierarchy of groups (`memberships`) that directly or transitively contain those objects
