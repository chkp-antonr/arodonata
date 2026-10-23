# Cache, Synchronization, and Search Specification Delta

## ADDED Requirements

### Requirement: Dedicated Service Cache Table and Selective Refresh

`ServiceCacheService` and `SqlCacheAdapter` SHALL persist service objects in a dedicated `arodonata_services` (`CPService`) table tracked per `(mgmt_name, domain_name, "services", item_type)` in `domain_sync_state` (with `last_published_at`, `last_session_uid`, and `synced_at`), refreshing `("service-tcp", "service-udp", "service-icmp", "service-group")` by default and fetching other types only when requested in `types`.

#### Scenario: Default service refresh loads core variable service types

- **WHEN** `await client.refresh_services(mode="smart")` runs without an explicit `types` list
- **THEN** the service SHALL synchronize `service-tcp`, `service-udp`, `service-icmp`, and `service-group` rows into `arodonata_services` and record each type's `last_published_at`, `last_session_uid`, and `synced_at` in `domain_sync_state`

#### Scenario: Explicit service types sync on demand without wiping other cached service types

- **WHEN** `await client.refresh_services(types=["service-other"])` is called on a domain that already has `service-tcp` cached
- **THEN** only `service-other` rows SHALL be fetched and replaced in `arodonata_services` (preserving existing `service-tcp` rows), and `domain_sync_state` SHALL record the sync state for `item_type="service-other"`

## MODIFIED Requirements

### Requirement: Object Cache Refresh Modes and Incremental Sync

`ObjectService` and `DomainSyncCoordinator` SHALL support four canonical `CacheMode` values (`"cache"`, `"smart"`, `"smart-fast"`, and `"force"`), default to syncing `("host", "network", "address-range", "group", "dns-domain")` into `arodonata_objects`, track revision state per `(mgmt_name, domain_name, scope, item_type)` in `domain_sync_state` (`last_published_at`, `last_session_uid`, `synced_at`), and expose paired `await refresh_objects(...)` and `stream_refresh_objects(...)` methods.

#### Scenario: Smart/Check refresh reloads only stale domains atomically

- **WHEN** `await client.refresh_objects(mode="smart")` or a read helper with `cache_mode="smart"` runs
- **THEN** the coordinator SHALL compare each domain's `show-last-published-session` publish timestamp (`last_published_at`) and UID (`last_session_uid`, when timestamps match) against the requested `item_type` rows in `domain_sync_state`, skip fresh types, verify the shared session is not dirty, and reload only missing or stale `item_type` slices under a per-domain distributed lock

#### Scenario: Incremental refresh applies show-changes diff or falls back safely

- **WHEN** `await client.refresh_objects(mode="smart-fast")` or a read helper with `cache_mode="smart-fast"` detects stale `item_type` rows with a known baseline in `domain_sync_state`
- **THEN** the service SHALL query `show-changes` from the stored baseline session, delete removed objects directly, re-fetch added/modified tracked objects in full (`show-object` with `details-level="full"`), and update `last_published_at`, `last_session_uid`, and `synced_at` in `domain_sync_state`; if changes exceed `max_incremental_changes` (default 500) or any error occurs, it SHALL fall back automatically to an atomic type-scoped reload

#### Scenario: Refresh failure visibility and InvalidCredentialsError handling

- **WHEN** a domain's staleness probe fails with `InvalidCredentialsError`
- **THEN** the probe SHALL report the domain as stale so the reload path records the domain in `RefreshOutcome.failed_domains` and emits a `DomainSyncFailedEvent` (`SyncProgressEvent`), while keeping previously cached objects intact

#### Scenario: Parallel domain refresh per MDS member and background first-use warm-up

- **WHEN** `DomainSyncCoordinator.ensure()` refreshes multiple domains
- **THEN** domains SHALL be refreshed concurrently at up to `max(1, concurrent_limit - 1)` domains at once per MDS member (`active_mds_ip`, with MDS members running in parallel), while `get_domains()` SHALL return the domain list without implicitly starting background object-cache warm-up (warm-up is invoked explicitly via `start_object_cache_warmup`)

### Requirement: Asset and Gateway Cache with Cluster and VSX Relationships

`AssetRefreshService` (`refresh_assets`, `stream_refresh_assets`) SHALL collect gateways, clusters, cluster members, VSX gateways/clusters (via encapsulated `generic-object` topology queries), and management servers across domains concurrently via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`) and enrich parent-child relationships via `ClusterRelationshipManager` and `VSXRelationshipManager`.

#### Scenario: Concurrent domain asset collection with interleaved SSE events

- **WHEN** `stream_refresh_assets()` runs across multiple servers and domains
- **THEN** it SHALL collect domains concurrently per MDS member (`max(1, concurrent_limit - 1)`), emit typed `SyncProgressEvent` items (convertible to `SSEEvent` via `adapters.sse`) tagged with `mgmt_name` and `domain`, link cluster members and VSX virtual systems to their parent asset IDs, and update `domain_sync_state` (`scope="assets"`, `item_type="*"`)

### Requirement: Cache-First Object Search with Recursive Group Membership Resolution

`SearchService.search_objects()` SHALL classify comma-separated search terms (IPv4 address, CIDR subnet, address range, wildcard pattern, UID, or object name), query cached objects (including any active `WriteSession` overlay in `contextvars`) across target servers and domains, and traverse parent group memberships up to `max_depth` (default 2), returning a typed `SearchResult`.

#### Scenario: Search resolves direct matches and containing groups

- **WHEN** `await client.search_objects("10.1.10.50", max_depth=2)` is called
- **THEN** it SHALL return a `SearchResult` containing both the matching host/network objects (reflecting any uncommitted `WriteSession` overlay in the current context) and the hierarchy of groups (`memberships`) that directly or transitively contain those objects
