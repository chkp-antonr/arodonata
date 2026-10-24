# Proposal: Milestone 3 — Domain Synchronization, Cache Services, Search, and ArodonataClient Facade

## Why

With the core hexagonal ports/models (`src/arodonata/core/`), SQL storage adapters (`src/arodonata/adapters/storage/`), and native `asyncio` Check Point transport and session lifecycle (`src/arodonata/adapters/checkpoint/`) delivered in Milestones 1 and 2, Arodonata v2 requires the core domain synchronization and search services (`src/arodonata/core/services/`) and the unified developer facade (`src/arodonata/client.py`) to provide cache-first multi-domain reads, incremental and atomic refresh workflows, gateway/cluster/VSX asset relationship resolution, recursive group search, structured aggregation (`describe_objects`, `query_objects`, `get_cache_status`), and `contextvars`-bound `WriteSession` overlay integration.

## What Changes

- Implement `src/arodonata/core/services/domain_service.py`: `DomainService` and `DomainListRefreshTracker` handling MDSM domain discovery (`show-domains`), `Global` domain row synthesis (`show-global-domain`), opt-in `include_global` filtering, active/standby server IP tracking and failover re-resolution, and 1-hour domain list TTL enforcement (`domain_list_ttl=3600`).
- Implement `src/arodonata/core/services/sync_coordinator.py`: `DomainSyncCoordinator` orchestrating multi-domain synchronization across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` with:
  - Parallel domain traversal grouped by `active_mds_ip` (`max(1, concurrent_limit - 1)` concurrent domains per MDS member, with MDS members running in parallel).
  - Per-domain distributed lock acquisition (`sync:{mgmt_name}:{domain_name}:{scope}`) via `LockPort` (`SqlLockAdapter`).
  - Shared read session cleanliness verification (`locks == 0` and `number-of-published-changes == 0`), raising or reporting `DirtySessionError` if uncommitted changes exist.
  - Staleness verification in `domain_sync_state` per `(mgmt_name, domain_name, scope, item_type)` comparing `last_published_at` first and `last_session_uid` when timestamps match, plus `cache_ttl` freshness memos and `invalidate_domain` hooks.
  - Graceful failure handling (including `InvalidCredentialsError` during staleness probes reporting the domain as stale so the reload path records `RefreshOutcome.failed_domains` and emits `DomainSyncFailedEvent` while preserving previously cached rows).
- Implement `src/arodonata/core/services/object_service.py`: `ObjectService` providing paired `await refresh_objects(...)` and `stream_refresh_objects(...)` methods across canonical `CacheMode` values (`"cache"`, `"smart"`, `"smart-fast"`, `"force"`), default type set `("host", "network", "address-range", "group", "dns-domain")`, type-scoped atomic replacement in `arodonata_objects`, and `"smart-fast"` incremental sync via `show-changes` (deleting removed UIDs, re-fetching added/modified tracked objects with `show-object` `details-level="full"`, and falling back to full type-scoped reload when changes exceed `max_incremental_changes` or any error occurs).
- Implement `src/arodonata/core/services/service_cache.py`: `ServiceCacheService` providing paired `await refresh_services(...)` and `stream_refresh_services(...)` methods for `arodonata_services`, defaulting to `("service-tcp", "service-udp", "service-icmp", "service-group")` and syncing additional types on demand via `types=[...]` without wiping other cached service types.
- Implement `src/arodonata/core/services/asset_service.py`: `AssetRefreshService` (`await refresh_assets(...)` and `stream_refresh_assets(...)`) collecting gateways, clusters, cluster members, VSX gateways/clusters, and management servers concurrently across domains, and enriching parent-child topology via `ClusterRelationshipManager` and `VSXRelationshipManager` (using encapsulated `generic-object` queries).
- Implement `src/arodonata/core/services/search_service.py`: `SearchService` providing `await search_objects(...)` (classifying comma-separated IPv4, CIDR, range, wildcard, UID, and name terms, applying active `WriteSession` overlays from `contextvars`, and recursively resolving parent group memberships up to `max_depth`), plus `describe_objects`, `query_objects`, and `get_cache_status`.
- Implement `src/arodonata/client.py`: `ArodonataClient` composition root and unified facade exposing typed read helpers (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_services`, `get_object_by_uid`, `get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules`), `WriteSession` overlay merging, built-in `write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`, explicit `start_object_cache_warmup`, and `invalidate_domain`.

## Capabilities

### New Capabilities

<!-- None: implements existing canonical specifications. -->

### Modified Capabilities

<!-- None: skip_specs is enabled in .openspec.yaml. -->

## Impact

- **Codebase**: Adds `src/arodonata/core/services/` (`__init__.py`, `domain_service.py`, `sync_coordinator.py`, `object_service.py`, `service_cache.py`, `asset_service.py`, `search_service.py`), adds `src/arodonata/client.py`, and exports `ArodonataClient` and core services in `src/arodonata/__init__.py`.
- **Tests**: Adds comprehensive unit tests in `tests/` covering `DomainService`, `DomainSyncCoordinator`, `ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `SearchService`, and `ArodonataClient`.
