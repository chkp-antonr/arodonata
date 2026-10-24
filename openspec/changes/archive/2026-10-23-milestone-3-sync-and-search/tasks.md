# Tasks: Milestone 3 — Domain Synchronization, Cache Services, Search, and ArodonataClient Facade

## 1. Domain Discovery and Refresh Tracking (`domain_service.py`)

- [x] 1.1 Implement `src/arodonata/core/services/domain_service.py` (`DomainListRefreshTracker` with 1-hour `domain_list_ttl` and invalidation support, `DomainService` discovering domains via `show-domains`, synthesizing the `Global` domain row via `show-global-domain`, filtering `Global` unless `include_global=True`, and re-resolving `active_ip` / `active_mds_ip` on failover) and verify unit tests in `tests/test_domain_service.py` pass

## 2. Unified Domain Synchronization Coordinator (`sync_coordinator.py`)

- [x] 2.1 Implement `src/arodonata/core/services/sync_coordinator.py` (`DomainSyncCoordinator` grouping domains by `active_mds_ip` with `max(1, concurrent_limit - 1)` concurrency per MDS member, acquiring per-domain locks via `LockPort`, checking shared read sessions for dirty state via `show-session`, comparing `(last_published_at, last_session_uid)` in `domain_sync_state`, and handling probe `InvalidCredentialsError` by marking stale and emitting `DomainSyncFailedEvent` during reload) and verify unit tests in `tests/test_sync_coordinator.py` pass

## 3. Object and Service Cache Synchronization (`object_service.py`, `service_cache.py`)

- [x] 3.1 Implement `src/arodonata/core/services/object_service.py` (`ObjectService` with paired `await refresh_objects` and `stream_refresh_objects`, `CacheMode` support `"cache" | "smart" | "smart-fast" | "force"`, default types `("host", "network", "address-range", "group", "dns-domain")`, `"smart-fast"` incremental sync via `show-changes` with fallback on `> max_incremental_changes` or error, and atomic type-scoped replacement) and verify unit tests in `tests/test_object_service.py` pass
- [x] 3.2 Implement `src/arodonata/core/services/service_cache.py` (`ServiceCacheService` with paired `await refresh_services` and `stream_refresh_services` for `arodonata_services`, default types `("service-tcp", "service-udp", "service-icmp", "service-group")`, and selective on-demand `types=[...]` refresh without wiping other cached service types) and verify unit tests in `tests/test_service_cache.py` pass

## 4. Asset Refresh and Topology Relationships (`asset_service.py`)

- [x] 4.1 Implement `src/arodonata/core/services/asset_service.py` (`AssetRefreshService` with paired `await refresh_assets` and `stream_refresh_assets`, concurrent per-MDS-member collection, `ClusterRelationshipManager`, and `VSXRelationshipManager` using encapsulated `generic-object` queries) and verify unit tests in `tests/test_asset_service.py` pass

## 5. Cache-First Object Search and Structured Aggregation (`search_service.py`)

- [x] 5.1 Implement `src/arodonata/core/services/search_service.py` (`SearchService.search_objects` with IP/CIDR/range/wildcard/UID/name classification, active `WriteSession` overlay merging, and recursive group membership traversal up to `max_depth`, plus `describe_objects`, `query_objects`, and `get_cache_status`) and verify unit tests in `tests/test_search_service.py` pass

## 6. Unified `ArodonataClient` Facade (`client.py`)

- [x] 6.1 Implement `src/arodonata/client.py`, `src/arodonata/core/services/__init__.py`, and update `src/arodonata/__init__.py` (`ArodonataClient` composition root with typed getters, `WriteSession` overlay integration, `write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`, `start_object_cache_warmup`, `invalidate_domain`, and deterministic lifecycle cleanup), verify unit tests in `tests/test_client.py` pass, and run all quality gates
