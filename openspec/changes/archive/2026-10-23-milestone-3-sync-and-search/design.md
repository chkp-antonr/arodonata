# Design: Milestone 3 — Domain Synchronization, Cache Services, Search, and ArodonataClient Facade

## Context

See `proposal.md` for motivation and `openspec/changes/archive/2026-10-23-revise-v2-architecture-specs/design.md` for overarching v2 architectural decisions. Milestone 3 implements the pure domain services in `src/arodonata/core/services/` (depending strictly on `ApiPort`, `CachePort`, and `LockPort`) and wires them together in `src/arodonata/client.py` (`ArodonataClient`).

## Goals / Non-Goals

**Goals:**

- Keep `src/arodonata/core/services/` 100% transport- and ORM-independent (no imports from `aiohttp`, `sqlalchemy`, `sqlmodel`, or `mcp`).
- Implement `DomainService` and `DomainListRefreshTracker` (`domain_service.py`) for MDSM `show-domains` discovery, `Global` domain synthesis, `include_global` filtering, 1-hour TTL refresh tracking, and failover IP resolution.
- Implement `DomainSyncCoordinator` (`sync_coordinator.py`) with per-MDS-member bounded concurrency (`max(1, concurrent_limit - 1)`), per-domain distributed locking (`sync:{mgmt_name}:{domain_name}:{scope}`), dirty-session detection (`locks == 0` and `number-of-published-changes == 0`), and `(last_published_at, last_session_uid)` revision comparison in `domain_sync_state`.
- Implement `ObjectService` (`object_service.py`) and `ServiceCacheService` (`service_cache.py`) with paired `await refresh_*` / `stream_refresh_*` APIs, canonical `CacheMode` (`"cache"`, `"smart"`, `"smart-fast"`, `"force"`), `"smart-fast"` incremental sync via `show-changes` (with automatic fallback on `> max_incremental_changes` or error), and type-scoped replacement.
- Implement `AssetRefreshService`, `ClusterRelationshipManager`, and `VSXRelationshipManager` (`asset_service.py`) with concurrent per-MDS-member domain asset collection and encapsulated `generic-object` VSX topology resolution.
- Implement `SearchService` (`search_service.py`) for multi-term IP/CIDR/range/wildcard/UID/name search with recursive group membership resolution (`max_depth`), plus `describe_objects`, `query_objects`, and `get_cache_status`.
- Implement `ArodonataClient` (`client.py`) as the unified composition root and facade with `contextvars`-aware `WriteSession` overlay merging, domain helper methods, explicit background cache warm-up, and deterministic teardown.

**Non-Goals:**

- Full rulebase pager/numbering/local filter engine (`src/arodonata/rulebase/`, scheduled for Milestone 4; `ArodonataClient` provides typed cached rulebase getters `get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules` backed by `CachePort.get_domain_rulebase`).
- CPCRUD planner/executor (`src/arodonata/cpcrud/`, scheduled for Milestone 5) and MCP server (`src/arodonata/mcp/`, scheduled for Milestone 6).

## Decisions

### 1. `DomainService` and `DomainListRefreshTracker` (`src/arodonata/core/services/domain_service.py`)

- **`DomainListRefreshTracker`**:
  - Tracks per-`mgmt_name` last refresh timestamps (both in-memory monotonic/UTC memo and via `domain_sync_state` with `scope="domains"`, `item_type="*"`) using `domain_list_ttl` (default `3600` seconds / 1 hour).
  - Determines that a server's domain list requires refresh when:
    1. `mode == "force"`, or
    2. No domains are cached for `mgmt_name` in `CachePort.get_domains(mgmt_name, include_global=True)`, or
    3. The `domain_list_ttl` (1 hour) has elapsed since the last refresh (`synced_at`), or
    4. The server was explicitly invalidated.
- **Discovery & `Global` Synthesis**:
  - Queries `show-domains` (`details-level="full"`) on the management server's system domain (`domain=None`).
  - If `show-domains` returns domain objects (MDSM server): parses each domain (`active_ip`, `active_mds_ip`, `standby_ips`, `servers`) and checks whether a `Global` domain row is already present; if not, queries `show-global-domain` (or `show-domains` / synthesizes a `Global` `DomainInfo` row with `is_global=True`, `domain_type="global"`, `active_ip=endpoint.host`, `active_mds_ip=endpoint.host`) so `Global` is always persisted in `domains` and returned when `include_global=True`.
  - If the server is a single-domain SmartCenter (where `show-domains` returns `objects=[]` or an unsupported command error), synthesizes a default domain row (`name=mgmt_name` or `"SMC User"`, `active_ip=endpoint.host`, `active_mds_ip=endpoint.host`) so single-domain servers work uniformly across all services.
  - Note: `get_domains()` never starts implicit background object-cache warm-up.

### 2. `DomainSyncCoordinator` (`src/arodonata/core/services/sync_coordinator.py`)

- **Per-MDS-Member Concurrency Grouping**:
  - Given target `DomainInfo` items across one or more management servers, groups domains by `mds_key = domain.active_mds_ip or domain.active_ip or endpoint.host`.
  - All MDS member groups execute concurrently via `asyncio.gather`, while within each MDS member group an `asyncio.Semaphore(max(1, settings.concurrent_limit - 1))` bounds concurrent domain operations.
- **Freshness Memo & Staleness Probe (`show-last-published-session`)**:
  - In `"cache"` mode: never contacts the Check Point server; all domains/types are treated as skipped.
  - In `"smart"` and `"smart-fast"` modes:
    - Checks if all requested `item_type` rows in `domain_sync_state` have `status == "ok"`, `synced_at` within `cache_ttl` (unless `(mgmt_name, domain_name)` was invalidated via `invalidate_domain`), and non-null `last_published_at`. If within `cache_ttl` and not invalidated, skips the server probe.
    - Otherwise calls `show-last-published-session` on `(mgmt_name, domain_name)` to extract `published_at` (`publish-time.iso-8601` or `publish-time.posix` ms/s) and `session_uid` (`uid`).
    - Compares each requested `item_type`'s `DomainSyncState`:
      - Fresh if `state.status == "ok"` and `state.last_published_at == remote_published_at` and (when `remote_session_uid` and `state.last_session_uid` are present) `state.last_session_uid == remote_session_uid`.
      - Stale otherwise (or if `state` is missing, or if `last_published_at != remote_published_at`, or if timestamps match but `last_session_uid` differs).
    - If the probe raises `InvalidCredentialsError` (or another error), the probe reports the domain as stale (carrying the probe error) so the reload path records `failed_domains[domain_key] = str(exc)` and emits `DomainSyncFailedEvent` while keeping previously cached rows intact.
- **Dirty Session Check**:
  - Before replacing or mutating cached domain rows from a shared read session, calls `show-session` (with `details-level="standard"` or `"full"`) and verifies `locks == 0` and `number-of-published-changes == 0` (also checking `changes == 0` if present). If non-zero, raises `DirtySessionError` so uncommitted changes in a dirty shared session never poison the shared SQL cache.
- **Per-Domain Distributed Lock**:
  - Acquires `lock_port.lock(f"sync:{mgmt_name}:{domain_name}:{scope}", ttl_seconds=...)` before executing the domain's reload/incremental callback.

### 3. `ObjectService` & `"smart-fast"` Incremental Sync (`src/arodonata/core/services/object_service.py`)

- **Default Types**: `DEFAULT_OBJECT_TYPES = ("host", "network", "address-range", "group", "dns-domain")`.
- **Type-to-Command Mapping**:
  - `"host"` -> `"show-hosts"`
  - `"network"` -> `"show-networks"`
  - `"address-range"` -> `"show-address-ranges"`
  - `"group"` -> `"show-groups"`
  - `"dns-domain"` -> `"show-dns-domains"`
  - Any other explicit `item_type` (e.g. `"wildcard"`, `"security-zone"`, `"dynamic-object"`, `"access-role"`) -> `"show-" + item_type + "s"` (or `"show-objects"` with `{"type": item_type}`).
- **Incremental Refresh (`mode="smart-fast"`)**:
  - Eligible when all stale `item_type` slices for `(mgmt_name, domain_name)` have a prior baseline `last_session_uid` (or `last_published_at`) in `domain_sync_state`.
  - Calls `show-changes` with `{"from-date": baseline_iso}` or `{"from-session": baseline_session_uid, "details-level": "standard"}`.
  - Inspects `tasks[].task-details[].changes[]` or `changes[]` for `operations` (`added-objects`, `modified-objects`, `deleted-objects`).
  - Counts total affected objects across tracked `types`. If `total_changes > settings.max_incremental_changes` (default 500) or `show-changes` fails, falls back automatically to full atomic type-scoped reload for the stale types.
  - Otherwise:
    - Deletes removed UIDs via `cache.delete_objects_by_uids(mgmt_name, domain_name, deleted_uids)`.
    - Re-fetches each added/modified UID (or batches via `show-object` / `show-objects` with `details-level="full"`) and upserts them via `cache.upsert_objects(...)`.
    - Updates `domain_sync_state` (`last_published_at`, `last_session_uid`, `synced_at`, `status="ok"`, `object_count`) for each synced `item_type`.
- **Atomic Type-Scoped Full Reload**:
  - For each stale `item_type`, pages objects via `api.api_query(..., details_level="full")`, converts to `CPObject.from_cp_dict(mgmt_name, domain_name, raw)`, calls `cache.replace_domain_objects(mgmt_name, domain_name, objects, types=stale_types)`, and updates `domain_sync_state` per `item_type`.

### 4. `ServiceCacheService` (`src/arodonata/core/services/service_cache.py`)

- **Default Types**: `DEFAULT_SERVICE_TYPES = ("service-tcp", "service-udp", "service-icmp", "service-group")`.
- **Type-to-Command Mapping**:
  - `"service-tcp"` -> `"show-services-tcp"`
  - `"service-udp"` -> `"show-services-udp"`
  - `"service-icmp"` -> `"show-services-icmp"`
  - `"service-icmp6"` -> `"show-services-icmp6"`
  - `"service-group"` -> `"show-service-groups"`
  - `"service-other"` -> `"show-services-other"`
  - `"service-dce-rpc"` -> `"show-services-dce-rpc"`
  - `"service-rpc"` -> `"show-services-rpc"`
  - `"service-sctp"` -> `"show-services-sctp"`
  - `"service-gtp"` -> `"show-services-gtp"`
  - `"service-citrix-tcp"` -> `"show-services-citrix-tcp"`
  - `"service-compound-tcp"` -> `"show-services-compound-tcp"`
- **Selective Replacement**:
  - Calls `cache.replace_domain_services(mgmt_name, domain_name, services, types=stale_types)` under `sync:{mgmt_name}:{domain_name}:services` lock so syncing `types=["service-other"]` replaces only `service-other` rows while preserving `service-tcp`, etc.
  - Also supports `"smart-fast"` incremental diffing via `show-changes` (filtering service types) with automatic fallback to type-scoped reload.

### 5. `AssetRefreshService`, `ClusterRelationshipManager`, and `VSXRelationshipManager` (`src/arodonata/core/services/asset_service.py`)

- **Collection**:
  - Queries `show-gateways-and-servers` (`details-level="full"`) per domain via `api_query`, and enriches detailed cluster/VSX metadata when needed.
- **`ClusterRelationshipManager`**:
  - Links `cluster-member` assets to their parent cluster (`simple-cluster` / `CpmiGatewayCluster` / `CpmiVsxClusterNetobj`) using `cluster-member-names` / `cluster-members` on the parent cluster or matching member UIDs/names, setting `member.parent_uid = cluster.uid`, `member.parent_name = cluster.name`, and `cluster.member_uids = [...]`.
- **`VSXRelationshipManager`**:
  - Queries Check Point `show-generic-objects` with `{"class-name": "com.checkpoint.objects.classes.dummy.CpmiVsxNetobj"}` / `CpmiVsxClusterNetobj` / `CpmiVsNetobj` (or inspects `virtual-systems` / `vsx-gateway` references via encapsulated `generic-object` calls) to link VSX virtual systems (`virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj`) to their parent VSX gateway or VSX cluster (`vs.parent_uid = vsx_parent.uid`, `vs.parent_name = vsx_parent.name`, `vsx_parent.virtual_system_uids = [...]`).
- **Paired Streaming & Coroutine API**:
  - `stream_refresh_assets(...)` runs domains concurrently per MDS member (`max(1, concurrent_limit - 1)`) via an `asyncio.Queue` of `SyncProgressEvent` items so progress events from concurrent domains stream in real time as they occur, and `await refresh_assets(...)` consumes `stream_refresh_assets(...)` into a `RefreshOutcome`.

### 6. `SearchService` and Structured Aggregation (`src/arodonata/core/services/search_service.py`)

- **Term Classification (`classify_search_term`)**:
  - Splits comma-separated search strings into individual terms.
  - Classifies each term as:
    - `"uid"`: UUID v4 / 8-4-4-4-12 hex pattern.
    - `"ipv4"`: Valid IPv4 address (`ipaddress.IPv4Address`).
    - `"cidr"`: Valid IPv4 network (`ipaddress.IPv4Network`, e.g. `10.1.0.0/16`).
    - `"range"`: `<ip1>-<ip2>` IPv4 range.
    - `"wildcard"`: Contains `*` or `?`.
    - `"name"`: Substring or case-insensitive object/FQDN/comment match.
- **Matching Semantics**:
  - An `"ipv4"` query matches hosts with that exact IP, networks (`subnet4`/`mask_length4`) containing that IP, and address ranges (`ipv4_address_first`..`ipv4_address_last`) containing that IP.
  - A `"cidr"` query matches networks equal to, contained in, or overlapping/containing the query subnet, plus hosts and ranges within the query subnet.
  - A `"range"` query matches hosts, networks, and address ranges overlapping `[start_ip, end_ip]`.
  - `"wildcard"`, `"uid"`, and `"name"` match object `uid`, `name`, `fqdn`, `ipv4_address`, `subnet4`, or `comments`.
- **Overlay Integration & Recursive Group Traversal**:
  - Merges active `WriteSession.overlay` (from `get_write_session(mgmt_name, domain_name)`) over cached domain objects before matching and before building the reverse `member_uid -> parent_groups` index.
  - Traverses parent groups BFS up to `max_depth` (default `2`), cycle-safe, populating `SearchResult.memberships[match.uid]` with `GroupMembershipNode(uid, name, mgmt_name, domain_name, depth, parent_uids)`.
- **Structured Query & Cache Status**:
  - `describe_objects(...)`: returns schema metadata, distinct cached `types`, `domains`, `mgmt_names`, and total counts across `arodonata_objects` and `arodonata_services`.
  - `query_objects(...)`: supports filtering by `mgmt_name`, `domain_name`, `types`, `scope_origin` (`"all"`, `"local"` where `original_domain == domain_name`, `"global"` where `original_domain == "Global"` or `original_domain != domain_name`), `name_pattern`, `ip_subnet`, `tags`, `group_by` (e.g. `["domain_name", "type"]`), and `aggregate` (`"count"` or `"list"` with `limit`/`offset`).
  - `get_cache_status(...)`: inspects `domain_sync_state` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"`, computing `cache_age_seconds = (now - state.synced_at).total_seconds()` for each entry.

### 7. `ArodonataClient` Facade (`src/arodonata/client.py`)

- Wires `AMgmtClient`, `DatabaseManager`, `SqlCacheAdapter`, `SqlLockAdapter`, `DomainService`, `DomainSyncCoordinator`, `ObjectService`, `ServiceCacheService`, `AssetRefreshService`, and `SearchService`.
- Provides typed read methods (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_services`, `get_object_by_uid`, `get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules`) supporting `cache_mode` and `cache_ttl` overrides and automatically applying any active `WriteSession.overlay` from `contextvars`.
- Provides `write_session`, `auth_context`, `user_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`, `start_object_cache_warmup`, and `invalidate_domain`.
- On `close(logout=None)`: cancels any running background warm-up tasks immediately, drains startup cleanup tasks, logs out active sessions if `_owns_engine == True` (or if `logout=True`), closes `AMgmtClient`, and disposes the SQLAlchemy engine only if `_owns_engine == True`.

## Risks / Trade-offs

- **[Risk] Concurrent streaming generators (`stream_refresh_*`) across multiple MDS members** → Mitigation: Use an internal `asyncio.Queue` fed by bounded worker tasks and drained by the async generator, ensuring proper task cancellation in `finally` if the caller breaks out of `async for` early.
- **[Risk] IPv4 math performance when searching across thousands of cached hosts/networks/ranges** → Mitigation: Pre-parse IPv4 integer bounds using `ipaddress.IPv4Address` / `IPv4Network` with graceful skip on malformed addresses.
