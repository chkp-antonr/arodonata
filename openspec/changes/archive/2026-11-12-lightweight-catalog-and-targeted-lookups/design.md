# Design: Lightweight Rulebase Catalog, Targeted Topology Object Resolution, and Fast Cold-Cache CPCRUD Lookups

## Context

See [proposal.md](./proposal.md) for motivation. Arodonata's storage schema (`arodonata_domain_sync_state`, `arodonata_rulebase_*`, `arodonata_objects`, `arodonata_services`, `arodonata_gateway_topology`) already tracks freshness per `(mgmt_name, domain_name, scope, item_type)` and stores package-layer links separately in `arodonata_rulebase_package_layer` (exposed via `CachePort.get_domain_rulebase_packages`). However, three service layers currently treat cold or stale domain slices as all-or-nothing barriers:

1. `CachedRulebaseSource.get_policy_packages` and `get_package_rulebase` invoke `RulebaseRefreshService.refresh_rulebases(...)` (`scope="rulebase", item_type="*"`), pulling all NAT rulebases, standalone layers, HTTPS/Threat layers, and all packages' access layers.
2. `TopologyService.refresh_topology` and `stream_refresh_topology` invoke `ObjectService.refresh_objects(..., types=DEFAULT_OBJECT_TYPES, include_global=True)` across every target domain before extracting gateway interfaces.
3. `HybridStateReader` value-conflict helpers (`find_host_by_ip`, `find_network_by_subnet`, `find_address_range_by_bounds`, `find_service_by_port`, `find_icmp_service`) call `list_objects_of_type` / `list_services_of_type`, issuing full paginated `show-hosts` / `show-services-*` queries whenever `arodonata_domain_sync_state` is cold or background warm-up is still running.

All core domain services MUST continue to depend strictly on `ApiPort`, `CachePort`, and `LockPort` protocols, preserve dirty-session safety (`verify_session_clean`), and enforce SID redaction across logs, errors, and telemetry spans.

## Goals / Non-Goals

**Goals:**

- Make `get_policy_packages` O(packages) via a `show-packages`-only sync slice (`item_type="packages"`) without downloading any rulebases.
- Make `get_package_rulebase` O(target package layers) via a package-scoped sync slice (`item_type="package:<rulebase_type>:<package_uid>"`) while keeping `item_type="*"` strictly reserved for full-domain rulebase snapshots (`refresh_rulebases`, `locate_rules`).
- Eliminate bulk `DEFAULT_OBJECT_TYPES` (`show-hosts`, `show-dns-domains`) refreshes from `refresh_topology` / `stream_refresh_topology` by resolving only gateway-referenced `"specific"` and `vpn-domain` objects/groups (and transitive group members) on demand.
- Make cold-cache `CPCRUDService.plan()` value-conflict checks O(1) API calls per candidate via `show-objects` (`type`, `filter`, `ip-only`) with exact attribute verification and intra-plan virtual overlay merging.
- Coalesce concurrent `ArodonataClient.start_object_cache_warmup` tasks per scope and expose `get_warmup_status()` without leaking unretrieved asyncio task exceptions.

**Non-Goals:**

- Altering Check Point write-session staging, `verify-policy`, or `publish` semantics in `cpcrud/executor.py`.
- Dropping or destructively migrating existing `arodonata_*` SQL tables (all slice keys fit existing `arodonata_domain_sync_state.item_type` VARCHAR columns).
- Changing full-domain `refresh_rulebases` or `locate_rules` semantics when callers explicitly request whole-domain rulebase analysis.

## Decisions

### 1. Granular `scope="rulebase"` Sync Slices (`"packages"` and `"package:<type>:<uid>"`) vs Full `"*"`

- **Decision**: Keep `scope="rulebase", item_type="*"` exclusively for complete domain snapshots (`refresh_rulebases`). Introduce two narrower coordinator-managed slices:
  1. `item_type="packages"`: `RulebaseRefreshService.refresh_policy_packages` runs under `DomainSyncCoordinator` (`verify_session_clean` + domain lock), queries `show-packages` (`details-level="full"`), parses `PolicyPackageInfo` + `RulebasePackageLayerLink` rows, and calls `CachePort.replace_domain_package_catalog(mgmt_name, domain_name, package_links, sync_states=[...])` which atomically replaces `arodonata_rulebase_package_layer` rows for that domain without touching `arodonata_rulebase_layer` / `section` / `rule` or stamping `item_type="*"`. When `get_policy_packages(mgmt_name, domain_name, cache_mode)` runs, it first checks if `item_type="*"` OR `item_type="packages"` is fresh for the domain head; if neither is fresh (or `cache_mode="force"`), it runs `refresh_policy_packages` and reads from `CachePort.get_domain_rulebase_packages`.
  2. `item_type=f"package:{rulebase_type}:{package_uid}"`: `RulebaseRefreshService.refresh_package_rulebase` ensures the package catalog (`"packages"` or `"*"`) is fresh to resolve `package` -> `PolicyPackageInfo`, then fetches only the layers belonging to `(package, rulebase_type)`:
     - For `rulebase_type="nat"`: `show-nat-rulebase` for `package`.
     - For `rulebase_type in ("access", "https", "threat")`: the package's ordered layers of that type, Global placeholder expansion (`show-*-rulebase` with `package=pkg.name` when a Global layer contains a `place-holder`), and BFS traversal of any `inline-layer` UIDs referenced by rules in those layers.
     - Persists via `CachePort.upsert_domain_rulebase_layers(mgmt_name, domain_name, layers=..., sections=..., access_rules=..., nat_rules=..., https_rules=..., threat_rules=..., replaced_layer_uids=..., sync_states=[...])`, deleting and re-inserting rows in `arodonata_rulebase_layer`, `arodonata_rulebase_section`, and `arodonata_rulebase_*_rule` **only** for `layer_uid in replaced_layer_uids` inside a single transaction while stamping `item_type=f"package:{rulebase_type}:{package_uid}"`.
- **Alternatives Considered**:
  - *In-memory ephemeral `show-packages` / `show-access-rulebase` bypass*: Rejected because bypassing `arodonata_rulebase_*` loses cross-request persistence, distributed lock protection, dirty-session checks, and `DomainSyncCoordinator` freshness reuse across concurrent engineer sessions.
  - *Stamping `item_type="*"` on partial sync*: Rejected because `locate_rules` and policy-reconciliation audit queries require all packages and layers in the domain; stamping `"*"` prematurely would hide unsynced packages.

### 2. On-Demand `"specific"` & `vpn-domain` Object Tree Resolution in `TopologyService`

- **Decision**: Remove `self._object_service.refresh_objects(..., types=list(DEFAULT_OBJECT_TYPES), include_global=True)` from `TopologyService.refresh_topology` and `stream_refresh_topology`. Instead, inside `_sync_domain_topology` (and `_stream_targeted_gateway_refresh`):
  1. Refresh/load domain `assets` (`show-gateways-and-servers` + existing `_fetch_asset_detail_on_demand` for gateways lacking interface details) and load lightweight `show-packages` metadata (`refresh_policy_packages(..., mode="smart")` when `arodonata_rulebase_package_layer` is empty and `mode != "cache"`).
  2. Load whatever objects are already cached in `arodonata_objects` for `(mgmt_name, domain_name)` and `"Global"`.
  3. Scan policy-enforcing gateways' normalized interfaces (`"specific"` mode: `specific_network_uid`, `specific_network_ref`) and `_extract_vpn_domain_refs(asset.raw_data)`.
  4. Collect any root references missing from the cached object index (or whose domain object slice is not verified fresh against the current published session head, or all referenced roots when `mode == "force"`), and run a cycle-safe, bounded-concurrency (`asyncio.Semaphore(8)`) BFS resolver `_resolve_topology_objects_on_demand(...)`:
     - Queries `show-object` (`{"uid": ref, "details-level": "full"}`) when `ref` looks like a UUID, or queries `show-objects` (`{"filter": name, "details-level": "full"}` exact-name match, falling back to singular `show-*` only if `show-objects` is unrecognized) in `domain_name` first and `"Global"` second (unwrapping Check Point's `{"object": {...}}` envelope on `show-object`).
     - Whenever a resolved `CPObject` is a `group` (or `group-with-exclusion`), enqueues any `member` UIDs/dicts not yet resolved (note: `show-group` with `details-level="full"` already embeds member dictionaries in Check Point responses, allowing immediate hydration of leaf `host` / `network` / `address-range` members without extra per-member round-trips when inline fields are present, falling back to `show-object` by UID only when members are bare UIDs or nested groups!).
     - Persists newly fetched `CPObject` records via `CachePort.upsert_objects(resolved_objs, sync_states=None)` so `arodonata_objects` retains them for subsequent `get_topology_diagnostics` and `cache` reads **without** writing a `DomainSyncState` row claiming the entire `"host"` or `"group"` slice is synced.
  5. Add optional `source_types: Sequence[TopologySourceType | str] | None = None` and `include_annotations: bool = True` parameters to `TopologyService.find_affected_gateways` and `ArodonataClient.find_affected_gateways` so callers like FPCR v2 can request static-only topology matching natively without copying internal service instances.
- **Alternatives Considered**:
  - *Refreshing `("network", "group", "address-range")` while excluding `"host"`*: Better than `DEFAULT_OBJECT_TYPES`, but in Check Point a `"specific"` group CAN contain `host` members (explicitly required by `gateway-topology/spec.md`), and large domains can also hold thousands of unused `network` and `group` objects. Targeted BFS resolution handles `host`, `network`, `address-range`, and nested `group` members accurately with minimal API calls (zero object calls when gateways use connected/external interfaces!).

### 3. Cold-Cache `show-objects` Filtered Value Lookups in `HybridStateReader`

- **Decision**: In `HybridStateReader` (`src/arodonata/cpcrud/state_reader.py`), keep the fast local SQL path whenever `await self.is_slice_cache_fresh(mgmt_name, domain_name, scope, item_type)` is `True` OR `_live_objects_memo` / `_live_services_memo` already holds that full slice. When the slice is cold/stale, add a targeted helper `_query_filtered_objects(mgmt_name, domain_name, *, obj_type, filter_text, ip_only)`:
  - Calls `self._api.api_query(mgmt_name, "show-objects", domain=domain_name or None, details_level="standard", payload={"type": obj_type, "filter": filter_text, **({"ip-only": True} if ip_only else {})})`, memoized by `(mgmt_name, domain_name, obj_type, filter_text, ip_only)`.
  - Applies exact Python predicate matching (e.g., `h.ipv4_address == target or h.ipv6_address == target` for `host`; `net.subnet4 == target_sub and norm_mask == mask_length4` for `network`; `(r.ipv4_address_first, r.ipv4_address_last) == (f_clean, l_clean)` for `address-range`; `s.port == target_port` and protocol match for `service-tcp`/`service-udp`) so Check Point's substring search (`filter="80"` matching `8080`, or `10.1.1.1` matching `10.1.1.10`) never causes false-positive `REUSE` conflicts. Because Check Point `show-objects` `filter` does not match numeric `icmp-type` fields (e.g. built-in `echo-request`), `find_icmp_service` continues to use single-page `show-services-icmp` / `show-services-icmp6` (`list_services_of_type`, memoized per domain).
  - Merges intra-plan `_deleted_objects` / `_virtual_objects` (or `_deleted_services` / `_virtual_services`) identically to `list_objects_of_type` / `list_services_of_type` so multiple operations within the same template see prior virtual creates/updates/deletes.
  - If `api_query("show-objects", ...)` fails specifically with `generic_err_command_not_recognized`, falls back transparently to `list_objects_of_type` / `list_services_of_type`; on any other failure or `paging_inconsistent`, raises `StateLookupError` (preserving fail-closed `Outcome.ERROR` planning).
  - Extend `FileReplayApiMock` (`src/arodonata/testing/replay_mock.py`) to handle `show-objects` (`type`, `filter`, `ip-only`, pagination, and `details-level` projection) across fixture object/service collections so replay and unit tests verify cold-cache `plan()` with zero `show-hosts` / `show-services-*` calls.
- **Alternatives Considered**:
  - *Populating `arodonata_objects` from `CPCRUDService.plan()`*: Rejected because `plan()` runs outside `DomainSyncCoordinator` locks and may run concurrently with background warm-up; keeping cold-cache filtered reads ephemeral inside `HybridStateReader` avoids partial-cache races while background `start_object_cache_warmup` populates persistent tables cleanly.

### 4. Single-Flight `start_object_cache_warmup` Registry and `get_warmup_status()`

- **Decision**: Track active warm-up flights on `ArodonataClient` keyed by `(eff_mgmt, norm_domains, norm_types, bool(include_global), bool(include_services), bool(mode == "force"))` alongside a bounded status dictionary (`dict[key, WarmupStatusEntry]` exposing `status: Literal["running", "completed", "failed", "cancelled"]`, `started_at`, `completed_at`, `refreshed_domains`, `failed_domains`, `error`).
  - Inside `_run_warmup()`, catch `asyncio.CancelledError` cleanly on `client.close()`, and catch `Exception` to record SID-redacted error details (`redact_sid`) in status + log at `WARNING` level without re-raising into an unawaited fire-and-forget task (or attach a done-callback that consumes task exceptions so Python's GC never logs `"Task exception was never retrieved"` while callers awaiting the task still observe `RefreshOutcome` including `failed_domains`).

## Risks / Trade-offs

- **[Risk] Partial `arodonata_objects` rows from on-demand topology group expansion could be mistaken for a complete object cache** → **Mitigation**: `TopologyService` calls `CachePort.upsert_objects(..., sync_states=None)` without writing `arodonata_domain_sync_state` for `"objects"`. Both `ObjectService` (`mode="smart"`) and `HybridStateReader.is_slice_cache_fresh` gate cache trust strictly on `arodonata_domain_sync_state`, so partial rows never suppress background object sync or cause false cache misses in `CPCRUD`.
- **[Risk] Partial `arodonata_rulebase_*` layers from `refresh_package_rulebase` could cause incomplete `locate_rules` results** → **Mitigation**: `refresh_package_rulebase` writes `item_type="package:<type>:<uid>"` and never stamps `item_type="*"`. `CachedRulebaseSource.locate_rules` and `refresh_rulebases` continue to check `item_type="*"` exclusively.
- **[Risk] Check Point `show-objects` `filter` performs tokenized/substring matching rather than strict equality** → **Mitigation**: `show-objects` is used strictly as a server-side candidate narrowing step (`ip-only=True` for IP/subnet/range queries), and `HybridStateReader` enforces exact field equality in Python after hydrating `CPObject` / `CPService`.

## Migration Plan

1. Implement additive `CachePort` / `SqlCacheAdapter` slice methods (`replace_domain_package_catalog`, `upsert_domain_rulebase_layers`) — no destructive SQLite/PostgreSQL table migrations required.
2. Implement `RulebaseRefreshService` + `CachedRulebaseSource` package/targeted-layer sync, `TopologyService` on-demand object tree resolution + `find_affected_gateways` filter kwargs, `HybridStateReader` `show-objects` targeted lookups + `FileReplayApiMock` `show-objects` handler, and `ArodonataClient` single-flight warm-up + facade methods.
3. Rollback is a clean code revert since existing table schemas and `DomainSyncState(item_type="*")` semantics remain intact.
