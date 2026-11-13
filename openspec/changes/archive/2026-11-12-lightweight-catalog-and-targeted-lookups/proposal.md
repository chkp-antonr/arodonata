# Proposal: Lightweight Rulebase Catalog, Targeted Topology Object Resolution, and Fast Cold-Cache CPCRUD Lookups

## Why

Interactive policy authoring workflows in downstream applications (such as FPCR v2) only need lightweight structural metadata (`domains`, `gateways` + static topology, `policy packages`, and `access sections` of a selected package) synchronously, while large object and service inventories (`hosts`, `services`, `application-sites`, etc.) can warm up asynchronously in the background. Today, three hot codepaths in Arodonata block foreground requests by triggering full-domain or multi-domain bulk downloads: (1) `get_policy_packages` and `get_package_rulebase` refresh the entire domain rulebase snapshot (including all NAT, HTTPS, Threat, standalone, and unrelated package rulebases), (2) `refresh_topology` / `stream_refresh_topology` unconditionally pull `DEFAULT_OBJECT_TYPES` (including tens of thousands of `host` and `dns-domain` objects) across all target domains and `"Global"`, and (3) `HybridStateReader` in `CPCRUDService.plan()` falls back to full-domain `show-hosts` / `show-networks` / `show-services-*` pagination whenever background cache warm-up has not yet completed.

## What Changes

- **Lightweight Policy Package Catalog & Targeted Single-Package Rulebase Sync (`rulebase`)**:
  - Add package-only synchronization (`refresh_policy_packages`, `DomainSyncState` slice `scope="rulebase", item_type="packages"`, `CachePort.replace_domain_package_catalog`) so `get_policy_packages(..., cache_mode="smart")` queries only `show-packages` instead of syncing every NAT, HTTPS, Threat, and Access rulebase in the domain when the full `item_type="*"` snapshot is not yet cached.
  - Add targeted per-package rulebase synchronization (`refresh_package_rulebase`, `DomainSyncState` slice `scope="rulebase", item_type="package:<rulebase_type>:<package_uid>"`, `CachePort.upsert_domain_rulebase_layers`) so `get_package_rulebase(..., rulebase_type="access", cache_mode="smart")` fetches only the selected package's ordered access layers, Global placeholder expansion, and referenced inline sub-layers — skipping NAT, HTTPS, Threat, standalone unused layers, and other packages in the domain without falsely marking `item_type="*"` as complete.
- **On-Demand Topology Object Resolution Without Bulk `show-hosts` Dumps (`gateway-topology`)**:
  - Remove the unconditional `ObjectService.refresh_objects(..., types=DEFAULT_OBJECT_TYPES, include_global=True)` barrier from `TopologyService.refresh_topology` and `stream_refresh_topology`.
  - Resolve only the actual `"specific"` interface network/group references and `vpn-domain` references present on policy-enforcing gateways (transitively expanding nested group members across the domain and `"Global"` via targeted `show-object` / `show-group` / singular `show-*` lookups when not already fresh in `arodonata_objects`) and persist resolved `CPObject` records via `CachePort.upsert_objects` without stamping whole-domain object slices as synced.
  - Add first-class `source_types` and `include_annotations` filter parameters on `find_affected_gateways` (and `ArodonataClient.find_affected_gateways`) plus lightweight `show-packages` catalog resolution when enriching gateway `policy_packages`.
- **Targeted Cold-Cache Value Lookups in `HybridStateReader` (`cpcrud`)**:
  - Update `HybridStateReader` value-conflict helpers (`find_host_by_ip`, `find_network_by_subnet`, `find_address_range_by_bounds`, `find_service_by_port`, `find_icmp_service`) so that when a domain's object/service cache slice is cold or still warming in the background, `CPCRUDService.plan()` queries Check Point `show-objects` with `type`, `filter`, and `ip-only` (verifying exact field equality in Python and merging intra-plan virtual/deleted overlays) instead of paginating full `show-hosts` / `show-networks` / `show-services-*` inventories.
  - Fall back cleanly to `list_objects_of_type` / `list_services_of_type` only if a custom `ApiPort` adapter reports `generic_err_command_not_recognized` on `show-objects`, and add `show-objects` (`type`, `filter`, `ip-only`) support to `FileReplayApiMock`.
- **Single-Flight Background Object & Service Warm-Up (`client-and-facade`)**:
  - Coalesce concurrent `ArodonataClient.start_object_cache_warmup(...)` calls per `(mgmt_name, normalized_domains, normalized_types, include_global, include_services)` flight key, log and capture background warm-up errors safely with SID redaction so fire-and-forget callers never emit unhandled task exception warnings, and expose `get_warmup_status()` plus `refresh_policy_packages` / `refresh_package_rulebase` on `ArodonataClient`.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `rulebase-and-numbering`: Add lightweight package-catalog slice sync (`item_type="packages"`) for `get_policy_packages` and targeted single-package rulebase sync (`item_type="package:<rulebase_type>:<package_uid>"`) for `get_package_rulebase` without triggering full-domain NAT/HTTPS/Threat/standalone rulebase downloads.
- `gateway-topology`: Replace bulk `DEFAULT_OBJECT_TYPES` synchronization during `refresh_topology` / `stream_refresh_topology` with on-demand resolution of gateway-referenced `"specific"` and `vpn-domain` objects/groups, and expose `source_types` and `include_annotations` filters on `find_affected_gateways`.
- `cpcrud`: Use targeted `show-objects` (`type`, `filter`, `ip-only`) queries in `HybridStateReader` value-conflict lookups during cold-cache `plan()` instead of full-domain `show-hosts` / `show-services-*` pagination.
- `client-and-facade`: Deduplicate in-flight `start_object_cache_warmup` background tasks with safe SID-redacted error handling, expose `get_warmup_status()`, and surface `refresh_policy_packages` and `refresh_package_rulebase` facade methods.

## Impact

- `src/arodonata/core/ports/__init__.py` & `src/arodonata/adapters/storage/cache_adapter.py`: Add `replace_domain_package_catalog` and `upsert_domain_rulebase_layers` to `CachePort` and `SqlCacheAdapter` (no breaking SQL table schema removals; existing `arodonata_rulebase_*` and `arodonata_domain_sync_state` tables already support slice `item_type` keys).
- `src/arodonata/rulebase/refresh.py` & `src/arodonata/rulebase/source.py`: Add lightweight `refresh_policy_packages` and targeted `refresh_package_rulebase`, wired into `CachedRulebaseSource.get_policy_packages` and `CachedRulebaseSource.get_package_rulebase`.
- `src/arodonata/core/services/topology_service.py`: Remove unconditional `DEFAULT_OBJECT_TYPES` pre-refresh, add bounded on-demand object/group tree resolution for `"specific"` and `vpn-domain` references, and add `source_types` / `include_annotations` parameters to `find_affected_gateways`.
- `src/arodonata/cpcrud/state_reader.py`: Add targeted `show-objects` filtered lookups with exact attribute verification and intra-plan virtual overlay merging.
- `src/arodonata/client.py`: Add single-flight `start_object_cache_warmup` deduplication, `get_warmup_status()`, `refresh_policy_packages()`, `refresh_package_rulebase()`, and updated `find_affected_gateways()` kwargs.
- `src/arodonata/testing/replay_mock.py`: Support `show-objects` (`type`, `filter`, `ip-only`) in `FileReplayApiMock` with call-counter tracking for cold-cache and topology tests.
- Fully backward-compatible for all existing callers (`refresh_rulebases`, `locate_rules`, `refresh_objects`, `CPCRUDService.plan`).
