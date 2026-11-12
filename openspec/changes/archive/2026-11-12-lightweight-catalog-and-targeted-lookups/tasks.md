# Tasks: Lightweight Rulebase Catalog, Targeted Topology Object Resolution, and Fast Cold-Cache CPCRUD Lookups

## 1. CachePort Slice Persistence & Lightweight Rulebase Synchronization

- [x] 1.1 Extend `CachePort` (`src/arodonata/core/ports/__init__.py`) and `SqlCacheAdapter` (`src/arodonata/adapters/storage/cache_adapter.py`) with `replace_domain_package_catalog` and `upsert_domain_rulebase_layers`, and verify unit tests pass on SQLite (`uv run pytest tests/unit -k cache`)
- [x] 1.2 Implement `RulebaseRefreshService.refresh_policy_packages` (`item_type="packages"`) and `RulebaseRefreshService.refresh_package_rulebase` (`item_type="package:<rulebase_type>:<package_uid>"`) in `src/arodonata/rulebase/refresh.py`, ensuring `verify_session_clean` and per-domain locks hold and `item_type="*"` is never stamped on partial syncs; verify with unit tests in `tests/unit/test_rulebase_refresh.py`
- [x] 1.3 Update `CachedRulebaseSource.get_policy_packages` and `CachedRulebaseSource.get_package_rulebase` (`src/arodonata/rulebase/source.py`) to use lightweight package catalog and targeted single-package sync when `item_type="*"` is not fresh (while keeping `locate_rules` gated on `item_type="*"`), and verify with unit tests asserting zero `show-nat-rulebase`, `show-https-rulebase`, `show-threat-rulebase`, or sibling-package queries on cold reads

## 2. On-Demand Topology Object Resolution & Candidate Filtering

- [x] 2.1 Remove the unconditional `ObjectService.refresh_objects(..., types=DEFAULT_OBJECT_TYPES, include_global=True)` barrier from `TopologyService.refresh_topology` and `stream_refresh_topology` (`src/arodonata/core/services/topology_service.py`), implement bounded cycle-safe BFS resolution of `"specific"` interface and `vpn-domain` objects/groups across domain and `"Global"` (`CachePort.upsert_objects(..., sync_states=None)`), and verify via `FileReplayApiMock` call-counter tests that cold `refresh_topology` executes zero `show-hosts` or `show-dns-domains` pagination while expanding nested groups containing hosts, subnets, and ranges
- [x] 2.2 Add `source_types` and `include_annotations` parameters to `TopologyService.find_affected_gateways` (and wire lightweight `refresh_policy_packages` fallback when enriching gateway `policy_packages`), and verify unit and enterprise replay topology tests pass (`uv run pytest tests/ -k topology`)

## 3. Targeted Cold-Cache CPCRUD Value Lookups & Replay Mock Support

- [x] 3.1 Add `show-objects` (`type`, `filter`, `ip-only`, pagination, and `details-level` projection) support to `FileReplayApiMock` (`src/arodonata/testing/replay_mock.py`) and verify mock unit tests cover IP, subnet, range, and port filtering
- [x] 3.2 Update `HybridStateReader` (`src/arodonata/cpcrud/state_reader.py`) value-conflict helpers (`find_host_by_ip`, `find_network_by_subnet`, `find_address_range_by_bounds`, `find_service_by_port`) to query `show-objects` with exact Python attribute verification and intra-plan virtual/deleted overlay merging when cache slices are cold (keeping single-page `show-services-icmp` / `show-services-icmp6` in `find_icmp_service`, with `generic_err_command_not_recognized` fallback and fail-closed `StateLookupError` on transport/paging errors), and verify with `tests/unit` CPCRUD planner tests asserting zero `show-hosts` / `show-services-tcp` calls on cold cache

## 4. Client Facade Single-Flight Background Warm-Up & Integration Verification

- [x] 4.1 Enhance `ArodonataClient` (`src/arodonata/client.py`) with single-flight deduplicated `start_object_cache_warmup(...)`, `get_warmup_status()`, `refresh_policy_packages(...)`, `refresh_package_rulebase(...)`, and `find_affected_gateways(..., source_types=..., include_annotations=...)`, verifying concurrent warm-up coalescing and SID-redacted fire-and-forget failure handling in `tests/unit/test_client.py`
- [x] 4.2 Run full quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, `uv run mypy src`, `uv run pytest`, and `openspec validate --specs --no-interactive`) and verify all checks pass

## Workflow follow-up

- Sync delta specs and archive `lightweight-catalog-and-targeted-lookups` once implementation and review are complete.
