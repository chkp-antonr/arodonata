# Proposal

## Why

Waves 7 and 8 closed all 54 security, correctness, and documentation-drift findings from the Deep Audit (`docs/_audit_/2611231222-deep-audit.json`), leaving 9 confirmed architectural refactoring and performance findings (`DA-046`..`DA-053`, `DA-063`). Addressing these remaining hotspots eliminates quadratic per-rule and per-object scans on the asyncio event loop, unifies three-way diverged object summary formatters that silently drop modified/dry-run attributes, and consolidates duplicated sync, session, discovery, and CPCRUD pipelines before future changes multiply drift.

## What Changes

1. **Hot-Path Performance & Unified Object Summary (`DA-046`, `DA-063`, `DA-047`)**:
   - Precompute query IP/CIDR parses, `reverse_parents` object/service group graphs, and per-token `(obj_ids, svc_ids)` match sets once in `filter_numbered_rulebase` (`src/arodonata/rulebase/filter.py`), passing them to `rule_matches_filter` via an optional parameter while preserving backward compatibility for direct callers.
   - Extract a single-pass `collect_referenced_uids()` helper in `src/arodonata/testing/_emulator_lookup.py` for O(1) membership checks in `find_unused_objects` and each fixed-point pass of `delete_unused_objects` while keeping `collect_blocking_references` for single-entity delete error diagnostics.
   - Consolidate the canonical object summary field registry and formatter into `src/arodonata/reports/_object_summary.py`, reused by `_collector_diffs.py`, `plan_report.py`, and `_renderer_formatting.py` (including `_SUMMARY_SPLIT_RE`), restoring omitted fields (`ip-protocol`, `icmp-type`, `icmp-code`, `primary-category`, `urls-defined-as-regular-expression`, `url-list`, `description`, `subnet6`, `mask-length6`, `ipv6-address-first/last`).
2. **Core Cache Sync, Search & Asset Decomposition (`DA-048`, `DA-050`)**:
   - Extract a shared generic typed cache sync and overlay helper `src/arodonata/core/services/_typed_cache_sync.py` parameterized by scope, type normalizer, model parser, command resolver, and cache callbacks; refactor `ObjectService` and `ServiceCacheService` as thin typed facades preserving exact public APIs, normalization, progress events, and `@traced` spans.
   - Decompose `src/arodonata/core/services/search_service.py` (1,841 LOC) into cohesive, acyclic submodules under `src/arodonata/core/services/search/` (`terms.py`, `resolver.py`, `finder.py`, `query.py`, `service.py`, `__init__.py`), keeping `search_service.py` as an import-compatible re-export shim preserving `SearchService`, `ClassifiedSearchTerm`, `classify_search_term`, `matches_classified_term`, `_resolve_implicit_domain_mode`, and `@traced` span names/qualnames.
   - Extract shared VSX slot-metadata parsing and bidirectional parent-child linking helpers into `src/arodonata/core/services/_asset_linking.py` (re-exported by `asset_service.py`), reused across `ClusterRelationshipManager`, `VSXRelationshipManager.enrich`, and `reconcile_cross_domain`.
3. **Domain Discovery, WriteSession, Script Execution & Route Collection (`DA-052`, `DA-049`)**:
   - Consolidate `parse_domain_entry` and `parse_domain_dict` into one canonical helper in `src/arodonata/core/models/domains.py` alongside shared MDS domain discovery in `src/arodonata/core/services/_domain_discovery.py`, re-exporting `parse_domain_entry` from `response_classifiers.py`, `sessions.py`, and `adapters/checkpoint/__init__.py` (preserving exact function identity) and `parse_domain_dict` from `domain_service.py` and `core/services/__init__.py`.
   - Add shared RBAC `details-level="standard"` fallback (preserving cached CMA IPs) to `fetch_domain_topology_from_mds` in `src/arodonata/adapters/checkpoint/target_resolver.py`.
   - Extract a shared `WriteSession` teardown/lifecycle helper in `src/arodonata/core/context.py` reused by both `open_api_write_session` and `AMgmtClient.write_session` while preserving `resolved_auth` and `session_uid`.
   - Decompose `ScriptRepositoryService.run_repository_script` (`_invoke_run_script_with_session`, `_decode_run_script_tasks`) in `src/arodonata/core/services/script_service.py` and extract cohesive target-coalescing, per-gateway persistence, and post-TaskGroup sync-state finalization helpers in `src/arodonata/core/services/topology/route_collection.py`.
4. **CPCRUD Deduplication & Decomposition (`DA-051`, `DA-053`)**:
   - Extract `_DomainPlanState` dataclass and `_record_action_outcome` in `src/arodonata/cpcrud/planner.py` (caching `_collect_ordered_steps(t)` during pass 1 so steps are not collected twice).
   - Split `compute_object_diff` into per-type helpers (`_diff_host`, `_diff_network`, `_diff_address_range`, `_diff_application_site`) and `compute_rule_diff` into `_diff_nat_rule` and `_diff_policy_rule` in `src/arodonata/cpcrud/differ.py`.
   - Consolidate shared cache/overlay/live-API lookup and listing helpers on `_HybridStateReaderBase` (`src/arodonata/cpcrud/_state_reader_common.py`), fixing the missing `item.name != name` guard in `get_service_by_name` (`_state_reader_services.py`), extract `_run_on_adopted_staged_session` in `src/arodonata/cpcrud/executor.py`, and extract `_copy_prior_fields` in `src/arodonata/cpcrud/inverse.py`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `rulebase-and-numbering`: Precomputed object/service/group index in `filter_numbered_rulebase` with exact `rule_matches_filter` parity (`REQ-RULE-008`).
- `change-reports`: Canonical object summary field schema and unified HTML/Markdown/dry-run plan formatter (`REQ-REPORT-007`).
- `cache-and-sync`: Unified typed cache sync/overlay pipeline for objects and services, decomposed `search/` package compatibility, and shared VSX/cluster relationship linking (`REQ-CACHE-018`).
- `sessions-and-mdm`: Canonical domain parser, MDS `details-level="standard"` fallback, shared `WriteSession` lifecycle helper, and decomposed script/route-collection lifecycle (`REQ-SESS-013`).
- `cpcrud`: Unified `_HybridStateReaderBase` lookup/listing with `get_service_by_name` exact-name guard, shared staged-session runner and inverse field copier, `_DomainPlanState` single-pass step caching, and split object/rule differ helpers (`REQ-CPCRUD-016`).
- `integration-testing-and-examples`: Single-pass `collect_referenced_uids` O(1) lookup in `find_unused_objects` and cascading fixed-point `delete_unused_objects` (`REQ-ITEST-020`).

## Impact

- **Source Modules**: `src/arodonata/rulebase/filter.py`, `src/arodonata/testing/_emulator_lookup.py`, `src/arodonata/reports/` (`_object_summary.py`, `_collector_diffs.py`, `_renderer_formatting.py`, `plan_report.py`), `src/arodonata/core/services/` (`_typed_cache_sync.py`, `_domain_discovery.py`, `_asset_linking.py`, `object_service.py`, `service_cache.py`, `search/`, `search_service.py`, `asset_service.py`, `script_service.py`, `domain_service.py`, `topology/route_collection.py`), `src/arodonata/core/` (`context.py`, `models/domains.py`), `src/arodonata/adapters/checkpoint/` (`response_classifiers.py`, `target_resolver.py`, `client.py`), and `src/arodonata/cpcrud/` (`planner.py`, `differ.py`, `_state_reader_common.py`, `_state_reader_objects.py`, `_state_reader_services.py`, `executor.py`, `inverse.py`).
- **Compatibility**: Preserves all public SDK entrypoints, backward-compatible re-exports (`search_service.py`, `parse_domain_entry`, `parse_domain_dict`), `@traced` span names/qualnames, `arlogi` logger names, `<= 700` LOC constraints, and hexagonal AST import boundaries (`test_architecture_boundaries.py`).
- **Breaking Changes**: None.
