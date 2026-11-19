# Design: Wave 5 Domain-Engine Decomposition, Virtual Overlay Coherency, and Rulebase BFS Unification

## Context

Monolithic domain engines in `cpcrud`, `rulebase`, and `reports` accumulated multiple responsibilities inside single 1,100–2,600 LOC files while duplicating BFS layer traversal in `rulebase/refresh.py` and drifting intra-plan virtual state across `UPDATE`/`DELETE` paths in `cpcrud/planner.py` and `cpcrud/state_reader.py`.

## Goals / Non-Goals

- **Goals**:
  - Split all 6 target modules into acyclic submodules (`<= 677` LOC per file) with zero `arodonata.adapters` / `arodonata.client` imports and full backward-compatible public and test-compatibility re-exports.
  - Preserve exact `arlogi.get_logger(...)` channel names and exact `@traced` wrapper `__module__` / `__qualname__` span names.
  - Fix virtual overlay coherency across `group`, `service-group`, object, and service `UPDATE` / `DELETE` steps in `Planner` and `HybridStateReader`.
  - Deduplicate `collect_package_rulebase_slice` and `collect_domain_rulebase_snapshot` via shared `_traverse_rulebase_layers` BFS traversal without changing emitted events or snapshot data.
- **Non-Goals**:
  - Altering public API method signatures, schema contracts (`checkpoint_ops_schema.json`), or OpenTelemetry span names.

## Decisions

1. **Cohesive Acyclic Submodule Splits**: Keep top-level public classes and `@traced` entry points (`Planner.decide`, `Executor.apply`/`publish_staged_session`/`discard_staged_session`, `RulebaseRefreshService.*`, `collect_change_report`, `render_change_report`/`build_change_report`) defined in their canonical modules while extracting helper layers underneath them (`_state_reader_*`, `_planner_*`, `_executor_*`, `rulebase/collector.py`, `_collector_*`, `_renderer_*`).
2. **Unified Virtual Overlay Mutation & Overlay Reconciliation**: Delegate both `group` and `service-group` update paths through `_plan_existing_object_diff` / `_plan_existing_service_diff`, synchronize full `CPObject` / `CPService` fields and `raw_data` via `_apply_object_update_to_model` / `_apply_service_update_to_model` and `_compute_post_update_members`, resolve wire selectors with `_entity_wire_identity` so `CREATE -> UPDATE`/`DELETE` never emit `planned:` UIDs, and reconcile cache/live single-entity reads through `_apply_fetched_entity_overlay`.
3. **Parameterized Rulebase BFS Traversal**: Centralize layer deduplication, parent-link backfilling, `fetch_paged_rulebase`, unresolved Global `place-holder` package-context re-fetch, inline access/HTTPS layer queuing, and `DomainSyncProgressEvent` emission inside `_traverse_rulebase_layers` in `arodonata.rulebase.collector`.
