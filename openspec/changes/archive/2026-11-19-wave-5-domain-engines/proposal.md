# Proposal: Wave 5 Domain-Engine Decomposition, Virtual Overlay Coherency, and Rulebase BFS Unification

## Why

Six core domain-engine modules across `cpcrud`, `rulebase`, and `reports` had grown well past single-responsibility boundaries (`planner.py` at 2,576 LOC, `executor.py` at 1,655 LOC, `collector.py` at 1,414 LOC, `refresh.py` at 1,347 LOC, `renderer.py` at 1,176 LOC, and `state_reader.py` at 1,133 LOC), and an audit uncovered two defects inside them:

- **CPCRUD virtual overlay drift (`planner.py` / `state_reader.py`)**: `Planner._plan_group_step` recorded created `group` and `service-group` models into `HybridStateReader`'s virtual overlay on `Outcome.CREATE` but omitted virtual overlay updates on `Outcome.UPDATE`, while object/service updates left `raw_data`, `members`, `protocol`, `icmp_type`/`icmp_code`, and `planned:` wire selectors out of sync for subsequent dependent steps in the same template.
- **Duplicated BFS layer traversal (`rulebase/refresh.py`)**: `collect_package_rulebase_slice` and `collect_domain_rulebase_snapshot` duplicated the ~150-LOC BFS `layer_queue` loop handling inline layers, Global `place-holder` resolution, package-context re-fetches, and `DomainSyncProgressEvent` emission.

## What Changes

- Decompose all six oversized domain-engine modules into cohesive, acyclic submodules (`<= 677` LOC each) while preserving exact backward-compatible re-exports, `arlogi.get_logger(...)` channel names, and 1-to-1 `@traced` span names/signatures:
  - `src/arodonata/cpcrud/state_reader.py` → `_state_reader_common.py`, `_state_reader_objects.py`, `_state_reader_services.py`, `state_reader.py`.
  - `src/arodonata/cpcrud/planner.py` → `_planner_helpers.py`, `_planner_diff.py`, `_planner_entity_steps.py`, `_planner_rule_steps.py`, `planner.py`.
  - `src/arodonata/cpcrud/executor.py` → `_executor_helpers.py`, `_executor_pass.py`, `_executor_staged.py`, `executor.py`.
  - `src/arodonata/rulebase/refresh.py` → `collector.py`, `refresh.py`.
  - `src/arodonata/reports/collector.py` → `_collector_diffs.py`, `_collector_changes.py`, `collector.py`.
  - `src/arodonata/reports/renderer.py` → `_renderer_formatting.py`, `_renderer_html.py`, `_renderer_markdown.py`, `renderer.py`.
- Fix intra-plan virtual overlay coherency across `group`, `service-group`, network object, and service `CREATE`, `UPDATE`, rename, and `DELETE` paths (including `dns-domain` leading-dot overlay reconciliation, `raw_data` member/attribute synchronization, wire identity resolution avoiding `planned:` UIDs, and `res_map` pruning on delete).
- Extract shared `_traverse_rulebase_layers` BFS engine and `_fetch_nat_package_rules` in `src/arodonata/rulebase/collector.py` so `collect_package_rulebase_slice` and `collect_domain_rulebase_snapshot` share one canonical traversal implementation.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `cpcrud`: Specify intra-plan virtual overlay coherency across same-template updates, renames, and deletions under `REQ-CPCRUD-003` (`SCN-CPCRUD-003-6`).

## Impact

- `src/arodonata/cpcrud/`, `src/arodonata/rulebase/`, and `src/arodonata/reports/`.
- `openspec/specs/cpcrud/spec.md`, `tests/unit/test_wave5_domain_engines.py`, and `CHANGELOG.md`.
