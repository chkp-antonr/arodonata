# Tasks: Wave 5 Domain-Engine Decomposition, Virtual Overlay Coherency, and Rulebase BFS Unification

## 1. CPCRUD Decomposition & Virtual Overlay Coherency

- [x] 1.1 Decompose `src/arodonata/cpcrud/state_reader.py` into `_state_reader_common.py`, `_state_reader_objects.py`, `_state_reader_services.py`, and `state_reader.py` with `_apply_fetched_entity_overlay` and leading-dot `dns-domain` virtual overlay lookup.
- [x] 1.2 Decompose `src/arodonata/cpcrud/planner.py` into `_planner_helpers.py`, `_planner_diff.py`, `_planner_entity_steps.py`, `_planner_rule_steps.py`, and `planner.py`, fixing `group`/`service-group`/`object`/`service` `UPDATE` and `DELETE` virtual overlay coherency, `planned:` wire selector avoidance, and `res_map` pruning.
- [x] 1.3 Decompose `src/arodonata/cpcrud/executor.py` into `_executor_helpers.py`, `_executor_pass.py`, `_executor_staged.py`, and `executor.py` preserving `@traced` methods and `_staged_sessions` LRU tracking.

## 2. Rulebase & Reports Decomposition & DRY Unification

- [x] 2.1 Extract `src/arodonata/rulebase/collector.py` from `refresh.py` and unify `collect_package_rulebase_slice` and `collect_domain_rulebase_snapshot` over `_traverse_rulebase_layers` and `_fetch_nat_package_rules`.
- [x] 2.2 Decompose `src/arodonata/reports/collector.py` into `_collector_diffs.py`, `_collector_changes.py`, and `collector.py` preserving `logger = arlogi.get_logger(__name__)` and `@traced collect_change_report`.
- [x] 2.3 Decompose `src/arodonata/reports/renderer.py` into `_renderer_formatting.py`, `_renderer_html.py`, `_renderer_markdown.py`, and `renderer.py` preserving `@traced render_change_report` and `@traced build_change_report`.

## 3. OpenSpec SDD, Regression Tests & Quality Gates

- [x] 3.1 Update `openspec/specs/cpcrud/spec.md` (`REQ-CPCRUD-003` / `SCN-CPCRUD-003-6`), archive `openspec/changes/archive/2026-11-19-wave-5-domain-engines/`, and update `CHANGELOG.md`.
- [x] 3.2 Add regression tests in `tests/unit/test_wave5_domain_engines.py` covering virtual overlay coherency, shared rulebase BFS parity, re-exports, logger identity, `@traced` parity, and LOC limits, and pass all 9 quality gates plus cold-import checks.
