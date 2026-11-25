# Proposal

## Why

Following Wave 7's hardening of foundational transport, TLS, session, storage, cache-sync, and MCP boundaries, `27` confirmed Deep-Audit findings (`DA-006`..`DA-010`, `DA-012`..`DA-015`, `DA-017`, `DA-018`, `DA-020`, `DA-026`..`DA-029`, `DA-032`..`DA-036`, `DA-038`..`DA-040`, `DA-043`, `DA-056`, `DA-062` from `docs/_audit_/2611231222-deep-audit.json`) and paired `VVAH` findings (`VVAH-CLAUDE-04`, `VVAH-CLAUDE-06`, `inverse.py`, `_executor_pass.py`, `_renderer_formatting.py`, `pager.py`) remain in the higher-level policy, reporting, rulebase, topology, and replay-emulator layers. Remediating these in a dedicated Wave 8 change closes silent policy drift, pagination truncation, HTML/Markdown rendering bypasses, cross-domain asset races, and replay-mock state corruption without mixing them into Wave 9's structural refactoring.

## What Changes

- **Declarative CPCRUD (`cpcrud`)**: Enforce per-rulebase `track` wire encoding (`access` object vs `https`/`threat` string) and `TrackSettingsForRequest` sub-field diffing (`DA-007`), unify fail-closed per-rulebase default actions (`"Drop"` / `"Inspect"` / `"Optimized"`, `DA-008`), restrict `default_any=True` away from `install-on` while rejecting empty-list `[]`/`''` replacements (`DA-013`), strip synthetic `planned:` UIDs and fix group/service-group rollback in `inverse.py` (`DA-032`, `VVAH`), hoist multi-target `Planner` tracking dicts (`DA-033`), shield staged `logout_sid` / `_register_staged_session` and verify domain-head staleness before staged publish (`DA-036`, `VVAH`), infer omitted `type` and align `operation > state > action` + `check_where_used` schema validation (`DA-039`), align `arodonata*` staged-session provenance verification (`DA-043`), pass `eff_obj_dict` into NAT/traffic-tuple helpers (`DA-056`), and remove the unconditional `return True` in `is_cleanup_rule` (`VVAH-CLAUDE-06`).
- **Change Reports (`change-reports`)**: Fail closed with empty matches + `ReportWarning` when `RangeScope` `from_session`/`to_session` UID is missing (`DA-009`), normalize prefixed `old_rule_number` in nested placement (`DA-010`), harden `render_safe_inline_markdown_md` and `_esc_md` against multiline code spans, unsafe `href`s, and CR/CRLF splits (`DA-014`, `VVAH`), verify `OwnedSession` liveness/domain with `sid=None` fallback (`DA-015`), preserve dotted string `rule_number` in `build_change_report_from_plan` (`DA-027`), and suppress order-only empty `FieldDiff`s (`DA-035`).
- **Rulebase & Numbering (`rulebase-and-numbering`)**: Continue `fetch_paged_rulebase` on zero-rule advancing pages, remove `' blade'` typo, unify fallback UIDs, and raise on truncated `total_reported` counts (`DA-038`, `VVAH`), paginate `show-*-layers` via `api.api_query` (`DA-040`), enforce post-fetch per-layer completeness before committing `status="ok"` (`VVAH-CLAUDE-04`), and record `LayerPrefixLocation` for empty/name-keyed inline and placeholder layers (`DA-010`).
- **Gateway Topology (`gateway-topology`)**: Propagate `ServerIdentityError` in `_enrich_group_raw_if_needed` (`DA-006`), defer domain-level `('topology', 'routes')` sync state until full-domain `TaskGroup` completion (`DA-012`), include `domain_name` in VSX `coalesce_key` and preserve upstream errors over `vsx_bundle_missing` (`DA-017`), unwrap list-valued Gaia/CPMI `next-hop` (`DA-018`), match spaces in `_VS_ERROR_RE` (`DA-020`), and include `disposition="manual"` prefixes in `export_topology_prefixes(include_ignored=True)` (`DA-026`).
- **Cache & Sync (`cache-and-sync`)**: Skip `_reconcile_cross_domain_vsx` during `mode="cache"` or when no domains wrote, key assets by `(mgmt_name, uid)`, and serialize cross-domain VSX reconciliation under a per-management distributed lock (`DA-034`).
- **Integration Testing & Emulator (`integration-testing-and-examples`)**: Enforce per-rulebase `track` wire types in `FileReplayApiMock` (`DA-007`), roll back failed entity/section mutations (`DA-028`), enforce `read_only` on `switch-session` / `set-session` / `discard` and rotate aliased SID bindings (`DA-029`), and lazily snapshot `_initial_domain_data` in memory before first mutation (`DA-062`).

## Capabilities

### New Capabilities

- None (`wave-8-policy-layer-remediation` updates existing capabilities only).

### Modified Capabilities

- `cpcrud`: Wire-format `track` parity, fail-closed rule defaults, `install-on` / empty-list anti-widening, `planned:` rollback & `is_cleanup_rule` accuracy, multi-target planner state, shielded staged sessions & provenance alignment (`REQ-CPCRUD-014`, `REQ-CPCRUD-015`).
- `change-reports`: Fail-closed `RangeScope` UID lookup, nested `old_rule_number` prefixing, `OwnedSession` fallback, order-only `FieldDiff` suppression, dotted `rule_number` synthesis, and safe inline Markdown/HTML escaping (`REQ-REPORT-006`).
- `rulebase-and-numbering`: Paged layer discovery, zero-rule advancing page handling, strict post-fetch completeness verification, and empty/name-keyed layer prefix preservation (`REQ-RULE-007`).
- `gateway-topology`: Fail-fast `ServerIdentityError` in group enrichment, full-domain `routes` sync-state atomicity, domain-scoped VSX coalescing, list `next-hop` unwrapping, space-safe `_VS_ERROR_RE`, and `manual` prefix export (`REQ-TOPO-021`).
- `cache-and-sync`: Lock-serialized, `(mgmt_name, uid)`-keyed cross-domain VSX reconciliation skipped on `cache` mode (`REQ-CACHE-017`).
- `integration-testing-and-examples`: Replay mock `track` wire validation, atomic entity/section mutation rollback, `switch-session` read-only/aliasing enforcement, and zero-disk-I/O in-memory reset (`REQ-ITEST-019`).

## Impact

- **Source Modules**:
  - `src/arodonata/cpcrud/` (`differ.py`, `rule_identity.py`, `_planner_helpers.py`, `_planner_diff.py`, `_planner_entity_steps.py`, `planner.py`, `validator.py`, `inverse.py`, `position_helper.py`, `executor.py`, `_executor_pass.py`, `_executor_staged.py`, `schemas/checkpoint_ops_schema.json`)
  - `src/arodonata/reports/` (`_collector_changes.py`, `_collector_diffs.py`, `collector.py`, `placement.py`, `plan_report.py`, `_renderer_formatting.py`)
  - `src/arodonata/rulebase/` (`pager.py`, `collector.py`, `refresh.py`, `numbering.py`)
  - `src/arodonata/core/services/topology/` (`objects.py`, `route_collection.py`, `route_parsers.py`, `route_executor.py`, `normalizer.py`, `scoring.py`)
  - `src/arodonata/core/services/asset_service.py`
  - `src/arodonata/testing/` (`replay_mock.py`, `_emulator_entity_crud.py`, `_emulator_rulebase_fields.py`, `_replay_sessions.py`, `_replay_dispatch.py`)
- **Tests**:
  - `tests/unit/test_cpcrud_*.py`, `tests/unit/test_change_reports.py`, `tests/unit/test_reports_plan_report.py`, `tests/unit/test_rulebase_*.py`, `tests/unit/test_topology_*.py`, `tests/unit/test_asset_service.py`, `tests/unit/test_replay_mock_*.py`, `tests/spec/test_spec_*.py`
