# Tasks

## 1. Snapshot Field Diff Synthesis, Old-Object UID Resolution, and System Noise Filtering

- [x] 1.1 Add `include_system_objects: bool = False` to `RenderOptions` in `src/arodonata/reports/models.py` while keeping `CURRENT_FORMAT_VERSION = 1`, and verify type safety with `uv run mypy src/arodonata/reports/models.py`.
- [x] 1.2 Extend `_collect_known_names_from_operations()` and `_parse_rule_and_object_changes()` in `src/arodonata/reports/collector.py` to recursively index nested `{uid, name}` dictionaries across `old-object` and `new-object` and synthesize `FieldDiff` entries (`old_value`, `new_value`, `added_items`, `removed_items`) for modified rules and non-rule objects when explicit `field-changes` are absent or partial, and verify with unit tests in `tests/unit/test_change_reports.py` covering partial rule cell removal, sole-member replacement with `Any` + rule disable, NAT leg updates, explicit `field-changes` merging, and zero false-positive rule diffs when an unchanged referenced group has internal member edits.
- [x] 1.3 Ensure bare UUIDs appearing only in `old-object` (including removed `group.members` UUIDs and removed rule references) resolve via `CachePort` and bounded `show-object` lookups, enrich `ObjectChangeEntry.summary` (IPv6, CIDR masks, `address-range` bounds, `comments`), and filter background Check Point `"System"` maintenance non-rule objects unless `RenderOptions.include_system_objects=True` while preserving `raw_responses`, verifying with unit tests via `uv run pytest tests/unit/test_change_reports.py`.

## 2. Inline HTML and Markdown Cell Diff Rendering

- [x] 2.1 Add self-contained inline diff CSS classes (`.diff-removed`, `.diff-added`, `.diff-arrow`), SmartConsole visual table styling (dark-blue `#253245` headers, full-width pale-yellow `#eee8aa` access section banner rows `tr.section-row`, gray `.col-num` cells, `Track` column, and action indicators), and cell-level HTML diff helpers in `src/arodonata/reports/renderer.py` so `Rule Changes` and `Object Changes` cells display removed items (`- name` struck-through), added/replacement items (`+ name`), and scalar `before → after` transitions inline with strict HTML escaping and zero `<script>` tags, and verify with HTML rendering and XSS-escaping unit tests in `tests/unit/test_change_reports.py`.
- [x] 2.2 Update `_render_markdown_document()` in `src/arodonata/reports/renderer.py` to render matching inline diff markers (`[-name]`, `[+name]`, and `old -> new`) inside Markdown `Rule Changes` and `Object Changes` table cells with pipe/newline/HTML escaping and identical JSON round-trip re-rendering, and verify via `uv run pytest tests/unit/test_change_reports.py`.

## 3. End-to-End Integration and Quality Gate Verification

- [x] 3.1 Extend `tests/integration/b5/test_change_report_session.py` to modify a rule cell and group membership in a live Check Point session and assert that synthesized `field_diffs` and inline HTML/Markdown diff markers surface the removed object (with baseline revert on teardown), verifying via `uv run pytest tests/integration/b5/test_change_report_session.py` against the lab environment.
- [x] 3.2 Run full repository quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest tests/unit`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, and `openspec validate "improve-change-report-object-and-rule-diffs" --strict --no-interactive`) and verify all commands exit `0`.

## Workflow follow-up

- Archive the change via `openspec archive` after implementation and review are complete.
- Verify downstream MMP Decom evidence HTML and email reports against `libs/arodonata` to confirm removed and `Any`-replaced decommissioned objects render inline.
