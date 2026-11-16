# Spec Delta

## ADDED Requirements

### Requirement: Offline Dry-Run ChangeReport Synthesis from CPCRUD Plan

`arodonata.reports` SHALL provide `build_change_report_from_plan(plan, ...)` to convert a CPCRUD `Plan` offline into a `ChangeReport` compatible with `render_change_report()`, capturing object, group, and rule creates, deletes, and field-level add/remove diffs without opening Check Point sessions.

#### Scenario: Dry-run ChangeReport renders HTML and JSON offline with added and removed item diffs

- **WHEN** a caller passes a multi-action `Plan` containing object creates (`Outcome.CREATE`), group member deltas (`Outcome.UPDATE` with `add`/`remove`), and incremental rule cell diffs (`Outcome.UPDATE` on `source`/`destination`/`service`) to `build_change_report_from_plan(plan)` and renders it via `render_change_report(report, formats=["html", "json"])`
- **THEN** `build_change_report_from_plan` SHALL produce a valid `ChangeReport` with zero Check Point API calls, populate `ObjectChangeEntry.field_diffs` and `RuleChangeEntry.field_diffs` (`added_items` and `removed_items`), and render self-contained SmartConsole-styled HTML and round-trippable JSON containing no SIDs or errors
