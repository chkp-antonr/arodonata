# Proposal

## Why

Downstream automation pipelines (such as MMP `tasks/decom`) follow a strict single-session post-publish audit workflow:

1. Mutate rules and objects inside a dedicated Check Point session (`sid`).
2. Call `publish` on `sid` so the session transitions to `state="published"` with an authoritative `publish-time`.
3. Collect auditable `ChangeReport` evidence immediately **while `sid` is still authenticated** (avoiding an extra login/logout cycle).
4. Call `logout` on `sid`.

Currently, `arodonata.reports` breaks down in four ways during this workflow:

1. **Post-publish `OwnedSession` rejection**: In Check Point Management API, calling `publish` keeps `sid` authenticated in the same domain while rotating the working session to a new clean open session (`changes == 0`, `live_uid != session_uid`), while the target `session_uid` becomes `published`. `apply_session_rule_placement()` treats `live_uid != session_uid` or `live_state == "published"` as an error, emits an `owned_session_not_used` warning, refuses to read the published rulebase via `sid`, and falls back to the SQLite rulebase cache.
2. **Spurious `(unavailable)` banner on object-only sessions**: When a session modifies or deletes only objects (`rule_changes == []`), `apply_session_rule_placement()` still queries `show-session` and `cache.get_domain_rulebase()`, and `render_change_report()` unconditionally renders `<div class="basis-banner">Numbering from cached rulebase snapshot (unavailable)</div>` (HTML) and `- **Numbering Basis**: ...` (Markdown) even though no rule table exists.
3. **Cold-cache failure (`(unavailable)` and `—` rule numbers)**: When `rule_changes` is non-empty and the local `arodonata_rulebase_*` SQL cache has not yet been warmed via `refresh_rulebases()`, `apply_session_rule_placement()` gives up instead of reading the published rulebase on-demand via `ApiPort` and warming the cache, leaving `#` as `—` and `Layer / Section` unnumbered.
4. **Unresolved bare layer UIDs**: When `show-changes` returns a rule's `layer` as a bare UUID string without an inline name and rulebase placement is unavailable, `collector.py` does not include `rc.layer_uid` in bounded `show-object` / cache UID name resolution, leaving a raw UUID in the rendered `Layer / Section` column.

## What Changes

- **Post-Publish Clean `OwnedSession` Reuse**:
  - Update `apply_session_rule_placement()` (`src/arodonata/reports/placement.py`) to accept an `OwnedSession` after `publish` (before `logout`) when the target `session_report` is already published (`state == "published"` or `published_at is not None`) and `show-session` on `owned_session.sid` confirms a live, non-discarded session with zero uncommitted edits (`changes == 0` when `live_uid != session_uid`).
  - Read the published rulebase snapshot live through `owned_session.sid`, assign SmartConsole rule numbers and package/layer/section metadata, best-effort persist the snapshot via `cache.replace_domain_rulebase(live_snapshot)`, set `numbering_source = "live_published"` and `numbering_basis = "Numbering read live after publish at <YYYY-MM-DD HH:MM:SS> UTC"`, and emit zero `owned_session_not_used` warnings.
  - Continue emitting `owned_session_not_used` when `live_state == "discarded"`, when the target session is unpublished and `live_uid != session_uid`, or when `live_uid != session_uid` holds dirty uncommitted changes (`changes > 0`) from another session.
- **Skip Placement & Omit Basis Banner for Object-Only Sessions**:
  - Short-circuit `apply_session_rule_placement()` immediately when `not session_report.rule_changes`, setting `numbering_source = "not_applicable"` and `numbering_basis = ""` without issuing API or cache queries.
  - Update HTML and Markdown renderers (`src/arodonata/reports/renderer.py`) to emit `.basis-banner` / `- **Numbering Basis**:` only when `s.rule_changes` is non-empty and `s.numbering_basis` is non-empty.
- **Cold-Cache On-Demand Live Rulebase Fallback & Cache Warming**:
  - When `session_report.rule_changes` is non-empty, no usable `OwnedSession` handled placement, and `cache.get_domain_rulebase(mgmt_name, domain_name)` has no cached rules/layers, attempt a read-only `collect_domain_rulebase_snapshot(api, mgmt_name, domain_name)`. If non-empty, apply rule placement, best-effort warm `cache.replace_domain_rulebase(live_snapshot)`, and set `numbering_source = "live_published"` and `numbering_basis = "Numbering read live from published rulebase at <YYYY-MM-DD HH:MM:SS> UTC"`. Fall back to `unnumbered` / `"Numbering from cached rulebase snapshot (unavailable)"` only if the live fetch fails or returns empty.
- **Bare Layer UID Name Resolution**:
  - Update `_parse_rule_and_object_changes()` and `_replace_resolved_uids_in_session()` (`src/arodonata/reports/collector.py`) so bare UUID `layer_uid` values on `RuleChangeEntry` (when `layer_name` is empty) participate in cache + bounded `show-object` UID resolution and populate `rc.layer_name`.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `change-reports`: Support post-publish clean `OwnedSession` rulebase numbering without spurious warnings, skip rulebase placement and suppress numbering banners on object-only sessions, fall back to on-demand live published rulebase collection (with best-effort cache warming) when the local rulebase cache is cold, and resolve bare rule `layer_uid` references via cache and bounded `show-object` lookups.

## Impact

- **Report Models (`src/arodonata/reports/models.py`)**: `SessionChangeReport.numbering_source` widens from `Literal["owned_session", "cache", "unnumbered"]` to `Literal["owned_session", "live_published", "cache", "unnumbered", "not_applicable"]` (fully backward-compatible with `format_version = 1` JSON payloads).
- **Collector & Placement (`src/arodonata/reports/collector.py`, `src/arodonata/reports/placement.py`)**: Smarter `OwnedSession` state classification, zero-rule short-circuit, cold-cache live fallback + `replace_domain_rulebase` cache warming, and bare `layer_uid` resolution.
- **Renderer (`src/arodonata/reports/renderer.py`)**: Suppresses `.basis-banner` and `- **Numbering Basis**:` when a session has no `rule_changes`.
- **Tests (`tests/unit/test_change_reports.py`)**: Updated and expanded unit tests covering post-publish `OwnedSession`, dirty unrelated `OwnedSession`, object-only sessions, cold-cache live fallback, and bare `layer_uid` resolution.
