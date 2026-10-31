# Change Reports Delta Specification

## ADDED Requirements

### Requirement: Snapshot-Based Field Diff Synthesis and System Noise Filtering

When collecting modified rules and objects from `show-changes`, the collector SHALL synthesize `FieldDiff` entries (`old_value`, `new_value`, `added_items`, `removed_items`) from `old-object` and `new-object` snapshots for any changed tracked fields not already covered by explicit `field-changes`, enrich object summaries, and omit background `"System"` maintenance non-rule objects unless `RenderOptions.include_system_objects` is `True`.

#### Scenario: Rule list cell partial removal and sole-member Any replacement

- **WHEN** `show-changes` returns a modified rule with `old-object` and `new-object` snapshots and no explicit `field-changes` (either removing one or more objects from a multi-item list field such as `source`, `destination`, or `service`, or replacing the sole remaining object with `Any` and disabling the rule)
- **THEN** the collector SHALL populate `RuleChangeEntry.field_diffs` with the removed object names in `removed_items` (and `Any` in `added_items` when replaced by `Any`), record scalar diffs such as `enabled` and `comments`, and NOT report false-positive cell diffs when an unchanged referenced group has internal member edits

#### Scenario: Explicit field-changes merge cleanly with snapshot diffs

- **WHEN** a `modified-objects` entry provides explicit `field-changes` covering a subset of modified fields alongside `old-object` and `new-object` snapshots with additional changed fields
- **THEN** the collector SHALL preserve the explicit `field-changes` entries and append synthesized `FieldDiff` entries only for changed tracked fields not already present in `field-changes`

#### Scenario: Non-rule object member diffs and enriched object summaries

- **WHEN** `show-changes` returns modified, added, or deleted non-rule objects (including `group`, `host`, `network`, `address-range`, and `service-*`)
- **THEN** the collector SHALL compute `FieldDiff` entries (including `added_items` and `removed_items` for `members`, and before/after values for `comments` and address/service attributes) and populate `ObjectChangeEntry.summary` with IPv4/IPv6 addresses, CIDR subnets, address-range bounds, service ports/protocols, resolved `members`, and `comments`

#### Scenario: Background Check Point System maintenance objects excluded by default

- **WHEN** `show-changes` for a non-`"System"` user session includes non-rule objects whose `meta-info.last-modifier` is `"System"` (or nameless/typeless internal `"System"` records such as `IpsProtectionUserSettings`, `cp-trusted-ca-certificate`, or `TrustedCaPackageConf`)
- **THEN** the collector SHALL exclude those `"System"` non-rule entries from `SessionChangeReport.object_changes` by default (including them when `RenderOptions.include_system_objects` is `True`) while preserving the complete sanitized `show-changes` payload in `ChangeReport.raw_responses`

## MODIFIED Requirements

### Requirement: Scope Validation and Read-Only Change Collection

`collect_change_report(api, cache, scopes, ...)` SHALL validate `SessionScope` and `RangeScope` inputs strictly (raising `pydantic.ValidationError` or `ChangeReportInputError` on invalid bounds or naive datetimes), bind unkeyed `OwnedSession` instances only to single-session scopes, query `show-changes` strictly read-only without directly mutating `CachePort` tables, deduplicate sessions, and record partial runtime failures as `ReportWarning` entries.

#### Scenario: Single-session change collection via to-session query and container filtering

- **WHEN** a `SessionScope` requests changes for explicit `session_uids`
- **THEN** the collector SHALL call `show-changes` with `{"to-session": s_uid, "details-level": "full"}` (omitting `from-session: s_uid` because `from-session` is exclusive in Check Point `show-changes`), filter the returned `changes[]` containers to the matching `session-uid`, and classify `modified-objects` entries that contain `new-object` without `old-object` as `"added"`

#### Scenario: Timezone-aware date range conversion and exact publish-time filtering

- **WHEN** a `RangeScope` includes timezone-aware `from_date` and/or `to_date`
- **THEN** the collector SHALL convert the bounds to the server's UTC offset, widen the server query window safely (or omit server date parameters when `from_session` is also given), and filter returned sessions by exact UTC publish timestamp

#### Scenario: Reference UID name resolution with bounded show-object lookups

- **WHEN** `show-changes` returns bare UIDs in either `new-object` or `old-object` snapshots (including removed `group.members` UUIDs, removed rule cell references, rule layers `layer`, or NAT fields) not already named in the session's own change entries or nested `{uid, name}` dictionaries
- **THEN** the collector SHALL recursively index nested `{uid, name}` dictionaries across `old-object` and `new-object`, resolve up to 200 distinct remaining bare UIDs per report (checking local cache first, then read-only `show-object` calls), substitute resolved names into rule fields, object summaries, and `FieldDiff` values (`old_value`, `new_value`, `added_items`, `removed_items`), populate `RuleChangeEntry.layer_name` when `layer_uid` resolves to a named layer, and emit a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails

#### Scenario: Multi-session scope does not bind an unkeyed OwnedSession across multiple sessions

- **WHEN** a `SessionScope` lists more than one UID in `session_uids` and supplies a bare `OwnedSession` whose `session_uid` is `None` or empty (or an `OwnedSession` whose explicit `mgmt_name` or `domain` disagrees with the scope)
- **THEN** `SessionScope.resolve_owned_session` SHALL NOT match that unkeyed or mismatched `OwnedSession` to arbitrary sessions in the scope

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: Self-contained HTML evidence output

- **WHEN** `"html"` is requested in `formats`
- **THEN** `render_change_report` SHALL produce a single self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, zero external network assets, SmartConsole-styled dark-blue table headers (`#253245` with white text), full-width pale-yellow access section banner rows (`<tr class="section-row">` on `#eee8aa` background displaying `▾ <section_name> (<section_range>)` and layer context), shaded gray `No.` rule-number cells (`.col-num`), visual change indicators (`NEW`, `DELETED`, `MODIFIED`, `MOVED` badges, disabled `✗` markers, and `Accept`/`Drop` action indicators), inline cell-level diff annotations inside `Rule Changes` and `Object Changes` rows showing removed items (`- <name>` struck-through), added/replacement items (`+ <name>`), and scalar `before → after` transitions, and optional per-rule/per-object `Field Diffs` detail tables when `RenderOptions.include_field_diffs` is `True`

#### Scenario: Inline diff markers in Markdown rule and object tables

- **WHEN** `"markdown"` is requested in `formats` for a report containing modified rules or modified objects with `field_diffs`
- **THEN** `render_change_report` SHALL render removed items (`[-<name>]`), added/replacement items (`[+<name>]`), and scalar `before -> after` transitions inline inside the Markdown `Rule Changes` and `Object Changes` table cells while escaping pipe characters, newlines, and raw HTML tags

#### Scenario: Round-trip JSON serialization with format_version check

- **WHEN** a `ChangeReport` is serialized to `"json"` and reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access, and reject JSON files whose `format_version` is newer than supported by the installed library
