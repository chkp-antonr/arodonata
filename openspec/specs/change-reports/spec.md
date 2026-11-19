# Auditable Session Change Report Specification

## Purpose

Defines read-only collection (`collect_change_report`), rulebase placement numbering (`apply_session_rule_placement`), dry-run CPCRUD plan conversion (`build_change_report_from_plan`), and multi-format rendering (`render_change_report`, `build_change_report`) of Check Point policy session change evidence (`ChangeReport`) across explicit session UIDs (`SessionScope`) and published session/date ranges (`RangeScope`).

## Requirements

### Requirement: Scope Validation and Read-Only Change Collection

**ID**: REQ-REPORT-001\
**Intent**: Collect auditable Check Point session change evidence safely in read-only mode while bounding UID resolution calls and validating scopes.\
**Non-goals**: Synthesizing field diffs or filtering background `"System"` maintenance noise (`REQ-REPORT-002`).

`collect_change_report(api, cache, scopes, ...)` SHALL validate `SessionScope` and `RangeScope` inputs strictly (raising `pydantic.ValidationError` or `ChangeReportInputError` on invalid bounds or naive datetimes), bind unkeyed `OwnedSession` only to single-session scopes, query `show-changes` strictly read-only without mutating `CachePort` tables, deduplicate sessions, and record partial failures as `ReportWarning` entries.

#### Scenario: SCN-REPORT-001-1 — Single-session change collection via to-session query and container filtering

- **GIVEN** a `SessionScope` requesting changes for explicit `session_uids`
- **WHEN** `collect_change_report` queries Check Point `show-changes`
- **THEN** it SHALL pass `{"to-session": s_uid, "details-level": "full"}` (omitting `from-session: s_uid` because `from-session` is exclusive in Check Point)
- **AND** it SHALL filter returned `changes[]` containers to the matching `session-uid`
- **AND** it SHALL classify `modified-objects` entries containing `new-object` without `old-object` as `"added"`

#### Scenario: SCN-REPORT-001-2 — Timezone-aware date range conversion and exact publish-time filtering

- **GIVEN** a `RangeScope` with timezone-aware `from_date` and/or `to_date`
- **WHEN** `collect_change_report` queries published sessions in the range
- **THEN** it SHALL convert bounds to the server's UTC offset and widen the server query window safely (or omit server date parameters when `from_session` is also given)
- **AND** it SHALL filter returned sessions by exact UTC publish timestamp

#### Scenario: SCN-REPORT-001-3 — Reference UID name resolution with bounded show-object lookups

- **GIVEN** `show-changes` returning bare UIDs in `new-object` or `old-object` snapshots (including removed `group.members`, removed rule cell references, `layer`, or NAT fields) not yet named
- **WHEN** `collect_change_report` resolves referenced object names
- **THEN** it SHALL recursively index nested `{uid, name}` dictionaries across `old-object` and `new-object`
- **AND** it SHALL resolve up to `200` (`MAX_UID_LOOKUPS`) distinct remaining bare UIDs per report via cache first and read-only `show-object` calls second
- **AND** it SHALL substitute resolved names into rule fields, object summaries, `FieldDiff` values (`old_value`, `new_value`, `added_items`, `removed_items`), and `RuleChangeEntry.layer_name` (when `layer_uid` resolves)
- **AND** it SHALL emit a `names_unresolved` `ReportWarning` if the lookup cap is exceeded or a lookup fails

#### Scenario: SCN-REPORT-001-4 — Multi-session scope does not bind an unkeyed OwnedSession across multiple sessions

- **GIVEN** a `SessionScope` listing multiple UIDs in `session_uids` with an unkeyed `OwnedSession` (`session_uid` empty/`None`), or an `OwnedSession` whose `mgmt_name`/`domain` disagrees with the scope
- **WHEN** `SessionScope.resolve_owned_session` resolves the owned session for a target session
- **THEN** it SHALL NOT match that unkeyed or mismatched `OwnedSession` to arbitrary sessions in the scope

### Requirement: Snapshot-Based Field Diff Synthesis and System Noise Filtering

**ID**: REQ-REPORT-002\
**Intent**: Provide accurate rule and object diffs from `show-changes` snapshots while hiding noisy `"System"` maintenance records by default.\
**Non-goals**: Live or cached rulebase numbering (`REQ-REPORT-003`) or output format rendering (`REQ-REPORT-005`).

When collecting modified rules and objects from `show-changes`, the collector SHALL synthesize `FieldDiff` entries (`old_value`, `new_value`, `added_items`, `removed_items`) from `old-object` and `new-object` snapshots for any changed tracked fields not already covered by explicit `field-changes`, enrich object summaries, and omit background `"System"` maintenance non-rule objects unless `RenderOptions.include_system_objects` is `True`.

#### Scenario: SCN-REPORT-002-1 — Rule list cell partial removal and sole-member Any replacement

- **GIVEN** `show-changes` returning a modified rule with `old-object` and `new-object` snapshots and no explicit `field-changes`
- **WHEN** items are removed from a multi-item list field (`source`, `destination`, `service`), or a sole remaining member is replaced with `Any` alongside disabling the rule
- **THEN** `RuleChangeEntry.field_diffs` SHALL populate `removed_items` (and `Any` in `added_items` when replaced by `Any`) plus scalar diffs (`enabled`, `comments`)
- **AND** it SHALL NOT report false-positive cell diffs when an unchanged referenced group has internal member edits

#### Scenario: SCN-REPORT-002-2 — Explicit field-changes merge cleanly with snapshot diffs

- **GIVEN** a `modified-objects` entry providing explicit `field-changes` for a subset of modified fields alongside `old-object` and `new-object` snapshots with additional changed fields
- **WHEN** the collector builds `field_diffs`
- **THEN** it SHALL preserve explicit `field-changes` entries and append synthesized `FieldDiff` entries only for changed tracked fields absent from `field-changes`

#### Scenario: SCN-REPORT-002-3 — Non-rule object member diffs and enriched object summaries

- **GIVEN** `show-changes` returning modified, added, or deleted non-rule objects (`group`, `host`, `network`, `address-range`, `service-*`)
- **WHEN** the collector processes those entries
- **THEN** it SHALL compute `FieldDiff` entries (`added_items`/`removed_items` for `members`, and before/after values for `comments` and address/service attributes)
- **AND** it SHALL populate `ObjectChangeEntry.summary_fields` and `summary` with IPv4/IPv6 addresses, CIDR subnets, ranges, service ports/protocols, resolved `members`, and `comments`

#### Scenario: SCN-REPORT-002-4 — Background Check Point System maintenance objects excluded by default

- **GIVEN** a non-`"System"` user session whose `show-changes` includes non-deleted (`added`/`modified`) non-rule objects with post-change `meta-info.last-modifier == "System"`
- **AND** internal records such as `IpsProtectionUserSettings`, `cp-trusted-ca-certificate`, or `TrustedCaPackageConf`
- **WHEN** the collector builds `SessionChangeReport.object_changes`
- **THEN** it SHALL exclude those `"System"` non-rule entries by default without emitting a `ReportWarning` (logging the filtered count at `DEBUG`)
- **AND** it SHALL never exclude `deleted` objects or filter by `old-object.meta-info.last-modifier`, and SHALL include them when `RenderOptions.include_system_objects` is `True`
- **AND** it SHALL preserve the complete sanitized `show-changes` payload in `ChangeReport.raw_responses`

### Requirement: Owned Session Live Numbering and Cached Snapshot Fallback

**ID**: REQ-REPORT-003\
**Intent**: Attach SmartConsole-accurate rule numbers to change reports without ever leaking SIDs or performing unsafe cache writes.\
**Non-goals**: Coordinator-managed rulebase cache synchronization (`REQ-CACHE-012`, `REQ-CLIENT-013`).

The change report builder SHALL number added, modified, moved, and deleted rules according to SmartConsole hierarchy using a verified `OwnedSession` in-memory snapshot, the domain's cached rulebase snapshot, or a coordinator-delegated / in-memory published rulebase fallback when the cache is cold, skipping placement for object-only sessions and NEVER calling `CachePort.replace_domain_rulebase` directly from `arodonata.reports`.

#### Scenario: SCN-REPORT-003-1 — Object-only session skips rulebase placement and omits numbering banner

- **GIVEN** a `SessionChangeReport` containing zero `rule_changes`
- **WHEN** `apply_session_rule_placement` runs
- **THEN** it SHALL return immediately without calling `show-session`, `collect_domain_rulebase_snapshot`, or `CachePort.get_domain_rulebase`
- **AND** it SHALL set `numbering_source = "not_applicable"` and `numbering_basis = ""`, and HTML/Markdown output SHALL omit the numbering basis banner/line

#### Scenario: SCN-REPORT-003-2 — Read-only live numbering via OwnedSession with strict SID hygiene

- **GIVEN** a `SessionScope` supplying an `OwnedSession` matching an unpublished session with rule changes
- **WHEN** `apply_session_rule_placement` verifies ownership and domain via `show-session`
- **THEN** it SHALL read `show-packages` and `show-*-rulebase` strictly read-only into memory without publishing, discarding, logging out, or calling `CachePort` writes
- **AND** it SHALL label the session `"Numbering read live in the owned session at <time> UTC"` (`numbering_source = "owned_session"`)
- **AND** it SHALL NEVER include or log the `sid` in `ChangeReport`, `RawResponse`, HTML, JSON, Markdown, or `repr()`

#### Scenario: SCN-REPORT-003-3 — Post-publish live numbering via clean OwnedSession before logout

- **GIVEN** a `SessionScope` supplying an `OwnedSession` bound to an already-published session (`session_uid` or single-session scope, matching `mgmt_name`/`domain`)
- **AND** `show-session` confirms a non-discarded session on the expected domain with `changes == 0`, `locks == 0`, and `number-of-published-changes == 0`
- **WHEN** `apply_session_rule_placement` numbers the session's rules
- **THEN** it SHALL read the published rulebase live in memory without calling `CachePort.replace_domain_rulebase` or emitting `owned_session_not_used`
- **AND** it SHALL set `numbering_source = "live_published"` and basis `"Numbering read live after publish at <time> UTC"`

#### Scenario: SCN-REPORT-003-4 — Graceful fallback when OwnedSession is already published or expired

- **GIVEN** an `OwnedSession` that fails `show-session`, is `discarded`, targets a different domain, omits `changes`/`locks`, reports non-zero activity on a post-publish session, or mismatches an unpublished UID
- **WHEN** `apply_session_rule_placement` runs
- **THEN** it SHALL record an `owned_session_not_used` or `owned_session_error` warning
- **AND** it SHALL fall back to numbering from the domain's cached rulebase snapshot (or cold-cache fallback)

#### Scenario: SCN-REPORT-003-5 — Cold-cache on-demand live published rulebase fallback

- **GIVEN** a session with rule changes where no usable `OwnedSession` handled numbering and `CachePort.get_domain_rulebase` is empty
- **WHEN** invoked via `ArodonataClient`
- **THEN** `ArodonataClient` SHALL delegate cache warming to `RulebaseRefreshService` / `DomainSyncCoordinator` (enforcing distributed locks and `DomainSyncState` stamps) before reading cache
- **AND** when called standalone without coordinator warming (no `refresh_rulebase_fn` executed), it SHALL attempt read-only in-memory `collect_domain_rulebase_snapshot` without writing to `CachePort` or double-fetching after coordinator sync
- **AND** that live fallback SHALL set `numbering_source = "live_published"` and basis `"Numbering read live from published rulebase at <time> UTC"`
- **AND** only if live collection fails or is empty SHALL it fall back to `"Numbering from cached rulebase snapshot (unavailable)"` (`numbering_source = "unnumbered"`)

### Requirement: Offline Dry-Run ChangeReport Synthesis from CPCRUD Plan

**ID**: REQ-REPORT-004\
**Intent**: Allow operators to preview and archive dry-run CPCRUD plans in the exact same evidence report format as live sessions.\
**Non-goals**: Live `show-changes` collection (`REQ-REPORT-001`) or executing a `Plan` (`REQ-CPCRUD-010`).

`arodonata.reports` SHALL provide `build_change_report_from_plan(plan, ...)` to convert a CPCRUD `Plan` offline into a `ChangeReport` compatible with `render_change_report()`, capturing object, group, and rule creates, deletes, and field-level add/remove diffs without opening Check Point sessions.

#### Scenario: SCN-REPORT-004-1 — Dry-run ChangeReport renders HTML and JSON offline with added and removed item diffs

- **GIVEN** a multi-action `Plan` containing object creates (`Outcome.CREATE`), group member deltas (`Outcome.UPDATE` with `add`/`remove`), and incremental rule cell diffs (`Outcome.UPDATE` on `source`/`destination`/`service`)
- **WHEN** `build_change_report_from_plan(plan)` converts the plan and `render_change_report(report, formats=["html", "json"])` renders it
- **THEN** `build_change_report_from_plan` SHALL produce a valid `ChangeReport` with zero Check Point API calls
- **AND** it SHALL populate `ObjectChangeEntry.field_diffs` and `RuleChangeEntry.field_diffs` (`added_items` and `removed_items`)
- **AND** `render_change_report` SHALL emit self-contained SmartConsole-styled HTML and round-trippable JSON containing no `sid`s or errors

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

**ID**: REQ-REPORT-005\
**Intent**: Render portable, XSS-safe HTML, JSON, and Markdown change reports offline with complete SmartConsole visual fidelity.\
**Non-goals**: Querying live Check Point APIs during rendering (`REQ-REPORT-001`).

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: SCN-REPORT-005-1 — Self-contained HTML evidence output

- **GIVEN** a `ChangeReport` with rule changes, section context, object changes, and field diffs
- **WHEN** `render_change_report(report, formats=["html"], options=...)` (or `formats=["md"]`) runs
- **THEN** it SHALL return a `RenderedReportBundle` (normalizing `"md"` to `"markdown"`) whose `.html` attribute contains a self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, and zero external network assets
- **AND** the HTML SHALL render SmartConsole-styled dark-blue headers (`#253245`), yellow section banner rows (`<tr class="section-row">` on `#eee8aa` with `▾ <section_name> (<section_range>)`), and shaded `.col-num` rule cells
- **AND** it SHALL display change badges (`NEW`, `DELETED`, `MODIFIED`, `MOVED`), disabled `✗` markers, and `Accept`/`Drop` action indicators
- **AND** it SHALL show inline `- <name>` / `+ <name>` / `before → after` cell diffs, plus `Field Diffs` tables when `RenderOptions.include_field_diffs=True`
- **AND** all Check Point object/rule strings SHALL be HTML-escaped while safe inline markdown in `title` and `header_fields` is rendered

#### Scenario: SCN-REPORT-005-2 — Inline diff markers in Markdown rule and object tables

- **GIVEN** a `ChangeReport` containing modified rules or objects with `field_diffs`
- **WHEN** `render_change_report(report, formats=["markdown"], ...)` runs
- **THEN** it SHALL render removed items (`[-<name>]`), added/replacement items (`[+<name>]`), and scalar `before -> after` transitions inline in `Rule Changes` (including `Track`) and `Object Changes` cells
- **AND** when `RenderOptions.include_field_diffs=True`, it SHALL emit detailed Markdown `Field Diffs` tables for both rule changes and object changes symmetrically to HTML
- **AND** it SHALL escape pipe characters, newlines, and raw HTML tags in Check Point strings

#### Scenario: SCN-REPORT-005-3 — Round-trip JSON serialization with format_version check

- **GIVEN** a `ChangeReport` serialized to `"json"`
- **WHEN** it is reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access
- **AND** it SHALL reject JSON payloads whose `format_version` is newer than supported by the installed library
