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

### Requirement: Fail-Closed Range Bounds, Safe Inline Markup, and Accurate Placement/Diff Reporting

**ID**: REQ-REPORT-006\
**Intent**: Prevent unbounded session history leaks, HTML/Markdown injection via inline markup or CR/CRLF splits, false `MOVED` flags, and spurious empty field diffs in change reports.\
**Non-goals**: Base scope validation (`REQ-REPORT-001`) or offline plan synthesis (`REQ-REPORT-004`).

`ChangeReportService` SHALL return empty matches with a `ReportWarning` when `RangeScope.from_session` or `to_session` UID is absent, verify `OwnedSession` liveness/domain with shared read-only fallback (`sid=None`), prefix nested `old_rule_number` values accurately, omit empty `FieldDiff`s for reordered unordered lists, preserve dotted `rule_number` strings in dry-run plan reports, and sanitize inline Markdown links, backtick spans, and CR/CRLF characters.

#### Scenario: SCN-REPORT-006-1 — Missing RangeScope UID fails closed and OwnedSession falls back cleanly

- **GIVEN** a `RangeScope` referencing a nonexistent `from_session` or `to_session` UID, OR an expired/wrong-domain `OwnedSession`
- **WHEN** `ArodonataClient.get_change_report()` collects session changes
- **THEN** a missing `RangeScope` UID SHALL return zero matched sessions with a `ReportWarning` instead of falling back to full domain history
- **AND** an unusable `OwnedSession` SHALL fall back to the shared read-only session (`sid=None`) with a warning while preserving report evidence

#### Scenario: SCN-REPORT-006-2 — Nested rule placement, order-only list diffs, and dotted plan rule numbers remain accurate

- **GIVEN** modified rules inside inline or Global-placeholder layers, unordered list fields whose items were only reordered, or dry-run `plan_report` actions with dotted `rule_number` strings (e.g., `"2.1"`)
- **WHEN** change reports or dry-run plan reports are synthesized
- **THEN** nested in-place edits SHALL NOT be falsely flagged as `MOVED` and deleted rules SHALL preserve layer prefixes
- **AND** reordered unordered Check Point list fields SHALL produce zero empty `FieldDiff`s and dotted `rule_number` strings SHALL be preserved

#### Scenario: SCN-REPORT-006-3 — Inline Markdown links, multiline code spans, and CR/CRLF comments are safely escaped

- **GIVEN** Check Point object names, comments, or descriptions containing multiline backtick code spans, unsafe `href` characters/schemes, or `\r`/`\r\n` line breaks
- **WHEN** `render_safe_inline_markdown_md` or Markdown/HTML report renderers format evidence
- **THEN** multiline inline tokens, unsafe `href` targets, and raw HTML tags SHALL be neutralized and `\r`/`\n` normalized so table rows and headings cannot be broken or injected

### Requirement: Canonical Object Summary Schema Across Diffs, Plans, and Renderers

**ID**: REQ-REPORT-007\
**Intent**: Prevent modified-object detail tables and dry-run plan reports from dropping Check Point attributes due to diverged duplicate summary formatters.\
**Non-goals**: Base report layout structure (`REQ-REPORT-002`) or inline Markdown escaping rules (`REQ-REPORT-006`).

`ChangeReportService` and dry-run `plan_report` synthesis SHALL use a single canonical object summary field registry across summary construction, summary token splitting, and HTML/Markdown cell rendering so `ip-protocol`, `icmp-type`, `icmp-code`, `primary-category`, `urls-defined-as-regular-expression`, `url-list`, `description`, `subnet6`, `mask-length6`, and `ipv6-address-first/last` are preserved uniformly on created, modified, deleted, and planned objects.

#### Scenario: SCN-REPORT-007-1 — Unified object summary formatter preserves protocol, ICMP, URL, description, and IPv6 fields

- **GIVEN** modified or planned `service-icmp`, `service-other`, `application-site`, `network`, or `address-range` objects carrying `icmp-type`/`icmp-code`, `ip-protocol`, `primary-category`, `urls-defined-as-regular-expression`, `url-list`, `description`, or IPv6 subnet/range fields
- **WHEN** `build_change_report()`, `build_plan_report()`, `render_change_report()`, or `format_plan_report()` renders object summaries and `Details` cells
- **THEN** all present canonical attributes SHALL be emitted in plain summaries, dry-run plan summaries, and both HTML and Markdown modified-object `Details` cells without silent field loss
- **AND** `_SUMMARY_SPLIT_RE` token parsing SHALL recognize every emitted canonical key consistently across collectors and renderers

### Requirement: Fail-Closed Timestamp Bounds, Validated Owned-Session Forwarding, and Nested Markdown Escaping

**ID**: REQ-REPORT-008\
**Intent**: Prevent unparsed bound sessions from leaking full domain history, avoid reusing invalidated `OwnedSession` instances or unredacted `known_names`, and block nested Markdown links/images inside bold/italic spans.\
**Non-goals**: Dry-run plan report field summaries (`REQ-REPORT-007`).

`collect_change_report()` SHALL fail closed when a requested `from_session`/`to_session` lacks a parseable timestamp, omit invalidated `OwnedSession` instances from downstream resolution/placement, redact substituted `known_names`, and neutralize nested Markdown links and images inside `**bold**` and `*italic*` spans.

#### Scenario: SCN-REPORT-008-1 — Unparsed range bounds fail closed, invalidated OwnedSession stops propagating, and known_names are redacted

- **GIVEN** a `RangeScope(from_session=...)` whose bound session exists without a parseable timestamp, or a `SessionScope` whose `OwnedSession` fails `show-session`/`show-changes` while `show-object` resolves a name containing a SID
- **WHEN** `collect_change_report()` filters sessions, resolves bare UIDs, and runs rule placement
- **THEN** the unparsed range bound SHALL fail closed with a warning and empty session set instead of returning full domain history
- **AND** invalidated `OwnedSession` instances SHALL NOT be forwarded to bare-UID lookup/placement, and substituted names SHALL pass `redact_sid(..., known_sids=...)`

#### Scenario: SCN-REPORT-008-2 — render_safe_inline_markdown_md blocks nested javascript: links and external images inside bold/italic spans

- **GIVEN** Markdown `title` or `header_fields` strings containing `**[label](javascript:alert(1))**` or `*![beacon](https://example.invalid/x.png)*`
- **WHEN** `render_safe_inline_markdown_md()` renders the Markdown report
- **THEN** nested `[` and `]` characters inside `**...**` and `*...*` spans SHALL be escaped so no active Markdown links or external image beacons are emitted

### Requirement: RangeScope Target Session Date Omission, Warning Schema Parity, and Single-Warning OwnedSession Context

**ID**: REQ-REPORT-009\
**Intent**: Ensure `to_session`-bounded ranges omit server-side date filters symmetrically with `from_session`, keep `WarningCode` aligned with emitted codes, and centralize `OwnedSession` invalidation cleanly.\
**Non-goals**: Unparsed timestamp fail-closed behavior (`REQ-REPORT-008`) or inline Markdown escaping (`REQ-REPORT-008`).

`RangeScope` SHALL omit server date bounds whenever `to_session` is specified, `WarningCode` SHALL include `"range_session_not_found"`, and `_OwnedSessionContext` SHALL track and disable failing `OwnedSession` credentials cleanly with a single warning.

#### Scenario: SCN-REPORT-009-1 — RangeScope to_session server-date omission, range_session_not_found schema parity, and single-disable OwnedSession context

- **GIVEN** a `RangeScope(to_session=..., from_date=..., to_date=...)` alongside a `SessionScope` whose `OwnedSession` fails on initial `show-session`
- **WHEN** `collect_change_report()` discovers target sessions and collects metadata/changes/UIDs
- **THEN** `show-sessions` SHALL omit `from` and `to` date parameters when `to_session` is set, `WarningCode` SHALL validate `"range_session_not_found"`, and `_OwnedSessionContext` SHALL disable the failing `OwnedSession` once with a single warning so subsequent calls never reuse it

### Requirement: Backslash-Safe Markdown Escaping, Owned-Session Fallback, and Partial-Slice Warming

**ID**: REQ-REPORT-010\
**Intent**: Prevent Markdown table/link escape bypasses, keep healthy `OwnedSession` instances active across single `show-object` 404s, warm partial rulebase slices, and align `WarningCode`.\
**Non-goals**: Changing HTML report styling or Check Point `show-changes` task polling intervals.

Markdown cell and inline sanitizers across reports and rulebase filters MUST escape literal backslashes before delimiter characters via shared core helpers. Single `show-object` 404 errors MUST fall back read-only without disabling healthy `OwnedSession` contexts, partial single-package slices MUST trigger full-domain warming, and `WarningCode` MUST include `"range_session_timestamp_missing"`.

#### Scenario: SCN-REPORT-010-1 — Backslash-safe Markdown cell and inline escaping

- **GIVEN** Check Point rule or object fields containing backslashes followed by `[`, `]`, `|`, or backticks
- **WHEN** change reports or filtered rulebase Markdown tables render those fields
- **THEN** shared escaping helpers SHALL escape literal backslashes prior to Markdown delimiters so active links and GFM table column splits are prevented
- **AND** inline code spans SHALL preserve ordinary backslashes without breaking table cells

#### Scenario: SCN-REPORT-010-2 — OwnedSession 404 recovery, partial-slice warming, and WarningCode completeness

- **GIVEN** an unpublished `OwnedSession` encountering a single `show-object` 404, a cached domain holding only a partial `package:<type>:<uid>` rulebase slice without `item_type="*"`, or a `RangeScope` session missing timestamps
- **WHEN** `collect_change_report()` resolves UIDs, places rule numbers, or emits `ReportWarning` codes
- **THEN** a single `show-object` 404 SHALL retry read-only without disabling `OwnedSession` for subsequent lookups or live numbering
- **AND** missing full-domain sync state (`sync_state is None`) SHALL trigger coordinator warming and `WarningCode` SHALL declare `"range_session_timestamp_missing"`
