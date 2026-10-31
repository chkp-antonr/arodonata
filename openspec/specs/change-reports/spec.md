# Auditable Session Change Report Specification

## Purpose

Defines read-only collection (`collect_change_report`), rulebase placement numbering (`placement.py`), and multi-format rendering (`render_change_report`, `build_change_report`) of Check Point policy session change evidence (`ChangeReport`) across explicit session UIDs (`SessionScope`) and published session/date ranges (`RangeScope`).

## Requirements

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

### Requirement: Owned Session Live Numbering and Cached Snapshot Fallback

The change report builder SHALL number added, modified, moved, and deleted rules according to SmartConsole hierarchy using a verified `OwnedSession` in-memory snapshot, the domain's cached rulebase snapshot, or a coordinator-delegated / in-memory published rulebase fallback when the cache is cold, skipping placement for object-only sessions and NEVER calling `CachePort.replace_domain_rulebase` directly from `arodonata.reports`.

#### Scenario: Object-only session skips rulebase placement and omits numbering banner

- **WHEN** a collected `SessionChangeReport` contains zero `rule_changes`
- **THEN** `apply_session_rule_placement` SHALL return immediately without calling `show-session`, `collect_domain_rulebase_snapshot`, or `CachePort.get_domain_rulebase`, setting `numbering_source = "not_applicable"` and `numbering_basis = ""`, and HTML/Markdown rendering SHALL omit the numbering basis banner/line for that session

#### Scenario: Read-only live numbering via OwnedSession with strict SID hygiene

- **WHEN** a `SessionScope` supplies an `OwnedSession` matching an unpublished session with rule changes in the scope
- **THEN** the collector SHALL verify ownership and matching domain via `show-session`, read `show-packages` and `show-*-rulebase` using that SID strictly read-only into memory (never publishing, discarding, logging out, or writing to `CachePort`), label the session `"Numbering read live in the owned session at <time> UTC"` (`numbering_source = "owned_session"`), and NEVER include or log the SID in `ChangeReport`, `RawResponse`, HTML, JSON, Markdown, or `repr()`

#### Scenario: Post-publish live numbering via clean OwnedSession before logout

- **WHEN** a `SessionScope` supplies an `OwnedSession` bound to an already-published session with rule changes (matching `OwnedSession.session_uid == session_uid` or a single-session scope, and matching `mgmt_name`/`domain` when set) and `show-session` on that SID confirms a non-discarded session on the expected domain with `changes` present and `0`, `locks` present and `0`, and `number-of-published-changes == 0`
- **THEN** the collector SHALL read the published rulebase snapshot live through that SID, number the session's rules strictly in-memory without calling `CachePort.replace_domain_rulebase` and without emitting `owned_session_not_used`, and label the session `"Numbering read live after publish at <time> UTC"` (`numbering_source = "live_published"`)

#### Scenario: Graceful fallback when OwnedSession is already published or expired

- **WHEN** a supplied `OwnedSession` fails `show-session`, is `discarded`, reports a different domain than the target session, omits `changes` or `locks`, reports non-zero `changes`, `locks`, or `number-of-published-changes` on a rotated post-publish session, or does not match an unpublished target session's UID
- **THEN** the collector SHALL record an `owned_session_not_used` or `owned_session_error` warning and fall back to numbering from the domain's cached rulebase snapshot (or cold-cache fallback)

#### Scenario: Cold-cache on-demand live published rulebase fallback

- **WHEN** a session has rule changes, no usable `OwnedSession` handled numbering, and `CachePort.get_domain_rulebase` contains no cached rules or layers for `(mgmt_name, domain_name)`
- **THEN** when invoked via `ArodonataClient`, the collector SHALL delegate warming to `RulebaseRefreshService` / `DomainSyncCoordinator` (enforcing per-domain distributed lock, dirty-session refusal, and atomic `DomainSyncState` stamping) and read the resulting cached snapshot; if invoked standalone without a coordinator or if warming does not populate the cache, it SHALL attempt a read-only in-memory `collect_domain_rulebase_snapshot` (`numbering_source = "live_published"`, basis `"Numbering read live from published rulebase at <time> UTC"`) without writing to `CachePort`, falling back to `"Numbering from cached rulebase snapshot (unavailable)"` (`numbering_source = "unnumbered"`) only when live collection fails or is empty

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: Self-contained HTML evidence output

- **WHEN** `"html"` is requested in `formats`
- **THEN** `render_change_report` SHALL produce a single self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, zero external network assets, SmartConsole-styled dark-blue table headers (`#253245` with white text), full-width pale-yellow access section banner rows (`<tr class="section-row">` on `#eee8aa` background displaying `▾ <section_name> (<section_range>)` and layer context), shaded gray `No.` rule-number cells (`.col-num`), visual change indicators (`NEW`, `DELETED`, `MODIFIED`, `MOVED` badges, disabled `✗` markers, and `Accept`/`Drop` action indicators), inline cell-level diff annotations inside `Rule Changes` and `Object Changes` rows showing removed items (`- <name>` struck-through), added/replacement items (`+ <name>`), and scalar `before → after` transitions, and optional per-rule/per-object `Field Diffs` detail tables when `RenderOptions.include_field_diffs` is `True`

#### Scenario: Inline diff markers in Markdown rule and object tables

- **WHEN** `"markdown"` is requested in `formats` for a report containing modified rules or modified objects with `field_diffs`
- **THEN** `render_change_report` SHALL render removed items (`[-<name>]`), added/replacement items (`[+<name>]`), and scalar `before -> after` transitions inline inside the Markdown `Rule Changes` (including the `Track` column) and `Object Changes` table cells while escaping pipe characters, newlines, and raw HTML tags

#### Scenario: Round-trip JSON serialization with format_version check

- **WHEN** a `ChangeReport` is serialized to `"json"` and reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access, and reject JSON files whose `format_version` is newer than supported by the installed library

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
- **THEN** the collector SHALL compute `FieldDiff` entries (including `added_items` and `removed_items` for `members`, and before/after values for `comments` and address/service attributes) and populate structured `ObjectChangeEntry.summary_fields` and formatted `ObjectChangeEntry.summary` with IPv4/IPv6 addresses, CIDR subnets, address-range bounds, service ports/protocols, resolved `members`, and `comments`

#### Scenario: Background Check Point System maintenance objects excluded by default

- **WHEN** `show-changes` for a non-`"System"` user session includes non-deleted (`added` or `modified`) non-rule objects whose post-change `meta-info.last-modifier` is `"System"` (or nameless/typeless internal `"System"` records such as `IpsProtectionUserSettings`, `cp-trusted-ca-certificate`, or `TrustedCaPackageConf`)
- **THEN** the collector SHALL exclude those `"System"` non-rule entries from `SessionChangeReport.object_changes` by default (never excluding `deleted` objects and never inspecting `old-object.meta-info.last-modifier`, and including them when `RenderOptions.include_system_objects` is `True`), log the filtered count at `DEBUG` level without emitting a user-facing `ReportWarning`, and preserve the complete sanitized `show-changes` payload in `ChangeReport.raw_responses`
