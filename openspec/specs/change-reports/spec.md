# Auditable Session Change Report Specification

## Purpose

Defines read-only collection (`collect_change_report`), rulebase placement numbering (`placement.py`), and multi-format rendering (`render_change_report`, `build_change_report`) of Check Point policy session change evidence (`ChangeReport`) across explicit session UIDs (`SessionScope`) and published session/date ranges (`RangeScope`).

## Requirements

### Requirement: Scope Validation and Read-Only Change Collection

`collect_change_report(client, scopes, ...)` SHALL validate `SessionScope` and `RangeScope` inputs strictly (raising `pydantic.ValidationError` or `ChangeReportInputError` on invalid bounds or naive datetimes), query `show-changes` read-only across target management servers and domains, deduplicate sessions named by multiple scopes, and record partial runtime failures as structured `ReportWarning` entries rather than aborting the whole report.

#### Scenario: Single-session change collection via to-session query and container filtering

- **WHEN** a `SessionScope` requests changes for explicit `session_uids`
- **THEN** the collector SHALL call `show-changes` with `{"to-session": s_uid, "details-level": "full"}` (omitting `from-session: s_uid` because `from-session` is exclusive in Check Point `show-changes`), filter the returned `changes[]` containers to the matching `session-uid`, and classify `modified-objects` entries that contain `new-object` without `old-object` as `"added"`

#### Scenario: Timezone-aware date range conversion and exact publish-time filtering

- **WHEN** a `RangeScope` includes timezone-aware `from_date` and/or `to_date`
- **THEN** the collector SHALL convert the bounds to the server's UTC offset, widen the server query window safely (or omit server date parameters when `from_session` is also given), and filter returned sessions by exact UTC publish timestamp

#### Scenario: Reference UID name resolution with bounded show-object lookups

- **WHEN** `show-changes` returns bare UIDs for rule layers (`layer`), group members, rule fields, or NAT fields not already named in the session's own change entries
- **THEN** the collector SHALL resolve up to 200 distinct UIDs per report (checking local cache first, then read-only `show-object` calls), populate `RuleChangeEntry.layer_name` when `layer_uid` resolves to a named layer, and emit a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails

### Requirement: Owned Session Live Numbering and Cached Snapshot Fallback

The change report builder SHALL number added, modified, moved, and deleted rules according to SmartConsole hierarchy using a caller-supplied `OwnedSession` (`sid`, `server_ip`), the domain's cached rulebase snapshot, or an on-demand read-only published rulebase fetch when the cache is cold, labeling each session that contains rule changes with its exact numbering basis and skipping placement altogether for sessions without rule changes.

#### Scenario: Object-only session skips rulebase placement and omits numbering banner

- **WHEN** a collected `SessionChangeReport` contains zero `rule_changes`
- **THEN** `apply_session_rule_placement` SHALL return immediately without calling `show-session`, `collect_domain_rulebase_snapshot`, or `CachePort.get_domain_rulebase`, setting `numbering_source = "not_applicable"` and `numbering_basis = ""`, and HTML/Markdown rendering SHALL omit the numbering basis banner/line for that session

#### Scenario: Read-only live numbering via OwnedSession with strict SID hygiene

- **WHEN** a `SessionScope` supplies an `OwnedSession` matching an unpublished session with rule changes in the scope
- **THEN** the collector SHALL verify ownership via `show-session`, read `show-packages` and `show-*-rulebase` using that SID strictly read-only (never publishing, discarding, or logging out), label the session `"Numbering read live in the owned session at <time> UTC"` (`numbering_source = "owned_session"`), and NEVER include or log the SID in `ChangeReport`, `RawResponse`, HTML, JSON, Markdown, or `repr()`

#### Scenario: Post-publish live numbering via clean OwnedSession before logout

- **WHEN** a `SessionScope` supplies an `OwnedSession` for an already-published session with rule changes (such as immediately after `publish` and before `logout`) and `show-session` on that SID confirms a live, non-discarded session with zero uncommitted changes (`changes == 0` when rotated to a new working session UID)
- **THEN** the collector SHALL read the published rulebase snapshot live through that SID without emitting `owned_session_not_used`, best-effort warm `CachePort.replace_domain_rulebase`, and label the session `"Numbering read live after publish at <time> UTC"` (`numbering_source = "live_published"`)

#### Scenario: Graceful fallback when OwnedSession is already published or expired

- **WHEN** a supplied `OwnedSession` fails verification, is `discarded`, does not match an unpublished target session, or belongs to a different open session with uncommitted edits (`changes > 0`) on a published target session, and the session has rule changes
- **THEN** the collector SHALL record an `owned_session_not_used` or `owned_session_error` warning and fall back to numbering from the domain's cached rulebase snapshot (or cold-cache live published rulebase fallback)

#### Scenario: Cold-cache on-demand live published rulebase fallback

- **WHEN** a session has rule changes, no usable `OwnedSession` handled numbering, and `CachePort.get_domain_rulebase` contains no cached rules or layers for `(mgmt_name, domain_name)`
- **THEN** the collector SHALL attempt a read-only `collect_domain_rulebase_snapshot` against `ApiPort`, apply rule numbering and best-effort persist the snapshot via `CachePort.replace_domain_rulebase` with basis `"Numbering read live from published rulebase at <time> UTC"` (`numbering_source = "live_published"`), falling back to `"Numbering from cached rulebase snapshot (unavailable)"` (`numbering_source = "unnumbered"`) only if the live snapshot fetch fails or returns empty

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: Self-contained HTML evidence output

- **WHEN** `"html"` is requested in `formats`
- **THEN** `render_change_report` SHALL produce a single self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, zero external network assets, visual change indicators (`NEW`, `DELETED`, yellow field diffs, moved rule badges, disabled `✗` markers), and per-rule field diff detail tables

#### Scenario: Round-trip JSON serialization with format_version check

- **WHEN** a `ChangeReport` is serialized to `"json"` and reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access, and reject JSON files whose `format_version` is newer than supported by the installed library
