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

- **WHEN** `show-changes` returns bare UIDs for group members or NAT fields not already named in the session's own change entries
- **THEN** the collector SHALL resolve up to 200 distinct UIDs per report via read-only `show-object` calls and emit a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails

### Requirement: Owned Session Live Numbering and Cached Snapshot Fallback

The change report builder SHALL number added, modified, moved, and deleted rules according to SmartConsole hierarchy using either a caller-supplied unpublished `OwnedSession` (`sid`, `server_ip`) or the domain's cached rulebase snapshot, labeling each session with its exact numbering basis.

#### Scenario: Read-only live numbering via OwnedSession with strict SID hygiene

- **WHEN** a `SessionScope` supplies an `OwnedSession` matching an unpublished session in the scope
- **THEN** the collector SHALL verify ownership via `show-session`, read `show-packages` and `show-*-rulebase` using that SID strictly read-only (never publishing, discarding, or logging out), label the session `"Numbering read live in the owned session at <time> UTC"`, and NEVER include or log the SID in `ChangeReport`, `RawResponse`, HTML, JSON, Markdown, or `repr()`

#### Scenario: Graceful fallback when OwnedSession is already published or expired

- **WHEN** a supplied `OwnedSession` no longer corresponds to an unpublished session or its SID fails
- **THEN** the collector SHALL record an `owned_session_not_used` or `owned_session_error` warning and fall back to numbering from the rulebase cache

### Requirement: Multi-Format Evidence Rendering and Safe Markup Escaping

`render_change_report(report, formats, options)` SHALL render a `ChangeReport` offline (without Check Point access) into any requested subset of `"html"`, `"json"`, and `"markdown"` (raising `UnsupportedFormat` for `"pdf"`), escaping all Check Point strings in every format while allowing safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title` and `header_fields`.

#### Scenario: Self-contained HTML evidence output

- **WHEN** `"html"` is requested in `formats`
- **THEN** `render_change_report` SHALL produce a single self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, zero external network assets, visual change indicators (`NEW`, `DELETED`, yellow field diffs, moved rule badges, disabled `✗` markers), and per-rule field diff detail tables

#### Scenario: Round-trip JSON serialization with format_version check

- **WHEN** a `ChangeReport` is serialized to `"json"` and reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access, and reject JSON files whose `format_version` is newer than supported by the installed library
