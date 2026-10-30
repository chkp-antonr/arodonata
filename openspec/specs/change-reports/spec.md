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

- **WHEN** `show-changes` returns bare UIDs for rule layers (`layer`), group members, rule fields, or NAT fields not already named in the session's own change entries
- **THEN** the collector SHALL resolve up to 200 distinct UIDs per report (checking local cache first, then read-only `show-object` calls), populate `RuleChangeEntry.layer_name` when `layer_uid` resolves to a named layer, and emit a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails

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
- **THEN** `render_change_report` SHALL produce a single self-contained UTF-8 HTML document (`bytes`) with inline CSS, zero `<script>` tags, zero external network assets, visual change indicators (`NEW`, `DELETED`, yellow field diffs, moved rule badges, disabled `✗` markers), and per-rule field diff detail tables

#### Scenario: Round-trip JSON serialization with format_version check

- **WHEN** a `ChangeReport` is serialized to `"json"` and reloaded via `ChangeReport.model_validate_json(...)`
- **THEN** it SHALL re-render into identical HTML or Markdown without network access, and reject JSON files whose `format_version` is newer than supported by the installed library
