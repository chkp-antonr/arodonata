# Spec Delta

## ADDED Requirements

### Requirement: RangeScope Target Session Date Omission, Warning Schema Parity, and Single-Warning OwnedSession Context

**ID**: REQ-REPORT-009\
**Intent**: Ensure `to_session`-bounded ranges omit server-side date filters symmetrically with `from_session`, keep `WarningCode` aligned with emitted codes, and centralize `OwnedSession` invalidation cleanly.\
**Non-goals**: Unparsed timestamp fail-closed behavior (`REQ-REPORT-008`) or inline Markdown escaping (`REQ-REPORT-008`).

`RangeScope` SHALL omit server date bounds whenever `to_session` is specified, `WarningCode` SHALL include `"range_session_not_found"`, and `_OwnedSessionContext` SHALL track and disable failing `OwnedSession` credentials cleanly with a single warning.

#### Scenario: SCN-REPORT-009-1 — RangeScope to_session server-date omission, range_session_not_found schema parity, and single-disable OwnedSession context

- **GIVEN** a `RangeScope(to_session=..., from_date=..., to_date=...)` alongside a `SessionScope` whose `OwnedSession` fails on initial `show-session`
- **WHEN** `collect_change_report()` discovers target sessions and collects metadata/changes/UIDs
- **THEN** `show-sessions` SHALL omit `from` and `to` date parameters when `to_session` is set, `WarningCode` SHALL validate `"range_session_not_found"`, and `_OwnedSessionContext` SHALL disable the failing `OwnedSession` once with a single warning so subsequent calls never reuse it
