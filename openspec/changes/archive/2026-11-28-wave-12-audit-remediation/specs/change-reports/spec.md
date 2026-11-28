# Spec Delta

## ADDED Requirements

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
