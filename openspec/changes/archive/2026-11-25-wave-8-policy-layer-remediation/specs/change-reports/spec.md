# Spec Delta

## ADDED Requirements

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
