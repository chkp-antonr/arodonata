# Spec Delta

## ADDED Requirements

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
