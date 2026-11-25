# Spec Delta

## ADDED Requirements

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
