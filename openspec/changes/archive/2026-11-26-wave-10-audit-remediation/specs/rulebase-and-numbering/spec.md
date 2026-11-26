# Spec Delta

## ADDED Requirements

### Requirement: Fail-Closed Rulebase Snapshot Collection, Bounded Drift-Safe Paging, and Empty Embedded Layer Prefix Continuity

**ID**: REQ-RULE-009\
**Intent**: Prevent rulebase collection from committing truncated 50-item fallbacks as `"ok"`, bound pagination against infinite loops and `total` drift, unify fallback UIDs, and preserve package prefixes for empty embedded layers.\
**Non-goals**: Hierarchical SmartConsole rule numbering syntax (`REQ-RULE-004`).

Rulebase snapshot collection SHALL fail closed on `paging_inconsistent` and non-RBAC errors without 50-item unpaginated fallbacks, bound `fetch_paged_rulebase` against infinite loops and `total` drift, emit consistent synthetic fallback UIDs, and preserve package prefixes for empty Global-placeholder and unnamed inline layers.

#### Scenario: SCN-RULE-009-1 — Fail-closed paging_inconsistent handling, bounded pagination, and total drift detection

- **GIVEN** a domain with >50 packages/layers encountering `paging_inconsistent` or API errors, or a layer page stream with omitted `total`, repeated UIDs, or mid-fetch `total` growth
- **WHEN** `collect_domain_rulebase_snapshot()` or `fetch_paged_rulebase()` executes
- **THEN** `collect_domain_rulebase_snapshot()` SHALL raise rather than committing truncated/empty 50-item fallback caches as `status="ok"`
- **AND** `fetch_paged_rulebase()` SHALL enforce `max_pages` and zero-new-rule bounds and fail or restart on mid-fetch `total` discontinuities

#### Scenario: SCN-RULE-009-2 — Unified synthetic fallback rule UIDs and empty Global-placeholder / inline layer prefixes

- **GIVEN** a section mixing real-UID and missing-UID rules or a package referencing an empty Global-placeholder domain layer or unnamed empty inline layer
- **WHEN** `fetch_paged_rulebase()` parses rules/sections or `locate_rules_in_snapshot()` indexes layer prefixes
- **THEN** `sec.rule_uids` SHALL match parsed rule UIDs identically across rulebase types, and `locate_rules_in_snapshot()` SHALL emit the package prefix (`"2."`) without duplicate standalone `prefix=""` entries
