# Spec Delta

## ADDED Requirements

### Requirement: Case-Consistent Rulebase Lookup, Placeholder Precedence, and Decomposed Pagination

**ID**: REQ-RULE-010\
**Intent**: Eliminate empty rulebase loads caused by case mismatches, misattributed empty Global-placeholder layers, and monolithic pagination state bugs.\
**Non-goals**: Altering Check Point SmartConsole hierarchical numbering syntax or rulebase cache table schemas.

Rulebase loading and numbering MUST apply exact-match-first with case-insensitive fallback consistently across package and layer names. Global-placeholder domain layer attribution MUST take precedence over inline layer attribution on placeholder rules, and `fetch_paged_rulebase()` MUST isolate page accumulation and rule materialization into cohesive helpers.

#### Scenario: SCN-RULE-010-1 — Case-insensitive package/layer fallback, placeholder precedence, and pagination helpers

- **GIVEN** a mixed-case package or layer query matching cached rulebase data, a multi-package domain with an empty Global-placeholder domain layer, or a multi-page rulebase fetch experiencing mid-fetch `total` drift
- **WHEN** `get_package_rulebase()`, `get_layer_rulebase()`, prefix tracking, or `fetch_paged_rulebase()` executes
- **THEN** package and layer lookups SHALL resolve case-insensitively when exact case does not match, and empty Global-placeholder domain layers SHALL resolve via `placeholder_domain_layer_uid` before `inline_layer_uid`
- **AND** `fetch_paged_rulebase()` SHALL manage accumulator resets and typed rule materialization through dedicated internal helpers
