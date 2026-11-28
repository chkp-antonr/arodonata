# Spec Delta

## ADDED Requirements

### Requirement: Strict Operation IDs, Virtual Rule Overlay Integrity, Protocol Zero Fidelity, and Concurrent/Owner-Fair Execution

**ID**: REQ-CPCRUD-018\
**Intent**: Reject blank or duplicate template IDs via unified verb normalization, prevent intra-plan virtual rule traffic collisions, preserve `ip_protocol=0` and access inline layers, restore empty description/additional-categories fields, and make concurrent executor/registry state race-free and owner-fair.\
**Non-goals**: Staged baseline verification (`REQ-CPCRUD-017`) or schema path settings (`REQ-CONFIG-009`).

CPCRUD SHALL reject blank/duplicate IDs via shared verb parsing, preserve `ip_protocol=0`, dereference `AccessRuleEntry` inline layers, isolate planned virtual rule traffic matching, restore empty `description`/`additional-categories` on rolling back `UPDATE`s, return per-call `ApplyReport`s, and evict staged sessions owner-fairly.

#### Scenario: SCN-CPCRUD-018-1 — Non-blank unique operation IDs, intra-plan virtual rule overlays, IP protocol zero, inline-layer deref, and empty-field inverse rollback

- **GIVEN** templates with blank or duplicate `id` fields, virtual rules created then chained in one plan (`explicit id` or distinct-named bottom rules), a service with `ip_protocol=0` (`HOPOPT`), an `AccessRuleEntry` with `inline-layer`, or an `UPDATE` adding `description`/`additional-categories` from empty prior state
- **WHEN** validation, planning, diffing, or `inverse()` runs
- **THEN** validator and planner SHALL reject blank/duplicate IDs via shared verb normalization, planner SHALL update virtual rule overlays without colliding differently named rules across traffic tuples, differ SHALL preserve `0` protocols and access inline layers, and inverse SHALL emit empty `""`/`[]` restoration values

#### Scenario: SCN-CPCRUD-018-2 — Race-free concurrent Executor.apply reports and owner-fair staged session registry eviction

- **GIVEN** concurrent `Executor.apply()` coroutines on one `Executor` instance, or a full 256-entry staged session registry holding single-session peers alongside a greedy multi-session owner
- **WHEN** concurrent applies execute or a new owner stages a 257th session
- **THEN** each `Executor.apply()` call SHALL return its own isolated `ApplyReport` from the completion event without shared-attribute races, and staged registry eviction SHALL discard the new or greedy multi-session owner's oldest SID while preserving single-session peers
