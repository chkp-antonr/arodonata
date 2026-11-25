# Spec Delta

## ADDED Requirements

### Requirement: Single-Pass Reference Collection for Unused Emulator Objects

**ID**: REQ-ITEST-020\
**Intent**: Eliminate quadratic per-object full rulebase and gateway scans in `find_unused_objects` and `delete_unused_objects` while preserving exact cascading fixed-point deletion semantics.\
**Non-goals**: Single-entity `collect_blocking_references` error detail formatting for direct `delete-*` calls (`REQ-ITEST-011`).

`FileReplayApiMock` unused-object inspection and cleanup (`find_unused_objects` and `delete_unused_objects`) SHALL compute referenced UIDs in a single pass per iteration via `collect_referenced_uids()` using O(1) membership lookups instead of scanning all rulebases and gateways for each candidate object.

#### Scenario: SCN-ITEST-020-1 — Unused object lookup and cascading deletion use single-pass reference sets cleanly

- **GIVEN** a mock domain containing referenced objects, nested group chains (`GroupA -> GroupB -> HostX`), rule/gateway references, and unreferenced objects
- **WHEN** `show-unused-objects` (`find_unused_objects`) and `delete-unused-objects` (`delete_unused_objects`) execute
- **THEN** `find_unused_objects()` SHALL scan rulebases and groups once via `collect_referenced_uids()` and return every truly unreferenced local object
- **AND** `delete_unused_objects()` SHALL preserve multi-pass cascading cleanup (removing parent groups first, then newly unreferenced child objects) using one single-pass reference scan per fixed-point iteration
