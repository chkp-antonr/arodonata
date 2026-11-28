# Spec Delta

## ADDED Requirements

### Requirement: Virtual Rule Cleanup Anchoring, Full Delta Overlays, and Context-Aware Staged Isolation

**ID**: REQ-CPCRUD-019\
**Intent**: Prevent intra-plan rules from landing below cleanup rules, bypassing anti-`Any`-widening guards, failing `where-used` checks, or evicting peer MCP callers' staged sessions.\
**Non-goals**: Altering CPCRUD YAML/JSON template schema syntax (`REQ-CPCRUD-001`).

Virtual rule overlays MUST preserve renamed indices, anchor created rules before trailing cleanup rules, apply incremental `{add, remove}` cell deltas and rule attributes, and fail closed on unnamed virtual rule updates/deletes. Virtual `where-used` filtering MUST recognize virtually deleted rules and active renamed entities, and `Executor` staged session tracking MUST isolate distinct `UserContext` callers without single-peer eviction.

#### Scenario: SCN-CPCRUD-019-1 — Cleanup-safe virtual rule placement, delta overlays, and where-used accuracy

- **GIVEN** a plan that renames or creates rules before adding `position="bottom"` rules, patches list cells via `{add, remove}` deltas, deletes or renames referenced entities, or targets an unnamed planned rule
- **WHEN** the CPCRUD planner resolves rule positions, updates virtual overlays, checks `where-used`, or validates intra-plan targets
- **THEN** renamed rules SHALL stay above trailing cleanup rules, virtual updates SHALL preserve `{add, remove}` deltas and rule fields for anti-`Any`-widening checks, and unnamed virtual rule mutations SHALL fail closed at plan time
- **AND** `where-used` checks SHALL ignore virtually deleted rules and keep active renamed referencing entities

#### Scenario: SCN-CPCRUD-019-2 — UserContext isolation and peer-safe eviction in Executor staged sessions

- **GIVEN** distinct authenticated `UserContext` callers sharing one `ArodonataClient` / `Executor` without separate `AuthContext` credentials at full 256-entry capacity
- **WHEN** `Executor` registers a newly staged Check Point session
- **THEN** `owner_key` SHALL incorporate `UserContext` caller identity alongside `AuthContext`
- **AND** eviction SHALL never discard a distinct single-session peer's uncommitted session
