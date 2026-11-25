# Spec Delta

## ADDED Requirements

### Requirement: Canonical Domain Discovery, Shared WriteSession Lifecycle, and Decomposed Session Execution

**ID**: REQ-SESS-013\
**Intent**: Eliminate diverged domain parsers, missing RBAC fallback in MDS discovery, duplicated `WriteSession` teardown logic, and monolithic session/route execution paths.\
**Non-goals**: Login throttle backoff semantics (`REQ-SESS-006`) or base VSX repository bundle parsing (`REQ-TOPO-008`).

`arodonata` SHALL use one canonical domain parser for `parse_domain_entry` and `parse_domain_dict`, support `details-level="standard"` RBAC fallback in `fetch_domain_topology_from_mds`, share a `WriteSession` teardown helper, and decompose `run_repository_script` and `_collect_gateway_routes_impl` into focused helpers.

#### Scenario: SCN-SESS-013-1 — Canonical domain parser identity, MDS standard RBAC fallback, and shared WriteSession lifecycle

- **GIVEN** raw MDS domain payloads parsed via `parse_domain_entry` or `parse_domain_dict`, an MDS returning permission denial on `details-level="full"`, or `WriteSession` exits (clean vs exception) across `open_api_write_session` and `AMgmtClient.write_session`
- **WHEN** domains are discovered or write sessions are opened and closed
- **THEN** `sessions.parse_domain_entry` and `response_classifiers.parse_domain_entry` SHALL preserve object identity and parse identically to `parse_domain_dict`
- **AND** `fetch_domain_topology_from_mds` SHALL fall back to `details-level="standard"` preserving cached CMA IPs, and both `WriteSession` entrypoints SHALL enforce identical publish/discard/logout semantics

#### Scenario: SCN-SESS-013-2 — Decomposed run_repository_script and route collection preserve SID redaction and coalescing

- **GIVEN** `ScriptRepositoryService.run_repository_script()` across session modes or `collect_gateway_routes()` across VSX coalesced nodes
- **WHEN** repository scripts run (with normal completion, validation failure, or session errors) or multi-gateway route collection executes
- **THEN** every session exception branch and task output SHALL scrub SIDs uniformly and close dedicated sessions cleanly
- **AND** coalescing execution, per-gateway persistence, and post-TaskGroup domain sync-state finalization SHALL run via isolated composable helpers
