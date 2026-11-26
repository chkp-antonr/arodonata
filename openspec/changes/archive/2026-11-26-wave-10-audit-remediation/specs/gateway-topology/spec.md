# Spec Delta

## ADDED Requirements

### Requirement: Isolated VSX Coalescing, Accurate LPM/Export Scoring, Atomic Route Streaming, and Scrubbed Topology Errors

**ID**: REQ-TOPO-022\
**Intent**: Ensure VSX coalesced execution isolates per-VS errors, topology streaming orders completion events accurately, LPM/export/VSID matching covers nested/manual/spaced targets, and topology/script errors scrub bare SIDs.\
**Non-goals**: Base VSX repository bundle parsing (`REQ-TOPO-008`) or LPM penalty weights (`REQ-TOPO-010`).

Topology and script services SHALL isolate per-VS bundle slice errors during VSX coalescing, hold `SyncCompletedEvent` until route collection completes, match annotations strictly on LPM `best_entry`, filter manual gateways across all canonical identifiers, resolve spaced VS names in `awk`, and scrub bare SIDs across write/topology error paths.

#### Scenario: SCN-TOPO-022-1 — Coalescing leader VS slice failure does not fail healthy sibling Virtual Systems

- **GIVEN** a physical VSX node hosting an alphabetically first broken Virtual System (`vs_context_error` or `vs_not_found_in_bundle`) alongside healthy sibling Virtual Systems
- **WHEN** `collect_gateway_routes()` runs in `"repository"` or `"auto"` mode
- **THEN** healthy sibling Virtual Systems SHALL still extract and persist their route slices while only the broken Virtual System records its error

#### Scenario: SCN-TOPO-022-2 — Streamed topology refresh, LPM annotation lookup, manual gateway export, and spaced VSID resolution

- **GIVEN** `stream_refresh_topology(collect_routes=True)`, overlapping interface subnets (`10.0.0.0/8` `standby_dynamic` + `10.10.1.0/24`), manual-only annotation gateways, or space-containing VS names without numeric `vsid`
- **WHEN** topology refresh streams, flows score, prefixes export by gateway name/composite ID, or inline/SSH route scripts run `vsx stat -l`
- **THEN** `SyncCompletedEvent` SHALL be yielded only after route collection completes, `_score_interface_group` SHALL match annotations for LPM `best_entry`, `export_topology_prefixes` SHALL match manual gateways by name/UID/composite ID, and `awk` SHALL resolve spaced VS names

#### Scenario: SCN-TOPO-022-3 — ScriptRepositoryService write paths and targeted topology refresh scrub bare SIDs and map permission errors

- **GIVEN** an active or isolated `WriteSession` in `ensure_repository_script` / `delete_repository_script`, or an exception during targeted topology refresh or lazy package loading
- **WHEN** a `SessionError`, `AuthenticationError`, or generic `Exception` embeds a bare session SID
- **THEN** `ScriptRepositoryService` SHALL map permission errors to `RepositoryScriptPermissionError` consistently and all error/log/event outputs SHALL scrub bare cached and active SIDs via `known_sids`
