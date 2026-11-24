# Spec Delta

## MODIFIED Requirements

### Requirement: Modular Topology Package Compatibility, Boundary SID Redaction, and Fail-Fast TLS Identity Propagation

**ID**: REQ-TOPO-020\
**Intent**: Guarantee backward-compatible shim re-exports and logger method hooking for the modular `arodonata.core.services.topology` package, enforce SID redaction at model and service boundaries, and fail fast on `ServerIdentityError` across live route collection and targeted refresh.\
**Non-goals**: Internal submodule file naming beyond public `topology` / shim compatibility (`REQ-CLIENT-018`).

`topology_service` and `route_collector` SHALL serve as backward-compatible shims for `arodonata.core.services.topology` with shared `logger` identity while omitting internal `collect_gateway_routes` from `topology.__all__`; script/CLI boundary models, `ScriptRepositoryService`, route collection, and targeted refresh SHALL redact patterned and bare SIDs; and `ServerIdentityError` SHALL propagate fail-fast while preserving `None` SSH fallback parity.

#### Scenario: SCN-TOPO-020-1 — Shims preserve exact re-export identity and logger method interception while omitting internal orchestration exports

- **WHEN** callers import `TopologyService`, shared helpers, normalizers, or route-collection utilities from `arodonata.core.services.topology_service` or `arodonata.core.services.route_collector` and monkeypatch `topology_service.logger.warning`
- **THEN** imported symbols SHALL reference the exact canonical objects in `arodonata.core.services.topology`, warnings emitted by topology submodules SHALL be intercepted by the patched `logger.warning`, and `arodonata.core.services.topology.__all__` SHALL omit internal `collect_gateway_routes`

#### Scenario: SCN-TOPO-020-2 — Boundary models, ScriptRepositoryService, route collection, and targeted refresh scrub patterned and dedicated SIDs

- **GIVEN** exceptions, API error payloads, task outputs, or `gateway_cli` return values containing `X-chkp-sid`, JSON `"sid"`, `Authorization: Bearer`, or bare dedicated `arodonata-route-collect` / `arodonata-run-repo-script` SID tokens across direct SSH (`fallback_to_cprid=False`), `_vs_error=` stdout, repository mode without `cprid_session_getter`, active `WriteSession` `run_repository_script` failures, `collect_gateway_routes`, or targeted `stream_refresh_topology(gateways=...)`
- **THEN** all resulting `GatewayCliResult` (`stdout`, `bundle_stdout`), `GatewayRouteCollectionStatus`, `DomainSyncState`, `DomainSyncFailedEvent`, `SyncCompletedEvent`, `RefreshOutcome`, `ScriptTargetExecutionResult` (`stdout`, `status_description`), `RepositoryScriptExecutionOutcome` (`status_description`), and `WARNING` log messages SHALL scrub every patterned and active/dedicated SID token with `***REDACTED***`

#### Scenario: SCN-TOPO-020-3 — Fatal ServerIdentityError propagates fail-fast across route collection and targeted refresh with SSH None fallback parity

- **GIVEN** a `ServerIdentityError` raised during SSH execution, inline or repository `cprid`, `AutoScriptModeResolver` probing, multi-gateway `collect_gateway_routes`, or multi-domain targeted `stream_refresh_topology(gateways=...)` / `refresh_topology(gateways=...)`
- **THEN** `ServerIdentityError` SHALL propagate immediately, cancel sibling route-collection tasks, preserve domain `routes` sync states (no `"failed"` downgrade), skip unvisited domains in targeted refresh without emitting `DomainSyncFailedEvent`, log out any opened dedicated sessions, and omit spurious SSH error prefixes when `gateway_cli` returns `None` during `cprid` fallback
