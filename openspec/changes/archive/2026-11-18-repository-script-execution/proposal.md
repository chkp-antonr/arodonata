# Proposal: Check Point Script Repository Management & Execution (`repository-script`)

## Why

Live gateway route collection and diagnostic scripts executed via Check Point Management API `run-script` currently support only ad-hoc `"one time"` inline scripts (`"script"` / `"script-base64"`), which require the administrator permission profile to grant `gateways.run-one-time-script: true`. That permission effectively grants arbitrary shell execution across managed gateways and cannot be enabled for least-privilege or read-only automation accounts.

Check Point Management API (`v1.9`–`v2.2`, verified on live MDSM `mdsH5` API `v2.2`) natively provides per-domain Script Repository management (`add-repository-script`, `show-repository-script`, `show-repository-scripts`, `set-repository-script`, `delete-repository-script`) and pre-approved script execution via `run-script` with `"script-type": "repository"` and positional `"args"`. With a `Domain Level Only` multi-domain profile and a customized domain profile setting `run-repository-script: true`, `run-one-time-script: false`, `manage-repository-scripts: "read"`, `edit-common-objects: false`, and `publish-sessions: false`, a restricted automation account can execute administrator-approved repository scripts while Check Point blocks unapproved inline `"one time"` scripts and any object or script edits.

Host applications need two cleanly separated layers in `arodonata`:

1. A **universal, application-agnostic Script Repository facade** (`ScriptRepositoryService` and `ArodonataClient` methods) that inspects, provisions, and executes any pre-approved repository script with caller-supplied `targets` and `args` forwarded transparently without route-collection or VSX assumptions.
2. **`TopologyService.collect_gateway_routes()` consuming that universal layer as an application**, supporting configurable `"inline"`, `"repository"`, and `"auto"` execution modes, an official versioned route-collection script (`arodonata-collect-routes-v1`), custom application script overrides, and pipelined concurrent readiness checks and provisioning across domains.

## What Changes

- **Configuration (`core/config.py`)**:
  - Add `CpridScriptMode = Literal["inline", "repository", "auto"]` (`cprid_script_mode: CpridScriptMode = "inline"`, alias `ARODONATA_CPRID_SCRIPT_MODE`) and `cprid_repository_script_name: str = "arodonata-collect-routes-v1"` (alias `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME`, validated non-blank) to `ArodonataSettings`, without implicit `.env` loading.
- **Universal Script Repository Models, Errors & Service (`core/models/scripts.py`, `core/errors.py`, `core/services/script_service.py`, `client.py`, `adapters/checkpoint/client.py`)**:
  - Define Pydantic v2 models in `src/arodonata/core/models/scripts.py` (re-exported from `arodonata.core.models` and `arodonata`): `CpridScriptMode`, `RepositoryScript`, `RepositoryScriptStatus`, `EnsureRepositoryScriptResult`, `ScriptTargetExecutionResult`, and `RepositoryScriptExecutionOutcome`.
  - Add typed exceptions in `src/arodonata/core/errors.py` (re-exported from `arodonata` and `arodonata.core.errors`): `RepositoryScriptError(ArodonataError)`, `RepositoryScriptNotFoundError(mgmt_name, domain_name, script_ref)`, and `RepositoryScriptPermissionError(mgmt_name, domain_name, script_ref, operation)`.
  - Add `"repository-script"`, `"api-key"`, `"md-permissions-profile"`, and `"domain-permissions-profile"` to `NON_OVERLAY_MUTATION_TARGETS` in `src/arodonata/adapters/checkpoint/client.py` so mutations on repository scripts or profiles inside a `WriteSession` never pollute `SessionOverlay` object caches.
  - Implement `ScriptRepositoryService` (`src/arodonata/core/services/script_service.py`, re-exported from `arodonata.core.services`) and traced `ArodonataClient` methods:
    - `get_repository_script(...)` and `list_repository_scripts(...)` (read-only over `sid_cache`, or using active `WriteSession` if present).
    - `check_repository_script(...)` returning `RepositoryScriptStatus` (`exists`, `script`, `matches_expected`, `error_code`, `error`) without opening any write session or mutating Check Point state.
    - `ensure_repository_script(...)` returning `EnsureRepositoryScriptResult` (`action: "unchanged" | "created" | "updated"`), performing a zero-write fast path over `sid_cache` when the normalized `script_body` already matches and otherwise creating or updating via `add-repository-script` / `set-repository-script` inside an isolated `write_session` (or the caller's active `WriteSession`).
    - `delete_repository_script(...)` for lifecycle cleanup/testing.
    - Universal `run_repository_script(mgmt_name, script_name_or_uid, targets, *, domain=None, args=None, comments=None, timeout=None, script_timeout=None)` forwarding `"script-type": "repository"` and caller `args` (`str` verbatim or `Sequence[str]` joined cleanly) over a dedicated non-read-only session without `publish` or `discard` (or the active `WriteSession`), decoding multi-target Base64 `show-task` results, and mapping missing-script / permission rejections to `RepositoryScriptNotFoundError` / `RepositoryScriptPermissionError`.
- **Route Collection Consuming Script Repository "As an Application" (`core/services/route_collector.py`, `core/services/topology_service.py`, `core/models/topology.py`, `client.py`)**:
  - Export `DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME = "arodonata-collect-routes-v1"`, `build_route_collection_repository_script()`, and `format_route_collection_repository_args(target, *, max_routes=None)` in `route_collector.py`.
  - Extend `GatewayCliResult` and `GatewayRouteCollectionStatus` (`core/models/topology.py`) with optional `error_code: str | None = None` (`"repository_script_not_found"`, `"repository_script_permission_denied"`).
  - Extend `execute_gateway_cli`, `TopologyService.collect_gateway_routes` (plus `refresh_topology`, `stream_refresh_topology`, and `reconcile_gateway_topology` route-collection forwarding), and `ArodonataClient` wrappers with optional `cprid_script_mode`, `repository_script_name`, and `repository_script_args_fn` overrides, plus `check_route_collection_script` and `ensure_route_collection_script` convenience methods.
  - Guarantee that `collect_gateway_routes(..., domain="DomainA")` and concurrent `ensure_repository_script(..., domain="DomainB")` isolate their Check Point sessions without `contextvars` leakage or domain lock contention.
- **Stateful Replay Emulator (`testing/_emulator_models.py`, `testing/replay_mock.py`)**:
  - Add stateful domain-scoped `add-repository-script`, `show-repository-script`, `show-repository-scripts`, `set-repository-script`, and `delete-repository-script` support (isolated in uncommitted `WorkSession` until `publish`) plus `script-type="repository"` execution, `read_only` session enforcement, positional `args` parsing, and simulated `run-repository-script` vs `run-one-time-script` permissions in `FileReplayApiMock`.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `configuration`: Add `cprid_script_mode` (`ARODONATA_CPRID_SCRIPT_MODE`) and `cprid_repository_script_name` (`ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME`) settings to `ArodonataSettings`.
- `client-and-facade`: Add universal Check Point Script Repository CRUD/status/execution facade methods (`get_repository_script`, `list_repository_scripts`, `check_repository_script`, `ensure_repository_script`, `delete_repository_script`, `run_repository_script`), route-collection convenience wrappers (`check_route_collection_script`, `ensure_route_collection_script`), `RepositoryScript*` exceptions/models, and repository-mode parameters on `collect_gateway_routes`.
- `gateway-topology`: Extend `TopologyService.collect_gateway_routes()` (and `refresh_topology` / `reconcile_gateway_topology`) to execute pre-approved repository scripts via `"script-type": "repository"` in `"repository"` and `"auto"` modes, support custom application script/args hooks, populate `error_code` on repository script errors, and add stateful repository script CRUD and permission emulation to `FileReplayApiMock`.

## Impact

- `src/arodonata/core/config.py`: `CpridScriptMode`, `cprid_script_mode`, `cprid_repository_script_name`.
- `src/arodonata/core/models/scripts.py` (new), `src/arodonata/core/models/topology.py`, `src/arodonata/core/models/__init__.py`.
- `src/arodonata/core/errors.py`.
- `src/arodonata/adapters/checkpoint/client.py`: `NON_OVERLAY_MUTATION_TARGETS` update.
- `src/arodonata/core/services/script_service.py` (new), `src/arodonata/core/services/route_collector.py`, `src/arodonata/core/services/topology_service.py`, `src/arodonata/core/services/__init__.py`.
- `src/arodonata/client.py` and `src/arodonata/__init__.py`.
- `src/arodonata/testing/_emulator_models.py`, `src/arodonata/testing/replay_mock.py`.
- `tests/unit/` and `tests/integration/` (new unit/replay coverage for universal repository script management, restricted permissions, `"inline"` / `"repository"` / `"auto"` route collection, and cross-domain pipelining).
