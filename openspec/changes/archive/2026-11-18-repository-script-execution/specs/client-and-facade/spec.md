# Spec Delta

## ADDED Requirements

### Requirement: Script Repository Read, Check, Ensure, and Delete Facade

`ArodonataClient` SHALL expose traced async methods `get_repository_script`, `list_repository_scripts`, `check_repository_script`, `ensure_repository_script`, and `delete_repository_script` using shared read-only sessions for reads/checks and isolated write sessions (omitting `"repository-script"` from `SessionOverlay`) only when creation, modification, or deletion is required.

#### Scenario: Read-only script check and zero-write fast path in ensure_repository_script

- **WHEN** `check_repository_script` or `ensure_repository_script(mgmt_name, "arodonata-collect-routes-v1", expected_body, domain="Corp")` runs while `"arodonata-collect-routes-v1"` already exists in `"Corp"` with matching normalized line endings (`\r\n` -> `\n`, stripped trailing whitespace) and matching any explicitly supplied metadata (`comments`, `color`, `tags`)
- **THEN** the inspection SHALL run strictly read-only over `sid_cache` (without opening a `WriteSession` or calling `publish`) and `ensure_repository_script` SHALL return `EnsureRepositoryScriptResult(action="unchanged")`

#### Scenario: Missing or outdated script created or updated without SessionOverlay pollution

- **WHEN** `ensure_repository_script(mgmt_name, script_name, script_body, domain="Corp")` runs while the script is absent, differs from `script_body`, or has mismatched explicit `comments`/`color`/`tags` (either standalone or inside an existing `WriteSession`)
- **THEN** standalone calls SHALL open an isolated `WriteSession`, execute `add-repository-script` or `set-repository-script`, publish and invalidate `"Corp"`, and return `action="created"` or `"updated"`, while active `WriteSession` calls SHALL reuse the caller's session without auto-publishing or polluting `SessionOverlay` object caches

#### Scenario: Permission error during script check or provisioning raises RepositoryScriptPermissionError

- **WHEN** a read-only or restricted administrator invokes `ensure_repository_script` or `delete_repository_script` in a domain lacking `manage-repository-scripts: write` or `publish-sessions` privileges
- **THEN** `ArodonataClient` SHALL discard any uncommitted session cleanly and raise `RepositoryScriptPermissionError` carrying `mgmt_name`, `domain_name`, `script_ref`, and `operation` without exposing `sid` or credentials

### Requirement: Universal Application-Agnostic Repository Script Execution Facade

`ArodonataClient` SHALL expose traced async `run_repository_script(mgmt_name, script_name_or_uid, targets, *, domain=None, args=None, comments=None, timeout=None, script_timeout=None)` sending `run-script` with `script-type="repository"` and caller-supplied `args` verbatim (`str`) or space-joined (`Sequence[str]`) over a dedicated non-read-only session (or active `WriteSession`) without `publish` or `discard`.

#### Scenario: Universal execution forwards application script name, targets, and args verbatim

- **WHEN** an external application invokes `await client.run_repository_script("mds1", "app-custom-diag", ["gw-01", "gw-02"], domain="Corp", args=["--mode", "fast"])` (or with `args="--mode fast"`)
- **THEN** `ArodonataClient` SHALL invoke `run-script` with `{"script-name": "app-custom-diag", "script-type": "repository", "targets": ["gw-01", "gw-02"], "args": "--mode fast"}` (omitting `"script"` and `"script-base64"`, or passing `"uid"` for UUID targets), poll `show-task`, Base64-decode per-target outputs into `RepositoryScriptExecutionOutcome`, and never inject route-collection or VSX logic

#### Scenario: Execution outside WriteSession uses a non-read-only session without publish or discard

- **WHEN** `run_repository_script` runs outside an active `WriteSession`
- **THEN** it SHALL authenticate a dedicated non-read-only session (`read_only=False`), execute `run-script` and `show-task`, log out cleanly without calling `publish` or `discard`, and never reuse `sid_cache`

#### Scenario: Missing script or read-only session denial maps to typed script exceptions

- **WHEN** Check Point rejects `run-script` because the named repository script does not exist in the domain or because the caller lacks `run-repository-script` (or authenticated with `read-only: true`)
- **THEN** `run_repository_script` SHALL raise `RepositoryScriptNotFoundError` or `RepositoryScriptPermissionError` respectively without falling back to inline `"one time"` script execution

### Requirement: Route-Collection Repository Script Convenience Helpers

`ArodonataClient` SHALL expose `check_route_collection_script` and `ensure_route_collection_script` helpers wrapping `check_repository_script` and `ensure_repository_script` with `settings.cprid_repository_script_name` (or an explicit `script_name` override) and the canonical route-collection repository script body.

#### Scenario: Host application checks and provisions the canonical route-collection script

- **WHEN** a host application calls `await client.check_route_collection_script("mds1", "Corp")` followed by `await client.ensure_route_collection_script("mds1", "Corp")`
- **THEN** `ArodonataClient` SHALL check and provision the canonical `arodonata-collect-routes-v1` script body in `"Corp"` using `settings.cprid_repository_script_name` (default `"arodonata-collect-routes-v1"`)

## MODIFIED Requirements

### Requirement: Gateway Topology and Candidate Discovery Facade Methods

`ArodonataClient` SHALL accept an optional `gateway_cli` (`GatewayCliPort` or async command callback) for SSH command execution on gateways, expose `topology_service` (`TopologyService`), and provide traced async facade methods `refresh_topology(..., gateways=..., collect_routes=...)`, `stream_refresh_topology(..., gateways=..., collect_routes=...)`, `collect_gateway_routes(..., cprid_script_mode=..., repository_script_name=..., repository_script_args_fn=...)`, `check_route_collection_script(...)`, `ensure_route_collection_script(...)`, `get_gateway_topology(...)`, `get_topology_diagnostics(...)`, `reconcile_gateway_topology(..., check_policy=...)`, `upsert_topology_annotations(...)`, `get_topology_annotations(...)`, `delete_topology_annotations(...)`, `export_topology_prefixes(...)`, and `find_affected_gateways(sources, destinations, ..., min_confidence=..., include_standby=..., include_policy_inferred=...)` returning typed Pydantic models.

#### Scenario: Consumer resolves affected gateways and policy packages via ArodonataClient

- **WHEN** a downstream consumer calls `await client.find_affected_gateways(sources=["10.1.1.10"], destinations=["10.2.2.20"], mgmt_name="mds1", include_policy_inferred=True, cache_mode="smart")`
- **THEN** `ArodonataClient` SHALL ensure the topology cache is synchronized according to `cache_mode` and return a ranked list of `AffectedGatewayCandidate` instances containing `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, `confidence_factors`, `warnings`, and `matched_flows` (including `policy_inferred` matches when enabled)

#### Scenario: Host application injects SSH callback and reconciles gateway routes via ArodonataClient

- **WHEN** a host application initializes `ArodonataClient(settings, gateway_cli=ssh_exec_fn)` and calls `await client.collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateways=["gw-01"])` followed by `await client.reconcile_gateway_topology(mgmt_name="mds1", domain="Corp", gateways=["gw-01"], check_policy=True)`
- **THEN** `ArodonataClient` SHALL invoke `ssh_exec_fn` for `"gw-01"`, persist the parsed route intervals into `arodonata_gateway_topology`, and return a `TopologyReconciliationReport` detailing any discrepancies between SmartConsole topology, live routes, and gateway-targeted policy rules

#### Scenario: Pipelined collection in one domain runs concurrently with script provisioning in another domain

- **WHEN** a host application runs `collect_gateway_routes(mgmt_name="mds1", domain="DomainA", cprid_script_mode="repository")` concurrently with `ensure_route_collection_script("mds1", "DomainB")`
- **THEN** both operations SHALL maintain isolated session contexts without `WriteSession` `contextvars` bleed or cross-domain lock blocking, allowing route collection in `"DomainA"` to complete while `"DomainB"` provisions and publishes its repository script
