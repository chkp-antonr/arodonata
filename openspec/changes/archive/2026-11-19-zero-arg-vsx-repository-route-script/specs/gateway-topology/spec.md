# Gateway Topology Specification Delta

## MODIFIED Requirements

### Requirement: CPRID Script Execution Modes for Route Collection

**ID**: REQ-TOPO-008\
**Intent**: Support pre-approved repository scripts, inline scripts, and automatic fallback when collecting gateway routes via `run-script`.\
**Non-goals**: General-purpose application repository scripts (`REQ-CLIENT-012`) or `ArodonataSettings` validation (`REQ-CONFIG-005`).

`collect_gateway_routes()`, `refresh_topology()`, `stream_refresh_topology()`, and `reconcile_gateway_topology()` SHALL honor `cprid_script_mode` (`"inline" | "repository" | "auto"`), `repository_script_name`, and `repository_script_args_fn` overrides, defaulting `"repository"` mode to zero-argument canonical execution with self-detecting multi-VS VSX bundling and per-node coalescing.

#### Scenario: SCN-TOPO-008-1 — Repository mode executes canonical pre-approved script across standalone, cluster, and VSX gateways

- **GIVEN** an account holding `run-repository-script` without `run-one-time-script`
- **WHEN** `collect_gateway_routes(..., cprid_script_mode="repository")` runs across standalone, cluster, and VSX (`vsid=3`, `vs_name="VS_DMZ"`) targets with `repository_script_args_fn=None`
- **THEN** `TopologyService` SHALL send `run-script` with `script-type="repository"`, `script-name=settings.cprid_repository_script_name`, and omitted `"args"` (plus zero `"script"`/`"script-base64"` fields) so least-privilege repository profiles succeed without `"Insufficient permissions to run this script with arguments."`
- **AND** it SHALL parse Gaia/Clish/VSX route markers identically to inline mode, or fail closed with `error_code="repository_script_not_found"` or `"repository_script_permission_denied"`

#### Scenario: SCN-TOPO-008-2 — Host application overrides repository script name and positional arguments builder

- **WHEN** `collect_gateway_routes(..., cprid_script_mode="repository", repository_script_name="corp-routes-v2", repository_script_args_fn=custom_fn)` runs
- **THEN** `TopologyService` SHALL invoke `"corp-routes-v2"` with `"script-type": "repository"` and pass `custom_fn(target, max_routes)` as `"args"`

#### Scenario: SCN-TOPO-008-3 — Auto mode falls back per domain on missing repository script while preserving strict repository errors

- **GIVEN** `"DomainA"` having `arodonata-collect-routes-v1` and `"DomainB"` lacking it
- **WHEN** `collect_gateway_routes(..., cprid_script_mode="auto")` runs vs `cprid_script_mode="repository"`
- **THEN** in `"auto"` mode, `"DomainA"` SHALL use `"script-type": "repository"` and `"DomainB"` SHALL fall back per domain to inline `"one time"` execution (cached per flight)
- **AND** in `"repository"` mode, `"DomainB"` SHALL fail with `error_code="repository_script_not_found"` without sending an inline script

#### Scenario: SCN-TOPO-008-4 — Zero-argument VSX self-detection bundle coalesces per physical VSX node and isolates per-VS errors

- **GIVEN** a VSX gateway or cluster hosting multiple L3 Virtual Systems (and optionally an L2 Virtual Switch or a failing VS context) collected in `"repository"` mode with `repository_script_args_fn=None`
- **WHEN** the canonical zero-argument route-collection script runs once per physical VSX node
- **THEN** the script SHALL auto-detect VSX via `vsx stat -l </dev/null`, iterate L3 Virtual Systems/Virtual Routers (`VSID > 0`, skipping Virtual Switches) with `vsenv` and `CTX%05d` verification, isolate single-VS errors via `===ARODONATA_VS_ERROR ...===`, and emit `===ARODONATA_VSX_BUNDLE_START===` / `===ARODONATA_VS_START vsid=<id> name=<name>===` ... `===ARODONATA_VS_END===` / `===ARODONATA_VSX_BUNDLE_END===`
- **AND** `collect_gateway_routes()` SHALL coalesce sibling Virtual Systems sharing `(mgmt_name, domain_name, node_key)` onto one `run-script` call per physical node per run, extract each VS slice by `vsid` (or `vs_name` fallback), enforce `max_routes_per_gateway`, and preserve backward-compatible single-context execution when explicit positional arguments are supplied

### Requirement: Stateful Script Repository and Repository-Mode Run-Script Emulation in FileReplayApiMock

**ID**: REQ-TOPO-018\
**Intent**: Enable offline end-to-end testing of repository-script provisioning, session isolation, and permission enforcement.\
**Non-goals**: General replay CRUD and session emulation (`REQ-ITEST-009`..`REQ-ITEST-014`).

`FileReplayApiMock` SHALL support per-domain repository script CRUD (isolated in uncommitted write sessions until `publish`), reject non-empty `"args"` on repository `run-script` unless `allow_one_time_script=True`, emit zero-argument VSX bundles or parameterized outputs, and optionally encode `"script-body"` as Base64.

#### Scenario: SCN-TOPO-018-1 — End-to-end provisioning and restricted-permission repository execution in FileReplayApiMock

- **GIVEN** `arodonata-collect-routes-v1` provisioned via `ensure_route_collection_script` (invisible to other sessions until `publish`) and `FileReplayApiMock(allow_one_time_script=False, allow_repository_script=True)`
- **WHEN** `collect_gateway_routes(cprid_script_mode="repository")` vs `cprid_script_mode="inline"` runs across cluster and VSX replay fixtures
- **THEN** `"repository"` mode SHALL succeed without `"args"` using `script-type="repository"`, whereas `"inline"` mode SHALL fail with `error_code="repository_script_permission_denied"`

#### Scenario: SCN-TOPO-018-2 — FileReplayApiMock rejects non-empty repository args without one-time permission and emulates R82 Base64 script-body

- **GIVEN** `FileReplayApiMock(allow_one_time_script=False, allow_repository_script=True, encode_repository_script_body_base64=True)`
- **WHEN** callers invoke `run-script` (`script-type="repository"`) with non-empty `"args"` vs omitted `"args"` on a VSX host, and inspect `show-repository-script`
- **THEN** non-empty `"args"` SHALL return HTTP `400` (`err_validation_failed`, `"Insufficient permissions to run this script with arguments."`), omitted `"args"` SHALL succeed emitting the zero-arg VSX bundle, and `show-repository-script` SHALL return Base64-encoded `"script-body"` decoded cleanly by `check_repository_script`
