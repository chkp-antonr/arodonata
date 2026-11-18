# Spec Delta

## MODIFIED Requirements

### Requirement: Live Gateway Route Collection via SSH Dependency Injection and CPRID Fallback

`TopologyService.collect_gateway_routes()` SHALL collect live IPv4 routing tables (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`, and `0.0.0.0/0` default routes) by invoking an injected `GatewayCliPort` (or async SSH callback in bash) first, and falling back to Check Point Management API `run-script` (`cprid` via `TaskWaiter`) when no SSH executor is provided or when SSH execution fails and `fallback_to_cprid=True`, honoring `cprid_script_mode` (`"inline" | "repository" | "auto"`), `repository_script_name`, and `repository_script_args_fn` overrides (also forwarded from `refresh_topology`, `stream_refresh_topology`, and `reconcile_gateway_topology`).

#### Scenario: Cluster and VSX Virtual System route collection via SSH DI and vsenv context switching

- **WHEN** `collect_gateway_routes()` runs for a `CpmiGatewayCluster` (with two `cluster-member` nodes) and a VSX `CpmiVsNetobj` (`vsid=3` hosted on physical parent `VSX-GW-01`)
- **THEN** it SHALL resolve the cluster to its `cluster-member` node targets and resolve the Virtual System to `VSX-GW-01` (`vsid=3`), executing a bash script that switches context via `vsenv "$vsid" >/dev/null 2>&1 </dev/null`, verifies `$FWDIR` contains `CTX00003`, and runs `ip -4 route show </dev/null` to persist normalized route intervals in `arodonata_gateway_topology`

#### Scenario: Automatic fallback from SSH callback to Management API run-script

- **WHEN** a host application provides an SSH `gateway_cli` callback that raises a connection error for a remote branch gateway while `fallback_to_cprid=True`
- **THEN** `TopologyService` SHALL execute the route collection script on that gateway via Management API `run-script`, wait for the task via `TaskWaiter`, decode the Base64 output from `task-details[].responseMessage`, and parse the resulting routes

#### Scenario: Per-physical-node VSX serialization, MDS concurrency cap, and single-flight route collection

- **WHEN** `collect_gateway_routes()` runs across multiple VSX Virtual Systems sharing one physical VSX host (`VS0`) alongside independent gateways, or when two callers invoke `collect_gateway_routes()` concurrently with identical scope
- **THEN** `TopologyService` SHALL serialize CLI/`cprid` execution per physical `node_uid` so at most one command runs at a time on `VS0` without blocking independent gateways up to `route_collect_concurrency`, and coalesce identical concurrent calls into a single in-flight collection

#### Scenario: Large routing table cap and clish bypass protect gateways holding BGP full-view tables

- **WHEN** `collect_gateway_routes()` runs on a gateway whose routing table exceeds `max_routes_per_gateway` (or `10000` kernel routes for `clish`)
- **THEN** the collection script SHALL skip `clish -c "show route"` when kernel routes exceed `10000` lines, truncate collected routes at `max_routes_per_gateway`, and record a truncation warning in `GatewayRouteCollectionStatus.warnings`

#### Scenario: Repository mode executes canonical pre-approved script across standalone, cluster, and VSX gateways

- **WHEN** `collect_gateway_routes(..., cprid_script_mode="repository")` runs against a standalone gateway, a `CpmiGatewayCluster`, and VSX Virtual Systems (`vsid=3` and `vs_name="VS_DMZ"`) using a restricted account holding `run-repository-script` without `run-one-time-script`
- **THEN** `TopologyService` SHALL invoke `run-script` with `script-type="repository"`, `script-name=settings.cprid_repository_script_name`, positional `args` (`"<max_routes> <vsid> <vs_name>"`), and zero `"script"`/`"script-base64"` fields, parse all Gaia/Clish/VSX route markers identically to inline mode, and reject/fail closed if the script is missing (`error_code="repository_script_not_found"`) or unauthorized (`error_code="repository_script_permission_denied"`)

#### Scenario: Host application overrides repository script name and positional arguments builder

- **WHEN** a host application invokes `collect_gateway_routes(..., cprid_script_mode="repository", repository_script_name="corp-routes-v2", repository_script_args_fn=custom_fn)`
- **THEN** `TopologyService` SHALL invoke `"corp-routes-v2"` with `"script-type": "repository"` and forward the string returned by `custom_fn(target, max_routes)` as `"args"`

#### Scenario: Auto mode falls back per domain on missing repository script while preserving strict repository errors

- **WHEN** `collect_gateway_routes(..., cprid_script_mode="auto")` runs across `"DomainA"` (where `arodonata-collect-routes-v1` exists) and `"DomainB"` (where the repository script is absent)
- **THEN** `"DomainA"` SHALL succeed via `"script-type": "repository"` and `"DomainB"` SHALL fall back automatically to inline `"one time"` execution (caching the per-flight fallback decision for `"DomainB"`), whereas `cprid_script_mode="repository"` SHALL fail `"DomainB"` targets with `error_code="repository_script_not_found"` without sending any inline script

## ADDED Requirements

### Requirement: Stateful Script Repository and Repository-Mode Run-Script Emulation in FileReplayApiMock

`FileReplayApiMock` SHALL support per-domain `add-repository-script`, `show-repository-script`, `show-repository-scripts`, `set-repository-script`, and `delete-repository-script` (isolated in uncommitted `WorkSession` until `publish`), enforce non-read-only sessions and configurable `run-repository-script` vs `run-one-time-script` permissions on `run-script`, and execute `script-type="repository"` targets using positional `args`.

#### Scenario: End-to-end provisioning and restricted-permission repository execution in FileReplayApiMock

- **WHEN** a test provisions `arodonata-collect-routes-v1` via `ensure_route_collection_script` (verified invisible to other sessions until `publish`) and then configures `FileReplayApiMock` with `allow_one_time_script=False, allow_repository_script=True`
- **THEN** `collect_gateway_routes(cprid_script_mode="repository")` SHALL succeed across cluster and VSX replay fixtures using `script-type="repository"`, whereas `collect_gateway_routes(cprid_script_mode="inline")` SHALL fail with `error_code="repository_script_permission_denied"`
