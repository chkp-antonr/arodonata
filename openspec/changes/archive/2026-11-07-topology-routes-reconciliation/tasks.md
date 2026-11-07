# Tasks

## 1. Core Models, Ports, and Confidence Weight Configuration

- [x] 1.1 Extend `src/arodonata/core/models/topology.py` with `AntiSpoofingMode`, `STATIC_TOPOLOGY_SOURCES`, `LIVE_ROUTE_SOURCES`, `GatewayCliTarget`, `GatewayCliResult`, `TopologyDiagnostic`, `TopologyDiscrepancy`, `TopologyReconciliationReport`, `TopologyAnnotation`, `ExportedTopologyPrefix`, `ConfidenceDelta`, `RouteCollectionOutcome`, and confidence/warning fields on `GatewayTopologyEntry`, `TrafficFlowMatch`, and `AffectedGatewayCandidate`, verifying model validation with unit tests
- [x] 1.2 Add `TopologyConfidenceWeights` to `src/arodonata/core/config.py` (`ArodonataSettings.topology_confidence_weights`) with configurable positive and negative evidence deltas, and verify defaults and overrides in unit tests
- [x] 1.3 Extend `src/arodonata/core/ports/__init__.py` with `GatewayCliPort` and updated `CachePort` methods for scoped topology replacement (`gateway_uids`, `source_types`) and `TopologyAnnotation` CRUD (`get_topology_annotations`, `upsert_topology_annotations`, `delete_topology_annotations`), verifying typing with `uv run mypy src`

## 2. Database Schema and Storage Adapter (`arodonata_gateway_topology` & `arodonata_topology_annotations`)

- [x] 2.1 Add `anti_spoofing_mode` to `GatewayTopologyRecord` and define `TopologyAnnotationRecord` (`arodonata_topology_annotations`) in `src/arodonata/adapters/storage/tables.py`, registering it in `ARODONATA_TABLE_NAMES`
- [x] 2.2 Implement scoped `replace_domain_topology` (`gateway_uids`, `source_types` filtering) and `TopologyAnnotation` persistence methods in `src/arodonata/adapters/storage/cache_adapter.py`, and verify with unit tests in `tests/unit/test_topology_service.py` that static topology refresh preserves live route rows and annotations

## 3. Static Topology Diagnostics and Targeted Per-Gateway Refresh

- [x] 3.1 Enhance `_normalize_interface` and `TopologyService` in `src/arodonata/core/services/topology_service.py` to extract `anti_spoofing_mode` (`"prevent" | "detect" | "off" | "unknown"`) and implement `get_topology_diagnostics()` covering `not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `unresolved_specific`, `empty_specific`, `missing_ip_mask`, `no_interfaces`, and informational `one_arm_topology` (without warning on internal-only gateways), verified by unit tests
- [x] 3.2 Add targeted `gateways: Sequence[str] | None = None` and `collect_routes: bool = False` support to `refresh_topology` and `stream_refresh_topology` so single-gateway refreshes update only the specified gateway's rows, verified by unit tests

## 4. Live Gateway Route Collection (`GatewayCliPort` SSH DI + `cprid` Fallback & VSX `vsenv`)

- [x] 4.1 Implement `collect_gateway_routes()` in `src/arodonata/core/services/topology_service.py` with `GatewayCliPort` / async SSH callback execution, automatic fallback to Check Point Management API `run-script` (`cprid` + Base64 `responseMessage` decoding), cluster member target resolution, and safe VSX `vsenv` context switching (`vsenv "$vsid" >/dev/null 2>&1 </dev/null` with `$FWDIR` `CTX%05d` verification), verified by unit tests
- [x] 4.2 Implement `ip -4 route show` and `clish -c "show route"` route output parsers producing `connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`, and `0.0.0.0/0` external route intervals, verified by unit tests

## 5. Reconciliation, Administrator Annotations, IPAM Export, and Delta Confidence Scoring

- [x] 5.1 Implement `reconcile_gateway_topology()` in `src/arodonata/core/services/topology_service.py` detecting `stale_in_topology`, `missing_in_topology`, `interface_mismatch`, `default_route_mismatch`, `cluster_member_drift`, and `resolved_by_routing` while honoring `TopologyAnnotation` dispositions, verified by unit tests
- [x] 5.2 Implement `upsert_topology_annotations()`, `get_topology_annotations()`, `delete_topology_annotations()`, and `export_topology_prefixes()` on `TopologyService`, verified by unit tests
- [x] 5.3 Implement Evidence Delta Confidence Scoring in `TopologyService.find_affected_gateways()` using `TopologyConfidenceWeights` and `TopologyAnnotation` overrides (`ignore`, `standby_dynamic`, `manual`, `trust_static_topology=False`), populating `confidence`, `is_standby_path`, `confidence_factors`, and `warnings` on `TrafficFlowMatch` and `AffectedGatewayCandidate`, verified by unit tests

## 6. Client Facade, MCP Tool Surface, and End-to-End Verification

- [x] 6.1 Wire `gateway_cli` and new topology methods (`collect_gateway_routes`, `get_topology_diagnostics`, `reconcile_gateway_topology`, `upsert_topology_annotations`, `get_topology_annotations`, `delete_topology_annotations`, `export_topology_prefixes`, and updated `refresh_topology` / `find_affected_gateways`) in `src/arodonata/client.py` and `src/arodonata/__init__.py`, verified by facade unit tests
- [x] 6.2 Update `locate_gateways` and `cache_control(scope="topology")` in `src/arodonata/mcp/tools.py` to support targeted `gateways`, `collect_routes`, `min_confidence`, `include_standby`, confidence breakdown, and topology warnings, verified by MCP unit tests
- [x] 6.3 Build a synthetic multi-hundred-gateway enterprise topology test suite (`tests/unit/test_topology_scale_scenarios.py`) covering transit chains, stale anti-spoofing groups, `Detect`-mode interfaces, BGP/OSPF routes, cluster member drift, and human `TopologyAnnotation` overrides (`standby_dynamic`, `ignore`, `manual`, `trust_static_topology=False`) to verify accuracy and search performance at scale
- [x] 6.4 Run all quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest`, `npx markdownlint-cli`, and `openspec validate --specs --no-interactive`) in the worktree
