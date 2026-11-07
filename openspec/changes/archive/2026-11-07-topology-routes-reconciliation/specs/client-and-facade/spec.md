# Client and Facade Specification Delta

## MODIFIED Requirements

### Requirement: Gateway Topology and Candidate Discovery Facade Methods

`ArodonataClient` SHALL accept an optional `gateway_cli` (`GatewayCliPort` or async command callback) for SSH command execution on gateways, expose `topology_service` (`TopologyService`), and provide traced async facade methods `refresh_topology(..., gateways=..., collect_routes=...)`, `stream_refresh_topology(..., gateways=..., collect_routes=...)`, `collect_gateway_routes(...)`, `get_gateway_topology(...)`, `get_topology_diagnostics(...)`, `reconcile_gateway_topology(...)`, `upsert_topology_annotations(...)`, `get_topology_annotations(...)`, `delete_topology_annotations(...)`, `export_topology_prefixes(...)`, and `find_affected_gateways(sources, destinations, ..., min_confidence=..., include_standby=...)` returning typed Pydantic models.

#### Scenario: Consumer resolves affected gateways and policy packages via ArodonataClient

- **WHEN** a downstream consumer calls `await client.find_affected_gateways(sources=["10.1.1.10"], destinations=["10.2.2.20"], mgmt_name="mds1", cache_mode="smart")`
- **THEN** `ArodonataClient` SHALL ensure the topology cache is synchronized according to `cache_mode` and return a ranked list of `AffectedGatewayCandidate` instances containing `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, `confidence_factors`, `warnings`, and `matched_flows`

#### Scenario: Host application injects SSH callback and reconciles gateway routes via ArodonataClient

- **WHEN** a host application initializes `ArodonataClient(settings, gateway_cli=ssh_exec_fn)` and calls `await client.collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateways=["gw-01"])` followed by `await client.reconcile_gateway_topology(mgmt_name="mds1", domain="Corp", gateway="gw-01")`
- **THEN** `ArodonataClient` SHALL invoke `ssh_exec_fn` for `"gw-01"`, persist the parsed route intervals into `arodonata_gateway_topology`, and return a `TopologyReconciliationReport` detailing any discrepancies between SmartConsole topology and live routes
