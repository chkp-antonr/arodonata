# Client Facade, Ports/Adapters, and Telemetry Specification (Delta)

## ADDED Requirements

### Requirement: Gateway Topology and Candidate Discovery Facade Methods

`ArodonataClient` SHALL expose `topology_service` (`TopologyService`) and traced async facade methods `refresh_topology(...)`, `stream_refresh_topology(...)`, `get_gateway_topology(...)`, and `find_affected_gateways(sources, destinations, ...)` returning typed Pydantic models (`GatewayTopologyEntry`, `GatewayInterfaceSummary`, `AffectedGatewayCandidate`).

#### Scenario: Consumer resolves affected gateways and policy packages via ArodonataClient

- **WHEN** a downstream consumer calls `await client.find_affected_gateways(sources=["10.1.1.10"], destinations=["10.2.2.20"], mgmt_name="mds1", cache_mode="smart")`
- **THEN** `ArodonataClient` SHALL ensure the topology cache is synchronized according to `cache_mode` and return a ranked list of `AffectedGatewayCandidate` instances containing `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `installed_access_policy`, `policy_packages`, `access_layers`, and `matched_flows`
