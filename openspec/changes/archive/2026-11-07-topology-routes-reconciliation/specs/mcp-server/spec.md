# MCP Server Specification Delta

## MODIFIED Requirements

### Requirement: MCP Gateway Topology Control and Affected Gateway Discovery Tool

The `arodonata[mcp]` server SHALL support `scope="topology"` (with optional `gateways` and `collect_routes` parameters) in `cache_control(action="status" | "refresh", ...)` and expose `locate_gateways(sources, destinations, mgmt_name=..., domain=..., min_confidence=..., include_standby=..., cache_mode="smart")` returning affected Check Point gateways, domains, policy packages, matched interfaces, delta-based `confidence` scores, `confidence_factors`, `is_standby_path` flags, and `topology_warnings`.

#### Scenario: MCP client locates candidate gateways and policy packages for a traffic flow

- **WHEN** an MCP client invokes `locate_gateways(sources=["10.10.1.5"], destinations=["172.16.20.10"], mgmt_name="mds1")`
- **THEN** the tool SHALL return a structured JSON envelope listing the affected gateways where source and destination reside behind distinct interfaces, along with each gateway's `domain_name`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, `confidence_factors`, per-flow `(src_interface -> dst_interface)` match details, and any domain `topology_warnings`
