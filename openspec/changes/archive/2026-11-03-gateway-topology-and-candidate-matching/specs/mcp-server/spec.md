# Model Context Protocol (MCP) Server Specification (Delta)

## ADDED Requirements

### Requirement: MCP Gateway Topology Control and Affected Gateway Discovery Tool

The `arodonata[mcp]` server SHALL support `scope="topology"` in `cache_control(action="status" | "refresh", ...)` and expose a `locate_gateways(sources, destinations, mgmt_name=..., domain=..., cache_mode="smart")` tool that resolves traffic flows into affected Check Point gateways, domains, policy packages, and matched interfaces.

#### Scenario: MCP client locates candidate gateways and policy packages for a traffic flow

- **WHEN** an MCP client invokes `locate_gateways(sources=["10.10.1.5"], destinations=["172.16.20.10"], mgmt_name="mds1")`
- **THEN** the tool SHALL return a structured JSON envelope listing the affected gateways where source and destination reside behind distinct interfaces, along with each gateway's `domain_name`, `installed_access_policy`, `policy_packages`, `access_layers`, and per-flow `(src_interface -> dst_interface)` match details
