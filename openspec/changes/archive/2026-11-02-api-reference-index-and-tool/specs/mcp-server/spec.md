## ADDED Requirements

### Requirement: Unified Progressive-Disclosure MCP API Reference Tool

The `arodonata[mcp]` server SHALL expose a single consolidated `api_reference` tool supporting `action="search" | "describe" | "validate"` (with automatic `version` inference from `mgmt_name` when `version` is omitted), enabling MCP clients and agents to search Check Point commands (`action="search"`), inspect version-filtered command parameters, nested objects, and examples (`action="describe"`), and validate candidate request payloads offline before calling `api_call` (`action="validate"`).

#### Scenario: Two-step MCP discovery and payload validation via api_reference tool

- **WHEN** an MCP client calls `api_reference(action="search", query="host", crud_type="add")`, then `api_reference(action="describe", command="add-host", version="v2.2")`, and finally `api_reference(action="validate", command="add-host", payload={"name": "web-01", "ip-address": "192.0.2.10"})`
- **THEN** `action="search"` SHALL return compact matching command summaries, `action="describe"` SHALL return the full `v2.2` field schema, `field_alternatives`, `nested_objects`, and canonical example for `add-host`, and `action="validate"` SHALL return `valid=True` with `errors=[]`
