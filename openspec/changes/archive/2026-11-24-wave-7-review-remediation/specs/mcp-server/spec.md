# Spec Delta

## ADDED Requirements

### Requirement: Cache-Only Domain Pre-Validation Without Live Refresh or Quota Charge

**ID**: REQ-MCP-013\
**Intent**: Keep MCP tool calls using `cache_mode="cache"` free of forced live domain discovery calls and live quota charges during domain pre-validation.\
**Non-goals**: Smart-mode domain-miss refresh fallback (`REQ-MCP-010`) or rate-limit bucket accounting (`REQ-MCP-012`).

When an MCP tool is invoked with `cache_mode="cache"` (with or without explicit `mgmt_name`), domain pre-validation SHALL inspect cached `arodonata_domains` rows only without invoking live `get_domains(cache_mode="force")` refreshes or consuming `live` quota slots.

#### Scenario: SCN-MCP-013-1 — Cache-only multi-server and single-server domain pre-validation performs zero live calls or quota charges

- **GIVEN** single- or multi-management MCP configuration where one or more servers have an empty `arodonata_domains` cache while another server has cached domains and initialized objects
- **WHEN** `locate_gateways(..., cache_mode="cache")`, `cache_control(action="refresh", cache_mode="cache", ...)`, or `query_objects(..., cache_mode="cache", domains=[...])` runs domain pre-validation (with or without `mgmt_name`)
- **THEN** domain pre-validation SHALL execute zero live `get_domains(cache_mode="force")` API calls and charge zero `live` quota slots
- **AND** when cached domains are present for the evaluated server(s) and do not contain the requested domain, pre-validation SHALL fail with `ToolFailure` listing the cached known domains
