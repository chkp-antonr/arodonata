# Spec Delta

## MODIFIED Requirements

### Requirement: Cache-Only Domain Pre-Validation Without Live Refresh or Quota Charge

**ID**: REQ-MCP-013\
**Intent**: Keep MCP tool calls using `cache_mode="cache"` (or `mode="cache"`) free of forced live domain discovery calls and live quota charges during domain pre-validation.\
**Non-goals**: Smart-mode domain-miss refresh fallback (`REQ-MCP-010`) or rate-limit bucket accounting (`REQ-MCP-012`).

When an MCP tool is invoked with `cache_mode="cache"` or `cache_control(action="refresh", mode="cache")` (with or without explicit `mgmt_name`), domain pre-validation and refresh routing SHALL inspect cached `arodonata_domains` rows only without invoking live `show-domains` refreshes or consuming `live` quota slots.

#### Scenario: SCN-MCP-013-1 — Cache-only multi-server and single-server domain pre-validation performs zero live calls or quota charges

- **GIVEN** single- or multi-management MCP configuration where one or more servers have an empty `arodonata_domains` cache while another server has cached domains and initialized objects
- **WHEN** `locate_gateways(..., cache_mode="cache")`, `cache_control(action="refresh", mode="cache", ...)`, or `query_objects(..., cache_mode="cache", domains=[...])` runs domain pre-validation and tool execution (with or without `mgmt_name`)
- **THEN** the invocation SHALL execute zero live `get_domains(cache_mode="force")` or `show-domains` API calls and charge zero `live` quota slots
- **AND** when cached domains are present for the evaluated server(s) and do not contain the requested domain, pre-validation SHALL fail with `ToolFailure` listing the cached known domains

## ADDED Requirements

### Requirement: Pre-Validation Fan-Out Quota Ordering, Unified Multi-MDS Scoping, Stalest Cache Age, and Guardrail Hardening

**ID**: REQ-MCP-016\
**Intent**: Enforce explicit fan-out quota before live domain discovery, unify multi-MDS scope resolution, report true stalest cache ages, harden error guards and staged SID/plan isolation, and fix typed `show_object` and `show_rulebase` bounds.\
**Non-goals**: `REQ-MCP-004` `group_by` asset routing in `query_objects` (tracked separately).

MCP tools SHALL charge explicit fan-out quotas before live domain pre-validation, unify multi-MDS scope validation across `search_objects` and siblings, report `min(synced_at)` stalest ages, guard error-handler cache lookups, protect staged SIDs and `plan_store`, handle typed UUID/`Cpmi*` `show_object` calls, and clamp cached `show_rulebase` paging.

#### Scenario: SCN-MCP-016-1 — Upfront fan-out quota rejection, unified multi-MDS scoping, and stalest cache_age_seconds

- **GIVEN** an oversize `cache_control(domains=...)` / `change_report(scopes=...)` fan-out, a multi-MDS `search_objects(mgmt_name=None, domain=...)` call, or multi-type/multi-domain caches with differing `synced_at` ages
- **WHEN** the MCP tool validates quota, resolves management scope, or computes `cache_age_seconds`
- **THEN** oversize fan-out SHALL fail quota checks BEFORE executing live `show-domains` pre-validation (probing failing servers at most once per call)
- **AND** `search_objects` SHALL span all configured servers when `mgmt_name` is omitted, and `cache_age_seconds` SHALL report the stalest (`min(synced_at)`) age across touched scopes, domains, and item types

#### Scenario: SCN-MCP-016-2 — Defensive error-guard lookups, staged SID redaction, and owner-fair plan_store eviction

- **GIVEN** an uninitialized cache DB during offline `api_reference` `ValidationError`, an exception during `cpcrud_staged_session`, or >256 `cpcrud_plan` calls by a second caller
- **WHEN** `mcp_tool_guard` handles the error or `cpcrud` tools manage staged SIDs and stored plans
- **THEN** `mcp_tool_guard` SHALL never leak unhandled `OperationalError` (and offline `api_reference` errors SHALL skip domain cache queries)
- **AND** `cpcrud_staged_session` SHALL register `stored_staged.sid` before execution, and `plan_store` SHALL evict same-owner entries first before cross-caller entries

#### Scenario: SCN-MCP-016-3 — Typed UUID live show_object lookups, Cpmi*/underscore type normalization, and clamped cached show_rulebase

- **GIVEN** a typed UUID `show_object(uid_or_name=<uuid>, obj_type='host')`, `obj_type='CpmiGatewayCluster'` / `'simple_gateway'`, or cached `show_rulebase(offset=-2, limit=100000)`
- **WHEN** `show_object` or `show_rulebase` executes
- **THEN** `live_show_object` SHALL send `uid` rather than `name` for UUIDs and `validate_show_object_type` SHALL normalize `Cpmi*`/underscore aliases safely
- **AND** cached `show_rulebase` SHALL clamp `offset >= 0` and `1 <= limit <= 500`
