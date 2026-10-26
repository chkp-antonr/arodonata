# Delta Specification: Model Context Protocol (MCP) Server (`mcp-server`)

## MODIFIED Requirements

### Requirement: Structured Object Aggregation and Cache Status Tools

The `arodonata[mcp]` server SHALL expose a structured query and schema-introspection tool (`query_objects` supporting `aggregate="list" | "count" | "describe"`) for cross-domain filtering, grouping, and counting over `arodonata_objects`, `arodonata_services`, and `arodonata_assets` without raw SQL, along with a unified `cache_control` tool (`action="status" | "refresh"`) reporting freshness per domain and scope from `domain_sync_state` or triggering scoped synchronization.

#### Scenario: Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` is called
- **THEN** the tool SHALL execute a parameterized query over the cached tables (distinguishing domain-owned vs Global objects via `original_domain`) and return the grouped counts in a single response

#### Scenario: Progressive-disclosure schema description via query_objects

- **WHEN** `query_objects(mgmt_name=..., domain=..., aggregate="describe")` is called
- **THEN** it SHALL return available domains, management servers, per-type object/service/asset counts, and the list of filterable and groupable fields from the cached tables

#### Scenario: Cache status inspection across scopes

- **WHEN** `cache_control(mgmt_name=..., action="status")` or `cache_control(mgmt_name=..., domain=..., action="refresh", scope="objects")` is called
- **THEN** `action="status"` SHALL return per-domain and per-`item_type` sync status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`, and `action="refresh"` SHALL synchronize the requested scope (`"domains"`, `"objects"`, `"services"`, `"assets"`, or `"rulebase"`) and return the `RefreshOutcome`

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose a consolidated cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `change_report`, `api_call`, and opt-in CPCRUD tools), pre-validating `domain` names against `arodonata_domains` before login, normalizing short and canonical `types`/`obj_type` values, resolving `show_object` across `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` with strict explicit wildcard matching and paginated substring candidate fallback, returning the domain's package and layer catalog in `show_rulebase` when `package`/`layer` is omitted or unmatched, enforcing a read-only command allowlist in `api_call` when `ARODONATA_MCP_ALLOW_WRITE_API=false`, isolating allowed write `api_call` invocations in a dedicated session, and passing `known_sids` into error redaction.

#### Scenario: List tool response envelope includes source and cache age

- **WHEN** a collection listing tool (`list_domains`, `list_objects`, `list_services`, or `list_assets`) returns a page of objects (including with short or canonical `types` filters such as `types=["tcp", "udp"]` on `list_services` or `parent="..."` on `list_assets`)
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds`, and `objects` sliced by `limit` and `offset`

#### Scenario: Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0)` is called
- **THEN** it SHALL search `arodonata_objects`, `arodonata_services`, `arodonata_assets` (returning cached gateway/cluster `interfaces`, `network_security_blades`, `member_uids`, and `virtual_system_uids`), and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer`:
  - if `uid_or_name` contains no `*` or `?` and matches an exact UID or name, it SHALL return that single entity with `match_type="exact"` and full details;
  - if `uid_or_name` contains an explicit wildcard (`*` or `?`), it SHALL evaluate `fnmatchcase` strictly against the pattern without adding implicit leading or trailing wildcards (`match_type="wildcard"`), returning the full object when `total == 1` or a paginated candidate slice (`limit` default `20`, max `500`) when `total > 1`;
  - if `uid_or_name` contains no wildcard and has no exact match in cache, it SHALL search for case-insensitive substring matches across cached names (`match_type="substring_candidates"`) and return up to `limit` (default `20`, max `500`) compact candidate summaries with `from`, `to`, and `total` so the caller can refine the next query without overflowing context

#### Scenario: Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_rulebase(mgmt_name=..., domain=..., rulebase_type="access" | "nat" | "https" | "threat", ...)` is called
- **THEN**:
  - when neither `package` nor `layer` (`name`/`uid`) is provided (or when the requested target name is not found in the domain's cached snapshot), it SHALL return the domain's cached `packages` (`arodonata_rulebase_package_layer`) and `layers` (`arodonata_rulebase_layer`, including inline layers, parent links, and `implicit_cleanup_action`) rather than an unguided error;
  - when a valid `package` or `layer` is provided on a domain with a fresh rulebase snapshot and without live-only parameters (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`, `hits_settings`, `dereference_group_members`, `show_membership`), it SHALL evaluate any `filter` locally against the cached rulebase and cached objects/services in `markdown`, `model_friendly`, `raw`, or `cpcrud` format;
  - when live-only parameters or `cache_mode="live"` are requested, it SHALL execute a live Management API query (`show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase`)

#### Scenario: Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** a tool is called with a `domain` not present in the `arodonata_domains` table (after a single domain-list refresh) or login raises `InvalidCredentialsError`
- **THEN** the server SHALL log the `ToolFailure` at WARNING (without arguments or secrets) and return an actionable error listing known domains on that management server rather than `"internal error: InvalidCredentialsError"`

#### Scenario: Write API protection and SID masking on error

- **WHEN** `api_call` is invoked while `ARODONATA_MCP_ALLOW_WRITE_API=false`, or invoked with a write command while `ARODONATA_MCP_ALLOW_WRITE_API=true`, or when an error message contains an active session SID
- **THEN** when `ALLOW_WRITE_API=false`, `api_call` SHALL permit ONLY commands in the explicit read-only command allowlist (rejecting path traversal, mutating commands, `publish`, `discard`, `logout`, and unlisted commands); when `ALLOW_WRITE_API=true`, mutating `api_call` invocations SHALL execute inside an isolated dedicated session (never the shared `arodonata_sid_cache` session) with bounded `timeout`; and any error text SHALL be sanitized via `redact_sid(..., known_sids=...)`

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was generated by `cpcrud_plan` (via server-side `plan_id` storage or HMAC-SHA256 signature verification), omit `force` and `validate_schema` from MCP tools, cap `retry_remaining` (`<= 3`), and expose a unified `cpcrud_staged_session(session_uid, action="publish" | "discard", ...)` tool.

#### Scenario: Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` is called with an unknown `plan_id` or a `plan` payload that was not issued/signed by this server's `cpcrud_plan` tool (or whose `command` / `object_type` / `payload` was altered)
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: Staged CPCRUD session published or discarded via dedicated MCP tools

- **WHEN** `cpcrud_apply(..., no_publish=True, keep_session=True)` stages changes in a dedicated session and the caller subsequently invokes `cpcrud_staged_session(session_uid=..., action="publish" | "discard", mgmt_name=..., domain=...)`
- **THEN** the tool SHALL adopt the staged session via `take-over-session` and either publish (invalidating the domain cache) or discard uncommitted changes and log out cleanly so no locks remain orphaned
