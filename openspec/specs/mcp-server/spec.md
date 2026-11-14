# Model Context Protocol (MCP) Server Specification

## Purpose

Defines the Streamable-HTTP Model Context Protocol server (`arodonata-mcp` CLI and `arodonata.mcp` embeddable ASGI application under `arodonata[mcp]`), authentication and security guards, tool surface (native, cached, structured query/aggregation, rulebase, change report, live compatibility, and opt-in CPCRUD tools), and prompt templates.

## Requirements

### Requirement: Standalone CLI and Embeddable ASGI Server Modes

The `arodonata.mcp` package SHALL provide a standalone CLI (`arodonata-mcp`) and ASGI factories (`create_mcp_server`, `create_asgi_app`), enforcing fail-closed auth in `"static"` and `"jwt"` modes, parsing `client_id=secret` token entries ONLY when the prefix matches `^[A-Za-z_][A-Za-z0-9_-]*$` with a 32-character minimum secret length, comparing SHA-256 digests via `hmac.compare_digest`, and validating numeric ports on wildcard `Host` patterns.

#### Scenario: Standalone startup validates TLS trust store and auth mode

- **WHEN** `arodonata-mcp` starts up
- **THEN** it SHALL verify the TLS trust store configuration and refuse `ARODONATA_MCP_AUTH_MODE=host` or `jwt` (without a verifier) with exit code `2` and a clear configuration error message, and refuse or emit a prominent security warning when `auth_mode="none"` is combined with non-loopback `--host` (`0.0.0.0`) or `ALLOWED_HOSTS=*`

#### Scenario: Static bearer token authentication maps token variable name to client_id

- **WHEN** `ARODONATA_MCP_AUTH_MODE=static` is configured with `ARODONATA_MCP_TOKEN_VARS="TEAM_A_TOKEN,TEAM_B_TOKEN"` or `ARODONATA_MCP_TOKENS` containing a base64 token with trailing `=` padding (e.g., `c2VjcmV0dG9rZW4xMjM0NTY3ODkwMTIzNDU2Nzg5MDEy==`) or an explicit `team_a=c2VjcmV0dG9rZW4xMjM0NTY3ODkwMTIzNDU2Nzg5MDEy==`
- **THEN** the parser SHALL split on the first `=` or `:` ONLY when the prefix matches `^[A-Za-z_][A-Za-z0-9_-]*$` and the secret is at least 32 characters (keeping raw unprefixed base64 tokens whole under a generated non-secret `client_id` such as `token_1`), reject any token secret shorter than 32 characters with `ConfigurationError`, compare SHA-256 digests via `hmac.compare_digest`, and NEVER log or expose any prefix of the secret in `client_id` or `repr()`

#### Scenario: Embedded JWT mode without token_verifier fails closed on startup

- **WHEN** `create_mcp_server` or `create_asgi_app` is called with `auth_mode="jwt"` and `token_verifier=None`
- **THEN** initialization SHALL raise `ConfigurationError` immediately rather than falling back to unauthenticated access

#### Scenario: Host authentication mode in embedded ASGI applications

- **WHEN** `create_mcp_server` is called with `auth_mode="host"` for embedding inside an authenticating ASGI host
- **THEN** Arodonata SHALL disable its internal token verifier and rely on the enclosing ASGI host middleware for request authentication

#### Scenario: DNS rebinding and Origin header protection

- **WHEN** a request arrives with a `Host` header not in `allowed_hosts` (including malformed ports on `host:*` entries such as `localhost:abc`) or a browser `Origin` header not in `allowed_origins`
- **THEN** the server SHALL reject an unlisted or malformed-port `Host` with HTTP `421` and an unlisted `Origin` with HTTP `403`

### Requirement: Structured Object Aggregation and Cache Status Tools

The `arodonata[mcp]` server SHALL expose a structured query and schema-introspection tool (`query_objects` supporting `aggregate="list" | "count" | "describe"`) for cross-domain filtering, grouping, and counting over `arodonata_objects`, `arodonata_services`, and `arodonata_assets` without raw SQL, along with a unified `cache_control` tool (`action="status" | "refresh"`) reporting freshness per domain and scope from `domain_sync_state` or triggering scoped synchronization. It SHALL normalize `group_by` field aliases (`domain` -> `domain_name`, `mgmt` / `server` / `management` -> `mgmt_name`, `object_type` / `asset_type` / `service_type` -> `type`, `orig_domain` -> `original_domain`) and expand asset type aliases (`gateway`, `cluster`, `member`, `vsx`, `vs`, `server`) to include Check Point `Cpmi*` classes (`CpmiGatewayPlain`, `CpmiGatewayCluster`, `CpmiClusterMember`, `CpmiVsxClusterMember`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`, `CpmiHostCkp`) with case-insensitive matching.

#### Scenario: Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` is called (or with `group_by=["domain", "type"]` and asset aliases such as `types=["cluster", "vsx", "vs"]`)
- **THEN** the tool SHALL execute a parameterized query over the cached tables (distinguishing domain-owned vs Global objects via `original_domain`), resolve `group_by` aliases and `Cpmi*` asset classes case-insensitively, and return the grouped counts in a single response (populating both requested alias keys and canonical keys when an alias is used)

#### Scenario: Progressive-disclosure schema description via query_objects

- **WHEN** `query_objects(mgmt_name=..., domain=..., aggregate="describe")` is called (defaulting to `cache_mode="smart"`)
- **THEN** if the object cache for the target scope has not been synchronized (`0` `scope="objects"` sync states, even if partial on-demand topology objects exist), it SHALL warm `arodonata_objects` first when `cache_mode != "cache"`, and return available domains, management servers, per-type object/service/asset counts, and the list of filterable and groupable fields from the cached tables

#### Scenario: Cache status inspection across scopes

- **WHEN** `cache_control(mgmt_name=..., action="status")` or `cache_control(mgmt_name=..., domain=..., action="refresh", scope="objects")` is called
- **THEN** `action="status"` SHALL return per-domain and per-`item_type` sync status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`, and `action="refresh"` SHALL synchronize the requested scope (`"domains"`, `"objects"`, `"services"`, `"assets"`, or `"rulebase"`) and return the `RefreshOutcome`

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose a consolidated cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `change_report`, `api_call`, and opt-in CPCRUD tools), pre-validating explicit `domain` names against `arodonata_domains` and normalizing short and canonical object/service/asset types (including case-insensitive `Cpmi*` equivalence expansion across `list_assets`, `search_objects`, and `query_objects`).

#### Scenario: List and search tool response envelope includes source, accurate cache age, and cold-cache auto-upgrade

- **WHEN** a collection listing or search tool (`list_domains`, `list_objects`, `list_services`, `list_assets`, `search_objects`, or `query_objects`) executes
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds` (`null` when no `synced_at` timestamp exists in `arodonata_domain_sync_state` rather than `0.0`), and `objects` sliced by `limit` and `offset`; when `cache_mode="cache"` is passed on an uninitialized scope (`0` sync states for that scope, or `0` cached domain rows for `domains`), the tool SHALL automatically upgrade to `"smart"` so cold caches are populated on first query; and when `mgmt_name` is omitted in `search_objects`, the search SHALL span all configured `mgmt_names` rather than only `mgmt_names[0]`

#### Scenario: Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0)` is called
- **THEN** it SHALL search `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` (using `cache_mode="cache"` and including `"Global"` whenever `domain` is omitted):
  - if `uid_or_name` contains no `*` or `?` and matches in exactly one domain, it SHALL return that single entity with `match_type="exact"` and full details;
  - if `domain` is omitted and `uid_or_name` matches exact entities in more than one domain, it SHALL return `match_type="ambiguous"` with `object=None` and `objects` listing the matching candidates across domains so the caller can disambiguate;
  - if `uid_or_name` contains an explicit wildcard (`*` or `?`), it SHALL evaluate `fnmatchcase` strictly (`match_type="wildcard"`), returning the full object when `total == 1` or a paginated candidate slice when `total > 1`;
  - if `uid_or_name` contains no wildcard and has no exact match in cache, it SHALL return up to `limit` compact case-insensitive substring candidates (`match_type="substring_candidates"`)

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

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was issued/signed by `cpcrud_plan`, omit `force`, `validate_schema`, and `server_ip` from MCP CPCRUD tools, cap `retry_remaining` (`<= 3`), and restrict `cpcrud_staged_session(session_uid, action="publish" | "discard", ...)` exclusively to session UIDs staged by `cpcrud_apply(keep_session=True)` in this server process.

#### Scenario: Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` is called with an unknown `plan_id` or a `plan` payload that was not issued/signed by this server's `cpcrud_plan` tool (or whose `command` / `object_type` / `payload` was altered)
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: Staged CPCRUD session published or discarded via dedicated MCP tools

- **WHEN** `cpcrud_apply(..., no_publish=True, keep_session=True)` stages changes in a dedicated session (recording `(mgmt_name, domain_key, session_uid)` in the server's staged-session registry) and the caller subsequently invokes `cpcrud_staged_session(session_uid=..., action="publish" | "discard", mgmt_name=..., domain=...)`
- **THEN** the tool SHALL verify `session_uid` is registered in this MCP server's staged-session store, adopt the session non-disruptively without exposing `server_ip` or `force_disconnect`, publish (invalidating the domain cache) or discard uncommitted changes, remove the completed entry from the staged store, and log out cleanly

#### Scenario: Unregistered or foreign session UID rejected by cpcrud_staged_session

- **WHEN** `cpcrud_staged_session` is called with a `session_uid` that was not created by `cpcrud_apply(..., no_publish=True, keep_session=True)` in this MCP server instance (for example, a SmartConsole administrator's session UID discovered via `show-sessions`)
- **THEN** `cpcrud_staged_session` SHALL raise `ToolFailure` immediately without opening a Check Point session or calling `take-over-session`, `switch-session`, `publish`, or `discard`

### Requirement: Cache-Only Cross-Domain Group Lookup and Ambiguity Reporting in MCP

When `get_group_members` is called without `domain` (and `group_name_or_uid` is not a `mgmt:domain:name` composite ID), the MCP server SHALL resolve the target group across cached domains including `"Global"` using `cache_mode="cache"` without triggering whole-MDS logins, and SHALL return a structured `match_type="ambiguous"` candidate response when matching groups exist in more than one domain.

#### Scenario: Cross-domain MCP get_group_members reports ambiguity without whole-MDS sync

- **WHEN** `get_group_members(group_name_or_uid="SharedAdmins")` is invoked without `domain` and `"SharedAdmins"` exists in multiple cached domains
- **THEN** the tool SHALL perform zero remote domain refreshes and return `match_type="ambiguous"` with the candidate domain/composite-ID list so the caller can re-query with an explicit `domain` or `mgmt:domain:name`

### Requirement: Unified Progressive-Disclosure MCP API Reference Tool

The `arodonata[mcp]` server SHALL expose a single consolidated `api_reference` tool supporting `action="search" | "describe" | "validate"` (with automatic `version` inference from `mgmt_name` when `version` is omitted), enabling MCP clients and agents to search Check Point commands (`action="search"`), inspect version-filtered command parameters, nested objects, and examples (`action="describe"`), and validate candidate request payloads offline before calling `api_call` (`action="validate"`).

#### Scenario: Two-step MCP discovery and payload validation via api_reference tool

- **WHEN** an MCP client calls `api_reference(action="search", query="host", crud_type="add")`, then `api_reference(action="describe", command="add-host", version="v2.2")`, and finally `api_reference(action="validate", command="add-host", payload={"name": "web-01", "ip-address": "192.0.2.10"})`
- **THEN** `action="search"` SHALL return compact matching command summaries, `action="describe"` SHALL return the full `v2.2` field schema, `field_alternatives`, `nested_objects`, and canonical example for `add-host`, and `action="validate"` SHALL return `valid=True` with `errors=[]`

### Requirement: MCP Gateway Topology Control and Affected Gateway Discovery Tool

The `arodonata[mcp]` server SHALL support `scope="topology"` (with optional `gateways` and `collect_routes` parameters) in `cache_control(action="status" | "refresh", ...)` and expose `locate_gateways(sources, destinations, mgmt_name=..., domain=..., min_confidence=..., include_standby=..., include_policy_inferred=..., cache_mode="smart")` returning affected Check Point gateways, domains, policy packages, matched interfaces, delta-based `confidence` scores, `confidence_factors`, `is_standby_path` flags, and `topology_warnings`.

#### Scenario: MCP client locates candidate gateways and policy packages for a traffic flow

- **WHEN** an MCP client invokes `locate_gateways(sources=["10.10.1.5"], destinations=["172.16.20.10"], mgmt_name="mds1", include_policy_inferred=True)`
- **THEN** the tool SHALL return a structured JSON envelope listing the affected gateways (both cross-interface L3 matches and `policy_inferred` one-arm or incomplete-topology matches when enabled), along with each gateway's `domain_name`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, `confidence_factors`, per-flow `(src_interface -> dst_interface)` match details, `include_policy_inferred`, and any domain `topology_warnings`
