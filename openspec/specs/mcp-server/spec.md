# Model Context Protocol (MCP) Server Specification

## Purpose

Defines the Streamable-HTTP Model Context Protocol server (`arodonata-mcp` CLI and `arodonata.mcp` embeddable ASGI application under `arodonata[mcp]`), authentication and security guards, tool surface (native, cached, structured query/aggregation, rulebase, change report, API reference, and opt-in CPCRUD tools), and prompt templates.

## Requirements

### Requirement: Standalone CLI and Embeddable ASGI Server Modes

**ID**: REQ-MCP-001\
**Intent**: Expose Arodonata securely over Streamable-HTTP MCP in both standalone and embedded ASGI deployments with unified fail-closed security policy, IPv6 support, and Host/Origin checks.\
**Non-goals**: Tool-level domain validation, per-client tool rate limiting (`REQ-MCP-012`), and write-API allowlisting (`REQ-MCP-010`).

The `arodonata.mcp` package SHALL provide `arodonata-mcp`, `create_mcp_server`, and `create_asgi_app`, enforcing unified fail-closed `validate_security_policy()` across all entry points (rejecting wildcards under DNS rebinding protection and unsafe `auth_mode="none"` unless opted in), IPv6 `issuer_url` bracketing, constant-time SHA-256 bearer auth, and `create_asgi_app(mcp_server=...)` parity.

#### Scenario: SCN-MCP-001-1 — Standalone startup validates TLS trust store and auth mode

- **WHEN** `arodonata-mcp` starts up
- **THEN** it SHALL verify the TLS trust store configuration before serving traffic
- **AND** it SHALL exit with code `2` and a clear error if `ARODONATA_MCP_AUTH_MODE=host` or `jwt` (without a verifier) is selected
- **AND** it SHALL fail closed with exit code `2` when `auth_mode="none"` is paired with non-loopback `--host` (`0.0.0.0`) or `ALLOWED_HOSTS=*` unless `allow_insecure_unauthenticated=True` (and DNS rebinding disabled for wildcards) is explicitly opted in with a `SECURITY WARNING`

#### Scenario: SCN-MCP-001-2 — Static bearer token authentication maps token variable name to client_id

- **GIVEN** `ARODONATA_MCP_AUTH_MODE=static` with `ARODONATA_MCP_TOKEN_VARS="TEAM_A_TOKEN,TEAM_B_TOKEN"` or `ARODONATA_MCP_TOKENS` (`c2Vj...=` or `team_a=c2Vj...==`)
- **WHEN** static tokens are parsed and verified
- **THEN** the parser SHALL split on the first `=` or `:` ONLY when the prefix matches `^[A-Za-z_][A-Za-z0-9_-]*$` and the secret is `>= 32` chars (keeping unprefixed base64 whole under a non-secret `client_id` like `token_1`)
- **AND** any secret shorter than 32 characters SHALL raise `ConfigurationError`
- **AND** token comparison SHALL use constant-time SHA-256 digest matching without exposing any secret prefix in `client_id` or `repr()`

#### Scenario: SCN-MCP-001-3 — Embedded JWT mode without token_verifier fails closed on startup

- **WHEN** `create_mcp_server` or `create_asgi_app` is called with `auth_mode="jwt"` and `token_verifier=None`
- **THEN** initialization SHALL raise `ConfigurationError` immediately rather than falling back to unauthenticated access

#### Scenario: SCN-MCP-001-4 — Host authentication mode in embedded ASGI applications

- **WHEN** `create_mcp_server` is called with `auth_mode="host"` for embedding inside an authenticating ASGI host
- **THEN** Arodonata SHALL disable its internal token verifier and rely on the enclosing ASGI host middleware for request authentication

#### Scenario: SCN-MCP-001-5 — DNS rebinding and Origin header protection

- **WHEN** a request arrives with a `Host` header not in `allowed_hosts` (including malformed ports on `host:*` like `localhost:abc`) or a browser `Origin` header not in `allowed_origins`
- **THEN** the server SHALL reject an unlisted or malformed-port `Host` with HTTP `421` and an unlisted `Origin` with HTTP `403`

#### Scenario: SCN-MCP-001-6 — Unified fail-closed security policy rejects unsafe unauthenticated and wildcard configurations across all entry points

- **WHEN** `run_cli`, `create_mcp_server`, or `create_asgi_app` evaluates `validate_security_policy()` on wildcard entries in `allowed_hosts`/`allowed_origins` with `enable_dns_rebinding_protection=True` OR on `auth_mode="none"` paired with non-loopback `host`, wildcards, `allow_write_api=True`, or `cpcrud=True`
- **THEN** all three entry points SHALL fail closed with `ConfigurationError` (or exit code `2` in CLI) unless `allow_insecure_unauthenticated=True` is explicitly configured for unsafe `auth_mode="none"` (while always permitting loopback read-only `auth_mode="none"`)

#### Scenario: SCN-MCP-001-7 — IPv6 issuer URL bracketing and create_asgi_app parity prevent split-brain drift

- **WHEN** `create_mcp_server` is constructed with an IPv6 `host` (`"::1"`, `"::"`, `"fe80::1"`) under `auth_mode="static"` or `"jwt"`, OR `create_asgi_app(mcp_server=srv, ...)` is called with an injected server
- **THEN** `AuthSettings.issuer_url` SHALL bracket IPv6 literals cleanly without `ValidationError`
- **AND** `create_asgi_app(mcp_server=srv, ...)` SHALL enforce `validate_security_policy()` on the effective settings and raise `ConfigurationError` whenever runtime overrides (`allow_write_api`, `cpcrud`, `auth_mode`, `client`, `settings`, `token_verifier`, `quota_manager`) conflict with `srv`

### Requirement: Cache-Aligned Tool Surface, Envelopes, and Single-Entity Lookup

**ID**: REQ-MCP-002\
**Intent**: Provide uniform paginated JSON envelopes with cold-cache upgrades and predictable exact/ambiguous/wildcard/substring `show_object` resolution.\
**Non-goals**: Structured SQL-backed aggregation (`REQ-MCP-004`) or cross-domain `get_group_members` (`REQ-MCP-003`).

The MCP server SHALL expose a cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `locate_gateways`, `api_reference`, `change_report`, `api_call`, and opt-in CPCRUD tools) returning consistent cache-backed JSON envelopes and multi-domain `show_object` resolution.

#### Scenario: SCN-MCP-002-1 — List and search tool response envelope includes source, accurate cache age, and cold-cache auto-upgrade

- **WHEN** `list_domains`, `list_objects`, `list_services`, `list_assets`, `search_objects`, or `query_objects` executes
- **THEN** the JSON text response SHALL return `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds` (`null` when no `synced_at` timestamp exists rather than `0.0`), and sliced `objects`
- **AND** when `cache_mode="cache"` runs on an uninitialized scope (`0` sync states for that scope, or `0` cached domain rows for `domains`), it SHALL auto-upgrade to `"smart"`
- **AND** when `mgmt_name` is omitted in `search_objects`, the search SHALL span all configured `mgmt_names` rather than only `mgmt_names[0]`

#### Scenario: SCN-MCP-002-2 — Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0)` runs across `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and cached rulebase layers (`cache_mode="cache"`, including `"Global"` when `domain` is omitted)
- **THEN** an exact non-wildcard match in one domain SHALL return that entity with `match_type="exact"` and full details
- **AND** an exact non-wildcard match across multiple domains when `domain` is omitted SHALL return `match_type="ambiguous"` with `object=None` and candidate `objects`
- **AND** an explicit `*` or `?` wildcard query SHALL evaluate `fnmatchcase` (`match_type="wildcard"`), returning the full object when `total == 1` or a paginated slice when `total > 1`
- **AND** a non-wildcard query with no exact match SHALL return up to `limit` compact case-insensitive substring candidates (`match_type="substring_candidates"`)

### Requirement: Cache-Only Cross-Domain Group Lookup and Ambiguity Reporting in MCP

**ID**: REQ-MCP-003\
**Intent**: Avoid expensive multi-domain logins when MCP clients inspect a group name without specifying a domain.\
**Non-goals**: Underlying `SearchService` group ambiguity rules (`REQ-CACHE-014`).

When `get_group_members` is called without `domain` (and `group_name_or_uid` is not a `mgmt:domain:name` composite ID), the MCP server SHALL resolve the target group across cached domains including `"Global"` using `cache_mode="cache"` without triggering whole-MDS logins, and SHALL return a structured `match_type="ambiguous"` candidate response when matching groups exist in more than one domain.

#### Scenario: SCN-MCP-003-1 — Cross-domain MCP get_group_members reports ambiguity without whole-MDS sync

- **GIVEN** a cache where `"SharedAdmins"` exists in multiple cached domains
- **WHEN** `get_group_members(group_name_or_uid="SharedAdmins")` is invoked without `domain`
- **THEN** the tool SHALL perform zero remote domain refreshes
- **AND** it SHALL return `match_type="ambiguous"` with candidate domain and composite-ID entries for caller disambiguation

### Requirement: Structured Object Querying, Aggregation, and Type/Field Alias Normalization

**ID**: REQ-MCP-004\
**Intent**: Give MCP agents fast parameterized filtering, counting, and schema discovery with consistent field and `Cpmi*` asset aliases.\
**Non-goals**: Single-entity text search (`REQ-MCP-002`).

`query_objects` (`aggregate="list" | "count" | "describe"`) SHALL support parameterized filtering, grouping, and counting across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` without raw SQL, normalizing `group_by` field aliases and expanding short asset type aliases to Check Point `Cpmi*` classes case-insensitively across `list_assets`, `search_objects`, and `query_objects`.

#### Scenario: SCN-MCP-004-1 — Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` (or with `group_by=["domain", "type"]` and `types=["cluster", "vsx", "vs"]`) is called
- **THEN** the tool SHALL run a parameterized cached query distinguishing domain-owned vs `Global` objects via `original_domain`
- **AND** it SHALL return grouped counts in one response, populating both requested alias keys and canonical keys when an alias is used

#### Scenario: SCN-MCP-004-2 — Progressive-disclosure schema description via query_objects

- **WHEN** `query_objects(mgmt_name=..., domain=..., aggregate="describe")` is called (defaulting to `cache_mode="smart"`)
- **THEN** if the target `scope="objects"` has `0` sync states (even if partial topology objects exist) and `cache_mode != "cache"`, it SHALL warm `arodonata_objects` first
- **AND** it SHALL return available domains, management servers, per-type object/service/asset counts, and filterable/groupable field lists

#### Scenario: SCN-MCP-004-3 — Field and asset type aliases normalize consistently across query and search tools

- **WHEN** callers supply `group_by` aliases (`domain` -> `domain_name`, `mgmt`/`server`/`management` -> `mgmt_name`, `object_type`/`asset_type`/`service_type` -> `type`, `orig_domain` -> `original_domain`)
- **AND** callers pass short asset types (`gateway`, `cluster`, `member`, `vsx`, `vs`, `server`) to `list_assets`, `search_objects`, or `query_objects`
- **THEN** the server SHALL normalize field names case-insensitively across `list_assets`, `search_objects`, and `query_objects`
- **AND** it SHALL expand short types to Check Point `Cpmi*` classes (`CpmiGatewayPlain`, `CpmiGatewayCluster`, `CpmiClusterMember`, `CpmiVsxClusterMember`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, `CpmiVsClusterNetobj`, `CpmiHostCkp`)

### Requirement: Unified Cache Status and Scoped Refresh Control Tool

**ID**: REQ-MCP-005\
**Intent**: Give MCP agents visibility into cache freshness and controlled refresh execution across all scopes.\
**Non-goals**: Background warm-up coalescing in Python client code (`REQ-CLIENT-002`).

The `arodonata[mcp]` server SHALL expose `cache_control` (`action="status" | "refresh"`) reporting per-domain and per-`item_type` freshness (`last_published_at`, `last_session_uid`, `synced_at`, `cache_age_seconds`) from `arodonata_domain_sync_state` and triggering scoped synchronization across `"domains"`, `"objects"`, `"services"`, `"assets"`, `"rulebase"`, and `"topology"` (with `gateways` and `collect_routes`).

#### Scenario: SCN-MCP-005-1 — Cache status inspection and refresh across core and topology scopes

- **WHEN** `cache_control(mgmt_name=..., action="status")` or `cache_control(mgmt_name=..., domain=..., action="refresh", scope="objects" | "topology", gateways=..., collect_routes=...)` is called
- **THEN** `action="status"` SHALL return per-domain and per-`item_type` status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across all six scopes
- **AND** `action="refresh"` SHALL synchronize the requested scope (forwarding `gateways` and `collect_routes` for `"topology"`), returning `RefreshOutcome` (or `{"scope": "domains", "mgmt_name": ..., "refreshed_count": ..., "domains": [...]}` for `scope="domains"`)

### Requirement: Rulebase Inspection and Local Filtering Tool

**ID**: REQ-MCP-006\
**Intent**: Allow MCP agents to inspect package catalogs and filter SmartConsole rulebases offline while falling back to live API for live-only flags.\
**Non-goals**: Underlying hierarchical rule numbering (`REQ-RULE-004`).

`show_rulebase` SHALL inspect cached rulebase catalogs (`arodonata_rulebase_package_layer`, `arodonata_rulebase_layer`) and evaluate local filters against fresh snapshots (`markdown`, `model_friendly`, `raw`, or `cpcrud` format), switching to live Management API queries when `cache_mode="live"` or live-only parameters are requested.

#### Scenario: SCN-MCP-006-1 — Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_rulebase(mgmt_name=..., domain=..., rulebase_type="access" | "nat" | "https" | "threat", ...)` is called
- **THEN** when `package` and `layer` are omitted (or the requested target is not in cache), it SHALL return the domain's cached `packages` and `layers` (including inline layers, parent links, and `implicit_cleanup_action`)
- **AND** when a valid `package` or `layer` has a fresh snapshot without live-only flags, it SHALL filter locally in `markdown`, `model_friendly`, `raw`, or `cpcrud` format
- **AND** `cache_mode="live"` or live-only flags (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`, `hits_settings`, `dereference_group_members`, `show_membership`) SHALL query the live rulebase API
- **AND** live queries SHALL call `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, or `show-threat-rulebase`

### Requirement: Affected Gateway Discovery Tool

**ID**: REQ-MCP-007\
**Intent**: Expose Check Point affected-gateway and policy-package flow matching directly as an MCP tool.\
**Non-goals**: Internal LPM and evidence-delta confidence math (`REQ-TOPO-011`..`REQ-TOPO-014`).

The `arodonata[mcp]` server SHALL expose `locate_gateways(sources, destinations, mgmt_name=..., domain=..., min_confidence=..., include_standby=..., include_policy_inferred=..., cache_mode="smart")` returning affected Check Point gateways, domains, policy packages, matched interfaces, delta-based `confidence` scores, `confidence_factors`, `is_standby_path` flags, and `topology_warnings`.

#### Scenario: SCN-MCP-007-1 — MCP client locates candidate gateways and policy packages for a traffic flow

- **WHEN** an MCP client invokes `locate_gateways(sources=["10.10.1.5"], destinations=["172.16.20.10"], mgmt_name="mds1", include_policy_inferred=True)`
- **THEN** the tool SHALL return affected gateways (both cross-interface L3 matches and `policy_inferred` matches when enabled)
- **AND** each candidate SHALL include `domain_name`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, and `confidence_factors`
- **AND** each candidate SHALL include per-flow `(src_interface -> dst_interface)` matches, `include_policy_inferred`, and `topology_warnings`

### Requirement: Unified Progressive-Disclosure MCP API Reference Tool

**ID**: REQ-MCP-008\
**Intent**: Keep LLM agent context lean by consolidating Check Point API command search, schema inspection, and payload validation into one tool.\
**Non-goals**: Direct Web API execution (`REQ-MCP-010`).

The `arodonata[mcp]` server SHALL expose a consolidated `api_reference` tool (`action="search" | "describe" | "validate"`, inferring `version` from `mgmt_name` when omitted) so clients can search commands, inspect version-filtered parameters, nested objects, and examples, and validate payloads offline before calling `api_call`.

#### Scenario: SCN-MCP-008-1 — Two-step MCP discovery and payload validation via api_reference tool

- **WHEN** an MCP client calls `api_reference` for `action="search"` (`query="host"`, `crud_type="add"`), `action="describe"` (`command="add-host"`, `version="v2.2"`), and `action="validate"` (`"add-host"`, `{"name": "web-01", "ip-address": "192.0.2.10"}`)
- **THEN** `action="search"` SHALL return compact matching summaries, `action="describe"` SHALL return the `v2.2` field schema, `field_alternatives`, `nested_objects`, and example, and `action="validate"` SHALL return `valid=True` with `errors=[]`

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

**ID**: REQ-MCP-009\
**Intent**: Prevent LLM-tampered plans or arbitrary session takeovers when write-capable CPCRUD tools are enabled on the MCP server.\
**Non-goals**: Direct Python SDK staged-session adoption options (`REQ-CPCRUD-011`).

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was issued/signed by `cpcrud_plan`, omit `force`, `validate_schema`, and `server_ip` from MCP CPCRUD tools, cap `retry_remaining` (`<= 3`), and restrict `cpcrud_staged_session(session_uid, action="publish" | "discard", ...)` exclusively to session UIDs staged by `cpcrud_apply(keep_session=True)` in this server process.

#### Scenario: SCN-MCP-009-1 — Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` receives an unknown `plan_id` or a `plan` whose signature fails or whose `command` / `object_type` / `payload` was altered after `cpcrud_plan`
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: SCN-MCP-009-2 — Staged CPCRUD session published or discarded via dedicated MCP tools

- **GIVEN** a session staged by `cpcrud_apply(..., no_publish=True, keep_session=True)` and registered under `(mgmt_name, domain_key, session_uid)` in this server process
- **WHEN** `cpcrud_staged_session(session_uid=..., action="publish" | "discard", mgmt_name=..., domain=...)` is called
- **THEN** the tool SHALL verify `session_uid` is in this server's staged registry and adopt it non-disruptively without exposing `server_ip` or `force_disconnect`
- **AND** it SHALL publish (invalidating the domain cache) or discard uncommitted changes, remove the registry entry, and log out cleanly

#### Scenario: SCN-MCP-009-3 — Unregistered or foreign session UID rejected by cpcrud_staged_session

- **WHEN** `cpcrud_staged_session` is called with a `session_uid` not created by `cpcrud_apply(..., no_publish=True, keep_session=True)` in this MCP server instance (such as a human administrator's SmartConsole UID)
- **THEN** `cpcrud_staged_session` SHALL raise `ToolFailure` immediately without opening a Check Point session or calling `take-over-session`, `switch-session`, `publish`, or `discard`

### Requirement: Domain Pre-Validation, Write API Guardrails, and SID-Redacted Tool Failures

**ID**: REQ-MCP-010\
**Intent**: Give callers actionable domain-validation errors, block unauthorized `api_call` writes, and keep `sid`s out of all MCP failures.\
**Non-goals**: Transport-level command-name validation (`REQ-TRANS-001`) or ASGI auth (`REQ-MCP-001`).

MCP tools SHALL pre-validate explicit `domain` arguments against `arodonata_domains`, return actionable `ToolFailure` responses on unknown domains or `InvalidCredentialsError`, restrict `api_call` to a read-only allowlist unless `ARODONATA_MCP_ALLOW_WRITE_API=true` (running allowed writes in isolated dedicated sessions), and redact active `sid` values and secrets from all error messages.

#### Scenario: SCN-MCP-010-1 — Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** a tool is called with a `domain` absent from `arodonata_domains` (after one domain-list refresh) or login raises `InvalidCredentialsError`
- **THEN** the server SHALL log the `ToolFailure` at `WARNING` without arguments or secrets
- **AND** it SHALL return an actionable error listing known domains on that management server rather than `"internal error: InvalidCredentialsError"`

#### Scenario: SCN-MCP-010-2 — Write API protection and SID masking on error

- **WHEN** `api_call` is invoked with `ARODONATA_MCP_ALLOW_WRITE_API=false`, or with a write command while `ARODONATA_MCP_ALLOW_WRITE_API=true`, or when an error contains an active session SID
- **THEN** with `ALLOW_WRITE_API=false`, `api_call` SHALL permit ONLY explicit read-only allowlisted commands (rejecting traversal, writes, `publish`, `discard`, `logout`, and unlisted commands)
- **AND** with `ALLOW_WRITE_API=true`, mutating `api_call` calls SHALL run in an isolated dedicated session (never shared `arodonata_sid_cache`) with bounded `timeout`
- **AND** any active `sid` in error output SHALL be redacted before logging or returning to the MCP client

### Requirement: Built-In MCP Domain Prompt Templates

**ID**: REQ-MCP-011\
**Intent**: Provide reusable workflow prompts guiding LLM clients to combine Arodonata read, topology, change-report, and API-reference tools effectively.\
**Non-goals**: Underlying MCP tool execution (`REQ-MCP-002`..`REQ-MCP-010`).

The `arodonata[mcp]` server (`arodonata.mcp.prompts`) SHALL register four reusable MCP prompt templates (`audit_access_rulebase`, `investigate_ip_exposure`, `summarize_recent_changes`, `lookup_api_command`) returning structured user-role guidance tailored to optional domain, package, IP, and command arguments.

#### Scenario: SCN-MCP-011-1 — MCP server registers all four domain workflow prompts with argument substitution

- **WHEN** `register_prompts(mcp)` registers prompt templates on a server (via `create_mcp_server`)
- **THEN** `audit_access_rulebase`, `investigate_ip_exposure`, `summarize_recent_changes`, and `lookup_api_command` SHALL be registered and callable
- **AND** invoking each prompt with domain, package, IP, or command arguments SHALL interpolate those parameters into workflow instructions without touching the network or database

### Requirement: Per-Client MCP Tool Rate Limiting and Quota Isolation

**ID**: REQ-MCP-012\
**Intent**: Protect management servers and cache databases from abusive tool bursts with independent per-client sliding-window throttling.\
**Non-goals**: HTTP transport DNS rebinding protection (`REQ-MCP-001`).

The `arodonata.mcp` server SHALL enforce per-`client_id` sliding-window tool quotas via `MCPToolQuotaManager` inside `mcp_tool_guard` (separating general and live/mutating limits, defaulting unauthenticated callers to `"anonymous"`), emitting `arlogi` `WARNING` audit logs and `arodonata.mcp_rate_limited` span attributes without secret leakage, and returning structured `rate_limit_exceeded` `ToolFailure` JSON payloads.

#### Scenario: SCN-MCP-012-1 — Independent per-client tool throttling emits audit warning, span attrs, and structured rejection without secret leakage

- **WHEN** a caller (`client_id` from `UserContext` or `"anonymous"`) invokes MCP tools exceeding `tool_rate_limit_per_minute` or `live_tool_rate_limit_per_minute`
- **THEN** `mcp_tool_guard` SHALL reject only the exhausted `client_id` (leaving other clients unaffected) with `is_error=True` and JSON `error_code="rate_limit_exceeded"` + positive `retry_after_seconds`
- **AND** live-bucket rejections SHALL NOT consume general quota, quotas SHALL recover cleanly after sliding-window expiry, `0` SHALL disable enforcement, and `arlogi` `WARNING` logs + `arodonata.mcp_rate_limited` span attributes SHALL never expose bearer tokens or SIDs
