# Spec Delta

## MODIFIED Requirements

### Requirement: Standalone CLI and Embeddable ASGI Server Modes

**ID**: REQ-MCP-001\
**Intent**: Expose Arodonata securely over Streamable-HTTP MCP in standalone and embedded ASGI deployments with unified fail-closed security policy, IPv6 support, strict `Host`/`Origin` checks, and an explicit service-account server-wide visibility trust boundary.\
**Non-goals**: Per-tenant RBAC partitioning across Check Point domains (authenticated MCP callers share the configured backend service-account domain visibility unless scoped by a host gateway), tool-level domain validation, per-client tool rate limiting (`REQ-MCP-012`), and write-API allowlisting (`REQ-MCP-010`).

The `arodonata.mcp` package SHALL provide `arodonata-mcp`, `create_mcp_server`, and `create_asgi_app`, enforcing `validate_security_policy()`, IPv6 `issuer_url` bracketing, constant-time SHA-256 bearer auth, `create_asgi_app(mcp_server=...)` parity, and strict `Host`/`Origin` rejection (rejecting present-but-blank `Origin` headers).

#### Scenario: SCN-MCP-001-1 — Standalone startup validates TLS trust store and auth mode

- **WHEN** `arodonata-mcp` starts up
- **THEN** it SHALL verify the TLS trust store configuration before serving traffic
- **AND** it SHALL exit with code `2` and a clear error if `ARODONATA_MCP_AUTH_MODE=host` or `jwt` (without a verifier) or an invalid ASGI configuration is encountered
- **AND** it SHALL fail closed with exit code `2` when `auth_mode="none"` is paired with non-loopback `--host` (`0.0.0.0`), disabled DNS rebinding protection, non-loopback `allowed_hosts`/`allowed_origins`, or `ALLOWED_HOSTS=*` unless `allow_insecure_unauthenticated=True` (emitting `SECURITY WARNING` once and closing the owned client cleanly)

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

- **WHEN** a request arrives with a `Host` header not in `allowed_hosts` (including malformed ports on `host:*` like `localhost:abc`) or a browser `Origin` header that is present-but-blank (`""`, `"   "`) or not in `allowed_origins`
- **THEN** the server SHALL reject an unlisted or malformed-port `Host` with HTTP `421` and a blank or unlisted `Origin` with HTTP `403` (permitting only absent `Origin is None` for non-browser CLI/agent clients)

#### Scenario: SCN-MCP-001-6 — Unified fail-closed security policy rejects unsafe unauthenticated and wildcard configurations across all entry points

- **WHEN** `run_cli`, `create_mcp_server`, or `create_asgi_app` evaluates `validate_security_policy()` on wildcard entries in `allowed_hosts`/`allowed_origins` with `enable_dns_rebinding_protection=True` OR on `auth_mode="none"` paired with non-loopback `host`, disabled DNS rebinding protection, wildcard or non-loopback `allowed_hosts`/`allowed_origins`, `allow_write_api=True`, or `cpcrud=True`
- **THEN** all three entry points SHALL fail closed with `ConfigurationError` (or exit code `2` in CLI) unless `allow_insecure_unauthenticated=True` is explicitly configured for unsafe `auth_mode="none"` (while always permitting loopback read-only `auth_mode="none"` with DNS rebinding protection)

#### Scenario: SCN-MCP-001-7 — IPv6 issuer URL bracketing and create_asgi_app parity prevent split-brain drift

- **WHEN** `create_mcp_server` is constructed with an IPv6 `host` (`"::1"`, `"::"`, `"fe80::1"`) under `auth_mode="static"` or `"jwt"`, OR `create_asgi_app(mcp_server=srv, ...)` is called with an injected server
- **THEN** `AuthSettings.issuer_url` SHALL bracket IPv6 literals cleanly without `ValidationError`
- **AND** `create_asgi_app(mcp_server=srv, ...)` SHALL enforce `validate_security_policy()` on the effective settings and raise `ConfigurationError` whenever runtime overrides (`allow_write_api`, `cpcrud`, `auth_mode`, `client`, conflicting `settings`, `trust_policy`, `token_verifier`, `quota_manager`) conflict with `srv` (while accepting identical `settings`)

### Requirement: Cache-Aligned Tool Surface, Envelopes, and Single-Entity Lookup

**ID**: REQ-MCP-002\
**Intent**: Provide uniform paginated JSON envelopes with cold-cache upgrades and predictable cache-faithful exact/ambiguous/wildcard/substring `show_object` resolution.\
**Non-goals**: Structured SQL-backed aggregation (`REQ-MCP-004`) or cross-domain `get_group_members` (`REQ-MCP-003`).

The MCP server SHALL expose a cache-aligned tool surface (`list_domains`, `list_objects`, `list_services`, `list_assets`, `show_object`, `show_rulebase`, `locate_rules`, `search_objects`, `get_group_members`, `query_objects`, `cache_control`, `locate_gateways`, `api_reference`, `change_report`, `api_call`, and opt-in CPCRUD tools) returning cache-backed JSON envelopes while honoring `cache_mode="cache"` and MDS cache-only downgrades in `show_object`.

#### Scenario: SCN-MCP-002-1 — List and search tool response envelope includes source, accurate cache age, and cold-cache auto-upgrade

- **WHEN** `list_domains`, `list_objects`, `list_services`, `list_assets`, `search_objects`, or `query_objects` executes
- **THEN** the JSON text response SHALL return `from`, `to`, `total`, `source` (`"cache"` or `"live"`), `cache_age_seconds` (`null` when no `synced_at` timestamp exists rather than `0.0`), and sliced `objects`
- **AND** when `cache_mode="cache"` runs on an uninitialized scope (`0` sync states for that scope, or `0` cached domain rows for `domains`), it SHALL auto-upgrade to `"smart"`
- **AND** when `mgmt_name` is omitted in `search_objects`, the search SHALL span all configured `mgmt_names` rather than only `mgmt_names[0]`

#### Scenario: SCN-MCP-002-2 — Single-entity show_object resolves across objects, services, assets, and layers with wildcard and substring fallback

- **WHEN** `show_object(uid_or_name=..., mgmt_name=..., domain=..., limit=20, offset=0, cache_mode=...)` runs across `arodonata_objects`, `arodonata_services`, `arodonata_assets`, and cached rulebase layers (`"Global"` included when `domain` is omitted)
- **THEN** an exact non-wildcard match in one domain SHALL return `match_type="exact"` with full details, multi-domain exact matches (`domain=None`) SHALL return `match_type="ambiguous"`, wildcards SHALL evaluate `fnmatchcase`, and misses SHALL return substring candidates (`match_type="substring_candidates"`)
- **AND** when `cache_mode="cache"` on an initialized cache or downgraded to cache-only on multi-domain MDS (`domain=None`), `show_object` SHALL NOT execute a remote `show-object` fallback API call on cache miss

### Requirement: Structured Object Querying, Aggregation, and Type/Field Alias Normalization

**ID**: REQ-MCP-004\
**Intent**: Give MCP agents fast parameterized filtering, counting, and schema discovery with bounded pagination/group cardinality and consistent field and `Cpmi*` asset aliases.\
**Non-goals**: Single-entity text search (`REQ-MCP-002`).

`query_objects` (`aggregate="list" | "count" | "describe"`) SHALL support parameterized filtering, grouping, and counting across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` without raw SQL, clamping `limit` (`1..1000`), normalizing non-negative `offset` and bounded `group_by` results, and normalizing field and `Cpmi*` asset aliases case-insensitively.

#### Scenario: SCN-MCP-004-1 — Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count", limit=..., offset=...)` (or with `group_by=["domain", "type"]` and `types=["cluster", "vsx", "vs"]`) is called
- **THEN** the tool SHALL clamp `limit` (`1..1000`), enforce `offset >= 0`, bound grouped result cardinality, and run a parameterized query distinguishing domain-owned vs `Global` objects via `original_domain`
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

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

**ID**: REQ-MCP-009\
**Intent**: Prevent LLM-tampered plans, `plan_id` re-keying, or cross-caller session disruptions when write-capable CPCRUD tools are enabled on the MCP server.\
**Non-goals**: Direct Python SDK staged-session adoption options (`REQ-CPCRUD-011`).

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify caller-and-`plan_id`-bound HMAC plans in `cpcrud_apply`/`cpcrud_inverse`, forbid cross-caller `plan_id` overwrites, omit `force`/`validate_schema`/`server_ip`, cap `retry_remaining` (`<= 3`), isolate stores by `client_id[:user_id]`, and prioritize same-caller staged-session eviction before cross-caller LRU eviction.

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

#### Scenario: SCN-MCP-009-4 — CPCRUD plans, ApplyReports, and staged sessions isolate per caller and discard cleanly on eviction

- **GIVEN** two authenticated MCP callers (`TEAM_A` and `TEAM_B`) sharing one server instance
- **WHEN** `TEAM_A` creates a CPCRUD `plan`, `ApplyReport`, or staged session, and `TEAM_B` attempts to reference/overwrite `TEAM_A`'s `plan_id`, replay `TEAM_A`'s signed `plan` with altered `plan_id`, read `TEAM_A`'s `last_report`, or publish/discard `TEAM_A`'s `session_uid`, OR when `staged_session_store` exceeds capacity
- **THEN** `plan_id` SHALL be bound into `_sign_plan`, all cross-caller plan accesses/overwrites and staged-session accesses SHALL fail before Check Point API calls, and capacity eviction SHALL evict same-caller entries before cross-caller entries (discarding, logging out cleanly, and emitting a SID-redacted `WARNING` audit log)

### Requirement: Domain Pre-Validation, Write API Guardrails, and SID-Redacted Tool Failures

**ID**: REQ-MCP-010\
**Intent**: Give callers actionable domain-validation errors across all tools, shield mutating `api_call` errors/cleanups, and scrub `sid`s from every MCP tool failure and output.\
**Non-goals**: Transport-level command-name validation (`REQ-TRANS-001`) or ASGI auth (`REQ-MCP-001`).

MCP tools SHALL resolve default `mgmt_name` and pre-validate explicit `domain`/`domains` arguments across all domain-accepting tools, enforce the read-only `api_call` allowlist unless `ALLOW_WRITE_API=true` (shielding `logout_sid` in `finally` and retaining just-closed `dedicated_sid` for error redaction), and pass `known_sids` into `json_tool_result` across read/admin/write tools.

#### Scenario: SCN-MCP-010-1 — Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** any domain-accepting tool (`query_objects`, `locate_gateways`, `cache_control`, etc.) is called with `domain` or `domains` (including when `mgmt_name` is omitted) absent from `arodonata_domains` (after one refresh), or login raises `InvalidCredentialsError`
- **THEN** the tool SHALL resolve default `mgmt_name` for domain validation, log `ToolFailure` at `WARNING` without arguments/secrets, and list known domains rather than `"internal error: InvalidCredentialsError"`

#### Scenario: SCN-MCP-010-2 — Write API protection and SID masking on error

- **WHEN** `api_call` runs with `ARODONATA_MCP_ALLOW_WRITE_API=false`, executes a mutating command under `ALLOW_WRITE_API=true` that raises an error (e.g. `TaskPollError`), or when object, asset, rulebase, `cache_control`, or `change_report` tools return results
- **THEN** `ALLOW_WRITE_API=false` SHALL permit ONLY read-only allowlisted commands, while `ALLOW_WRITE_API=true` mutating `api_call` SHALL run in a dedicated session, shield `logout_sid` cleanup on error, retain the just-closed `dedicated_sid` in `known_sids` before `mcp_tool_guard` runs, and thread `known_sids` into `json_tool_result` across all read/admin/write tool envelopes and errors

### Requirement: Per-Client MCP Tool Rate Limiting and Quota Isolation

**ID**: REQ-MCP-012\
**Intent**: Protect management servers and cache databases from abusive tool bursts with accurate per-caller sliding-window throttling across multi-scope, composite-ID, and multi-domain fan-out calls.\
**Non-goals**: HTTP transport DNS rebinding protection (`REQ-MCP-001`).

The `arodonata.mcp` server SHALL enforce per-caller (`client_id[:user_id]` or `"anonymous"`) sliding-window quotas via `MCPToolQuotaManager` inside `mcp_tool_guard` and deferred checks covering every touched scope (`objects`, `services`, `assets`), composite-ID domain, and multi-domain fan-out (`cache_control`, `change_report`), returning protected `rate_limit_exceeded` JSON responses.

#### Scenario: SCN-MCP-012-1 — Independent per-client tool throttling emits audit warning, span attrs, and structured rejection without secret leakage

- **WHEN** a caller (`client_id` from `UserContext` or `"anonymous"`) invokes MCP tools exceeding `tool_rate_limit_per_minute` or `live_tool_rate_limit_per_minute`
- **THEN** `mcp_tool_guard` SHALL reject only the exhausted caller (leaving other clients unaffected) with `is_error=True` and JSON `error_code="rate_limit_exceeded"` + positive `retry_after_seconds`
- **AND** live-bucket rejections SHALL NOT consume general quota, quotas SHALL recover cleanly after sliding-window expiry, `0` SHALL disable enforcement, and `arlogi` `WARNING` logs + `arodonata.mcp_rate_limited` span attributes SHALL never expose bearer tokens or SIDs

#### Scenario: SCN-MCP-012-2 — Composite caller identity isolation and deferred smart-sync live quota enforcement

- **WHEN** distinct `user_id` principals share one `client_id`, `query_objects`/`show_object`/`get_group_members` touch `objects`, `services`, `assets`, or composite-ID domains in `cache`/`smart` mode, OR `cache_control(action="refresh")` / `change_report(scopes=...)` fans out across multiple domains/scopes
- **THEN** quota accounting SHALL isolate `client_id:user_id` pairs independently, run live-quota and cold-upgrade checks across every touched scope and composite-ID domain, and charge proportional live slots (or cap domain fan-out) while keeping warm single-hit `cache` calls on `general` quota
