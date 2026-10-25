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

The `arodonata[mcp]` server SHALL expose progressive-disclosure query tools (`describe_objects` and `query_objects`) for cross-domain filtering, grouping, and counting over `arodonata_objects` and `arodonata_services` without raw SQL, along with a `cache_status` tool reporting freshness per domain and scope from `domain_sync_state`.

#### Scenario: Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` is called
- **THEN** the tool SHALL execute a parameterized query over the cached tables (distinguishing domain-owned vs Global objects via `original_domain`) and return the grouped counts in a single response

#### Scenario: Cache status inspection across scopes

- **WHEN** `cache_status(mgmt_name=...)` is called
- **THEN** it SHALL return per-domain and per-`item_type` sync status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose native, cached, rulebase, change-report, optional live-compat, and opt-in CPCRUD tools, pre-validating `domain` names against `arodonata_domains` before login, validating `obj_type` in `show_object` against the canonical type registry, enforcing a read-only command allowlist in `api_call` when `ARODONATA_MCP_ALLOW_WRITE_API=false`, isolating allowed write `api_call` invocations in a dedicated session, and passing `known_sids` into error redaction.

#### Scenario: List tool response envelope includes source and cache age

- **WHEN** a list tool (`show_hosts`, `show_networks`, `show_services`, etc.) returns a page of objects
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), and `cache_age_seconds`

#### Scenario: Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_access_rulebase` or `show_nat_rulebase` is called (including with `filter`) on a domain with a fresh rulebase snapshot and without live-only parameters (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`)
- **THEN** it SHALL evaluate any `filter` locally against the cached rulebase and cached objects/services in `markdown`, `model_friendly`, or `raw` format, and execute a live Management API query only when live-only parameters or `cache_mode="live"` are requested

#### Scenario: Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** a tool is called with a `domain` not present in the `arodonata_domains` table (after a single domain-list refresh) or login raises `InvalidCredentialsError`
- **THEN** the server SHALL log the `ToolFailure` at WARNING (without arguments or secrets) and return an actionable error listing known domains on that management server rather than `"internal error: InvalidCredentialsError"`

#### Scenario: Write API protection and SID masking on error

- **WHEN** `api_call` is invoked while `ARODONATA_MCP_ALLOW_WRITE_API=false`, or invoked with a write command while `ARODONATA_MCP_ALLOW_WRITE_API=true`, or when an error message contains an active session SID
- **THEN** when `ALLOW_WRITE_API=false`, `api_call` SHALL permit ONLY commands in the explicit read-only command allowlist (rejecting path traversal, mutating commands, `publish`, `discard`, `logout`, and unlisted commands); when `ALLOW_WRITE_API=true`, mutating `api_call` invocations SHALL execute inside an isolated dedicated session (never the shared `arodonata_sid_cache` session) with bounded `timeout`; and any error text SHALL be sanitized via `redact_sid(..., known_sids=...)`

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was generated by `cpcrud_plan` (via server-side `plan_id` storage or HMAC-SHA256 signature verification), omit `force` and `validate_schema` from MCP tools, cap `retry_remaining` (`<= 3`), and expose `cpcrud_publish_staged` and `cpcrud_discard_staged` tools.

#### Scenario: Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` is called with an unknown `plan_id` or a `plan` payload that was not issued/signed by this server's `cpcrud_plan` tool (or whose `command` / `object_type` / `payload` was altered)
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: Staged CPCRUD session published or discarded via dedicated MCP tools

- **WHEN** `cpcrud_apply(..., no_publish=True, keep_session=True)` stages changes in a dedicated session and the caller subsequently invokes `cpcrud_publish_staged(mgmt_name, domain, session_uid)` or `cpcrud_discard_staged(mgmt_name, domain, session_uid)`
- **THEN** the tool SHALL adopt the staged session via `take-over-session` and publish (invalidating the domain cache) or discard and log out cleanly so no locks remain orphaned
