# Spec Delta: Model Context Protocol (MCP) Server

## MODIFIED Requirements

### Requirement: Standalone CLI and Embeddable ASGI Server Modes

The `arodonata.mcp` package SHALL provide both a standalone CLI (`arodonata-mcp`) serving Streamable HTTP via `uvicorn` and library functions (`create_mcp_server`, `create_asgi_app`) for mounting inside an external Starlette/FastAPI application, enforcing fail-closed authentication in `"static"` and `"jwt"` modes, parsing `client_id=secret` static token entries ONLY when the left-hand side matches `^[A-Za-z_][A-Za-z0-9_-]*$` with a minimum secret length of 32 characters, hashing both sides with SHA-256 before `hmac.compare_digest`, and validating numeric ports on wildcard `Host` patterns.

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

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose native, cached, hybrid rulebase, change-report, optional live-compatibility (`ARODONATA_MCP_LIVE_COMPAT=true`), and opt-in CPCRUD (`ARODONATA_MCP_CPCRUD=true`) tools, pre-validating target `domain` names against the cached `arodonata_domains` table before attempting server login, validating `obj_type` in `show_object` against the canonical object type registry, enforcing an explicit allowlist of read-only commands in `api_call` when `ARODONATA_MCP_ALLOW_WRITE_API=false`, isolating any allowed write `api_call` inside a dedicated session, and passing active `known_sids` into all MCP error redaction paths.

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

## ADDED Requirements

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify that every plan passed to `cpcrud_apply` or `cpcrud_inverse` was generated by `cpcrud_plan` (via server-side `plan_id` storage or HMAC-SHA256 signature verification), omit `force` and `validate_schema` from MCP tools, cap `retry_remaining` (`<= 3`), and expose `cpcrud_publish_staged` and `cpcrud_discard_staged` tools.

#### Scenario: Model-forged or modified plan rejected by cpcrud_apply

- **WHEN** `cpcrud_apply` is called with an unknown `plan_id` or a `plan` payload that was not issued/signed by this server's `cpcrud_plan` tool (or whose `command` / `object_type` / `payload` was altered)
- **THEN** `cpcrud_apply` SHALL reject the request before opening a Check Point session or executing any API call

#### Scenario: Staged CPCRUD session published or discarded via dedicated MCP tools

- **WHEN** `cpcrud_apply(..., no_publish=True, keep_session=True)` stages changes in a dedicated session and the caller subsequently invokes `cpcrud_publish_staged(mgmt_name, domain, session_uid)` or `cpcrud_discard_staged(mgmt_name, domain, session_uid)`
- **THEN** the tool SHALL adopt the staged session via `take-over-session` and publish (invalidating the domain cache) or discard and log out cleanly so no locks remain orphaned
