# Spec Delta

## MODIFIED Requirements

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

## ADDED Requirements

### Requirement: Per-Client MCP Tool Rate Limiting and Quota Isolation

**ID**: REQ-MCP-012\
**Intent**: Protect management servers and cache databases from abusive tool bursts with independent per-client sliding-window throttling.\
**Non-goals**: HTTP transport DNS rebinding protection (`REQ-MCP-001`).

The `arodonata.mcp` server SHALL enforce per-`client_id` sliding-window tool quotas via `MCPToolQuotaManager` inside `mcp_tool_guard` (separating general and live/mutating limits, defaulting unauthenticated callers to `"anonymous"`), emitting `arlogi` `WARNING` audit logs and `arodonata.mcp_rate_limited` span attributes without secret leakage, and returning structured `rate_limit_exceeded` `ToolFailure` JSON payloads.

#### Scenario: SCN-MCP-012-1 — Independent per-client tool throttling emits audit warning, span attrs, and structured rejection without secret leakage

- **WHEN** a caller (`client_id` from `UserContext` or `"anonymous"`) invokes MCP tools exceeding `tool_rate_limit_per_minute` or `live_tool_rate_limit_per_minute`
- **THEN** `mcp_tool_guard` SHALL reject only the exhausted `client_id` (leaving other clients unaffected) with `is_error=True` and JSON `error_code="rate_limit_exceeded"` + positive `retry_after_seconds`
- **AND** live-bucket rejections SHALL NOT consume general quota, quotas SHALL recover cleanly after sliding-window expiry, `0` SHALL disable enforcement, and `arlogi` `WARNING` logs + `arodonata.mcp_rate_limited` span attributes SHALL never expose bearer tokens or SIDs
