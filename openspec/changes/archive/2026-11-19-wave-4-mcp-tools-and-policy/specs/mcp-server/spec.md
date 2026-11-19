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

- **WHEN** a request arrives with a `Host` header not in `allowed_hosts` (including malformed ports on `host:*` like `localhost:abc`) or a browser `Origin` header not in `allowed_origins`
- **THEN** the server SHALL reject an unlisted or malformed-port `Host` with HTTP `421` and an unlisted `Origin` with HTTP `403`

#### Scenario: SCN-MCP-001-6 — Unified fail-closed security policy rejects unsafe unauthenticated and wildcard configurations across all entry points

- **WHEN** `run_cli`, `create_mcp_server`, or `create_asgi_app` evaluates `validate_security_policy()` on wildcard entries in `allowed_hosts`/`allowed_origins` with `enable_dns_rebinding_protection=True` OR on `auth_mode="none"` paired with non-loopback `host`, disabled DNS rebinding protection, wildcard or non-loopback `allowed_hosts`/`allowed_origins`, `allow_write_api=True`, or `cpcrud=True`
- **THEN** all three entry points SHALL fail closed with `ConfigurationError` (or exit code `2` in CLI) unless `allow_insecure_unauthenticated=True` is explicitly configured for unsafe `auth_mode="none"` (while always permitting loopback read-only `auth_mode="none"` with DNS rebinding protection)

#### Scenario: SCN-MCP-001-7 — IPv6 issuer URL bracketing and create_asgi_app parity prevent split-brain drift

- **WHEN** `create_mcp_server` is constructed with an IPv6 `host` (`"::1"`, `"::"`, `"fe80::1"`) under `auth_mode="static"` or `"jwt"`, OR `create_asgi_app(mcp_server=srv, ...)` is called with an injected server
- **THEN** `AuthSettings.issuer_url` SHALL bracket IPv6 literals cleanly without `ValidationError`
- **AND** `create_asgi_app(mcp_server=srv, ...)` SHALL enforce `validate_security_policy()` on the effective settings and raise `ConfigurationError` whenever runtime overrides (`allow_write_api`, `cpcrud`, `auth_mode`, `client`, conflicting `settings`, `trust_policy`, `token_verifier`, `quota_manager`) conflict with `srv` (while accepting identical `settings`)

### Requirement: Tamper-Proof MCP CPCRUD Plan Execution and Staged Session Lifecycle Tools

**ID**: REQ-MCP-009\
**Intent**: Prevent LLM-tampered plans or cross-caller/foreign session takeovers when write-capable CPCRUD tools are enabled on the MCP server.\
**Non-goals**: Direct Python SDK staged-session adoption options (`REQ-CPCRUD-011`).

When `ARODONATA_MCP_CPCRUD=true`, the MCP server SHALL verify caller-bound HMAC plans in `cpcrud_apply`/`cpcrud_inverse`, omit `force`/`validate_schema`/`server_ip`, cap `retry_remaining` (`<= 3`), isolate `plan_store`, `last_report`, and `staged_session_store` by resolved caller identity (`client_id[:user_id]`), and discard+logout evicted staged sessions on capacity overflow.

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
- **WHEN** `TEAM_A` creates a CPCRUD `plan`, `ApplyReport`, or staged session, and `TEAM_B` attempts to reference `TEAM_A`'s `plan_id`, replay `TEAM_A`'s signed `plan`, read `TEAM_A`'s `last_report` in `cpcrud_inverse`, or publish/discard `TEAM_A`'s `session_uid`, OR when `staged_session_store` exceeds `MAX_STORED_PLANS`
- **THEN** all cross-caller plan and staged-session accesses SHALL fail before executing Check Point API calls
- **AND** capacity eviction of an oldest staged session SHALL discard uncommitted changes, log out its session cleanly, and emit a SID-redacted `WARNING` audit log

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

- **WHEN** `api_call` is invoked with `ARODONATA_MCP_ALLOW_WRITE_API=false`, or with a write command while `ARODONATA_MCP_ALLOW_WRITE_API=true`, or when an error contains an active or just-closed dedicated session SID (including `LoginCoordinator.active_dedicated_sids`)
- **THEN** with `ALLOW_WRITE_API=false`, `api_call` SHALL permit ONLY explicit read-only allowlisted commands (rejecting traversal, writes, `publish`, `discard`, `logout`, and unlisted commands)
- **AND** with `ALLOW_WRITE_API=true`, mutating `api_call` calls SHALL run in an isolated dedicated session (never shared `arodonata_sid_cache`) with bounded `timeout`
- **AND** any active or dedicated `sid` collected via `ArodonataClient.get_active_dedicated_sids()` or tracked by `api_call` SHALL be redacted before logging or returning to the MCP client

## ADDED Requirements

### Requirement: Per-Client MCP Tool Rate Limiting and Quota Isolation

**ID**: REQ-MCP-012\
**Intent**: Protect management servers and cache databases from abusive tool bursts with independent per-caller sliding-window throttling.\
**Non-goals**: HTTP transport DNS rebinding protection (`REQ-MCP-001`).

The `arodonata.mcp` server SHALL enforce per-caller (`client_id[:user_id]` or `"anonymous"`) sliding-window quotas via `MCPToolQuotaManager` inside `mcp_tool_guard` and deferred live-sync checks (charging both explicit live calls and cold/stale `smart` syncs against `live` quota while keeping warm cache hits on `general` quota), returning protected `rate_limit_exceeded` JSON `ToolFailure` responses without secret leakage.

#### Scenario: SCN-MCP-012-1 — Independent per-client tool throttling emits audit warning, span attrs, and structured rejection without secret leakage

- **WHEN** a caller (`client_id` from `UserContext` or `"anonymous"`) invokes MCP tools exceeding `tool_rate_limit_per_minute` or `live_tool_rate_limit_per_minute`
- **THEN** `mcp_tool_guard` SHALL reject only the exhausted caller (leaving other clients unaffected) with `is_error=True` and JSON `error_code="rate_limit_exceeded"` + positive `retry_after_seconds`
- **AND** live-bucket rejections SHALL NOT consume general quota, quotas SHALL recover cleanly after sliding-window expiry, `0` SHALL disable enforcement, and `arlogi` `WARNING` logs + `arodonata.mcp_rate_limited` span attributes SHALL never expose bearer tokens or SIDs

#### Scenario: SCN-MCP-012-2 — Composite caller identity isolation and deferred smart-sync live quota enforcement

- **WHEN** distinct `user_id` principals share one OAuth `client_id`, OR read tools execute in `cache_mode="smart"` across cold/stale syncs vs warm cached hits, OR domain pre-validation / `show_object` triggers a live fallback call
- **THEN** quota accounting SHALL isolate `client_id:user_id` pairs independently, charge cold/stale syncs, domain-miss refreshes, and `show_object` live fallbacks to `live` quota once per invocation, and keep warm `smart`/`cache` hits strictly on the `general` quota
