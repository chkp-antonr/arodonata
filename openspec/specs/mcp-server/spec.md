# Model Context Protocol (MCP) Server Specification

## Purpose

Defines the Streamable-HTTP Model Context Protocol server (`arodonata-mcp` CLI and `arodonata.mcp` embeddable ASGI application under `arodonata[mcp]`), authentication and security guards, tool surface (native, cached, structured query/aggregation, rulebase, change report, live compatibility, and opt-in CPCRUD tools), and prompt templates.

## Requirements

### Requirement: Standalone CLI and Embeddable ASGI Server Modes

The `arodonata.mcp` package SHALL provide both a standalone CLI (`arodonata-mcp`) serving Streamable HTTP via `uvicorn` and library functions (`create_mcp_server`, `create_asgi_app`) for mounting inside an external Starlette/FastAPI application.

#### Scenario: Standalone startup validates TLS trust store and auth mode

- **WHEN** `arodonata-mcp` starts up
- **THEN** it SHALL verify the TLS trust store configuration and refuse `ARODONATA_MCP_AUTH_MODE=host` or `jwt` with exit code `2` and a clear configuration error message

#### Scenario: Static bearer token authentication maps token variable name to client_id

- **WHEN** `ARODONATA_MCP_AUTH_MODE=static` is configured with `ARODONATA_MCP_TOKEN_VARS="TEAM_A_TOKEN,TEAM_B_TOKEN"`
- **THEN** the server SHALL verify incoming `Authorization: Bearer <token>` headers using constant-time comparison and record the matching environment variable name (`TEAM_A_TOKEN`) as the caller's `client_id` in logs without ever logging the token value

#### Scenario: Host authentication mode in embedded ASGI applications

- **WHEN** `create_mcp_server` is called with `auth_mode="host"` for embedding inside an authenticating ASGI host
- **THEN** Arodonata SHALL disable its internal token verifier and rely on the enclosing ASGI host middleware for request authentication

#### Scenario: DNS rebinding and Origin header protection

- **WHEN** a request arrives with a `Host` header not in `allowed_hosts` or a browser `Origin` header not in `allowed_origins`
- **THEN** the server SHALL reject an unlisted `Host` with HTTP `421` and an unlisted `Origin` with HTTP `403`

### Requirement: Structured Object Aggregation and Cache Status Tools

The `arodonata[mcp]` server SHALL expose progressive-disclosure query tools (`describe_objects` and `query_objects`) for cross-domain filtering, grouping, and counting over `arodonata_objects` and `arodonata_services` without raw SQL, along with a `cache_status` tool reporting freshness per domain and scope from `domain_sync_state`.

#### Scenario: Aggregate object counts across domains in a single tool call

- **WHEN** `query_objects(types=["host", "network"], group_by=["domain_name", "type"], aggregate="count")` is called
- **THEN** the tool SHALL execute a parameterized query over the cached tables (distinguishing domain-owned vs Global objects via `original_domain`) and return the grouped counts in a single response

#### Scenario: Cache status inspection across scopes

- **WHEN** `cache_status(mgmt_name=...)` is called
- **THEN** it SHALL return per-domain and per-`item_type` sync status, `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose native, cached, hybrid rulebase, change-report, optional live-compatibility (`ARODONATA_MCP_LIVE_COMPAT=true`), and opt-in CPCRUD (`ARODONATA_MCP_CPCRUD=true`) tools, pre-validating target `domain` names against the cached `domains` table before attempting server login and mapping `InvalidCredentialsError` to actionable model-facing messages.

#### Scenario: List tool response envelope includes source and cache age

- **WHEN** a list tool (`show_hosts`, `show_networks`, `show_services`, etc.) returns a page of objects
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), and `cache_age_seconds`

#### Scenario: Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_access_rulebase` or `show_nat_rulebase` is called (including with `filter`) on a domain with a fresh rulebase snapshot and without live-only parameters (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`)
- **THEN** it SHALL evaluate any `filter` locally against the cached rulebase and cached objects/services in `markdown`, `model_friendly`, or `raw` format, and execute a live Management API query only when live-only parameters or `cache_mode="live"` are requested

#### Scenario: Unknown domain or rejected login returns actionable ToolFailure

- **WHEN** a tool is called with a `domain` not present in the `domains` table (after a single domain-list refresh) or login raises `InvalidCredentialsError`
- **THEN** the server SHALL log the `ToolFailure` at WARNING (without arguments or secrets) and return an actionable error listing known domains on that management server rather than `"internal error: InvalidCredentialsError"`

#### Scenario: Write API protection and SID masking on error

- **WHEN** `api_call` is invoked with a non-`show-*` command while `ARODONATA_MCP_ALLOW_WRITE_API=false`, or when a Management API error message echoes a session SID
- **THEN** non-`show-*` commands SHALL be rejected before execution, any echoed SID in error messages SHALL be masked, and unexpected internal exceptions SHALL return `"internal error: <ExceptionClass>"` without leaking stack traces
