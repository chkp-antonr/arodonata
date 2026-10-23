# Model Context Protocol (MCP) Server Specification

## Purpose

Defines the Streamable-HTTP Model Context Protocol server (`arodonata-mcp` CLI and `arodonata.mcp` embeddable ASGI application), authentication and security guards, tool surface (native, cached, rulebase, change report, live compatibility, and opt-in CPCRUD tools), and prompt templates.

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

### Requirement: Multi-Server Tool Surface and Cache-Backed Envelopes

The MCP server SHALL expose native, cached, hybrid rulebase, change-report, optional live-compatibility (`ARODONATA_MCP_LIVE_COMPAT=true`), and opt-in CPCRUD (`ARODONATA_MCP_CPCRUD=true`) tools across all configured management servers and domains.

#### Scenario: List tool response envelope includes source and cache age

- **WHEN** a list tool (`show_hosts`, `show_networks`, etc.) returns a page of objects
- **THEN** the JSON text response SHALL include `from`, `to`, `total`, `source` (`"cache"` or `"live"`), and `cache_age_seconds`

#### Scenario: Rulebase tool switches between cached SmartConsole view and live query

- **WHEN** `show_access_rulebase` is called without live-only filter/hit parameters
- **THEN** it SHALL serve the numbered rulebase from the domain's rulebase cache in `markdown` (default), `model_friendly`, or `raw` format; when live-only parameters (`filter`, `show_hits`, `order`, etc.) are passed, it SHALL execute a live Management API query

#### Scenario: Write API protection and SID masking on error

- **WHEN** `api_call` is invoked with a non-`show-*` command while `ARODONATA_MCP_ALLOW_WRITE_API=false`, or when a Management API error message echoes a session SID
- **THEN** non-`show-*` commands SHALL be rejected before execution, any echoed SID in error messages SHALL be masked, and unexpected internal exceptions SHALL return `"internal error: <ExceptionClass>"` without leaking stack traces
