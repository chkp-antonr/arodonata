# Proposal: Milestone 6 — Streamable-HTTP MCP Server & CLI (`milestone-6-mcp-server`)

## Why

With Milestones 1–5 complete (`core`, `adapters/checkpoint`, `adapters/storage`, `adapters/sse`, `rulebase`, `reports`, `cpcrud`, and `ArodonataClient`), Arodonata v2 requires the final Milestone 6 subsystem: `src/arodonata/mcp/` (`arodonata[mcp]`). This package provides both a standalone Streamable-HTTP Model Context Protocol CLI (`arodonata-mcp`) and embeddable factory functions (`create_mcp_server`, `create_asgi_app`) for Starlette/FastAPI applications, exposing Check Point management, cache-backed object/service discovery, progressive-disclosure cross-domain aggregation (`describe_objects`, `query_objects`, `cache_status`), hybrid SmartConsole rulebase introspection, auditable session change reporting, optional live-compatibility tools, and opt-in CPCRUD policy-as-code tools to LLM agents with strict security guards.

## What Changes

- Implement `src/arodonata/mcp/config.py` (`ArodonataMCPSettings`):
  - Type-safe MCP server settings prefixed with `ARODONATA_MCP_` (`host`, `port`, `path`, `auth_mode` in `{"static", "host", "jwt", "none"}`, `token_vars`, `tokens`, `allowed_hosts`, `allowed_origins`, `enable_dns_rebinding_protection`, `allow_write_api`, `live_compat`, `cpcrud`, `json_response`, `stateless_http`).
  - Redacts `tokens` in `__repr__` (`***REDACTED***`) and resolves `ARODONATA_MCP_TOKEN_VARS` to `(env_var_name, secret_value)` pairs for constant-time `client_id` attribution.
- Implement `src/arodonata/mcp/security.py` (`StaticTokenVerifier`, `MCPOriginHostGuardMiddleware`, `MCPAuthGuardMiddleware`):
  - Constant-time `hmac.compare_digest` bearer token verification against `ARODONATA_MCP_TOKEN_VARS` / `ARODONATA_MCP_TOKENS`, mapping the matched environment variable name (e.g. `TEAM_A_TOKEN`) to `client_id` in `AccessToken` and `UserContext` (`contextvars`) and logging the authenticated `client_id` without ever logging the token value.
  - `auth_mode="host"` pass-through mode when embedding inside an authenticating ASGI host (disables Arodonata's internal token verifier and relies on the enclosing ASGI host middleware).
  - DNS rebinding and browser `Origin` protection middleware that enforces `allowed_hosts` (returning HTTP `421 Misdirected Request` on unlisted `Host` headers) and `allowed_origins` (returning HTTP `403 Forbidden` on unlisted `Origin` headers) across all HTTP methods (`GET`, `POST`, `DELETE`, `OPTIONS`).
- Implement `src/arodonata/mcp/errors.py` (`ToolFailure`, `validate_domain_or_fail`, `handle_tool_errors`):
  - `ToolFailure` exception for model-facing actionable errors; logged at `WARNING` with tool name, `mgmt_name`, `domain`, and error summary (never logging raw tool arguments or secrets/SIDs).
  - Pre-login domain validation (`validate_domain_or_fail`) against the cached `domains` table, performing at most one domain-list refresh (`client.get_domains(..., cache_mode="force")`) on a miss before raising an actionable `ToolFailure` listing known domains on that management server.
  - Translates `InvalidCredentialsError` and `DomainNotFoundError` into actionable `ToolFailure` messages listing known domains rather than `"internal error: InvalidCredentialsError"`.
  - Redacts any echoed session SIDs or secrets via `redact_sid` and converts unexpected internal exceptions into `CallToolResult(is_error=True, content=[TextContent(type="text", text="internal error: <ExceptionClass>")])` without leaking stack traces.
- Implement `src/arodonata/mcp/tools.py`, `src/arodonata/mcp/prompts.py`, `src/arodonata/mcp/server.py`, and `src/arodonata/mcp/cli.py`:
  - Cached list & lookup tools (`show_domains`, `show_hosts`, `show_networks`, `show_address_ranges`, `show_dns_domains`, `show_services`, `show_groups`, `show_gateways_and_servers`, `show_object`, `search_objects`, `find_object`, `get_group_members`) returning JSON text envelopes containing `from`, `to`, `total`, `source` (`"cache"` or `"live"`), and `cache_age_seconds` (preserving server-level fields on `show_domains` at `details_level="standard"`).
  - Progressive-disclosure aggregation and cache status tools (`describe_objects`, `query_objects` distinguishing domain-owned vs `Global` objects via `original_domain`, and `cache_status` reporting `last_published_at`, `last_session_uid`, `synced_at`, and `cache_age_seconds` across `"domains"`, `"objects"`, `"services"`, `"assets"`, and `"rulebase"` from `domain_sync_state`).
  - Hybrid rulebase tools (`show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase`, `show_policy_packages`, `locate_rules`) serving numbered SmartConsole rulebases from fresh cache and evaluating `filter` locally against cached rules/objects/services in `markdown` (default), `model_friendly`, or `raw` format, switching to live Management API queries only when live-only parameters (`show_hits`, `order`, `show_as_ranges`, `show_expiration_settings`, `filter_settings`, `hits_settings`) or `cache_mode="live"` are passed.
  - Auditable change-report tool (`change_report` / `build_change_report`), gated `api_call` (`ARODONATA_MCP_ALLOW_WRITE_API=false` rejecting non-`show-*` commands and masking any echoed SIDs), optional live-compatibility tools (`ARODONATA_MCP_LIVE_COMPAT=true`), opt-in CPCRUD tools (`ARODONATA_MCP_CPCRUD=true`: `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`), and MCP prompt templates.
  - Standalone `arodonata-mcp` CLI (`src/arodonata/mcp/cli.py`) validating TLS trust store configuration at startup and refusing `ARODONATA_MCP_AUTH_MODE=host` or `jwt` in standalone mode with exit code `2` and a clear configuration error message.

## Capabilities

### New Capabilities

<!-- None: implements existing canonical specification in openspec/specs/mcp-server/spec.md. -->

### Modified Capabilities

<!-- None: skip_specs is enabled in .openspec.yaml. -->

## Impact

- **Codebase**: Adds `src/arodonata/mcp/` (`__init__.py`, `config.py`, `errors.py`, `security.py`, `tools.py`, `prompts.py`, `server.py`, `cli.py`) and updates `src/arodonata/__init__.py`.
- **Tests**: Adds comprehensive unit and ASGI integration tests in `tests/test_mcp_config_and_cli.py`, `tests/test_mcp_security.py`, and `tests/test_mcp_tools.py`.
