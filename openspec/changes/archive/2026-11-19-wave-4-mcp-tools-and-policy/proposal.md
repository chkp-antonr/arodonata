# Proposal: Wave 4 MCP Tools Decomposition, Server Parity, and Fail-Closed Security Policy

## Why

The monolithic MCP tool module (`src/arodonata/mcp/tools.py`, 2,457 LOC) bundled object querying, entity lookup, topology discovery, rulebase inspection, API administration, and HMAC-signed CPCRUD orchestration inside a single 1,982-LOC registration function while reaching into private `client._*` attributes and importing `arodonata.adapters` directly. Additionally, SAST findings **#1, #2, #5, and #6** and server edge-case reviews highlighted:

- Inconsistent startup policy enforcement across `arodonata-mcp` CLI, `create_mcp_server()`, and `create_asgi_app()` allowing unauthenticated `auth_mode="none"` on non-loopback hosts, mutating tools, or wildcard `"*"` `allowed_hosts` / `allowed_origins` while DNS rebinding protection was enabled.
- Split-brain parameter drift when callers passed conflicting runtime settings (`allow_write_api`, `cpcrud`, `auth_mode`, `client`, `settings`, `token_verifier`, `quota_manager`) alongside a pre-built `mcp_server` in `create_asgi_app(mcp_server=...)`.
- Unbracketed IPv6 literal formatting (`::`, `::1`, `fe80::1`) causing Pydantic `AnyHttpUrl` `ValidationError` in `AuthSettings.issuer_url`.
- Missing per-client rate limiting on MCP tool invocations (`mcp_tool_guard`).

## What Changes

- Decompose `src/arodonata/mcp/tools.py` into the cohesive, acyclic `src/arodonata/mcp/tools/` package (`__init__`, `_common`, `_show_object`, `objects`, `lookup`, `topology`, `rulebase`, `admin`, `cpcrud`), keeping every module `<= 477` LOC, preserving exact backward-compatible re-exports and tool behavior, deduplicating `RULEBASE_TYPE_TO_COMMAND` and live collection loops, and replacing all `client._*` and `arodonata.adapters` imports with public facade methods and `arodonata.core.primitives` / `arodonata.core.context`.
- Move `READONLY_EXACT_COMMANDS`, `is_readonly_command`, `validate_command_name`, and `format_host_attr_for_url` to `arodonata.core.primitives` with exact-identity re-exports in `arodonata.adapters.checkpoint`, expose `build_validated_trust_policy` / `TrustPolicy` via `arodonata.client`, and add `"mcp"` import-boundary enforcement (`arodonata.adapters`, `arodonata.testing`) in `tests/unit/test_architecture_boundaries.py`.
- Implement unified fail-closed `ArodonataMCPSettings.validate_security_policy()` called across `cli.py`, `create_mcp_server()`, and `create_asgi_app()` with explicit `allow_insecure_unauthenticated` opt-in (`ARODONATA_MCP_ALLOW_INSECURE_UNAUTHENTICATED` / `--allow-insecure-unauthenticated`), closing SAST #1, #2, and #5.
- Fix IPv6 `issuer_url` formatting via `format_host_attr_for_url()` and reject conflicting baked overrides in `create_asgi_app(mcp_server=...)` with `ConfigurationError`.
- Introduce `MCPToolQuotaManager` (`src/arodonata/mcp/quota.py`) wired into `mcp_tool_guard` (`src/arodonata/mcp/errors.py`) with independent per-`client_id` general and live sliding-window limits, structured `rate_limit_exceeded` JSON `ToolFailure` responses, `arlogi` `WARNING` logs, and `arodonata.mcp_rate_limited` span attributes, closing SAST #6.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `mcp-server`: Enforce unified fail-closed `validate_security_policy()`, IPv6 `issuer_url` bracketing, `create_asgi_app(mcp_server=...)` parity, and per-client sliding-window tool throttling (`REQ-MCP-001` / `SCN-MCP-001-1`, `SCN-MCP-001-6`, `SCN-MCP-001-7`, and `REQ-MCP-012` / `SCN-MCP-012-1`).
- `client-and-facade`: Enforce AST hexagonal import boundaries on `mcp` alongside `core`, `adapters`, `cpcrud`, `rulebase`, and `reports` (`REQ-CLIENT-018` / `SCN-CLIENT-018-1`).

## Impact

- `src/arodonata/mcp/` (replacing `tools.py` with `tools/`, adding `quota.py`, updating `config.py`, `cli.py`, `errors.py`, `security.py`, `server.py`, `__init__.py`).
- `src/arodonata/core/primitives.py`, `src/arodonata/core/services/search_service.py`, `src/arodonata/rulebase/source.py`, `src/arodonata/client/` (`_base.py`, `__init__.py`, `rulebase_reports.py`), and backward-compatible re-exports in `src/arodonata/adapters/checkpoint/`.
- `openspec/specs/mcp-server/spec.md`, `openspec/specs/client-and-facade/spec.md`, `tests/`, `docs/mcp/index.md`, and `CHANGELOG.md`.
