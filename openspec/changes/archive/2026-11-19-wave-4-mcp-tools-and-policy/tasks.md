# Tasks: Wave 4 MCP Tools Decomposition, Server Parity, and Fail-Closed Security Policy

## 1. Hexagonal Boundary Cleanup & Primitives

- [x] 1.1 Move `READONLY_EXACT_COMMANDS`, `is_readonly_command`, `validate_command_name`, and `format_host_attr_for_url` into `src/arodonata/core/primitives.py` with backward-compatible re-exports in `src/arodonata/adapters/checkpoint/`.
- [x] 1.2 Expose `build_validated_trust_policy` / `TrustPolicy` on `arodonata.client` and public `resolve_api_version`, `ensure_and_load_snapshot`, and `resolve_implicit_domain_mode` methods; enforce `"mcp"` import isolation (`arodonata.adapters`, `arodonata.testing`) in `tests/unit/test_architecture_boundaries.py`.

## 2. MCP Tool Package Decomposition (`src/arodonata/mcp/tools/`)

- [x] 2.1 Replace 2,457-LOC `src/arodonata/mcp/tools.py` with cohesive submodules (`__init__.py`, `_common.py`, `_show_object.py`, `objects.py`, `lookup.py`, `topology.py`, `rulebase.py`, `admin.py`, `cpcrud.py`), each `<= 477` LOC, reusing `RULEBASE_TYPE_TO_COMMAND` and deduplicating live collection fetching and model serialization.
- [x] 2.2 Eliminate all `client._*` private attribute accesses in MCP tools and re-export all legacy helpers/constants from `arodonata.mcp.tools`.

## 3. Unified Security Policy, Server Parity & Per-Client Throttling

- [x] 3.1 Implement `ArodonataMCPSettings.validate_security_policy()`, `LOOPBACK_HOSTS`, `is_loopback_host()`, `allow_insecure_unauthenticated`, `tool_rate_limit_per_minute`, and `live_tool_rate_limit_per_minute` in `src/arodonata/mcp/config.py`, plus `--allow-insecure-unauthenticated` in `src/arodonata/mcp/cli.py` (SAST #1, #2, #5).
- [x] 3.2 Fix IPv6 `issuer_url` bracketing via `format_host_attr_for_url()`, call `validate_security_policy()` across `cli.py`, `create_mcp_server()`, and `create_asgi_app()`, and reject conflicting overrides in `create_asgi_app(mcp_server=...)`.
- [x] 3.3 Implement `MCPToolQuotaManager` in `src/arodonata/mcp/quota.py`, wire per-client general/live throttling into `mcp_tool_guard` (`src/arodonata/mcp/errors.py`) with `arlogi` `WARNING` logs, `span_attrs()`, and structured `rate_limit_exceeded` JSON `ToolFailure` responses (SAST #6).

## 4. Verification, OpenSpec SDD & Documentation

- [x] 4.1 Update `openspec/specs/mcp-server/spec.md`, `openspec/specs/client-and-facade/spec.md`, `docs/mcp/index.md`, and `CHANGELOG.md`, add spec-traced unit tests (`SCN-MCP-001-1`, `SCN-MCP-001-6`, `SCN-MCP-001-7`, `SCN-MCP-012-1`, `SCN-CLIENT-018-1`), and pass all 9 repository quality gates and cold-import checks.
