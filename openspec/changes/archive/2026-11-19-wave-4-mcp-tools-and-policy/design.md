# Design: Wave 4 MCP Tools Decomposition, Server Parity, and Fail-Closed Security Policy

## Context

`src/arodonata/mcp/tools.py` reached 2,457 LOC and directly imported Check Point adapter modules (`adapters.checkpoint.*`) and private client internals (`client._rulebase_source`, `client._resolve_api_version`, `client._cache`). Meanwhile, SAST #1, #2, #5, and #6 required unifying security policy validation across all MCP entry points, eliminating `create_asgi_app(mcp_server=...)` split-brain configuration drift, fixing IPv6 literal `AnyHttpUrl` crashes, and adding per-client MCP tool throttling.

## Goals / Non-Goals

- **Goals**:
  - Decompose `mcp/tools.py` into acyclic domain submodules (`<= 500` LOC per file) with zero `arodonata.adapters` imports and zero private `client._*` accesses.
  - Enforce `ArodonataMCPSettings.validate_security_policy()` consistently across `arodonata-mcp` CLI, `create_mcp_server()`, and `create_asgi_app()`.
  - Fail closed on unsafe `auth_mode="none"` (non-loopback, wildcards, `allow_write_api`, `cpcrud`) unless `allow_insecure_unauthenticated=True` is explicitly set, and fail closed on wildcard host/origin entries when DNS rebinding protection is active.
  - Bracket IPv6 hosts in `AuthSettings.issuer_url` and fail loudly when `create_asgi_app(mcp_server=...)` receives overrides incompatible with the baked `MCPServer`.
  - Enforce per-`client_id` sliding-window tool quotas (`general` + stricter `live`) inside `mcp_tool_guard` with `arlogi` `WARNING` logs, OpenTelemetry span attributes, and structured `rate_limit_exceeded` JSON `ToolFailure` errors.
- **Non-Goals**:
  - Altering MCP tool names, JSON response envelopes, or existing Check Point API command behavior.

## Decisions

1. **Pure Core Primitives & Public Facade Hooks**: Move `READONLY_EXACT_COMMANDS`, `is_readonly_command`, `validate_command_name`, and `format_host_attr_for_url` into `arodonata.core.primitives` (keeping identical exports on `arodonata.adapters.checkpoint.*`), expose `build_validated_trust_policy` / `TrustPolicy` via `arodonata.client`, and expose public `resolve_api_version`, `ensure_and_load_snapshot`, and `resolve_implicit_domain_mode` methods so `arodonata.mcp` remains strictly decoupled from `arodonata.adapters`.
2. **Acyclic `mcp/tools/` Package**: Split tool registration into `_common.py`, `_show_object.py`, `objects.py`, `lookup.py`, `topology.py`, `rulebase.py`, `admin.py`, `cpcrud.py`, and `__init__.py` (sharing `RULEBASE_TYPE_TO_COMMAND` from `arodonata.rulebase` and `_fetch_live_collection` for objects/services) while preserving all legacy symbol imports on `arodonata.mcp.tools`.
3. **Unified Security Policy & ASGI Parity**: Centralize validation in `ArodonataMCPSettings.validate_security_policy(standalone=..., has_token_verifier=..., environ=...)`, distinguishing loopback read-only `auth_mode="none"` (permitted ergonomically for local tests/dev) from exposed/mutating `auth_mode="none"` (blocked unless `allow_insecure_unauthenticated=True`) and wildcard DNS rebinding entries (always blocked while `enable_dns_rebinding_protection=True`). In `create_asgi_app(mcp_server=...)`, `_validate_injected_server_compatibility()` raises `ConfigurationError` if baked server fields (`client`, `settings`, `auth_mode`, `allow_write_api`, `cpcrud`, `token_verifier`, `quota_manager`, rate limits) conflict with `mcp_server`.
4. **Synchronous Per-Client Sliding-Window Quota (`MCPToolQuotaManager`)**: Store bounded LRU per-`client_id` `(general, live)` timestamp deques in `OrderedDict`, pruning and checking both buckets synchronously without `await` so asyncio interleaving cannot race and live-bucket rejections never consume general quota.
