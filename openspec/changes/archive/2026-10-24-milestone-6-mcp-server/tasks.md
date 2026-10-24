# Tasks: Milestone 6 — Streamable-HTTP MCP Server & CLI (`milestone-6-mcp-server`)

## 1. MCP Configuration, Security Guards, and Error Handling (`config.py`, `security.py`, `errors.py`)

- [x] 1.1 Implement `src/arodonata/mcp/config.py` (`ArodonataMCPSettings` with `ARODONATA_MCP_*` environment variables, secret masking in `__repr__`, token variable resolution, and standalone startup validation)
- [x] 1.2 Implement `src/arodonata/mcp/security.py` (`StaticTokenVerifier` with constant-time `hmac.compare_digest` mapping matched env var names to `client_id` without logging tokens, `auth_mode="host"` pass-through, and ASGI `MCPOriginHostGuardMiddleware` returning HTTP `421` for unlisted `Host` and HTTP `403` for unlisted `Origin`)
- [x] 1.3 Implement `src/arodonata/mcp/errors.py` (`ToolFailure`, pre-login `domain` validation against the cached `domains` table with a single domain-list refresh on miss, `InvalidCredentialsError` translation to actionable messages listing known domains, `WARNING` logging without arguments or secrets, SID redaction, and `"internal error: <ExceptionClass>"` fallback)

## 2. MCP Tool Surface, Prompts, Server Factory, and Standalone CLI (`tools.py`, `prompts.py`, `server.py`, `cli.py`)

- [x] 2.1 Implement cached object/service/domain/asset list and lookup tools in `src/arodonata/mcp/tools.py` (`show_domains` preserving server-level fields at `details_level="standard"`, `show_hosts`, `show_networks`, `show_address_ranges`, `show_dns_domains`, `show_services`, `show_groups`, `show_gateways_and_servers`, `show_object`, `find_object`, `search_objects`, `get_group_members`) with `from`, `to`, `total`, `source`, and `cache_age_seconds` response envelopes
- [x] 2.2 Implement progressive-disclosure aggregation and cache status tools (`describe_objects`, `query_objects` distinguishing domain-owned vs `Global` objects via `original_domain`, `cache_status` across all `domain_sync_state` scopes and `item_type`s, and `refresh_cache`)
- [x] 2.3 Implement hybrid rulebase tools (`show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase`, `show_policy_packages`, `locate_rules`) evaluating `filter` locally against fresh cached snapshots and cached objects/services in `markdown`, `model_friendly`, or `raw` format and switching to live Management API queries only for live-only flags or `cache_mode="live"`
- [x] 2.4 Implement `change_report`, write-protected `api_call` (`ARODONATA_MCP_ALLOW_WRITE_API=false`, SID redaction), optional live-compatibility tools (`ARODONATA_MCP_LIVE_COMPAT=true`), opt-in CPCRUD tools (`ARODONATA_MCP_CPCRUD=true`: `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`, `cpcrud_inverse`), and prompt templates (`src/arodonata/mcp/prompts.py`)
- [x] 2.5 Implement `src/arodonata/mcp/server.py` (`create_mcp_server`, `create_asgi_app`), `src/arodonata/mcp/cli.py` (`arodonata-mcp` standalone CLI checking TLS trust store and refusing `auth_mode="host"` or `"jwt"` with exit code `2`), and `src/arodonata/mcp/__init__.py`

## 3. Unit & ASGI Integration Tests and Quality Gates

- [x] 3.1 Write comprehensive unit and ASGI tests in `tests/test_mcp_config_and_cli.py`, `tests/test_mcp_security.py`, and `tests/test_mcp_tools.py` covering all specification scenarios
- [x] 3.2 Archive the OpenSpec change, run all quality gates (`pytest`, `ruff`, `mypy`, `markdownlint-cli`, `openspec validate`), and finalize with `/archive-task milestone-6-mcp-server`
