# Tasks

## 1. Sync Invalidation Race & Rulebase Slice TTL

- [x] 1.1 Capture `(probe_started_at, inv_ts_before, inv_seq_before)` prior to `show-last-published-session` in `DomainSyncCoordinator.probe_domain_staleness`, expose `probe_started_at`/`invalidation_seq_at_start` on `DomainProbeResult` and `target_seq` on `_record_slice_synced`, and preserve in-flight domain/wildcard invalidations across `probe_domain_staleness` and `stream_ensure` (`src/arodonata/core/services/sync_coordinator.py`, `REQ-CACHE-015`); verify with `@pytest.mark.spec("SCN-CACHE-015-1")` tests in `tests/unit/test_sync_coordinator.py` covering both advancing and frozen clocks (`uv run pytest tests/unit/test_sync_coordinator.py`).
- [x] 1.2 Update `RulebaseRefreshService.refresh_package_rulebase` (`src/arodonata/rulebase/refresh.py`) to look up `DomainSyncState` for `("rulebase", f"package:{rulebase_type}:{pkg_uid}")` and pass `scope`, `item_type`, and `synced_at` to `is_domain_invalidated(...)` instead of calling unscoped `is_domain_invalidated(mgmt_name, clean_dom)` (`REQ-RULE-003`); verify with `@pytest.mark.spec("SCN-RULE-003-3")` tests in `tests/unit/test_rulebase_refresh.py` (`uv run pytest tests/unit/test_rulebase_refresh.py`).

## 2. MCP Cache-Only Domain Pre-Validation

- [x] 2.1 Add `allow_refresh: bool = True` to `validate_domain_or_fail` (`src/arodonata/mcp/errors.py`) and `cache_mode: CacheMode = "smart"` to `_validate_optional_domains` (`src/arodonata/mcp/tools/_common.py`), normalize `cache_mode` prior to domain pre-validation in `objects.py`, `topology.py`, `admin.py`, `lookup.py`, and `rulebase.py`, and ensure `cache_mode="cache"` checks cached `arodonata_domains` rows only with zero `get_domains(cache_mode="force")` calls and zero `live` quota charges (`REQ-MCP-013`); verify with `@pytest.mark.spec("SCN-MCP-013-1")` tests in `tests/unit/test_mcp_tools.py` (`uv run pytest tests/unit/test_mcp_tools.py tests/unit/test_mcp_security.py`).

## 3. Fail-Closed DNS Pinning, Startup Cleanup, and Docstring Alignment

- [x] 3.1 Remove the unpinned `elif canonical_ip in trusted_ips: pinned_target = cleaned_ip` fallback in `validate_explicit_server_ip` (`src/arodonata/adapters/checkpoint/target_resolver.py`) and update its docstring so unresolvable non-IP explicit hostnames fail closed with `ValidationError` before connecting (`REQ-SESS-010`); verify with `@pytest.mark.spec("SCN-SESS-010-1")` tests in `tests/spec/test_spec_sessions_and_mdm.py` (`uv run pytest tests/spec/test_spec_sessions_and_mdm.py`).
- [x] 3.2 Remove `seed_system_sid` and the early `return True` cached-RO-SID shortcut from `SessionCleaner.cleanup_server_sessions`, `schedule_startup_cleanup`, and `run_startup_cleanup` (`src/arodonata/adapters/checkpoint/session_cleaner.py`) so startup cleanup always inspects `show-sessions`, discards abandoned Arodonata-owned sessions, preserves cached RO SIDs, and logs out its temporary RW session (`REQ-SESS-011`); update affected assertions in `tests/unit/test_wave3_compat_and_fixes.py` and `tests/unit/test_sessions.py`, and verify with `@pytest.mark.spec("SCN-SESS-011-1")` tests (`uv run pytest tests/unit/test_sessions.py tests/unit/test_wave3_compat_and_fixes.py`).
- [x] 3.3 Update `LoginCoordinator.is_sid_entry_fresh` docstring (`src/arodonata/adapters/checkpoint/sessions.py`) to match the `expires_at` / sliding `last_used_at` freshness behavior in `session_credentials.py` (`uv run ruff check src/arodonata/adapters/checkpoint/sessions.py` and `uv run pytest tests/unit/test_sessions.py`).

## 4. Replay Mock Command-Validation Parity

- [x] 4.1 Replace permissive `command.strip().lstrip("/")` normalization in `FileReplayApiMock.api_call` and `FileReplayApiMock.api_query` (`src/arodonata/testing/replay_mock.py`) with `validate_command_name(command)` (`REQ-ITEST-007`); verify with `@pytest.mark.spec("SCN-ITEST-007-3")` tests in `tests/spec/test_spec_integration_harness_and_emulator.py` (`uv run pytest tests/spec/test_spec_integration_harness_and_emulator.py tests/unit/test_transport.py`).

## 5. Full Repository Quality Gates

- [x] 5.1 Run full quality gates across `/Users/antonr/Code/2026/arodonata_v2_wave7`: `openspec schema validate arodonata`, `openspec validate --specs --strict --no-interactive`, `openspec validate wave-7-review-remediation --strict --no-interactive`, `uv run python scripts/check_spec_traceability.py`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest tests/unit/test_architecture_boundaries.py`, full `uv run pytest`, and `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv` cleanly with zero failures.
