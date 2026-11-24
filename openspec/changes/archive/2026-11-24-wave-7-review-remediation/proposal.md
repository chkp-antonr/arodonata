# Proposal

## Why

An external `/claude-review` audit (`docs/_audit_/2611240658.md`) of Wave 7 (`fix/wave-7-security-and-cache-integrity`) confirmed seven remaining defects across sync invalidation concurrency, rulebase slice TTL preservation, MCP cache-mode domain validation, unresolvable explicit hostname pinning, startup session cleanup short-circuiting, replay-mock command validation parity, and docstring alignment. Addressing these findings before merging Wave 7 prevents silent stale cache reads, unintended live API/quota calls during cache-only MCP operations, unpinned DNS fallbacks, skipped startup cleanup, and emulator-vs-client validation drift.

## What Changes

- Preserve in-flight domain and wildcard invalidations during smart staleness probes and sync handlers so concurrent publishes are never masked by an earlier probe completion timestamp or sequence counter.
- Update single-package rulebase refresh invalidation checks to evaluate `(scope="rulebase", item_type, synced_at)` instead of calling unscoped `is_domain_invalidated(...)`, restoring `cache_ttl` honoring after refresh under persistent invalidation maps.
- Thread caller `cache_mode` into MCP domain pre-validation (`_validate_optional_domains` and `validate_domain_or_fail`) so `cache_mode="cache"` validates solely against cached domains without forcing `get_domains(cache_mode="force")` or charging live quota.
- Reject unresolvable explicit hostnames fail-closed with `ValidationError` in `validate_explicit_server_ip` when DNS yields zero answers, eliminating fallback to raw unresolved hostnames.
- Remove the `seed_system_sid` parameter (**internal signature cleanup**) and the cached System Data RO SID early-return bypass in `SessionCleaner.cleanup_server_sessions` so startup cleanup always inspects `show-sessions` and discards abandoned Arodonata-owned sessions.
- Enforce strict `validate_command_name()` validation parity inside `FileReplayApiMock.api_call` and `FileReplayApiMock.api_query` instead of `command.strip().lstrip("/")`.
- Align the `LoginCoordinator.is_sid_entry_fresh` docstring with the sliding `expires_at` / `last_used_at` freshness semantics implemented in `session_credentials.py`.

## Capabilities

### New Capabilities

- None (`wave-7-review-remediation` updates existing capabilities only).

### Modified Capabilities

- `cache-and-sync`: Add `REQ-CACHE-015` requiring in-flight staleness probes and slice syncs to preserve concurrent domain/wildcard invalidations arriving after probe start.
- `rulebase-and-numbering`: Modify `REQ-RULE-003` so single-package rulebase refresh evaluates slice-scoped invalidation (`scope="rulebase"`, `item_type`, `synced_at`) and honors `cache_ttl` once synchronized.
- `mcp-server`: Add `REQ-MCP-013` requiring `cache_mode="cache"` domain pre-validation across single- and multi-server configurations to inspect cached domains only without live `get_domains` refreshes or live quota charges.
- `sessions-and-mdm`: Add `REQ-SESS-010` (fail-closed `ValidationError` on unresolvable explicit hostnames without deferring DNS resolution to transport) and `REQ-SESS-011` (unconditional startup stale-session inspection despite cached read-only System Data SIDs).
- `integration-testing-and-examples`: Modify `REQ-ITEST-007` so `FileReplayApiMock` enforces strict `validate_command_name()` parity with `AMgmtClient`.

## Impact

- **Source Modules**:
  - `src/arodonata/core/services/sync_coordinator.py`
  - `src/arodonata/rulebase/refresh.py`
  - `src/arodonata/mcp/errors.py`, `src/arodonata/mcp/tools/_common.py`, `src/arodonata/mcp/tools/objects.py`, `src/arodonata/mcp/tools/topology.py`, `src/arodonata/mcp/tools/admin.py`, `src/arodonata/mcp/tools/lookup.py`, `src/arodonata/mcp/tools/rulebase.py`
  - `src/arodonata/adapters/checkpoint/target_resolver.py`
  - `src/arodonata/adapters/checkpoint/session_cleaner.py`
  - `src/arodonata/adapters/checkpoint/sessions.py`
  - `src/arodonata/testing/replay_mock.py`
- **Tests**:
  - `tests/unit/test_sync_coordinator.py`
  - `tests/unit/test_rulebase_refresh.py`
  - `tests/unit/test_mcp_tools.py`
  - `tests/spec/test_spec_sessions_and_mdm.py`, `tests/unit/test_sessions.py`, `tests/unit/test_wave3_compat_and_fixes.py`
  - `tests/spec/test_spec_integration_harness_and_emulator.py`
