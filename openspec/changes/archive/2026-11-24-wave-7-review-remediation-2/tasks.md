# Tasks

## 1. Slice Sync Start-Epoch Timestamping & Mid-Handler Invalidation Preservation

- [x] 1.1 Expose `invalidation_at_start: tuple[datetime | None, int]` alongside `probe_started_at`/`invalidation_seq_at_start` across all `DomainSyncCoordinator.probe_domain_staleness` return paths, guard `stream_ensure`'s `_record_slice_synced` call on `self._effective_invalidation(dom.mgmt_name, dom.name) == probe.invalidation_at_start`, and clarify lifetime watermark semantics in `DomainSyncCoordinator.invalidated_domains`'s docstring (`src/arodonata/core/services/sync_coordinator.py`, `REQ-CACHE-016`); verify with `uv run ruff check src/arodonata/core/services/sync_coordinator.py` and `uv run mypy src/arodonata/core/services/sync_coordinator.py`.
- [x] 1.2 Stamp `DomainSyncState.synced_at` using `probe.probe_started_at or now` across all slice sync handlers (`src/arodonata/core/services/object_service.py`, `src/arodonata/core/services/service_cache.py`, `src/arodonata/core/services/asset_service.py`, `src/arodonata/rulebase/refresh.py`, `src/arodonata/core/services/topology/extractor.py`) and guard live-route `_record_slice_synced` in `src/arodonata/core/services/topology/refresh.py` (`REQ-CACHE-016`); add `@pytest.mark.spec("SCN-CACHE-016-1")` tests in `tests/unit/test_sync_coordinator.py` covering mid-handler invalidations under advancing and frozen clocks (`uv run pytest tests/unit/test_sync_coordinator.py tests/unit/test_rulebase_refresh.py tests/unit/test_topology_service.py`).

## 2. MCP Fan-Out Quota Capping, Slot Rollback, and Multi-Scope Cache Age

- [x] 2.1 Add `rollback_consumed` to `MCPToolQuotaManager` (`src/arodonata/mcp/quota.py`), extend `_ActiveQuotaState` and `consume_live_quota_if_needed(..., cap_at_limit_if_empty=...)` (`src/arodonata/mcp/errors.py`), and pass `cap_at_limit_if_empty=(domain is None and domains is None)` in `cache_control(action="refresh")` (`src/arodonata/mcp/tools/admin.py`) so implicit all-domain refreshes cap at `live_tool_rate_limit_per_minute` on an empty live bucket while oversize explicit `domains`/`scopes` calls fail upfront with zero leaked general/live slots and batching guidance (`REQ-MCP-014`); verify with `@pytest.mark.spec("SCN-MCP-014-1", "SCN-MCP-014-2")` tests in `tests/unit/test_mcp_security.py` (`uv run pytest tests/unit/test_mcp_security.py`).
- [x] 2.2 Aggregate `cache_age_seconds` via `max(...)` across all touched scopes with non-null ages in `query_objects` and multi-scope `search_objects` (`src/arodonata/mcp/tools/objects.py`, `REQ-MCP-015`); verify with `@pytest.mark.spec("SCN-MCP-015-1")` tests in `tests/unit/test_mcp_tools.py` (`uv run pytest tests/unit/test_mcp_tools.py`).

## 3. Hostname-Bound TLS Fingerprint Verification Across Canonical IP Pinning

- [x] 3.1 Add `identity_host: str | None = None` enforcement to `TrustPolicy.verify_der` and `TrustPolicy.verify_fingerprint` (`src/arodonata/adapters/checkpoint/tls.py`) and thread `tls_identity_host` through `ApiTransport.execute`, `FingerprintTCPConnector`, `LoginCoordinator`, and `AMgmtClient` (`src/arodonata/adapters/checkpoint/connector.py`, `src/arodonata/adapters/checkpoint/transport.py`, `src/arodonata/adapters/checkpoint/sessions.py`, `src/arodonata/adapters/checkpoint/client.py`) whenever a non-IP hostname is resolved to a pinned IP literal (`REQ-SESS-012`); verify with `@pytest.mark.spec("SCN-SESS-012-1")` tests in `tests/spec/test_spec_sessions_and_mdm.py` covering both `"pinned"` and `"tofu"` modes (`uv run pytest tests/spec/test_spec_sessions_and_mdm.py tests/unit/test_transport.py`).

## 4. Full Repository Quality Gates

- [x] 4.1 Run full quality gates across `/Users/antonr/Code/2026/arodonata_v2_wave7`: `openspec schema validate arodonata`, `openspec validate --specs --strict --no-interactive`, `openspec validate wave-7-review-remediation-2 --strict --no-interactive`, `uv run python scripts/check_spec_traceability.py`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest tests/unit/test_architecture_boundaries.py`, full `uv run pytest`, and `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv` cleanly with zero failures.

## Workflow follow-up

- Review or run `/claude-review` after implementation if desired, then archive stacked Wave 7 changes via `/openspec-archive-change` once verified.
