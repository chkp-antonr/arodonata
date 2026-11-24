# Proposal

## Why

A follow-up external `/claude-review` audit (`docs/_audit_/2611241139.md`) of the Wave 7 working tree (`fix/wave-7-security-and-cache-integrity`) identified two important defects, two minor accuracy/documentation gaps, and an unverified TLS hostname-pinning edge case: slice sync handlers still stamp `DomainSyncState.synced_at` with completion time instead of `probe_started_at` (allowing mid-handler invalidations to be masked until `cache_ttl` expires), `cache_control(action="refresh")` on `> 30`-domain MDS deployments deadlocks permanently against the default `30/min` live quota (while rejected multi-unit fan-out calls leak pre-charged quota slots and emit misleading retry hints), multi-scope `query_objects` reports the first scope's `cache_age_seconds` rather than the stalest scope's age, `DomainSyncCoordinator.invalidated_domains` lacks lifetime documentation, and pinning an explicit hostname to a canonical IP literal must still enforce any pinned or TOFU certificate fingerprint recorded under that hostname.

## What Changes

- Stamp `DomainSyncState.synced_at` with the pre-probe start epoch (`probe.probe_started_at`) across all `DomainSyncHandler` implementations (`object_service`, `service_cache`, `asset_service`, `rulebase/refresh`, `topology/extractor`, and live `topology/route_collection`), expose `invalidation_at_start` on `DomainProbeResult`, and guard `DomainSyncCoordinator.stream_ensure` so `_record_slice_synced` only advances sequence watermarks when no invalidation arrived between probe start and handler completion, plus document lifetime semantics on `DomainSyncCoordinator.invalidated_domains`.
- Cap implicit all-domains `cache_control(action="refresh")` (`domains=None` and `domain=None`) live-quota fan-out cost at `live_tool_rate_limit_per_minute` when the caller's live bucket is empty (allowing one full-MDS refresh per window at `default=30`), while rejecting explicit `cost > live_tool_rate_limit_per_minute` (`cache_control(domains=...)` or `change_report(scopes=...)`) upfront with full rollback of `mcp_tool_guard`'s pre-charged general/live slots and actionable batching guidance instead of a misleading `retry_after_seconds` loop.
- Compute `cache_age_seconds` in multi-scope `query_objects` (and multi-scope `search_objects` spanning `objects` and `assets`) as `max(...)` across all touched scopes with non-null ages so the envelope reflects the stalest contributing dataset.
- Preserve hostname-bound `TrustPolicy` pinned and TOFU fingerprint verification (`tls_identity_host`) when `validate_explicit_server_ip` resolves an explicit hostname to a pinned canonical IP literal, preventing TOFU first-contact bypass or cross-host pin substitution on the resolved IP.

## Capabilities

### New Capabilities

- None (`wave-7-review-remediation-2` updates existing capabilities only).

### Modified Capabilities

- `cache-and-sync`: Add `REQ-CACHE-016` requiring slice sync handlers and `stream_ensure` to stamp `DomainSyncState.synced_at` from `probe_started_at` and preserve invalidations arriving anywhere during probe, lock acquisition, or handler execution.
- `mcp-server`: Add `REQ-MCP-014` and `REQ-MCP-015` defining empty-bucket capping for implicit all-domains `cache_control(action="refresh")`, upfront batching rejection with pre-charged slot rollback when explicit fan-out exceeds `live_tool_rate_limit_per_minute`, and stalest-scope (`max`) `cache_age_seconds` reporting on multi-scope queries.
- `sessions-and-mdm`: Add `REQ-SESS-012` requiring `AMgmtClient` / `ApiTransport` / `TrustPolicy` to enforce hostname-keyed pinned and TOFU certificate fingerprints alongside IP-keyed entries whenever an explicit hostname is resolved and pinned to a canonical IP literal.

## Impact

- **Source Modules**:
  - `src/arodonata/core/services/sync_coordinator.py`
  - `src/arodonata/core/services/object_service.py`
  - `src/arodonata/core/services/service_cache.py`
  - `src/arodonata/core/services/asset_service.py`
  - `src/arodonata/rulebase/refresh.py`
  - `src/arodonata/core/services/topology/extractor.py`, `src/arodonata/core/services/topology/refresh.py`, `src/arodonata/core/services/topology/route_collection.py`
  - `src/arodonata/mcp/quota.py`, `src/arodonata/mcp/errors.py`, `src/arodonata/mcp/tools/admin.py`, `src/arodonata/mcp/tools/objects.py`
  - `src/arodonata/adapters/checkpoint/tls.py`, `src/arodonata/adapters/checkpoint/connector.py`, `src/arodonata/adapters/checkpoint/transport.py`, `src/arodonata/adapters/checkpoint/sessions.py`, `src/arodonata/adapters/checkpoint/client.py`
- **Tests**:
  - `tests/unit/test_sync_coordinator.py`
  - `tests/unit/test_mcp_security.py`, `tests/unit/test_mcp_tools.py`
  - `tests/spec/test_spec_sessions_and_mdm.py`
