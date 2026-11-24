# Design

## Context

See [proposal.md](proposal.md) for the `/claude-review` findings (`docs/_audit_/2611241139.md`) and scope boundaries (`specs/`). All core invariants from `AGENTS.md` and `openspec/config.yaml` hold unchanged: strict `ApiPort` / `CachePort` boundaries, zero SID leakage across logs/spans/errors/outputs, naive UTC database timestamps, provider-agnostic OpenTelemetry tracing, and non-overlapping OpenSpec delta stacking alongside `wave-7-security-and-cache-integrity` and `wave-7-review-remediation`.

## Goals / Non-Goals

**Goals:**

- Guarantee causal `DomainSyncState.synced_at` ordering across all slice sync handlers so mid-flight invalidations (`probe`, lock wait, or `handler`) survive completion under advancing and frozen clocks (`REQ-CACHE-016`).
- Allow one implicit full-MDS `cache_control(action="refresh")` per idle 60-second window when cached domain count exceeds `live_tool_rate_limit_per_minute`, while rejecting oversize explicit fan-out requests upfront with zero leaked quota slots and clear batching guidance (`REQ-MCP-014`).
- Report the stalest (`max`) `cache_age_seconds` across touched scopes in multi-scope `query_objects` and `search_objects` (`REQ-MCP-015`).
- Enforce hostname-keyed `TrustPolicy` pins and TOFU records when an explicit hostname is resolved and dialed by its pinned canonical IP literal (`REQ-SESS-012`).

**Non-Goals:**

- Changing `show_object` cache-only behavior when multi-domain MDS queries omit `domain` (`SCN-MCP-002-2` / `DA-044` — verified intentional, since `show-object` on `System Data` cannot resolve tenant domain objects).
- Relaxing `validate_command_name()` rejection of leading slashes, whitespace, or uppercase characters (`REQ-TRANS-001` / `REQ-ITEST-007` — verified intentional spec invariant).
- Modifying default `ARODONATA_MCP_LIVE_TOOL_RATE_LIMIT_PER_MINUTE=30` or Wave 8/9 scope.

## Decisions

1. **Pre-Probe Start Epoch Across All Slice Sync Handlers (`REQ-CACHE-016`)**
   - *Choice*: Add `invalidation_at_start: tuple[datetime | None, int] = (None, 0)` to `DomainProbeResult` (populated alongside `probe_started_at` and `invalidation_seq_at_start` in `probe_domain_staleness` across `"smart"`, `"smart-fast"`, and `"force"` paths). Update every `DomainSyncHandler` (`ObjectService._incremental_sync_types` & `_full_reload_types`, `ServiceCacheService._incremental_sync_types` & `_full_reload_types`, `AssetRefreshService._sync_domain_assets`, `RulebaseRefreshService._sync_domain_rulebase` / `_sync_domain_packages` / `_sync_single_package`, and `_sync_domain_topology` in `topology/extractor.py`) to set `synced_at = probe.probe_started_at or now`. In `DomainSyncCoordinator.stream_ensure`, replace post-lock `handler_start_seq` with a post-handler check `self._effective_invalidation(dom.mgmt_name, dom.name) == probe.invalidation_at_start`, calling `_record_slice_synced(..., target_seq=probe.invalidation_seq_at_start)` only when no invalidation arrived between probe start and handler completion. Apply the same pre-execution `(inv_ts_before, inv_seq_before)` guard around `collect_routes_fn` in `_collect_routes_for_refresh` (`topology/refresh.py`), and clarify lifetime watermark semantics in `DomainSyncCoordinator.invalidated_domains`'s docstring.
   - *Alternative Rejected*: Stamping `synced_at = self._now()` at handler completion and comparing `seq` only on timestamp equality — any invalidation at `T_inv` between `T_probe` and `T_complete` yields `synced_at > inv_ts`, causing `is_slice_invalidated` to return `False` and serve stale data for the remainder of `cache_ttl`.

2. **Empty-Bucket Implicit Fan-Out Cap & Transactional Slot Rollback (`REQ-MCP-014`)**
   - *Choice*: Add `rollback_consumed(client_id, *, general: int, live: int)` on `MCPToolQuotaManager` (`mcp/quota.py`) and track invocation-consumed general/live slot counts on `_ActiveQuotaState` (`mcp/errors.py`). Extend `consume_live_quota_if_needed(*, cost: int = 1, cap_at_limit_if_empty: bool = False)`:
     - In `cache_control(action="refresh")` (`mcp/tools/admin.py`), pass `cap_at_limit_if_empty=(domain is None and domains is None)`. When `live_limit > 0` and `cap_at_limit_if_empty=True` with `cost >= live_limit`, clamp target invocation live cost to `live_limit` — succeeding iff the caller's `live` bucket was empty prior to `mcp_tool_guard` (`len(live_dq) == state.live_units_consumed`) and filling all `live_limit` slots so a second live call within the window is throttled.
     - When `cap_at_limit_if_empty=False` and `cost > live_limit` (`cache_control(domains=...)` or `change_report(scopes=...)`), roll back `mcp_tool_guard`'s pre-charged `general` and `live` slots immediately and raise `ToolFailure(error_code="rate_limit_exceeded")` with `retry_after_seconds=0.0`, `exceeds_per_minute_limit=True`, and explicit guidance to batch `<= live_limit` items.
     - Whenever `check_and_consume_live_only` rejects a multi-unit `delta` (`cost <= live_limit`, insufficient remaining window capacity), also roll back `mcp_tool_guard`'s pre-charged `general` and `live` slots before raising `rate_limit_exceeded` so rejected calls consume zero slots.
   - *Alternative Rejected*: Capping explicit `domains=[...]` fan-out at `live_limit` — breaks `SCN-MCP-012-2` proportional fan-out enforcement (`3` explicit domains must be denied when `live_limit=2`); leaving `domains=None` uncapped — makes full-MDS refresh permanently impossible on `> 30`-domain MDS deployments under default settings.

3. **Maximum (`max`) Multi-Scope `cache_age_seconds` (`REQ-MCP-015`)**
   - *Choice*: In `query_objects` (`mcp/tools/objects.py`), evaluate `_compute_cache_age(...)` across all `(q_scope, q_types)` entries in `target_scopes` (instead of `break`ing on the first non-`None` age) and set `age = max(non_null_ages)` when non-empty (`None` otherwise). Apply the same `max(...)` aggregation in `search_objects` when both `want_search_objects` and `want_search_assets` are `True`.
   - *Alternative Rejected*: Breaking on the first scope or overwriting in loop order — understates staleness by reporting a `120s` service/asset sync age when combined with `7200s`-old objects.

4. **Hostname-Bound TLS Identity Preservation Across Canonical IP Pinning (`REQ-SESS-012`)**
   - *Choice*: Extend `TrustPolicy.verify_der` and `TrustPolicy.verify_fingerprint` (`adapters/checkpoint/tls.py`) with optional `identity_host: str | None = None`. When `identity_host` is a non-IP hostname distinct from `host` (`pinned_ip`), check explicit pins in `self._pinned` and stored entries in `self._store` for **both** `format_host_port(host, port)` and `format_host_port(identity_host, port)` before consulting `_is_fingerprint_trusted_elsewhere` or TOFU first-contact: if either key has an explicit pin or stored fingerprint that differs from `presented`, raise `CertificateMismatchError` immediately. Thread `tls_identity_host` through `ApiTransport.execute` (`_TransportPoolContext` for `FingerprintTCPConnector`, custom-sender path, and pooled-socket reuse re-verification) from `AMgmtClient` / `LoginCoordinator` (`api_call`, `_perform_login`, `keepalive_sid`, `logout_sid`) whenever the caller supplied a non-IP `server_ip` (or `endpoint.host`) that resolved to a pinned IP literal, keeping the 3-tuple return signature of `resolve_target_ips` / `validate_explicit_server_ip` unchanged.
   - *Alternative Rejected*: Passing the raw hostname back to `ApiTransport` — reintroduces connect-time DNS rebinding TOCTOU (`DA-001` / `REQ-SESS-008`).

## Risks / Trade-offs

- `[Using probe_started_at for synced_at slightly increases reported cache_age_seconds right after a slow full sync]` -> `probe_started_at` is the true causal snapshot point (`show-last-published-session` head time); aging from `probe_started_at` is strictly safer for `cache_ttl` expiry than aging from completion time.
- `[Implicit all-domains cache_control refresh on >30-domain MDS consumes the caller's entire 30-slot live window]` -> Intentional burst trade-off (`REQ-MCP-014`): unblocks single-call full-MDS refresh while preventing back-to-back multi-MDS refresh floods; warm cached reads continue using `general` quota unaffected.
- `[Enforcing both identity_host:port and pinned_ip:port pins rejects configurations where hostname and IP were manually pinned to conflicting fingerprints]` -> Conflicting pins for the same resolved endpoint indicate misconfiguration or active MITM; failing closed with `CertificateMismatchError` is desired.
