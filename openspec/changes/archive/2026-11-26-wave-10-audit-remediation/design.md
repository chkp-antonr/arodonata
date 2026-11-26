# Design

## Context

See `proposal.md` for motivation and `specs/*/spec.md` for normative behavior contracts across the 10 modified capabilities covering all 43 core findings from `docs/_audit_/2611261737-deep-audit.json`.

## Goals / Non-Goals

**Goals:**

- Close all 7 cross-module attack/failure chains (`CHAIN-01`..`CHAIN-07`) and all 43 core findings (bugs, concurrency races, security gaps, OpenSpec drift, and architectural hotspots) cleanly within existing hexagonal boundaries (`core` depends strictly on `ApiPort`, `LockPort`, and `CachePort`).
- Preserve public SDK exports, `@traced` span names, `arlogi` structured logging hygiene (`<= 700` LOC module discipline where practical), and strict test traceability (`@pytest.mark.spec("SCN-...")`).

**Non-Goals:**

- Changes specific to `feat/arodonata-aibuilder` (`DA-003`, `DA-004`, `DA-023`, `DA-027`, `DA-040`, `DA-046`, `DA-048`, `DA-049`), which live in `add-asset-role-and-platform-classification`.
- Introducing new database tables or wiping warm caches.

## Decisions

### 1. Transport, TLS Pinning, Sessions & MDM (`DA-001`, `DA-007`, `DA-010`, `DA-021`, `DA-022`, `DA-030`, `DA-036`, `DA-050`)

- **Hostname-Bound TLS Pinning (`DA-001`)**:
  - In `TrustPolicy.verify_fingerprint()` (`src/arodonata/adapters/checkpoint/tls.py`), whenever `id_host` is present: (a) record both `(host, port)` and `(id_host, port)` on first-contact TOFU/lab-memory/known-identity persistence; (b) when `(id_host, port)` matches `stored_id_entry` in `tofu`/`lab-memory` mode, bind `(host, port)` as `known-identity`.
  - In `LoginCoordinator` (`src/arodonata/adapters/checkpoint/sessions.py`), retain `tls_identity_host` (original hostname alongside resolved IP) in `SIDCacheEntry` and `_active_dedicated_sids` so `sweep_keepalives()`, `logout_sid()`, `logout_all()`, and non-system cached `api_call()` passes preserve `tls_identity_host`.
- **Failed Discovery Retry Gating (`DA-007`)**: In `DomainService._ensure_server_domains_fresh()` (`src/arodonata/core/services/domain_service.py`), compute `persisted_synced_at = sync_state.synced_at if (sync_state is not None and sync_state.status == "ok") else None` and preserve prior `synced_at` when persisting failed `show-domains` state.
- **Lock Timeout & Cleaner Throttling (`DA-010`, `DA-021`)**:
  - Wrap `self._lock_port.lock(...)` inside `LoginGate.acquire()` (`src/arodonata/adapters/checkpoint/rate_limiter.py`) to translate `LockAcquisitionError` into `AuthenticationError`.
  - In `SessionCleaner.cleanup_server_sessions()` (`src/arodonata/adapters/checkpoint/session_cleaner.py`), resolve target `mds_ip` via `resolve_target_ips(mgmt_name, domain, explicit_server_ip=server_ip)` and acquire `self._rate_limiter.slot(mds_ip)` instead of `endpoint.host`.
- **Secret Masking & Residue Removal (`DA-022`, `DA-030`, `DA-050`)**:
  - Add `@field_serializer` returning `REDACTED_PLACEHOLDER` (when truthy) on `AuthContext.password`, `AuthContext.api_key` (`src/arodonata/core/context.py`), and `ServerEndpointConfig.api_key` (`src/arodonata/core/config.py`).
  - Sync Wave 7 `REQ-SESS-004` (`SCN-SESS-004-1`) into `sessions-and-mdm` (`DA-030`) and remove dead `adopt_dedicated_sid()`, `has_inflight_or_cached_login()`, `_inflight_logins`, and stale docstring from `LoginCoordinator` (`DA-050`).
- **`AMgmtClient.api_call` Decomposition (`DA-036`)**: Extract `_resolve_call_session()`, `_retry_domain_failover()` (shared by connect-phase and HTTP-response failover), `_retry_expired_readonly_session()` (re-running `resolve_target_ips(..., explicit_server_ip=ro_ip)` to update `mds_ip` and hostname IP pinning after `force_new=True`), and `_poll_task_if_needed()` in `src/arodonata/adapters/checkpoint/client.py`.

### 2. Storage Cache, Sync Coordinator & SSE Framing (`DA-006`, `DA-019`, `DA-038`, `DA-041`)

- **`DomainSyncCoordinator.stream_ensure` Hardening & Decomposition (`DA-006`, `DA-038`)**:
  - Never register `mode="cache"` flights in `sync_registry.in_flight` (or reject coalescing non-`"cache"` waiters onto `mode="cache"` flights). Track `verified_remote`, `effective_ttl`, and `invalidation_at_start` on `_InFlightDomainSync`. Only set `my_flight.completed_ok = True` when `_effective_invalidation(dom.mgmt_name, dom.name) == probe.invalidation_at_start`, and in `_record_domain_failure()` iterate `probe.stale_types` rather than all `type_list` so already-fresh sibling slices stay `"ok"`.
  - Decompose `stream_ensure()` (`src/arodonata/core/services/sync_coordinator.py`) into cohesive methods (`_collect_discovery_failures`, `_can_reuse_in_flight`, `_run_locked_domain_sync`, `_record_domain_failure`, `_sync_single_domain`).
- **SQLite Symlink & Mode Hardening (`DA-019`)**: In `DatabaseManager._create_engine()` (`src/arodonata/adapters/storage/database.py`), when `os.path.lexists(db_file)` is `True` on POSIX, inspect via `os.lstat()`: reject `stat.S_ISLNK` and non-regular files, and tighten owner-owned files with group/other permission bits to `0o600` via `os.chmod(db_file, 0o600)`.
- **SSE Wire Header Sanitization (`DA-041`)**: Strip `\r`, `\n`, and `\x00` from `self.id` and `self.event` and apply `redact_sid()` to `self.event` in `SSEEvent.encode()` (`src/arodonata/adapters/sse/__init__.py`).

### 3. Topology, Route Collection & Script Repository (`DA-002`, `DA-011`, `DA-012`, `DA-028`, `DA-039`, `DA-042`)

- **VSX Coalescing Slice Error Isolation (`DA-002`)**: Publish bundle-level `GatewayCliResult` (carrying `outcome.success` and bundle errors, never leader per-VS `vs_context_error`/`vs_not_found_in_bundle`) into `repo_node_flights` before slicing for the leader in `route_executor.py` / `route_collection.py`.
- **Stream Completion Ordering (`DA-011`)**: In full-domain `stream_refresh_topology(..., collect_routes=True)` (`src/arodonata/core/services/topology/refresh.py`), hold the terminal `SyncCompletedEvent` until `await _collect_routes_for_refresh(...)` completes, then yield it last.
- **Scoring, Export & Script Resolution (`DA-012`, `DA-039`, `DA-042`)**:
  - In `_score_interface_group()` (`src/arodonata/core/services/topology/scoring.py`), resolve annotations against `best_entry`'s exact CIDR / span before any fallback rather than breaking on the first wider supernet in `matching_entries`.
  - In `export_topology_prefixes()` (`scoring.py`), match annotation-only gateways across `gateway_uid`, `gateway_name`, and composite IDs (`{mgmt}:{domain}:{uid|name}`).
  - In `route_scripts.py`, replace `awk` `$2 == target` checks with `sub(/^Name:[ \t]*/, ""); sub(/[ \t\r]+$/, ""); if ($0 == target)` so space-containing VS names resolve cleanly.
- **Bare-SID Scrubbing (`DA-028`)**: Extract a shared session-exception scrubbing and `RepositoryScriptPermissionError` mapping helper in `src/arodonata/core/services/script_service.py` covering both active- and isolated-`WriteSession` branches in `ensure_repository_script` and `delete_repository_script`, and pass `known_sids` (cached + active `WriteSession` SID) to `redact_sid()` in `topology/refresh.py` and `topology/policy_rules.py`.

### 4. Rulebase, CPCRUD & Change Reports (`DA-005`, `DA-008`, `DA-014`, `DA-018`, `DA-020`, `DA-025`, `DA-026`, `DA-029`, `DA-033`, `DA-044`, `DA-047`, `DA-051`)

- **Rulebase Collection, Paging & Numbering (`DA-005`, `DA-029`, `DA-033`, `DA-047`)**:
  - In `rulebase/collector.py`, never fall back to unpaginated `api_call` on `paging_inconsistent` or empty `objects=[]`; restrict `api_call` fallback strictly to command-unsupported responses and restrict `strict=False` degradation to explicit RBAC denials.
  - In `rulebase/pager.py`, enforce `max_pages` and consecutive-zero-new-rule limits, track new UIDs separately from raw counts, detect mid-fetch `data['total']` discontinuities, and share `_synthetic_rule_uid()` across rule parsers and `final_sections`.
  - In `rulebase/numbering.py`, persist resolved `target_dom_layer_uid` onto `NumberedRule.placeholder_domain_layer_uid`, handle `placeholder_domain_layer_uid` in `_record_layer_prefixes_from_rules()`, resolve missing `child_layer_name` from `snapshot.layers`, and pass `seen_layer_uids=seen_package_layer_uids` at line 619.
- **CPCRUD Safety, Rollback & Consolidation (`DA-008`, `DA-014`, `DA-020`, `DA-044`, `DA-051`)**:
  - Fail closed in `Executor.stream_publish_staged_session()` when `allow_stale=False` and no verified baseline stamp exists, and accept/forward explicit baseline stamp fields from `mcp/tools/cpcrud.py`'s `stored_staged` (`DA-008`). Dispatch `self._check_domain_head` consistently inside `_check_current_domain_head()` (`DA-044`).
  - Consolidate `_plan_existing_object_diff` / `_plan_existing_service_diff` and `_apply_*_update_to_model` `groups` updates in `_planner_diff.py`, and extract a shared `check_where_used` helper invoked across `plan_object_step`, `plan_service_step`, and `plan_group_step` (plus add `check_where_used` to `GroupOperation` in `checkpoint_ops_schema.json`) inspecting `used-directly` / `used-indirectly` against active non-deleted references (`DA-014`, `DA-051`).
  - In `inverse.py`, inspect `action.diffs` on `Outcome.UPDATE` and emit `op['groups'] = []` / `op['tags'] = []` when mutated from empty/absent `prior_state` (`DA-020`).
- **Change Reports (`DA-018`, `DA-025`, `DA-026`)**:
  - Fail closed with `ReportWarning` and `[]` in `_filter_range_sessions` when a requested `from_session`/`to_session` lacks a parseable timestamp (`DA-025`).
  - Pass `owned if eff_sid is not None else None` to `_resolve_session_bare_uids` and `apply_session_rule_placement`, and pass `redacted_names` to `_replace_resolved_uids_in_session` (`DA-026`).
  - Escape `[` and `]` inside `**...**` and `*...*` branches in `render_safe_inline_markdown_md()` (`DA-018`).

### 5. MCP Server & API Reference (`DA-009`, `DA-013`, `DA-015`, `DA-016`, `DA-017`, `DA-024`, `DA-031`, `DA-032`, `DA-037`, `DA-043`)

- **Quota Ordering & Cache-Mode Semantics (`DA-009`, `DA-032`)**: Enforce `consume_live_quota_if_needed(cost=...)` for explicit fan-out requests in `cache_control` and `change_report` BEFORE live domain pre-validation, deduplicate per-server domain-list probes per call (`DA-009`), return `False` from `_is_refresh_action()` when `mode == "cache"`, pass `cache_mode="cache"` for `scope="domains"` when `mode == "cache"`, and align `REQ-MCP-013` to `mode="cache"` (`DA-032`).
- **Unified Multi-MDS Scoping & Stalest Cache Age (`DA-013`, `DA-016`, `DA-037`)**: Extract `resolve_and_validate_scope()` in `mcp/tools/_common.py` preserving `eff_mgmt = None` when omitted (`search_objects`, `query_objects`, `locate_gateways`, `cache_control`); switch `_compute_cache_age()` to `min(synced_times)` with explicit `domains` and `item_types` filtering, pass `eff_mgmt` in `locate_gateways`, cover `("objects", "services", "assets")` in `describe` age calculation, and derive age from matched entity scopes in `lookup.py` (`DA-016`).
- **Guardrails, Staged SIDs, `show_object` & `show_rulebase` (`DA-015`, `DA-017`, `DA-024`, `DA-043`)**: Wrap metadata lookups in `mcp_tool_guard` defensively and skip `get_known_domain_names` on non-domain errors (`DA-015`); register `stored_staged.sid` before staged publish/discard and make `_store_plan_entry` evict same-owner entries first (`DA-024`); set `payload["uid"]` whenever `is_uuid(query_str)` and normalize `obj_type` via `normalize_any_type()` before `validate_command_name()` (`DA-017`); clamp `offset >= 0` and `1 <= limit <= 500` in cached `show_rulebase` (`DA-043`).
- **Gaia/CME API Reference (`DA-031`)**: Skip management version field filtering in `_describe_single` / `_collect_resolved_objects` whenever `cmd.get("api_family") != "management"`.

### 6. Testing Replay Mock & Emulator (`DA-034`, `DA-035`, `DA-045`)

- Snapshot/restore section index and original section dict on failed `set-*-section`, pre-validate `members`/`groups` (or snapshot affected buckets) before mutating sibling objects in `_apply_entity_fields` (`DA-034`), rotate aliased active `SidBinding`s in `handle_switch_session`, reject read-only `handle_disconnect` on other sessions (`DA-035`), and call `self._get_clean_domain_baseline(dom_name)` inside `_mark_domain_mutated` before marking `_dirty_domains` (`DA-045`).

## Risks / Trade-offs

- **[Risk]** `allow_stale=False` failing closed without a verified baseline stamp breaks callers/tests adopting post-restart sessions without a stamp → **Mitigation**: Forward `stored_staged` baseline fields from `mcp/tools/cpcrud.py` and update post-restart adoption tests/docs to pass explicit baseline stamps or `allow_stale=True`.
- **[Risk]** `AuthContext.model_dump()` and `ServerEndpointConfig.model_dump()` masking secrets could affect callers expecting raw secrets → **Mitigation**: Direct Python attribute access (`auth.password`, `endpoint.api_key`) remains unchanged while serialization paths safely match `ArodonataSettings` (`INV-2`).
- **[Risk]** Restricting `strict=False` fallback in `collect_domain_rulebase_snapshot()` to explicit RBAC denials could surface transient errors instead of empty rulebases → **Mitigation**: Raising lets `DomainSyncCoordinator` preserve warm cached rulebases and record `status="failed"` rather than overwriting caches with empty snapshots.

## Migration Plan

1. Implement fixes by dependency group (`tasks.md` Sections 1–7) with unit/spec `@pytest.mark.spec("SCN-...")` tests per group.
2. Run full quality gates (`ruff`, `markdownlint-cli`, `mypy`, `pytest`, `openspec validate --specs --strict`, `check_spec_traceability.py`) before archiving Wave 10 and opening a PR to `master_v2`.
