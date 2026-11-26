# Proposal

## Why

The Deep Audit (`docs/_audit_/2611261737-deep-audit.md`, `docs/_audit_/2611261737-deep-audit.json`) identified 51 confirmed defects across the repository, of which 43 affect the core library and main specifications inherited from `master_v2` (while the 8 `feat/arodonata-aibuilder` branch-specific findings are tracked in `add-asset-role-and-platform-classification`). Remediating all 43 core bugs, security gaps, specification drifts, and architectural hotspots in one coordinated wave closes 7 cross-module failure chains before new AI Builder integrations ship on top of `master_v2`.

## What Changes

1. **Transport, TLS Pinning, Sessions & MDM (`DA-001`, `DA-007`, `DA-010`, `DA-021`, `DA-022`, `DA-030`, `DA-036`, `DA-050`)**:
   - Preserve `tls_identity_host` across cached/dedicated session lifecycles (`SIDCacheEntry`, `_active_dedicated_sids`, `keepalive`/`logout` sweeps) and bind both `(host, port)` and `(id_host, port)` on first-contact TOFU/known-identity verification (`DA-001`).
   - Gate `DomainService` `domain_list_ttl` freshness on `sync_state.status == "ok"` so transient `show-domains` failures do not suppress `smart` retries for 1 hour (`DA-007`).
   - Translate `LockAcquisitionError` inside `LoginGate.acquire()` to `AuthenticationError` (`DA-010`), bill `SessionCleaner` rate-limiter slots against the target domain's active `mds_ip` (`DA-021`), mask `password`/`api_key` in `AuthContext`/`ServerEndpointConfig.model_dump()` via `@field_serializer` (**BREAKING** if callers expected plaintext `model_dump()`, `DA-022`), and sync `REQ-SESS-004`/`SCN-SESS-004-1` with fail-closed RW cleanup without cache seeding (`DA-030`).
   - Decompose `AMgmtClient.api_call` (`DA-036`, unifying duplicated failover retries and fixing stale `mds_ip`/hostname pinning on expired-SID retries) and remove dead startup-seed residue (`_inflight_logins`, `adopt_dedicated_sid`, `has_inflight_or_cached_login`) in `LoginCoordinator` (`DA-050`).
2. **Cache Sync, Storage Security & SSE Framing (`DA-006`, `DA-019`, `DA-038`, `DA-041`)**:
   - Fix `DomainSyncCoordinator` single-flight coalescing so `mode="cache"` flights do not suppress `smart` waiters, mid-flight invalidations prevent setting `completed_ok = True`, and failed stale-type syncs do not overwrite sibling `fresh_types` as `"failed"` (`DA-006`); decompose `stream_ensure()` into focused helper methods (`DA-038`).
   - Enforce `os.lstat()` `S_ISLNK`/regular-file validation and tighten existing SQLite cache files to `0o600` in `DatabaseManager._create_engine()` (`DA-019`).
   - Strip `\r`, `\n`, `\x00` from `SSEEvent.id`/`event` and apply `redact_sid()` to `event` in `SSEEvent.encode()` (`DA-041`).
3. **Gateway Topology, Route Collection & Script Repository (`DA-002`, `DA-011`, `DA-012`, `DA-028`, `DA-039`, `DA-042`)**:
   - Decouple bundle-level VSX coalesced execution status from the leader VS's per-VS slice errors (`vs_context_error`/`vs_not_found_in_bundle`) so healthy sibling Virtual Systems stay isolated (`DA-002`).
   - Buffer `SyncCompletedEvent` until `_collect_routes_for_refresh()` finishes in full-domain `stream_refresh_topology(collect_routes=True)` (`DA-011`).
   - Match annotations strictly against LPM `best_entry` in `_score_interface_group` (`DA-012`), match manual-only gateways across all canonical identifiers in `export_topology_prefixes` (`DA-039`), fix `awk` space-containing VS name resolution in `route_scripts.py` (`DA-042`), and apply `known_sids` scrubbing + `RepositoryScriptPermissionError` mapping in `ScriptRepositoryService` write paths, targeted topology refresh, and `_load_domain_package_snapshot` (`DA-028`).
4. **Rulebase, CPCRUD & Change Reports (`DA-005`, `DA-008`, `DA-014`, `DA-018`, `DA-020`, `DA-025`, `DA-026`, `DA-029`, `DA-033`, `DA-044`, `DA-047`, `DA-051`)**:
   - Fail closed on `paging_inconsistent` and API errors in `collect_domain_rulebase_snapshot()` instead of falling back to 50-item unpaginated `api_call` (`DA-005`), bound `fetch_paged_rulebase()` with `max_pages`/zero-new-rule limits and mid-fetch `total` drift checks (`DA-029`), unify synthetic fallback rule UIDs (`DA-047`), and fix `locate_rules_in_snapshot` prefix tracking for empty Global-placeholder and unnamed inline layers (`DA-033`).
   - Fail closed in `Executor.stream_publish_staged_session` when `allow_stale=False` lacks a verified baseline stamp (**BREAKING** for callers relying on post-restart adoption without explicit baseline or `allow_stale=True`) and forward `stored_staged` baseline stamps from MCP `cpcrud_staged_session` (`DA-008`).
   - Wire `check_where_used: true` usage inspection across `plan_object_step`, `plan_service_step`, and `plan_group_step` (`DA-014`), emit `groups: []` / `tags: []` in `CPCRUDService.inverse()` when `action.diffs` added them from empty `[]` (`DA-020`), honor `Executor._check_domain_head` consistently (`DA-044`), and consolidate `_planner_diff.py`/`_planner_entity_steps.py` (`DA-051`).
   - Fail closed when `from_session`/`to_session` lacks a parseable timestamp (`DA-025`), avoid forwarding failed `OwnedSession` or unredacted `known_names` in `collect_change_report` (`DA-026`), and escape nested `[` / `]` inside `**bold**` and `*italic*` spans in `render_safe_inline_markdown_md` (`DA-018`).
5. **MCP Server & API Reference (`DA-009`, `DA-013`, `DA-015`, `DA-016`, `DA-017`, `DA-024`, `DA-031`, `DA-032`, `DA-037`, `DA-043`)**:
   - Enforce explicit fan-out quota before domain pre-validation in `cache_control` and `change_report` (`DA-009`), unify multi-MDS scope resolution via `resolve_and_validate_scope` (`DA-037`) fixing `search_objects` `mgmt_names[0]` pinning (`DA-013`), fix `cache_control(action="refresh", mode="cache")` quota/live-call leaks and spec alignment (`DA-032`), register `stored_staged.sid` before staged publish/discard and make `plan_store` owner-fair (`DA-024`), wrap `mcp_tool_guard` error metadata lookups defensively (`DA-015`), compute stalest-scope `min(synced_times)` in `_compute_cache_age` (`DA-016`), fix `live_show_object` typed UUID + `Cpmi*`/underscore validation (`DA-017`), and clamp `offset`/`limit` on cached `show_rulebase` (`DA-043`).
   - Skip management-only field version filtering for `api_family != "management"` in `ApiReferenceEngine` so Gaia/CME commands describe and validate cleanly under default `v2.2` and `v2.0.1` (`DA-031`).
6. **Testing Replay Mock & Emulator (`DA-034`, `DA-035`, `DA-045`)**:
   - Restore section order/name and pre-validate `members`/`groups` atomically on failed mutations (`DA-034`), rotate aliased SIDs in `handle_switch_session` and guard read-only `handle_disconnect` (`DA-035`), and capture clean domain baselines inside `_mark_domain_mutated` before mutating (`DA-045`).

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `sessions-and-mdm`: Sync `REQ-SESS-004` (`SCN-SESS-004-1`) with fail-closed RW cleanup without cache seeding, and add `REQ-SESS-014` for lifecycle TLS identity binding, failed-discovery retry gating, `LoginGate` `AuthenticationError` mapping, target-MDS `SessionCleaner` throttling, `model_dump()` secret masking, and `AMgmtClient.api_call` / `LoginCoordinator` hardening.
- `cache-and-sync`: Add `REQ-CACHE-020` for single-flight invalidation/`mode="cache"`/`cache_ttl` safety, decomposed `stream_ensure()`, and SQLite `0o600` + symlink rejection on `DatabaseManager`.
- `client-and-facade`: Add `REQ-CLIENT-019` for CR/LF/NUL sanitization and SID redaction in `SSEEvent.encode()`.
- `gateway-topology`: Add `REQ-TOPO-022` for VSX coalesced leader slice error isolation, buffered `SyncCompletedEvent` on `collect_routes=True`, LPM annotation matching, manual-gateway prefix filtering, space-containing VSID awk matching, and `known_sids` scrubbing across script/topology error paths.
- `rulebase-and-numbering`: Add `REQ-RULE-009` for fail-closed `paging_inconsistent`/error handling, bounded pagination with `total` drift checks, unified synthetic fallback UIDs, and empty embedded layer prefix continuity.
- `cpcrud`: Add `REQ-CPCRUD-017` for fail-closed `allow_stale=False` staged publishing, active `check_where_used` reference blocking across objects/services/groups, empty-`groups`/`tags` rollback in `inverse()`, consistent `check_domain_head` callback dispatch, and consolidated entity planning.
- `change-reports`: Add `REQ-REPORT-008` for fail-closed unparsed session bounds, non-forwarding of invalidated `OwnedSession` + redacted `known_names`, and nested Markdown link/image escaping.
- `mcp-server`: Align `REQ-MCP-013` (`SCN-MCP-013-1`) with `cache_control(action="refresh", mode="cache")` offline zero-quota semantics, and add `REQ-MCP-016` for pre-validation fan-out quota ordering, unified multi-MDS scope validation, stalest `cache_age_seconds`, defensive `mcp_tool_guard` handling, staged SID redaction + owner-fair `plan_store`, typed UUID/`Cpmi*` `show_object`, and clamped cached `show_rulebase` pagination.
- `api-reference`: Extend `REQ-APIREF-003` (`SCN-APIREF-003-3`) so non-management (`gaia`/`cme`) schemas and payload validation remain intact across default `v2.2` and `v2.0.1`.
- `integration-testing-and-examples`: Add `REQ-ITEST-021` for atomic section/group rollback, aliased SID rotation on `switch-session`, read-only `disconnect` guards, and zero-disk clean baseline capture on direct mutations.

## Impact

- **Source Modules**: `src/arodonata/adapters/checkpoint/` (`tls.py`, `sessions.py`, `rate_limiter.py`, `session_cleaner.py`, `client.py`, `target_resolver.py`), `src/arodonata/adapters/storage/database.py`, `src/arodonata/adapters/sse/__init__.py`, `src/arodonata/core/` (`context.py`, `config.py`, `services/domain_service.py`, `services/sync_coordinator.py`, `services/script_service.py`, `services/topology/{refresh.py,route_executor.py,route_parsers.py,route_scripts.py,scoring.py,policy_rules.py}`), `src/arodonata/rulebase/` (`collector.py`, `pager.py`, `numbering.py`), `src/arodonata/cpcrud/` (`executor.py`, `_executor_pass.py`, `_planner_diff.py`, `_planner_entity_steps.py`, `_planner_helpers.py`, `inverse.py`, `checkpoint_ops_schema.json`), `src/arodonata/reports/` (`collector.py`, `_collector_changes.py`, `_renderer_formatting.py`), `src/arodonata/mcp/` (`errors.py`, `tools/{_cache.py,_common.py,_show_object.py,admin.py,cpcrud.py,lookup.py,objects.py,rulebase.py,topology.py}`), `src/arodonata/api_reference/engine.py`, and `src/arodonata/testing/` (`replay_mock.py`, `_emulator_rulebase_crud.py`, `_emulator_entity_crud.py`, `_replay_sessions.py`, `_replay_global_and_policy.py`, `_replay_state.py`).
- **Breaking Changes**:
  - `AuthContext.model_dump()` and `ServerEndpointConfig.model_dump()` mask `password` and `api_key` (`DA-022`), matching `ArodonataSettings` and `SIDCacheEntry`.
  - `Executor.stream_publish_staged_session(..., allow_stale=False)` fails closed when no verified baseline stamp is available (`DA-008`); callers adopting post-restart sessions without a stamp must pass explicit baseline parameters or `allow_stale=True`.
