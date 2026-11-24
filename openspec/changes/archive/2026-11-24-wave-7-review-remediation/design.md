# Design

## Context

See [proposal.md](proposal.md) for the `/claude-review` findings summary (`docs/_audit_/2611240658.md`). Architectural invariants from `AGENTS.md` and `openspec/config.yaml` remain unchanged: strict hexagonal port boundaries (`ApiPort` / `CachePort`), zero SID exposure across logs/errors/outputs, naive UTC database timestamps, provider-agnostic OpenTelemetry tracing, and cross-change OpenSpec stackability alongside `wave-7-security-and-cache-integrity`.

## Goals / Non-Goals

**Goals:**

- Eliminate lost domain/wildcard invalidations during concurrent smart-mode staleness probes and sync handlers.
- Restore `cache_ttl` reuse for targeted single-package rulebase refreshes under persistent invalidation maps.
- Enforce strictly offline cache-only MCP domain pre-validation when callers request `cache_mode="cache"`.
- Fail closed on unresolvable explicit hostnames without forwarding raw hostnames to transport connect-time DNS.
- Remove the `seed_system_sid` early-return bypass in `SessionCleaner` so startup stale-session inspection always runs when static credentials exist.
- Align `FileReplayApiMock` command-name validation with `AMgmtClient` (`validate_command_name`) and update `LoginCoordinator.is_sid_entry_fresh` docstring to match sliding-window semantics.

**Non-Goals:**

- Broad Wave 8/9 policy-engine or refactoring work outside the seven targeted remediation points (`REQ-RULE-001`, CPCRUD semantic planner fixes, change-report rendering, topology route completeness, monolith splitting).
- Altering `validate_domain_or_fail` live refresh behavior when `cache_mode` is `"smart"`, `"smart-fast"`, or `"force"`.

## Decisions

1. **Start-Epoch Invalidation Guard (`sync_coordinator.py`, `REQ-CACHE-015`)**
   - *Choice*: At the start of `probe_domain_staleness`, capture `probe_started_at = self._now()` and `(inv_ts_before, inv_seq_before) = self._effective_invalidation(mgmt_name, dom_name)` before querying `show-last-published-session`. Expose `probe_started_at` and `invalidation_seq_at_start` on `DomainProbeResult`, and add an optional `target_seq: int | None = None` parameter to `_record_slice_synced`. Before updating `fresh_types` after `show-last-published-session`, compare current `_effective_invalidation(mgmt_name, dom_name)` against `(inv_ts_before, inv_seq_before)`: if an invalidation arrived while the probe was in flight, skip stamping `synced_at` and skip `_record_slice_synced` so `is_slice_invalidated` continues returning `True`. Otherwise write `synced_at = probe_started_at` (never post-probe `self._now()`) and record `target_seq=inv_seq_before` so invalidations arriving during the `upsert_sync_state` await or under frozen clocks still win on `(norm_sync <= inv_ts, seq < inv_seq)`. Similarly, in `stream_ensure`, capture `handler_start_seq = self._effective_invalidation(dom.mgmt_name, dom.name)` before `handler(probe, _emit)` and only invoke `_record_slice_synced(..., target_seq=handler_start_seq[1])` when no newer invalidation arrived mid-sync (avoiding masking mid-sync invalidations with a post-sync sequence counter; if an invalidation arrived mid-handler, preserve `last_inv` wins via invalidation bump or skip recording).
   - *Alternative Rejected*: Calling `self._now()` after `show-last-published-session` and recording current `self._invalidation_counter` — `norm_sync > inv_ts` and equal sequence numbers cause `is_slice_invalidated` to return `False` immediately after a mid-probe publish.

2. **Slice-Scoped Rulebase Invalidation Check (`rulebase/refresh.py`, `REQ-RULE-003`)**
   - *Choice*: In `RulebaseRefreshService.refresh_package_rulebase`, evaluate `refresh_policy_packages(...)` and resolve `matched_pkg` / `pkg_uid` / `slice_item_type = f"package:{rulebase_type}:{pkg_uid}"` first, read `slice_state = await self._cache.get_sync_state(mgmt_name, clean_dom, "rulebase", slice_item_type)`, and compute `was_invalidated = self._coordinator.is_domain_invalidated(mgmt_name, clean_dom, scope="rulebase", item_type=slice_item_type, synced_at=slice_state.synced_at if slice_state is not None else None)` (matching the pattern established in `topology/refresh.py` and `topology/extractor.py`) before deciding `eff_slice_ttl`.
   - *Alternative Rejected*: Calling unscoped `is_domain_invalidated(mgmt_name, clean_dom)` without `(scope, item_type, synced_at)` — under persistent invalidation maps (`DA-002`), unscoped queries return `True` for the lifetime of the process and zero out `cache_ttl` permanently.

3. **Cache-Mode-Aware MCP Domain Pre-Validation (`mcp/errors.py`, `mcp/tools/_common.py`, tool modules, `REQ-MCP-013`)**
   - *Choice*: Add `allow_refresh: bool = True` to `validate_domain_or_fail` and `cache_mode: CacheMode = "smart"` to `_validate_optional_domains`. Normalize `cache_mode` ahead of domain validation in MCP tool handlers (`objects.py`, `topology.py`, `admin.py`, `lookup.py`, `rulebase.py`), and pass `cache_mode=mode` / `allow_refresh=(mode != "cache")` into validation helpers. When `mode == "cache"`, `_validate_optional_domains` passes `refresh_if_empty=False` to `get_known_domain_names` across all management servers and skips `consume_live_quota_if_needed()`, validating strictly against cached `arodonata_domains` rows while preserving `REQ-MCP-002` cold-cache upgrades downstream in tools that support it (`query_objects`, `list_*`, `search_objects`) and keeping `locate_gateways` / `cache_control(cache_mode="cache")` completely offline.
   - *Alternative Rejected*: Unconditionally calling `get_known_domain_names(..., refresh_if_empty=True)` and `validate_domain_or_fail(..., cache_mode="force")` regardless of caller `cache_mode` — causes live `show-domains` traffic and unexpected `live` quota consumption on partial multi-MDS or offline `cache_mode="cache"` calls.

4. **Fail-Closed Explicit Hostname Pinning (`target_resolver.py`, `REQ-SESS-010`)**
   - *Choice*: Remove the `elif canonical_ip in trusted_ips: pinned_target = cleaned_ip` fallback inside `validate_explicit_server_ip` when `_resolve_hostname_ips(cleaned_ip)` returns an empty set, so unresolvable non-IP explicit hostnames fail closed with `ValidationError` before transport connection instead of passing an unpinned hostname to `aiohttp`. Update the `validate_explicit_server_ip` docstring return annotation description from `pinned_ip_or_host` to `pinned_ip`.
   - *Alternative Rejected*: Falling back to an arbitrary entry in `trusted_ips` or passing raw `cleaned_ip` to transport — passing a raw hostname reintroduces TOCTOU connect-time DNS resolution, while guessing another IP breaks multi-IP / CMA topology semantics when DNS fails.

5. **Unconditional Startup Stale-Session Inspection (`session_cleaner.py`, `REQ-SESS-011`)**
   - *Choice*: Remove `seed_system_sid` parameter and the early `if seed_system_sid and existing_cached ...: return True` short-circuit from `SessionCleaner.cleanup_server_sessions`, `schedule_startup_cleanup`, and `run_startup_cleanup`. Retain read-only cached SID preservation (`cached_by_uid`) and unconditional temporary RW session logout in `finally` (`DA-042`). Update legacy tests in `tests/unit/test_wave3_compat_and_fixes.py` and `tests/unit/test_sessions.py` that called `seed_system_sid=...` or asserted the bypassed startup behavior.
   - *Alternative Rejected*: Retaining `seed_system_sid=True` as a startup shortcut — leaves abandoned Arodonata sessions from prior runs undisposed whenever an unexpired System Data RO SID exists in cache.

6. **Replay Mock Strict Command Validation (`testing/replay_mock.py`, `REQ-ITEST-007`)**
   - *Choice*: Replace `command.strip().lstrip("/")` and manual `web_api/` prefix stripping in `FileReplayApiMock.api_call` and `FileReplayApiMock.api_query` with `validate_command_name(command)` from `arodonata.core.primitives`.
   - *Alternative Rejected*: Keeping permissive `.strip().lstrip("/")` normalization in the emulator — masks validation regressions caught by `AMgmtClient` in production.

7. **Keepalive Freshness Docstring Alignment (`adapters/checkpoint/sessions.py`)**
   - *Choice*: Update `LoginCoordinator.is_sid_entry_fresh` docstring to match `session_credentials.py` (`expires_at` precedence when present, sliding `last_used_at or created_at` within `session_expire_seconds` otherwise).
   - *Alternative Rejected*: Leaving the legacy docstring referencing total age from `created_at` — misleads maintainers auditing session freshness guarantees.

8. **OpenSpec Stacking Hygiene**
   - *Choice*: Author strictly non-overlapping `ADDED` requirements (`REQ-CACHE-015`, `REQ-MCP-013`, `REQ-SESS-010`, `REQ-SESS-011`) in capabilities already modified by `wave-7-security-and-cache-integrity`, and `MODIFIED` requirements only in untouched capabilities (`REQ-RULE-003`, `REQ-ITEST-007`). Both changes can validate simultaneously and archive in either order without merge or scenario-ID collisions.

## Risks / Trade-offs

- [Removing `elif canonical_ip in trusted_ips` breaks offline tests that pass an unresolved `mgmt_ip` hostname as `explicit_server_ip` without stubbing `_resolve_hostname_ips`] -> Audit all `explicit_server_ip` tests (already verified none currently rely on unresolved hostname passthrough) and add deterministic DNS stubbing in unit tests alongside `SCN-SESS-010-1`.
- [Removing `seed_system_sid` increases startup `login` + `show-sessions` + `logout` calls by one lightweight RW session per configured static server on restart even if DB cache has a warm System Data RO SID] -> Acceptable fail-closed trade-off under `REQ-SESS-011` and `REQ-SESS-004`; update `test_wave3_compat_and_fixes.py` to keep verifying per-identity RO SID preservation without skipping `show-sessions`.
- [Enforcing `validate_command_name()` inside `FileReplayApiMock` could fail tests passing slash-prefixed commands directly to the mock] -> Pre-flight grep of `tests/` confirmed no existing replay-mock tests rely on malformed `/cmd` strings; add `SCN-ITEST-007-3` coverage confirming parity with `AMgmtClient`.
