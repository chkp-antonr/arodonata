# Design

## Context

See [proposal.md](proposal.md) and `specs/*/spec.md` for the Wave 8 scope (`27` `DA-*` items + `VVAH` policy/renderer/pager/CPCRUD findings). All hexagonal invariants (`ApiPort` / `CachePort` / `LockPort` boundaries, zero SID leakage, naive UTC timestamps, provider-agnostic OTel) remain unchanged.

## Goals / Non-Goals

**Goals:**

- Eliminate silent policy drift, wire-format mismatches, and staged-session leaks in `cpcrud` (`REQ-CPCRUD-014`, `REQ-CPCRUD-015`).
- Harden `reports` against unbounded `RangeScope` history leaks, inline HTML/Markdown injection, false `MOVED` flags, and empty `FieldDiff`s (`REQ-REPORT-006`).
- Guarantee complete rulebase layer discovery, advancing zero-rule pagination, and post-fetch completeness verification before committing `status="ok"` (`REQ-RULE-007`).
- Ensure fail-fast `ServerIdentityError` propagation, atomic full-domain `routes` sync state, domain-isolated VSX coalescing, and `manual` prefix export in `topology` (`REQ-TOPO-021`), plus lock-serialized cross-domain VSX asset reconciliation (`REQ-CACHE-017`).
- Align `FileReplayApiMock` with real Check Point wire validation, atomic mutation rollback, read-only `switch-session` blocking, and zero-disk-I/O reset (`REQ-ITEST-019`).

**Non-Goals:**

- Wave 9 structural refactoring / deduplication (`DA-046`..`DA-053`, `DA-063`).
- Modifying foundational transport/TLS/MCP quota layers already completed in Wave 7.

## Decisions

1. **Per-Rulebase `track` Wire Encoding & Fail-Closed Defaults (`REQ-CPCRUD-014`)**
   - *Choice*: Introduce shared helpers `_encode_track_for_rulebase(value, rulebase_type)` and `_resolve_desired_rule_action(spec, rulebase_type)` used by `_planner_helpers.py`, `differ.py`, and `rule_identity.py`. Encode `track` as `TrackSettingsForRequest` dict on `access` (preserving sub-fields in diffs and `prior_state`) and plain string on `https`/`threat`. Default omitted rule actions fail-closed (`"Drop"` / `"Inspect"` / `"Optimized"`).
   - *Alternative Rejected*: Keeping `"Accept"` in `_build_add_rule_payload` while `rule_identity.py` uses `"Drop"` — breaks unnamed-rule idempotency and creates overly permissive rules.

2. **Anti-Widening `install-on`, Empty-List Rejection, and `is_cleanup_rule` (`REQ-CPCRUD-014`)**
   - *Choice*: Pass `default_any=(field_key in ("source", "destination", "service"))` to `deref_rule_list`, reject `[]`/`""`/`[""]` with `DiffSafetyError`/`ValidationError` (plus `minItems: 1` in `checkpoint_ops_schema.json`), and remove the unconditional `return True` in `position_helper.is_cleanup_rule` so `"cleanup"`-named rules still require `Any`/`Any`/`Any` traffic.
   - *Alternative Rejected*: Allowing `[]` to coerce to `("Any",)` — violates `REQ-CPCRUD-009` anti-`Any`-widening guarantees.

3. **Staged Session Cleanup, Provenance, and Placeholder-Free Rollback (`REQ-CPCRUD-015`)**
   - *Choice*: Extract `_real_uid()` in `inverse.py` (filtering `planned:*`), route `service-group` to group inversion, restore parent-group memberships on group rollback, shield all staged `logout_sid` calls under `suppress(BaseException)` (including `_register_staged_session` inside `try ... finally`), verify domain-head staleness in `publish_staged_session(allow_stale=False)`, and align `_inspect_and_verify_provenance` with `REQ-CPCRUD-011`.
   - *Alternative Rejected*: Leaving `is_arodonata_tagged` dead in `_executor_staged.py` — causes post-restart `arodonata*` sessions to fail closed unexpectedly.

4. **Report Safety, Placement Prefixing, and Pager/Refresh Completeness (`REQ-REPORT-006`, `REQ-RULE-007`)**
   - *Choice*: Return empty matches + `ReportWarning` on missing `RangeScope` UIDs; verify `OwnedSession` with `sid=None` fallback; return `None` from `_list_field_diff` on order-only diffs; preserve dotted `rule_number` strings in `plan_report.py`; restrict `_INLINE_TOKEN_RE` to single-line tokens and escape/validate `href` + `\r` in `_renderer_formatting.py`; record `LayerPrefixLocation` even for empty inline/placeholder layers and normalize nested `old_rule_number`. In `rulebase`, paginate `show-*-layers` via `api_query`, continue `fetch_paged_rulebase` on zero-rule advancing pages, raise on `< total_reported` truncation, and verify per-layer totals before committing `status="ok"`.
   - *Alternative Rejected*: Silently clamping `PagedRulebaseResult.total = len(ordered_raw_rules)` — hides truncation and corrupts downstream CPCRUD rollback templates.

5. **Topology Atomicity, VSX Coalescing, Asset Locking, and Replay Mock (`REQ-TOPO-021`, `REQ-CACHE-017`, `REQ-ITEST-019`)**
   - *Choice*: Propagate `ServerIdentityError` in `_enrich_group_raw_if_needed`; defer `("topology", "routes")` sync state until full-domain `TaskGroup` completion (`gw_tokens` empty); key VSX coalescing by `(mgmt_name, domain_name, node_key)` and check `base_result.success` before `vsx_bundle_missing`; unwrap list `next-hop` in `normalizer.py`; match spaces in `_VS_ERROR_RE`; include `manual` entries in `export_topology_prefixes(include_ignored=True)`. In `AssetRefreshService._reconcile_cross_domain_vsx`, skip `mode="cache"` / no-op runs, key by `(mgmt_name, uid)`, and lock per `mgmt_name`. In `FileReplayApiMock`, validate per-rulebase `track` wire types, roll back failed entity/section mutations, enforce `read_only` on `switch-session`/`set-session`/`discard`, and snapshot `_initial_domain_data` lazily in memory before first mutation.
   - *Alternative Rejected*: Re-reading disk JSON fixtures on first `restore_state()`/`reset()` — violates `REQ-ITEST-015` zero-disk-I/O reset contract.

## Risks / Trade-offs

- `[Strict per-rulebase track wire validation in FileReplayApiMock and rulebase completeness errors may surface previously masked issues in existing tests]` → Update any test fixtures that relied on permissive `"Accept"` defaults, truncated mocks, or per-gateway route sync-state overwrites (`DA-012` notes `test_topology_service.py` and `test_topology_compat_and_security.py`).
- `[Requiring Any/Any/Any traffic in is_cleanup_rule changes placement when a rule named *cleanup* has narrow traffic]` → Matches the documented intent and prevents silent policy-ordering drift (`VVAH-CLAUDE-06`).
