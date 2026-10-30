# Design

## Context

See `proposal.md` for motivation and `docs/_audit_/2610301251.md` for the full Independent Principal Security Architect & Spec Compliance Audit findings (`C1`–`C2`, `W1`–`W6`, `I1`–`I6`). Commit `f3711d2` on `fix/post-publish-owned-session-placement` archived `2026-10-30-post-publish-owned-session-and-placement` while bundling un-specced edits to `cpcrud/executor.py`, `mcp/tools.py`, `client.py`, and `core/services/search_service.py`. Two changes introduced critical security/correctness regressions (`C1` foreign session takeover/disconnect; `C2` unlocked out-of-band `arodonata_rulebase_*` writes from `reports/placement.py`), alongside committed session/IP warnings (`W1`, `W2`), whole-MDS sync & cross-domain ambiguity warnings (`W3`), strict spec validation failures (`W5`), and six targeted hardening improvements (`I1`–`I6`).

All remediations must preserve Hexagonal Architecture purity (`core/`, `rulebase/`, and `reports/` remain free of transport, SQLAlchemy/SQLModel, and MCP imports), zero-leak SID/secret hygiene, and naive UTC timestamps.

## Goals / Non-Goals

**Goals:**

- Remediate all 14 findings (`C1`–`C2`, `W1`–`W6`, `I1`–`I6`) in `docs/_audit_/2610301251.md` with zero regressions to existing valid `change-reports` features (zero-rule short-circuit, banner suppression, post-publish `OwnedSession` numbering, bare `layer_uid` resolution).
- Guarantee that `RulebaseRefreshService` under `DomainSyncCoordinator` is the sole writer to `arodonata_rulebase_*` across the entire codebase.
- Guarantee that neither the Python SDK (by default) nor the MCP server (ever) can disconnect an active human SmartConsole administrator or publish/discard a foreign session.
- Achieve 10/10 pass rate on `openspec validate --specs --strict --no-interactive` after syncing/archiving delta specs.

**Non-Goals:**

- Adding new database tables or altering the Check Point Web API wire protocol.
- Changing `ChangeReport.format_version` (v1 JSON compatibility is preserved).

## Decisions

### Decision 1: Provenance-Gated, Non-Disruptive Staged-Session Adoption (`C1`, `I6`, `W2`)

- **Approach**:
  1. **Default Arodonata Session Naming & Client Staged Registry**: In `Executor._stream_single_pass` (`src/arodonata/cpcrud/executor.py`), when `session_name` (and `UserContext.session_name`) is omitted, default `eff_session_name` to `"arodonata-cpcrud-staged"` when `no_publish and keep_session` else `"arodonata-cpcrud"`. Maintain a bounded in-memory registry `_staged_sessions: OrderedDict[tuple[str, str, str], StagedSessionInfo]` keyed by `(mgmt_name, normalize_domain_key(domain), session_uid)` populated whenever `apply(..., no_publish=True, keep_session=True)` creates a staged session, and evicted when published or discarded.
  2. **Direct Active-SID Reuse (Avoid Self-Takeover)**: In `Executor._adopt_staged_session`, if `sid` is provided (or recovered from `_staged_sessions` when caller omitted `sid`), first call `show-session {}` on that `sid`. If `show-session` succeeds, `uid == session_uid`, and `state` is not `"published"` or `"discarded"`, return `(sid, server_ip, verify_res)` directly without calling `take-over-session` (a live session already owns itself on Check Point).
  3. **Provenance Verification Before Takeover/Switch on `fresh_sid`**: When `sid` is absent or expired, open `fresh_sid` via `create_dedicated_session` and call `show-session {"uid": session_uid}` on `fresh_sid` **before** any takeover command:
     - Refuse immediately (logging out `fresh_sid`) if `show-session` fails, if `state` is `"published"` or `"discarded"` (or `publish-time` is present), or if the session's reported domain mismatches the requested `domain`.
     - Verify provenance: require either `(mgmt_name, dom_key, session_uid) in self._staged_sessions` **or** `session_name.lower().startswith("arodonata")` **or** `application.lower() == "arodonata"`. Foreign SmartConsole or non-Arodonata sessions are rejected with `error_code="foreign_session_refused"` before `take-over-session` or `switch-session` is ever called.
  4. **Non-Disruptive Takeover Default & Dual-Error Reporting**: Add keyword-only `force_disconnect: bool = False` to `Executor._adopt_staged_session`, `stream_publish_staged_session`, `publish_staged_session`, `discard_staged_session`, `CPCRUDService`, and `ArodonataClient` (never exposed in MCP). Build `takeover_payload = {"uid": session_uid}` by default, adding `"disconnect-active-session": True` **only** when `force_disconnect is True`. If `take-over-session` fails on a provenance-verified session, attempt `switch-session {"uid": session_uid}` (which Check Point uses for disconnected sessions owned by the same administrator); if `switch-session` also fails, combine both redacted error messages (`take-over-session: <err1>; switch-session: <err2>`) on the returned `ApiCallResult` (`I6`) and log out `fresh_sid`.
  5. **MCP Server-Side Staged-Session Enforcement**: In `register_mcp_tools` (`src/arodonata/mcp/tools.py`), maintain a bounded `staged_session_store: OrderedDict[tuple[str, str, str], StagedSessionInfo]` alongside `plan_store`. Populate it from `report.staged_sessions` inside `cpcrud_apply` when `no_publish and keep_session`. In `cpcrud_staged_session`, remove the `server_ip` parameter (`W2`), look up `(eff_mgmt, normalize_domain_key(eff_domain), session_uid.strip())` in `staged_session_store`, and raise `ToolFailure` immediately if missing — passing `force_disconnect=False` and removing the entry once publish/discard succeeds.
- **Alternatives Considered**:
  - *Dropping `switch-session` entirely*: Rejected because Check Point rejects `take-over-session` when an administrator attempts to take over their own disconnected Web API session under certain permission profiles, where `switch-session` is the documented same-admin command. Gating `switch-session` behind the exact same `show-session` provenance check and MCP `staged_session_store` check preserves compatibility safely.

### Decision 2: Pure Read-Only `arodonata.reports` & Coordinator-Delegated Cold-Cache Warming (`C2`)

- **Approach**:
  1. **Remove All `cache.replace_domain_rulebase` Calls from `reports/placement.py`**: Neither Case 2 (post-publish `OwnedSession`) nor the cold-cache fallback in `apply_session_rule_placement` calls `cache.replace_domain_rulebase`. Case 2 numbers rules strictly from the in-memory `live_snapshot`.
  2. **Optional Coordinator Callback for Cold-Cache Warming**: Add an optional keyword parameter `refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None` to `collect_change_report`, `build_change_report`, and `apply_session_rule_placement`.
     - `ArodonataClient.collect_change_report` and `ArodonataClient.build_change_report` pass a closure calling `await self.refresh_rulebases(mgmt_name=m, domains=[d] if d else None, mode="smart")` (wrapped in `suppress(Exception)` except `ServerIdentityError`).
     - In `apply_session_rule_placement`, when `not has_cached_rules` and `refresh_rulebase_fn is not None`, invoke `await refresh_rulebase_fn(mgmt_name, domain_name)` — which acquires the `DomainSyncCoordinator` per-domain distributed lock, verifies session cleanliness (`DirtySessionError`), and atomically writes `arodonata_rulebase_*` + `DomainSyncState` — then re-read `cache.get_domain_rulebase` and `cache.get_sync_state`. If `has_cached_rules` is now `True`, use `numbering_source = "cache"` with the stamped session basis!
     - If `refresh_rulebase_fn is None` (standalone `(api, cache)` caller) or cache remains empty (e.g., stub test without coordinator), fall back to an **in-memory-only** `collect_domain_rulebase_snapshot` without touching `CachePort`.
  3. **Strict Case 2 Cleanliness, Domain & Scope Ownership Checks**:
     - In `SessionScope.resolve_owned_session` (`src/arodonata/reports/models.py`), require `(self.owned_sessions.session_uid == session_uid or len(self.session_uids) == 1)` for a bare `OwnedSession` (matching the existing single-session guard on `dict["*"]` and `list`), and reject any `OwnedSession` whose explicit `mgmt_name` or `domain` (when non-empty) disagrees with `(self.mgmt_name, self.domain)`.
     - In `apply_session_rule_placement` (`placement.py`), check `s_data` from `show-session {}`:
       - Extract reported domain name (`s_data.get("domain", {}).get("name")` when `domain` is a dict, or `s_data.get("domain")` when a non-empty string). If both `domain_name` and reported domain are non-empty and differ (case-insensitively), reject with `owned_session_not_used` (wrong-domain SID).
       - For Case 2 (`target_is_published`), require `"changes" in s_data` and `"locks" in s_data`, with `int(s_data["changes"]) == 0`, `int(s_data["locks"]) == 0`, and `int(s_data.get("number-of-published-changes") or 0) == 0` (matching `DomainSyncCoordinator.verify_session_clean`). Also require that if `owned_session.session_uid` was set, `owned_session.session_uid == session_uid`. Any failure emits `owned_session_not_used` and falls back cleanly.
- **Alternatives Considered**:
  - *Importing `DomainSyncCoordinator` directly inside `arodonata.reports`*: Rejected to keep `arodonata.reports` loosely coupled to `(ApiPort, CachePort)` protocols; injecting `refresh_rulebase_fn` from `ArodonataClient` achieves full coordinator locking without cross-package coupling.

### Decision 3: Identity-Scoped SID Eviction, `"read-only": true` Logins, Trusted `server_ip` & Cancellation Hygiene (`W1`, `W2`, `I1`, `I2`, `I4`)

- **Identity-Scoped `evict_sid` (`W1`)**:
  - Add `get_readonly_session_entry` (or return/resolve `auth_identity` via `await self._login_coordinator.resolve_auth_identity(mgmt_name, domain)`) in `LoginCoordinator`, and pass `auth_identity=active_identity` at all four `self._cache.evict_sid(mgmt_name, dom_key, auth_identity=active_identity)` sites in `AMgmtClient.api_call` (`src/arodonata/adapters/checkpoint/client.py:457, 472, 494, 505`), as well as `auth_identity=entry.auth_identity` in `LoginCoordinator.logout_all` (`sessions.py:930`) and identity-aware lookup in `keepalive_sid`.
- **Server-Enforced Read-Only Shared Sessions (`I1`)**:
  - Change `read_only=False` to `read_only=True` in `LoginCoordinator.get_readonly_session` (`sessions.py:435`), sending `"read-only": True` in Check Point `login` payloads for shared `arodonata_sid_cache` sessions while keeping `read_only=False` on `create_dedicated_session` / `write_session`.
- **Trusted `explicit_server_ip` Validation (`W2`)**:
  - In `LoginCoordinator.resolve_target_ips` (`sessions.py:304-325`), when `explicit_server_ip` is provided, build the set of trusted hosts for `mgmt_name`: `{endpoint.host}` union `{d.active_ip, d.active_mds_ip, *d.standby_ips}` across `await self._cache.get_domains(mgmt_name, include_global=True)` (plus any active dedicated session IPs already authenticated for `mgmt_name`). If `explicit_server_ip` is not in the trusted set, raise `ValidationError` before any network connection or TOFU certificate learning occurs.
- **`SIDCacheEntry` Serialization & Key Hygiene (`I2`)**:
  - In `src/arodonata/core/models/domains.py`, declare `sid: str = Field(repr=False, exclude=True)` on `SIDCacheEntry` (internal persistence in `SqlCacheAdapter.upsert_sid` reads `entry.sid` directly as a Python attribute, so DB storage is unaffected while `model_dump()` / `model_dump_json()` never leak `sid`), and update `model_post_init` to set `self.id = f"{self.mgmt_name}:{self.domain_name}:{self.auth_identity}"` whenever `self.auth_identity` is present.
- **`RateLimiter.slot` Cancellation Propagation (`I4`)**:
  - In `RateLimiter.slot` (`src/arodonata/adapters/checkpoint/rate_limiter.py:179-185`), change `with suppress(BaseException):` to `with suppress(Exception):` around `await asyncio.shield(self._lock_port.release(lock_key, owner_id=owner_id))`. Because `_release_local_fifo_slot(target_ip, local_slot)` is in the outer `finally`, the local FIFO slot is still guaranteed to release on `CancelledError`, while cancellation is properly propagated to the caller instead of silently swallowed.

### Decision 4: Cache-Only Cross-Domain Entity/Group Lookups & `AmbiguousObjectError` (`W3`, `I3`)

- **New Exception (`AmbiguousObjectError`)**:
  - Define `AmbiguousObjectError(ValidationError)` in `src/arodonata/core/errors.py` (exported in `arodonata/__init__.py`) with `mgmt_name: str`, `query: str`, and `candidates: list[dict[str, str]]` (each containing `domain`, `uid`, `name`, `type`, and composite `id`/`object_id`/`service_id`/`asset_id`).
- **Required Non-Empty Target & Cache-Only Cross-Domain Resolution**:
  - In `ArodonataClient.find_object`, `ArodonataClient.get_group_members`, and `SearchService.get_group_members`, keep positional compatibility `(mgmt_name, domain, name_or_uid)` while validating `if not name_or_uid or not name_or_uid.strip(): raise ValidationError(...)` (`I3`).
  - If `domain` is `None` or blank and `name_or_uid` begins with `f"{mgmt_name}:"` (`mgmt:domain:target` with 3 non-empty segments), extract `eff_domain = parts[1]` and run a normal single-domain lookup.
  - Otherwise, when `eff_domain is None`:
    - Force `eff_cache_mode: CacheMode = "cache"` and `include_global = True` across `get_objects`, `get_services`, and `get_assets` so cross-domain lookups never trigger whole-MDS logins/syncs and include `"Global"` domain entities (`W3`).
    - Collect all exact matches across domains (exact UID/composite ID first; otherwise exact name, or case-insensitive exact name). Deduplicate matches by `(domain_name, uid)`; if matches span more than one distinct `domain_name`, raise `AmbiguousObjectError` with the sorted candidate list (`W3`).
- **MCP `show_object` & `get_group_members` Ambiguity Envelope**:
  - In `src/arodonata/mcp/tools.py`, when `eff_domain is None`, pass `cache_mode="cache"` and `include_global=True` on candidate queries (including `"Global"` in `layer_domains`), catch `AmbiguousObjectError` (and check multi-domain exact layer/package collisions), and return a clean JSON tool result with `"match_type": "ambiguous"`, `"total": len(candidates)`, `"object": None`, `"objects": candidates`, and an actionable `"hint"` instructing the model to pass `domain` or a `mgmt:domain:name` composite identifier.

### Decision 5: Splitting Over-Long Requirements for Strict OpenSpec Compliance (`W5`, `I5`)

- Under OpenSpec's strict validator (`openspec validate --specs --strict`), every requirement statement must be `<= 500` characters, while `MODIFIED` requirements must retain all existing scenarios.
- The delta specs for `cache-and-sync`, `client-and-facade`, and `mcp-server` tighten the four `>500`-character requirement statements (`cache-and-sync` requirements `[4]` and `[6]`, `client-and-facade` requirement `[2]`, `mcp-server` requirement `[2]`) to `< 440` characters each without dropping any scenario, and move split-out concerns into dedicated concise `ADDED` requirements (`Cluster and Cross-Domain VSX Parent-Child Topology Enrichment`, `Cache-Only Cross-Domain Entity Lookup and Ambiguity Refusal`, `Cache-Only Cross-Domain Group Lookup and Ambiguity Reporting in MCP`).

## Risks / Trade-offs

- **[Risk] Cold-cache cross-domain `find_object(mgmt, None, name)` returns `None` if no domain has been synced yet** → **Mitigation**: By design (`W3`), omitting `domain` on an MDS with dozens of domains must never trigger an implicit whole-MDS login storm; callers wanting populated cross-domain caches run `refresh_objects` / `cache_control(action="refresh")` first or specify `domain`.
- **[Risk] `explicit_server_ip` supplied on a cold cache before `show-domains` has run** → **Mitigation**: `endpoint.host` is always trusted immediately; if `explicit_server_ip != endpoint.host` and `arodonata_domains` is empty for `mgmt_name`, `resolve_target_ips` checks cached domains (and active dedicated session IPs for `mgmt_name`), rejecting arbitrary unconfigured IPs while allowing CMA IPs once discovered via `get_domains` / `refresh_domain_active_ip`.
- **[Risk] Existing unit tests in `test_cpcrud_executor.py` and `test_change_reports.py` assert `"disconnect-active-session": True` and direct `cache.replace_domain_rulebase` writes** → **Mitigation**: Update those tests (`W6`) to assert non-disruptive takeover + provenance refusal and coordinator-only rulebase cache writes, plus add adversarial negative and concurrency race tests.

## Migration Plan

1. Add `AmbiguousObjectError` to `core/errors.py`, harden `SIDCacheEntry` (`exclude=True`, `auth_identity` default `id`) in `core/models/domains.py`, and fix `RateLimiter.slot` cancellation propagation (`I2`, `I4`).
2. Harden `LoginCoordinator` (`read_only=True` for `sid_cache`, `explicit_server_ip` allowlist validation, identity-scoped `evict_sid` helper) and update all `evict_sid` call sites in `AMgmtClient` and `LoginCoordinator` (`W1`, `W2`, `I1`).
3. Harden `Executor._adopt_staged_session` (`arodonata-cpcrud*` default session naming, staged registry, active-`sid` reuse, `show-session` provenance check, `force_disconnect: bool = False` default, dual-error `switch-session` fallback) and add `staged_session_store` + `server_ip` removal in MCP `cpcrud_staged_session` (`C1`, `W2`, `I6`).
4. Remove direct `cache.replace_domain_rulebase` writes from `reports/placement.py`, tighten `SessionScope.resolve_owned_session` and Case 2 `show-session` cleanliness/domain checks, and wire `refresh_rulebase_fn` from `ArodonataClient.collect_change_report` / `build_change_report` (`C2`).
5. Enforce non-empty target validation, `cache_mode="cache"`, `include_global=True`, and `AmbiguousObjectError` / `match_type="ambiguous"` for `domain=None` in `SearchService.get_group_members`, `ArodonataClient.{find_object,get_group_members}`, and MCP `{show_object,get_group_members}` (`W3`, `I3`).
6. Expand adversarial unit/race tests (`W6`), sync/validate all specs under `openspec validate --specs --strict --no-interactive`, and run full quality gates.
