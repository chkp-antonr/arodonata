# Proposal

## Why

An independent Principal Security Architect & Spec Compliance Audit (`docs/_audit_/2610301251.md`) identified 2 Critical regressions (`C1`, `C2`), 6 Warnings (`W1`–`W6`), and 6 Improvements (`I1`–`I6`) across the `v2.1.0` baseline and commit `f3711d2` (`2026-10-30-post-publish-owned-session-and-placement`) on `fix/post-publish-owned-session-placement`. Resolving every finding in a cohesive OpenSpec remediation change (`audit-remediation-261030`) is required before merging to `master_v2` so staged-session adoption cannot hijack foreign administrator sessions, change reporting cannot corrupt the shared rulebase cache, cross-domain lookups remain bounded and unambiguous, and `openspec validate --specs --strict` passes 10/10.

## What Changes

- **CPCRUD Staged-Session Provenance & Non-Disruptive Adoption (`C1`, `I6`, `W4`)**:
  - Remove unconditional `"disconnect-active-session": True` from `Executor._adopt_staged_session` (`src/arodonata/cpcrud/executor.py`); default takeover to non-disruptive (`"disconnect-active-session"` omitted/`False`) and expose disruptive takeover strictly as an explicit library-only keyword (`force_disconnect: bool = False`) that is never reachable from MCP.
  - Default dedicated CPCRUD session names to `"arodonata-cpcrud-staged"` (when `keep_session=True`) or `"arodonata-cpcrud"` when omitted, and track staged sessions (`(mgmt_name, domain_key, session_uid)`) created in-process.
  - When an explicit `sid` is still active and `show-session {}` confirms `uid == session_uid` in an unpublished/non-discarded state, reuse `sid` directly without self-takeover.
  - Before adopting via `fresh_sid`, inspect `show-session {"uid": session_uid}` and refuse unless the session is open (not `published`/`discarded`) and either recorded in the client's staged-session registry or carries an `arodonata*` session name / `application == "arodonata"`.
  - Retain `switch-session {"uid": session_uid}` strictly as a provenance-verified same-administrator fallback after `take-over-session` rejection, reporting both `take-over-session` and `switch-session` errors on failure (`I6`) and always logging out `fresh_sid` when adoption fails.
- **Change-Report Cache Isolation, Strict Post-Publish Verification & Cold-Cache Delegation (`C2`, `W4`)**:
  - Eliminate all direct `cache.replace_domain_rulebase(...)` writes from `src/arodonata/reports/placement.py` so `RulebaseRefreshService` under `DomainSyncCoordinator` remains the sole writer to `arodonata_rulebase_*`.
  - Preserve the valid `change-reports` enhancements from the superseded draft: object-only session short-circuit (`numbering_source = "not_applicable"`, `numbering_basis = ""`, suppressing `.basis-banner` and `Numbering Basis`), bare `layer_uid` name resolution in `collector.py`, and post-publish `OwnedSession` live in-memory numbering.
  - Tighten post-publish Case 2 verification in `placement.py` and `SessionScope.resolve_owned_session` (`reports/models.py`): require `changes`, `locks`, and `number-of-published-changes` to be explicitly zero (`changes` and `locks` present and `0`, `number-of-published-changes` `0` when present/applicable), verify `show-session` domain matches the target `domain_name` (and `OwnedSession.mgmt_name` / `OwnedSession.domain` when set), and prevent unkeyed `OwnedSession(session_uid=None)` from matching multi-session `SessionScope` lists (`len(session_uids) > 1`).
  - On cold rulebase cache (`not has_cached_rules`), delegate warming via an optional `refresh_rulebase_fn` callback wired by `ArodonataClient.collect_change_report` to `client.refresh_rulebases(mgmt_name=..., domains=[domain_name], mode="smart")` (acquiring the per-domain distributed lock, checking `verify_session_clean`, and recording `DomainSyncState`), falling back to a purely in-memory `collect_domain_rulebase_snapshot` read when standalone `collect_change_report(api, cache, ...)` is called without a client coordinator.
- **Identity-Scoped SID Eviction, Server-Enforced Read-Only SIDs, Trusted `server_ip` & Cancellation Hygiene (`W1`, `W2`, `I1`, `I2`, `I4`)**:
  - Pass the resolved `auth_identity` to `cache.evict_sid(mgmt_name, dom_key, auth_identity=...)` across all four eviction sites in `AMgmtClient.api_call` (`src/arodonata/adapters/checkpoint/client.py`) and in `LoginCoordinator.logout_all` (`sessions.py`) (`W1`).
  - Validate `explicit_server_ip` in `LoginCoordinator.resolve_target_ips` (`src/arodonata/adapters/checkpoint/sessions.py`) against configured server endpoints and cached domain `active_ip`, `active_mds_ip`, and `standby_ips` / MDS member addresses for `mgmt_name`, rejecting arbitrary untrusted hosts (`W2`).
  - Authenticate shared `arodonata_sid_cache` sessions in `LoginCoordinator.get_readonly_session` with `read_only=True` (`"read-only": True` in Check Point `login` payload) for server-enforced write/lock prevention (`I1`).
  - Add `exclude=True` to `SIDCacheEntry.sid` so `model_dump()` / `model_dump_json()` never serialize raw SIDs, and include `auth_identity` in `SIDCacheEntry`'s default `id` (`f"{mgmt_name}:{domain_name}:{auth_identity}"`) (`I2`).
  - Replace `with suppress(BaseException):` around `asyncio.shield(self._lock_port.release(...))` in `RateLimiter.slot` (`src/arodonata/adapters/checkpoint/rate_limiter.py`) with `suppress(Exception)` so `asyncio.CancelledError` is re-raised cleanly after `_release_local_fifo_slot` runs in `finally` (`I4`).
- **Cache-Only Cross-Domain Lookups, Ambiguity Detection & Non-Empty Target Validation (`W3`, `I3`, `W4`)**:
  - Validate `name_or_uid` / `group_name_or_uid` as required non-empty strings (raising `ValidationError` when blank) in `ArodonataClient.find_object`, `ArodonataClient.get_group_members`, and `SearchService.get_group_members` (`I3`).
  - When `domain=None` (and `name_or_uid` is not a domain-qualified composite ID `mgmt:domain:name`), execute cross-domain lookups strictly with `cache_mode="cache"` and `include_global=True` so single lookups never trigger whole-MDS domain logins/syncs (`W3`).
  - Introduce `AmbiguousObjectError` (subclass of `ValidationError` carrying structured candidate metadata across matching domains): raise `AmbiguousObjectError` in `ArodonataClient.find_object` and `get_group_members` when `domain=None` matches entities in more than one domain, and return a structured `match_type="ambiguous"` candidate envelope in MCP `show_object` (and actionable candidate details in MCP `get_group_members`) (`W3`).
- **MCP Staged-Session Registry & Parameter Hardening (`C1`, `W2`, `W4`)**:
  - Record `(mgmt_name, domain_key, session_uid)` entries created by `cpcrud_apply(..., no_publish=True, keep_session=True)` in a bounded in-memory registry inside `register_mcp_tools` (`src/arodonata/mcp/tools.py`), refuse any `cpcrud_staged_session` call for an unregistered `session_uid` before contacting Check Point, and remove the `server_ip` parameter from `cpcrud_staged_session` (`C1`, `W2`).
- **Strict OpenSpec Specification Compliance & Adversarial Regression Tests (`W5`, `W6`, `I5`)**:
  - Refactor the four over-long (`>500` chars) requirement statements in `cache-and-sync`, `client-and-facade`, and `mcp-server` into concise single-behavior requirements with scenarios so `openspec validate --specs --strict --no-interactive` passes 10/10 (`W5`, `I5`).
  - Replace permissive unit assertions with adversarial negative and race tests covering foreign/active session refusal in `_adopt_staged_session` and MCP `cpcrud_staged_session`, concurrent refresh vs report placement, missing/dirty `show-session` fields and wrong-domain SIDs in Case 2, hybrid-auth `evict_sid` isolation, untrusted `explicit_server_ip` rejection, cross-domain cache-only ambiguity, `SIDCacheEntry` dump redaction, and `RateLimiter.slot` cancellation propagation (`W6`).

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `cpcrud`: Enforce `show-session` provenance verification before staged-session adoption, default to non-disruptive `take-over-session` (`force_disconnect: bool = False` library-only), reuse active owned `sid` without self-takeover, gate `switch-session` fallback on provenance while reporting both errors on failure, and default CPCRUD session names to `arodonata-cpcrud*`.
- `change-reports`: Prohibit direct `CachePort.replace_domain_rulebase` writes from `arodonata.reports`, enforce full dirty-field (`changes`, `locks`, `number-of-published-changes`), domain, and `SessionScope` ownership checks on post-publish `OwnedSession` in-memory numbering, delegate cold-cache warming to `DomainSyncCoordinator` / `RulebaseRefreshService` when called via `ArodonataClient` (in-memory-only standalone), skip placement/banners on object-only sessions, and resolve bare `layer_uid` UUIDs.
- `sessions-and-mdm`: Pass `auth_identity` to all `evict_sid` calls, validate `explicit_server_ip` against configured/discovered server IPs for `mgmt_name`, authenticate shared `arodonata_sid_cache` sessions with `"read-only": true`, exclude `SIDCacheEntry.sid` from model dumps while including `auth_identity` in default `id`, and propagate `CancelledError` after releasing `RateLimiter` slots.
- `client-and-facade`: Support cross-domain `domain=None` in `find_object` and `get_group_members` using `cache_mode="cache"` and `include_global=True` with non-empty target validation and `AmbiguousObjectError` on multi-domain collisions, wire coordinator-backed cold-cache rulebase refresh into `ArodonataClient.collect_change_report`, and split over-long requirement text for strict OpenSpec validation.
- `cache-and-sync`: Enforce `DomainSyncCoordinator` / `RulebaseRefreshService` as the sole writer to shared `arodonata_rulebase_*` tables, align `SearchService.get_group_members` with non-empty validation, `cache_mode="cache"`, `include_global=True`, and `AmbiguousObjectError` when `domain=None`, and split the two over-long requirements (`>500` chars) for strict OpenSpec validation.
- `mcp-server`: Restrict `cpcrud_staged_session` to `session_uid`s staged by `cpcrud_apply(keep_session=True)` in the same MCP server instance, remove `server_ip` from `cpcrud_staged_session`, enforce cache-only cross-domain `show_object` / `get_group_members` with `match_type="ambiguous"` candidate reporting, and split the over-long tool-surface requirement for strict OpenSpec validation.

## Impact

- **Affected Code**: `src/arodonata/cpcrud/{executor,service}.py`, `src/arodonata/reports/{models,collector,placement,renderer}.py`, `src/arodonata/adapters/checkpoint/{client,sessions,rate_limiter}.py`, `src/arodonata/core/{errors,models/domains}.py`, `src/arodonata/core/services/search_service.py`, `src/arodonata/client.py`, `src/arodonata/mcp/tools.py`, `.ruff.toml`, and `tests/unit/`.
- **Public API & MCP Surface**:
  - New `AmbiguousObjectError` (subclass of `ValidationError`) exported from `arodonata.core.errors` and `arodonata`.
  - `CPCRUDService.publish_staged_session`, `stream_publish_staged_session`, and `discard_staged_session` (and `ArodonataClient` delegates) gain keyword-only `force_disconnect: bool = False` (library-only; omitted from MCP).
  - MCP `cpcrud_staged_session` drops the `server_ip` parameter and rejects session UIDs not staged by `cpcrud_apply(keep_session=True)` on that MCP server.
  - `SIDCacheEntry.model_dump()` / `model_dump_json()` omit `sid` (`exclude=True`).
- **OpenSpec Hygiene**: Adds complete spec deltas for all previously un-specced `f3711d2` behavior (`W4`) and brings all 10 canonical specifications to 10/10 under `openspec validate --specs --strict --no-interactive`.
