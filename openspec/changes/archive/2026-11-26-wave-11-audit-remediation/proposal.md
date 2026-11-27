# Proposal

## Why

Following the merge of Wave 10 (`5357d79`), additional audit findings across transport, sessions, secret redaction, write-session cancellation safety, pagination bounds, asset linking, topology cache isolation, script repository error handling, CPCRUD planner/differ/inverse/executor, change reports, MCP tools, and Wave-7/aibuilder spec drift remained open. Remediating all remaining confirmed bugs, security findings, specification drifts, and refactoring targets in Wave 11 aligns code, tests, OpenSpec specifications, and generated documentation.

## What Changes

1. **Configuration, Pagination & Transport Sync (`DA-008`, `DA-031`)**:
   - Bound `AMgmtClient.api_query()` with `max_query_pages` (default `5000`) and `max_query_objects` (default `1000000`, `code="paging_limit_exceeded"`), and bound `fetch_paged_rulebase()` with `MAX_RULEBASE_OBJECTS = 1000000`.
   - Sync missing Wave-7 clauses in `openspec/specs/configuration/spec.md` (`REQ-CONFIG-009` bounds) and `openspec/specs/transport-and-tls/spec.md` (`REQ-TRANS-001`, `REQ-TRANS-003`, `REQ-TRANS-004`, `REQ-TRANS-007`).
2. **Sessions, Redaction, Write-Session Safety & Script Repository (`DA-009`, `DA-012`, `DA-013`, `DA-016`, `DA-017`, `DA-018`, `DA-024`, `DA-026`, `DA-041`)**:
   - Re-raise `ServerIdentityError` explicitly inside `SessionCleaner`, prevent `auth_identity=None` fallback in `LoginCoordinator.keepalive_sid()` while routing dedicated SIDs, guard `evict_sid`, and pass `prevalidated_target` in `get_readonly_session()`.
   - Extend `redact_sid()` for key=value secrets and DB URL passwords; add `shielded_best_effort()` and wrap write-session `publish`/`discard`/`logout` against `CancelledError` and pre-send `TransportError`; discard failed `_mutate_object()` calls cleanly.
   - Add `RepositoryScriptUnsupportedError`, scrub active `WriteSession` SIDs in `ScriptRepositoryService`, and decompose task decoding & SID scrubbing helpers.
3. **Asset Linking & Gateway Topology (`DA-004`, `DA-010`, `DA-014`, `DA-034`, `DA-039`, `DA-055`, `DA-056`)**:
   - Add `vsx_cluster_member` and `vs_netobj` aliases, centralize self-link and invalid child exclusions across `_asset_linking.py`, and decompose `reconcile_cross_domain()`.
   - Skip persistent SQL cache writes under active `WriteSession` in topology resolution, enforce `verify_session_clean()` in targeted refresh, scope CLI targets to `gateway_asset.mgmt_name`, match all canonical IDs in annotations, and preserve `mask-length: 0` prefixes.
4. **CPCRUD & Change Reports (`DA-005`, `DA-021`, `DA-027`, `DA-028`, `DA-029`, `DA-030`, `DA-033`, `DA-042`, `DA-045`, `DA-047`, `DA-057`)**:
   - Reject blank/duplicate operation `id`s via shared verb normalization (`extract_raw_verb`/`normalize_operation_verb`), fix intra-plan virtual rule overlays and traffic-tuple collision avoidance, preserve `ip_protocol=0` and `AccessRuleEntry` inline layers, and restore empty `description`/`additional-categories` on `inverse()` `UPDATE`.
   - Return isolated per-call `ApplyReport` via `CPCRUDCompletedEvent.report`, enforce owner-fair staged registry eviction (`_select_staged_eviction_key`), add `"range_session_not_found"` to `WarningCode`, omit dates when `RangeScope(to_session=...)` is set, and introduce `_OwnedSessionContext`.
5. **MCP Tools & Asset Classification Specs (`DA-022`, `DA-032`, `DA-040`, `DA-049`, `DA-052`, `DA-054`)**:
   - Update error messages to `list_domains`, add multi-domain `domains` support to `_upgrade_uninitialized_cache_mode()`, factor shared `_run_typed_collection_tool()`, expose `roles`/`platforms` (`list_assets`, `query_objects`) and `is_policy_target`/`is_execution_target` (`query_objects`), and protect single-session peers in `staged_session_store`.

## Capabilities

### Modified Capabilities

- `configuration`: `REQ-CONFIG-009` bounds + pagination caps (`SCN-CONFIG-009-1`, `SCN-CONFIG-009-2`).
- `transport-and-tls`: Wave-7 sync on `REQ-TRANS-001`, `REQ-TRANS-003`, `REQ-TRANS-004`, `REQ-TRANS-007`.
- `sessions-and-mdm`: Add `REQ-SESS-015` (`SCN-SESS-015-1`).
- `client-and-facade`: Add `REQ-CLIENT-020` (`SCN-CLIENT-020-1`, `SCN-CLIENT-020-2`).
- `gateway-topology`: Add `REQ-TOPO-023` (`SCN-TOPO-023-1`).
- `cpcrud`: Add `REQ-CPCRUD-018` (`SCN-CPCRUD-018-1`, `SCN-CPCRUD-018-2`).
- `change-reports`: Add `REQ-REPORT-009` (`SCN-REPORT-009-1`).
- `mcp-server`: Add `REQ-MCP-017` (`SCN-MCP-017-1`).

## Impact

- Source modules across `adapters/checkpoint/`, `core/`, `client/`, `rulebase/`, `cpcrud/`, `reports/`, and `mcp/`, plus OpenSpec canonical specs and `docs-notebooklm/*` bundles.
