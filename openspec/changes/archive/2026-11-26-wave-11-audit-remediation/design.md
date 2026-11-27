# Design

## Architectural Approach

Wave 11 closes remaining cross-cutting audit gaps without breaking existing public interfaces:

1. **Fail-Fast Identity & Cancellation Discipline**:
   - `SessionCleaner` always re-raises `ServerIdentityError` before general session/transport recovery.
   - `shielded_best_effort()` shields cleanup coroutines while propagating `CancelledError` and `ServerIdentityError`, and `run_write_session_lifecycle()` rolls back `publish` on cancellation or pre-send `TransportError(request_sent=False)`.
2. **Owner-Fair Bounded Staged Registries**:
   - Both `cpcrud._executor_pass._select_staged_eviction_key()` and `mcp.tools.cpcrud._select_store_eviction_key()` prioritize evicting entries from the incoming caller or multi-slot owners before single-session peers, rejecting new staged sessions cleanly in MCP when all slots are single-session peers (while discarding the new server session).
3. **Overlay & Cache Isolation**:
   - Virtual rule planning propagates `ref_action_ids`/`entity_action_ids` unconditionally on `CREATE`/`UPDATE` and skips cross-name traffic-tuple matching for `planned:` rules.
   - Topology on-demand object/global lookups avoid SQL writes during active `WriteSession`s.
4. **Spec Traceability Parity**:
   - All Wave-7, `add-asset-role-and-platform-classification`, and Wave-11 requirements are synchronized in `openspec/specs/*` and linked via `@pytest.mark.spec("SCN-...")`.
