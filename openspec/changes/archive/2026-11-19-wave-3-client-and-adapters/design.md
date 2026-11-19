# Design: Wave 3 Client and Adapter Decomposition and TLS/Session Hardening

## Context

Phase 2 architectural refactoring decomposed the four largest remaining modules (`client.py`, `cache_adapter.py`, `sessions.py`, `transport.py`) into focused, acyclic packages under `src/arodonata/` while closing SAST #3/#4 and resolving post-decomposition audit findings F1–F10.

## Goals / Non-Goals

- **Goals**:
  - Keep every module concise (`<= 750` LOC) with zero circular imports and full `@traced` span parity (61 traced methods on `ArodonataClient`).
  - Close SAST #3/#4 by auditing first-contact TOFU events, recording `arodonata.tls_decision` span attributes, binding `PolicyBoundSSLContext` to a validated `TrustPolicy`, and preventing rejected concurrent TOFU fingerprints from remaining trusted in memory.
  - Prevent `SessionCleaner` max-sessions infinite recursion and preserve live cached SIDs across principals and domains.
  - Enforce AST import isolation on the `"adapters"` layer in `tests/unit/test_architecture_boundaries.py`.
- **Non-Goals**:
  - Changing Check Point Web API wire payloads, database schema hashes, or removing public compatibility re-exports required by existing consumers.

## Decisions

1. **Client Facade Mixins (`src/arodonata/client/`)**: Compose `ArodonataClient` via `ClientBase` -> `ClientLifecycleMixin` -> (`ClientInventoryMixin`, `ClientRulebaseReportsMixin`, `ClientTopologyMixin`) with shared `logger = arlogi.get_logger("arodonata.client")` and a single late-bound `on_domain_invalidated` path to avoid double invalidation on `publish`.
2. **Search Fallback & Concurrency (`SearchService.find_object`)**: Fall back to `self._cache.get_services()` (+ `ServiceCacheService.apply_context_overlay`) and `self._cache.get_assets()` when optional `service_cache`/`asset_service` dependencies are omitted, and execute independent Pass-1/Pass-2 cross-domain queries concurrently with `asyncio.gather()` while reusing loaded assets across passes.
3. **Policy-Bound TLS & Atomic Rollback (`tls.py`, `connector.py`)**: Return `PolicyBoundSSLContext` (subclass of `ssl.SSLContext` carrying `trust_policy_mode` and weakref `trust_policy`) from `TrustPolicy.create_ssl_context()`, validate `TrustPolicy` in `FingerprintTCPConnector`, serialize from `merged` in `_save_atomic()`, and commit `self._entries = merged` only after `os.replace()`.
4. **Non-Recursive Cleanup (`sessions.py`, `session_cleaner.py`)**: Pass `allow_max_sessions_cleanup=False` from `SessionCleaner` and maintain `_cleaning_max_sessions` per `mgmt_name`; skip any cached SID that is fresh or owned by another `auth_identity`, and attempt `logout_sid` before `evict_sid` when reclaiming an expired cached SID of the active identity.
