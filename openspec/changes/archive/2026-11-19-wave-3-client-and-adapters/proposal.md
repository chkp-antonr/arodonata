# Proposal: Wave 3 Client and Adapter Decomposition and TLS/Session Hardening

## Why

Monolithic modules in `arodonata.client` (`client.py`, 2,837 LOC), `arodonata.adapters.storage.cache_adapter` (`cache_adapter.py`, 2,064 LOC), `arodonata.adapters.checkpoint.sessions` (`sessions.py`, 1,462 LOC), and `arodonata.adapters.checkpoint.transport` (`transport.py`, 1,070 LOC) coupled orchestration, persistence, session lifecycle, and TLS/HTTP transport concerns in oversized files. Additionally, Wave 3 audit findings identified SAST #3/#4 TLS audit gaps, concurrent TOFU in-memory poisoning on mismatch, recursive max-sessions recovery, live multi-principal SID eviction when `seed_system_sid=False`, and missing cache-only fallbacks in `SearchService.find_object()`.

## What Changes

- Decompose `src/arodonata/client.py` into the acyclic `src/arodonata/client/` package (`_base`, `warmup`, `lifecycle`, `inventory`, `rulebase_reports`, `topology`, `__init__`), move `find_object` resolution into `SearchService.find_object()`, eliminate duplicate `invalidate_domain()` calls on `publish`, and remove dead `ArodonataSettings._CaptureExplicitAuthMode` and unused warmup/helper aliases.
- Decompose `src/arodonata/adapters/storage/cache_adapter.py` into `src/arodonata/adapters/storage/cache/` (`_base`, `mappers`, `rulebase_mappers`, `control`, `inventory`, `topology`, `rulebase`, `__init__`) with unified SQLite/PostgreSQL upserts and removal of 5 unused `*_to_record` helpers while keeping `cache_adapter.py` as a backward-compatible shim.
- Split `sessions.py` (`response_classifiers`, `target_resolver`, `session_cleaner`, `session_credentials`, `sessions`), guard `LoginCoordinator` max-sessions recovery against unbounded recursion, encapsulate coordinator helpers, and preserve live fresh cached SIDs across principals during `SessionCleaner` runs while logging out and evicting only the active principal's expired sessions.
- Split `transport.py` (`connection_pool`, `connector`, `transport`), bind `SSLContext` creation to `TrustPolicy` via `PolicyBoundSSLContext` (removing the unreferenced global `_DEFAULT_CHECKPOINT_SSL_CONTEXT`), roll back failed atomic `TrustStore.record()` persists cleanly, emit structured `WARNING`/`ERROR` audit logs and `arodonata.tls_decision` spans (mapping legacy `"stored"` entries to `"stored_match"`), and extend AST boundary tests in `tests/unit/test_architecture_boundaries.py` to cover the `"adapters"` layer.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `client-and-facade`: Enforce AST hexagonal import boundaries for `adapters` alongside `core`, `cpcrud`, `rulebase`, and `reports` (`REQ-CLIENT-018` / `SCN-CLIENT-018-1`).
- `transport-and-tls`: Bind `PolicyBoundSSLContext` creation to validated `TrustPolicy`, emit TOFU first-contact `WARNING` audit logs, and record `arodonata.tls_decision` span attributes including `"stored_match"` (`REQ-TRANS-002` / `SCN-TRANS-002-6`).

## Impact

- `src/arodonata/client/` (replacing `src/arodonata/client.py`), `src/arodonata/core/services/search_service.py`, `src/arodonata/core/config.py`.
- `src/arodonata/adapters/storage/cache/` and `src/arodonata/adapters/storage/cache_adapter.py`.
- `src/arodonata/adapters/checkpoint/` (`sessions.py`, `session_cleaner.py`, `session_credentials.py`, `response_classifiers.py`, `target_resolver.py`, `transport.py`, `connection_pool.py`, `connector.py`, `tls.py`, `__init__.py`).
- `openspec/specs/client-and-facade/spec.md`, `openspec/specs/transport-and-tls/spec.md`, `tests/unit/`, and `CHANGELOG.md`.
