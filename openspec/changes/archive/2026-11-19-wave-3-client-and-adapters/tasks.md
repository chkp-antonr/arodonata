# Tasks: Wave 3 Client and Adapter Decomposition and TLS/Session Hardening

## 1. Facade & Search Decomposition

- [x] 1.1 Split `src/arodonata/client.py` into `src/arodonata/client/` (`_base`, `warmup`, `lifecycle`, `inventory`, `rulebase_reports`, `topology`, `__init__`), preserve all 61 `@traced` methods, remove dead aliases (`_warmup_*`, `_ensure_db_initialized`, `_handle_amgmt_domain_invalidated`), eliminate double `invalidate_domain()` on `publish`, and drop dead `_CaptureExplicitAuthMode` from `core/config.py`.
- [x] 1.2 Move `find_object` resolution into `SearchService.find_object()`, add `ServiceCachePort` / `AssetCachePort` fallbacks when optional services are `None`, deduplicate asset matching, and run independent cross-domain Pass-1/Pass-2 queries concurrently via `asyncio.gather()`.

## 2. Storage & Check Point Adapter Decomposition

- [x] 2.1 Split `src/arodonata/adapters/storage/cache_adapter.py` into `src/arodonata/adapters/storage/cache/` with unified SQLite/PostgreSQL `_dialect_upsert`, removing the 5 dead `*_to_record` helpers and keeping `cache_adapter.py` as a shim.
- [x] 2.2 Split `sessions.py` (`response_classifiers`, `target_resolver`, `session_cleaner`, `session_credentials`, `sessions`), guard max-sessions recovery against recursion (`allow_max_sessions_cleanup=False` + `_cleaning_max_sessions`), preserve live fresh cached SIDs across principals in `SessionCleaner`, and attempt `logout_sid` before `evict_sid` on expired owned SIDs.

## 3. Transport, TLS Hardening & Boundaries

- [x] 3.1 Split `transport.py` into `connection_pool.py`, `connector.py`, and `transport.py`, introduce `PolicyBoundSSLContext` validated by `FingerprintTCPConnector`, remove unused `_DEFAULT_CHECKPOINT_SSL_CONTEXT` and unused `transport.logger`, roll back uncommitted `TrustStore._entries` on `_save_atomic()` failure, emit first-contact TOFU `WARNING` logs, and record `arodonata.tls_decision` (including `"stored_match"`).
- [x] 3.2 Add `"adapters"` import boundary enforcement in `tests/unit/test_architecture_boundaries.py`, synchronize OpenSpec (`client-and-facade`, `transport-and-tls`), update `CHANGELOG.md`, and pass all 9 repository quality gates.
