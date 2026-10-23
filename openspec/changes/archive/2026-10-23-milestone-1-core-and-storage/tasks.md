# Tasks: Milestone 1 — Core Foundation, Ports, and SQL Storage Adapter

## 1. Core Configuration, Exceptions, Events, Context, and Telemetry

- [x] 1.1 Implement `src/arodonata/core/errors.py` (exception hierarchy and SID/secret redaction helpers) and `src/arodonata/core/telemetry.py` (`@traced`, `span_attrs`, `apply_trace_modules`, SID/secret masking) and verify unit tests pass
- [x] 1.2 Implement `src/arodonata/core/config.py` (`ArodonataSettings`, positional server topology `mgmt_names`/`mgmt_servers`/`api_keys`/`API_KEY_VARS`, `auth_mode` resolution, timeout budgets, and `trace_modules` rules) and verify unit tests in `tests/test_config.py` pass
- [x] 1.3 Implement `src/arodonata/core/events.py` (`SyncProgressEvent` and `CPCRUDEvent` hierarchies without `SSEEvent`) and `src/arodonata/core/context.py` (`contextvars` for `AuthContext`, `UserContext`, and `WriteSession` with `SessionOverlay`) and verify unit tests pass

## 2. Core Domain Models and Hexagonal Ports

- [x] 2.1 Implement `src/arodonata/core/models/` (Pydantic v2 models for sessions, domains, `CPObject`, `CPService`, `Asset`, sync state, rulebase entries, and API call results) and `src/arodonata/core/ports/` (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`) and verify unit tests and `mypy --strict` pass

## 3. SQL Storage Adapter (`DatabaseManager`, `SqlLockAdapter`, `SqlCacheAdapter`)

- [x] 3.1 Implement `src/arodonata/adapters/storage/tables.py` (SQLModel tables: `arodonata_schema_version`, `distributed_locks`, `domains`, `sid_cache` without SID in `repr()`, `domain_sync_state`, `arodonata_objects`, `arodonata_services`, `assets`, and `rulebase_*`) and `src/arodonata/adapters/storage/database.py` (`DatabaseManager` with default in-memory SQLite, 30s busy timeout, and SHA-256 schema hash auto-migration) and verify SQLite migration tests pass
- [x] 3.2 Implement `src/arodonata/adapters/storage/lock_adapter.py` (`SqlLockAdapter` / `DatabaseLockManager` with expired `expires_at` reclamation) and `src/arodonata/adapters/storage/cache_adapter.py` (`SqlCacheAdapter` implementing `CachePort` with type-scoped object/service replacement) and verify unit tests in `tests/test_storage.py` pass

## 4. SSE Event Converter and Final Verification

- [x] 4.1 Implement `src/arodonata/adapters/sse/` (`SSEEvent` and domain event converter) and verify unit tests in `tests/test_sse_and_events.py` and all quality gates (`pytest`, `mypy src`, `ruff`, `markdownlint`, `openspec validate`) pass
