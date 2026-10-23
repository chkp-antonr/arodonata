# Proposal: Milestone 1 — Core Foundation, Ports, and SQL Storage Adapter

## Why

With the Arodonata v2 architecture and canonical specifications established in `openspec/specs/`, the project requires the foundational core layer (`src/arodonata/core/`) and database storage/SSE adapters (`src/arodonata/adapters/storage/`, `src/arodonata/adapters/sse/`) before transport, synchronization, rulebase, CPCRUD, and MCP layers can be built on top of hexagonal ports.

## What Changes

- Implement `src/arodonata/core/config.py`: `ArodonataSettings` (`pydantic-settings` without implicit `.env` loading), positional server topology (`mgmt_names`, `mgmt_servers`, `api_keys` / `API_KEY_VARS` with `API_KEYS` precedence), authentication mode resolution (`"api_key"`, `"credential"`, `"dynamic"`), distinct operational timeout budgets (`connect_timeout`, `api_timeout`, `login_timeout`, `task_timeout`, `rate_limit_slot_timeout`), and OpenTelemetry span module gating rules (`trace_modules`).
- Implement `src/arodonata/core/errors.py`: domain, configuration, authentication, transport, task, and storage exception hierarchy with secret/SID redaction helpers.
- Implement `src/arodonata/core/events.py`: typed domain progress events (`SyncProgressEvent`, `CPCRUDEvent`, and concrete event variants) completely decoupled from HTTP/SSE transport.
- Implement `src/arodonata/core/context.py`: `contextvars`-backed `AuthContext`, `UserContext`, and active `WriteSession` state with an in-memory `SessionOverlay` (`upserted` models and `deleted` UID tombstones) for read-your-own-writes isolation.
- Implement `src/arodonata/core/telemetry.py`: provider-agnostic OpenTelemetry `@traced` wrapper, `span_attrs` helper attaching `arodonata.*`-namespaced attributes, module gating registration, and strict SID/secret masking.
- Implement `src/arodonata/core/models/`: Pydantic v2 domain models for API results, sessions, domains, network objects (`CPObject` and typed views), services (`CPService` and typed views), gateway/server assets (`Asset`), sync outcomes (`RefreshOutcome`, `DomainSyncStatus`), and search results.
- Implement `src/arodonata/core/ports/`: hexagonal `Protocol` interfaces (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`).
- Implement `src/arodonata/adapters/storage/`:
  - `DatabaseManager`: async SQLAlchemy 2.0+ / SQLModel engine management supporting SQLite (`sqlite+aiosqlite:///:memory:` default when `engine=None`, 30s busy timeout) and PostgreSQL (`asyncpg`), deterministic `compute_schema_hash` SHA-256 auto-migration tracked in `arodonata_schema_version`, and safe missing column/index evolution.
  - `SqlLockAdapter` (`DatabaseLockManager`): cross-process distributed locking over `distributed_locks` with atomic expired-lock reclamation (`expires_at`).
  - `SqlCacheAdapter` and SQLModel tables: `domains`, `sid_cache` (strictly omitting `sid` from `repr()`), `domain_sync_state` (keyed by `{mgmt_name}:{domain_name}:{scope}:{item_type}` with `last_published_at`, `last_session_uid`, `synced_at`, `status`, `last_error`), `arodonata_objects`, `arodonata_services`, `assets`, and `rulebase_*` snapshot tables (`rulebase_access`, `rulebase_nat`, `rulebase_https`, `rulebase_threat`, `rulebase_layer`, `rulebase_section`, `rulebase_package_layer`).
- Implement `src/arodonata/adapters/sse/`: `SSEEvent` model and converter translating `SyncProgressEvent` and `CPCRUDEvent` instances into Server-Sent Events payloads.

## Capabilities

### New Capabilities

<!-- None: implements existing canonical specifications. -->

### Modified Capabilities

<!-- None: no spec-level requirements change; skip_specs is enabled in .openspec.yaml. -->

## Impact

- **Codebase**: Adds `src/arodonata/core/`, `src/arodonata/adapters/storage/`, and `src/arodonata/adapters/sse/`.
- **Tests**: Adds comprehensive unit and integration tests on in-memory and file-backed SQLite in `tests/`.
