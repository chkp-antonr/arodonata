# Design: Milestone 1 — Core Foundation, Ports, and SQL Storage Adapter

## Context

See `proposal.md` for motivation and `openspec/changes/archive/2026-10-23-revise-v2-architecture-specs/design.md` for the overarching v2 architectural decisions. Milestone 1 establishes the zero-dependency hexagonal core (`src/arodonata/core/`) and the SQL/SSE adapter layers (`src/arodonata/adapters/storage/`, `src/arodonata/adapters/sse/`).

## Goals / Non-Goals

**Goals:**

- Keep `arodonata.core` strictly free of transport (`aiohttp`), ORM (`sqlalchemy`, `sqlmodel`), or MCP (`mcp`, `starlette`) imports.
- Provide deterministic, environment-and-kwarg-driven settings resolution (`ArodonataSettings`) supporting multi-server positional pairing, `API_KEYS` over `API_KEY_VARS` precedence, `auth_mode` inference (`"api_key"`, `"credential"`, `"dynamic"`), socket read timeout helpers, and OpenTelemetry module span gating.
- Provide `contextvars` state management (`AuthContext`, `UserContext`, `WriteSessionState`, and `SessionOverlay`) so read operations in higher layers can transparently overlay uncommitted session creations, updates, and deletions.
- Implement `DatabaseManager` with automatic `sqlite+aiosqlite:///:memory:` fallback when `engine=None`, SQLite `PRAGMA busy_timeout=30000`, and SHA-256 schema hash auto-migration (`arodonata_schema_version`).
- Implement `SqlLockAdapter` (`DatabaseLockManager`) with atomic expiration reclamation on `distributed_locks` and `SqlCacheAdapter` covering all domain, SID, sync state, object, service, asset, and rulebase tables.
- Provide `adapters/sse` to convert `SyncProgressEvent` and `CPCRUDEvent` models into `SSEEvent` instances.

**Non-Goals:**

- Implementing HTTP/TLS transport (`adapters/checkpoint`), `LoginCoordinator`, or `DomainSyncCoordinator` orchestration (deferred to Milestones 2 and 3).

## Decisions

### 1. Configuration Resolution (`src/arodonata/core/config.py`)

- `ArodonataSettings` subclasses `pydantic_settings.BaseSettings` with `env_file=None` and `extra="ignore"`, reading `ARODONATA_*` prefixed variables alongside top-level topology aliases (`MGMT_NAMES`, `MGMT_SERVERS`, `API_KEYS`, `API_KEY_VARS`, `MGMT_IP`, `MGMT_PORT`, `MGMT_USER`, `MGMT_PASSWORD`, `MGMT_API_KEY`).
- Precedence order: explicit constructor keyword arguments > explicit `API_KEYS` / `ARODONATA_API_KEYS` > `API_KEY_VARS` / `ARODONATA_API_KEY_VARS` (which dereferences named environment variables per server position).
- `auth_mode` resolution:
  - `"api_key"` when one or more API keys are resolved (validating that `len(mgmt_names) == len(mgmt_servers) == len(api_keys)` and raising `ConfigurationError` on mismatch).
  - `"credential"` when `username` and `password` are provided (requiring at least one server via `mgmt_ip` or `mgmt_servers`, otherwise raising `MissingConfigurationError`).
  - `"dynamic"` when management server topology (`mgmt_servers` or `mgmt_ip`) is configured without static API keys or static username/password (or when explicitly set to `"dynamic"`), deferring credentials to runtime `AuthContext` or `AuthProvider`.
- Socket timeout helpers:
  - Connect/handshake timeout: `connect_timeout` (default `30.0`s).
  - Per-call read timeout: `budget + 5.0` when `budget` is given, or `max(api_timeout, login_timeout) + 5.0` when no per-call budget is specified.
- OpenTelemetry module gating:
  - `trace_modules` defaults to `""`. `trace_modules_rules` parses `"arodonata:on,arodonata.api.client:off"` into `{"arodonata": True, "arodonata.api.client": False}`. When `trace_modules` is empty, `apply_trace_modules()` is a no-op so host application tracing rules are never overwritten.

### 2. Context Propagation & Read-Your-Own-Writes Overlay (`src/arodonata/core/context.py`)

- `SessionOverlay` stores uncommitted mutations per `(object_kind, uid)` (`upserted: dict[str, dict[str, Any]]`) and deleted UIDs (`deleted: set[str]`), plus name-to-UID tracking so subsequent reads (`apply_to_objects`, `apply_to_services`) merge created/updated items and filter out deleted items without mutating the shared SQLite/PostgreSQL cache.
- `ContextVar` bindings (`current_auth_context`, `current_user_context`, `current_write_session`) expose clean context managers (`auth_context_scope`, `user_context_scope`, `write_session_scope`).

### 3. Deterministic Schema Hashing & Auto-Migration (`src/arodonata/adapters/storage/database.py`)

- `compute_schema_hash(metadata)` serializes all table names, column definitions (name, normalized type, nullable, primary key), and index signatures in sorted order and computes a SHA-256 hex digest.
- On `DatabaseManager.initialize()`:
  1. Ensure `arodonata_schema_version` exists.
  2. Query whether `compute_schema_hash()` is already present in `arodonata_schema_version`. If present, skip table/column/index inspection and mark initialized.
  3. Otherwise, run `metadata.create_all`, inspect existing tables via `sqlalchemy.inspect`, add any missing columns (`ALTER TABLE ... ADD COLUMN ...`) and missing indexes (`CREATE INDEX IF NOT EXISTS ...`), and insert the new `schema_hash` record.
- When `engine=None` is passed to `DatabaseManager`, it creates an internal `sqlite+aiosqlite:///:memory:` engine with `owns_engine=True` and attaches a SQLite `connect` listener executing `PRAGMA busy_timeout=30000`.

### 4. Distributed Lock Reclamation (`src/arodonata/adapters/storage/lock_adapter.py`)

- `SqlLockAdapter` (`DatabaseLockManager`) manages rows in `distributed_locks` (`lock_key`, `owner_id`, `acquired_at`, `expires_at`).
- When acquiring `lock_key`, if an existing row has `expires_at <= now`, `SqlLockAdapter` atomically deletes/updates the expired row and claims the lock for the new `owner_id`, preventing deadlocks after worker crashes.

### 5. Unified Sync State & Type-Scoped Object/Service Tables (`src/arodonata/adapters/storage/cache_adapter.py`)

- `domain_sync_state` uses composite key `id = "{mgmt_name}:{domain_name}:{scope}:{item_type}"` and stores `last_published_at`, `last_session_uid`, `synced_at`, `status`, `object_count`, and `last_error`.
- `SqlCacheAdapter.replace_domain_objects(mgmt_name, domain_name, objects, types=...)` deletes only rows matching `(mgmt_name, domain_name, type IN types)` before inserting new `CPObjectRecord` rows, preserving other cached types in that domain.
- `SqlCacheAdapter.replace_domain_services(mgmt_name, domain_name, services, types=...)` similarly scopes replacement in `arodonata_services` by `type IN types`.
- `SIDCacheRecord.__repr__` and `SIDCacheEntry.__repr__` mask/omit `sid` so session tokens never leak into logs or tracebacks.

## Risks / Trade-offs

- **[Risk] SQLite in-memory connection sharing across async sessions** → Mitigation: Use `StaticPool` (or shared in-memory URI with `check_same_thread=False`) for `:memory:` SQLite engines so all `AsyncSession` instances see the same schema and data within the `DatabaseManager` lifecycle.
- **[Risk] Concurrent lock contention on `distributed_locks`** → Mitigation: Handle `IntegrityError` on insert and perform conditional update/delete where `expires_at <= now`, verified by unit tests simulating expired and active locks.
