# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Check Point native `asyncio` transport and session adapter (`arodonata.adapters.checkpoint`): `TrustStore` and `TrustPolicy` (`pinned`, `tofu`, `lab-memory` with atomic `0600` `tls_known_hosts.json` persistence and cross-IP MDS member certificate recognition), `ApiTransport` over `aiohttp` (post-handshake pre-request SHA-256 fingerprint verification, separate `connect_timeout`/`read_timeout` `ApiTimeoutError` phases, no automatic re-send after socket write, and `VerifiedConnectionPool` reusing keep-alive sockets up to 10s idle strictly for `show-*` commands), `TaskWaiter` (exponential backoff `2s..10s` polling under `task_timeout` tolerating up to 5 transient poll errors), continuity-verified object pager (`pager.py` with `±10` boundary swap window recovery and single restart on discontinuity), per-MDS-member `RateLimiter` (database slot locks + FIFO waiter queue + coalesced keepalive sweeps) and `LoginGate` (`70s` throttle recovery and fast-fail `InvalidCredentialsError`), `LoginCoordinator`, `SessionCleaner`, context-bound `WriteSession` (`SessionOverlay` updates, auto-`publish` / `discard`), and `AMgmtClient` implementing `ApiPort`.
- Core foundation (`arodonata.core`): `ArodonataSettings` (positional multi-server topology, `API_KEYS` vs `API_KEY_VARS` precedence, `api_key`/`credential`/`dynamic` auth mode resolution, timeout budgets, OTel module gating), exception hierarchy with SID/secret redaction (`errors.py`), `@traced` and `span_attrs` instrumentation (`telemetry.py`), typed domain progress events (`SyncProgressEvent`, `CPCRUDEvent` in `events.py`), `contextvars`-bound `AuthContext`, `UserContext`, and `WriteSession` with `SessionOverlay` (`context.py`), Pydantic v2 domain models (`models/`), and hexagonal protocols (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider` in `ports/`).
- SQL storage adapter (`arodonata.adapters.storage`): `DatabaseManager` (SQLite with 30s busy timeout, default in-memory `sqlite+aiosqlite:///:memory:` when `engine=None`, PostgreSQL support, and SHA-256 schema hash auto-migration via `arodonata_schema_version`), `SqlLockAdapter` (`DatabaseLockManager` over `distributed_locks` with expired lock reclamation), and `SqlCacheAdapter` with SQLModel tables (`domains`, `sid_cache`, `domain_sync_state`, `arodonata_objects`, `arodonata_services`, `assets`, and `rulebase_*`).
- SSE boundary adapter (`arodonata.adapters.sse`): `SSEEvent` model and `to_sse_event` / `stream_as_sse` converters.
- Python package structure (`pyproject.toml`, `src/arodonata/`, `tests/`) with optional extras `postgres`, `mcp`, and `all`.
- Dedicated `arodonata_services` cache specification, `(mgmt_name, domain_name, scope, item_type)` revision tracking in `domain_sync_state` (`last_published_at`, `last_session_uid`, `synced_at`), `VerifiedConnectionPool` for read-only commands, hybrid/dynamic authentication (`AuthContext` / `AuthProvider`), `contextvars`-bound `WriteSession` with `SessionOverlay`, and MCP `describe_objects` / `query_objects` / `cache_status` specifications.
- Initial repository structure, OpenSpec capability specifications, and developer tooling.
- Agent guidelines, linting rules, and workflows (`/archive-task`, `/save-plan`).
- Strict Git branching policy: separate working branches, integration to `master` only via PR and squash merge.

### Changed

- Revised all 9 OpenSpec capability specifications for Arodonata v2 clean-slate hexagonal architecture: native `aiohttp` transport (replacing `cpapi`), `SqlCacheAdapter` (replacing `PostgresCacheAdapter`/`CacheRepository`), canonical `CacheMode` names (`cache`, `smart`, `smart-fast`, `force`), paired coroutine and `stream_*` domain event APIs (removing `SSEEvent` from core), and unified `ArodonataClient` facade (replacing `arodonata.helpers`).
