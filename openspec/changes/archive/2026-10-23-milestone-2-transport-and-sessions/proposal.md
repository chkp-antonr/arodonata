# Proposal: Milestone 2 — Native Asyncio Check Point Transport, TLS, and Sessions

## Why

With the core hexagonal contracts (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`) and SQL storage adapters (`DatabaseManager`, `SqlCacheAdapter`, `SqlLockAdapter`) established in Milestone 1, Arodonata v2 requires the native `asyncio` Check Point Management Web API adapter (`src/arodonata/adapters/checkpoint/`) to replace the legacy synchronous `cpapi` SDK and manage TLS certificate fingerprint trust, read-only keep-alive connection pooling, asynchronous server task polling, continuity-verified pagination, per-MDS-member concurrency and login rate limiting, and session lifecycle management (`sid_cache`, `WriteSession`, `SessionCleaner`, and `AMgmtClient`).

## What Changes

- Implement `src/arodonata/adapters/checkpoint/tls.py`: `TrustStore` and `TrustPolicy` supporting `"pinned"`, `"tofu"`, and `"lab-memory"` (gated by `ARODONATA_LAB`), atomic `tls_known_hosts.json` persistence with mode `0600`, cross-IP MDS member certificate fingerprint recognition (`known-identity`), and strict non-retryable `ServerIdentityError` handling (`UnknownServerCertificateError`, `CertificateMismatchError`, `TrustStoreError`).
- Implement `src/arodonata/adapters/checkpoint/transport.py`: native `aiohttp` `ApiTransport` calling `POST https://<host>:<port>/web_api/<command>` (`X-chkp-sid`) with:
  - Immediate post-handshake, pre-request SHA-256 certificate fingerprint verification on the raw SSL socket before any HTTP request line, headers, or payload bytes are written.
  - Explicit `connect_timeout` (`ApiTimeoutError(phase="connect")`) and per-call socket `read_timeout` (`ApiTimeoutError(phase="read")`), with a complete prohibition of silent request re-transmission after bytes are written to the socket (on read timeout, `ConnectionResetError`, or `BrokenPipeError`).
  - `VerifiedConnectionPool`: reuse of fingerprint-verified keep-alive connections per `(server_ip, port)` for up to 10 seconds idle exclusively for read-only `show-*` commands, while always opening fresh connections for login, logout, keepalive, publish, discard, and mutating commands.
- Implement `src/arodonata/adapters/checkpoint/task_waiter.py`: `TaskWaiter` polling `show-task` with exponential backoff (`2s` up to `10s`) within `task_timeout`, tolerating up to 5 consecutive transient poll errors before raising `TaskPollError`, raising `TaskTimeoutError` on deadline expiration, and returning `ApiCallResult(success=False)` (without raising) when a task finishes with `failed` or `partially succeeded`.
- Implement `src/arodonata/adapters/checkpoint/pager.py`: continuity-verified object listing pagination (`api_query`) in chunks of 300 (max 500), releasing the `RateLimiter` slot between pages, recovering displaced objects via a single `±10` boundary window re-read on duplicate UID, restarting once on `total` or `from`/`to` discontinuity before returning `code="paging_inconsistent"`, and supporting `TASK_QUERY_COMMANDS` through `TaskWaiter`.
- Implement `src/arodonata/adapters/checkpoint/rate_limiter.py`: `RateLimiter` enforcing `concurrent_limit` per MDS member (`active_mds_ip`) via database-backed slot locks (`SqlLockAdapter`) and in-process FIFO waiter queues (bounded by `rate_limit_slot_timeout`), coalescing overlapping background keepalive sweeps, and `LoginGate` serializing logins per `active_mds_ip` with `login_throttle_window` (`70s`) recovery (bounded by `login_max_wait`) and fast-fail on `InvalidCredentialsError`.
- Implement `src/arodonata/adapters/checkpoint/sessions.py`: `LoginCoordinator`, `SessionCleaner`, and `WriteSession` context management:
  - `sid_cache` strictly for shared read-only sessions, transparent single re-login and retry on session expiration error, and immediate SID eviction when `keepalive` returns `success=False`.
  - Support for static (`"api_key"` / `"credential"`), hybrid, and `"dynamic"` authentication via `AuthContext` (`contextvars`) and `AuthProvider` (with immediate credential eviction and `on_auth_failed` notification on `InvalidCredentialsError`).
  - Active domain server failover IP re-resolution via the MDS system domain (`show-domains` / `show-domain`) when a domain's cached `active_ip` fails with an unreachable/failover error.
  - `SessionCleaner` cleaning up stale sessions on startup (retaining the system domain SID in `sid_cache` when the cache is empty, and skipping network cleanup on cold startup in `"dynamic"` mode) and upon max-sessions refusal.
  - Context-bound isolated `WriteSession` (`write_session` async context manager) populating `SessionOverlay` on `add-*` / `set-*` / `delete-*` responses, auto-publishing on clean exit, and auto-discarding on unhandled exceptions.
- Implement `src/arodonata/adapters/checkpoint/client.py`: low-level `AMgmtClient` implementing `ApiPort`, defaulting `engine=None` to an auto-owned `sqlite+aiosqlite:///:memory:` engine, and wiring transport, rate limiting, task waiting, pagination, and session coordination.

## Capabilities

### New Capabilities

<!-- None: implements existing canonical specifications. -->

### Modified Capabilities

<!-- None: skip_specs is enabled in .openspec.yaml. -->

## Impact

- **Codebase**: Adds `src/arodonata/adapters/checkpoint/` (`__init__.py`, `tls.py`, `transport.py`, `task_waiter.py`, `pager.py`, `rate_limiter.py`, `sessions.py`, `client.py`) and exports `AMgmtClient` in `src/arodonata/__init__.py`.
- **Tests**: Adds unit test suites in `tests/` covering all scenarios from `openspec/specs/transport-and-tls/spec.md` and `openspec/specs/sessions-and-mdm/spec.md`.
