# Tasks: Milestone 2 — Native Asyncio Check Point Transport, TLS, and Sessions

## 1. TLS Certificate Fingerprint Verification (`tls.py`)

- [x] 1.1 Implement `src/arodonata/adapters/checkpoint/tls.py` (`TrustStore` with atomic `0600` persistence to `tls_known_hosts.json`, `TrustPolicy` supporting `"pinned"`, `"tofu"`, and `"lab-memory"` gated by `ARODONATA_LAB`, cross-IP MDS member `known-identity` recognition, and `"No request was sent."` identity errors) and verify unit tests in `tests/test_tls.py` pass

## 2. Native `aiohttp` Transport and Verified Connection Pool (`transport.py`)

- [x] 2.1 Implement `src/arodonata/adapters/checkpoint/transport.py` (`VerifiedConnectionPool` reusing verified sockets up to 10s idle strictly for `show-*` commands, `ApiTransport` with post-handshake pre-request SHA-256 certificate verification, separate `connect_timeout` / `read_timeout` raising `ApiTimeoutError(phase="connect"|"read")`, and strict no-resend after socket write on read timeout, `ConnectionResetError`, or `BrokenPipeError`) and verify unit tests in `tests/test_transport.py` pass

## 3. Asynchronous Task Polling (`task_waiter.py`) and Continuity-Verified Pager (`pager.py`)

- [x] 3.1 Implement `src/arodonata/adapters/checkpoint/task_waiter.py` (`TaskWaiter` polling `show-task` with `2s..10s` exponential backoff within `task_timeout`, tolerating `< 5` consecutive transient errors, raising `TaskPollError` at 5 or `TaskTimeoutError` on timeout, returning `success=False` without raising on `failed` / `partially succeeded`, and never retrying `ServerIdentityError`) and verify unit tests in `tests/test_task_waiter.py` pass
- [x] 3.2 Implement `src/arodonata/adapters/checkpoint/pager.py` (`api_query` paging 300/500 items with per-page `RateLimiter` slot release, `±10` window recovery on boundary duplicate UID, single full restart on `total` or `from`/`to` discontinuity before returning `code="paging_inconsistent"`, and `TASK_QUERY_COMMANDS` support) and verify unit tests in `tests/test_pager.py` pass

## 4. Per-MDS-Member Concurrency Semaphore and Login Gate (`rate_limiter.py`)

- [x] 4.1 Implement `src/arodonata/adapters/checkpoint/rate_limiter.py` (`RateLimiter` with database-backed slot locks and FIFO in-process waiter queues per `active_mds_ip`, `RateLimitTimeoutError`, coalesced background keepalive sweeps, and `LoginGate` serializing per-MDS-member logins) and verify unit tests in `tests/test_rate_limiter.py` pass

## 5. Session Lifecycle, Hybrid/Dynamic Auth, WriteSession, and `AMgmtClient` (`sessions.py`, `client.py`)

- [x] 5.1 Implement `src/arodonata/adapters/checkpoint/sessions.py` (`LoginCoordinator` with `sid_cache` reuse, transparent re-login on expired SID, immediate eviction on `keepalive -> success=False`, `login_throttle_window=70s` recovery, fast-fail `InvalidCredentialsError` with `AuthProvider.on_auth_failed` callback, active domain IP failover re-resolution, and `SessionCleaner` with startup system-domain SID seeding and cold `"dynamic"` mode skip) and verify unit tests in `tests/test_sessions.py` pass
- [x] 5.2 Implement `src/arodonata/adapters/checkpoint/client.py` and `src/arodonata/adapters/checkpoint/__init__.py` (`AMgmtClient` implementing `ApiPort` with default in-memory SQLite when `engine=None`, `write_session` context manager updating `SessionOverlay` on `add-*`/`set-*`/`delete-*` and auto-publishing/discarding, and `invalidate_domain` hooks) and run all quality gates (`pytest`, `mypy src`, `ruff`, `markdownlint`, `openspec validate`)
