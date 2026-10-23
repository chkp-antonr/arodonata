# Design: Milestone 2 — Native Asyncio Check Point Transport, TLS, and Sessions

## Context

See `proposal.md` for motivation and `openspec/changes/archive/2026-10-23-revise-v2-architecture-specs/design.md` for overarching v2 architectural decisions. Milestone 2 implements `src/arodonata/adapters/checkpoint/` to fulfill `openspec/specs/transport-and-tls/spec.md` and the transport/session requirements of `openspec/specs/sessions-and-mdm/spec.md`.

## Goals / Non-Goals

**Goals:**

- Implement `TrustStore` and `TrustPolicy` (`tls.py`) enforcing pre-request SHA-256 certificate fingerprint verification across `"pinned"`, `"tofu"`, and `"lab-memory"` modes, atomic `0600` persistence for `tls_known_hosts.json`, and cross-IP MDS member identity recognition.
- Implement native `aiohttp` `ApiTransport` (`transport.py`) with post-handshake pre-request certificate verification, explicit `connect_timeout` and `read_timeout` mapping to `ApiTimeoutError(phase="connect" | "read")`, zero automatic request re-transmission after socket write, and `VerifiedConnectionPool` reusing keep-alive sockets up to 10s idle strictly for `show-*` commands.
- Implement `TaskWaiter` (`task_waiter.py`) with exponential backoff (`2s..10s`), `task_timeout` enforcement, tolerance for up to 5 consecutive transient poll failures, and explicit `succeeded` terminal validation.
- Implement continuity-verified pagination (`pager.py`) with per-page `RateLimiter` slot acquisition/release, `±10` boundary window recovery on duplicate UIDs, single restart on continuity break (`code="paging_inconsistent"`), and `TASK_QUERY_COMMANDS` unpacking.
- Implement `RateLimiter` and `LoginGate` (`rate_limiter.py`) keyed by `active_mds_ip` with database-backed slot locks, FIFO in-process waiter queues, coalesced keepalive sweeps, `70s` throttle window waiting, and fast-fail on `InvalidCredentialsError`.
- Implement `LoginCoordinator`, `SessionCleaner`, and `WriteSession` lifecycle (`sessions.py`) plus `AMgmtClient` (`client.py`) implementing `ApiPort`.

**Non-Goals:**

- Implementing high-level `DomainSyncCoordinator`, `ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `SearchService`, or `ArodonataClient` (scheduled for Milestone 3).

## Decisions

### 1. Pre-Request TLS Certificate Verification (`src/arodonata/adapters/checkpoint/tls.py`)

- **SHA-256 Normalization**: Fingerprints are normalized to uppercase colon-separated hex (`AA:BB:...` or `SHA256:AA:BB:...` stripped of prefix and colons for comparison, formatted canonically as 64-char lowercase or colon-separated uppercase hex). Both colon-separated hex and raw 64-char hex strings in `ARODONATA_TLS_FINGERPRINTS` (e.g. `"10.0.0.1:443=AA:BB...,10.0.0.2=CC:DD..."` or JSON/CSV) are supported.
- **Verification Before Any Bytes Leave the Socket**: During connection establishment, the TLS handshake completes with `ssl.CERT_NONE` (so self-signed Check Point management certificates complete handshake), and immediately after the handshake—before any HTTP request line, `X-chkp-sid` header, or JSON payload is written—the peer certificate DER bytes (`ssl_object.getpeercert(binary_form=True)`) are hashed with `hashlib.sha256(der).hexdigest()` and checked via `TrustPolicy.verify(host, port, fingerprint_hex)`.
- **On Verification Failure**: The transport closes/aborts the socket immediately before writing any HTTP data and raises `UnknownServerCertificateError` or `CertificateMismatchError` with `"No request was sent."` in the exception message.
- **Cross-IP MDS Member Recognition**: If `host:port` is not yet bound in `TrustStore` or `tls_fingerprints`, `TrustPolicy` checks whether the presented fingerprint is already trusted for any other `host:port` entry in the trust store or `tls_fingerprints`. If so, it is accepted (and in `"tofu"` mode persisted for `host:port` with `source="known-identity"`).
- **Atomic `0600` TrustStore Persistence**: `TrustStore` writes to a temporary file in the same directory with `os.open(..., os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)`, `os.chmod(..., 0o600)`, flushes/fsyncs, and atomically replaces the target file via `os.replace()`.

### 2. Native `aiohttp` Transport & `VerifiedConnectionPool` (`src/arodonata/adapters/checkpoint/transport.py`)

- **Connection Pooling Rules**:
  - Only commands starting with `"show-"` are eligible for connection reuse via `VerifiedConnectionPool`.
  - Pooled entries are keyed by `(host, port)` and track `last_used_monotonic`. Any pooled connection idle for `> 10.0` seconds (or whose underlying transport is closed/closing) is closed and discarded before use.
  - Non-`show-*` commands (`login`, `logout`, `keepalive`, `publish`, `discard`, `add-*`, `set-*`, `delete-*`, etc.) always open a fresh TLS-verified connection and close it (or do not pool it) after the call.
- **Socket Timeouts & No Re-send Guarantee**:
  - Connection + TLS handshake is bounded by `connect_timeout`. Timeout during connect/handshake raises `ApiTimeoutError(..., phase="connect", host=host, port=port, command=command)`.
  - Once the connection is established and verified, request bytes are written. Waiting for and reading the HTTP response is bounded by `read_timeout = settings.resolve_read_timeout(timeout)`.
  - Timeout during response wait/read closes the socket and raises `ApiTimeoutError(..., phase="read", host=host, port=port, command=command)` with a warning that the command may still have executed on the server.
  - `ConnectionResetError`, `BrokenPipeError`, and `aiohttp.ClientOSError` / `ServerDisconnectedError` occurring after request transmission are never retried by `ApiTransport`; they raise `TransportError` (preserving `__cause__`) immediately.

### 3. Asynchronous Task Polling (`src/arodonata/adapters/checkpoint/task_waiter.py`)

- When `wait_for_task=True` and an API response contains `"task-id"` (str) or `"tasks"` (list of dicts with `"task-id"`), `TaskWaiter.wait_for_tasks(...)` polls `show-task` with `{"task-id": task_ids, "details-level": "full"}`.
- Backoff schedule starts at `2.0s` and grows exponentially (`min(10.0, 2.0 * (1.5 ** attempt))` or `2s -> 4s -> 8s -> 10s`) within `task_timeout`.
- Terminal statuses: `succeeded`, `failed`, `partially succeeded` (and `aborted`). Only when all polled tasks reach terminal status and every task status is in `{"succeeded"}` does `TaskWaiter` return `ApiCallResult(success=True, data=final_payload)`. If any task finishes with `failed`, `partially succeeded`, or `aborted`, `TaskWaiter` returns `ApiCallResult(success=False, status_code=..., data=final_payload, error_message=...)` without raising an exception.
- Transient poll errors (`ApiTimeoutError`, `TransportError`, or HTTP 5xx / non-success `show-task` call, excluding `ServerIdentityError` which propagates immediately) increment a consecutive failure counter. If `< 5`, polling continues; on the 5th consecutive failure, `TaskPollError` is raised. If `task_timeout` elapses first, `TaskTimeoutError` is raised.

### 4. Continuity-Verified Object Pager (`src/arodonata/adapters/checkpoint/pager.py`)

- `api_query` clamps `limit` to `1..500` (default `300`) and fetches pages sequentially. Each page call goes through `api_call` so the `RateLimiter` slot is acquired for the page request and released between pages.
- For standard object listings, each page response provides `objects` (or `access-layers`, `packages`, `domains`, `sessions`, etc.), `from`, `to`, and `total`.
- **Continuity Checks**:
  - `total` must remain constant across all pages of a pass.
  - For non-empty pages, `from` must equal `offset + 1` and `to` must equal `offset + len(page_objects)`.
- **Boundary Swap Duplicate UID Recovery**:
  - If a page contains an object whose `uid` was already seen at the end of the previous page (because Check Point reordered two equal-named objects across the page boundary), the pager drops the duplicate UID and performs a single targeted window query (`offset = max(0, boundary_offset - 10)`, `limit = 20`) to recover the displaced neighbor UID without restarting the full query.
- **Single Restart on Discontinuity**:
  - If `total` changes mid-listing, `from`/`to` continuity breaks, or after collecting all pages `len(distinct_objects) != total` (even after boundary window recovery), the pager restarts the listing once from the initial offset. If the second pass also fails continuity checks, `api_query` returns `ApiQueryResult(success=False, code="paging_inconsistent", error_message=...)`.
- **`TASK_QUERY_COMMANDS`**:
  - Commands in `TASK_QUERY_COMMANDS` (e.g. `where-used`, `show-unused-objects`, or task-returning queries) execute each page via `api_call(..., wait_for_task=True)`, unpack objects/pagination metadata from `tasks[].task-details[]`, and advance until `to >= total`.

### 5. Per-MDS-Member `RateLimiter` and `LoginGate` (`src/arodonata/adapters/checkpoint/rate_limiter.py`)

- **`RateLimiter`**:
  - Keyed by `mds_ip` (`active_mds_ip` or configured server host).
  - Maintains an in-process FIFO `collections.deque[asyncio.Future[None]]` of waiters per `mds_ip` and acquires one of `concurrent_limit` named slot locks (`rate_slot:{mds_ip}:{slot_idx}`) in `SqlLockAdapter`.
  - When all `concurrent_limit` slots are busy, coroutines wait in strict FIFO arrival order up to `rate_limit_slot_timeout`, raising `RateLimitTimeoutError` on timeout.
  - Background keepalive sweeps use `run_coalesced_keepalive(key, coro_factory)`: if a sweep is already running for that key, overlapping triggers coalesce onto the in-flight sweep rather than queueing redundant keepalive requests.
- **`LoginGate`**:
  - Serializes login attempts per `mds_ip` via an `asyncio.Lock` + distributed lock (`login_gate:{mds_ip}`).
  - If Check Point rejects a login due to rate limiting / throttling (e.g. HTTP 429 or message matching throttle/too many logins), `LoginGate` / `LoginCoordinator` waits `login_throttle_window` (`70.0s`) before retrying, bounded by `login_max_wait` (`900.0s`).
  - Explicit credential rejection (`Authentication to server failed` / invalid API key or password, distinct from `Database revision is in progress`) raises `InvalidCredentialsError` immediately without retrying.

### 6. `LoginCoordinator`, `SessionCleaner`, `WriteSession`, and `AMgmtClient`

- **`LoginCoordinator`**:
  - Resolves target `(server_ip, active_mds_ip)` for `(mgmt_name, domain)` from cached `domains` table (falling back to configured server endpoint).
  - For read-only calls: checks `sid_cache` (`CachePort.get_sid`). If an entry exists and its age (`now - created_at` or `now - last_used_at`) is `< session_expire_seconds` (and `expires_at` is in the future), reuses `entry.sid`.
  - If an API call using a cached SID returns a session expiration code/message (`generic_err_invalid_session_id`, `session_expired`, HTTP 401/403 session invalid), `evict_sid` is called immediately, a fresh session is acquired via `LoginCoordinator`, and the API call is retried once transparently.
  - If `keepalive` returns `success=False`, `evict_sid` is called immediately.
  - If a domain's cached `active_ip` fails with a failover/unreachable error, `LoginCoordinator` queries the MDS system domain (`show-domains` / `show-domain`) to refresh `active_ip` and `active_mds_ip` in `domains` before retrying.
  - Supports static (`api_key`, `credential`), hybrid (shared read-only credentials + per-admin `AuthContext` for `WriteSession`), and `"dynamic"` authentication (resolving credentials from `get_auth_context()` or `AuthProvider.get_credentials(...)`). On `InvalidCredentialsError`, evicts any cached session for that credential and invokes `await auth_provider.on_auth_failed(mgmt_name, auth, exc)` without retrying.
- **`SessionCleaner`**:
  - `schedule_startup_cleanup()`: in `"dynamic"` mode without static credentials, skips network cleanup cleanly. When static credentials exist and no cached SID or in-flight login exists for a server's system domain, opens a system domain session, inspects/discards stale sessions (`show-sessions` / `disconnect` / `discard`), and retains the opened SID in `sid_cache` as the initial system domain read session.
- **`WriteSession` Lifecycle**:
  - `async with client.write_session(mgmt_name, domain, auth=..., publish_on_exit=True) as ws:` opens a dedicated session outside `sid_cache`, binds `ws` to `contextvars`, intercepts `add-*` / `set-*` / `delete-*` calls executed via `AMgmtClient.api_call` within that context to update `ws.overlay` (`CPObject` / `CPService` upserts and deletes), executes `publish` on normal exit (and invokes any registered domain invalidation callback), executes `discard` and clears `ws.overlay` if an exception escapes the `async with` block, and always logs out the dedicated SID in `finally`.

## Risks / Trade-offs

- **[Risk] Testing post-handshake TLS verification without external Check Point appliances** → Mitigation: Provide both a custom socket/SSL-object verification hook in `ApiTransport` and tests covering real `ssl.SSLObject` / DER peer certificates as well as deterministic transport doubles verifying zero bytes are written when `TrustPolicy.verify` raises `ServerIdentityError`.
- **[Risk] Time-sensitive tests (`70s` login throttle, `2s..10s` task polling, `10s` connection pool idle)** → Mitigation: Inject configurable clock (`monotonic_fn`) and sleep (`sleep_fn`) callables into `TrustPolicy`, `VerifiedConnectionPool`, `TaskWaiter`, `RateLimiter`, and `LoginCoordinator` so unit tests run in milliseconds while verifying exact wait durations and deadlines.
