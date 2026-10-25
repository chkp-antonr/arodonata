# Spec Delta: Sessions, Multi-Domain Resolution, and Concurrency

## MODIFIED Requirements

### Requirement: Persistent SID Caching and Auto-Recovery

The system SHALL persist shared read-only session identifiers (`sid`) in the `arodonata_sid_cache` table with primary key `f"{mgmt_name}:{domain_key}:{auth_identity}"` where `auth_identity` is a cryptographic HMAC-SHA256 digest of the resolved credentials (`username` + `password` or `api_key`, scoped with `user_id` and `auth_mode`), automatically re-authenticate when a cached session expires, immediately evict a cached SID if `keepalive` returns `success=False`, and strictly reject or isolate any mutating command so non-read-only commands never run on a shared `arodonata_sid_cache` session.

#### Scenario: Reuse of unexpired cached session scoped by authentication identity

- **WHEN** a read-only API call targets `(mgmt_name, domain)` under resolved credentials (`auth_identity`) and a cached SID exists in `arodonata_sid_cache` with the exact `f"{mgmt_name}:{domain_key}:{auth_identity}"` key whose age is less than `session_expire_seconds`
- **THEN** `LoginCoordinator` SHALL reuse that SID without performing a new login call, whereas a call with a different password, different API key, or `auth_identity=None` SHALL NEVER match or overwrite that cached SID

#### Scenario: Transparent re-login on session expiration error

- **WHEN** a read-only API call using a cached SID receives a session expiration error or a background `keepalive` returns `success=False`
- **THEN** the client SHALL immediately evict only that specific `(mgmt_name, domain_key, auth_identity)` row from `arodonata_sid_cache` and, for active read-only API calls, acquire a fresh session via `LoginCoordinator` and retry the call once transparently

#### Scenario: Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called for isolated write workflows
- **THEN** `LoginCoordinator` SHALL authenticate a fresh session with retry/backoff resilience, return `(sid, server_ip)` without storing the SID in `arodonata_sid_cache`, keep the SID registered in `_active_dedicated_sids` until `logout_sid()` succeeds, and shield `discard`/`logout_sid()` against `asyncio.CancelledError` (`BaseException`)

#### Scenario: Mutating commands refused on shared cached SID path

- **WHEN** `AMgmtClient.api_call` is invoked with a non-read-only command (`add-*`, `set-*`, `delete-*`, `publish`, `discard`, `install-policy`, `run-script`, etc.) without an explicit `sid` or active `WriteSession` in `contextvars`
- **THEN** `AMgmtClient` SHALL refuse to execute the command on the shared `arodonata_sid_cache` session (raising `SessionStateError` unless called via high-level `ArodonataClient` helpers that open an isolated dedicated session)

### Requirement: Per-MDS-Member Login Gate and Throttle Recovery

The system SHALL serialize and rate-limit logins per hosting MDS member (`active_mds_ip`, falling back to configured server IP) via `LoginGate`, enforcing a minimum inter-login spacing and shared throttle cooldown inside the gate, bounding local `asyncio.Lock` acquisition by `wait_timeout`, and executing CMA failover IP refreshes (`refresh_domain_active_ip`) and retry backoff sleeps outside the gate so recursive system-domain logins on the same MDS IP never deadlock.

#### Scenario: Throttled login waits out Check Point throttle window

- **WHEN** a login attempt is rejected due to Check Point login throttling or times out during the read phase
- **THEN** `LoginGate` SHALL record the per-MDS cooldown window (`login_throttle_window`, default 70s, or exponential read-timeout backoff) so subsequent queued callers respect the cooldown before sending another `login`, and `LoginCoordinator` SHALL release the gate before sleeping and retrying within `login_max_wait` (default 900s)

#### Scenario: Cold-cache CMA failover during login does not deadlock LoginGate

- **WHEN** a login to a customer domain on `mds_ip` encounters a transport or failover error and triggers `refresh_domain_active_ip()` while the system domain SID is not yet cached (requiring a system domain login to the same `mds_ip`)
- **THEN** `LoginCoordinator` SHALL release the `LoginGate` for `mds_ip` before invoking `refresh_domain_active_ip()` so the nested system-domain login acquires `LoginGate(mds_ip)` cleanly without self-deadlock

#### Scenario: Credential rejection or locked account fails fast with InvalidCredentialsError

- **WHEN** the Check Point server rejects login credentials (`Authentication to server failed` or `Administrator account is locked`) rather than reporting a transient revision/lock condition (`Database revision is in progress`)
- **THEN** `LoginCoordinator` SHALL raise `InvalidCredentialsError` (a subclass of `AuthenticationError`) without exhausting transient retry loops

### Requirement: Per-MDS-Member Concurrency Semaphore

The `RateLimiter` SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using database-backed slot locks (with TTL `>= max(api_timeout, login_timeout) + 60s`) and FIFO in-process waiter queues, guaranteeing local FIFO slot release in `finally` even if database lock release raises an error or is cancelled.

#### Scenario: Fair waiter wakeup on slot release

- **WHEN** all `concurrent_limit` slots for an MDS member are occupied, multiple coroutines are waiting, and the active slot holder exits (even if the database lock release raises an exception or `asyncio.CancelledError`)
- **THEN** `RateLimiter` SHALL always release the local FIFO slot in `finally` (shielding DB lock cleanup) and wake the longest-waiting coroutine in arrival order within the client, or raise a timeout error if no slot becomes free within `rate_limit_slot_timeout`

#### Scenario: Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity (including when one awaiting caller is cancelled)
- **THEN** overlapping keepalive sweeps SHALL be coalesced and protected via `asyncio.shield` so at most one sweep runs at a time without starving active caller slots or aborting sibling waiters

### Requirement: Stale Session Cleanup and Startup Session Seed

`SessionCleaner` SHALL clean up stale or abandoned Arodonata-owned API sessions on configured management servers on startup (when static credentials are available) and upon max-sessions refusal, strictly restricting `discard` to sessions created by Arodonata (`application == "arodonata"` or `arodonata` session-name prefix) that have `changes == 0` and `locks == 0`.

#### Scenario: Startup cleanup seeds system domain SID when cache is empty

- **WHEN** `schedule_startup_cleanup()` runs on client entry with static credentials and no cached SID or in-flight login exists for a server's system domain
- **THEN** the session opened by `SessionCleaner` to inspect/discard stale sessions SHALL be retained in `arodonata_sid_cache` for subsequent read calls rather than logged out

#### Scenario: Foreign administrator sessions and sessions with unpublished changes are never discarded

- **WHEN** `SessionCleaner` inspects `show-sessions` and encounters sessions belonging to human administrators, other tools, or sessions with non-zero `changes` or `locks`
- **THEN** `SessionCleaner` SHALL skip those sessions and NEVER issue `discard` or `take-over-session` against them

#### Scenario: Cold startup in dynamic auth mode skips network cleanup

- **WHEN** `ArodonataClient` enters its context manager in `"dynamic"` auth mode before any administrator credentials have been supplied
- **THEN** startup session cleanup SHALL be skipped without raising an authentication error
