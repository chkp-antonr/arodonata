# Sessions, Multi-Domain Resolution, and Concurrency Specification

## Purpose

Defines the lifecycle of Check Point API sessions (`LoginCoordinator`, `SessionCleaner`, `SIDCache`), hybrid and dynamic authentication with `contextvars`-bound `WriteSession` overlays (`SessionOverlay`), per-MDS-member login gating and request concurrency limiting (`LoginGate`, `RateLimiter`), and Multi-Domain Security Management (MDSM) domain/server resolution (`DomainService`, `DomainListRefreshTracker`).

## Requirements

### Requirement: Persistent SID Caching and Auto-Recovery

The system SHALL persist shared read-only session identifiers (`sid`) in `arodonata_sid_cache` keyed by `f"{mgmt_name}:{domain_key}:{auth_identity}"` (where `auth_identity` is an HMAC-SHA256 credential digest), re-authenticate when a cached session expires, evict a cached SID when `keepalive` returns `success=False`, and reject or isolate mutating commands so they never use `arodonata_sid_cache`.

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

### Requirement: Hybrid and Dynamic Authentication with Context-Bound WriteSession Overlay

The system SHALL support hybrid authentication (shared read-only credentials with per-admin write credentials) and dynamic authentication via `contextvars` (`AuthContext` / `AuthProvider`), and SHALL bind isolated `WriteSession` instances in `contextvars` with an in-memory `SessionOverlay` so read operations within that session reflect uncommitted creations, updates, and deletions.

#### Scenario: WriteSession opens under administrator credentials and isolates uncommitted state

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_creds):` executes `add_host`, `set_host`, or `delete_host` followed by `get_hosts()`
- **THEN** the session SHALL authenticate under `admin_creds`, record the mutated objects in the session's `SessionOverlay` via `contextvars`, and return `get_hosts()` with created/updated hosts included and deleted hosts excluded without modifying the shared database cache until `publish`

#### Scenario: Dynamic authentication resolves credentials from AuthContext and evicts stale admin password

- **WHEN** the client runs in `"dynamic"` mode without static startup credentials and an admin request provides credentials via `client.auth_context(...)` or `AuthProvider`
- **THEN** `LoginCoordinator` SHALL use those credentials to establish sessions, and if a subsequent login fails with `InvalidCredentialsError` (e.g., after a password change), it SHALL immediately evict those credentials and notify `AuthProvider` without retrying

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

### Requirement: Multi-Domain Discovery, Failover IP Resolution, and Global Domain Support

`DomainService` SHALL discover and cache all domains on MDS servers (`show-domains`), synthesize an explicit `Global` domain row (`show-global-domain`), and track each domain's `active_ip`, `active_mds_ip`, and standby servers.

#### Scenario: Opt-in Global domain visibility

- **WHEN** `get_domains(include_global=False)` (the default) is called
- **THEN** the `Global` domain row SHALL be excluded from the returned list; when `include_global=True`, the `Global` domain row SHALL be included

#### Scenario: Periodic domain list refresh via DomainListRefreshTracker

- **WHEN** `get_domains` or smart cache refresh runs
- **THEN** the domain list (`show-domains`) SHALL be re-fetched from the management server when the `domains` table is empty, when the 1-hour domain-list TTL has elapsed, or when `mode="force"` is requested

#### Scenario: Cold-cache CMA IP resolution and active domain server failover re-resolution

- **WHEN** a customer or `Global` domain login runs before `domains` is cached (cold cache) or when a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** `LoginCoordinator` SHALL query the MDS system domain (`show-domains`, `show-mdss`, and `show-global-domain`) to resolve and cache the domain's `active_ip` (CMA IP) and `active_mds_ip` in the `domains` table before authenticating against the domain
