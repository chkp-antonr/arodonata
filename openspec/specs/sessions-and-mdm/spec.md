# Sessions, Multi-Domain Resolution, and Concurrency Specification

## Purpose

Defines the lifecycle of Check Point API sessions (`LoginCoordinator`, `SessionCleaner`, `SIDCache`), hybrid and dynamic authentication with `contextvars`-bound `WriteSession` overlays (`SessionOverlay`), per-MDS-member login gating and request concurrency limiting (`LoginGate`, `RateLimiter`), and Multi-Domain Security Management (MDSM) domain/server resolution (`DomainService`, `DomainListRefreshTracker`).

## Requirements

### Requirement: Persistent SID Caching and Auto-Recovery

The system SHALL persist shared read-only session identifiers (`sid`) in the `sid_cache` table keyed by `mgmt_name:domain`, automatically re-authenticate when a cached session expires, immediately evict a cached SID if `keepalive` returns `success=False`, and route all mutating operations through isolated dedicated sessions outside `sid_cache`.

#### Scenario: Reuse of unexpired cached session

- **WHEN** a read-only API call targets `(mgmt_name, domain)` and a cached SID exists in `sid_cache` whose age is less than `session_expire_seconds`
- **THEN** `LoginCoordinator` SHALL reuse that SID without performing a new login call

#### Scenario: Transparent re-login on session expiration error

- **WHEN** an API call using a cached SID receives a session expiration error or a background `keepalive` returns `success=False`
- **THEN** the client SHALL immediately evict the SID from `sid_cache` and, for active API calls, acquire a fresh session via `LoginCoordinator` and retry the API call once transparently

#### Scenario: Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called for isolated write workflows
- **THEN** `LoginCoordinator` SHALL authenticate a fresh session with retry/backoff resilience, return `(sid, server_ip)` without storing the SID in `sid_cache`, and ensure `logout_sid()` is called when finished

### Requirement: Hybrid and Dynamic Authentication with Context-Bound WriteSession Overlay

The system SHALL support hybrid authentication (shared read-only credentials with per-admin write credentials) and dynamic authentication via `contextvars` (`AuthContext` / `AuthProvider`), and SHALL bind isolated `WriteSession` instances in `contextvars` with an in-memory `SessionOverlay` so read operations within that session reflect uncommitted creations, updates, and deletions.

#### Scenario: WriteSession opens under administrator credentials and isolates uncommitted state

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_creds):` executes `add_host`, `set_host`, or `delete_host` followed by `get_hosts()`
- **THEN** the session SHALL authenticate under `admin_creds`, record the mutated objects in the session's `SessionOverlay` via `contextvars`, and return `get_hosts()` with created/updated hosts included and deleted hosts excluded without modifying the shared database cache until `publish`

#### Scenario: Dynamic authentication resolves credentials from AuthContext and evicts stale admin password

- **WHEN** the client runs in `"dynamic"` mode without static startup credentials and an admin request provides credentials via `client.auth_context(...)` or `AuthProvider`
- **THEN** `LoginCoordinator` SHALL use those credentials to establish sessions, and if a subsequent login fails with `InvalidCredentialsError` (e.g., after a password change), it SHALL immediately evict those credentials and notify `AuthProvider` without retrying

### Requirement: Per-MDS-Member Login Gate and Throttle Recovery

The system SHALL serialize and rate-limit logins per hosting MDS member (`active_mds_ip`, falling back to configured server IP) so concurrent domain logins against the same MDS member do not trigger Check Point's per-IP login rate limit (3 logins/minute).

#### Scenario: Throttled login waits out Check Point throttle window

- **WHEN** a login attempt is rejected due to Check Point login throttling
- **THEN** `LoginCoordinator` SHALL wait `login_throttle_window` (default 70s) before retrying, bounded by `login_max_wait` (default 900s)

#### Scenario: Credential rejection fails fast with InvalidCredentialsError

- **WHEN** the Check Point server rejects login credentials (`Authentication to server failed`) rather than reporting a transient revision/lock condition (`Database revision is in progress`)
- **THEN** `LoginCoordinator` SHALL raise `InvalidCredentialsError` (a subclass of `AuthenticationError`) without exhausting transient retry loops

### Requirement: Per-MDS-Member Concurrency Semaphore

The `RateLimiter` SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using database-backed slot locks and FIFO in-process waiter queues.

#### Scenario: Fair waiter wakeup on slot release

- **WHEN** all `concurrent_limit` slots for an MDS member are occupied and multiple coroutines are waiting
- **THEN** releasing a slot SHALL wake the longest-waiting coroutine in arrival order within the client, or raise a timeout error if no slot becomes free within `rate_limit_slot_timeout`

#### Scenario: Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity
- **THEN** overlapping keepalive sweeps SHALL be coalesced so at most one sweep runs at a time without starving active caller slots

### Requirement: Stale Session Cleanup and Startup Session Seed

`SessionCleaner` SHALL clean up stale or abandoned API sessions on configured management servers on startup (when static credentials are available) and upon max-sessions refusal, deferring cleanup in `"dynamic"` auth mode until valid credentials are provided.

#### Scenario: Startup cleanup seeds system domain SID when cache is empty

- **WHEN** `schedule_startup_cleanup()` runs on client entry with static credentials and no cached SID or in-flight login exists for a server's system domain
- **THEN** the session opened by `SessionCleaner` to inspect/discard stale sessions SHALL be retained in `sid_cache` for subsequent read calls rather than logged out

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

#### Scenario: Active domain server failover re-resolution

- **WHEN** a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** `LoginCoordinator` SHALL re-query the MDS system domain to update the domain's `active_ip` and `active_mds_ip` in the `domains` table before retrying
