# Sessions, Multi-Domain Resolution, and Concurrency Specification

## Purpose

Defines the lifecycle of Check Point API sessions (`AMgmtClient`, `SIDCacheEntry`, `arodonata_sid_cache`), hybrid and dynamic authentication with `contextvars`-bound `WriteSession` overlays (`SessionOverlay`, `AuthContext`, `AuthProvider`), per-MDS-member login serialization and request concurrency limiting, and Multi-Domain Security Management (MDSM) domain/server discovery (`DomainService`).

## Requirements

### Requirement: Multi-Domain Discovery, Failover IP Resolution, and Global Domain Visibility

**ID**: REQ-SESS-001\
**Intent**: Discover and cache MDS domains reliably with RBAC fallback, failover server tracking, and opt-in `Global` visibility.\
**Non-goals**: Validating explicit caller-supplied IP addresses (`REQ-SESS-008`) or read-only SID caching (`REQ-SESS-003`).

`DomainService` and `AMgmtClient` SHALL discover and cache MDS domains (`show-domains`, `show-mdss`, `show-global-domain`), track each domain's `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`, support opt-in `include_global`, periodically refresh cached domains when their 1-hour TTL expires, and log `DEBUG` discovery and `WARNING` failure messages.

#### Scenario: SCN-SESS-001-1 — Opt-in Global domain visibility

- **WHEN** `get_domains(include_global=False)` (default) vs `get_domains(include_global=True)` is called
- **THEN** the `Global` domain row SHALL be excluded when `include_global=False` and included when `include_global=True`

#### Scenario: SCN-SESS-001-2 — Periodic TTL-based domain list refresh

- **WHEN** `get_domains` or smart cache refresh runs while `arodonata_domains` is empty, the 1-hour domain-list TTL expired, or `mode="force"` is set
- **THEN** `show-domains` SHALL refresh domains, retrying with `details-level="standard"` if `details-level="full"` is denied by RBAC while preserving cached `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`
- **AND** discovery start and completion SHALL log `DEBUG` messages, and discovery failure SHALL log `WARNING` with the server error code and message

#### Scenario: SCN-SESS-001-3 — Cold-cache CMA IP resolution and active domain server failover re-resolution

- **WHEN** a customer or `Global` domain login runs before `arodonata_domains` is cached or when a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** the client SHALL query the MDS system domain (`show-domains`, `show-mdss`, `show-global-domain`), cache `active_ip` and `active_mds_ip` in `arodonata_domains`, and log a `DEBUG` message before authenticating

### Requirement: Hybrid and Dynamic Authentication with Context-Bound WriteSession Overlay

**ID**: REQ-SESS-002\
**Intent**: Support per-request dynamic credentials and isolated `contextvars` write overlays without exposing secrets or dirtying shared caches.\
**Non-goals**: Shared read-only SID caching (`REQ-SESS-003`).

The system SHALL support hybrid authentication (shared read-only credentials with per-admin write credentials) and dynamic authentication via `contextvars` (`AuthContext` / `AuthProvider`), and SHALL bind isolated `WriteSession` instances in `contextvars` with an in-memory `SessionOverlay` so read operations within that session reflect uncommitted creations, updates, and deletions.

#### Scenario: SCN-SESS-002-1 — WriteSession opens under administrator credentials and isolates uncommitted state

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_creds):` executes `add_host`, `set_host`, or `delete_host` followed by `get_hosts()`
- **THEN** the session SHALL authenticate under `admin_creds` and record mutations in `SessionOverlay` via `contextvars`
- **AND** `get_hosts()` SHALL return created/updated hosts and exclude deleted hosts without mutating shared database cache rows until `publish`

#### Scenario: SCN-SESS-002-2 — Dynamic authentication resolves credentials from AuthContext and evicts stale admin password

- **GIVEN** `"dynamic"` mode without static startup credentials where credentials come from `client.auth_context(...)` or `AuthProvider`
- **WHEN** a subsequent login using those credentials fails with `InvalidCredentialsError` (e.g., after a password change)
- **THEN** the client SHALL immediately evict those credentials and notify `AuthProvider` without retrying

### Requirement: Identity-Scoped Read-Only SID Caching and Dedicated Write Sessions

**ID**: REQ-SESS-003\
**Intent**: Prevent cross-principal SID reuse and ensure mutating commands never execute on shared read-only sessions.\
**Non-goals**: Startup cleanup of abandoned Arodonata sessions (`REQ-SESS-004`).

The system SHALL authenticate shared `arodonata_sid_cache` sessions with `"read-only": true`, key rows by `f"{mgmt_name}:{domain_key}:{auth_identity}"` (excluding `SIDCacheEntry.sid` from model dumps and defaulting `SIDCacheEntry.id` to include `auth_identity`), evict only the affected `auth_identity` row on expiry, failover, keepalive failure, or logout failure, and refuse mutating commands on `arodonata_sid_cache`.

#### Scenario: SCN-SESS-003-1 — Reuse of unexpired cached session scoped by authentication identity

- **WHEN** a read-only API call targets `(mgmt_name, domain)` under resolved credentials (`auth_identity`)
- **THEN** new `arodonata_sid_cache` sessions SHALL authenticate with `"read-only": true` and reuse only an unexpired row matching exact `f"{mgmt_name}:{domain_key}:{auth_identity}"`
- **AND** `SIDCacheEntry.model_dump()` / `model_dump_json()` SHALL omit raw `sid`, and another principal's cached SID SHALL NEVER be matched or overwritten

#### Scenario: SCN-SESS-003-2 — Transparent re-login on session expiration error

- **WHEN** a read-only call using a cached SID hits session expiration/CMA failover, a keepalive returns `success=False`, or `logout_all` fails to log out a cached SID
- **THEN** only that specific `(mgmt_name, domain_key, auth_identity)` row SHALL be evicted from `arodonata_sid_cache` (preserving other principals' SIDs)
- **AND** active read-only API calls SHALL acquire a fresh session and retry once

#### Scenario: SCN-SESS-003-3 — Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called
- **THEN** `AMgmtClient` SHALL authenticate a fresh read-write session (`"read-only"` omitted/`False`) with retry/backoff resilience and return `(sid, server_ip)` without storing it in `arodonata_sid_cache`
- **AND** the session SHALL remain tracked for cleanup until `logout_sid()` succeeds, shielding `discard` and `logout_sid()` against any `BaseException` (including `asyncio.CancelledError`)

#### Scenario: SCN-SESS-003-4 — Mutating commands refused on shared cached SID path

- **WHEN** `AMgmtClient.api_call` receives a mutating command (`add-*`, `set-*`, `delete-*`, `publish`, `discard`, `install-policy`, `run-script`, etc.) without an explicit `sid` or active `WriteSession` in `contextvars`
- **THEN** `AMgmtClient` SHALL refuse to run it on the shared `arodonata_sid_cache` session by raising `SessionStateError`

### Requirement: Stale Session Cleanup and Startup Session Seed

**ID**: REQ-SESS-004\
**Intent**: Reclaim abandoned Arodonata API sessions safely without ever touching human or dirty sessions, and reuse the startup probe session.\
**Non-goals**: Read-only SID cache scoping (`REQ-SESS-003`).

The session manager SHALL clean up stale or abandoned Arodonata-owned API sessions on configured management servers on startup (when static credentials are available) and upon max-sessions refusal, logging `DEBUG` entries when discarding stale Arodonata sessions, and strictly restricting `discard` to sessions created by Arodonata (`application == "arodonata"` or `arodonata` session-name prefix) that have `changes == 0` and `locks == 0`.

#### Scenario: SCN-SESS-004-1 — Startup cleanup seeds system domain SID when cache is empty

- **GIVEN** static credentials and no cached SID or in-flight login for a server's system domain
- **WHEN** startup session cleanup runs on client entry
- **THEN** the session opened to inspect/discard stale sessions SHALL be retained in `arodonata_sid_cache` for subsequent read calls rather than logged out

#### Scenario: SCN-SESS-004-2 — Foreign administrator sessions and sessions with unpublished changes are never discarded

- **WHEN** stale-session cleanup inspects `show-sessions` and sees sessions belonging to human administrators, other tools, or sessions with non-zero `changes` or `locks`
- **THEN** cleanup SHALL skip those sessions and NEVER issue `discard` or `take-over-session` against them

#### Scenario: SCN-SESS-004-3 — Cold startup in dynamic auth mode skips network cleanup

- **WHEN** `ArodonataClient` enters its context manager in `"dynamic"` auth mode before any administrator credentials are supplied
- **THEN** startup session cleanup SHALL be skipped without raising an authentication error

### Requirement: Per-MDS-Member Login Serialization and Deadlock-Free Failover

**ID**: REQ-SESS-005\
**Intent**: Serialize login bursts per MDS member to respect Check Point login pacing while avoiding self-deadlock on nested CMA failover lookups.\
**Non-goals**: Login throttle cooldown windows and fast credential rejection (`REQ-SESS-006`).

The client SHALL serialize logins per hosting MDS member (`active_mds_ip`, falling back to configured server IP) with minimum inter-login spacing and `wait_timeout`-bounded `asyncio.Lock` acquisition, while executing CMA failover IP refreshes and retry sleeps outside the gate so nested system-domain logins never deadlock.

#### Scenario: SCN-SESS-005-1 — Cold-cache CMA failover during login does not deadlock login serialization

- **GIVEN** a customer-domain login on `mds_ip` encountering a transport/failover error while the system-domain SID is not yet cached
- **WHEN** failover recovery triggers a nested system-domain login to refresh the domain's active IP on `mds_ip`
- **THEN** `AMgmtClient` SHALL release the per-`mds_ip` login serialization lock before refreshing the domain IP so the nested system-domain login completes without self-deadlock

### Requirement: Login Throttle Cooldown and Fast Credential Rejection

**ID**: REQ-SESS-006\
**Intent**: Coordinate login throttle cooldowns across queued callers while failing fast on wrong credentials or locked accounts.\
**Non-goals**: Per-MDS login lock release during CMA failover (`REQ-SESS-005`).

The client SHALL enforce a shared per-MDS throttle cooldown inside the login gate with a `WARNING` log on login throttling or read-phase timeout, retry within `login_max_wait`, and raise `InvalidCredentialsError` immediately without retrying when credentials are rejected or an administrator account is locked.

#### Scenario: SCN-SESS-006-1 — Throttled login waits out Check Point throttle window

- **WHEN** a login attempt is rejected for Check Point login throttling or times out during the read phase
- **THEN** the per-MDS login gate SHALL record the cooldown (`login_throttle_window`, default `70s`, or exponential read-timeout backoff) and log a `WARNING` with server IP, non-secret administrator principal (resolved from credentials or Check Point login response `'user-name'`, falling back to `'api_key'`), and cooldown duration
- **AND** queued callers SHALL wait out the cooldown, and the caller SHALL release the gate before sleeping and retrying within `login_max_wait` (default `900s`)

#### Scenario: SCN-SESS-006-2 — Credential rejection or locked account fails fast with InvalidCredentialsError

- **WHEN** Check Point rejects login (`Authentication to server failed` or `Administrator account is locked`) rather than reporting a transient lock (`Database revision is in progress`)
- **THEN** login SHALL raise `InvalidCredentialsError` (subclass of `AuthenticationError`) immediately without exhausting transient retry loops

### Requirement: Per-MDS-Member Concurrency Semaphore

**ID**: REQ-SESS-007\
**Intent**: Bound concurrent API requests per MDS safely using FIFO fairness, shielded cleanup, and coalesced keepalive sweeps.\
**Non-goals**: Login serialization and throttle windows (`REQ-SESS-005`, `REQ-SESS-006`).

The client SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using database-backed slot locks (with TTL `>= max(api_timeout, login_timeout) + 60s`) and FIFO in-process waiter queues, suppressing database `Exception` errors during shielded DB lock release while always releasing the local FIFO slot and propagating `asyncio.CancelledError`.

#### Scenario: SCN-SESS-007-1 — Fair waiter wakeup on slot release

- **GIVEN** all `concurrent_limit` slots for an MDS member are occupied and multiple coroutines are queued in arrival order
- **WHEN** an active slot holder exits (including when DB lock release raises an `Exception` or `asyncio.CancelledError` occurs)
- **THEN** DB lock cleanup SHALL be shielded (`suppress(Exception)`), the local FIFO slot SHALL ALWAYS release in `finally` to wake the longest-waiting coroutine, and `asyncio.CancelledError` SHALL propagate

#### Scenario: SCN-SESS-007-2 — Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity (including if an awaiting caller is cancelled)
- **THEN** overlapping keepalive sweeps SHALL coalesce under `asyncio.shield` so at most one sweep runs at a time without starving active caller slots or aborting sibling waiters

### Requirement: Untrusted Explicit Server IP Rejection

**ID**: REQ-SESS-008\
**Intent**: Prevent SSRF or credential/SID exfiltration to arbitrary IP addresses passed via `explicit_server_ip`.\
**Non-goals**: Pre-request TLS certificate fingerprint verification (`REQ-TRANS-002`).

`AMgmtClient` (across `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, and `logout_sid`) SHALL validate any caller-supplied `explicit_server_ip` against `mgmt_name`'s configured endpoint hosts and cached/discovered MDS and domain server addresses, rejecting untrusted IPs with `ValidationError` before connecting.

#### Scenario: SCN-SESS-008-1 — Untrusted explicit_server_ip rejected before connection or SID transmission

- **WHEN** `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid` receives an `explicit_server_ip` absent from `mgmt_name`'s configured endpoints and cached/discovered MDS or domain server IPs
- **THEN** the client SHALL raise `ValidationError` before opening a TLS connection, learning a TOFU certificate, or transmitting `X-chkp-sid`

### Requirement: Contextual User Attribution Propagation

**ID**: REQ-SESS-009\
**Intent**: Attribute dedicated Web API work sessions to downstream application users and metadata via `contextvars` without mixing identity across concurrent tasks.\
**Non-goals**: Authentication credentials passed via `AuthContext` (`REQ-CONFIG-003`).

`arodonata.core.context` (`UserContext`) and `ArodonataClient.user_context()` SHALL bind caller attribution metadata (`session_name`, `session_description`, `user_id`, `username`) to `contextvars`, applying `session_name` and `session_description` automatically to dedicated write sessions while preserving clean outer context on exit.

#### Scenario: SCN-SESS-009-1 — UserContext attributes dedicated sessions safely via contextvars

- **WHEN** `create_dedicated_session` or `write_session` runs inside `async with` / `with client.user_context(session_name="change-42", session_description="ticket", username="alice"):` without explicit session metadata overrides
- **THEN** the opened session SHALL receive `session_name` and `session_description` from the active `UserContext` (`login` / `set-session`)
- **AND** exiting the `user_context` block SHALL restore the previous `UserContext` without mutating concurrent tasks
