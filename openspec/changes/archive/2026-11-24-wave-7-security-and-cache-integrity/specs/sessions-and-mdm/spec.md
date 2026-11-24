# Spec Delta

## ADDED Requirements

### Requirement: Stale Session Cleanup Without Read-Write Cache Seeding

**ID**: REQ-SESS-004\
**Intent**: Reclaim abandoned Arodonata API sessions fail-closed without ever touching human/dirty sessions or placing read-write SIDs into shared read-only caches.\
**Non-goals**: Read-only SID cache scoping (`REQ-SESS-003`).

The session manager SHALL clean up stale or abandoned Arodonata-owned sessions on startup (when static credentials exist) and on max-sessions refusal, restricting `discard` to Arodonata sessions (`application == "arodonata"` or `arodonata` prefix) with `changes == 0` and `locks == 0`, and SHALL log out its read-write cleanup session without seeding `arodonata_sid_cache`.

#### Scenario: SCN-SESS-004-1 — Startup cleanup logs out read-write probe session without seeding shared read-only SID cache

- **GIVEN** static credentials on client entry
- **WHEN** startup session cleanup runs `show-sessions` and discards stale Arodonata sessions using its temporary read-write cleanup session
- **THEN** `SessionCleaner` SHALL close that temporary read-write session via `logout_sid` on completion or error
- **AND** it SHALL NEVER insert a read-write SID into `arodonata_sid_cache` (so subsequent read-only calls acquire fresh `"read-only": true` sessions under `REQ-SESS-003`)

#### Scenario: SCN-SESS-004-2 — Foreign administrator sessions and sessions with unpublished changes are never discarded

- **WHEN** stale-session cleanup inspects `show-sessions` and sees sessions belonging to human administrators, other tools, or sessions with non-zero `changes` or `locks`
- **THEN** cleanup SHALL skip those sessions and NEVER issue `discard` or `take-over-session` against them

#### Scenario: SCN-SESS-004-3 — Cold startup in dynamic auth mode skips network cleanup

- **WHEN** `ArodonataClient` enters its context manager in `"dynamic"` auth mode before any administrator credentials are supplied
- **THEN** startup session cleanup SHALL be skipped without raising an authentication error

## MODIFIED Requirements

### Requirement: Hybrid and Dynamic Authentication with Context-Bound WriteSession Overlay

**ID**: REQ-SESS-002\
**Intent**: Support per-request dynamic credentials and isolated `contextvars` write overlays without exposing secrets, dirtying shared caches, or misrouting `System Data` calls.\
**Non-goals**: Shared read-only SID caching (`REQ-SESS-003`).

The system SHALL support hybrid and dynamic `contextvars` authentication (`AuthContext` / `AuthProvider`), bind `WriteSession` instances with an in-memory `SessionOverlay`, and match target `(mgmt_name, domain)` via `normalize_domain_key()` so `domain=None` (`"System Data"`) calls never route into a domain-scoped `WriteSession`.

#### Scenario: SCN-SESS-002-1 — WriteSession opens under administrator credentials and isolates uncommitted state

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_creds):` executes `add_host`, `set_host`, or `delete_host` followed by `get_hosts()`, OR executes a `domain=None` (`"System Data"`) call (`show-domains`, `show-mdss`) inside an active domain-scoped `WriteSession`
- **THEN** domain mutations SHALL record in `SessionOverlay` via `contextvars` without mutating shared database cache rows until `publish`
- **AND** `domain=None` calls SHALL normalize via `normalize_domain_key(None)` (`"System Data"`), never match a non-system domain `WriteSession`, and execute outside that domain write session

#### Scenario: SCN-SESS-002-2 — Dynamic authentication resolves credentials from AuthContext and evicts stale admin password

- **GIVEN** `"dynamic"` mode without static startup credentials where credentials come from `client.auth_context(...)` or `AuthProvider`
- **WHEN** a subsequent login using those credentials fails with `InvalidCredentialsError` (e.g., after a password change)
- **THEN** the client SHALL immediately evict those credentials and notify `AuthProvider` without retrying

### Requirement: Identity-Scoped Read-Only SID Caching and Dedicated Write Sessions

**ID**: REQ-SESS-003\
**Intent**: Prevent cross-principal SID reuse, preserve keepalive-extended read-only SIDs, and ensure mutating commands never execute on shared read-only sessions.\
**Non-goals**: Startup cleanup of abandoned Arodonata sessions (`REQ-SESS-004`).

The system SHALL authenticate `arodonata_sid_cache` sessions with `"read-only": true` keyed by `f"{mgmt_name}:{domain_key}:{auth_identity}"` (omitting `sid` in model dumps), honor `keepalive_sid`-extended `expires_at` freshness, normalize omitted `domain` on keepalive eviction, preserve healthy SIDs on `RateLimitTimeoutError`, and refuse mutating commands on shared SIDs.

#### Scenario: SCN-SESS-003-1 — Reuse of unexpired cached session scoped by authentication identity

- **WHEN** a read-only API call targets `(mgmt_name, domain)` under resolved credentials (`auth_identity`), including after `keepalive_sid` extended `expires_at` past the original `created_at + session_expire_seconds` window
- **THEN** new `arodonata_sid_cache` sessions SHALL authenticate with `"read-only": true` and `is_sid_entry_fresh` SHALL honor the extended `expires_at` window for exact `f"{mgmt_name}:{domain_key}:{auth_identity}"` rows
- **AND** `SIDCacheEntry.model_dump()` / `model_dump_json()` SHALL omit raw `sid`, and another principal's cached SID SHALL NEVER be matched or overwritten

#### Scenario: SCN-SESS-003-2 — Transparent re-login on session expiration error

- **WHEN** a read-only call using a cached SID hits session expiration/CMA failover, `keepalive_sid` returns `success=False` (with explicit or omitted `domain`), or `logout_all` fails — vs when local semaphore acquisition raises `RateLimitTimeoutError` (`request_sent=False`)
- **THEN** expiration, keepalive failure (under normalized `domain`), or logout failure SHALL evict ONLY that `(mgmt_name, domain_key, auth_identity)` row from `arodonata_sid_cache` and retry active read-only calls once
- **AND** `RateLimitTimeoutError` (`request_sent=False`) SHALL NOT evict the healthy cached read-only SID

#### Scenario: SCN-SESS-003-3 — Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called
- **THEN** `AMgmtClient` SHALL authenticate a fresh read-write session (`"read-only"` omitted/`False`) with retry/backoff resilience and return `(sid, server_ip)` without storing it in `arodonata_sid_cache`
- **AND** the session SHALL remain tracked for cleanup until `logout_sid()` succeeds, shielding `discard` and `logout_sid()` against any `BaseException` (including `asyncio.CancelledError`)

#### Scenario: SCN-SESS-003-4 — Mutating commands refused on shared cached SID path

- **WHEN** `AMgmtClient.api_call` receives a mutating command (`add-*`, `set-*`, `delete-*`, `publish`, `discard`, `install-policy`, `run-script`, etc.) without an explicit `sid` or active `WriteSession` in `contextvars`
- **THEN** `AMgmtClient` SHALL refuse to run it on the shared `arodonata_sid_cache` session by raising `SessionStateError`

### Requirement: Per-MDS-Member Concurrency Semaphore

**ID**: REQ-SESS-007\
**Intent**: Bound concurrent API requests per MDS safely using FIFO fairness, shielded cleanup, cancellation propagation, and coalesced keepalive sweeps.\
**Non-goals**: Login serialization and throttle windows (`REQ-SESS-005`, `REQ-SESS-006`).

The client SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using DB slot locks (`>= max(api_timeout, login_timeout) + 60s`) and FIFO waiter queues, suppressing only `Exception` during shielded DB cleanup while propagating `asyncio.CancelledError` across semaphore release and `logout_sid`.

#### Scenario: SCN-SESS-007-1 — Fair waiter wakeup on slot release

- **GIVEN** all `concurrent_limit` slots for an MDS member are occupied and multiple coroutines are queued in arrival order, OR a task calling `LoginCoordinator.logout_sid` is cancelled
- **WHEN** an active slot holder exits (including when DB lock release raises `Exception` or `asyncio.CancelledError` occurs) OR `logout_sid` receives `asyncio.CancelledError`
- **THEN** DB lock cleanup SHALL suppress only `Exception`, the local FIFO slot SHALL ALWAYS release in `finally` to wake the longest-waiting coroutine, and `asyncio.CancelledError` SHALL propagate out of both semaphore waiters and `logout_sid` without being swallowed

#### Scenario: SCN-SESS-007-2 — Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity (including if an awaiting caller is cancelled)
- **THEN** overlapping keepalive sweeps SHALL coalesce under `asyncio.shield` so at most one sweep runs at a time without starving active caller slots or aborting sibling waiters

### Requirement: Untrusted Explicit Server IP Rejection

**ID**: REQ-SESS-008\
**Intent**: Prevent SSRF or credential/SID exfiltration via untrusted `explicit_server_ip` or dual-A-record / DNS-rebinding hostnames.\
**Non-goals**: Pre-request TLS certificate fingerprint verification (`REQ-TRANS-002`).

`AMgmtClient` (across `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, and `logout_sid`) SHALL validate `explicit_server_ip` against `mgmt_name`'s trusted addresses requiring all resolved DNS A/AAAA IPs to be a subset of trusted IPs, returning and connecting to the validated canonical IP rather than re-resolving hostnames.

#### Scenario: SCN-SESS-008-1 — Untrusted explicit_server_ip rejected before connection or SID transmission

- **WHEN** `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid` receives an `explicit_server_ip` whose IP literal or any resolved DNS A/AAAA record is absent from `mgmt_name`'s configured/discovered server IPs (e.g., dual-A-record returning one trusted IP and `169.254.169.254`), OR receives a trusted hostname resolving exclusively to trusted IPs
- **THEN** any non-subset address SHALL raise `ValidationError` before opening a TLS connection, learning a TOFU certificate, or transmitting `X-chkp-sid`
- **AND** when valid, `validate_explicit_server_ip` SHALL return the canonical validated IP string and callers SHALL connect to that pinned IP without a second unpinned DNS lookup

## REMOVED Requirements

### Requirement: Stale Session Cleanup and Startup Session Seed

**Reason**: Replaced fail-closed by `Stale Session Cleanup Without Read-Write Cache Seeding` (`DA-042`) so a read-write cleanup probe SID is never seeded into the shared read-only `arodonata_sid_cache` (`REQ-SESS-003`).

**Migration**: Close `SessionCleaner`'s read-write probe session via `logout_sid` on exit and let subsequent read-only calls acquire fresh `"read-only": true` SIDs via `REQ-SESS-003`.
