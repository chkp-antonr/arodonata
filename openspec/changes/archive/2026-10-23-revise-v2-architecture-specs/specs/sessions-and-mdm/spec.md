# Sessions, Multi-Domain Resolution, and Concurrency Specification Delta

## ADDED Requirements

### Requirement: Hybrid and Dynamic Authentication with Context-Bound WriteSession Overlay

The system SHALL support hybrid authentication (shared read-only credentials with per-admin write credentials) and dynamic authentication via `contextvars` (`AuthContext` / `AuthProvider`), and SHALL bind isolated `WriteSession` instances in `contextvars` with an in-memory `SessionOverlay` so read operations within that session reflect uncommitted creations, updates, and deletions.

#### Scenario: WriteSession opens under administrator credentials and isolates uncommitted state

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_creds):` executes `add_host`, `set_host`, or `delete_host` followed by `get_hosts()`
- **THEN** the session SHALL authenticate under `admin_creds`, record the mutated objects in the session's `SessionOverlay` via `contextvars`, and return `get_hosts()` with created/updated hosts included and deleted hosts excluded without modifying the shared database cache until `publish`

#### Scenario: Dynamic authentication resolves credentials from AuthContext and evicts stale admin password

- **WHEN** the client runs in `"dynamic"` mode without static startup credentials and an admin request provides credentials via `client.auth_context(...)` or `AuthProvider`
- **THEN** `LoginCoordinator` SHALL use those credentials to establish sessions, and if a subsequent login fails with `InvalidCredentialsError` (e.g., after a password change), it SHALL immediately evict those credentials and notify `AuthProvider` without retrying

## MODIFIED Requirements

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

### Requirement: Stale Session Cleanup and Startup Session Seed

`SessionCleaner` SHALL clean up stale or abandoned API sessions on configured management servers on startup (when static credentials are available) and upon max-sessions refusal, deferring cleanup in `"dynamic"` auth mode until valid credentials are provided.

#### Scenario: Startup cleanup seeds system domain SID when cache is empty

- **WHEN** `schedule_startup_cleanup()` runs on client entry with static credentials and no cached SID or in-flight login exists for a server's system domain
- **THEN** the session opened by `SessionCleaner` to inspect/discard stale sessions SHALL be retained in `sid_cache` for subsequent read calls rather than logged out

#### Scenario: Cold startup in dynamic auth mode skips network cleanup

- **WHEN** `ArodonataClient` enters its context manager in `"dynamic"` auth mode before any administrator credentials have been supplied
- **THEN** startup session cleanup SHALL be skipped without raising an authentication error
