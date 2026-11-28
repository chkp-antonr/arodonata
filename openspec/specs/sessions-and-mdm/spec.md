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

### Requirement: Fail-Closed DNS Pinning for Unresolvable Explicit Hostnames

**ID**: REQ-SESS-010\
**Intent**: Prevent unpinned hostname forwarding to transport when DNS resolution returns no answers during explicit server validation.\
**Non-goals**: Subset validation when DNS resolves or explicit IP literals (`REQ-SESS-008`).

When `AMgmtClient` validates an explicit non-IP hostname `server_ip` whose DNS lookup yields zero A/AAAA answers, validation SHALL fail closed with `ValidationError` before any connection attempt rather than forwarding an unresolved hostname to transport.

#### Scenario: SCN-SESS-010-1 — Unresolvable explicit hostname raises ValidationError before transport connect

- **GIVEN** a management endpoint configured with a hostname (`mgmt.example.com`) whose DNS resolution returns zero A/AAAA records during validation
- **WHEN** `AMgmtClient` (`api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid`) receives `explicit_server_ip="mgmt.example.com"`
- **THEN** validation SHALL raise `ValidationError` before opening a TLS connection or transmitting `X-chkp-sid`
- **AND** callers SHALL never receive an unpinned raw hostname for transport connect-time re-resolution

### Requirement: Unconditional Startup Stale-Session Inspection

**ID**: REQ-SESS-011\
**Intent**: Guarantee startup stale-session cleanup always inspects and discards abandoned Arodonata sessions even when a previous run left an unexpired read-only System Data SID in cache.\
**Non-goals**: Read-only SID cache reuse (`REQ-SESS-003`) or RW cleanup logout/filtering rules (`REQ-SESS-004`).

On startup cleanup when static credentials exist, `AMgmtClient` and `SessionCleaner` SHALL open a temporary read-write session, inspect `show-sessions`, discard eligible abandoned Arodonata-owned sessions, and log out via `logout_sid` without short-circuiting on cached read-only System Data SIDs.

#### Scenario: SCN-SESS-011-1 — Startup cleanup inspects and discards abandoned sessions despite cached read-only System Data SID

- **GIVEN** static credentials and an unexpired read-only System Data `SIDCacheEntry` persisted in `arodonata_sid_cache` alongside an abandoned Arodonata-owned session (`changes == 0`, `locks == 0`) on the server
- **WHEN** startup session cleanup runs (`run_startup_cleanup()` or `schedule_startup_cleanup()`)
- **THEN** cleanup SHALL NOT return early on the cached read-only SID and SHALL query `show-sessions`, discard eligible abandoned sessions, and close its temporary read-write session via `logout_sid`
- **AND** the pre-existing fresh cached read-only System Data SID SHALL remain preserved in `arodonata_sid_cache`

### Requirement: Hostname-Bound TLS Fingerprint Enforcement Across Canonical IP Pinning

**ID**: REQ-SESS-012\
**Intent**: Prevent TOFU first-contact bypass or cross-host pin substitution when an explicit hostname is resolved and connected via its pinned canonical IP literal.\
**Non-goals**: Unresolvable hostname rejection (`REQ-SESS-010`) or DNS-rebinding subset validation (`REQ-SESS-008`).

When an explicit `server_ip` hostname is resolved and pinned to a canonical trusted IP literal before connecting, TLS certificate fingerprint verification (`TrustPolicy` in `"pinned"`, `"tofu"`, and `"lab-memory"` modes) SHALL also enforce any certificate fingerprint pinned or previously persisted under that hostname (`<hostname>:<port>`), rejecting mismatched peer certificates with `CertificateMismatchError` before transmitting any HTTP request or `X-chkp-sid`.

#### Scenario: SCN-SESS-012-1 — Hostname-pinned and TOFU-learned TLS fingerprints remain enforced when connecting to a resolved canonical IP

- **GIVEN** a management endpoint with a certificate fingerprint pinned in `ARODONATA_TLS_FINGERPRINTS` or previously persisted in `tls_known_hosts.json` under `mgmt.example.com:443` while `mgmt.example.com` resolves to trusted IP `10.0.0.50`
- **WHEN** `AMgmtClient` executes an API call, read-only login, keepalive, or logout with `server_ip="mgmt.example.com"` and `10.0.0.50:443` presents either the expected fingerprint or a different certificate (including another server's pinned fingerprint or an unknown MITM certificate in `"tofu"` mode)
- **THEN** the connection SHALL dial `10.0.0.50:443` directly without connect-time DNS re-resolution and succeed when `10.0.0.50:443` presents `mgmt.example.com:443`'s fingerprint
- **AND** any certificate mismatch against `mgmt.example.com:443`'s pinned or TOFU-stored fingerprint SHALL raise `CertificateMismatchError` before sending HTTP headers or `X-chkp-sid`

### Requirement: Canonical Domain Discovery, Shared WriteSession Lifecycle, and Decomposed Session Execution

**ID**: REQ-SESS-013\
**Intent**: Eliminate diverged domain parsers, missing RBAC fallback in MDS discovery, duplicated `WriteSession` teardown logic, and monolithic session/route execution paths.\
**Non-goals**: Login throttle backoff semantics (`REQ-SESS-006`) or base VSX repository bundle parsing (`REQ-TOPO-008`).

`arodonata` SHALL use one canonical domain parser for `parse_domain_entry` and `parse_domain_dict`, support `details-level="standard"` RBAC fallback in `fetch_domain_topology_from_mds`, share a `WriteSession` teardown helper, and decompose `run_repository_script` and `_collect_gateway_routes_impl` into focused helpers.

#### Scenario: SCN-SESS-013-1 — Canonical domain parser identity, MDS standard RBAC fallback, and shared WriteSession lifecycle

- **GIVEN** raw MDS domain payloads parsed via `parse_domain_entry` or `parse_domain_dict`, an MDS returning permission denial on `details-level="full"`, or `WriteSession` exits (clean vs exception) across `open_api_write_session` and `AMgmtClient.write_session`
- **WHEN** domains are discovered or write sessions are opened and closed
- **THEN** `sessions.parse_domain_entry` and `response_classifiers.parse_domain_entry` SHALL preserve object identity and parse identically to `parse_domain_dict`
- **AND** `fetch_domain_topology_from_mds` SHALL fall back to `details-level="standard"` preserving cached CMA IPs, and both `WriteSession` entrypoints SHALL enforce identical publish/discard/logout semantics

#### Scenario: SCN-SESS-013-2 — Decomposed run_repository_script and route collection preserve SID redaction and coalescing

- **GIVEN** `ScriptRepositoryService.run_repository_script()` across session modes or `collect_gateway_routes()` across VSX coalesced nodes
- **WHEN** repository scripts run (with normal completion, validation failure, or session errors) or multi-gateway route collection executes
- **THEN** every session exception branch and task output SHALL scrub SIDs uniformly and close dedicated sessions cleanly
- **AND** coalescing execution, per-gateway persistence, and post-TaskGroup domain sync-state finalization SHALL run via isolated composable helpers

### Requirement: Lifecycle TLS Identity Binding, Discovery Retry Integrity, and Session Secret Hardening

**ID**: REQ-SESS-014\
**Intent**: Preserve hostname-bound TLS pins across the full session lifecycle, prevent failed domain discovery from suppressing retries, enforce target-MDS throttling and typed lock-timeout errors, and mask secrets on model serialization.\
**Non-goals**: Base rate-limit sizing (`REQ-SESS-007`) or initial TOFU enrollment policy (`REQ-TRANS-002`).

`ArodonataClient` SHALL preserve hostname TLS pin binding across cached/dedicated sessions and expired-SID retries, gate `domain_list_ttl` on `status == "ok"`, translate distributed login-gate lock timeouts to `AuthenticationError`, throttle stale-session cleanup on the target MDS member, and mask secrets in `AuthContext` and `ServerEndpointConfig` `model_dump()` outputs.

#### Scenario: SCN-SESS-014-1 — Hostname-bound TLS pinning persists across first-contact TOFU, keepalive/logout sweeps, and expired-SID retries

- **GIVEN** a hostname endpoint (`mgmt.example.com`) verified via `TrustPolicy` in `tofu` or `pinned` mode
- **WHEN** first-contact TOFU records fingerprints, cached or dedicated sessions run `keepalive` / `logout` / non-system `api_call()`, or an expired read-only SID retries
- **THEN** `TrustPolicy` SHALL bind both `(resolved_ip, port)` and `(hostname, port)`, and session operations SHALL preserve `tls_identity_host` and target IP pinning end-to-end

#### Scenario: SCN-SESS-014-2 — Failed domain discovery does not suppress subsequent smart refreshes for domain_list_ttl

- **GIVEN** a management server whose cached domain list exceeded `domain_list_ttl` and whose `show-domains` call fails transiently (`status="failed"`)
- **WHEN** a caller (including a restarted process or sibling worker) invokes `get_domains(cache_mode="smart")` shortly thereafter
- **THEN** `DomainService` SHALL treat `status != "ok"` sync state as stale and re-attempt live domain discovery instead of suppressing retries for `domain_list_ttl`

#### Scenario: SCN-SESS-014-3 — Distributed LoginGate timeout raises AuthenticationError and SessionCleaner throttles target MDS member

- **GIVEN** a contended distributed `login_gate:<mds_ip>` lock or a multi-MDS domain hosted on a secondary MDS member
- **WHEN** `LoginGate.acquire()` times out on `LockPort` or `SessionCleaner` runs `show-sessions` / `discard` for that domain
- **THEN** `LoginGate.acquire()` SHALL raise `AuthenticationError` rather than `LockAcquisitionError`
- **AND** `SessionCleaner` SHALL acquire `RateLimiter` slots against the target domain's resolved `mds_ip` (while expired-SID retries in `api_call` also refresh `mds_ip`)

#### Scenario: SCN-SESS-014-4 — AuthContext and ServerEndpointConfig mask password and api_key on model_dump and clean obsolete login residue

- **GIVEN** `AuthContext` or `ServerEndpointConfig` instances populated with `password` or `api_key`
- **WHEN** `.model_dump()` or `.model_dump_json()` is called directly or through an enclosing Pydantic model
- **THEN** `password` and `api_key` SHALL be emitted as `REDACTED_PLACEHOLDER` (never plaintext), while `LoginCoordinator` omits dead startup-seeding methods and racy `_inflight_logins` state

### Requirement: SessionCleaner Identity Fail-Fast, Keepalive Isolation, and Single-Resolution Read-Only Target Lookup

**ID**: REQ-SESS-015\
**Intent**: Prevent silent swallowing of TLS identity errors in background session cleanup, isolate dedicated SIDs from `auth_identity=None` keepalive sweeps, and eliminate redundant DNS resolution.\
**Non-goals**: Base rate-limiting rules (`REQ-SESS-007`) or startup cleanup SID exclusion (`REQ-SESS-004`).

`SessionCleaner` SHALL propagate `ServerIdentityError` immediately, `LoginCoordinator.keepalive_sid()` SHALL avoid `auth_identity=None` fallbacks and route dedicated SIDs safely, `target_resolver` SHALL guard `evict_sid` when `expired_identity is None`, and `get_readonly_session()` SHALL pass prevalidated host targets without repeating DNS resolution.

#### Scenario: SCN-SESS-015-1 — SessionCleaner identity propagation, dedicated keepalive isolation, and single-DNS read-only login

- **GIVEN** a TLS `ServerIdentityError` inside `SessionCleaner`, a `keepalive_sid()` sweep across explicit dedicated SIDs or credential errors, or an explicit hostname target in `get_readonly_session()`
- **WHEN** cleanup, keepalive maintenance, or read-only session acquisition runs
- **THEN** `SessionCleaner` SHALL re-raise `ServerIdentityError`, `keepalive_sid()` SHALL return `False` on credential failure without evicting unrelated `auth_identity=None` caches, and `get_readonly_session()` SHALL resolve explicit hostnames once per call

### Requirement: Pinned Session Cleanup, Recursive Overlay Redaction, and Accurate Script Stage Attribution

**ID**: REQ-SESS-016\
**Intent**: Close DNS-rebinding windows in startup/recovery session cleanup, strip nested secrets from session overlays, and report accurate operation names on script errors.\
**Non-goals**: Changing Check Point session expiry thresholds or RBAC permissions.

`SessionCleaner` MUST preserve DNS-pinned IP and `tls_identity_host` when calling `show-sessions` and `discard`. Session overlay tracking MUST recursively strip sensitive keys at every nesting depth, and `ScriptRepositoryService` MUST attribute `RepositoryScriptPermissionError.operation` to the exact failing stage.

#### Scenario: SCN-SESS-016-1 — Pinned SessionCleaner TLS calls, recursive overlay stripping, and stage-accurate script errors

- **GIVEN** a DNS hostname management server during `SessionCleaner` cleanup, a `WriteSession` command containing nested sensitive keys, or a `ScriptRepositoryService` login/mutation/publish permission failure
- **WHEN** cleanup RPCs execute, overlay command history updates, or script repository methods raise `RepositoryScriptPermissionError`
- **THEN** `SessionCleaner` SHALL pass the DNS-pinned IP and `tls_identity_host` to `show-sessions` and `discard`
- **AND** `SessionOverlay` SHALL strip sensitive keys recursively and `ScriptRepositoryService` SHALL report the true failing phase in `operation`
