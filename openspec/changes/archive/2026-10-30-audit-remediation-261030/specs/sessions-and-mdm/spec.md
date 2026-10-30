# Spec Delta

## MODIFIED Requirements

### Requirement: Persistent SID Caching and Auto-Recovery

The system SHALL authenticate shared `arodonata_sid_cache` sessions with `"read-only": true`, key rows by `f"{mgmt_name}:{domain_key}:{auth_identity}"` (excluding `SIDCacheEntry.sid` from model dumps and defaulting `SIDCacheEntry.id` to include `auth_identity`), evict only the affected `auth_identity` row on expiry, failover, keepalive failure, or logout failure, and refuse mutating commands on `arodonata_sid_cache`.

#### Scenario: Reuse of unexpired cached session scoped by authentication identity

- **WHEN** a read-only API call targets `(mgmt_name, domain)` under resolved credentials (`auth_identity`)
- **THEN** `LoginCoordinator` SHALL authenticate new `arodonata_sid_cache` sessions with `"read-only": true`, reuse an unexpired row matching exact `f"{mgmt_name}:{domain_key}:{auth_identity}"`, omit raw `sid` from `SIDCacheEntry.model_dump()` / `model_dump_json()`, and NEVER match or overwrite another principal's cached SID

#### Scenario: Transparent re-login on session expiration error

- **WHEN** a read-only API call using a cached SID encounters session expiration or CMA failover, a background `keepalive` returns `success=False`, or `logout_all` evicts an unloggable cached SID
- **THEN** the client SHALL evict ONLY that specific `(mgmt_name, domain_key, auth_identity)` row from `arodonata_sid_cache` (leaving other administrators' cached SIDs for the same domain intact) and, for active read-only API calls, acquire a fresh session via `LoginCoordinator` and retry once

#### Scenario: Dedicated write sessions bypass global SID cache

- **WHEN** `create_dedicated_session` or `write_session` is called for isolated write workflows
- **THEN** `LoginCoordinator` SHALL authenticate a fresh read-write session (`"read-only"` omitted/`False`) with retry/backoff resilience, return `(sid, server_ip)` without storing the SID in `arodonata_sid_cache`, keep the SID registered in `_active_dedicated_sids` until `logout_sid()` succeeds, and shield `discard`/`logout_sid()` against `asyncio.CancelledError` (`BaseException`)

#### Scenario: Mutating commands refused on shared cached SID path

- **WHEN** `AMgmtClient.api_call` is invoked with a non-read-only command (`add-*`, `set-*`, `delete-*`, `publish`, `discard`, `install-policy`, `run-script`, etc.) without an explicit `sid` or active `WriteSession` in `contextvars`
- **THEN** `AMgmtClient` SHALL refuse to execute the command on the shared `arodonata_sid_cache` session (raising `SessionStateError` unless called via high-level `ArodonataClient` helpers that open an isolated dedicated session)

### Requirement: Per-MDS-Member Concurrency Semaphore

The `RateLimiter` SHALL cap in-flight API requests per MDS member to `concurrent_limit` (default 4, max 20) using database-backed slot locks (with TTL `>= max(api_timeout, login_timeout) + 60s`) and FIFO in-process waiter queues, suppressing database `Exception` errors during shielded DB lock release while always releasing the local FIFO slot and propagating `asyncio.CancelledError`.

#### Scenario: Fair waiter wakeup on slot release

- **WHEN** all `concurrent_limit` slots for an MDS member are occupied, multiple coroutines are waiting, and the active slot holder exits (including when DB lock release raises an `Exception` or the task receives `asyncio.CancelledError`)
- **THEN** `RateLimiter` SHALL shield DB lock cleanup (`suppress(Exception)`), ALWAYS release the local FIFO slot in `finally` to wake the longest-waiting coroutine in arrival order, and re-raise `asyncio.CancelledError` if cancellation occurred rather than swallowing it

#### Scenario: Coalesced background keepalive sweeps

- **WHEN** background session keepalive sweeps are triggered during API activity (including when one awaiting caller is cancelled)
- **THEN** overlapping keepalive sweeps SHALL be coalesced and protected via `asyncio.shield` so at most one sweep runs at a time without starving active caller slots or aborting sibling waiters

### Requirement: Multi-Domain Discovery, Failover IP Resolution, and Global Domain Support

`DomainService` and `LoginCoordinator` SHALL discover and cache domains on MDS servers (`show-domains`, `show-mdss`, `show-global-domain`), track each domain's `active_ip`, `active_mds_ip`, and standby servers, and validate any caller-supplied `explicit_server_ip` against configured endpoint hosts and discovered MDS/domain server addresses for `mgmt_name`.

#### Scenario: Opt-in Global domain visibility

- **WHEN** `get_domains(include_global=False)` (the default) is called
- **THEN** the `Global` domain row SHALL be excluded from the returned list; when `include_global=True`, the `Global` domain row SHALL be included

#### Scenario: Periodic domain list refresh via DomainListRefreshTracker

- **WHEN** `get_domains` or smart cache refresh runs
- **THEN** the domain list (`show-domains`) SHALL be re-fetched from the management server when the `domains` table is empty, when the 1-hour domain-list TTL has elapsed, or when `mode="force"` is requested

#### Scenario: Cold-cache CMA IP resolution and active domain server failover re-resolution

- **WHEN** a customer or `Global` domain login runs before `domains` is cached (cold cache) or when a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** `LoginCoordinator` SHALL query the MDS system domain (`show-domains`, `show-mdss`, and `show-global-domain`) to resolve and cache the domain's `active_ip` (CMA IP) and `active_mds_ip` in the `domains` table before authenticating against the domain

#### Scenario: Untrusted explicit_server_ip rejected before connection or SID transmission

- **WHEN** `resolve_target_ips` (via `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid`) receives an `explicit_server_ip` that does not match `mgmt_name`'s configured endpoint host or any cached domain `active_ip`, `active_mds_ip`, or `standby_ips` / MDS member IP for `mgmt_name`
- **THEN** `LoginCoordinator` SHALL reject the target with `ValidationError` before opening a TLS connection, learning a TOFU certificate, or transmitting `X-chkp-sid`
