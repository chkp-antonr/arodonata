## MODIFIED Requirements

### Requirement: Per-MDS-Member Login Gate and Throttle Recovery

The system SHALL serialize and rate-limit logins per hosting MDS member (`active_mds_ip`, falling back to configured server IP) via `LoginGate`, enforcing a minimum inter-login spacing and shared throttle cooldown inside the gate, logging a `WARNING` when entering a login throttle cooldown, bounding local `asyncio.Lock` acquisition by `wait_timeout`, and executing CMA failover IP refreshes (`refresh_domain_active_ip`) and retry backoff sleeps outside the gate so recursive system-domain logins on the same MDS IP never deadlock.

#### Scenario: Throttled login waits out Check Point throttle window

- **WHEN** a login attempt is rejected due to Check Point login throttling or times out during the read phase
- **THEN** `LoginGate` SHALL record the per-MDS cooldown window (`login_throttle_window`, default 70s, or exponential read-timeout backoff) and log a `WARNING` message with the server IP and cooldown duration so subsequent queued callers respect the cooldown before sending another `login`, and `LoginCoordinator` SHALL release the gate before sleeping and retrying within `login_max_wait` (default 900s)

#### Scenario: Cold-cache CMA failover during login does not deadlock LoginGate

- **WHEN** a login to a customer domain on `mds_ip` encounters a transport or failover error and triggers `refresh_domain_active_ip()` while the system domain SID is not yet cached (requiring a system domain login to the same `mds_ip`)
- **THEN** `LoginCoordinator` SHALL release the `LoginGate` for `mds_ip` before invoking `refresh_domain_active_ip()` so the nested system-domain login acquires `LoginGate(mds_ip)` cleanly without self-deadlock

#### Scenario: Credential rejection or locked account fails fast with InvalidCredentialsError

- **WHEN** the Check Point server rejects login credentials (`Authentication to server failed` or `Administrator account is locked`) rather than reporting a transient revision/lock condition (`Database revision is in progress`)
- **THEN** `LoginCoordinator` SHALL raise `InvalidCredentialsError` (a subclass of `AuthenticationError`) without exhausting transient retry loops

### Requirement: Stale Session Cleanup and Startup Session Seed

`SessionCleaner` SHALL clean up stale or abandoned Arodonata-owned API sessions on configured management servers on startup (when static credentials are available) and upon max-sessions refusal, logging `DEBUG` entries when discarding stale Arodonata sessions, and strictly restricting `discard` to sessions created by Arodonata (`application == "arodonata"` or `arodonata` session-name prefix) that have `changes == 0` and `locks == 0`.

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

`DomainService` and `LoginCoordinator` SHALL discover and cache domains on MDS servers (`show-domains`, `show-mdss`, `show-global-domain`), log `DEBUG` messages when discovering/caching domains and resolving active domain CMA/MDS IPs, track each domain's `active_ip`, `active_mds_ip`, and standby servers, and validate any caller-supplied `explicit_server_ip` against configured endpoint hosts and discovered MDS/domain server addresses for `mgmt_name`.

#### Scenario: Opt-in Global domain visibility

- **WHEN** `get_domains(include_global=False)` (the default) is called
- **THEN** the `Global` domain row SHALL be excluded from the returned list; when `include_global=True`, the `Global` domain row SHALL be included

#### Scenario: Periodic domain list refresh via DomainListRefreshTracker

- **WHEN** `get_domains` or smart cache refresh runs
- **THEN** the domain list (`show-domains`) SHALL be re-fetched from the management server when the `domains` table is empty, when the 1-hour domain-list TTL has elapsed, or when `mode="force"` is requested, retrying with `details-level="standard"` if `details-level="full"` is rejected by Check Point RBAC (preserving any previously cached `active_ip`, `active_mds_ip`, `standby_ips`, and `servers`), logging `DEBUG` messages at discovery start and after caching the discovered domain records, and logging a `WARNING` with the server error code and message if discovery fails

#### Scenario: Cold-cache CMA IP resolution and active domain server failover re-resolution

- **WHEN** a customer or `Global` domain login runs before `domains` is cached (cold cache) or when a domain's cached `active_ip` fails with a failover/unreachable error code
- **THEN** `LoginCoordinator` SHALL query the MDS system domain (`show-domains`, `show-mdss`, and `show-global-domain`) to resolve and cache the domain's `active_ip` (CMA IP) and `active_mds_ip` in the `domains` table and log a `DEBUG` entry before authenticating against the domain

#### Scenario: Untrusted explicit_server_ip rejected before connection or SID transmission

- **WHEN** `resolve_target_ips` (via `api_call`, `get_readonly_session`, `create_dedicated_session`, `keepalive_sid`, or `logout_sid`) receives an `explicit_server_ip` that does not match `mgmt_name`'s configured endpoint host or any cached domain `active_ip`, `active_mds_ip`, or `standby_ips` / MDS member IP for `mgmt_name`
- **THEN** `LoginCoordinator` SHALL reject the target with `ValidationError` before opening a TLS connection, learning a TOFU certificate, or transmitting `X-chkp-sid`
