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

## REMOVED Requirements

### Requirement: Stale Session Cleanup and Startup Session Seed

**Reason**: Replaced fail-closed by `Stale Session Cleanup Without Read-Write Cache Seeding` (`REQ-SESS-004`, `DA-030`) because Wave 7's delta was never synced into `openspec/specs/sessions-and-mdm/spec.md`.

**Migration**: Close `SessionCleaner`'s read-write probe session via `logout_sid` on exit and let subsequent read-only calls acquire fresh `"read-only": true` SIDs via `REQ-SESS-003`.
