# Spec Delta

## ADDED Requirements

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
