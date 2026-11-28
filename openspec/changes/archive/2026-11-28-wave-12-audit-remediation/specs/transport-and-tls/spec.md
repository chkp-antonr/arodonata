# Spec Delta

## ADDED Requirements

### Requirement: Atomic Multi-Key TOFU Binding and Cooldown-Safe Login Locking

**ID**: REQ-TRANS-008\
**Intent**: Eliminate TOFU trust-store poisoning, asymmetric hostname/IP binding gaps, premature read-SID eviction, and distributed login-lock TTL exhaustion under load.\
**Non-goals**: Replacing SHA-256 fingerprint pinning or altering Check Point server-side throttle limits.

TLS trust verification MUST bind both `(hostname, port)` and `(resolved_ip, port)` atomically before writing TOFU entries to disk. Read timeouts and non-failover connect errors MUST NOT evict healthy cached read-only SIDs, and login rate-limit cooldown waits MUST complete before acquiring the distributed login DB lock.

#### Scenario: SCN-TRANS-008-1 — Atomic multi-key TOFU persistence and symmetric hostname pin binding

- **GIVEN** a `tofu` or `lab-memory` trust store where `(resolved_ip, port)` is already pinned or two workers race on concurrent dual-key TOFU writes
- **WHEN** a hostname connection verifies a matching or conflicting certificate fingerprint
- **THEN** a matching fingerprint SHALL bind `(hostname, port)` symmetrically when `identity_host` is present and not yet recorded
- **AND** conflicting multi-key writes SHALL check all target keys atomically under the trust-store lock so a rejected certificate is never persisted

#### Scenario: SCN-TRANS-008-2 — Read-SID preservation on read timeout and pre-lock cooldown waiting

- **GIVEN** a cached read-only SID experiencing an `ApiTimeoutError` or non-failover `TransportError`, or a queued login facing an active rate-limit cooldown
- **WHEN** `api_call()` handles the read timeout/connect failure or `LoginGate` acquires a login slot
- **THEN** healthy cached read-only SIDs SHALL remain cached without premature eviction or orphaned sessions
- **AND** `LoginGate` SHALL wait out any active in-process cooldown before acquiring the distributed database lock
