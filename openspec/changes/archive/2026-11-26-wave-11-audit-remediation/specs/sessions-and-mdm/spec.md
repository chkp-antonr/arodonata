# Spec Delta

## ADDED Requirements

### Requirement: SessionCleaner Identity Fail-Fast, Keepalive Isolation, and Single-Resolution Read-Only Target Lookup

**ID**: REQ-SESS-015\
**Intent**: Prevent silent swallowing of TLS identity errors in background session cleanup, isolate dedicated SIDs from `auth_identity=None` keepalive sweeps, and eliminate redundant DNS resolution.\
**Non-goals**: Base rate-limiting rules (`REQ-SESS-007`) or startup cleanup SID exclusion (`REQ-SESS-004`).

`SessionCleaner` SHALL propagate `ServerIdentityError` immediately, `LoginCoordinator.keepalive_sid()` SHALL avoid `auth_identity=None` fallbacks and route dedicated SIDs safely, `target_resolver` SHALL guard `evict_sid` when `expired_identity is None`, and `get_readonly_session()` SHALL pass prevalidated host targets without repeating DNS resolution.

#### Scenario: SCN-SESS-015-1 — SessionCleaner identity propagation, dedicated keepalive isolation, and single-DNS read-only login

- **GIVEN** a TLS `ServerIdentityError` inside `SessionCleaner`, a `keepalive_sid()` sweep across explicit dedicated SIDs or credential errors, or an explicit hostname target in `get_readonly_session()`
- **WHEN** cleanup, keepalive maintenance, or read-only session acquisition runs
- **THEN** `SessionCleaner` SHALL re-raise `ServerIdentityError`, `keepalive_sid()` SHALL return `False` on credential failure without evicting unrelated `auth_identity=None` caches, and `get_readonly_session()` SHALL resolve explicit hostnames once per call
