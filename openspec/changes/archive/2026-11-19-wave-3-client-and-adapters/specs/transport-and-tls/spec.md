# Spec Delta

## MODIFIED Requirements

### Requirement: Pre-Request TLS Certificate Fingerprint Verification

**ID**: REQ-TRANS-002\
**Intent**: Pin and verify management server TLS identities after handshake and prior to sending any secrets, headers, or payloads.\
**Non-goals**: TOFU known-hosts file locking and IPv6 key syntax (`REQ-TRANS-003`).

The transport SHALL verify the server certificate SHA-256 fingerprint at `host:port` immediately after the TLS handshake and BEFORE sending HTTP headers, credentials, API keys, or payloads across `"pinned"`, `"tofu"`, and `ARODONATA_LAB`-gated `"lab-memory"` modes, bind `SSLContext` creation to `TrustPolicy`, log TOFU first-contact warnings and `arodonata.tls_decision` spans, forbid proxies (`trust_env=False`), and never retry `ServerIdentityError`.

#### Scenario: SCN-TRANS-002-6 — First-contact TOFU and lab-memory trust emit audit warning, record tls_decision span attribute, and bind SSLContext to TrustPolicy

- **WHEN** `TrustPolicy.verify_der()` / `verify_fingerprint()` trusts a server on first contact (`"tofu"` or `"lab-memory"`), matches a stored or pinned certificate, or rejects an untrusted/mismatched/missing certificate, OR when `TrustPolicy.create_ssl_context()` / `create_verified_ssl_context()` creates a client `SSLContext`
- **THEN** first-contact `"tofu"` and `"lab-memory"` acceptance SHALL emit a structured `WARNING` audit log (`event="tls_tofu_first_contact"`, `host`, `port`, `fingerprint`, `mode`) without secrets or SIDs
- **AND** OpenTelemetry spans SHALL record `arodonata.tls_decision` (`"pinned_match"`, `"tofu_match"`, `"stored_match"`, `"tofu_first_contact"`, `"lab_memory_first_contact"`, `"known_identity_match"`, `"lab_memory_match"`, `"mismatch"`, `"unpinned_rejected"`, or `"missing_cert"`)
- **AND** `TrustPolicy.create_ssl_context()` / `create_verified_ssl_context(policy)` SHALL return a `PolicyBoundSSLContext` enforcing TLS 1.2+, `OP_NO_COMPRESSION`, and HTTP/1.1 ALPN bound to the validated `TrustPolicy`, while `FingerprintTCPConnector` SHALL reject invalid `TrustPolicy` objects with `ConfigurationError`
