# Spec Delta: Transport, TLS Identity Verification, and Task Polling

## MODIFIED Requirements

### Requirement: Verified Connection Pooling for Read-Only Commands

`ApiTransport` SHALL pool fingerprint-verified keep-alive HTTPS connections (`VerifiedConnectionPool`) for up to 10 seconds idle and fewer than 95 requests per socket across read-only `show-*` commands and non-boundary dedicated-session commands (`session_scope`), closing idle sockets before non-pooled commands and never exposing raw SIDs in pool keys or `repr()`.

#### Scenario: Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and the pooled socket remains open below 95 requests
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: Mutating commands and idle connections bypass reuse

- **WHEN** a session-boundary command (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`), an un-scoped non-`show-*` command, or a command after a >10s idle gap executes
- **THEN** `ApiTransport` SHALL close matching idle pooled sockets before initiating a new handshake, evict closed protocol tracking entries, send `Connection: close`, and open a fresh TLS-verified connection

#### Scenario: Sequential commands within a dedicated session reuse session-scoped keep-alive connection

- **WHEN** non-boundary commands (such as `show-session`, `add-*`, `set-*`, `delete-*`, or `show-task`) run with a dedicated `session_scope` on the same `(server_ip, port)` within 10 seconds and fewer than 95 requests
- **THEN** they SHALL reuse the pooled verified connection isolated to that `session_scope` (without setting `Connection: close`), while concurrent shared read-only calls or distinct `session_scope` values remain isolated

#### Scenario: Pooled socket rotates cleanly before server max-keepalive request limit

- **WHEN** a pooled socket reaches 95 HTTP requests in `FingerprintTCPConnector` or reports `should_close`
- **THEN** the transport SHALL close that socket on release instead of re-pooling it, so the next request opens a fresh TLS-verified connection before hitting the server's 100-request keep-alive limit
