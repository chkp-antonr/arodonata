# Spec Delta

## MODIFIED Requirements

### Requirement: Strict Web API Command Name Validation

**ID**: REQ-TRANS-001\
**Intent**: Block path traversal, query injection, and malformed API commands on the client before opening connections, logging in, or touching pools.\
**Non-goals**: Payload schema validation against Check Point API reference (`REQ-APIREF-004`).

`AMgmtClient` transport and `api_call` execution SHALL validate every Check Point Web API command string against `^[a-z0-9]+(-[a-z0-9]+)*$` before `is_readonly_command()` classification, login, or request URL construction, rejecting whitespace, slashes, traversal, percent-encoding, and uppercase characters.

#### Scenario: SCN-TRANS-001-1 — Path traversal or malformed command rejected before network I/O

- **WHEN** `AMgmtClient.api_call` or transport execution receives a command violating `^[a-z0-9]+(-[a-z0-9]+)*$` (such as `"show-hosts/../publish"`, `"show-x/%2e%2e/publish"`, `"../../gaia_api/v1.7/run-script"`, `"show-hosts?x=1"`, `" show-hosts "`, or `"SHOW-HOSTS"`)
- **THEN** the client SHALL raise `ValidationError` immediately before `is_readonly_command()` classification, session login, connection acquisition, or sending any network bytes

### Requirement: Atomic Cross-Process Known-Hosts Persistence and IPv6 Key Normalization

**ID**: REQ-TRANS-003\
**Intent**: Prevent multi-worker TOFU known-hosts file corruption, enforce owner-only directory/file security, and support IPv6 literal endpoints reliably.\
**Non-goals**: TLS trust mode policy enforcement (`REQ-TRANS-002`).

TLS trust-store persistence SHALL create parent directories with `0700`, reject symlinked trust stores (`S_ISLNK`) and non-sticky group/world-writable parent directories before network I/O, write `tls_known_hosts.json` (`0600`) under cross-process locking atomically, and normalize RFC-compliant `[host]:port` IPv6 keys.

#### Scenario: SCN-TRANS-003-1 — First contact learned in TOFU mode

- **GIVEN** `tls_trust="tofu"` and `host:port` absent from `tls_known_hosts.json`
- **WHEN** the first TLS handshake completes
- **THEN** the SHA-256 fingerprint SHALL be persisted atomically to `tls_known_hosts.json` (mode `0600`) under an exclusive OS lock after re-reading and merging on-disk entries
- **AND** a subsequent connection to `host:port` presenting a different fingerprint SHALL raise `CertificateMismatchError`

#### Scenario: SCN-TRANS-003-2 — IPv6 host and port keys parsed without ambiguity

- **WHEN** a management server or domain endpoint uses an IPv6 literal (`[2001:db8::1]:443` or `2001:db8::1`)
- **THEN** both `tls_known_hosts.json` and `ARODONATA_TLS_FINGERPRINTS` SHALL normalize and match `[ipv6]:port` without splitting on internal colons

#### Scenario: SCN-TRANS-003-3 — Symlinked trust store or unsafe parent directory permissions rejected before network I/O

- **WHEN** `tls_known_hosts.json` or its lock target is a symlink, its parent directory has unsafe group/world write bits without a sticky bit, OR an owner-managed `euid` store in `"tofu"` mode has group/world read bits (`S_IRGRP | S_IROTH`) vs a `uid=0` read-only mounted `ConfigMap` (`0444`/`0644`)
- **THEN** `TrustStore` SHALL raise `TrustStoreError` for symlinks and unsafe writable dirs before API requests, create new parent dirs with mode `0700`, emit a `WARNING` for over-readable `euid` `tofu` stores, and preserve compatibility with `uid=0` read-only mounts

### Requirement: Verified Connection Pooling for Read-Only and Session-Scoped Commands

**ID**: REQ-TRANS-004\
**Intent**: Reduce TLS handshake overhead across sequential read-only and dedicated-session commands without leaking SIDs or missing host-key eviction.\
**Non-goals**: Socket timeout classification (`REQ-TRANS-007`) or task polling (`REQ-TRANS-005`).

The HTTPS transport SHALL pool fingerprint-verified keep-alive connections keyed by canonicalized `(host, port)` (lowercase DNS, uncompressed-agnostic RFC-5952 IPv6) for up to 10s idle and `< 95` requests, closing matching canonical idle sockets on `close_host`/`close_scope` and non-pooled commands without exposing raw `sid`s.

#### Scenario: SCN-TRANS-004-1 — Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and below 95 requests on that socket
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: SCN-TRANS-004-2 — Mutating commands and idle connections bypass reuse

- **WHEN** a session-boundary command (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`), an un-scoped non-`show-*` command, `close_host`/`close_scope` with mixed-case hostname or equivalent IPv6 spelling (`"2001:0db8::1"` / `"[2001:db8::1]"`), or a call after `> 10s` idle runs
- **THEN** the transport SHALL canonicalize the host key, close all matching idle pooled sockets before connecting, send `Connection: close`, and open a fresh TLS-verified connection

#### Scenario: SCN-TRANS-004-3 — Sequential commands within a dedicated session reuse session-scoped keep-alive connection

- **WHEN** non-boundary commands (`show-session`, `add-*`, `set-*`, `delete-*`, `show-task`) run with a dedicated `session_scope` on the same `(server_ip, port)` within 10s and `< 95` requests
- **THEN** they SHALL reuse the pooled connection isolated to that `session_scope` without setting `Connection: close`, while keeping shared read-only calls and distinct `session_scope`s isolated

#### Scenario: SCN-TRANS-004-4 — Pooled socket rotates cleanly before server max-keepalive request limit

- **WHEN** a pooled socket reaches 95 HTTP requests or signals closure (`should_close`)
- **THEN** the transport SHALL close that socket on release instead of re-pooling it so the next request opens a fresh verified connection before the server's 100-request keep-alive limit

### Requirement: Socket-Level Connect and Read Timeouts Without Automatic Resend

**ID**: REQ-TRANS-007\
**Intent**: Enforce unambiguous failure semantics and never double-execute non-idempotent Check Point commands after bytes leave the socket.\
**Non-goals**: Timeout budget settings resolution (`REQ-CONFIG-004`).

`AMgmtClient` HTTPS transport SHALL enforce connect/read timeouts and `max_response_bytes` response-body limits, disable redirects (`allow_redirects=False`), classify `TransportError` (`phase="connect"` / `request_sent=False` before wire send, including `RateLimitTimeoutError`, vs `"read"` / `"post-send"` with `request_sent=True`), and never resend after `request_sent=True`.

#### Scenario: SCN-TRANS-007-1 — Socket connect or handshake timeout

- **WHEN** TCP connect or TLS handshake exceeds `connect_timeout`, OR local MDS concurrency slot acquisition raises `RateLimitTimeoutError` before any network I/O
- **THEN** TCP/TLS timeouts SHALL raise `ApiTimeoutError` (`TimeoutError` subclass) with `phase="connect"`, `request_sent=False`, and target `host`/`port`, and `RateLimitTimeoutError` SHALL set `request_sent=False` so callers know no bytes were transmitted

#### Scenario: SCN-TRANS-007-2 — Socket read timeout

- **WHEN** waiting for the server's HTTP response exceeds the call's read timeout
- **THEN** the transport SHALL raise `ApiTimeoutError` with `phase="read"`, `request_sent=True`, naming the server and command and warning that the command may still have executed

#### Scenario: SCN-TRANS-007-3 — Connection reset or broken pipe after request transmission never resends

- **WHEN** the peer resets or closes the connection (`ConnectionResetError`, `BrokenPipeError`, `ServerDisconnectedError`, or post-connect `ClientOSError`) after request bytes were written
- **THEN** the transport SHALL raise `TransportError` with `phase="post-send"` (`request_sent=True`), and neither the transport nor CMA failover recovery SHALL resend the request

#### Scenario: SCN-TRANS-007-4 — HTTP redirects are never followed

- **WHEN** the server responds with any `3xx` redirect status (`301`, `302`, `303`, `307`, `308`)
- **THEN** the transport SHALL NOT follow the redirect (`allow_redirects=False`), SHALL NOT transmit `X-chkp-sid` or request bodies to `Location`, and SHALL fail the call immediately

#### Scenario: SCN-TRANS-007-5 — Oversized HTTP response body rejected before unbounded memory buffering

- **WHEN** a server sends a response whose `Content-Length` header or streamed byte count exceeds `ArodonataSettings.max_response_bytes`
- **THEN** `ApiTransport` SHALL abort reading at `max_response_bytes + 1` bytes, close the socket without pooling, raise `TransportError` with `phase="read"` (`request_sent=True`), and never automatically resend the request
