# Transport, TLS Identity Verification, and Task Polling Specification

## Purpose

Defines the native `asyncio` Check Point Management API HTTPS transport (`AMgmtClient`), pre-request SHA-256 certificate fingerprint identity verification and TOFU persistence, verified keep-alive connection pooling, socket-level connect and read timeout handling without unsafe retries, asynchronous `show-task` polling, and continuity-verified pagination (`api_query`).

## Requirements

### Requirement: Strict Web API Command Name Validation

**ID**: REQ-TRANS-001\
**Intent**: Block path traversal, query injection, and malformed API commands on the client before opening connections or touching pools.\
**Non-goals**: Payload schema validation against Check Point API reference (`REQ-APIREF-004`).

`AMgmtClient` transport execution SHALL validate every Check Point Web API command string against `^[a-z0-9]+(-[a-z0-9]+)*$` before constructing the request URL, rejecting path traversal sequences, slashes, percent-encoding, whitespace, and uppercase characters.

#### Scenario: SCN-TRANS-001-1 — Path traversal or malformed command rejected before network I/O

- **WHEN** a call executes with a command violating `^[a-z0-9]+(-[a-z0-9]+)*$` (such as `"show-hosts/../publish"`, `"show-x/%2e%2e/publish"`, `"../../gaia_api/v1.7/run-script"`, `"show-hosts?x=1"`, or `"SHOW-HOSTS"`)
- **THEN** the transport SHALL raise `ValidationError` before acquiring a connection or sending any network bytes

### Requirement: Pre-Request TLS Certificate Fingerprint Verification

**ID**: REQ-TRANS-002\
**Intent**: Pin and verify management server TLS identities after handshake and prior to sending any secrets, headers, or payloads.\
**Non-goals**: TOFU known-hosts file locking and IPv6 key syntax (`REQ-TRANS-003`).

The transport SHALL verify the peer SHA-256 fingerprint immediately after TLS handshake and BEFORE sending headers or payloads across `"pinned"`, `"tofu"`, and `"lab-memory"` modes, bind `SSLContext` creation to `TrustPolicy`, log first-contact TOFU warnings and `arodonata.tls_decision` spans, forbid proxies and unverified hooks, and never retry `ServerIdentityError`.

#### Scenario: SCN-TRANS-002-1 — Untrusted certificate refused in pinned mode

- **GIVEN** `tls_trust="pinned"` where the server at `host:port` presents a certificate whose SHA-256 fingerprint is absent from both the trust store and `ARODONATA_TLS_FINGERPRINTS`
- **WHEN** a connection is established
- **THEN** the connection SHALL close before any request bytes are sent
- **AND** `UnknownServerCertificateError` (or `CertificateMismatchError` if another fingerprint was pinned) SHALL be raised with `"No request was sent."` in the message

#### Scenario: SCN-TRANS-002-2 — Known MDS member fingerprint accepted on a new domain IP

- **GIVEN** a domain server IP presenting a certificate whose SHA-256 fingerprint is already trusted for another address in the trust store or `ARODONATA_TLS_FINGERPRINTS`
- **WHEN** the transport connects to that domain IP
- **THEN** the certificate SHALL be accepted (and recorded as `known-identity` in `"tofu"` mode)

#### Scenario: SCN-TRANS-002-3 — Lab-memory mode restricted to lab environment

- **WHEN** `tls_trust="lab-memory"` is configured without `ARODONATA_LAB` set in the environment
- **THEN** trust configuration initialization SHALL raise `ConfigurationError`

#### Scenario: SCN-TRANS-002-4 — Proxy connections and unverified sender seams rejected

- **WHEN** proxy environment variables (`HTTPS_PROXY`, `ALL_PROXY`) are present, a proxy connection is attempted, or a custom sender seam lacks peer certificate verification outside explicit unit test fixtures
- **THEN** the transport SHALL ignore ambient proxy variables (`trust_env=False`), refuse proxy connections before sending request bytes, and never bypass pre-request certificate verification

#### Scenario: SCN-TRANS-002-5 — Identity errors are never retried

- **WHEN** a connection raises `ServerIdentityError` (`CertificateMismatchError`, `UnknownServerCertificateError`, or `TrustStoreError`)
- **THEN** login, keepalive, and task-wait loops SHALL propagate the error immediately without retrying

#### Scenario: SCN-TRANS-002-6 — First-contact TOFU and lab-memory trust emit audit warning, record tls_decision span attribute, and bind SSLContext to TrustPolicy

- **WHEN** `TrustPolicy.verify_der()` / `verify_fingerprint()` trusts a server on first contact (`"tofu"` or `"lab-memory"`), matches a stored or pinned certificate, or rejects an untrusted/mismatched/missing certificate, OR when `TrustPolicy.create_ssl_context()` / `create_verified_ssl_context()` creates a client `SSLContext`
- **THEN** first-contact `"tofu"` and `"lab-memory"` acceptance SHALL emit a structured `WARNING` audit log (`event="tls_tofu_first_contact"`, `host`, `port`, `fingerprint`, `mode`) without secrets or SIDs
- **AND** OpenTelemetry spans SHALL record `arodonata.tls_decision` (`"pinned_match"`, `"tofu_match"`, `"tofu_first_contact"`, `"lab_memory_first_contact"`, `"known_identity_match"`, `"lab_memory_match"`, `"mismatch"`, `"unpinned_rejected"`, or `"missing_cert"`)
- **AND** `TrustPolicy.create_ssl_context()` / `create_verified_ssl_context(policy)` SHALL validate `TrustPolicy` and enforce TLS 1.2+, `OP_NO_COMPRESSION`, and HTTP/1.1 ALPN for post-handshake SHA-256 verification

### Requirement: Atomic Cross-Process Known-Hosts Persistence and IPv6 Key Normalization

**ID**: REQ-TRANS-003\
**Intent**: Prevent multi-worker TOFU known-hosts file corruption and support IPv6 literal endpoints reliably.\
**Non-goals**: TLS trust mode policy enforcement (`REQ-TRANS-002`).

TLS trust-store persistence SHALL write `tls_known_hosts.json` with `0600` permission checks using cross-process file locking and atomic read-merge-write, and SHALL normalize RFC-compliant IPv6 `[host]:port` address keys in both `tls_known_hosts.json` and `ARODONATA_TLS_FINGERPRINTS`.

#### Scenario: SCN-TRANS-003-1 — First contact learned in TOFU mode

- **GIVEN** `tls_trust="tofu"` and `host:port` absent from `tls_known_hosts.json`
- **WHEN** the first TLS handshake completes
- **THEN** the SHA-256 fingerprint SHALL be persisted atomically to `tls_known_hosts.json` (mode `0600`) under an exclusive OS lock after re-reading and merging on-disk entries
- **AND** a subsequent connection to `host:port` presenting a different fingerprint SHALL raise `CertificateMismatchError`

#### Scenario: SCN-TRANS-003-2 — IPv6 host and port keys parsed without ambiguity

- **WHEN** a management server or domain endpoint uses an IPv6 literal (`[2001:db8::1]:443` or `2001:db8::1`)
- **THEN** both `tls_known_hosts.json` and `ARODONATA_TLS_FINGERPRINTS` SHALL normalize and match `[ipv6]:port` without splitting on internal colons

### Requirement: Verified Connection Pooling for Read-Only and Session-Scoped Commands

**ID**: REQ-TRANS-004\
**Intent**: Reduce TLS handshake overhead across sequential read-only and dedicated-session commands without leaking SIDs or violating session-boundary hygiene.\
**Non-goals**: Socket timeout classification (`REQ-TRANS-007`) or task polling (`REQ-TRANS-005`).

The HTTPS transport SHALL pool fingerprint-verified keep-alive connections for up to 10 seconds idle and fewer than 95 requests per socket across read-only `show-*` commands and non-boundary dedicated-session commands (`session_scope`), closing idle sockets before non-pooled commands and never exposing raw `sid`s in pool keys or `repr()`.

#### Scenario: SCN-TRANS-004-1 — Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and below 95 requests on that socket
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: SCN-TRANS-004-2 — Mutating commands and idle connections bypass reuse

- **WHEN** a session-boundary command (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`), an un-scoped non-`show-*` command, or a call after `> 10s` idle runs
- **THEN** the transport SHALL close matching idle pooled sockets before connecting, send `Connection: close`, and open a fresh TLS-verified connection

#### Scenario: SCN-TRANS-004-3 — Sequential commands within a dedicated session reuse session-scoped keep-alive connection

- **WHEN** non-boundary commands (`show-session`, `add-*`, `set-*`, `delete-*`, `show-task`) run with a dedicated `session_scope` on the same `(server_ip, port)` within 10s and `< 95` requests
- **THEN** they SHALL reuse the pooled connection isolated to that `session_scope` without setting `Connection: close`, while keeping shared read-only calls and distinct `session_scope`s isolated

#### Scenario: SCN-TRANS-004-4 — Pooled socket rotates cleanly before server max-keepalive request limit

- **WHEN** a pooled socket reaches 95 HTTP requests or signals closure (`should_close`)
- **THEN** the transport SHALL close that socket on release instead of re-pooling it so the next request opens a fresh verified connection before the server's 100-request keep-alive limit

### Requirement: Self-Managed Asynchronous Task Polling

**ID**: REQ-TRANS-005\
**Intent**: Handle long-running Check Point async operations reliably without blocking event loops or misclassifying partial task failures as success.\
**Non-goals**: Paging over task-based query results (`REQ-TRANS-006`).

`AMgmtClient` SHALL execute Check Point Web API commands asynchronously without blocking worker threads and poll any returned `task-id` / `tasks` entries via `show-task` using exponential backoff (`2s` up to `10s`) under the separate `task_timeout` budget.

#### Scenario: SCN-TRANS-005-1 — Successful task completion returns final show-task response

- **WHEN** an API command (`publish`, `install-policy`, `revert-to-revision`, `assign-global-assignment`, etc.) returns a task identifier
- **THEN** `AMgmtClient` SHALL poll `show-task` until all tasks reach terminal state and return `success=True` only when every task's status is in the explicit success allowlist (`succeeded`)

#### Scenario: SCN-TRANS-005-2 — Failed or partially succeeded task returns success=False without raising

- **WHEN** a polled server task finishes with `failed` or `partially succeeded`
- **THEN** `api_call` SHALL return `ApiCallResult(success=False, ...)` with the raw `show-task` payload and error message rather than raising an exception

#### Scenario: SCN-TRANS-005-3 — Tolerance of transient poll failures

- **WHEN** individual `show-task` polls fail or time out transiently fewer than 5 consecutive times within `task_timeout`
- **THEN** polling SHALL continue until completion, or raise `TaskPollError` on 5 consecutive poll failures or `TaskTimeoutError` (`TimeoutError` subclass) if `task_timeout` expires

### Requirement: Continuity-Verified Object Listing Pagination

**ID**: REQ-TRANS-006\
**Intent**: Guarantee gap-free and duplicate-free multi-page Check Point object listings even under concurrent SmartConsole mutations.\
**Non-goals**: Rulebase section-merge pagination (`REQ-RULE-001`).

`AMgmtClient.api_query()` SHALL page object listings in chunks (default 300, max 500), acquiring and releasing a per-MDS concurrency slot per page so short API calls can interleave between pages, and verifying `from`, `to`, `total`, and object UID uniqueness across pages.

#### Scenario: SCN-TRANS-006-1 — Boundary swap duplicate UID recovery

- **WHEN** Check Point reorders two equal-name objects across a page boundary, producing a duplicate UID on the new page
- **THEN** `api_query` SHALL drop the duplicate and re-read a small boundary window (up to 10 objects on each side) in one request to recover the displaced object without restarting the full listing

#### Scenario: SCN-TRANS-006-2 — Total count change or continuity break triggers single restart

- **WHEN** `total` changes mid-listing, `from`/`to` continuity breaks, or the distinct UID count disagrees with `total`
- **THEN** `api_query` SHALL restart once from the initial offset, and if the second pass also fails continuity checks, return a failed `ApiQueryResult` with `code="paging_inconsistent"` instead of silent gaps or duplicates

#### Scenario: SCN-TRANS-006-3 — Task-based query commands paged through show-task polling

- **WHEN** `api_query` executes a task-based query command (such as `show-changes` or `show-logs`)
- **THEN** each page SHALL run via `api_call` (`show-task` polling unpacking `tasks[].task-details[]`) until `to >= total`, failing the entire query if any page fails or stops advancing

### Requirement: Socket-Level Connect and Read Timeouts Without Automatic Resend

**ID**: REQ-TRANS-007\
**Intent**: Enforce unambiguous failure semantics and never double-execute non-idempotent Check Point commands after bytes leave the socket.\
**Non-goals**: Timeout budget settings resolution (`REQ-CONFIG-004`).

`AMgmtClient` HTTPS transport SHALL enforce explicit TCP/TLS `connect_timeout` and socket read timeouts on every `/web_api/<command>` call, disable HTTP redirects (`allow_redirects=False`), classify every `TransportError` with `phase` (`"connect"` / `request_sent=False` vs `"read"` / `"post-send"` with `request_sent=True`), and NEVER automatically resend a general API request after `request_sent=True` (except `LoginCoordinator`'s gated single `login` retry under `REQ-SESS-006`).

#### Scenario: SCN-TRANS-007-1 — Socket connect or handshake timeout

- **WHEN** TCP connect or TLS handshake exceeds `connect_timeout`
- **THEN** the transport SHALL raise `ApiTimeoutError` (`TimeoutError` subclass) with `phase="connect"`, `request_sent=False`, and the target `host` and `port`

#### Scenario: SCN-TRANS-007-2 — Socket read timeout

- **WHEN** waiting for the server's HTTP response exceeds the call's read timeout
- **THEN** the transport SHALL raise `ApiTimeoutError` with `phase="read"`, `request_sent=True`, naming the server and command and warning that the command may still have executed

#### Scenario: SCN-TRANS-007-3 — Connection reset or broken pipe after request transmission never resends

- **WHEN** the peer resets or closes the connection (`ConnectionResetError`, `BrokenPipeError`, `ServerDisconnectedError`, or post-connect `ClientOSError`) after request bytes were written
- **THEN** the transport SHALL raise `TransportError` with `phase="post-send"` (`request_sent=True`), and neither the transport nor CMA failover recovery SHALL resend the request

#### Scenario: SCN-TRANS-007-4 — HTTP redirects are never followed

- **WHEN** the server responds with any `3xx` redirect status (`301`, `302`, `303`, `307`, `308`)
- **THEN** the transport SHALL NOT follow the redirect (`allow_redirects=False`), SHALL NOT transmit `X-chkp-sid` or request bodies to `Location`, and SHALL fail the call immediately
