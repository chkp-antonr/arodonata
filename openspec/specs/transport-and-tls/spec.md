# Transport, TLS Identity Verification, and Task Polling Specification

## Purpose

Defines the native `asyncio` Check Point Management API transport (`ApiTransport` over `aiohttp`), SHA-256 certificate fingerprint identity verification (`TrustPolicy` and `TrustStore`), verified read-only connection pooling (`VerifiedConnectionPool`), socket-level timeout enforcement, transport-owned asynchronous task polling (`TaskWaiter`), and continuity-verified pagination (`pager.py`).

## Requirements

### Requirement: Pre-Request TLS Certificate Fingerprint Verification

The transport SHALL verify the SHA-256 fingerprint of the server certificate presented at `host:port` immediately after the TLS handshake and BEFORE sending any HTTP headers, credentials, API keys, or command payloads, and SHALL protect `TrustStore` persistence with cross-process file locking, atomic read-merge-write, `0600` permission checks, and RFC-compliant IPv6 `[host]:port` address keys while forbidding unverified HTTP proxies (`trust_env=False`).

#### Scenario: Untrusted certificate refused in pinned mode

- **WHEN** `tls_trust="pinned"` and the server at `host:port` presents a certificate whose SHA-256 fingerprint is neither in the trust store nor in `ARODONATA_TLS_FINGERPRINTS`
- **THEN** the connection SHALL be closed before any request bytes are sent and `UnknownServerCertificateError` (or `CertificateMismatchError` if another fingerprint was pinned for that address) SHALL be raised with `"No request was sent."` in the message

#### Scenario: First contact learned in TOFU mode

- **WHEN** `tls_trust="tofu"` and `host:port` has no entry in the trust store
- **THEN** the presented certificate's SHA-256 fingerprint SHALL be persisted atomically to the trust store (`tls_known_hosts.json` with mode `0600`) under an exclusive OS file lock after re-reading and merging on-disk entries so concurrent workers never clobber learned fingerprints, and subsequent connections to `host:port` presenting a different fingerprint SHALL raise `CertificateMismatchError`

#### Scenario: Known MDS member fingerprint accepted on a new domain IP

- **WHEN** a domain server IP presents a certificate whose SHA-256 fingerprint is already trusted for another address (either in the trust store or in `ARODONATA_TLS_FINGERPRINTS`)
- **THEN** the certificate SHALL be accepted for the new address (and recorded as `known-identity` in `tofu` mode)

#### Scenario: Lab-memory mode restricted to lab environment

- **WHEN** `tls_trust="lab-memory"` is configured without `ARODONATA_LAB` set in the environment
- **THEN** `TrustPolicy` initialization SHALL raise `ConfigurationError`

#### Scenario: Identity errors are never retried

- **WHEN** a connection raises `ServerIdentityError` (`CertificateMismatchError`, `UnknownServerCertificateError`, or `TrustStoreError`)
- **THEN** login, keepalive, and task-wait loops SHALL NOT retry the request and SHALL propagate the error immediately

#### Scenario: IPv6 host and port keys parsed without ambiguity

- **WHEN** a management server or domain endpoint uses an IPv6 literal (`[2001:db8::1]:443` or `2001:db8::1`)
- **THEN** `TrustStore` and `ARODONATA_TLS_FINGERPRINTS` SHALL normalize and match the canonical `[ipv6]:port` key without splitting on internal colons

#### Scenario: Proxy connections and unverified sender seams rejected

- **WHEN** environment proxy variables (`HTTPS_PROXY`, `ALL_PROXY`) are present or `_create_proxy_connection` is invoked on the connector, or `ApiTransport` is given a `request_sender` without `peer_cert_getter` outside explicit unit test fixtures
- **THEN** the transport SHALL ignore ambient proxy variables (`trust_env=False`), refuse proxy connections before sending any request bytes, and never skip pre-request certificate verification

### Requirement: Socket-Level Connect and Read Timeouts Without Automatic Resend

The native `aiohttp` transport SHALL enforce explicit TCP/TLS connect (`connect_timeout`) and socket read timeouts on every Check Point Web API (`/web_api/<command>`) connection, disable HTTP redirects (`allow_redirects=False`), classify every `TransportError` with an execution phase (`phase="connect"` with `request_sent=False` vs `phase="post-send"` with `request_sent=True`), and NEVER automatically re-send a request after bytes have been written to the socket.

#### Scenario: Socket connect or handshake timeout

- **WHEN** TCP connection or TLS handshake exceeds `connect_timeout`
- **THEN** the transport SHALL raise `ApiTimeoutError` (a subclass of `TimeoutError`) with `phase="connect"`, `request_sent=False`, and the target `host` and `port`

#### Scenario: Socket read timeout

- **WHEN** waiting for the server's HTTP response exceeds the call's read timeout
- **THEN** the transport SHALL raise `ApiTimeoutError` with `phase="read"`, `request_sent=True`, naming the server and command, and warning that the command may still have run on the server

#### Scenario: Connection reset or broken pipe after request transmission never resends

- **WHEN** the peer resets or closes the connection (`ConnectionResetError`, `BrokenPipeError`, `ServerDisconnectedError`, or post-connect `ClientOSError`) after HTTP request bytes were written
- **THEN** the transport SHALL raise `TransportError` with `phase="post-send"` (`request_sent=True`), and neither `ApiTransport` nor `AMgmtClient` CMA failover recovery SHALL re-execute the request

#### Scenario: HTTP redirects are never followed

- **WHEN** the target server responds with any `3xx` redirect status (`301`, `302`, `303`, `307`, `308`)
- **THEN** the transport SHALL NOT follow the redirect (`allow_redirects=False`), SHALL NOT transmit `X-chkp-sid` or request bodies to the `Location` target, and SHALL fail the call immediately

### Requirement: Verified Connection Pooling for Read-Only Commands

`ApiTransport` SHALL pool and reuse fingerprint-verified keep-alive HTTPS connections (`VerifiedConnectionPool`) per `(server_ip, port)` for up to 10 seconds idle exclusively for read-only `show-*` commands, reaping expired idle sockets and bounding per-protocol fingerprint tracking without memory growth while always establishing a fresh connection for login, logout, keepalive, publish, discard, and mutating commands.

#### Scenario: Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and the pooled socket remains open
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: Mutating commands and idle connections bypass reuse

- **WHEN** a non-`show-*` command is executed or a pooled connection has been idle for more than 10 seconds
- **THEN** `ApiTransport` SHALL close any expired pooled socket, evict closed protocol fingerprint entries, and open a fresh TLS-verified connection

### Requirement: Self-Managed Asynchronous Task Polling

The native `aiohttp` transport SHALL execute Check Point Web API commands asynchronously without blocking worker threads and poll any returned `task-id` / `tasks` entries via `TaskWaiter` using exponential backoff (`2s` up to `10s`) under the separate `task_timeout` budget.

#### Scenario: Successful task completion returns final show-task response

- **WHEN** an API command (such as `publish`, `install-policy`, `revert-to-revision`, or `assign-global-assignment`) returns a task identifier
- **THEN** `TaskWaiter` SHALL poll `show-task` until all tasks reach a terminal state and return the final `show-task` payload with `success=True` only when every task's status is in the explicit success allowlist (`succeeded`)

#### Scenario: Failed or partially succeeded task returns success=False without raising

- **WHEN** a polled server task finishes with `failed` or `partially succeeded`
- **THEN** `api_call` SHALL return `ApiCallResult(success=False, ...)` containing the raw `show-task` data and error message rather than raising an exception

#### Scenario: Tolerance of transient poll failures

- **WHEN** individual `show-task` poll calls fail or time out transiently fewer than 5 consecutive times within `task_timeout`
- **THEN** `TaskWaiter` SHALL continue polling until the task completes or 5 consecutive poll errors occur (raising `TaskPollError`) or `task_timeout` expires (raising `TaskTimeoutError`, a subclass of `TimeoutError`)

### Requirement: Continuity-Verified Object Listing Pagination

The `api_query` pager (`pager.py`) SHALL page object listings in chunks (default 300, max 500), acquiring and releasing a `RateLimiter` slot per page so short API calls can interleave between pages, and verifying `from`, `to`, `total`, and object UID uniqueness across pages.

#### Scenario: Boundary swap duplicate UID recovery

- **WHEN** Check Point reorders two objects with equal names across a page boundary, causing a duplicate UID on the new page
- **THEN** the pager SHALL drop the duplicate and re-read a small window (up to 10 objects on each side of the boundary) in a single request to recover the displaced object without restarting the entire listing

#### Scenario: Total count change or continuity break triggers single restart

- **WHEN** `total` changes mid-listing, `from`/`to` continuity breaks, or the final distinct object count does not match `total`
- **THEN** the pager SHALL restart the listing once from the caller's initial offset, and if the second pass also fails continuity checks, return a failed result with `code="paging_inconsistent"` instead of returning silent gaps or duplicates

#### Scenario: Task-based query commands paged through TaskWaiter

- **WHEN** `api_query` is called with a command in `TASK_QUERY_COMMANDS`
- **THEN** each page SHALL be executed via `api_call` (awaited by `TaskWaiter` and unpacked from `tasks[].task-details[]`) until `to >= total`, failing the entire query if any page fails or fails to advance

### Requirement: Strict Web API Command Name Validation

`ApiTransport.execute` SHALL validate every Check Point Web API command string against `^[a-z0-9]+(-[a-z0-9]+)*$` before constructing the request URL, rejecting path traversal sequences, slashes, percent-encoding, whitespace, and uppercase characters.

#### Scenario: Path traversal or malformed command rejected before network I/O

- **WHEN** `ApiTransport.execute` is called with a command that does not match `^[a-z0-9]+(-[a-z0-9]+)*$` (such as `"show-hosts/../publish"`, `"show-x/%2e%2e/publish"`, `"../../gaia_api/v1.7/run-script"`, `"show-hosts?x=1"`, or `"SHOW-HOSTS"`)
- **THEN** the transport SHALL raise `ValidationError` before acquiring a connection or sending any network bytes
