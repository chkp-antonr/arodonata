# Transport and TLS Specification Delta

## ADDED Requirements

### Requirement: Verified Connection Pooling for Read-Only Commands

`ApiTransport` SHALL pool and reuse fingerprint-verified keep-alive HTTPS connections (`VerifiedConnectionPool`) per `(server_ip, port)` for up to 10 seconds idle exclusively for read-only `show-*` commands, while always establishing a fresh connection for login, logout, keepalive, publish, discard, and mutating commands.

#### Scenario: Consecutive show commands reuse verified keep-alive connection

- **WHEN** two `show-*` API calls target the same `(server_ip, port)` within 10 seconds and the pooled socket remains open
- **THEN** the second call SHALL reuse the pooled verified connection without repeating the TCP/TLS handshake

#### Scenario: Mutating commands and idle connections bypass reuse

- **WHEN** a non-`show-*` command is executed or a pooled connection has been idle for more than 10 seconds
- **THEN** `ApiTransport` SHALL close any expired pooled socket and open a fresh TLS-verified connection

## MODIFIED Requirements

### Requirement: Socket-Level Connect and Read Timeouts Without Automatic Resend

The native `aiohttp` transport SHALL enforce explicit TCP/TLS connect (`connect_timeout`) and socket read timeouts on every Check Point Web API (`/web_api/<command>`) connection and SHALL NEVER automatically re-send an API request after request bytes have been written to the socket (whether on read timeout, `ConnectionResetError`, or `BrokenPipeError`).

#### Scenario: Socket connect or handshake timeout

- **WHEN** TCP connection or TLS handshake exceeds `connect_timeout`
- **THEN** the transport SHALL raise `ApiTimeoutError` (a subclass of `TimeoutError`) with `phase="connect"` and the target `host` and `port`

#### Scenario: Socket read timeout

- **WHEN** waiting for the server's HTTP response exceeds the call's read timeout
- **THEN** the transport SHALL raise `ApiTimeoutError` with `phase="read"`, naming the server and command, and warning that the command may still have run on the server

#### Scenario: Connection reset or broken pipe after request transmission never resends

- **WHEN** the peer resets or closes the connection (`ConnectionResetError` or `BrokenPipeError`) after HTTP request bytes were written
- **THEN** the transport SHALL propagate the transport error immediately without re-sending the request

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
