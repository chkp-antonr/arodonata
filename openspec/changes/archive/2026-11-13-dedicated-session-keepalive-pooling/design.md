# Design: Dedicated-Session Keep-Alive Connection Pooling and Transport Pool Lifecycle Hardening

## Context

See [proposal.md](./proposal.md) for motivation. Under `master_v2`, `VerifiedConnectionPool` keyed connections strictly by `(host, port)` and restricted keep-alive reuse exclusively to `show-*` commands. Every `WriteSession` or dedicated-session mutation (`add-*`, `set-*`, `delete-*`) bypassed the pool with `Connection: close`, while `close_host()` ran only *after* non-pooled commands finished rather than *before* connecting. Additionally, `FingerprintTCPConnector._release()` constructed a fresh `PooledSocketEntry(..., request_count=1)` on every release, making `is_usable()`'s `request_count >= 95` guard unreachable in real `aiohttp` execution, and `ssl.create_default_context()` loaded system CA certificates synchronously despite `CERT_NONE` + `TrustPolicy` fingerprint verification.

## Goals / Non-Goals

**Goals:**

- Reuse fingerprint-verified keep-alive sockets across in-session commands inside dedicated sessions (`WriteSession` / explicit `sid`) without mixing connections across distinct sessions or the shared `sid_cache` scope.
- Guarantee zero raw SID presence in `VerifiedConnectionPool` keys, `PooledSocketEntry`, logs, or `repr()`.
- Evict and close idle pooled sockets *before* opening fresh TLS connections for session-boundary commands and un-scoped mutations, and upon `logout_sid()`.
- Track per-protocol `request_count` accurately across `aiohttp` connector releases so sockets rotate cleanly at `95` requests, and initialize a lightweight TLS 1.2+ `SSLContext` at module import time.
- Preserve `phase="post-send"` (`request_sent=True`) non-resend guarantees unchanged.

**Non-Goals:**

- Automatic transport-level retry or re-send after HTTP request bytes have been written to a socket.
- Keep-alive reuse across session-boundary commands (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`) or across un-scoped mutating commands on shared sessions.

## Decisions

### 1. SHA-256 Derived `session_scope` Keying in `VerifiedConnectionPool`

- **Decision**: Add `derive_session_pool_scope(sid: str) -> str` returning `f"s:{sha256(sid)[:16]}"` (empty string `""` for shared read-only scope). Key `VerifiedConnectionPool._pool` by `(host, port, scope)`.
- **Rationale**: Grouping in-session commands (`show-session`, `add-*`, `set-*`, `delete-*`, `show-task`, etc.) by derived `session_scope` avoids 120+ redundant TLS handshakes during bulk writes (`test_large_layer.py`, CPCRUD plans) while isolating concurrent admin sessions on separate sockets and never storing raw SIDs in pool structures or `repr()`.
- **Alternatives Considered**:
  - *Single shared `(host, port)` keep-alive pool for all commands including mutations*: Rejected because overlapping callers on shared vs dedicated sessions could inherit unexpected socket state, whereas scope isolation guarantees boundary separation and instant teardown via `close_session_scope()` on `logout_sid()`.

### 2. Pre-Connect Eviction and Boundary Command Enforcement

- **Decision**: Maintain `NON_POOLABLE_SESSION_COMMANDS` (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`). When acquiring a connection for a non-poolable command, `acquire_for_command()` closes both any matching `scope` queue and the shared `""` queue for `(host, port)` *before* opening the new TLS socket. Similarly, when a dedicated session opens a fresh socket (cache miss on `(host, port, scope)`), idle shared `""` sockets on `(host, port)` are closed first so `CPWS` (`httpd2`) worker slots are freed immediately. `LoginCoordinator.logout_sid()` also calls `close_session_scope(scope)` before and after `logout`.
- **Rationale**: Prevents idle `show-*` sockets from occupying Check Point `CPWS` worker slots while parallel `login`/`add-*`/`publish` handshakes run.

### 3. `ContextVar` Command/Scope Propagation & Per-Protocol `request_count` in `FingerprintTCPConnector`

- **Decision**: Pass `(command, session_scope)` from `ApiTransport._execute_with_aiohttp()` to `FingerprintTCPConnector.connect()` via `_transport_pool_ctx` (`ContextVar`), and store `_ProtoTrackEntry(fingerprint, command, pool_scope, request_count)` in a `WeakKeyDictionary[ResponseHandler, _ProtoTrackEntry]`. Check `getattr(self.protocol, "should_close", False)` in `PooledSocketEntry.is_usable()` and enforce `MAX_KEEPALIVE_REQUESTS_PER_SOCKET = 95`.
- **Rationale**: `aiohttp`'s `ClientRequest` does not carry `session_scope`, and `aiohttp` creates `ResponseHandler` once per TCP/TLS socket; tracking `request_count` in `WeakKeyDictionary` preserves the count across releases without memory leaks and cleanly rotates connections at request 95.
- **PITFALL Avoidance**: `AMgmtClient.api_call()` passes `session_scope=...` to `self._transport.execute(...)` *only* when `session_scope is not None`, preserving compatibility with test wrappers (e.g., `tests/integration/b3/test_throttling.py`) that monkeypatch `transport.execute` without a `session_scope` parameter.

### 4. Lightweight Pre-Built TLS 1.2+ `SSLContext`

- **Decision**: Create `_DEFAULT_CHECKPOINT_SSL_CONTEXT` once at module import with `ssl.PROTOCOL_TLS_CLIENT`, `CERT_NONE`, `check_hostname = False`, `TLSVersion.TLSv1_2`, `OP_NO_COMPRESSION`, `OP_NO_RENEGOTIATION` (when available), and ALPN `("http/1.1",)`. Do not pass deprecated `ssl_shutdown_timeout` to `aiohttp.TCPConnector.__init__`.
- **Rationale**: Eliminates blocking system CA bundle disk loads during `FingerprintTCPConnector.__init__` while enforcing TLS 1.2+ and HTTP/1.1 semantics before `TrustPolicy` verifies the DER certificate fingerprint.

## Risks / Trade-offs

- **[Risk] Server closes a pooled socket cleanly with 0-byte EOF between requests in `WriteSession`** → **Mitigation**: Pre-connect eviction, `should_close` inspection, 10s idle timeout, and 95-request rotation minimize server-initiated idle/limit closures. Because Check Point `POST` mutations are non-idempotent, post-send `ServerDisconnectedError` still fails fast with `phase="post-send", request_sent=True` rather than risking duplicate writes.
- **[Risk] Shared `""` idle sockets closed when a non-pooled command runs on the same `(host, port)`** → **Mitigation**: Re-establishing a shared `show-*` socket costs a single TLS handshake only when transitioning between read-only discovery and write/login bursts, avoiding concurrent worker contention on `CPWS`.

## Migration Plan

1. Implement transport and client/session pool changes behind backwards-compatible optional `session_scope: str | None = None` API.
2. Verify with unit tests (`tests/unit/test_transport.py`, `tests/unit/test_sessions.py`), static checks (`ruff`, `mypy`, `markdownlint`, `openspec validate`), and live Check Point MDSM integration bucket `int-5`.
3. Rollback is a clean revert with zero database schema changes.
