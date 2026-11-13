# Proposal: Dedicated-Session Keep-Alive Connection Pooling and Transport Pool Lifecycle Hardening

## Why

Live integration runs against Check Point MDSM (`CPWS` / `httpd2`) revealed intermittent `ServerDisconnectedError` (`0`-byte pre-response EOF) failures during sequential mutations (`test_change_report_session.py` and `test_large_layer.py`) caused by three transport pooling flaws: (1) idle `show-*` keep-alive sockets were only evicted *after* non-`show-*` commands executed rather than *before* opening a fresh connection, holding `CPWS` worker slots while parallel TLS handshakes occurred; (2) restricting keep-alive reuse strictly to `show-*` forced sequential commands inside an isolated dedicated write session (`WriteSession` or explicit `sid`) to perform a full TCP+TLS handshake per mutation (`124` handshakes in `test_large_layer.py`); and (3) `FingerprintTCPConnector._release()` reset `PooledSocketEntry.request_count` to `1` on every release, preventing socket rotation at `95` requests before `CPWS`'s `100`-request keep-alive limit, while `ssl.create_default_context()` performed unnecessary synchronous CA loading.

## What Changes

- **Session-Scoped Keep-Alive Pooling for Dedicated Sessions**: Extend `VerifiedConnectionPool`, `FingerprintTCPConnector`, `ApiTransport`, `AMgmtClient`, and `LoginCoordinator` with an optional non-reversible `session_scope` tag derived via `derive_session_pool_scope(sid)` (`s:<16-hex>` SHA-256 prefix) so sequential in-session commands inside dedicated sessions reuse their own verified keep-alive connection (up to 10s idle and `< 95` requests) without exposing raw SIDs in pool keys or `repr()`.
- **Pre-Connect Idle Socket Eviction & Session Boundary Isolation**: Close idle pooled sockets *before* connecting for session-boundary commands (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`) and un-scoped mutating commands, keep shared `sid_cache` pooling restricted to `show-*` commands, and evict dedicated-session sockets upon `logout_sid()`.
- **Connector Request-Count Tracking & Lightweight TLS 1.2+ Context**: Preserve per-protocol `request_count` across `FingerprintTCPConnector` acquire/release cycles, check `ResponseHandler.should_close` in `PooledSocketEntry.is_usable()`, and initialize a module-level TLS 1.2+ `SSLContext` (`PROTOCOL_TLS_CLIENT`, `TLSVersion.TLSv1_2`, `OP_NO_COMPRESSION`, `OP_NO_RENEGOTIATION`, ALPN `http/1.1`) without disk CA bundle loads.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `transport-and-tls`: Extend `VerifiedConnectionPool` and `ApiTransport` to support session-scoped keep-alive pooling for dedicated sessions alongside shared `show-*`-only pooling, pre-connect idle socket closure before boundary/non-pooled commands, 95-request socket rotation, and lightweight TLS 1.2+ `SSLContext` initialization while retaining strict `phase="post-send"` (`request_sent=True`) non-resend guarantees.

## Impact

- `src/arodonata/adapters/checkpoint/transport.py` and `src/arodonata/adapters/checkpoint/__init__.py`: Pool keying by `(host, port, scope)`, `derive_session_pool_scope`, `is_poolable_command`, `MAX_KEEPALIVE_REQUESTS_PER_SOCKET`, `NON_POOLABLE_SESSION_COMMANDS`, pre-connect eviction, `FingerprintTCPConnector` per-protocol state tracking, and `_DEFAULT_CHECKPOINT_SSL_CONTEXT`.
- `src/arodonata/adapters/checkpoint/client.py`: Pass `session_scope` conditionally on dedicated-session `api_call` / `show-task` executions and bind `self._connection_pool` to `transport.connection_pool` when a custom `transport` is supplied.
- `src/arodonata/adapters/checkpoint/sessions.py`: Close dedicated-session pooled sockets via `close_session_scope` in `LoginCoordinator.logout_sid`.
- `tests/unit/test_transport.py` and `tests/unit/test_sessions.py`: Unit and loopback TLS integration tests for pre-connect closure, scope isolation, SID non-exposure, `WriteSession` keep-alive reuse, and 95-request socket rotation.
