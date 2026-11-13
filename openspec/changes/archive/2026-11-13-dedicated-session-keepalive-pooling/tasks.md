# Tasks: Dedicated-Session Keep-Alive Connection Pooling and Transport Pool Lifecycle Hardening

## 1. Transport Connection Pooling, Eviction, and TLS Context (`transport.py`)

- [x] 1.1 Add `MAX_KEEPALIVE_REQUESTS_PER_SOCKET = 95`, `NON_POOLABLE_SESSION_COMMANDS`, `derive_session_pool_scope(sid)`, `is_poolable_command(command, session_scope=...)`, and pre-built `_DEFAULT_CHECKPOINT_SSL_CONTEXT` in `src/arodonata/adapters/checkpoint/transport.py` and re-export in `src/arodonata/adapters/checkpoint/__init__.py`
- [x] 1.2 Extend `PooledSocketEntry` (`pool_scope`, `should_close` check, `MAX_KEEPALIVE_REQUESTS_PER_SOCKET`) and `VerifiedConnectionPool` (`(host, port, scope)` keying, `close_scope`, `close_session_scope`, pre-connect eviction before non-pooled commands and fresh dedicated-session connects)
- [x] 1.3 Update `FingerprintTCPConnector` (`_transport_pool_ctx` `ContextVar`, `WeakKeyDictionary` `_proto_state` preserving `request_count` across releases, default `_DEFAULT_CHECKPOINT_SSL_CONTEXT`) and `ApiTransport.execute` / `_execute_with_custom_sender` / `_execute_with_aiohttp` (`session_scope: str | None = None`, pre/post-response boundary cleanup)

## 2. Client & Session Coordinator Wiring (`client.py`, `sessions.py`)

- [x] 2.1 Update `AMgmtClient.__init__` to bind `self._connection_pool` to `transport.connection_pool` when a custom `transport` is provided, and pass `session_scope=derive_session_pool_scope(active_sid)` in `AMgmtClient.api_call` (and its `show-task` poller) only when using a dedicated session (`not using_cached_sid and active_sid`)
- [x] 2.2 Update `LoginCoordinator.logout_sid` (`src/arodonata/adapters/checkpoint/sessions.py`) to close all pooled sockets for `derive_session_pool_scope(sid)` before and after executing `logout`

## 3. Unit Tests, Spec Sync, and Verification

- [x] 3.1 Add unit and loopback TLS tests in `tests/unit/test_transport.py` covering pre-connect socket eviction, `derive_session_pool_scope` non-exposure & isolation, `NON_POOLABLE_SESSION_COMMANDS` boundary enforcement, `_DEFAULT_CHECKPOINT_SSL_CONTEXT` flags, and 95-request socket rotation
- [x] 3.2 Add `AMgmtClient` `WriteSession` keep-alive reuse and publish/logout cleanup test in `tests/unit/test_sessions.py`
- [x] 3.3 Run quality gates (`ruff`, `mypy`, `markdownlint-cli`, `./pytest.sh`, `openspec validate --specs --no-interactive`) and verify live MDSM integration bucket `./pytest.sh int-5`
