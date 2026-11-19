# Hexagonal Ports & Adapters

Arodonata v2 isolates all Check Point Management API, gateway CLI execution, and SQL database details behind five core `Protocol` interfaces defined in `src/arodonata/core/ports/__init__.py`.

## Core Protocols (`arodonata.core.ports`)

### 1. `ApiPort`

Defines the asynchronous contract for communicating with Check Point Management and MDSM servers:

- `api_call(mgmt_name, command, payload=None, *, domain=None, sid=None, server_ip=None, wait_for_task=True, timeout=None) -> ApiCallResult`
- `api_query(mgmt_name, command, *, domain=None, details_level="standard", payload=None, sid=None, server_ip=None, limit=300) -> ApiQueryResult`
- `create_dedicated_session(mgmt_name, domain=None, *, auth=None, session_name=None, session_description=None) -> tuple[str, str]`
- `logout_sid(mgmt_name, sid, *, server_ip=None) -> Awaitable[bool]`
- `close(*, logout=None) -> None` (when `logout=None`, auto-logs out active sessions only if the client owns an auto-created ephemeral `:memory:` SQLite engine)

**Default Adapter**: `AMgmtClient` (`src/arodonata/adapters/checkpoint/client.py`), backed by:

- `ApiTransport` (`transport.py`): Native `aiohttp` client with `allow_redirects=False`, `trust_env=False`, post-handshake and pre-request SHA-256 certificate verification (`TrustPolicy` / `TrustStore` in `tls.py`), and phase-tagged `TransportError` (`phase="connect" | "post-send"`) / `ApiTimeoutError` (`phase="connect" | "read"`) carrying `request_sent: bool` so mutating calls are never re-sent after bytes leave the socket.
- `VerifiedConnectionPool`: Reuses verified keep-alive connections (`<= 10s` idle, `< 95` requests) for idempotent `show-*` commands under shared scope AND for non-boundary commands within scoped dedicated sessions (`s:<sha256_prefix>`), while `NON_POOLABLE_SESSION_COMMANDS` (`login`, `logout`, `keepalive`, `publish`, `discard`, `continue-session`, `switch-session`, `take-over-session`, `disconnect`) bypass pooling.
- `LoginCoordinator` & `SessionCleaner` (`sessions.py`): Credential-bound read-only session cache lookup, isolated `WriteSession` management, coalesced keepalive sweeps, and startup cleanup of orphaned Arodonata sessions.
- `RateLimiter` & `LoginGate` (`rate_limiter.py`): Enforces `concurrent_limit` per MDS member IP and a `70.0s` cooldown window on login throttling (`err_too_many_requests`).
- `paginate_objects` (`pager.py`) & `TaskWaiter` (`task_waiter.py`): Continuity-verified pagination (`limit=300`, clamped to `500`, `±10` boundary overlap recovery and single restart on `total` shift) plus exponential-backoff `show-task` polling (`2s..10s` up to `task_timeout`).

### 2. `CachePort`

Defines the contract for reading and persisting cached Check Point topology, sessions, objects, services, assets, gateway topology intervals, annotations, rulebases, and sync states:

- **Domain topology**: `get_domains()`, `get_domain()`, `upsert_domains()`
- **Shared sessions**: `get_sid()`, `upsert_sid()`, `evict_sid()`, `list_sids()`
- **Sync state**: `get_sync_state()`, `list_sync_states()`, `upsert_sync_state()`
- **Objects & Services**: `get_objects()`, `get_object_by_uid()`, `replace_domain_objects()`, `upsert_objects()`, `delete_objects_by_uids()`, `get_services()`, `get_service_by_uid()`, `replace_domain_services()`, `upsert_services()`, `delete_services_by_uids()`
- **Assets**: `get_assets()`, `replace_domain_assets()`, `upsert_assets()`
- **Gateway topology & annotations**: `get_gateway_topology()`, `replace_domain_topology()`, `upsert_gateway_topology()`, `get_topology_annotations()`, `upsert_topology_annotations()`, `delete_topology_annotations()`
- **Rulebase snapshots & slices**: `replace_domain_rulebase()`, `replace_domain_package_catalog()`, `upsert_domain_rulebase_layers()`, `get_domain_rulebase()`, `get_domain_rulebase_packages()`

*(Note: Cross-domain filtering and aggregation methods `describe_objects()` and `query_objects()` live in `SearchService` and `ArodonataClient`, built on top of `CachePort`.)*

**Default Adapter**: `SqlCacheAdapter` (`src/arodonata/adapters/storage/cache_adapter.py`), which executes atomic transactions, deduplicates primary keys before batched writes (`_BATCH_ROWS = 500`), and runs dialect-specific `ON CONFLICT DO UPDATE` upserts on PostgreSQL and SQLite.

### 3. `LockPort`

Coordinates distributed cross-process critical sections (per-domain cache refreshes, `LoginGate` serialization, and cross-worker `RateLimiter` slots):

- `acquire(lock_key, *, ttl_seconds=60.0, owner_id=None, wait_timeout=None, poll_interval=0.05) -> bool`
- `renew(lock_key, *, ttl_seconds=60.0, owner_id=None) -> bool`
- `release(lock_key, *, owner_id=None) -> bool`
- `lock(lock_key, *, ttl_seconds=60.0, owner_id=None, wait_timeout=None, poll_interval=0.05) -> AbstractAsyncContextManager[str]` (yields `owner_id`; raises `LockAcquisitionError` on contention/timeout)

**Default Adapter**: `SqlLockAdapter` (aliased as `DatabaseLockManager`, `src/arodonata/adapters/storage/lock_adapter.py`) backed by `arodonata_distributed_locks`, evaluating expiration against the database server's UTC clock.

### 4. `AuthProvider`

Optional pluggable protocol for resolving runtime credentials dynamically per `(mgmt_name, domain)` and receiving failure notifications when `auth_mode="dynamic"` is used without an explicit `auth_context`:

- `get_credentials(mgmt_name, domain=None, *, user=None) -> AuthContext`
- `on_auth_failed(mgmt_name, auth, exc) -> None`

### 5. `GatewayCliPort` (& `GatewayCliCallable`)

Optional protocol for executing shell/clish diagnostics on Check Point gateways and VSX Virtual Systems (e.g., via SSH):

- `execute_command(target: GatewayCliTarget, command: str, *, timeout: float = 30.0) -> GatewayCliResult | str`
- `GatewayCliCallable = Callable[[GatewayCliTarget, str], Awaitable[GatewayCliResult | str]]`

Injected via `ArodonataClient(..., gateway_cli=...)` or `client.set_gateway_cli(...)` for `TopologyService.collect_gateway_routes()`. When unavailable or failing, route collection falls back to Check Point `cprid` via `AMgmtClient` (`run-script` one-time or repository scripts managed by `ScriptRepositoryService`).

## Boundary, Storage & Testing Adapters

- **`DatabaseManager`** (`src/arodonata/adapters/storage/database.py`): Manages async SQLAlchemy engines (`asyncpg` / `aiosqlite`), cross-worker schema locks, and SHA-256 schema hash auto-migration restricted to `ARODONATA_TABLE_NAMES`.
- **`SSEAdapter`** (`src/arodonata/adapters/sse/__init__.py`): Converts core `DomainEvent` streams (`SyncProgressEvent`, `CPCRUDEvent`) into SID-redacted `SSEEvent` frames via `to_sse_event()` and `stream_as_sse()`.
- **Replay & Test Doubles (`arodonata.testing`)**: `FileReplayApiMock`, `FileReplayCliMock`, and `CheckPointReplayHttpServer` implement `ApiPort` and `GatewayCliPort` against realistic MDSM/VSX fixture datasets with stateful session overlays and call auditing.

## Dependency Injection in Tests & Custom Hosts

Because `ArodonataClient` accepts custom `api: ApiPort`, `cache: CachePort`, `lock_port: LockPort`, `auth_provider: AuthProvider`, and `gateway_cli: GatewayCliPort | GatewayCliCallable` instances in its constructor, unit tests and downstream applications can inject in-memory fakes or custom adapters without monkeypatching internal classes:

```python
client = ArodonataClient(
    settings,
    api=custom_api_port,
    cache=custom_cache_port,
    lock_port=custom_lock_port,
    auth_provider=custom_auth_provider,
    gateway_cli=custom_gateway_cli,
)
```
