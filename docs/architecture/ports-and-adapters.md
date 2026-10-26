# Hexagonal Ports & Adapters

Arodonata v2 isolates all Check Point Management API and SQL database details behind four core `Protocol` interfaces defined in `src/arodonata/core/ports/__init__.py`.

## Core Protocols (`arodonata.core.ports`)

### 1. `ApiPort`

Defines the asynchronous contract for communicating with Check Point Management and MDSM servers:

- `api_call(mgmt_name, command, payload, *, domain=None, sid=None, server_ip=None, wait_for_task=True, timeout=None) -> ApiCallResult`
- `api_query(mgmt_name, command, *, domain=None, details_level="standard", payload=None, sid=None, server_ip=None, limit=500) -> ApiQueryResult`
- `create_dedicated_session(mgmt_name, domain=None, *, auth=None, session_name=None, session_description=None) -> tuple[str, str]`
- `logout_sid(mgmt_name, sid, *, server_ip=None) -> bool`
- `close(*, logout=False) -> None`

**Default Adapter**: `AMgmtClient` (`src/arodonata/adapters/checkpoint/client.py`), backed by:

- `ApiTransport`: Native `aiohttp` client with `allow_redirects=False`, `trust_env=False`, post-handshake SHA-256 certificate verification, and phase-tagged `TransportError` (`phase="connect"` vs `"post-send"` so mutating calls are never re-sent after bytes leave the socket).
- `VerifiedConnectionPool`: Reuses verified keep-alive connections (up to `10s` idle) strictly for idempotent `show-*` commands.
- `RateLimiter` & `LoginGate`: Enforces `concurrent_limit` per MDS member IP and a `70s` cooldown window on login throttling (`err_too_many_requests`).
- `TaskWaiter`: Polls asynchronous Check Point `task-id` responses with exponential backoff (`2s..10s`) up to `task_timeout`.

### 2. `CachePort`

Defines the contract for reading and persisting cached Check Point topology, objects, services, assets, rulebases, sessions, and sync states:

- Domain topology: `get_domains()`, `replace_domains()`
- Shared sessions: `get_cached_sid()`, `upsert_cached_sid()`, `delete_cached_sid()`, `list_cached_sids()`
- Sync state: `get_sync_state()`, `list_sync_states()`, `upsert_sync_state()`
- Objects & Services: `get_objects()`, `get_object_by_uid()`, `replace_domain_objects()`, `apply_incremental_objects()`, `get_services()`, `get_service_by_uid()`, `replace_domain_services()`, `apply_incremental_services()`
- Assets: `get_assets()`, `replace_domain_assets()`
- Rulebase snapshots: `get_domain_rulebase()`, `replace_domain_rulebase()`
- Structured aggregation: `describe_objects()`, `query_objects()`

**Default Adapter**: `SqlCacheAdapter` (`src/arodonata/adapters/storage/cache_adapter.py`), which executes atomic transactions and dialect-specific `ON CONFLICT DO UPDATE` upserts on PostgreSQL and SQLite.

### 3. `LockPort`

Coordinates distributed cross-process critical sections (per-domain cache refreshes, login serialization, and cross-worker rate-limit slots):

- `acquire(lock_key, *, ttl_seconds=60.0, timeout_seconds=30.0, poll_interval=0.25) -> str` (returns `owner_id`)
- `renew(lock_key, owner_id, *, ttl_seconds=60.0) -> bool`
- `release(lock_key, owner_id) -> bool`
- `lock(lock_key, *, ttl_seconds=60.0, timeout_seconds=30.0) -> AsyncIterator[str]`

**Default Adapter**: `SqlLockAdapter` (`src/arodonata/adapters/storage/lock_adapter.py`) backed by the `arodonata_distributed_locks` table, evaluating expiration against the database server's UTC clock.

### 4. `AuthProvider`

Optional pluggable protocol for resolving credentials dynamically per `(mgmt_name, domain)` when `auth_mode="dynamic"` is used without an explicit `auth_context`.

## Dependency Injection in Tests & Custom Hosts

Because `ArodonataClient` accepts custom `api: ApiPort`, `cache: CachePort`, and `lock_port: LockPort` instances in its constructor, unit tests and downstream applications can inject in-memory fakes or custom adapters without monkeypatching internal classes:

```python
client = ArodonataClient(
    settings,
    api=custom_api_port,
    cache=custom_cache_port,
    lock_port=custom_lock_port,
)
```
