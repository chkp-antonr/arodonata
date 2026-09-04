# Arodonata — Full API Reference

Complete, auto-generated reference of every public class, function, and method in the `arodonata` package, grouped by subpackage. Each entry shows the exact signature (as written in source) and its docstring. This is the third companion document alongside the Guide and the Examples — use it to look up exact function names, parameters, and return types.

## Package Map

- **Top-Level Package** — 4 module(s)
- **api — High-Level Client & Services** — 10 module(s)
- **adapters — External Integrations (API transport, cache backend)** — 5 module(s)
- **asdk — Low-Level Check Point Management API SDK** — 7 module(s)
- **cache — Database-Backed Caching Layer** — 8 module(s)
- **config — Settings & Constants** — 3 module(s)
- **core — Core Domain Logic, Protocols & Exceptions** — 10 module(s)
- **cpcrud — Declarative CRUD / Rule Engine** — 15 module(s)
- **extractors — Bulk Data Extraction** — 4 module(s)
- **helpers — Convenience Helper Functions** — 5 module(s)
- **models — Data Models** — 4 module(s)
- **ports — Abstract Interfaces (Hexagonal Architecture Ports)** — 3 module(s)
- **utils — Utility Functions** — 2 module(s)
- **services — (reserved)** — 1 module(s)


---

## Top-Level Package

### `arodonata/__init__.py`

Arodonata - Check Point API Operations Library.

A comprehensive Python library for Check Point management and monitoring operations
with async support, automatic session management, and intelligent caching.

Example:
    from sqlalchemy.ext.asyncio import create_async_engine
    from arodonata import ArodonataClient, ArodonataSettings

    # Main app creates engine from its own database config
    engine = create_async_engine("postgresql+asyncpg://...")

    # Arodonata settings contain only mgmt server config
    settings = ArodonataSettings(
        mgmt_names="mgmt1,mgmt2",
        mgmt_servers="10.0.0.1,10.0.0.2",
        api_keys="actual_key1,actual_key2",
    )

    client = ArodonataClient(engine=engine, settings=settings)
    async with client:
        result = await client.api_call("mgmt1", "show-hosts")
        print(result.data)

    await engine.dispose()

_No public classes or functions in this module._

### `arodonata/db_utils.py`

Database utilities for arodonata.

Provides generalized error handling for SQLModel table initialization
with automatic recovery on schema changes.

#### Module-Level Functions

##### `async def safe_init_table(engine_or_conn: Any, table_class: type[SQLModel], table_name: str | None = None) -> bool`

Initialize a SQLModel table with automatic recovery on schema errors.

If the table exists but has a different schema (e.g., columns added/removed),
this function will:
1. Log the error at CRITICAL level
2. Drop the problematic table
3. Recreate it with the correct schema

Args:
    engine_or_conn: AsyncEngine or AsyncConnection
    table_class: SQLModel class to initialize
    table_name: Optional table name (defaults to table_class.__tablename__)

Returns:
    True if table was created/recreated successfully, False otherwise

##### `async def ensure_missing_columns(engine_or_conn: Any, table_class: type[SQLModel] | Table) -> None`

Add any columns present in the SQLModel but missing from the live table.

Accepts either a mapped SQLModel class or a raw SQLAlchemy ``Table``
(e.g. from ``SQLModel.metadata.tables.values()``), so callers can migrate
every registered table generically instead of listing classes by hand.

Safe for both PostgreSQL and SQLite. Uses inspect to check before altering,
so no IF NOT EXISTS dialect differences needed.

### `arodonata/logger.py`

#### Module-Level Functions

##### `def get_logger(name: str) -> LoggerProtocol`

Get a logger instance, ensuring arodonata defaults are applied.

##### `def lazy_logger(name: str) -> Callable[[], LoggerProtocol]`

Create a lazy logger function for a module.

Args:
    name: Logger name (usually __name__).

Returns:
    A function that returns a LoggerProtocol instance when called.

### `arodonata/telemetry.py`

Span attribute helper for arodonata OTEL instrumentation.

arodonata is a provider-agnostic span producer: it depends on opentelemetry-api
only and never configures a TracerProvider. Without a provider every call here
is a no-op. Never pass credentials, full SIDs, or customer payloads.

#### Module-Level Functions

##### `def span_attrs(**attrs: Any) -> None`

Set arodonata.*-namespaced attributes on the current span; None skipped.


---

## api — High-Level Client & Services

### `arodonata/api/__init__.py`

Public API layer - main entry point for applications.

This module exports the main client for Arodonata.

Example:
    from sqlalchemy.ext.asyncio import create_async_engine
    from arodonata import ArodonataClient, ArodonataSettings

    settings = ArodonataSettings()
    engine = create_async_engine(settings.database_url, ...)

    client = ArodonataClient(engine=engine, settings=settings)
    async with client:
        result = await client.api_call("mgmt1", "show-hosts")

    await engine.dispose()

_No public classes or functions in this module._

### `arodonata/api/asset_transformer.py`

Asset transformation utilities for Check Point API objects.

This module provides methods to transform API response objects into Asset models
with proper validation and relationship handling.

#### class `AssetTransformer`

Handles transformation of API objects to Asset models.

##### Methods

###### `def transform_to_asset(obj: Any, mgmt_name: str, domain_name: str, domain_uid: str) -> Asset | None`

```python
@staticmethod
```
Transform API object to Asset model.

Args:
    obj: API response object.
    mgmt_name: Management server name.
    domain_name: Domain name.
    domain_uid: Domain UID.

Returns:
    Asset object or None if transformation fails.

###### `def build_cluster_member_mappings(objects_list: list[dict[str, Any]]) -> dict[str, str]`

```python
@staticmethod
```
Build mapping from cluster member names to cluster asset IDs.

Args:
    objects_list: List of objects from show-gateways-and-servers.

Returns:
    Dictionary mapping member names to cluster names.

###### `def transform_to_asset_with_cluster_relationships(obj: Any, mgmt_name: str, domain_name: str, domain_uid: str, cluster_member_mappings: dict[str, str]) -> Asset | None`

```python
@staticmethod
```
Transform API object to Asset with cluster relationship handling.

Args:
    obj: API response object.
    mgmt_name: Management server name.
    domain_name: Domain name.
    domain_uid: Domain UID.
    cluster_member_mappings: Mapping from member names to cluster names.

Returns:
    Asset object or None if transformation fails.

### `arodonata/api/client.py`

High-level async client for Check Point  API operations.

Applications create and inject the database engine.
The client manages all other components internally.

#### class `ArodonataClient`

High-level async client for Check Point API operations.

Applications create the database engine and inject it.
The client creates and manages all other components.

Example:
    import os
    from sqlalchemy.ext.asyncio import create_async_engine
    from arodonata import ArodonataClient, ArodonataSettings

    settings = ArodonataSettings()
    engine = create_async_engine(os.environ["DATABASE_URL"])

    client = ArodonataClient(engine=engine, settings=settings)
    async with client:
        result = await client.api_call("mgmt1", "show-hosts")
        for name in client.get_mgmt_names():
            print(name)

    # App is responsible for disposing the engine
    await engine.dispose()

##### Methods

###### `def __init__(self, engine: AsyncEngine | None = None, settings: ArodonataSettings | None = None, *, username: str | None = None, password: str | None = None, mgmt_ip: str | None = None, cache_mode: str = 'smart', cache_ttl: int = 300, max_incremental_changes: int = 500, _db: DatabaseManager | None = None, _cache: CacheRepository | None = None, _mgmt: AMgmtClient | None = None) -> None`

Initialize Arodonata client with dependency injection.

Supports two authentication modes:

1. API Key mode (existing):
    ``ArodonataClient(engine=engine, settings=settings)``

2. Credential mode (new):
    ``ArodonataClient(username="admin", password="pass", mgmt_ip="1.2.3.4")``

In credential mode without an explicit engine, an in-memory SQLite
database is created automatically and owned by the client.

Args:
    engine: SQLAlchemy AsyncEngine for database operations.
           Optional in credential mode (auto-creates in-memory SQLite).
    settings: Configuration settings. Auto-built from constructor args
             if credentials provided and settings is None.
    username: Username for credential-based auth (takes priority over api_key).
    password: Password for credential-based auth.
    mgmt_ip: Management server IP (required when credentials provided).
    cache_mode: Default cache refresh mode for v2 read helpers
               ("cache", "smart", "smart-fast", "force"). Defaults to "smart".
    cache_ttl: Default cache freshness TTL (seconds) for v2 read helpers.
              Defaults to 300.
    max_incremental_changes: Cap on show-changes entries an
               incremental refresh (mode="incremental" or smart-fast
               reads) will apply before falling back to a full domain
               reload. Defaults to 500.
    _db: Optional internal DatabaseManager override (for testing).
    _cache: Optional internal CacheRepository override (for testing).
    _mgmt: Optional internal AMgmtClient override (for testing).

###### `def schedule_startup_cleanup(self) -> None`

Fire session cleanup for all servers as a background asyncio task.

Call once after the event loop is running and the database is initialized.
Safe to call multiple times — each call fires an independent background task.
No-op when no login coordinator is configured (e.g. injected _mgmt path).

###### `async def close(self) -> None`

Close client and release resources.

If the client owns the engine (auto-created for credential mode),
it will be disposed here. App-provided engines are NOT closed.

###### `async def logout(self, mgmt_name: str, domain: str = '') -> bool`

```python
@traced
```
Explicitly logout of a session.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).

Returns:
    True if logout was successful, False otherwise.

###### `def settings(self) -> ArodonataSettings`

```python
@property
```
Get configuration settings.

###### `def cache(self) -> CacheRepository`

```python
@property
```
Get cache repository for direct access.

###### `def cpcrud(self) -> CPCRUDService`

```python
@property
```
Lazy CPCRUD (idempotent object CRUD) service.

###### `def get_mgmt_names(self) -> list[str]`

Get list of all configured management server names.

Returns:
    List of server name strings.

###### `async def get_server(self, name: str) -> ServerConfig | None`

Get server configuration by name.

Args:
    name: Server name to lookup.

Returns:
    Server configuration or None if not found.

###### `async def api_call(self, mgmt_name: str, command: str, domain: str = '', details_level: Literal['uid', 'standard', 'full'] | None = None, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1, cache_mode: str = 'auto', session_name: str | None = None, session_description: str | None = None) -> ApiCallResult`

```python
@traced
```
Execute API call with automatic session management.

Args:
    mgmt_name: Management server name.
    command: API command to execute.
    domain: Domain name (empty for system domain).
    details_level: Detail level for response.
    payload: Additional command parameters.
    wait_for_task: Wait for task completion.
    timeout: Request timeout in seconds (-1 for default).
    cache_mode: Cache behavior ("auto", "refresh", "off").
    session_name: Optional name applied when this call has to create a
        fresh session (cache miss/relogin). Ignored on a cache hit that
        reuses an already-open session. Sessions named/described with a
        recognized test marker (see session_cleaner.TEST_SESSION_MARKERS)
        get a much shorter discard grace period.
    session_description: Optional description, same caveat as session_name.

Returns:
    Validated API call result.

###### `async def api_call_with_sid(self, mgmt_name: str, sid: str, server_ip: str, command: str, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1) -> ApiCallResult`

```python
@traced
```
Execute API call with an explicit SID (no auto-session management).

Used by write workflows (e.g. CPCRUD) that manage their own sessions
and need to ensure a specific SID is used for publish/discard.

Args:
    mgmt_name: Management server name.
    sid: Session ID to use.
    server_ip: Server IP address for the session.
    command: API command to execute.
    payload: Additional command parameters.
    wait_for_task: Wait for task completion.
    timeout: Request timeout in seconds (-1 for default).

Returns:
    Validated API call result.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str = '', session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]`

```python
@traced
```
Create a dedicated session bypassing the global SID cache.

Used by write workflows (e.g. CPCRUD) that need session isolation
from the shared pool. The returned SID is NOT stored in the cache.
Use api_call_with_sid() to make calls, and logout_sid() when done.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).
    session_name: Optional session name visible in SmartConsole.
    session_description: Optional session description.

Returns:
    Tuple of (SID, Server IP).

###### `async def logout_sid(self, sid: str, server_ip: str, mgmt_name: str = '') -> bool`

```python
@traced
```
Logout a specific SID (e.g. a dedicated session).

Args:
    sid: Session ID to logout.
    server_ip: Server IP of the session.
    mgmt_name: Optional management server name (for port lookup).

Returns:
    True if logout was successful.

###### `async def api_query(self, mgmt_name: str, command: str, domain: str = '', details_level: Literal['uid', 'standard', 'full'] = 'standard', payload: dict[str, Any] | None = None, container_key: str = 'objects', cache_mode: str = 'auto') -> ApiQueryResult`

```python
@traced
```
Execute paginated API query with automatic session management.

Args:
    mgmt_name: Management server name.
    command: API query command.
    domain: Domain name.
    details_level: Detail level for response.
    payload: Additional query parameters.
    container_key: Key containing objects in response.

Returns:
    Validated API query result.

###### `async def collect_gateways_and_servers(self, mgmt_names: list[str] | None = None, domains: list[str] | None = None) -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Collect gateway/server assets with streaming progress.

Args:
    mgmt_names: List of server names (None = all).
    domains: List of domains to scope the query to (None = system domain).

Yields:
    SSEEvent objects for progress, results, and completion.

###### `async def clear_cache(self) -> None`

```python
@traced
```
Clear all cached sessions.

###### `async def build_refresh_assets_cache(self, mgmt_names: str | list[str] = '', domains: str | list[str] = '', cache_mode: str = 'auto') -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Build and refresh the assets cache with comprehensive asset collection.

This method delegates to the AssetRefreshService for the actual implementation.

Args:
    mgmt_names: Server names as comma-separated string or list (empty = all).
    domains: Domains as comma-separated string or list (empty = all).

Yields:
    SSEEvent objects for progress, results, errors, and completion.

Example:
    ```python
    async with await factory.create_client() as client:
        async for event in client.build_refresh_assets_cache(
            mgmt_names="mgmt1,mgmt2", domains="domain1,domain2"
        ):
            if event.event_type == SSEEventType.LOG:
                print(f"Progress: {event.data.get('message')}")
            elif event.event_type == SSEEventType.COMPLETE:
                print(f"Complete: {event.data}")
    ```

###### `async def refresh_domain_assets(self, mgmt_name: str, domain_name: str, cache_mode: str = 'auto') -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Refresh cached assets for a single domain.

This method delegates to AssetRefreshService.refresh_domain_assets —
a narrower alternative to build_refresh_assets_cache for callers that
only need one domain refreshed without a full multi-domain rebuild.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.
    cache_mode: Cache mode passed through to the underlying API query.

Yields:
    SSEEvent objects for progress, results, and errors.

###### `async def refresh_last_published_session(self, mgmt_name: str, domain_name: str) -> LastPublishedSession | None`

```python
@traced
```
Refresh the last-published-session record for a single domain.

Makes one lightweight API call and upserts LastPublishedSession —
does not touch the object or asset caches.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    The upserted LastPublishedSession record, or None on failure.

###### `async def search_objects(self, search_input: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, refresh: Literal['skip', 'check', 'force', 'incremental'] = 'skip', max_depth: int = 2) -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Search for Check Point objects with cache-first queries.

Args:
    search_input: Comma-separated search terms.
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    refresh: Refresh mode - "skip", "check", "force", or "incremental".
    max_depth: Maximum depth for group membership traversal.

Yields:
    SSEEvent with refresh progress and domain-grouped search results.

###### `async def refresh_objects(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: Literal['skip', 'check', 'force', 'incremental'] = 'force') -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Refresh object cache from API.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: Refresh mode - "skip", "check", "force", or "incremental".

Yields:
    SSEEvent with progress updates.

###### `async def refresh_rulebases(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: Literal['skip', 'check', 'force'] = 'force') -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Refresh rulebase cache from API.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: Refresh mode - "skip", "check", or "force".

Yields:
    SSEEvent with progress updates.

###### `async def get_domains(self, mgmt_names: list[str] | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[Domain]`

```python
@traced
```
Get domains from cache as Pydantic models.

Args:
    mgmt_names: Optional list of management server names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Domain models.

Example:
    domains = await client.get_domains(mgmt_names=["mgmt1"])
    for domain in domains:
        print(f"{domain.name}: {domain.active_ip}")

###### `async def get_gateways(self, mgmt_names: list[str] | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[Gateway]`

```python
@traced
```
Get gateways and servers from cache as Pydantic models.

Gateways/servers live in a separate asset cache populated by
``build_refresh_assets_cache()`` (not the object-cache pipeline that
backs ``get_domains``/``get_hosts``/etc.), so this method drives that
refresh directly instead of going through the object-cache
coordinator: "force" always refreshes first, and an empty cache
triggers one refresh-then-retry regardless of mode (except "cache",
which never calls the API).

Args:
    mgmt_names: Optional list of management server names to filter.
    cache_mode: Optional per-call cache refresh mode override
        ("cache", "smart", "smart-fast", "force"). Defaults to the
        client's configured cache mode.
    cache_ttl: Unused for gateways (asset cache has no TTL check yet);
        accepted for signature parity with the other get_* helpers.

Returns:
    List of Gateway models.

Example:
    gateways = await client.get_gateways(mgmt_names=["mgmt1"])
    for gw in gateways:
        print(f"{gw.name}: {gw.ip_address} ({gw.type})")

###### `async def get_hosts(self, name_filter: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[Host]`

```python
@traced
```
Get host objects from cache as Pydantic models.

Args:
    name_filter: Optional name filter (supports wildcards).
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Host models.

Example:
    hosts = await client.get_hosts(name_filter="web*")
    for host in hosts:
        print(f"{host.name}: {host.ip_address}")

###### `async def get_networks(self, subnet: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[Network]`

```python
@traced
```
Get network objects from cache as Pydantic models.

Args:
    subnet: Optional subnet filter (CIDR notation).
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Network models.

Example:
    networks = await client.get_networks(subnet="192.168.1.0/24")
    for net in networks:
        print(f"{net.name}: {net.subnet4}/{net.subnet_mask}")

###### `async def get_groups(self, name_filter: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[Group]`

```python
@traced
```
Get group objects from cache as Pydantic models.

Args:
    name_filter: Optional name filter (supports wildcards).
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Group models.

Example:
    groups = await client.get_groups(name_filter="firewall*")
    for group in groups:
        print(f"{group.name}: {len(group.member_uids)} members")

###### `async def get_object_by_uid(self, uid: str, mgmt_name: str, domain_name: str = '') -> CPObject | None`

```python
@traced
```
Get any object by UID from cache.

Args:
    uid: Object UID.
    mgmt_name: Management server name.
    domain_name: Domain name (default: system domain).

Returns:
    CPObject or None if not found.

Example:
    obj = await client.get_object_by_uid("123abc", "mgmt1")
    if obj:
        print(f"{obj.name} ({obj.type})")

###### `async def get_access_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[AccessRule]`

```python
@traced
```
Get access control rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "Network").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of AccessRule Pydantic models.

###### `async def get_nat_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[NATRule]`

```python
@traced
```
Get NAT rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "NAT").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of NATRule Pydantic models.

###### `async def get_https_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[HTTPSRule]`

```python
@traced
```
Get HTTPS inspection rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "CVD").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of HTTPSRule Pydantic models.

###### `async def get_threat_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: str | None = None, cache_ttl: int | None = None) -> list[ThreatRule]`

```python
@traced
```
Get threat prevention rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "Threat").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of ThreatRule Pydantic models.

### `arodonata/api/cluster_relationship_manager.py`

Cluster/cluster-member relationship management for Check Point API objects.

This module provides methods to handle cluster and cluster-member object relationships,
including building parent-child mappings and parent asset ID updates.

#### class `ClusterRelationshipManager`

Manages cluster/cluster-member relationships for Check Point objects.

##### Methods

###### `def __init__(self, client: ArodonataClient) -> None`

Initialize with ArodonataClient instance.

Args:
    client: ArodonataClient instance for cache access.

###### `async def build_cluster_member_mappings(self, mgmt_name: str) -> dict[str, str]`

Build mapping from cluster member names to cluster asset IDs.

Queries the cache for all assets of a management server and extracts
cluster-to-cluster-member relationships from raw_data.

Args:
    mgmt_name: Management server name.

Returns:
    Dictionary mapping cluster member names to cluster asset IDs.

###### `async def update_cluster_member_parent_asset_ids(self, mgmt_name: str, cluster_member_mappings: dict[str, str]) -> int`

Update parent_asset_id for cluster member objects in the cache.

Args:
    mgmt_name: Management server name.
    cluster_member_mappings: Mapping from cluster member names to cluster asset IDs.

Returns:
    Number of relationships updated.

### `arodonata/api/schemas.py`

Public API response schemas for Arodonata library.

These Pydantic models provide type-safe response handling
and validation for API operations.

#### class `SSEEventType(StrEnum)`

Server-Sent Event types for streaming operations.

#### class `ApiCallResult(BaseModel)`

Result of an API call operation.

##### Fields / Class Variables

```python
success: bool = Field(description='Whether the call succeeded')
data: dict[str, Any] | None = Field(default=None, description='Response data from API')
message: str = Field(default='', description='Error or status message')
code: str = Field(default='', description='Error code if failed')
```
##### Methods

###### `def has_data(self) -> bool`

```python
@property
```
Check if result has data.

#### class `ApiQueryResult(BaseModel)`

Result of an API query operation.

##### Fields / Class Variables

```python
success: bool = Field(description='Whether the query succeeded')
data: list[dict[str, Any]] | dict[str, Any] | None = Field(default=None, description='Response data from API (list for success, dict for errors)')
objects: list[dict[str, Any]] = Field(default_factory=list, description='Query result objects')
message: str = Field(default='', description='Error or status message')
code: str = Field(default='', description='Error code if failed')
total: int = Field(default=0, description='Total number of results')
res_obj: dict[str, Any] | None = Field(default=None, description='The raw response object when data cannot be processed normally')
```
##### Methods

###### `def handle_response_data(cls, values: Any) -> Any`

```python
@model_validator(mode='before')
@classmethod
```
Handle cases where data is a list, dict, or error response.

For successful responses with list data, store in objects for easier access.
For error responses with dict data, extract error details into code/message.

###### `def has_objects(self) -> bool`

```python
@property
```
Check if result has objects.

#### class `SSEEvent(BaseModel)`

Server-Sent Event for streaming operations.

##### Fields / Class Variables

```python
event_type: SSEEventType = Field(description='Type of event')
data: dict[str, Any] = Field(default_factory=dict, description='Event payload')
message: str | None = Field(default=None, description='Optional status or log message')
asset_id: str | None = Field(default=None, description='Optional asset identifier')
timestamp: datetime = Field(default_factory=lambda : datetime.now(UTC), description='Event timestamp')
mgmt_name: str | None = Field(default=None, description='Management server name')
domain: str | None = Field(default=None, description='Domain name')
```
##### Methods

###### `def to_sse_format(self) -> str`

Format as Server-Sent Event string.

#### class `ResultEvent(SSEEvent)`

Result data event.

##### Fields / Class Variables

```python
event_type: SSEEventType = SSEEventType.RESULT
result_type: str = Field(default='', description='Type of result (asset, gateway, etc)')
count: int = Field(default=0, ge=0)
```
#### class `ErrorEvent(SSEEvent)`

Error event.

##### Fields / Class Variables

```python
event_type: SSEEventType = SSEEventType.ERROR
error_code: str = Field(default='')
error_message: str = Field(default='')
```
#### class `CompleteEvent(SSEEvent)`

Collection complete event.

##### Fields / Class Variables

```python
event_type: SSEEventType = SSEEventType.COMPLETE
total_results: int = Field(default=0, ge=0)
duration_seconds: float = Field(default=0.0, ge=0)
```
### `arodonata/api/services/__init__.py`

High-level business logic services.

These services contain complex business logic that was previously
embedded in ArodonataClient. They are injected via the factory.

_No public classes or functions in this module._

### `arodonata/api/services/asset_refresh_service.py`

Asset collection and cache refresh service.

Handles asset collection, transformation, and relationship processing.

#### class `AssetRefreshService`

Asset collection and cache refresh service.

Orchestrates asset collection from Check Point management servers,
handles transformation and caching, and processes relationships.

##### Methods

###### `def __init__(self, mgmt_client: AMgmtClient, cache: CacheRepository, domain_service: DomainService, cluster_manager: Any, vsx_manager: Any, settings: ArodonataSettings, api_query_method: Callable[..., Any]) -> None`

Initialize asset refresh service.

Args:
    mgmt_client: ASDK management client.
    cache: Cache repository instance.
    domain_service: Domain discovery service.
    cluster_manager: Cluster relationship manager instance.
    vsx_manager: VSX relationship manager instance.
    settings: Configuration settings.
    api_query_method: Reference to ArodonataClient.api_query method.

###### `async def build_refresh_assets_cache(self, mgmt_names: str | list[str] = '', domains: str | list[str] = '', cache_mode: str = 'auto', client_wrapper: Any = None) -> AsyncGenerator[SSEEvent]`

```python
@distributed_lock('asset_refresh:{mgmt_names}:{domains}', timeout=300, ttl=300)
```
Build and refresh the assets cache with comprehensive asset collection.

Collects gateways, servers, clusters, VSX, and VS objects from specified
management servers and domains, stores them in the cache with proper
relationship mapping, and streams progress updates.

Args:
    mgmt_names: Server names as comma-separated string or list (empty = all).
    domains: Domains as comma-separated string or list (empty = all).
    client_wrapper: ArodonataClient wrapper for relationship managers.

Yields:
    SSEEvent objects for progress, results, and completion.

###### `async def refresh_domain_assets(self, mgmt_name: str, domain_name: str, cache_mode: str = 'auto') -> AsyncGenerator[SSEEvent]`

```python
@distributed_lock('asset_refresh:{mgmt_name}:{domain_name}', timeout=60, ttl=60)
```
Refresh cached assets for a single domain.

Unlike build_refresh_assets_cache, this does not delete existing
assets first, does not touch any other domain, and does not run
cluster/VSX relationship processing. Intended for callers that only
need fresh policy/status data for a small, known set of domains
without paying for a full multi-domain refresh.

Acquires its own per-domain lock — do not call this from a context
that already holds an asset_refresh lock covering the same
mgmt_name/domain_name (use _refresh_domain_assets_impl instead in
that case, e.g. build_refresh_assets_cache's own per-domain loop).

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.
    cache_mode: Cache mode passed through to the underlying API query.

Yields:
    SSEEvent objects for progress, results, and errors.

### `arodonata/api/services/domain_service.py`

Domain discovery and caching service.

Handles domain enumeration, caching, and IP resolution for Check Point management servers.

#### class `DomainService`

Domain discovery and caching service.

Handles domain enumeration and caching for both Smart Center and MDM servers.

##### Methods

###### `def __init__(self, mgmt_client: AMgmtClient, cache: CacheRepository, api_client: Any) -> None`

Initialize domain service.

Args:
    mgmt_client: ASDK management client.
    cache: Cache repository instance.
    api_client: ArodonataClient instance for API calls.

###### `async def populate_domain_cache(self, mgmt_name: str, cache_mode: str = 'auto') -> list[str]`

Query domains from management server and populate cache.

Args:
    mgmt_name: Management server name.

Returns:
    List of domain names (including system domain as empty string).

###### `async def get_domain_uid(self, mgmt_name: str, domain_name: str) -> str`

Get domain UID from cache.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).

Returns:
    Domain UID or empty string if not found.

### `arodonata/api/services/rulebase_refresh_service.py`

Rulebase population and refresh service.

#### class `RulebaseRefreshService`

Service for refreshing rulebase cache from Check Point API.

##### Methods

###### `def __init__(self, client: ArodonataClient, cache: CacheRepository) -> None`

Initialize rulebase refresh service.

Args:
    client: ArodonataClient instance for API calls.
    cache: Cache repository instance.

###### `async def refresh_all(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: Literal['skip', 'check', 'force'] = 'force') -> AsyncGenerator[dict[str, Any]]`

Refresh all rulebases for specified managements and domains.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: Refresh mode (only "force" currently implemented for rules).

Yields:
    Progress dictionaries.

###### `async def refresh_access_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Refresh all access control rulebases for a domain.

###### `async def refresh_nat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Refresh NAT rulebase for a domain.

###### `async def refresh_https_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Refresh HTTPS inspection rulebases for a domain.

###### `async def refresh_threat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Refresh threat prevention rulebases for a domain.

### `arodonata/api/vsx_relationship_manager.py`

VSX/VS relationship management for Check Point API objects.

This module provides methods to handle VSX and VS object relationships,
including cross-domain relationship building and parent asset ID updates.

#### class `VSXRelationshipManager`

Manages VSX/VS relationships for Check Point objects.

##### Methods

###### `def __init__(self, client: ArodonataClient) -> None`

Initialize with ArodonataClient instance.

Args:
    client: ArodonataClient instance for API calls.

###### `async def get_vsx_objects(self, mgmt_name: str, domain: str) -> list[dict[str, Any]]`

Get VSX objects from a management server and domain.

Args:
    mgmt_name: Management server name.
    domain: Domain name.

Returns:
    List of VSX objects with their details.

###### `async def get_vs_objects(self, mgmt_name: str, domain: str) -> list[dict[str, Any]]`

Get VS (Virtual System) objects from a management server and domain.

Args:
    mgmt_name: Management server name.
    domain: Domain name.

Returns:
    List of VS objects with their details.

###### `async def build_cross_domain_vsx_vs_mapping(self, mgmt_name: str, domains: list[str]) -> dict[str, str]`

Build mapping from VS objects to their parent VSX objects across all domains.

Args:
    mgmt_name: Management server name.
    domains: List of domain names to process.

Returns:
    Dictionary mapping VS UIDs and domain:name to VSX asset IDs.

###### `async def update_vs_parent_asset_ids(self, mgmt_name: str, vsx_vs_mappings: dict[str, str]) -> int`

Update parent_asset_id for VS objects in the cache.

Args:
    mgmt_name: Management server name.
    vsx_vs_mappings: Mapping from VS UIDs to VSX asset IDs.

Returns:
    Number of relationships updated.


---

## adapters — External Integrations (API transport, cache backend)

### `arodonata/adapters/__init__.py`

Adapters for Port/Adapter architecture.

_No public classes or functions in this module._

### `arodonata/adapters/api/__init__.py`

API adapters for ApiPort protocol.

_No public classes or functions in this module._

### `arodonata/adapters/api/asdk_adapter.py`

ASDK API adapter wrapping AMgmtClient.

#### class `ASDKApiAdapter`

Check Point API adapter wrapping AMgmtClient.

Implements ApiPort protocol.

##### Methods

###### `def __init__(self, client: 'AMgmtClient') -> None`

Initialize adapter with ASDK client.

Args:
    client: AMgmtClient instance to wrap.

###### `async def query(self, mgmt_name: str, command: str, domain: str = '', payload: dict[str, Any] | None = None, details_level: Literal['uid', 'standard', 'full'] = 'standard', container_key: str | None = None) -> 'ApiQueryResult'`

Execute paginated query via ASDK.

###### `async def show_changes(self, mgmt_name: str, domain: str = '', from_session: str | None = None, from_date: str | None = None, to_session: str | None = None, to_date: str | None = None) -> Any`

Get changes for smart refresh.

###### `async def publish(self, mgmt_name: str, domain: str = '') -> Any`

Publish the current session via ASDK.

###### `def get_mgmt_names(self) -> list[str]`

Get list of configured management server names.

### `arodonata/adapters/cache/__init__.py`

Cache adapters for CachePort protocol.

_No public classes or functions in this module._

### `arodonata/adapters/cache/postgres_adapter.py`

PostgreSQL cache adapter implementing CachePort protocol.

#### class `PostgresCacheAdapter`

PostgreSQL cache adapter wrapping CacheRepository.

Implements CachePort protocol for cache operations.

##### Methods

###### `def __init__(self, repository: 'CacheRepository') -> None`

Initialize adapter with cache repository.

Args:
    repository: CacheRepository instance to wrap.

###### `async def get_objects(self, object_type: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, filters: dict[str, Any] | None = None) -> list['CPObject']`

Query objects from cache with optional filters.

###### `async def get_object_by_uid(self, uid: str, mgmt_name: str, domain_name: str) -> 'CPObject | None'`

Get single object by UID.

###### `async def upsert_objects(self, objects: list['CPObject']) -> int`

Insert or update objects. Returns count of upserted objects.

###### `async def replace_domain_objects(self, mgmt_name: str, domain_name: str, objects: list['CPObject']) -> tuple[int, int]`

Atomically replace all objects for a domain in one transaction.

###### `async def delete_object(self, uid: str, mgmt_name: str, domain_name: str) -> int`

Delete a single object by UID. Returns count deleted (0 if absent).

###### `async def get_domains(self, mgmt_names: list[str] | None = None) -> list['Domain']`

Get cached domains.

###### `async def get_gateways(self, mgmt_names: list[str] | None = None) -> list['Gateway']`

Get cached gateways and servers.

###### `async def get_last_published_session(self, mgmt_name: str, domain_name: str) -> 'LastPublishedSession | None'`

Get last published session for smart refresh.

###### `async def get_rulebase(self, rulebase_type: str, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None) -> list[Any]`

Get rulebase rules from cache.

Args:
    rulebase_type: Type of rulebase ("access", "nat", "https", "threat").
    layer_name: Optional layer name filter.
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.

Returns:
    List of rule cache models.


---

## asdk — Low-Level Check Point Management API SDK

### `arodonata/asdk/__init__.py`

Async SDK wrapper layer for Check Point Management API.

This module provides the async wrappers around the synchronous
cp-mgmt-api-sdk with proper session management, rate limiting,
and dependency injection support.

_No public classes or functions in this module._

### `arodonata/asdk/client.py`

AMgmtClient facade - main entry point for ASDK operations.

Orchestrates all async client functionality including session management,
rate limiting, and error handling.

#### class `AMgmtClient`

Facade orchestrating all async client functionality.

Main entry point for Check Point API operations with automatic
session management, rate limiting, and error handling.

Example:
    client = AMgmtClient(
        registry=server_registry,
        transport=transport,
        rate_limiter=rate_limiter,
        login_coordinator=login_coordinator,
    )
    async with client:
        result = await client.api_call("mgmt1", "show-hosts")

##### Methods

###### `def __init__(self, registry: ServerRegistry, transport: ApiTransport, rate_limiter: RateLimiter, login_coordinator: LoginCoordinator) -> None`

_No docstring._

###### `async def close(self) -> None`

Close client and clean up resources.

###### `async def logout(self, mgmt_name: str, domain: str = '') -> bool`

Explicitly logout of a session.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).

Returns:
    True if logout was successful, False otherwise.

###### `def get_mgmt_names(self) -> list[str]`

Get list of all management server names.

###### `async def get_server(self, name: str) -> ServerConfig | None`

Get server configuration by name, fetching metadata if missing.

Args:
    name: Server name to lookup.

Returns:
    Server configuration with populated metadata or None.

###### `async def api_call(self, mgmt_name: str, command: str, domain: str = '', details_level: Literal['uid', 'standard', 'full'] | None = None, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1, cache_mode: str = 'auto', session_name: str | None = None, session_description: str | None = None) -> RawApiResponse`

Execute API call with automatic session management and retry.

Args:
    mgmt_name: Management server name.
    command: API command to execute.
    domain: Domain name (empty string for system domain).
    details_level: Level of detail in response.
    payload: Additional command parameters.
    wait_for_task: Wait for task completion.
    timeout: Request timeout in seconds.

Returns:
    API response dictionary.

###### `async def api_call_with_sid(self, mgmt_name: str, sid: str, server_ip: str, command: str, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1) -> RawApiResponse`

Execute API call with an explicit SID (no auto-session management).

Used by write workflows (e.g. CPCRUD) that manage their own sessions
and need to ensure a specific SID is used for publish/discard.

Args:
    mgmt_name: Management server name.
    sid: Session ID to use.
    server_ip: Server IP address for the session.
    command: API command to execute.
    payload: Additional command parameters.
    wait_for_task: Wait for task completion.
    timeout: Request timeout in seconds.

Returns:
    API response dictionary.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str = '', session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]`

Create a dedicated session bypassing the global SID cache.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).
    session_name: Optional session name visible in SmartConsole.
    session_description: Optional session description.

Returns:
    Tuple of (SID, Server IP).

###### `async def logout_sid(self, sid: str, server_ip: str, mgmt_name: str = '') -> bool`

Logout a specific SID (e.g. a dedicated session).

Args:
    sid: Session ID to logout.
    server_ip: Server IP of the session.
    mgmt_name: Optional management server name (for port lookup).

Returns:
    True if logout was successful.

###### `async def api_query(self, mgmt_name: str, command: str, domain: str = '', details_level: Literal['uid', 'standard', 'full'] = 'standard', payload: dict[str, Any] | None = None, container_key: str = 'objects', cache_mode: str = 'auto') -> RawApiResponse`

Execute API query with automatic session management.

### `arodonata/asdk/login_coordinator.py`

Login coordinator for session management with domain resolution.

Handles login orchestration with proper locking, retry logic,
and session caching.

#### class `LoginCoordinator`

Handles login operations with domain active server resolution.

Manages distributed locks per (mgmt_name, domain) to prevent concurrent
login attempts across multiple workers and implements proper retry logic with backoff.

Example:
    coordinator = LoginCoordinator(
        registry=server_registry,
        transport=transport,
        rate_limiter=rate_limiter,
        cache=cache_repository,
        settings=settings,
    )
    sid, server_ip = await coordinator.login("mgmt1", "domain1")

##### Methods

###### `def __init__(self, registry: ServerRegistry, transport: ApiTransport, rate_limiter: RateLimiter, cache: CacheRepository, settings: ArodonataSettings, lock_manager: DatabaseLockManager | None = None, session_cleaner: SessionCleaner | None = None) -> None`

Initialize login coordinator.

Args:
    registry: Server registry instance.
    transport: API transport instance.
    rate_limiter: Rate limiter instance.
    cache: Cache repository instance.
    settings: Configuration settings.
    lock_manager: Optional DatabaseLockManager instance.
    session_cleaner: Optional SessionCleaner for max-sessions cleanup.

###### `async def close(self) -> None`

Clean up resources.

Note: This method does NOT logout sessions - they remain cached in the
database for reuse across application runs. Use logout() or logout_all()
explicitly if you need to invalidate sessions on the server.

###### `async def run_startup_cleanup(self) -> None`

```python
@traced
```
Run session cleanup for all configured servers at library initialization.

Called once as a background task when ArodonataClient enters its async context.
For each server, acquires a temporary SID, discards stale sessions, and logs out.
Errors per-server are logged but never propagate.

###### `async def maintain_keepalives(self, exclude_key: str | None = None) -> None`

```python
@traced
```
Send keepalives for all stale cached sessions concurrently.

Called as a background task after every API call. Skips the SID
that was just used (it is implicitly fresh).

Args:
    exclude_key: mgmt_dmn_key of the SID that just made an API call.

###### `async def logout(self, mgmt_name: str, domain: str) -> bool`

```python
@traced
```
Explicitly logout of a session.

Args:
    mgmt_name: Management server name.
    domain: Domain name.

Returns:
    True if logout was successful (or session didn't exist), False otherwise.

###### `async def logout_all(self) -> None`

```python
@traced
```
Logout of all active sessions and clear cache.

###### `async def login(self, mgmt_name: str, domain: str = '', force: bool = False, *, cache_mode: str = 'auto', session_name: str | None = None, session_description: str | None = None, _skip_prefetch: bool = False, refresh_domain_ip: bool = False) -> tuple[str, str]`

```python
@traced
```
Login to management server or domain.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).
    force: Force fresh login ignoring SID cache.
    cache_mode: Cache behavior ("auto", "refresh", "off").
    _skip_prefetch: Internal use to prevent recursion.
    refresh_domain_ip: Force refresh of domain server IP (use only for failover).
                       Session-expiry retries should NOT set this — the domain IP
                       is still valid and bypassing the cache causes redundant
                       system-domain logins that trigger too_many_requests throttling.

Returns:
    Tuple of (SID, Server IP).

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str = '', session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]`

```python
@traced
```
Create a dedicated session that bypasses the global SID cache.

Used by write-intensive workflows (e.g. CPCRUD) that need session
isolation from the shared pool. The returned SID is NOT stored
in the cache — the caller is responsible for using it directly
via api_call_with_sid and for logout when done.

Retries with the same exponential backoff as the shared login path
(`_retry_with_backoff`) on a failed attempt -- unlike `login()`, this
previously made a single, unretried attempt, so a routine, recoverable
server-side throttling/lockout response (e.g. "Too many requests in a
given amount of time") surfaced as a hard failure to the caller instead
of being absorbed the way every other login path in this module already
handles it.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).
    session_name: Optional session name visible in SmartConsole.
    session_description: Optional session description.

Returns:
    Tuple of (SID, Server IP).

Raises:
    ValueError: If management server is unknown.
    AuthenticationError: If login fails after all retries.

### `arodonata/asdk/rate_limiter.py`

Rate limiter for per-server concurrent API request limiting.

Manages distributed locks to limit concurrent operations per server IP,
preventing overload of management servers across multiple workers.

#### class `RateLimiter`

Per-server distributed lock for concurrent API operation limiting.

Uses SQL-database-backed distributed locks (any SQLAlchemy-supported
dialect) to enforce concurrent operation limits across multiple
workers/processes.

Lock keys use a slot-based approach: ratelimit:{server_ip}:slot_{n}
where n is determined by hashing the operation ID to distribute load.

Example:
    limiter = RateLimiter(concurrent_limit=3)
    async with limiter.acquire("192.168.1.10"):
        # Make API call - limited to 3 concurrent per server across all workers
        pass

##### Methods

###### `def __init__(self, concurrent_limit: int = 3, lock_manager: DatabaseLockManager | None = None, slot_timeout: int = DEFAULT_RATE_LIMIT_SLOT_TIMEOUT) -> None`

Initialize rate limiter.

Args:
    concurrent_limit: Maximum concurrent operations per server.
    lock_manager: Optional DatabaseLockManager instance.
    slot_timeout: Default seconds acquire() waits for a free slot before
        giving up (see DEFAULT_RATE_LIMIT_SLOT_TIMEOUT for why this must
        comfortably exceed a single login retry-with-backoff sequence).

###### `async def close(self) -> None`

Clean up resources.

###### `async def acquire(self, server_ip: str, timeout: int | None = None) -> AsyncGenerator[None]`

```python
@asynccontextmanager
@traced
```
Acquire lock for server operations (reentrant per task).

Args:
    server_ip: Server IP address.
    timeout: Maximum time to wait for lock acquisition in seconds.
        Defaults to the slot_timeout this RateLimiter was constructed
        with (see DEFAULT_RATE_LIMIT_SLOT_TIMEOUT).

Yields:
    None when lock is acquired.

Raises:
    LockAcquisitionError: If lock cannot be acquired within timeout.

### `arodonata/asdk/server_registry.py`

Server registry for management server configuration lookup.

Manages the in-memory configuration map built from settings,
providing lookup and enumeration capabilities.

#### class `ServerConfig`

```python
@dataclass
```
Configuration for a management server.

##### Fields / Class Variables

```python
name: str
server_ip: str
api_key: SecretStr
port: int | None = None
is_mdm: bool | None = None
version: str | None = None
```
##### Methods

###### `def host(self) -> str`

```python
@property
```
Extract host from server_ip (handles host:port format).

Returns:
    Host part of server_ip (without port)

#### class `ServerRegistry`

Immutable view over configuration → in-memory server mapping.

Provides lookup and enumeration capabilities for management servers.

Example:
    registry = ServerRegistry(settings)
    names = registry.get_names()
    server = registry.get_server("my-server")

##### Methods

###### `def __init__(self, settings: ArodonataSettings) -> None`

Initialize server registry from configuration settings.

Args:
    settings: Configuration settings instance.

###### `def get_server(self, name: str) -> ServerConfig | None`

Get server configuration by name.

Args:
    name: Server name to lookup.

Returns:
    Server configuration or None if not found.

###### `def get_names(self) -> list[str]`

Get list of all management server names.

Returns:
    List of server name strings.

###### `def get_all_servers(self) -> dict[str, ServerConfig]`

Get all server configurations.

Returns:
    Dictionary mapping server names to ServerConfig objects.

###### `def has_server(self, name: str) -> bool`

Check if server exists in registry.

Args:
    name: Server name to check.

Returns:
    True if server exists.

###### `async def update_metadata(self, name: str, is_mdm: bool | None = None, version: str | None = None) -> None`

Update server metadata (MDM status, version).

Args:
    name: Server name to update.
    is_mdm: Multi-Domain Management status.
    version: API version.

### `arodonata/asdk/session_cleaner.py`

Session cleanup logic for Check Point management API sessions.

Enumerates active sessions via show-sessions, then discards stale
disconnected API sessions according to age/changes criteria.

#### class `CleanupResult`

```python
@dataclass
```
Result of a session cleanup operation.

##### Fields / Class Variables

```python
discarded: int = 0
skipped: int = 0
errors: list[str] = field(default_factory=list)
```
#### class `SessionCleaner`

Cleans up stale disconnected API sessions on Check Point management servers.

Only processes sessions where application is a known programmatic API type
('Management API' or 'WEB_API') to avoid
touching SmartConsole operator sessions.

Example:
    cleaner = SessionCleaner(transport, rate_limiter, registry)
    result = await cleaner.cleanup_stale_sessions(
        "mgmt1", "", system_sid, "10.0.0.1"
    )
    print(f"Discarded {result.discarded} sessions")

##### Methods

###### `def __init__(self, transport: ApiTransport, rate_limiter: RateLimiter, registry: ServerRegistry) -> None`

_No docstring._

###### `def is_max_sessions_error(error_msg: str) -> bool`

```python
@staticmethod
```
Return True if the error indicates the max-sessions limit was hit.

###### `async def cleanup_stale_sessions(self, mgmt_name: str, domain: str, system_sid: str, server_ip: str, port: int | None = None) -> CleanupResult`

```python
@traced
```
Discard stale disconnected Management API sessions.

Calls show-sessions, filters to Management API sessions only, then
discards those that are disconnected and meet the age/changes criteria:
  - marked as a test session (name/description contains "pytest") and
    age > 10 min → discard, regardless of changes
  - 0 changes AND age > 60 min → discard
  - >0 changes AND age > 24h  → discard (abandoned with unpublished work)
  - read-write/in-work session, 0 changes AND age > 72h → discard
  - read-write/in-work session, >0 changes AND age > 7 days → discard

Args:
    mgmt_name: Management server name (for logging).
    domain: Domain name (for logging).
    system_sid: Already-authenticated SID to use for show-sessions/discard.
    server_ip: Management server IP address.
    port: Optional port number.

Returns:
    CleanupResult with counts of discarded/skipped/errored sessions.

### `arodonata/asdk/transport.py`

API transport layer - wraps sync Check Point SDK with async execution.

Handles the actual communication with Check Point management servers
using asyncio.to_thread to run sync SDK operations in an async context.

#### class `ApiTransport`

Thin wrapper around sync SDK calls with async execution.

Uses asyncio.to_thread to run sync SDK operations in an async context,
allowing concurrent API operations without blocking the event loop.

Example:
    transport = ApiTransport()
    response = await transport.api_call(
        server_ip="192.168.1.10",
        sid="session123",
        command="show-hosts"
    )

##### Methods

###### `def __init__(self) -> None`

Initialize API transport.

###### `async def api_call(self, server_ip: str, sid: str, command: str, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1, port: int | None = None) -> RawApiResponse`

```python
@traced
```
Execute API call using sync SDK in async context.

Args:
    server_ip: Management server IP address.
    sid: Session identifier.
    command: API command to execute.
    payload: Request payload.
    wait_for_task: Whether to wait for task completion.
    timeout: Request timeout in seconds.
    port: Optional port number (defaults to 443 if not specified).

Returns:
    API response dictionary.

Raises:
    asyncio.TimeoutError: If operation times out.

###### `async def api_query(self, server_ip: str, sid: str, command: str, details_level: str = 'standard', payload: dict[str, Any] | None = None, container_key: str = 'objects', port: int | None = None) -> RawApiResponse`

```python
@traced
```
Execute API query using sync SDK in async context.

Args:
    server_ip: Management server IP address.
    sid: Session identifier.
    command: API query command to execute.
    details_level: Detail level for response.
    payload: Request payload.
    container_key: Key to extract objects from response.
    port: Optional port number (defaults to 443 if not specified).

Returns:
    API response dictionary.

Raises:
    ValueError: If response is None or invalid.

###### `async def login_with_apikey(self, server_ip: str, api_key: str, domain: str | None = None, timeout: int = 120, port: int | None = None, session_name: str | None = None, session_description: str | None = None, session_timeout: int | None = None) -> RawApiResponse`

```python
@traced
```
Perform login using an API key.

Args:
    server_ip: Management server IP address.
    api_key: API key for authentication.
    domain: Optional domain name.
    timeout: Login timeout in seconds (default: 120).
    port: Optional port number (defaults to 443 if not specified).
    session_name: Optional session name visible in SmartConsole.
    session_description: Optional session description.
    session_timeout: Session timeout in seconds (default: 600).

Returns:
    Login response dictionary.

Raises:
    asyncio.TimeoutError: If login times out.

###### `async def login_with_credentials(self, server_ip: str, username: str, password: str, domain: str | None = None, timeout: int = 120, port: int | None = None, session_name: str | None = None, session_description: str | None = None, session_timeout: int | None = None) -> RawApiResponse`

```python
@traced
```
Perform login with username/password credentials.

Args:
    server_ip: Management server IP address.
    username: Username for authentication.
    password: Password for authentication.
    domain: Optional domain name.
    timeout: Login timeout in seconds (default: 120).
    port: Optional port number (defaults to 443 if not specified).
    session_name: Optional session name visible in SmartConsole.
    session_description: Optional session description.
    session_timeout: Session timeout in seconds (default: 600).

Returns:
    Login response dictionary.

Raises:
    asyncio.TimeoutError: If login times out.

###### `async def logout(self, server_ip: str, sid: str, port: int | None = None) -> RawApiResponse`

```python
@traced
```
Perform logout for a session.

Args:
    server_ip: Management server IP address.
    sid: Session ID to logout.
    port: Optional port number (defaults to 443 if not specified).

Returns:
    API response dictionary.

###### `async def keepalive(self, server_ip: str, sid: str, port: int | None = None) -> RawApiResponse`

```python
@traced
```
Send keepalive ping to keep a session active.

Args:
    server_ip: Management server IP address.
    sid: Session identifier to keep alive.
    port: Optional port number (defaults to 443 if not specified).

Returns:
    API response dictionary.

###### `async def show_sessions(self, server_ip: str, sid: str, port: int | None = None) -> RawApiResponse`

```python
@traced
```
Retrieve all active sessions for the current admin.

Args:
    server_ip: Management server IP address.
    sid: Session identifier with sufficient privileges.
    port: Optional port number (defaults to 443 if not specified).

Returns:
    API response with 'objects' list of session dictionaries.

###### `async def discard_session(self, server_ip: str, sid: str, target_uid: str, port: int | None = None) -> RawApiResponse`

```python
@traced
```
Discard a specific session by its UID.

Args:
    server_ip: Management server IP address.
    sid: Session identifier used to issue the discard command.
    target_uid: UID of the session to discard (from show-sessions).
    port: Optional port number (defaults to 443 if not specified).

Returns:
    API response dictionary.


---

## cache — Database-Backed Caching Layer

### `arodonata/cache/__init__.py`

Centralized cache module - the ONLY database access point.

All database operations go through this module. Other modules MUST NOT
access PostgreSQL directly.

Usage:
    from sqlalchemy.ext.asyncio import create_async_engine
    from arodonata.cache import CacheRepository, DatabaseManager

    # Main app creates engine from its own config
    engine = create_async_engine("postgresql+asyncpg://...")

    # Initialize database manager and cache
    db = DatabaseManager(engine)
    await db.initialize()
    cache = CacheRepository(db)

    # All DB operations through cache
    sid = await cache.get_sid("mgmt1", "domain1")
    assets = await cache.get_assets(mgmt_names=["mgmt1"])

    # Main app disposes engine
    await engine.dispose()

_No public classes or functions in this module._

### `arodonata/cache/database.py`

SQLModel async database engine and session management.

This module provides the database connection infrastructure.
All other modules access the database through CacheRepository.

#### class `DatabaseManager`

Manages database sessions from pre-configured engine.

Applications create and own the AsyncEngine lifecycle.
This class wraps the engine and provides session management.

Example:
    from sqlalchemy.ext.asyncio import create_async_engine

    # Main app creates engine from its own config
    engine = create_async_engine("postgresql+asyncpg://...")

    db = DatabaseManager(engine)
    await db.initialize()

    async with db.session() as session:
        # Use session for queries
        pass

    # Note: App is responsible for disposing the engine
    await engine.dispose()

##### Methods

###### `def __init__(self, engine: AsyncEngine) -> None`

Initialize database manager with pre-configured engine.

Args:
    engine: Pre-configured AsyncEngine instance owned by the application.
           The application is responsible for disposing this engine.

###### `def engine(self) -> AsyncEngine`

```python
@property
```
Get the underlying engine.

###### `def is_initialized(self) -> bool`

```python
@property
```
Check if database tables have been initialized.

###### `async def initialize(self) -> None`

Create database tables if needed and add any missing columns.

Fast path: when the stored schema hash in arodonata_schema_version
matches the hash of the currently registered SQLModel metadata, the
per-table migration scan is skipped entirely (1 round trip).
Set ARODONATA_FORCE_SCHEMA_SCAN=1 to force the full scan.

###### `async def session(self) -> AsyncGenerator[AsyncSession]`

```python
@asynccontextmanager
```
Get an async database session.

Yields:
    AsyncSession for database operations.

Raises:
    RuntimeError: If database not initialized.

### `arodonata/cache/json_column.py`

JSONColumn TypeDecorator for cross-database JSON/JSONB support.

#### class `JSONColumn(TypeDecorator[Any])`

JSON type that uses JSONB for PostgreSQL, JSON for SQLite.

This TypeDecorator provides optimal JSON storage for each database:
- PostgreSQL: JSONB (binary JSON, faster queries, indexed)
- SQLite: JSON (stored as text, converted on access)

Benefits of JSONB on PostgreSQL:
- Efficient storage (binary format)
- Faster queries (no reparsing on each access)
- Supports GIN indexes for containment queries
- Supports operators like @>, ?, ?&, ?|

Usage:
    class MyModel(SQLModel, table=True):
        data: dict | None = Field(
            default=None,
            sa_column=Column("data", JSONColumn, nullable=True),
        )

##### Methods

###### `def load_dialect_impl(self, dialect: Dialect) -> TypeDecorator[Any]`

Return the appropriate JSON type for the database dialect.

Args:
    dialect: SQLAlchemy dialect (postgresql, sqlite, etc.)

Returns:
    JSONB for PostgreSQL, JSON for other databases.

###### `def process_bind_param(self, value: Any, dialect: Dialect) -> Any`

Process Python value for storage in database.

Args:
    value: Python dict/list to store
    dialect: Database dialect

Returns:
    JSON-compatible value for database storage.

###### `def process_result_value(self, value: Any, dialect: Dialect) -> Any`

Process database value for Python usage.

Args:
    value: Value from database
    dialect: Database dialect

Returns:
    Python dict/list from database JSON.

###### `def coerce_to_in_types(self, value: Any, dialect: Dialect) -> Any`

Coerce value to appropriate in-clause types.

### `arodonata/cache/lock_manager.py`

Database-backed distributed lock manager for cross-process coordination.

This module provides SQL-database-backed distributed locking (works with any
SQLAlchemy-supported dialect, e.g. SQLite or PostgreSQL) to coordinate
operations across multiple gunicorn workers, CLI sessions, or service instances.

Lock acquisition uses INSERT with retry logic and exponential backoff.
Locks automatically expire based on TTL to prevent deadlocks.

#### Module-Level Functions

##### `def generate_owner_id() -> str`

Generate unique owner ID for this process/worker.

Returns:
    Owner ID string in format 'hostname:pid:worker_id'.

Example:
    'web-server-1:12345:worker-2'

##### `def get_current_lock_context() -> LockContext | None`

Get the current lock context from context variable.

Returns:
    Current LockContext if in a decorated function, None otherwise.

Example:
    @distributed_lock("my_key")
    async def my_function():
        ctx = get_current_lock_context()
        if ctx:
            await ctx.renew_if_needed()

##### `def set_global_lock_manager(lock_manager: DatabaseLockManager | None) -> None`

Set the global lock manager instance.

This allows sharing a DatabaseLockManager across the application,
for example, using the same DatabaseManager as the ArodonataClient.

Args:
    lock_manager: The lock manager to use as the global instance, or None to reset.

Example:
    # In your application setup
    db_manager = DatabaseManager()
    lock_manager = DatabaseLockManager(db_manager)
    set_global_lock_manager(lock_manager)

    # Now all @distributed_lock decorated functions will use this instance

    # To reset (useful in tests):
    set_global_lock_manager(None)

##### `def distributed_lock(lock_key_template: str, timeout: int = 30, ttl: int | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]`

Decorator for async function-level distributed locking.

The lock_key_template can contain parameter placeholders in {braces}.
For example, "asset_refresh:{mgmt_names}" will substitute the mgmt_names
parameter value.

Args:
    lock_key_template: Lock key template, can use {param} placeholders.
    timeout: Maximum time to wait for lock acquisition in seconds.
    ttl: Lock time-to-live in seconds. If None, uses default (300s).

Returns:
    Decorator function.

Example:
    @distributed_lock("asset_refresh:{mgmt_names}", timeout=300, ttl=300)
    async def build_refresh_assets_cache(self, mgmt_names: str, domains: str):
        # Function is automatically locked
        # Can access lock context for manual renewal:
        ctx = get_current_lock_context()
        if ctx:
            await ctx.renew_if_needed()

#### class `LockAcquisitionError(Exception)`

Raised when lock acquisition fails due to timeout.

##### Methods

###### `def __init__(self, lock_key: str, timeout: int) -> None`

Initialize lock acquisition error.

Args:
    lock_key: The lock key that could not be acquired.
    timeout: The timeout period in seconds.

#### class `LockOwnershipError(Exception)`

Raised when lock operation fails due to ownership mismatch.

##### Methods

###### `def __init__(self, lock_key: str, owner_id: str) -> None`

Initialize lock ownership error.

Args:
    lock_key: The lock key with ownership issue.
    owner_id: The owner ID that doesn't match.

#### class `LockContext`

Context for an acquired lock, supporting renewal.

This class is returned by the acquire() context manager and provides
methods for lock renewal and metadata access.

##### Methods

###### `def __init__(self, lock_key: str, owner_id: str, acquired_at: datetime, expires_at: datetime, ttl: int, manager: DatabaseLockManager) -> None`

Initialize lock context.

Args:
    lock_key: The lock key.
    owner_id: The owner ID.
    acquired_at: When the lock was acquired.
    expires_at: When the lock expires.
    ttl: The lock TTL in seconds.
    manager: The DatabaseLockManager instance.

###### `async def renew(self, ttl: int | None = None) -> bool`

Renew the lock with a new TTL.

Args:
    ttl: New TTL in seconds. If None, uses original TTL.

Returns:
    True if renewed successfully, False if lock lost/expired.

Raises:
    LockOwnershipError: If lock is not owned by current owner.

###### `async def renew_if_needed(self, threshold: float = 0.5) -> bool`

Renew lock only if more than threshold of TTL has elapsed.

Args:
    threshold: Fraction of TTL that must elapse before renewal (default 0.5 = 50%).

Returns:
    True if renewed, False if renewal not needed yet or failed.

Raises:
    LockOwnershipError: If lock is not owned by current owner.

#### class `DatabaseLockManager`

SQL-database-backed distributed lock manager.

Provides distributed locking across multiple processes using the
consumer's configured SQL database (any SQLAlchemy-supported dialect,
e.g. SQLite or PostgreSQL) as the coordination backend. Locks
automatically expire to prevent deadlocks.

Example:
    manager = DatabaseLockManager()
    await manager.initialize()

    # Context manager usage
    async with await manager.acquire("my_lock", timeout=30, ttl=60) as lock:
        # Critical section
        pass

    # Manual usage
    lock = await manager.acquire_lock("my_lock", timeout=30, ttl=60)
    try:
        # Critical section
        pass
    finally:
        await manager.release_lock("my_lock", lock.owner_id)

##### Methods

###### `def __init__(self, db_manager: DatabaseManager) -> None`

Initialize lock manager.

Args:
    db_manager: DatabaseManager instance.

###### `async def initialize(self) -> None`

Initialize database connection.

This method is idempotent - calling it multiple times is safe.

###### `async def close(self) -> None`

Close database connection.

###### `async def acquire(self, lock_key: str, timeout: int = 30, ttl: int | None = None) -> AsyncGenerator[LockContext]`

```python
@asynccontextmanager
```
Acquire lock as async context manager.

Args:
    lock_key: Unique lock identifier.
    timeout: Maximum time to wait for lock acquisition in seconds.
    ttl: Lock time-to-live in seconds. If None, uses default (300s).

Yields:
    LockContext: Lock context with renewal methods.

Raises:
    LockAcquisitionError: If lock cannot be acquired within timeout.

###### `async def acquire_lock(self, lock_key: str, timeout: int = 30, ttl: int = 300) -> LockContext`

```python
@traced
```
Acquire a lock with retry logic and exponential backoff.

Args:
    lock_key: Unique lock identifier.
    timeout: Maximum time to wait for lock acquisition in seconds.
    ttl: Lock time-to-live in seconds.

Returns:
    LockContext with lock details.

Raises:
    LockAcquisitionError: If lock cannot be acquired within timeout.

###### `async def release_lock(self, lock_key: str, owner_id: str) -> None`

```python
@traced
```
Release a lock with one conditional DELETE.

Idempotent when the lock is already gone. Raises LockOwnershipError
when the lock exists but belongs to another owner (rare path — only
then is a second query issued).

###### `async def is_lock_held(self, lock_key: str, owner_id: str) -> bool`

Check if a lock is currently held by a specific owner.

Args:
    lock_key: Lock key to check.
    owner_id: Owner ID to check.

Returns:
    True if the lock exists and is held by the owner and not expired.

###### `async def renew_lock(self, lock_key: str, owner_id: str, ttl: int | None = None) -> bool`

```python
@traced
```
Renew a lock with one conditional UPDATE.

Returns False when the lock is gone; raises LockOwnershipError when
it exists under another owner (rare path — only then a second query).

### `arodonata/cache/models.py`

SQLModel table definitions for PostgreSQL cache.

Supports JSONB columns for complex data types with binary keys.

#### class `ServerList`

```python
@dataclass(frozen=True)
```
Value object for comma-separated server lists.

Provides type-safe handling of standby server lists.

Example:
    servers = ServerList.from_csv("server1,server2,server3")
    assert servers.servers == ["server1", "server2", "server3"]
    assert servers.to_csv() == "server1,server2,server3"

    empty = ServerList.from_csv("")
    assert empty.servers == []
    assert empty.to_csv() == ""

##### Fields / Class Variables

```python
servers: list[str]
```
##### Methods

###### `def from_csv(cls, csv: str) -> ServerList`

```python
@classmethod
```
Create ServerList from comma-separated string.

Args:
    csv: Comma-separated string (empty string returns empty list).

Returns:
    ServerList instance.

###### `def to_csv(self) -> str`

Convert to comma-separated string.

Returns:
    Comma-separated string (empty string if no servers).

#### class `SIDCache(SQLModel)`

Cached Check Point API session identifiers.

##### Fields / Class Variables

```python
mgmt_dmn_key: str = Field(primary_key=True, max_length=255, description="Composite key: 'mgmt_name:domain' (api-key mode) or 'mgmt_name:domain:username' (credential mode)")
sid: str = Field(max_length=255, description='Session identifier')
uid: str | None = Field(default=None, max_length=255, index=True, description='User identifier')
server_ip: str = Field(max_length=45, description='Management server IP')
created_at: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), description='Cache entry timestamp')
last_keepalive: datetime | None = Field(default=None, description='Last keepalive sent for this session (naive UTC)')
metadata_: dict[str, Any] | None = Field(default=None, sa_column=Column('metadata', JSON, nullable=True))
```
#### class `Asset(SQLModel)`

Cached gateway and server assets from Check Point.

##### Fields / Class Variables

```python
asset_id: str = Field(primary_key=True, max_length=255, description="Composite key: 'mgmt_name:domain:name'")
name: str = Field(max_length=255, index=True)
asset_type: str = Field(max_length=100, index=True)
asset_hardware: str = Field(default='', max_length=100, index=True)
asset_uid: str = Field(max_length=255)
domain_name: str = Field(default='', max_length=255)
domain_uid: str = Field(default='', max_length=255)
mgmt_name: str = Field(max_length=100, index=True)
parent_asset_id: str | None = Field(default=None, max_length=255, foreign_key='assets.asset_id', index=True)
path: str = Field(default='', max_length=1000)
ip_address: str = Field(default='', max_length=45)
ssh_ip: str = Field(default='', max_length=45)
comments: str = Field(default='', max_length=2000, description='Asset comments from API')
tags: list[dict[str, Any]] | None = Field(default=None, sa_column=Column('tags', JSON, nullable=True))
deployed_as: str | None = Field(default=None, max_length=20, description='Device deployment: virtual or physical')
device_type: str | None = Field(default=None, max_length=50, description='Specific device type (e.g., CLM, MDS, ClusterMember)')
device_category: str | None = Field(default=None, max_length=50, description='Broader functional category (e.g., Domain_CLM, Physical_FW)')
region: str | None = Field(default=None, max_length=100, index=True)
country_code: str | None = Field(default=None, max_length=10, index=True)
country_name: str | None = Field(default=None, max_length=100)
city_code: str | None = Field(default=None, max_length=10, index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `Domain(SQLModel)`

Cached domain information with MDS server mappings.

##### Fields / Class Variables

```python
mdm_dmn: str = Field(primary_key=True, description="'active_mds:domain' or 'sms:'")
domain_name: str = Field(index=True)
domain_uid: str = Field(default='', max_length=255)
active_mds: str
active_ip: str
active_server: str
standby_mdss: str = Field(default='')
standby_ips: str = Field(default='')
standby_servers: str = Field(default='')
mgmt_name: str
is_mdm: bool = Field(default=False)
```
##### Methods

###### `def build(cls, *, mgmt_name: str, domain_name: str, domain_uid: str = '', active_ip: str, active_server: str = '', standby_mdss: str = '', standby_ips: str = '', standby_servers: str = '', is_mdm: bool = False) -> Domain`

```python
@classmethod
```
Factory method to create Domain objects with proper defaults.

Eliminates duplication in domain creation across the codebase.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.
    domain_uid: Domain UID (default: "").
    active_ip: Active server IP address.
    active_server: Active server name (default: mgmt_name).
    standby_mdss: Comma-separated MDS standby servers.
    standby_ips: Comma-separated standby IPs.
    standby_servers: Comma-separated standby server names.
    is_mdm: Multi-Domain Management status.

Returns:
    Configured Domain instance.

Example:
    domain = Domain.build(
        mgmt_name="mgmt1",
        domain_name="dmn1",
        domain_uid="123abc",
        active_ip="192.168.1.10"
    )

#### class `DistributedLock(SQLModel)`

Distributed lock record for cross-process coordination.

##### Fields / Class Variables

```python
lock_key: str = Field(primary_key=True, max_length=255, description='Unique lock identifier')
owner_id: str = Field(max_length=255, description='Process/worker holding the lock (format: hostname:pid:worker_id)')
acquired_at: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), description='Lock acquisition timestamp')
expires_at: datetime = Field(description='Lock expiration timestamp for safety')
metadata_: dict[str, Any] | None = Field(default=None, sa_column=Column('metadata', JSON, nullable=True))
```
#### class `SchemaVersion(SQLModel)`

Row-per-applied-hash record of confirmed-applied model schema hashes.

DatabaseManager.initialize() skips the per-table migration scan when a
row for the currently registered metadata hash already exists. The hash
itself (rather than a synthetic single row id) is the primary key so that
multiple processes sharing one DB but registering different model sets
(e.g. different DISABLED_PLUGINS) each get their own row instead of
thrashing: with a single mutable row, each process's init would mismatch
the other's stored hash, pay the full scan every time, and overwrite the
other's hash.

##### Fields / Class Variables

```python
schema_hash: str = Field(primary_key=True, max_length=64, description='SHA-256 of the applied model metadata')
updated_at: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), description='When this schema hash was last confirmed applied (naive UTC)')
```
#### class `CPObject(SQLModel)`

Cached Check Point network object with extracted fields and raw data.

Stores relevant fields from Check Point API responses with automatic field
filtering for fast queries, plus raw JSONB for complete object access.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=384, description="Composite key: 'mgmt_name:domain_name:uid'")
uid: str = Field(index=True, max_length=64, description='Check Point object UID')
name: str = Field(index=True, max_length=255, description='Object name')
type: str = Field(index=True, max_length=64, description='Object type (host, network, group, etc.)')
mgmt_name: str = Field(index=True, max_length=64, description='Management server name')
domain_name: str = Field(index=True, max_length=255, default='', description='Domain name')
original_domain: str = Field(default='', max_length=255, description='Original domain')
ipv4_address: str = Field(default='', max_length=45, index=True, description='IPv4 address')
subnet4: str = Field(default='', max_length=43, description='Subnet network (CIDR)')
subnet_mask: str = Field(default='', max_length=18, description='Subnet mask')
ipv4_address_first: str = Field(default='', max_length=45, description='First IP in address range')
ipv4_address_last: str = Field(default='', max_length=45, description='Last IP in address range')
members: str = Field(default='', description='Comma-separated member UIDs')
color: str = Field(default='', max_length=32)
comments: str = Field(default='')
tags: str = Field(default='', description='Comma-separated tags')
nat_settings: dict[str, Any] | None = Field(default=None, sa_column=Column('nat_settings', JSON, nullable=True), description='NAT settings as JSON')
interfaces: list[dict[str, Any]] | None = Field(default=None, sa_column=Column('interfaces', JSON, nullable=True), description='Network interfaces as JSON list')
version: str = Field(default='', max_length=16, description='Object version')
cluster_uid: str = Field(default='', max_length=64, description='Cluster UID if member')
original_domain_uid: str = Field(default='', max_length=64, description='Original domain UID')
creation_time: datetime | None = Field(default=None)
last_modify_time: datetime | None = Field(default=None)
update_time: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), index=True, description='Last cache update')
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True), description='Complete API response as JSON')
```
#### class `LastPublishedSession(SQLModel)`

Last published session for smart refresh detection.

Tracks the last published session time per domain to determine if cache
refresh is needed during "check" mode.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=319)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255)
published_time: datetime = Field(default_factory=lambda : datetime(1970, 1, 1).replace(tzinfo=None), description='Session publish timestamp (naive UTC)')
uid: str = Field(default='', max_length=64)
name: str = Field(default='', max_length=255)
ip_address: str = Field(default='', max_length=45)
comments: str = Field(default='')
creator: str = Field(default='', max_length=255)
description: str = Field(default='')
update_time: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), index=True)
```
#### class `RulebaseAccess(SQLModel)`

Cached access control rules from Network layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_name:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True, description='Rule position in layer')
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
sources: str = Field(default='', description='Comma-separated source UIDs')
destinations: str = Field(default='', description='Comma-separated destination UIDs')
services: str = Field(default='', description='Comma-separated service UIDs')
action: str = Field(default='accept', max_length=32)
track: str = Field(default='', max_length=32)
update_time: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `RulebaseNAT(SQLModel)`

Cached NAT rules from NAT layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_name:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True)
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
original_source: str = Field(default='', max_length=255)
original_destination: str = Field(default='', max_length=255)
original_service: str = Field(default='', max_length=255)
translated_source: str = Field(default='', max_length=255)
translated_destination: str = Field(default='', max_length=255)
translated_service: str = Field(default='', max_length=255)
update_time: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `RulebaseHTTPS(SQLModel)`

Cached HTTPS inspection rules from CVD layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_name:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True)
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
sources: str = Field(default='', description='Comma-separated source UIDs')
destinations: str = Field(default='', description='Comma-separated destination UIDs')
track: str = Field(default='', max_length=32)
update_time: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `RulebaseThreat(SQLModel)`

Cached threat prevention rules from Threat layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_name:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True)
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
track: str = Field(default='', max_length=32)
protections: str = Field(default='', description='Comma-separated protection names')
update_time: datetime = Field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
### `arodonata/cache/object_service.py`

High-level object cache operations.

#### Module-Level Functions

##### `def classify_input(raw: str) -> tuple[SearchType, str]`

Classify search input and return (SearchType, cleaned_input).

Args:
    raw: User input string (IP, network, range, or name).

Returns:
    Tuple of (SearchType, cleaned_input).

Examples:
    >>> classify_input("127.0.0.1")
    (SearchType.HOST, '127.0.0.1')
    >>> classify_input("192.168.1.0/24")
    (SearchType.NETWORK, '192.168.1.0/24')
    >>> classify_input("10.0.0.1-10.0.0.10")
    (SearchType.RANGE, '10.0.0.1-10.0.0.10')
    >>> classify_input("web-server-01")
    (SearchType.NAME, 'web-server-01')

##### `def api_object_to_cpobject(api_obj: dict[str, Any], mgmt_name: str, domain_name: str) -> CPObject | None`

Convert a full-detail API object dict to a CPObject row.

The single canonical converter: both the full-reload path and the
incremental re-fetch path produce rows through this function.

#### class `SearchType(StrEnum)`

Classification of search input.

#### class `GroupNode`

```python
@dataclass
```
A node in the group membership tree.

##### Fields / Class Variables

```python
uid: str
name: str
domain: str
depth: int
children: list[GroupNode] | None = None
```
#### class `SearchResult`

```python
@dataclass
```
Search result for a single term.

##### Fields / Class Variables

```python
search_term: str
search_type: SearchType
objects: list[CPObject]
memberships: dict[str, list[GroupNode]] | None = None
```
#### class `ObjectService`

High-level object cache operations.

Provides search and refresh functionality with cache-first queries,
API fallback, and SSE streaming for progress tracking.

##### Methods

###### `def __init__(self, db_manager: DatabaseManager, client: ArodonataClient, max_incremental_changes: int = 500) -> None`

Initialize ObjectService.

Args:
    db_manager: DatabaseManager instance.
    client: ArodonataClient instance for API fallback.
    max_incremental_changes: Max in-scope changes an incremental
        apply will accept before falling back to a full reload.

###### `async def search_objects(self, search_input: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, max_depth: int = 2) -> AsyncIterator[SearchResult]`

Search for objects by IP, name, UID, or type.

Args:
    search_input: Comma-separated search terms.
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    max_depth: Maximum depth for group membership traversal.

Yields:
    SearchResult for each search term.

###### `async def refresh_objects(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: str = 'force') -> AsyncIterator[dict[str, Any]]`

Refresh object cache from API.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: Refresh mode (skip/check/force/incremental).

Yields:
    Progress dictionaries with keys:
        - message: str - Progress message
        - mgmt_name: str - Management server name
        - domain_name: str - Domain name
        - object_type: str - Type being fetched
        - count: int - Number of objects processed
        - total: int - Total objects to process

###### `async def refresh_last_published_session(self, mgmt_name: str, domain_name: str) -> LastPublishedSession | None`

Refresh and upsert the last-published-session record for one domain.

Makes a single, lightweight `show-last-published-session` API call —
does not touch CPObject or Asset caches. Safe to call independently
of a full object/asset refresh.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    The upserted LastPublishedSession record, or None if the API
    call failed or returned no usable timestamp.

###### `async def fetch_full_object(self, mgmt_name: str, domain_name: str, uid: str) -> dict[str, Any] | None`

Fetch one object in full detail via show-object.

Returns the raw object dict, or None ONLY when the management server
cleanly reports the object does not exist (deleted since the diff was
taken). Any other failure raises RuntimeError — callers treat that as
"incremental apply unsafe".

### `arodonata/cache/repository.py`

Centralized cache repository - ALL database operations go through here.

Other modules MUST NOT access PostgreSQL directly.

#### class `CacheRepository`

High-level cache operations for all modules.

This is the ONLY class that performs database operations.
All other modules must use this repository for data access.

Example:
    from sqlalchemy.ext.asyncio import create_async_engine

    # Main app creates engine from its own config
    engine = create_async_engine("postgresql+asyncpg://...")
    db_manager = DatabaseManager(engine)

    cache = CacheRepository(db_manager)
    await cache.initialize()

    # Session operations
    await cache.set_sid("mgmt1", "domain1", "sid123", "192.168.1.1")
    sid = await cache.get_sid("mgmt1", "domain1")

    # Asset operations
    assets = await cache.get_assets(mgmt_names=["mgmt1"])

##### Methods

###### `def __init__(self, db_manager: DatabaseManager) -> None`

Initialize cache repository with database manager.

Args:
    db_manager: DatabaseManager instance for database access.

###### `async def get_sid(self, mgmt_name: str, domain: str, max_age_seconds: int | None = None, session: Any | None = None, username: str | None = None) -> SIDCache | None`

Retrieve cached session ID.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).
    max_age_seconds: If set, check expiration and delete if expired.
    session: Optional database session.
    username: CP username (credential mode). Scopes the cache to this user.

Returns:
    SIDCache record or None if not found/expired.

###### `async def set_sid(self, mgmt_name: str, domain: str, sid: str, server_ip: str, uid: str | None = None, session: Any | None = None, username: str | None = None) -> None`

Store or update session ID in cache.

Args:
    mgmt_name: Management server name.
    domain: Domain name.
    sid: Session identifier.
    server_ip: Management server IP address.
    uid: Optional CP session UID from login response.
    session: Optional database session.
    username: CP username (credential mode). Scopes the cache to this user.

###### `async def delete_sid(self, mgmt_name: str, domain: str, username: str | None = None) -> None`

Delete specific session from cache.

Args:
    mgmt_name: Management server name.
    domain: Domain name.
    username: CP username (credential mode). Scopes the delete to this user.

###### `async def clear_sessions(self, older_than_seconds: int | None = None) -> int`

Clear session entries from cache.

Args:
    older_than_seconds: If set, only delete entries older than this.
                       If None, delete all entries.

Returns:
    Number of entries deleted.

###### `async def list_all_sids(self) -> list[SIDCache]`

List all session IDs in cache.

Returns:
    List of SIDCache records.

###### `async def update_keepalive(self, mgmt_name: str, domain: str, username: str | None = None) -> None`

Update last_keepalive timestamp for a cached session.

Does nothing if no record exists for the given key.

Args:
    mgmt_name: Management server name.
    domain: Domain name (empty string for system domain).
    username: CP username (credential mode). Scopes the update to this user.

###### `async def list_stale_keepalives(self, threshold_seconds: int = 600) -> list[SIDCache]`

Return all SID cache entries with a stale or missing keepalive.

Args:
    threshold_seconds: Age in seconds after which keepalive is considered stale.

Returns:
    List of SIDCache records needing a keepalive ping.

###### `async def get_by_sid(self, sid: str) -> SIDCache | None`

Retrieve cached session by session ID.

Args:
    sid: Session identifier.

Returns:
    SIDCache record or None if not found.

###### `async def get_by_uid(self, uid: str) -> SIDCache | None`

Retrieve cached session by user ID.

Args:
    uid: User identifier.

Returns:
    SIDCache record or None if not found.

###### `async def get_uid_by_sid(self, sid: str) -> str | None`

Get user ID by session ID.

Args:
    sid: Session identifier.

Returns:
    User ID or None if not found.

###### `async def get_sid_by_uid(self, uid: str) -> str | None`

Get session ID by user ID.

Args:
    uid: User identifier.

Returns:
    Session ID or None if not found.

###### `async def get_assets(self, asset_ids: list[str] | None = None, asset_types: list[str] | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[Asset]`

Retrieve assets with optional filters.

Args:
    asset_ids: Filter by specific asset IDs.
    asset_types: Filter by asset types.
    mgmt_names: Filter by management server names.
    domain_names: Filter by domain names.

Returns:
    List of matching Asset records.

###### `async def upsert_asset(self, asset: Asset, session: Any | None = None) -> None`

Insert or update a single asset.

Args:
    asset: Asset record to upsert.
    session: Optional database session.

###### `async def upsert_assets(self, assets: list[Asset], session: Any | None = None) -> int`

Bulk insert or update assets using merge in a single transaction.

Args:
    assets: List of Asset records to upsert.
    session: Optional database session.

Returns:
    Number of assets processed.

###### `async def delete_assets(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> int`

Delete assets with optional filters.

Args:
    mgmt_names: Delete only for these management servers.
    domain_names: Delete only for these domains.

Returns:
    Number of assets deleted.

###### `async def restore_asset_local_fields(self, snapshot: dict[str, dict[str, str]]) -> int`

Restore locally-owned path/ip_address/ssh_ip fields onto refreshed assets.

A raw refresh (delete_assets + upsert_assets from live management-API
data) has no notion of these fields and always writes them blank.
Callers that need them preserved across a refresh call get_assets()
beforehand to build `snapshot`, then call this after the refresh
completes. Only fills in fields that came back empty - never
overwrites a value the refresh legitimately set.

Args:
    snapshot: Mapping of asset_id to its pre-refresh path/ip_address/
        ssh_ip, as produced by get_assets().

Returns:
    Number of assets whose fields were restored.

###### `async def get_domain(self, mdm_dmn: str) -> Domain | None`

Get domain by composite key.

Args:
    mdm_dmn: Composite key 'active_mds:domain'.

Returns:
    Domain record or None.

###### `async def get_domains(self, mgmt_name: str | None = None, mgmt_names: list[str] | None = None) -> list[Domain]`

Get all domains, optionally filtered by management server.

Args:
    mgmt_name: Optional single management server filter (deprecated, use mgmt_names).
    mgmt_names: Optional list of management server names to filter.

Returns:
    List of Domain records.

###### `async def upsert_domain(self, domain: Domain) -> None`

Insert or update domain record.

Args:
    domain: Domain record to upsert.

###### `async def initialize(self) -> None`

Initialize cache repository database connections.

###### `async def close(self) -> None`

Close cache repository connections.

Note: Does not dispose the engine - main app is responsible for that.

###### `async def upsert_objects(self, objects: list[CPObject], session: Any | None = None) -> int`

Bulk insert or update CPObject records.

Uses merge for upsert - updates existing records or creates new ones.

Args:
    objects: List of CPObject records to upsert.
    session: Optional database session.

Returns:
    Number of objects processed.

###### `async def get_objects_by_ip(self, ip_address: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[CPObject]`

Retrieve objects by IP address.

Searches ipv4_address, ipv4_address_first, and ipv4_address_last fields.

Args:
    ip_address: IP address to search for.
    mgmt_names: Optional list of management servers to filter by.
    domain_names: Optional list of domains to filter by.

Returns:
    List of matching CPObject records.

###### `async def get_objects_by_subnet(self, subnet: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[CPObject]`

Retrieve objects by subnet CIDR.

Args:
    subnet: Subnet CIDR (e.g., "192.168.1.0/24").
    mgmt_names: Optional list of management servers to filter by.
    domain_names: Optional list of domains to filter by.

Returns:
    List of matching CPObject records.

###### `async def get_objects_in_ip_range(self, start_ip: str, end_ip: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[CPObject]`

Retrieve address-range objects that contain the specified IP range.

Args:
    start_ip: Start IP address of range.
    end_ip: End IP address of range.
    mgmt_names: Optional list of management servers to filter by.
    domain_names: Optional list of domains to filter by.

Returns:
    List of matching CPObject records.

###### `async def get_objects_by_name(self, name: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[CPObject]`

Retrieve objects by name with optional wildcards.

Args:
    name: Object name to search for (supports * and ?).
    mgmt_names: Optional list of management servers to filter by.
    domain_names: Optional list of domains to filter by.

Returns:
    List of matching CPObject records.

###### `async def get_objects_by_uids(self, uids: list[str], mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[CPObject]`

Retrieve objects by a list of UIDs.

Args:
    uids: List of object UIDs.
    mgmt_names: Optional management filter.
    domain_names: Optional domain filter.

Returns:
    List of matching CPObject records.

###### `async def get_object_by_uid(self, uid: str, mgmt_name: str | None = None, domain_name: str | None = None) -> CPObject | None`

Retrieve object by UID.

Args:
    uid: Object UID to search for.
    mgmt_name: Optional management server name.
    domain_name: Optional domain name.

Returns:
    CPObject record or None if not found.

###### `async def get_objects(self, object_type: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, filters: dict[str, Any] | None = None) -> list[CPObject]`

Retrieve objects from cache with flexible filtering.

Args:
    object_type: Optional object type filter (host, network, group, etc.).
    mgmt_names: Optional list of management servers to filter by.
    domain_names: Optional list of domains to filter by.
    filters: Optional additional filters as key-value pairs (supports wildcards in string values).

Returns:
    List of matching CPObject records.

###### `async def get_objects_by_type(self, object_type: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[CPObject]`

Retrieve objects by type.

Args:
    object_type: Object type (host, network, group, etc.).
    mgmt_names: Optional list of management servers to filter by.
    domain_names: Optional list of domains to filter by.

Returns:
    List of matching CPObject records.

###### `async def get_objects_by_members(self, member_uid: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> list[CPObject]`

Retrieve groups that contain the specified member UID.

Searches for groups where the members field contains the member UID.
Members are stored as comma-separated quoted strings like '"uid1","uid2","uid3"'.

Args:
    member_uid: Member UID to search for.
    mgmt_names: Optional list of management servers to filter by.
    domain_names: Optional list of domains to filter by.

Returns:
    List of group CPObject records containing the member.

###### `async def delete_domain_objects(self, mgmt_name: str, domain_name: str) -> int`

Delete all objects for a management server and domain.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    Number of records deleted.

###### `async def replace_domain_objects(self, mgmt_name: str, domain_name: str, objects: list[CPObject]) -> tuple[int, int]`

Atomically replace all objects for a domain.

Delete + bulk insert run in ONE transaction, so concurrent readers
never observe an empty/partial domain and a failure rolls back to
the previous cache contents. Input is deduped by primary key (the
API occasionally returns duplicate uids within a page set).

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.
    objects: Full replacement set for the domain.

Returns:
    (deleted_count, inserted_count).

###### `async def delete_object(self, uid: str, mgmt_name: str, domain_name: str) -> int`

Delete a single object by UID within a management server/domain.

Args:
    uid: Object UID.
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    Number of records deleted (0 if not present).

###### `async def get_last_published_session(self, mgmt_name: str, domain_name: str) -> LastPublishedSession | None`

Retrieve last published session for a domain.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    LastPublishedSession record or None.

###### `async def upsert_last_published_session(self, record: LastPublishedSession) -> None`

Insert or update last published session record.

Args:
    record: LastPublishedSession record to upsert.

###### `async def get_rulebase(self, model_class: type, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, filters: dict[str, Any] | None = None) -> list[Any]`

Query rulebase rules from cache with optional filters.

Args:
    model_class: Rulebase model class (RulebaseAccess, RulebaseNAT, etc.).
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    filters: Optional additional filters (e.g., layer_name, enabled).

Returns:
    List of rulebase records.

###### `async def upsert_rulebase(self, rule: Any, session: Any | None = None) -> None`

Insert or update a single rulebase rule.

Args:
    rule: Rulebase model instance to upsert.
    session: Optional database session.

###### `async def upsert_rulebases(self, rules: list[Any], session: Any | None = None) -> int`

Bulk insert or update rulebase rules.

Args:
    rules: List of rulebase model instances to upsert.
    session: Optional database session.

Returns:
    Number of rules processed.

###### `async def delete_rulebase(self, model_class: type, mgmt_name: str, domain_name: str, layer_name: str | None = None) -> int`

Delete rules from cache for a specific domain.

Args:
    model_class: Rulebase model class.
    mgmt_name: Management server name.
    domain_name: Domain name.
    layer_name: Optional layer name filter.

Returns:
    Number of rules deleted.

### `arodonata/cache/schema_version.py`

Deterministic hash of SQLModel/SQLAlchemy metadata.

Used by DatabaseManager.initialize() to skip the per-table auto-migration
scan when the registered model schema is unchanged since the last run.

#### Module-Level Functions

##### `def compute_schema_hash(metadata: MetaData) -> str`

Compute a deterministic SHA-256 over the metadata's schema shape.

Covers table names, columns (name, type, nullability, default, PK),
indexes (name, columns, unique) and unique constraints. Purely
in-memory — no DB access. Registration order does not affect the hash.

Args:
    metadata: SQLAlchemy MetaData (e.g. SQLModel.metadata).

Returns:
    64-char hex SHA-256 digest.


---

## config — Settings & Constants

### `arodonata/config/__init__.py`

Configuration management for Arodonata library.

_No public classes or functions in this module._

### `arodonata/config/constants.py`

Static constants for Arodonata library.

_No public classes or functions in this module._

### `arodonata/config/settings.py`

Configuration settings for Arodonata library.

Uses Pydantic v2 BaseSettings for type-safe configuration.
Settings can be provided via:
1. Environment variables (e.g., ARODONATA_LOG_LEVEL, MGMT_NAMES, etc.)
2. Explicit constructor parameters (overrides env vars)

Priority: Constructor parameters > Environment variables > Defaults

#### class `ArodonataSettings(BaseSettings)`

Configuration for Arodonata library.

Settings can be provided via environment variables or explicit parameters.
Explicit parameters override environment variables.

Examples:
    # Approach 1: Environment variables (automatic)
    # Set MGMT_NAMES, MGMT_SERVERS, API_KEYS in .env file
    from arodonata import ArodonataSettings
    settings = ArodonataSettings()  # Auto-reads from environment

    # Approach 2: Explicit parameters (override env vars)
    settings = ArodonataSettings(
        mgmt_names="mgmt1,mgmt2",
        mgmt_servers="10.0.0.1,10.0.0.2",
        api_keys="key1,key2",  # Actual keys, not variable names
    )

    # Approach 3: Mix of both (specific overrides)
    # MGMT_NAMES from env, but explicit server/keys
    settings = ArodonataSettings(
        mgmt_servers="custom.server.com",
        api_keys="my_key",
    )

##### Fields / Class Variables

```python
mgmt_names: str = Field(default='', description='Comma-separated management server names', validation_alias='MGMT_NAMES')
mgmt_servers: str = Field(default='', description='Comma-separated management server IPs/hosts', validation_alias='MGMT_SERVERS')
api_keys_raw: str = Field(default='', validation_alias='API_KEYS', exclude=True)
api_key_vars: str = Field(default='', validation_alias='API_KEY_VARS', exclude=True)
api_keys: str = Field(default='', description='Comma-separated API keys (actual values)')
username: str | None = Field(default=None, description='Username for credential-based auth', validation_alias='ARODONATA_USERNAME')
password: SecretStr | None = Field(default=None, description='Password for credential-based auth', validation_alias='ARODONATA_PASSWORD')
mgmt_ip: str | None = Field(default=None, description='Management server IP for credential mode', validation_alias='ARODONATA_MGMT_IP')
session_expire_seconds: int = Field(default=DEFAULT_SESSION_EXPIRE, ge=0, description='Session expiration in seconds', validation_alias='ARODONATA_SESSION_EXPIRE')
session_timeout: int = Field(default=DEFAULT_SESSION_TIMEOUT, ge=0, description='Session timeout in seconds (passed to login API)', validation_alias='ARODONATA_SESSION_TIMEOUT')
concurrent_limit: int = Field(default=DEFAULT_CONCURRENT_LIMIT, ge=1, le=20, description='Max concurrent API requests per server', validation_alias='ARODONATA_CONCURRENT_LIMIT')
rate_limit_slot_timeout: int = Field(default=DEFAULT_RATE_LIMIT_SLOT_TIMEOUT, ge=1, description='Seconds a caller waits for a free concurrency slot (RateLimiter.acquire) before giving up. Must comfortably exceed how long another caller can legitimately hold a slot during its own login retry-with-backoff sequence, or concurrent callers fail fast under real server-side throttling even though the server would have accepted a login moments later.', validation_alias='ARODONATA_RATE_LIMIT_SLOT_TIMEOUT')
api_timeout: int = Field(default=DEFAULT_API_TIMEOUT, ge=1, description='API timeout in seconds', validation_alias='ARODONATA_API_TIMEOUT')
login_retry_backoff: int = Field(default=DEFAULT_LOGIN_BACKOFF, ge=1, description='Login retry backoff in seconds', validation_alias='ARODONATA_LOGIN_BACKOFF')
login_max_retries: int = Field(default=DEFAULT_LOGIN_RETRIES, ge=1, description='Maximum login retry attempts', validation_alias='ARODONATA_LOGIN_RETRIES')
log_level: str = Field(default='INFO', description='Logging level', validation_alias='ARODONATA_LOG_LEVEL')
trace_modules: str = Field(default='', description="Comma-separated 'module:on|off' span gating rules", validation_alias='ARODONATA_TRACE_MODULES')
cpcrud_on_name_conflict: str = Field(default='update', description="Name conflict policy: 'update' | 'error'", validation_alias='ARODONATA_CPCRUD_ON_NAME_CONFLICT')
cpcrud_on_ip_conflict: str = Field(default='reuse', description="IP conflict policy: 'reuse' | 'error' | 'create_new'", validation_alias='ARODONATA_CPCRUD_ON_IP_CONFLICT')
cpcrud_auto_name_prefix_host: str = Field(default='Host_', validation_alias='ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST')
cpcrud_auto_name_prefix_network: str = Field(default='Net_', validation_alias='ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK')
cpcrud_auto_name_prefix_range: str = Field(default='IPR_', validation_alias='ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE')
cpcrud_auto_name_prefix_svc_tcp: str = Field(default='TCP_', validation_alias='ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP')
cpcrud_auto_name_prefix_svc_udp: str = Field(default='UDP_', validation_alias='ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP')
cpcrud_auto_name_prefix_svc_icmp: str = Field(default='ICMP_', validation_alias='ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP')
cpcrud_refresh_mode: str = Field(default='invalidate', description="Post-publish cache refresh: 'invalidate' | 'force'", validation_alias='ARODONATA_CPCRUD_REFRESH_MODE')
cpcrud_schema_path: str = Field(default='', description='Override path to checkpoint_ops_schema.json', validation_alias='ARODONATA_CPCRUD_SCHEMA_PATH')
```
##### Methods

###### `def __init__(self, **data: Any) -> None`

Construct settings, allowing plain Python field names as kwargs.

Every field above declares a ``validation_alias`` — its intended
environment-variable name (e.g. ``ARODONATA_USERNAME``, ``MGMT_NAMES``).
Pydantic only accepts that alias as input by default, so a plain kwarg
like ``ArodonataSettings(username=...)`` would silently be dropped.

To support that ergonomic kwarg form *without* also turning every bare
field name into a valid environment variable (which a blanket
``populate_by_name=True`` on ``model_config`` would do — see
``pydantic_settings.sources.base.EnvSettingsSource._extract_field_info``,
which registers an env-var candidate for every name the field accepts
as input), remap explicit constructor kwargs from their plain field
name to their alias *before* handing off to ``BaseSettings.__init__``.

This only touches keys the caller passed in directly here; it never
changes what ``model_config`` or any field's ``validation_alias``
declares, so environment variable sourcing is completely unaffected —
an ambient env var like ``USERNAME`` or ``LOG_LEVEL`` is never
absorbed.

###### `def auth_mode(self) -> str`

```python
@property
```
Return authentication mode based on provided credentials.

Returns:
    'credential' if username and password provided, else 'api_key'.

###### `def mgmt_names_list(self) -> list[str]`

```python
@property
```
Parse comma-separated management names to list.

###### `def mgmt_servers_list(self) -> list[str]`

```python
@property
```
Parse comma-separated management servers to list.

###### `def trace_modules_rules(self) -> dict[str, bool]`

```python
@property
```
Parsed gating rules for arlogi's set_trace_modules().

###### `def api_keys_list(self) -> list[str]`

```python
@property
```
Parse comma-separated API keys to list.

Returns:
    List of API key values.

###### `def resolve_api_keys(cls, v: Any, info: ValidationInfo) -> str`

```python
@field_validator('api_keys', mode='before')
@classmethod
```
Resolve API keys with priority: explicit parameter > API_KEY_VARS > API_KEYS > default.

This allows both automatic environment reading AND explicit override support,
plus support for the API_KEY_VARS indirection pattern.

###### `def validate_log_level(cls, v: Any) -> str`

```python
@field_validator('log_level', mode='before')
@classmethod
```
Validate log level is one of the allowed values.

###### `def validate_trace_modules(cls, v: str) -> str`

```python
@field_validator('trace_modules')
@classmethod
```
Each entry must be 'dotted.module:on' or 'dotted.module:off'.

###### `def validate_credential_mode(self) -> ArodonataSettings`

```python
@model_validator(mode='after')
```
Validate that mgmt_ip is provided when using credential-based auth.


---

## core — Core Domain Logic, Protocols & Exceptions

### `arodonata/core/__init__.py`

Core domain layer - protocols, models, and exceptions.

This module contains the foundational abstractions and domain models
for the Arodonata library.

_No public classes or functions in this module._

### `arodonata/core/cache_mode.py`

#### class `CacheMode(StrEnum)`

Cache read/refresh modes for read helpers.

CACHE:      Read cache as-is, never call the API.
SMART:      TTL-throttled staleness check; full domain reload if stale.
SMART_FAST: Same check; incremental show-changes apply, falling back to SMART.
FORCE:      Unconditional full reload of every in-scope domain (ignores TTL).

### `arodonata/core/cache_policy.py`

Value objects for cache refresh policy resolution.

#### class `Clock(Protocol)`

Injectable time source (keeps staleness logic deterministic in tests).

##### Methods

###### `def now(self) -> datetime`

_No docstring._

#### class `SystemClock`

Default wall-clock implementation (naive UTC, matches cache timestamps).

##### Methods

###### `def now(self) -> datetime`

_No docstring._

#### class `CachePolicy`

```python
@dataclass(frozen=True)
```
What a caller wants for a single read: a mode and an optional freshness TTL.

##### Fields / Class Variables

```python
mode: CacheMode
ttl: int | None = None
```
##### Methods

###### `def resolve(cls, mode: CacheMode | str | None, ttl: int | None, default: CachePolicy) -> CachePolicy`

```python
@classmethod
```
Merge a per-call (mode, ttl) with the client default.

A None call arg falls back to the default's value for that field.

#### class `RefreshScope`

```python
@dataclass(frozen=True)
```
The management servers / domains a read touches (None = all in scope).

##### Fields / Class Variables

```python
mgmt_names: list[str] | None = None
domain_names: list[str] | None = None
```
#### class `RefreshOutcome`

```python
@dataclass
```
Result of a coordinator.ensure() call, for logging/telemetry and tests.

##### Fields / Class Variables

```python
mode_used: CacheMode
refreshed_domains: list[tuple[str, str]] = field(default_factory=list)
fell_back: bool = False
skipped_reason: str | None = None
```
### `arodonata/core/cache_refresh_coordinator.py`

Coordinates cache freshness/refresh decisions ahead of reads.

#### class `CacheRefreshCoordinator`

Decides whether/how to refresh cache before a read, per CachePolicy.

##### Methods

###### `def __init__(self, cache: Any, api: Any, object_service: Any, session_tracker: Any = None, default_mode: CacheMode = CacheMode.SMART, default_ttl: int = 300, clock: Clock | None = None, max_incremental_changes: int = 500) -> None`

_No docstring._

###### `async def ensure(self, scope: RefreshScope, policy: CachePolicy) -> RefreshOutcome`

Ensure cache satisfies `policy` over `scope` before a read.

###### `def invalidate(self, mgmt_name: str, domain_name: str) -> None`

Drop the TTL memo for a domain so the next check cannot be skipped.

### `arodonata/core/change_processor.py`

Change processor for parsing show-changes API responses.

#### class `ChangeType(StrEnum)`

Type of object change.

#### class `ObjectChange`

```python
@dataclass
```
Represents a single object change from show-changes API.

##### Fields / Class Variables

```python
uid: str
object_type: str
change_type: ChangeType
name: str
raw_data: dict[str, Any]
```
#### class `ChangeProcessor`

Process show-changes API responses.

Parses the response and provides methods for filtering/grouping changes.

##### Fields / Class Variables

```python
_OPERATION_KEYS: tuple[tuple[str, ChangeType], ...] = (('added-objects', ChangeType.ADD), ('modified-objects', ChangeType.UPDATE), ('deleted-objects', ChangeType.DELETE))
```
##### Methods

###### `def parse_changes(self, api_response: dict[str, Any]) -> list[ObjectChange]`

Parse changes from show-changes API response.

Supports both response shapes:
- Real CP (R80+): task-wrapped and session-grouped —
  data.tasks[].task-details[].changes[].operations.{added,modified,
  deleted}-objects[], where each entry is the full object.
- Legacy/flat: data.changes[] with per-entry "change-type" fields
  (used by older fixtures and kept for compatibility).

Args:
    api_response: Raw API response from show-changes command.

Returns:
    List of ObjectChange objects.

###### `def group_by_object_type(self, changes: list[ObjectChange]) -> dict[str, list[ObjectChange]]`

Group changes by object type.

Args:
    changes: List of ObjectChange objects.

Returns:
    Dictionary mapping object type to list of changes.

###### `def filter_by_change_type(self, changes: list[ObjectChange], change_type: ChangeType) -> list[ObjectChange]`

Filter changes by change type.

Args:
    changes: List of ObjectChange objects.
    change_type: Change type to filter by.

Returns:
    Filtered list of changes.

###### `def get_adds_and_updates(self, changes: list[ObjectChange]) -> list[ObjectChange]`

Get only adds and updates (excluding deletes).

Args:
    changes: List of ObjectChange objects.

Returns:
    List of changes with type ADD or UPDATE.

### `arodonata/core/exceptions.py`

Custom exceptions for Arodonata library.

Provides a hierarchy of exceptions for proper error handling
throughout the library.

#### class `ArodonataError(Exception)`

Base exception for all Arodonata errors.

##### Methods

###### `def __init__(self, message: str, *args: object) -> None`

_No docstring._

#### class `ConfigurationError(ArodonataError)`

Configuration-related errors.

#### class `MissingConfigurationError(ConfigurationError)`

Required configuration is missing.

#### class `ConnectionError(ArodonataError)`

Connection-related errors.

#### class `DatabaseConnectionError(ConnectionError)`

Database connection failed.

#### class `ApiConnectionError(ConnectionError)`

API connection failed.

#### class `AuthenticationError(ArodonataError)`

Authentication-related errors.

#### class `SessionExpiredError(AuthenticationError)`

Session has expired and needs relogin.

#### class `InvalidCredentialsError(AuthenticationError)`

Credentials are invalid.

#### class `ApiError(ArodonataError)`

API operation errors.

##### Methods

###### `def __init__(self, message: str, *args: object, err_code: str | int | None = None, err_message: str | None = None) -> None`

_No docstring._

#### class `ApiCallError(ApiError)`

API call failed.

#### class `ApiQueryError(ApiError)`

API query failed.

#### class `ThrottlingError(ApiError)`

API request was throttled.

#### class `CacheError(ArodonataError)`

Cache-related errors.

#### class `CacheNotInitializedError(CacheError)`

Cache not initialized.

#### class `ClientError(ArodonataError)`

Client-related errors.

#### class `ClientClosedError(ClientError)`

Client has been closed and cannot be used.

#### class `ServerNotFoundError(ClientError)`

Management server not found in configuration.

### `arodonata/core/incremental_refresh.py`

Shared show-changes incremental refresh engine.

One implementation used by both consumers:
- CacheRefreshCoordinator._incremental_reload (smart-fast read path)
- ObjectService.refresh_objects(mode="incremental") (bulk refresh path)

Semantics: the show-changes diff is only a CHANGE LIST. Every added or
modified in-scope object is re-fetched in full via show-object and converted
by the canonical full-reload converter — diff payload bodies are never
written to the cache. Any condition that would make the apply unsafe raises
FallbackToFull; the caller performs an atomic full-domain reload instead.
The engine never advances the LastPublishedSession baseline — callers do,
and only on success.

#### class `FallbackToFull(Exception)`

Incremental apply would be unsafe; the caller must do a full reload.

#### class `IncrementalRefresher`

Applies a show-changes diff for one domain with re-fetch-in-full semantics.

##### Methods

###### `def __init__(self, *, api: Any, cache: Any, fetch_full_object: Callable[[str, str, str], Awaitable[dict[str, Any] | None]], to_cpobject: Callable[[dict[str, Any], str, str], CPObject | None], in_scope_types: frozenset[str] = DEFAULT_IN_SCOPE_TYPES, max_changes: int = DEFAULT_MAX_CHANGES) -> None`

_No docstring._

###### `async def apply(self, mgmt: str, domain: str) -> int`

Apply all in-scope changes since the stored baseline.

Returns the number of rows written (upserts + deletes); 0 means the
publish touched nothing the object cache holds. Raises FallbackToFull
whenever an incremental apply would be unsafe. Never advances the
baseline stamp — that is the caller's responsibility.

### `arodonata/core/orchestration.py`

Cache orchestration service for smart caching.

#### class `CacheOrchestrationService`

Orchestrates cache and API interactions.

Responsibilities:
- Provide typed cache-read helper methods (get_domains, get_gateways, etc.)
- Check cache freshness for smart-refresh callers
- Handle session-aware change tracking
- Coordinate smart refresh

##### Fields / Class Variables

```python
DEFAULT_FRESHNESS_SECONDS: dict[str, int] = {'objects': 900, 'assets': 3600, 'domains': 86400}
```
##### Methods

###### `def __init__(self, cache: 'CachePort', api: 'ApiPort', session_tracker: 'SessionChangeTracker | None', coordinator: 'CacheRefreshCoordinator | None' = None) -> None`

Initialize orchestration service.

Args:
    cache: Cache implementation.
    api: API implementation.
    session_tracker: Session change tracker (optional for now).
    coordinator: Cache refresh coordinator (optional; when absent,
        read helpers skip cache-mode-driven refresh entirely).

###### `async def get_domains(self, mgmt_names: list[str] | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['Domain']`

Get domains from cache.

Args:
    mgmt_names: Optional list of management server names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Domain Pydantic models.

###### `async def get_gateways(self, mgmt_names: list[str] | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['Gateway']`

Get gateways and servers from cache.

Args:
    mgmt_names: Optional list of management server names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Gateway Pydantic models.

###### `async def get_hosts(self, name_filter: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['Host']`

Get host objects from cache.

Args:
    name_filter: Optional name filter (supports wildcards).
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Host Pydantic models.

###### `async def get_networks(self, subnet: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['Network']`

Get network objects from cache.

Args:
    subnet: Optional subnet filter (CIDR notation).
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Network Pydantic models.

###### `async def get_groups(self, name_filter: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['Group']`

Get group objects from cache.

Args:
    name_filter: Optional name filter (supports wildcards).
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of Group Pydantic models.

###### `async def get_object_by_uid(self, uid: str, mgmt_name: str, domain_name: str = '') -> 'CPObject | None'`

Get any object by UID.

Args:
    uid: Object UID.
    mgmt_name: Management server name.
    domain_name: Domain name (default: system domain).

Returns:
    CPObject or None if not found.

###### `async def get_access_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['AccessRule']`

Get access control rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "Network").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of AccessRule Pydantic models.

###### `async def get_nat_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['NATRule']`

Get NAT rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "NAT").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of NATRule Pydantic models.

###### `async def get_https_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['HTTPSRule']`

Get HTTPS inspection rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "CVD").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of HTTPSRule Pydantic models.

###### `async def get_threat_rules(self, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None) -> list['ThreatRule']`

Get threat prevention rules from cache.

Args:
    layer_name: Optional layer name filter (e.g., "Threat").
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.
    cache_mode: Optional per-call cache refresh mode override.
    cache_ttl: Optional per-call cache freshness TTL override.

Returns:
    List of ThreatRule Pydantic models.

###### `async def publish(self, mgmt_name: str, domain: str) -> None`

Publish the session, then reconcile cache from server truth.

The API mints authoritative UIDs on publish, so we do not upsert local
SessionChange rows. Instead we publish, then run a smart-fast refresh
(which diffs last-cached -> new last-published) to pull the just-published
objects with their real UIDs, then clear the in-memory tracker.

###### `async def discard(self, mgmt_name: str, domain: str) -> None`

Discard session changes without persisting.

Clears in-memory session changes without writing to cache.

Args:
    mgmt_name: Management server name.
    domain: Domain name.

### `arodonata/core/protocols.py`

Core protocols (interfaces) for Arodonata library.

Defines abstract interfaces using Python Protocols for proper dependency
inversion and testability. All major components implement these protocols.

#### class `RefreshMode(StrEnum)`

Cache refresh mode for object operations.

Attributes:
    SKIP: Use cache as-is without refresh.
    CHECK: Refresh stale domains only (based on LastPublishedSession);
        stale domains get a full atomic reload.
    FORCE: Refresh all domains unconditionally (full atomic reload).
    INCREMENTAL: Refresh stale domains only (same staleness probe as
        CHECK); stale domains get a show-changes incremental apply with
        fallback to a full atomic reload on any unsafe condition.

#### class `ICacheRepository(Protocol)`

```python
@runtime_checkable
```
Interface for cache operations.

All database access goes through this protocol.

##### Methods

###### `async def get_sid(self, mgmt_name: str, domain: str, max_age_seconds: int | None = None, *, username: str | None = None) -> SIDCache | None`

Retrieve cached session ID.

###### `async def set_sid(self, mgmt_name: str, domain: str, sid: str, server_ip: str, uid: str | None = None, session: Any | None = None, *, username: str | None = None) -> None`

Store session ID in cache.

###### `async def delete_sid(self, mgmt_name: str, domain: str, *, username: str | None = None) -> None`

Delete specific session from cache.

###### `async def clear_sessions(self, older_than_seconds: int | None = None) -> int`

Clear session entries from cache.

###### `async def get_assets(self, asset_ids: list[str] | None = None, asset_types: list[str] | None = None, mgmt_names: list[str] | None = None) -> list[Asset]`

Retrieve assets with optional filters.

###### `async def upsert_asset(self, asset: Asset) -> None`

Insert or update a single asset.

###### `async def upsert_assets(self, assets: list[Asset]) -> int`

Bulk insert or update assets.

###### `async def initialize(self) -> None`

Initialize the cache (creates tables if needed).

###### `async def close(self) -> None`

Close database connections.

#### class `IApiTransport(Protocol)`

```python
@runtime_checkable
```
Interface for API communication layer.

##### Methods

###### `async def api_call(self, server_ip: str, sid: str, command: str, payload: dict[str, Any] | None = None, timeout: int = -1, wait_for_task: bool = True) -> RawApiResponse`

Execute API call.

###### `async def api_query(self, server_ip: str, sid: str, command: str, details_level: str = 'standard', payload: dict[str, Any] | None = None, container_key: str = 'objects') -> RawApiResponse`

Execute API query.

#### class `IServerRegistry(Protocol)`

```python
@runtime_checkable
```
Interface for server configuration lookup.

##### Methods

###### `def get_server(self, name: str) -> ServerConfig | None`

Get server configuration by name.

###### `def get_names(self) -> list[str]`

Get list of all server names.

###### `def update_metadata(self, name: str, is_mdm: bool | None = None, version: str | None = None) -> None`

Update server metadata.

#### class `IRateLimiter(Protocol)`

```python
@runtime_checkable
```
Interface for rate limiting per server.

##### Methods

###### `async def acquire(self, server_ip: str) -> AsyncGenerator[None]`

```python
@asynccontextmanager
```
Acquire rate limit slot for server.

#### class `ILoginCoordinator(Protocol)`

```python
@runtime_checkable
```
Interface for login orchestration.

##### Methods

###### `async def login(self, mgmt_name: str, domain: str, force: bool = False) -> tuple[str, str]`

Login and return (sid, server_ip).

#### class `ServerConfig`

Server configuration data.

##### Fields / Class Variables

```python
name: str
server_ip: str
is_mdm: bool | None
version: str | None
```
#### class `SIDRecord`

Cached SID record data.

##### Fields / Class Variables

```python
sid: str
server_ip: str
created_at: datetime
```
### `arodonata/core/session_tracker.py`

Session change tracker for in-memory change tracking.

#### class `SessionChange`

```python
@dataclass
```
A change within the current unpublished session.

##### Fields / Class Variables

```python
operation: Literal['add', 'modify', 'delete']
object_type: str
uid: str
name: str
data: dict[str, Any] | None = None
timestamp: datetime = field(default_factory=lambda : datetime.now(UTC).replace(tzinfo=None))
```
#### class `SessionChangeTracker`

Tracks in-memory changes for the current unpublished session.

Changes are NOT persisted to cache until publish is called.

##### Methods

###### `def __init__(self) -> None`

_No docstring._

###### `def add_change(self, mgmt_name: str, domain: str, change: SessionChange) -> None`

Track a change for a session.

Args:
    mgmt_name: Management server name.
    domain: Domain name.
    change: SessionChange to track.

###### `def get_session_changes(self, mgmt_name: str, domain: str) -> list[SessionChange]`

Get all tracked changes for current session.

Args:
    mgmt_name: Management server name.
    domain: Domain name.

Returns:
    List of SessionChange objects (empty if no changes).

###### `def clear_session(self, mgmt_name: str, domain: str) -> None`

Clear tracked changes for a session.

Called after publish or discard.

Args:
    mgmt_name: Management server name.
    domain: Domain name.

###### `def has_changes(self, mgmt_name: str, domain: str) -> bool`

Check if session has any tracked changes.

Args:
    mgmt_name: Management server name.
    domain: Domain name.

Returns:
    True if session has changes, False otherwise.


---

## cpcrud — Declarative CRUD / Rule Engine

### `arodonata/cpcrud/__init__.py`

Idempotent Policy-as-Code CRUD for Check Point objects.

_No public classes or functions in this module._

### `arodonata/cpcrud/differ.py`

Field-level diff between desired (template) and existing (API) object state.

#### Module-Level Functions

##### `def diff_object(object_type: str, desired: dict[str, Any], existing: ObjectState) -> FieldDiff`

Compare desired (template) fields against existing (API) object. Returns FieldDiff.

### `arodonata/cpcrud/executor.py`

Execute phase: walk the Plan grouped per (mgmt, domain); dedicated-session lifecycle.

#### Module-Level Functions

##### `def fold_reports(first: ApplyReport, second: ApplyReport) -> ApplyReport`

Merge a retry pass into the prior report: last result per action_id wins.

##### `def classify_api_error(message: str, code: str) -> str | None`

Best-effort classification of CP API write errors for drift/lock reconciliation.

#### class `Executor`

_No docstring._

##### Methods

###### `def __init__(self, client: ArodonataClient, reader: Any) -> None`

_No docstring._

###### `async def stream(self, plan: Plan, *, force: bool = False, dry_run: bool = False, no_publish: bool = False, discard: bool = False, session_name: str | None = None, session_description: str | None = None, refresh: str = 'invalidate') -> AsyncIterator[ActionResult | ApplyReport]`

_No docstring._

###### `async def execute(self, plan: Plan, **kwargs: Any) -> ApplyReport`

_No docstring._

### `arodonata/cpcrud/inverse.py`

Inverse templates: compensate an applied Plan via a normal schema-valid template.

#### Module-Level Functions

##### `def build_inverse_template(plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]`

Build a schema-valid template that compensates `plan`.

With `report`, only actions that actually executed (per ActionResult) are inverted, and
created-object uids from the report are used as precise delete keys. Apply the result via
the normal plan()/apply() pipeline -- it re-resolves, re-orders, re-stamps and re-guards.

### `arodonata/cpcrud/models.py`

Pydantic models and enums for CPCRUD (v2 shapes).

#### class `NameConflictPolicy(StrEnum)`

_No docstring._

#### class `IpConflictPolicy(StrEnum)`

_No docstring._

#### class `Outcome(StrEnum)`

_No docstring._

#### class `ObjectMatch(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
name: str
uid: str
type: str = ''
where_used_total: int = 0
matches_convention: bool = False
lock: str | None = None
```
#### class `ConflictInfo(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
axis: Literal['name', 'ip', 'lock']
policy: str
requested: dict[str, Any] = Field(default_factory=dict)
candidates: list[ObjectMatch] = Field(default_factory=list)
```
#### class `FieldDiff(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
changes: dict[str, dict[str, Any]] = Field(default_factory=dict)
```
##### Methods

###### `def has_changes(self) -> bool`

```python
@property
```
_No docstring._

#### class `CPCRUDResult(BaseModel)`

Per-action view used in SSE events and legacy-style summaries.

##### Fields / Class Variables

```python
operation: str
type: str
outcome: Outcome
name: str
uid: str | None = None
matches: list[ObjectMatch] = Field(default_factory=list)
changes: dict[str, dict[str, Any]] | None = None
conflict: ConflictInfo | None = None
message: str = ''
```
#### class `PlannedAction(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
id: str
depends_on: list[str] = Field(default_factory=list)
operation: str
type: str
mgmt_name: str
domain_name: str
desired: dict[str, Any] = Field(default_factory=dict)
key: dict[str, Any] | None = None
outcome: Outcome = Outcome.CREATE
resolved_uid: str | None = None
resolved_name: str = ''
matches: list[ObjectMatch] = Field(default_factory=list)
changes: dict[str, dict[str, Any]] | None = None
conflict: ConflictInfo | None = None
command: str | None = None
payload: dict[str, Any] | None = None
auto_created: bool = False
warnings: list[str] = Field(default_factory=list)
layer: str | None = None
position: Any | None = None
package: str | None = None
message: str = ''
prior_state: dict[str, Any] | None = None
```
##### Methods

###### `def to_result(self) -> CPCRUDResult`

_No docstring._

#### class `DomainStamp(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
last_publish_session: str
```
#### class `Plan(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
actions: list[PlannedAction] = Field(default_factory=list)
stamps: list[DomainStamp] = Field(default_factory=list)
template_hash: str = ''
```
##### Methods

###### `def domains(self) -> list[tuple[str, str]]`

Distinct (mgmt_name, domain_name) pairs in action order.

#### class `ActionResult(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
action_id: str
outcome: Outcome
type: str = ''
name: str = ''
mgmt_name: str = ''
domain_name: str = ''
uid: str | None = None
locking_session: dict[str, Any] | None = None
message: str = ''
```
#### class `ApplyReport(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
results: list[ActionResult] = Field(default_factory=list)
published_domains: list[DomainStamp] = Field(default_factory=list)
remaining: Plan | None = None
summary: dict[str, int] = Field(default_factory=dict)
```
#### class `ObjectState(BaseModel)`

Actual state of an existing object, as returned by show-<type>.

##### Fields / Class Variables

```python
uid: str
name: str
type: str
raw: dict[str, Any] = Field(default_factory=dict)
```
##### Methods

###### `def lock(self) -> str | None`

```python
@property
```
_No docstring._

#### class `LayerInfo(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
type: str
parent_layer_uid: str | None = None
```
#### class `SectionInfo(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
layer_uid: str
```
#### class `RuleMatch(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
rule_number: int
raw: dict[str, Any] = Field(default_factory=dict)
```
### `arodonata/cpcrud/naming.py`

Object naming conventions (from FPCR ObjectMatcher), prefix-configurable.

#### Module-Level Functions

##### `def matches_convention(object_type: str, name: str, prefixes: NamingPrefixes | None = None) -> bool`

_No docstring._

#### class `NamingPrefixes(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
host: str = 'Host_'
network: str = 'Net_'
range: str = 'IPR_'
svc_tcp: str = 'TCP_'
svc_udp: str = 'UDP_'
svc_icmp: str = 'ICMP_'
```
##### Methods

###### `def from_settings(cls, settings: Any) -> NamingPrefixes`

```python
@classmethod
```
_No docstring._

### `arodonata/cpcrud/nat.py`

NAT settings transformation (ported from MMP cpcrud object_manager).

#### Module-Level Functions

##### `def transform_nat_settings(object_type: str, nat_settings: dict[str, Any] | None) -> dict[str, Any] | None`

Normalize template NAT settings to the CP API shape. Returns None when empty.

### `arodonata/cpcrud/planner.py`

Decide phase: normalized template + StateReader + policy -> single Plan.

#### Module-Level Functions

##### `def template_hash(normalized_doc: dict[str, Any]) -> str`

_No docstring._

#### class `Planner`

_No docstring._

##### Methods

###### `def __init__(self, reader: StateReader, settings: Any | None = None) -> None`

_No docstring._

###### `async def decide(self, doc: dict[str, Any], on_name: NameConflictPolicy | None = None, on_ip: IpConflictPolicy | None = None) -> Plan`

_No docstring._

### `arodonata/cpcrud/position_helper.py`

Resolve a schema-validated rule_position value into the exact apply-time API position (spec §9).

#### Module-Level Functions

##### `async def resolve_position(reader: Any, position: Any, layer_scope_uid: str, layer_type: str, *, mgmt: str, domain: str) -> dict[str, Any]`

Resolve `position` (already schema-validated) into the exact API position payload fragment.

##### `def resolve_nat_position(position: Any) -> dict[str, Any]`

NAT counterpart to `resolve_position`: package-scoped, no layer/section concept.

Cleanup-aware `bottom` is deliberately NOT extended here -- spec section 9 defines it in
terms of a layer's implicit cleanup action, a concept that doesn't exist for NAT rulebases
(no implicit "cleanup" NAT rule). NAT rulebases do have their own `nat-section` objects, but
no StateReader method resolves a NAT section to a scope the way `get_section` does for
access/https/threat-prevention layers -- building that is out of scope for this fix, so a
section-relative NAT position is a hard, non-silent error rather than a silent guess (same
philosophy as `resolve_position`'s missing-section error above).

### `arodonata/cpcrud/resolver.py`

Kind-generic create-or-reuse resolver (Decide phase, no writes).

#### Module-Level Functions

##### `async def resolve_add(reader: StateReader, object_type: str, desired: dict[str, Any], *, on_name: NameConflictPolicy, on_ip: IpConflictPolicy, mgmt: str, domain: str, action_id: str) -> PlannedAction`

_No docstring._

##### `async def resolve_update(reader: StateReader, object_type: str, key: dict[str, Any], data: dict[str, Any], *, mgmt: str, domain: str, action_id: str) -> PlannedAction`

_No docstring._

##### `async def resolve_delete(reader: StateReader, object_type: str, key: dict[str, Any], *, mgmt: str, domain: str, action_id: str) -> PlannedAction`

_No docstring._

##### `async def resolve_show(reader: StateReader, object_type: str, key: dict[str, Any], *, mgmt: str, domain: str, action_id: str) -> PlannedAction`

_No docstring._

##### `async def resolve_ip_reference(reader: StateReader, text: str, *, mgmt: str, domain: str, action_id: str, prefixes: NamingPrefixes | None = None) -> tuple[str, PlannedAction | None]`

Resolve a bare IP/CIDR/range string in a rule's source/destination to a reference or a synthesized CREATE.

Returns the object's NAME, not its uid, for an existing match -- confirmed against the live
lab (Task 14) that `find_rules_by_traffic`'s traffic-tuple comparison works against the live
rulebase's *dereferenced* (uid->name) fields (see statereader.py's `_dereference_rule`), so
this side of the comparison must speak names too, matching the "Any"/auto-created-dependency
cases below (which were already name-based) instead of mixing uid and name representations.
CP's add/set-*-rule commands accept either form for these fields, so this is payload-safe.

##### `async def resolve_service_reference(reader: StateReader, text: str, *, mgmt: str, domain: str, action_id: str, prefixes: NamingPrefixes | None = None) -> tuple[str, PlannedAction | None]`

Find-or-create resolve one rule-service entry, using Plan B's resolve_service.

Returns the service's NAME (not uid) for an existing match -- see `resolve_ip_reference`'s
docstring for why: the live rulebase comparison speaks names (Task 14's dereferencing fix),
so this side must too.

##### `async def resolve_rule(reader: StateReader, rule_type: str, op: dict[str, Any], *, mgmt: str, domain: str, action_id: str, counter: int, prefixes: NamingPrefixes | None = None) -> tuple[PlannedAction, list[PlannedAction], int]`

Create-or-reuse decision for one access/threat-prevention/https rule.

Unlike plain objects (identity = name), a rule's identity is its traffic tuple
(source, destination, service) -- see rule_identity.py. Renaming a rule in the template
is therefore never a CREATE: if the traffic tuple already matches an existing rule, that
rule is the target of an UPDATE (or UNCHANGED), regardless of name differences.

##### `async def resolve_nat_rule(reader: StateReader, op: dict[str, Any], *, mgmt: str, domain: str, action_id: str, counter: int, prefixes: NamingPrefixes | None = None) -> tuple[PlannedAction, list[PlannedAction], int]`

Create-or-reuse decision for one nat-rule.

NAT has no layer concept -- identity is package-scoped (see `StateReader.find_nat_rules_by_tuple`)
and the tuple itself is positional, not order-independent like access/threat-prevention/https
rules' traffic tuple (see rule_identity.nat_tuple): original and translated sides are never
interchangeable, and each side is a single value, not a set.

##### `async def resolve_rule_by_key(reader: StateReader, rule_type: str, operation: str, op: dict[str, Any], *, mgmt: str, domain: str, action_id: str, counter: int, prefixes: NamingPrefixes | None = None) -> tuple[PlannedAction, list[PlannedAction], int]`

Key-based update/delete/show for one access/threat-prevention/https rule.

Unlike `resolve_rule` (used for `add`), a rule addressed by `key: {name|uid|rule-number}`
is already unambiguously identified by the user -- no traffic-tuple discovery needed, and
(per the CP CRUD convention already established for objects) no create-on-miss either:
the user named a specific existing rule, not a desired traffic pattern to find-or-create.

##### `async def resolve_nat_rule_by_key(reader: StateReader, operation: str, op: dict[str, Any], *, mgmt: str, domain: str, action_id: str, counter: int, prefixes: NamingPrefixes | None = None) -> tuple[PlannedAction, list[PlannedAction], int]`

Key-based update/delete/show for one nat-rule (package-scoped, no layer concept).

Mirrors `resolve_rule_by_key`'s reasoning exactly, substituting NAT's `package` scoping
for access/threat/https's `layer` scoping (the same distinction `resolve_nat_rule` draws
from `resolve_rule` for `add`).

#### class `StateReader(Protocol)`

```python
@runtime_checkable
```
_No docstring._

##### Methods

###### `async def get_by_name(self, type: str, name: str, *, mgmt: str, domain: str) -> ObjectState | None`

_No docstring._

###### `async def find_by_ip(self, *, type: str, ip_value: dict[str, Any], mgmt: str, domain: str) -> list[ObjectState]`

_No docstring._

###### `async def where_used(self, uid: str, *, mgmt: str, domain: str) -> int`

_No docstring._

###### `async def get_last_publish_session(self, *, mgmt: str, domain: str) -> str`

_No docstring._

###### `async def get_service(self, spec: ServiceSpec, original_text: str, *, mgmt: str, domain: str) -> ObjectState | None`

_No docstring._

###### `async def get_layer(self, layer_ref: str, layer_type: str, *, mgmt: str, domain: str) -> LayerInfo | None`

_No docstring._

###### `async def get_section(self, section_ref: str, layer_uid: str, layer_type: str, *, mgmt: str, domain: str) -> SectionInfo | None`

_No docstring._

###### `async def get_last_rule(self, scope_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def find_rules_by_traffic(self, scope_uid: str, layer_type: str, source_uids: list[str], dest_uids: list[str], service_uids: list[str], *, mgmt: str, domain: str) -> list[RuleMatch]`

_No docstring._

###### `async def find_nat_rules_by_tuple(self, package: str, tup: tuple[str, str, str, str, str, str], *, mgmt: str, domain: str) -> list[RuleMatch]`

_No docstring._

###### `async def get_last_nat_rule(self, package: str, *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def get_rule_by_key(self, scope_uid: str, layer_type: str, key: dict[str, Any], *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def get_nat_rule_by_key(self, package: str, key: dict[str, Any], *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

### `arodonata/cpcrud/rule_identity.py`

Traffic-based rule identity: a rule's identity is its traffic, never its name.

#### Module-Level Functions

##### `def traffic_tuple(source_uids: list[str], dest_uids: list[str], service_uids: list[str]) -> tuple[frozenset[str], frozenset[str], frozenset[str]]`

Order-independent identity for access/threat-prevention/https rules.

##### `def nat_tuple(orig_src: str, orig_dst: str, orig_svc: str, xlate_src: str, xlate_dst: str, xlate_svc: str) -> tuple[str, str, str, str, str, str]`

Positional (NOT set-like) 6-tuple identity for nat-rule.

Unlike traffic_tuple, position matters: original and translated sides are
never interchangeable, so this is a plain tuple, not built from frozensets.

##### `def pick_tie_break(candidates: list[RuleMatch], declared_name: str | None) -> RuleMatch`

When multiple rules share a traffic tuple: prefer the declared name, else topmost.

### `arodonata/cpcrud/schema.py`

Template loading and JSON-schema validation for CPCRUD.

#### Module-Level Functions

##### `def load_template(source: str | Path | dict[str, Any]) -> dict[str, Any]`

Load a template from a dict, a file path, or a YAML/JSON string.

##### `def normalize_operations(doc: dict[str, Any]) -> dict[str, Any]`

Set operation='add' where missing. Returns a normalized copy.

##### `def validate_template(doc: dict[str, Any]) -> list[str]`

Validate a template against the schema. Returns a list of error strings (empty = valid).

### `arodonata/cpcrud/service.py`

CPCRUDService: public validate/plan/apply orchestration (shape v2; SSE streaming).

#### class `CPCRUDService`

_No docstring._

##### Methods

###### `def __init__(self, client: ArodonataClient) -> None`

_No docstring._

###### `def validate(self, template: str | Path | dict[str, Any]) -> list[str]`

```python
@traced
```
_No docstring._

###### `def inverse(self, plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]`

```python
@traced
```
Compensating template for a plan (optionally filtered by what actually executed).

###### `async def plan(self, template: str | Path | dict[str, Any], on_name_conflict: NameConflictPolicy | None = None, on_ip_conflict: IpConflictPolicy | None = None) -> Plan`

```python
@traced
```
_No docstring._

###### `async def apply(self, plan_or_template: Plan | str | Path | dict[str, Any], *, force: bool = False, dry_run: bool = False, no_publish: bool = False, discard: bool = False, session_name: str | None = None, session_description: str | None = None, on_name_conflict: NameConflictPolicy | None = None, on_ip_conflict: IpConflictPolicy | None = None, retry_remaining: int = 0, refresh: str | None = None) -> AsyncIterator[SSEEvent | ApplyReport]`

```python
@traced
```
_No docstring._

### `arodonata/cpcrud/services.py`

Service string spec parsing and deterministic naming (FPCR ServiceMatcher grammar).

#### Module-Level Functions

##### `def parse_service_spec(text: str) -> ServiceSpec`

Parse a rule-service string per FPCR ServiceMatcher grammar.

Order matters: any -> tcp/udp explicit protocol -> bare port (defaults tcp)
-> icmp -> named (fallback, resolved by exact-name lookup only, never auto-created).

##### `def auto_service_name(spec: ServiceSpec, prefixes: NamingPrefixes | None = None) -> str`

Deterministic name for an auto-created service (never used for kind='named').

##### `async def resolve_service(reader: _ServiceStateReader, text: str, *, mgmt: str, domain: str, prefixes: NamingPrefixes | None = None) -> ServiceResolution`

Find-or-create decision for one rule-service entry (FPCR ServiceMatcher + ServiceValidator).

Format check (pure, from parse_service_spec) happens before any API call. Named services
(kind='named') are never auto-created -- an unresolved name is a plan-time error directing
the user to SmartConsole.

#### class `ServiceSpec(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
kind: Literal['any', 'named', 'tcp', 'udp', 'icmp']
name: str | None = None
port: str | None = None
icmp_type: int | None = None
icmp_code: int | None = None
```
#### class `ServiceResolution(BaseModel)`

_No docstring._

##### Fields / Class Variables

```python
outcome: Literal['any', 'match', 'create', 'error']
uid: str | None = None
name: str = ''
type: str = ''
command: str | None = None
payload: dict[str, Any] = Field(default_factory=dict)
message: str = ''
```
### `arodonata/cpcrud/statereader.py`

StateReader port and the live (API-backed) implementation.

#### class `LiveStateReader`

Reads actual object state from the live Check Point API (auto-session reads).

##### Methods

###### `def __init__(self, client: ArodonataClient) -> None`

_No docstring._

###### `async def get_by_name(self, type: str, name: str, *, mgmt: str, domain: str) -> ObjectState | None`

_No docstring._

###### `async def find_by_ip(self, *, type: str, ip_value: dict[str, Any], mgmt: str, domain: str) -> list[ObjectState]`

_No docstring._

###### `async def where_used(self, uid: str, *, mgmt: str, domain: str) -> int`

_No docstring._

###### `async def get_last_publish_session(self, *, mgmt: str, domain: str) -> str`

_No docstring._

###### `async def get_service(self, spec: Any, original_text: str, *, mgmt: str, domain: str) -> ObjectState | None`

_No docstring._

###### `async def get_layer(self, layer_ref: str, layer_type: str, *, mgmt: str, domain: str) -> LayerInfo | None`

_No docstring._

###### `async def get_section(self, section_ref: str, layer_uid: str, layer_type: str, *, mgmt: str, domain: str) -> SectionInfo | None`

_No docstring._

###### `async def get_last_rule(self, scope_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def find_rules_by_traffic(self, scope_uid: str, layer_type: str, source_uids: list[str], dest_uids: list[str], service_uids: list[str], *, mgmt: str, domain: str) -> list[RuleMatch]`

_No docstring._

###### `async def find_nat_rules_by_tuple(self, package: str, tup: tuple[str, str, str, str, str, str], *, mgmt: str, domain: str) -> list[RuleMatch]`

_No docstring._

###### `async def get_last_nat_rule(self, package: str, *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def get_rule_by_key(self, scope_uid: str, layer_type: str, key: dict[str, Any], *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def get_nat_rule_by_key(self, package: str, key: dict[str, Any], *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

#### class `HybridStateReader`

Cache-first StateReader: object cache lookups with immediate live-API fallback.

where-used has no cache backing yet -> always live (spec decision).

##### Methods

###### `def __init__(self, client: ArodonataClient) -> None`

_No docstring._

###### `async def get_by_name(self, type: str, name: str, *, mgmt: str, domain: str) -> ObjectState | None`

_No docstring._

###### `async def find_by_ip(self, *, type: str, ip_value: dict[str, Any], mgmt: str, domain: str) -> list[ObjectState]`

_No docstring._

###### `async def where_used(self, uid: str, *, mgmt: str, domain: str) -> int`

_No docstring._

###### `async def get_last_publish_session(self, *, mgmt: str, domain: str) -> str`

_No docstring._

###### `async def get_service(self, spec: Any, original_text: str, *, mgmt: str, domain: str) -> ObjectState | None`

_No docstring._

###### `async def get_layer(self, layer_ref: str, layer_type: str, *, mgmt: str, domain: str) -> LayerInfo | None`

_No docstring._

###### `async def get_section(self, section_ref: str, layer_uid: str, layer_type: str, *, mgmt: str, domain: str) -> SectionInfo | None`

_No docstring._

###### `async def get_last_rule(self, scope_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def find_rules_by_traffic(self, scope_uid: str, layer_type: str, source_uids: list[str], dest_uids: list[str], service_uids: list[str], *, mgmt: str, domain: str) -> list[RuleMatch]`

_No docstring._

###### `async def find_nat_rules_by_tuple(self, package: str, tup: tuple[str, str, str, str, str, str], *, mgmt: str, domain: str) -> list[RuleMatch]`

_No docstring._

###### `async def get_last_nat_rule(self, package: str, *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def get_rule_by_key(self, scope_uid: str, layer_type: str, key: dict[str, Any], *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._

###### `async def get_nat_rule_by_key(self, package: str, key: dict[str, Any], *, mgmt: str, domain: str) -> RuleMatch | None`

_No docstring._


---

## extractors — Bulk Data Extraction

### `arodonata/extractors/__init__.py`

Object extractors for transforming API responses.

_No public classes or functions in this module._

### `arodonata/extractors/base.py`

Base extractor classes and types.

#### class `ExtractionContext`

```python
@dataclass
```
Context information for object extraction.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
objects_map: dict[str, str] | None = None
```
#### class `BaseExtractor`

Base class for all extractors.

### `arodonata/extractors/objects.py`

Object extractor for network objects.

#### class `ObjectExtractor(BaseExtractor)`

Extractor for network objects (hosts, networks, groups, etc.).

##### Fields / Class Variables

```python
_TYPE_EXTRACTORS: dict[str, Any] = {'host': _extract_host_fields, 'network': _extract_network_fields, 'group': _extract_group_fields, 'service-group': _extract_group_fields, 'address-range': _extract_address_range_fields}
```
##### Methods

###### `def extract(self, raw_data: dict[str, Any], context: ExtractionContext) -> dict[str, Any]`

Extract model fields from raw API response.

Args:
    raw_data: Raw API response data.
    context: Extraction context with mgmt/domain info.

Returns:
    Dictionary with extracted fields suitable for CPObject model.

### `arodonata/extractors/rulebases.py`

Rulebase extractors for access, NAT, HTTPS, and threat rules.

#### class `AccessRuleExtractor(BaseExtractor)`

Extractor for access control rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from access rule API response.

Args:
    raw_data: Raw API response data.
    context: Extraction context with mgmt/domain info.

Returns:
    Dictionary with extracted fields suitable for AccessRule model.

#### class `NATRuleExtractor(BaseExtractor)`

Extractor for NAT rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from NAT rule API response.

Args:
    raw_data: Raw API response data.
    context: Extraction context with mgmt/domain info.

Returns:
    Dictionary with extracted fields suitable for NATRule model.

#### class `HTTPSRuleExtractor(BaseExtractor)`

Extractor for HTTPS inspection rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from HTTPS rule API response.

Args:
    raw_data: Raw API response data.
    context: Extraction context with mgmt/domain info.

Returns:
    Dictionary with extracted fields suitable for HTTPSRule model.

#### class `ThreatRuleExtractor(BaseExtractor)`

Extractor for threat prevention rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from threat rule API response.

Args:
    raw_data: Raw API response data.
    context: Extraction context with mgmt/domain info.

Returns:
    Dictionary with extracted fields suitable for ThreatRule model.


---

## helpers — Convenience Helper Functions

### `arodonata/helpers/__init__.py`

arodonata.helpers - Domain-organized helper functions for plugins.

This module provides cache-first, user-aware helper functions organized
by Check Point domains: assets, objects, and policy.

Example usage:
    from arodonata import ArodonataClient
    from arodonata.helpers import find_object, get_gateways
    from arodonata.helpers._context import UserContext

    context = UserContext.from_cli()
    client = await ArodonataClient.create(settings)

    host = await find_object(client, "web-server", user_context=context)
    gateways = await get_gateways(client, user_context=context)

_No public classes or functions in this module._

### `arodonata/helpers/_context.py`

User context models for session tracking.

#### class `UserContext`

```python
@dataclass
```
User information for session tracking.

Authentication is handled separately by ArodonataClient.
This is only for tracking who made what changes.

##### Fields / Class Variables

```python
username: str
source: str
```
##### Methods

###### `def from_fastapi_user(cls, user: dict) -> UserContext`

```python
@classmethod
```
Create from FastAPI request state (WebUI/API).

Args:
    user: User dict from JWT token claims.

Returns:
    UserContext instance.

###### `def from_cli(cls) -> UserContext`

```python
@classmethod
```
Create from CLI environment.

Returns:
    UserContext with OS username.

### `arodonata/helpers/assets.py`

Helper functions for asset (gateway/server) operations.

Provides cache-first asset queries with SMART/CACHE/FORCE modes.

#### Module-Level Functions

##### `async def get_gateways(client: ArodonataClient, mgmt_names: list[str] | None = None, cache_mode: Literal['smart', 'cache', 'force'] = 'smart', user_context: UserContext | None = None) -> list[Gateway]`

Get gateways and servers.

Args:
    client: ArodonataClient instance.
    mgmt_names: Optional list of management servers to filter.
    cache_mode: Cache mode - "smart" (default), "cache", or "force".
    user_context: Optional user context for logging.

Returns:
    List of Gateway Pydantic models.

##### `async def refresh_assets(client: ArodonataClient, mgmt_names: list[str], cache_mode: Literal['smart', 'force'] = 'force', user_context: UserContext | None = None) -> dict[str, Any]`

Refresh asset cache.

Args:
    client: ArodonataClient instance.
    mgmt_names: Management servers to refresh.
    cache_mode: "force" (default) = refresh, "smart" = check freshness first.
    user_context: Optional user context for logging.

Returns:
    RefreshResult with statistics.

### `arodonata/helpers/objects.py`

Helper functions for network object operations.

Provides cache-first queries with SMART/CACHE/FORCE modes.
Wraps ObjectService and CacheOrchestrationService.

#### Module-Level Functions

##### `async def find_object(client: ArodonataClient, search: str, object_type: str | None = None, cache_mode: Literal['smart', 'cache', 'force'] = 'smart', user_context: UserContext | None = None) -> CPObject | None`

Find object by name, IP address, or UID.

Args:
    client: ArodonataClient instance.
    search: Object name, IP address, or UID to search for.
    object_type: Optional filter by object type.
    cache_mode: Cache mode - "smart" (default), "cache", or "force".
    user_context: Optional user context for logging.

Returns:
    CPObject if found, None otherwise.

##### `async def get_objects(client: ArodonataClient, object_type: str, filters: dict[str, Any] | None = None, mgmt_name: str | None = None, domain_name: str | None = None, cache_mode: Literal['smart', 'cache', 'force'] = 'smart', user_context: UserContext | None = None) -> list[CPObject]`

Get objects by type with optional filters.

Args:
    client: ArodonataClient instance.
    object_type: Object type (host, network, group, etc.).
    filters: Optional field filters.
    mgmt_name: Optional management server filter.
    domain_name: Optional domain filter.
    cache_mode: Cache mode - "smart" (default), "cache", or "force".
    user_context: Optional user context for logging.

Returns:
    List of CPObject instances.

##### `async def get_group_members(client: ArodonataClient, group_uid: str, mgmt_name: str, domain_name: str, cache_mode: Literal['smart', 'cache', 'force'] = 'smart', user_context: UserContext | None = None) -> AsyncIterator[dict[str, Any]]`

Get group membership tree as async iterator.

Args:
    client: ArodonataClient instance.
    group_uid: Group UID to resolve.
    mgmt_name: Management server name.
    domain_name: Domain name.
    cache_mode: Cache mode - "smart" (default), "cache", or "force".
    user_context: Optional user context for logging.

Yields:
    Group membership nodes as dicts.

### `arodonata/helpers/policy.py`

Helper functions for policy and session management operations.

Provides session management, write operations, and rule queries.

#### Module-Level Functions

##### `async def create_session(client: ArodonataClient, mgmt_name: str, domain_name: str, user_context: UserContext, description: str | None = None) -> str`

Create a write session for policy changes.

Args:
    client: ArodonataClient instance.
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).
    user_context: User context for session tracking.
    description: Optional session description.

Returns:
    Session ID string.

##### `async def publish_session(client: ArodonataClient, mgmt_name: str, domain_name: str, session_id: str, user_context: UserContext) -> dict[str, Any]`

Publish session changes.

Args:
    client: ArodonataClient instance.
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).
    session_id: Session ID from create_session().
    user_context: User context for session tracking.

Returns:
    API call result as dictionary.

##### `async def discard_session(client: ArodonataClient, mgmt_name: str, domain_name: str, session_id: str, user_context: UserContext) -> None`

Discard session changes.

Args:
    client: ArodonataClient instance.
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).
    session_id: Session ID from create_session().
    user_context: User context for session tracking.

##### `async def write_session(client: ArodonataClient, mgmt_name: str, domain_name: str, user_context: UserContext, description: str | None = None, auto_publish: bool = True) -> AsyncIterator[str]`

```python
@asynccontextmanager
```
Context manager for write sessions.

Automatically handles publish/discard based on success/exception.

Args:
    client: ArodonataClient instance.
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).
    user_context: User context for session tracking.
    description: Optional session description.
    auto_publish: If True (default), publish on successful completion.
                  If False, discard on exit (useful for testing).

Yields:
    Session ID string.

Example:
    async with write_session(client, "mgmt1", "domain1", context, "Add host") as session_id:
        await add_object(client, mgmt_name="mgmt1", domain_name="domain1", session_id=session_id, ...)

##### `async def add_object(client: ArodonataClient, mgmt_name: str, domain_name: str, object_type: str, data: dict[str, Any], session_id: str, user_context: UserContext) -> CPObject`

Add object to session.

Args:
    client: ArodonataClient instance.
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).
    object_type: Object type (host, network, group, etc.).
    data: Object properties (must include 'name' field).
    session_id: Session ID from create_session().
    user_context: User context for session tracking.

Returns:
    CPObject instance for the created object.

##### `async def set_object(client: ArodonataClient, mgmt_name: str, domain_name: str, uid: str, data: dict[str, Any], session_id: str, user_context: UserContext) -> CPObject`

Update object in session.

Args:
    client: ArodonataClient instance.
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).
    uid: Object UID to update.
    data: Object properties to update.
    session_id: Session ID from create_session().
    user_context: User context for session tracking.

Returns:
    CPObject instance for the updated object.

##### `async def delete_object(client: ArodonataClient, mgmt_name: str, domain_name: str, uid: str, session_id: str, user_context: UserContext) -> None`

Delete object in session.

Args:
    client: ArodonataClient instance.
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).
    uid: Object UID to delete.
    session_id: Session ID from create_session().
    user_context: User context for session tracking.

##### `async def get_access_rules(client: ArodonataClient, layer_name: str | None = None, mgmt_name: str | None = None, domain_name: str | None = None, cache_mode: Literal['smart', 'smart-fast', 'cache', 'force'] | None = None, cache_ttl: int | None = None, user_context: UserContext | None = None) -> list[AccessRule]`

Get access rules.

Args:
    client: ArodonataClient instance.
    layer_name: Optional layer name filter.
    mgmt_name: Optional management server filter.
    domain_name: Optional domain filter.
    cache_mode: Optional per-call cache refresh mode override
        ("cache" = never call the API).
    cache_ttl: Optional per-call cache freshness TTL override.
    user_context: Optional user context for logging.

Returns:
    List of access rules.

##### `async def get_nat_rules(client: ArodonataClient, layer_name: str | None = None, mgmt_name: str | None = None, domain_name: str | None = None, cache_mode: Literal['smart', 'smart-fast', 'cache', 'force'] | None = None, cache_ttl: int | None = None, user_context: UserContext | None = None) -> list[NATRule]`

Get NAT rules.

Args:
    client: ArodonataClient instance.
    layer_name: Optional layer name filter.
    mgmt_name: Optional management server filter.
    domain_name: Optional domain filter.
    cache_mode: Optional per-call cache refresh mode override
        ("cache" = never call the API).
    cache_ttl: Optional per-call cache freshness TTL override.
    user_context: Optional user context for logging.

Returns:
    List of NAT rules.

##### `async def get_https_rules(client: ArodonataClient, layer_name: str | None = None, mgmt_name: str | None = None, domain_name: str | None = None, cache_mode: Literal['smart', 'smart-fast', 'cache', 'force'] | None = None, cache_ttl: int | None = None, user_context: UserContext | None = None) -> list[HTTPSRule]`

Get HTTPS rules.

Args:
    client: ArodonataClient instance.
    layer_name: Optional layer name filter.
    mgmt_name: Optional management server filter.
    domain_name: Optional domain filter.
    cache_mode: Optional per-call cache refresh mode override
        ("cache" = never call the API).
    cache_ttl: Optional per-call cache freshness TTL override.
    user_context: Optional user context for logging.

Returns:
    List of HTTPS rules.

##### `async def get_threat_rules(client: ArodonataClient, layer_name: str | None = None, mgmt_name: str | None = None, domain_name: str | None = None, cache_mode: Literal['smart', 'smart-fast', 'cache', 'force'] | None = None, cache_ttl: int | None = None, user_context: UserContext | None = None) -> list[ThreatRule]`

Get threat rules.

Args:
    client: ArodonataClient instance.
    layer_name: Optional layer name filter.
    mgmt_name: Optional management server filter.
    domain_name: Optional domain filter.
    cache_mode: Optional per-call cache refresh mode override
        ("cache" = never call the API).
    cache_ttl: Optional per-call cache freshness TTL override.
    user_context: Optional user context for logging.

Returns:
    List of threat rules.


---

## models — Data Models

### `arodonata/models/__init__.py`

Pydantic models for arodonata v2.

_No public classes or functions in this module._

### `arodonata/models/common.py`

Common base models for arodonata.

#### class `BaseModelWithRaw(BaseModel)`

Base model with raw_data field.

##### Fields / Class Variables

```python
raw_data: dict[str, Any] = Field(default_factory=dict)
```
### `arodonata/models/domains.py`

Domain and Gateway models for arodonata.

#### class `Domain(BaseModelWithRaw)`

Cached domain information.

##### Fields / Class Variables

```python
uid: str
name: str
active_mds: str
active_ip: str
active_server: str
standby_ips: list[str] = []
standby_servers: list[str] = []
mgmt_name: str
is_mdm: bool = False
```
#### class `Gateway(BaseModelWithRaw)`

Cached gateway/server asset.

##### Fields / Class Variables

```python
uid: str
name: str
type: str
ip_address: str
ssh_ip: str = ''
domain_name: str = ''
mgmt_name: str
parent_uid: str | None = None
```
#### class `Host(BaseModelWithRaw)`

Cached host object.

##### Fields / Class Variables

```python
uid: str
name: str
ip_address: str = ''
mgmt_name: str
domain_name: str = ''
```
#### class `Network(BaseModelWithRaw)`

Cached network object.

##### Fields / Class Variables

```python
uid: str
name: str
subnet4: str = ''
subnet_mask: str = ''
mgmt_name: str
domain_name: str = ''
```
#### class `Group(BaseModelWithRaw)`

Cached group object.

##### Fields / Class Variables

```python
uid: str
name: str
member_uids: list[str] = []
mgmt_name: str
domain_name: str = ''
```
### `arodonata/models/rulebases.py`

Rulebase models for arodonata v2.

#### class `AccessRule(BaseModelWithRaw)`

Access control rule from Network layer.

##### Fields / Class Variables

```python
uid: str
rule_number: int
name: str
enabled: bool
sources: list[str]
destinations: list[str]
services: list[str]
action: str
track: str
layer_name: str
mgmt_name: str
domain_name: str = ''
```
##### Methods

###### `def uid_must_not_be_empty(cls, v: str) -> str`

```python
@field_validator('uid')
@classmethod
```
Validate that uid is not empty.

#### class `NATRule(BaseModelWithRaw)`

NAT rule from NAT layer.

##### Fields / Class Variables

```python
uid: str
rule_number: int
name: str
enabled: bool
original_source: str
original_destination: str
original_service: str
translated_source: str
translated_destination: str
translated_service: str
layer_name: str
mgmt_name: str
domain_name: str = ''
```
#### class `HTTPSRule(BaseModelWithRaw)`

HTTPS inspection rule from CVD layer.

##### Fields / Class Variables

```python
uid: str
rule_number: int
name: str
enabled: bool
sources: list[str]
destinations: list[str]
track: str
layer_name: str
mgmt_name: str
domain_name: str = ''
```
#### class `ThreatRule(BaseModelWithRaw)`

Threat prevention rule from Threat layer.

##### Fields / Class Variables

```python
uid: str
rule_number: int
name: str
enabled: bool
track: str
protections: list[str]
layer_name: str
mgmt_name: str
domain_name: str = ''
```

---

## ports — Abstract Interfaces (Hexagonal Architecture Ports)

### `arodonata/ports/__init__.py`

Protocol interfaces for Port/Adapter architecture.

_No public classes or functions in this module._

### `arodonata/ports/api_port.py`

ApiPort protocol interface for Check Point API operations.

#### class `ApiPort(Protocol)`

```python
@runtime_checkable
```
Port for Check Point API operations - structural interface.

##### Methods

###### `async def query(self, mgmt_name: str, command: str, domain: str = '', payload: dict[str, Any] | None = None, details_level: Literal['uid', 'standard', 'full'] = 'standard', container_key: str | None = None) -> 'ApiQueryResult'`

Execute paginated API query.

###### `async def show_changes(self, mgmt_name: str, domain: str = '', from_session: str | None = None, from_date: str | None = None, to_session: str | None = None, to_date: str | None = None) -> Any`

Get changes for smart refresh.

###### `async def publish(self, mgmt_name: str, domain: str = '') -> Any`

Publish the current session on the management server.

###### `def get_mgmt_names(self) -> list[str]`

Get list of configured management server names.

### `arodonata/ports/cache_port.py`

CachePort protocol interface for cache operations.

#### class `CachePort(Protocol)`

```python
@runtime_checkable
```
Port for cache operations - structural interface.

Any class with these methods satisfies this protocol - no inheritance needed.

##### Methods

###### `async def get_objects(self, object_type: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, filters: dict[str, Any] | None = None) -> list['CPObject']`

Query objects from cache with optional filters.

###### `async def get_object_by_uid(self, uid: str, mgmt_name: str, domain_name: str) -> 'CPObject | None'`

Get single object by UID.

###### `async def upsert_objects(self, objects: list['CPObject']) -> int`

Insert or update objects. Returns count of upserted objects.

###### `async def replace_domain_objects(self, mgmt_name: str, domain_name: str, objects: list['CPObject']) -> tuple[int, int]`

Atomically replace all objects for a domain in one transaction.

###### `async def delete_object(self, uid: str, mgmt_name: str, domain_name: str) -> int`

Delete a single object by UID. Returns count deleted (0 if absent).

###### `async def get_domains(self, mgmt_names: list[str] | None = None) -> list['Domain']`

Get cached domains.

###### `async def get_gateways(self, mgmt_names: list[str] | None = None) -> list[Any]`

Get cached gateways and servers.

###### `async def get_last_published_session(self, mgmt_name: str, domain_name: str) -> 'LastPublishedSession | None'`

Get last published session for smart refresh.

###### `async def get_rulebase(self, rulebase_type: str, layer_name: str | None = None, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, enabled_only: bool | None = None) -> list[Any]`

Get rulebase rules from cache.

Args:
    rulebase_type: Type of rulebase ("access", "nat", "https", "threat").
    layer_name: Optional layer name filter.
    mgmt_names: Optional list of management server names to filter.
    domain_names: Optional list of domain names to filter.
    enabled_only: If True, only return enabled rules.

Returns:
    List of rule objects (type depends on cache implementation).


---

## utils — Utility Functions

### `arodonata/utils/__init__.py`

Utility functions for Arodonata library.

_No public classes or functions in this module._

### `arodonata/utils/helpers.py`

Utility functions for Arodonata library.

#### Module-Level Functions

##### `def utc_now_naive() -> datetime`

Get current time as naive UTC datetime.

Returns:
    Current time with timezone info removed (database-compatible).

Example:
    >>> now = utc_now_naive()
    >>> now.tzinfo is None
    True

##### `def to_db_datetime(dt: datetime | None) -> datetime | None`

Convert datetime to naive UTC for database storage.

Args:
    dt: Datetime to convert (can be aware or naive).

Returns:
    Naive UTC datetime, or None if input is None.

Example:
    >>> from datetime import timezone, timedelta
    >>> dt = datetime(2025, 1, 1, tzinfo=timezone(timedelta(hours=2)))
    >>> result = to_db_datetime(dt)
    >>> result.tzinfo is None
    True

##### `def get_caller_name(levels: int = 2) -> str`

Get the name of the calling function/method.

Args:
    levels: Number of frames to go back in the call stack.
            Default 2 returns the caller of the function that called get_caller_name.

Returns:
    String in format "module.class.method" or "module.function"

##### `def normalize_input_to_list(value: str | list[str] | set[str] | None) -> list[str]`

Normalize various input types to a list of strings.

Args:
    value: Input that could be a string, list, set, or None.
           Strings are split by comma.

Returns:
    List of non-empty stripped strings.

##### `def make_composite_key(*parts: str) -> str`

Create a composite key from parts.

Args:
    *parts: String parts to join with colon separator.

Returns:
    Colon-separated composite key.

##### `def parse_composite_key(key: str) -> list[str]`

Parse a composite key into parts.

Args:
    key: Colon-separated composite key.

Returns:
    List of string parts.

##### `def safe_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any`

Safely navigate nested dict structure.

Args:
    data: Dictionary to navigate.
    *keys: Keys to traverse in order.
    default: Value to return if any key is missing.

Returns:
    Value at the nested key path, or default if not found.

##### `def extract_data_from_response(response: Any) -> Any`

Extract data from API response with robust handling of various response types.

This function handles:
- Pydantic v2 models (using model_dump())
- Objects with .data attribute (ApiCallResult, ApiQueryResult)
- Raw dictionaries
- None or missing responses

Args:
    response: API response object from arodonata (ApiCallResult, ApiQueryResult,
              or raw dict).

Returns:
    Extracted data, typically a dict for single objects or the raw data type.
    Returns None if response is falsy or has no data attribute.

Examples:
    >>> from arodonata.utils import extract_data_from_response
    >>> result = await client.api_call("mgmt1", "show-host", {"name": "my-host"})
    >>> data = extract_data_from_response(result)
    >>> print(data.get("ip-address"))

##### `def extract_objects_from_response(response: Any) -> list[dict[str, Any]]`

Extract objects from API response in a consistent format.

Handles various response structures from Check Point API:
- response.data.objects (list of objects)
- response.data.object (single object, returned as list)
- response.data (direct dict/list)
- Objects with model_dump() for Pydantic serialization

Args:
    response: API response object (ApiCallResult, ApiQueryResult, or raw dict).

Returns:
    List of object dictionaries. Empty list if:
    - Response is falsy or failed
    - No objects found
    - Response structure is unrecognized

Examples:
    >>> from arodonata.utils import extract_objects_from_response
    >>> result = await client.api_call("mgmt1", "show-hosts")
    >>> hosts = extract_objects_from_response(result)
    >>> for host in hosts:
    ...     print(host.get("name"), host.get("ip-address"))


---

## services — (reserved)

### `arodonata/services/__init__.py`

Business logic services layer.

This module contains high-level business logic services that orchestrate
operations across multiple lower-level components. Services provide
domain-specific functionality while abstracting away the complexity
of individual API calls and database operations.

Example services that may be added:
    - AssetCollectionService: Orchestrates asset discovery across domains
    - HealthCheckService: Monitors management server health
    - SynchronizationService: Keeps cache synchronized with servers

_No public classes or functions in this module._
