# Arodonata — Full API Reference

Complete, auto-generated reference of every public class, function, and method in the `arodonata` package, grouped by subpackage. Each entry shows the exact signature (as written in source) and its docstring. This is the third companion document alongside the Guide and the Examples — use it to look up exact function names, parameters, and return types.

## Package Map

- **Top-Level Package** — 4 module(s)
- **api — High-Level Client & Services** — 12 module(s)
- **adapters — External Integrations (API transport, cache backend)** — 5 module(s)
- **asdk — Low-Level Check Point Management API SDK** — 13 module(s)
- **cache — Database-Backed Caching Layer** — 9 module(s)
- **config — Settings & Constants** — 4 module(s)
- **core — Core Domain Logic, Protocols & Exceptions** — 12 module(s)
- **cpcrud — Declarative CRUD / Rule Engine** — 16 module(s)
- **mcp — Model Context Protocol (MCP) Server & Tools** — 19 module(s)
- **extractors — Bulk Data Extraction** — 4 module(s)
- **helpers — Convenience Helper Functions** — 5 module(s)
- **models — Data Models** — 4 module(s)
- **ports — Abstract Interfaces (Hexagonal Architecture Ports)** — 3 module(s)
- **utils — Utility Functions** — 3 module(s)
- **services — (reserved)** — 2 module(s)
- **reports** — 15 module(s)
- **rulebase** — 6 module(s)


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

###### `async def api_call_with_sid(self, mgmt_name: str, sid: str, server_ip: str, command: str, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1, *, domain: str | None = None) -> ApiCallResult`

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
    domain: The session's domain, if known: selects the RateLimiter slot of its hosting MDS member
        (LoginCoordinator.mds_host). Without it the member is looked up by server_ip
        (LoginCoordinator.mds_host_for_ip).

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
does not touch the object or asset caches. The stored record is the
object cache's freshness stamp, so this marks the domain's cache as
current without refreshing it; to only read the head, use
`fetch_last_published_session`.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    The upserted LastPublishedSession record, or None on failure.

###### `async def fetch_last_published_session(self, mgmt_name: str, domain_name: str) -> LastPublishedSession | None`

```python
@traced
```
Read the last-published session of a single domain WITHOUT storing it.

The read-only counterpart of `refresh_last_published_session`: the stored record is the object cache's
freshness stamp, so a caller that only wants to know the domain's head (cpcrud's plan and publish stamps)
must not store it, or the cache reads as fresh without having been refreshed.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    An unsaved LastPublishedSession, or None on failure.

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

###### `async def refresh_objects(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: Literal['skip', 'check', 'force', 'incremental'] = 'force', include_global: bool = False) -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Refresh object cache from API.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: Refresh mode - "skip", "check", "force", or "incremental".
    include_global: When False (default), the "Global" domain
        is excluded from the all-domains refresh path so existing
        callers see today's behavior.

Yields:
    SSEEvent with progress updates.

###### `def invalidate_domain(self, mgmt_name: str, domain_name: str) -> None`

Drop the object and the rulebase freshness memos of one domain, so the next smart read re-checks it.

Called after every publish the library sees (cpcrud, ``helpers.policy.publish_session``,
``CacheOrchestrationService.publish``, a successful ``api_call('publish')``). It only drops memos; the
published-session comparison decides whether anything is refreshed.

###### `async def refresh_rulebases(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: Literal['skip', 'check', 'force'] = 'force', include_global: bool = False) -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Refresh rulebase cache from API.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: Refresh mode - "skip", "check", or "force".
    include_global: When False (default), the "Global" domain is excluded, as in `refresh_objects`.

Yields:
    SSEEvent with progress updates.

###### `async def get_policy_packages(self, mgmt_name: str | None, domain_name: str, cache_mode: CacheMode | str | None = None, cache_ttl: int | None = None) -> list[PackageLayout]`

```python
@traced
```
Policy packages of a domain with their ordered layers per rulebase type (from the rulebase cache).

###### `async def get_package_rulebase(self, mgmt_name: str | None, domain_name: str | None, package: str, rulebase_type: RulebaseType = 'access', cache_mode: CacheMode | str | None = None, cache_ttl: int | None = None) -> PackageRulebase`

```python
@traced
```
A package's rulebase numbered exactly like SmartConsole (global layer, parent rule, ``2.x``, ``2.2.1``).

``domain_name`` None/'' resolves to the one cached domain holding the package (``SMC User`` on an SMS).
Numbers reflect the cached snapshot's session (``snapshot_session_uid``).

###### `async def get_layer_rulebase(self, mgmt_name: str | None, domain_name: str | None, layer: str, rulebase_type: RulebaseType = 'access', cache_mode: CacheMode | str | None = None, cache_ttl: int | None = None) -> LayerRulebase`

```python
@traced
```
One layer (uid, or unique name) numbered without package context: layer-relative numbers, sections,
place-holders, inline layers expanded. ``domain_name`` None/'' resolves like ``get_package_rulebase``.

###### `async def locate_rules(self, mgmt_name: str | None, domain_name: str, rule_uids: Collection[str] = (), rulebase_type: RulebaseType | None = None, *, layer_uids: Collection[str] = (), cache_mode: CacheMode | str | None = None, cache_ttl: int | None = None) -> RuleLocations`

```python
@traced
```
Every SmartConsole position of each rule uid, and every numbering prefix of each layer uid (``""`` for an
ordered layer, ``"2."``/``"2.2."`` for nested ones), across the domain's packages; ``[]`` for unknown uids.

The result carries the snapshot's session uid, publish time, refresh time and sync status, so a caller can
tell which published state the numbers describe (a deleted or unpublished rule is numbered as a layer's
prefix plus its show-changes position).

Raises:
    ValueError: No ``domain_name``.
    TypeError: ``rule_uids`` or ``layer_uids`` is a bare ``str`` (pass a list of uids).

###### `async def collect_change_report(self, scopes: Sequence[Scope], *, include_raw: bool = False, concurrency: int = 4, max_sessions: int | None = None) -> ChangeReport`

```python
@traced
```
Collect the changes of sessions (``SessionScope``) or published ranges (``RangeScope``) into a ChangeReport.

Reads ``show-changes`` through the shared session (read-only), member names through ``show-object``, and
numbers rules from the rulebase cache, or live through an ``owned_session``'s SID for unpublished sessions.
Partial failures are warnings in the report; invalid input raises ``ChangeReportInputError``. See the user
guide "Change Report".

###### `async def build_change_report(self, scopes: Sequence[Scope], formats: Collection[ReportFormat], options: RenderOptions | None = None, *, include_raw: bool = False, concurrency: int = 4, max_sessions: int | None = None) -> ChangeReportResult`

```python
@traced
```
``collect_change_report`` then ``render_change_report`` (HTML needs the ``report`` extra).

###### `async def get_domains(self, mgmt_names: list[str] | None = None, cache_mode: str | None = None, cache_ttl: int | None = None, include_global: bool = False) -> list[Domain]`

```python
@traced
```
Get domains from cache as Pydantic models.

Only the domain list itself is refreshed (one ``show-domains`` per management server), never the domains'
objects: ``cache`` reads the table as is; ``smart``/``smart-fast`` re-read the list when the table is empty
or the domain-list TTL has passed; ``force`` re-reads it now. Without ``mgmt_names`` every cached server is
read and the first configured server's list is refreshed. When a server's object cache is still empty and
``warm_object_cache_on_first_use`` is on (the default), its objects start loading in the background; the call
returns without waiting for them.

Args:
    mgmt_names: Optional list of management server names to filter.
    cache_mode: Optional per-call cache refresh mode override (for the domain list).
    cache_ttl: Accepted for signature compatibility; the domain list uses its own TTL.
    include_global: When False (default), the "Global" domain
        is excluded so existing callers see today's behavior.

Returns:
    List of Domain models.

Example:
    domains = await client.get_domains(mgmt_names=["mgmt1"])
    for domain in domains:
        print(f"{domain.name}: {domain.active_ip}")

###### `def object_cache_warm_up(self, mgmt_name: str) -> ObjectCacheWarmUp | None`

The background object-cache load of `mgmt_name` started by this client, or None if none was started.

`get_domains` starts one, once per server, when it finds that server's object cache empty (see
`warm_object_cache_on_first_use`). Counts are known once it has finished.

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
    layer_name: Optional policy package name filter; NAT rules are keyed by package, e.g. layer_name="Standard".
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

#### class `ObjectCacheWarmUp(BaseModel)`

Background load of a server's empty object cache, started by the first ``get_domains`` (once per client).

##### Fields / Class Variables

```python
state: Literal['running', 'finished', 'failed', 'cancelled'] = Field(description='Where the load is')
started_at: datetime = Field(description='When the load started (UTC)')
finished_at: datetime | None = Field(default=None, description='When it ended; None while running')
refreshed_domains: int = Field(default=0, description='Domains loaded (known once finished)')
failed_domains: int = Field(default=0, description='Domains that failed to load (known once finished)')
```
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
data: list[dict[str, Any]] | dict[str, Any] | None = Field(default=None, description="Response data from API: on success usually the list of objects (also in `objects`), but a dict for task queries such as show-changes (the items under their key, plus `total`) or a response without a listing; on failure the server's error dict, or None")
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
timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), description='Event timestamp')
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

###### `async def populate_domain_cache(self, mgmt_name: str, cache_mode: str = 'auto', include_global: bool = False) -> list[str]`

Query domains from management server and populate cache.

Args:
    mgmt_name: Management server name.
    cache_mode: Cache mode for the underlying API query.
    include_global: When False (default), the "Global" domain
        is written to the cache table (for MDMs) but excluded from the
        *returned* list, so unflagged callers (e.g. asset collection)
        are unaffected by its existence.

Returns:
    List of domain names (including system domain as empty string).

###### `async def get_domain_uid(self, mgmt_name: str, domain_name: str) -> str`

Get domain UID from cache.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name (empty string for system domain).

Returns:
    Domain UID or empty string if not found.

### `arodonata/api/services/live_rulebase_source.py`

Live rulebase reads inside an app-owned session (the change report's unpublished-session numbering, spec 5.3).

The SID is unwrapped only inside SidCaller, used only for SID_READ_COMMANDS (never publish, discard or logout: the
app owns the session), and scrubbed — the full value and any 8+ character prefix — from every message and exception
before anything leaves this module. Takes ``sid``/``server_ip``, never an OwnedSession, so api/services never imports
arodonata.reports.

#### class `SidCallError(RuntimeError)`

A call through an owned session raised; the message is scrubbed of the SID.

#### class `SidCaller`

RulebaseCaller bound to one app-owned SID (read-only).

The SID is domain-bound: ``domain`` only selects the RateLimiter slot (the hosting member).

##### Methods

###### `def __init__(self, client: ArodonataClient, mgmt_name: str, sid: SecretStr, server_ip: str) -> None`

_No docstring._

###### `def scrub(self, text: str) -> str`

Remove the SID and every prefix of it of 8 or more characters.

###### `async def api_call(self, *, mgmt_name: str, domain: str, command: str, payload: dict[str, Any]) -> ApiCallResult`

_No docstring._

###### `async def api_query(self, *, mgmt_name: str, domain: str, command: str, details_level: DetailsLevel, container_key: str) -> ApiQueryResult`

api_call_with_sid has no paging: pages with details-level/limit/offset until total; any failed page fails
the whole query.

#### class `LiveRulebaseSource`

RulebaseSource read once inside one app-owned session (status "live").

``snapshot_session_uid`` is the owned session's uid and ``snapshot_published_at`` is None (the session is not
published); ``snapshot_refreshed_at`` is the read time, naive UTC like the cache. ``warnings`` holds the read's
warnings (a failed place-holder link or layer page); any warning means the numbers may be wrong.

##### Methods

###### `def __init__(self, client: ArodonataClient, mgmt_name: str, domain_name: str, sid: SecretStr, server_ip: str, *, session_uid: str, packages: Collection[str] | None, clock: Callable[[], datetime] = _naive_utcnow) -> None`

_No docstring._

###### `async def packages(self, mgmt_name: str, domain_name: str) -> list[PackageLayout]`

_No docstring._

###### `async def package_rulebase(self, mgmt_name: str, domain_name: str, package: str, rulebase_type: RulebaseType) -> PackageRulebase`

_No docstring._

###### `async def layer_rulebase(self, mgmt_name: str, domain_name: str, layer: str, rulebase_type: RulebaseType) -> LayerRulebase`

_No docstring._

###### `async def locate_rules(self, mgmt_name: str, domain_name: str, rule_uids: Collection[str] = (), rulebase_type: RulebaseType | None = None, *, layer_uids: Collection[str] = ()) -> RuleLocations`

_No docstring._

### `arodonata/api/services/rulebase_reader.py`

Rulebase read pipeline shared by the cache refresh and the change report's live source (cache v2 2.8).

Per domain: show-packages and NAT per package, every layer of each type (package layers, listing, inline closure),
then the global place-holder links per package. ``caller`` is anything with the RulebaseCaller methods: the
ArodonataClient (cache refresh, shared session) or a SidCaller (live read inside an app-owned session).

#### Module-Level Functions

##### `async def read_domain(caller: RulebaseCaller, mgmt_name: str, domain: str, warnings: list[str], *, packages: Collection[str] | None = None) -> tuple[list[PackageLayout], dict[str, LayerSnapshot]]`

Read a domain's rulebases completely. With ``packages``, only those packages (and their NAT), no
``show-*-layers`` listings: targets are the selected packages' ordered layers, their inline closure and the
place-holder links (the change report's package-scoped live read, D25).

#### class `RulebaseCaller(Protocol)`

What read_domain calls. ArodonataClient satisfies it structurally (mypy-checked through its uses).

##### Methods

###### `async def api_call(self, *, mgmt_name: str, domain: str, command: str, payload: dict[str, Any]) -> Any`

_No docstring._

###### `async def api_query(self, *, mgmt_name: str, domain: str, command: str, details_level: DetailsLevel, container_key: str) -> Any`

_No docstring._

#### class `DomainReadFailed(Exception)`

A domain read step failed: nothing is replaced (cache) / the live numbers cannot be trusted.

### `arodonata/api/services/rulebase_refresh_service.py`

Rulebase refresh: per domain, every policy package, layer and NAT policy is read completely, with sections, place-holders and the global place-holder link, then the domain's snapshot and sync state are replaced in one transaction.

#### class `RulebaseRefreshService`

Refreshes the rulebase cache from the Check Point API, one domain snapshot at a time.

##### Methods

###### `def __init__(self, client: ArodonataClient, cache: CacheRepository, domain_list_refresh_ttl: int = DOMAIN_LIST_REFRESH_TTL_SECONDS, clock: Clock | None = None, object_service: ObjectService | None = None) -> None`

Initialize rulebase refresh service.

Args:
    client: ArodonataClient instance for API calls.
    cache: Cache repository instance.
    domain_list_refresh_ttl: Seconds between opportunistic ("check"-mode)
        re-fetches of a management server's domain list ahead of
        `refresh_all`. "force" mode ignores this and always re-fetches.
        See `arodonata.core.domain_list_refresh`.
    clock: Injectable time source for the TTL memo (tests only;
        defaults to the real wall clock).
    object_service: Reads the domain's published head (``read_last_published_session``). Optional so the
        exported class stays source-compatible; ``refresh_domain`` and ``is_rulebase_stale`` raise
        RuntimeError without it.

###### `async def refresh_domain(self, mgmt_name: str, domain: str, *, force: bool = False) -> AsyncGenerator[dict[str, Any]]`

Read one domain's rulebases completely and replace its snapshot atomically.

Steps: published head (before any rulebase read), dirty-session guard, show-packages and NAT per package,
every layer of each type (package layers, listing, inline closure), place-holder links per package and
global layer (skipped for the Global domain), then one replace with the sync state. Any failure keeps the
old snapshot and marks the sync state failed. ``force`` only changes head failure: the snapshot is then
stored unversioned instead of failing. ``asyncio.CancelledError`` is not caught.

Yields:
    Progress events; ``warning`` events; the last event has status ``domain_refreshed`` or
    ``domain_failed`` and carries the DomainRefreshResult under ``result``.

###### `async def is_rulebase_stale(self, mgmt_name: str, domain: str) -> bool`

Whether the domain's rulebase snapshot is older than its last published session (spec 2.9).

###### `async def refresh_all(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: Literal['skip', 'check', 'force'] = 'force', include_global: bool = False) -> AsyncGenerator[dict[str, Any]]`

Refresh all rulebases for specified managements and domains.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: "skip" does nothing; "check" refreshes only stale domains
        (see `is_rulebase_stale`); "force" refreshes every domain. The
        mode also decides whether the domain *list* is re-fetched before
        resolving `target_domains` below - see
        `_ensure_domain_list_fresh`.
    include_global: When False (default), the "Global" domain
        is excluded so existing callers see today's behavior.

Yields:
    Progress dictionaries.

###### `async def refresh_access_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``.

###### `async def refresh_nat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``.

###### `async def refresh_https_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``.

###### `async def refresh_threat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]`

Deprecated: refreshes the whole domain (every rulebase type), like ``refresh_domain(force=True)``.

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

###### `async def get_domains(self, mgmt_names: list[str] | None = None, include_global: bool = False) -> list['Domain']`

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

###### `async def get_rulebase_sync_state(self, mgmt_name: str, domain_name: str) -> 'RulebaseSyncState | None'`

The domain's rulebase sync state, or None before its first rulebase refresh.

###### `async def load_domain_rulebase_snapshot(self, mgmt_name: str, domain_name: str) -> 'DomainRulebaseSnapshot | None'`

The domain's cached rulebase snapshot, or None when it has no sync state.

###### `async def find_rulebase_layers(self, mgmt_name: str, layer: str, rulebase_type: str) -> list[tuple[str, str]]`

(domain_name, layer_uid) of cached layers of that type matching ``layer`` by uid or name.

###### `async def find_rulebase_packages(self, mgmt_name: str, package: str) -> list[tuple[str, str]]`

(domain_name, package_uid) of cached packages matching ``package`` by name or uid.


---

## asdk — Low-Level Check Point Management API SDK

### `arodonata/asdk/__init__.py`

Async SDK wrapper layer for Check Point Management API.

This module provides the async wrappers around the synchronous
cp-mgmt-api-sdk with proper session management, rate limiting,
and dependency injection support.

_No public classes or functions in this module._

### `arodonata/asdk/_sid.py`

SID log hygiene (Backlog #25, #2).

A log line may name its session by a SID prefix — the first 8 characters, ``SID=[3f9a1c2e...]`` — at DEBUG (or TRACE)
only; nothing about the SID at INFO and above, and the full SID never anywhere. A prefix cannot be replayed; a full
live SID is a bearer token. Session UIDs are not secrets and stay in logs and spans at every level.

#### Module-Level Functions

##### `def sid_prefix(sid: SecretStr | str | None) -> str`

``SID=[<first 8>...]`` for a DEBUG/TRACE log line; never use it at INFO and above.

##### `def redact_sid(text: str, sid: SecretStr | str | None) -> str`

Remove ``sid`` (the full value and every prefix of 8+ characters) and any SID inside a Check Point
"session id [...]" phrase from a text that is logged or handed back (a server message or exception text).

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

###### `async def api_call(self, mgmt_name: str, command: str, domain: str = '', details_level: Literal['uid', 'standard', 'full'] | None = None, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1, task_timeout: int = -1, cache_mode: str = 'auto', session_name: str | None = None, session_description: str | None = None) -> RawApiResponse`

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

###### `async def api_call_with_sid(self, mgmt_name: str, sid: str, server_ip: str, command: str, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1, task_timeout: int = -1, *, domain: str | None = None) -> RawApiResponse`

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
    domain: The session's domain, if known: selects the RateLimiter slot of its hosting MDS member
        (LoginCoordinator.mds_host). Without it the member is looked up by server_ip
        (LoginCoordinator.mds_host_for_ip).

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

Page a listing command to the end, one call per page (asdk/pager.py).

Each page runs through _execute_with_retry like any api_call: it takes its own RateLimiter slot
and releases it after the page, so other callers of the member get in between pages; a session
that expires mid-listing re-logs in and retries that page only. The caller's `limit` is the page
size (QUERY_PAGE_SIZE, 300, when absent or below 1, at most QUERY_MAX_PAGE_SIZE, 500) and `offset` the
starting point; the caller's payload is not modified. On success `data` is the list of objects, as with
cpapi's api_query.

show-access-rulebase, show-nat-rulebase, show-https-rulebase and show-threat-rulebase are paged by rules
instead, through rulebase/pager.py: pages of the caller's `limit` rules (RULEBASE_PAGE_SIZE, 100, when
absent or below 1, and at most that), `offset` the starting rule; a section split by a page boundary is
merged into one entry with all its rules, and on success `data` is the list of top-level rulebase entries
(sections, rules, place-holders).

A listing that keeps changing under the cursor is restarted once from `offset`, then fails with code
`paging_inconsistent` instead of returning duplicates or gaps.

### `arodonata/asdk/domain_servers.py`

Read a domain's server layout out of `show-domains`, and member IPs out of `show-mdss`.

One place for parsing that LoginCoordinator and DomainService used to duplicate,
extended to read which Multi-Domain Server member hosts each domain server. That
member is the machine Check Point rate-limits logins on (asdk/login_gate.py), and
domains move between members on failover, so callers re-read this whenever a
domain's active server is re-resolved. Pure functions; no I/O.

#### Module-Level Functions

##### `def extract_domain_servers(domain_obj: dict[str, Any]) -> DomainServers`

Split a domain's `servers` list into the active server and the standbys.

The active server is the first entry with `active: true` and a non-empty
`ipv4-address` -- the rule the two former `_extract_active_server_ip`
methods applied. Every other entry with an address is a standby. Entries
that are not dicts, or have no address, are ignored.

##### `def extract_global_domain_mdss(global_domain_obj: dict[str, Any]) -> GlobalDomainMdss`

Read the Global domain's UID and its active and standby MDS members.

Deliberately not `extract_domain_servers`: that one skips every entry
without an `ipv4-address`, which for Global is every entry, so it would
report an empty layout and the caller would silently keep using whichever
MDS it happened to be configured with. On a standby MDS that is a
read-only replica, and every write to Global fails - as a login error
rather than a permission one.

##### `def mds_ip_map(mds_objects: list[Any]) -> dict[str, str]`

{member name: ipv4-address} from `show-mdss` objects; entries missing either are skipped.

#### class `DomainServers`

```python
@dataclass(frozen=True)
```
A domain's servers as `show-domains` (details-level full) reports them.

##### Fields / Class Variables

```python
active_ip: str = ''
active_server: str = ''
active_mds: str = ''
standby_ips: tuple[str, ...] = ()
standby_servers: tuple[str, ...] = ()
standby_mdss: tuple[str, ...] = ()
```
#### class `GlobalDomainMdss`

```python
@dataclass(frozen=True)
```
Which MDS member serves the writable copy of the implicit Global domain.

Global has no domain server of its own, so `show-global-domain` reports its
members by MDS name with no address at all (verified on mdsNP2, R82,
2026-09-22):

    {"name": "", "ipv4-address": "", "multi-domain-server": "mdsNP2", "active": false}
    {                               "multi-domain-server": "mdsNP1", "active": true }

Resolve the name to an address with `mds_ip_map`. `active_mds` is empty when
no member is flagged active; a caller must then fall back deliberately
rather than be handed an arbitrary member.

`uid` is the Global domain's own UID, from the same object (`show-domains`
never lists Global, so this is the only place it comes from); empty when the
call failed.

##### Fields / Class Variables

```python
active_mds: str = ''
standby_mdss: tuple[str, ...] = ()
uid: str = ''
```
### `arodonata/asdk/login_coordinator.py`

Login coordinator for session management with domain resolution.

Handles login orchestration with proper locking, retry logic,
and session caching.

#### class `LoginCoordinator`

Handles login operations with domain active server resolution.

Manages distributed locks per (mgmt_name, domain) to prevent concurrent
login attempts across multiple workers and implements proper retry logic with backoff.
Logins to one management server are paced together through a `LoginGate`
(asdk/login_gate.py), keyed on the MDS member hosting the domain, because
Check Point rate-limits logins per server machine.

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

###### `def __init__(self, registry: ServerRegistry, transport: ApiTransport, rate_limiter: RateLimiter, cache: CacheRepository, settings: ArodonataSettings, lock_manager: DatabaseLockManager | None = None, session_cleaner: SessionCleaner | None = None, login_gate: LoginGate | None = None) -> None`

Initialize login coordinator.

Args:
    registry: Server registry instance.
    transport: API transport instance.
    rate_limiter: Rate limiter instance.
    cache: Cache repository instance.
    settings: Configuration settings.
    lock_manager: Optional DatabaseLockManager instance.
    session_cleaner: Optional SessionCleaner for max-sessions cleanup.
    login_gate: Optional LoginGate; built lazily over the lock manager when absent.

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

Overlapping calls coalesce: if a sweep is already in flight this call
returns immediately. A burst of API calls (e.g. rapid logout/login
cycles) must not turn into a burst of sweeps, each holding rate-limiter
slots for every stale session against a possibly throttled server —
one in-flight sweep already covers the same stale set.

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

###### `async def mds_host(self, mgmt_name: str, domain: str) -> str`

The MDS member a call to `mgmt_name`/`domain` counts against: what the login gate and the RateLimiter key on.

Check Point serves every domain of a member from that member's one API server, and rate-limits logins per
member. A domain's requests go to its domain server, hosted on some member -- and domains move between
members on failover -- so for a domain it is the member IP recorded on the domain's cache row by
`_cache_domain_active_ip`. The system domain, Global without a known member, a SmartCenter, or a row
without that information fall back to the configured host.

###### `async def mds_host_for_ip(self, mgmt_name: str, server_ip: str) -> str`

The MDS member serving `server_ip`, for a call that knows only the address (an explicit SID).

The domain row whose active server is at `server_ip` names the domain, and its member is whatever
`mds_host` says for that domain (the row's `active_mds_ip`, else the configured host, exactly as for a
call that names the domain). Without such a row -- the system domain, a SmartCenter, a domain not cached
yet -- the address itself is the key.

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

### `arodonata/asdk/login_gate.py`

Per-MDS login gate: wait out Check Point's login rate limit once, together.

Check Point rate-limits logins per management server -- every domain hosted on a
Multi-Domain Server member shares that member's allowance -- over roughly a
minute, to a server-configured count this library does not know. The gate does
not try to know it. It records one fact, "this server just refused a login", as
a row in the distributed_locks table with a TTL of one throttle window, and
makes every login attempt to that server, in every worker sharing the database,
sleep until the row lapses. One refusal per window is the price of discovery;
the gate stops it being paid more than once.

Which server a login counts against is the caller's business (see
LoginCoordinator.mds_host): the gate is keyed on whatever string it is given.

This is a *rate* concern and deliberately separate from RateLimiter, which caps
*concurrency* per MDS member, keyed like the gate (LoginCoordinator.mds_host).
Design: docs/superpowers/specs/2026-09-14-mds-login-gate-design.md

#### class `LoginGateDeadlineError(ThrottlingError)`

Waited at the gate until the login's deadline and never got a turn.

A ThrottlingError, so anything that already handles throttling handles this;
a distinct class, so LoginCoordinator can tell "the deadline passed" (end the
sequence) from "the server refused" (close the gate, keep going) by type.
Internal: it never leaves LoginCoordinator unwrapped.

##### Methods

###### `def __init__(self, mds_host: str, waited: float, max_wait: int, *, throttles: int | None = None, failures: int = 0, timeouts: int = 0, last_error: BaseException | None = None) -> None`

Args:
    mds_host: The machine the login counts against.
    waited: Seconds spent before giving up.
    max_wait: The configured budget (login_max_wait).
    throttles: Throttle refusals this login received, or None when the
        raiser cannot know (the gate itself). The retry loop re-raises
        with the tally via `with_attempts`, because the deadline passes
        the same way whether the attempts were refused for rate or timed
        out, and only the tally says which.
    failures: Non-throttle failed attempts (timeouts included).
    timeouts: How many of `failures` were timeouts.
    last_error: The last attempt's exception, if any.

###### `def with_attempts(self, *, throttles: int, failures: int, timeouts: int, last_error: BaseException | None) -> LoginGateDeadlineError`

The same deadline, with what this login's attempts actually ran into.

#### class `LoginGate`

One marker row per management server: `loginthrottle:{mds_host}`, TTL = window.

##### Methods

###### `def __init__(self, lock_manager: DatabaseLockManager, window: int, *, now: Callable[[], datetime] = _utcnow) -> None`

Args:
    lock_manager: Where the marker rows live (the same table as every other lock).
    window: Seconds a refusal closes the gate for, measured from the *last* refusal.
    now: Clock returning naive UTC; injectable for tests.

###### `async def close(self, mds_host: str, window: int | None = None, *, target: str = '') -> None`

```python
@traced
```
Record that `mds_host` just refused a login: nobody tries again for one window.

Upserts the row, or -- if another task already closed the gate -- pushes its
expiry out, because the window that matters runs from the *last* refusal.
The row is never released; it lapses. `target` ("mgmt/domain") names the
refused login in the log line, the only one a throttle produces.

###### `async def wait_open(self, mds_host: str, *, deadline: float, max_wait: int, keepalive: Callable[[], Awaitable[Any]] | None = None) -> None`

```python
@traced
```
Return once no refusal is live for `mds_host`; raise if that would pass `deadline`.

Args:
    mds_host: The server the login counts against (LoginCoordinator.mds_host).
    deadline: Absolute `loop.time()` after which the login gives up.
    max_wait: The setting behind `deadline`, for the error message only.
    keepalive: Awaited before every sleep chunk -- the caller's lock renewal.

### `arodonata/asdk/pager.py`

Own paging for listing commands (spec D3): one call per page, so a caller holds a RateLimiter slot per page.

cpapi's api_query fetched every page inside one call and checked nothing across pages. Here every page is checked
against the previous one. An object can come twice for two reasons: Check Point swapped two objects with equal names
at a page boundary between requests, which hides the other one, so the repeat is dropped and a few objects on both
sides of the boundary are read again in one request to recover it (spec D3a); or a publish between pages shifted offsets. A changed
`total` or a final count of distinct objects other than `total` catches the publishes that shift the boundary. An
insert and a delete before the cursor that cancel out shift nothing and read like a slightly older snapshot; the
cache's freshness stamp is taken before the listing, so the next incremental refresh picks them up. A failed check
restarts the listing once from the caller's offset, and a second failure fails the query instead of returning
duplicates or gaps.

#### Module-Level Functions

##### `async def fetch_all_pages(fetch_page: PageFetcher, *, command: str, container_key: str, offset: int, page_size: int) -> RawApiResponse`

Page `command` from `offset` to the end, `page_size` objects per call.

Returns cpapi's api_query shape: on success `data` is the list of objects. A first page that is unsuccessful, not a
dict or without a `container_key` list is returned as is; one with the list but no paging (no `total`, `total` 0 or
an empty list) comes back with `data` replaced by that list, as cpapi does. An unsuccessful later page (or window
re-read) fails the query with that page's code. A repeated uid on a later page is dropped and up to `_TIE_WINDOW`
objects on each side of that page's start are re-read in one request to recover the object an equal-name swap hid; the listing must end with
`total - offset` distinct objects, or it is restarted once. Exceptions from `fetch_page` propagate untouched:
nothing here retries a timeout or an identity error.

### `arodonata/asdk/rate_limiter.py`

Rate limiter for per-MDS member concurrent API request limiting.

Manages distributed locks to limit concurrent operations per MDS member,
preventing overload of management servers across multiple workers.

#### class `RateLimiter`

Per-MDS member distributed lock for concurrent API operation limiting.

Uses SQL-database-backed distributed locks (any SQLAlchemy-supported
dialect) to enforce concurrent operation limits across multiple
workers/processes.

Lock keys use a slot-based approach: ratelimit:{host}:slot_{n}
where host is the MDS member hosting the target (LoginCoordinator.mds_host)
and n is determined by hashing the operation ID to distribute load.
A held slot's row is renewed every third of its TTL until release, so a
request that outlasts the TTL (a publish task, a long single call) keeps it.

Waiters for one host are served in arrival order within this limiter (one per client): a caller
that finds others waiting queues behind them, only the longest waiter sweeps the slots, and a
release wakes it at once. A caller that releases after a page and asks again (asdk/pager.py)
therefore lets the waiter in first. Slots freed by other processes or other limiters are found by
the longest waiter's polling sweep.

Example:
    limiter = RateLimiter(concurrent_limit=4)
    async with limiter.acquire("192.168.1.10"):
        # Make API call - limited to 4 concurrent per member across all workers
        pass

##### Methods

###### `def __init__(self, concurrent_limit: int = DEFAULT_CONCURRENT_LIMIT, lock_manager: DatabaseLockManager | None = None, slot_timeout: int = DEFAULT_RATE_LIMIT_SLOT_TIMEOUT, slot_renew_interval: float | None = None) -> None`

Initialize rate limiter.

Args:
    concurrent_limit: Maximum concurrent operations per MDS member.
    lock_manager: Optional DatabaseLockManager instance.
    slot_timeout: Default seconds acquire() waits for a free slot before
        giving up. Size it for queueing behind other callers of the member:
        a call that waits for a task (publish, revert) holds its slot for the
        whole task, while listings release it between pages and a login holds
        it for one attempt only, never across its retries or a throttle wait
        (see DEFAULT_RATE_LIMIT_SLOT_TIMEOUT).
    slot_renew_interval: Seconds between renewals of a held slot's lock row.
        Defaults to a third of the row's TTL (DEFAULT_TTL_RATE_LIMIT, so 100 s);
        must be positive.

###### `async def close(self) -> None`

Clean up resources.

###### `async def acquire(self, server_ip: str, timeout: int | None = None) -> AsyncGenerator[None]`

```python
@asynccontextmanager
@traced
```
Acquire lock for server operations (reentrant per task).

Args:
    server_ip: The slot key — the MDS member hosting the target (LoginCoordinator.mds_host).
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

###### `async def cleanup_stale_sessions(self, mgmt_name: str, domain: str, system_sid: str, server_ip: str, port: int | None = None, *, slot_host: str | None = None) -> CleanupResult`

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
    slot_host: RateLimiter key for the discards -- the MDS member the session lives on
        (LoginCoordinator.mds_host); defaults to server_ip.

Returns:
    CleanupResult with counts of discarded/skipped/errored sessions.

### `arodonata/asdk/task_waiter.py`

Self-managed polling of Check Point long-running tasks.

Check Point answers `publish`, `revert-to-revision`, `install-policy` and
`run-script` with a `task-id` instead of a result. cpapi can wait for such a task
itself (`api_call(..., wait_for_task=True)`), but it does so in a blocking loop
inside one thread: its `show-task` calls bypass this library's transport entirely
-- no rate limiting, no OTel span, no log line -- and a timeout surfaces as a bare
`TimeoutError` carrying no task-id, status or progress. A ten-minute revert was
therefore ~300 invisible API calls followed, at worst, by an empty exception
(seen 2026-09-13: `API CALL TIMEOUT: revert-to-revision (timeout=120s)` and no
way to tell whether the revert had started, was half-done, or had hung).

`TaskWaiter` takes that wait over. It is stateless and owned by `ApiTransport`,
which constructs it once with the policy knobs and hands `wait()` a `show_task`
callable already bound to the live server/session of the call being waited on --
so this module stays free of any client, session or transport type and is
testable with a plain async lambda (the same shape `cpcrud/nat_sentinels.py` uses).

It does NOT raise on task failure. A `failed` or `partially succeeded` task is
data, returned to the caller, which renders it exactly as cpapi's
`check_tasks_status` did: `success=False` on the response, no exception. That is a
hard backward-compatibility requirement -- applications branch on
`if not result.success`, and turning that into an exception would break them.

#### Module-Level Functions

##### `def extract_task_ids(data: Any) -> list[str]`

Pull task ids out of a command response's `data`, tolerating every known shape.

Publish and revert-to-revision return `{"task-id": "<id>"}` in this repo's
observed traffic. install-policy and run-script are believed to return a
`tasks` list (cpapi has a separate `__wait_for_tasks` path for it) but this has
not been verified against the lab, so both list-of-dicts and list-of-strings
are accepted, as is a `task-id` that is itself a list. Order-preserving and
de-duplicated; [] for anything that carries no task.

##### `def parse_task_statuses(response: TaskResponse) -> list[TaskStatus]`

Read the `tasks` entries out of a `show-task` response; [] if malformed.

#### class `TaskStatus`

```python
@dataclass(frozen=True)
```
One task's last observed state, as read from a `show-task` entry.

##### Fields / Class Variables

```python
task_id: str
status: str
progress: int | None
raw: dict[str, Any]
```
##### Methods

###### `def is_terminal(self) -> bool`

```python
@property
```
True once the task has left `in progress` -- successfully or not.

Matches cpapi's completion rule exactly (`status != "in progress"`), so an
unrecognized status ends the wait rather than polling forever.

###### `def is_success(self) -> bool`

```python
@property
```
True only for an explicit `succeeded`.

An allowlist where cpapi's `check_tasks_status` is a denylist: cpapi flips
success off only for `failed` / `partially succeeded` / `in progress` and
lets anything unfamiliar through as a success. An unknown status is far
more likely to be a new failure mode than a new way of succeeding, so it
is not a success here.

###### `def describe(self) -> str`

`task <id> '<status>' at <progress>%`, for logs and the timeout message.

#### class `TaskWaiter`

Polls `show-task` until every task is terminal, with backoff and a budget.

Stateless: one instance is constructed by `ApiTransport` and reused for every
call, so the policy knobs live in one place and nothing per-call is retained.
`sleep` and `clock` are injectable only so the unit tests can run a ten-minute
wait instantly; production never passes them.

##### Methods

###### `def __init__(self, *, poll_initial: float = DEFAULT_TASK_POLL_INITIAL_SECONDS, poll_max: float = DEFAULT_TASK_POLL_MAX_SECONDS, poll_failure_tolerance: int = DEFAULT_TASK_POLL_FAILURE_TOLERANCE, sleep: Sleep = asyncio.sleep, clock: Clock = time.monotonic) -> None`

_No docstring._

###### `async def wait(self, show_task: ShowTask, task_ids: list[str], *, timeout: float, context: str = '') -> list[TaskStatus]`

```python
@traced
```
Poll until every task in `task_ids` is terminal; return their statuses.

Args:
    show_task: Async callable taking a `show-task` payload and returning
        the response dict. Supplied by the transport as a closure already
        bound to the live server_ip/sid/port of the call being waited on.
    task_ids: Task ids to wait on.
    timeout: Total budget in seconds for the remaining wait. <= 0 means no
        deadline, matching `api_call(timeout=-1)`.
    context: Free text for logs and the timeout message, e.g.
        "revert-to-revision on 10.0.0.1".

Returns:
    The final `TaskStatus` for each task, successful or not. Task failure
    is never raised -- see the module docstring.

Raises:
    TaskTimeoutError: The budget expired. Subclasses `TimeoutError`.
    TaskPollError: `show-task` failed more times in a row than tolerated.

### `arodonata/asdk/tls.py`

Verified, time-bounded connections to Check Point servers (Backlog #1 and #12).

Identity is a pinned SHA-256 certificate fingerprint per ``host:port`` (trust on first use by default), checked in
``connect()`` after the TLS handshake and before any application byte. cpapi's own ``check_fingerprint`` (cwd
``fingerprints.txt``, ``input()`` prompt, unchecked re-send) is bypassed. The only module allowed to build an
``ssl.SSLContext`` or to construct cpapi clients (``tests/unit/test_tls_hygiene.py``). Design:
``docs/superpowers/specs/2026-10-04-tls-fingerprint-verification-design.md``.

#### Module-Level Functions

##### `def host_key(host: str, port: int) -> str`

Trust-store key: ``host:port`` as dialled, IPs normalised, IPv6 bracketed, hostnames lowercased.

##### `def reset_lab_memory() -> None`

Forget everything lab-memory learned in this process (tests only).

##### `def anchored_context(pems: Sequence[str]) -> ssl.SSLContext`

CERT_REQUIRED with the pinned certificate(s) as the only trust anchors; no hostname, no expiry check.

##### `def probe_certificate(host: str, port: int, timeout: float) -> bytes`

Handshake only, to read the presented certificate; never carries application data (spec D3).

The single CERT_NONE site in the repo: the certificate is judged by ``TrustPolicy.check`` afterwards, and only
an accepted one becomes the trust anchor of the connection that carries data.

##### `def verified_api_client(server: str, port: int | None = None, *, sid: str | None = None, policy: TrustPolicy | None = None, settings: ArodonataSettings | None = None, connect_timeout: float | None = None, read_timeout: float | None = None) -> VerifiedAPIClient`

The only way arodonata (and its lab scripts) builds a cpapi client (spec D23).

#### class `TrustEntry`

```python
@dataclass(frozen=True)
```
One trusted certificate: SHA-256 (64 lowercase hex), its PEM when known, how it was learned, when.

##### Fields / Class Variables

```python
sha256: str
pem: str | None
source: str
first_seen: str
```
#### class `TrustStore`

The persisted ``host:port`` -> certificate map (spec D11-D13). Reads are lock-free; writes are atomic.

##### Methods

###### `def __init__(self, path: Path) -> None`

_No docstring._

###### `def load(self) -> dict[str, TrustEntry]`

_No docstring._

###### `def record(self, key: str, entry: TrustEntry) -> TrustEntry`

Persist ``entry`` unless ``key`` is already recorded; return what the store holds for ``key``.

###### `def ensure_writable(self) -> None`

Preflight for ``tofu``: the directory and lock file can be created and the store is sane.

#### class `TrustPolicy`

Decides whether a presented certificate is the trusted one for ``host:port`` (spec D6).

##### Methods

###### `def __init__(self, mode: TrustMode, store: TrustStore, pins: Iterable[str]) -> None`

_No docstring._

###### `def from_settings(cls, settings: ArodonataSettings) -> TrustPolicy`

```python
@classmethod
```
_No docstring._

###### `def preflight(self) -> None`

Fail at startup instead of at the first new host (spec D14).

###### `def anchor_pems(self, host: str, port: int) -> list[str] | None`

_No docstring._

###### `def check(self, host: str, port: int, der: bytes) -> TrustEntry`

_No docstring._

#### class `PinnedHTTPSConnection(_CpapiHTTPSConnection)`

cpapi's connection with the identity check in ``connect()`` (spec D4).

##### Fields / Class Variables

```python
sock: socket.socket | None
```
##### Methods

###### `def __init__(self, client: VerifiedAPIClient, pems: Sequence[str]) -> None`

_No docstring._

###### `def connect(self) -> None`

_No docstring._

#### class `VerifiedAPIClient(APIClient)`

cpapi client whose every connection is verified and time-bounded (spec D5).

##### Fields / Class Variables

```python
conn: PinnedHTTPSConnection | None
```
##### Methods

###### `def __init__(self, args: APIClientArgs, *, policy: TrustPolicy, connect_timeout: float, read_timeout: float) -> None`

_No docstring._

###### `def record_failure(self, exc: ArodonataError) -> None`

_No docstring._

###### `def check_fingerprint(self) -> bool`

_No docstring._

###### `def create_https_connection(self) -> PinnedHTTPSConnection`

_No docstring._

###### `def api_call(self, command, payload = None, sid = None, wait_for_task = True, timeout = -1, method = 'POST')`

_No docstring._

### `arodonata/asdk/transport.py`

API transport layer - wraps sync Check Point SDK with async execution.

Handles the actual communication with Check Point management servers
using asyncio.to_thread to run sync SDK operations in an async context.

#### Module-Level Functions

##### `def mask_secret(secret: SecretStr | str | None) -> str`

Log-safe stand-in for a credential: its last four characters at most.

Enough to tell two keys apart in a log, too little to be worth stealing.
Short secrets (8 characters or fewer) are fully masked.

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

###### `def __init__(self, task_waiter: TaskWaiter | None = None, *, tls_policy: TrustPolicy | None = None, connect_timeout: float | None = None, default_read_timeout: float | None = None) -> None`

Initialize API transport.

Args:
    task_waiter: Optional TaskWaiter for polling async tasks.
    tls_policy: Certificate trust policy; None builds it from ArodonataSettings() on first use.
    connect_timeout: TCP connect + TLS handshake bound; None means settings.connect_timeout.
    default_read_timeout: Socket read bound for calls without a budget; None means
        settings.default_read_timeout.

###### `async def api_call(self, server_ip: str, sid: str, command: str, payload: dict[str, Any] | None = None, wait_for_task: bool = True, timeout: int = -1, port: int | None = None, task_timeout: int = -1) -> RawApiResponse`

```python
@traced
```
Execute API call using sync SDK in async context.

Args:
    server_ip: Management server IP address.
    sid: Session identifier.
    command: API command to execute.
    payload: Request payload.
    wait_for_task: Whether to wait for task completion. The wait is done
        here, by `TaskWaiter`, never by cpapi -- see `_await_tasks`.
    timeout: Budget in seconds for the WHOLE operation: the initial call
        plus, when it returns a task and `task_timeout` is not set, the
        polling until that task ends. <= 0 means no overall budget; each
        socket read is then still bounded by `default_read_timeout` (and
        each connect by `connect_timeout`).
    port: Optional port number (defaults to 443 if not specified).
    task_timeout: Budget in seconds for waiting out the task alone, apart
        from `timeout`. <= 0 means the wait gets what is left of `timeout`
        (no bound when that is <= 0 too).

Returns:
    API response dictionary. For a task-returning command with
    `wait_for_task=True`, the final `show-task` response, with `success`
    False if any task ended other than `succeeded`.

Raises:
    TaskTimeoutError: The task did not finish within its budget. A
        `TimeoutError` subclass, so `except TimeoutError` still catches it.
    TimeoutError: The initial call itself did not return within `timeout`.
    ApiTimeoutError: A socket connect or read timed out. Also a
        `TimeoutError` subclass; the request is not re-sent.
    ServerIdentityError: The server's TLS certificate is not the one
        trusted for that address; nothing was sent.
    TaskPollError: `show-task` kept failing past the tolerated count.

###### `async def login_with_apikey(self, server_ip: str, api_key: SecretStr | str, domain: str | None = None, timeout: int = DEFAULT_LOGIN_TIMEOUT, port: int | None = None, session_name: str | None = None, session_description: str | None = None, session_timeout: int | None = None, *, log_sid: bool = True) -> RawApiResponse`

```python
@traced
```
Perform login using an API key. ``log_sid=False`` keeps any part of the new SID out of the log (sessions
an app owns, D20).

Args:
    server_ip: Management server IP address.
    api_key: API key for authentication. Pass a SecretStr: it is
        unwrapped only inside the cpapi call, so no frame on the login
        path holds the plain value for a traceback to print.
    domain: Optional domain name.
    timeout: Per-attempt login timeout in seconds (default:
        DEFAULT_LOGIN_TIMEOUT). A login is one round trip; it does not
        inherit the much larger API/task budget.
    port: Optional port number (defaults to 443 if not specified).
    session_name: Optional session name visible in SmartConsole.
    session_description: Optional session description.
    session_timeout: Session timeout in seconds (default: 600).

Returns:
    Login response dictionary.

Raises:
    asyncio.TimeoutError: If login times out.

###### `async def login_with_credentials(self, server_ip: str, username: str, password: SecretStr | str, domain: str | None = None, timeout: int = DEFAULT_LOGIN_TIMEOUT, port: int | None = None, session_name: str | None = None, session_description: str | None = None, session_timeout: int | None = None) -> RawApiResponse`

```python
@traced
```
Perform login with username/password credentials.

Args:
    server_ip: Management server IP address.
    username: Username for authentication.
    password: Password for authentication (SecretStr or str).
    domain: Optional domain name.
    timeout: Per-attempt login timeout in seconds (default:
        DEFAULT_LOGIN_TIMEOUT). A login is one round trip; it does not
        inherit the much larger API/task budget.
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

For SQLite engines it registers a ``do_connect`` listener on the caller's engine that defaults the driver
timeout to ``SQLITE_BUSY_TIMEOUT_SECONDS`` (an explicit ``connect_args`` timeout wins), so concurrent writers
and several processes on one file wait for a busy database instead of failing with "database is locked".

##### Methods

###### `def __init__(self, engine: AsyncEngine) -> None`

Initialize database manager with pre-configured engine.

For SQLite engines this registers a ``do_connect`` listener on ``engine`` (the caller's engine, not a copy)
that defaults the driver timeout to ``SQLITE_BUSY_TIMEOUT_SECONDS``; a ``timeout`` set through
``connect_args`` wins. Other dialects are untouched.

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

###### `async def try_acquire_lock(self, lock_key: str, ttl: int) -> LockContext | None`

```python
@traced
```
Acquire the lock if it is free right now; never wait.

Returns the LockContext on success, or None when a live owner holds the
key. This is the primitive a caller needs to sweep several candidate
locks (e.g. RateLimiter slots) rather than block on one of them.
Release with `release_lock(lock_key, ctx.owner_id)`.

Args:
    lock_key: Unique lock identifier.
    ttl: Lock time-to-live in seconds.

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

###### `async def peek_expiry(self, lock_key: str) -> datetime | None`

`expires_at` of a live row for `lock_key`; None if absent or already expired.

Read-only. For callers that use a row as a shared *marker* rather than a
mutual-exclusion lock (asdk/login_gate.py): they need to know when it
lapses so they can sleep until then instead of polling.

###### `async def extend_lock(self, lock_key: str, ttl: int) -> bool`

```python
@traced
```
Push `lock_key`'s `expires_at` out to now + ttl, whoever owns the row.

Unlike `renew_lock` this deliberately ignores ownership: it is for rows
used as shared markers (asdk/login_gate.py), where the fact that matters
is *when the row lapses*, not who wrote it. Never shortens -- a row that
already expires later than now + ttl is left alone. Returns False only
when there is no row at all.

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
created_at: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), description='Cache entry timestamp')
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
mdm_dmn: str = Field(primary_key=True, description="'mgmt_name:domain' ('mgmt_name:' for the system domain)")
domain_name: str = Field(index=True)
domain_uid: str = Field(default='', max_length=255)
active_mds: str
active_ip: str
active_mds_ip: str = Field(default='', description="IPv4 of the MDS member hosting the active domain server -- what Check Point rate-limits logins on (asdk/login_gate.py). '' when unknown: SmartCenter, show-mdss unavailable, or a row written before this column existed.")
active_server: str
standby_mdss: str = Field(default='')
standby_ips: str = Field(default='')
standby_servers: str = Field(default='')
mgmt_name: str
is_mdm: bool = Field(default=False)
```
##### Methods

###### `def build(cls, *, mgmt_name: str, domain_name: str, domain_uid: str = '', active_ip: str, active_server: str = '', active_mds: str = '', active_mds_ip: str = '', standby_mdss: str = '', standby_ips: str = '', standby_servers: str = '', is_mdm: bool = False) -> Domain`

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
    active_mds: Hosting MDS member's name (default: mgmt_name).
    active_mds_ip: Hosting member's IPv4 (default: "" = unknown).
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
acquired_at: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), description='Lock acquisition timestamp')
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
updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), description='When this schema hash was last confirmed applied (naive UTC)')
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
update_time: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), index=True, description='Last cache update')
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
published_time: datetime = Field(default_factory=lambda: datetime(1970, 1, 1).replace(tzinfo=None), description='Session publish timestamp (naive UTC)')
uid: str = Field(default='', max_length=64)
name: str = Field(default='', max_length=255)
ip_address: str = Field(default='', max_length=45)
comments: str = Field(default='')
creator: str = Field(default='', max_length=255)
description: str = Field(default='')
update_time: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), index=True)
```
#### class `RulebaseAccess(SQLModel)`

Cached access control rules from Network layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_uid:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True, description='Rule position in layer')
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
layer_uid: str | None = Field(default=None, max_length=64, description='Layer uid from the response; NULL marks a pre-v2 row')
kind: str = Field(default='rule', max_length=32, description="'rule' or 'place-holder'")
section_uid: str | None = Field(default=None, max_length=64, description='Enclosing section uid')
inline_layer_uid: str | None = Field(default=None, max_length=64, description="The rule's inline-layer uid")
domain_type: str = Field(default='', max_length=32, description="The rule's domain.domain-type")
sources: str = Field(default='', description='Comma-separated source names (uid when unresolved); a name containing a comma is split wrongly on read')
destinations: str = Field(default='', description='Comma-separated destination names (uid when unresolved); a name containing a comma is split wrongly on read')
services: str = Field(default='', description='Comma-separated service names (uid when unresolved); a name containing a comma is split wrongly on read')
action: str = Field(default='Accept', max_length=64, description='Action name (Accept, Drop, Inner Layer...)')
track: str = Field(default='', max_length=64, description='Track type name (Log, None...)')
update_time: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `RulebaseNAT(SQLModel)`

Cached NAT rules from NAT layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_uid:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True)
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
layer_uid: str | None = Field(default=None, max_length=64, description='Layer uid from the response; NULL marks a pre-v2 row')
kind: str = Field(default='rule', max_length=32, description="'rule' or 'place-holder'")
section_uid: str | None = Field(default=None, max_length=64, description='Enclosing section uid')
inline_layer_uid: str | None = Field(default=None, max_length=64, description="The rule's inline-layer uid")
domain_type: str = Field(default='', max_length=32, description="The rule's domain.domain-type")
auto_generated: bool = Field(default=False, description='CP auto-generated NAT rule')
original_source: str = Field(default='', max_length=255)
original_destination: str = Field(default='', max_length=255)
original_service: str = Field(default='', max_length=255)
translated_source: str = Field(default='', max_length=255)
translated_destination: str = Field(default='', max_length=255)
translated_service: str = Field(default='', max_length=255)
update_time: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `RulebaseHTTPS(SQLModel)`

Cached HTTPS inspection rules from CVD layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_uid:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True)
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
layer_uid: str | None = Field(default=None, max_length=64, description='Layer uid from the response; NULL marks a pre-v2 row')
kind: str = Field(default='rule', max_length=32, description="'rule' or 'place-holder'")
section_uid: str | None = Field(default=None, max_length=64, description='Enclosing section uid')
inline_layer_uid: str | None = Field(default=None, max_length=64, description="The rule's inline-layer uid")
domain_type: str = Field(default='', max_length=32, description="The rule's domain.domain-type")
sources: str = Field(default='', description='Comma-separated source names (uid when unresolved); a name containing a comma is split wrongly on read')
destinations: str = Field(default='', description='Comma-separated destination names (uid when unresolved); a name containing a comma is split wrongly on read')
track: str = Field(default='', max_length=64, description='Track type name (Log, None...)')
update_time: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `RulebaseThreat(SQLModel)`

Cached threat prevention rules from Threat layer.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="Composite key: 'mgmt_name:domain_name:layer_uid:uid'")
uid: str = Field(index=True, max_length=64)
rule_number: int = Field(index=True)
name: str = Field(max_length=255)
enabled: bool = Field(index=True)
layer_name: str = Field(index=True, max_length=255)
mgmt_name: str = Field(index=True, max_length=64)
domain_name: str = Field(index=True, max_length=255, default='')
layer_uid: str | None = Field(default=None, max_length=64, description='Layer uid from the response; NULL marks a pre-v2 row')
kind: str = Field(default='rule', max_length=32, description="'rule' or 'place-holder'")
section_uid: str | None = Field(default=None, max_length=64, description='Enclosing section uid')
inline_layer_uid: str | None = Field(default=None, max_length=64, description="The rule's inline-layer uid")
domain_type: str = Field(default='', max_length=32, description="The rule's domain.domain-type")
track: str = Field(default='', max_length=64, description='Track type name (Log, None...)')
protections: str = Field(default='', description='Comma-separated protection names (uid when unresolved); a name containing a comma is split wrongly on read')
update_time: datetime = Field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None), index=True)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
```
#### class `RulebaseLayer(SQLModel)`

One cached layer of a domain's rulebase snapshot (an empty layer has a row with total=0).

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="'mgmt_name:domain_name:rulebase_type:layer_uid'")
mgmt_name: str = Field(max_length=64)
domain_name: str = Field(max_length=255, default='')
rulebase_type: str = Field(max_length=16)
layer_uid: str = Field(max_length=64)
layer_name: str = Field(max_length=255, default='')
layer_domain_type: str = Field(max_length=32, default='')
total: int = Field(default=0)
objects_dictionary: list[dict[str, Any]] | None = Field(default=None, sa_column=Column('objects_dictionary', JSON, nullable=True), description='Trimmed {uid, name, type}')
update_time: datetime = Field(default_factory=_utcnow)
```
#### class `RulebaseSection(SQLModel)`

One section of a cached layer (from/to are in-layer rule numbers; NULL for an empty section).

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="'mgmt_name:domain_name:layer_uid:section_uid'")
mgmt_name: str = Field(max_length=64)
domain_name: str = Field(max_length=255, default='')
rulebase_type: str = Field(max_length=16)
layer_uid: str = Field(max_length=64)
section_uid: str = Field(max_length=64)
name: str = Field(max_length=255, default='')
from_number: int | None = Field(default=None)
to_number: int | None = Field(default=None)
rules_before: int = Field(default=0)
seq: int = Field(default=0)
raw_data: dict[str, Any] | None = Field(default=None, sa_column=Column('raw_data', JSON, nullable=True))
update_time: datetime = Field(default_factory=_utcnow)
```
#### class `PolicyPackageLayer(SQLModel)`

One ordered layer of a policy package (a package with no ordered layers has no rows).

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="'mgmt_name:domain_name:package_uid:rulebase_type:position'")
mgmt_name: str = Field(max_length=64)
domain_name: str = Field(max_length=255, default='')
package_uid: str = Field(max_length=64)
package_name: str = Field(max_length=255)
rulebase_type: str = Field(max_length=16)
position: int = Field(default=0)
slot: str = Field(max_length=16, default='')
layer_uid: str = Field(max_length=64)
layer_name: str = Field(max_length=255, default='')
layer_domain_type: str = Field(max_length=32, default='')
placeholder_uid: str | None = Field(default=None, max_length=64)
parent_rule_uid: str | None = Field(default=None, max_length=64)
parent_rule_name: str | None = Field(default=None, max_length=255)
domain_layer_uid: str | None = Field(default=None, max_length=64)
update_time: datetime = Field(default_factory=_utcnow)
```
#### class `RulebaseSyncState(SQLModel)`

Which published session a domain's rulebase snapshot was built from (separate from the object baseline).

##### Fields / Class Variables

```python
id: str = Field(primary_key=True, max_length=512, description="'mgmt_name:domain_name'")
mgmt_name: str = Field(max_length=64)
domain_name: str = Field(max_length=255, default='')
session_uid: str | None = Field(default=None, max_length=64)
session_published_time: datetime | None = Field(default=None)
refreshed_at: datetime | None = Field(default=None)
format_version: int = Field(default=0)
status: str = Field(default='', max_length=16, description="'ok' | 'unversioned' | 'failed'")
last_error: str | None = Field(default=None)
update_time: datetime = Field(default_factory=_utcnow)
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

###### `def __init__(self, db_manager: DatabaseManager, client: ArodonataClient, max_incremental_changes: int = 500, domain_list_refresh_ttl: int = DOMAIN_LIST_REFRESH_TTL_SECONDS, clock: Clock | None = None) -> None`

Initialize ObjectService.

Args:
    db_manager: DatabaseManager instance.
    client: ArodonataClient instance for API fallback.
    max_incremental_changes: Max in-scope changes an incremental
        apply will accept before falling back to a full reload.
    domain_list_refresh_ttl: Seconds between opportunistic (CHECK/
        INCREMENTAL-mode) re-fetches of a management server's domain
        list. FORCE mode ignores this and always re-fetches. See
        `DOMAIN_LIST_REFRESH_TTL_SECONDS`.
    clock: Injectable time source for the TTL memo (tests only;
        defaults to the real wall clock).

###### `async def search_objects(self, search_input: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, max_depth: int = 2) -> AsyncIterator[SearchResult]`

Search for objects by IP, name, UID, or type.

Args:
    search_input: Comma-separated search terms.
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    max_depth: Maximum depth for group membership traversal.

Yields:
    SearchResult for each search term.

###### `async def refresh_objects(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, mode: str = 'force', include_global: bool = False, *, refresh_domain_list: bool = True) -> AsyncIterator[dict[str, Any]]`

Refresh object cache from API.

Args:
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    mode: Refresh mode (skip/check/force/incremental).
    include_global: When False (default), the "Global" domain
        is excluded from the all-domains refresh path so existing
        callers see today's behavior. An explicit ``domain_names``
        request for "Global" is honored regardless of this flag.
    refresh_domain_list: When True (default), a FORCE refresh (and a
        smart refresh whose domain-list TTL ran out) re-reads the
        server's domain list (show-domains/show-mdss) and rewrites
        the domain rows. Pass False when the caller already knows
        its domains, as ``CacheRefreshCoordinator`` does: with
        several domains reloading at once every reload would
        otherwise issue those calls and rewrite every domain row.
        An empty domain table and a ``domain_names`` entry missing
        from the table still trigger the re-read.

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
does not touch CPObject or Asset caches. The stored record is the
object cache's freshness stamp, so this marks the domain's cache as
current without refreshing it; to only read the head, use
`fetch_last_published_session`.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    The upserted LastPublishedSession record, or None if the API
    call failed or returned no usable timestamp.

###### `async def store_last_published_session(self, record: LastPublishedSession) -> LastPublishedSession | None`

Upsert a last-published-session record; None (logged) if the cache write fails.

###### `async def read_last_published_session(self, mgmt_name: str, domain_name: str) -> LastPublishedSession`

Read the domain's current last-published session WITHOUT storing it, or raise.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    An unsaved LastPublishedSession.

Raises:
    InvalidCredentialsError: The login was refused for invalid credentials (propagated unchanged).
    PublishedHeadError: The call failed, raised, or returned no usable timestamp.

###### `async def fetch_last_published_session(self, mgmt_name: str, domain_name: str) -> LastPublishedSession | None`

Read the domain's current last-published session WITHOUT storing it.

The read-only half of `refresh_last_published_session`. Callers that need
to know where the domain's head is *before* deciding what to do with the
cache must not advance the stored baseline in the process — doing so
empties the diff window they are about to use. `CacheRefreshCoordinator`
uses this to tell a forward publish from a revert.

Args:
    mgmt_name: Management server name.
    domain_name: Domain name.

Returns:
    An unsaved LastPublishedSession, or None if the API call failed or
    returned no usable timestamp. Never raises (see
    `read_last_published_session` for the raising variant).

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

##### Fields / Class Variables

```python
_SNAPSHOT_TABLES: tuple[type[SQLModel], ...] = (RulebaseLayer, RulebaseSection, PolicyPackageLayer)
```
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

###### `async def get_domains(self, mgmt_name: str | None = None, mgmt_names: list[str] | None = None, include_global: bool = False) -> list[Domain]`

Get all domains, optionally filtered by management server.

Args:
    mgmt_name: Optional single management server filter (deprecated, use mgmt_names).
    mgmt_names: Optional list of management server names to filter.
    include_global: When False (default), the "Global" domain
        row is excluded so existing callers see today's behavior.

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

###### `async def get_objects_last_update(self, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> datetime | None`

Most recent ``update_time`` among cached objects in scope, or ``None`` when the scope is empty.

###### `async def get_rulebase_last_update(self, rulebase_type: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None) -> datetime | None`

Most recent ``update_time`` among cached rules of one rulebase type in scope, or ``None`` when empty.

Args:
    rulebase_type: One of ``"access"``, ``"nat"``, ``"https"``, ``"threat"``.
    mgmt_names: Optional management server names to filter.
    domain_names: Optional domain names to filter.

Raises:
    ValueError: If ``rulebase_type`` is not one of the supported types.

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
API occasionally returns duplicate uids within a page set). Swaps of
one repository run one at a time (see the lock).

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

###### `async def replace_domain_rulebases(self, mgmt_name: str, domain_name: str, rows: Sequence[SQLModel], state: RulebaseSyncState) -> int`

Atomically replace a domain's whole rulebase snapshot and its sync state.

One session and commit: deletes the domain's rows from the four rule tables, ``rulebase_layer``,
``rulebase_section`` and ``rulebase_package_layer`` (this also purges pre-v2 rule rows, whatever their id),
inserts ``rows`` (deduped by primary key) and merges ``state``. A failure rolls back to the previous snapshot
and state.

Returns:
    Number of rule rows inserted (all four types, place-holders included).

###### `async def get_rulebase_sync_state(self, mgmt_name: str, domain_name: str) -> RulebaseSyncState | None`

The domain's rulebase sync state, or None before its first rulebase refresh.

###### `async def mark_rulebase_sync_failed(self, mgmt_name: str, domain_name: str, error: str) -> None`

Record a failed refresh: status 'failed' and ``last_error``; ``session_uid`` and ``format_version`` stay.

###### `async def find_rulebase_layers(self, mgmt_name: str, layer: str, rulebase_type: str) -> list[tuple[str, str]]`

``(domain_name, layer_uid)`` of every cached layer of that type whose uid or name is ``layer``.

###### `async def find_rulebase_packages(self, mgmt_name: str, package: str) -> list[tuple[str, str]]`

``(domain_name, package_uid)`` of every cached package whose name or uid is ``package``.

###### `async def load_domain_rulebase_snapshot(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot | None`

The domain's cached rulebase snapshot (canonical order), or None when it has no sync state.

### `arodonata/cache/rulebase_rows.py`

A domain's rulebase snapshot as cache rows, and back. The only code that knows both shapes.

#### Module-Level Functions

##### `def build_rulebase_rows(snapshot: DomainRulebaseSnapshot) -> list[SQLModel]`

Rule, layer, section and package-layer rows of one domain (the sync state is built by the caller).

##### `def snapshot_from_rows(state: RulebaseSyncState, layer_rows: Iterable[RulebaseLayer], section_rows: Iterable[RulebaseSection], rule_rows: Iterable[Any], package_rows: Iterable[PolicyPackageLayer]) -> DomainRulebaseSnapshot`

Rebuild the snapshot in canonical order. Rule rows without ``layer_uid`` (pre-v2) are ignored.

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
api_keys: SecretStr = Field(default_factory=lambda: SecretStr(''), description='Comma-separated API keys (actual values)', validate_default=True)
username: str | None = Field(default=None, description='Username for credential-based auth', validation_alias='ARODONATA_USERNAME')
password: SecretStr | None = Field(default=None, description='Password for credential-based auth', validation_alias='ARODONATA_PASSWORD')
mgmt_ip: str | None = Field(default=None, description='Management server IP for credential mode', validation_alias='ARODONATA_MGMT_IP')
session_expire_seconds: int = Field(default=DEFAULT_SESSION_EXPIRE, ge=0, description='Session expiration in seconds', validation_alias='ARODONATA_SESSION_EXPIRE')
session_timeout: int = Field(default=DEFAULT_SESSION_TIMEOUT, ge=0, description='Session timeout in seconds (passed to login API)', validation_alias='ARODONATA_SESSION_TIMEOUT')
concurrent_limit: int = Field(default=DEFAULT_CONCURRENT_LIMIT, ge=1, le=20, description='Max concurrent API requests per MDS member (per server for a SmartCenter)', validation_alias='ARODONATA_CONCURRENT_LIMIT')
rate_limit_slot_timeout: int = Field(default=DEFAULT_RATE_LIMIT_SLOT_TIMEOUT, ge=1, description='Seconds a caller waits for a free concurrency slot (RateLimiter.acquire) before giving up. Size it for queueing behind other callers of the same MDS member: a call that waits for a task (publish, revert) holds its slot for the whole task, while listings release it between pages and a login holds it for one attempt only, never across its retries or a throttle wait.', validation_alias='ARODONATA_RATE_LIMIT_SLOT_TIMEOUT')
api_timeout: int = Field(default=DEFAULT_API_TIMEOUT, ge=1, description='API timeout in seconds', validation_alias='ARODONATA_API_TIMEOUT')
task_timeout: int = Field(default=DEFAULT_TASK_TIMEOUT, ge=1, description='Seconds to wait for a server-side task (publish, install-policy, assign-global-assignment, revert-to-revision) after the call that started it has returned. Separate from api_timeout on purpose: see DEFAULT_TASK_TIMEOUT', validation_alias='ARODONATA_TASK_TIMEOUT')
login_timeout: int = Field(default=DEFAULT_LOGIN_TIMEOUT, ge=1, description='Per-attempt login timeout in seconds (see DEFAULT_LOGIN_TIMEOUT)', validation_alias='ARODONATA_LOGIN_TIMEOUT')
login_throttle_window: int = Field(default=LOGIN_THROTTLE_WINDOW_SECONDS, ge=1, description="Seconds to wait for Check Point's login rate limit to clear before retrying a throttled login (see LOGIN_THROTTLE_WINDOW_SECONDS)", validation_alias='ARODONATA_LOGIN_THROTTLE_WINDOW')
login_max_wait: int = Field(default=DEFAULT_LOGIN_MAX_WAIT, ge=1, description="Total seconds one login() may spend waiting out Check Point's per-MDS login rate limit before failing; also the login-lock acquire timeout (see DEFAULT_LOGIN_MAX_WAIT)", validation_alias='ARODONATA_LOGIN_MAX_WAIT')
login_retry_backoff: int = Field(default=DEFAULT_LOGIN_BACKOFF, ge=1, description='Login retry backoff in seconds', validation_alias='ARODONATA_LOGIN_BACKOFF')
login_max_retries: int = Field(default=DEFAULT_LOGIN_RETRIES, ge=1, description='Maximum login retry attempts', validation_alias='ARODONATA_LOGIN_RETRIES')
warm_object_cache_on_first_use: bool = Field(default=True, description="When get_domains finds a management server's object cache empty, start loading every domain's objects in the background (get_domains itself returns the domain list at once)", validation_alias='ARODONATA_WARM_OBJECT_CACHE_ON_FIRST_USE')
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
tls_trust: str = Field(default=DEFAULT_TLS_TRUST, description="Certificate trust mode: 'tofu' (learn and persist) | 'pinned' | 'lab-memory' (lab runs only)", validation_alias='ARODONATA_TLS_TRUST')
tls_fingerprints: str = Field(default='', description="Comma-separated SHA-256 fingerprints trusted at any address (from 'api fingerprint -f json')", validation_alias='ARODONATA_TLS_FINGERPRINTS')
tls_known_hosts_path: str = Field(default='', description='Trust store file; empty means ${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json', validation_alias='ARODONATA_TLS_KNOWN_HOSTS_PATH')
connect_timeout: int = Field(default=DEFAULT_CONNECT_TIMEOUT, ge=1, description='Seconds for TCP connect plus TLS handshake to a Check Point server', validation_alias='ARODONATA_CONNECT_TIMEOUT')
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

###### `def tls_fingerprints_list(self) -> list[str]`

```python
@property
```
Normalised SHA-256 pins (64 lowercase hex digits each).

###### `def default_read_timeout(self) -> int`

```python
@property
```
Socket read timeout for calls that carry no budget of their own (spec D16).

###### `def api_keys_list(self) -> list[str]`

```python
@property
```
Parse comma-separated API keys to list.

Returns:
    List of API key values.

###### `def resolve_api_keys(cls, v: Any, info: ValidationInfo) -> SecretStr`

```python
@field_validator('api_keys', mode='before')
@classmethod
```
Resolve API keys with priority: explicit parameter or API_KEYS > API_KEY_VARS > default.

This allows both automatic environment reading AND explicit override support,
plus support for the API_KEY_VARS indirection pattern. The field validates its
default too, so a bare ``ArodonataSettings()`` resolves API_KEY_VARS.

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

###### `def validate_tls_trust(cls, v: Any) -> str`

```python
@field_validator('tls_trust', mode='before')
@classmethod
```
Must be one of the TrustMode values (case-insensitive).

###### `def validate_tls_fingerprints(cls, v: str) -> str`

```python
@field_validator('tls_fingerprints')
@classmethod
```
Every entry must be a SHA-256 fingerprint.

###### `def validate_credential_mode(self) -> ArodonataSettings`

```python
@model_validator(mode='after')
```
Validate that mgmt_ip is provided when using credential-based auth.

### `arodonata/config/tls.py`

TLS identity settings helpers: trust modes, SHA-256 fingerprint parsing, trust-store path.

Pure functions only (no cpapi, no sockets, no file writes), so `config.settings` can import them. The
verification itself lives in `arodonata.asdk.tls` (spec D1).

#### Module-Level Functions

##### `def normalize_sha256(value: str) -> str`

Return the 64 lowercase hex digits of a SHA-256 fingerprint, or raise ValueError with a hint.

##### `def parse_fingerprints(value: str) -> list[str]`

Parse ARODONATA_TLS_FINGERPRINTS: comma-separated SHA-256 values, blanks ignored.

##### `def colon_hex(hex_digits: str) -> str`

`ab01…` -> `AB:01:…`, the form `api fingerprint` and openssl print.

##### `def default_store_path() -> Path`

`${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json` (spec D11).

##### `def resolve_store_path(configured: str) -> Path`

The store file for ARODONATA_TLS_KNOWN_HOSTS_PATH; empty means the default, relative means cwd-relative.

#### class `TrustMode(StrEnum)`

How unknown Check Point server certificates are treated (spec D6).


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
failed_domains: list[tuple[str, str]] = field(default_factory=list)
fell_back: bool = False
skipped_reason: str | None = None
```
### `arodonata/core/cache_refresh_coordinator.py`

Coordinates cache freshness/refresh decisions ahead of reads.

#### class `CacheRefreshCoordinator`

Decides whether/how to refresh cache before a read, per CachePolicy.

##### Methods

###### `def __init__(self, cache: Any, api: Any, object_service: Any, session_tracker: Any = None, default_mode: CacheMode = CacheMode.SMART, default_ttl: int = 300, clock: Clock | None = None, max_incremental_changes: int = 500, member_of: MemberOf | None = None, domain_concurrency: int = 1) -> None`

Create the coordinator.

Args:
    cache: Cache repository.
    api: API facade used for change and head lookups.
    object_service: Object service that performs the reloads.
    session_tracker: Optional session tracker.
    default_mode: Cache mode used when a read names none.
    default_ttl: Freshness window in seconds for the smart modes.
    clock: Clock for freshness checks (tests inject one).
    max_incremental_changes: Largest change set applied incrementally before a full reload.
    member_of: Resolver `(mgmt, domain) -> MDS member`; `ensure` refreshes members in parallel and at most
        `domain_concurrency` domains of one member at once. Without it, domains group by management server
        name, so different servers refresh in parallel (previously they refreshed one after another) and
        the domains of one server share one `domain_concurrency` budget.
    domain_concurrency: Domain refreshes started at once per member per `ensure` call.

###### `async def ensure(self, scope: RefreshScope, policy: CachePolicy) -> RefreshOutcome`

Ensure cache satisfies `policy` over `scope` before a read.

###### `def invalidate(self, mgmt_name: str, domain_name: str) -> None`

Drop the TTL memo for a domain so the next check cannot be skipped.

### `arodonata/core/change_processor.py`

Change processor for parsing show-changes API responses.

#### Module-Level Functions

##### `def unwrap_change_entry(obj: Any) -> Any`

The object a show-changes operations entry describes.

Added and deleted entries are the object itself. Modified entries arrive
wrapped -- ``{"new-object": {...}}`` (seen on R82.20), with ``"old-object"``
as the fallback -- and carry no uid or type at the top level. Anything
else is returned unchanged so the caller's own checks still apply.

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

### `arodonata/core/domain_list_refresh.py`

Shared TTL bookkeeping for opportunistic domain-list re-fetches.

A management server's *domain list itself* (as opposed to any one domain's
objects/rulebases) used to only ever get re-fetched from the API when the
local domains table came back completely empty. That meant a domain created
in SmartConsole after the table was first seeded stayed invisible to every
refresh forever - both `arodonata.cache.object_service.ObjectService` and
`arodonata.api.services.rulebase_refresh_service.RulebaseRefreshService` had
this exact gap independently.

The fix is the same shape in both places: a force/full refresh always
re-fetches the domain list unconditionally, while a check/smart refresh
re-fetches it at most once per `DOMAIN_LIST_REFRESH_TTL_SECONDS` so repeated
smart-refresh ticks don't hammer `show-domains`. `DomainListRefreshTracker`
holds the per-mgmt "last re-fetched at" memo each service needs to make that
decision, mirroring `CacheRefreshCoordinator`'s `_ttl_fresh`/`_mark_checked`
pattern (inverted to "is stale" instead of "is fresh") but scoped to
mgmt-server domain discovery rather than per-(mgmt, domain) object staleness.

#### class `DomainListRefreshTracker`

Per-mgmt-name "when was the domain list last re-fetched" memo with a TTL.

##### Methods

###### `def __init__(self, ttl_seconds: int = DOMAIN_LIST_REFRESH_TTL_SECONDS, clock: Clock | None = None) -> None`

_No docstring._

###### `def is_stale(self, mgmt_name: str) -> bool`

True when `mgmt_name`'s domain list has never been re-fetched, or the TTL has
elapsed since it last was - i.e. an opportunistic re-fetch is due.

###### `def mark_checked(self, mgmt_name: str) -> None`

Record that `mgmt_name`'s domain list was just re-fetched.

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

#### class `ServerUnreachableError(ApiConnectionError)`

A management or domain server never answered at the address we used.

Distinct from every other login failure because the remedy is different: a
server that *answers* with a refusal (throttling, "Database revision is in
progress") clears on its own, so backing off and retrying the same address is
right. A server that answers nothing may simply not live at that address any
more -- Check Point's `show-domains` reports a domain's active server, and
that is exactly the value that can go stale. Retrying it cannot help; asking
where the domain moved can.

Carries `server_ip` so the log and the resulting AuthenticationError can name
the address that went silent.

##### Methods

###### `def __init__(self, message: str, *args: object, server_ip: str = '') -> None`

_No docstring._

#### class `AuthenticationError(ArodonataError)`

Authentication-related errors.

#### class `SessionExpiredError(AuthenticationError)`

Session has expired and needs relogin.

#### class `InvalidCredentialsError(AuthenticationError)`

Credentials are invalid.

#### class `PublishedHeadError(Exception)`

``show-last-published-session`` could not tell where a domain's head is (failed call, exception, no timestamp).

##### Methods

###### `def __init__(self, reason: str) -> None`

_No docstring._

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

#### class `TaskTimeoutError(ArodonataError, TimeoutError)`

A Check Point task did not finish within the caller's timeout budget.

Deliberately subclasses the builtin ``TimeoutError``: before self-managed
polling, a task timeout surfaced as a bare ``TimeoutError`` from
``asyncio.wait_for``, so every existing ``except TimeoutError`` handler in a
consuming application must keep catching this unchanged. What is new is only
the message and the two attributes -- the task-id, last observed status and
progress that the old bare ``TimeoutError`` never carried.

##### Methods

###### `def __init__(self, message: str, *args: object, task_ids: Sequence[str] = (), statuses: Sequence[Any] = ()) -> None`

_No docstring._

#### class `TaskPollError(ApiCallError)`

``show-task`` failed more times in a row than the waiter tolerates.

Subclasses ``ApiCallError`` so broad handlers keep working. cpapi raised its
own ``APIException`` here, which nothing in the compatibility contract names.

##### Methods

###### `def __init__(self, message: str, *args: object, task_ids: Sequence[str] = (), err_code: str | int | None = None, err_message: str | None = None) -> None`

_No docstring._

#### class `ServerIdentityError(ArodonataError)`

A Check Point server's TLS certificate is not the one trusted for that address. Nothing was sent.

Never retried: a different certificate does not fix itself. Deliberately not an ``OSError`` (cpapi would
re-send), an ``ApiConnectionError`` (login would re-resolve the domain) or an ``AuthenticationError`` (login
would wrap and retry it).

##### Methods

###### `def __init__(self, message: str, *args: object, host: str = '', port: int = 0, presented_sha256: str = '', presented_sha1: str = '', expected_sha256: str = '', source: str = '') -> None`

_No docstring._

#### class `CertificateMismatchError(ServerIdentityError)`

The server presented a different certificate than the one recorded or pinned for it.

#### class `UnknownServerCertificateError(ServerIdentityError)`

``ARODONATA_TLS_TRUST=pinned`` and the presented certificate is not trusted anywhere.

#### class `TrustStoreError(ConfigurationError)`

The TLS trust store cannot be read, is unsafe (owner/permissions), is corrupt, or cannot be written.

#### class `ApiTimeoutError(ArodonataError, TimeoutError)`

A socket connect or read to a Check Point server timed out. The request is never re-sent after a timeout.

(cpapi may already have re-sent it once after a dropped connection, before the timeout: Backlog #30.)
A ``TimeoutError`` subclass like ``TaskTimeoutError``, so existing ``except TimeoutError`` handlers keep working.
Every field has a default, so the error can be unpickled (the built-in reduce restores the fields).

##### Methods

###### `def __init__(self, message: str, *args: object, phase: str = '', host: str = '', port: int = 0, timeout: float = 0.0, command: str = '') -> None`

_No docstring._

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
and only on success, with the head the engine read before the diff.

#### class `FallbackToFull(Exception)`

Incremental apply would be unsafe; the caller must do a full reload.

#### class `IncrementalApplyResult`

```python
@dataclass(frozen=True)
```
Outcome of a successful incremental apply.

`head` is the domain's last-published session read BEFORE `show-changes`, so a publish after that read
stays after the stamp the caller stores and reaches the cache through the next refresh. None when the
engine was built without `fetch_head`; the caller then stores no stamp.

##### Fields / Class Variables

```python
applied: int
head: LastPublishedSession | None
```
#### class `IncrementalRefresher`

Applies a show-changes diff for one domain with re-fetch-in-full semantics.

##### Methods

###### `def __init__(self, *, api: Any, cache: Any, fetch_full_object: Callable[[str, str, str], Awaitable[dict[str, Any] | None]], to_cpobject: Callable[[dict[str, Any], str, str], CPObject | None], fetch_head: Callable[[str, str], Awaitable[LastPublishedSession | None]] | None = None, in_scope_types: frozenset[str] = DEFAULT_IN_SCOPE_TYPES, max_changes: int = DEFAULT_MAX_CHANGES) -> None`

_No docstring._

###### `async def apply(self, mgmt: str, domain: str) -> IncrementalApplyResult`

Apply all in-scope changes since the stored baseline.

Returns the number of rows written (upserts + deletes; 0 means the
publish touched nothing the object cache holds) and the head read
before the diff. Raises FallbackToFull whenever an incremental apply
would be unsafe. Never advances the baseline stamp — that is the
caller's responsibility, with the returned head.

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

###### `def __init__(self, cache: 'CachePort', api: 'ApiPort', session_tracker: 'SessionChangeTracker | None', coordinator: 'CacheRefreshCoordinator | None' = None, rulebase_coordinator: 'RulebaseRefreshCoordinator | None' = None) -> None`

Initialize orchestration service.

Args:
    cache: Cache implementation.
    api: API implementation.
    session_tracker: Session change tracker (optional for now).
    coordinator: Cache refresh coordinator (optional; when absent,
        read helpers skip cache-mode-driven refresh entirely).
    rulebase_coordinator: Rulebase refresh coordinator (optional; when
        absent, rule reads skip cache-mode-driven refresh).

###### `async def get_domains(self, mgmt_names: list[str] | None = None, cache_mode: 'CacheMode | str | None' = None, cache_ttl: int | None = None, include_global: bool = False) -> list['Domain']`

Get domains from cache (a pure read).

It never refreshes the object cache: listing domains must not load every domain's objects. The client
refreshes the domain list itself (``ArodonataClient.get_domains``).

Args:
    mgmt_names: Optional list of management server names to filter.
    cache_mode: Accepted for compatibility and ignored (this is a pure read).
    cache_ttl: Accepted for compatibility and ignored.
    include_global: When False (default), the "Global" domain
        is excluded so existing callers see today's behavior.

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
    layer_name: Optional policy package name filter; NAT rules are keyed by package, e.g. layer_name="Standard".
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
Interface for rate limiting per MDS member.

##### Methods

###### `async def acquire(self, server_ip: str) -> AsyncGenerator[None]`

```python
@asynccontextmanager
```
Acquire a rate limit slot; server_ip is the slot key (the MDS member hosting the target).

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
### `arodonata/core/rulebase_refresh_coordinator.py`

Decides whether a named domain's rulebase snapshot is refreshed before a rule read (spec 2.10).

#### class `RulebaseRefreshCoordinator`

Rulebase counterpart of CacheRefreshCoordinator.

Only explicitly named, non-empty domains are refreshed (a broad read serves the cache; ``''`` is never
refreshed; ``Global`` only when named), on the named mgmt servers, or on the first configured one when none is
named (an application that omits the mgmt has one server). SMART and SMART_FAST: TTL memo, then the service's session-uid check,
then a full domain refresh. FORCE: refresh, memo ignored. CACHE: nothing. The memo is marked after every
outcome, failures included, so a failing domain is retried at most once per TTL.

##### Methods

###### `def __init__(self, refresh_service: Any, api: Any, default_mode: CacheMode = CacheMode.SMART, default_ttl: int = 300, clock: Clock | None = None) -> None`

_No docstring._

###### `async def ensure(self, scope: RefreshScope, policy: CachePolicy) -> RefreshOutcome`

Refresh the named domains of ``scope`` that ``policy`` says are due.

###### `def invalidate(self, mgmt_name: str, domain_name: str) -> None`

Drop the TTL memo for a domain so the next smart read re-checks it.

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
timestamp: datetime = field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None))
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

### `arodonata/cpcrud/nat_sentinels.py`

Runtime resolver for Check Point's two platform-fixed NAT "empty cell" objects.

``NAT_ANY_OBJECT_UID``/``NAT_ORIGINAL_OBJECT_UID`` (see ``resolver.py``) were live-verified
identical on two independent Check Point installations (``mdsNP2.np.cparch.in`` and ``smsNP82``,
2026-09-03) and are safe to use as a hardcoded default. But they are still, in principle, values a
management server generates once at install time -- a customer's server could theoretically have
different UIDs for these objects. Writing a foreign UID into a live NAT rule's cell would either
fail loudly or, worse, silently write the wrong object into a customer's production rule.

This module resolves both UIDs at runtime, by name/type, once per management server, and caches
the result for the process. Resolution never blocks a NAT removal: any failure (API error, object
not found, unexpected response shape, missing package) degrades to the verified constant and logs
a warning. If a resolved UID ever *differs* from the constant, that is logged prominently at
warning level -- naming the management server, the object, and both UIDs -- since that is the
exact early-warning signal for the scenario this module exists to guard against.

The two objects need different resolution strategies, both empirically verified against
``mdsNP2.np.cparch.in`` (MDS, domain ``General``) and ``smsNP82`` (plain SmartCenter) on
2026-09-03:

* The "Any" object (type ``CpmiAnyObject``) IS a normal, catalog-listed object: a read-only
  ``show-objects`` call filtered by ``filter="Any", type="CpmiAnyObject"`` returns exactly one
  match on both servers, with a UID matching ``NAT_ANY_OBJECT_UID``.
* The "Original" object (type ``Global``) is NOT catalog-listed: ``show-objects`` rejects
  ``type="Global"`` outright ("Requested API type: [Global] not found"), and a name filter for
  "Original" with no type filter returns 15 unrelated objects, none of them the sentinel. It is
  only reachable indirectly, e.g. by reading it off a real NAT rule -- exactly how the constant
  itself was originally discovered (see ``resolver.py``'s module docstring above
  ``NAT_ORIGINAL_OBJECT_UID``). This module resolves it by reading a page of an existing NAT
  rulebase (the same package the caller is already operating against) and taking the first
  ``translated-*`` cell whose embedded object has type ``Global``.

#### Module-Level Functions

##### `def reset_nat_sentinel_cache() -> None`

Clear the per-process cache. Test-only; production code never needs to call this.

##### `async def resolve_nat_sentinel_uids(call: ApiCall, mgmt_name: str, package: str = '') -> NatSentinelUids`

Resolve (or fall back to) the "Any"/"Original" NAT sentinel UIDs for `mgmt_name`.

Resolved once per management server and cached for the process -- a second call for the same
`mgmt_name` returns the cached result without making any API call, regardless of `package`.

Args:
    call: Async `(command, payload) -> ApiCallResult`-shaped callable, e.g. MMP's
        `ApiSession.call` bound to the right management server/domain/session.
    mgmt_name: Management server name -- used only for cache keying and log messages, never
        sent on the wire (the caller's `call` already knows which server it targets).
    package: NAT policy package name/uid the caller is already operating against, used to
        resolve the "Original" object (see module docstring). If empty, "Original" resolution
        is skipped and the verified constant is used, with a warning.

Returns:
    NatSentinelUids with both UIDs -- resolved where possible, the verified constant
    otherwise. Never raises: any failure degrades to the constant.

#### class `NatSentinelUids`

```python
@dataclass(frozen=True)
```
The two resolved (or fallback) NAT sentinel UIDs for one management server.

##### Fields / Class Variables

```python
any_uid: str
original_uid: str
```
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

#### class `StateReadError(Exception)`

A StateReader lookup could not be completed (failed or partial listing).

Never means "not found": the planner turns it into an ERROR action for the whole operation, so
nothing is created on the strength of a lookup that did not happen (Backlog #37).

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

###### `async def get_last_rule_in_section(self, layer_uid: str, section_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None`

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

###### `async def get_last_rule_in_section(self, layer_uid: str, section_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None`

The last rule of a section, from a read of its LAYER: show-*-rulebase refuses a section uid (Backlog #40).

A section split across pages comes once per page here, so the last part holds its last rule.

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

The cache is used for a domain only while it is as new as the domain's head: the stored freshness stamp must be
the session the planner read with `get_last_publish_session` (Backlog #41). Otherwise, and before that read,
every lookup goes live: a row from before the last publish may be gone or changed on the server.

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

###### `async def get_last_rule_in_section(self, layer_uid: str, section_uid: str, layer_type: str, *, mgmt: str, domain: str) -> RuleMatch | None`

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

## mcp — Model Context Protocol (MCP) Server & Tools

### `arodonata/mcp/__init__.py`

MCP server support for Arodonata (optional extra ``arodonata[mcp]``).

Importing this package must never require the ``mcp`` SDK to be installed: only
``_sdk.py`` imports it directly, and every public name below is resolved lazily via
``__getattr__`` on first access, so ``import arodonata.mcp`` (or any of its submodules
that do not themselves need the SDK, e.g. ``arodonata.mcp.settings``) always succeeds.

_No public classes or functions in this module._

### `arodonata/mcp/__main__.py`

``arodonata-mcp``: serve Arodonata as a streamable-HTTP MCP server for a team.

#### Module-Level Functions

##### `def parse_args(argv: list[str] | None) -> argparse.Namespace`

_No docstring._

##### `def load_env_files(paths: list[str]) -> list[str]`

_No docstring._

##### `def build_settings(args: argparse.Namespace)`

_No docstring._

##### `async def serve(args: argparse.Namespace) -> None`

_No docstring._

##### `def configure_logging(level: str) -> None`

Root logging at ``level``; the SDK loggers in QUIET_SDK_LOGGERS at WARNING unless ``level`` is debug.

##### `def main(argv: list[str] | None = None) -> int`

_No docstring._

#### class `CLIArgumentError(Exception)`

A command-line usage error, reported by ``main`` as a single configuration-error line.

### `arodonata/mcp/_messages.py`

Zero-dependency constants shared by ``_sdk`` and the package ``__init__``.

This module must never import the ``mcp`` SDK (or anything else optional) so that
``arodonata.mcp.__init__`` can surface ``MISSING_EXTRA_MESSAGE`` without pulling in the
optional dependency it is warning about.

_No public classes or functions in this module._

### `arodonata/mcp/_sdk.py`

The one module allowed to import the ``mcp`` SDK.

Every other module under ``arodonata.mcp`` imports SDK names from here so the optional
dependency is guarded in exactly one place.

_No public classes or functions in this module._

### `arodonata/mcp/app.py`

Factories: a configured MCPServer and a mountable Starlette app.

#### Module-Level Functions

##### `def create_mcp_server(client: ArodonataClient, settings: ArodonataMCPSettings | None = None, *, name: str = 'arodonata', environ: Mapping[str, str] | None = None) -> MCPServer`

Build an MCPServer with Arodonata tools and the configured bearer-token verifier.

``auth_mode="jwt"`` is reserved but not implemented (see ``JwtTokenVerifier``): it is rejected here rather than
left to fail at request time, since the stub verifier raises ``NotImplementedError`` on every call.

##### `def create_asgi_app(client: ArodonataClient, settings: ArodonataMCPSettings | None = None, *, server: MCPServer | None = None) -> Starlette`

Starlette app serving streamable HTTP at ``settings.path``; mount it in a host app or run it with uvicorn.

The returned app's lifespan runs the MCP session manager only. The caller owns ``client`` (open it before serving,
close it after) and the database engine.

### `arodonata/mcp/auth.py`

Bearer-token verification for the MCP HTTP transport.

#### Module-Level Functions

##### `def build_token_verifier(settings: ArodonataMCPSettings, environ: Mapping[str, str] | None = None) -> TokenVerifier | None`

Return the verifier for ``settings.auth_mode``; ``None`` only for ``host`` mode.

#### class `StaticTokenVerifier`

Constant-time comparison against tokens resolved from named environment variables.

##### Methods

###### `def __init__(self, tokens: Mapping[str, SecretStr]) -> None`

_No docstring._

###### `async def verify_token(self, token: str) -> AccessToken | None`

_No docstring._

#### class `JwtTokenVerifier`

Reserved: JWT verification against an identity provider (see spec, 'Reserved JWT mode').

##### Methods

###### `def __init__(self, issuer: str, audience: str, jwks_url: str) -> None`

_No docstring._

###### `async def verify_token(self, token: str) -> AccessToken | None`

_No docstring._

### `arodonata/mcp/cached_tools.py`

Reference-named ``show_*`` tools answered from the Arodonata cache.

#### Module-Level Functions

##### `def register_cached_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]`

_No docstring._

### `arodonata/mcp/change_report_tools.py`

MCP tool change_report: read-only evidence of what policy sessions changed, as markdown (spec 7).

#### Module-Level Functions

##### `def register_change_report_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]`

_No docstring._

### `arodonata/mcp/common.py`

Helpers shared by every MCP tool: server resolution, error mapping, envelopes, JSON.

#### Module-Level Functions

##### `def log_tool_call(name: str, access_token: AccessToken | None) -> None`

Log one INFO line naming the tool and the caller identity.

The caller identity is the access token's ``client_id`` (the token's environment-variable name, see
``auth.py``), or ``anonymous`` when the request carries none (stdio, or HTTP without auth). Never logs the
token value, the tool arguments or the result.

##### `def describe_for_model(exc: ServerIdentityError | TrustStoreError | ApiTimeoutError) -> str`

Tool-facing text: the facts, never a ready-to-run command that would re-pin the presented certificate.

The MCP client may have a shell on the MCP host, so the text names no ``ARODONATA_TLS_FINGERPRINTS=<value>``
command; the operator gets the full message from the server log (spec D21). No SID or key either. The identity
text names where the expected value came from (``(from <store path>)``, or ``this process (lab-memory)``) so the
operator knows what to edit; trust-store and timeout texts carry no path.

##### `def add_guarded_tool(server: MCPServer, fn: Callable[..., Awaitable[Any]], *, name: str, description: str | None = None) -> None`

Register ``fn`` with exception redaction and plain JSON-text output.

Unexpected exceptions are logged with their traceback and surfaced as ``internal error: <Class>`` so payload text
never leaks to the caller. ``structured_output=False`` keeps results as JSON text (the SDK would otherwise wrap
``dict``/``str`` returns in a ``{"result": ...}`` object).

A ``ToolError`` (including ``ToolFailure``) is returned as an already-built error ``CallToolResult`` rather than
re-raised: the installed SDK's ``Tool.run()`` unconditionally prefixes any ``ToolError`` that escapes the tool
body with ``"Error executing tool <name>: "`` before it reaches the client. Returning the result directly instead
of raising bypasses that prefix, so the model sees exactly the message the tool raised.

##### `def resolve_mgmt_name(client: ArodonataClient, mgmt_name: str | None) -> str`

_No docstring._

##### `def ensure_success(result: ApiCallResult | ApiQueryResult, command: str) -> None`

_No docstring._

##### `def to_api_payload(args: dict[str, Any]) -> dict[str, Any]`

Drop ``None`` values and convert snake_case keys to the API's kebab-case, recursively for dicts.

##### `def list_envelope(objects: list[Any], *, offset: int, limit: int, total: int, source: str, cache_age_seconds: int | None = None, key: str = 'objects') -> dict[str, Any]`

_No docstring._

##### `def dump_json(obj: Any) -> str`

_No docstring._

##### `def truncate_json(text: str, max_chars: int, *, offset: int, returned: int, total: int) -> str`

_No docstring._

#### class `ToolFailure(ToolError)`

A tool-level failure returned to the model as an error result (never a traceback).

### `arodonata/mcp/compat.py`

Build live ``show_*`` tool handlers from ``MANIFEST`` with synthesized signatures.

#### Module-Level Functions

##### `def build_handler(entry: CompatTool, client: ArodonataClient, opts: ToolOptions) -> Callable[..., Coroutine[Any, Any, str]]`

_No docstring._

##### `def register_live_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]`

_No docstring._

### `arodonata/mcp/cpcrud_tools.py`

Opt-in cpcrud tools: validate, plan, apply (dry-run by default), inverse.

#### Module-Level Functions

##### `def template_to_dict(template: str | dict[str, Any]) -> dict[str, Any]`

Turn a caller-supplied template into a dict without ever touching the server's filesystem.

cpcrud's own loader treats a ``str`` that names an existing file as a path and reads it, so a ``str`` must never
reach cpcrud from an MCP caller: it is parsed here as YAML (a superset of JSON) instead.

##### `def register_cpcrud_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]`

_No docstring._

### `arodonata/mcp/manifest.py`

Data-only description of the live ``show_*`` tools (mirrors @chkp/quantum-management-mcp).

#### class `ParamSpec`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
name: str
kind: ParamKind
description: str = ''
default: Any = None
```
#### class `CompatTool`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
name: str
command: str
kind: Literal['list', 'single']
container_key: str = 'objects'
params: tuple[ParamSpec, ...] = ()
description: str = ''
```
### `arodonata/mcp/native.py`

Tools that have no counterpart in the reference server.

#### Module-Level Functions

##### `async def drain_events(events: AsyncIterator[SSEEvent], ctx: Context | None) -> tuple[dict[str, Any], dict[str, Any], list[str], list[str]]`

Consume a facade event stream. Returns (result_data, complete_data, warnings, errors).

##### `async def drain_search_events(events: AsyncIterator[SSEEvent], ctx: Context | None) -> tuple[list[dict[str, Any]], dict[str, Any], list[str], list[str]]`

Consume ``search_objects``' event stream. Returns (results, complete_data, warnings, errors).

``search_service.search_objects`` streams each domain's matches inside ``LOG`` events' ``data``
(keys: mgmt_name, domain, search_term, search_type, objects, memberships) rather than a single
``RESULT`` event, so every ``LOG`` event carrying an ``objects`` key is collected as one result
entry. A ``RESULT`` event is still honoured if one is ever emitted and has the same shape (an
``objects`` key), for forward/backward compatibility with the facade.

##### `def register_native_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]`

_No docstring._

### `arodonata/mcp/projection.py`

Project a cached raw API object to the requested ``details-level``.

#### Module-Level Functions

##### `def project(raw: dict[str, Any], details_level: str) -> dict[str, Any]`

_No docstring._

##### `def cache_age_seconds(last_update: datetime | None, now: datetime | None = None) -> int | None`

_No docstring._

### `arodonata/mcp/prompts.py`

Guidance prompts, adapted from the reference server to Arodonata tool names.

#### Module-Level Functions

##### `def register_prompts(server: MCPServer, opts: ToolOptions) -> list[str]`

_No docstring._

### `arodonata/mcp/registry.py`

Register Arodonata tools and prompts on a caller-owned ``MCPServer``.

#### Module-Level Functions

##### `def register_arodonata_tools(server: MCPServer, client: ArodonataClient, *, live_compat: bool = True, cpcrud: bool = False, allow_write_api: bool = False, tool_prefix: str = '', default_limit: int = 50, max_result_chars: int = 200000) -> RegisteredTools`

Add the Arodonata tool set to ``server``. The caller owns ``client`` and its lifecycle.

#### class `ToolOptions`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
tool_prefix: str = ''
default_limit: int = 50
max_result_chars: int = 200000
allow_write_api: bool = False
```
##### Methods

###### `def name(self, base: str) -> str`

_No docstring._

#### class `RegisteredTools`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
cached: tuple[str, ...] = field(default_factory=tuple)
live: tuple[str, ...] = field(default_factory=tuple)
native: tuple[str, ...] = field(default_factory=tuple)
cpcrud: tuple[str, ...] = field(default_factory=tuple)
```
##### Methods

###### `def all(self) -> tuple[str, ...]`

```python
@property
```
_No docstring._

### `arodonata/mcp/rulebase_format.py`

Turn numbered rulebase entries (cache or live) into rows, then into markdown or compact structured text.

Ported in spirit from the reference server's rulebase parser. The reference's padded fixed-width table is intentionally
not reproduced (decision 2026-09-27): cells always carry full values.

#### Module-Level Functions

##### `def layer_header(name: str) -> RuleRow`

The header row printed before an ordered layer when a package view shows several.

##### `def rows_from_entries(entries: Sequence[NumberedEntry], layer_names: Mapping[str, str], layer_dictionaries: Mapping[str, Sequence[Mapping[str, str]]]) -> list[RuleRow]`

Rows of numbered entries; references resolve through the dictionary of the layer that holds each entry.

##### `def drop_disabled(entries: Sequence[NumberedEntry]) -> list[NumberedEntry]`

Remove disabled rules and their inline subtree (deeper entries that follow); numbers are unchanged.

##### `def package_layers(result: PackageRulebase, layer: str | None = None, *, enabled_only: bool = False) -> list[OrderedEntries]`

The package's ordered layers, or only the one whose uid or name is ``layer``; ``enabled_only`` applies
``drop_disabled`` to each.

Raises:
    LookupError: ``layer`` is not an ordered layer of the package (the message lists the package's layers).

##### `def rows_from_package(result: PackageRulebase, layers: Sequence[OrderedEntries] | None = None) -> list[RuleRow]`

Rows of a package's ordered layers (default: all of them; pass ``package_layers(...)`` to narrow or filter),
with a ``layer`` header row before each when there are several.

##### `def raw_entries(entries: Sequence[NumberedEntry], details_level: str) -> list[dict[str, Any]]`

``format='raw'`` entries: rules/place-holders as projected raw items plus number/depth/layer; sections and parent
rules as small records.

##### `def raw_package_entries(layers: Sequence[OrderedEntries], details_level: str) -> list[dict[str, Any]]`

``format='raw'`` entries of a package view, with an ``ordered-layer`` record before each layer when there are
several (the same rule as the header rows of ``rows_from_package``).

##### `def rows_from_live(response: dict[str, Any], rulebase_type: RulebaseType = 'access') -> list[RuleRow]`

Rows of one live layer, numbered with sections; inline layers are named, not expanded (one layer fetched).

##### `def render_markdown(rows: Sequence[RuleRow], title: str) -> str`

_No docstring._

##### `def render_model_friendly(rows: Sequence[RuleRow], title: str) -> str`

_No docstring._

#### class `RuleRow`

```python
@dataclass
```
_No docstring._

##### Fields / Class Variables

```python
number: str
name: str
enabled: bool
sources: list[str]
destinations: list[str]
services: list[str]
action: str
track: str
section: str = ''
inline_layer: str = ''
comments: str = ''
depth: int = 0
negate: dict[str, bool] = field(default_factory=dict)
extra: dict[str, str] = field(default_factory=dict)
kind: str = 'rule'
section_range: str = ''
```
### `arodonata/mcp/rulebase_tools.py`

show_*_rulebase tools: cache-backed by default, live when a live-only parameter is given.

#### Module-Level Functions

##### `def register_rulebase_tools(server: MCPServer, client: ArodonataClient, opts: ToolOptions) -> list[str]`

_No docstring._

### `arodonata/mcp/settings.py`

Settings for the Arodonata MCP server (env prefix ``ARODONATA_MCP_``).

#### class `ArodonataMCPConfigError(ValueError)`

Raised when MCP settings are inconsistent (e.g. static auth with no tokens).

#### class `ArodonataMCPSettings(BaseSettings)`

Server-side configuration. Library settings (``ArodonataSettings``) are separate and unchanged.

##### Fields / Class Variables

```python
host: str = Field(default='127.0.0.1', description='Bind address')
port: int = Field(default=8765, ge=1, le=65535)
path: str = Field(default='/mcp', description='Streamable HTTP path')
public_url: str = Field(default='http://127.0.0.1:8765/mcp', description='URL clients use; resource_server_url')
stateless: bool = Field(default=True)
json_response: bool = Field(default=True)
live_compat: bool = Field(default=True, description='Register live show_* tools from the manifest')
cpcrud: bool = Field(default=False, description='Register cpcrud validate/plan/apply/inverse tools')
allow_write_api: bool = Field(default=False, description='Allow non show-* commands through api_call')
auth_mode: Literal['static', 'jwt', 'host'] = Field(default='static')
token_vars: str = Field(default='', description='Comma-separated env var names holding bearer tokens')
jwt_issuer: str = Field(default='')
jwt_audience: str = Field(default='')
jwt_jwks_url: str = Field(default='')
default_limit: int = Field(default=50, ge=0)
max_result_chars: int = Field(default=200000, ge=1000)
shutdown_timeout: int = Field(default=5, ge=0, description='Seconds Ctrl+C waits for open client connections and for SDK calls stuck in network I/O')
allowed_hosts: str = Field(default='', description='Comma-separated Host header values accepted (DNS-rebinding protection); default derives from host, port and public_url')
allowed_origins: str = Field(default='', description='Comma-separated Origin values accepted; default derives from public_url')
```
##### Methods

###### `def token_var_names(self) -> list[str]`

```python
@property
```
_No docstring._

###### `def allowed_hosts_list(self) -> list[str]`

```python
@property
```
_No docstring._

###### `def allowed_origins_list(self) -> list[str]`

```python
@property
```
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

Every reference field resolves through ``context.objects_map`` ({uid: name}, built from the response's
``objects-dictionary``) and falls back to the uid when unresolved. ``layer_name`` is not extracted: rules do not
carry their layer; the caller sets it from the response's top-level ``name`` (NAT: the package name).

#### Module-Level Functions

##### `def resolve_ref(value: Any, objects_map: dict[str, str] | None) -> str`

One reference as a name: a uid string via ``objects_map``; a dict by its ``name``, else its resolved ``uid``.

#### class `AccessRuleExtractor(BaseExtractor)`

Extractor for access control rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from an access rule.

Args:
    raw_data: One rule from a ``show-access-rulebase`` response.
    context: Extraction context with mgmt/domain info and the layer's objects map.

Returns:
    Fields for ``RulebaseAccess`` except ``id`` and ``layer_name``.

#### class `NATRuleExtractor(BaseExtractor)`

Extractor for NAT rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from a NAT rule (fields for ``RulebaseNAT`` except ``id`` and ``layer_name``).

#### class `HTTPSRuleExtractor(BaseExtractor)`

Extractor for HTTPS inspection rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from an HTTPS rule (fields for ``RulebaseHTTPS`` except ``id`` and ``layer_name``).

#### class `ThreatRuleExtractor(BaseExtractor)`

Extractor for threat prevention rules.

##### Methods

###### `def extract(self, raw_data: dict, context: ExtractionContext) -> dict[str, Any]`

Extract model fields from a threat rule (fields for ``RulebaseThreat`` except ``id`` and ``layer_name``).


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
active_mds_ip: str = ''
standby_ips: list[str] = []
standby_servers: list[str] = []
standby_mdss: list[str] = []
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
layer_uid: str | None = None
section_uid: str | None = None
inline_layer_uid: str | None = None
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
auto_generated: bool = False
layer_uid: str | None = None
section_uid: str | None = None
inline_layer_uid: str | None = None
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
layer_uid: str | None = None
section_uid: str | None = None
inline_layer_uid: str | None = None
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
layer_uid: str | None = None
section_uid: str | None = None
inline_layer_uid: str | None = None
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

###### `async def get_domains(self, mgmt_names: list[str] | None = None, include_global: bool = False) -> list['Domain']`

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

###### `async def get_rulebase_sync_state(self, mgmt_name: str, domain_name: str) -> 'RulebaseSyncState | None'`

The domain's rulebase sync state, or None before its first rulebase refresh.

###### `async def load_domain_rulebase_snapshot(self, mgmt_name: str, domain_name: str) -> 'DomainRulebaseSnapshot | None'`

The domain's cached rulebase snapshot, or None when it has no sync state.

###### `async def find_rulebase_layers(self, mgmt_name: str, layer: str, rulebase_type: str) -> list[tuple[str, str]]`

(domain_name, layer_uid) of cached layers of that type matching ``layer`` by uid or name.

###### `async def find_rulebase_packages(self, mgmt_name: str, package: str) -> list[tuple[str, str]]`

(domain_name, package_uid) of cached packages matching ``package`` by name or uid.


---

## utils — Utility Functions

### `arodonata/utils/__init__.py`

Utility functions for Arodonata library.

_No public classes or functions in this module._

### `arodonata/utils/background_tasks.py`

Shut down a client's background tasks without cutting them off mid-operation.

#### Module-Level Functions

##### `async def drain_background_tasks(tasks: Iterable[asyncio.Task[None]], grace: float) -> None`

Wait up to `grace` seconds for `tasks` to finish, then cancel the rest.

Cancelling straight away interrupts a task wherever it happens to be: a
keepalive sweep holding a pooled SQLite connection then fails the pool's
rollback, and SQLAlchemy logs a CancelledError traceback. Waiting first lets
such work release its resources normally.

Never raises for the tasks' own failures: background work is best effort
and must not break close().

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

_No public classes or functions in this module._

### `arodonata/services/search_service.py`

Search service for Check Point objects across management servers and domains.

Orchestrates input parsing, cache queries, group membership resolution with
cycle protection, and SSE event streaming.

#### class `SearchService`

Service providing search across Check Point objects with SSE streaming.

##### Methods

###### `def __init__(self, object_service: ObjectService, refresh_objects_fn: Callable[..., AsyncGenerator[SSEEvent]]) -> None`

Initialize SearchService.

Args:
    object_service: ObjectService for database cache lookups and group resolution.
    refresh_objects_fn: Callable delegating to object cache refresh generator.

###### `async def search_objects(self, search_input: str, mgmt_names: list[str] | None = None, domain_names: list[str] | None = None, refresh: Literal['skip', 'check', 'force', 'incremental'] = 'skip', max_depth: int = 2) -> AsyncGenerator[SSEEvent]`

```python
@traced
```
Search for Check Point objects with cache-first queries and SSE streaming.

Args:
    search_input: Comma-separated search terms.
    mgmt_names: Optional management server filter.
    domain_names: Optional domain filter.
    refresh: Refresh mode - "skip", "check", "force", or "incremental".
    max_depth: Maximum depth for group membership traversal.

Yields:
    SSEEvent with refresh progress and domain-grouped search results.


---

## reports

### `arodonata/reports/__init__.py`

Reports built on arodonata (namespace).

_No public classes or functions in this module._

### `arodonata/reports/changes/__init__.py`

Change report: Check Point show-changes of sessions turned into evidence (HTML, JSON, markdown).

Importing this package loads neither Jinja2 nor MarkupSafe nor the MCP SDK; HTML needs the ``report`` extra.

_No public classes or functions in this module._

### `arodonata/reports/changes/_messages.py`

Messages that must import nothing optional.

_No public classes or functions in this module._

### `arodonata/reports/changes/build.py`

Pure: one show-changes session entry -> SessionChanges (spec 4).

added-objects -> added; deleted-objects -> deleted (the body is the pre-session state); modified-objects with
old-object -> modified, without old-object -> added (created in the session). Rules get one cell per data column and,
when modified, field deltas; objects, sections, other and internal types get key values and field deltas.

#### Module-Level Functions

##### `def session_uid(entry: dict[str, Any]) -> str`

_No docstring._

##### `def published_at(meta: dict[str, Any]) -> datetime | None`

``publish-time.posix`` (milliseconds) as an aware UTC datetime; None for an unpublished session.

##### `def classify(obj_type: str) -> Category`

_No docstring._

##### `def ref(value: Any) -> NamedRef | None`

A reference: dereferenced object -> uid and name; bare uid string -> the uid as both (names.py resolves).

##### `def refs(value: Any) -> list[NamedRef]`

_No docstring._

##### `def build_session(entry: dict[str, Any]) -> SessionChanges`

One show-changes session entry as SessionChanges; numbering source "none" and no rulebase blocks yet.

### `arodonata/reports/changes/collect.py`

Collect a change report: show-changes per session or range through the shared session, then build, member
names and numbering (spec 2.2, 2.3, 4, 5).

#### Module-Level Functions

##### `def cache_domain(domain: str) -> str`

_No docstring._

##### `async def collect_change_report(client: ArodonataClient, scopes: Iterable[Scope], *, include_raw: bool = False, concurrency: int = 4, max_sessions: int | None = None, now: Callable[[], datetime] = _utcnow) -> ChangeReport`

```python
@traced
```
Collect the changes of the given scopes into one ChangeReport (spec 2.2). Errors become warnings; only
invalid input raises (ChangeReportInputError, or pydantic's ValidationError when the scope was built).

#### class `RuleLocator(Protocol)`

Structural subset of RulebaseSource that numbering needs (spec 5.1).

##### Methods

###### `async def locate_rules(self, mgmt_name: str, domain_name: str, rule_uids: Collection[str] = (), rulebase_type: RulebaseType | None = None, *, layer_uids: Collection[str] = ()) -> RuleLocations`

_No docstring._

#### class `CacheLocator`

```python
@dataclass(frozen=True)
```
RuleLocator over the client facade with a fixed cache_mode ("smart", or "force" for the D19 re-locate).

##### Fields / Class Variables

```python
client: Any
mode: str
```
##### Methods

###### `async def locate_rules(self, mgmt_name: str, domain_name: str, rule_uids: Collection[str] = (), rulebase_type: RulebaseType | None = None, *, layer_uids: Collection[str] = ()) -> RuleLocations`

_No docstring._

### `arodonata/reports/changes/columns.py`

Column specs per rulebase (SmartConsole-like), report order, object key fields and compare allowlists (spec 4).

Field names are pinned by test_column_fields_exist_in_recordings (fixtures/rule_field_names.json, plan decision 1).

#### Module-Level Functions

##### `def is_internal_type(obj_type: str) -> bool`

CamelCase CP bookkeeping types (AccessPolicy, NatRulebase, ...); real API types are kebab-case.

##### `def data_columns(kind: RulebaseKind) -> tuple[Column, ...]`

_No docstring._

##### `def key_value(obj_type: str, body: dict[str, Any]) -> str`

The value shown for an added or deleted object (address, subnet, range, port, ICMP type).

##### `def visible_columns(kind: RulebaseKind, rules: Iterable[RuleChange]) -> list[str]`

Column keys of one table: structural columns always; a data column when any row's cell is not default.

#### class `Column`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
key: str
title: str
field: str | None
kind: ColumnKind
negate_field: str | None = None
default_names: tuple[str, ...] = ('Any',)
structural: bool = False
```
### `arodonata/reports/changes/markup.py`

Limited markdown for titles and header fields, and markdown escaping for CP-sourced strings (spec 6.2).

Allowed: ``**bold**``, ``*italic*``, `` `code` ``, ``[text](url)`` with an http, https or mailto URL without control
characters; no nesting except plain text inside bold/italic; unclosed markers are literal. Standard library only:
MarkupSafe arrives only with the ``report`` extra, so the markdown and JSON paths must not import it.

#### Module-Level Functions

##### `def inline_html(text: str) -> str`

Escaped HTML built from escaped parts only; render_html.py wraps it in markupsafe.Markup.

##### `def escape_md(text: str) -> str`

Backslash-escape markdown metacharacters (backslash included) and fold newlines into spaces.

##### `def inline_markdown(text: str) -> str`

Markdown: the allowed constructs kept, everything else escaped.

### `arodonata/reports/changes/model.py`

The change report: one JSON-serialisable model, the single source for every renderer (spec 3).

#### class `ReportWarning(_Model)`

codes: domain_unavailable, session_not_found, owned_session_not_used, owned_session_error,
owned_session_conflict, live_numbering_degraded, numbering_failed, names_unresolved, range_truncated

##### Fields / Class Variables

```python
mgmt: str
domain: str
code: str
message: str
severity: Literal['info', 'warning'] = 'warning'
session_uid: str | None = None
```
#### class `RequestedScope(_Model)`

What the caller asked for; never a SID.

##### Fields / Class Variables

```python
kind: Literal['session', 'range']
mgmt_name: str
domain: str
session_uids: list[str] = Field(default_factory=list)
from_session: str | None = None
to_session: str | None = None
from_date: UtcDatetime | None = None
to_date: UtcDatetime | None = None
owned_session_supplied: bool = False
```
#### class `RawResponse(_Model)`

_No docstring._

##### Fields / Class Variables

```python
mgmt: str
domain: str
request: dict[str, Any]
success: bool
code: str = ''
message: str = ''
response: dict[str, Any] | None = None
```
#### class `NumberingInfo(_Model)`

_No docstring._

##### Fields / Class Variables

```python
source: Literal['cache', 'live', 'none']
snapshot_session_uid: str | None = None
snapshot_published_at: UtcDatetime | None = None
snapshot_refreshed_at: UtcDatetime | None = None
status: str = 'none'
last_error: str | None = None
provisional: bool = False
global_packages: bool = False
```
#### class `NamedRef(_Model)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
```
#### class `CellItem(_Model)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
status: ItemStatus = 'unchanged'
anchor: str | None = None
```
#### class `Cell(_Model)`

_No docstring._

##### Fields / Class Variables

```python
items: list[CellItem] | None = None
text: str | None = None
changed: bool = False
negated: bool = False
default: bool = False
```
#### class `FieldChange(_Model)`

_No docstring._

##### Fields / Class Variables

```python
field: str
old: str | None = None
new: str | None = None
removed: list[NamedRef] = Field(default_factory=list)
added: list[NamedRef] = Field(default_factory=list)
```
#### class `RuleChange(_Model)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
type: str
rulebase: RulebaseKind
name: str = ''
status: ChangeStatus
enabled: bool
enabled_changed: bool = False
layer_uid: str | None
position: int | None
old_layer_uid: str | None = None
old_position: int | None = None
moved: bool = False
inline_layer_uid: str | None = None
cells: dict[str, Cell]
changes: list[FieldChange] = Field(default_factory=list)
other_fields: list[str] = Field(default_factory=list)
anchor_base: str
```
#### class `RulePlacement(_Model)`

_No docstring._

##### Fields / Class Variables

```python
kind: Literal['rule'] = 'rule'
rule_uid: str
anchor: str
number: str | None
previous_number: str | None = None
basis: NumberBasis
section_uid: str | None = None
section_name: str | None = None
section_range: str | None = None
section_position: int | None = None
```
#### class `SectionHeader(_Model)`

_No docstring._

##### Fields / Class Variables

```python
kind: Literal['section'] = 'section'
uid: str | None
name: str
range: str | None
status: ChangeStatus | None = None
changes: list[FieldChange] = Field(default_factory=list)
```
#### class `LayerBlock(_Model)`

_No docstring._

##### Fields / Class Variables

```python
ordered_layer_name: str
ordered_layer_position: int
rows: list[Annotated[RulePlacement | SectionHeader, Field(discriminator='kind')]]
```
#### class `PackageBlock(_Model)`

_No docstring._

##### Fields / Class Variables

```python
package_name: str
layers: list[LayerBlock]
```
#### class `RulebaseBlock(_Model)`

_No docstring._

##### Fields / Class Variables

```python
rulebase: RulebaseKind
packages: list[PackageBlock]
unplaced: list[RulePlacement] = Field(default_factory=list)
columns: list[str]
```
#### class `ObjectChange(_Model)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
type: str
name: str
status: ChangeStatus
category: Literal['object', 'section', 'other']
internal: bool = False
key_value: str = ''
changes: list[FieldChange] = Field(default_factory=list)
other_fields: list[str] = Field(default_factory=list)
anchor: str
```
#### class `SessionChanges(_Model)`

_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
description: str = ''
user_name: str = ''
published: bool
published_at: UtcDatetime | None
numbering: NumberingInfo
rules: list[RuleChange]
rulebases: list[RulebaseBlock]
sections: list[ObjectChange]
objects: list[ObjectChange]
other: list[ObjectChange]
internal: list[ObjectChange]
```
#### class `DomainError(_Model)`

_No docstring._

##### Fields / Class Variables

```python
code: str
message: str
```
#### class `DomainChanges(_Model)`

_No docstring._

##### Fields / Class Variables

```python
domain: str
display_name: str
unavailable: DomainError | None = None
sessions: list[SessionChanges]
```
#### class `MgmtChanges(_Model)`

_No docstring._

##### Fields / Class Variables

```python
mgmt_name: str
domains: list[DomainChanges]
```
#### class `ChangeReport(_Model)`

_No docstring._

##### Fields / Class Variables

```python
format_version: int = FORMAT_VERSION
generated_at: UtcDatetime
arodonata_version: str
requested: list[RequestedScope]
servers: list[MgmtChanges]
warnings: list[ReportWarning] = Field(default_factory=list)
raw: list[RawResponse] | None = None
```
### `arodonata/reports/changes/names.py`

Bare-uid names (group members, NAT references): the session's own entries first, then read-only show-object
through the shared session (at most NAME_LOOKUP_CAP per report), else the uid itself (spec 4, D26).

#### Module-Level Functions

##### `def known_names(value: Any, into: dict[str, str] | None = None) -> dict[str, str]`

uid -> name of every object body or dereferenced reference anywhere in a session entry.

##### `def unresolved_uids(session: SessionChanges) -> set[str]`

_No docstring._

##### `def apply_names(session: SessionChanges, names: dict[str, str]) -> SessionChanges`

Replace unresolved names (name == uid) found in ``names``.

##### `async def resolve_names(client: ArodonataClient, mgmt: str, domain: str, built: list[tuple[SessionChanges, dict[str, Any]]], budget: NameBudget, concurrency: int) -> tuple[list[SessionChanges], ReportWarning | None]`

Names for one domain's sessions; one names_unresolved warning with the count of uids left as uids.

#### class `NameBudget`

```python
@dataclass
```
show-object lookups left for the whole report.

##### Fields / Class Variables

```python
remaining: int = NAME_LOOKUP_CAP
```
##### Methods

###### `def take(self, wanted: int) -> int`

_No docstring._

### `arodonata/reports/changes/placement.py`

Pure: SessionChanges + RuleLocations -> numbered RulebaseBlocks (spec 5.2 as amended by D27).

show-changes gives ``position`` only for rules the session moved (and for added and deleted rules), counted within
the rule's section (lab F1/F2). Numbers therefore come from ``locations`` (cache or live) or ``prior`` (the cache's
pre-session state of an unpublished session) wherever the rule is there; a position becomes a number only in a layer
without sections, otherwise the placement carries ``section_position``. Per rule: (1) in locations — for basis
provisional only when unmoved; (2) positional with the session's position; (3) in an inline layer created in the
session: the parent's number + "." + position; (4) deleted: its prior (else locations) number, else positional with the
pre-session layer/position, else the deleted parent; (5) otherwise "Not placed in a package".

#### Module-Level Functions

##### `def number_key(number: str | None) -> tuple[int, ...]`

'2.2.1' -> (2, 2, 1); None (or a non-numeric number) sorts last.

##### `def place_session(session: SessionChanges, locations: RuleLocations | None, *, basis: NumberBasis, prior: RuleLocations | None = None) -> SessionChanges`

Number every rule of the session and group it: rulebase (RULEBASE_ORDER) > package > ordered layer > number.

``prior`` is the cache's pre-session state of an unpublished session (deleted rules, previous numbers).

### `arodonata/reports/changes/render.py`

Render a ChangeReport into the requested formats only (spec 6.1). No Check Point access; a stored report
(``ChangeReport.model_validate_json``) re-renders identically. HTML needs the ``report`` extra (lazy import).

#### Module-Level Functions

##### `def render_json(report: ChangeReport, options: RenderOptions) -> bytes`

_No docstring._

##### `def render_change_report(report: ChangeReport, formats: Collection[ReportFormat] = (), options: RenderOptions | None = None) -> ChangeReportResult`

```python
@traced
```
Build only the requested formats; ``report`` is always returned.

#### class `RenderOptions(BaseModel)`

``title`` and ``header_fields`` accept limited markdown (bold, italic, code, http/https/mailto links).

##### Fields / Class Variables

```python
title: str = 'Policy change report'
header_fields: dict[str, str] = Field(default_factory=dict)
generated_by: str | None = None
markdown_max_rules: int | None = None
markdown_max_objects: int | None = None
```
#### class `ChangeReportResult`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
report: ChangeReport
html: bytes | None = None
json: bytes | None = None
markdown: str | None = None
pdf: bytes | None = None
```
#### class `UnsupportedFormat(ValueError)`

A known but not (yet) supported format, e.g. 'pdf' (reserved).

### `arodonata/reports/changes/render_html.py`

HTML change report, layout A: one self-contained file, Jinja2 with autoescape on (spec 6.3). Needs the 'report'
extra; imported lazily by render.py only.

#### Module-Level Functions

##### `def render_html(report: ChangeReport, options: RenderOptions) -> bytes`

_No docstring._

### `arodonata/reports/changes/render_markdown.py`

Markdown change report for MCP (spec 6.4): the HTML structure without colour.

Markers: ``[+]`` added, ``[-]`` deleted (row cells struck through), ``[~]`` modified, ``[x]`` appended for disabled;
items ``+added``, ``~~removed~~``, ``modified*``; changed scalars bold; negation ``not (a, b)``. Every CP-sourced string
goes through escape_md first, so these markers are the only live markup. No raw appendix.

#### Module-Level Functions

##### `def render_markdown(report: ChangeReport, options: RenderOptions) -> str`

_No docstring._

### `arodonata/reports/changes/scopes.py`

Change-report inputs: which sessions of which management servers and domains (validated at construction).

#### class `ChangeReportInputError(ValueError)`

Invalid input found when collecting: empty scope list, a non-scope item, unknown mgmt_name, no server.

#### class `OwnedSession(BaseModel)`

An app-owned session's SID, used read-only to number its unpublished rules. Never serialised or logged.

##### Fields / Class Variables

```python
sid: SecretStr
server_ip: str
```
#### class `SessionScope(BaseModel)`

Explicit sessions of one domain, each fetched on its own (published or not).

##### Fields / Class Variables

```python
mgmt_name: str | None = None
domain: str = ''
session_uids: list[str] = Field(min_length=1)
owned_session: OwnedSession | None = None
```
#### class `RangeScope(BaseModel)`

Published sessions of one domain between bounds: from_session exclusive, to_session inclusive (server
semantics); dates inclusive and exact (applied client-side on the publish time).

##### Fields / Class Variables

```python
mgmt_name: str | None = None
domain: str = ''
from_session: str | None = None
to_session: str | None = None
from_date: AwareDatetime | None = None
to_date: AwareDatetime | None = None
```
### `arodonata/reports/changes/view.py`

Pure: a ChangeReport as render-ready rows shared by the HTML and markdown renderers (plan decision 4).

#### Module-Level Functions

##### `def fmt_time(dt: datetime | None) -> str`

_No docstring._

##### `def numbering_label(session: SessionChanges) -> str`

_No docstring._

##### `def session_view(s: SessionChanges) -> SessionView`

_No docstring._

##### `def report_view(report: ChangeReport) -> ReportView`

_No docstring._

#### class `ItemView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
name: str
status: ItemStatus
link: str | None
```
#### class `CellView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
key: str
items: tuple[ItemView, ...] | None
text: str | None
changed: bool
negated: bool
link: str | None
```
#### class `RowView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
kind: Literal['rule', 'section']
status: ChangeStatus | None
name: str = ''
disabled: bool = False
enabled_changed: bool = False
number: str | None = None
previous_number: str | None = None
moved: bool = False
basis_label: str = ''
cells: tuple[CellView, ...] = ()
section_range: str | None = None
section_changes: tuple[FieldChange, ...] = ()
section_position: int | None = None
anchor: str | None = None
```
#### class `DetailView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
anchor: str
label: str
changes: tuple[FieldChange, ...]
other_fields: tuple[str, ...]
```
#### class `TableView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
title: str
columns: tuple[tuple[str, str], ...]
rows: tuple[RowView, ...]
details: tuple[DetailView, ...]
```
#### class `RulebaseView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
kind: RulebaseKind
title: str
tables: tuple[TableView, ...]
unplaced: TableView | None
```
#### class `SessionView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
session: SessionChanges
anchor: str
published_label: str
numbering_label: str
rulebases: tuple[RulebaseView, ...]
sections: tuple[ObjectChange, ...]
added_deleted: tuple[ObjectChange, ...]
modified_objects: tuple[ObjectChange, ...]
other: tuple[ObjectChange, ...]
internal_count: int
empty: bool
counts_text: str
```
#### class `DomainView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
domain: str
display_name: str
unavailable: DomainError | None
sessions: tuple[SessionView, ...]
```
#### class `ServerView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
name: str
domains: tuple[DomainView, ...]
```
#### class `WarningGroup`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
mgmt: str
domain: str
items: tuple[ReportWarning, ...]
```
#### class `ReportView`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
generated_at: str
version: str
servers: tuple[ServerView, ...]
warnings: tuple[WarningGroup, ...]
raw: tuple[RawResponse, ...]
```

---

## rulebase

### `arodonata/rulebase/__init__.py`

Rulebase reading helpers shared by the cache and live paths (pure: no DB or API imports).

_No public classes or functions in this module._

### `arodonata/rulebase/model.py`

Parsed rulebase structures shared by the cache, the numbering and the change report (pure: no DB or API imports).

Numbers here are Check Point's in-layer ``rule-number``s; hierarchical SmartConsole numbers are computed by
``arodonata.rulebase.numbering`` and never stored.

#### class `SectionItem`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
from_number: int | None
to_number: int | None
rules_before: int
seq: int
raw: dict[str, Any]
```
#### class `RuleItem`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
uid: str
name: str
kind: ItemKind
rule_number: int
enabled: bool
section_uid: str | None
inline_layer_uid: str | None
domain_type: str
auto_generated: bool
raw: dict[str, Any]
```
#### class `LayerSnapshot`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
rulebase_type: RulebaseType
layer_uid: str
layer_name: str
layer_domain_type: str
total: int
sections: tuple[SectionItem, ...]
items: tuple[RuleItem, ...]
objects_dictionary: tuple[dict[str, str], ...]
```
#### class `OrderedLayer`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
rulebase_type: RulebaseType
position: int
slot: str
layer_uid: str
layer_name: str
layer_domain_type: str
placeholder_uid: str | None = None
parent_rule_uid: str | None = None
parent_rule_name: str | None = None
domain_layer_uid: str | None = None
```
#### class `PackageLayout`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
package_uid: str
package_name: str
layers: tuple[OrderedLayer, ...]
```
#### class `DomainRulebaseSnapshot`

```python
@dataclass(frozen=True)
```
One domain's rulebases. Canonical order: layers by (rulebase_type, layer_uid), packages by package_name.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
session_uid: str | None
session_published_time: datetime | None
refreshed_at: datetime | None
packages: tuple[PackageLayout, ...]
layers: tuple[LayerSnapshot, ...]
```
#### class `DomainRefreshResult`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
status: Literal['ok', 'unversioned', 'fresh', 'failed']
session_uid: str | None
counts: dict[str, int]
error: str | None
warnings: tuple[str, ...]
```
#### class `ParentRule`

```python
@dataclass(frozen=True)
```
The rule CP shows in place of a global place-holder when the global layer is read with ``package``.

##### Fields / Class Variables

```python
uid: str
name: str
domain_layer_uid: str
```
### `arodonata/rulebase/numbering.py`

SmartConsole rule numbering over parsed rulebase snapshots (pure).

Each ordered layer numbers from 1. A rule with an inline layer, and a global place-holder linked to its package's
domain layer, number their children with the parent's number as prefix ("2." -> "2.1", "2.2.1"). Sections carry a
range ("2.1-2.2", "2.3", "No Rules") and precede their first rule; an empty section stays where it sits in the layer.

#### Module-Level Functions

##### `def section_range(prefix: str, from_number: int | None, to_number: int | None) -> str`

SmartConsole's section range: ``2.1-2.2``, ``2.3`` for one rule, ``No Rules`` for an empty section.

##### `def number_layer(layer_uid: str, layers: Mapping[str, LayerSnapshot], *, prefix: str = '', depth: int = 0, ordered_layer: OrderedLayer | None = None, expand_inline: bool = True, _path: frozenset[str] = frozenset()) -> list[NumberedEntry]`

Number one layer and, recursively, its inline layers and (with ``ordered_layer`` link context) the domain
layer under a global place-holder.

The cycle guard holds only the layers on the current descent path, so a layer shared by two parents is expanded
under both and only a true cycle stops. A layer missing from ``layers`` is logged and yields no entries.
``expand_inline=False`` names inline layers (``inline_layer_uid``) without descending (a single fetched layer).

##### `def number_package(layout: PackageLayout, rulebase_type: RulebaseType, layers: Mapping[str, LayerSnapshot]) -> list[list[NumberedEntry]]`

One numbered list per ordered layer of ``rulebase_type`` in the package, in position order.

#### class `NumberedEntry`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
kind: Literal['rule', 'section', 'place-holder', 'parent-rule']
rulebase_type: RulebaseType
number: str
range: str
depth: int
uid: str
name: str
layer_uid: str
layer_name: str
rule_number: int | None
section_uid: str | None
section_name: str | None
inline_layer_uid: str | None
item: RuleItem | SectionItem | None
```
### `arodonata/rulebase/pager.py`

Page a ``show-*-rulebase`` command to completion, or fail: never a partial layer.

The pager assumes ``offset`` counts rules and continues from the previous page's ``to``. It checks that
assumption on every page (``from`` must be the previous ``to + 1``), so a server that pages differently makes it
raise instead of silently skipping or duplicating rules. A full last page omits trailing empty sections, so the
pager then re-reads the last rule on a page with room.

#### Module-Level Functions

##### `async def fetch_full_rulebase(client: Any, mgmt_name: str, domain: str, command: str, payload: dict[str, Any], *, page_size: int = RULEBASE_PAGE_SIZE, offset: int = 0) -> dict[str, Any]`

Every page of one layer from rule `offset` on, merged into one response.

Args:
    client: Anything with ``api_call(mgmt_name=, domain=, command=, payload=)`` returning an
        ``ApiCallResult``-like object (``success``, ``data``, ``code``, ``message``).
    mgmt_name: Management server name.
    domain: Domain name ('' for the system domain).
    command: ``show-access-rulebase``, ``show-nat-rulebase``, ``show-https-rulebase`` or ``show-threat-rulebase``.
    payload: uid/name/package, details-level, use-object-dictionary and any live-only parameters; ``limit`` and
        ``offset`` are set by the pager.
    page_size: Rules per page.
    offset: Rules to skip; the first page must start at rule ``offset + 1``.

Returns:
    The first page's top-level keys (including its ``from``, ``to``, and ``total``), with ``rulebase`` holding
    every item (a section split across pages merged by uid) and ``objects-dictionary`` merged by uid.

Raises:
    RulebaseFetchError: A page failed, was not a dict, did not advance, or did not start right after the
        previous one. Exceptions raised by ``client.api_call`` itself propagate unchanged.

#### class `RulebaseFetchError(Exception)`

A rulebase page failed, or CP paged the layer in a way the pager cannot trust.

##### Methods

###### `def __init__(self, code: str, message: str) -> None`

_No docstring._

### `arodonata/rulebase/parse.py`

Parse Check Point show-* responses into the frozen structures of ``arodonata.rulebase.model`` (pure).

#### Module-Level Functions

##### `def objects_map(dictionary: Iterable[Mapping[str, str]]) -> dict[str, str]`

{uid: name} of a trimmed objects-dictionary (entries without a name are left out).

##### `def parse_layer_response(data: dict[str, Any], rulebase_type: RulebaseType, *, layer_name: str | None = None, layer_domain_type: str = '') -> LayerSnapshot`

One complete ``show-*-rulebase`` response (``fetch_full_rulebase``) as a LayerSnapshot.

Sections at any depth become SectionItems and their children inherit ``section_uid``; ``<type>-rule`` items
become ``kind='rule'``, ``place-holder`` items ``kind='place-holder'``; anything else is skipped (debug log).

Args:
    data: The merged response; its top-level ``uid`` is the layer uid (required).
    rulebase_type: "access", "nat", "https" or "threat".
    layer_name: Overrides the response's ``name`` (NAT responses have none: pass the package name).
    layer_domain_type: The layer's domain-type from its package or listing entry.

Raises:
    ValueError: The response has no ``uid``.

##### `def parse_packages(packages: Iterable[Any], *, nat_layer_uids: Mapping[str, str] | None = None) -> list[PackageLayout]`

``show-packages details-level full`` objects as PackageLayouts (listing order).

Access and threat layers keep their list order; HTTPS uses fixed slots (inbound 0, outbound 1); a package gets one
NAT ordered layer when ``nat-policy`` is true and its uid is in ``nat_layer_uids`` (package uid -> the NAT
response's uid). A blade flag set to false (``access``, ``threat-prevention``, ``https-inspection-policy``) gives
no ordered layers of that type. A global layer's nested domain layer is still listed here; ``link_placeholder``
removes it.

Raises:
    ValueError: A package without uid/name, or a layer reference without uid.

##### `def find_parent_rule(data: dict[str, Any], rulebase_type: RulebaseType, rule_number: int) -> ParentRule | None`

The domain parent rule at a place-holder's position in a global layer read with ``package``.

Returns None unless the entry at ``rule_number`` is a ``<type>-rule`` of domain-type ``domain`` with an
``inline-layer`` (the domain layer).

##### `def link_placeholder(layout: PackageLayout, rulebase_type: RulebaseType, layer_uid: str, placeholder_uid: str, parent: ParentRule) -> PackageLayout`

Record the place-holder link on the global ordered layer and drop the nested domain layer from the ordered
layers of that type (it is numbered only under the parent rule). Positions of that type are renumbered from 0,
except HTTPS, whose positions are fixed slots.

### `arodonata/rulebase/source.py`

Read contract over rulebase snapshots: SmartConsole-numbered packages and layers, and rule positions.

The builders are pure (a ``DomainRulebaseSnapshot`` in, numbered results out). ``CachedRulebaseSource`` adds the cache
reads and the readiness rule; a live source can wrap the same builders.

#### Module-Level Functions

##### `def check_uid_collections(**collections: Collection[str]) -> None`

Reject a bare ``str`` passed as a collection of uids (it would be iterated per character).

Raises:
    TypeError: One of the arguments is a ``str``.

##### `def resolve_layer(snapshot: DomainRulebaseSnapshot, layer: str, rulebase_type: RulebaseType) -> LayerSnapshot`

A layer of the given type by uid, else by name.

Raises:
    RulebaseNotFound: No layer with that uid or name.
    AmbiguousLayerName: The name matches several layers.

##### `def package_rulebase_from_snapshot(snapshot: DomainRulebaseSnapshot, package: str, rulebase_type: RulebaseType, *, status: str = 'ok', last_error: str | None = None) -> PackageRulebase`

A package's SmartConsole numbering for one rulebase type (one entry list per ordered layer).

Raises:
    RulebaseNotFound: No package with that name or uid.

##### `def layer_rulebase_from_snapshot(snapshot: DomainRulebaseSnapshot, layer: str, rulebase_type: RulebaseType, *, status: str = 'ok', last_error: str | None = None) -> LayerRulebase`

One layer numbered without package context (layer-relative numbers, inline layers expanded).

##### `def locate_rules_in_snapshot(snapshot: DomainRulebaseSnapshot, rule_uids: Collection[str] = (), rulebase_type: RulebaseType | None = None, *, layer_uids: Collection[str] = (), status: str = 'ok', last_error: str | None = None) -> RuleLocations`

Every position of each rule uid and each layer uid in every package's numbering.

A rule position is its SmartConsole number (shared and inline layers give several). A layer position is the
prefix its rules get there: ``""`` for an ordered layer, ``"<n>."`` for a layer reached through rule ``n`` (an
inline layer, or the domain layer under Global's parent rule). Unknown uids map to ``[]``.

#### class `RulePosition`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
package_name: str
rulebase_type: RulebaseType
ordered_layer_position: int
ordered_layer_name: str
number: str
section_name: str | None
section_range: str | None
layer_uid: str
layer_name: str
section_uid: str | None = None
```
#### class `LayerPosition`

```python
@dataclass(frozen=True)
```
Where a layer appears in a package's numbering; a rule at in-layer position n there is ``prefix + str(n)``.

##### Fields / Class Variables

```python
package_name: str
rulebase_type: RulebaseType
ordered_layer_position: int
ordered_layer_name: str
prefix: str
has_sections: bool = False
```
#### class `RuleLocations`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
snapshot_session_uid: str | None
snapshot_published_at: datetime | None
snapshot_refreshed_at: datetime | None
status: str
last_error: str | None
rules: dict[str, list[RulePosition]]
layers: dict[str, list[LayerPosition]]
```
#### class `PackageRulebase`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
package_name: str
rulebase_type: RulebaseType
snapshot_session_uid: str | None
snapshot_published_at: datetime | None
snapshot_refreshed_at: datetime | None
status: str
last_error: str | None
layers: tuple[tuple[OrderedLayer, tuple[NumberedEntry, ...]], ...]
layer_names: Mapping[str, str]
layer_dictionaries: Mapping[str, tuple[dict[str, str], ...]]
```
#### class `LayerRulebase`

```python
@dataclass(frozen=True)
```
_No docstring._

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
rulebase_type: RulebaseType
layer_uid: str
layer_name: str
snapshot_session_uid: str | None
snapshot_published_at: datetime | None
snapshot_refreshed_at: datetime | None
status: str
last_error: str | None
entries: tuple[NumberedEntry, ...]
layer_names: Mapping[str, str]
layer_dictionaries: Mapping[str, tuple[dict[str, str], ...]]
```
#### class `RulebaseCacheNotReady(Exception)`

The domain has no usable rulebase snapshot (no sync state, or an older cache format).

#### class `RulebaseNotFound(LookupError)`

The layer or package is not in the domain's snapshot.

#### class `AmbiguousLayerName(Exception)`

A layer (or package) name matches several layers; candidates are (domain_name, uid).

##### Methods

###### `def __init__(self, name: str, candidates: tuple[tuple[str, str], ...]) -> None`

_No docstring._

#### class `RulebaseSource(Protocol)`

Numbered rulebases of one domain, whatever they are read from.

A cached source reports the sync-state status (``ok`` | ``unversioned`` | ``failed``) with ``snapshot_*`` fields
describing the cached snapshot. A live source reports status ``live``, with ``snapshot_*`` describing what it
read (the head session it read at, that session's publish time, and the read time as ``snapshot_refreshed_at``).
A live source reading inside an unpublished app-owned session reports that session's uid as
``snapshot_session_uid`` and ``None`` as ``snapshot_published_at``.

##### Methods

###### `async def packages(self, mgmt_name: str, domain_name: str) -> list[PackageLayout]`

_No docstring._

###### `async def package_rulebase(self, mgmt_name: str, domain_name: str, package: str, rulebase_type: RulebaseType) -> PackageRulebase`

_No docstring._

###### `async def layer_rulebase(self, mgmt_name: str, domain_name: str, layer: str, rulebase_type: RulebaseType) -> LayerRulebase`

_No docstring._

###### `async def locate_rules(self, mgmt_name: str, domain_name: str, rule_uids: Collection[str] = (), rulebase_type: RulebaseType | None = None, *, layer_uids: Collection[str] = ()) -> RuleLocations`

_No docstring._

#### class `RulebaseDomainIndex(Protocol)`

Which domains hold a layer or package; used only to resolve the facade's domainless calls.

##### Methods

###### `async def find_layer_domains(self, mgmt_name: str, layer: str, rulebase_type: RulebaseType) -> list[tuple[str, str]]`

_No docstring._

###### `async def find_package_domains(self, mgmt_name: str, package: str) -> list[tuple[str, str]]`

_No docstring._

#### class `CachedRulebaseSource`

RulebaseSource (and RulebaseDomainIndex) over the rulebase cache. Never calls the API.

Readable = a sync row with ``format_version >= RULEBASE_CACHE_FORMAT`` (Phase 2 writes that version only together
with the domain's complete snapshot). Status is not checked: a ``failed`` domain is served from its last good
snapshot with ``status``/``last_error`` exposed; a domain whose refreshes only ever failed has format 0.

##### Methods

###### `def __init__(self, cache: Any) -> None`

_No docstring._

###### `async def packages(self, mgmt_name: str, domain_name: str) -> list[PackageLayout]`

_No docstring._

###### `async def package_rulebase(self, mgmt_name: str, domain_name: str, package: str, rulebase_type: RulebaseType) -> PackageRulebase`

_No docstring._

###### `async def layer_rulebase(self, mgmt_name: str, domain_name: str, layer: str, rulebase_type: RulebaseType) -> LayerRulebase`

_No docstring._

###### `async def locate_rules(self, mgmt_name: str, domain_name: str, rule_uids: Collection[str] = (), rulebase_type: RulebaseType | None = None, *, layer_uids: Collection[str] = ()) -> RuleLocations`

_No docstring._

###### `async def find_layer_domains(self, mgmt_name: str, layer: str, rulebase_type: RulebaseType) -> list[tuple[str, str]]`

_No docstring._

###### `async def find_package_domains(self, mgmt_name: str, package: str) -> list[tuple[str, str]]`

_No docstring._
