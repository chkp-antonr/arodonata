# Arodonata v2 — Full API Reference

Complete, auto-generated reference of every public class, SQLModel table, function, and method in the `arodonata` v2.0.0 package, extracted directly from `src/arodonata` via AST.

## Package Map

- **Top-Level Package & ArodonataClient Facade (`arodonata`, `arodonata.client`)** — 2 module(s)
- **core — Configuration, Contexts, Models, Hexagonal Ports, Sync & Search Services** — 21 module(s)
- **adapters — Check Point Transport (`AMgmtClient`), SQL Storage (15 Tables) & SSE** — 15 module(s)
- **rulebase — Cached Rulebase Source, SmartConsole Numbering & Local Filtering** — 7 module(s)
- **cpcrud — Declarative Policy-as-Code Engine (Validator, Planner, Executor, Inverse)** — 11 module(s)
- **reports — Auditable Session Change Report Collector & Multi-Format Renderer** — 5 module(s)
- **mcp — Streamable-HTTP Model Context Protocol Server & Consolidated Tools** — 8 module(s)


---

## Top-Level Package & ArodonataClient Facade (`arodonata`, `arodonata.client`)

### `arodonata/__init__.py`

Arodonata v2 — Async-first Python SDK for Check Point Management & MDSM.

_No public classes or functions in this module._

### `arodonata/client.py`

Primary composition root and unified developer facade (`ArodonataClient`).

Wires `ApiPort` (`AMgmtClient`), `CachePort` (`SqlCacheAdapter`), and `LockPort` (`SqlLockAdapter`)
into core domain services (`DomainService`, `DomainSyncCoordinator`, `ObjectService`,
`ServiceCacheService`, `AssetRefreshService`, `SearchService`), defaulting `engine=None` to an
auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`).

#### class `ArodonataClient`

Unified composition root and async facade for Check Point Management & MDSM.

##### Methods

###### `def __init__(self, settings: ArodonataSettings | None = None, *, engine: AsyncEngine | str | None = None, db_manager: DatabaseManager | None = None, cache: CachePort | None = None, lock_port: LockPort | None = None, api: ApiPort | None = None, transport: ApiTransport | None = None, trust_policy: TrustPolicy | None = None, connection_pool: VerifiedConnectionPool | None = None, task_waiter: TaskWaiter | None = None, rate_limiter: RateLimiter | None = None, login_gate: LoginGate | None = None, auth_provider: AuthProvider | None = None, domain_tracker: DomainListRefreshTracker | None = None, cluster_manager: ClusterRelationshipManager | None = None, vsx_manager: VSXRelationshipManager | None = None, monotonic_fn: Callable[[], float] = time.monotonic, now_fn: Callable[[], datetime] = utc_now, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep, **settings_kwargs: Any) -> None`

_No docstring._

###### `def settings(self) -> ArodonataSettings`

```python
@property
```
Active `ArodonataSettings`.

###### `def db(self) -> DatabaseManager`

```python
@property
```
Underlying `DatabaseManager`.

###### `def owns_engine(self) -> bool`

```python
@property
```
Return `True` if this client auto-created and owns its SQLAlchemy `AsyncEngine`.

###### `def cache(self) -> CachePort`

```python
@property
```
Active `CachePort` adapter.

###### `def lock_port(self) -> LockPort`

```python
@property
```
Active `LockPort` adapter.

###### `def api(self) -> ApiPort`

```python
@property
```
Active `ApiPort` adapter.

###### `def amgmt(self) -> AMgmtClient | None`

```python
@property
```
Underlying `AMgmtClient` if constructed with the default transport adapter.

###### `def domain_service(self) -> DomainService`

```python
@property
```
Core `DomainService`.

###### `def sync_coordinator(self) -> DomainSyncCoordinator`

```python
@property
```
Core `DomainSyncCoordinator`.

###### `def object_service(self) -> ObjectService`

```python
@property
```
Core `ObjectService`.

###### `def service_cache(self) -> ServiceCacheService`

```python
@property
```
Core `ServiceCacheService`.

###### `def asset_service(self) -> AssetRefreshService`

```python
@property
```
Core `AssetRefreshService`.

###### `def search_service(self) -> SearchService`

```python
@property
```
Core `SearchService`.

###### `def rulebase_refresh(self) -> RulebaseRefreshService`

```python
@property
```
Rulebase snapshot refresh service (`RulebaseRefreshService`).

###### `def rulebase_source(self) -> CachedRulebaseSource`

```python
@property
```
Cached rulebase introspection and numbering source (`CachedRulebaseSource`).

###### `def cpcrud(self) -> CPCRUDService`

```python
@property
```
Declarative Check Point Policy-as-Code CRUD engine (`CPCRUDService`).

###### `def warmup_tasks(self) -> set[asyncio.Task[Any]]`

```python
@property
```
Currently running background warm-up tasks.

###### `async def initialize(self, *, run_startup_cleanup: bool = True) -> None`

Initialize the database schema and optionally schedule startup session cleanup.

###### `async def close(self, *, logout: bool | None = None) -> None`

```python
@traced
```
Cancel running background warm-up tasks immediately, drain startup cleanup, close transport, and dispose owned engine.

###### `def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None`

Invalidate freshness memos for `(mgmt_name, domain)` so the next smart read re-checks published head.

###### `def start_object_cache_warmup(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, include_services: bool = False, mode: CacheMode = 'smart') -> asyncio.Task[RefreshOutcome]`

Explicitly schedule background object (and optional service) cache warm-up.

###### `async def api_call(self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None, wait_for_task: bool = True, timeout: float | None = None) -> ApiCallResult`

```python
@traced
```
Execute a Check Point Management API command, updating active `WriteSession` overlay and invalidating domain on `publish`.

###### `async def api_query(self, mgmt_name: str, command: str, *, domain: str | None = None, details_level: str = 'standard', payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None, limit: int = DEFAULT_PAGE_LIMIT) -> ApiQueryResult`

```python
@traced
```
Execute a continuity-verified paginated Check Point object listing query.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]`

Open an isolated write session outside `sid_cache`, returning `(sid, server_ip)`.

###### `def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> Awaitable[bool]`

Log out a specific session identifier.

###### `def auth_context(self, auth: AuthContext | None = None, *, username: str | None = None, password: str | None = None, api_key: str | None = None, user_id: str | None = None) -> Iterator[AuthContext]`

```python
@contextmanager
```
Bind runtime administrator credentials (`AuthContext`) in `contextvars`.

###### `def user_context(self, user: UserContext | None = None, *, user_id: str | None = None, username: str | None = None, session_name: str | None = None, session_description: str | None = None, client_id: str | None = None, extra: dict[str, Any] | None = None) -> Iterator[UserContext]`

```python
@contextmanager
```
Bind operator attribution metadata (`UserContext`) in `contextvars`.

###### `async def write_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None, publish_on_exit: bool = True) -> AsyncIterator[WriteSession]`

```python
@asynccontextmanager
```
Open a context-bound isolated `WriteSession` with `SessionOverlay` read-your-own-writes isolation.

###### `async def refresh_objects(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize network objects across target domains and return `RefreshOutcome`.

###### `async def stream_refresh_objects(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing network objects.

###### `async def refresh_services(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize service objects across target domains and return `RefreshOutcome`.

###### `async def stream_refresh_services(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing service objects.

###### `async def refresh_assets(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize gateway, cluster, VSX, and server assets across domains and return `RefreshOutcome`.

###### `async def stream_refresh_assets(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing gateway, cluster, VSX, and server assets.

###### `async def refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize policy rulebase snapshots across target domains and return `RefreshOutcome`.

###### `async def stream_refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing policy rulebase snapshots.

###### `async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[DomainInfo]`

```python
@traced
```
Return discovered domains, excluding `Global` unless `include_global=True`.

Never triggers implicit background object-cache warm-up.

###### `async def get_gateways(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[Asset]`

```python
@traced
```
Return cached gateway, cluster, VSX, and server `Asset` models.

###### `async def get_hosts(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]`

```python
@traced
```
Return cached `host` `CPObject` models, merging any active `WriteSession` overlay.

###### `async def get_networks(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]`

```python
@traced
```
Return cached `network` `CPObject` models, merging any active `WriteSession` overlay.

###### `async def get_address_ranges(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]`

```python
@traced
```
Return cached `address-range` `CPObject` models, merging any active `WriteSession` overlay.

###### `async def get_dns_domains(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]`

```python
@traced
```
Return cached `dns-domain` `CPObject` models, merging any active `WriteSession` overlay.

###### `async def get_groups(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]`

```python
@traced
```
Return cached `group` `CPObject` models, merging any active `WriteSession` overlay.

###### `async def get_objects(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]`

```python
@traced
```
Return cached network `CPObject` models across `types`, merging any active `WriteSession` overlay.

###### `async def get_services(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPService]`

```python
@traced
```
Return cached `CPService` models, merging any active `WriteSession` overlay.

###### `async def get_object_by_uid(self, mgmt_name: str, domain: str, uid: str, *, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | None`

```python
@traced
```
Return a single `CPObject` by `(mgmt_name, domain, uid)`, respecting any active `WriteSession` overlay.

###### `async def get_access_rules(self, mgmt_name: str, domain: str, *, layer_uid: str | None = None, layer_name: str | None = None) -> list[AccessRuleEntry]`

```python
@traced
```
Return cached access-control rules for `(mgmt_name, domain)`.

###### `async def get_nat_rules(self, mgmt_name: str, domain: str, *, package_uid: str | None = None, package_name: str | None = None) -> list[NatRuleEntry]`

```python
@traced
```
Return cached NAT rules for `(mgmt_name, domain)`.

###### `async def get_https_rules(self, mgmt_name: str, domain: str, *, layer_uid: str | None = None, layer_name: str | None = None) -> list[HttpsRuleEntry]`

```python
@traced
```
Return cached HTTPS inspection rules for `(mgmt_name, domain)`.

###### `async def get_threat_rules(self, mgmt_name: str, domain: str, *, layer_uid: str | None = None, layer_name: str | None = None) -> list[ThreatRuleEntry]`

```python
@traced
```
Return cached Threat Prevention rules for `(mgmt_name, domain)`.

###### `async def get_policy_packages(self, mgmt_name: str, domain_name: str | None = None, *, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> list[PolicyPackageInfo]`

```python
@traced
```
Return cached `PolicyPackageInfo` entries for `(mgmt_name, domain_name)`.

###### `async def get_package_rulebase(self, mgmt_name: str, domain_name: str | None, package: str, *, rulebase_type: RulebaseType = 'access', cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> PackageRulebase`

```python
@traced
```
Return a SmartConsole-numbered `PackageRulebase` for `package` in `(mgmt_name, domain_name)`.

###### `async def get_layer_rulebase(self, mgmt_name: str, domain_name: str | None, layer: str, *, rulebase_type: RulebaseType | None = None, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> NumberedLayerRulebase`

```python
@traced
```
Return a SmartConsole-numbered `NumberedLayerRulebase` for `layer` in `(mgmt_name, domain_name)`.

###### `async def locate_rules(self, mgmt_name: str, domain_name: str | None = None, *, rule_uids: Sequence[str] | None = None, layer_uids: Sequence[str] | None = None, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> RuleLocations`

```python
@traced
```
Locate SmartConsole rule numbers and layer prefixes across all packages and layers of a domain.

###### `async def filter_rulebase(self, mgmt_name: str, domain_name: str | None = None, *, package: str | None = None, layer: str | None = None, rulebase_type: RulebaseType = 'access', filter_query: str = '', output_format: RuleFormat = 'model_friendly', cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> FilteredRulebaseResult`

```python
@traced
```
Evaluate `filter_query` locally against cached rulebase and cached objects/services.

###### `async def collect_change_report(self, scopes: Sequence[ReportScope | dict[str, Any]], *, options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS) -> ChangeReport`

```python
@traced
```
Collect read-only auditable session change evidence (`ChangeReport`) across `scopes`.

###### `def render_change_report(self, report: ChangeReport, *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None) -> RenderedReportBundle`

```python
@traced
```
Render a `ChangeReport` offline into any requested subset of `'html'`, `'json'`, and `'markdown'`.

###### `async def build_change_report(self, scopes: Sequence[ReportScope | dict[str, Any]], *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS) -> RenderedReportBundle`

```python
@traced
```
Collect and render a `ChangeReport` across `scopes` into `formats`.

###### `async def search_objects(self, query: str, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, max_depth: int = 2, exact_match: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> SearchResult`

```python
@traced
```
Search cached objects across comma-separated terms and resolve parent groups up to `max_depth`.

###### `async def describe_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, include_global: bool = True) -> dict[str, Any]`

```python
@traced
```
Return progressive-disclosure schema and summary counts for cached objects and services.

###### `async def query_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, domains: Sequence[str] | None = None, types: Sequence[str] | None = None, scope_origin: Literal['all', 'local', 'global'] = 'all', name_pattern: str | None = None, ip_subnet: str | None = None, port: str | None = None, protocol: str | None = None, tags: Sequence[str] | None = None, include_global: bool = False, group_by: Sequence[str] | None = None, aggregate: Literal['count', 'list', 'describe'] = 'list', limit: int = 100, offset: int = 0, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> dict[str, Any]`

```python
@traced
```
Execute structured cross-domain filtering, grouping, and counting over cached objects and services.

###### `async def get_cache_status(self, *, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> dict[str, Any]`

```python
@traced
```
Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness and `cache_age_seconds`.

###### `async def add_object(self, mgmt_name: str, obj_type: str, payload: dict[str, Any], *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None) -> ApiCallResult`

```python
@traced
```
Create a Check Point object (`add-<obj_type>`) using active `WriteSession` context, explicit `sid`, or an automatic isolated `write_session` (`C8`).

###### `async def set_object(self, mgmt_name: str, obj_type: str, payload: dict[str, Any], *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None) -> ApiCallResult`

```python
@traced
```
Update a Check Point object (`set-<obj_type>`) using active `WriteSession` context, explicit `sid`, or an automatic isolated `write_session` (`C8`).

###### `async def delete_object(self, mgmt_name: str, obj_type: str, *, uid: str | None = None, name: str | None = None, payload: dict[str, Any] | None = None, domain: str | None = None, sid: str | None = None, server_ip: str | None = None) -> ApiCallResult`

```python
@traced
```
Delete a Check Point object (`delete-<obj_type>`) by `uid` or `name` using active `WriteSession`, explicit `sid`, or automatic isolated `write_session` (`C8`).

###### `async def find_object(self, mgmt_name: str, domain: str, name_or_uid: str, *, obj_type: str | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | CPService | Asset | None`

```python
@traced
```
Find a single `CPObject`, `CPService`, or `Asset` by exact `uid` or `name` in `(mgmt_name, domain)`, including active `WriteSession` overlay.

###### `async def get_group_members(self, mgmt_name: str, domain: str, group_name_or_uid: str, *, recursive: bool = True, max_depth: int = 5, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject | CPService | Asset]`

```python
@traced
```
Resolve direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items for a group, service-group, cluster, or VSX container in `(mgmt_name, domain)`.

###### `async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid` via `take-over-session`, publish it, log out, and invalidate the domain cache.

###### `async def stream_publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None) -> AsyncIterator[CPCRUDEvent]`

Adopt `session_uid` via `take-over-session`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate the domain cache.

###### `async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid` via `take-over-session`, discard uncommitted changes, and log out.


---

## core — Configuration, Contexts, Models, Hexagonal Ports, Sync & Search Services

### `arodonata/core/__init__.py`

Arodonata v2 pure domain core (`config`, `context`, `errors`, `events`, `models`, `ports`, `telemetry`).

_No public classes or functions in this module._

### `arodonata/core/config.py`

Configuration and topology settings for Arodonata v2.

#### Module-Level Functions

##### `def mask_database_url(url: str) -> str`

Mask password embedded in a database connection URL (`postgresql+asyncpg://user:***@host/db`).

##### `def parse_host_port(raw_server: str, *, default_port: int = 443) -> tuple[str, int]`

Split `host`, `host:port`, `[ipv6]:port`, or bare IPv6 `2001:db8::1` into `(host, port)`.

#### class `ServerEndpointConfig(BaseModel)`

Resolved connection configuration for a single Check Point management server.

##### Fields / Class Variables

```python
name: str
host: str
port: int = 443
api_key: str | None = Field(default=None, repr=False)
```
#### class `ArodonataSettings(BaseSettings)`

Type-safe configuration for Arodonata resolved from kwargs and `os.environ`.

Never loads `.env` files implicitly.

##### Fields / Class Variables

```python
mgmt_names: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('ARODONATA_MGMT_NAMES', 'MGMT_NAMES'))
mgmt_servers: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('ARODONATA_MGMT_SERVERS', 'MGMT_SERVERS'))
api_keys: CsvStrList = Field(default_factory=list, repr=False, validation_alias=AliasChoices('ARODONATA_API_KEYS', 'API_KEYS'))
api_key_vars: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('ARODONATA_API_KEY_VARS', 'API_KEY_VARS'))
mgmt_name: str | None = Field(default=None, validation_alias=AliasChoices('ARODONATA_MGMT_NAME', 'MGMT_NAME'))
mgmt_ip: str | None = Field(default=None, validation_alias=AliasChoices('ARODONATA_MGMT_IP', 'MGMT_IP'))
mgmt_port: int = Field(default=443, validation_alias=AliasChoices('ARODONATA_MGMT_PORT', 'MGMT_PORT'))
api_key: str | None = Field(default=None, repr=False, validation_alias=AliasChoices('ARODONATA_API_KEY', 'MGMT_API_KEY'))
username: str | None = Field(default=None, validation_alias=AliasChoices('ARODONATA_USERNAME', 'MGMT_USER', 'MGMT_USERNAME'))
password: str | None = Field(default=None, repr=False, validation_alias=AliasChoices('ARODONATA_PASSWORD', 'MGMT_PASSWORD'))
auth_mode: AuthMode = Field(default='dynamic', validation_alias=AliasChoices('ARODONATA_AUTH_MODE'))
connect_timeout: float = Field(default=30.0, gt=0, validation_alias=AliasChoices('ARODONATA_CONNECT_TIMEOUT'))
api_timeout: float = Field(default=120.0, gt=0, validation_alias=AliasChoices('ARODONATA_API_TIMEOUT'))
login_timeout: float = Field(default=120.0, gt=0, validation_alias=AliasChoices('ARODONATA_LOGIN_TIMEOUT'))
task_timeout: float = Field(default=900.0, gt=0, validation_alias=AliasChoices('ARODONATA_TASK_TIMEOUT'))
rate_limit_slot_timeout: float = Field(default=90.0, gt=0, validation_alias=AliasChoices('ARODONATA_RATE_LIMIT_SLOT_TIMEOUT'))
session_timeout: int = Field(default=600, gt=0, validation_alias=AliasChoices('ARODONATA_SESSION_TIMEOUT'))
session_expire_seconds: int = Field(default=540, gt=0, validation_alias=AliasChoices('ARODONATA_SESSION_EXPIRE_SECONDS', 'ARODONATA_SESSION_EXPIRE'))
concurrent_limit: int = Field(default=4, ge=1, le=20, validation_alias=AliasChoices('ARODONATA_CONCURRENT_LIMIT'))
login_throttle_window: float = Field(default=70.0, gt=0, validation_alias=AliasChoices('ARODONATA_LOGIN_THROTTLE_WINDOW'))
login_max_wait: float = Field(default=900.0, gt=0, validation_alias=AliasChoices('ARODONATA_LOGIN_MAX_WAIT'))
cache_ttl: int = Field(default=300, ge=0, validation_alias=AliasChoices('ARODONATA_CACHE_TTL'))
domain_list_ttl: int = Field(default=3600, ge=0, validation_alias=AliasChoices('ARODONATA_DOMAIN_LIST_TTL'))
max_incremental_changes: int = Field(default=500, ge=1, validation_alias=AliasChoices('ARODONATA_MAX_INCREMENTAL_CHANGES'))
tls_trust: TlsTrustMode = Field(default='tofu', validation_alias=AliasChoices('ARODONATA_TLS_TRUST'))
tls_known_hosts_path: str = Field(default_factory=lambda: str(Path.home() / '.config' / 'arodonata' / 'tls_known_hosts.json'), validation_alias=AliasChoices('ARODONATA_TLS_KNOWN_HOSTS_PATH'))
tls_fingerprints: str = Field(default='', validation_alias=AliasChoices('ARODONATA_TLS_FINGERPRINTS'))
database_url: str = Field(default='sqlite+aiosqlite:///:memory:', validation_alias=AliasChoices('ARODONATA_DATABASE_URL'))
sqlite_busy_timeout_ms: int = Field(default=30000, ge=0, validation_alias=AliasChoices('ARODONATA_SQLITE_BUSY_TIMEOUT_MS'))
cpcrud_schema_path: str | None = Field(default=None, validation_alias=AliasChoices('ARODONATA_CPCRUD_SCHEMA_PATH'))
trace_modules: str = Field(default='', validation_alias=AliasChoices('ARODONATA_TRACE_MODULES'))
```
##### Methods

###### `def __init__(self, **data: Any) -> None`

_No docstring._

###### `def servers(self) -> dict[str, ServerEndpointConfig]`

```python
@property
```
Return positional mapping of `mgmt_name -> ServerEndpointConfig`.

###### `def domain_sync_concurrency(self) -> int`

```python
@property
```
Maximum concurrent domain refreshes per MDS member (`max(1, concurrent_limit - 1)`).

###### `def trace_modules_rules(self) -> dict[str, bool]`

```python
@property
```
Parsed OpenTelemetry module span gating rules.

###### `def configure_tracing(self) -> dict[str, bool]`

Apply `trace_modules` rules if non-empty; preserve host rules when empty.

###### `def resolve_read_timeout(self, budget: float | None = None) -> float`

Compute socket read timeout for an API call (`budget + 5` or `max(api, login) + 5`).

###### `def model_dump(self, **kwargs: Any) -> dict[str, Any]`

Serialize settings with secrets and database URL passwords masked.

###### `def model_dump_json(self, **kwargs: Any) -> str`

Serialize settings to JSON with secrets and database URL passwords masked.

### `arodonata/core/context.py`

Contextvars propagation for authentication, operator metadata, and WriteSession overlays.

#### Module-Level Functions

##### `def get_auth_context() -> AuthContext | None`

Return the active `AuthContext` bound in the current execution context, if any.

##### `def auth_context(auth: AuthContext | None = None, *, username: str | None = None, password: str | None = None, api_key: str | None = None, user_id: str | None = None) -> Iterator[AuthContext]`

```python
@contextmanager
```
Bind an `AuthContext` to the current `contextvars` scope.

##### `def get_user_context() -> UserContext | None`

Return the active `UserContext` bound in the current execution context, if any.

##### `def user_context(user: UserContext | None = None, *, user_id: str | None = None, username: str | None = None, session_name: str | None = None, session_description: str | None = None, client_id: str | None = None, extra: dict[str, Any] | None = None) -> Iterator[UserContext]`

```python
@contextmanager
```
Bind a `UserContext` to the current `contextvars` scope.

##### `def get_write_session(mgmt_name: str | None = None, domain_name: str | None = None) -> WriteSession | None`

Return the active `WriteSession` if one is bound and matches `(mgmt_name, domain_name)`.

##### `def write_session_context(session: WriteSession) -> Iterator[WriteSession]`

```python
@contextmanager
```
Bind a `WriteSession` to the current `contextvars` scope.

#### class `AuthContext(BaseModel)`

Runtime authentication credentials propagated via `contextvars`.

##### Fields / Class Variables

```python
username: str | None = None
password: str | None = Field(default=None, repr=False)
api_key: str | None = Field(default=None, repr=False)
user_id: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def identity_key(self) -> str`

```python
@property
```
Stable non-secret HMAC-SHA256 identifier bound to the resolved credentials (`C4`).

#### class `UserContext(BaseModel)`

Operator and session attribution context propagated via `contextvars`.

##### Fields / Class Variables

```python
user_id: str
username: str | None = None
session_name: str | None = None
session_description: str | None = None
client_id: str | None = None
extra: dict[str, Any] = Field(default_factory=dict)
```
#### class `SessionOverlay`

In-memory read-your-own-writes overlay for an active `WriteSession`.

Tracks uncommitted object and service creations, updates, and deletions so read
methods within the same `WriteSession` context reflect uncommitted state without
mutating the shared database cache prior to `publish`.

##### Methods

###### `def __init__(self, mgmt_name: str, domain_name: str) -> None`

_No docstring._

###### `def upserted_objects(self) -> dict[str, CPObject]`

```python
@property
```
Return a shallow copy of upserted `CPObject` instances keyed by UID.

###### `def deleted_object_uids(self) -> set[str]`

```python
@property
```
Return a copy of deleted object UID tombstones.

###### `def upserted_services(self) -> dict[str, CPService]`

```python
@property
```
Return a shallow copy of upserted `CPService` instances keyed by UID.

###### `def deleted_service_uids(self) -> set[str]`

```python
@property
```
Return a copy of deleted service UID tombstones.

###### `def record_object_upsert(self, obj: CPObject) -> None`

Record an uncommitted object creation or update in this session.

###### `def record_object_delete(self, *, uid: str | None = None, name: str | None = None, obj_type: str | None = None) -> None`

Record an uncommitted object deletion in this session.

###### `def record_service_upsert(self, svc: CPService) -> None`

Record an uncommitted service creation or update in this session.

###### `def record_service_delete(self, *, uid: str | None = None, name: str | None = None, svc_type: str | None = None) -> None`

Record an uncommitted service deletion in this session.

###### `def apply_to_objects(self, cached_objects: Sequence[CPObject], *, types: Sequence[str] | None = None) -> list[CPObject]`

Merge uncommitted object creations, updates, and deletions onto `cached_objects`.

###### `def apply_to_services(self, cached_services: Sequence[CPService], *, types: Sequence[str] | None = None) -> list[CPService]`

Merge uncommitted service creations, updates, and deletions onto `cached_services`.

###### `def lookup_object_by_uid(self, uid: str) -> tuple[bool, CPObject | None]`

Check whether `uid` is overridden or deleted in this overlay.

Returns:
    `(True, None)` if deleted in the overlay,
    `(True, obj)` if created/updated in the overlay,
    `(False, None)` if untouched by the overlay.

###### `def lookup_service_by_uid(self, uid: str) -> tuple[bool, CPService | None]`

Check whether service `uid` is overridden or deleted in this overlay.

###### `def clear(self) -> None`

Discard all uncommitted overlay state (called on publish or discard).

#### class `WriteSession`

Isolated write session handle bound to `contextvars` with an in-memory `SessionOverlay`.

##### Methods

###### `def __init__(self, *, mgmt_name: str, domain_name: str, sid: str, server_ip: str, session_uid: str | None = None, session_name: str | None = None, auth: AuthContext | None = None, user: UserContext | None = None, overlay: SessionOverlay | None = None) -> None`

_No docstring._

###### `def sid(self) -> str`

```python
@property
```
Return the raw session identifier for transport calls (never included in repr).

###### `def matches_scope(self, mgmt_name: str | None = None, domain_name: str | None = None) -> bool`

Return True if this write session targets the specified `(mgmt_name, domain_name)`.

### `arodonata/core/errors.py`

Exception hierarchy and secret/SID redaction utilities for Arodonata.

#### Module-Level Functions

##### `def is_sensitive_key(key: str) -> bool`

Return True if a key name represents a credential, token, or session identifier.

##### `def redact_secret(value: str | None) -> str`

Return a constant placeholder for any secret or SID value.

##### `def redact_sid(text: str, known_sids: Iterable[str] | None = None) -> str`

Mask Check Point session identifiers and credentials in arbitrary text.

##### `def sanitize_mapping(data: dict[str, Any], known_sids: Iterable[str] | None = None) -> dict[str, Any]`

Recursively redact sensitive keys and SID strings from a dictionary.

#### class `ArodonataError(Exception)`

Base exception for all Arodonata errors with automatic SID/secret redaction.

##### Methods

###### `def __init__(self, message: str = '', *, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

#### class `ValidationError(ArodonataError, ValueError)`

Raised when a command, object type, template, or input parameter fails validation.

#### class `ConfigurationError(ArodonataError)`

Raised when configuration values are invalid, inconsistent, or unsupported.

#### class `MissingConfigurationError(ConfigurationError)`

Raised when required configuration parameters (e.g. target servers) are missing.

#### class `AuthenticationError(ArodonataError)`

Raised when authentication with a Check Point management server fails.

#### class `InvalidCredentialsError(AuthenticationError)`

Raised when the server explicitly rejects credentials or API keys (non-retryable).

#### class `SessionError(ArodonataError)`

Base exception for Check Point management session lifecycle errors.

#### class `SessionExpiredError(SessionError)`

Raised when a Check Point session identifier (SID) has expired or is invalid.

#### class `DirtySessionError(SessionError)`

Raised when a shared read session holds unpublished changes or object locks.

#### class `SessionStateError(SessionError)`

Raised when an operation violates session isolation or lifecycle constraints.

#### class `ServerIdentityError(ArodonataError)`

Base exception for TLS certificate fingerprint verification failures (never retried).

#### class `UnknownServerCertificateError(ServerIdentityError)`

Raised in pinned mode when a server presents an unpinned certificate fingerprint.

#### class `CertificateMismatchError(ServerIdentityError)`

Raised when a server presents a certificate differing from its pinned/TOFU fingerprint.

#### class `TrustStoreError(ServerIdentityError)`

Raised when the TLS trust store file cannot be read, parsed, or safely written.

#### class `TransportError(ArodonataError)`

Raised when low-level HTTP/TCP transport communication fails.

##### Methods

###### `def __init__(self, message: str = '', *, phase: TransportPhase = 'post-send', request_sent: bool | None = None, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

#### class `ApiTimeoutError(TransportError, TimeoutError)`

Raised when a socket connect/TLS handshake or HTTP response read times out.

##### Methods

###### `def __init__(self, message: str, *, phase: TransportPhase = 'read', request_sent: bool | None = None, host: str | None = None, port: int | None = None, command: str | None = None, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

#### class `RateLimitTimeoutError(TransportError, TimeoutError)`

Raised when acquiring a concurrency slot from RateLimiter exceeds rate_limit_slot_timeout.

#### class `TaskError(ArodonataError)`

Base exception for asynchronous Check Point server task failures.

#### class `TaskPollError(TaskError)`

Raised when consecutive show-task polling failures exceed the tolerance threshold.

#### class `TaskTimeoutError(TaskError, TimeoutError)`

Raised when a server task does not reach a terminal state within task_timeout.

#### class `CacheError(ArodonataError)`

Base exception for database cache and synchronization errors.

#### class `LockAcquisitionError(CacheError)`

Raised when a distributed database lock cannot be acquired within the timeout.

#### class `DomainNotFoundError(ArodonataError)`

Raised when a requested Check Point domain does not exist on the target server.

#### class `AmbiguousLayerName(ArodonataError)`

Raised when a domainless rulebase query matches layers/packages in multiple domains.

##### Methods

###### `def __init__(self, layer_or_package: str, candidates: list[tuple[str, str]]) -> None`

_No docstring._

#### class `ChangeReportInputError(ArodonataError)`

Raised when ChangeReport scope bounds or options are invalid.

#### class `UnsupportedFormat(ArodonataError)`

Raised when an unsupported report rendering format (e.g. 'pdf') is requested.

### `arodonata/core/events.py`

Typed domain progress events for synchronization and CPCRUD workflows.

Strictly decoupled from HTTP/SSE transport (`SSEEvent` lives in `arodonata.adapters.sse`).

#### class `DomainEvent(BaseModel)`

Base model for all domain progress events.

##### Fields / Class Variables

```python
event_type: str = 'domain_event'
timestamp: datetime = Field(default_factory=utc_now)
mgmt_name: str | None = None
domain: str | None = None
message: str = ''
details: dict[str, Any] = Field(default_factory=dict)
```
##### Methods

###### `def safe_details(self) -> dict[str, Any]`

Return `details` scrubbed of any sensitive keys or session identifiers.

#### class `SyncProgressEvent(DomainEvent)`

Typed progress event emitted during `stream_refresh_*` synchronization operations.

##### Fields / Class Variables

```python
event_type: str = 'sync_progress'
scope: SyncScope = 'objects'
phase: SyncPhase = 'syncing'
item_type: str = '*'
processed: int = 0
total: int | None = None
error: str | None = None
```
#### class `SyncStartedEvent(SyncProgressEvent)`

Emitted when a multi-domain synchronization run begins.

##### Fields / Class Variables

```python
event_type: str = 'sync_started'
phase: SyncPhase = 'started'
```
#### class `DomainSyncStartedEvent(SyncProgressEvent)`

Emitted when synchronization begins for a specific `(mgmt_name, domain)`.

##### Fields / Class Variables

```python
event_type: str = 'domain_sync_started'
phase: SyncPhase = 'syncing'
```
#### class `DomainSyncProgressEvent(SyncProgressEvent)`

Emitted as object/service/asset/rulebase pages are fetched for a domain.

##### Fields / Class Variables

```python
event_type: str = 'domain_sync_progress'
phase: SyncPhase = 'syncing'
```
#### class `DomainSyncSkippedEvent(SyncProgressEvent)`

Emitted when a domain or item_type slice is already fresh and skipped.

##### Fields / Class Variables

```python
event_type: str = 'domain_sync_skipped'
phase: SyncPhase = 'skipped'
```
#### class `DomainSyncCompletedEvent(SyncProgressEvent)`

Emitted when a domain or item_type slice completes synchronization.

##### Fields / Class Variables

```python
event_type: str = 'domain_sync_completed'
phase: SyncPhase = 'completed'
```
#### class `DomainSyncFailedEvent(SyncProgressEvent)`

Emitted when synchronization of a domain fails (e.g. InvalidCredentialsError or dirty session).

##### Fields / Class Variables

```python
event_type: str = 'domain_sync_failed'
phase: SyncPhase = 'failed'
```
#### class `SyncCompletedEvent(SyncProgressEvent)`

Emitted when an entire synchronization run completes across all target domains.

##### Fields / Class Variables

```python
event_type: str = 'sync_completed'
phase: SyncPhase = 'completed'
```
#### class `CPCRUDEvent(DomainEvent)`

Typed progress event emitted during `cpcrud.stream_apply()`.

##### Fields / Class Variables

```python
event_type: str = 'cpcrud_progress'
phase: CPCRUDPhase = 'action_completed'
action_id: str | None = None
operation: str | None = None
object_type: str | None = None
object_name: str | None = None
outcome: str | None = None
error: str | None = None
```
#### class `CPCRUDStartedEvent(CPCRUDEvent)`

Emitted when a CPCRUD plan execution begins.

##### Fields / Class Variables

```python
event_type: str = 'cpcrud_started'
phase: CPCRUDPhase = 'started'
```
#### class `CPCRUDActionEvent(CPCRUDEvent)`

Emitted before or after an individual planned action executes.

##### Fields / Class Variables

```python
event_type: str = 'cpcrud_action'
```
#### class `StagedSessionEvent(CPCRUDEvent)`

Emitted when `apply(..., no_publish=True, keep_session=True)` leaves a write session staged.

##### Fields / Class Variables

```python
event_type: str = 'cpcrud_staged_session'
phase: CPCRUDPhase = 'staged_session'
server_ip: str = ''
session_uid: str | None = None
session_name: str | None = None
sid: str | None = Field(default=None, repr=False, exclude=True)
```
#### class `CPCRUDDomainPublishedEvent(CPCRUDEvent)`

Emitted when a domain's dedicated write session is published during CPCRUD apply.

##### Fields / Class Variables

```python
event_type: str = 'cpcrud_domain_published'
phase: CPCRUDPhase = 'published'
session_uid: str | None = None
```
#### class `CPCRUDCompletedEvent(CPCRUDEvent)`

Emitted when `cpcrud.stream_apply()` finishes.

##### Fields / Class Variables

```python
event_type: str = 'cpcrud_completed'
phase: CPCRUDPhase = 'completed'
succeeded_count: int = 0
failed_count: int = 0
skipped_count: int = 0
```
### `arodonata/core/models/__init__.py`

Pydantic v2 domain models for Arodonata.

_No public classes or functions in this module._

### `arodonata/core/models/assets.py`

Gateway, cluster, VSX, and management server asset models (`Asset`).

#### class `Asset(BaseModel)`

Canonical Check Point gateway, cluster, cluster member, VSX, or server asset model.

##### Fields / Class Variables

```python
id: str = ''
asset_id: str = ''
uid: str
name: str
type: str
mgmt_name: str
domain_name: str
ipv4_address: str | None = Field(default=None, validation_alias=AliasChoices('ipv4_address', 'ipv4-address'))
ipv6_address: str | None = Field(default=None, validation_alias=AliasChoices('ipv6_address', 'ipv6-address'))
version: str | None = None
os_name: str | None = Field(default=None, validation_alias=AliasChoices('os_name', 'os-name'))
hardware: str | None = None
sic_status: str | None = Field(default=None, validation_alias=AliasChoices('sic_status', 'sic-status'))
parent_uid: str | None = None
parent_name: str | None = None
parent_id: str | None = None
parent_asset_id: str | None = None
member_uids: list[str] = Field(default_factory=list)
member_asset_ids: list[str] = Field(default_factory=list)
virtual_system_uids: list[str] = Field(default_factory=list)
virtual_system_asset_ids: list[str] = Field(default_factory=list)
interfaces: list[dict[str, Any]] = Field(default_factory=list)
network_security_blades: dict[str, Any] = Field(default_factory=dict, validation_alias=AliasChoices('network_security_blades', 'network-security-blades'))
comments: str = ''
color: str | None = None
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> Asset`

```python
@classmethod
```
Construct an `Asset` from a raw Check Point gateway/server dictionary.

### `arodonata/core/models/common.py`

Common domain types, constants, and API result models.

#### Module-Level Functions

##### `def normalize_object_type(item_type: str) -> str`

Normalize a network object type alias (e.g. `'range'` -> `'address-range'`).

##### `def normalize_service_type(item_type: str) -> str`

Normalize a service type alias (e.g. `'tcp'` -> `'service-tcp'`, `'group'` -> `'service-group'`).

##### `def normalize_asset_type(item_type: str) -> str`

Normalize an asset type alias (e.g. `'gateway'` -> `'simple-gateway'`, `'cluster'` -> `'simple-cluster'`).

##### `def normalize_any_type(item_type: str) -> str`

Normalize an object, service, or asset type alias across all scopes.

##### `def utc_now() -> datetime`

Return current naive UTC datetime (tzinfo=None).

##### `def to_naive_utc(dt: datetime) -> datetime`

```python
@overload
```
_No docstring._

##### `def to_naive_utc(dt: None) -> None`

```python
@overload
```
_No docstring._

##### `def to_naive_utc(dt: datetime | None) -> datetime | None`

Convert any datetime to naive UTC (tzinfo=None).

Aware datetimes are converted to UTC and stripped of tzinfo;
naive datetimes are assumed to already be in UTC and returned as-is.

#### class `ApiCallResult(BaseModel)`

Typed result of a single Check Point Management API call.

##### Fields / Class Variables

```python
success: bool
status_code: int = 200
data: dict[str, Any] = Field(default_factory=dict)
error_message: str | None = None
error_code: str | None = None
task_id: str | None = None
```
#### class `ApiQueryResult(BaseModel)`

Typed result of a paginated Check Point Management API query.

##### Fields / Class Variables

```python
success: bool
objects: list[dict[str, Any]] = Field(default_factory=list)
total: int = 0
error_message: str | None = None
code: str | None = None
```
### `arodonata/core/models/domains.py`

Domain, session cache, and synchronization state models.

#### class `DomainInfo(BaseModel)`

Check Point Management / MDSM domain metadata.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
uid: str
name: str
domain_type: str = 'domain'
active_ip: str | None = None
active_mds_ip: str | None = None
standby_ips: list[str] = Field(default_factory=list)
servers: list[dict[str, Any]] = Field(default_factory=list)
is_global: bool = False
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `SIDCacheEntry(BaseModel)`

Shared read-only Check Point session identifier entry with SID-safe repr().

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
sid: str = Field(repr=False)
server_ip: str
session_uid: str | None = None
auth_identity: str | None = None
created_at: datetime = Field(default_factory=utc_now)
last_used_at: datetime = Field(default_factory=utc_now)
expires_at: datetime | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `DomainSyncState(BaseModel)`

Per-(mgmt_name, domain_name, scope, item_type) synchronization state.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
scope: SyncScope
item_type: str = '*'
last_published_at: datetime | None = None
last_session_uid: str | None = None
synced_at: datetime | None = None
status: SyncStatus = 'idle'
object_count: int = 0
last_error: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def make_id(mgmt_name: str, domain_name: str, scope: str, item_type: str = '*') -> str`

```python
@staticmethod
```
Build the canonical composite primary key for domain_sync_state.

#### class `RefreshOutcome(BaseModel)`

Summary outcome returned by `refresh_objects`, `refresh_services`, `refresh_assets`, and `refresh_rulebases`.

##### Fields / Class Variables

```python
scope: SyncScope
refreshed_domains: list[str] = Field(default_factory=list)
skipped_domains: list[str] = Field(default_factory=list)
failed_domains: dict[str, str] = Field(default_factory=dict)
total_items: int = 0
```
### `arodonata/core/models/objects.py`

Network object domain models (`CPObject`) and search result structures.

#### class `CPObject(BaseModel)`

Canonical network object model stored in `arodonata_objects`.

##### Fields / Class Variables

```python
id: str = ''
object_id: str = ''
uid: str
name: str
type: str
mgmt_name: str
domain_name: str
original_domain: str | None = None
ipv4_address: str | None = Field(default=None, validation_alias=AliasChoices('ipv4_address', 'ipv4-address'))
ipv6_address: str | None = Field(default=None, validation_alias=AliasChoices('ipv6_address', 'ipv6-address'))
subnet4: str | None = None
mask_length4: int | None = Field(default=None, validation_alias=AliasChoices('mask_length4', 'mask-length4'))
subnet_mask: str | None = Field(default=None, validation_alias=AliasChoices('subnet_mask', 'subnet-mask'))
ipv4_address_first: str | None = Field(default=None, validation_alias=AliasChoices('ipv4_address_first', 'ipv4-address-first'))
ipv4_address_last: str | None = Field(default=None, validation_alias=AliasChoices('ipv4_address_last', 'ipv4-address-last'))
fqdn: str | None = None
is_sub_domain: bool | None = Field(default=None, validation_alias=AliasChoices('is_sub_domain', 'is-sub-domain'))
members: list[str] = Field(default_factory=list)
comments: str = ''
color: str | None = None
tags: list[str] = Field(default_factory=list)
nat_settings: dict[str, Any] = Field(default_factory=dict, validation_alias=AliasChoices('nat_settings', 'nat-settings'))
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> CPObject`

```python
@classmethod
```
Construct a `CPObject` from a raw Check Point Web API object dictionary.

#### class `GroupMembershipNode(BaseModel)`

Represents a group that directly or transitively contains a matched object.

##### Fields / Class Variables

```python
id: str = ''
object_id: str = ''
uid: str
name: str
mgmt_name: str
domain_name: str
depth: int = 1
parent_uids: list[str] = Field(default_factory=list)
parent_object_ids: list[str] = Field(default_factory=list)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `SearchResult(BaseModel)`

Result of `search_objects` with direct object matches and containing group hierarchies.

##### Fields / Class Variables

```python
query: str
matches: list[CPObject] = Field(default_factory=list)
memberships: dict[str, list[GroupMembershipNode]] = Field(default_factory=dict)
```
### `arodonata/core/models/rulebase.py`

Rulebase snapshot domain models for packages, layers, sections, and rules.

#### class `RulebasePackageLayerEntry(BaseModel)`

Links a policy package to an ordered layer or NAT policy in `rulebase_package_layer`.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
package_uid: str
package_name: str
rulebase_type: RulebaseType
layer_uid: str
layer_name: str
position: int = 0
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `RulebaseLayerEntry(BaseModel)`

Cached rulebase layer metadata in `rulebase_layer`.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
uid: str
name: str
rulebase_type: RulebaseType
parent_layer_uid: str | None = None
parent_rule_uid: str | None = None
is_global: bool = False
shared: bool = False
implicit_cleanup_action: str | None = None
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `RulebaseSectionEntry(BaseModel)`

Cached rulebase section header in `rulebase_section`.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
layer_uid: str
layer_name: str
rulebase_type: RulebaseType
uid: str
name: str
position: int = 0
from_rule: int | None = None
to_rule: int | None = None
rule_uids: list[str] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `AccessRuleEntry(BaseModel)`

Cached access-control rule or placeholder in `rulebase_access`.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
layer_uid: str
layer_name: str
section_uid: str | None = None
section_name: str | None = None
uid: str
name: str = ''
rule_type: str = 'access-rule'
position: int = 0
rule_number: str | None = None
enabled: bool = True
action: str | None = None
inline_layer_uid: str | None = None
inline_layer_name: str | None = None
placeholder_domain_layer_uid: str | None = None
source: list[str] = Field(default_factory=list)
destination: list[str] = Field(default_factory=list)
service: list[str] = Field(default_factory=list)
source_negate: bool = False
destination_negate: bool = False
service_negate: bool = False
track: str | None = None
install_on: list[str] = Field(default_factory=list)
comments: str = ''
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `NatRuleEntry(BaseModel)`

Cached NAT rule in `rulebase_nat`.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
package_uid: str
package_name: str
section_uid: str | None = None
section_name: str | None = None
uid: str
name: str = ''
rule_type: str = 'nat-rule'
position: int = 0
rule_number: str | None = None
enabled: bool = True
method: str | None = None
auto_generated: bool = False
original_source: str | None = None
original_destination: str | None = None
original_service: str | None = None
translated_source: str | None = None
translated_destination: str | None = None
translated_service: str | None = None
install_on: list[str] = Field(default_factory=list)
comments: str = ''
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `HttpsRuleEntry(BaseModel)`

Cached HTTPS inspection rule in `rulebase_https`.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
layer_uid: str
layer_name: str
section_uid: str | None = None
section_name: str | None = None
uid: str
name: str = ''
rule_type: str = 'https-rule'
position: int = 0
rule_number: str | None = None
enabled: bool = True
action: str | None = None
inline_layer_uid: str | None = None
source: list[str] = Field(default_factory=list)
destination: list[str] = Field(default_factory=list)
service: list[str] = Field(default_factory=list)
site_category: list[str] = Field(default_factory=list)
certificate: str | None = None
track: str | None = None
install_on: list[str] = Field(default_factory=list)
comments: str = ''
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `ThreatRuleEntry(BaseModel)`

Cached Threat Prevention rule in `rulebase_threat`.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
layer_uid: str
layer_name: str
section_uid: str | None = None
section_name: str | None = None
uid: str
name: str = ''
rule_type: str = 'threat-rule'
position: int = 0
rule_number: str | None = None
enabled: bool = True
action: str | None = None
protected_scope: list[str] = Field(default_factory=list)
source: list[str] = Field(default_factory=list)
destination: list[str] = Field(default_factory=list)
service: list[str] = Field(default_factory=list)
track: str | None = None
install_on: list[str] = Field(default_factory=list)
comments: str = ''
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `DomainRulebaseSnapshot(BaseModel)`

Complete rulebase snapshot for a single `(mgmt_name, domain_name)` replaced atomically.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
package_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
layers: list[RulebaseLayerEntry] = Field(default_factory=list)
sections: list[RulebaseSectionEntry] = Field(default_factory=list)
access_rules: list[AccessRuleEntry] = Field(default_factory=list)
nat_rules: list[NatRuleEntry] = Field(default_factory=list)
https_rules: list[HttpsRuleEntry] = Field(default_factory=list)
threat_rules: list[ThreatRuleEntry] = Field(default_factory=list)
```
### `arodonata/core/models/services.py`

Service object domain models (`CPService`).

#### class `CPService(BaseModel)`

Canonical service object model stored in `arodonata_services`.

##### Fields / Class Variables

```python
id: str = ''
service_id: str = ''
uid: str
name: str
type: str
mgmt_name: str
domain_name: str
original_domain: str | None = None
port: str | None = None
protocol: str | None = None
icmp_type: int | None = Field(default=None, validation_alias=AliasChoices('icmp_type', 'icmp-type'))
icmp_code: int | None = Field(default=None, validation_alias=AliasChoices('icmp_code', 'icmp-code'))
members: list[str] = Field(default_factory=list)
session_timeout: int | None = Field(default=None, validation_alias=AliasChoices('session_timeout', 'session-timeout'))
match_for_any: bool | None = Field(default=None, validation_alias=AliasChoices('match_for_any', 'match-for-any'))
comments: str = ''
color: str | None = None
tags: list[str] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> CPService`

```python
@classmethod
```
Construct a `CPService` from a raw Check Point Web API service dictionary.

### `arodonata/core/ports/__init__.py`

Hexagonal architectural ports (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`).

Pure typing protocols with zero transport or ORM dependencies.

#### class `AuthProvider(Protocol)`

```python
@runtime_checkable
```
Protocol for resolving dynamic credentials and receiving auth failure callbacks.

##### Methods

###### `async def get_credentials(self, mgmt_name: str, domain: str | None = None, *, user: UserContext | None = None) -> AuthContext`

Resolve runtime `AuthContext` for `(mgmt_name, domain)`.

###### `async def on_auth_failed(self, mgmt_name: str, auth: AuthContext, exc: Exception) -> None`

Notify provider that `auth` was rejected with `InvalidCredentialsError`.

#### class `LockPort(Protocol)`

```python
@runtime_checkable
```
Protocol for distributed cross-process lock coordination.

##### Methods

###### `async def acquire(self, lock_key: str, *, ttl_seconds: float = 60.0, owner_id: str | None = None, wait_timeout: float | None = None, poll_interval: float = 0.05) -> bool`

Attempt to acquire `lock_key`, reclaiming any expired lock row.

###### `async def renew(self, lock_key: str, *, ttl_seconds: float = 60.0, owner_id: str | None = None) -> bool`

Extend `expires_at` for an active lock held by `owner_id`.

###### `async def release(self, lock_key: str, *, owner_id: str | None = None) -> bool`

Release `lock_key` if owned by `owner_id`.

###### `def lock(self, lock_key: str, *, ttl_seconds: float = 60.0, owner_id: str | None = None, wait_timeout: float | None = None, poll_interval: float = 0.05) -> AbstractAsyncContextManager[str]`

Async context manager acquiring `lock_key` on entry and releasing it on exit.

#### class `CachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent cache operations across domains, sessions, objects, services, assets, and rulebases.

##### Methods

###### `async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False) -> list[DomainInfo]`

Return cached domains, excluding `Global` domains unless `include_global=True`.

###### `async def get_domain(self, mgmt_name: str, domain_name: str) -> DomainInfo | None`

Return a single cached domain by `(mgmt_name, domain_name)`.

###### `async def upsert_domains(self, domains: Sequence[DomainInfo]) -> None`

Insert or update domain rows in `arodonata_domains`.

###### `async def get_sid(self, mgmt_name: str, domain_name: str, *, auth_identity: str | None = None) -> SIDCacheEntry | None`

Fetch a cached shared read-only session entry for `(mgmt_name, domain_name, auth_identity)`.

###### `async def upsert_sid(self, entry: SIDCacheEntry) -> None`

Insert or update a shared read-only session entry in `arodonata_sid_cache`.

###### `async def evict_sid(self, mgmt_name: str, domain_name: str, *, auth_identity: str | None = None) -> bool`

Remove the cached SID for `(mgmt_name, domain_name)` (and optional `auth_identity`) immediately.

###### `async def list_sids(self, mgmt_name: str | None = None) -> list[SIDCacheEntry]`

List cached shared read-only SIDs, optionally filtered by `mgmt_name`.

###### `async def get_sync_state(self, mgmt_name: str, domain_name: str, scope: SyncScope, item_type: str = '*') -> DomainSyncState | None`

Fetch synchronization state for `(mgmt_name, domain_name, scope, item_type)`.

###### `async def list_sync_states(self, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> list[DomainSyncState]`

List synchronization states matching optional filters.

###### `async def upsert_sync_state(self, state: DomainSyncState) -> None`

Insert or update a `DomainSyncState` row in `arodonata_domain_sync_state`.

###### `async def get_objects(self, mgmt_name: str | None = None, domain_name: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPObject]`

Query cached network objects from `arodonata_objects`.

###### `async def get_object_by_uid(self, mgmt_name: str, domain_name: str, uid: str) -> CPObject | None`

Fetch a single cached `CPObject` by `(mgmt_name, domain_name, uid)`.

###### `async def replace_domain_objects(self, mgmt_name: str, domain_name: str, objects: Sequence[CPObject], *, types: Sequence[str], sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically replace objects of `types` for `(mgmt_name, domain_name)` without deleting other types.

###### `async def upsert_objects(self, objects: Sequence[CPObject], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

Insert or update `CPObject` rows in `arodonata_objects` (incremental sync).

###### `async def delete_objects_by_uids(self, mgmt_name: str, domain_name: str, uids: Sequence[str]) -> int`

Delete `CPObject` rows matching `uids` in `(mgmt_name, domain_name)`.

###### `async def get_services(self, mgmt_name: str | None = None, domain_name: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPService]`

Query cached service objects from `arodonata_services`.

###### `async def get_service_by_uid(self, mgmt_name: str, domain_name: str, uid: str) -> CPService | None`

Fetch a single cached `CPService` by `(mgmt_name, domain_name, uid)`.

###### `async def replace_domain_services(self, mgmt_name: str, domain_name: str, services: Sequence[CPService], *, types: Sequence[str], sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically replace services of `types` for `(mgmt_name, domain_name)` without deleting other types.

###### `async def upsert_services(self, services: Sequence[CPService], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

Insert or update `CPService` rows in `arodonata_services`.

###### `async def delete_services_by_uids(self, mgmt_name: str, domain_name: str, uids: Sequence[str]) -> int`

Delete `CPService` rows matching `uids` in `(mgmt_name, domain_name)`.

###### `async def get_assets(self, mgmt_name: str | None = None, domain_name: str | None = None, *, types: Sequence[str] | None = None) -> list[Asset]`

Query cached gateway/cluster/VSX/server assets from `arodonata_assets`.

###### `async def replace_domain_assets(self, mgmt_name: str, domain_name: str, assets: Sequence[Asset], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically replace all cached assets for `(mgmt_name, domain_name)`.

###### `async def upsert_assets(self, assets: Sequence[Asset]) -> int`

Insert or update `Asset` rows in `arodonata_assets`.

###### `async def replace_domain_rulebase(self, snapshot: DomainRulebaseSnapshot, *, sync_state: DomainSyncState | None = None) -> None`

Atomically replace all `arodonata_rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`.

###### `async def get_domain_rulebase(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot`

Load the cached `DomainRulebaseSnapshot` for `(mgmt_name, domain_name)`.

#### class `ApiPort(Protocol)`

```python
@runtime_checkable
```
Protocol for Check Point Management Web API transport and session operations.

##### Methods

###### `async def api_call(self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None, wait_for_task: bool = True, timeout: float | None = None) -> ApiCallResult`

Execute a single Check Point Management API command.

###### `async def api_query(self, mgmt_name: str, command: str, *, domain: str | None = None, details_level: str = 'standard', payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None, limit: int = 300) -> ApiQueryResult`

Execute a continuity-verified paginated Check Point object listing query.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]`

Open an isolated write session outside `sid_cache`, returning `(sid, server_ip)`.

###### `def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> Awaitable[bool]`

Log out a specific session identifier.

###### `async def close(self, *, logout: bool | None = None) -> None`

Close transport connections and optionally log out active sessions.

### `arodonata/core/services/__init__.py`

Core domain services for Arodonata v2 (`DomainService`, `DomainSyncCoordinator`,
`ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `SearchService`).

Strictly depends on `ApiPort`, `CachePort`, and `LockPort` protocols without transport or ORM imports.

_No public classes or functions in this module._

### `arodonata/core/services/asset_service.py`

Asset and gateway cache synchronization service (`AssetRefreshService`).

Provides:
- Paired `await refresh_assets(...)` and `stream_refresh_assets(...)` methods.
- Concurrent per-MDS-member domain asset collection via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`).
- `ClusterRelationshipManager`: links cluster members (`cluster-member` / `CpmiClusterMember`) to their
  parent cluster (`simple-cluster` / `CpmiGatewayCluster` / `CpmiVsxClusterNetobj`), populating
  `parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, and `member_asset_ids`.
- `VSXRelationshipManager`: resolves VSX gateways/clusters and virtual systems (`virtual-system` /
  `CpmiVsNetobj` / `CpmiVsClusterNetobj`) via encapsulated `generic-object` topology queries
  (`show-generic-objects`) and cross-domain MDS reconciliation, populating `parent_uid`, `parent_name`,
  `parent_id`, `parent_asset_id`, `virtual_system_uids`, and `virtual_system_asset_ids`.

#### class `ClusterRelationshipManager`

Enriches parent-child relationships between Check Point clusters and cluster members.

##### Methods

###### `def enrich(self, assets: Sequence[Asset]) -> list[Asset]`

Link cluster members to their parent clusters and return updated `Asset` models.

#### class `VSXRelationshipManager`

Resolves VSX gateway/cluster and virtual system relationships using encapsulated `generic-object` queries.

##### Methods

###### `def __init__(self, api: ApiPort) -> None`

_No docstring._

###### `async def enrich(self, mgmt_name: str, domain_name: str, assets: Sequence[Asset]) -> list[Asset]`

Resolve VSX parent-child topology for `assets` in `(mgmt_name, domain_name)`.

###### `def reconcile_cross_domain(self, assets: Sequence[Asset]) -> list[Asset]`

Reconcile VSX parent-child relationships across domains within the same `mgmt_name`.

Returns only the `Asset` instances whose `parent_uid`, `parent_name`, `parent_id`,
`parent_asset_id`, `virtual_system_uids`, or `virtual_system_asset_ids` changed.

#### class `AssetRefreshService`

Synchronizes and queries cached gateway, cluster, VSX, and management server assets (`assets`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: CachePort, coordinator: DomainSyncCoordinator, cluster_manager: ClusterRelationshipManager | None = None, vsx_manager: VSXRelationshipManager | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `def cluster_manager(self) -> ClusterRelationshipManager`

```python
@property
```
Return the `ClusterRelationshipManager`.

###### `def vsx_manager(self) -> VSXRelationshipManager`

```python
@property
```
Return the `VSXRelationshipManager`.

###### `async def stream_refresh_assets(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing gateway/cluster/VSX assets across domains.

###### `async def refresh_assets(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Refresh gateway/cluster/VSX assets across domains and return `RefreshOutcome`.

###### `async def get_assets(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[Asset]`

```python
@traced
```
Ensure assets are fresh (unless `cache_mode="cache"`), then return cached `Asset` models.

### `arodonata/core/services/domain_service.py`

Multi-Domain Security Management (MDSM) discovery, Global domain synthesis, and TTL tracking.

Implements `DomainListRefreshTracker` and `DomainService`:
- Discovers and caches domains across configured management servers via `show-domains`.
- Synthesizes an explicit `Global` domain row (`show-global-domain` or fallback synthesis).
- Excludes `Global` domains by default (`include_global=False`) and includes them when `include_global=True`.
- Tracks each domain's `active_ip`, `active_mds_ip`, and `standby_ips`, and re-resolves on failover.
- Enforces the 1-hour domain list TTL (`domain_list_ttl = 3600` seconds) via `DomainListRefreshTracker`.

#### Module-Level Functions

##### `def parse_domain_dict(mgmt_name: str, raw: dict[str, Any], *, default_host: str | None = None, mds_ip_by_name: dict[str, str] | None = None, now_fn: Callable[[], datetime] = utc_now) -> DomainInfo`

Convert a raw Check Point `show-domains` / `show-domain` / `show-global-domain` object into `DomainInfo`.

#### class `DomainListRefreshTracker`

Tracks per-server domain list freshness against the 1-hour (`domain_list_ttl`) TTL.

##### Methods

###### `def __init__(self, *, ttl_seconds: float = 3600.0, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `def ttl_seconds(self) -> float`

```python
@property
```
Configured domain list TTL in seconds (default 3600s / 1 hour).

###### `def mark_refreshed(self, mgmt_name: str, refreshed_at: datetime | None = None) -> datetime`

Record that `mgmt_name`'s domain list was refreshed at `refreshed_at`.

###### `def invalidate(self, mgmt_name: str | None = None) -> None`

Invalidate the domain list TTL memo for `mgmt_name` (or all servers if `None`).

###### `def last_refreshed_at(self, mgmt_name: str) -> datetime | None`

Return the last recorded in-memory refresh timestamp for `mgmt_name`.

###### `def needs_refresh(self, mgmt_name: str, *, has_cached_domains: bool, persisted_synced_at: datetime | None = None, mode: CacheMode = 'smart', ttl_override: float | None = None) -> bool`

Return `True` if `show-domains` should be re-fetched for `mgmt_name`.

#### class `DomainService`

Discovers, caches, and resolves MDSM domains (`show-domains`, `Global`, failover IPs).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: CachePort, lock_port: LockPort | None = None, tracker: DomainListRefreshTracker | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `def tracker(self) -> DomainListRefreshTracker`

```python
@property
```
Return the underlying `DomainListRefreshTracker`.

###### `def resolve_mgmt_names(self, mgmt_name: str | None = None) -> list[str]`

Return the target management server name(s).

###### `async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[DomainInfo]`

```python
@traced
```
Return domains for `mgmt_name` (or all configured servers), refreshing when stale.

Never triggers implicit background object-cache warm-up.

###### `async def get_domain(self, mgmt_name: str, domain_name: str, *, cache_mode: CacheMode = 'smart') -> DomainInfo`

```python
@traced
```
Resolve a single `DomainInfo` by `(mgmt_name, domain_name)`, refreshing once if missing.

###### `async def refresh_domains(self, mgmt_name: str | None = None, *, mode: CacheMode = 'force', include_global: bool = False) -> list[DomainInfo]`

```python
@traced
```
Explicitly refresh the domain list for `mgmt_name` (or all configured servers).

###### `async def refresh_domain_failover(self, mgmt_name: str, domain_name: str) -> DomainInfo | None`

```python
@traced
```
Re-query the MDS system domain to update `active_ip` and `active_mds_ip` after a failover.

### `arodonata/core/services/object_service.py`

Network object cache synchronization service (`ObjectService`).

Provides:
- Paired `await refresh_objects(...)` and `stream_refresh_objects(...)` methods.
- Canonical `CacheMode` support (`"cache"`, `"smart"`, `"smart-fast"`, `"force"`).
- Default tracked object types `DEFAULT_OBJECT_TYPES = ("host", "network", "address-range", "group", "dns-domain")`.
- Type-scoped atomic replacement in `arodonata_objects` (`CachePort.replace_domain_objects`).
- `"smart-fast"` incremental sync via `show-changes`: deletes removed UIDs directly, re-fetches
  added/modified tracked objects in full (`show-object` with `details-level="full"`), and falls back
  automatically to an atomic type-scoped reload when changes exceed `max_incremental_changes`
  (default 500) or any error occurs.

#### Module-Level Functions

##### `def resolve_object_query_command(item_type: str) -> tuple[str, dict[str, Any]]`

Map an object `item_type` to `(command, extra_payload)` for `api_query`.

##### `def extract_changes_from_show_changes(data: dict[str, Any], *, tracked_types: set[str]) -> tuple[list[tuple[str, str]], list[str]]`

Extract `(added_or_modified_uid_and_type, deleted_uids)` for `tracked_types` from `show-changes` response.

Returns:
    `(upserts, deleted_uids)` where `upserts` is a list of `(uid, obj_type)` pairs and
    `deleted_uids` is a list of deleted object UIDs.

#### class `ObjectService`

Synchronizes and queries cached network objects (`arodonata_objects`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: CachePort, coordinator: DomainSyncCoordinator, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def stream_refresh_objects(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing network objects across domains.

###### `async def refresh_objects(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Refresh network objects across domains and return `RefreshOutcome`.

###### `async def get_objects(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]`

```python
@traced
```
Ensure requested object types are fresh (unless `cache_mode="cache"`), then return objects with active `WriteSession` overlay applied.

###### `async def get_object_by_uid(self, mgmt_name: str, domain: str, uid: str, *, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | None`

```python
@traced
```
Fetch a single `CPObject` by `(mgmt_name, domain, uid)`, checking active `WriteSession` overlay first.

###### `def apply_context_overlay(cached_objects: Sequence[CPObject], *, mgmt_name: str | None = None, domain_name: str | None = None, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPObject]`

```python
@staticmethod
```
Merge active `WriteSession` overlay from `contextvars` onto `cached_objects`.

### `arodonata/core/services/search_service.py`

Cache-first object search, recursive group resolution, and structured aggregation (`SearchService`).

Provides:
- `search_objects`: classifies comma-separated search terms (`"ipv4"`, `"cidr"`, `"range"`,
  `"wildcard"`, `"uid"`, `"name"`), merges any active `WriteSession` overlay from `contextvars`,
  and traverses parent group memberships recursively up to `max_depth` (default 2).
- `describe_objects`: progressive-disclosure metadata describing cached object/service types,
  domains, servers, and filterable/groupable fields.
- `query_objects`: structured cross-domain filtering, grouping (`group_by`), and aggregation
  (`aggregate="count" | "list"`) over `arodonata_objects` and `arodonata_services` (distinguishing
  local vs Global objects via `original_domain`).
- `get_cache_status`: inspects `domain_sync_state` across `"domains"`, `"objects"`, `"services"`,
  `"assets"`, and `"rulebase"`, reporting `last_published_at`, `last_session_uid`, `synced_at`,
  and `cache_age_seconds`.

#### Module-Level Functions

##### `def classify_search_term(term: str) -> ClassifiedSearchTerm`

Classify a single search term into `"ipv4"`, `"cidr"`, `"range"`, `"wildcard"`, `"uid"`, or `"name"`.

##### `def matches_classified_term(obj: CPObject, term: ClassifiedSearchTerm, *, exact_match: bool = False) -> bool`

Return `True` if `obj` matches `term`.

#### class `ClassifiedSearchTerm`

Parsed representation of a single search term.

##### Methods

###### `def __init__(self, raw: str, kind: SearchTermKind, *, ip: ipaddress.IPv4Address | None = None, network: ipaddress.IPv4Network | None = None, range_bounds: tuple[int, int] | None = None) -> None`

_No docstring._

#### class `SearchService`

Cache-first object search, recursive group membership resolution, and structured queries.

##### Methods

###### `def __init__(self, *, cache: CachePort, object_service: ObjectService, service_cache: ServiceCacheService | None = None, asset_service: AssetRefreshService | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def search_objects(self, query: str, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, max_depth: int = 2, exact_match: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> SearchResult`

```python
@traced
```
Search cached objects across comma-separated terms and resolve parent group memberships up to `max_depth`.

###### `async def get_group_members(self, mgmt_name: str, domain: str, group_name_or_uid: str, *, recursive: bool = True, max_depth: int = 5, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject | CPService | Asset]`

```python
@traced
```
Return direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items for a group, service-group, cluster, or VSX container in `(mgmt_name, domain)`.

###### `async def describe_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, include_global: bool = True) -> dict[str, Any]`

```python
@traced
```
Return progressive-disclosure schema and summary counts for cached objects, services, and assets.

###### `async def query_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, domains: Sequence[str] | None = None, types: Sequence[str] | None = None, scope_origin: Literal['all', 'local', 'global'] = 'all', name_pattern: str | None = None, ip_subnet: str | None = None, port: str | None = None, protocol: str | None = None, tags: Sequence[str] | None = None, include_global: bool = False, group_by: Sequence[str] | None = None, aggregate: Literal['count', 'list', 'describe'] = 'list', limit: int = 100, offset: int = 0, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> dict[str, Any]`

```python
@traced
```
Execute structured cross-domain filtering, grouping, counting, or schema description over cached objects, services, and assets.

###### `async def get_cache_status(self, *, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> dict[str, Any]`

```python
@traced
```
Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness and `cache_age_seconds`.

### `arodonata/core/services/service_cache.py`

Dedicated service object cache synchronization service (`ServiceCacheService`).

Provides:
- Paired `await refresh_services(...)` and `stream_refresh_services(...)` methods for `arodonata_services`.
- Default tracked service types `DEFAULT_SERVICE_TYPES = ("service-tcp", "service-udp", "service-icmp", "service-group")`.
- On-demand syncing of additional types via `types=[...]` (e.g. `types=["service-other"]`) using
  type-scoped replacement (`CachePort.replace_domain_services`) without wiping other cached service types.
- `"smart-fast"` incremental sync via `show-changes` with automatic fallback to type-scoped reload.

#### Module-Level Functions

##### `def resolve_service_query_command(item_type: str) -> tuple[str, dict[str, Any]]`

Map a service `item_type` to `(command, extra_payload)` for `api_query`.

#### class `ServiceCacheService`

Synchronizes and queries cached service objects (`arodonata_services`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: CachePort, coordinator: DomainSyncCoordinator, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def stream_refresh_services(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing service objects across domains.

###### `async def refresh_services(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Refresh service objects across domains and return `RefreshOutcome`.

###### `async def get_services(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPService]`

```python
@traced
```
Ensure requested service types are fresh (unless `cache_mode="cache"`), then return services with active `WriteSession` overlay applied.

###### `async def get_service_by_uid(self, mgmt_name: str, domain: str, uid: str, *, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPService | None`

```python
@traced
```
Fetch a single `CPService` by `(mgmt_name, domain, uid)`, checking active `WriteSession` overlay first.

###### `def apply_context_overlay(cached_services: Sequence[CPService], *, mgmt_name: str | None = None, domain_name: str | None = None, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPService]`

```python
@staticmethod
```
Merge active `WriteSession` overlay from `contextvars` onto `cached_services`.

### `arodonata/core/services/sync_coordinator.py`

Unified domain synchronization coordinator (`DomainSyncCoordinator`).

Coordinates multi-domain cache synchronization across `"domains"`, `"objects"`, `"services"`,
`"assets"`, and `"rulebase"`:
- Groups target domains by `active_mds_ip` and bounds concurrent domain refreshes per MDS member
  to `max(1, concurrent_limit - 1)` (with MDS members running in parallel).
- Verifies freshness in `domain_sync_state` per `(mgmt_name, domain_name, scope, item_type)`,
  comparing `last_published_at` first and `last_session_uid` when timestamps match.
- Honors `cache_ttl` freshness memos unless invalidated via `invalidate_domain(mgmt_name, domain)`.
- Acquires per-domain distributed locks (`sync:{mgmt_name}:{domain_name}:{scope}`) via `LockPort`.
- Verifies that the shared read session is not dirty (`locks == 0` and
  `number-of-published-changes == 0`), raising `DirtySessionError` if uncommitted changes exist.
- Handles `InvalidCredentialsError` during staleness probes by reporting the domain as stale so
  the reload path records `RefreshOutcome.failed_domains` and emits `DomainSyncFailedEvent`
  while keeping previously cached rows intact.

#### Module-Level Functions

##### `def parse_cp_publish_timestamp(raw_time: Any) -> datetime | None`

Parse Check Point `publish-time` or `last-modify-time` dict/string/int into a naive UTC `datetime`.

#### class `DomainProbeResult`

Result of probing a single `(mgmt_name, domain_name)` for staleness across `item_types`.

##### Methods

###### `def __init__(self, *, mgmt_name: str, domain: DomainInfo, stale_types: list[str], fresh_types: list[str], existing_states: dict[str, DomainSyncState], remote_published_at: datetime | None = None, remote_session_uid: str | None = None, probe_error: Exception | None = None) -> None`

_No docstring._

###### `def is_stale(self) -> bool`

```python
@property
```
Return `True` if any requested `item_type` is stale or the probe failed.

#### class `DomainSyncCoordinator`

Coordinates bounded per-MDS-member domain synchronization, locking, and staleness probes.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: CachePort, lock_port: LockPort, domain_service: DomainService, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `def invalidated_domains(self) -> set[tuple[str, str]]`

```python
@property
```
Set of `(mgmt_name, domain_name)` pairs whose `cache_ttl` memo was invalidated.

###### `def invalidate_domain(self, mgmt_name: str, domain_name: str | None = None) -> None`

Invalidate freshness memo for `(mgmt_name, domain_name)` (or all domains on `mgmt_name` if None).

###### `async def resolve_target_domains(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart') -> list[DomainInfo]`

Resolve the list of `DomainInfo` targets for a synchronization run.

###### `async def verify_session_clean(self, mgmt_name: str, domain_name: str) -> None`

```python
@traced
```
Verify that the shared read session for `(mgmt_name, domain_name)` has no uncommitted changes.

Checks `locks == 0` and `number-of-published-changes == 0` (and `changes == 0`).
Raises `DirtySessionError` if the session is dirty.

###### `async def probe_domain_staleness(self, domain: DomainInfo, *, scope: SyncScope, item_types: Sequence[str], mode: CacheMode = 'smart', cache_ttl: float | None = None) -> DomainProbeResult`

```python
@traced
```
Determine which `item_types` are stale for `domain` under `scope` and `mode`.

###### `async def stream_ensure(self, *, scope: SyncScope, item_types: Sequence[str], handler: DomainSyncHandler, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, lock_ttl_seconds: float = 300.0) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing target domains concurrently per MDS member.

###### `async def ensure(self, *, scope: SyncScope, item_types: Sequence[str], handler: DomainSyncHandler, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, lock_ttl_seconds: float = 300.0) -> RefreshOutcome`

```python
@traced
```
Synchronize target domains and return the aggregated `RefreshOutcome`.

### `arodonata/core/telemetry.py`

Provider-agnostic OpenTelemetry instrumentation, module gating, and attribute sanitization.

#### Module-Level Functions

##### `def parse_trace_modules(spec: str) -> dict[str, bool]`

Parse comma-separated `module.prefix:on|off` rules into a boolean dictionary.

Example:
    `"arodonata:on,arodonata.api.client:off"` -> `{"arodonata": True, "arodonata.api.client": False}`

##### `def apply_trace_modules(spec_or_rules: str | dict[str, bool] | None) -> dict[str, bool]`

Apply module span gating rules ONLY when non-empty rules are provided.

When `spec_or_rules` is empty (`""`, `None`, or `{}`), this function intentionally
does NOT call `set_trace_modules({})` so any existing process-global trace rules
configured by the host application are preserved.

##### `def span_attrs(**attrs: Any) -> None`

Attach `arodonata.<key>` attributes to the current recording OpenTelemetry span.

- `None` values are omitted.
- Sensitive keys (`sid`, `api_key`, `password`, `token`, `secret`, etc.) are never recorded.
- String values are scrubbed via `redact_sid`.
- Operates as a zero-overhead no-op when no recording span is active.

##### `def traced(func: Callable[P, R]) -> Callable[P, R]`

```python
@overload
```
_No docstring._

##### `def traced(*, name: str | None = None, attrs: dict[str, Any] | None = None) -> Callable[[Callable[P, R]], Callable[P, R]]`

```python
@overload
```
_No docstring._

##### `def traced(func: Callable[P, R] | None = None, *, name: str | None = None, attrs: dict[str, Any] | None = None) -> Any`

Wrap a function in `@arlogi.otel.traced` while scrubbing chained `__cause__`/`__context__` exceptions.


---

## adapters — Check Point Transport (`AMgmtClient`), SQL Storage (15 Tables) & SSE

### `arodonata/adapters/__init__.py`

Hexagonal adapters for Arodonata (`checkpoint`, `storage`, `sse`).

_No public classes or functions in this module._

### `arodonata/adapters/checkpoint/__init__.py`

Check Point Management Web API adapter package (`arodonata.adapters.checkpoint`).

_No public classes or functions in this module._

### `arodonata/adapters/checkpoint/client.py`

Low-level Check Point Management API client (`AMgmtClient`) implementing `ApiPort`.

Provides:
- `api_call` with automatic read-only `sid_cache` reuse, active `WriteSession` context routing,
  transparent single re-login on session expiration, active domain IP failover re-resolution,
  `RateLimiter` concurrency gating per MDS member, `TaskWaiter` asynchronous task polling,
  and `SessionOverlay` updates for `add-*` / `set-*` / `delete-*` mutations.
- `api_query` continuity-verified pagination releasing the `RateLimiter` slot between pages.
- `create_dedicated_session` and `write_session` isolated write context manager.
- Default in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) when `engine=None`.

#### Module-Level Functions

##### `def is_readonly_command(command: str) -> bool`

Return `True` if `command` is a read-only Check Point Web API command (`C8`).

#### class `AMgmtClient`

Low-level asynchronous Check Point Management API client implementing `ApiPort`.

##### Methods

###### `def __init__(self, settings: ArodonataSettings | None = None, *, engine: AsyncEngine | str | None = None, db_manager: DatabaseManager | None = None, cache: CachePort | None = None, lock_port: LockPort | None = None, transport: ApiTransport | None = None, trust_policy: TrustPolicy | None = None, connection_pool: VerifiedConnectionPool | None = None, task_waiter: TaskWaiter | None = None, rate_limiter: RateLimiter | None = None, login_gate: LoginGate | None = None, auth_provider: AuthProvider | None = None, on_domain_invalidated: Callable[[str, str | None], None] | None = None, monotonic_fn: Callable[[], float] = time.monotonic, now_fn: Callable[[], datetime] = utc_now, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep, **settings_kwargs: Any) -> None`

_No docstring._

###### `def settings(self) -> ArodonataSettings`

```python
@property
```
Active `ArodonataSettings`.

###### `def db(self) -> DatabaseManager`

```python
@property
```
Underlying `DatabaseManager`.

###### `def owns_engine(self) -> bool`

```python
@property
```
Return `True` if this client created and owns its SQLAlchemy `AsyncEngine`.

###### `def cache(self) -> CachePort`

```python
@property
```
Underlying `CachePort` adapter.

###### `def lock_port(self) -> LockPort`

```python
@property
```
Underlying `LockPort` adapter.

###### `def transport(self) -> ApiTransport`

```python
@property
```
Underlying `ApiTransport`.

###### `def trust_policy(self) -> TrustPolicy`

```python
@property
```
Active `TrustPolicy`.

###### `def connection_pool(self) -> VerifiedConnectionPool`

```python
@property
```
Active `VerifiedConnectionPool`.

###### `def task_waiter(self) -> TaskWaiter`

```python
@property
```
Active `TaskWaiter`.

###### `def rate_limiter(self) -> RateLimiter`

```python
@property
```
Active `RateLimiter`.

###### `def login_gate(self) -> LoginGate`

```python
@property
```
Active `LoginGate`.

###### `def login_coordinator(self) -> LoginCoordinator`

```python
@property
```
Active `LoginCoordinator`.

###### `def session_cleaner(self) -> SessionCleaner`

```python
@property
```
Active `SessionCleaner`.

###### `def invalidated_domains(self) -> set[tuple[str, str]]`

```python
@property
```
Set of `(mgmt_name, domain_key)` pairs invalidated by `publish`.

###### `async def initialize(self, *, run_startup_cleanup: bool = False) -> None`

Ensure the database schema is initialized and optionally schedule startup cleanup.

###### `def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None`

Mark `(mgmt_name, domain)` as invalidated after `publish` and notify any facade callback.

###### `async def api_call(self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None, wait_for_task: bool = True, timeout: float | None = None) -> ApiCallResult`

```python
@traced
```
Execute a single Check Point Management API command (`/web_api/<command>`).

- Uses explicit `sid` if provided, else active `WriteSession` from `contextvars` if matching
  `(mgmt_name, domain)`, else shared read-only session from `LoginCoordinator` (`sid_cache`).
- Transparently evicts expired cached SIDs and retries once with a fresh session.
- Re-resolves domain `active_ip` on failover/unreachable error and retries once.
- Polls returned `task-id` / `tasks` via `TaskWaiter` when `wait_for_task=True`.
- Updates `WriteSession.overlay` on `add-*` / `set-*` / `delete-*` and invalidates domain on `publish`.

###### `async def api_query(self, mgmt_name: str, command: str, *, domain: str | None = None, details_level: str = 'standard', payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None, limit: int = DEFAULT_PAGE_LIMIT) -> ApiQueryResult`

```python
@traced
```
Execute a continuity-verified paginated Check Point object listing query.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]`

```python
@traced
```
Open an isolated write session outside `sid_cache`, returning `(sid, server_ip)`.

###### `async def write_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None, publish_on_exit: bool = True) -> AsyncIterator[WriteSession]`

```python
@asynccontextmanager
```
Open a context-bound isolated `WriteSession` outside `sid_cache`.

- Authenticates under `auth` (or active `AuthContext` / `AuthProvider` / static settings).
- Binds the `WriteSession` to `contextvars` so nested `api_call` mutations and read
  helpers automatically use its SID and `SessionOverlay`.
- Automatically executes `publish` on clean exit (when `publish_on_exit=True`),
  invalidating the domain freshness memo and clearing the overlay.
- Automatically executes `discard` and clears the overlay if an unhandled exception
  escapes the `async with` block.
- Always logs out the dedicated SID in `finally`.

###### `def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> Awaitable[bool]`

Log out a specific session identifier.

###### `async def close(self, *, logout: bool | None = None) -> None`

```python
@traced
```
Close transport connections, drain startup cleanup tasks, and dispose owned engine.

### `arodonata/adapters/checkpoint/pager.py`

Continuity-verified Check Point object listing pagination (`pager.py`).

Pages object listings in chunks (default 300, max 500), acquiring and releasing
a `RateLimiter` slot per page, recovering displaced objects across page boundaries
via a single `±10` window re-read on duplicate UID, and restarting once on
`total` or `from`/`to` discontinuity before failing with `code="paging_inconsistent"`.

#### Module-Level Functions

##### `async def paginate_objects(command: str, page_caller: PageCaller, *, details_level: str = 'standard', payload: dict[str, Any] | None = None, limit: int = DEFAULT_PAGE_LIMIT, collection_key: str | None = None) -> ApiQueryResult`

```python
@traced
```
Execute a continuity-verified paginated Check Point query (`api_query`).

Acquires and releases a `RateLimiter` slot per page (via `page_caller`), recovers
boundary-swapped duplicate UIDs via a single `±10` window re-read, and restarts
the listing at most once on `from`/`to`/`total` discontinuity before returning
`ApiQueryResult(success=False, code="paging_inconsistent")`.

### `arodonata/adapters/checkpoint/rate_limiter.py`

Per-MDS-member concurrency semaphore (`RateLimiter`) and login serialization (`LoginGate`).

Enforces `concurrent_limit` per MDS member (`active_mds_ip`) using database-backed
slot locks (`LockPort`) and strict FIFO in-process waiter queues, coalesces
overlapping background keepalive sweeps, and serializes logins per `active_mds_ip`.

#### class `RateLimiter`

Caps in-flight API requests per MDS member (`active_mds_ip`) to `concurrent_limit`.

Uses both in-process strict FIFO waiter queues and optional database-backed
slot locks (`LockPort`) so multiple coroutines wake in exact arrival order
and cross-process workers coordinate over `distributed_locks`.

##### Methods

###### `def __init__(self, *, concurrent_limit: int = 4, slot_timeout: float = 90.0, lock_port: LockPort | None = None, slot_lock_ttl: float = 180.0, monotonic_fn: Callable[[], float] = time.monotonic, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None`

_No docstring._

###### `def concurrent_limit(self) -> int`

```python
@property
```
Maximum concurrent requests per MDS member.

###### `def slot_timeout(self) -> float`

```python
@property
```
Default timeout in seconds when waiting for a free slot.

###### `async def slot(self, mds_ip: str, *, timeout: float | None = None) -> AsyncIterator[int]`

```python
@asynccontextmanager
```
Acquire a concurrency slot for `mds_ip` in FIFO order and release on exit.

###### `async def run_coalesced_keepalive(self, sweep_key: str, sweep_factory: Callable[[], Awaitable[T]]) -> T`

```python
@traced
```
Coalesce overlapping background keepalive sweeps for `sweep_key`.

If a keepalive sweep is already running for `sweep_key`, concurrent callers
await the active task via `asyncio.shield` (`I7`) instead of scheduling duplicate
sweeps or cancelling the shared task when a single waiter is cancelled.

#### class `LoginGate`

Serializes and rate-limits logins per MDS member (`active_mds_ip`) so concurrent domain logins
against the same MDS member do not trigger Check Point's 3 logins/minute rate limit (`C7`, `W4`, `W5`).

##### Methods

###### `def __init__(self, *, lock_port: LockPort | None = None, gate_lock_ttl: float = 180.0, min_login_interval: float = 0.0, monotonic_fn: Callable[[], float] = time.monotonic, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None`

_No docstring._

###### `def record_cooldown(self, mds_ip: str, cooldown_seconds: float) -> None`

Record a shared throttle or backoff cooldown window for `mds_ip` (`W4`).

###### `async def acquire(self, mds_ip: str, *, wait_timeout: float = 900.0) -> AsyncIterator[str]`

```python
@asynccontextmanager
```
Serialize login execution for `mds_ip` across in-process coroutines and distributed workers.

### `arodonata/adapters/checkpoint/sessions.py`

Session lifecycle, hybrid/dynamic authentication, failover resolution, and stale session cleanup.

Implements `LoginCoordinator` and `SessionCleaner`:
- Persists shared read-only session identifiers (`sid`) in `sid_cache`, reuses unexpired
  SIDs (`age < session_expire_seconds`), and immediately evicts a SID on session expiration
  error or when `keepalive` returns `success=False`.
- Supports static (`api_key`, `credential`), hybrid, and `"dynamic"` authentication via
  `contextvars` (`AuthContext`) and `AuthProvider` (with fast-fail `InvalidCredentialsError`,
  credential eviction, and `on_auth_failed` notification).
- Serializes logins per MDS member (`active_mds_ip`) via `LoginGate`, waits
  `login_throttle_window` (`70s`) on Check Point login throttling (bounded by `login_max_wait`),
  and retries transient database revision/lock conditions (`Database revision is in progress`).
- Re-resolves domain `active_ip` and `active_mds_ip` from the MDS system domain on failover.
- Cleans up stale sessions via `SessionCleaner` and seeds the system domain SID on startup.

#### Module-Level Functions

##### `def normalize_domain_key(domain: str | None) -> str`

Normalize `domain=None` or `""` to `'System Data'` for `sid_cache` keys.

##### `def is_session_expired_result(result: ApiCallResult) -> bool`

Return `True` if `result` indicates an invalid or expired Check Point session (`sid`).

##### `def is_login_throttled_result(result: ApiCallResult) -> bool`

Return `True` if `result` indicates Check Point per-IP login rate limiting / throttling.

##### `def is_transient_revision_lock_result(result: ApiCallResult) -> bool`

Return `True` if login failed transiently due to `Database revision is in progress` or lock contention.

##### `def is_invalid_credentials_result(result: ApiCallResult) -> bool`

Return `True` if the server explicitly rejected login credentials (non-retryable).

##### `def is_max_sessions_exceeded_result(result: ApiCallResult) -> bool`

Return `True` if login was refused because max sessions limit was reached.

##### `def is_failover_or_unreachable_result(result: ApiCallResult) -> bool`

Return `True` if a domain server IP returned a standby/failover or unreachable error.

##### `def parse_domain_entry(mgmt_name: str, raw: dict[str, Any], *, mds_ip_by_name: dict[str, str] | None = None) -> DomainInfo`

Parse a raw Check Point `show-domains` / `show-domain` / `show-global-domain` dictionary into `DomainInfo`.

#### class `LoginCoordinator`

Coordinates read-only `sid_cache` reuse, dedicated write sessions, per-MDS-member
login gating, throttle recovery (`70s`), dynamic credential resolution, and active
domain failover IP re-resolution.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, transport: ApiTransport, cache: CachePort, login_gate: LoginGate, rate_limiter: RateLimiter, auth_provider: AuthProvider | None = None, session_cleaner: SessionCleaner | None = None, monotonic_fn: Callable[[], float] = time.monotonic, now_fn: Callable[[], datetime] = utc_now, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None`

_No docstring._

###### `def active_dedicated_sids(self) -> dict[tuple[str, str], str]`

```python
@property
```
Mapping of `(mgmt_name, sid) -> server_ip` for open dedicated write sessions.

###### `def bind_session_cleaner(self, cleaner: SessionCleaner) -> None`

Attach `SessionCleaner` for max-sessions recovery.

###### `def has_inflight_or_cached_login(self, mgmt_name: str, domain: str | None = None) -> bool`

Return `True` if a login is currently in flight for `(mgmt_name, domain)`.

###### `def get_server_endpoint(self, mgmt_name: str) -> ServerEndpointConfig`

Resolve `ServerEndpointConfig` for `mgmt_name` from `ArodonataSettings`.

###### `async def resolve_target_ips(self, mgmt_name: str, domain: str | None = None, *, explicit_server_ip: str | None = None) -> tuple[str, str, int]`

Resolve `(server_ip, active_mds_ip, port)` for `(mgmt_name, domain)`.

###### `async def resolve_credentials(self, mgmt_name: str, domain: str | None = None, *, explicit_auth: AuthContext | None = None) -> AuthContext`

Resolve authentication credentials from explicit override, `contextvars`, `AuthProvider`, or static settings.

###### `def has_static_credentials(self, mgmt_name: str | None = None) -> bool`

Return `True` if static startup credentials exist for `mgmt_name` (or all configured servers).

###### `async def get_readonly_session(self, mgmt_name: str, domain: str | None = None, *, server_ip: str | None = None, force_new: bool = False) -> tuple[str, str]`

```python
@traced
```
Return `(sid, server_ip)` for a shared read-only session, reusing `arodonata_sid_cache` when fresh.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None, server_ip: str | None = None) -> tuple[str, str, str | None]`

```python
@traced
```
Open an isolated dedicated session outside `sid_cache`, returning `(sid, server_ip, session_uid)`.

###### `async def refresh_domain_active_ip(self, mgmt_name: str, domain_name: str) -> DomainInfo | None`

```python
@traced
```
Query the MDS system domain (`show-domains` / `show-global-domain` / `show-mdss`) to update `active_ip` and `active_mds_ip`.

###### `async def keepalive_sid(self, mgmt_name: str, domain: str | None = None, *, sid: str | None = None, server_ip: str | None = None) -> bool`

```python
@traced
```
Send `keepalive` for a cached or explicit session; immediately evict from `sid_cache` on failure.

###### `async def sweep_keepalives(self, mgmt_name: str | None = None) -> dict[str, bool]`

```python
@traced
```
Run a coalesced background keepalive sweep across cached read-only sessions.

###### `async def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> bool`

```python
@traced
```
Log out a specific session identifier and remove it from `arodonata_sid_cache` / dedicated tracking (`W7`).

###### `async def logout_all(self, *, include_cached_readonly: bool = True) -> int`

```python
@traced
```
Log out all dedicated sessions and optionally all cached read-only sessions.

#### class `SessionCleaner`

Cleans up stale or abandoned Check Point API sessions on startup and max-sessions refusal.

Invariants:
- When `schedule_startup_cleanup()` runs on client entry with static credentials and
  no cached SID or in-flight login exists for a server's system domain, the session
  opened by `SessionCleaner` is retained in `sid_cache` for subsequent read calls
  rather than logged out.
- When `ArodonataClient` / `AMgmtClient` enters in `"dynamic"` auth mode before any
  administrator credentials have been supplied, startup session cleanup is skipped
  without raising an authentication error.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, login_coordinator: LoginCoordinator, transport: ApiTransport, cache: CachePort, rate_limiter: RateLimiter) -> None`

_No docstring._

###### `def startup_tasks(self) -> set[asyncio.Task[Any]]`

```python
@property
```
Currently running startup cleanup tasks.

###### `def schedule_startup_cleanup(self) -> list[asyncio.Task[bool]]`

Schedule startup stale-session cleanup for all configured servers when static credentials exist.

###### `async def run_startup_cleanup(self) -> dict[str, bool]`

```python
@traced
```
Run startup session cleanup across all configured servers (skipping in cold dynamic mode).

###### `async def cleanup_server_sessions(self, mgmt_name: str, *, domain: str | None = None, auth: AuthContext | None = None, seed_system_sid: bool = False) -> bool`

```python
@traced
```
Inspect open Web API sessions on `mgmt_name` and discard stale/abandoned sessions.

###### `async def drain_startup_tasks(self, timeout: float = 5.0) -> None`

Wait up to `timeout` seconds for any background startup cleanup tasks to finish.

### `arodonata/adapters/checkpoint/task_waiter.py`

Self-managed asynchronous Check Point server task polling (`TaskWaiter`).

Polls `show-task` with exponential backoff (`2s` up to `10s`) within `task_timeout`,
tolerates up to 5 consecutive transient poll errors, and returns `ApiCallResult(success=True)`
only when every task reaches a status in the explicit success allowlist (`succeeded`).

#### Module-Level Functions

##### `def extract_task_ids(data: dict[str, Any]) -> list[str]`

Extract all `task-id` strings from a Check Point API response dictionary.

#### class `TaskWaiter`

Polls Check Point `show-task` until all tasks reach a terminal state.

##### Methods

###### `def __init__(self, *, task_timeout: float = 900.0, initial_delay: float = DEFAULT_INITIAL_DELAY, max_delay: float = DEFAULT_MAX_DELAY, backoff_factor: float = DEFAULT_BACKOFF_FACTOR, max_consecutive_errors: int = MAX_CONSECUTIVE_POLL_ERRORS, monotonic_fn: Callable[[], float] = time.monotonic, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None`

_No docstring._

###### `def task_timeout(self) -> float`

```python
@property
```
Default task timeout budget in seconds.

###### `async def wait_for_tasks(self, task_ids: list[str] | str, poll_fn: PollCallable, *, timeout: float | None = None, initial_result: ApiCallResult | None = None) -> ApiCallResult`

```python
@traced
```
Poll `show-task` via `poll_fn` until all `task_ids` complete.

Args:
    task_ids: One or more Check Point `task-id` strings.
    poll_fn: Async callable executing `show-task` with the given payload.
    timeout: Optional override for `task_timeout`.
    initial_result: Optional initial `ApiCallResult` that returned the task IDs.

### `arodonata/adapters/checkpoint/tls.py`

TLS certificate SHA-256 fingerprint verification (`TrustStore` and `TrustPolicy`).

Verifies server identity immediately after the TLS handshake and before any HTTP
request line, headers (`X-chkp-sid`), credentials, or JSON payloads are sent.

#### Module-Level Functions

##### `def normalize_fingerprint(raw: str) -> str`

Normalize a SHA-256 certificate fingerprint to colon-separated uppercase hex (`AA:BB:...`).

Accepts raw 64-character hex strings, colon-separated hex strings, or strings prefixed
with `SHA256:` / `sha256:`.

##### `def compute_der_fingerprint(der_bytes: bytes) -> str`

Compute the canonical colon-separated uppercase SHA-256 fingerprint of DER certificate bytes.

##### `def format_host_attr_for_url(host: str) -> str`

Wrap raw IPv6 literal in brackets `[...]` for URL/key construction.

##### `def format_host_port(host: str, port: int = 443) -> str`

Format `(host, port)` into canonical `host:port` or `[ipv6]:port` key.

##### `def parse_tls_fingerprints(raw: str | dict[str, str] | None, *, default_port: int = 443) -> dict[str, str]`

Parse `ARODONATA_TLS_FINGERPRINTS` into a mapping of `host:port -> normalized_fingerprint` and
collect standalone fingerprints under `*{index}` if no host is specified.

Supports:
- JSON object: `'{"10.0.0.1:443": "AA:BB...", "10.0.0.2": "CC:DD..."}'`
- Key-value CSV: `'10.0.0.1:443=AA:BB...,10.0.0.2=CC:DD...'`
- Bare fingerprint CSV: `'AA:BB...,CC:DD...'` (stored under `*:<idx>` as global trusted fingerprints)

#### class `KnownHostEntry(BaseModel)`

Persisted record for a trusted `host:port` certificate fingerprint.

##### Fields / Class Variables

```python
fingerprint: str
source: str = 'tofu'
first_seen_at: str = Field(default_factory=lambda: utc_now().isoformat())
last_seen_at: str = Field(default_factory=lambda: utc_now().isoformat())
```
#### class `TrustStore`

Manages persistent `tls_known_hosts.json` storage with atomic `0600` file writes and flock locking.

##### Methods

###### `def __init__(self, path: str | Path = DEFAULT_TLS_KNOWN_HOSTS_PATH, *, in_memory: bool = False) -> None`

_No docstring._

###### `def path(self) -> Path`

```python
@property
```
File path for `tls_known_hosts.json`.

###### `def in_memory(self) -> bool`

```python
@property
```
Return `True` if this store operates solely in memory without disk I/O.

###### `def entries(self) -> dict[str, KnownHostEntry]`

```python
@property
```
Return a copy of loaded known-host entries.

###### `def load(self) -> dict[str, KnownHostEntry]`

Load entries from disk if not already loaded (or no-op in memory mode).

###### `def get(self, host: str, port: int = 443) -> KnownHostEntry | None`

Return the `KnownHostEntry` for `(host, port)`, if present.

###### `def has_fingerprint_anywhere(self, fingerprint: str) -> bool`

Return `True` if `fingerprint` is already trusted for any address in the store.

###### `def record(self, host: str, port: int, fingerprint: str, *, source: str = 'tofu', persist: bool = True) -> KnownHostEntry`

Record a trusted fingerprint for `(host, port)` and atomically persist with mode `0600`.

#### class `TrustPolicy`

Enforces Check Point server TLS certificate fingerprint verification (`pinned`, `tofu`, `lab-memory`).

##### Methods

###### `def __init__(self, mode: TlsTrustMode = 'tofu', *, trust_store: TrustStore | None = None, known_hosts_path: str | Path = DEFAULT_TLS_KNOWN_HOSTS_PATH, pinned_fingerprints: str | dict[str, str] | None = None, lab_env: str | None = None) -> None`

_No docstring._

###### `def mode(self) -> TlsTrustMode`

```python
@property
```
Active TLS trust policy mode (`'pinned'`, `'tofu'`, or `'lab-memory'`).

###### `def trust_store(self) -> TrustStore`

```python
@property
```
Underlying `TrustStore` instance.

###### `def pinned_fingerprints(self) -> dict[str, str]`

```python
@property
```
Explicitly configured fingerprint pins (`ARODONATA_TLS_FINGERPRINTS`).

###### `def verify_der(self, host: str, port: int, der_cert: bytes | None) -> str`

```python
@traced
```
Verify raw DER certificate bytes presented by `(host, port)` before sending any HTTP request.

###### `def verify_fingerprint(self, host: str, port: int, presented_fingerprint: str) -> str`

```python
@traced
```
Verify a normalized or hex SHA-256 fingerprint for `(host, port)` according to `self.mode`.

### `arodonata/adapters/checkpoint/transport.py`

Native `aiohttp` Check Point Web API transport and `VerifiedConnectionPool`.

Enforces pre-request SHA-256 certificate fingerprint verification immediately after
the TLS handshake, separate socket connect/read timeouts, strict prohibition of
silent request re-transmission after socket write, and 10-second idle keep-alive
pooling restricted to read-only `show-*` commands.

#### Module-Level Functions

##### `def validate_command_name(command: str) -> str`

Validate and normalize a Check Point Web API command name against `^[a-z0-9]+(-[a-z0-9]+)*$`.

##### `def is_readonly_poolable_command(command: str) -> bool`

Return `True` if `command` is a read-only `show-*` command eligible for connection reuse.

##### `def extract_peer_der_cert(transport: asyncio.BaseTransport | None) -> bytes | None`

Extract binary DER peer certificate from an `asyncio` SSL transport.

##### `def verify_transport_peer_certificate(transport: asyncio.BaseTransport | None, *, host: str, port: int, trust_policy: TrustPolicy) -> str`

Verify the peer certificate on `transport` immediately after TLS handshake.

If verification fails, closes `transport` immediately before any HTTP bytes are written
and propagates `ServerIdentityError`.

#### class `PooledSocketEntry`

```python
@dataclass
```
Represents a fingerprint-verified keep-alive connection in `VerifiedConnectionPool`.

##### Fields / Class Variables

```python
host: str
port: int
fingerprint: str
protocol: Any
last_used_at: float
request_count: int = 1
```
##### Methods

###### `def is_usable(self, now: float, max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS) -> bool`

Return `True` if the connection is still open and within the idle window.

###### `def close(self) -> None`

Close the underlying protocol/transport.

#### class `VerifiedConnectionPool`

Pools fingerprint-verified keep-alive connections per `(server_ip, port)` for up to 10s idle.

Exclusively reuses connections for read-only `show-*` commands; mutating commands,
logins, logouts, keepalives, publish, and discard bypass pooling and close any
expired idle sockets.

##### Methods

###### `def __init__(self, *, max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS, monotonic_fn: Callable[[], float] = time.monotonic) -> None`

_No docstring._

###### `def max_idle_seconds(self) -> float`

```python
@property
```
Maximum idle duration in seconds (default 10.0s).

###### `def reuse_count(self) -> int`

```python
@property
```
Total number of requests that reused a pooled verified connection.

###### `def fresh_count(self) -> int`

```python
@property
```
Total number of requests that opened a fresh connection.

###### `def evict_expired(self, host: str | None = None, port: int | None = None) -> int`

Close and remove any pooled connections idle for more than `max_idle_seconds`.

###### `def acquire_for_command(self, host: str, port: int, command: str) -> PooledSocketEntry | None`

Acquire a pooled verified connection for `(host, port)` if `command` is `show-*`.

Always evicts expired connections first. For non-`show-*` commands, returns `None`
so a fresh TLS-verified connection is established.

###### `def release_after_command(self, entry: PooledSocketEntry, command: str, *, should_close: bool = False) -> bool`

Return a healthy verified connection to the pool if `command` is `show-*`, else close it.

###### `def close_host(self, host: str, port: int) -> int`

Close all pooled connections for `(host, port)`.

###### `def close_all(self) -> int`

Close all pooled connections across all hosts.

###### `def pooled_count(self, host: str | None = None, port: int | None = None) -> int`

Return the number of currently pooled idle connections.

#### class `FingerprintTCPConnector(aiohttp.TCPConnector)`

Custom `aiohttp.TCPConnector` that verifies peer SHA-256 certificate fingerprints
immediately after the TLS handshake and delegates keep-alive reuse to `VerifiedConnectionPool`.

##### Methods

###### `def __init__(self, *, trust_policy: TrustPolicy, connection_pool: VerifiedConnectionPool, ssl_context: ssl.SSLContext | None = None, **kwargs: Any) -> None`

_No docstring._

###### `async def connect(self, req: ClientRequest, traces: list[Trace], timeout: aiohttp.ClientTimeout) -> Connection`

_No docstring._

#### class `RawHttpResponse`

```python
@dataclass
```
Low-level HTTP response returned by a request executor.

##### Fields / Class Variables

```python
status: int
body: bytes
headers: dict[str, str] = field(default_factory=dict)
reused_connection: bool = False
```
#### class `RequestSenderProtocol(Protocol)`

Injectable low-level connection/request hook for deterministic unit testing.

#### class `ApiTransport`

Native `aiohttp` transport for Check Point Management Web API (`/web_api/<command>`).

Invariants:
- Verifies peer SHA-256 certificate fingerprint via `TrustPolicy` immediately after
  the TLS handshake and BEFORE sending any HTTP headers (`X-chkp-sid`), credentials,
  or command payload bytes.
- Enforces separate `connect_timeout` (`phase="connect"`) and socket `read_timeout`
  (`phase="read"`).
- NEVER automatically re-sends a request after request bytes have been written to
  the socket (on read timeout, `ConnectionResetError`, or `BrokenPipeError`).
- Reuses verified keep-alive connections via `VerifiedConnectionPool` (up to 10s idle)
  strictly for read-only `show-*` commands.

##### Methods

###### `def __init__(self, settings: ArodonataSettings | None = None, *, trust_policy: TrustPolicy | None = None, connection_pool: VerifiedConnectionPool | None = None, peer_cert_getter: Callable[[str, int], bytes | Awaitable[bytes | None] | None] | None = None, request_sender: RequestSenderProtocol | None = None) -> None`

_No docstring._

###### `def settings(self) -> ArodonataSettings`

```python
@property
```
Active `ArodonataSettings`.

###### `def trust_policy(self) -> TrustPolicy`

```python
@property
```
Active `TrustPolicy`.

###### `def connection_pool(self) -> VerifiedConnectionPool`

```python
@property
```
Active `VerifiedConnectionPool`.

###### `async def execute(self, host: str, command: str, payload: dict[str, Any] | None = None, *, port: int = 443, sid: str | None = None, timeout: float | None = None) -> ApiCallResult`

```python
@traced
```
Execute `POST https://<host>:<port>/web_api/<command>` with pre-request TLS verification.

###### `async def close(self) -> None`

```python
@traced
```
Close all pooled connections and the underlying `aiohttp.ClientSession`.

### `arodonata/adapters/sse/__init__.py`

Server-Sent Events (`SSEEvent`) adapter converting core `DomainEvent` models at the HTTP boundary.

#### Module-Level Functions

##### `def to_sse_event(domain_event: DomainEvent, *, event_id: str | None = None) -> SSEEvent`

Convert a typed `DomainEvent` (`SyncProgressEvent` or `CPCRUDEvent`) into an `SSEEvent`.

##### `async def stream_as_sse(events: AsyncIterable[DomainEvent]) -> AsyncIterator[SSEEvent]`

Convert an async stream of `DomainEvent` instances into `SSEEvent` items.

#### class `SSEEvent(BaseModel)`

Server-Sent Event wire model.

##### Fields / Class Variables

```python
event: str = 'message'
data: dict[str, Any] = Field(default_factory=dict)
id: str | None = None
retry: int | None = None
```
##### Methods

###### `def encode(self) -> str`

Serialize the event into a standard SSE wire frame (`event: ...\ndata: ...\n\n`).

### `arodonata/adapters/storage/__init__.py`

SQL storage adapters (`DatabaseManager`, `SqlCacheAdapter`, `SqlLockAdapter`, and SQLModel tables).

_No public classes or functions in this module._

### `arodonata/adapters/storage/cache_adapter.py`

SQL cache adapter (`SqlCacheAdapter`) implementing `CachePort` over SQLite and PostgreSQL.

#### class `SqlCacheAdapter`

SQLAlchemy/SQLModel cache adapter implementing `CachePort`.

##### Methods

###### `def __init__(self, db: DatabaseManager) -> None`

_No docstring._

###### `def db(self) -> DatabaseManager`

```python
@property
```
Return the underlying `DatabaseManager`.

###### `async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False) -> list[DomainInfo]`

```python
@traced
```
Return cached domains, excluding Global domains unless `include_global=True`.

###### `async def get_domain(self, mgmt_name: str, domain_name: str) -> DomainInfo | None`

```python
@traced
```
Return a single cached domain by `(mgmt_name, domain_name)`.

###### `async def upsert_domains(self, domains: Sequence[DomainInfo]) -> None`

```python
@traced
```
Insert or update domain rows in `arodonata_domains`.

###### `async def get_sid(self, mgmt_name: str, domain_name: str, *, auth_identity: str | None = None) -> SIDCacheEntry | None`

```python
@traced
```
Fetch a cached shared read-only session entry for `(mgmt_name, domain_name)`.

###### `async def upsert_sid(self, entry: SIDCacheEntry) -> None`

```python
@traced
```
Insert or update a shared read-only session entry in `arodonata_sid_cache`.

###### `async def evict_sid(self, mgmt_name: str, domain_name: str, *, auth_identity: str | None = None) -> bool`

```python
@traced
```
Remove the cached SID for `(mgmt_name, domain_name)` immediately.

###### `async def list_sids(self, mgmt_name: str | None = None) -> list[SIDCacheEntry]`

```python
@traced
```
List cached shared read-only SIDs, optionally filtered by `mgmt_name`.

###### `async def get_sync_state(self, mgmt_name: str, domain_name: str, scope: SyncScope, item_type: str = '*') -> DomainSyncState | None`

```python
@traced
```
Fetch synchronization state for `(mgmt_name, domain_name, scope, item_type)`.

###### `async def list_sync_states(self, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> list[DomainSyncState]`

```python
@traced
```
List synchronization states matching optional filters.

###### `async def upsert_sync_state(self, state: DomainSyncState) -> None`

```python
@traced
```
Insert or update a `DomainSyncState` row in `arodonata_domain_sync_state`.

###### `async def get_objects(self, mgmt_name: str | None = None, domain_name: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPObject]`

```python
@traced
```
Query cached network objects from `arodonata_objects`.

###### `async def get_object_by_uid(self, mgmt_name: str, domain_name: str, uid: str) -> CPObject | None`

```python
@traced
```
Fetch a single cached `CPObject` by `(mgmt_name, domain_name, uid)`.

###### `async def replace_domain_objects(self, mgmt_name: str, domain_name: str, objects: Sequence[CPObject], *, types: Sequence[str], sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically replace objects of `types` for `(mgmt_name, domain_name)` without deleting other types.

###### `async def upsert_objects(self, objects: Sequence[CPObject], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Insert or update `CPObject` rows in `arodonata_objects`.

###### `async def delete_objects_by_uids(self, mgmt_name: str, domain_name: str, uids: Sequence[str]) -> int`

```python
@traced
```
Delete `CPObject` rows matching `uids` in `(mgmt_name, domain_name)`.

###### `async def get_services(self, mgmt_name: str | None = None, domain_name: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPService]`

```python
@traced
```
Query cached service objects from `arodonata_services`.

###### `async def get_service_by_uid(self, mgmt_name: str, domain_name: str, uid: str) -> CPService | None`

```python
@traced
```
Fetch a single cached `CPService` by `(mgmt_name, domain_name, uid)`.

###### `async def replace_domain_services(self, mgmt_name: str, domain_name: str, services: Sequence[CPService], *, types: Sequence[str], sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically replace services of `types` for `(mgmt_name, domain_name)` without deleting other types.

###### `async def upsert_services(self, services: Sequence[CPService], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Insert or update `CPService` rows in `arodonata_services`.

###### `async def delete_services_by_uids(self, mgmt_name: str, domain_name: str, uids: Sequence[str]) -> int`

```python
@traced
```
Delete `CPService` rows matching `uids` in `(mgmt_name, domain_name)`.

###### `async def get_assets(self, mgmt_name: str | None = None, domain_name: str | None = None, *, types: Sequence[str] | None = None) -> list[Asset]`

```python
@traced
```
Query cached gateway/cluster/VSX/server assets from `arodonata_assets`.

###### `async def replace_domain_assets(self, mgmt_name: str, domain_name: str, assets: Sequence[Asset], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically replace all cached assets for `(mgmt_name, domain_name)`.

###### `async def upsert_assets(self, assets: Sequence[Asset]) -> int`

```python
@traced
```
Insert or update `Asset` rows in `arodonata_assets`.

###### `async def replace_domain_rulebase(self, snapshot: DomainRulebaseSnapshot, *, sync_state: DomainSyncState | None = None) -> None`

```python
@traced
```
Atomically replace all `arodonata_rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`.

###### `async def get_domain_rulebase(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot`

```python
@traced
```
Load the cached `DomainRulebaseSnapshot` for `(mgmt_name, domain_name)`.

### `arodonata/adapters/storage/database.py`

Database lifecycle manager and SHA-256 schema hash auto-migration (`DatabaseManager`).

#### Module-Level Functions

##### `def compute_schema_hash(metadata: MetaData | None = None) -> str`

Compute a deterministic SHA-256 hex digest over managed SQLModel tables, columns, and indexes.

#### class `DatabaseManager`

Manages SQLAlchemy AsyncEngine, sessions, and SHA-256 schema hash auto-migration.

##### Methods

###### `def __init__(self, engine: AsyncEngine | str | None = None, *, busy_timeout_ms: int = 30000, metadata: MetaData | None = None) -> None`

_No docstring._

###### `def engine(self) -> AsyncEngine`

```python
@property
```
Return the underlying `AsyncEngine`.

###### `def owns_engine(self) -> bool`

```python
@property
```
Return `True` if this `DatabaseManager` created and owns the `AsyncEngine`.

###### `def is_initialized(self) -> bool`

```python
@property
```
Return `True` after `initialize()` has completed.

###### `def migration_inspection_count(self) -> int`

```python
@property
```
Number of times full per-table column/index migration inspection ran.

###### `async def initialize(self) -> str`

```python
@traced
```
Initialize schema and apply missing tables/columns/indexes when `schema_hash` changes.

Serializes schema inspection and DDL across workers (`pg_advisory_xact_lock` on PostgreSQL,
`BEGIN IMMEDIATE` + in-process lock on SQLite) and verifies both `arodonata_schema_version`
and the existence of all managed tables before skipping migration.

###### `async def session(self) -> AsyncIterator[AsyncSession]`

```python
@asynccontextmanager
```
Provide a transactional `AsyncSession` scope.

###### `async def close(self) -> None`

```python
@traced
```
Dispose of the underlying `AsyncEngine` if owned by this `DatabaseManager`.

### `arodonata/adapters/storage/lock_adapter.py`

Database-backed distributed lock adapter (`SqlLockAdapter` / `DatabaseLockManager`).

#### class `SqlLockAdapter`

Coordinates cross-process locks via the `arodonata_distributed_locks` table with DB-time expiration.

##### Methods

###### `def __init__(self, db: DatabaseManager, *, default_owner_id: str | None = None, db_now_fn: Callable[[AsyncSession], Any] | None = None) -> None`

_No docstring._

###### `def default_owner_id(self) -> str`

```python
@property
```
Default lock owner identifier for this adapter instance.

###### `async def acquire(self, lock_key: str, *, ttl_seconds: float = 60.0, owner_id: str | None = None, wait_timeout: float | None = None, poll_interval: float = 0.05) -> bool`

```python
@traced
```
Acquire `lock_key`, reclaiming expired rows and optionally waiting up to `wait_timeout`.

###### `async def renew(self, lock_key: str, *, ttl_seconds: float = 60.0, owner_id: str | None = None) -> bool`

```python
@traced
```
Extend `expires_at` for an active (unexpired) lock held by `owner_id` (`W13`, `W16`, `I6`).

###### `async def release(self, lock_key: str, *, owner_id: str | None = None) -> bool`

```python
@traced
```
Release `lock_key` ONLY when owned by `owner_id` (defaults to `default_owner_id`) (`I6`).

###### `async def lock(self, lock_key: str, *, ttl_seconds: float = 60.0, owner_id: str | None = None, wait_timeout: float | None = None, poll_interval: float = 0.05) -> AsyncIterator[str]`

```python
@asynccontextmanager
```
Async context manager acquiring `lock_key` on entry and releasing on exit.

### `arodonata/adapters/storage/tables.py`

SQLModel table definitions for Arodonata v2 persistence (`SQLite` and `PostgreSQL`).

#### class `SchemaVersionRecord(SQLModel)`

Tracks applied SQLModel metadata SHA-256 hashes to skip redundant migration checks.

##### Fields / Class Variables

```python
schema_hash: str = Field(primary_key=True)
applied_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `DistributedLockRecord(SQLModel)`

Cross-process distributed lock row with expiration timestamp in `arodonata_distributed_locks`.

##### Fields / Class Variables

```python
lock_key: str = Field(primary_key=True)
owner_id: str = Field(index=True)
acquired_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
expires_at: datetime = Field(sa_column=Column(DateTime(timezone=False), nullable=False, index=True))
```
#### class `DomainRecord(SQLModel)`

Cached Check Point domain metadata in `arodonata_domains`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
uid: str = Field(index=True)
name: str = Field(index=True)
domain_type: str = Field(default='domain')
active_ip: str | None = Field(default=None)
active_mds_ip: str | None = Field(default=None, index=True)
standby_ips: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
servers: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
is_global: bool = Field(default=False, index=True)
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `SIDCacheRecord(SQLModel)`

Persistent shared read-only session cache row in `arodonata_sid_cache`.

Strictly omits `sid` from `__repr__` and `__str__`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
sid: str = Field(repr=False)
server_ip: str
session_uid: str | None = Field(default=None)
auth_identity: str | None = Field(default=None)
created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
last_used_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
expires_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=False), nullable=True))
```
#### class `DomainSyncStateRecord(SQLModel)`

Unified per-`(mgmt_name, domain_name, scope, item_type)` synchronization state in `arodonata_domain_sync_state`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
scope: str = Field(index=True)
item_type: str = Field(default='*', index=True)
last_published_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=False), nullable=True))
last_session_uid: str | None = Field(default=None)
synced_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=False), nullable=True))
status: str = Field(default='idle')
object_count: int = Field(default=0)
last_error: str | None = Field(default=None)
```
#### class `CPObjectRecord(SQLModel)`

Cached network object row in `arodonata_objects`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
object_id: str = Field(default='', index=True)
uid: str = Field(index=True)
name: str = Field(index=True)
type: str = Field(index=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
original_domain: str | None = Field(default=None, index=True)
ipv4_address: str | None = Field(default=None, index=True)
ipv6_address: str | None = Field(default=None)
subnet4: str | None = Field(default=None, index=True)
mask_length4: int | None = Field(default=None)
subnet_mask: str | None = Field(default=None)
ipv4_address_first: str | None = Field(default=None)
ipv4_address_last: str | None = Field(default=None)
fqdn: str | None = Field(default=None, index=True)
is_sub_domain: bool | None = Field(default=None)
members: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
comments: str = Field(default='')
color: str | None = Field(default=None)
tags: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
nat_settings: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `CPServiceRecord(SQLModel)`

Cached service object row in `arodonata_services`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
service_id: str = Field(default='', index=True)
uid: str = Field(index=True)
name: str = Field(index=True)
type: str = Field(index=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
original_domain: str | None = Field(default=None, index=True)
port: str | None = Field(default=None, index=True)
protocol: str | None = Field(default=None, index=True)
icmp_type: int | None = Field(default=None)
icmp_code: int | None = Field(default=None)
members: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
session_timeout: int | None = Field(default=None)
match_for_any: bool | None = Field(default=None)
comments: str = Field(default='')
color: str | None = Field(default=None)
tags: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `AssetRecord(SQLModel)`

Cached gateway, cluster, cluster member, VSX, or management server asset row in `arodonata_assets`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
asset_id: str = Field(default='', index=True)
uid: str = Field(index=True)
name: str = Field(index=True)
type: str = Field(index=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
ipv4_address: str | None = Field(default=None, index=True)
ipv6_address: str | None = Field(default=None)
version: str | None = Field(default=None)
os_name: str | None = Field(default=None)
hardware: str | None = Field(default=None)
sic_status: str | None = Field(default=None)
parent_uid: str | None = Field(default=None, index=True)
parent_name: str | None = Field(default=None)
parent_id: str | None = Field(default=None, index=True)
parent_asset_id: str | None = Field(default=None, index=True)
member_uids: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
member_asset_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
virtual_system_uids: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
virtual_system_asset_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
interfaces: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
network_security_blades: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
comments: str = Field(default='')
color: str | None = Field(default=None)
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `RulebasePackageLayerRecord(SQLModel)`

Cached policy package to ordered layer/NAT linkage in `arodonata_rulebase_package_layer`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
package_uid: str = Field(index=True)
package_name: str = Field(index=True)
rulebase_type: str = Field(index=True)
layer_uid: str = Field(index=True)
layer_name: str = Field(index=True)
position: int = Field(default=0)
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `RulebaseLayerRecord(SQLModel)`

Cached rulebase layer row in `arodonata_rulebase_layer`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
uid: str = Field(index=True)
name: str = Field(index=True)
rulebase_type: str = Field(index=True)
parent_layer_uid: str | None = Field(default=None, index=True)
parent_rule_uid: str | None = Field(default=None, index=True)
is_global: bool = Field(default=False)
shared: bool = Field(default=False)
implicit_cleanup_action: str | None = Field(default=None)
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `RulebaseSectionRecord(SQLModel)`

Cached rulebase section header row in `arodonata_rulebase_section`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
layer_uid: str = Field(index=True)
layer_name: str = Field(index=True)
rulebase_type: str = Field(index=True)
uid: str = Field(index=True)
name: str = Field(index=True)
position: int = Field(default=0)
from_rule: int | None = Field(default=None)
to_rule: int | None = Field(default=None)
rule_uids: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `AccessRuleRecord(SQLModel)`

Cached access-control rule row in `arodonata_rulebase_access`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
layer_uid: str = Field(index=True)
layer_name: str = Field(index=True)
section_uid: str | None = Field(default=None, index=True)
section_name: str | None = Field(default=None)
uid: str = Field(index=True)
name: str = Field(default='', index=True)
rule_type: str = Field(default='access-rule')
position: int = Field(default=0)
rule_number: str | None = Field(default=None)
enabled: bool = Field(default=True)
action: str | None = Field(default=None)
inline_layer_uid: str | None = Field(default=None)
inline_layer_name: str | None = Field(default=None)
placeholder_domain_layer_uid: str | None = Field(default=None)
source: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
destination: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
service: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
source_negate: bool = Field(default=False)
destination_negate: bool = Field(default=False)
service_negate: bool = Field(default=False)
track: str | None = Field(default=None)
install_on: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
comments: str = Field(default='')
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `NatRuleRecord(SQLModel)`

Cached NAT rule row in `arodonata_rulebase_nat`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
package_uid: str = Field(index=True)
package_name: str = Field(index=True)
section_uid: str | None = Field(default=None, index=True)
section_name: str | None = Field(default=None)
uid: str = Field(index=True)
name: str = Field(default='', index=True)
rule_type: str = Field(default='nat-rule')
position: int = Field(default=0)
rule_number: str | None = Field(default=None)
enabled: bool = Field(default=True)
method: str | None = Field(default=None)
auto_generated: bool = Field(default=False)
original_source: str | None = Field(default=None)
original_destination: str | None = Field(default=None)
original_service: str | None = Field(default=None)
translated_source: str | None = Field(default=None)
translated_destination: str | None = Field(default=None)
translated_service: str | None = Field(default=None)
install_on: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
comments: str = Field(default='')
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `HttpsRuleRecord(SQLModel)`

Cached HTTPS inspection rule row in `arodonata_rulebase_https`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
layer_uid: str = Field(index=True)
layer_name: str = Field(index=True)
section_uid: str | None = Field(default=None, index=True)
section_name: str | None = Field(default=None)
uid: str = Field(index=True)
name: str = Field(default='', index=True)
rule_type: str = Field(default='https-rule')
position: int = Field(default=0)
rule_number: str | None = Field(default=None)
enabled: bool = Field(default=True)
action: str | None = Field(default=None)
inline_layer_uid: str | None = Field(default=None)
source: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
destination: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
service: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
site_category: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
certificate: str | None = Field(default=None)
track: str | None = Field(default=None)
install_on: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
comments: str = Field(default='')
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `ThreatRuleRecord(SQLModel)`

Cached Threat Prevention rule row in `arodonata_rulebase_threat`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
layer_uid: str = Field(index=True)
layer_name: str = Field(index=True)
section_uid: str | None = Field(default=None, index=True)
section_name: str | None = Field(default=None)
uid: str = Field(index=True)
name: str = Field(default='', index=True)
rule_type: str = Field(default='threat-rule')
position: int = Field(default=0)
rule_number: str | None = Field(default=None)
enabled: bool = Field(default=True)
action: str | None = Field(default=None)
protected_scope: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
source: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
destination: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
service: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
track: str | None = Field(default=None)
install_on: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
comments: str = Field(default='')
raw_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```

---

## rulebase — Cached Rulebase Source, SmartConsole Numbering & Local Filtering

### `arodonata/rulebase/__init__.py`

Rulebase introspection, snapshot caching, SmartConsole numbering, and local filtering (`arodonata.rulebase`).

_No public classes or functions in this module._

### `arodonata/rulebase/filter.py`

Local cache-backed rulebase filtering and formatting (`rulebase/filter.py`).

Evaluates search/filter expressions locally against a numbered rulebase (`PackageRulebase`
or `NumberedLayerRulebase`) and cached `CPObject` / `CPService` dictionaries without
Check Point Management API round-trips, formatting output as `"markdown"`,
`"model_friendly"`, `"raw"`, or `"cpcrud"`.

#### Module-Level Functions

##### `def rule_matches_filter(rule: NumberedRule, tokens: Sequence[tuple[str | None, str]], *, objects: Sequence[CPObject] = (), services: Sequence[CPService] = ()) -> bool`

Return `True` if `rule` satisfies all `(qualifier, value)` filter tokens.

##### `def format_rules_markdown(target_name: str, rulebase_type: str, rules: Sequence[NumberedRule], sections: Sequence[NumberedSection] | None = None) -> str`

Format numbered rules (and optional sections) into a Markdown table.

##### `def format_rules_model_friendly(target_name: str, rulebase_type: str, rules: Sequence[NumberedRule]) -> str`

Format numbered rules into compact, LLM-friendly one-line entries.

##### `def rule_to_cpcrud_operation(rule: AccessRuleEntry | NatRuleEntry | HttpsRuleEntry | ThreatRuleEntry | NumberedRule, *, operation: Literal['add', 'set', 'delete', 'present', 'absent'] = 'set', package: str | None = None, layer: str | None = None) -> dict[str, Any]`

Convert a cached or numbered rule into a schema-valid `cpcrud` `RuleOperation` dict.

Normalizes Check Point NAT `"Original"` (`NAT_ORIGINAL_OBJECT_UID`) and `"Any"`
(`NAT_ANY_OBJECT_UID`) sentinel UIDs so the resulting dict passes
`CPCRUDService.validate()` and `Planner.decide()` without false diffs.

##### `def filter_numbered_rulebase(rulebase: PackageRulebase | NumberedLayerRulebase, *, filter_query: str = '', output_format: RuleFormat = 'model_friendly', objects: Sequence[CPObject] = (), services: Sequence[CPService] = (), cache_age_seconds: float | None = None) -> FilteredRulebaseResult`

Evaluate `filter_query` locally against `rulebase` and format the matching rules.

### `arodonata/rulebase/models.py`

Typed domain models for rulebase introspection, SmartConsole numbering, and local filtering.

#### class `PolicyPackageInfo(BaseModel)`

Summary of a cached policy package and its attached ordered layers / NAT policy.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
uid: str
name: str
has_nat_policy: bool = False
access_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
https_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
threat_layers: list[RulebasePackageLayerEntry] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `NumberedRule(BaseModel)`

A rule or placeholder carrying its dynamically computed SmartConsole hierarchical number.

##### Fields / Class Variables

```python
uid: str
name: str = ''
rule_number: str
position: int = 0
rule_type: str = 'access-rule'
rulebase_type: RulebaseType = 'access'
enabled: bool = True
layer_uid: str = ''
layer_name: str = ''
package_uid: str | None = None
package_name: str | None = None
section_uid: str | None = None
section_name: str | None = None
parent_rule_uid: str | None = None
action: str | None = None
method: str | None = None
inline_layer_uid: str | None = None
inline_layer_name: str | None = None
placeholder_domain_layer_uid: str | None = None
source: list[str] = Field(default_factory=list)
destination: list[str] = Field(default_factory=list)
service: list[str] = Field(default_factory=list)
source_negate: bool = False
destination_negate: bool = False
service_negate: bool = False
original_source: str | None = None
original_destination: str | None = None
original_service: str | None = None
translated_source: str | None = None
translated_destination: str | None = None
translated_service: str | None = None
site_category: list[str] = Field(default_factory=list)
certificate: str | None = None
protected_scope: list[str] = Field(default_factory=list)
track: str | None = None
install_on: list[str] = Field(default_factory=list)
comments: str = ''
children: list[NumberedRule] = Field(default_factory=list)
nested_sections: list[NumberedSection] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
```
##### Methods

###### `def from_access_entry(cls, entry: AccessRuleEntry, *, rule_number: str, package_uid: str | None = None, package_name: str | None = None, parent_rule_uid: str | None = None, children: list[NumberedRule] | None = None, nested_sections: list[NumberedSection] | None = None) -> NumberedRule`

```python
@classmethod
```
Construct a `NumberedRule` from an `AccessRuleEntry`.

###### `def from_nat_entry(cls, entry: NatRuleEntry, *, rule_number: str) -> NumberedRule`

```python
@classmethod
```
Construct a `NumberedRule` from a `NatRuleEntry`.

###### `def from_https_entry(cls, entry: HttpsRuleEntry, *, rule_number: str, package_uid: str | None = None, package_name: str | None = None, parent_rule_uid: str | None = None, children: list[NumberedRule] | None = None, nested_sections: list[NumberedSection] | None = None) -> NumberedRule`

```python
@classmethod
```
Construct a `NumberedRule` from an `HttpsRuleEntry`.

###### `def from_threat_entry(cls, entry: ThreatRuleEntry, *, rule_number: str, package_uid: str | None = None, package_name: str | None = None, parent_rule_uid: str | None = None) -> NumberedRule`

```python
@classmethod
```
Construct a `NumberedRule` from a `ThreatRuleEntry`.

#### class `NumberedSection(BaseModel)`

A rulebase section header with SmartConsole range display (`1-3`, `2.1-2.2`, or `No Rules`).

##### Fields / Class Variables

```python
uid: str
name: str
position: int = 0
layer_uid: str = ''
layer_name: str = ''
rulebase_type: RulebaseType = 'access'
range_label: str = 'No Rules'
from_rule: str | None = None
to_rule: str | None = None
rules: list[NumberedRule] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
```
##### Methods

###### `def from_section_entry(cls, sec: RulebaseSectionEntry, rules: list[NumberedRule]) -> NumberedSection`

```python
@classmethod
```
Construct a `NumberedSection` with computed SmartConsole `range_label`.

#### class `NumberedLayerRulebase(BaseModel)`

Numbered rulebase for a single ordered or standalone layer (with inline/placeholder expansions).

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
layer_uid: str
layer_name: str
rulebase_type: RulebaseType
package_uid: str | None = None
package_name: str | None = None
prefix: str = ''
is_global: bool = False
implicit_cleanup_action: str | None = None
sections: list[NumberedSection] = Field(default_factory=list)
rules: list[NumberedRule] = Field(default_factory=list)
flat_rules: list[NumberedRule] = Field(default_factory=list)
snapshot_session_uid: str | None = None
snapshot_published_at: datetime | None = None
sync_status: SyncStatus = 'idle'
layer_metadata: RulebaseLayerEntry | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `PackageRulebase(BaseModel)`

SmartConsole-numbered rulebase for a policy package across its ordered layers or NAT policy.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
package_uid: str
package_name: str
rulebase_type: RulebaseType = 'access'
layers: list[NumberedLayerRulebase] = Field(default_factory=list)
sections: list[NumberedSection] = Field(default_factory=list)
rules: list[NumberedRule] = Field(default_factory=list)
flat_rules: list[NumberedRule] = Field(default_factory=list)
snapshot_session_uid: str | None = None
snapshot_published_at: datetime | None = None
sync_status: SyncStatus = 'idle'
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `RuleLocation(BaseModel)`

A single SmartConsole position of a rule within a package and/or layer.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
rule_uid: str
rule_name: str = ''
rule_number: str
position: int = 0
rulebase_type: RulebaseType = 'access'
package_uid: str | None = None
package_name: str | None = None
layer_uid: str
layer_name: str
section_uid: str | None = None
section_name: str | None = None
section_range: str | None = None
parent_rule_uid: str | None = None
context: Literal['package', 'layer'] = 'package'
```
#### class `LayerPrefixLocation(BaseModel)`

Numbering prefix (`""`, `"2."`, `"2.2."`) of a layer in a package or standalone context.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
layer_uid: str
layer_name: str
rulebase_type: RulebaseType = 'access'
prefix: str = ''
package_uid: str | None = None
package_name: str | None = None
parent_layer_uid: str | None = None
parent_rule_uid: str | None = None
context: Literal['package', 'layer'] = 'package'
```
#### class `RuleLocations(BaseModel)`

Result of `locate_rules(...)` across all packages and layers of a domain.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
rule_locations: dict[str, list[RuleLocation]] = Field(default_factory=dict)
layer_prefixes: dict[str, list[LayerPrefixLocation]] = Field(default_factory=dict)
snapshot_session_uid: str | None = None
snapshot_published_at: datetime | None = None
sync_status: SyncStatus = 'idle'
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `FilteredRulebaseResult(BaseModel)`

Result of evaluating a filter locally against a cached rulebase snapshot.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
target_name: str
target_uid: str
rulebase_type: RulebaseType
query: str = ''
format: RuleFormat = 'model_friendly'
total_rules: int = 0
matched_count: int = 0
rules: list[NumberedRule] = Field(default_factory=list)
rendered_text: str = ''
raw_items: list[dict[str, Any]] = Field(default_factory=list)
source: Literal['cache', 'live'] = 'cache'
cache_age_seconds: float | None = None
snapshot_session_uid: str | None = None
snapshot_published_at: datetime | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

### `arodonata/rulebase/numbering.py`

SmartConsole-identical hierarchical rule and section numbering (`rulebase/numbering.py`).

Computes hierarchical rule numbers (`1`, `2`, `2.1`, `2.2.1`) and section range labels
(`1-3`, `2.1-2.2`, or `"No Rules"`) dynamically from a `DomainRulebaseSnapshot` both in
standalone layer context (`number_layer_rulebase`) and policy package context
(`number_package_rulebase`), and locates rules and layer prefixes across a domain
(`locate_rules_in_snapshot`).

#### Module-Level Functions

##### `def extract_policy_packages(snapshot: DomainRulebaseSnapshot) -> list[PolicyPackageInfo]`

Build `PolicyPackageInfo` models from `snapshot.package_layers`.

##### `def number_layer_rulebase(snapshot: DomainRulebaseSnapshot, layer_name_or_uid: str, *, rulebase_type: RulebaseType | None = None, prefix: str = '', package_uid: str | None = None, package_name: str | None = None, parent_rule_uid: str | None = None, fallback_domain_layer_uid: str | None = None, expand_placeholders: bool = False, expand_inline_layers: bool = True, snapshot_session_uid: str | None = None, snapshot_published_at: datetime | None = None, sync_status: SyncStatus = 'idle', _visited_layers: set[str] | None = None) -> NumberedLayerRulebase`

Compute SmartConsole hierarchical numbering for a layer (and its inline / placeholder sub-layers).

##### `def number_package_rulebase(snapshot: DomainRulebaseSnapshot, package_name_or_uid: str, *, rulebase_type: RulebaseType = 'access', snapshot_session_uid: str | None = None, snapshot_published_at: datetime | None = None, sync_status: SyncStatus = 'idle') -> PackageRulebase`

Compute SmartConsole-accurate hierarchical numbering for a policy package.

##### `def locate_rules_in_snapshot(snapshot: DomainRulebaseSnapshot, *, rule_uids: Sequence[str] | None = None, layer_uids: Sequence[str] | None = None, snapshot_session_uid: str | None = None, snapshot_published_at: datetime | None = None, sync_status: SyncStatus = 'idle') -> RuleLocations`

Locate rules and layer numbering prefixes across all packages and layers in `snapshot`.

### `arodonata/rulebase/pager.py`

Rulebase pagination (`rulebase/pager.py`) for `show-*-rulebase` commands.

Pages `show-access-rulebase`, `show-nat-rulebase`, `show-https-rulebase`, and `show-threat-rulebase`
in chunks of up to 100 rules, merges split `rulebase-section` headers repeated across consecutive
page boundaries, resolves `objects-dictionary` references, and recovers empty trailing sections.

#### Module-Level Functions

##### `def parse_access_rule_entry(*, mgmt_name: str, domain_name: str, layer_uid: str, layer_name: str, raw_rule: dict[str, Any], position: int, section_uid: str | None = None, section_name: str | None = None, obj_dict: dict[str, dict[str, Any]] | None = None) -> AccessRuleEntry`

Convert a raw Check Point access rule or `place-holder` dict into `AccessRuleEntry`.

##### `def parse_nat_rule_entry(*, mgmt_name: str, domain_name: str, package_uid: str, package_name: str, raw_rule: dict[str, Any], position: int, section_uid: str | None = None, section_name: str | None = None, obj_dict: dict[str, dict[str, Any]] | None = None) -> NatRuleEntry`

Convert a raw Check Point NAT rule dict into `NatRuleEntry`.

##### `def parse_https_rule_entry(*, mgmt_name: str, domain_name: str, layer_uid: str, layer_name: str, raw_rule: dict[str, Any], position: int, section_uid: str | None = None, section_name: str | None = None, obj_dict: dict[str, dict[str, Any]] | None = None) -> HttpsRuleEntry`

Convert a raw Check Point HTTPS rule dict into `HttpsRuleEntry`.

##### `def parse_threat_rule_entry(*, mgmt_name: str, domain_name: str, layer_uid: str, layer_name: str, raw_rule: dict[str, Any], position: int, section_uid: str | None = None, section_name: str | None = None, obj_dict: dict[str, dict[str, Any]] | None = None) -> ThreatRuleEntry`

Convert a raw Check Point Threat Prevention rule dict into `ThreatRuleEntry`.

##### `async def fetch_paged_rulebase(api: ApiPort, mgmt_name: str, domain_name: str | None, *, rulebase_type: RulebaseType, layer_uid: str = '', layer_name: str = '', package_uid: str | None = None, package_name: str | None = None, details_level: str = 'standard', use_object_dictionary: bool = True, limit: int = MAX_RULEBASE_PAGE_LIMIT, extra_payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None) -> PagedRulebaseResult`

```python
@traced
```
Page `show-*-rulebase` in chunks of up to 100 rules, stitching split sections and preserving empty trailing sections.

#### class `PagedRulebaseResult(BaseModel)`

Normalized result of paging a single layer or package NAT rulebase.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
rulebase_type: RulebaseType
layer_uid: str
layer_name: str
package_uid: str | None = None
package_name: str | None = None
sections: list[RulebaseSectionEntry] = Field(default_factory=list)
access_rules: list[AccessRuleEntry] = Field(default_factory=list)
nat_rules: list[NatRuleEntry] = Field(default_factory=list)
https_rules: list[HttpsRuleEntry] = Field(default_factory=list)
threat_rules: list[ThreatRuleEntry] = Field(default_factory=list)
objects_dictionary: dict[str, dict[str, Any]] = Field(default_factory=dict)
raw_rules: list[dict[str, Any]] = Field(default_factory=list)
raw_sections: list[dict[str, Any]] = Field(default_factory=list)
total: int = 0
```
### `arodonata/rulebase/refresh.py`

Atomic multi-domain rulebase snapshot refresh (`RulebaseRefreshService`).

Implements `refresh_rulebases` and `stream_refresh_rulebases`:
- Refuses to proceed if the shared read session is dirty (`locks != 0` or
  `number-of-published-changes != 0`), preserving any existing cached snapshot and
  marking `domain_sync_state.status = "failed"` (`scope="rulebase"`) with `last_error`.
- Fetches `show-packages`, NAT rulebases for packages with `nat-policy`, ordered
  access/HTTPS/threat layers, standalone layer listings (`show-access-layers`,
  `show-https-layers`, `show-threat-layers`), inline layers referenced by rules, and
  resolves Global layer `place-holder` rules in `package` context.
- Replaces the domain's entire rulebase snapshot atomically under the per-domain
  distributed lock (`sync:{mgmt_name}:{domain_name}:rulebase`).

#### Module-Level Functions

##### `async def collect_domain_rulebase_snapshot(api: ApiPort, mgmt_name: str, domain_name: str, *, sid: str | None = None, server_ip: str | None = None, page_limit: int = MAX_RULEBASE_PAGE_LIMIT, emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None) -> DomainRulebaseSnapshot`

Traverse all packages, NAT policies, ordered/standalone/inline layers, and Global placeholders for a domain.

#### class `RulebaseRefreshService`

Session-aware atomic rulebase snapshot refresh service (`refresh_rulebases`, `stream_refresh_rulebases`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: CachePort, coordinator: DomainSyncCoordinator, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def stream_refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing domain rulebase snapshots.

###### `async def refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Refresh domain rulebase snapshots and return `RefreshOutcome`.

### `arodonata/rulebase/source.py`

Cached rulebase introspection source (`CachedRulebaseSource`).

Provides:
- `get_policy_packages(mgmt_name, domain_name, ...)`
- `get_package_rulebase(mgmt_name, domain_name, package, rulebase_type=..., ...)`
- `get_layer_rulebase(mgmt_name, domain_name, layer, rulebase_type=..., ...)`
- `locate_rules(mgmt_name, domain_name, rule_uids=..., layer_uids=..., ...)`
- `filter_rulebase(...)`
- Automatic domain resolution when `domain_name` is `None` or `""`, raising
  `AmbiguousLayerName` listing all `(domain, uid)` candidates when multiple cached
  domains match.

#### class `CachedRulebaseSource`

High-level cached rulebase introspection, SmartConsole numbering, and local filtering engine.

##### Methods

###### `def __init__(self, *, cache: CachePort, refresh_service: RulebaseRefreshService | None = None, object_service: ObjectService | None = None, service_cache: ServiceCacheService | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def get_policy_packages(self, mgmt_name: str, domain_name: str | None = None, *, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> list[PolicyPackageInfo]`

```python
@traced
```
Return cached `PolicyPackageInfo` entries for `(mgmt_name, domain_name)`.

###### `async def get_package_rulebase(self, mgmt_name: str, domain_name: str | None, package: str, *, rulebase_type: RulebaseType = 'access', cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> PackageRulebase`

```python
@traced
```
Return a SmartConsole-numbered `PackageRulebase` for `package` in `(mgmt_name, domain_name)`.

###### `async def get_layer_rulebase(self, mgmt_name: str, domain_name: str | None, layer: str, *, rulebase_type: RulebaseType | None = None, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> NumberedLayerRulebase`

```python
@traced
```
Return a SmartConsole-numbered `NumberedLayerRulebase` for `layer` in `(mgmt_name, domain_name)`.

###### `async def locate_rules(self, mgmt_name: str, domain_name: str | None = None, *, rule_uids: Sequence[str] | None = None, layer_uids: Sequence[str] | None = None, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> RuleLocations`

```python
@traced
```
Locate SmartConsole rule numbers and layer prefixes across all packages and layers of a domain.

###### `async def filter_rulebase(self, mgmt_name: str, domain_name: str | None = None, *, package: str | None = None, layer: str | None = None, rulebase_type: RulebaseType = 'access', filter_query: str = '', output_format: RuleFormat = 'model_friendly', cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> FilteredRulebaseResult`

```python
@traced
```
Evaluate `filter_query` locally against cached rulebase and cached objects/services.


---

## cpcrud — Declarative Policy-as-Code Engine (Validator, Planner, Executor, Inverse)

### `arodonata/cpcrud/__init__.py`

Declarative Check Point Policy-as-Code CRUD engine (`src/arodonata/cpcrud/`).

_No public classes or functions in this module._

### `arodonata/cpcrud/differ.py`

Field-level difference computation (`src/arodonata/cpcrud/differ.py`).

Computes deterministic field diffs (`dict[str, FieldChange]`) and update payloads between
desired template specifications and existing `CPObject`, `CPService`, or rule models.

#### Module-Level Functions

##### `def resolve_member_reference(ref: str, name_resolutions: Mapping[str, str] | None = None) -> str`

Substitute any auto-named or reused object/service name for `ref`.

##### `def compute_object_diff(desired: Mapping[str, Any], existing: CPObject, *, name_resolutions: Mapping[str, str] | None = None) -> tuple[dict[str, FieldChange], dict[str, Any]]`

Compute field diffs and `set-<type>` update payload between `desired` spec and `existing` `CPObject`.

##### `def compute_service_diff(desired: Mapping[str, Any], existing: CPService, *, name_resolutions: Mapping[str, str] | None = None) -> tuple[dict[str, FieldChange], dict[str, Any]]`

Compute field diffs and `set-<service-type>` update payload between `desired` spec and `existing` `CPService`.

##### `def compute_rule_diff(desired: Mapping[str, Any], existing: RuleEntryUnion, *, rulebase_type: RulebaseType, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None) -> tuple[dict[str, FieldChange], dict[str, Any]]`

Compute field diffs and `set-*-rule` update payload between `desired` spec and `existing` rule.

### `arodonata/cpcrud/executor.py`

Dedicated-session CPCRUD executor (`src/arodonata/cpcrud/executor.py`).

Implements `Executor`:
- Paired `await apply(plan, ...) -> ApplyReport` and `stream_apply(plan, ...) -> AsyncIterator[CPCRUDEvent]`.
- Verifies each target domain's current `show-last-published-session` against the `DomainStamp`
  recorded in `Plan` when `force=False`; if drifted or unreadable, marks all actions in that
  domain as `Outcome.PLAN_STALE` and performs zero writes in that domain.
- Executes planned write actions inside an isolated `WriteSession` per `(mgmt_name, domain_name)`,
  updating `SessionOverlay` as each action succeeds.
- Supports `no_publish=True, keep_session=True` staging mode, leaving the dedicated session open,
  recording `StagedSessionInfo` in `ApplyReport.staged_sessions`, and emitting `StagedSessionEvent`.
- Calls `invalidate_domain(mgmt_name, domain_name)` after publish and supports `retry_remaining > 0`
  passes that re-run failed/remaining actions and fold their `ApplyReport` into the cumulative report.

#### Module-Level Functions

##### `def resolve_allowlisted_command(action: PlannedAction) -> str`

Derive the canonical Web API write command for `action` from the strict `(object_type, outcome)` allowlist.

#### class `Executor`

Executes `Plan` actions in an isolated `WriteSession` per `(mgmt_name, domain_name)`.

##### Methods

###### `def __init__(self, *, api: ApiPort, on_domain_invalidated: Callable[[str, str | None], None] | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `def last_report(self) -> ApplyReport | None`

```python
@property
```
Return the `ApplyReport` produced by the most recent `stream_apply` or `apply` run.

###### `async def stream_apply(self, plan: Plan, *, force: bool = False, no_publish: bool = False, keep_session: bool = False, retry_remaining: int = 0, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None) -> AsyncIterator[CPCRUDEvent]`

Execute `plan` in a dedicated `WriteSession` per domain and yield `CPCRUDEvent` updates.

###### `async def apply(self, plan: Plan, *, force: bool = False, no_publish: bool = False, keep_session: bool = False, retry_remaining: int = 0, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None) -> ApplyReport`

```python
@traced
```
Execute `plan` and return the final `ApplyReport`.

###### `async def stream_publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None) -> AsyncIterator[CPCRUDEvent]`

Adopt `session_uid` via `take-over-session`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate domain cache.

###### `async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid` via `take-over-session`, publish it, log out, and invalidate the domain cache.

###### `async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid` via `take-over-session`, discard all uncommitted changes in the session, and log out.

### `arodonata/cpcrud/inverse.py`

Compensating rollback template generator (`src/arodonata/cpcrud/inverse.py`).

Implements `build_inverse_template` (`CPCRUDService.inverse(plan, report)`):
- Builds a dictionary valid against `checkpoint_ops_schema.json` that reverses applied
  `CREATE`, `UPDATE`, and `DELETE` actions using captured `PlannedAction.prior_state`.
- Reverses execution order so dependent rules and groups are rolled back before the
  objects/services they reference.

#### Module-Level Functions

##### `def build_inverse_template(plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]`

Generate a schema-valid compensating template from `plan` (and optional `report`).

- `CREATE` actions become `delete` operations.
- `UPDATE` actions become `set` operations restoring prior attribute values from `prior_state`.
- `DELETE` actions become `add` operations populated from `prior_state`.
- Actions within each target domain are emitted in reverse execution order so rules/groups
  are removed or restored in safe dependency order.

### `arodonata/cpcrud/models.py`

Domain models for the declarative CPCRUD policy-as-code engine (`src/arodonata/cpcrud/models.py`).

#### class `Outcome(StrEnum)`

Outcome of a planned or executed CPCRUD action.

#### class `NamingPrefixes(BaseModel)`

Convention prefixes used when `on_ip_conflict='create_new'` auto-names an object or service.

##### Fields / Class Variables

```python
host: str = 'Host_'
network: str = 'Net_'
address_range: str = Field(default='IPR_', validation_alias='address_range')
tcp: str = 'TCP_'
udp: str = 'UDP_'
icmp: str = 'ICMP_'
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def from_mapping(cls, data: Any) -> NamingPrefixes`

```python
@classmethod
```
Construct `NamingPrefixes` accepting both short (`tcp`) and `service_*` (`service_tcp`) keys.

###### `def format_host(self, ip_address: str) -> str`

Generate convention-compliant host name (`Host_<ip>`).

###### `def format_network(self, subnet: str, mask_length: int | str) -> str`

Generate convention-compliant network name (`Net_<subnet>_<mask_len>`).

###### `def format_address_range(self, first_ip: str, last_ip: str) -> str`

Generate convention-compliant address range name (`IPR_<first>-<last>`).

###### `def format_tcp(self, port: str | int) -> str`

Generate convention-compliant TCP service name (`TCP_<port>`).

###### `def format_udp(self, port: str | int) -> str`

Generate convention-compliant UDP service name (`UDP_<port>`).

###### `def format_icmp(self, icmp_type: int | str, icmp_code: int | None = None) -> str`

Generate convention-compliant ICMP service name (`ICMP_<type>` or `ICMP_<type>_<code>`).

#### class `ConflictPolicy(BaseModel)`

Two-axis conflict resolution configuration (`on_name_conflict` x `on_ip_conflict`).

##### Fields / Class Variables

```python
on_name_conflict: NameConflictPolicy = 'update'
on_ip_conflict: IpConflictPolicy = 'reuse'
```
#### class `DomainStamp(BaseModel)`

Snapshot of a domain's `show-last-published-session` head captured BEFORE planning lookups.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str = ''
last_session_uid: str | None = None
last_published_at: datetime | None = None
readable: bool = True
error: str | None = None
captured_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def key(self) -> str`

```python
@property
```
Canonical `(mgmt_name, domain_name)` lookup key.

#### class `FieldChange(BaseModel)`

Field-level difference computed by `differ.py` during planning.

##### Fields / Class Variables

```python
field: str
old_value: Any = None
new_value: Any = None
```
#### class `PlannedAction(BaseModel)`

A single deterministic action produced by `Planner`.

##### Fields / Class Variables

```python
action_id: str
mgmt_name: str
domain_name: str = ''
operation: str
object_type: str
name: str = ''
requested_name: str = ''
resolved_name: str = ''
target_uid: str | None = None
layer: str | None = None
package: str | None = None
outcome: Outcome
status: str = ''
command: str | None = None
payload: dict[str, Any] = Field(default_factory=dict)
diffs: dict[str, FieldChange] = Field(default_factory=dict)
prior_state: dict[str, Any] | None = None
desired_spec: dict[str, Any] = Field(default_factory=dict)
depends_on: list[str] = Field(default_factory=list)
message: str = ''
error: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def is_write_action(self) -> bool`

```python
@property
```
Return `True` if this action mutates Check Point state (`CREATE`, `UPDATE`, `DELETE`).

#### class `Plan(BaseModel)`

Deterministic multi-domain execution plan produced by `CPCRUDService.plan()`.

##### Fields / Class Variables

```python
created_at: datetime = Field(default_factory=utc_now)
domain_stamps: dict[str, DomainStamp] = Field(default_factory=dict)
actions: list[PlannedAction] = Field(default_factory=list)
name_resolutions: dict[str, str] = Field(default_factory=dict)
template: dict[str, Any] = Field(default_factory=dict)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def has_errors(self) -> bool`

```python
@property
```
Return `True` if any planned action has `Outcome.ERROR` or `Outcome.SKIPPED_DEPENDENCY`.

###### `def write_actions(self) -> list[PlannedAction]`

```python
@property
```
Return all planned actions that perform API writes (`CREATE`, `UPDATE`, `DELETE`).

#### class `ActionResult(BaseModel)`

Execution result of a single `PlannedAction` during `apply()`.

##### Fields / Class Variables

```python
action_id: str
mgmt_name: str
domain_name: str = ''
operation: str
object_type: str
name: str = ''
resolved_name: str = ''
target_uid: str | None = None
planned_outcome: Outcome
outcome: Outcome
status: str = ''
success: bool = True
command: str | None = None
response_data: dict[str, Any] = Field(default_factory=dict)
prior_state: dict[str, Any] | None = None
message: str = ''
error: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `StagedSessionInfo(BaseModel)`

Metadata for a dedicated write session left open when `apply(no_publish=True, keep_session=True)` runs.

Redacts `sid` in `repr()`, `str()`, and serialized JSON while keeping `.sid` accessible programmatically.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str = ''
server_ip: str
session_uid: str | None = None
session_name: str | None = None
_sid: str = PrivateAttr(default='')
```
##### Methods

###### `def __init__(self, *, sid: str = '', **data: Any) -> None`

_No docstring._

###### `def sid(self) -> str`

```python
@property
```
Return the raw session identifier for external workflow continuation (never included in `repr()`).

#### class `ApplyReport(BaseModel)`

Final execution report returned by `CPCRUDService.apply()`.

##### Fields / Class Variables

```python
started_at: datetime = Field(default_factory=utc_now)
completed_at: datetime = Field(default_factory=utc_now)
results: list[ActionResult] = Field(default_factory=list)
published_domains: list[str] = Field(default_factory=list)
published_sessions: dict[str, str] = Field(default_factory=dict)
staged_sessions: list[StagedSessionInfo] = Field(default_factory=list)
stale_domains: list[str] = Field(default_factory=list)
retry_passes: int = 0
retry_reports: list[ApplyReport] = Field(default_factory=list)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def success(self) -> bool`

```python
@property
```
Return `True` if no action ended in `ERROR` or `PLAN_STALE` and all results succeeded.

###### `def has_failures(self) -> bool`

```python
@property
```
Return `True` if any action failed, was skipped due to dependency, or encountered a stale plan.

###### `def created_count(self) -> int`

```python
@property
```
Number of actions that succeeded with `Outcome.CREATE`.

###### `def updated_count(self) -> int`

```python
@property
```
Number of actions that succeeded with `Outcome.UPDATE`.

###### `def deleted_count(self) -> int`

```python
@property
```
Number of actions that succeeded with `Outcome.DELETE`.

###### `def unchanged_count(self) -> int`

```python
@property
```
Number of actions with `Outcome.UNCHANGED` or `Outcome.REUSE`.

###### `def failed_count(self) -> int`

```python
@property
```
Number of actions that failed or were aborted due to error/stale plan.

### `arodonata/cpcrud/planner.py`

Declarative CPCRUD planner (`src/arodonata/cpcrud/planner.py`).

Implements `Planner` (`Planner.decide`):
- Reads `DomainStamp` (`show-last-published-session`) for every target `(mgmt_name, domain_name)`
  BEFORE performing any object, service, or rulebase lookups.
- Creates an isolated `HybridStateReader` per `plan()` run.
- Evaluates two-axis conflict policies (`NameConflictPolicy` x `IpConflictPolicy`) with
  convention-compliant auto-naming via `NamingPrefixes`.
- Emits `Outcome.ERROR` (`"lookup failed, nothing planned (re-plan to retry): ..."`) on any
  failed lookup or unreadable domain head instead of a false `CREATE`, and marks dependent
  actions as `Outcome.SKIPPED_DEPENDENCY` (`status="skipped_dependency"`).
- Resolves rules by key (`uid`, `name`, `rule_number`) or traffic tuple, normalizes Check Point
  NAT `"Original"` / `"Any"` sentinels, and anchors `"bottom"` placements above trailing cleanup rules.

#### class `Planner`

Declarative CPCRUD planner producing deterministic, idempotent `Plan` objects.

##### Methods

###### `def __init__(self, *, api: ApiPort, cache: CachePort, default_mgmt_name: str | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def decide(self, template: Mapping[str, Any], *, on_name_conflict: NameConflictPolicy | None = None, on_ip_conflict: IpConflictPolicy | None = None, naming_prefixes: NamingPrefixes | Mapping[str, Any] | None = None) -> Plan`

```python
@traced
```
Produce a deterministic `Plan` for `template` using an isolated `HybridStateReader`.

### `arodonata/cpcrud/position_helper.py`

Cleanup-rule-aware rule positioning helper (`src/arodonata/cpcrud/position_helper.py`).

Resolves rule `position` values (`"top"`, `"bottom"`, `{"bottom": "<section>"}`, `{"above": ...}`,
`{"below": ...}`) against a layer or package rulebase, automatically anchoring `"bottom"` placements
at `{"above": "<cleanup_rule_uid>"}` when the last rule in the layer or target section is an
`Any / Any / Any` cleanup rule.

#### Module-Level Functions

##### `def is_cleanup_rule(rule: RuleEntryUnion, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> bool`

Return `True` if `rule` is an `Any / Any / Any` cleanup rule.

##### `def resolve_rule_position(requested_position: Any, rules: Sequence[RuleEntryUnion], sections: Sequence[RulebaseSectionEntry] = (), obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> str | int | dict[str, str]`

Resolve `requested_position` into the Check Point API `position` payload value.

- When `requested_position` is `"bottom"` (or `None`, defaulting to `"bottom"`) and the last rule
  in `rules` is an `Any / Any / Any` cleanup rule, returns `{"above": "<cleanup_rule_uid>"}`.
- When `requested_position` is `{"bottom": "<section_name_or_uid>"}` and the last rule in that
  section is a cleanup rule, returns `{"above": "<cleanup_rule_uid>"}`.

### `arodonata/cpcrud/rule_identity.py`

Rule identity matching and Check Point NAT sentinel normalization (`src/arodonata/cpcrud/rule_identity.py`).

Handles:
- Check Point NAT `"Original"` (`NAT_ORIGINAL_OBJECT_UID`) and `"Any"` (`NAT_ANY_OBJECT_UID`) sentinel UIDs.
- Matching access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`)
  or by canonical traffic tuple.

#### Module-Level Functions

##### `def normalize_nat_original_sentinel(value: Any, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> str`

Normalize a NAT `translated-*` field (`None`, `""`, `"Original"`, `NAT_ORIGINAL_OBJECT_UID`, or dict) to `"Original"`.

##### `def normalize_any_sentinel(value: Any, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> str`

Normalize a traffic reference (`None`, `""`, `"Any"`, `NAT_ANY_OBJECT_UID`, or dict) to `"Any"` or object name.

##### `def normalize_traffic_list(value: Any, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None) -> tuple[str, ...]`

Normalize a rule traffic field (`source`, `destination`, `service`) into a sorted canonical tuple of names.

##### `def normalize_nat_traffic_ref(value: Any, *, is_translated: bool, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None) -> str`

Normalize a single NAT rule traffic reference (`original-*` or `translated-*`).

##### `def desired_access_traffic_tuple(spec: Mapping[str, Any], name_resolutions: Mapping[str, str] | None = None) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]`

Compute canonical `(source, destination, service, action)` tuple for a desired access/HTTPS/threat rule.

##### `def existing_access_traffic_tuple(rule: AccessRuleEntry | HttpsRuleEntry | ThreatRuleEntry, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]`

Compute canonical `(source, destination, service, action)` tuple for an existing access/HTTPS/threat rule.

##### `def desired_nat_traffic_tuple(spec: Mapping[str, Any], name_resolutions: Mapping[str, str] | None = None) -> tuple[str, str, str, str, str, str, str]`

Compute canonical 7-tuple for a desired NAT rule, normalizing `Original` and `Any` sentinels.

##### `def existing_nat_traffic_tuple(rule: NatRuleEntry, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[str, str, str, str, str, str, str]`

Compute canonical 7-tuple for an existing `NatRuleEntry`, normalizing `NAT_ORIGINAL_OBJECT_UID` and `NAT_ANY_OBJECT_UID`.

##### `def match_rule(spec: Mapping[str, Any], rules: Sequence[RuleEntryUnion], *, rulebase_type: RulebaseType, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None) -> RuleEntryUnion | None`

Match a desired rule specification against existing rules by explicit key (`uid`, `name`, `rule_number`) or traffic tuple.

### `arodonata/cpcrud/service.py`

Unified CPCRUD service facade (`src/arodonata/cpcrud/service.py`).

Exposes:
- `validate(template, *, schema_path=None) -> list[str]`
- `await plan(template, ...) -> Plan`
- `await apply(plan, ...) -> ApplyReport`
- `stream_apply(plan, ...) -> AsyncIterator[CPCRUDEvent]`
- `inverse(plan, report=None) -> dict[str, Any]`

#### class `CPCRUDService`

Declarative Check Point Policy-as-Code CRUD engine (`client.cpcrud`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: CachePort, on_domain_invalidated: Callable[[str, str | None], None] | None = None, ensure_initialized: Callable[[], Any] | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `def planner(self) -> Planner`

```python
@property
```
Underlying `Planner` instance.

###### `def executor(self) -> Executor`

```python
@property
```
Underlying `Executor` instance.

###### `def last_report(self) -> ApplyReport | None`

```python
@property
```
Return the `ApplyReport` from the most recent `apply` or `stream_apply` run.

###### `def validate(self, template: dict[str, Any] | str, *, schema_path: str | Path | None = None) -> list[str]`

```python
@traced
```
Validate `template` offline against `checkpoint_ops_schema.json` using `jsonschema.Draft7Validator`.

Performs zero network or database calls.

###### `async def plan(self, template: dict[str, Any] | str, *, on_name_conflict: NameConflictPolicy | None = None, on_ip_conflict: IpConflictPolicy | None = None, naming_prefixes: NamingPrefixes | Mapping[str, Any] | None = None, validate_schema: bool = True) -> Plan`

```python
@traced
```
Inspect domain state via an isolated `HybridStateReader` and build a deterministic `Plan`.

###### `async def apply(self, plan: Plan, *, force: bool = False, no_publish: bool = False, keep_session: bool = False, retry_remaining: int = 0, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None) -> ApplyReport`

```python
@traced
```
Execute `plan` in an isolated `WriteSession` per domain and return `ApplyReport`.

###### `async def stream_apply(self, plan: Plan, *, force: bool = False, no_publish: bool = False, keep_session: bool = False, retry_remaining: int = 0, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None) -> AsyncIterator[CPCRUDEvent]`

Execute `plan` in an isolated `WriteSession` per domain and stream `CPCRUDEvent` items.

###### `def inverse(self, plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]`

```python
@traced
```
Build a schema-valid compensating rollback template from `plan` (and optional `report`).

###### `async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid` via `take-over-session`, publish it, log out, and invalidate the domain cache.

###### `async def stream_publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None) -> AsyncIterator[CPCRUDEvent]`

Adopt `session_uid` via `take-over-session`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate the domain cache.

###### `async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid` via `take-over-session`, discard uncommitted changes, and log out.

### `arodonata/cpcrud/state_reader.py`

Hybrid cache-first + live API fallback state reader (`src/arodonata/cpcrud/state_reader.py`).

Implements `HybridStateReader`:
- Isolated per-run state reader created for each `plan()` invocation.
- Reads network objects (`host`, `network`, `address-range`, `dns-domain`, `group`) from
  `arodonata_objects` and services (`service-tcp`, `service-udp`, `service-icmp`, `service-group`,
  `service-other`) from `arodonata_services` ONLY when the domain's stored `domain_sync_state`
  row for that specific `(scope, item_type)` has `status == "ok"` and matches the planner's
  `DomainStamp` (`last_published_at` and `last_session_uid`).
- Falls back to live Management API calls (`show-*` / `api_query`) otherwise.
- Raises `StateLookupError` when any lookup fails or `api_query` returns `paging_inconsistent`
  so the planner emits `Outcome.ERROR` rather than mistaking a failed read for "not found".
- Maintains an in-run virtual state overlay so objects/services planned for creation, update,
  or deletion earlier in the same `plan()` run are visible to subsequent steps.

#### Module-Level Functions

##### `def is_not_found_error(status_code: int, error_code: str | None, error_message: str | None) -> bool`

Return `True` if a Check Point API response specifically indicates 'object not found'.

##### `def normalize_mask_length(mask_length: int | str | None, subnet_mask: str | None = None) -> int | None`

Normalize a mask length or dotted-quad subnet mask into an integer prefix length (0..32).

#### class `StateLookupError(ArodonataError)`

Raised when a cache or live API state lookup fails during planning.

#### class `HybridStateReader`

Isolated per-plan state reader combining `DomainStamp`-gated cache lookups with live API fallback.

##### Methods

###### `def __init__(self, *, api: ApiPort, cache: CachePort, domain_stamps: dict[str, DomainStamp] | None = None) -> None`

_No docstring._

###### `def set_domain_stamp(self, stamp: DomainStamp) -> None`

Record or update a `DomainStamp` for `(stamp.mgmt_name, stamp.domain_name)`.

###### `def get_domain_stamp(self, mgmt_name: str, domain_name: str = '') -> DomainStamp | None`

Return the recorded `DomainStamp` for `(mgmt_name, domain_name)`.

###### `async def is_slice_cache_fresh(self, mgmt_name: str, domain_name: str, scope: SyncScope, item_type: str) -> bool`

Check whether `(mgmt_name, domain_name, scope, item_type)` in `domain_sync_state` matches `DomainStamp`.

###### `def record_virtual_object(self, obj: CPObject, *, previous_name: str | None = None) -> None`

Record an object planned for creation or update within the current `plan()` run.

###### `def record_virtual_object_delete(self, mgmt_name: str, domain_name: str, *, obj_type: str, name: str | None = None, uid: str | None = None) -> None`

Record an object planned for deletion within the current `plan()` run.

###### `def record_virtual_service(self, svc: CPService, *, previous_name: str | None = None) -> None`

Record a service planned for creation or update within the current `plan()` run.

###### `def record_virtual_service_delete(self, mgmt_name: str, domain_name: str, *, svc_type: str, name: str | None = None, uid: str | None = None) -> None`

Record a service planned for deletion within the current `plan()` run.

###### `async def get_object_by_name(self, mgmt_name: str, domain_name: str, obj_type: str, name: str) -> CPObject | None`

Look up a network object by `(mgmt_name, domain_name, obj_type, name)`.

###### `async def get_object_by_uid(self, mgmt_name: str, domain_name: str, obj_type: str, uid: str) -> CPObject | None`

Look up a network object by `(mgmt_name, domain_name, obj_type, uid)`.

###### `async def list_objects_of_type(self, mgmt_name: str, domain_name: str, obj_type: str) -> list[CPObject]`

Return all objects of `obj_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`.

###### `async def find_host_by_ip(self, mgmt_name: str, domain_name: str, ip_address: str) -> list[CPObject]`

Find all existing `host` objects matching `ip_address` (IPv4 or IPv6).

###### `async def find_network_by_subnet(self, mgmt_name: str, domain_name: str, subnet4: str, mask_length4: int) -> list[CPObject]`

Find all existing `network` objects matching `(subnet4, mask_length4)`.

###### `async def find_address_range_by_bounds(self, mgmt_name: str, domain_name: str, first_ip: str, last_ip: str) -> list[CPObject]`

Find all existing `address-range` objects matching `(first_ip, last_ip)`.

###### `async def get_service_by_name(self, mgmt_name: str, domain_name: str, svc_type: str, name: str) -> CPService | None`

Look up a service object by `(mgmt_name, domain_name, svc_type, name)`.

###### `async def get_service_by_uid(self, mgmt_name: str, domain_name: str, svc_type: str, uid: str) -> CPService | None`

Look up a service object by `(mgmt_name, domain_name, svc_type, uid)`.

###### `async def list_services_of_type(self, mgmt_name: str, domain_name: str, svc_type: str) -> list[CPService]`

Return all services of `svc_type` in `(mgmt_name, domain_name)` from fresh cache or live `api_query`.

###### `async def find_service_by_port(self, mgmt_name: str, domain_name: str, svc_type: str, port: str, protocol: str | None = None) -> list[CPService]`

Find existing TCP/UDP services matching `(svc_type, port, protocol)`.

###### `async def find_icmp_service(self, mgmt_name: str, domain_name: str, svc_type: str, icmp_type: int, icmp_code: int | None = None) -> list[CPService]`

Find existing ICMP services matching `(icmp_type, icmp_code)`.

###### `async def get_rulebase(self, mgmt_name: str, domain_name: str, *, rulebase_type: RulebaseType, layer: str | None = None, package: str | None = None) -> PagedRulebaseResult`

Read a rulebase layer or NAT package via `fetch_paged_rulebase`, raising `StateLookupError` on failure.

###### `async def check_where_used(self, mgmt_name: str, domain_name: str, *, name: str | None = None, uid: str | None = None) -> dict[str, Any]`

Run `where-used` on `(name or uid)`, raising `StateLookupError` if the API call fails.

### `arodonata/cpcrud/validator.py`

Offline JSON Schema validator and template normalizer (`src/arodonata/cpcrud/validator.py`).

Validates YAML or JSON declarative templates against `checkpoint_ops_schema.json`
(or an explicit `schema_path` override) using `jsonschema.Draft7Validator` without
making any network or database calls.

#### Module-Level Functions

##### `def load_cpcrud_schema(schema_path: str | Path | None = None) -> dict[str, Any]`

Load and cache the CPCRUD Draft-07 JSON Schema from disk.

##### `def parse_template_input(template: dict[str, Any] | str) -> tuple[dict[str, Any] | None, list[str]]`

Parse a dictionary or YAML/JSON string into a template dict, returning `(parsed, errors)`.

##### `def validate_template(template: dict[str, Any] | str, *, schema_path: str | Path | None = None) -> list[str]`

Validate `template` against `checkpoint_ops_schema.json` using `jsonschema.Draft7Validator`.

Returns:
    Empty list `[]` when valid, or a non-empty list of human-readable validation error strings.
    Performs zero network or database calls.


---

## reports — Auditable Session Change Report Collector & Multi-Format Renderer

### `arodonata/reports/__init__.py`

Auditable session change report collection, placement numbering, and rendering (`arodonata.reports`).

_No public classes or functions in this module._

### `arodonata/reports/collector.py`

Read-only session change collector (`arodonata.reports.collector`).

Implements `collect_change_report`:
- Validates `SessionScope` and `RangeScope` inputs strictly (raising `ValidationError` or
  `ChangeReportInputError` on invalid bounds or naive datetimes).
- Converts timezone-aware `from_date` / `to_date` to UTC, widens server query bounds safely
  (or omits server date parameters when `from_session` is also given), and filters returned
  sessions by exact UTC publish timestamp.
- Deduplicates sessions named across multiple scopes while preserving any attached `OwnedSession`.
- Resolves up to 200 distinct bare reference UIDs per report via read-only `show-object` calls,
  emitting a `names_unresolved` `ReportWarning` if the cap is exceeded or a lookup fails.
- Applies SmartConsole rule placement numbering via `apply_session_rule_placement`.

#### Module-Level Functions

##### `def is_bare_uid(value: Any) -> bool`

Return `True` if `value` is a bare UUID string (`8-4-4-4-12` hex).

##### `async def collect_change_report(api: ApiPort, cache: CachePort, scopes: Sequence[ReportScope | dict[str, Any]], *, options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS, now_fn: Callable[[], datetime] = utc_now) -> ChangeReport`

```python
@traced
```
Collect read-only session change evidence across `SessionScope` and `RangeScope` definitions.

### `arodonata/reports/models.py`

Domain models for auditable session change reports (`arodonata.reports.models`).

#### class `OwnedSession(BaseModel)`

Caller-supplied live unpublished write session (`sid`, `server_ip`) for live rulebase numbering.

Strictly redacts `sid` from `repr()`, `str()`, and JSON serialization (`exclude=True`).

##### Fields / Class Variables

```python
sid: str = Field(repr=False, exclude=True)
server_ip: str = ''
session_uid: str | None = None
mgmt_name: str | None = None
domain: str | None = None
```
#### class `SessionScope(BaseModel)`

Explicit Check Point session UID collection scope.

##### Fields / Class Variables

```python
mgmt_name: str
domain: str | None = None
session_uids: list[str] = Field(default_factory=list)
owned_sessions: dict[str, OwnedSession] | list[OwnedSession] | OwnedSession | None = Field(default=None, repr=False, exclude=True)
```
##### Methods

###### `def resolve_owned_session(self, session_uid: str) -> OwnedSession | None`

Return an `OwnedSession` matching `session_uid` if supplied on this scope.

#### class `RangeScope(BaseModel)`

Published session and/or date range collection scope.

##### Fields / Class Variables

```python
mgmt_name: str
domain: str | None = None
from_date: datetime | None = None
to_date: datetime | None = None
from_session: str | None = None
to_session: str | None = None
```
#### class `FieldDiff(BaseModel)`

Per-field before/after diff for a modified rule or object.

##### Fields / Class Variables

```python
field_name: str
old_value: Any = None
new_value: Any = None
added_items: list[str] = Field(default_factory=list)
removed_items: list[str] = Field(default_factory=list)
```
#### class `RuleChangeEntry(BaseModel)`

A single added, modified, moved, or deleted rule within a session.

##### Fields / Class Variables

```python
uid: str
name: str = ''
operation: ChangeOperation = 'modified'
rulebase_type: RulebaseType = 'access'
package_uid: str | None = None
package_name: str | None = None
layer_uid: str = ''
layer_name: str = ''
section_uid: str | None = None
section_name: str | None = None
section_range: str | None = None
rule_number: str | None = None
old_rule_number: str | None = None
moved: bool = False
enabled: bool = True
action: str | None = None
method: str | None = None
source: list[str] = Field(default_factory=list)
destination: list[str] = Field(default_factory=list)
service: list[str] = Field(default_factory=list)
source_negate: bool = False
destination_negate: bool = False
service_negate: bool = False
original_source: str | None = None
original_destination: str | None = None
original_service: str | None = None
translated_source: str | None = None
translated_destination: str | None = None
translated_service: str | None = None
track: str | None = None
install_on: list[str] = Field(default_factory=list)
comments: str = ''
field_diffs: list[FieldDiff] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
```
#### class `ObjectChangeEntry(BaseModel)`

A single added, modified, or deleted network/service/policy object in a session.

##### Fields / Class Variables

```python
uid: str
name: str = ''
object_type: str = 'object'
operation: ChangeOperation = 'modified'
summary: str = ''
field_diffs: list[FieldDiff] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
```
#### class `ReportWarning(BaseModel)`

Structured warning recorded when a partial failure, fallback, or lookup cap occurs.

##### Fields / Class Variables

```python
code: WarningCode | str
message: str
mgmt_name: str | None = None
domain: str | None = None
session_uid: str | None = None
details: dict[str, Any] = Field(default_factory=dict)
```
#### class `RawResponse(BaseModel)`

Sanitized raw API response preserved in `ChangeReport` for auditability (never contains SIDs).

##### Fields / Class Variables

```python
mgmt_name: str
domain: str | None = None
session_uid: str | None = None
command: str
payload: dict[str, Any] = Field(default_factory=dict)
response: dict[str, Any] = Field(default_factory=dict)
```
#### class `SessionChangeReport(BaseModel)`

Auditable change evidence for a single Check Point management session.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
session_uid: str
session_name: str = ''
description: str = ''
user_name: str = ''
state: str = 'published'
published_at: datetime | None = None
last_modify_time: datetime | None = None
locks: int = 0
changes_count: int = 0
numbering_basis: str = 'Numbering from cached rulebase snapshot'
numbering_source: Literal['owned_session', 'cache', 'unnumbered'] = 'cache'
rule_changes: list[RuleChangeEntry] = Field(default_factory=list)
object_changes: list[ObjectChangeEntry] = Field(default_factory=list)
resolved_names: dict[str, str] = Field(default_factory=dict)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `RenderOptions(BaseModel)`

Formatting options for `render_change_report` and `build_change_report`.

##### Fields / Class Variables

```python
title: str = 'Check Point Policy Change Report'
header_fields: dict[str, str] = Field(default_factory=dict)
include_object_changes: bool = True
include_field_diffs: bool = True
include_warnings: bool = True
```
#### class `ChangeReport(BaseModel)`

Top-level auditable session change report model supporting round-trip JSON serialization.

##### Fields / Class Variables

```python
format_version: int = CURRENT_FORMAT_VERSION
generated_at: datetime = Field(default_factory=utc_now)
title: str = 'Check Point Policy Change Report'
header_fields: dict[str, str] = Field(default_factory=dict)
sessions: list[SessionChangeReport] = Field(default_factory=list)
warnings: list[ReportWarning] = Field(default_factory=list)
raw_responses: list[RawResponse] = Field(default_factory=list)
```
#### class `RenderedReportBundle(BaseModel)`

Container returned by `render_change_report` and `build_change_report`.

##### Fields / Class Variables

```python
report: ChangeReport
html: bytes | None = None
markdown: str | None = None
json_text: str | None = None
```
### `arodonata/reports/placement.py`

Rulebase placement numbering (`arodonata.reports.placement`) for session change reports.

Numbers added, modified, moved, and deleted rules according to SmartConsole hierarchy:
1. When a matching unpublished `OwnedSession` (`sid`, `server_ip`) is supplied:
   - Verifies session ownership and unpublished state via read-only `show-session`.
   - Reads `show-packages` and `show-*-rulebase` using that SID strictly read-only
     (never calling `publish`, `discard`, or `logout`).
   - Labels the session `"Numbering read live in the owned session at <time> UTC"`.
   - Scrubs any occurrence of the SID from warnings, errors, and raw responses.
2. When no `OwnedSession` is supplied, or the `OwnedSession` is already published / fails:
   - Records an `owned_session_not_used` or `owned_session_error` `ReportWarning`.
   - Falls back to numbering from the domain's cached rulebase snapshot (`CachePort.get_domain_rulebase`).

#### Module-Level Functions

##### `async def apply_session_rule_placement(session_report: SessionChangeReport, *, api: ApiPort, cache: CachePort, owned_session: OwnedSession | None = None, warnings: list[ReportWarning], now_fn: Callable[[], datetime] = utc_now) -> None`

```python
@traced
```
Populate SmartConsole rule numbers on `session_report.rule_changes` via `OwnedSession` or cached snapshot.

### `arodonata/reports/renderer.py`

Multi-format offline evidence rendering (`arodonata.reports.renderer`).

Implements `render_change_report` and `build_change_report`:
- Offline rendering of `ChangeReport` into `"html"` (`bytes`), `"markdown"` (`str`), and
  `"json"` (`str`), raising `UnsupportedFormat` for `"pdf"` or unknown formats.
- Escapes all Check Point strings in every format while supporting safe inline markdown
  (`**bold**`, `*italic*`, `` `code` ``, `[text](http/https/mailto)`) in `RenderOptions.title`
  and `header_fields`.
- Produces self-contained UTF-8 HTML (`bytes`) with inline CSS, zero `<script>` tags, zero
  external network assets, visual change indicators (`NEW`, `DELETED`, yellow field diffs,
  moved rule badges, disabled `✗` markers), and per-rule field diff detail tables.

#### Module-Level Functions

##### `def render_safe_inline_markdown_html(text: str) -> str`

Escape `text` for HTML while converting safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[label](http/https/mailto)`).

##### `def render_safe_inline_markdown_md(text: str) -> str`

Sanitize inline markdown for Markdown output (neutralizing HTML tags and unsafe link schemes).

##### `def render_change_report(report: ChangeReport, *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None) -> RenderedReportBundle`

```python
@traced
```
Render `report` offline into any requested subset of `'html'`, `'json'`, and `'markdown'`.

Raises `UnsupportedFormat` if `'pdf'` or any unrecognized format is requested.

##### `async def build_change_report(api: ApiPort, cache: CachePort, scopes: Sequence[ReportScope | dict[str, Any]], *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS, now_fn: Callable[[], datetime] = utc_now) -> RenderedReportBundle`

```python
@traced
```
Collect a `ChangeReport` and render it into `formats` in a single call.


---

## mcp — Streamable-HTTP Model Context Protocol Server & Consolidated Tools

### `arodonata/mcp/__init__.py`

Streamable-HTTP Model Context Protocol (MCP) server package (`arodonata.mcp`).

_No public classes or functions in this module._

### `arodonata/mcp/cli.py`

Standalone CLI entry point (`arodonata-mcp`) for the Arodonata Streamable-HTTP MCP server.

#### Module-Level Functions

##### `def run_cli(argv: Sequence[str] | None = None, *, environ: dict[str, str] | None = None, uvicorn_runner: Callable[..., Any] | None = None) -> int`

Run the standalone `arodonata-mcp` Streamable-HTTP server and return an integer exit code.

Validates TLS trust store configuration and authentication mode at startup.
Refuses `ARODONATA_MCP_AUTH_MODE=host` or `jwt` with exit code `2` and a clear
configuration error message written to `stderr`.

##### `def main(argv: Sequence[str] | None = None, *, environ: dict[str, str] | None = None, uvicorn_runner: Callable[..., Any] | None = None, raise_system_exit: bool | None = None) -> int`

Console script entry point for `arodonata-mcp`.

When invoked with no arguments (`argv is None` and `uvicorn_runner is None`, as in the console
script entry point) or `raise_system_exit=True`, raises `SystemExit(code)` on non-zero exit code.
Otherwise returns `code` directly for programmatic callers and tests.

### `arodonata/mcp/config.py`

Configuration and startup validation for the Arodonata MCP server (`arodonata.mcp.config`).

#### class `ArodonataMCPSettings(BaseSettings)`

Type-safe configuration for the Arodonata MCP server (`ARODONATA_MCP_*`).

Never loads `.env` files implicitly.

##### Fields / Class Variables

```python
host: str = Field(default='127.0.0.1', validation_alias=AliasChoices('host', 'ARODONATA_MCP_HOST'))
port: int = Field(default=8000, ge=1, le=65535, validation_alias=AliasChoices('port', 'ARODONATA_MCP_PORT'))
path: str = Field(default='/mcp', validation_alias=AliasChoices('path', 'ARODONATA_MCP_PATH'))
auth_mode: MCPAuthMode = Field(default='static', validation_alias=AliasChoices('auth_mode', 'ARODONATA_MCP_AUTH_MODE'))
token_vars: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('token_vars', 'ARODONATA_MCP_TOKEN_VARS'))
tokens: CsvStrList = Field(default_factory=list, repr=False, validation_alias=AliasChoices('tokens', 'ARODONATA_MCP_TOKENS'))
enable_dns_rebinding_protection: bool = Field(default=True, validation_alias=AliasChoices('enable_dns_rebinding_protection', 'ARODONATA_MCP_ENABLE_DNS_REBINDING_PROTECTION'))
allowed_hosts: CsvStrList = Field(default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS), validation_alias=AliasChoices('allowed_hosts', 'ARODONATA_MCP_ALLOWED_HOSTS'))
allowed_origins: CsvStrList = Field(default_factory=lambda: list(DEFAULT_ALLOWED_ORIGINS), validation_alias=AliasChoices('allowed_origins', 'ARODONATA_MCP_ALLOWED_ORIGINS'))
allow_write_api: bool = Field(default=False, validation_alias=AliasChoices('allow_write_api', 'ARODONATA_MCP_ALLOW_WRITE_API'))
live_compat: bool = Field(default=False, validation_alias=AliasChoices('live_compat', 'ARODONATA_MCP_LIVE_COMPAT'))
cpcrud: bool = Field(default=False, validation_alias=AliasChoices('cpcrud', 'ARODONATA_MCP_CPCRUD'))
json_response: bool = Field(default=False, validation_alias=AliasChoices('json_response', 'ARODONATA_MCP_JSON_RESPONSE'))
stateless_http: bool = Field(default=False, validation_alias=AliasChoices('stateless_http', 'ARODONATA_MCP_STATELESS_HTTP'))
server_name: str = Field(default='arodonata-mcp', validation_alias=AliasChoices('server_name', 'ARODONATA_MCP_SERVER_NAME'))
```
##### Methods

###### `def resolve_static_tokens(self, environ: dict[str, str] | None = None) -> list[tuple[str, str]]`

Resolve `(client_id, token_secret)` pairs from `token_vars` and `tokens`.

Each environment variable name in `token_vars` becomes the caller's `client_id`.
Entries in `tokens` may be `"client_id=secret"` or `"client_id:secret"` ONLY when
`client_id` matches `^[A-Za-z_][A-Za-z0-9_-]*$` and `secret` has non-padding content;
otherwise the entry is treated as a bare secret (e.g. a base64 token with trailing `=`
padding) and assigned a non-secret `client_id` (`f"token_{idx}"`).
Every resolved token secret MUST be at least 32 characters (`MIN_STATIC_TOKEN_LENGTH`).

###### `def validate_standalone_startup(self, core_settings: ArodonataSettings | None = None, *, environ: dict[str, str] | None = None) -> TrustPolicy`

Validate standalone CLI (`arodonata-mcp`) auth mode and TLS trust store configuration.

Refuses `auth_mode="host"` or `"jwt"` in standalone mode by raising `ConfigurationError`.
Emits a prominent warning when `auth_mode="none"` is combined with a non-loopback host or `*`.
Verifies TLS trust policy and loads/validates the trust store.

###### `def model_dump(self, **kwargs: Any) -> dict[str, Any]`

Serialize MCP settings with `tokens` masked.

###### `def model_dump_json(self, **kwargs: Any) -> str`

Serialize MCP settings to JSON with `tokens` masked.

### `arodonata/mcp/errors.py`

MCP tool error handling, domain pre-validation, `InvalidCredentialsError` mapping, and SID masking.

#### Module-Level Functions

##### `async def collect_known_sids(client: ArodonataClient, mgmt_name: str | None = None) -> list[str]`

Collect active session tokens from the SID cache and transport adapter for redaction.

##### `def resolve_mgmt_name(client: ArodonataClient, mgmt_name: str | None = None) -> str`

Resolve `mgmt_name`, defaulting to the single configured server or first server in `settings`.

##### `async def get_known_domain_names(client: ArodonataClient, mgmt_name: str, *, refresh_if_empty: bool = False) -> list[str]`

Return sorted known domain names for `mgmt_name` from the `domains` cache table.

##### `async def validate_domain_or_fail(client: ArodonataClient, mgmt_name: str, domain: str | None) -> str | None`

Pre-validate `domain` against the cached `domains` table before attempting a domain login.

If `domain` is not present in the cached `domains` table, performs a single domain-list
refresh (`client.get_domains(..., cache_mode="force")`). If still not present and the
server has known domains, raises an actionable `ToolFailure` listing known domains.

##### `def format_invalid_credentials_failure(*, mgmt_name: str, domain: str | None, known_domains: Iterable[str], exc: InvalidCredentialsError | None = None, known_sids: Iterable[str] | None = None) -> ToolFailure`

Build an actionable model-facing `ToolFailure` for `InvalidCredentialsError`.

##### `def json_tool_result(payload: dict[str, Any] | list[Any] | str, *, is_error: bool = False, known_sids: Iterable[str] | None = None) -> CallToolResult`

Serialize `payload` into a sanitized MCP `CallToolResult`.

##### `def mcp_tool_guard(tool_name: str, client_getter: Callable[[], ArodonataClient]) -> Callable[[Callable[..., Awaitable[CallToolResult]]], Callable[..., Awaitable[CallToolResult]]]`

Wrap an async MCP tool function with `ToolFailure` WARNING logging, `InvalidCredentialsError`
translation, SID masking, and `"internal error: <ExceptionClass>"` crash protection.

Never logs tool arguments or secrets.

#### class `ToolFailure(ArodonataError)`

Actionable model-facing tool error logged at WARNING without arguments or secrets.

##### Methods

###### `def __init__(self, message: str, *, mgmt_name: str | None = None, domain: str | None = None, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

### `arodonata/mcp/prompts.py`

MCP prompt templates for Check Point security policy exploration and auditing (`arodonata.mcp.prompts`).

#### Module-Level Functions

##### `def register_mcp_prompts(server: MCPServer) -> None`

Register standard Check Point operational prompt templates on `server`.

### `arodonata/mcp/security.py`

Security guards for the Arodonata MCP server (`arodonata.mcp.security`).

Provides:
- `StaticTokenVerifier`: constant-time (`hmac.compare_digest`) bearer token verification mapping
  the matching environment variable name (`ARODONATA_MCP_TOKEN_VARS`) to `client_id` in logs and
  `AccessToken` without ever logging the token value.
- `host_matches_allowed` and `origin_matches_allowed` helpers.
- `MCPOriginHostGuardMiddleware`: ASGI middleware enforcing DNS rebinding (`Host` -> HTTP `421`)
  and browser `Origin` (`Origin` -> HTTP `403`) protection across all HTTP methods.
- `MCPClientIdContextMiddleware`: ASGI middleware binding the authenticated `client_id` into
  Arodonata's `UserContext` (`contextvars`) for downstream tool calls.

#### Module-Level Functions

##### `def host_matches_allowed(host: str | None, allowed_hosts: Sequence[str]) -> bool`

Return `True` if `host` matches an entry in `allowed_hosts` (supporting `host:*` port wildcards).

##### `def origin_matches_allowed(origin: str | None, allowed_origins: Sequence[str]) -> bool`

Return `True` if `origin` is absent or matches an entry in `allowed_origins` (supporting `scheme://host:*`).

#### class `StaticTokenVerifier(TokenVerifier)`

Verifies incoming `Authorization: Bearer <token>` headers in constant time.

Maps the matching environment variable name from `ARODONATA_MCP_TOKEN_VARS` (e.g.
`TEAM_A_TOKEN`) to the caller's `client_id` and records `client_id` in structured
logs without ever logging the token value. Hashes both sides with SHA-256 before
`hmac.compare_digest` so token length is never leaked via timing (`W26`).

##### Methods

###### `def __init__(self, token_pairs: Sequence[tuple[str, str]]) -> None`

_No docstring._

###### `def from_settings(cls, mcp_settings: ArodonataMCPSettings, *, environ: dict[str, str] | None = None) -> StaticTokenVerifier`

```python
@classmethod
```
Build a `StaticTokenVerifier` from `ArodonataMCPSettings`.

###### `def client_ids(self) -> list[str]`

```python
@property
```
Configured `client_id` names (never exposes token secrets).

###### `async def verify_token(self, token: str) -> AccessToken | None`

Verify `token` using SHA-256 digest + `hmac.compare_digest` across all configured pairs without early exit.

#### class `MCPOriginHostGuardMiddleware`

ASGI middleware enforcing DNS rebinding (`Host` -> `421`) and browser `Origin` (`Origin` -> `403`) checks.

##### Methods

###### `def __init__(self, app: ASGIApp, *, allowed_hosts: Sequence[str], allowed_origins: Sequence[str], enabled: bool = True) -> None`

_No docstring._

#### class `MCPBearerAuthMiddleware`

ASGI middleware enforcing static bearer token authentication and binding `client_id` to `UserContext`.

##### Methods

###### `def __init__(self, app: ASGIApp, *, verifier: TokenVerifier) -> None`

_No docstring._

### `arodonata/mcp/server.py`

MCP server and embeddable ASGI application factories (`create_mcp_server`, `create_asgi_app`).

#### Module-Level Functions

##### `def create_mcp_server(client: ArodonataClient | None = None, *, settings: ArodonataSettings | None = None, mcp_settings: ArodonataMCPSettings | None = None, auth_mode: MCPAuthMode | None = None, token_verifier: TokenVerifier | None = None, allowed_hosts: list[str] | None = None, allowed_origins: list[str] | None = None, allow_write_api: bool | None = None, live_compat: bool | None = None, cpcrud: bool | None = None, environ: dict[str, str] | None = None) -> MCPServer`

Create and configure an `MCPServer` instance wired to `ArodonataClient`.

When `auth_mode="host"` is specified for embedding inside an authenticating ASGI host,
Arodonata disables its internal token verifier (`token_verifier=None`) and relies on the
enclosing ASGI host middleware for request authentication.

##### `def create_asgi_app(client: ArodonataClient | None = None, *, mcp_server: MCPServer | None = None, settings: ArodonataSettings | None = None, mcp_settings: ArodonataMCPSettings | None = None, auth_mode: MCPAuthMode | None = None, token_verifier: TokenVerifier | None = None, allowed_hosts: list[str] | None = None, allowed_origins: list[str] | None = None, allow_write_api: bool | None = None, live_compat: bool | None = None, cpcrud: bool | None = None, path: str | None = None, json_response: bool | None = None, stateless_http: bool | None = None, environ: dict[str, str] | None = None) -> ArodonataASGIApp`

Create a Streamable-HTTP ASGI application ready for `uvicorn` or Starlette/FastAPI mounting.

Enforces:
- DNS rebinding protection (`Host` not in `allowed_hosts` -> HTTP `421`).
- Browser `Origin` header validation (`Origin` not in `allowed_origins` -> HTTP `403`).
- Static bearer token verification (`auth_mode="static"`) mapping matched env var names to `client_id`
  and binding `UserContext(client_id=...)` in `contextvars`, or pass-through in `auth_mode="host"`.

#### class `ArodonataASGIApp`

ASGI wrapper combining `MCPOriginHostGuardMiddleware`, optional `MCPBearerAuthMiddleware`,
and the underlying `Starlette` Streamable-HTTP MCP application (preserving its `router.lifespan_context`).

##### Methods

###### `def __init__(self, *, starlette_app: Any, guarded_app: ASGIApp, mcp_server: MCPServer, client: ArodonataClient, mcp_settings: ArodonataMCPSettings, token_verifier: TokenVerifier | None) -> None`

_No docstring._

### `arodonata/mcp/tools.py`

MCP tool surface registration (`arodonata.mcp.tools`).

Exposes a consolidated, cache-aligned tool surface:
- Collection listing tools (`list_domains`, `list_objects`, `list_services`, `list_assets`)
  with `from`, `to`, `total`, `source`, and `cache_age_seconds`.
- Multi-table single-entity lookup (`show_object`) across `arodonata_objects`, `arodonata_services`,
  `arodonata_assets`, and `arodonata_rulebase_layer` / `arodonata_rulebase_package_layer` with
  three-tier matching (exact match, strict explicit wildcard `fnmatchcase`, and paginated
  substring candidate fallback).
- Hybrid rulebase inspection and package/layer discovery (`show_rulebase`, `locate_rules`).
- Search, group/cluster membership, and structured aggregation (`search_objects`,
  `get_group_members`, `query_objects` with `aggregate="list" | "count" | "describe"`).
- Unified cache status and synchronization (`cache_control` with `action="status" | "refresh"`).
- Change report (`change_report`) and write-protected `api_call`.
- Opt-in CPCRUD tools (`ARODONATA_MCP_CPCRUD=true`: `cpcrud_validate`, `cpcrud_plan`,
  `cpcrud_apply`, `cpcrud_inverse`, `cpcrud_staged_session`).

#### Module-Level Functions

##### `def register_mcp_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], mcp_settings: ArodonataMCPSettings) -> None`

Register all configured MCP tools on `server`.
