# Arodonata v2 — Full API Reference

Complete, auto-generated reference of every public class, SQLModel table, function, and method in the `arodonata` v2.6.7 package, extracted directly from `src/arodonata` via AST.

## Package Map

- **Top-Level Package & ArodonataClient Facade (`arodonata`, `arodonata.client`)** — 1 module(s)
- **core — Configuration, Contexts, Models, Hexagonal Ports, Sync & Search Services** — 54 module(s)
- **adapters — Check Point Transport (`AMgmtClient`), SQL Storage & SSE** — 29 module(s)
- **rulebase — Cached Rulebase Source, SmartConsole Numbering & Local Filtering** — 8 module(s)
- **cpcrud — Declarative Policy-as-Code Engine (Validator, Planner, Executor, Inverse)** — 23 module(s)
- **reports — Auditable Session Change Report Collector & Multi-Format Renderer** — 12 module(s)
- **mcp — Streamable-HTTP Model Context Protocol Server & Consolidated Tools** — 18 module(s)
- **api_reference** — 4 module(s)
- **client** — 7 module(s)
- **testing** — 32 module(s)


---

## Top-Level Package & ArodonataClient Facade (`arodonata`, `arodonata.client`)

### `arodonata/__init__.py`

Arodonata v2 — Async-first Python SDK for Check Point Management & MDSM.

_No public classes or functions in this module._


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
port: int = Field(default=443, ge=1, le=65535)
api_key: str | None = Field(default=None, repr=False)
api_version: str | None = Field(default=None)
```
#### class `TopologyConfidenceWeights(BaseModel)`

Configurable signed evidence deltas for gateway topology and route confidence calculation.

##### Fields / Class Variables

```python
route_connected: float = 0.65
route_static: float = 0.55
route_dynamic: float = 0.5
topology_connected: float = 0.5
topology_specific_prevent: float = 0.4
topology_specific_detect: float = 0.15
topology_external_fallback: float = 0.3
admin_confirmed: float = 0.5
admin_manual: float = 0.6
admin_standby_dynamic: float = 0.35
policy_rule_evidence: float = 0.25
vpn_encryption_domain: float = 0.45
policy_rule_match: float = 0.25
vpn_domain_match: float = 0.45
bridge_arp_mac_match: float = 0.4
conflict_missing_in_live_routes: float = -0.35
conflict_routed_to_other_interface_static: float = -0.5
conflict_routed_to_other_interface_route: float = -0.1
conflict_cluster_member_drift: float = -0.2
```
#### class `NamingPrefixes(BaseModel)`

Convention prefixes and formatting rules used when CPCRUD auto-names objects or services.

##### Fields / Class Variables

```python
host: str = 'Host_'
network: str = 'Net_'
address_range: str = Field(default='IPR_', validation_alias='address_range')
range_separator: str = '-'
compress_range_same_subnet: bool = False
group: str = 'grp'
group_suffix: str = ''
tcp: str = 'TCP_'
udp: str = 'UDP_'
icmp: str = 'ICMP_'
app_site: str = 'Site_'
app_site_wildcard_marker: str = '_'
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

###### `def from_mapping(cls, data: Any, *, base: NamingPrefixes | None = None) -> NamingPrefixes`

```python
@classmethod
```
Construct `NamingPrefixes` accepting short, kebab-case, and `service_*` keys.

###### `def format_host(self, ip_address: str) -> str`

Generate convention-compliant host name (`Host_<ip>`).

###### `def format_network(self, subnet: str, mask_length: int | str) -> str`

Generate convention-compliant network name (`Net_<subnet>_<mask_len>`).

###### `def format_address_range(self, first_ip: str, last_ip: str) -> str`

Generate convention-compliant address range name (`IPR_<first>-<last>` or compressed same-`/24`).

###### `def format_group(self, base_name: str) -> str`

Generate convention-compliant group name applying configured prefix and suffix without duplication.

###### `def format_tcp(self, port: str | int) -> str`

Generate convention-compliant TCP service name (`TCP_<port>`).

###### `def format_udp(self, port: str | int) -> str`

Generate convention-compliant UDP service name (`UDP_<port>`).

###### `def format_icmp(self, icmp_type: int | str, icmp_code: int | None = None) -> str`

Generate convention-compliant ICMP service name (`ICMP_<type>` or `ICMP_<type>_<code>`).

###### `def format_app_site(self, domain: str, *, is_wildcard: bool = False) -> str`

Generate Check Point-safe application-site name (replacing wildcard `*` with marker).

#### class `ArodonataSettings(BaseSettings)`

Type-safe configuration for Arodonata resolved from kwargs and `os.environ`.

Never loads `.env` files implicitly.

##### Fields / Class Variables

```python
mgmt_names: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('ARODONATA_MGMT_NAMES', 'MGMT_NAMES'))
mgmt_servers: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('ARODONATA_MGMT_SERVERS', 'MGMT_SERVERS'))
api_keys: CsvStrList = Field(default_factory=list, repr=False, validation_alias=AliasChoices('ARODONATA_API_KEYS', 'API_KEYS'))
api_key_vars: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('ARODONATA_API_KEY_VARS', 'API_KEY_VARS'))
api_versions: CsvStrList = Field(default_factory=list, validation_alias=AliasChoices('ARODONATA_API_VERSIONS', 'MGMT_API_VERSIONS'))
mgmt_name: str | None = Field(default=None, validation_alias=AliasChoices('ARODONATA_MGMT_NAME', 'MGMT_NAME'))
mgmt_ip: str | None = Field(default=None, validation_alias=AliasChoices('ARODONATA_MGMT_IP', 'MGMT_IP'))
mgmt_port: int = Field(default=443, ge=1, le=65535, validation_alias=AliasChoices('ARODONATA_MGMT_PORT', 'MGMT_PORT'))
max_response_bytes: int = Field(default=67108864, ge=1024, validation_alias=AliasChoices('ARODONATA_MAX_RESPONSE_BYTES'))
api_version: str | None = Field(default=None, validation_alias=AliasChoices('ARODONATA_API_VERSION', 'MGMT_API_VERSION'))
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
domain_sync_concurrency: int = Field(default=0, ge=0, le=20, validation_alias=AliasChoices('ARODONATA_DOMAIN_SYNC_CONCURRENCY'))
route_collect_concurrency: int = Field(default=0, ge=0, le=32, validation_alias=AliasChoices('ARODONATA_ROUTE_COLLECT_CONCURRENCY'))
max_routes_per_gateway: int = Field(default=50000, ge=100, le=500000, validation_alias=AliasChoices('ARODONATA_MAX_ROUTES_PER_GATEWAY'))
max_query_pages: int = Field(default=5000, ge=1, le=100000, validation_alias=AliasChoices('ARODONATA_MAX_QUERY_PAGES'))
max_query_objects: int = Field(default=1000000, ge=1, le=10000000, validation_alias=AliasChoices('ARODONATA_MAX_QUERY_OBJECTS'))
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
cpcrud_naming_prefixes: NamingPrefixes = Field(default_factory=NamingPrefixes, validation_alias=AliasChoices('ARODONATA_CPCRUD_NAMING_PREFIXES', 'CPCRUD_NAMING_PREFIXES'))
trace_modules: str = Field(default='', validation_alias=AliasChoices('ARODONATA_TRACE_MODULES'))
topology_confidence_weights: TopologyConfidenceWeights = Field(default_factory=TopologyConfidenceWeights, validation_alias=AliasChoices('ARODONATA_TOPOLOGY_CONFIDENCE_WEIGHTS'))
cprid_script_mode: CpridScriptMode = Field(default='inline', validation_alias=AliasChoices('ARODONATA_CPRID_SCRIPT_MODE'))
cprid_repository_script_name: str = Field(default='arodonata-collect-routes-v1', validation_alias=AliasChoices('ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME'))
```
##### Methods

###### `def __init__(self, **data: Any) -> None`

_No docstring._

###### `def servers(self) -> dict[str, ServerEndpointConfig]`

```python
@property
```
Return positional mapping of `mgmt_name -> ServerEndpointConfig`.

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

##### `def normalize_domain_key(domain: str | None) -> str`

Normalize `domain=None` or whitespace-only domain strings to `'System Data'`.

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

##### `async def shielded_best_effort(awaitable: Awaitable[Any]) -> None`

Await a cleanup coroutine under `asyncio.shield`, propagating cancellation and TLS identity failures.

##### `async def run_write_session_lifecycle(ws: WriteSession, *, api_call_fn: Callable[..., Awaitable[ApiCallResult]], logout_fn: Callable[..., Awaitable[Any]], domain: str | None = None, publish_on_exit: bool = True, on_domain_invalidated: Callable[[str, str | None], None] | None = None) -> AsyncIterator[WriteSession]`

```python
@asynccontextmanager
```
Bind `ws` to `contextvars`, auto-discard on error, auto-publish on clean exit, and always log out.

##### `async def open_api_write_session(api: ApiPort, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None, publish_on_exit: bool = True, on_domain_invalidated: Callable[[str, str | None], None] | None = None) -> AsyncIterator[WriteSession]`

```python
@asynccontextmanager
```
Open an isolated `WriteSession` directly against an `ApiPort` with discard/publish/logout lifecycle.

##### `def update_overlay_from_command(overlay: SessionOverlay, command: str, payload: dict[str, Any] | None, result: ApiCallResult) -> None`

Update `SessionOverlay` when `add-*`, `set-*`, or `delete-*` succeeds inside a `WriteSession`.

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

###### `def apply_to_single_object(self, obj: CPObject) -> CPObject | None`

Apply uncommitted updates/deletions to a single `CPObject` without appending unrelated entities.

###### `def apply_to_single_service(self, svc: CPService) -> CPService | None`

Apply uncommitted updates/deletions to a single `CPService` without appending unrelated entities.

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

##### `def sanitize_mapping(data: Mapping[str, Any], known_sids: Iterable[str] | None = None) -> dict[str, Any]`

Recursively redact sensitive keys and SID strings from a dictionary.

##### `def is_script_permission_error(error_code: str | None, error_message: str | None) -> bool`

Return True if a Check Point API code or message indicates script or read-only permission denial.

##### `def is_unsupported_script_command_error(error_code: str | None, error_message: str | None) -> bool`

Return True if a Check Point API error indicates Script Repository commands are unsupported (< v1.9).

#### class `ArodonataError(Exception)`

Base exception for all Arodonata errors with automatic SID/secret redaction.

##### Methods

###### `def __init__(self, message: str = '', *, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

#### class `ValidationError(ArodonataError, ValueError)`

Raised when a command, object type, template, or input parameter fails validation.

#### class `AmbiguousObjectError(ValidationError)`

Raised when a cross-domain lookup (domain=None) matches entities in multiple domains.

##### Methods

###### `def __init__(self, mgmt_name: str, query: str, candidates: list[dict[str, Any]], *, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

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

##### Methods

###### `def __init__(self, message: str = '', *, phase: TransportPhase = 'connect', request_sent: bool | None = False, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

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

#### class `RepositoryScriptError(ArodonataError)`

Base exception for Check Point Script Repository operations.

#### class `RepositoryScriptNotFoundError(RepositoryScriptError)`

Raised when a Check Point Script Repository entry does not exist in the target domain.

##### Methods

###### `def __init__(self, mgmt_name: str, domain_name: str, script_ref: str, message: str | None = None, *, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

#### class `RepositoryScriptPermissionError(RepositoryScriptError)`

Raised when Check Point denies permission to inspect, manage, or run a repository script.

##### Methods

###### `def __init__(self, mgmt_name: str, domain_name: str, script_ref: str, operation: str = 'execute', message: str | None = None, *, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

#### class `RepositoryScriptUnsupportedError(RepositoryScriptError)`

Raised when the Check Point Management API does not support Script Repository commands (< R81.20 / v1.9).

##### Methods

###### `def __init__(self, mgmt_name: str, domain_name: str, script_ref: str, operation: str = 'execute', message: str | None = None, *, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

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
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

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
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

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
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

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
report: Any = Field(default=None, exclude=True, repr=False)
```
### `arodonata/core/models/__init__.py`

Pydantic v2 domain models for Arodonata.

_No public classes or functions in this module._

### `arodonata/core/models/assets.py`

Gateway, cluster, VSX, and management server asset models (`Asset`) and vendor-neutral classification.

#### Module-Level Functions

##### `def classify_asset_role(asset: Asset | Mapping[str, Any], *, parent_type: str | None = None) -> AssetRole`

Classify an `Asset` or raw Check Point payload into a normalized `AssetRole`.

##### `def classify_asset_platform(asset: Asset | Mapping[str, Any]) -> AssetPlatform`

Classify an `Asset` or raw Check Point payload into a normalized `AssetPlatform` from vendor fields only.

##### `def classify_asset(asset: Asset, *, parent_type: str | None = None) -> Asset`

Recompute vendor-neutral role, platform, and target flags on an `Asset`, returning an updated copy if needed.

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
management_blades: dict[str, Any] = Field(default_factory=dict, validation_alias=AliasChoices('management_blades', 'management-blades'))
asset_role: AssetRole = 'unknown'
platform_family: AssetPlatform = 'unknown'
is_policy_target: bool = False
is_execution_target: bool = False
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

##### `def expand_asset_type(item_type: str) -> tuple[str, ...]`

Expand an asset type or alias to all equivalent REST and Check Point `Cpmi*` classes.

##### `def expand_asset_types(types: Sequence[str]) -> list[str]`

Expand asset types/aliases into deduplicated REST and Check Point `Cpmi*` classes.

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

##### `def parse_cp_publish_timestamp(raw_time: Any) -> datetime | None`

Parse Check Point `publish-time` or `last-modify-time` dict/string/int into a naive UTC `datetime`.

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

#### Module-Level Functions

##### `def parse_domain_entry(mgmt_name: str, raw: dict[str, Any], *, mds_ip_by_name: dict[str, str] | None = None, default_host: str | None = None, now_fn: Callable[[], datetime] | None = None, fallback_uid: bool = False) -> DomainInfo`

Convert a raw Check Point `show-domains` / `show-domain` / `show-global-domain` dict into `DomainInfo`.

##### `def parse_domain_dict(mgmt_name: str, raw: dict[str, Any], *, default_host: str | None = None, mds_ip_by_name: dict[str, str] | None = None, now_fn: Callable[[], datetime] = utc_now) -> DomainInfo`

Convert a raw Check Point `show-domains` / `show-domain` / `show-global-domain` dict with domain fallbacks.

##### `def is_rbac_or_details_level_rejected(res: ApiCallResult) -> bool`

Return `True` if `show-domains` with `details-level=full` was rejected due to RBAC / permissions.

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
sid: str = Field(repr=False, exclude=True)
server_ip: str
tls_identity_host: str | None = None
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
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `WarmupStatusEntry(BaseModel)`

Structured status record for background object/service cache warm-up flights.

##### Fields / Class Variables

```python
mgmt_name: str
domains: list[str] = Field(default_factory=list)
types: list[str] = Field(default_factory=list)
include_global: bool = False
include_services: bool = False
status: WarmupTaskStatus = 'running'
started_at: datetime = Field(default_factory=utc_now)
completed_at: datetime | None = None
refreshed_domains: list[str] = Field(default_factory=list)
failed_domains: dict[str, str] = Field(default_factory=dict)
error: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

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
primary_category: str | None = Field(default=None, validation_alias=AliasChoices('primary_category', 'primary-category'))
url_list: list[str] = Field(default_factory=list, validation_alias=AliasChoices('url_list', 'url-list'))
urls_defined_as_regular_expression: bool | None = Field(default=None, validation_alias=AliasChoices('urls_defined_as_regular_expression', 'urls-defined-as-regular-expression'))
description: str = ''
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

#### Module-Level Functions

##### `def extract_policy_packages(snapshot: DomainRulebaseSnapshot) -> list[PolicyPackageInfo]`

Build `PolicyPackageInfo` models from `snapshot.package_layers`.

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

### `arodonata/core/models/scripts.py`

Check Point Script Repository models and script-body normalization helpers.

#### Module-Level Functions

##### `def normalize_script_body(body: str) -> str`

Normalize line endings (`\r\n` / `\r` -> `\n`) and strip trailing line whitespace.

##### `def decode_base64_task_message(raw_val: str) -> str`

Decode a Base64-encoded Check Point task message when plausible UTF-8 text, else return `raw_val`.

#### class `RepositoryScript(BaseModel)`

Check Point Management Script Repository entry (`add/show/set-repository-script`).

##### Fields / Class Variables

```python
uid: str = ''
name: str
mgmt_name: str = ''
domain_name: str = ''
script_body: str = ''
args: str = ''
comments: str = ''
color: str = 'black'
tags: list[str] = Field(default_factory=list)
raw_data: dict[str, Any] = Field(default_factory=dict)
```
##### Methods

###### `def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: Mapping[str, Any], *, fallback_body: str | None = None) -> RepositoryScript`

```python
@classmethod
```
Build a `RepositoryScript` from a Check Point Management API response payload.

#### class `RepositoryScriptStatus(BaseModel)`

Read-only inspection status of a Check Point Script Repository entry.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
script_ref: str = ''
exists: bool
script: RepositoryScript | None = None
matches_expected: bool | None = None
error_code: str | None = None
error: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `EnsureRepositoryScriptResult(BaseModel)`

Result of idempotently ensuring a repository script matches the desired body.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
action: RepositoryScriptEnsureAction
script: RepositoryScript
published: bool = False
```
#### class `ScriptTargetExecutionResult(BaseModel)`

Per-target execution output decoded from Check Point `run-script` / `show-task`.

##### Fields / Class Variables

```python
target: str
target_name: str = ''
target_uid: str = ''
task_id: str = ''
status: str = ''
success: bool
stdout: str = ''
stderr: str = ''
status_description: str = ''
revision: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `RepositoryScriptExecutionOutcome(BaseModel)`

Aggregated outcome of executing a Check Point Script Repository entry via `run-script`.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
script_ref: str
args: str = ''
success: bool
task_ids: list[str] = Field(default_factory=list)
targets: list[ScriptTargetExecutionResult] = Field(default_factory=list)
stdout: str = ''
stderr: str = ''
error_code: str | None = None
error_message: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

### `arodonata/core/models/sentinels.py`

Canonical Check Point built-in sentinel object UIDs, token sets, and normalizers.

#### Module-Level Functions

##### `def normalize_nat_original_sentinel(value: Any, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> str`

Normalize a NAT `translated-*` field (`None`, `""`, `"Original"`, `NAT_ORIGINAL_OBJECT_UID`, or dict) to `"Original"`.

##### `def normalize_any_sentinel(value: Any, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> str`

Normalize a traffic reference (`None`, `""`, `"Any"`, `NAT_ANY_OBJECT_UID`, or dict) to `"Any"` or object name.

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

### `arodonata/core/models/topology.py`

Gateway interface topology, live routing reconciliation, annotations, and candidate matching models.

#### class `ConfidenceDelta(BaseModel)`

Single signed evidence delta contributing to an endpoint or traffic flow confidence score.

##### Fields / Class Variables

```python
code: str
delta: float
detail: str = ''
```
#### class `GatewayTopologyEntry(BaseModel)`

Normalized IPv4 interval behind a specific Check Point gateway/cluster/VS interface.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
gateway_id: str = ''
gateway_asset_id: str = ''
gateway_uid: str
gateway_name: str
gateway_type: str
interface_name: str
interface_ipv4: str | None = None
interface_mask_length: int | None = None
topology_zone: TopologyZone = 'internal'
leads_to_dmz: bool = False
anti_spoofing_mode: AntiSpoofingMode = 'unknown'
source_type: TopologySourceType
source_ref: str = ''
cidr_or_range: str
ip_first_int: int
ip_last_int: int
prefix_len: int = 32
installed_access_policy: str | None = None
policy_packages: list[str] = Field(default_factory=list)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `GatewayInterfaceSummary(BaseModel)`

Aggregated topology view for a single gateway interface.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
gateway_id: str
gateway_asset_id: str
gateway_uid: str
gateway_name: str
gateway_type: str
interface_name: str
interface_ipv4: str | None = None
interface_mask_length: int | None = None
topology_zone: TopologyZone
leads_to_dmz: bool = False
anti_spoofing_mode: AntiSpoofingMode = 'unknown'
source_types: list[str] = Field(default_factory=list)
cidrs_and_ranges: list[str] = Field(default_factory=list)
```
#### class `TrafficFlowMatch(BaseModel)`

Evidence of a `(source, destination)` pair traversing two distinct interfaces on a gateway.

##### Fields / Class Variables

```python
source_query: str
destination_query: str
source_cidr_or_range: str
destination_cidr_or_range: str
src_interface: str
dst_interface: str
src_topology_zone: TopologyZone
dst_topology_zone: TopologyZone
src_matched_cidr: str
dst_matched_cidr: str
src_source_type: str
dst_source_type: str
src_source_ref: str = ''
dst_source_ref: str = ''
match_type: FlowMatchType
src_confidence: float = 1.0
dst_confidence: float = 1.0
confidence: float = 1.0
is_standby_path: bool = False
confidence_factors: list[ConfidenceDelta] = Field(default_factory=list)
warnings: list[str] = Field(default_factory=list)
```
#### class `AffectedGatewayCandidate(BaseModel)`

Policy-enforcing gateway/cluster/VS candidate positioned on the path between sources and destinations.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
gateway_id: str
gateway_asset_id: str
gateway_uid: str
gateway_name: str
gateway_type: str
ipv4_address: str | None = None
parent_id: str | None = None
parent_asset_id: str | None = None
installed_access_policy: str | None = None
policy_packages: list[str] = Field(default_factory=list)
access_layers: list[str] = Field(default_factory=list)
match_types: list[str] = Field(default_factory=list)
matched_sources: list[str] = Field(default_factory=list)
matched_destinations: list[str] = Field(default_factory=list)
confidence: float = 1.0
is_standby_path: bool = False
confidence_factors: list[ConfidenceDelta] = Field(default_factory=list)
warnings: list[str] = Field(default_factory=list)
matched_flows: list[TrafficFlowMatch] = Field(default_factory=list)
```
#### class `GatewayCliTarget(BaseModel)`

Target node specification for executing CLI commands via SSH DI or Check Point `cprid` `run-script`.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
gateway_id: str = ''
gateway_asset_id: str = ''
gateway_uid: str
gateway_name: str
gateway_type: str
node_uid: str
node_name: str
node_ipv4: str | None = None
vsid: int | None = None
vs_name: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `GatewayCliResult(BaseModel)`

Result of executing a CLI command/script on a gateway node.

##### Fields / Class Variables

```python
success: bool = True
stdout: str = ''
stderr: str = ''
exit_code: int = 0
executor: Literal['ssh', 'cprid'] = 'ssh'
error_code: str | None = None
error_message: str | None = None
bundle_stdout: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `GatewayRouteCollectionStatus(BaseModel)`

Per-gateway execution summary from `collect_gateway_routes`.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
gateway_id: str = ''
gateway_asset_id: str = ''
gateway_uid: str
gateway_name: str
gateway_type: str
success: bool
executor: str = ''
routes_collected: int = 0
member_drift_detected: bool = False
warnings: list[str] = Field(default_factory=list)
error_code: str | None = None
error: str | None = None
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `RouteCollectionOutcome(BaseModel)`

Aggregated outcome of `collect_gateway_routes` across target gateways.

##### Fields / Class Variables

```python
total_gateways: int = 0
succeeded_gateways: int = 0
failed_gateways: int = 0
total_routes: int = 0
gateways: list[GatewayRouteCollectionStatus] = Field(default_factory=list)
```
#### class `TopologyDiagnostic(BaseModel)`

Completeness, trust, or topology mode diagnostic for a gateway or interface.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
gateway_id: str = ''
gateway_asset_id: str = ''
gateway_uid: str
gateway_name: str
gateway_type: str
interface_name: str | None = None
code: TopologyDiagnosticCode
severity: TopologyDiagnosticSeverity = 'warning'
behind_mode: str = ''
anti_spoofing_mode: AntiSpoofingMode = 'unknown'
specific_network_ref: str | None = None
message: str
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `TopologyDiscrepancy(BaseModel)`

Discrepancy between SmartConsole static topology, live routing tables, and cluster members.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
gateway_id: str = ''
gateway_asset_id: str = ''
gateway_uid: str
gateway_name: str
gateway_type: str
discrepancy_type: TopologyDiscrepancyType
severity: TopologyDiagnosticSeverity = 'warning'
interface_name: str
routed_interface_name: str | None = None
cidr_or_range: str
static_sources: list[str] = Field(default_factory=list)
route_sources: list[str] = Field(default_factory=list)
annotation_disposition: str | None = None
suppressed_by_annotation: bool = False
confidence_delta: float = 0.0
member_details: dict[str, list[str]] = Field(default_factory=dict)
message: str
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `TopologyReconciliationReport(BaseModel)`

Combined static topology diagnostics and static-vs-live route reconciliation report.

##### Fields / Class Variables

```python
mgmt_name: str | None = None
domain_name: str | None = None
gateway_count: int = 0
diagnostics: list[TopologyDiagnostic] = Field(default_factory=list)
discrepancies: list[TopologyDiscrepancy] = Field(default_factory=list)
```
#### class `TopologyAnnotation(BaseModel)`

Persistent administrator override, standby route marker, or IPAM metadata annotation.

##### Fields / Class Variables

```python
id: str = ''
mgmt_name: str
domain_name: str
gateway_uid: str
gateway_name: str = ''
interface_name: str = '*'
cidr_or_range: str = '*'
trust_static_topology: bool | None = None
disposition: AnnotationDisposition | None = None
topology_zone: TopologyZone | None = None
zone: str = ''
site: str = ''
comment: str = ''
custom_metadata: dict[str, Any] = Field(default_factory=dict)
updated_at: datetime = Field(default_factory=utc_now)
```
##### Methods

###### `def model_post_init(self, __context: Any) -> None`

_No docstring._

#### class `ExportedTopologyPrefix(BaseModel)`

Enriched gateway/interface prefix record for IPAM export and reconciliation.

##### Fields / Class Variables

```python
mgmt_name: str
domain_name: str
gateway_id: str
gateway_asset_id: str
gateway_uid: str
gateway_name: str
gateway_type: str
interface_name: str
interface_ipv4: str | None = None
interface_mask_length: int | None = None
cidr_or_range: str
prefix_len: int
topology_zone: TopologyZone
leads_to_dmz: bool = False
source_types: list[str] = Field(default_factory=list)
source_refs: list[str] = Field(default_factory=list)
anti_spoofing_mode: AntiSpoofingMode = 'unknown'
disposition: AnnotationDisposition | None = None
is_standby_path: bool = False
confidence: float = 1.0
confidence_factors: list[ConfidenceDelta] = Field(default_factory=list)
zone: str = ''
site: str = ''
comment: str = ''
custom_metadata: dict[str, Any] = Field(default_factory=dict)
```
### `arodonata/core/ports/__init__.py`

Hexagonal architectural ports (`ApiPort`, `CachePort`, `LockPort`, `AuthProvider`, `GatewayCliPort`, `RulebaseRefreshPort`).

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

#### class `GatewayCliPort(Protocol)`

```python
@runtime_checkable
```
Protocol for executing CLI scripts/commands on Check Point gateways (e.g., via SSH in bash/expert mode).

##### Methods

###### `async def execute_command(self, target: GatewayCliTarget, command: str, *, timeout: float = 30.0) -> GatewayCliResult | str`

Execute `command` on `target` and return `GatewayCliResult` or raw stdout string.

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

#### class `DomainCachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent domain metadata cache operations.

##### Methods

###### `async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False) -> list[DomainInfo]`

Return cached domains, excluding `Global` domains unless `include_global=True`.

###### `async def get_domain(self, mgmt_name: str, domain_name: str) -> DomainInfo | None`

Return a single cached domain by `(mgmt_name, domain_name)`.

###### `async def upsert_domains(self, domains: Sequence[DomainInfo]) -> None`

Insert or update domain rows in `arodonata_domains`.

#### class `SidCachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent shared read-only session identifier (`sid`) cache operations.

##### Methods

###### `async def get_sid(self, mgmt_name: str, domain_name: str, *, auth_identity: str | None = None) -> SIDCacheEntry | None`

Fetch a cached shared read-only session entry for `(mgmt_name, domain_name, auth_identity)`.

###### `async def upsert_sid(self, entry: SIDCacheEntry) -> None`

Insert or update a shared read-only session entry in `arodonata_sid_cache`.

###### `async def evict_sid(self, mgmt_name: str, domain_name: str, *, auth_identity: str | None = None) -> bool`

Remove the cached SID for `(mgmt_name, domain_name)` (and optional `auth_identity`) immediately.

###### `async def list_sids(self, mgmt_name: str | None = None) -> list[SIDCacheEntry]`

List cached shared read-only SIDs, optionally filtered by `mgmt_name`.

#### class `SyncStatePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent domain synchronization state tracking.

##### Methods

###### `async def get_sync_state(self, mgmt_name: str, domain_name: str, scope: SyncScope, item_type: str = '*') -> DomainSyncState | None`

Fetch synchronization state for `(mgmt_name, domain_name, scope, item_type)`.

###### `async def list_sync_states(self, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> list[DomainSyncState]`

List synchronization states matching optional filters.

###### `async def upsert_sync_state(self, state: DomainSyncState) -> None`

Insert or update a `DomainSyncState` row in `arodonata_domain_sync_state`.

#### class `ObjectCachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent network object cache operations.

##### Methods

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

###### `async def apply_object_diff(self, mgmt_name: str, domain_name: str, *, deleted_uids: Sequence[str] = (), objects: Sequence[CPObject] = (), sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically delete `deleted_uids`, upsert `objects`, and update `sync_states` in one transaction.

#### class `ServiceCachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent service object cache operations.

##### Methods

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

###### `async def apply_service_diff(self, mgmt_name: str, domain_name: str, *, deleted_uids: Sequence[str] = (), services: Sequence[CPService] = (), sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically delete `deleted_uids`, upsert `services`, and update `sync_states` in one transaction.

#### class `AssetCachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent gateway, cluster, VSX, and server asset cache operations.

##### Methods

###### `async def get_assets(self, mgmt_name: str | None = None, domain_name: str | None = None, *, types: Sequence[str] | None = None) -> list[Asset]`

Query cached gateway/cluster/VSX/server assets from `arodonata_assets`.

###### `async def replace_domain_assets(self, mgmt_name: str, domain_name: str, assets: Sequence[Asset], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically replace all cached assets for `(mgmt_name, domain_name)`.

###### `async def upsert_assets(self, assets: Sequence[Asset]) -> int`

Insert or update `Asset` rows in `arodonata_assets`.

#### class `TopologyCachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent gateway topology intervals and administrator annotations.

##### Methods

###### `async def get_gateway_topology(self, mgmt_name: str | None = None, domain_name: str | None = None, *, gateway_uids: Sequence[str] | None = None, gateway_names: Sequence[str] | None = None, topology_zone: str | None = None, source_types: Sequence[str] | None = None) -> list[GatewayTopologyEntry]`

Query cached gateway interface topology intervals from `arodonata_gateway_topology`.

###### `async def replace_domain_topology(self, mgmt_name: str, domain_name: str, entries: Sequence[GatewayTopologyEntry], *, gateway_uids: Sequence[str] | None = None, source_types: Sequence[str] | None = None, active_gateway_uids: Sequence[str] | None = None, sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically replace cached gateway topology entries for `(mgmt_name, domain_name)` (optionally scoped by `gateway_uids` and `source_types`).

###### `async def upsert_gateway_topology(self, entries: Sequence[GatewayTopologyEntry], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

Insert or update `GatewayTopologyEntry` rows in `arodonata_gateway_topology`.

###### `async def get_topology_annotations(self, mgmt_name: str | None = None, domain_name: str | None = None, *, gateway_uids: Sequence[str] | None = None, interface_name: str | None = None) -> list[TopologyAnnotation]`

Query persistent administrator topology annotations from `arodonata_topology_annotations`.

###### `async def upsert_topology_annotations(self, annotations: Sequence[TopologyAnnotation]) -> int`

Insert or update `TopologyAnnotation` rows in `arodonata_topology_annotations`.

###### `async def delete_topology_annotations(self, annotation_ids: Sequence[str]) -> int`

Delete `TopologyAnnotation` rows matching `annotation_ids`.

#### class `RulebaseCachePort(Protocol)`

```python
@runtime_checkable
```
Protocol for persistent rulebase snapshot and package catalog cache operations.

##### Methods

###### `async def replace_domain_rulebase(self, snapshot: DomainRulebaseSnapshot, *, sync_state: DomainSyncState | None = None) -> None`

Atomically replace all `arodonata_rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`.

###### `async def replace_domain_package_catalog(self, mgmt_name: str, domain_name: str, package_layers: Sequence[RulebasePackageLayerEntry], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically replace `arodonata_rulebase_package_layer` rows for `(mgmt_name, domain_name)` without touching layer, section, or rule tables.

###### `async def upsert_domain_rulebase_layers(self, mgmt_name: str, domain_name: str, *, layers: Sequence[RulebaseLayerEntry] = (), sections: Sequence[RulebaseSectionEntry] = (), access_rules: Sequence[AccessRuleEntry] = (), nat_rules: Sequence[NatRuleEntry] = (), https_rules: Sequence[HttpsRuleEntry] = (), threat_rules: Sequence[ThreatRuleEntry] = (), package_layers: Sequence[RulebasePackageLayerEntry] = (), replaced_layer_uids: Sequence[str] = (), replaced_nat_package_uids: Sequence[str] = (), sync_states: Sequence[DomainSyncState] | None = None) -> int`

Atomically replace rulebase layers, sections, and rules strictly for `replaced_layer_uids` (and NAT packages) in `(mgmt_name, domain_name)`.

###### `async def get_domain_rulebase(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot`

Load the cached `DomainRulebaseSnapshot` for `(mgmt_name, domain_name)`.

###### `async def get_domain_rulebase_packages(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot`

Load lightweight `package_layers` and NAT package metadata for `(mgmt_name, domain_name)` without loading rule rows.

#### class `CachePort(DomainCachePort, SidCachePort, SyncStatePort, ObjectCachePort, ServiceCachePort, AssetCachePort, TopologyCachePort, RulebaseCachePort, Protocol)`

```python
@runtime_checkable
```
Composite protocol for persistent cache operations across domains, sessions, objects, services, assets, topology, and rulebases.

#### class `RulebaseRefreshPort(Protocol)`

```python
@runtime_checkable
```
Protocol for refreshing lightweight policy package catalogs without full rulebases.

##### Methods

###### `async def refresh_policy_packages(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

Synchronize lightweight policy package catalogs (`item_type='packages'`).

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

### `arodonata/core/primitives.py`

Shared pure core primitives for UUID matching, composite IDs, string sequences, and IPv4 bounds.

#### Module-Level Functions

##### `def is_readonly_command(command: str) -> bool`

Return `True` if `command` is a read-only Check Point Web API command (`C8`).

##### `def validate_command_name(command: str) -> str`

Validate and normalize a Check Point Web API command name against `^[a-z0-9]+(-[a-z0-9]+)*$`.

##### `def format_host_attr_for_url(host: str) -> str`

Wrap raw IPv6 literal in brackets `[...]` for URL/key construction.

##### `def is_uuid(value: Any) -> bool`

Return `True` if `value` is a canonical 8-4-4-4-12 hexadecimal UUID string.

##### `def format_composite_id(*parts: str | int) -> str`

Join key segments into a colon-delimited composite cache identifier.

##### `def parse_composite_id(composite_id: str, *, expected_parts: int = 3) -> tuple[str, ...] | None`

Split a colon-delimited composite identifier into `expected_parts` non-empty segments.

##### `def normalize_str_sequence(value: Sequence[str] | str | None, *, split_csv: bool = True, lowercase: bool = False, deduplicate: bool = False) -> list[str]`

Normalize a string, CSV string, or sequence of strings into a clean list of non-empty tokens.

##### `def mask_to_prefix_len(mask_val: str | int | float | None, *, allow_hostmask: bool = False, allow_prefix_int: bool = True) -> int | None`

Convert a dotted-quad netmask or prefix length (`0..32`) into an integer prefix length.

By default only contiguous IPv4 netmasks (e.g. `'255.255.255.0'`) and prefix lengths `0..32`
are accepted; wildcard/hostmasks such as `'0.0.0.255'` return `None` unless `allow_hostmask=True`.
Integral floats (e.g. `24.0`) are accepted when `allow_prefix_int=True`.

##### `def prefix_len_to_mask(prefix_len: int | str | None) -> str | None`

Convert an integer prefix length (`0..32`) into a dotted-quad IPv4 subnet mask string.

##### `def effective_range_prefix_len(ip_first_int: int, ip_last_int: int) -> int`

Compute an effective specificity (`0..32`) from an IPv4 integer interval span.

##### `def object_ipv4_bounds(obj: CPObject) -> tuple[int, int] | None`

Return `(min_ip_int, max_ip_int)` for a `host`, `network`, or `address-range` `CPObject`.

##### `def parse_cidr_or_range_bounds(cidr_or_range: str) -> tuple[int, int, int] | None`

Parse a CIDR (`10.0.0.0/24`), single IPv4 (`10.0.0.1`), or range (`10.0.0.1-10.0.0.10`) into `(lo, hi, prefix_len)`.

### `arodonata/core/services/__init__.py`

Core domain services for Arodonata v2 (`DomainService`, `DomainSyncCoordinator`,
`ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `SearchService`).

Strictly depends on `ApiPort`, `CachePort`, and `LockPort` protocols without transport or ORM imports.

_No public classes or functions in this module._

### `arodonata/core/services/_asset_linking.py`

Cluster and VSX topology relationship enrichment helpers for `AssetRefreshService`.

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
`parent_asset_id`, `virtual_system_uids`, `virtual_system_asset_ids`, `interfaces`,
or `raw_data` changed.

### `arodonata/core/services/_domain_discovery.py`

Canonical bounded MDS domain discovery helper (`arodonata.core.services._domain_discovery`).

#### Module-Level Functions

##### `def is_single_domain_unsupported(res: ApiCallResult) -> bool`

Return `True` if `show-domains` failed because the server is a single-domain SmartCenter.

##### `def coerce_total_domains(raw_total: Any, fallback: int) -> int`

Safely parse server-reported `total` domain count without throwing on malformed payloads.

##### `async def fetch_mds_ip_map(execute_cmd: Callable[[str, dict[str, Any]], Awaitable[ApiCallResult]], *, on_mds_ip: Callable[[str], None] | None = None) -> dict[str, str]`

Query `show-mdss` on the system domain to map MDS member names to IP addresses.

##### `async def fetch_global_domain_entry(mgmt_name: str, execute_cmd: Callable[[str, dict[str, Any]], Awaitable[ApiCallResult]], *, default_host: str | None = None, mds_ip_by_name: dict[str, str] | None = None, now_fn: Callable[[], datetime] = utc_now, require_uid: bool = True, fallback_uid: bool = False) -> DomainInfo | None`

Query `show-global-domain` and parse it into a normalized `Global` `DomainInfo` row.

##### `async def discover_mds_domains(mgmt_name: str, execute_cmd: Callable[[str, dict[str, Any]], Awaitable[ApiCallResult]], *, existing_domains: Sequence[DomainInfo], default_host: str | None = None, use_default_host_on_parse: bool = True, fallback_uid: bool = False, need_mdss_for_global: bool = False, now_fn: Callable[[], datetime] = utc_now, on_mds_ip: Callable[[str], None] | None = None, log: Any = logger) -> MdsDiscoveryResult`

Execute bounded `show-domains` (with RBAC fallback) and `show-mdss` discovery.

#### class `MdsDiscoveryResult`

```python
@dataclass(frozen=True, slots=True)
```
Structured result returned by `discover_mds_domains`.

##### Fields / Class Variables

```python
res: ApiCallResult
fallback_failed_res: ApiCallResult | None
is_single_domain: bool
saw_objects_list: bool
domains: list[DomainInfo]
mds_ip_by_name: dict[str, str]
```
### `arodonata/core/services/_typed_cache_sync.py`

Shared generic incremental/full sync and WriteSession overlay helpers for objects and services.

#### Module-Level Functions

##### `def unwrap_change_item(item: Any) -> Any`

Unwrap R82+ `show-changes` modified-object wrapper (`{'new-object': {...}}` or `{'old-object': {...}}`).

##### `def extract_changes_from_show_changes(data: dict[str, Any], *, tracked_types: set[str]) -> tuple[list[tuple[str, str]], list[str]]`

Extract `(added_or_modified_uid_and_type, deleted_uids)` for `tracked_types` from `show-changes` response.

##### `def can_try_incremental(probe: DomainProbeResult) -> bool`

Return `True` if every stale `item_type` in `probe` has a baseline `DomainSyncState`.

##### `async def try_incremental_sync(*, scope: Literal['objects', 'services'], probe: DomainProbeResult, emit: Callable[[SyncProgressEvent], Awaitable[None]], api: ApiPort, settings: ArodonataSettings, now_fn: Callable[[], datetime], model_from_cp_dict: Callable[[str, str, dict[str, Any]], TEntity], get_cached_by_type: Callable[[str, str, list[str]], Awaitable[Sequence[TEntity]]], apply_diff_fn: Callable[[str, str, Sequence[str], Sequence[TEntity], Sequence[DomainSyncState]], Awaitable[Any]]) -> int | None`

Attempt incremental refresh via `show-changes`; return `None` to fall back to full reload.

##### `async def full_reload_types(*, scope: Literal['objects', 'services'], probe: DomainProbeResult, emit: Callable[[SyncProgressEvent], Awaitable[None]], api: ApiPort, now_fn: Callable[[], datetime], resolve_command_fn: Callable[[str], tuple[str, dict[str, Any]]], model_from_cp_dict: Callable[[str, str, dict[str, Any]], TEntity], replace_domain_fn: Callable[[str, str, list[TEntity], Sequence[str], Sequence[DomainSyncState]], Awaitable[Any]]) -> int`

Fetch all entities for `probe.stale_types` and atomically replace them in cache.

##### `def apply_typed_context_overlay(cached_items: Sequence[TEntity], *, overlay_apply_fn: Callable[[Any, list[TEntity], Sequence[str] | None], list[TEntity]], mgmt_name: str | None = None, domain_name: str | None = None, allowed_domains: Collection[str] | None = None, include_global: bool = True, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[TEntity]`

Merge active `WriteSession` overlay from `contextvars` onto `cached_items`.

### `arodonata/core/services/asset_service.py`

Asset and gateway cache synchronization service (`AssetRefreshService`).

Provides:
- Paired `await refresh_assets(...)` and `stream_refresh_assets(...)` methods.
- Concurrent per-MDS-member domain asset collection via `DomainSyncCoordinator` (`scope="assets"`, `item_type="*"`).
- Re-exported `ClusterRelationshipManager` and `VSXRelationshipManager` relationship enrichers.

#### class `AssetRefreshService`

Synchronizes and queries cached gateway, cluster, VSX, and management server assets (`assets`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: AssetCachePort, coordinator: DomainSyncCoordinator, cluster_manager: ClusterRelationshipManager | None = None, vsx_manager: VSXRelationshipManager | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

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

###### `async def get_assets(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[Asset]`

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

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _DomainServiceCachePort, lock_port: LockPort | None = None, tracker: DomainListRefreshTracker | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

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

#### class `ObjectService`

Synchronizes and queries cached network objects (`arodonata_objects`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _ObjectServiceCachePort, coordinator: DomainSyncCoordinator, now_fn: Callable[[], datetime] = utc_now) -> None`

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

###### `def apply_context_overlay(cached_objects: Sequence[CPObject], *, mgmt_name: str | None = None, domain_name: str | None = None, allowed_domains: Collection[str] | None = None, include_global: bool = True, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPObject]`

```python
@staticmethod
```
Merge active `WriteSession` overlay from `contextvars` onto `cached_objects`.

### `arodonata/core/services/route_collector.py`

Backward-compatible re-export shim for live route collection, scripts, and CLI parsers.

_No public classes or functions in this module._

### `arodonata/core/services/script_service.py`

Application-agnostic Check Point Script Repository management and execution service.

#### class `ScriptRepositoryService`

Universal Check Point Script Repository CRUD, status, and execution service.

##### Methods

###### `def __init__(self, *, api: ApiPort, settings: ArodonataSettings | None = None, write_session_factory: Callable[..., AbstractAsyncContextManager[WriteSession]] | None = None, on_domain_invalidated: Callable[[str, str | None], None] | None = None) -> None`

_No docstring._

###### `async def get_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, details_level: str = 'full') -> RepositoryScript`

```python
@traced
```
Fetch a single repository script by name or UID (`show-repository-script`).

###### `async def list_repository_scripts(self, mgmt_name: str, *, domain: str | None = None, details_level: str = 'full', limit: int = 300) -> list[RepositoryScript]`

```python
@traced
```
List repository scripts in `domain` (`show-repository-scripts`).

###### `async def check_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, expected_body: str | None = None) -> RepositoryScriptStatus`

```python
@traced
```
Check whether a repository script exists and matches `expected_body` strictly read-only.

Note: `exists=False` is also returned when permission is denied (`error_code='repository_script_permission_denied'`)
or when the Management API does not support Script Repository commands (`error_code='repository_script_unsupported'`).
Callers MUST inspect `error_code` before treating `exists=False` as absence of the script.

###### `async def ensure_repository_script(self, mgmt_name: str, script_name: str, script_body: str, *, domain: str | None = None, comments: str | None = None, color: str | None = None, tags: Sequence[str] | None = None) -> EnsureRepositoryScriptResult`

```python
@traced
```
Idempotently ensure `script_name` exists with `script_body`, avoiding writes when already matching.

###### `async def delete_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None) -> bool`

```python
@traced
```
Delete a repository script from `domain` (`delete-repository-script`).

###### `async def run_repository_script(self, mgmt_name: str, script_name_or_uid: str, targets: Sequence[str] | str, *, domain: str | None = None, args: Sequence[str] | str | None = None, comments: str | None = None, timeout: float | None = None, script_timeout: int | None = None, sid: str | None = None, server_ip: str | None = None, session_getter: Callable[[str, str | None], Awaitable[tuple[str, str]]] | None = None) -> RepositoryScriptExecutionOutcome`

```python
@traced
```
Execute a pre-approved repository script via Check Point `run-script` (`script-type="repository"`).

Forwards `targets` and `args` (`str` verbatim or space-joined sequence) without route-collection
or VSX assumptions, running in a dedicated non-read-only session (without `publish` or `discard`)
unless an explicit `sid` or matching active `WriteSession` is already bound.

### `arodonata/core/services/search/__init__.py`

Modular cache-first search, group resolution, and structured query package (`arodonata.core.services.search`).

_No public classes or functions in this module._

### `arodonata/core/services/search/finder.py`

Exact/case-insensitive cross-entity object lookup helpers for `SearchService`.

#### Module-Level Functions

##### `def match_assets(assets: Sequence[Asset], clean_query: str, lookup_key: str, *, case_insensitive: bool = False) -> list[Asset]`

Match assets by `uid`, `name`, `asset_id`, or `id` (exact or case-insensitive).

##### `async def find_object_impl(svc: Any, mgmt_name: str, domain: str | None = None, name_or_uid: str = '', *, obj_type: str | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | CPService | Asset | None`

Find a single `CPObject`, `CPService`, or `Asset` by exact `uid`, `name`, or composite ID.

### `arodonata/core/services/search/query.py`

Structured cross-domain object/service/asset filtering, aggregation, and cache-status helpers.

#### Module-Level Functions

##### `def resolve_query_scopes(types: Sequence[str] | None, *, port: str | None = None, protocol: str | None = None, parent_id: str | None = None, parent_asset_id: str | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, is_policy_target: bool | None = None, is_execution_target: bool | None = None, group_by_attrs: Sequence[str] | None = None) -> tuple[list[str] | None, bool, bool, bool]`

Normalize `types` filters and compute `(requested_types, want_objects, want_services, want_assets)`.

##### `async def describe_objects_impl(svc: Any, *, mgmt_name: str | None = None, domain_name: str | None = None, include_global: bool = True) -> dict[str, Any]`

Return progressive-disclosure schema and summary counts for cached objects, services, and assets.

##### `async def query_objects_impl(svc: Any, *, mgmt_name: str | None = None, domain_name: str | None = None, domains: Sequence[str] | None = None, types: Sequence[str] | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, is_policy_target: bool | None = None, is_execution_target: bool | None = None, scope_origin: Literal['all', 'local', 'global'] = 'all', name_pattern: str | None = None, ip_subnet: str | None = None, port: str | None = None, protocol: str | None = None, tags: Sequence[str] | None = None, parent_id: str | None = None, parent_asset_id: str | None = None, include_global: bool = False, group_by: Sequence[str] | None = None, aggregate: Literal['count', 'list', 'describe'] = 'list', limit: int = 100, offset: int = 0, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> dict[str, Any]`

Execute structured cross-domain filtering, grouping, counting, or schema description.

##### `async def get_cache_status_impl(svc: Any, *, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> dict[str, Any]`

Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness.

### `arodonata/core/services/search/resolver.py`

Group/service-group/asset membership resolution, deduplication, and implicit domain mode helpers.

#### Module-Level Functions

##### `def dedup_entities_by_uid(items: Sequence[CPObject | CPService | Asset]) -> list[CPObject | CPService | Asset]`

Deduplicate cross-domain entities by `uid`, preferring the owning (`original_domain` / `Global`) copy.

##### `async def resolve_implicit_domain_mode_impl(svc: Any, mgmt_name: str, eff_domain: str | None, cache_mode: CacheMode) -> tuple[str | None, CacheMode]`

Resolve `(single_domain_or_none, effective_cache_mode)` when `domain` is omitted.

##### `async def resolve_group_with_members_impl(svc: Any, mgmt_name: str, domain: str | None = None, group_name_or_uid: str = '', *, recursive: bool = True, max_depth: int = 5, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> tuple[CPObject | CPService | Asset | None, list[CPObject | CPService | Asset]]`

Resolve `(target_group_entity, members)` for `group_name_or_uid` in `(mgmt_name, domain)`.

### `arodonata/core/services/search/service.py`

`SearchService` facade class preserving `@traced` telemetry and public SDK surface.

#### class `SearchService`

Cache-first object search, recursive group membership resolution, and structured queries.

##### Methods

###### `def __init__(self, *, cache: _SearchServiceCachePort, object_service: ObjectService, service_cache: ServiceCacheService | None = None, asset_service: AssetRefreshService | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def search_objects(self, query: str, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, max_depth: int = 2, exact_match: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> SearchResult`

```python
@traced(module=_SEARCH_TRACE_MODULE)
```
Search cached objects across comma-separated terms and resolve parent group memberships up to `max_depth`.

###### `async def resolve_implicit_domain_mode(self, mgmt_name: str, eff_domain: str | None, cache_mode: CacheMode) -> tuple[str | None, CacheMode]`

Resolve `(single_domain_or_none, effective_cache_mode)` when `domain` is omitted.

###### `async def resolve_group_with_members(self, mgmt_name: str, domain: str | None = None, group_name_or_uid: str = '', *, recursive: bool = True, max_depth: int = 5, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> tuple[CPObject | CPService | Asset | None, list[CPObject | CPService | Asset]]`

```python
@traced(module=_SEARCH_TRACE_MODULE)
```
Resolve `(target_group_entity, members)` for `group_name_or_uid` in `(mgmt_name, domain)`.

###### `async def get_group_members(self, mgmt_name: str, domain: str | None = None, group_name_or_uid: str = '', *, recursive: bool = True, max_depth: int = 5, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject | CPService | Asset]`

```python
@traced(module=_SEARCH_TRACE_MODULE)
```
Return direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items.

###### `async def find_object(self, mgmt_name: str, domain: str | None = None, name_or_uid: str = '', *, obj_type: str | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | CPService | Asset | None`

```python
@traced(module=_SEARCH_TRACE_MODULE)
```
Find a single `CPObject`, `CPService`, or `Asset` by exact `uid`, `name`, or composite ID.

###### `async def describe_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, include_global: bool = True) -> dict[str, Any]`

```python
@traced(module=_SEARCH_TRACE_MODULE)
```
Return progressive-disclosure schema and summary counts for cached objects, services, and assets.

###### `async def query_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, domains: Sequence[str] | None = None, types: Sequence[str] | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, is_policy_target: bool | None = None, is_execution_target: bool | None = None, scope_origin: Literal['all', 'local', 'global'] = 'all', name_pattern: str | None = None, ip_subnet: str | None = None, port: str | None = None, protocol: str | None = None, tags: Sequence[str] | None = None, parent_id: str | None = None, parent_asset_id: str | None = None, include_global: bool = False, group_by: Sequence[str] | None = None, aggregate: Literal['count', 'list', 'describe'] = 'list', limit: int = 100, offset: int = 0, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> dict[str, Any]`

```python
@traced(module=_SEARCH_TRACE_MODULE)
```
Execute structured cross-domain filtering, grouping, counting, or schema description.

###### `async def get_cache_status(self, *, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> dict[str, Any]`

```python
@traced(module=_SEARCH_TRACE_MODULE)
```
Inspect `domain_sync_state` across scopes and return per-domain/per-type freshness.

### `arodonata/core/services/search/terms.py`

Search term classification, term matching, and BFS group-membership resolution.

#### Module-Level Functions

##### `def classify_search_term(term: str) -> ClassifiedSearchTerm`

Classify a single search term into `"ipv4"`, `"cidr"`, `"range"`, `"wildcard"`, `"uid"`, or `"name"`.

##### `def matches_classified_term(obj: CPObject, term: ClassifiedSearchTerm, *, exact_match: bool = False) -> bool`

Return `True` if `obj` matches `term`.

##### `def resolve_group_memberships(matches: Sequence[CPObject], all_objects: Sequence[CPObject], *, max_depth: int) -> dict[str, list[GroupMembershipNode]]`

Build reverse member-to-group index per `(mgmt_name, domain_name)` and traverse BFS up to `max_depth`.

##### `async def search_objects_impl(svc: Any, query: str, *, classified_terms: list[ClassifiedSearchTerm], mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, max_depth: int = 2, exact_match: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> SearchResult`

Execute cache-first object/asset term search and parent group expansion.

#### class `ClassifiedSearchTerm`

Parsed representation of a single search term.

##### Methods

###### `def __init__(self, raw: str, kind: SearchTermKind, *, ip: ipaddress.IPv4Address | None = None, network: ipaddress.IPv4Network | None = None, range_bounds: tuple[int, int] | None = None) -> None`

_No docstring._

### `arodonata/core/services/search_service.py`

Backward-compatible re-export shim for `arodonata.core.services.search` (`SearchService`).

_No public classes or functions in this module._

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

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _ServiceCachePort, coordinator: DomainSyncCoordinator, now_fn: Callable[[], datetime] = utc_now) -> None`

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

###### `def apply_context_overlay(cached_services: Sequence[CPService], *, mgmt_name: str | None = None, domain_name: str | None = None, allowed_domains: Collection[str] | None = None, include_global: bool = True, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None) -> list[CPService]`

```python
@staticmethod
```
Merge active `WriteSession` overlay from `contextvars` onto `cached_services`.

### `arodonata/core/services/sync_coordinator.py`

Unified domain synchronization coordinator (`DomainSyncCoordinator`).

Coordinates multi-domain cache synchronization across `"domains"`, `"objects"`, `"services"`,
`"assets"`, and `"rulebase"`:
- Groups target domains by `active_mds_ip` and bounds concurrent domain refreshes per MDS member
  to `settings.domain_sync_concurrency` (default `min(2, max(1, concurrent_limit - 1))`, shared
  process-wide across coordinators attached to the same database engine, with MDS members running
  in parallel).
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

##### `def resolve_engine_registry(cache: Any, registries: WeakKeyDictionary[Any, T], fallback: T, factory: Callable[[], T]) -> T`

Resolve process-wide state keyed weakly by the shared database engine exposed by `cache`.

##### `def resolve_loop_state(loop_states: WeakKeyDictionary[asyncio.AbstractEventLoop, T], fallback_by_id: dict[int, T], factory: Callable[[], T]) -> T`

Resolve per-event-loop state weakly keyed by the running loop so closed loops are pruned automatically.

#### class `DomainProbeResult`

Result of probing a single `(mgmt_name, domain_name)` for staleness across `item_types`.

##### Methods

###### `def __init__(self, *, mgmt_name: str, domain: DomainInfo, stale_types: list[str], fresh_types: list[str], existing_states: dict[str, DomainSyncState], remote_published_at: datetime | None = None, remote_session_uid: str | None = None, probe_error: Exception | None = None, probe_started_at: datetime | None = None, invalidation_seq_at_start: int = 0, invalidation_at_start: tuple[datetime | None, int] = (None, 0), verified_remote: bool = False) -> None`

_No docstring._

###### `def is_stale(self) -> bool`

```python
@property
```
Return `True` if any requested `item_type` is stale or the probe failed.

#### class `DomainSyncCoordinator`

Coordinates bounded per-MDS-member domain synchronization, locking, and staleness probes.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _SyncCoordinatorCachePort, lock_port: LockPort, domain_service: DomainService, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `def invalidated_domains(self) -> set[tuple[str, str]]`

```python
@property
```
Set of `(mgmt_name, domain_name)` pairs invalidated via `invalidate_domain`.

Entries act as monotonic lifetime watermarks (retained across subsequent syncs and compared
against per-slice `synced_at` timestamps and `_slice_synced_seq` rather than deleted on sync).

###### `def invalidate_domain(self, mgmt_name: str, domain_name: str | None = None) -> None`

Invalidate freshness memo for `(mgmt_name, domain_name)` (or all domains on `mgmt_name` if None).

###### `def invalidation_timestamp(self, mgmt_name: str, domain_name: str | None = None) -> datetime | None`

Return the latest invalidation UTC timestamp for `(mgmt_name, domain_name)` (including `*` wildcard).

###### `def is_slice_invalidated(self, mgmt_name: str, domain_name: str, scope: str, item_type: str, synced_at: datetime | None) -> bool`

Return `True` when `(mgmt_name, domain_name)` invalidation is newer than `(scope, item_type)` `synced_at`.

###### `def is_domain_invalidated(self, mgmt_name: str, domain_name: str | None = None, *, scope: str | None = None, item_type: str | None = None, synced_at: datetime | None = None) -> bool`

Return `True` if `(mgmt_name, domain_name)` has an active invalidation (optionally compared against `synced_at`).

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

### `arodonata/core/services/topology/__init__.py`

Gateway topology extraction, live route collection, diagnostics, reconciliation, and matching.

_No public classes or functions in this module._

### `arodonata/core/services/topology/_shared.py`

Shared loggers, constants, internal models, and synchronization primitives for topology modules.

#### Module-Level Functions

##### `def is_policy_enforcing_gateway(asset: Asset) -> bool`

Return `True` if `asset` is a policy-enforcing gateway, cluster, or VSX Virtual System.

### `arodonata/core/services/topology/diagnostics.py`

Gateway topology query/summarization, static health diagnostics, and persistent annotation CRUD.

#### Module-Level Functions

##### `async def get_gateway_topology(cache: _TopologyServiceCachePort, rulebase_refresh: RulebaseRefreshPort | None, *, refresh_topology_fn: _RefreshTopologyFn, mgmt_name: str | None = None, domain: str | None = None, gateway: str | None = None, topology_zone: TopologyZone | None = None, source_types: Sequence[TopologySourceType | str] | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[GatewayTopologyEntry]`

Ensure topology is synchronized (unless `cache_mode="cache"`) and return cached `GatewayTopologyEntry` rows.

##### `def summarize_gateway_interfaces(entries: Sequence[GatewayTopologyEntry]) -> list[GatewayInterfaceSummary]`

Aggregate flat `GatewayTopologyEntry` rows into per-interface `GatewayInterfaceSummary` models.

##### `async def get_topology_diagnostics(cache: _TopologyServiceCachePort, *, refresh_topology_fn: _RefreshTopologyFn, mgmt_name: str | None = None, domain: str | None = None, gateways: Sequence[str] | str | None = None, gateway: str | None = None, min_severity: TopologyDiagnosticSeverity = 'info', cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[TopologyDiagnostic]`

Inspect gateway and interface definitions and return `TopologyDiagnostic` items.

##### `async def get_topology_annotations(cache: _TopologyServiceCachePort, mgmt_name: str | None = None, domain: str | None = None, *, gateway: str | None = None, interface_name: str | None = None) -> list[TopologyAnnotation]`

Return persistent `TopologyAnnotation` records from `arodonata_topology_annotations`.

##### `async def upsert_topology_annotations(cache: _TopologyServiceCachePort, annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any]) -> list[TopologyAnnotation]`

Insert or update persistent `TopologyAnnotation` records and return the normalized models.

##### `async def delete_topology_annotations(cache: _TopologyServiceCachePort, annotation_ids: Sequence[str] | str | None = None, *, mgmt_name: str | None = None, domain: str | None = None, gateway_uid: str | None = None) -> int`

Delete persistent `TopologyAnnotation` records by ID or filter.

### `arodonata/core/services/topology/extractor.py`

Domain topology sync-head checks, trusted object domain analysis, and static/VSX extraction.

_No public classes or functions in this module._

### `arodonata/core/services/topology/flow_matching.py`

Cross-interface LPM flow matching, policy rule confidence boosting, one-arm inference, and candidate assembly.

_No public classes or functions in this module._

### `arodonata/core/services/topology/normalizer.py`

Multi-format Check Point gateway interface, static route, VPN domain, and policy metadata normalization.

_No public classes or functions in this module._

### `arodonata/core/services/topology/objects.py`

Domain-scoped object loading, on-demand asset/group/object fetching, indexing, and expansion.

_No public classes or functions in this module._

### `arodonata/core/services/topology/policy_matcher.py`

Affected gateway LPM flow matching, policy rule evidence scoring, and one-arm gateway inference.

#### Module-Level Functions

##### `async def find_affected_gateways(*, api: ApiPort, cache: _TopologyServiceCachePort, rulebase_refresh: RulebaseRefreshPort | None, weights: TopologyConfidenceWeights, now_fn: Callable[[], datetime], refresh_topology_fn: _RefreshTopologyFn, sources: Sequence[str] | str, destinations: Sequence[str] | str, mgmt_name: str | None = None, domain: str | None = None, source_types: Sequence[TopologySourceType | str] | None = None, include_annotations: bool = True, min_confidence: float = 0.0, include_standby: bool = True, include_policy_inferred: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[AffectedGatewayCandidate]`

Locate all policy-enforcing gateways where `sources` and `destinations` resolve to distinct interfaces (`src_interface != dst_interface`), or via explicit installed policy rules when `include_policy_inferred=True`.

### `arodonata/core/services/topology/policy_rules.py`

Policy package snapshot loading, gateway policy metadata resolution, rule expansion, and one-arm checks.

_No public classes or functions in this module._

### `arodonata/core/services/topology/reconciler.py`

Static topology vs live routing reconciliation and gateway-targeted policy verification.

#### Module-Level Functions

##### `async def reconcile_gateway_topology(*, cache: _TopologyServiceCachePort, rulebase_refresh: RulebaseRefreshPort | None, weights: TopologyConfidenceWeights, refresh_topology_fn: _RefreshTopologyFn, collect_routes_fn: _CollectRoutesFn, mgmt_name: str | None = None, domain: str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, collect_live_routes: bool = False, check_policy: bool = False, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> TopologyReconciliationReport`

Compare SmartConsole static topology against live gateway routing tables (and optionally gateway-targeted policy rules) and return `TopologyReconciliationReport`.

### `arodonata/core/services/topology/refresh.py`

Targeted and full-domain topology refresh orchestration and streaming progress handlers.

#### Module-Level Functions

##### `async def stream_refresh_topology(*, settings: ArodonataSettings, api: ApiPort, cache: _TopologyServiceCachePort, coordinator: DomainSyncCoordinator, asset_service: AssetRefreshService, rulebase_refresh: RulebaseRefreshPort | None, now_fn: Callable[[], datetime], collect_routes_fn: _CollectRoutesFn, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing gateway topology across domains (or targeted `gateways`).

##### `async def refresh_topology(*, settings: ArodonataSettings, api: ApiPort, cache: _TopologyServiceCachePort, coordinator: DomainSyncCoordinator, asset_service: AssetRefreshService, rulebase_refresh: RulebaseRefreshPort | None, now_fn: Callable[[], datetime], collect_routes_fn: _CollectRoutesFn, refresh_flights: dict[tuple[Any, ...], asyncio.Future[RefreshOutcome]], mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RefreshOutcome`

Refresh gateway topology across domains (or targeted `gateways`) and return `RefreshOutcome`.

### `arodonata/core/services/topology/route_collection.py`

Multi-gateway live IPv4 route collection orchestration and sync-state persistence.

#### Module-Level Functions

##### `async def collect_gateway_routes(*, settings: ArodonataSettings, api: ApiPort, cache: _TopologyServiceCachePort, asset_service: AssetRefreshService, rulebase_refresh: RulebaseRefreshPort | None, script_service: ScriptRepositoryService, default_gateway_cli: GatewayCliPort | GatewayCliCallable | None, now_fn: Callable[[], datetime], route_collect_flights: dict[tuple[Any, ...], asyncio.Future[RouteCollectionOutcome]], get_node_lock: Callable[[str, str], asyncio.Lock], get_semaphore: Callable[[str, int], asyncio.Semaphore], mgmt_name: str | None = None, domain: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, include_global: bool = True, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, timeout: float = 30.0, concurrency: int | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RouteCollectionOutcome`

Collect live IPv4 routing tables (`ip -4 route show` and `clish -c "show route"`) from gateways via SSH DI or `cprid` `run-script`.

### `arodonata/core/services/topology/route_executor.py`

Live CLI execution (`SSH` + `cprid` inline and repository `run-script` fallback).

#### Module-Level Functions

##### `async def execute_gateway_cli(target: GatewayCliTarget, script: str, *, api: ApiPort, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, timeout: float = 30.0, cprid_session_getter: Callable[[str, str], Awaitable[tuple[str, str]]] | None = None, cprid_script_mode: CpridScriptMode = 'inline', repository_script_name: str = DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME, repository_script_args_fn: RepositoryScriptArgsCallable | None = None, max_routes: int | None = None, script_service: ScriptRepositoryService | None = None, domain_fallback_inline: dict[tuple[str, str], bool] | None = None, auto_mode_resolver: AutoScriptModeResolver | None = None, preclaimed_auto_probe: bool = False) -> GatewayCliResult`

Execute `script` on `target` via injected `gateway_cli` (SSH) with optional `cprid` `run-script` fallback.

### `arodonata/core/services/topology/route_parsers.py`

Parsers for Check Point `run-script` task output, Gaia `ip route` / `clish` tables, and topology entry conversion.

#### Module-Level Functions

##### `def parse_vsx_bundle_output(stdout: str) -> list[VsxBundleSlice]`

Parse a multi-VS text bundle emitted by zero-argument `arodonata-collect-routes-v1`.

##### `def extract_vs_slice_from_bundle(stdout: str, *, vsid: int | None = None, vs_name: str | None = None, executor: Literal['ssh', 'cprid'] = 'cprid', base_result: GatewayCliResult | None = None) -> GatewayCliResult`

Extract a specific Virtual System slice from VSX bundle output, or return original output if not bundled.

##### `def decode_cprid_task_output(data: dict[str, Any]) -> tuple[bool, str, str]`

Extract and Base64-decode `responseMessage` / `responseError` from Check Point `run-script` / `show-task`.

##### `def parse_ip_route_show(output: str) -> list[ParsedCliRoute]`

Parse Linux/Gaia `ip -4 route show` output into `ParsedCliRoute` items.

##### `def parse_clish_show_route(output: str) -> list[ParsedCliRoute]`

Parse Gaia `clish -c "show route"` output into `ParsedCliRoute` items.

##### `def parse_combined_cli_routes_with_status(stdout: str, *, max_routes: int | None = None) -> tuple[list[ParsedCliRoute], bool]`

Parse combined `ip -4 route show` and `clish -c "show route"` stdout and report whether `max_routes` truncated any entry.

##### `def parse_combined_cli_routes(stdout: str, *, max_routes: int | None = None) -> list[ParsedCliRoute]`

Parse combined `ip -4 route show` and `clish -c "show route"` stdout, upgrading protocol specificity from clish when both report the same `(destination, interface)`.

##### `def routes_to_topology_entries(*, gateway_asset: Asset, parsed_routes_by_node: dict[str, list[ParsedCliRoute]], interface_meta: Mapping[str, tuple[str | None, int | None, bool, str] | tuple[str | None, int | None, bool, str, bool]], installed_access_policy: str | None, policy_packages: list[str], now: datetime | None = None) -> tuple[list[GatewayTopologyEntry], bool, dict[tuple[str, str], list[str]]]`

Convert per-node `ParsedCliRoute` lists into `GatewayTopologyEntry` rows and detect cluster member drift.

Returns `(entries, member_drift_detected, drift_map)` where `drift_map` maps `(interface_name, cidr_or_range)`
to the subset of cluster node names that reported the route whenever not all nodes reported it.

#### class `VsxBundleSlice`

```python
@dataclass(slots=True)
```
Parsed Virtual System slice from a zero-argument VSX repository bundle.

##### Fields / Class Variables

```python
vsid: int
vs_name: str
raw_output: str
error: str | None = None
```
### `arodonata/core/services/topology/route_scripts.py`

Route-collection bash script builders, argument formatting, VSX target resolution, and auto-mode resolver.

#### Module-Level Functions

##### `def build_route_collection_script(vsid: int | None = None, vs_name: str | None = None, *, max_routes: int | None = None) -> str`

Build a safe bash script for collecting IPv4 routes from Gaia OS or a VSX Virtual System context.

When `vsid` is specified (`> 0`), switches context via `vsenv "$vsid" >/dev/null 2>&1 </dev/null`
and verifies that `$FWDIR` contains `printf "CTX%05d" "$vsid"` before querying routes, redirecting
stdin from `/dev/null` so nested loops or parent shells never lose stdin. When `vsid` is `None`
but `vs_name` is set, dynamically resolves `vsid` via `vsx stat -l` on `VS0` and fails cleanly
if the VSID cannot be resolved. When `max_routes` (`> 0`) is specified, caps CLI output lines via
`awk` and skips `clish -c "show route"` on BGP full-view / large tables (`> 10000` kernel routes).

##### `def build_route_collection_repository_script(*, default_max_routes: int = DEFAULT_REPOSITORY_MAX_ROUTES, default_skip_threshold: int = DEFAULT_CLISH_SKIP_THRESHOLD) -> str`

Build the canonical self-detecting bash script (`arodonata-collect-routes-v1`) for Check Point Script Repository.

Execution modes:
- Zero-argument (`$# -eq 0`): auto-detects VSX via `vsx stat -l </dev/null 2>/dev/null`.
  - On VSX chassis: iterates all L3 Virtual Systems / Virtual Routers (`VSID > 0`, skipping Virtual Switches),
    emitting a bundle delimited by `===ARODONATA_VSX_BUNDLE_START===` ... `===ARODONATA_VSX_BUNDLE_END===`
    with per-VS markers `===ARODONATA_VS_START vsid=<id> name=<name>===` ... `===ARODONATA_VS_END===`
    and isolating failed `vsenv` contexts with `===ARODONATA_VS_ERROR vsid=<id> name=<name> error=<err>===`.
  - On non-VSX gateways: executes with built-in route limit (`default_max_routes`) and clish skip threshold.
- Parameterized (`$# -gt 0`): preserves backward-compatible positional argument handling:
  - `$1`: `max_routes` (digits-only; `0` or empty = unlimited)
  - `$2`: `vsid` (digits-only; `0` or empty = host / non-VSX)
  - `$3`: `vs_name` (optional Virtual System name resolved dynamically via `vsx stat -l` when `vsid=0`)

##### `def format_route_collection_repository_args(target: GatewayCliTarget, *, max_routes: int | None = None) -> str`

Format safe positional `args` (`<max_routes> <vsid> [<vs_name>]`) for `arodonata-collect-routes-v1`.

##### `def resolve_gateway_cli_targets(gateway_asset: Asset, all_assets: Sequence[Asset]) -> list[GatewayCliTarget]`

Resolve a policy-enforcing gateway, cluster, or VSX Virtual System into concrete CLI execution targets.

- `simple-gateway` -> `[gateway_asset]`
- `simple-cluster` / `CpmiGatewayCluster` -> each `cluster-member` linked to the cluster (or the cluster itself if no members exist in cache)
- `virtual-system` / `CpmiVsNetobj` / `CpmiVsClusterNetobj` -> the physical VSX parent (`VS0`) or its cluster members, carrying `vsid` and `vs_name`

#### class `AutoScriptModeResolver`

Single-flight per-domain resolver for `cprid_script_mode='auto'`.

##### Methods

###### `def __init__(self) -> None`

_No docstring._

###### `def get_resolved(self, mgmt_name: str, domain_name: str | None) -> Literal['repository', 'inline'] | None`

Return the cached script mode decision for `(mgmt_name, domain_name)` if already resolved.

###### `async def acquire_probe_turn(self, mgmt_name: str, domain_name: str | None) -> bool`

Acquire a single per-domain probe slot or await the in-flight probe without holding `mgmt_sem`.

###### `def resolve_probe(self, mgmt_name: str, domain_name: str | None, mode: Literal['repository', 'inline']) -> None`

Record the domain's script mode decision and wake waiting targets.

###### `def abort_probe_if_unresolved(self, mgmt_name: str, domain_name: str | None, *, exc: BaseException | None = None) -> None`

Release the in-flight probe slot if the prober exited before resolving.

#### class `ParsedCliRoute`

```python
@dataclass(frozen=True)
```
Normalized IPv4 route entry parsed from `ip -4 route show` or `clish -c "show route"`.

##### Fields / Class Variables

```python
destination: ipaddress.IPv4Network
interface_name: str
nexthop: ipaddress.IPv4Address | None
source_type: TopologySourceType
protocol_label: str
```
### `arodonata/core/services/topology/scoring.py`

Annotation indexing, effective interval assembly, evidence delta scoring, endpoint resolution, and IPAM export.

#### Module-Level Functions

##### `async def export_topology_prefixes(cache: TopologyCachePort, weights: TopologyConfidenceWeights, *, refresh_topology_fn: _RefreshTopologyFn, mgmt_name: str | None = None, domain: str | None = None, gateways: Sequence[str] | str | None = None, gateway: str | None = None, include_external: bool = False, include_ignored: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[ExportedTopologyPrefix]`

Export deduplicated gateway/interface prefixes with confidence scores and IPAM annotations.

### `arodonata/core/services/topology/service.py`

Gateway interface topology extraction, caching, and affected gateway candidate matching (`TopologyService`).

#### class `TopologyService`

Extracts, caches, reconciles, and matches gateway interface topology and live routes across domains.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _TopologyServiceCachePort, coordinator: DomainSyncCoordinator, asset_service: AssetRefreshService, object_service: ObjectService, rulebase_refresh: RulebaseRefreshPort | None = None, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, script_service: ScriptRepositoryService | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

Initialize `TopologyService`; pass `rulebase_refresh` (`RulebaseRefreshPort`) to enable lazy `show-packages` catalog warming.

###### `def gateway_cli(self) -> GatewayCliPort | GatewayCliCallable | None`

```python
@property
```
Configured `GatewayCliPort` or async callable for executing CLI commands on gateways.

###### `def script_service(self) -> ScriptRepositoryService`

```python
@property
```
Associated `ScriptRepositoryService` used for repository-mode route collection.

###### `def set_gateway_cli(self, gateway_cli: GatewayCliPort | GatewayCliCallable | None) -> None`

Set or replace the runtime `GatewayCliPort` or async callable.

###### `async def check_route_collection_script(self, mgmt_name: str, domain: str | None = None, *, script_name: str | None = None) -> RepositoryScriptStatus`

```python
@traced
```
Check read-only whether the canonical route-collection repository script exists and matches.

###### `async def ensure_route_collection_script(self, mgmt_name: str, domain: str | None = None, *, script_name: str | None = None, comments: str | None = None) -> EnsureRepositoryScriptResult`

```python
@traced
```
Idempotently provision or update the canonical route-collection script in `domain`.

###### `async def stream_refresh_topology(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing gateway topology across domains (or targeted `gateways`).

###### `async def refresh_topology(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RefreshOutcome`

```python
@traced
```
Refresh gateway topology across domains (or targeted `gateways`) and return `RefreshOutcome`.

###### `async def get_gateway_topology(self, mgmt_name: str | None = None, domain: str | None = None, *, gateway: str | None = None, topology_zone: TopologyZone | None = None, source_types: Sequence[TopologySourceType | str] | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[GatewayTopologyEntry]`

```python
@traced
```
Ensure topology is synchronized (unless `cache_mode="cache"`) and return cached `GatewayTopologyEntry` rows.

###### `def summarize_gateway_interfaces(entries: Sequence[GatewayTopologyEntry]) -> list[GatewayInterfaceSummary]`

```python
@staticmethod
```
Aggregate flat `GatewayTopologyEntry` rows into per-interface `GatewayInterfaceSummary` models.

###### `async def get_topology_diagnostics(self, mgmt_name: str | None = None, domain: str | None = None, *, gateways: Sequence[str] | str | None = None, gateway: str | None = None, min_severity: TopologyDiagnosticSeverity = 'info', cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[TopologyDiagnostic]`

```python
@traced
```
Inspect gateway and interface definitions and return `TopologyDiagnostic` items.

###### `async def collect_gateway_routes(self, mgmt_name: str | None = None, domain: str | None = None, *, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, include_global: bool = True, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, timeout: float = 30.0, concurrency: int | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RouteCollectionOutcome`

```python
@traced
```
Collect live IPv4 routing tables (`ip -4 route show` and `clish -c "show route"`) from gateways via SSH DI or `cprid` `run-script`.

###### `async def get_topology_annotations(self, mgmt_name: str | None = None, domain: str | None = None, *, gateway: str | None = None, interface_name: str | None = None) -> list[TopologyAnnotation]`

```python
@traced
```
Return persistent `TopologyAnnotation` records from `arodonata_topology_annotations`.

###### `async def upsert_topology_annotations(self, annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any]) -> list[TopologyAnnotation]`

```python
@traced
```
Insert or update persistent `TopologyAnnotation` records and return the normalized models.

###### `async def delete_topology_annotations(self, annotation_ids: Sequence[str] | str | None = None, *, mgmt_name: str | None = None, domain: str | None = None, gateway_uid: str | None = None) -> int`

```python
@traced
```
Delete persistent `TopologyAnnotation` records by ID or filter.

###### `async def reconcile_gateway_topology(self, mgmt_name: str | None = None, domain: str | None = None, *, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, collect_live_routes: bool = False, check_policy: bool = False, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> TopologyReconciliationReport`

```python
@traced
```
Compare SmartConsole static topology against live gateway routing tables (and optionally gateway-targeted policy rules) and return `TopologyReconciliationReport`.

###### `async def export_topology_prefixes(self, mgmt_name: str | None = None, domain: str | None = None, *, gateways: Sequence[str] | str | None = None, gateway: str | None = None, include_external: bool = False, include_ignored: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[ExportedTopologyPrefix]`

```python
@traced
```
Export deduplicated gateway/interface prefixes with confidence scores and IPAM annotations.

###### `async def find_affected_gateways(self, sources: Sequence[str] | str, destinations: Sequence[str] | str, *, mgmt_name: str | None = None, domain: str | None = None, source_types: Sequence[TopologySourceType | str] | None = None, include_annotations: bool = True, min_confidence: float = 0.0, include_standby: bool = True, include_policy_inferred: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[AffectedGatewayCandidate]`

```python
@traced
```
Locate all policy-enforcing gateways where `sources` and `destinations` resolve to distinct interfaces (`src_interface != dst_interface`), or via explicit installed policy rules when `include_policy_inferred=True`.

### `arodonata/core/services/topology_service.py`

Backward-compatible re-export shim for `arodonata.core.services.topology`.

_No public classes or functions in this module._

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

##### `def traced(*, name: str | None = None, attrs: dict[str, Any] | None = None, module: str | None = None) -> Callable[[Callable[P, R]], Callable[P, R]]`

```python
@overload
```
_No docstring._

##### `def traced(func: Callable[P, R] | None = None, *, name: str | None = None, attrs: dict[str, Any] | None = None, module: str | None = None) -> Any`

Wrap a function in `@arlogi.otel.traced` while scrubbing chained `__cause__`/`__context__` exceptions.


---

## adapters — Check Point Transport (`AMgmtClient`), SQL Storage & SSE

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

### `arodonata/adapters/checkpoint/connection_pool.py`

Verified keep-alive connection pool for Check Point Management Web API sockets.

#### Module-Level Functions

##### `def canonicalize_pool_host(host: str) -> str`

Normalize IPv4/IPv6 literals (unbracketed compressed RFC-5952) and lowercase DNS hostnames.

##### `def is_readonly_poolable_command(command: str) -> bool`

Return `True` if `command` is a read-only `show-*` command eligible for connection reuse.

##### `def derive_session_pool_scope(sid: str) -> str`

Derive a non-reversible pool scope tag from `sid` so raw SIDs never appear in memory keys or repr().

##### `def is_poolable_command(command: str, *, session_scope: str | None = None) -> bool`

Return `True` if `command` is eligible for keep-alive connection reuse in `VerifiedConnectionPool`.

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
pool_scope: str = ''
```
##### Methods

###### `def is_usable(self, now: float, max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS) -> bool`

Return `True` if the connection is still open and within the idle and request limits.

###### `def close(self) -> None`

Close the underlying protocol/transport.

#### class `VerifiedConnectionPool`

Pools fingerprint-verified keep-alive connections per `(server_ip, port, scope)` for up to 10s idle.

Reuses connections for read-only `show-*` commands under shared scope (`""`) and for
non-boundary commands under dedicated `session_scope` tags; session-boundary commands
and un-scoped mutations bypass pooling and close idle sockets before connecting.

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

###### `def acquire_for_command(self, host: str, port: int, command: str, *, session_scope: str | None = None) -> PooledSocketEntry | None`

Acquire a pooled verified connection for `(host, port, scope)` if eligible.

Always evicts expired connections first. For non-pooled commands, closes idle sockets
before returning `None` so a fresh TLS-verified connection is established cleanly.

###### `def release_after_command(self, entry: PooledSocketEntry, command: str, *, should_close: bool = False, session_scope: str | None = None) -> bool`

Return a healthy verified connection to the pool if eligible, else close it.

###### `def close_scope(self, host: str, port: int, session_scope: str = '') -> int`

Close all pooled connections for `(host, port, session_scope)`.

###### `def close_session_scope(self, session_scope: str) -> int`

Close all pooled connections associated with `session_scope` across all hosts.

###### `def close_host(self, host: str, port: int) -> int`

Close all pooled connections across all scopes for `(host, port)`.

###### `def close_all(self) -> int`

Close all pooled connections across all hosts and scopes.

###### `def pooled_count(self, host: str | None = None, port: int | None = None, *, session_scope: str | None = None) -> int`

Return the number of currently pooled idle connections.

### `arodonata/adapters/checkpoint/connector.py`

Custom `aiohttp.TCPConnector` enforcing pre-request TLS fingerprint pinning and pool scoping.

#### Module-Level Functions

##### `def extract_peer_der_cert(transport: asyncio.BaseTransport | None) -> bytes | None`

Extract binary DER peer certificate from an `asyncio` SSL transport.

##### `def verify_transport_peer_certificate(transport: asyncio.BaseTransport | None, *, host: str, port: int, trust_policy: TrustPolicy, identity_host: str | None = None) -> str`

Verify the peer certificate on `transport` immediately after TLS handshake.

If verification fails, closes `transport` immediately before any HTTP bytes are written
and propagates `ServerIdentityError`.

#### class `FingerprintTCPConnector(aiohttp.TCPConnector)`

Custom `aiohttp.TCPConnector` that verifies peer SHA-256 certificate fingerprints
immediately after the TLS handshake and delegates keep-alive reuse to `VerifiedConnectionPool`.

##### Methods

###### `def __init__(self, *, trust_policy: TrustPolicy, connection_pool: VerifiedConnectionPool, ssl_context: ssl.SSLContext | None = None, **kwargs: Any) -> None`

_No docstring._

###### `async def connect(self, req: ClientRequest, traces: list[Trace], timeout: aiohttp.ClientTimeout) -> Connection`

_No docstring._

### `arodonata/adapters/checkpoint/pager.py`

Continuity-verified Check Point object listing pagination (`pager.py`).

Pages object listings in chunks (default 300, max 500), acquiring and releasing
a `RateLimiter` slot per page, recovering displaced objects across page boundaries
via a single `±10` window re-read on duplicate UID, and restarting once on
`total` or `from`/`to` discontinuity before failing with `code="paging_inconsistent"`.

#### Module-Level Functions

##### `async def paginate_objects(command: str, page_caller: PageCaller, *, details_level: str = 'standard', payload: dict[str, Any] | None = None, limit: int = DEFAULT_PAGE_LIMIT, collection_key: str | None = None, max_pages: int = DEFAULT_MAX_QUERY_PAGES, max_objects: int = DEFAULT_MAX_QUERY_OBJECTS) -> ApiQueryResult`

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
and cross-process workers coordinate over `arodonata_distributed_locks`.

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

###### `def record_cooldown(self, mds_ip: str, cooldown_seconds: float, *, principal: str | None = None) -> None`

Record a shared throttle or backoff cooldown window for `mds_ip` (`W4`).

###### `async def acquire(self, mds_ip: str, *, wait_timeout: float = 900.0) -> AsyncIterator[str]`

```python
@asynccontextmanager
```
Serialize login execution for `mds_ip` across in-process coroutines and distributed workers.

### `arodonata/adapters/checkpoint/response_classifiers.py`

Check Point Web API response classifiers and domain-entry parser.

#### Module-Level Functions

##### `def is_session_expired_result(result: ApiCallResult, *, command: str | None = None) -> bool`

Return `True` if `result` indicates an invalid or expired Check Point session (`sid`).

On Check Point MDSM, after `revert-to-revision` wipes sessions created after the target
revision, calling `show-session` with no `uid` parameter on a wiped session returns
`generic_err_object_not_found` (`Requested object [<session-uid>] not found`).

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

### `arodonata/adapters/checkpoint/session_cleaner.py`

Stale and abandoned Check Point Web API session cleaner (`SessionCleaner`).

#### class `SessionCleaner`

Cleans up stale or abandoned Check Point API sessions on startup and max-sessions refusal.

Invariants:
- Opens a temporary read-write cleanup session, discards only Arodonata-owned sessions
  with `changes == 0` and `locks == 0`, and ALWAYS logs out that temporary read-write
  session via `logout_sid` without ever seeding a read-write SID into `arodonata_sid_cache`.
- When `ArodonataClient` / `AMgmtClient` enters in `"dynamic"` auth mode before any
  administrator credentials have been supplied, startup session cleanup is skipped
  without raising an authentication error.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, login_coordinator: LoginCoordinator, transport: ApiTransport, cache: SidCachePort, rate_limiter: RateLimiter) -> None`

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

###### `async def cleanup_server_sessions(self, mgmt_name: str, *, domain: str | None = None, auth: AuthContext | None = None) -> bool`

```python
@traced
```
Inspect open Web API sessions on `mgmt_name` and discard stale/abandoned sessions.

###### `async def drain_startup_tasks(self, timeout: float = 5.0) -> None`

Wait up to `timeout` seconds for any background startup cleanup tasks to finish.

### `arodonata/adapters/checkpoint/session_credentials.py`

Credential resolution, SID freshness checks, and Check Point login payload builder.

#### Module-Level Functions

##### `def build_login_payload(*, session_timeout: int, auth: AuthContext, dom_key: str, session_name: str | None = None, session_description: str | None = None, read_only: bool = False) -> dict[str, Any]`

Construct the JSON payload for a Check Point Web API `login` call.

##### `async def resolve_auth_credentials(*, mgmt_name: str, domain: str | None, settings: ArodonataSettings, endpoint: ServerEndpointConfig, auth_provider: AuthProvider | None, evicted_identities: set[tuple[str, str]], explicit_auth: AuthContext | None = None) -> AuthContext`

Resolve authentication credentials from explicit override, `contextvars`, `AuthProvider`, or static settings.

##### `def is_sid_entry_fresh(entry: SIDCacheEntry, *, now: datetime, session_expire_seconds: float) -> bool`

Return `True` if `entry` is within its extended `expires_at` window (or `session_expire_seconds` fallback).

##### `def is_sid_entry_usable(entry: SIDCacheEntry, auth: AuthContext, *, now: datetime, session_expire_seconds: float) -> bool`

Return `True` if `entry` is fresh and belongs to the exact same `auth.identity_key` (`C4`).

##### `async def handle_invalid_credentials(*, mgmt_name: str, dom_key: str, auth: AuthContext, res: ApiCallResult, cache: SidCachePort, settings: ArodonataSettings, auth_provider: AuthProvider | None, evicted_identities: set[tuple[str, str]]) -> None`

Evict cached SID and credentials, notify `AuthProvider`, and raise `InvalidCredentialsError`.

### `arodonata/adapters/checkpoint/sessions.py`

Session lifecycle, hybrid/dynamic authentication, failover resolution, and stale session cleanup.

Implements `LoginCoordinator` and re-exports `SessionCleaner`, domain parser,
response classifiers, and shared `logger`:
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
- Cleans up stale sessions via `SessionCleaner`.

#### class `LoginCoordinator`

Coordinates read-only `sid_cache` reuse, dedicated write sessions, per-MDS-member
login gating, throttle recovery (`70s`), dynamic credential resolution, and active
domain failover IP re-resolution.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, transport: ApiTransport, cache: _LoginCachePort, login_gate: LoginGate, rate_limiter: RateLimiter, auth_provider: AuthProvider | None = None, session_cleaner: SessionCleaner | None = None, monotonic_fn: Callable[[], float] = time.monotonic, now_fn: Callable[[], datetime] = utc_now, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None`

_No docstring._

###### `def active_dedicated_sids(self) -> dict[tuple[str, str], str]`

```python
@property
```
Mapping of `(mgmt_name, sid) -> server_ip` for open dedicated write sessions.

###### `def bind_session_cleaner(self, cleaner: SessionCleaner) -> None`

Attach `SessionCleaner` for max-sessions recovery.

###### `def get_tls_identity_host(self, mgmt_name: str, sid: str) -> str | None`

Return remembered hostname-pin identity for `(mgmt_name, sid)` if any.

###### `def get_server_endpoint(self, mgmt_name: str) -> ServerEndpointConfig`

Resolve `ServerEndpointConfig` for `mgmt_name` from `ArodonataSettings`.

###### `async def resolve_target_ips(self, mgmt_name: str, domain: str | None = None, *, explicit_server_ip: str | None = None) -> tuple[str, str, int]`

Resolve `(server_ip, active_mds_ip, port)` for `(mgmt_name, domain)`.

###### `async def resolve_credentials(self, mgmt_name: str, domain: str | None = None, *, explicit_auth: AuthContext | None = None) -> AuthContext`

Resolve authentication credentials from explicit override, `contextvars`, `AuthProvider`, or static settings.

###### `def has_static_credentials(self, mgmt_name: str | None = None) -> bool`

Return `True` if static startup credentials exist for `mgmt_name` (or all configured servers).

###### `def now(self) -> datetime`

Return the current UTC timestamp using the coordinator's injected clock.

###### `def has_dynamic_auth_provider(self) -> bool`

Return `True` if a fallback `AuthProvider` callback is configured.

###### `def is_sid_entry_fresh(self, entry: SIDCacheEntry) -> bool`

Return `True` if `entry` is still fresh.

When `expires_at` is present it takes precedence (`now < expires_at`); otherwise the sliding window applies,
i.e. the age since `last_used_at` (falling back to `created_at`) is below `session_expire_seconds`.

###### `async def get_readonly_session(self, mgmt_name: str, domain: str | None = None, *, server_ip: str | None = None, force_new: bool = False) -> tuple[str, str]`

```python
@traced
```
Return `(sid, server_ip)` for a shared read-only session, reusing `arodonata_sid_cache` when fresh.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None, server_ip: str | None = None, allow_max_sessions_cleanup: bool = True) -> tuple[str, str, str | None]`

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

### `arodonata/adapters/checkpoint/target_resolver.py`

Shared session logger, target host/IP resolution, and MDS domain topology lookup helpers.

#### Module-Level Functions

##### `def resolve_tls_identity_host(raw_host: str | None, pinned_ip: str) -> str | None`

Return `raw_host` when it is a non-IP hostname that resolved to a different `pinned_ip`.

##### `def resolve_active_mds_ip_for_target(target_ip: str, default_mds_ip: str, cached_domains: Sequence[DomainInfo]) -> str`

Resolve the active MDS member IP hosting `target_ip` from `cached_domains`.

##### `async def collect_trusted_hosts(*, cache: TargetResolverCachePort, known_mds_ips: set[str], active_dedicated_sids: Mapping[tuple[str, str], str], mgmt_name: str, endpoint_host: str) -> tuple[set[str], list[DomainInfo]]`

Collect canonicalized trusted host/IP strings and cached `DomainInfo` rows for `mgmt_name`.

##### `async def fetch_domain_topology_from_mds(*, mgmt_name: str, domain_name: str, endpoint: ServerEndpointConfig, transport: ApiTransport, cache: TargetResolverCachePort, rate_limiter: RateLimiter, settings: ArodonataSettings, known_mds_ips: set[str], get_readonly_session_fn: Callable[..., Awaitable[tuple[str, str]]], resolve_identity_fn: Callable[[], Awaitable[str | None]]) -> DomainInfo | None`

Query the MDS system domain (`show-domains` / `show-global-domain` / `show-mdss`) to update `active_ip`.

##### `async def validate_explicit_server_ip(*, mgmt_name: str, domain: str | None, explicit_server_ip: str, endpoint: ServerEndpointConfig, collect_hosts_fn: Callable[[str, str], Awaitable[tuple[set[str], list[DomainInfo]]]], refresh_domain_fn: Callable[[str, str], Awaitable[DomainInfo | None]]) -> tuple[str, str, int]`

Validate `explicit_server_ip` against trusted endpoints and return `(pinned_ip, mds_ip, port)`.

Explicit hostnames are resolved and pinned to a trusted IP literal; hostnames that cannot be resolved fail
closed with `ValidationError` before any connection is attempted.

##### `async def resolve_failover_domain_ip(*, mgmt_name: str, dom_key: str, target_ip: str, require_change: bool, reason: str, refresh_domain_fn: Callable[[str, str], Awaitable[DomainInfo | None]]) -> tuple[str, str] | None`

Re-query MDS for the domain's active IP and return `(active_ip, active_mds_ip)` if usable.

#### class `TargetResolverCachePort(DomainCachePort, SidCachePort, Protocol)`

Combined domain + SID cache port required by target/topology resolution.

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

###### `async def wait_for_tasks(self, task_ids: list[str] | str, poll_fn: PollCallable, *, timeout: float | None = None, initial_result: ApiCallResult | None = None, known_sids: Sequence[str] | None = None) -> ApiCallResult`

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

##### `def format_host_port(host: str, port: int = 443) -> str`

Format `(host, port)` into canonical `host:port` or `[ipv6]:port` key.

##### `def parse_tls_fingerprints(raw: str | dict[str, str] | None, *, default_port: int = 443) -> dict[str, str]`

Parse `ARODONATA_TLS_FINGERPRINTS` into a mapping of `host:port -> normalized_fingerprint` and
collect standalone fingerprints under `*{index}` if no host is specified.

Supports:
- JSON object: `'{"10.0.0.1:443": "AA:BB...", "10.0.0.2": "CC:DD..."}'`
- Key-value CSV: `'10.0.0.1:443=AA:BB...,10.0.0.2=CC:DD...'`
- Bare fingerprint CSV: `'AA:BB...,CC:DD...'` (stored under `*:<idx>` as global trusted fingerprints)

##### `def create_verified_ssl_context(trust_policy: TrustPolicy) -> PolicyBoundSSLContext`

Create a TLS 1.2+ `PolicyBoundSSLContext` explicitly bound to a validated `TrustPolicy`.

Raises:
    ConfigurationError: If `trust_policy` is not a valid `TrustPolicy` instance.

#### class `PolicyBoundSSLContext(ssl.SSLContext)`

TLS 1.2+ `ssl.SSLContext` bound explicitly to an immutable `TrustPolicy` reference and mode.

##### Fields / Class Variables

```python
_trust_policy_mode: TlsTrustMode
_trust_policy_ref: weakref.ReferenceType[TrustPolicy]
```
##### Methods

###### `def trust_policy_mode(self) -> TlsTrustMode`

```python
@property
```
TLS trust mode (`'pinned'`, `'tofu'`, or `'lab-memory'`) bound to this SSL context.

###### `def trust_policy(self) -> TrustPolicy | None`

```python
@property
```
Referenced `TrustPolicy` instance if still alive.

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

###### `def __init__(self, path: str | Path = DEFAULT_TLS_KNOWN_HOSTS_PATH, *, in_memory: bool = False, trust_mode: TlsTrustMode | None = None) -> None`

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

###### `def create_ssl_context(self) -> PolicyBoundSSLContext`

Create a TLS 1.2+ client `PolicyBoundSSLContext` bound to this validated `TrustPolicy`.

Security Invariant:
    Hostname checking and CA store verification are intentionally delegated to
    post-handshake, pre-request SHA-256 DER fingerprint verification (`verify_der`)
    because Check Point Internal CA (ICA) certificates frequently lack IP SANs and
    loading system CA stores synchronously would block the event loop. Calling
    `FingerprintTCPConnector` ensures `verify_der()` completes before any HTTP request
    line, credentials, or `X-chkp-sid` headers are sent on the wire.

###### `def verify_der(self, host: str, port: int, der_cert: bytes | None, *, identity_host: str | None = None) -> str`

```python
@traced
```
Verify raw DER certificate bytes presented by `(host, port)` before sending any HTTP request.

###### `def verify_fingerprint(self, host: str, port: int, presented_fingerprint: str, *, identity_host: str | None = None) -> str`

```python
@traced
```
Verify a normalized or hex SHA-256 fingerprint for `(host, port)` according to `self.mode`.

### `arodonata/adapters/checkpoint/transport.py`

Native `aiohttp` Check Point Web API transport and backward-compatible transport exports.

Enforces pre-request SHA-256 certificate fingerprint verification immediately after
the TLS handshake, separate socket connect/read timeouts, strict prohibition of
silent request re-transmission after socket write, and 10-second idle keep-alive
pooling restricted to read-only `show-*` and session-scoped commands.

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
- Reuses verified keep-alive connections via `VerifiedConnectionPool` (up to 10s idle
  and `< 95` requests) for read-only `show-*` commands and scoped dedicated-session
  commands while closing idle sockets before non-pooled boundary/mutating commands.

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

###### `async def execute(self, host: str, command: str, payload: dict[str, Any] | None = None, *, port: int = 443, sid: str | None = None, timeout: float | None = None, session_scope: str | None = None, tls_identity_host: str | None = None) -> ApiCallResult`

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

### `arodonata/adapters/storage/cache/__init__.py`

SQL cache adapter package (`SqlCacheAdapter`) implementing `CachePort` over SQLite and PostgreSQL.

#### class `SqlCacheAdapter(ControlCacheMixin, InventoryCacheMixin, TopologyCacheMixin, RulebaseCacheMixin)`

SQLAlchemy/SQLModel cache adapter implementing `CachePort`.

### `arodonata/adapters/storage/cache/_base.py`

Shared session execution and batched SQLite/PostgreSQL dialect helpers for `SqlCacheAdapter`.

#### class `SqlCacheBase`

Shared base class holding `DatabaseManager` and batched SQL Core helpers.

##### Methods

###### `def __init__(self, db: DatabaseManager) -> None`

_No docstring._

###### `def db(self) -> DatabaseManager`

```python
@property
```
Return the underlying `DatabaseManager`.

### `arodonata/adapters/storage/cache/control.py`

Domain metadata, SID cache, and sync-state operations for `SqlCacheAdapter`.

#### class `ControlCacheMixin(SqlCacheBase)`

Implements `DomainCachePort`, `SidCachePort`, and `SyncStatePort` over SQL storage.

##### Methods

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

### `arodonata/adapters/storage/cache/inventory.py`

Objects, services, and gateway/VSX asset CRUD operations for `SqlCacheAdapter`.

#### class `InventoryCacheMixin(SqlCacheBase)`

Implements `ObjectCachePort`, `ServiceCachePort`, and `AssetCachePort` over SQL storage.

##### Methods

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

###### `async def apply_object_diff(self, mgmt_name: str, domain_name: str, *, deleted_uids: Sequence[str] = (), objects: Sequence[CPObject] = (), sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically delete `deleted_uids`, upsert `objects`, and update `sync_states` in one transaction.

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

###### `async def apply_service_diff(self, mgmt_name: str, domain_name: str, *, deleted_uids: Sequence[str] = (), services: Sequence[CPService] = (), sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically delete `deleted_uids`, upsert `services`, and update `sync_states` in one transaction.

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

### `arodonata/adapters/storage/cache/mappers.py`

Record <-> domain model and row-dict converters for control, inventory, and topology tables.

_No public classes or functions in this module._

### `arodonata/adapters/storage/cache/rulebase.py`

Rulebase snapshot, package catalog, and layer replacement/hydration for `SqlCacheAdapter`.

#### class `RulebaseCacheMixin(SqlCacheBase)`

Implements `RulebaseCachePort` over SQL storage.

##### Methods

###### `async def replace_domain_rulebase(self, snapshot: DomainRulebaseSnapshot, *, sync_state: DomainSyncState | None = None) -> None`

```python
@traced
```
Atomically replace all `arodonata_rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`.

###### `async def replace_domain_package_catalog(self, mgmt_name: str, domain_name: str, package_layers: Sequence[RulebasePackageLayerEntry], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically replace `arodonata_rulebase_package_layer` rows for `(mgmt_name, domain_name)` without touching layer, section, or rule tables.

###### `async def upsert_domain_rulebase_layers(self, mgmt_name: str, domain_name: str, *, layers: Sequence[RulebaseLayerEntry] = (), sections: Sequence[RulebaseSectionEntry] = (), access_rules: Sequence[AccessRuleEntry] = (), nat_rules: Sequence[NatRuleEntry] = (), https_rules: Sequence[HttpsRuleEntry] = (), threat_rules: Sequence[ThreatRuleEntry] = (), package_layers: Sequence[RulebasePackageLayerEntry] = (), replaced_layer_uids: Sequence[str] = (), replaced_nat_package_uids: Sequence[str] = (), sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically replace rulebase layers, sections, and rules strictly for `replaced_layer_uids` (and NAT packages) in `(mgmt_name, domain_name)`.

###### `async def get_domain_rulebase_packages(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot`

```python
@traced
```
Load only `package_layers` and distinct NAT package stubs for `(mgmt_name, domain_name)` without loading rule tables.

###### `async def get_domain_rulebase(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot`

```python
@traced
```
Load the cached `DomainRulebaseSnapshot` for `(mgmt_name, domain_name)`.

### `arodonata/adapters/storage/cache/rulebase_mappers.py`

Rulebase record <-> domain model and row-dict converters for `SqlCacheAdapter`.

_No public classes or functions in this module._

### `arodonata/adapters/storage/cache/topology.py`

Gateway interface topology and administrator annotation operations for `SqlCacheAdapter`.

#### class `TopologyCacheMixin(SqlCacheBase)`

Implements `TopologyCachePort` over SQL storage.

##### Methods

###### `async def get_gateway_topology(self, mgmt_name: str | None = None, domain_name: str | None = None, *, gateway_uids: Sequence[str] | None = None, gateway_names: Sequence[str] | None = None, topology_zone: str | None = None, source_types: Sequence[str] | None = None) -> list[GatewayTopologyEntry]`

```python
@traced
```
Query cached gateway interface topology intervals from `arodonata_gateway_topology`.

###### `async def replace_domain_topology(self, mgmt_name: str, domain_name: str, entries: Sequence[GatewayTopologyEntry], *, gateway_uids: Sequence[str] | None = None, source_types: Sequence[str] | None = None, active_gateway_uids: Sequence[str] | None = None, sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Atomically replace cached gateway topology entries for `(mgmt_name, domain_name)` (optionally scoped by `gateway_uids` and `source_types`).

###### `async def upsert_gateway_topology(self, entries: Sequence[GatewayTopologyEntry], *, sync_states: Sequence[DomainSyncState] | None = None) -> int`

```python
@traced
```
Insert or update `GatewayTopologyEntry` rows in `arodonata_gateway_topology`.

###### `async def get_topology_annotations(self, mgmt_name: str | None = None, domain_name: str | None = None, *, gateway_uids: Sequence[str] | None = None, interface_name: str | None = None) -> list[TopologyAnnotation]`

```python
@traced
```
Query persistent administrator topology annotations from `arodonata_topology_annotations`.

###### `async def upsert_topology_annotations(self, annotations: Sequence[TopologyAnnotation]) -> int`

```python
@traced
```
Insert or update `TopologyAnnotation` rows in `arodonata_topology_annotations`.

###### `async def delete_topology_annotations(self, annotation_ids: Sequence[str]) -> int`

```python
@traced
```
Delete `TopologyAnnotation` rows matching `annotation_ids`.

### `arodonata/adapters/storage/cache_adapter.py`

Backward-compatible re-export shim for `arodonata.adapters.storage.cache`.

_No public classes or functions in this module._

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

###### `def is_in_memory(self) -> bool`

```python
@property
```
Return `True` when the bound `AsyncEngine` uses an ephemeral in-memory SQLite database.

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
tls_identity_host: str | None = Field(default=None)
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
management_blades: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON, nullable=True))
asset_role: str | None = Field(default=None, index=True)
platform_family: str | None = Field(default=None, index=True)
is_policy_target: bool | None = Field(default=None, index=True)
is_execution_target: bool | None = Field(default=None, index=True)
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
#### class `GatewayTopologyRecord(SQLModel)`

Cached pre-expanded IPv4 topology interval behind a gateway interface in `arodonata_gateway_topology`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
gateway_id: str = Field(default='', index=True)
gateway_asset_id: str = Field(default='', index=True)
gateway_uid: str = Field(index=True)
gateway_name: str = Field(index=True)
gateway_type: str = Field(default='simple-gateway')
interface_name: str = Field(index=True)
interface_ipv4: str | None = Field(default=None)
interface_mask_length: int | None = Field(default=None)
topology_zone: str = Field(default='internal', index=True)
leads_to_dmz: bool = Field(default=False)
anti_spoofing_mode: str = Field(default='unknown')
source_type: str = Field(default='interface_connected', index=True)
source_ref: str = Field(default='')
cidr_or_range: str = Field(default='')
ip_first_int: int = Field(sa_column=Column(BigInteger, nullable=False, index=True))
ip_last_int: int = Field(sa_column=Column(BigInteger, nullable=False, index=True))
prefix_len: int = Field(default=32)
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```
#### class `TopologyAnnotationRecord(SQLModel)`

Persistent administrator override, standby route marker, or IPAM metadata in `arodonata_topology_annotations`.

##### Fields / Class Variables

```python
id: str = Field(primary_key=True)
mgmt_name: str = Field(index=True)
domain_name: str = Field(index=True)
gateway_uid: str = Field(index=True)
gateway_name: str = Field(default='', index=True)
interface_name: str = Field(default='*', index=True)
cidr_or_range: str = Field(default='*', index=True)
trust_static_topology: bool | None = Field(default=None)
disposition: str | None = Field(default=None, index=True)
topology_zone: str | None = Field(default=None)
zone: str = Field(default='')
site: str = Field(default='')
comment: str = Field(default='')
custom_metadata: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=False), nullable=False))
```

---

## rulebase — Cached Rulebase Source, SmartConsole Numbering & Local Filtering

### `arodonata/rulebase/__init__.py`

Rulebase introspection, snapshot caching, SmartConsole numbering, and local filtering (`arodonata.rulebase`).

_No public classes or functions in this module._

### `arodonata/rulebase/collector.py`

Raw Check Point rulebase collection and shared BFS layer traversal (`arodonata.rulebase.collector`).

#### Module-Level Functions

##### `def extract_package_layer_entries(mgmt_name: str, domain_name: str, packages: Sequence[dict[str, Any]], *, now: datetime | None = None) -> list[RulebasePackageLayerEntry]`

Build `RulebasePackageLayerEntry` catalog rows from raw `show-packages` dictionaries.

##### `async def collect_package_rulebase_slice(api: ApiPort, mgmt_name: str, domain_name: str, package_info: PolicyPackageInfo, *, rulebase_type: RulebaseType = 'access', sid: str | None = None, server_ip: str | None = None, page_limit: int = MAX_RULEBASE_PAGE_LIMIT, emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None) -> tuple[DomainRulebaseSnapshot, list[str], list[str]]`

Fetch only the layers reachable for `(package_info, rulebase_type)`, skipping unrelated packages and types.

##### `async def collect_domain_rulebase_snapshot(api: ApiPort, mgmt_name: str, domain_name: str, *, sid: str | None = None, server_ip: str | None = None, page_limit: int = MAX_RULEBASE_PAGE_LIMIT, emit: Callable[[SyncProgressEvent], Awaitable[None]] | None = None) -> DomainRulebaseSnapshot`

Traverse all packages, NAT policies, ordered/standalone/inline layers, and Global placeholders for a domain.

### `arodonata/rulebase/filter.py`

Local cache-backed rulebase filtering and formatting (`rulebase/filter.py`).

Evaluates search/filter expressions locally against a numbered rulebase (`PackageRulebase`
or `NumberedLayerRulebase`) and cached `CPObject` / `CPService` dictionaries without
Check Point Management API round-trips, formatting output as `"markdown"`,
`"model_friendly"`, `"raw"`, or `"cpcrud"`.

#### Module-Level Functions

##### `def rule_matches_filter(rule: NumberedRule, tokens: Sequence[tuple[str | None, str]], *, objects: Sequence[CPObject] = (), services: Sequence[CPService] = (), _precomputed: _RulebaseFilterIndex | None = None) -> bool`

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

##### `def number_layer_rulebase(snapshot: DomainRulebaseSnapshot, layer_name_or_uid: str, *, rulebase_type: RulebaseType | None = None, prefix: str = '', package_uid: str | None = None, package_name: str | None = None, parent_rule_uid: str | None = None, fallback_domain_layer_uid: str | None = None, allowed_domain_layer_uids: set[str] | None = None, expand_placeholders: bool = False, expand_inline_layers: bool = True, snapshot_session_uid: str | None = None, snapshot_published_at: datetime | None = None, sync_status: SyncStatus = 'idle', _visited_layers: set[str] | None = None) -> NumberedLayerRulebase`

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

##### `async def fetch_paged_rulebase(api: ApiPort, mgmt_name: str, domain_name: str | None, *, rulebase_type: RulebaseType, layer_uid: str = '', layer_name: str = '', package_uid: str | None = None, package_name: str | None = None, details_level: str = 'standard', use_object_dictionary: bool = True, limit: int = MAX_RULEBASE_PAGE_LIMIT, extra_payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None, max_pages: int = MAX_RULEBASE_PAGES, max_objects: int = MAX_RULEBASE_OBJECTS) -> PagedRulebaseResult`

```python
@traced
```
Page `show-*-rulebase` in chunks of up to 100 rules, stitching split sections and preserving empty trailing sections.

##### `async def list_collection_with_fallback(api: ApiPort, mgmt_name: str, domain_name: str, command: str, *, data_keys: tuple[str, ...], sid: str | None = None, server_ip: str | None = None, strict: bool = True) -> list[dict[str, Any]]`

Query a paginated list command via `api_query`, falling back to `api_call` only if unsupported.

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

#### class `RulebaseRefreshService`

Session-aware atomic rulebase snapshot refresh service (`refresh_rulebases`, `stream_refresh_rulebases`).

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _RulebaseRefreshCachePort, coordinator: DomainSyncCoordinator, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def stream_refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing domain rulebase snapshots.

###### `async def refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Refresh domain rulebase snapshots and return `RefreshOutcome`.

###### `async def stream_refresh_policy_packages(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, _skip_full_fresh_check: bool = False) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while refreshing lightweight policy package catalogs (`item_type='packages'`).

###### `async def refresh_policy_packages(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, _skip_full_fresh_check: bool = False) -> RefreshOutcome`

```python
@traced
```
Synchronize lightweight policy package catalogs (`item_type='packages'`) without downloading rulebases.

###### `async def refresh_package_rulebase(self, mgmt_name: str, domain_name: str, package: str, *, rulebase_type: RulebaseType = 'access', mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize only the layers belonging to `(package, rulebase_type)` (`item_type='package:<type>:<uid>'`).

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

###### `def __init__(self, *, cache: _RulebaseSourceCachePort, refresh_service: RulebaseRefreshService | None = None, object_service: ObjectService | None = None, service_cache: ServiceCacheService | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

_No docstring._

###### `async def resolve_domain_for_target(self, mgmt_name: str, domain_name: str | None, target_name_or_uid: str, *, kind: Literal['package', 'layer'], rulebase_type: RulebaseType | None = None, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> str`

Resolve `domain_name` when `None` or `""`, raising `AmbiguousLayerName` if multiple domains match.

###### `async def ensure_and_load_snapshot(self, mgmt_name: str, domain_name: str, *, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> tuple[DomainRulebaseSnapshot, str | None, datetime | None, SyncStatus, float | None]`

Optionally refresh full rulebase for `(mgmt_name, domain_name)` and return snapshot + sync metadata.

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

### `arodonata/cpcrud/_executor_helpers.py`

Shared command allowlist, domain-head, and retry-folding helpers (`arodonata.cpcrud._executor_helpers`).

#### Module-Level Functions

##### `def resolve_allowlisted_command(action: PlannedAction) -> str`

Derive the canonical Web API write command for `action` from the strict `(object_type, outcome)` allowlist.

##### `async def check_current_domain_head(api: ApiPort, mgmt_name: str, domain_name: str, *, known_sids: Sequence[str] | None = None) -> tuple[bool, str | None, datetime | None, str | None]`

Read `show-last-published-session` and return `(readable, uid, published_at, error)`.

### `arodonata/cpcrud/_executor_pass.py`

Single-pass execution helpers for `Executor` (`arodonata.cpcrud._executor_pass`).

#### Module-Level Functions

##### `async def execute_single_pass(*, api: ApiPort, now_fn: Callable[[], datetime], on_domain_invalidated: Callable[[str, str | None], None] | None, staged_registry: OrderedDict[tuple[str, str, str], StagedSessionInfo], plan: Plan, check_domain_head: _HeadCheckFn | None = None, invalidate_domain: _InvalidateFn | None = None, force: bool = False, no_publish: bool = False, keep_session: bool = False, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None) -> tuple[list[CPCRUDEvent], ApplyReport]`

Execute one pass of `plan`, collecting both `CPCRUDEvent` items and the pass `ApplyReport`.

### `arodonata/cpcrud/_executor_staged.py`

Staged session verification, provenance checking, and adoption (`arodonata.cpcrud._executor_staged`).

#### Module-Level Functions

##### `async def adopt_staged_session(*, api: ApiPort, staged_registry: OrderedDict[tuple[str, str, str], StagedSessionInfo], mgmt_name: str, domain: str | None, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False) -> tuple[str | None, str | None, ApiCallResult]`

Adopt ownership of `session_uid` via direct SID reuse or verified `take-over-session`.

### `arodonata/cpcrud/_planner_diff.py`

Existing-entity diff planning and virtual overlay model mutation (`arodonata.cpcrud._planner_diff`).

_No public classes or functions in this module._

### `arodonata/cpcrud/_planner_entity_steps.py`

Per-entity planning helpers for objects, services, and groups (`arodonata.cpcrud._planner_entity_steps`).

#### Module-Level Functions

##### `async def plan_object_step(*, action_id: str, mgmt_name: str, domain_name: str, spec: Mapping[str, Any], policy: ConflictPolicy, prefixes: NamingPrefixes, reader: HybridStateReader, res_map: dict[str, str], collect_known_sids: Callable[[str], Awaitable[list[str]]]) -> PlannedAction`

Plan a `host`, `network`, `address-range`, `dns-domain`, or `application-site` operation.

##### `async def plan_service_step(*, action_id: str, mgmt_name: str, domain_name: str, spec: Mapping[str, Any], policy: ConflictPolicy, prefixes: NamingPrefixes, reader: HybridStateReader, res_map: dict[str, str], collect_known_sids: Callable[[str], Awaitable[list[str]]]) -> PlannedAction`

Plan a `service-tcp`, `service-udp`, `service-icmp`, `service-icmp6`, or `service-other` operation.

##### `async def plan_group_step(*, action_id: str, mgmt_name: str, domain_name: str, spec: Mapping[str, Any], policy: ConflictPolicy, reader: HybridStateReader, res_map: dict[str, str], collect_known_sids: Callable[[str], Awaitable[list[str]]]) -> PlannedAction`

Plan a `group` or `service-group` operation while keeping the virtual overlay coherent.

### `arodonata/cpcrud/_planner_helpers.py`

Shared constants, reference extractors, prior-state builders, and payload builders (`arodonata.cpcrud._planner_helpers`).

_No public classes or functions in this module._

### `arodonata/cpcrud/_planner_rule_steps.py`

Rulebase step planning helper (`arodonata.cpcrud._planner_rule_steps`).

#### Module-Level Functions

##### `async def plan_rule_step(*, action_id: str, mgmt_name: str, domain_name: str, spec: Mapping[str, Any], policy: ConflictPolicy, reader: HybridStateReader, res_map: dict[str, str], collect_known_sids: Callable[[str], Awaitable[list[str]]]) -> PlannedAction`

Plan an `access-rule`, `nat-rule`, `https-rule`, or `threat-rule` operation.

### `arodonata/cpcrud/_state_reader_common.py`

Shared constants, overlay helpers, and base state reader (`arodonata.cpcrud._state_reader_common`).

#### Module-Level Functions

##### `def normalize_mask_length(mask_length: int | float | str | None, subnet_mask: str | None = None, *, strict: bool = False) -> int | None`

Normalize a mask length or dotted-quad subnet mask into an integer prefix length (0..32).

When `strict=True`, explicitly supplied invalid `mask_length` or `subnet_mask` values raise
`ValidationError` instead of silently returning `None`.

### `arodonata/cpcrud/_state_reader_constants.py`

Constant tables and normalization helpers shared across CPCRUD state readers.

#### Module-Level Functions

##### `def normalize_app_site_url_key(url: str, *, is_regex: bool) -> str`

Return canonical comparison key for an `application-site` URL entry (case-folded when `is_regex=False`).

##### `def is_not_found_error(status_code: int, error_code: str | None, error_message: str | None) -> bool`

Return `True` if a Check Point API response specifically indicates 'object not found'.

#### class `StateLookupError(ArodonataError)`

Raised when a cache or live API state lookup fails during planning.

### `arodonata/cpcrud/_state_reader_objects.py`

Network object lookup mixin for `HybridStateReader` (`arodonata.cpcrud._state_reader_objects`).

_No public classes or functions in this module._

### `arodonata/cpcrud/_state_reader_services.py`

Service lookup mixin for `HybridStateReader` (`arodonata.cpcrud._state_reader_services`).

_No public classes or functions in this module._

### `arodonata/cpcrud/differ.py`

Field-level difference computation (`src/arodonata/cpcrud/differ.py`).

Computes deterministic field diffs (`dict[str, FieldChange]`) and update payloads between
desired template specifications and existing `CPObject`, `CPService`, or rule models.

#### Module-Level Functions

##### `def resolve_member_reference(ref: str, name_resolutions: Mapping[str, str] | None = None) -> str`

Substitute any auto-named or reused object/service name for `ref`.

##### `def parse_existing_member_entries(existing_members: Sequence[str], raw_data: Mapping[str, Any] | None, *, key: str = 'members') -> list[dict[str, Any]]`

Normalize existing group `members` or `groups` into ordered `{uid, name, ...}` dicts.

##### `def compute_object_diff(desired: Mapping[str, Any], existing: CPObject, *, name_resolutions: Mapping[str, str] | None = None) -> tuple[dict[str, FieldChange], dict[str, Any]]`

Compute field diffs and `set-<type>` update payload between `desired` spec and `existing` `CPObject`.

##### `def compute_service_diff(desired: Mapping[str, Any], existing: CPService, *, name_resolutions: Mapping[str, str] | None = None) -> tuple[dict[str, FieldChange], dict[str, Any]]`

Compute field diffs and `set-<service-type>` update payload between `desired` spec and `existing` `CPService`.

##### `def validate_non_blank_rule_items(field_key: str, raw_val: Any) -> None`

Reject empty or blank/whitespace-only elements that Check Point or sentinels would coerce to 'Any'.

##### `def compute_rule_diff(desired: Mapping[str, Any], existing: RuleEntryUnion, *, rulebase_type: RulebaseType, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None) -> tuple[dict[str, FieldChange], dict[str, Any]]`

Compute field diffs and `set-*-rule` update payload between `desired` spec and `existing` rule.

#### class `DiffSafetyError(ValidationError)`

Raised when an incremental diff violates Check Point safety invariants.

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

#### class `Executor`

Executes `Plan` actions in an isolated `WriteSession` per `(mgmt_name, domain_name)`.

##### Methods

###### `def __init__(self, *, api: ApiPort, on_domain_invalidated: Callable[[str, str | None], None] | None = None, now_fn: Callable[[], datetime] = utc_now, check_domain_head: _HeadCheckFn | None = None) -> None`

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

###### `async def stream_publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False, baseline_readable: bool | None = None, baseline_session_uid: str | None = None, baseline_published_at: datetime | None = None) -> AsyncIterator[CPCRUDEvent]`

Adopt `session_uid`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate domain cache.

###### `async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False, baseline_readable: bool | None = None, baseline_session_uid: str | None = None, baseline_published_at: datetime | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid`, publish it, log out, and invalidate the domain cache.

###### `def notify_sid_logged_out(self, mgmt_name: str, sid: str) -> None`

Clear `_sid` on any tracked staged session whose `sid` was explicitly logged out.

###### `async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid`, discard all uncommitted changes in the session, and log out.

### `arodonata/cpcrud/expressions.py`

Pure shorthand expression parser for declarative CPCRUD templates (`src/arodonata/cpcrud/expressions.py`).

Parses shorthand object, range, DNS domain, wildcard application-site, service, and inline
group expressions into schema-valid CPCRUD operation dictionaries formatted with `NamingPrefixes`.

#### Module-Level Functions

##### `def normalize_wildcard_domain(token: str) -> str`

Normalize `*domain` or `*.domain` into a validated bare DNS domain string.

##### `def wildcard_domain_to_cp_regex_urls(token: str) -> list[str]`

Convert `*domain` or `*.domain` into Check Point `url-list` regex patterns `[r'\/domain', r'\.domain']`.

##### `def parse_range_token(token: str, *, prefixes: NamingPrefixes | None = None) -> tuple[str, str]`

Parse full or compressed IPv4 range expressions (`10.1.1.1-9`, `Range_10.1.1.1_9`, `10.1.1.1-10.1.1.9`).

##### `def parse_app_site_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]`

Parse `*domain`, `*.domain`, or `SiteName(*d1, *.d2)` into a CPCRUD `application-site` spec.

##### `def parse_service_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]`

Parse TCP, UDP, or ICMP shorthand service expressions into CPCRUD `ServiceOperation` dicts.

##### `def expand_group_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]`

Parse `GroupName(m1, m2)` into `(member_object_specs, group_spec)` formatted with `NamingPrefixes`.

##### `def parse_group_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]`

Parse `GroupName(m1, m2)` into a schema-valid CPCRUD `group` dictionary.

##### `def parse_object_expression(expr: str, *, prefixes: NamingPrefixes | None = None) -> dict[str, Any]`

Parse a shorthand host, CIDR, range, `.domain`, wildcard app-site, or inline group expression.

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
added_items: list[str] = Field(default_factory=list)
removed_items: list[str] = Field(default_factory=list)
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
baseline_readable: bool = False
baseline_session_uid: str | None = None
baseline_published_at: datetime | None = None
owner_key: str = Field(default='', exclude=True, repr=False)
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

###### `def clear_sid(self) -> None`

Clear the active SID after logout while preserving session provenance.

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

###### `def __init__(self, *, api: ApiPort, cache: _PlannerCachePort, default_mgmt_name: str | None = None, default_naming_prefixes: NamingPrefixes | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

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

##### `def rule_spec_has_delta_mapping(spec: Mapping[str, Any]) -> bool`

Return `True` if `spec` contains an incremental `{add, remove}` mapping on any rule list cell.

##### `def extract_raw_verb(spec: Mapping[str, Any], *, is_rule: bool = False) -> str`

Extract raw CPCRUD verb from `operation`/`state` (or `action` when not a rule verdict).

##### `def normalize_operation_verb(spec: Mapping[str, Any], *, is_rule: bool = False) -> str`

Resolve canonical planner verb (`present`, `set`, or `delete`) from an operation spec.

##### `def build_effective_obj_dict(raw_data: Mapping[str, Any] | None, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Mapping[str, Any]]`

Merge `_resolved_objects` from `raw_data` with `obj_dict` into a unified lookup dictionary.

##### `def normalize_traffic_list(value: Any, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None) -> tuple[str, ...]`

Normalize a rule traffic field (`source`, `destination`, `service`) into a sorted canonical tuple of names.

##### `def deref_rule_list(items: Sequence[str] | None, raw_fallback: Any, eff_obj_dict: Mapping[str, Mapping[str, Any]], *, default_any: bool = False) -> list[str]`

Dereference UIDs/dicts in a rule list cell via `eff_obj_dict`, preserving order and deduplicating.

##### `def normalize_nat_traffic_ref(value: Any, *, is_translated: bool, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None) -> str`

Normalize a single NAT rule traffic reference (`original-*` or `translated-*`).

##### `def resolve_desired_rule_action(spec: Mapping[str, Any], rulebase_type: str = 'access') -> str`

Resolve the desired Check Point rule action, defaulting fail-closed per `rulebase_type`.

##### `def encode_track_for_rulebase(value: Any, rulebase_type: str) -> Any`

Encode `track` into Check Point's per-rulebase wire representation.

##### `def normalize_track_dict(value: Any, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]`

Normalize an `access` `track` value (str or TrackSettingsForRequest dict) for equality comparison.

##### `def desired_access_traffic_tuple(spec: Mapping[str, Any], name_resolutions: Mapping[str, str] | None = None, *, rulebase_type: str = 'access') -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]`

Compute canonical `(source, destination, service, action)` tuple for a desired access/HTTPS/threat rule.

##### `def existing_access_traffic_tuple(rule: AccessRuleEntry | HttpsRuleEntry | ThreatRuleEntry, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str]`

Compute canonical `(source, destination, service, action)` tuple for an existing access/HTTPS/threat rule.

##### `def desired_nat_traffic_tuple(spec: Mapping[str, Any], name_resolutions: Mapping[str, str] | None = None) -> tuple[str, str, str, str, str, str, str]`

Compute canonical 7-tuple for a desired NAT rule, normalizing `Original` and `Any` sentinels.

##### `def existing_nat_traffic_tuple(rule: NatRuleEntry, obj_dict: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[str, str, str, str, str, str, str]`

Compute canonical 7-tuple for an existing `NatRuleEntry`, normalizing `NAT_ORIGINAL_OBJECT_UID` and `NAT_ANY_OBJECT_UID`.

##### `def match_rule(spec: Mapping[str, Any], rules: Sequence[RuleEntryUnion], *, rulebase_type: RulebaseType, obj_dict: Mapping[str, Mapping[str, Any]] | None = None, name_resolutions: Mapping[str, str] | None = None, strict_name: bool = False) -> RuleEntryUnion | None`

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

###### `def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _PlannerCachePort, on_domain_invalidated: Callable[[str, str | None], None] | None = None, ensure_initialized: Callable[[], Any] | None = None, now_fn: Callable[[], datetime] = utc_now) -> None`

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

###### `async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False, baseline_readable: bool | None = None, baseline_session_uid: str | None = None, baseline_published_at: datetime | None = None) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid`, publish it, log out, and invalidate the domain cache.

###### `async def stream_publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False, baseline_readable: bool | None = None, baseline_session_uid: str | None = None, baseline_published_at: datetime | None = None) -> AsyncIterator[CPCRUDEvent]`

Adopt `session_uid`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate the domain cache.

###### `def notify_sid_logged_out(self, mgmt_name: str, sid: str) -> None`

Propagate `logout_sid` notification to the underlying CPCRUD executor.

###### `async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid`, discard uncommitted changes, and log out.

### `arodonata/cpcrud/state_reader.py`

Hybrid cache-first + live API fallback state reader (`src/arodonata.cpcrud.state_reader`).

Implements `HybridStateReader`:
- Isolated per-run state reader created for each `plan()` invocation.
- Reads network objects (`host`, `network`, `address-range`, `dns-domain`, `group`,
  `application-site`) from `arodonata_objects` and services (`service-tcp`, `service-udp`,
  `service-icmp`, `service-icmp6`, `service-group`, `service-other`) from
  `arodonata_services` ONLY when the domain's stored `domain_sync_state` row for that
  specific `(scope, item_type)` has `status == "ok"` and matches the planner's `DomainStamp`
  (`last_published_at` and `last_session_uid`).
- Falls back to live Management API calls (`show-*` / `api_query`) otherwise.
- Raises `StateLookupError` when any lookup fails or `api_query` returns `paging_inconsistent`
  so the planner emits `Outcome.ERROR` rather than mistaking a failed read for "not found".
- Maintains an in-run virtual state overlay so objects/services planned for creation, update,
  or deletion earlier in the same `plan()` run are visible to subsequent steps.

#### class `HybridStateReader(_ObjectLookupMixin, _ServiceLookupMixin)`

Isolated per-plan state reader combining `DomainStamp`-gated cache lookups with live API fallback.

##### Methods

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

### `arodonata/reports/_collector_changes.py`

Change-container parsing, UID substitution, and range filtering (`arodonata.reports._collector_changes`).

_No public classes or functions in this module._

### `arodonata/reports/_collector_diffs.py`

Field-diff synthesis, UID harvesting, and object summary builders (`arodonata.reports._collector_diffs`).

#### Module-Level Functions

##### `def is_bare_uid(value: Any) -> bool`

Return `True` if `value` is a bare UUID string (`8-4-4-4-12` hex).

### `arodonata/reports/_object_summary.py`

Canonical Check Point object summary field registry, parser, and unified formatter (`arodonata.reports._object_summary`).

#### Module-Level Functions

##### `def build_object_summary_fields(source: Mapping[str, Any], *, members: Sequence[str] | None = None, diff_by_name: Mapping[str, FieldDiff] | None = None, allow_underscore_keys: bool = False) -> dict[str, Any]`

Extract canonical structured summary attributes for a non-rule Check Point object.

##### `def format_plain_object_summary(fields: Mapping[str, Any]) -> str`

Format canonical `summary_fields` into plain text.

##### `def parse_object_summary_clauses(oc: ObjectChangeEntry) -> dict[str, Any]`

Extract `summary_fields` from `oc.summary_fields` or by splitting `oc.summary`.

##### `def render_object_details_with_diffs(oc: ObjectChangeEntry, *, render_scalar: Callable[[Any, FieldDiff | None], str], render_list: Callable[[list[str], FieldDiff | None], str], esc: Callable[[Any], str]) -> str`

Render an object's canonical summary fields + extra field diffs for HTML/Markdown cells.

### `arodonata/reports/_renderer_formatting.py`

Safe inline markdown, cell formatters, and object detail renderers (`arodonata.reports._renderer_formatting`).

#### Module-Level Functions

##### `def render_safe_inline_markdown_html(text: str) -> str`

Escape `text` for HTML while converting safe inline markdown (`**bold**`, `*italic*`, `` `code` ``, `[label](http/https/mailto)`).

##### `def render_safe_inline_markdown_md(text: str) -> str`

Sanitize inline markdown for Markdown output (neutralizing HTML tags and unsafe link/image schemes).

### `arodonata/reports/_renderer_html.py`

Self-contained HTML document rendering and CSS styles (`arodonata.reports._renderer_html`).

_No public classes or functions in this module._

### `arodonata/reports/_renderer_markdown.py`

Standalone Markdown document rendering (`arodonata.reports._renderer_markdown`).

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

##### `async def collect_change_report(api: ApiPort, cache: _ReportCachePort, scopes: Sequence[ReportScope | dict[str, Any]], *, options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS, now_fn: Callable[[], datetime] = utc_now, refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None) -> ChangeReport`

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
summary_fields: dict[str, Any] = Field(default_factory=dict)
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
numbering_source: Literal['owned_session', 'live_published', 'cache', 'unnumbered', 'not_applicable'] = 'cache'
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
include_system_objects: bool = False
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
   - Falls back to numbering from the domain's cached rulebase snapshot (`CachePort.get_domain_rulebase`),
     warming it first via the coordinator-backed `refresh_rulebase_fn` when provided and the cache is cold,
     or performing a read-only in-memory published rulebase snapshot read when no coordinator callback is provided.

#### Module-Level Functions

##### `async def apply_session_rule_placement(session_report: SessionChangeReport, *, api: ApiPort, cache: _PlacementCachePort, owned_session: OwnedSession | None = None, warnings: list[ReportWarning], now_fn: Callable[[], datetime] = utc_now, refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None) -> None`

```python
@traced
```
Populate SmartConsole rule numbers on `session_report.rule_changes` via `OwnedSession` or cached snapshot.

### `arodonata/reports/plan_report.py`

Offline Dry-Run `ChangeReport` synthesis from a CPCRUD `Plan` (`arodonata.reports.plan_report`).

#### Module-Level Functions

##### `def build_change_report_from_plan(plan: Plan, *, title: str | None = None, header_fields: Mapping[str, str] | None = None, include_unchanged: bool = False) -> ChangeReport`

```python
@traced
```
Synthesize an offline `ChangeReport` directly from a CPCRUD `Plan` for dry-run previews.

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

##### `def render_change_report(report: ChangeReport, *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None) -> RenderedReportBundle`

```python
@traced
```
Render `report` offline into any requested subset of `'html'`, `'json'`, and `'markdown'`.

Raises `UnsupportedFormat` if `'pdf'` or any unrecognized format is requested.

##### `async def build_change_report(api: ApiPort, cache: _ReportCachePort, scopes: Sequence[ReportScope | dict[str, Any]], *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS, now_fn: Callable[[], datetime] = utc_now, refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None) -> RenderedReportBundle`

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

#### Module-Level Functions

##### `def is_loopback_host(host: str) -> bool`

Return `True` if `host` is a local loopback address (`127.0.0.1`, `localhost`, or `::1`).

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
cpcrud: bool = Field(default=False, validation_alias=AliasChoices('cpcrud', 'ARODONATA_MCP_CPCRUD'))
allow_insecure_unauthenticated: bool = Field(default=False, validation_alias=AliasChoices('allow_insecure_unauthenticated', 'ARODONATA_MCP_ALLOW_INSECURE_UNAUTHENTICATED'))
tool_rate_limit_per_minute: int = Field(default=120, ge=0, validation_alias=AliasChoices('tool_rate_limit_per_minute', 'ARODONATA_MCP_TOOL_RATE_LIMIT_PER_MINUTE'))
live_tool_rate_limit_per_minute: int = Field(default=30, ge=0, validation_alias=AliasChoices('live_tool_rate_limit_per_minute', 'ARODONATA_MCP_LIVE_TOOL_RATE_LIMIT_PER_MINUTE'))
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

###### `def validate_security_policy(self, *, standalone: bool = False, has_token_verifier: bool = False, environ: dict[str, str] | None = None, emit_warning: bool = True) -> None`

Enforce unified fail-closed MCP security invariants across CLI, server, and ASGI factories.

1. Rejects `auth_mode="host"` or `"jwt"` in standalone CLI mode, and rejects `auth_mode="jwt"`
   without an explicit `token_verifier`.
2. Requires at least one valid static bearer token in standalone `auth_mode="static"`.
3. Rejects hostname/origin wildcards (`"*"`) whenever DNS rebinding protection is active.
4. Rejects `auth_mode="none"` paired with non-loopback `host`, disabled DNS rebinding protection,
   wildcard or non-loopback `allowed_hosts` / `allowed_origins`, or mutating capabilities
   (`allow_write_api=True`, `cpcrud=True`) unless `allow_insecure_unauthenticated=True` is
   explicitly set (in which case a prominent `WARNING` is logged when `emit_warning=True`).

###### `def validate_standalone_startup(self, core_settings: ArodonataSettings | None = None, *, environ: dict[str, str] | None = None, emit_warning: bool = True) -> TrustPolicy`

Validate standalone CLI (`arodonata-mcp`) security policy and TLS trust store configuration.

###### `def model_dump(self, **kwargs: Any) -> dict[str, Any]`

Serialize MCP settings with `tokens` masked.

###### `def model_dump_json(self, **kwargs: Any) -> str`

Serialize MCP settings to JSON with `tokens` masked.

### `arodonata/mcp/errors.py`

MCP tool error handling, domain pre-validation, `InvalidCredentialsError` mapping, and SID masking.

#### Module-Level Functions

##### `def register_active_mcp_sid(sid: str | None) -> None`

Register a session identifier created during the current MCP tool call for guaranteed redaction.

##### `async def collect_known_sids(client: ArodonataClient | None, mgmt_name: str | None = None) -> list[str]`

Collect active session tokens from the SID cache, public dedicated-SID registry, and active MCP context.

##### `def resolve_mcp_caller_id() -> str`

Resolve the active MCP caller identity (`client_id[:user_id]`) from `UserContext`, or `'anonymous'`.

##### `def consume_live_quota_if_needed(*, cost: int = 1, cap_at_limit_if_empty: bool = False) -> None`

Ensure at least `cost` `live` quota slots are consumed for the active guarded tool call.

##### `def resolve_mgmt_name(client: ArodonataClient, mgmt_name: str | None = None) -> str`

Resolve `mgmt_name`, defaulting to the single configured server or first server in `settings`.

##### `async def get_known_domain_names(client: ArodonataClient, mgmt_name: str, *, refresh_if_empty: bool = False) -> list[str]`

Return sorted known domain names for `mgmt_name` from the `domains` cache table.

##### `async def validate_domain_or_fail(client: ArodonataClient, mgmt_name: str, domain: str | None, *, allow_refresh: bool = True) -> str | None`

Pre-validate `domain` against the cached `domains` table before attempting a domain login.

If `domain` is not present in the cached `domains` table and `allow_refresh` is `True`, performs a single
domain-list refresh (`client.get_domains(..., cache_mode="force")`). With `allow_refresh=False` (caller
`cache_mode="cache"`) no live call or quota charge occurs and only cached rows are consulted. If still not
present and the server has known domains, raises an actionable `ToolFailure` listing known domains.

##### `def format_invalid_credentials_failure(*, mgmt_name: str, domain: str | None, known_domains: Iterable[str], exc: InvalidCredentialsError | None = None, known_sids: Iterable[str] | None = None) -> ToolFailure`

Build an actionable model-facing `ToolFailure` for `InvalidCredentialsError`.

##### `def json_tool_result(payload: dict[str, Any] | list[Any] | str, *, is_error: bool = False, known_sids: Iterable[str] | None = None) -> CallToolResult`

Serialize `payload` into a sanitized MCP `CallToolResult`.

##### `def mcp_tool_guard(tool_name: str, client_getter: Callable[[], ArodonataClient], *, quota_manager: MCPToolQuotaManager | None = None, is_live_tool: bool | Callable[[dict[str, Any]], bool] = False) -> Callable[[Callable[..., Awaitable[CallToolResult]]], Callable[..., Awaitable[CallToolResult]]]`

Wrap an async MCP tool function with per-client rate limiting, `ToolFailure` WARNING logging,
`InvalidCredentialsError` translation, SID masking, and `"internal error: <ExceptionClass>"` crash protection.

Never logs tool arguments or secrets.

#### class `ToolFailure(ArodonataError)`

Actionable model-facing tool error logged at WARNING without arguments or secrets.

##### Methods

###### `def __init__(self, message: str, *, mgmt_name: str | None = None, domain: str | None = None, error_code: str | None = None, details: dict[str, Any] | None = None, known_sids: Iterable[str] | None = None) -> None`

_No docstring._

### `arodonata/mcp/prompts.py`

MCP prompt templates for Check Point security policy exploration and auditing (`arodonata.mcp.prompts`).

#### Module-Level Functions

##### `def register_mcp_prompts(server: MCPServer) -> None`

Register standard Check Point operational prompt templates on `server`.

### `arodonata/mcp/quota.py`

Per-client sliding-window tool quota management for the Arodonata MCP server (`arodonata.mcp.quota`).

#### class `QuotaDecision`

```python
@dataclass(frozen=True, slots=True)
```
Outcome of evaluating a single MCP tool invocation against a client's sliding-window quota.

##### Fields / Class Variables

```python
allowed: bool
client_id: str
bucket: QuotaBucket
limit: int
remaining: int
retry_after_seconds: float
```
#### class `MCPToolQuotaManager`

Asyncio-safe per-client sliding-window rate limiter for MCP tool calls.

Tracks general tool invocations and stricter live/mutating tool invocations separately
per `client_id` (defaulting to `"anonymous"` when unauthenticated). All state updates
occur synchronously without yielding across `await` boundaries, ensuring atomic window
accounting in single-threaded asyncio event loops. Setting a limit to `0` disables
enforcement for that bucket.

##### Methods

###### `def __init__(self, *, rate_limit_per_minute: int = 120, live_rate_limit_per_minute: int = 30, window_seconds: float = 60.0, monotonic_fn: Callable[[], float] = time.monotonic, max_tracked_clients: int = 4096) -> None`

_No docstring._

###### `def from_settings(cls, mcp_settings: ArodonataMCPSettings, *, monotonic_fn: Callable[[], float] = time.monotonic) -> MCPToolQuotaManager`

```python
@classmethod
```
Construct an `MCPToolQuotaManager` configured from `ArodonataMCPSettings`.

###### `def rate_limit_per_minute(self) -> int`

```python
@property
```
Configured per-client general tool calls allowed per window (`0` = unlimited).

###### `def live_rate_limit_per_minute(self) -> int`

```python
@property
```
Configured per-client live/mutating tool calls allowed per window (`0` = unlimited).

###### `def window_seconds(self) -> float`

```python
@property
```
Sliding window length in seconds.

###### `def check_and_consume(self, client_id: str | None, *, is_live: bool = False) -> QuotaDecision`

Check per-client quotas and consume a slot if permitted.

###### `def check_and_consume_live_only(self, client_id: str | None, *, cost: int = 1) -> QuotaDecision`

Check and consume `cost` slots from the `live` quota bucket after `general` was already charged.

###### `def live_bucket_count(self, client_id: str | None) -> int`

Return the number of active (non-expired) slots in `client_id`'s `live` quota bucket.

###### `def rollback_consumed(self, client_id: str | None, *, general: int = 0, live: int = 0) -> None`

Roll back up to `general` and `live` most-recently consumed slots for `client_id`.

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

##### `def create_mcp_server(client: ArodonataClient | None = None, *, settings: ArodonataSettings | None = None, trust_policy: TrustPolicy | None = None, mcp_settings: ArodonataMCPSettings | None = None, auth_mode: MCPAuthMode | None = None, token_verifier: TokenVerifier | None = None, allowed_hosts: list[str] | None = None, allowed_origins: list[str] | None = None, allow_write_api: bool | None = None, cpcrud: bool | None = None, host: str | None = None, port: int | None = None, enable_dns_rebinding_protection: bool | None = None, allow_insecure_unauthenticated: bool | None = None, quota_manager: MCPToolQuotaManager | None = None, environ: dict[str, str] | None = None) -> MCPServer`

Create and configure an `MCPServer` instance wired to `ArodonataClient`.

Enforces `ArodonataMCPSettings.validate_security_policy()` fail-closed prior to tool registration.
When `auth_mode="host"` is specified for embedding inside an authenticating ASGI host,
Arodonata disables its internal token verifier (`token_verifier=None`) and relies on the
enclosing ASGI host middleware for request authentication.

##### `def create_asgi_app(client: ArodonataClient | None = None, *, mcp_server: MCPServer | None = None, settings: ArodonataSettings | None = None, trust_policy: TrustPolicy | None = None, mcp_settings: ArodonataMCPSettings | None = None, auth_mode: MCPAuthMode | None = None, token_verifier: TokenVerifier | None = None, allowed_hosts: list[str] | None = None, allowed_origins: list[str] | None = None, allow_write_api: bool | None = None, cpcrud: bool | None = None, path: str | None = None, host: str | None = None, port: int | None = None, enable_dns_rebinding_protection: bool | None = None, allow_insecure_unauthenticated: bool | None = None, json_response: bool | None = None, stateless_http: bool | None = None, quota_manager: MCPToolQuotaManager | None = None, environ: dict[str, str] | None = None) -> ArodonataASGIApp`

Create a Streamable-HTTP ASGI application ready for `uvicorn` or Starlette/FastAPI mounting.

Enforces:
- Unified `validate_security_policy()` parity whether `mcp_server` is constructed internally
  or injected externally (rejecting conflicting baked settings on an injected `mcp_server`
  with `ConfigurationError`).
- DNS rebinding protection (`Host` not in `allowed_hosts` -> HTTP `421`).
- Browser `Origin` header validation (`Origin` not in `allowed_origins` -> HTTP `403`).
- Static/JWT bearer token verification (`auth_mode="static"` / `"jwt"`) binding `client_id`
  in `UserContext`, or pass-through in `auth_mode="host"`. In `auth_mode="host"`, the enclosing
  ASGI middleware must bind `UserContext` on every request, and multi-tenant hosts serving
  varying identities over one endpoint should set `stateless_http=True`.

#### class `ArodonataASGIApp`

ASGI wrapper combining `MCPOriginHostGuardMiddleware`, optional `MCPBearerAuthMiddleware`,
and the underlying `Starlette` Streamable-HTTP MCP application (preserving its `router.lifespan_context`).

##### Methods

###### `def __init__(self, *, starlette_app: Any, guarded_app: ASGIApp, mcp_server: MCPServer, client: ArodonataClient, mcp_settings: ArodonataMCPSettings, token_verifier: TokenVerifier | None) -> None`

_No docstring._

### `arodonata/mcp/tools/__init__.py`

MCP tool surface registration (`arodonata.mcp.tools`).

Exposes a consolidated, cache-aligned tool surface across focused domain submodules:
- Collection listing & structured queries (`objects.py`): `list_objects`, `list_services`,
  `list_assets`, `search_objects`, `query_objects`.
- Single-entity & group lookup (`lookup.py`): `list_domains`, `show_object`, `get_group_members`.
- Rulebase inspection & numbering (`rulebase.py`): `show_rulebase`, `locate_rules`.
- Gateway topology matching (`topology.py`): `locate_gateways`.
- Administration, reports & API tools (`admin.py`): `cache_control`, `change_report`,
  `api_call`, `api_reference`.
- Opt-in declarative CPCRUD (`cpcrud.py`): `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply`,
  `cpcrud_inverse`, `cpcrud_staged_session`.

#### Module-Level Functions

##### `def register_mcp_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], mcp_settings: ArodonataMCPSettings, *, quota_manager: MCPToolQuotaManager | None = None) -> None`

Register all configured MCP tools on `server`, enforcing per-client quota if enabled.

### `arodonata/mcp/tools/_cache.py`

Cache freshness, cold-cache upgrade, sync failure inspection, and deferred live-quota helpers for MCP tools.

_No public classes or functions in this module._

### `arodonata/mcp/tools/_common.py`

Shared serialization, cache freshness, pagination, filtering, and plan-signing helpers for MCP tools.

#### Module-Level Functions

##### `async def resolve_and_validate_scope(client: ArodonataClient, mgmt_name: str | None, *, domain: str | None = None, domains: Sequence[str] | None = None, cache_mode: CacheMode = 'smart') -> tuple[str | None, str | None, list[str] | None]`

Resolve optional `mgmt_name`, normalize `domain`/`domains`, and pre-validate domains once.

### `arodonata/mcp/tools/_show_object.py`

Internal 3-tier candidate loading, matching, and live fallback helpers for MCP `show_object`.

#### Module-Level Functions

##### `def validate_show_object_type(obj_type: str | None, eff_mgmt: str, eff_domain: str | None) -> str | None`

Validate and canonicalize an optional `show_object(obj_type=...)` parameter.

##### `async def load_show_object_candidates(client: ArodonataClient, *, eff_mgmt: str, eff_domain: str | None, sync_domain: str | None, clean_obj_type: str | None, eff_mode: CacheMode, has_explicit_wildcard: bool, is_service_type: bool, is_asset_type: bool, is_layer_or_pkg_type: bool) -> list[EntityUnion]`

Load candidate entities across cached tables for Tier 1 (layers/packages), Tier 2, or Tier 3.

##### `def dedupe_exact_candidates(raw_exact_cands: Sequence[EntityUnion]) -> list[EntityUnion]`

Deduplicate exact UID matches across replicated Global objects, preferring owning domains.

##### `async def exact_match_result(client: ArodonataClient, entity: EntityUnion, *, eff_mgmt: str, target_domain: str, details_level: str, known_sids: Sequence[str] | None = None) -> CallToolResult`

_No docstring._

##### `def ambiguous_show_result(eff_mgmt: str, serialized: list[dict[str, Any]], hint: str, *, known_sids: Sequence[str] | None = None) -> CallToolResult`

_No docstring._

##### `def sliced_candidate_result(matches: Sequence[EntityUnion], *, match_type: Literal['wildcard', 'substring_candidates'], age: float | None, eff_mgmt: str, domain: str, offset: int, limit: int, single_object: dict[str, Any] | None = None, hint: str | None = None, known_sids: Sequence[str] | None = None) -> CallToolResult`

_No docstring._

##### `async def live_show_object(client: ArodonataClient, *, query_str: str, uid_or_name: str, eff_mgmt: str, eff_domain: str | None, target_domain: str, clean_obj_type: str | None, details_level: str) -> CallToolResult`

Fallback live `show-*` API call when cached tiers miss or `cache_mode='live'` is requested.

### `arodonata/mcp/tools/admin.py`

MCP administrative, cache synchronization, reporting, API reference, and raw API call tools.

#### Module-Level Functions

##### `def register_admin_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], mcp_settings: ArodonataMCPSettings, *, quota_manager: MCPToolQuotaManager | None = None) -> None`

Register `cache_control`, `change_report`, `api_call`, and `api_reference`.

### `arodonata/mcp/tools/cpcrud.py`

Opt-in declarative CPCRUD MCP tools with HMAC-signed plan verification and staged session isolation.

#### Module-Level Functions

##### `def register_cpcrud_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], mcp_settings: ArodonataMCPSettings, *, quota_manager: MCPToolQuotaManager | None = None) -> None`

Register the five HMAC-verified CPCRUD tools when `mcp_settings.cpcrud` is `True`.

### `arodonata/mcp/tools/lookup.py`

MCP lookup tools (`list_domains`, `show_object`, `get_group_members`).

#### Module-Level Functions

##### `def register_lookup_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], _mcp_settings: ArodonataMCPSettings, *, quota_manager: MCPToolQuotaManager | None = None) -> None`

Register `list_domains`, `show_object`, and `get_group_members`.

### `arodonata/mcp/tools/objects.py`

MCP tools for listing, searching, and structured querying of objects, services, and assets.

#### Module-Level Functions

##### `def register_object_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], _mcp_settings: ArodonataMCPSettings, *, quota_manager: MCPToolQuotaManager | None = None) -> None`

Register `list_objects`, `list_services`, `list_assets`, `search_objects`, and `query_objects`.

### `arodonata/mcp/tools/rulebase.py`

MCP rulebase inspection and numbering tools (`show_rulebase`, `locate_rules`).

#### Module-Level Functions

##### `def register_rulebase_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], _mcp_settings: ArodonataMCPSettings, *, quota_manager: MCPToolQuotaManager | None = None) -> None`

Register `show_rulebase` and `locate_rules`.

### `arodonata/mcp/tools/topology.py`

MCP gateway topology matching tools (`locate_gateways`).

#### Module-Level Functions

##### `def register_topology_tools(server: MCPServer, client_getter: Callable[[], ArodonataClient], _mcp_settings: ArodonataMCPSettings, *, quota_manager: MCPToolQuotaManager | None = None) -> None`

Register `locate_gateways`.


---

## api_reference

### `arodonata/api_reference/__init__.py`

Bundled Multi-Version Check Point API Reference & Payload Validation Engine (`arodonata.api_reference`).

_No public classes or functions in this module._

### `arodonata/api_reference/data/__init__.py`

Bundled Check Point API reference schema data (`cp_api_index.json.gz`).

_No public classes or functions in this module._

### `arodonata/api_reference/engine.py`

Offline Two-Step Check Point API Reference & Payload Validation Engine (`arodonata.api_reference.engine`).

#### Module-Level Functions

##### `def normalize_api_version(version: str | None, *, default: str = DEFAULT_API_VERSION) -> str`

Normalize a Check Point API version string into canonical index form (`v1.9`, `v2`, `v2.1`, `v2.2`).

##### `def get_api_reference() -> ApiReferenceEngine`

Return the singleton `ApiReferenceEngine` loaded lazily from bundled `cp_api_index.json.gz`.

##### `def search_api_commands(query: str = '', *, category: str | None = None, crud_type: str | None = None, api_family: str | None = None, version: str | None = DEFAULT_API_VERSION, limit: int = 15) -> list[dict[str, Any]]`

Step 1: Search Check Point API commands by keyword, category, `crud_type`, `api_family`, and `version`.

##### `def describe_api_command(command: str | Sequence[str], *, version: str | None = DEFAULT_API_VERSION, resolve_nested: bool = True, include_examples: bool = True) -> dict[str, Any] | None`

Step 2: Return the version-filtered command schema (or batch of schemas when passed a list of names).

##### `def validate_api_payload(command: str, payload: dict[str, Any] | None, *, version: str | None = DEFAULT_API_VERSION) -> dict[str, Any]`

Step 3: Validate a candidate request `payload` dictionary offline against a command's versioned schema.

#### class `ApiReferenceEngine`

In-memory multi-version Check Point API reference and payload validation engine.

##### Methods

###### `def __init__(self, index_data: dict[str, Any]) -> None`

_No docstring._

###### `def default(cls) -> ApiReferenceEngine`

```python
@classmethod
```
Return the lazily loaded singleton `ApiReferenceEngine` backed by bundled `cp_api_index.json.gz`.

###### `async def async_default(cls) -> ApiReferenceEngine`

```python
@classmethod
```
Return the lazily loaded singleton `ApiReferenceEngine`, decompressing off the event loop via `asyncio.to_thread` (`R9`).

###### `def from_path(cls, path: Path | str) -> ApiReferenceEngine`

```python
@classmethod
```
Load an `ApiReferenceEngine` from a custom `.json` or `.json.gz` file path.

###### `def search_commands(self, query: str = '', *, category: str | None = None, crud_type: str | None = None, api_family: str | None = None, version: str | None = DEFAULT_API_VERSION, limit: int = 15) -> list[dict[str, Any]]`

Step 1: Search commands filtered by version, category, CRUD type, and API family, ranked by relevance.

###### `def describe_command(self, command: str | Sequence[str], *, version: str | None = DEFAULT_API_VERSION, resolve_nested: bool = True, include_examples: bool = True) -> dict[str, Any] | None`

Step 2: Return the resolved command schema(s) dynamically filtered to the target API version.

When `command` is a single command name (`str`), returns the resolved command dict or `None` if not found
or unsupported in `version`.
When `command` is a sequence of command names (`list[str]` / `tuple[str, ...]`), returns a batch dictionary:
`{"target_version": ..., "commands": {...}, "not_found": [...]}`.

###### `def validate_payload(self, command: str, payload: dict[str, Any] | None, *, version: str | None = DEFAULT_API_VERSION) -> dict[str, Any]`

Step 3: Offline validation of a candidate request payload against the command's versioned schema.

### `arodonata/api_reference/models.py`

Pydantic v2 models and TypedDict definitions for the Check Point API Reference Engine.

#### class `ApiValidationIssue(BaseModel)`

Single validation error or warning reported by `validate_payload`.

##### Fields / Class Variables

```python
code: Literal['unknown_command', 'unsupported_command_version', 'unknown_field', 'unsupported_field_version', 'missing_required_field', 'missing_alternative_group', 'conflicting_alternatives', 'invalid_type', 'invalid_enum_value']
message: str
field: str | None = None
allowed_values: list[str] = Field(default_factory=list)
supported_versions: list[str] = Field(default_factory=list)
```
#### class `ApiPayloadValidationResult(BaseModel)`

Structured result returned by `validate_payload`.

##### Fields / Class Variables

```python
valid: bool
command: str
target_version: str
error_count: int = 0
errors: list[ApiValidationIssue] = Field(default_factory=list)
suggestions: list[dict[str, Any]] = Field(default_factory=list)
```

---

## client

### `arodonata/client/__init__.py`

Primary composition root and unified developer facade (`ArodonataClient`).

Wires `ApiPort` (`AMgmtClient`), `CachePort` (`SqlCacheAdapter`), and `LockPort` (`SqlLockAdapter`)
into core domain services (`DomainService`, `DomainSyncCoordinator`, `ObjectService`,
`ServiceCacheService`, `AssetRefreshService`, `SearchService`), defaulting `engine=None` to an
auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`).

#### class `ArodonataClient(ClientTopologyMixin, ClientRulebaseReportsMixin, ClientInventoryMixin, ClientLifecycleMixin)`

Unified composition root and async facade for Check Point Management & MDSM.

### `arodonata/client/_base.py`

Composition root base class, service wiring, and properties for `ArodonataClient`.

#### Module-Level Functions

##### `def build_validated_trust_policy(core_settings: ArodonataSettings, *, environ: dict[str, str] | None = None) -> TrustPolicy`

Build and validate a `TrustPolicy` from `ArodonataSettings`, loading and checking its trust store.

#### class `ClientBase`

Base composition root wiring adapters, core services, and shared facade properties.

##### Methods

###### `def __init__(self, settings: ArodonataSettings | None = None, *, engine: AsyncEngine | str | None = None, db_manager: DatabaseManager | None = None, cache: CachePort | None = None, lock_port: LockPort | None = None, api: ApiPort | None = None, transport: ApiTransport | None = None, trust_policy: TrustPolicy | None = None, connection_pool: VerifiedConnectionPool | None = None, task_waiter: TaskWaiter | None = None, rate_limiter: RateLimiter | None = None, login_gate: LoginGate | None = None, auth_provider: AuthProvider | None = None, domain_tracker: DomainListRefreshTracker | None = None, cluster_manager: ClusterRelationshipManager | None = None, vsx_manager: VSXRelationshipManager | None = None, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, monotonic_fn: Callable[[], float] = time.monotonic, now_fn: Callable[[], datetime] = utc_now, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep, **settings_kwargs: Any) -> None`

_No docstring._

###### `def write_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None, publish_on_exit: bool = True) -> AbstractAsyncContextManager[WriteSession]`

Open a context-bound isolated `WriteSession` (implemented by `ClientLifecycleMixin`).

###### `def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None`

Invalidate freshness memos for `(mgmt_name, domain)` so the next smart read re-checks published head.

###### `def get_active_dedicated_sids(self, mgmt_name: str | None = None) -> list[str]`

Return deduplicated active dedicated session SIDs tracked by the transport or injected API double.

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

###### `def topology_service(self) -> TopologyService`

```python
@property
```
Core `TopologyService`.

###### `def script_service(self) -> ScriptRepositoryService`

```python
@property
```
Core `ScriptRepositoryService`.

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

###### `def api_reference(self) -> ApiReferenceEngine`

```python
@property
```
Offline Check Point API Reference & Payload Validation Engine (`ApiReferenceEngine`).

###### `def warmup_tasks(self) -> set[asyncio.Task[Any]]`

```python
@property
```
Currently running background warm-up tasks.

### `arodonata/client/inventory.py`

Inventory read, search, query, refresh, mutation, and warmup facade methods for `ArodonataClient`.

#### class `ClientInventoryMixin(ClientLifecycleMixin)`

Provides domain, object, service, asset, search, warmup, and mutation facade methods.

##### Methods

###### `def get_warmup_status(self, mgmt_name: str | None = None) -> list[WarmupStatusEntry]`

Return structured status entries for active and recent background warm-up flights.

###### `def start_object_cache_warmup(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, include_services: bool = False, mode: CacheMode = 'smart') -> asyncio.Task[RefreshOutcome]`

Explicitly schedule single-flight deduplicated background object (and optional service) cache warm-up.

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

###### `async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[DomainInfo]`

```python
@traced
```
Return discovered domains, excluding `Global` unless `include_global=True`.

Never triggers implicit background object-cache warm-up.

###### `async def get_gateways(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[Asset]`

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

###### `async def query_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, domains: Sequence[str] | None = None, types: Sequence[str] | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, is_policy_target: bool | None = None, is_execution_target: bool | None = None, scope_origin: Literal['all', 'local', 'global'] = 'all', name_pattern: str | None = None, ip_subnet: str | None = None, port: str | None = None, protocol: str | None = None, tags: Sequence[str] | None = None, parent_id: str | None = None, parent_asset_id: str | None = None, include_global: bool = False, group_by: Sequence[str] | None = None, aggregate: Literal['count', 'list', 'describe'] = 'list', limit: int = 100, offset: int = 0, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> dict[str, Any]`

```python
@traced
```
Execute structured cross-domain filtering, grouping, and counting over cached objects, services, and assets.

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

###### `async def find_object(self, mgmt_name: str, domain: str | None = None, name_or_uid: str = '', *, obj_type: str | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | CPService | Asset | None`

```python
@traced
```
Find a single `CPObject`, `CPService`, or `Asset` by exact `uid` or `name` in `(mgmt_name, domain)` (or across all domains when `domain` is `None`), including active `WriteSession` overlay.

###### `async def get_group_members(self, mgmt_name: str, domain: str | None = None, group_name_or_uid: str = '', *, recursive: bool = True, max_depth: int = 5, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject | CPService | Asset]`

```python
@traced
```
Resolve direct (and optionally recursive) member `CPObject`, `CPService`, or child `Asset` items for a group, service-group, cluster, or VSX container in `(mgmt_name, domain)`.

### `arodonata/client/lifecycle.py`

Lifecycle, context managers, raw API transport, and staged session methods for `ArodonataClient`.

#### class `ClientLifecycleMixin(ClientBase)`

Provides lifecycle management, context binding, raw API calls, and staged session methods.

##### Methods

###### `async def initialize(self, *, run_startup_cleanup: bool = True) -> None`

Initialize the database schema and optionally schedule startup session cleanup.

###### `async def close(self, *, logout: bool | None = None) -> None`

```python
@traced
```
Cancel running background warm-up tasks immediately, drain startup cleanup, close transport, and dispose owned engine.

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

###### `async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid`, publish it, log out, and invalidate the domain cache.

###### `async def stream_publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False) -> AsyncIterator[CPCRUDEvent]`

Adopt `session_uid`, publish it while streaming `CPCRUDEvent` items, log out, and invalidate the domain cache.

###### `async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False) -> ApiCallResult`

```python
@traced
```
Adopt `session_uid`, discard uncommitted changes, and log out.

### `arodonata/client/rulebase_reports.py`

Rulebase introspection, change reports, API reference, and repository script facades for `ArodonataClient`.

#### class `ClientRulebaseReportsMixin(ClientBase)`

Provides rulebase, change-report, API-reference, and repository-script facade methods.

##### Methods

###### `async def refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize policy rulebase snapshots across target domains and return `RefreshOutcome`.

###### `async def stream_refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing policy rulebase snapshots.

###### `async def refresh_policy_packages(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize lightweight policy package catalogs (`item_type='packages'`) without downloading rulebases.

###### `async def stream_refresh_policy_packages(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing lightweight policy package catalogs.

###### `async def refresh_package_rulebase(self, mgmt_name: str, domain_name: str | None, package: str, *, rulebase_type: RulebaseType = 'access', mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize only the layers belonging to `(package, rulebase_type)` without pulling other packages or rulebase types.

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

###### `def build_change_report_from_plan(self, plan: Plan, *, title: str | None = None, header_fields: Mapping[str, str] | None = None, include_unchanged: bool = False) -> ChangeReport`

```python
@traced
```
Synthesize an offline `ChangeReport` directly from a CPCRUD `Plan` for dry-run previews.

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

###### `async def ensure_api_reference(self) -> ApiReferenceEngine`

Return `self.api_reference`, loading the bundled gzipped index via `asyncio.to_thread` when needed (`R9`).

###### `def resolve_api_version(self, version: str | None = None, mgmt_name: str | None = None) -> str`

Resolve canonical Check Point API version (`v1.9`..`v2.2`) from explicit `version` or `mgmt_name` settings.

###### `def search_api_commands(self, query: str = '', *, category: str | None = None, crud_type: str | None = None, api_family: str | None = None, version: str | None = None, mgmt_name: str | None = None, limit: int = 15) -> list[dict[str, Any]]`

Step 1: Search Check Point API commands offline, inferring `version` from `mgmt_name` when omitted.

###### `def describe_api_command(self, command: str | Sequence[str], *, version: str | None = None, mgmt_name: str | None = None, resolve_nested: bool = True, include_examples: bool = True) -> dict[str, Any] | None`

Step 2: Describe one or more Check Point API commands offline, inferring `version` from `mgmt_name`.

###### `def validate_api_payload(self, command: str, payload: dict[str, Any] | None, *, version: str | None = None, mgmt_name: str | None = None) -> dict[str, Any]`

Step 3: Validate a candidate request payload offline against the command's schema for `version` / `mgmt_name`.

###### `async def get_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, details_level: str = 'full') -> RepositoryScript`

```python
@traced
```
Fetch a single Check Point Script Repository entry by name or UID (`show-repository-script`).

###### `async def list_repository_scripts(self, mgmt_name: str, *, domain: str | None = None, details_level: str = 'full', limit: int = 300) -> list[RepositoryScript]`

```python
@traced
```
List Check Point Script Repository entries in `domain` (`show-repository-scripts`).

###### `async def check_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, expected_body: str | None = None) -> RepositoryScriptStatus`

```python
@traced
```
Inspect a repository script strictly read-only over `sid_cache` and compare against `expected_body`.

###### `async def ensure_repository_script(self, mgmt_name: str, script_name: str, script_body: str, *, domain: str | None = None, comments: str | None = None, color: str | None = None, tags: Sequence[str] | None = None) -> EnsureRepositoryScriptResult`

```python
@traced
```
Idempotently ensure `script_name` exists with `script_body`, avoiding writes when already matching.

###### `async def delete_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None) -> bool`

```python
@traced
```
Delete a Check Point Script Repository entry from `domain` (`delete-repository-script`).

###### `async def run_repository_script(self, mgmt_name: str, script_name_or_uid: str, targets: Sequence[str] | str, *, domain: str | None = None, args: Sequence[str] | str | None = None, comments: str | None = None, timeout: float | None = None, script_timeout: int | None = None) -> RepositoryScriptExecutionOutcome`

```python
@traced
```
Execute any approved Check Point Script Repository entry via `run-script` (`script-type="repository"`).

### `arodonata/client/topology.py`

Gateway topology, route collection, reconciliation, and annotation facades for `ArodonataClient`.

#### class `ClientTopologyMixin(ClientBase)`

Provides gateway topology, route collection, diagnostics, reconciliation, and annotation methods.

##### Methods

###### `def set_gateway_cli(self, gateway_cli: GatewayCliPort | GatewayCliCallable | None) -> None`

Register or replace the optional SSH/CLI callback or `GatewayCliPort` adapter.

###### `async def refresh_topology(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RefreshOutcome`

```python
@traced
```
Synchronize gateway interface topology across target domains (or specific `gateways`) and return `RefreshOutcome`.

###### `async def stream_refresh_topology(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> AsyncIterator[SyncProgressEvent]`

Stream `SyncProgressEvent` items while synchronizing gateway interface topology.

###### `async def get_gateway_topology(self, mgmt_name: str | None = None, domain: str | None = None, *, gateway: str | None = None, topology_zone: TopologyZone | None = None, source_types: Sequence[TopologySourceType | str] | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[GatewayTopologyEntry]`

```python
@traced
```
Return cached `GatewayTopologyEntry` rows for policy-enforcing gateways.

###### `async def find_affected_gateways(self, sources: Sequence[str] | str, destinations: Sequence[str] | str, *, mgmt_name: str | None = None, domain: str | None = None, min_confidence: float = 0.0, include_standby: bool = True, include_policy_inferred: bool = True, source_types: Sequence[TopologySourceType | str] | None = None, include_annotations: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[AffectedGatewayCandidate]`

```python
@traced
```
Locate policy-enforcing gateways where `sources` and `destinations` resolve to distinct interfaces or via explicit installed policy rules.

###### `async def collect_gateway_routes(self, *, mgmt_name: str | None = None, domain: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, gateways: Sequence[str] | str | None = None, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, timeout: float = 45.0, concurrency: int | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RouteCollectionOutcome`

```python
@traced
```
Collect live OS/Clish routing tables from gateways via SSH (`GatewayCliPort`) or `cprid` `run-script` fallback.

###### `async def check_route_collection_script(self, mgmt_name: str, domain: str | None = None, *, script_name: str | None = None) -> RepositoryScriptStatus`

```python
@traced
```
Check read-only whether the canonical route-collection repository script exists and matches in `domain`.

###### `async def ensure_route_collection_script(self, mgmt_name: str, domain: str | None = None, *, script_name: str | None = None, comments: str | None = None) -> EnsureRepositoryScriptResult`

```python
@traced
```
Idempotently provision or update the canonical route-collection script in `domain`.

###### `async def get_topology_diagnostics(self, mgmt_name: str | None = None, domain: str | None = None, *, gateways: Sequence[str] | str | None = None, gateway: str | None = None, min_severity: TopologyDiagnosticSeverity = 'info', cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[TopologyDiagnostic]`

```python
@traced
```
Return static topology health diagnostics (`TopologyDiagnostic`) across policy-enforcing gateways.

###### `async def reconcile_gateway_topology(self, *, mgmt_name: str | None = None, domain: str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, collect_live_routes: bool = False, check_policy: bool = False, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> TopologyReconciliationReport`

```python
@traced
```
Reconcile SmartConsole static topology against cached/collected live routes, gateway-targeted policy rules, and administrator annotations.

###### `async def get_topology_annotations(self, mgmt_name: str | None = None, domain: str | None = None, *, gateway: str | None = None, interface_name: str | None = None) -> list[TopologyAnnotation]`

```python
@traced
```
Return persistent administrator `TopologyAnnotation` records.

###### `async def upsert_topology_annotations(self, annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any]) -> list[TopologyAnnotation]`

```python
@traced
```
Persist one or more administrator `TopologyAnnotation` overrides and IPAM metadata records.

###### `async def delete_topology_annotations(self, annotation_ids: Sequence[str] | str | None = None, *, mgmt_name: str | None = None, domain: str | None = None, gateway_uid: str | None = None) -> int`

```python
@traced
```
Delete persistent administrator `TopologyAnnotation` rows matching the supplied filters.

###### `async def export_topology_prefixes(self, *, mgmt_name: str | None = None, domain: str | None = None, gateways: Sequence[str] | str | None = None, gateway: str | None = None, include_external: bool = False, include_ignored: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[ExportedTopologyPrefix]`

```python
@traced
```
Export consolidated `ExportedTopologyPrefix` records for IPAM comparison.

### `arodonata/client/warmup.py`

Single-flight background object and service cache warm-up coordinator.

#### class `CacheWarmupCoordinator`

Manages single-flight deduplicated background object/service cache warm-up tasks.

##### Methods

###### `def __init__(self, *, settings: ArodonataSettings, now_fn: Callable[[], datetime], ensure_initialized: Callable[[], Awaitable[None]]) -> None`

_No docstring._

###### `def warmup_tasks(self) -> set[asyncio.Task[Any]]`

```python
@property
```
Currently running background warm-up tasks.

###### `def get_warmup_status(self, mgmt_name: str | None = None) -> list[WarmupStatusEntry]`

Return structured status entries for active and recent background warm-up flights.

###### `def start_object_cache_warmup(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, include_services: bool = False, mode: CacheMode = 'smart', refresh_objects_fn: Callable[..., Awaitable[RefreshOutcome]], refresh_services_fn: Callable[..., Awaitable[RefreshOutcome]]) -> asyncio.Task[RefreshOutcome]`

Explicitly schedule single-flight deduplicated background object (and optional service) cache warm-up.

###### `async def cancel_all(self) -> None`

Cancel all running background warm-up tasks immediately and clear flight tracking.


---

## testing

### `arodonata/testing/__init__.py`

Enterprise raw dataset generator, file-backed replay mocks, and HTTPS mock server (`arodonata.testing`).

_No public classes or functions in this module._

### `arodonata/testing/__main__.py`

CLI entrypoint for `python -m arodonata.testing` (delegates to `arodonata.testing.mock_server`).

_No public classes or functions in this module._

### `arodonata/testing/_dataset_common.py`

Shared constants, IO helpers, specs, and build context for the enterprise raw dataset generator.

#### Module-Level Functions

##### `def write_json(path: Path, data: Any) -> None`

Serialize `data` as pretty JSON with trailing newline.

##### `def write_text(path: Path, text: str) -> None`

Write UTF-8 text content to `path`, creating parent directories.

##### `def encode_task_payload(task_id: str, node_name: str, stdout: str, *, status: str = 'succeeded') -> dict[str, Any]`

Build a Check Point `show-task` JSON payload with Base64-encoded CLI stdout.

##### `def make_cli_output(ip_routes: list[str], clish_routes: list[str] | None = None) -> str`

Render delimited `ip -4 route show` and optional `clish -c "show route"` CLI output.

##### `def make_internal_if(name: str, ip_addr: str) -> dict[str, Any]`

Build a standard anti-spoofing-enabled internal gateway interface dictionary.

#### class `ExtraGatewaySpec(NamedTuple)`

Descriptor for an extra standalone simple gateway.

##### Fields / Class Variables

```python
domain: str
name: str
host_id: int
```
#### class `ExtraClusterSpec(NamedTuple)`

Descriptor for an extra HA cluster and its two cluster members.

##### Fields / Class Variables

```python
domain: str
name: str
m1_name: str
m2_name: str
base: int
internal_only: bool = False
```
#### class `ExtraVsxHostSpec(NamedTuple)`

Descriptor for an extra physical VSX chassis host.

##### Fields / Class Variables

```python
domain: str
name: str
mgmt_ip: str
wrp_idx: int
```
#### class `ExtraVsSpec(NamedTuple)`

Descriptor for an extra local or cross-domain Virtual System.

##### Fields / Class Variables

```python
host_name: str
domain: str
name: str
vsid: int
internal_only: bool = False
```
#### class `DatasetBuildContext`

```python
@dataclass
```
Mutable per-domain accumulators shared across deterministic dataset generation stages.

##### Fields / Class Variables

```python
domains_raw: list[dict[str, Any]] = field(default_factory=list)
global_domain_raw: dict[str, Any] = field(default_factory=dict)
domain_sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
gateways_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
simple_gw_details: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
simple_cl_details: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
generic_by_class: dict[str, dict[str, list[dict[str, Any]]]] = field(default_factory=lambda: {d: {} for d in ALL_DOMAINS})
generic_by_uid: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
hosts_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
networks_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
ranges_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
groups_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
dns_domains_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
services_tcp_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
services_udp_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
services_icmp_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
service_groups_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
packages_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
access_layers_by_domain: dict[str, list[dict[str, Any]]] = field(default_factory=_domain_buckets)
access_rulebases_by_domain: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
nat_rulebases_by_domain: dict[str, dict[str, dict[str, Any]]] = field(default_factory=_domain_dicts)
cli_outputs: dict[tuple[str, int | None], str] = field(default_factory=dict)
vsx_stat_lines_by_host: dict[str, list[str]] = field(default_factory=dict)
vsx_stat_outputs: dict[str, str] = field(default_factory=dict)
chassis1_vs_uids: list[str] = field(default_factory=list)
chassis2_vs_uids: list[str] = field(default_factory=list)
```
##### Methods

###### `def init_vsx_stat(self, host_name: str) -> None`

Initialize `vsx stat -l` output buffer for VSX chassis `host_name`.

###### `def append_vsx_stat(self, host_name: str, vs_id: int, vs_name: str) -> None`

Append a Virtual System entry to `vsx stat -l` output for `host_name`.

###### `def add_gw(self, domain: str, gw: dict[str, Any], *, full_detail: dict[str, Any] | None = None) -> None`

Register a gateway or cluster object across summary, detail, and generic indexes.

###### `def add_generic(self, domain: str, class_name: str, obj: dict[str, Any]) -> None`

Register a generic Check Point object by class name and UID.

### `arodonata/testing/_dataset_domains_dc.py`

Dataset builders for `DC_Spine` and `DC_Pod` VSX domains.

#### Module-Level Functions

##### `def populate_dc_spine_domain(ctx: DatasetBuildContext) -> None`

Populate `DC_Spine` physical VSX chassis (`dc-vsx-chassis-01`, `dc-vsx-chassis-02`) and spine VSs.

##### `def populate_dc_pod_domain(ctx: DatasetBuildContext) -> None`

Populate `DC_Pod` cross-domain Virtual Systems (`dc-vs-tier1-web`, `dc-vs-tier2-app`, `dc-vs-pod-21..45`).

### `arodonata/testing/_dataset_domains_edge.py`

Dataset builders for `Branch`, `Regional`, and `WAN_Core` domains.

#### Module-Level Functions

##### `def populate_branch_domain(ctx: DatasetBuildContext) -> None`

Populate `Branch` domain objects, 140 simple gateways, and CLI outputs.

##### `def populate_regional_domain(ctx: DatasetBuildContext) -> None`

Populate `Regional` domain 7-level nested groups, HA cluster, hub gateways, and CLI outputs.

##### `def populate_wan_core_domain(ctx: DatasetBuildContext) -> None`

Populate `WAN_Core` domain ECMP legs, standby BGP gateway, core routers, and CLI outputs.

### `arodonata/testing/_dataset_domains_partner.py`

Dataset builders for `DB_Seg` and `Partner_DMZ` domains.

#### Module-Level Functions

##### `def populate_db_seg_domain(ctx: DatasetBuildContext) -> None`

Populate `DB_Seg` internal-only segmentation gateways and CLI outputs.

##### `def populate_partner_dmz_domain(ctx: DatasetBuildContext) -> None`

Populate `Partner_DMZ` one-arm gateways, drifting B2B cluster, external gateways, and CLI outputs.

### `arodonata/testing/_dataset_domains_transit.py`

Dataset builders for `Perimeter` and `Transit` domains.

#### Module-Level Functions

##### `def populate_perimeter_domain(ctx: DatasetBuildContext) -> None`

Populate `Perimeter` edge cluster (with empty summary interfaces), DMZ gateways, and CLI outputs.

##### `def populate_transit_domain(ctx: DatasetBuildContext) -> None`

Populate `Transit` domain LPM Matryoshka, anomaly audit, interconnect gateways, and CLI outputs.

### `arodonata/testing/_dataset_global.py`

MDSM domain metadata, Global domain objects, and domain service builders.

#### Module-Level Functions

##### `def populate_mdsm_domains_and_sessions(ctx: DatasetBuildContext) -> None`

Populate MDSM domains, Global domain metadata, and baseline published/current sessions.

##### `def populate_global_and_services(ctx: DatasetBuildContext) -> None`

Populate Global network/group/host objects plus TCP/UDP/ICMP/service-group/DNS fixtures across all domains.

### `arodonata/testing/_dataset_heterogeneous.py`

Heterogeneous multi-domain gateways, HA clusters, VSX hosts, and cross-domain Virtual Systems.

#### Module-Level Functions

##### `def populate_heterogeneous_mix(ctx: DatasetBuildContext) -> None`

Populate the +57 heterogeneous gateway/cluster/VSX/cross-domain VS assets and render `vsx stat -l`.

### `arodonata/testing/_dataset_policies.py`

Bulk object generation, Global domain tagging, and policy/rulebase builders.

#### Module-Level Functions

##### `def populate_bulk_objects(ctx: DatasetBuildContext, rng: random.Random) -> None`

Populate bulk hosts/networks/ranges/groups across user domains and tag Global ownership metadata.

##### `def populate_policies_and_rulebases(ctx: DatasetBuildContext) -> tuple[int, int]`

Build policy packages, access layers, access rulebases, and NAT rulebases for all domains.

### `arodonata/testing/_dataset_writer.py`

Disk writer and manifest assembly for the enterprise raw replay dataset.

#### Module-Level Functions

##### `def write_dataset_and_manifest(ctx: DatasetBuildContext, root: Path, *, seed: int, total_access_rules: int, total_nat_rules: int) -> dict[str, Any]`

Write MDS, per-domain, CLI, task, and manifest JSON files to `root` and return manifest.

### `arodonata/testing/_emulator_changes.py`

Change delta computation and `show-changes` synthesis for the stateful replay emulator.

#### Module-Level Functions

##### `def compute_session_delta(before_dom: Mapping[str, Any], after_dom: Mapping[str, Any], *, global_before: Mapping[str, Any] | None = None, global_after: Mapping[str, Any] | None = None, session_meta: Mapping[str, Any] | None = None) -> dict[str, Any]`

Compute a Check Point `show-changes` delta dict between two domain snapshots.

##### `def count_delta_items(delta: Mapping[str, Any]) -> int`

Count total object and rule change items inside a `show-changes` delta container.

##### `def parse_checkpoint_date_ms(value: Any) -> int | None`

Parse an ISO-8601 date string or posix int/dict into epoch milliseconds.

##### `def build_show_changes_task(task_id: str, change_entries: list[dict[str, Any]]) -> dict[str, Any]`

Build a Check Point `show-changes` task object matching `ChangeReportCollector`.

### `arodonata/testing/_emulator_crud.py`

Backward-compatible re-export facade for stateful emulator CRUD, lookup, and slicing helpers.

_No public classes or functions in this module._

### `arodonata/testing/_emulator_entity_crud.py`

Entity CRUD, group membership synchronization, and rename propagation for the replay emulator.

#### Module-Level Functions

##### `def handle_entity_crud(command: str, req: Mapping[str, Any], *, dom_name: str, dom_files: dict[str, Any], global_files: Mapping[str, Any], all_domains_effective: Mapping[str, Mapping[str, Any]], uid_allocator: Callable[[str], str], now_ms: int, user_name: str, locked_uids_out: set[str]) -> tuple[ApiCallResult, str | None] | None`

Execute `show-*`, `add-*`, `set-*`, `delete-*` for all 12 `ENTITY_SPECS` types.

### `arodonata/testing/_emulator_lookup.py`

Domain lookup, `show-objects` filtering, referential integrity, and unused-object helpers.

#### Module-Level Functions

##### `def as_list(val: Any) -> list[Any]`

Coerce a scalar or None value into a list while returning list inputs as-is.

##### `def ref_uid(item: Any) -> str`

Extract the `uid` or `name` identifier string from a reference value.

##### `def ensure_entity_bucket(dom_files: dict[str, Any], spec: EntitySpec) -> list[dict[str, Any]]`

Ensure a domain's plural entity bucket exists and return its mutable `objects` list.

##### `def refresh_entity_bucket_counts(dom_files: dict[str, Any], spec: EntitySpec) -> None`

Recompute `total`, `from`, and `to` metadata on an entity bucket after mutation.

##### `def is_global_owned(obj: Mapping[str, Any], owning_dom: str, caller_dom: str) -> bool`

Return True when `obj` belongs to Global and `caller_dom` is a local domain.

##### `def global_read_only_error(target_ref: str, caller_dom: str) -> ApiCallResult`

Build a Check Point read-only ownership error for Global objects accessed locally.

##### `def find_in_scope(scope_files: Mapping[str, Any], lookup: str, *, preferred_spec: EntitySpec | None = None, include_extras: bool = True) -> tuple[dict[str, Any], EntitySpec | None] | None`

Locate a mutable object dict by `uid` or `name` inside a single domain map.

##### `def find_effective_object(dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, lookup: str, *, preferred_spec: EntitySpec | None = None, local_only: bool = False, allow_sentinels: bool = False, include_extras: bool = True) -> tuple[dict[str, Any], str, EntitySpec | None] | None`

Resolve an object by `uid` or `name` in `dom_name` (and `Global` when inherited).

##### `def filter_show_objects(dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, req: Mapping[str, Any], type_to_cmd: Mapping[str, str], match_fn: Callable[[dict[str, Any]], bool]) -> list[dict[str, Any]]`

Gather matching `show-objects` candidates honoring local-first Global shadowing and domain filters.

##### `def collect_blocking_references(target_uid: str, *, dom_name: str, dom_files: Mapping[str, Any], all_domains_effective: Mapping[str, Mapping[str, Any]]) -> list[str]`

Return human-readable descriptions of groups, rules, and gateways directly referencing `target_uid`.

##### `def collect_referenced_uids(*, dom_name: str, dom_files: Mapping[str, Any], all_domains_effective: Mapping[str, Mapping[str, Any]]) -> set[str]`

Collect all UIDs referenced by groups, rulebases, or gateways across applicable scopes in one pass.

##### `def find_unused_objects(dom_files: Mapping[str, Any], *, dom_name: str, all_domains_effective: Mapping[str, Mapping[str, Any]], req: Mapping[str, Any] | None = None) -> list[dict[str, Any]]`

Return all local `ENTITY_SPECS` objects with zero incoming group, rule, or gateway references.

##### `def delete_unused_objects(dom_files: dict[str, Any], *, dom_name: str, all_domains_effective: Mapping[str, Mapping[str, Any]], locked_uids_out: set[str], req: Mapping[str, Any] | None = None) -> int`

Iteratively delete unreferenced local objects matching optional filters and return the number removed.

##### `def preview_delete_unused_uids(dom_files: Mapping[str, Any], *, dom_name: str, all_domains_effective: Mapping[str, Mapping[str, Any]], req: Mapping[str, Any] | None = None) -> set[str]`

Return the set of UIDs that `delete-unused-objects` would remove for preflight lock checking.

### `arodonata/testing/_emulator_models.py`

Shared models, constants, and error builders for the stateful Check Point replay emulator.

#### Module-Level Functions

##### `def is_mutating_command(command: str) -> bool`

Return True when `command` mutates management database or session state.

##### `def format_timestamp(posix_ms: int) -> dict[str, Any]`

Build a Check Point API `{posix, iso-8601}` timestamp object.

##### `def format_domain_meta(domain_name: str, existing: Mapping[str, Any] | None = None) -> dict[str, Any]`

Build deterministic domain metadata dict matching dataset fixtures.

##### `def sanitize_call_payload(payload: Mapping[str, Any] | None, *, known_sids: Iterable[str] | None = None) -> dict[str, Any]`

Deep-sanitize an API request payload so secrets and SIDs never enter call logs.

##### `def summarize_payload(command: str, payload: Mapping[str, Any] | None, *, known_sids: Iterable[str] | None = None) -> str`

Produce a concise, SID-safe summary string for a request payload.

##### `def cp_ok(data: dict[str, Any] | None = None, *, status_code: int = 200, task_id: str | None = None) -> ApiCallResult`

Create a successful `ApiCallResult`.

##### `def cp_error(code: str, message: str, *, status_code: int = 400, blocking_errors: list[dict[str, Any]] | None = None, errors: list[dict[str, Any]] | None = None, warnings: list[dict[str, Any]] | None = None) -> ApiCallResult`

Create a failed `ApiCallResult` formatted compatibly with `ApiTransport`.

#### class `EntitySpec`

```python
@dataclass(frozen=True)
```
Declarative specification for a CRUD-managed Check Point entity type.

##### Fields / Class Variables

```python
obj_type: str
plural_show: str
is_service: bool = False
is_group: bool = False
ip_fields: tuple[str, ...] = ()
text_fields: tuple[str, ...] = ('name', 'comments')
default_fields: tuple[tuple[str, Any], ...] = ()
```
##### Methods

###### `def singular_show(self) -> str`

```python
@property
```
_No docstring._

###### `def add_cmd(self) -> str`

```python
@property
```
_No docstring._

###### `def set_cmd(self) -> str`

```python
@property
```
_No docstring._

###### `def delete_cmd(self) -> str`

```python
@property
```
_No docstring._

#### class `MutationRecord`

```python
@dataclass
```
Recorded staged mutation for publish-time rebase replay.

##### Fields / Class Variables

```python
command: str
domain: str
payload: dict[str, Any]
assigned_uid: str | None = None
```
#### class `PublishedDelta`

```python
@dataclass
```
Immutable change delta emitted when a work session is published.

##### Fields / Class Variables

```python
session_uid: str
session_name: str
domain: str
user_name: str
publish_time_posix: int
publish_time_iso: str
changes: dict[str, Any]
```
#### class `WorkSession`

```python
@dataclass
```
In-memory Check Point work session with optional isolated staging overlay.

##### Fields / Class Variables

```python
uid: str
domain: str
user_name: str
name: str
description: str
application: str
read_only: bool
state: str
base_published_uid: str
created_time_posix: int
last_modify_posix: int
base_domain_gen: int = 0
domain_meta: dict[str, Any] = field(default_factory=dict)
base_snapshot: dict[str, dict[str, Any]] | None = None
overlay_data: dict[str, dict[str, Any]] | None = None
locked_uids: set[str] = field(default_factory=set)
mutation_records: list[MutationRecord] = field(default_factory=list)
published_time_posix: int | None = None
published_changes: int = 0
changes_count: int = 0
comments: str = ''
color: str = ''
tags: list[Any] = field(default_factory=list)
```
##### Methods

###### `def to_checkpoint_dict(self) -> dict[str, Any]`

Serialize session metadata in Check Point `show-session` JSON shape.

#### class `SidBinding`

```python
@dataclass
```
Mapping between a secret session token (`sid`) and its attached `WorkSession`.

##### Fields / Class Variables

```python
sid: str
sid_ref: str
mgmt_name: str
domain: str
user_name: str
session_uid: str
read_only: bool = False
active: bool = True
```
#### class `ReplayStateSnapshot`

```python
@dataclass
```
In-memory snapshot of full emulator state for fast test isolation.

##### Fields / Class Variables

```python
domain_copies: dict[str, dict[str, Any]]
dirty_domains: set[str]
work_sessions: dict[str, WorkSession]
sid_bindings: dict[str, SidBinding]
published_session_by_domain: dict[str, str]
published_deltas: dict[str, list[PublishedDelta]]
tasks: dict[str, dict[str, Any]]
show_global_assignments: list[dict[str, Any]]
counters: dict[str, int]
cli_overrides: dict[tuple[str, int], str]
fail_ssh_nodes: set[str]
call_log: list[dict[str, Any]]
domain_generations: dict[str, int] = field(default_factory=dict)
allow_one_time_script: bool = True
allow_repository_script: bool = True
manage_repository_scripts: str = 'write'
encode_repository_script_body_base64: bool = False
```
### `arodonata/testing/_emulator_projection.py`

Shared projection, pagination, object-dictionary, and rulebase-slicing helpers for the replay emulator.

#### Module-Level Functions

##### `def is_section_node(node: Mapping[str, Any]) -> bool`

Return True if a rulebase node represents a rule section container.

##### `def extract_ref_uids(value: Any) -> set[str]`

Extract referenced UIDs from a string, mapping, or nested list of references.

##### `def iter_flat_rule_entries(nodes: Any) -> list[tuple[dict[str, Any] | None, dict[str, Any]]]`

Flatten top-level and section-nested rules into `(section_meta, rule_dict)` pairs.

##### `def project_replay_details_level(obj: Mapping[str, Any], details_level: str) -> dict[str, Any]`

Apply strict Check Point `details-level` (`uid`, `standard`, `full`) projection for replay reads.

##### `def project_details_level(obj: Mapping[str, Any], details_level: str) -> dict[str, Any]`

Apply Check Point `details-level` (`uid`, `standard`, `full`) projection to a CRUD object.

##### `def paginate_items(items: list[dict[str, Any]], req: Mapping[str, Any], *, collection_key: str = 'objects', details_level: str | None = None, default_limit: int = 100, default_details_level: str | None = None, min_limit: int = 1, projector: Callable[[Mapping[str, Any], str], dict[str, Any]] = project_details_level) -> dict[str, Any]`

Paginate a list using Check Point `limit` / `offset` conventions.

##### `def make_object_summary(obj: Mapping[str, Any], *, default_domain: str | None = None) -> dict[str, Any]`

Build a compact Check Point summary reference dict `{uid, name, type, domain}`.

##### `def build_objects_dictionary(dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, nodes: Any, existing_dict: Iterable[Mapping[str, Any]] = ()) -> list[dict[str, Any]]`

Reconstruct `objects-dictionary` from all live UIDs referenced in `nodes`.

##### `def inline_rule_objects(rule: dict[str, Any], obj_map: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]`

Replace UID references in a copied rule with full objects from `objects-dictionary`.

##### `def slice_rulebase_with_sections(layer_payload: Mapping[str, Any], *, dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, offset: int, limit: int, use_object_dictionary: bool = True) -> dict[str, Any]`

Slice an access/NAT rulebase by rule `offset`/`limit`, preserving live objects and empty sections.

##### `def build_scope_ref_to_uids(scope_files: Mapping[str, Any], global_files: Mapping[str, Any] | None = None) -> dict[str, str]`

Map object UIDs and names to canonical UIDs (local objects shadow `Global` names).

##### `def extract_resolved_ref_uids(value: Any, ref_to_uid: Mapping[str, str]) -> set[str]`

Extract UID/name tokens from `value` and map names to canonical UIDs when known.

##### `def iter_gateway_topology_refs(scope_files: Mapping[str, Any], ref_to_uid: Mapping[str, str]) -> Iterator[tuple[str, str | None, set[str]]]`

Yield `(gw_label, iface_name_or_none, resolved_uids)` across gateway VPN domains and interfaces.

### `arodonata/testing/_emulator_rulebase_crud.py`

Access, NAT, HTTPS, and Threat rulebase CRUD handlers for the stateful replay emulator.

#### Module-Level Functions

##### `def handle_rulebase_crud(command: str, req: Mapping[str, Any], *, dom_name: str, dom_files: dict[str, Any], global_files: Mapping[str, Any], uid_allocator: Callable[[str], str], now_ms: int, user_name: str, locked_uids_out: set[str]) -> tuple[ApiCallResult, str | None] | None`

Execute Access, NAT, HTTPS, & Threat rule and section CRUD commands against live domain state.

### `arodonata/testing/_emulator_rulebase_fields.py`

Rule cell reference resolution, normalization, and response formatting for rulebase CRUD.

#### Module-Level Functions

##### `def resolve_rule_cell_ref(ref: Any, *, dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, existing_dict_map: Mapping[str, Mapping[str, Any]]) -> tuple[str | None, str | None]`

Resolve a rule object reference (`uid`, `name`, or dict) to a UID or `(None, error_ref)`.

##### `def apply_cell_list_update(current_uids: list[str], spec_val: Any, *, dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, existing_dict_map: Mapping[str, Mapping[str, Any]], revert_empty_to_any: bool = True, allow_literal_strings: bool = False) -> tuple[list[str], ApiCallResult | None]`

Apply full list replacement or `{add, remove}` patch to a rule cell UID list.

##### `def normalize_action(val: Any, *, rule_kind: str = 'access') -> str | ApiCallResult`

Normalize a rule `action` UID or display name for the given rulebase kind.

##### `def normalize_track(val: Any, *, rule_kind: str = 'access') -> dict[str, Any] | str | ApiCallResult`

Normalize a rule `track` field into per-rulebase wire format (`dict` for access, `str` for https/threat).

##### `def normalize_inline_layer(val: Any, *, rule_kind: str, dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, existing_dict_map: Mapping[str, Mapping[str, Any]]) -> tuple[str | None, ApiCallResult | None]`

Resolve an `inline-layer` UID or layer name within domain/Global layer stores.

##### `def format_rule_response(rule: Mapping[str, Any], *, layer_payload: Mapping[str, Any], dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, rule_kind: str = 'access') -> dict[str, Any]`

Return a single Check Point rule response with resolved object summary dicts.

##### `def normalize_nat_scalar_field(val: Any, *, is_translated: bool, dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, existing_dict_map: Mapping[str, Mapping[str, Any]]) -> tuple[str | None, ApiCallResult | None]`

Resolve a scalar NAT cell reference (`Original`, `Any`, object UID, or object name).

##### `def detect_rule_kind(command: str) -> str | None`

Return the rulebase kind (`access`, `nat`, `https`, `threat`) for a rule/section command.

### `arodonata/testing/_emulator_rulebase_tree.py`

Rulebase container resolution, tree lookup, rule/section insertion, and renumbering helpers.

#### Module-Level Functions

##### `def resolve_rulebase_container(dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, req: Mapping[str, Any], *, rule_kind: str = 'access') -> tuple[dict[str, Any], str] | None`

Resolve the mutable layer/NAT package rulebase container and its owning domain.

##### `def parse_rule_number(raw: Any) -> tuple[int | None, bool]`

Parse a Check Point `rule-number` value safely, returning `(parsed_int, is_valid)`.

##### `def locate_rule_in_tree(nodes: list[Any], req: Mapping[str, Any]) -> tuple[list[Any], int, dict[str, Any], dict[str, Any] | None] | None`

Return `(parent_list, index_in_parent, rule_dict, enclosing_section_or_None)`.

##### `def locate_section_in_tree(nodes: list[Any], req: Mapping[str, Any]) -> tuple[int, dict[str, Any]] | None`

Locate a section dict inside top-level rulebase `nodes` by `uid` or `name`.

##### `def insert_rule_into_tree(nodes: list[Any], rule: dict[str, Any], pos_spec: Any) -> ApiCallResult | None`

Insert `rule` into `nodes` according to Check Point `position` / `new-position` semantics.

##### `def insert_section_into_tree(nodes: list[Any], sec: dict[str, Any], pos_spec: Any) -> ApiCallResult | None`

Insert `sec` into top-level rulebase `nodes` according to `position` / `new-position`.

##### `def renumber_layer(layer_payload: dict[str, Any], dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str) -> None`

Recompute sequential 1-based `rule-number`s, section `from`/`to` bounds, `total`, and `objects-dictionary`.

### `arodonata/testing/_replay_cli.py`

File-backed `GatewayCliPort` replay adapter for gateway SSH and VSX route collection.

#### class `FileReplayCliMock(GatewayCliPort)`

File-backed `GatewayCliPort` replay adapter for gateway SSH route collection.

##### Methods

###### `def __init__(self, dataset_dir: Path | str = DEFAULT_DATASET_DIR, *, fail_ssh_nodes: set[str] | None = None) -> None`

_No docstring._

###### `def reset_counters(self) -> None`

Clear all CLI execution counters and logs.

###### `def set_cli_stdout(self, node_name: str, vsid: int, stdout: str) -> None`

Override the raw CLI stdout returned for `(node_name, vsid)` in memory.

###### `def get_raw_cli_stdout(self, node_name: str, vsid: int | None = 0) -> str | None`

Return the raw CLI stdout for `(node_name, vsid)` from memory override or disk fixture.

###### `def resolve_vsid_from_stat(self, node_name: str, vs_name: str) -> int | None`

Emulate `vsx stat -l` awk resolution of `vs_name` -> `vsid` on `node_name` (`VS0`).

###### `def list_virtual_systems(self, node_name: str) -> list[tuple[int, str]]`

Return list of `(vsid, vs_name)` for all non-switch Virtual Systems on `node_name`.

###### `async def execute_command(self, target: GatewayCliTarget, command: str, *, timeout: float = 30.0) -> GatewayCliResult`

Validate the incoming route-collection bash script and return raw CLI output from `cli/`.

### `arodonata/testing/_replay_dispatch.py`

Top-level command routing and domain mutation dispatcher for `FileReplayApiMock`.

#### Module-Level Functions

##### `def apply_domain_mutation(mock: FileReplayApiMock, clean_cmd: str, req: Mapping[str, Any], *, dom_name: str, target_files: dict[str, Any], global_files: Mapping[str, Any], all_domains: Mapping[str, Mapping[str, Any]], user_name: str, locked_uids_out: set[str], override_now_ms: int | None = None) -> tuple[ApiCallResult, str | None] | None`

Apply an entity, rulebase, repository-script, or unused-object command against `target_files`.

##### `def dispatch_api_call(mock: FileReplayApiMock, mgmt_name: str, clean_cmd: str, req: dict[str, Any], *, dom_name: str, sid: str | None, binding: SidBinding | None, wait_for_task: bool) -> ApiCallResult`

Dispatch a single normalized Check Point Management API call on `FileReplayApiMock`.

### `arodonata/testing/_replay_global_and_policy.py`

Lock preflight, MDSM global assignments, and policy verify/install handlers.

#### Module-Level Functions

##### `def candidate_preflight_layers(store: Any, *, dom_files: Mapping[str, Any], pkg_or_lyr: str, rule_kind: str, allow_multi: bool) -> list[Mapping[str, Any]]`

Return rulebase layers/packages targeted by a rule or section preflight lock scan.

##### `def preflight_target_uids(command: str, req: Mapping[str, Any], dom_files: Mapping[str, Any], global_files: Mapping[str, Any], dom_name: str, *, all_domains_effective: Mapping[str, Mapping[str, Any]] | None = None) -> set[str]`

Identify object, script, rule, or section UIDs affected by a write command for lock checking.

##### `def check_cross_session_locks(mock: FileReplayApiMock, ws: WorkSession, candidate_uids: set[str]) -> ApiCallResult | None`

Reject mutations targeting UIDs locked by another open or disconnected session.

##### `def handle_global_assignments_cmd(mock: FileReplayApiMock, clean_cmd: str, req: Mapping[str, Any], *, binding: SidBinding | None, wait_for_task: bool) -> ApiCallResult`

Handle `show-global-assignments`, `show-global-assignment`, and `assign-global-*` commands.

##### `def handle_verify_or_install_policy(mock: FileReplayApiMock, clean_cmd: str, req: Mapping[str, Any], *, dom_name: str, dom_files: Mapping[str, Any], global_files: Mapping[str, Any], wait_for_task: bool) -> ApiCallResult`

Handle `verify-policy` and `install-policy` async task synthesis.

### `arodonata/testing/_replay_queries.py`

Query, layer/NAT resolution, `show-objects` filter, and `where-used` builders for `FileReplayApiMock`.

#### Module-Level Functions

##### `def matches_show_objects_filter(item: dict[str, Any], *, filter_needle: str, ip_only: bool) -> bool`

Evaluate Check Point `show-objects` substring filtering (`filter` and `ip-only`).

##### `def empty_where_used_bucket() -> dict[str, Any]`

Return an empty Check Point `where-used` usage bucket.

##### `def find_domain_object_by_ref(dom_files: dict[str, Any], lookup: str) -> dict[str, Any] | None`

Resolve an object by `uid` or `name` across a domain's fixture payloads.

##### `def resolve_layer_payload(dom_files: dict[str, Any], global_files: dict[str, Any], lookup: str, *, store_key: str = 'show-access-rulebase', layer_store_key: str = 'show-access-layers', layer_list_key: str = 'access-layers') -> dict[str, Any] | None`

Resolve an access/https/threat rulebase layer payload by key, layer UID, or layer name.

##### `def resolve_access_layer_payload(dom_files: dict[str, Any], global_files: dict[str, Any], lookup: str) -> dict[str, Any] | None`

Resolve an access rulebase layer payload by store key, layer UID, or layer name.

##### `def resolve_nat_package_payload(dom_files: dict[str, Any], pkg_lookup: str) -> dict[str, Any] | None`

Resolve a NAT rulebase payload by package name, package UID, or rulebase UID.

##### `def collect_group_parents(dom_files: dict[str, Any], global_files: dict[str, Any], dom_name: str) -> dict[str, list[tuple[dict[str, Any], str]]]`

Build `member_uid -> [(group_dict, owning_domain)]` across groups in domain and Global.

##### `def build_where_used_response(dom_files: dict[str, Any], global_files: dict[str, Any], dom_name: str, target_uid: str, *, indirect: bool, max_depth: int) -> dict[str, Any]`

Compute Check Point `where-used` payload for `target_uid` from domain fixtures.

### `arodonata/testing/_replay_reads.py`

Read-only `show-*` and `where-used` command handlers for `FileReplayApiMock`.

#### Module-Level Functions

##### `def handle_show_checkpoint_host(mock: FileReplayApiMock, mgmt_name: str, dom_name: str, req: Mapping[str, Any], *, binding: SidBinding | None) -> ApiCallResult`

Resolve `show-checkpoint-host` across effective domain, system scopes, and MDS records.

##### `def handle_domain_read_command(mock: FileReplayApiMock, clean_cmd: str, req: dict[str, Any], *, dom_name: str, dom_files: dict[str, Any], global_files: dict[str, Any], binding: SidBinding | None) -> ApiCallResult | None`

Handle domain-scoped read queries (`show-*` and `where-used`).

### `arodonata/testing/_replay_repo_scripts.py`

Repository script CRUD and listing handlers for `FileReplayApiMock`.

#### Module-Level Functions

##### `def project_repository_script(item: Mapping[str, Any], details_level: str) -> dict[str, Any]`

Project a repository script object according to Check Point `details-level`.

##### `def extract_repo_script_body(req: Mapping[str, Any], *, fallback: str | None = None) -> str | None`

Extract `script-body` or Base64-decoded `script-body-base64` from a request payload.

##### `def handle_repository_script_mutation(mock: FileReplayApiMock, clean_cmd: str, req: Mapping[str, Any], *, dom_name: str, target_files: dict[str, Any], now_ms: int, user_name: str, locked_uids_out: set[str]) -> tuple[ApiCallResult, str | None] | None`

Execute `add-repository-script`, `set-repository-script`, or `delete-repository-script`.

##### `def handle_show_repository_scripts(mock: FileReplayApiMock, clean_cmd: str, req: Mapping[str, Any], *, dom_files: Mapping[str, Any]) -> ApiCallResult`

Handle `show-repository-script` and `show-repository-scripts` with optional R82 Base64 parity.

### `arodonata/testing/_replay_run_script.py`

Stateful `run-script` handler for one-time, repository, and zero-arg VSX bundle execution.

#### Module-Level Functions

##### `def handle_run_script(mock: FileReplayApiMock, dom_name: str, payload: dict[str, Any], *, binding: SidBinding | None = None, active_ws: WorkSession | None = None, wait_for_task: bool) -> ApiCallResult`

Emulate Check Point `run-script` for one-time inline scripts and repository scripts.

### `arodonata/testing/_replay_sessions.py`

Session lifecycle, publish/rebase, discard, takeover, and `show-changes` handlers.

#### Module-Level Functions

##### `def handle_login(mock: FileReplayApiMock, mgmt_name: str, req: Mapping[str, Any], *, dom_name: str) -> ApiCallResult`

Create or resume a stateful mock session and bind a fresh `sid`.

##### `def handle_logout(req: Mapping[str, Any], *, binding: SidBinding | None, active_ws: WorkSession | None) -> ApiCallResult`

Deactivate `binding` and either disconnect dirty sessions or discard clean ones.

##### `def handle_disconnect(mock: FileReplayApiMock, req: Mapping[str, Any], *, binding: SidBinding | None, active_ws: WorkSession | None) -> ApiCallResult`

Handle `disconnect` and `continue-session-in-smartconsole` commands.

##### `def handle_set_session(mock: FileReplayApiMock, req: Mapping[str, Any], *, active_ws: WorkSession | None) -> ApiCallResult`

Update metadata on the active open `WorkSession`.

##### `def handle_take_over_session(mock: FileReplayApiMock, req: Mapping[str, Any], *, binding: SidBinding | None, active_ws: WorkSession | None) -> ApiCallResult`

Transfer an open or disconnected session onto the caller's SID binding.

##### `def handle_switch_session(mock: FileReplayApiMock, req: Mapping[str, Any], *, binding: SidBinding | None, active_ws: WorkSession | None) -> ApiCallResult`

Switch the caller's SID binding to another open or disconnected session.

##### `def handle_discard(mock: FileReplayApiMock, req: Mapping[str, Any], *, binding: SidBinding | None, active_ws: WorkSession | None) -> ApiCallResult`

Discard uncommitted changes for the target or active session and rotate if active.

##### `def resolve_session_by_uid(mock: FileReplayApiMock, uid: str, dom_name: str) -> dict[str, Any] | None`

Resolve a session dictionary from active work sessions or domain published history.

##### `def handle_show_changes(mock: FileReplayApiMock, dom_name: str, req: Mapping[str, Any], *, binding: SidBinding | None, wait_for_task: bool) -> ApiCallResult`

Compute and return a `show-changes` task for staged or published revisions.

##### `def rotate_sid_bindings_for_session(mock: FileReplayApiMock, ws: WorkSession) -> None`

Rebind active SIDs attached to `ws.uid` onto fresh open sessions (`OwnedSession` invariant).

##### `def record_publish_task(mock: FileReplayApiMock, session_uid: str | None, n_changes: int, *, wait_for_task: bool) -> ApiCallResult`

Create and store a Check Point publish completion task payload.

##### `def handle_publish(mock: FileReplayApiMock, req: Mapping[str, Any], *, binding: SidBinding | None, wait_for_task: bool) -> ApiCallResult`

Commit or rebase a session's overlay into published domain state and record delta history.

### `arodonata/testing/_replay_state.py`

Snapshot/restore, call-log assertions, and in-memory test mutation helpers for `FileReplayApiMock`.

#### Module-Level Functions

##### `def load_domain_files(mock: FileReplayApiMock, dom_name: str) -> dict[str, Any]`

Load all per-command JSON fixture files for `dom_name` from disk.

##### `def initialize_dataset_state(mock: FileReplayApiMock) -> None`

Load MDS/domain JSON fixtures and index node UIDs and published session pointers.

##### `def capture_snapshot(mock: FileReplayApiMock) -> ReplayStateSnapshot`

Capture an in-memory snapshot of modified domains, sessions, locks, tasks, and CLI overrides.

##### `def apply_snapshot(mock: FileReplayApiMock, snapshot: ReplayStateSnapshot) -> None`

Restore emulator state rapidly from a previously captured `ReplayStateSnapshot`.

##### `def reset_mock_state(mock: FileReplayApiMock) -> None`

Reset all in-memory domain data, sessions, locks, tasks, counters, and CLI overrides to baseline.

##### `def filter_calls(mock: FileReplayApiMock, *, domain: str | None = None, command: str | None = None, mutating_only: bool = False) -> list[dict[str, Any]]`

Return recorded `call_log` entries matching optional `domain`, `command`, and `mutating_only` filters.

##### `def assert_no_global_mutations(mock: FileReplayApiMock) -> None`

Fail if any mutating API command targeted the `Global` domain.

##### `def assert_no_full_object_scans(mock: FileReplayApiMock, commands: Iterable[str] = ('show-hosts', 'show-networks', 'show-address-ranges', 'show-groups')) -> None`

Fail if any command in `commands` was invoked (e.g., to guard against uncached full-table scans).

##### `def assert_command_called(mock: FileReplayApiMock, command: str, *, domain: str | None = None, times: int | None = None) -> None`

Assert that `command` was called (optionally within `domain` and exact `times` count).

##### `def assert_command_not_called(mock: FileReplayApiMock, command: str, *, domain: str | None = None) -> None`

Assert that `command` was never called (optionally restricted to `domain`).

##### `def update_gateway_interfaces(mock: FileReplayApiMock, domain: str, gateway_name_or_uid: str, interfaces: list[dict[str, Any]]) -> None`

Update the raw `interfaces` list for a single gateway across summary and detail payloads in memory.

##### `def bump_published_session(mock: FileReplayApiMock, domain: str, *, new_session_uid: str, new_iso_time: str = '2026-11-09T12:00:00Z', new_posix_time: int = 1794225600000) -> None`

Simulate a new `publish` in `domain` by updating `show-last-published-session` and `show-sessions`.

### `arodonata/testing/dataset_generator.py`

Deterministic enterprise raw dataset generator for Check Point MDSM API & CLI replay testing.

Generates `tests/fixtures/enterprise_raw_dataset/` with fixed seed (`20261108`) containing:
- 9 user MDSM domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`,
  `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`.
- 315 policy-enforcing gateways (341 total domain assets including cluster members and physical VSX chassis),
  with heterogeneous appliance, HA cluster, Virtual System, and cross-domain VSX distribution across every domain.
- 2,951 network objects and 210 service objects across domains, including 7-level nested object groups and address ranges.
- 1,050+ access and NAT rules across domain and Global policy packages with sections and inline layers.
- Raw CLI routing outputs (`ip -4 route show`, `clish -c "show route"`, `vsx stat -l`) covering
  `kernel`/`C`, `static`/`S`, `bgp`/`B`, `ospf`/`O`, `routed`/`R`, `I` IS-IS, ECMP, and cluster member drift.
- Base64-encoded `run-script` / `show-task` JSON payloads for `cprid` fallback verification.

#### Module-Level Functions

##### `def generate_enterprise_raw_dataset(output_dir: Path | str | None = None, *, seed: int = DEFAULT_SEED) -> dict[str, Any]`

Generate the complete raw Check Point MDSM API and CLI dataset on disk and return its manifest.

##### `def ensure_enterprise_raw_dataset(output_dir: Path | str | None = None, *, seed: int = DEFAULT_SEED, force: bool = False) -> Path`

Ensure `tests/fixtures/enterprise_raw_dataset/` exists and matches `DATASET_VERSION` and `seed`.

### `arodonata/testing/mock_server.py`

Standalone and embeddable Check Point Management HTTPS mock server (`mock_server.py`).

Allows downstream applications (MMP, FPCR, or custom scripts) to point `ArodonataClient` at
`localhost:443` (or any custom `host:port`) and interact with the full 10-domain, 315-gateway,
2,950+-object, 1,050+-rule enterprise dataset over real HTTPS without hardware appliances,
artificial rate limits, or login throttling delays.

CLI usage:
    python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443

#### Module-Level Functions

##### `def build_arg_parser() -> argparse.ArgumentParser`

Build the CLI argument parser for `python -m arodonata.testing.mock_server`.

##### `def main(argv: list[str] | None = None) -> int`

CLI entrypoint for `python -m arodonata.testing.mock_server`.

#### class `CheckPointReplayHttpServer`

Embeddable `aiohttp.web` HTTPS server exposing Check Point `/web_api/<command>` backed by `FileReplayApiMock`.

##### Methods

###### `def __init__(self, *, dataset_dir: Path | str = DEFAULT_DATASET_DIR, api_mock: FileReplayApiMock | None = None, host: str = '127.0.0.1', port: int = 0, advertise_host: str | None = None, rewrite_domain_ips: bool = True, cert_path: Path | str | None = None, key_path: Path | str | None = None, enable_test_control: bool = False, test_control_token: str | None = None) -> None`

_No docstring._

###### `def api_mock(self) -> FileReplayApiMock`

```python
@property
```
Underlying `FileReplayApiMock` instance.

###### `def snapshot_state(self) -> ReplayStateSnapshot`

Capture an in-memory snapshot of underlying emulator state.

###### `def restore_state(self, snapshot: ReplayStateSnapshot) -> None`

Restore underlying emulator state from `snapshot`.

###### `def reset(self) -> None`

Reset underlying emulator state back to dataset baseline.

###### `def host(self) -> str`

```python
@property
```
Bound host address.

###### `def port(self) -> int`

```python
@property
```
Bound TCP port (resolved after `start()` when initialized with `port=0`).

###### `def fingerprint(self) -> str`

```python
@property
```
SHA-256 fingerprint (`SHA256:...` or hex) of the server's TLS certificate.

###### `def base_url(self) -> str`

```python
@property
```
HTTPS base URL (`https://<host>:<port>/web_api`).

###### `def test_control_token(self) -> str`

```python
@property
```
Shared secret token accepted via `X-Arodonata-Test-Token` on `/__testing__/*` endpoints.

###### `async def start(self) -> None`

Start the HTTPS server on `(self.host, self.port)`.

###### `async def stop(self) -> None`

Stop the HTTPS server and clean up any temporary TLS certificate directory.

### `arodonata/testing/replay_mock.py`

File-backed Check Point Management API and Gateway CLI replay adapters (`replay_mock.py`).

Provides:
- `FileReplayApiMock` (`ApiPort`): serves raw Check Point Management API JSON fixtures from
  `tests/fixtures/enterprise_raw_dataset/` with pagination (`limit`, `offset` -> `from`, `to`, `total`),
  `details-level` (`uid`, `standard`, `full`), `uid`/`name` and `class-name` filtering, rulebase section
  slicing (`show-access-rulebase`, `show-nat-rulebase`), `run-script` + `show-task` Base64 task execution,
  in-memory mutation helpers for targeted refresh tests, and per-domain/per-command call counters.
- `FileReplayCliMock` (`GatewayCliPort`): parses bash scripts produced by `build_route_collection_script`,
  verifies `vsenv "$vsid"` / `vsx stat -l` and `CTX%05d` `$FWDIR` checks, returns raw stdout/stderr from
  `cli/`, supports per-node SSH failure injection to trigger `cprid` `run-script` fallback, and records
  CLI execution counters.

#### class `FileReplayApiMock(ApiPort)`

File-backed `ApiPort` replay adapter emulating Check Point MDSM and CMA domains from disk fixtures.

##### Fields / Class Variables

```python
_manifest: dict[str, Any]
_show_domains: dict[str, Any]
_show_global_domain: dict[str, Any]
_show_mdss: dict[str, Any]
_domain_data: dict[str, dict[str, Any]]
_node_uid_to_name: dict[str, str]
_show_global_assignments: list[dict[str, Any]]
_initial_domain_data: dict[str, dict[str, Any]]
_initial_global_assignments: list[dict[str, Any]]
_dirty_domains: set[str]
_domain_generation: Counter[str]
_tasks: dict[str, dict[str, Any]]
_sid_bindings: dict[str, SidBinding]
_work_sessions: dict[str, WorkSession]
_published_session_by_domain: dict[str, str]
_published_deltas: dict[str, list[PublishedDelta]]
```
##### Methods

###### `def __init__(self, dataset_dir: Path | str = DEFAULT_DATASET_DIR, *, cli_mock: FileReplayCliMock | None = None, allow_one_time_script: bool = True, allow_repository_script: bool = True, manage_repository_scripts: str = 'write', encode_repository_script_body_base64: bool = False) -> None`

_No docstring._

###### `def dataset_dir(self) -> Path`

```python
@property
```
Path to the backing `enterprise_raw_dataset` fixture directory.

###### `def cli_mock(self) -> FileReplayCliMock`

```python
@property
```
Associated `FileReplayCliMock` instance.

###### `def manifest(self) -> dict[str, Any]`

```python
@property
```
Loaded `manifest.json` metadata dictionary.

###### `def reset_counters(self) -> None`

Reset all API and CLI call counters and logs.

###### `def get_active_sid_binding(self, sid: str | None) -> SidBinding | None`

Return the active `SidBinding` for `sid`, or `None` if unknown or logged out.

###### `def snapshot_state(self) -> ReplayStateSnapshot`

Capture an in-memory snapshot of modified domains, sessions, locks, tasks, and CLI overrides.

###### `def restore_state(self, snapshot: ReplayStateSnapshot) -> None`

Restore emulator state rapidly from a previously captured `ReplayStateSnapshot`.

###### `def reset(self) -> None`

Reset all in-memory domain data, sessions, locks, tasks, counters, and CLI overrides to baseline.

###### `def get_calls(self, *, domain: str | None = None, command: str | None = None, mutating_only: bool = False) -> list[dict[str, Any]]`

Return recorded `call_log` entries matching optional `domain`, `command`, and `mutating_only` filters.

###### `def assert_no_global_mutations(self) -> None`

Fail if any mutating API command targeted the `Global` domain.

###### `def assert_no_full_object_scans(self, commands: Iterable[str] = ('show-hosts', 'show-networks', 'show-address-ranges', 'show-groups')) -> None`

Fail if any command in `commands` was invoked (e.g., to guard against uncached full-table scans).

###### `def assert_command_called(self, command: str, *, domain: str | None = None, times: int | None = None) -> None`

Assert that `command` was called (optionally within `domain` and exact `times` count).

###### `def assert_command_not_called(self, command: str, *, domain: str | None = None) -> None`

Assert that `command` was never called (optionally restricted to `domain`).

###### `def update_gateway_interfaces(self, domain: str, gateway_name_or_uid: str, interfaces: list[dict[str, Any]]) -> None`

Update the raw `interfaces` list for a single gateway across summary and detail payloads in memory.

###### `def update_gateway_cli_stdout(self, node_name: str, stdout: str, *, vsid: int = 0) -> None`

Update the raw CLI routing stdout for `(node_name, vsid)` in the associated `FileReplayCliMock`.

###### `def bump_published_session(self, domain: str, *, new_session_uid: str, new_iso_time: str = '2026-11-09T12:00:00Z', new_posix_time: int = 1794225600000) -> None`

Simulate a new `publish` in `domain` by updating `show-last-published-session` and `show-sessions`.

###### `async def api_call(self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None, wait_for_task: bool = True, timeout: float | None = None) -> ApiCallResult`

```python
@traced
```
Execute a single Check Point Management API command with stateful sessions, overlays, and OTEL spans.

###### `async def api_query(self, mgmt_name: str, command: str, *, domain: str | None = None, details_level: str = 'standard', payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None, limit: int = DEFAULT_PAGE_LIMIT) -> ApiQueryResult`

```python
@traced
```
Execute a continuity-verified paginated listing query via `paginate_objects`.

###### `async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]`

```python
@traced
```
Open a registered stateful mock session and return `(sid, server_ip)`.

###### `def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> Awaitable[bool]`

Log out a registered mock session identifier and clean up uncommitted work.

###### `async def close(self, *, logout: bool | None = None) -> None`

Close the mock adapter, optionally logging out all active sessions.
