# Arodonata v2 (`2.6.7`) — SDK & CLI Quick-Reference

Auto-generated deterministic cheat sheet from `src/arodonata` (`arodonata==2.6.7`). Use this quick-reference to verify exact symbols, method signatures, and model fields without loading the full multi-megabyte `02-api-reference.md` bundle.

## 1. `ArodonataClient` (`arodonata.ArodonataClient`)

Async-first facade (`ClientTopologyMixin`, `ClientRulebaseReportsMixin`, `ClientInventoryMixin`, `ClientLifecycleMixin`, `ClientBase`).
Properties: `settings`, `db`, `owns_engine`, `cache`, `lock_port`, `api`, `amgmt`, `cpcrud`, `api_reference`, `script_service`, `topology_service`.
Streaming variants (`AsyncIterator[SyncProgressEvent | CPCRUDEvent]`): `stream_refresh_objects`, `stream_refresh_services`, `stream_refresh_assets`, `stream_refresh_rulebases`, `stream_refresh_policy_packages`, `stream_refresh_topology`, `stream_publish_staged_session`.

### Initialization & Lifecycle

```python
def __init__(self, settings: ArodonataSettings | None = None, *, engine: AsyncEngine | str | None = None, db_manager: DatabaseManager | None = None, cache: CachePort | None = None, lock_port: LockPort | None = None, api: ApiPort | None = None, transport: ApiTransport | None = None, trust_policy: TrustPolicy | None = None, connection_pool: VerifiedConnectionPool | None = None, task_waiter: TaskWaiter | None = None, rate_limiter: RateLimiter | None = None, login_gate: LoginGate | None = None, auth_provider: AuthProvider | None = None, domain_tracker: DomainListRefreshTracker | None = None, cluster_manager: ClusterRelationshipManager | None = None, vsx_manager: VSXRelationshipManager | None = None, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, monotonic_fn: Callable[[], float] = time.monotonic, now_fn: Callable[[], datetime] = utc_now, sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep, **settings_kwargs: Any) -> None
def invalidate_domain(self, mgmt_name: str, domain: str | None = None) -> None
def get_active_dedicated_sids(self, mgmt_name: str | None = None) -> list[str]
async def initialize(self, *, run_startup_cleanup: bool = True) -> None
async def close(self, *, logout: bool | None = None) -> None
async def api_call(self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None, wait_for_task: bool = True, timeout: float | None = None) -> ApiCallResult
async def api_query(self, mgmt_name: str, command: str, *, domain: str | None = None, details_level: str = 'standard', payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None, limit: int = DEFAULT_PAGE_LIMIT) -> ApiQueryResult
async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]
def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> Awaitable[bool]
def auth_context(self, auth: AuthContext | None = None, *, username: str | None = None, password: str | None = None, api_key: str | None = None, user_id: str | None = None) -> Iterator[AuthContext]
def user_context(self, user: UserContext | None = None, *, user_id: str | None = None, username: str | None = None, session_name: str | None = None, session_description: str | None = None, client_id: str | None = None, extra: dict[str, Any] | None = None) -> Iterator[UserContext]
async def write_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None, publish_on_exit: bool = True) -> AsyncIterator[WriteSession]
async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False) -> ApiCallResult
async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False) -> ApiCallResult
```

### Inventory, Cache, Search & CRUD

```python
def get_warmup_status(self, mgmt_name: str | None = None) -> list[WarmupStatusEntry]
def start_object_cache_warmup(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, include_services: bool = False, mode: CacheMode = 'smart') -> asyncio.Task[RefreshOutcome]
async def refresh_objects(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome
async def refresh_services(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome
async def refresh_assets(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome
async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[DomainInfo]
async def get_gateways(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[Asset]
async def get_hosts(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]
async def get_networks(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]
async def get_address_ranges(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]
async def get_dns_domains(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]
async def get_groups(self, mgmt_name: str | None = None, domain: str | None = None, *, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]
async def get_objects(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject]
async def get_services(self, mgmt_name: str | None = None, domain: str | None = None, *, types: Sequence[str] | None = None, names: Sequence[str] | None = None, uids: Sequence[str] | None = None, include_global: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPService]
async def get_object_by_uid(self, mgmt_name: str, domain: str, uid: str, *, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | None
async def search_objects(self, query: str, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, types: Sequence[str] | None = None, include_global: bool = False, max_depth: int = 2, exact_match: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> SearchResult
async def describe_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, include_global: bool = True) -> dict[str, Any]
async def query_objects(self, *, mgmt_name: str | None = None, domain_name: str | None = None, domains: Sequence[str] | None = None, types: Sequence[str] | None = None, roles: Sequence[str] | None = None, platforms: Sequence[str] | None = None, is_policy_target: bool | None = None, is_execution_target: bool | None = None, scope_origin: Literal['all', 'local', 'global'] = 'all', name_pattern: str | None = None, ip_subnet: str | None = None, port: str | None = None, protocol: str | None = None, tags: Sequence[str] | None = None, parent_id: str | None = None, parent_asset_id: str | None = None, include_global: bool = False, group_by: Sequence[str] | None = None, aggregate: Literal['count', 'list', 'describe'] = 'list', limit: int = 100, offset: int = 0, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> dict[str, Any]
async def get_cache_status(self, *, mgmt_name: str | None = None, domain_name: str | None = None, scope: SyncScope | None = None) -> dict[str, Any]
async def add_object(self, mgmt_name: str, obj_type: str, payload: dict[str, Any], *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None) -> ApiCallResult
async def set_object(self, mgmt_name: str, obj_type: str, payload: dict[str, Any], *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None) -> ApiCallResult
async def delete_object(self, mgmt_name: str, obj_type: str, *, uid: str | None = None, name: str | None = None, payload: dict[str, Any] | None = None, domain: str | None = None, sid: str | None = None, server_ip: str | None = None) -> ApiCallResult
async def find_object(self, mgmt_name: str, domain: str | None = None, name_or_uid: str = '', *, obj_type: str | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> CPObject | CPService | Asset | None
async def get_group_members(self, mgmt_name: str, domain: str | None = None, group_name_or_uid: str = '', *, recursive: bool = True, max_depth: int = 5, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[CPObject | CPService | Asset]
```

### Rulebases, Change Reports, API Reference & Repository Scripts

```python
async def refresh_rulebases(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome
async def refresh_policy_packages(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome
async def refresh_package_rulebase(self, mgmt_name: str, domain_name: str | None, package: str, *, rulebase_type: RulebaseType = 'access', mode: CacheMode = 'smart', cache_ttl: float | None = None) -> RefreshOutcome
async def get_access_rules(self, mgmt_name: str, domain: str, *, layer_uid: str | None = None, layer_name: str | None = None) -> list[AccessRuleEntry]
async def get_nat_rules(self, mgmt_name: str, domain: str, *, package_uid: str | None = None, package_name: str | None = None) -> list[NatRuleEntry]
async def get_https_rules(self, mgmt_name: str, domain: str, *, layer_uid: str | None = None, layer_name: str | None = None) -> list[HttpsRuleEntry]
async def get_threat_rules(self, mgmt_name: str, domain: str, *, layer_uid: str | None = None, layer_name: str | None = None) -> list[ThreatRuleEntry]
async def get_policy_packages(self, mgmt_name: str, domain_name: str | None = None, *, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> list[PolicyPackageInfo]
async def get_package_rulebase(self, mgmt_name: str, domain_name: str | None, package: str, *, rulebase_type: RulebaseType = 'access', cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> PackageRulebase
async def get_layer_rulebase(self, mgmt_name: str, domain_name: str | None, layer: str, *, rulebase_type: RulebaseType | None = None, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> NumberedLayerRulebase
async def locate_rules(self, mgmt_name: str, domain_name: str | None = None, *, rule_uids: Sequence[str] | None = None, layer_uids: Sequence[str] | None = None, cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> RuleLocations
async def filter_rulebase(self, mgmt_name: str, domain_name: str | None = None, *, package: str | None = None, layer: str | None = None, rulebase_type: RulebaseType = 'access', filter_query: str = '', output_format: RuleFormat = 'model_friendly', cache_mode: CacheMode = 'cache', cache_ttl: float | None = None) -> FilteredRulebaseResult
async def collect_change_report(self, scopes: Sequence[ReportScope | dict[str, Any]], *, options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS) -> ChangeReport
def build_change_report_from_plan(self, plan: Plan, *, title: str | None = None, header_fields: Mapping[str, str] | None = None, include_unchanged: bool = False) -> ChangeReport
def render_change_report(self, report: ChangeReport, *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None) -> RenderedReportBundle
async def build_change_report(self, scopes: Sequence[ReportScope | dict[str, Any]], *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS) -> RenderedReportBundle
async def ensure_api_reference(self) -> ApiReferenceEngine
def resolve_api_version(self, version: str | None = None, mgmt_name: str | None = None) -> str
def search_api_commands(self, query: str = '', *, category: str | None = None, crud_type: str | None = None, api_family: str | None = None, version: str | None = None, mgmt_name: str | None = None, limit: int = 15) -> list[dict[str, Any]]
def describe_api_command(self, command: str | Sequence[str], *, version: str | None = None, mgmt_name: str | None = None, resolve_nested: bool = True, include_examples: bool = True) -> dict[str, Any] | None
def validate_api_payload(self, command: str, payload: dict[str, Any] | None, *, version: str | None = None, mgmt_name: str | None = None) -> dict[str, Any]
async def get_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, details_level: str = 'full') -> RepositoryScript
async def list_repository_scripts(self, mgmt_name: str, *, domain: str | None = None, details_level: str = 'full', limit: int = 300) -> list[RepositoryScript]
async def check_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, expected_body: str | None = None) -> RepositoryScriptStatus
async def ensure_repository_script(self, mgmt_name: str, script_name: str, script_body: str, *, domain: str | None = None, comments: str | None = None, color: str | None = None, tags: Sequence[str] | None = None) -> EnsureRepositoryScriptResult
async def delete_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None) -> bool
async def run_repository_script(self, mgmt_name: str, script_name_or_uid: str, targets: Sequence[str] | str, *, domain: str | None = None, args: Sequence[str] | str | None = None, comments: str | None = None, timeout: float | None = None, script_timeout: int | None = None) -> RepositoryScriptExecutionOutcome
```

### Gateway Topology & Route Collection

```python
def set_gateway_cli(self, gateway_cli: GatewayCliPort | GatewayCliCallable | None) -> None
async def refresh_topology(self, *, mgmt_name: str | None = None, domains: Sequence[str] | str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, include_global: bool = False, mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RefreshOutcome
async def get_gateway_topology(self, mgmt_name: str | None = None, domain: str | None = None, *, gateway: str | None = None, topology_zone: TopologyZone | None = None, source_types: Sequence[TopologySourceType | str] | None = None, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[GatewayTopologyEntry]
async def find_affected_gateways(self, sources: Sequence[str] | str, destinations: Sequence[str] | str, *, mgmt_name: str | None = None, domain: str | None = None, min_confidence: float = 0.0, include_standby: bool = True, include_policy_inferred: bool = True, source_types: Sequence[TopologySourceType | str] | None = None, include_annotations: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[AffectedGatewayCandidate]
async def collect_gateway_routes(self, *, mgmt_name: str | None = None, domain: str | None = None, domains: Sequence[str] | str | None = None, include_global: bool = False, gateways: Sequence[str] | str | None = None, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, timeout: float = 45.0, concurrency: int | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> RouteCollectionOutcome
async def check_route_collection_script(self, mgmt_name: str, domain: str | None = None, *, script_name: str | None = None) -> RepositoryScriptStatus
async def ensure_route_collection_script(self, mgmt_name: str, domain: str | None = None, *, script_name: str | None = None, comments: str | None = None) -> EnsureRepositoryScriptResult
async def get_topology_diagnostics(self, mgmt_name: str | None = None, domain: str | None = None, *, gateways: Sequence[str] | str | None = None, gateway: str | None = None, min_severity: TopologyDiagnosticSeverity = 'info', cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[TopologyDiagnostic]
async def reconcile_gateway_topology(self, *, mgmt_name: str | None = None, domain: str | None = None, gateways: Sequence[str] | str | None = None, collect_routes: bool = False, collect_live_routes: bool = False, check_policy: bool = False, gateway_cli: GatewayCliPort | GatewayCliCallable | None = None, fallback_to_cprid: bool = True, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None, cprid_script_mode: CpridScriptMode | None = None, repository_script_name: str | None = None, repository_script_args_fn: RepositoryScriptArgsCallable | None = None) -> TopologyReconciliationReport
async def get_topology_annotations(self, mgmt_name: str | None = None, domain: str | None = None, *, gateway: str | None = None, interface_name: str | None = None) -> list[TopologyAnnotation]
async def upsert_topology_annotations(self, annotations: Sequence[TopologyAnnotation | dict[str, Any]] | TopologyAnnotation | dict[str, Any]) -> list[TopologyAnnotation]
async def delete_topology_annotations(self, annotation_ids: Sequence[str] | str | None = None, *, mgmt_name: str | None = None, domain: str | None = None, gateway_uid: str | None = None) -> int
async def export_topology_prefixes(self, *, mgmt_name: str | None = None, domain: str | None = None, gateways: Sequence[str] | str | None = None, gateway: str | None = None, include_external: bool = False, include_ignored: bool = False, cache_mode: CacheMode = 'smart', cache_ttl: float | None = None) -> list[ExportedTopologyPrefix]
```

## 2. `ArodonataSettings` (`arodonata.ArodonataSettings`)

```python
mgmt_names: CsvStrList = []
mgmt_servers: CsvStrList = []
api_keys: CsvStrList = []
api_key_vars: CsvStrList = []
api_versions: CsvStrList = []
mgmt_name: str | None = None
mgmt_ip: str | None = None
mgmt_port: int = 443
max_response_bytes: int = 67108864
api_version: str | None = None
api_key: str | None = None
username: str | None = None
password: str | None = None
auth_mode: AuthMode = 'dynamic'
connect_timeout: float = 30.0
api_timeout: float = 120.0
login_timeout: float = 120.0
task_timeout: float = 900.0
rate_limit_slot_timeout: float = 90.0
session_timeout: int = 600
session_expire_seconds: int = 540
concurrent_limit: int = 4
domain_sync_concurrency: int = 0
route_collect_concurrency: int = 0
max_routes_per_gateway: int = 50000
max_query_pages: int = 5000
max_query_objects: int = 1000000
login_throttle_window: float = 70.0
login_max_wait: float = 900.0
cache_ttl: int = 300
domain_list_ttl: int = 3600
max_incremental_changes: int = 500
tls_trust: TlsTrustMode = 'tofu'
tls_known_hosts_path: str = str(Path.home() / '.config' / 'arodonata' / 'tls_known_hosts.json')
tls_fingerprints: str = ''
database_url: str = 'sqlite+aiosqlite:///:memory:'
sqlite_busy_timeout_ms: int = 30000
cpcrud_schema_path: str | None = None
cpcrud_naming_prefixes: NamingPrefixes = NamingPrefixes()
trace_modules: str = ''
topology_confidence_weights: TopologyConfidenceWeights = TopologyConfidenceWeights()
cprid_script_mode: CpridScriptMode = 'inline'
cprid_repository_script_name: str = 'arodonata-collect-routes-v1'
```

## 3. Core Models (`Asset`, `CPObject`, `CPService`, `DomainInfo`)

### `Asset`

```python
id: str = ''
asset_id: str = ''
uid: str
name: str
type: str
mgmt_name: str
domain_name: str
ipv4_address: str | None = None
ipv6_address: str | None = None
version: str | None = None
os_name: str | None = None
hardware: str | None = None
sic_status: str | None = None
parent_uid: str | None = None
parent_name: str | None = None
parent_id: str | None = None
parent_asset_id: str | None = None
member_uids: list[str] = []
member_asset_ids: list[str] = []
virtual_system_uids: list[str] = []
virtual_system_asset_ids: list[str] = []
interfaces: list[dict[str, Any]] = []
network_security_blades: dict[str, Any] = {}
management_blades: dict[str, Any] = {}
asset_role: AssetRole = 'unknown'
platform_family: AssetPlatform = 'unknown'
is_policy_target: bool = False
is_execution_target: bool = False
comments: str = ''
color: str | None = None
raw_data: dict[str, Any] = {}
updated_at: datetime = utc_now()

def model_post_init(self, __context: Any) -> None
@classmethod def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> Asset

def classify_asset_role(asset: Asset | Mapping[str, Any], *, parent_type: str | None = None) -> AssetRole
def classify_asset_platform(asset: Asset | Mapping[str, Any]) -> AssetPlatform
def classify_asset(asset: Asset, *, parent_type: str | None = None) -> Asset
```

### `CPObject`

```python
id: str = ''
object_id: str = ''
uid: str
name: str
type: str
mgmt_name: str
domain_name: str
original_domain: str | None = None
ipv4_address: str | None = None
ipv6_address: str | None = None
subnet4: str | None = None
mask_length4: int | None = None
subnet_mask: str | None = None
ipv4_address_first: str | None = None
ipv4_address_last: str | None = None
fqdn: str | None = None
is_sub_domain: bool | None = None
primary_category: str | None = None
url_list: list[str] = []
urls_defined_as_regular_expression: bool | None = None
description: str = ''
members: list[str] = []
comments: str = ''
color: str | None = None
tags: list[str] = []
nat_settings: dict[str, Any] = {}
raw_data: dict[str, Any] = {}
updated_at: datetime = utc_now()

def model_post_init(self, __context: Any) -> None
@classmethod def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> CPObject
```

### `CPService`

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
icmp_type: int | None = None
icmp_code: int | None = None
members: list[str] = []
session_timeout: int | None = None
match_for_any: bool | None = None
comments: str = ''
color: str | None = None
tags: list[str] = []
raw_data: dict[str, Any] = {}
updated_at: datetime = utc_now()

def model_post_init(self, __context: Any) -> None
@classmethod def from_cp_dict(cls, mgmt_name: str, domain_name: str, data: dict[str, Any]) -> CPService
```

### `DomainInfo`

```python
id: str = ''
mgmt_name: str
uid: str
name: str
domain_type: str = 'domain'
active_ip: str | None = None
active_mds_ip: str | None = None
standby_ips: list[str] = []
servers: list[dict[str, Any]] = []
is_global: bool = False
raw_data: dict[str, Any] = {}
updated_at: datetime = utc_now()

def parse_domain_entry(mgmt_name: str, raw: dict[str, Any], *, mds_ip_by_name: dict[str, str] | None = None, default_host: str | None = None, now_fn: Callable[[], datetime] | None = None, fallback_uid: bool = False) -> DomainInfo
def parse_domain_dict(mgmt_name: str, raw: dict[str, Any], *, default_host: str | None = None, mds_ip_by_name: dict[str, str] | None = None, now_fn: Callable[[], datetime] = utc_now) -> DomainInfo
```

## 4. `ScriptRepositoryService` (`arodonata.ScriptRepositoryService`)

```python
def __init__(self, *, api: ApiPort, settings: ArodonataSettings | None = None, write_session_factory: Callable[..., AbstractAsyncContextManager[WriteSession]] | None = None, on_domain_invalidated: Callable[[str, str | None], None] | None = None) -> None
async def get_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, details_level: str = 'full') -> RepositoryScript
async def list_repository_scripts(self, mgmt_name: str, *, domain: str | None = None, details_level: str = 'full', limit: int = 300) -> list[RepositoryScript]
async def check_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None, expected_body: str | None = None) -> RepositoryScriptStatus
async def ensure_repository_script(self, mgmt_name: str, script_name: str, script_body: str, *, domain: str | None = None, comments: str | None = None, color: str | None = None, tags: Sequence[str] | None = None) -> EnsureRepositoryScriptResult
async def delete_repository_script(self, mgmt_name: str, script_name_or_uid: str, *, domain: str | None = None) -> bool
async def run_repository_script(self, mgmt_name: str, script_name_or_uid: str, targets: Sequence[str] | str, *, domain: str | None = None, args: Sequence[str] | str | None = None, comments: str | None = None, timeout: float | None = None, script_timeout: int | None = None, sid: str | None = None, server_ip: str | None = None, session_getter: Callable[[str, str | None], Awaitable[tuple[str, str]]] | None = None) -> RepositoryScriptExecutionOutcome
```

## 5. `CPCRUDService` (`arodonata.CPCRUDService`)

```python
def __init__(self, *, settings: ArodonataSettings, api: ApiPort, cache: _PlannerCachePort, on_domain_invalidated: Callable[[str, str | None], None] | None = None, ensure_initialized: Callable[[], Any] | None = None, now_fn: Callable[[], datetime] = utc_now) -> None
@property def planner(self) -> Planner
@property def executor(self) -> Executor
@property def last_report(self) -> ApplyReport | None
def validate(self, template: dict[str, Any] | str, *, schema_path: str | Path | None = None) -> list[str]
async def plan(self, template: dict[str, Any] | str, *, on_name_conflict: NameConflictPolicy | None = None, on_ip_conflict: IpConflictPolicy | None = None, naming_prefixes: NamingPrefixes | Mapping[str, Any] | None = None, validate_schema: bool = True) -> Plan
async def apply(self, plan: Plan, *, force: bool = False, no_publish: bool = False, keep_session: bool = False, retry_remaining: int = 0, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None) -> ApplyReport
async def stream_apply(self, plan: Plan, *, force: bool = False, no_publish: bool = False, keep_session: bool = False, retry_remaining: int = 0, auth: AuthContext | None = None, user: UserContext | None = None, session_name: str | None = None, session_description: str | None = None) -> AsyncIterator[CPCRUDEvent]
def inverse(self, plan: Plan, report: ApplyReport | None = None) -> dict[str, Any]
async def publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False, baseline_readable: bool | None = None, baseline_session_uid: str | None = None, baseline_published_at: datetime | None = None) -> ApiCallResult
async def stream_publish_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, timeout: float | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False, allow_stale: bool = False, baseline_readable: bool | None = None, baseline_session_uid: str | None = None, baseline_published_at: datetime | None = None) -> AsyncIterator[CPCRUDEvent]
def notify_sid_logged_out(self, mgmt_name: str, sid: str) -> None
async def discard_staged_session(self, mgmt_name: str, domain: str | None = None, *, session_uid: str, sid: str | None = None, server_ip: str | None = None, auth: AuthContext | None = None, force_disconnect: bool = False, expected_session_name: str | None = None, allow_foreign: bool = False) -> ApiCallResult
```

## 6. `ApiReferenceEngine` & Offline Reference (`arodonata.api_reference`)

```python
def __init__(self, index_data: dict[str, Any]) -> None
@classmethod def default(cls) -> ApiReferenceEngine
@classmethod async def async_default(cls) -> ApiReferenceEngine
@classmethod def from_path(cls, path: Path | str) -> ApiReferenceEngine
def search_commands(self, query: str = '', *, category: str | None = None, crud_type: str | None = None, api_family: str | None = None, version: str | None = DEFAULT_API_VERSION, limit: int = 15) -> list[dict[str, Any]]
def describe_command(self, command: str | Sequence[str], *, version: str | None = DEFAULT_API_VERSION, resolve_nested: bool = True, include_examples: bool = True) -> dict[str, Any] | None
def validate_payload(self, command: str, payload: dict[str, Any] | None, *, version: str | None = DEFAULT_API_VERSION) -> dict[str, Any]

def normalize_api_version(version: str | None, *, default: str = DEFAULT_API_VERSION) -> str
def get_api_reference() -> ApiReferenceEngine
def search_api_commands(query: str = '', *, category: str | None = None, crud_type: str | None = None, api_family: str | None = None, version: str | None = DEFAULT_API_VERSION, limit: int = 15) -> list[dict[str, Any]]
def describe_api_command(command: str | Sequence[str], *, version: str | None = DEFAULT_API_VERSION, resolve_nested: bool = True, include_examples: bool = True) -> dict[str, Any] | None
def validate_api_payload(command: str, payload: dict[str, Any] | None, *, version: str | None = DEFAULT_API_VERSION) -> dict[str, Any]
```

## 7. `ChangeReport` & Audit Helpers (`arodonata.reports`)

```python
# ChangeReport
format_version: int = CURRENT_FORMAT_VERSION
generated_at: datetime = utc_now()
title: str = 'Check Point Policy Change Report'
header_fields: dict[str, str] = {}
sessions: list[SessionChangeReport] = []
warnings: list[ReportWarning] = []
raw_responses: list[RawResponse] = []

# SessionChangeReport
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
rule_changes: list[RuleChangeEntry] = []
object_changes: list[ObjectChangeEntry] = []
resolved_names: dict[str, str] = {}

# Scopes & Options
SessionScope.mgmt_name: str
SessionScope.domain: str | None = None
SessionScope.session_uids: list[str] = []
SessionScope.owned_sessions: dict[str, OwnedSession] | list[OwnedSession] | OwnedSession | None = None
RangeScope.mgmt_name: str
RangeScope.domain: str | None = None
RangeScope.from_date: datetime | None = None
RangeScope.to_date: datetime | None = None
RangeScope.from_session: str | None = None
RangeScope.to_session: str | None = None
OwnedSession.sid: str
OwnedSession.server_ip: str = ''
OwnedSession.session_uid: str | None = None
OwnedSession.mgmt_name: str | None = None
OwnedSession.domain: str | None = None
RenderOptions.title: str = 'Check Point Policy Change Report'
RenderOptions.header_fields: dict[str, str] = {}
RenderOptions.include_object_changes: bool = True
RenderOptions.include_field_diffs: bool = True
RenderOptions.include_warnings: bool = True
RenderOptions.include_system_objects: bool = False

# Report Functions
async def collect_change_report(api: ApiPort, cache: _ReportCachePort, scopes: Sequence[ReportScope | dict[str, Any]], *, options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS, now_fn: Callable[[], datetime] = utc_now, refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None) -> ChangeReport
def build_change_report_from_plan(plan: Plan, *, title: str | None = None, header_fields: Mapping[str, str] | None = None, include_unchanged: bool = False) -> ChangeReport
async def build_change_report(api: ApiPort, cache: _ReportCachePort, scopes: Sequence[ReportScope | dict[str, Any]], *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None, max_uid_lookups: int = MAX_UID_LOOKUPS, now_fn: Callable[[], datetime] = utc_now, refresh_rulebase_fn: Callable[[str, str], Awaitable[Any]] | None = None) -> RenderedReportBundle
def render_change_report(report: ChangeReport, *, formats: Sequence[str] = ('html', 'markdown', 'json'), options: RenderOptions | None = None) -> RenderedReportBundle
```

## 8. `arodonata.testing` Replay & Mock Helpers

Exports (`__all__`): `ALL_DOMAINS, DATASET_VERSION, DEFAULT_DATASET_DIR, DEFAULT_SEED, USER_DOMAINS, CheckPointReplayHttpServer, FileReplayApiMock, FileReplayCliMock, ReplayStateSnapshot, ensure_enterprise_raw_dataset, generate_enterprise_raw_dataset`.

```python
# FileReplayApiMock
def __init__(self, dataset_dir: Path | str = DEFAULT_DATASET_DIR, *, cli_mock: FileReplayCliMock | None = None, allow_one_time_script: bool = True, allow_repository_script: bool = True, manage_repository_scripts: str = 'write', encode_repository_script_body_base64: bool = False) -> None
@property def dataset_dir(self) -> Path
@property def cli_mock(self) -> FileReplayCliMock
@property def manage_repository_scripts(self) -> str
def manage_repository_scripts(self, value: str) -> None
@property def manifest(self) -> dict[str, Any]
def reset_counters(self) -> None
def get_active_sid_binding(self, sid: str | None) -> SidBinding | None
def snapshot_state(self) -> ReplayStateSnapshot
def restore_state(self, snapshot: ReplayStateSnapshot) -> None
def reset(self) -> None
def get_calls(self, *, domain: str | None = None, command: str | None = None, mutating_only: bool = False) -> list[dict[str, Any]]
def assert_no_global_mutations(self) -> None
def assert_no_full_object_scans(self, commands: Iterable[str] = ('show-hosts', 'show-networks', 'show-address-ranges', 'show-groups')) -> None
def assert_command_called(self, command: str, *, domain: str | None = None, times: int | None = None) -> None
def assert_command_not_called(self, command: str, *, domain: str | None = None) -> None
def update_gateway_interfaces(self, domain: str, gateway_name_or_uid: str, interfaces: list[dict[str, Any]]) -> None
def update_gateway_cli_stdout(self, node_name: str, stdout: str, *, vsid: int = 0) -> None
def bump_published_session(self, domain: str, *, new_session_uid: str, new_iso_time: str = '2026-11-09T12:00:00Z', new_posix_time: int = 1794225600000) -> None
async def api_call(self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, *, domain: str | None = None, sid: str | None = None, server_ip: str | None = None, wait_for_task: bool = True, timeout: float | None = None) -> ApiCallResult
async def api_query(self, mgmt_name: str, command: str, *, domain: str | None = None, details_level: str = 'standard', payload: dict[str, Any] | None = None, sid: str | None = None, server_ip: str | None = None, limit: int = DEFAULT_PAGE_LIMIT) -> ApiQueryResult
async def create_dedicated_session(self, mgmt_name: str, domain: str | None = None, *, auth: AuthContext | None = None, session_name: str | None = None, session_description: str | None = None) -> tuple[str, str]
def logout_sid(self, mgmt_name: str, sid: str, *, server_ip: str | None = None) -> Awaitable[bool]
async def close(self, *, logout: bool | None = None) -> None

# FileReplayCliMock
def __init__(self, dataset_dir: Path | str = DEFAULT_DATASET_DIR, *, fail_ssh_nodes: set[str] | None = None) -> None
def reset_counters(self) -> None
def set_cli_stdout(self, node_name: str, vsid: int, stdout: str) -> None
def get_raw_cli_stdout(self, node_name: str, vsid: int | None = 0) -> str | None
def resolve_vsid_from_stat(self, node_name: str, vs_name: str) -> int | None
def list_virtual_systems(self, node_name: str) -> list[tuple[int, str]]
async def execute_command(self, target: GatewayCliTarget, command: str, *, timeout: float = 30.0) -> GatewayCliResult

# CheckPointReplayHttpServer
def __init__(self, *, dataset_dir: Path | str = DEFAULT_DATASET_DIR, api_mock: FileReplayApiMock | None = None, host: str = '127.0.0.1', port: int = 0, advertise_host: str | None = None, rewrite_domain_ips: bool = True, cert_path: Path | str | None = None, key_path: Path | str | None = None, enable_test_control: bool = False, test_control_token: str | None = None) -> None
@property def api_mock(self) -> FileReplayApiMock
def snapshot_state(self) -> ReplayStateSnapshot
def restore_state(self, snapshot: ReplayStateSnapshot) -> None
def reset(self) -> None
@property def host(self) -> str
@property def port(self) -> int
@property def fingerprint(self) -> str
@property def base_url(self) -> str
@property def test_control_token(self) -> str
async def start(self) -> None
async def stop(self) -> None

# ReplayStateSnapshot
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

# Dataset Generators
def generate_enterprise_raw_dataset(output_dir: Path | str | None = None, *, seed: int = DEFAULT_SEED) -> dict[str, Any]
def ensure_enterprise_raw_dataset(output_dir: Path | str | None = None, *, seed: int = DEFAULT_SEED, force: bool = False) -> Path
```

## 9. Idiomatic `arlogi` CLI Bootstrap

```python
import arlogi

arlogi.setup_logging(level="INFO", json_file_name="logs/cli.jsonl", json_file_only=False)
logger = arlogi.get_logger(__name__)
logger.info("inventory sync finished", mgmt_name="prod-mds", count=42)
```

- Keep `json_file_only=False` for interactive CLI scripts so operators see console logs while JSONL audit logs persist on disk.
- Never pass `sid`, `api_key`, `password`, or raw auth headers in log messages or `extra` kwargs.

## 10. 3-Tier Check Point API Lookup Ladder

1. **Tier 1 (`arodonata.api_reference`)**: Query the bundled offline Check Point API index first via `search_api_commands()`, `describe_api_command()`, and `validate_api_payload()` (or `client.search_api_commands()` / `client.describe_api_command()` / `client.validate_api_payload()`).
2. **Tier 2 (`context7` / `cp-documentation` MCP)**: When deeper vendor semantics, MDSM edge cases, or Gaia/CDT behavior are needed, consult `docs/troubleshooting/checkpoint-api-quirks.md`, `docs/troubleshooting/checkpoint-ops-quirks.md`, or the documentation MCP servers.
3. **Tier 3 (Explicit Verification Flag)**: For undocumented commands or site-specific R81.x/R82+ nuances not verified by Tiers 1–2, emit an explicit `# VERIFY:` note and confirm against a read-only lab/replay check before mutating production state.
