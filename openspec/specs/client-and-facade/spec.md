# Client Facade, Ports/Adapters, and Telemetry Specification

## Purpose

Defines the primary composition root and unified developer facade (`ArodonataClient`), hexagonal architectural ports (`ApiPort`, `CachePort`, `LockPort`) and adapters (`AMgmtClient`, `SqlCacheAdapter`, `SqlLockAdapter`), `contextvars`-aware session and object mutation methods, and OpenTelemetry instrumentation (`telemetry.py`).

## Requirements

### Requirement: Hexagonal Composition Root and Lifecycle Management

`ArodonataClient` SHALL serve as the unified composition root wiring `ApiPort` (`AMgmtClient`), `CachePort` (`SqlCacheAdapter`), and `LockPort` (`SqlLockAdapter`) into core domain services, defaulting `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) and cleaning up sessions, background tasks, and owned engines deterministically on `close()` / `__aexit__()`.

#### Scenario: Context manager initializes database and drains or cancels background work on close

- **WHEN** `async with ArodonataClient(...) as client:` enters and exits
- **THEN** `__aenter__` SHALL initialize the database schema (and schedule startup session cleanup if static credentials are present), and `__aexit__` (`close()`) SHALL cancel any running background warm-up tasks immediately, drain startup cleanup tasks up to the grace period, close `AMgmtClient`, and dispose of the SQLAlchemy engine ONLY if `client` auto-created it (`_owns_engine == True`)

#### Scenario: Automatic logout policy on client close

- **WHEN** `client.close(logout=None)` is called
- **THEN** the client SHALL automatically log out active Check Point sessions if it auto-created an in-memory database (`_owns_engine == True`), and preserve cached read-only sessions in the database if an external persistent engine was provided

### Requirement: Typed Read Facade and Domain Invalidation

`ArodonataClient` SHALL expose typed async read methods returning Pydantic v2 models (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_services`, `get_object_by_uid`, `get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules`) with `cache_mode` and `cache_ttl` overrides, overlay uncommitted `WriteSession` changes from `contextvars`, and invalidate domain freshness memos on publish (`invalidate_domain`).

#### Scenario: Read helpers reflect active WriteSession overlay via contextvars

- **WHEN** `await client.get_hosts(mgmt_name, domain)` or `await client.get_services(mgmt_name, domain)` is called inside an active `async with client.write_session(mgmt_name, domain):` block
- **THEN** the returned list SHALL include objects created or updated in that `WriteSession` and exclude objects deleted in that `WriteSession` without mutating the shared database rows

#### Scenario: Publish via api_call invalidates domain freshness memos

- **WHEN** a `WriteSession` publishes or `await client.api_call(mgmt_name, "publish", domain=domain)` succeeds
- **THEN** `client.invalidate_domain(mgmt_name, domain)` SHALL be invoked automatically so the next `"smart"` or `"smart-fast"` read re-checks the domain's published session head even within `cache_ttl`

### Requirement: User-Aware Domain Helper Functions

`ArodonataClient` SHALL provide `contextvars`-aware session, mutation, and lookup helpers (`write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`), auto-wrapping standalone object mutations in an isolated write session, stripping secret request fields from `SessionOverlay`, and redacting secrets in `ApiCallResult`.

#### Scenario: Context manager write_session publishes on success and discards on exception

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_auth)` is entered
- **THEN** it SHALL open an isolated write session, bind it to `contextvars` so nested mutations and reads use its SID and `SessionOverlay` (with secret request keys such as `one-time-password`, `shared-secret`, `password`, and `api-key` stripped from cached `raw_data`), auto-publish on clean exit (or discard before logout if `publish` returns `success=False`), and automatically shield `discard` and `logout_sid` on any unhandled `BaseException` (including `asyncio.CancelledError`)

#### Scenario: Standalone object mutation helpers never dirty the shared read-only SID cache

- **WHEN** `await client.add_object(...)`, `await client.set_object(...)`, or `await client.delete_object(...)` is called outside an active `async with client.write_session(...)` block and without an explicit `sid`
- **THEN** the helper SHALL execute inside a dedicated isolated session (never using the shared `arodonata_sid_cache` session) and `ApiCallResult.__repr__()` SHALL redact `sid` and secret payload fields

#### Scenario: find_object and get_group_members resolve across objects, services, and assets by UID, name, or composite ID

- **WHEN** `await client.find_object(mgmt_name, domain, name_or_uid)` or `await client.get_group_members(mgmt_name, domain, group_name_or_uid)` is called with a raw UID, object name, or composite identifier (`object_id`, `service_id`, `asset_id`, or `id`, such as `"mds:General:hWebHost"` or `"mds:VSX:VSX-Cluster-01"`)
- **THEN** `find_object` SHALL look up the target across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` (returning `CPObject | CPService | Asset | None` with `object_id` / `service_id` / `asset_id` populated), and `get_group_members` SHALL expand direct and recursive members of a network group (`CPObject`), a `service-group` (`CPService`), or a cluster/VSX parent asset (`Asset` via `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`, including cross-domain Virtual Systems) from cache

### Requirement: Composite Identifier Resolution in Facade and Search Helpers

`ArodonataClient.find_object()`, `ArodonataClient.get_group_members()`, `SearchService.search_objects()`, and `SearchService.query_objects()` SHALL accept and filter by composite human-readable identifiers (`object_id`, `service_id`, `asset_id` formatted as `"{mgmt_name}:{domain_name}:{name}"`) or composite UID keys (`id` formatted as `"{mgmt_name}:{domain_name}:{uid}"`) in addition to raw `name` or `uid`.

#### Scenario: find_object and get_group_members resolve composite human-readable IDs

- **WHEN** `await client.find_object(mgmt_name, domain, "mds:General:hWebHost")` or `await client.get_group_members(mgmt_name, domain, "mds:General:Cluster01")` is called with a composite `object_id`, `service_id`, `asset_id`, or `id`
- **THEN** the helper SHALL match the corresponding `CPObject`, `CPService`, or `Asset` (or expand its members/child assets) identically to passing the raw `name` or `uid`

#### Scenario: Structured query_objects and describe_objects expose composite ID fields

- **WHEN** `await client.describe_objects()` or `await client.query_objects(...)` is called
- **THEN** `describe_objects()` SHALL list `id`, `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id` among filterable fields, and `query_objects()` SHALL include the composite fields on returned items

### Requirement: Provider-Agnostic OpenTelemetry Instrumentation and Secret Redaction

All major client, transport, login, lock, cache, and CPCRUD entry points SHALL be decorated with `@traced` and attach `arodonata.*`-namespaced span attributes (`span_attrs`) while recursively sanitizing mappings, nested lists/tuples, and chained exception causes (`__cause__` and `__context__`) so credentials, API keys, or unredacted session SIDs are never recorded.

#### Scenario: Span attributes omit None values and never expose secrets

- **WHEN** `span_attrs(**attrs)` is called inside a traced operation or an exception with a chained `__cause__` / `__context__` is recorded on a span
- **THEN** non-`None` attributes SHALL be set on the current OpenTelemetry span under the `arodonata.<key>` namespace with recursive secret/SID redaction applied to mappings, lists, and chained exception messages, operating as a zero-overhead no-op when no `TracerProvider` is configured by the host application

### Requirement: Cache-Only Cross-Domain Entity Lookup and Ambiguity Refusal

`ArodonataClient.find_object()` and `ArodonataClient.get_group_members()` SHALL require a non-empty target identifier (`ValidationError` on empty/blank input), and when `domain` is `None` (and cannot be extracted from a `mgmt:domain:key` composite ID) SHALL query strictly from local cache (`cache_mode="cache"`, `include_global=True`) and raise `AmbiguousObjectError` if more than one domain matches.

#### Scenario: Blank target identifier rejected immediately

- **WHEN** `client.find_object(mgmt_name, domain, "")` or `client.get_group_members(mgmt_name, domain, "   ")` is called with an empty or whitespace-only target string
- **THEN** the method SHALL raise `ValidationError` immediately without scanning cached or remote domains

#### Scenario: Cross-domain lookup runs cache-only with Global visibility and raises AmbiguousObjectError on multi-domain collision

- **WHEN** `await client.find_object(mgmt_name, None, name_or_uid)` or `await client.get_group_members(mgmt_name, None, group_name_or_uid)` is called without a domain
- **THEN** it SHALL search cached `arodonata_objects`, `arodonata_services`, and `arodonata_assets` across all cached domains including `"Global"` using `cache_mode="cache"` (triggering zero live domain logins or whole-MDS syncs), return the match when unique to a single domain, and raise `AmbiguousObjectError` listing the candidate domains and composite IDs when multiple domains match

### Requirement: Coordinator-Delegated Cold-Cache Rulebase Warming in Client Change Reports

`ArodonataClient.collect_change_report()` and `ArodonataClient.build_change_report()` SHALL wire cold-cache rulebase placement fallback through `ArodonataClient.refresh_rulebases(..., mode="smart")` so any rulebase cache population triggered during report generation obeys `DomainSyncCoordinator` distributed locks, dirty-session checks, and `DomainSyncState` stamps.

#### Scenario: Cold-cache report collection via ArodonataClient warms rulebase through coordinator

- **WHEN** `await client.collect_change_report(scopes)` processes a session with rule changes on a domain whose `arodonata_rulebase_*` cache is empty and no `OwnedSession` handled placement
- **THEN** `ArodonataClient` SHALL invoke `refresh_rulebases(mgmt_name=mgmt_name, domains=[domain_name], mode="smart")` via `DomainSyncCoordinator` rather than performing an unlocked direct `replace_domain_rulebase` write

### Requirement: Client Facade API Reference Introspection with Management Version Inference

`ArodonataClient` SHALL expose `api_reference` (`ApiReferenceEngine`) and convenience methods `search_api_commands(...)`, `describe_api_command(...)`, and `validate_api_payload(...)` that automatically infer the default target API `version` from the configured management server's `api_version` when `version=None` (using `mgmt_name` or the sole configured management server, and falling back to the index's `latest` version `"v2.2"` when no server version is configured).

#### Scenario: Client facade infers target API version from configured management server

- **WHEN** `client.describe_api_command("add-interface", mgmt_name="corp-mds")` is called with `version=None` on a client where `"corp-mds"` is configured with `api_version="1.9"`
- **THEN** `ArodonataClient` SHALL resolve `version="v1.9"` automatically from `"corp-mds"` settings and return the `v1.9`-filtered schema for `add-interface`

### Requirement: Gateway Topology and Candidate Discovery Facade Methods

`ArodonataClient` SHALL accept an optional `gateway_cli` (`GatewayCliPort` or async command callback) for SSH command execution on gateways, expose `topology_service` (`TopologyService`), and provide traced async facade methods `refresh_topology(..., gateways=..., collect_routes=...)`, `stream_refresh_topology(..., gateways=..., collect_routes=...)`, `collect_gateway_routes(..., cprid_script_mode=..., repository_script_name=..., repository_script_args_fn=...)`, `check_route_collection_script(...)`, `ensure_route_collection_script(...)`, `get_gateway_topology(...)`, `get_topology_diagnostics(...)`, `reconcile_gateway_topology(..., check_policy=...)`, `upsert_topology_annotations(...)`, `get_topology_annotations(...)`, `delete_topology_annotations(...)`, `export_topology_prefixes(...)`, and `find_affected_gateways(sources, destinations, ..., min_confidence=..., include_standby=..., include_policy_inferred=...)` returning typed Pydantic models.

#### Scenario: Consumer resolves affected gateways and policy packages via ArodonataClient

- **WHEN** a downstream consumer calls `await client.find_affected_gateways(sources=["10.1.1.10"], destinations=["10.2.2.20"], mgmt_name="mds1", include_policy_inferred=True, cache_mode="smart")`
- **THEN** `ArodonataClient` SHALL ensure the topology cache is synchronized according to `cache_mode` and return a ranked list of `AffectedGatewayCandidate` instances containing `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `installed_access_policy`, `policy_packages`, `access_layers`, `confidence`, `is_standby_path`, `confidence_factors`, `warnings`, and `matched_flows` (including `policy_inferred` matches when enabled)

#### Scenario: Host application injects SSH callback and reconciles gateway routes via ArodonataClient

- **WHEN** a host application initializes `ArodonataClient(settings, gateway_cli=ssh_exec_fn)` and calls `await client.collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateways=["gw-01"])` followed by `await client.reconcile_gateway_topology(mgmt_name="mds1", domain="Corp", gateways=["gw-01"], check_policy=True)`
- **THEN** `ArodonataClient` SHALL invoke `ssh_exec_fn` for `"gw-01"`, persist the parsed route intervals into `arodonata_gateway_topology`, and return a `TopologyReconciliationReport` detailing any discrepancies between SmartConsole topology, live routes, and gateway-targeted policy rules

#### Scenario: Pipelined collection in one domain runs concurrently with script provisioning in another domain

- **WHEN** a host application runs `collect_gateway_routes(mgmt_name="mds1", domain="DomainA", cprid_script_mode="repository")` concurrently with `ensure_route_collection_script("mds1", "DomainB")`
- **THEN** both operations SHALL maintain isolated session contexts without `WriteSession` `contextvars` bleed or cross-domain lock blocking, allowing route collection in `"DomainA"` to complete while `"DomainB"` provisions and publishes its repository script

### Requirement: Single-Flight Background Object and Service Cache Warm-Up

`ArodonataClient.start_object_cache_warmup()` SHALL coalesce concurrent in-flight background warm-up calls sharing the same `(mgmt_name, domains, types, include_global, include_services)` scope, handle background failures with SID-redacted structured logging without emitting unretrieved asyncio task warnings for fire-and-forget callers, and expose active/recent warm-up state via `get_warmup_status()`.

#### Scenario: Concurrent warm-up calls for the same domain coalesce into one task

- **WHEN** a host application invokes `client.start_object_cache_warmup(mgmt_name="mds1", domains=["Corp"], include_services=True)` multiple times while the initial warm-up task for `"Corp"` is still running
- **THEN** `start_object_cache_warmup` SHALL return the existing in-flight task rather than spawning duplicate concurrent `refresh_objects` / `refresh_services` runs, and `client.get_warmup_status(mgmt_name="mds1")` SHALL report `"Corp"` as `"running"` until completion

#### Scenario: Fire-and-forget warm-up failure logs redacted warning without unretrieved exception

- **WHEN** a caller schedules `client.start_object_cache_warmup(mgmt_name="mds1", domains=["UnreachableCMA"])` without awaiting the returned `asyncio.Task` and the background refresh raises an error
- **THEN** the client SHALL record the SID-redacted failure in `get_warmup_status()` and emit a structured warning log without producing an `"Task exception was never retrieved"` warning on garbage collection

### Requirement: Lightweight Package Catalog and Targeted Package Rulebase Facade Methods

`ArodonataClient` SHALL expose traced async facade methods `refresh_policy_packages(...)` and `refresh_package_rulebase(...)` in addition to `get_policy_packages(...)` and `get_package_rulebase(...)`, and SHALL forward `source_types` and `include_annotations` filtering parameters on `find_affected_gateways(...)`.

#### Scenario: Consumer refreshes single package access sections and static gateway candidates via facade

- **WHEN** a consumer calls `await client.get_policy_packages("mds1", "Corp", cache_mode="smart")`, `await client.get_package_rulebase("mds1", "Corp", "Corp_Pkg", rulebase_type="access", cache_mode="smart")`, and `await client.find_affected_gateways(sources, destinations, mgmt_name="mds1", source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)`
- **THEN** `ArodonataClient` SHALL return the domain's `PolicyPackageInfo` catalog, the numbered `PackageRulebase` for `"Corp_Pkg"`, and the static-only `AffectedGatewayCandidate` list without triggering full-domain NAT/HTTPS/Threat rulebase syncs or full-domain `show-hosts` downloads

### Requirement: Script Repository Read, Check, Ensure, and Delete Facade

`ArodonataClient` SHALL expose traced async methods `get_repository_script`, `list_repository_scripts`, `check_repository_script`, `ensure_repository_script`, and `delete_repository_script` using shared read-only sessions for reads/checks and isolated write sessions (omitting `"repository-script"` from `SessionOverlay`) only when creation, modification, or deletion is required.

#### Scenario: Read-only script check and zero-write fast path in ensure_repository_script

- **WHEN** `check_repository_script` or `ensure_repository_script(mgmt_name, "arodonata-collect-routes-v1", expected_body, domain="Corp")` runs while `"arodonata-collect-routes-v1"` already exists in `"Corp"` with matching normalized line endings (`\r\n` -> `\n`, stripped trailing whitespace) and matching any explicitly supplied metadata (`comments`, `color`, `tags`)
- **THEN** the inspection SHALL run strictly read-only over `sid_cache` (without opening a `WriteSession` or calling `publish`) and `ensure_repository_script` SHALL return `EnsureRepositoryScriptResult(action="unchanged")`

#### Scenario: Missing or outdated script created or updated without SessionOverlay pollution

- **WHEN** `ensure_repository_script(mgmt_name, script_name, script_body, domain="Corp")` runs while the script is absent, differs from `script_body`, or has mismatched explicit `comments`/`color`/`tags` (either standalone or inside an existing `WriteSession`)
- **THEN** standalone calls SHALL open an isolated `WriteSession`, execute `add-repository-script` or `set-repository-script`, publish and invalidate `"Corp"`, and return `action="created"` or `"updated"`, while active `WriteSession` calls SHALL reuse the caller's session without auto-publishing or polluting `SessionOverlay` object caches

#### Scenario: Permission error during script check or provisioning raises RepositoryScriptPermissionError

- **WHEN** a read-only or restricted administrator invokes `ensure_repository_script` or `delete_repository_script` in a domain lacking `manage-repository-scripts: write` or `publish-sessions` privileges
- **THEN** `ArodonataClient` SHALL discard any uncommitted session cleanly and raise `RepositoryScriptPermissionError` carrying `mgmt_name`, `domain_name`, `script_ref`, and `operation` without exposing `sid` or credentials

### Requirement: Universal Application-Agnostic Repository Script Execution Facade

`ArodonataClient` SHALL expose traced async `run_repository_script(mgmt_name, script_name_or_uid, targets, *, domain=None, args=None, comments=None, timeout=None, script_timeout=None)` sending `run-script` with `script-type="repository"` and caller-supplied `args` verbatim (`str`) or space-joined (`Sequence[str]`) over a dedicated non-read-only session (or active `WriteSession`) without `publish` or `discard`.

#### Scenario: Universal execution forwards application script name, targets, and args verbatim

- **WHEN** an external application invokes `await client.run_repository_script("mds1", "app-custom-diag", ["gw-01", "gw-02"], domain="Corp", args=["--mode", "fast"])` (or with `args="--mode fast"`)
- **THEN** `ArodonataClient` SHALL invoke `run-script` with `{"script-name": "app-custom-diag", "script-type": "repository", "targets": ["gw-01", "gw-02"], "args": "--mode fast"}` (omitting `"script"` and `"script-base64"`, or passing `"uid"` for UUID targets), poll `show-task`, Base64-decode per-target outputs into `RepositoryScriptExecutionOutcome`, and never inject route-collection or VSX logic

#### Scenario: Execution outside WriteSession uses a non-read-only session without publish or discard

- **WHEN** `run_repository_script` runs outside an active `WriteSession`
- **THEN** it SHALL authenticate a dedicated non-read-only session (`read_only=False`), execute `run-script` and `show-task`, log out cleanly without calling `publish` or `discard`, and never reuse `sid_cache`

#### Scenario: Missing script or read-only session denial maps to typed script exceptions

- **WHEN** Check Point rejects `run-script` because the named repository script does not exist in the domain or because the caller lacks `run-repository-script` (or authenticated with `read-only: true`)
- **THEN** `run_repository_script` SHALL raise `RepositoryScriptNotFoundError` or `RepositoryScriptPermissionError` respectively without falling back to inline `"one time"` script execution

### Requirement: Route-Collection Repository Script Convenience Helpers

`ArodonataClient` SHALL expose `check_route_collection_script` and `ensure_route_collection_script` helpers wrapping `check_repository_script` and `ensure_repository_script` with `settings.cprid_repository_script_name` (or an explicit `script_name` override) and the canonical route-collection repository script body.

#### Scenario: Host application checks and provisions the canonical route-collection script

- **WHEN** a host application calls `await client.check_route_collection_script("mds1", "Corp")` followed by `await client.ensure_route_collection_script("mds1", "Corp")`
- **THEN** `ArodonataClient` SHALL check and provision the canonical `arodonata-collect-routes-v1` script body in `"Corp"` using `settings.cprid_repository_script_name` (default `"arodonata-collect-routes-v1"`)
