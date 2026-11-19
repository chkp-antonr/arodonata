# Client Facade, Ports/Adapters, and Telemetry Specification

## Purpose

Defines the primary composition root and unified developer facade (`ArodonataClient`), hexagonal architectural ports (`ApiPort`, `CachePort` composed of `DomainCachePort`, `SidCachePort`, `SyncStatePort`, `ObjectCachePort`, `ServiceCachePort`, `AssetCachePort`, `TopologyCachePort`, and `RulebaseCachePort`, plus `LockPort`, `AuthProvider`, `GatewayCliPort`, and `RulebaseRefreshPort`), adapters (`AMgmtClient`), shared core primitives and sentinel UIDs, `contextvars`-aware session and object mutation methods, gateway topology and repository script facades, change-report and API-reference integration, and provider-agnostic OpenTelemetry instrumentation (`@traced`, `span_attrs`).

## Requirements

### Requirement: Hexagonal Composition Root and Lifecycle Management

**ID**: REQ-CLIENT-001\
**Intent**: Provide a single client entry point that owns default SQLite lifecycle, drains background tasks, and cleans up sessions deterministically.\
**Non-goals**: Underlying SQL schema migration (`REQ-CACHE-001`) or transport TLS pinning (`REQ-TRANS-002`).

`ArodonataClient` SHALL serve as the unified composition root wiring `ApiPort` (`AMgmtClient`), `CachePort`, and `LockPort` into core domain services, defaulting `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) and cleaning up sessions, background tasks, and owned engines deterministically on `close()` / `__aexit__()`.

#### Scenario: SCN-CLIENT-001-1 — Context manager initializes database and drains or cancels background work on close

- **WHEN** `async with ArodonataClient(...) as client:` enters and exits
- **THEN** `__aenter__` SHALL initialize the cache schema (and schedule startup session cleanup if static credentials are present)
- **AND** `__aexit__` (`close()`) SHALL cancel running background warm-up tasks immediately, drain startup cleanup tasks up to the grace period, and close `AMgmtClient`
- **AND** it SHALL dispose of the SQLAlchemy engine ONLY if `client` auto-created it from `engine=None`

#### Scenario: SCN-CLIENT-001-2 — Automatic logout policy on client close

- **WHEN** `client.close(logout=None)` is called
- **THEN** the client SHALL automatically log out active Check Point sessions when it auto-created an in-memory engine (`engine=None`)
- **AND** it SHALL preserve cached read-only sessions in the database when an external persistent engine was supplied

### Requirement: Single-Flight Background Object and Service Cache Warm-Up

**ID**: REQ-CLIENT-002\
**Intent**: Warm domain object and service caches asynchronously without spawning duplicate tasks or leaking unhandled task exceptions.\
**Non-goals**: Foreground synchronous/streaming refresh coordination (`REQ-CACHE-004`, `REQ-CACHE-005`).

`ArodonataClient.start_object_cache_warmup()` SHALL coalesce concurrent in-flight background warm-up calls sharing the same 6-tuple flight key `(mgmt_name, domains, types, include_global, include_services, mode == "force")` (so `"force"` runs never coalesce with `"smart"`), handle failures with `sid`-redacted structured logging without unretrieved asyncio task warnings, and expose status via `get_warmup_status()`.

#### Scenario: SCN-CLIENT-002-1 — Concurrent warm-up calls for the same domain coalesce into one task

- **GIVEN** an in-flight warm-up task started for `(mgmt_name="mds1", domains=["Corp"], include_services=True)`
- **WHEN** `client.start_object_cache_warmup(mgmt_name="mds1", domains=["Corp"], include_services=True)` is called again while the first task is running
- **THEN** it SHALL return the existing in-flight task rather than spawning duplicate concurrent refreshes
- **AND** `client.get_warmup_status(mgmt_name="mds1")` SHALL report `"Corp"` as `"running"` until completion

#### Scenario: SCN-CLIENT-002-2 — Fire-and-forget warm-up failure logs redacted warning without unretrieved exception

- **GIVEN** a caller schedules `client.start_object_cache_warmup(mgmt_name="mds1", domains=["UnreachableCMA"])` without awaiting the returned `asyncio.Task`
- **WHEN** the background refresh raises an error
- **THEN** the client SHALL record the `sid`-redacted failure in `get_warmup_status()` and emit a structured `WARNING` log
- **AND** garbage collection SHALL produce zero `"Task exception was never retrieved"` warnings

### Requirement: Typed Read Facade and Domain Invalidation

**ID**: REQ-CLIENT-003\
**Intent**: Expose typed Pydantic v2 getters honoring `WriteSession` overlays and immediate cache invalidation after publish.\
**Non-goals**: Low-level Check Point pagination (`REQ-TRANS-006`) or search query classification (`REQ-CACHE-013`).

`ArodonataClient` SHALL expose typed getters (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_objects`, `get_services`, `get_object_by_uid`) with `cache_mode`/`cache_ttl`, snapshot rulebase getters (`get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules`), apply `WriteSession` overlays, and invalidate domain freshness on publish.

#### Scenario: SCN-CLIENT-003-1 — Read helpers reflect active WriteSession overlay via contextvars

- **WHEN** `await client.get_hosts(mgmt_name, domain)` or `await client.get_services(mgmt_name, domain)` runs inside `async with client.write_session(mgmt_name, domain):`
- **THEN** the returned list SHALL include objects created or updated in that `WriteSession` and exclude deleted objects
- **AND** shared database cache rows SHALL remain unmodified until `publish`

#### Scenario: SCN-CLIENT-003-2 — Publish via api_call invalidates domain freshness memos

- **WHEN** a `WriteSession` publishes or `await client.api_call(mgmt_name, "publish", domain=domain)` succeeds
- **THEN** `client.invalidate_domain(mgmt_name, domain)` SHALL be invoked automatically so the next `"smart"` or `"smart-fast"` read re-checks the domain head even within `cache_ttl`

### Requirement: Policy Package Catalog and Targeted Package Rulebase Facade Methods

**ID**: REQ-CLIENT-004\
**Intent**: Give SDK consumers fast targeted package and single-package rulebase access without full-domain scans.\
**Non-goals**: Cross-package full-domain `locate_rules` indexing (`REQ-RULE-003`, `REQ-RULE-004`).

`ArodonataClient` SHALL expose traced async facade methods `refresh_policy_packages(...)` and `refresh_package_rulebase(...)` in addition to `get_policy_packages(...)` and `get_package_rulebase(...)`, enabling targeted catalog and single-package rulebase queries without full-domain rulebase or bulk host scans.

#### Scenario: SCN-CLIENT-004-1 — Consumer refreshes policy packages and single package access sections via facade

- **WHEN** a consumer calls `await client.get_policy_packages("mds1", "Corp", cache_mode="smart")` and `await client.get_package_rulebase("mds1", "Corp", "Corp_Pkg", rulebase_type="access", cache_mode="smart")`
- **THEN** `ArodonataClient` SHALL return the domain's `PolicyPackageInfo` catalog and the numbered `PackageRulebase` for `"Corp_Pkg"`
- **AND** it SHALL execute zero full-domain NAT/HTTPS/Threat rulebase syncs or full-domain `show-hosts` downloads

### Requirement: Entity Lookup, Group Expansion, and Composite Identifier Resolution

**ID**: REQ-CLIENT-005\
**Intent**: Allow consumers to locate and expand objects, services, groups, and cluster/VSX assets uniformly by UID, name, or composite ID.\
**Non-goals**: Cross-domain disambiguation when `domain=None` (`REQ-CLIENT-006`).

`ArodonataClient.find_object()`, `ArodonataClient.get_group_members()`, `SearchService.search_objects()`, and `SearchService.query_objects()` SHALL resolve entities across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` by raw `name`/`uid`, UID composite `id` (`"{mgmt_name}:{domain_name}:{uid}"`), or human-readable composite IDs (`object_id`, `service_id`, `asset_id` formatted as `"{mgmt_name}:{domain_name}:{name}"`).

#### Scenario: SCN-CLIENT-005-1 — find_object and get_group_members resolve across objects, services, and assets by UID, name, or composite ID

- **WHEN** `await client.find_object(mgmt_name, domain, name_or_uid)` or `await client.get_group_members(mgmt_name, domain, group_name_or_uid)` is called
- **AND** the target is a raw UID, object name, or composite ID (`"mds:General:hWebHost"`, `"mds:General:Cluster01"`, `"mds:VSX:VSX-Cluster-01"`)
- **THEN** `find_object` SHALL look up the target across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` returning `CPObject | CPService | Asset | None` with composite IDs populated
- **AND** `get_group_members` SHALL expand direct and recursive members of a network group, `service-group`, or cluster/VSX parent asset (including cross-domain Virtual Systems) from cache

#### Scenario: SCN-CLIENT-005-2 — Structured query_objects and describe_objects expose composite ID fields

- **WHEN** `await client.describe_objects()` or `await client.query_objects(...)` is called
- **THEN** `describe_objects()` SHALL list `id`, `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id` among filterable fields
- **AND** `query_objects()` SHALL include those composite fields on returned items

### Requirement: Cache-Only Cross-Domain Entity Lookup and Ambiguity Refusal

**ID**: REQ-CLIENT-006\
**Intent**: Keep unqualified cross-domain lookups fast, strictly local to cache, and safe against multi-domain name collisions.\
**Non-goals**: Explicit-domain lookups (`REQ-CLIENT-005`).

`ArodonataClient.find_object()` and `ArodonataClient.get_group_members()` SHALL require a non-empty target (`ValidationError` on blank input); when `domain` is `None` (not a `mgmt:domain:key` composite ID), multi-domain MDS (`> 1` non-global cached domains) SHALL run strictly cache-only (`cache_mode="cache"`, `include_global=True`) while single-domain SMC or cold caches MAY probe `show-domains` when `cache_mode != "cache"`, raising `AmbiguousObjectError` on multi-domain collisions.

#### Scenario: SCN-CLIENT-006-1 — Blank target identifier rejected immediately

- **WHEN** `client.find_object(mgmt_name, domain, "")` or `client.get_group_members(mgmt_name, domain, "   ")` is called
- **THEN** the method SHALL raise `ValidationError` immediately without scanning cached or remote domains

#### Scenario: SCN-CLIENT-006-2 — Cross-domain lookup enforces MDS cache-only guard with Global visibility and raises AmbiguousObjectError on multi-domain collision

- **WHEN** `await client.find_object(mgmt_name, None, name_or_uid)` or `await client.get_group_members(mgmt_name, None, group_name_or_uid)` runs without a domain
- **THEN** on multi-domain MDS (`> 1` non-global cached domains), it SHALL search cached tables including `"Global"` (`cache_mode="cache"`) with zero remote logins or syncs (while single-domain SMC or cold caches MAY probe `show-domains` when `cache_mode != "cache"`)
- **AND** it SHALL return the match if unique to one domain, or raise `AmbiguousObjectError` listing candidate domains and composite IDs if multiple domains match

### Requirement: Context-Aware Write Sessions and Isolated Object Mutation Helpers

**ID**: REQ-CLIENT-007\
**Intent**: Guarantee atomic, isolated write sessions with read-your-own-writes overlays and automatic rollback on cancellation or error.\
**Non-goals**: Declarative multi-action CPCRUD plans (`REQ-CPCRUD-010`, `REQ-CPCRUD-011`).

`ArodonataClient` SHALL provide `contextvars`-aware session and mutation helpers (`write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`), auto-wrapping standalone mutations in an isolated write session, stripping secret fields from `SessionOverlay`, and redacting secrets in `ApiCallResult`.

#### Scenario: SCN-CLIENT-007-1 — Context manager write_session publishes on success and discards on exception

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_auth)` is entered
- **THEN** it SHALL open an isolated write session bound to `contextvars` so nested mutations and reads share its SID and `SessionOverlay`
- **AND** secret request keys (`one-time-password`, `shared-secret`, `password`, `api-key`) SHALL be stripped from cached `raw_data`
- **AND** clean exit SHALL auto-publish (discarding before logout if `publish` returns `success=False`), and any unhandled `BaseException` (including `asyncio.CancelledError`) SHALL shield `discard` and `logout_sid`

#### Scenario: SCN-CLIENT-007-2 — Standalone object mutation helpers never dirty the shared read-only SID cache

- **WHEN** `await client.add_object(...)`, `await client.set_object(...)`, or `await client.delete_object(...)` runs outside `write_session()` without an explicit `sid`
- **THEN** it SHALL execute inside a dedicated isolated session (never using the shared `arodonata_sid_cache` session)
- **AND** `ApiCallResult.__repr__()` SHALL redact `sid` and secret payload fields

### Requirement: Gateway Topology Synchronization, Route Collection, Reconciliation, and Annotation Facade

**ID**: REQ-CLIENT-008\
**Intent**: Expose gateway topology, live SSH/CPRID route collection, diagnostics, reconciliation, and IPAM exports directly on `ArodonataClient`.\
**Non-goals**: Detailed topology extraction and LPM matching rules (`REQ-TOPO-001`..`REQ-TOPO-018`).

`ArodonataClient` SHALL accept optional `gateway_cli` (`GatewayCliPort` or async callback), expose `topology_service`, and provide traced async methods (`refresh_topology`, `stream_refresh_topology`, `collect_gateway_routes`, `get_gateway_topology`, `get_topology_diagnostics`, `reconcile_gateway_topology`, `upsert_topology_annotations`, `get_topology_annotations`, `delete_topology_annotations`, `export_topology_prefixes`).

#### Scenario: SCN-CLIENT-008-1 — Host application injects SSH callback and reconciles gateway routes via ArodonataClient

- **GIVEN** `ArodonataClient(settings, gateway_cli=ssh_exec_fn)`
- **WHEN** the host calls `collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateways=["gw-01"])` and `reconcile_gateway_topology(mgmt_name="mds1", domain="Corp", gateways=["gw-01"], check_policy=True)`
- **THEN** `ArodonataClient` SHALL invoke `ssh_exec_fn` for `"gw-01"` and persist parsed routes into `arodonata_gateway_topology`
- **AND** it SHALL return a `TopologyReconciliationReport` detailing discrepancies across SmartConsole topology, live routes, and gateway-targeted policy rules

#### Scenario: SCN-CLIENT-008-2 — Pipelined collection in one domain runs concurrently with script provisioning in another domain

- **WHEN** `collect_gateway_routes(mgmt_name="mds1", domain="DomainA", cprid_script_mode="repository")` runs concurrently with `ensure_route_collection_script("mds1", "DomainB")`
- **THEN** both operations SHALL maintain isolated session contexts without `WriteSession` `contextvars` bleed or cross-domain lock blocking

#### Scenario: SCN-CLIENT-008-3 — Topology facade methods forward targeting, script override, annotation, and export parameters

- **WHEN** callers invoke `refresh_topology(..., gateways=..., collect_routes=...)`, `stream_refresh_topology(...)`, or `collect_gateway_routes(..., cprid_script_mode=..., repository_script_name=..., repository_script_args_fn=...)`
- **AND** callers invoke `get_gateway_topology(...)`, `get_topology_diagnostics(...)`, `reconcile_gateway_topology(..., check_policy=...)`, annotation helpers, or `export_topology_prefixes(...)`
- **THEN** `ArodonataClient` SHALL trace and forward all parameters to `topology_service` (`TopologyService`) and return the corresponding typed Pydantic models

### Requirement: Affected Gateway Candidate Discovery Facade

**ID**: REQ-CLIENT-009\
**Intent**: Provide a clean, traced client method for finding affected Check Point gateways and policy packages for traffic flows.\
**Non-goals**: Underlying LPM, confidence-delta, and policy-inference matching algorithms (`REQ-TOPO-011`..`REQ-TOPO-014`).

`ArodonataClient` SHALL expose traced async `find_affected_gateways(sources, destinations, ..., min_confidence=..., include_standby=..., include_policy_inferred=..., source_types=..., include_annotations=...)` delegating to `topology_service` and returning ranked `AffectedGatewayCandidate` Pydantic models.

#### Scenario: SCN-CLIENT-009-1 — Consumer resolves affected gateways and policy packages via ArodonataClient

- **WHEN** `await client.find_affected_gateways(sources=["10.1.1.10"], destinations=["10.2.2.20"], mgmt_name="mds1", include_policy_inferred=True, cache_mode="smart")` is called
- **THEN** `ArodonataClient` SHALL synchronize topology according to `cache_mode`
- **AND** it SHALL return ranked `AffectedGatewayCandidate` models with `mgmt_name`, `domain_name`, `gateway_id`, `gateway_asset_id`, `installed_access_policy`, `policy_packages`, and `access_layers`
- **AND** each candidate SHALL populate `confidence`, `is_standby_path`, `confidence_factors`, `warnings`, and `matched_flows`

#### Scenario: SCN-CLIENT-009-2 — Consumer filters affected gateway candidates to static topology sources without annotations

- **WHEN** `await client.find_affected_gateways(sources, destinations, mgmt_name="mds1", source_types=STATIC_TOPOLOGY_SOURCES, include_annotations=False)` is called
- **THEN** `ArodonataClient` SHALL return the static-only `AffectedGatewayCandidate` list without triggering full-domain NAT/HTTPS/Threat rulebase syncs or full-domain `show-hosts` downloads

### Requirement: Script Repository Read, Check, Ensure, and Delete Facade

**ID**: REQ-CLIENT-010\
**Intent**: Manage Check Point repository scripts idempotently across read-only checks and isolated write provisioning.\
**Non-goals**: Executing repository scripts against gateway targets (`REQ-CLIENT-012`) or route-script defaults (`REQ-CLIENT-011`).

`ArodonataClient` SHALL expose traced async methods `get_repository_script`, `list_repository_scripts`, `check_repository_script`, `ensure_repository_script`, and `delete_repository_script` using shared read-only sessions for reads/checks and isolated write sessions (omitting `"repository-script"` from `SessionOverlay`) only when creation, modification, or deletion is required.

#### Scenario: SCN-CLIENT-010-1 — Read-only script check and zero-write fast path in ensure_repository_script

- **GIVEN** `"arodonata-collect-routes-v1"` already exists in `"Corp"` with matching normalized line endings (`\r\n` -> `\n`, stripped trailing whitespace) and matching explicit metadata (`comments`, `color`, `tags`)
- **WHEN** `check_repository_script` or `ensure_repository_script(mgmt_name, "arodonata-collect-routes-v1", expected_body, domain="Corp")` runs
- **THEN** the inspection SHALL run strictly read-only over cached read-only sessions without opening a `WriteSession` or calling `publish`
- **AND** `ensure_repository_script` SHALL return `EnsureRepositoryScriptResult(action="unchanged")`

#### Scenario: SCN-CLIENT-010-2 — Missing or outdated script created or updated without SessionOverlay pollution

- **GIVEN** a repository script that is absent, differs in body, or has mismatched explicit `comments`/`color`/`tags`
- **WHEN** `ensure_repository_script(mgmt_name, script_name, script_body, domain="Corp")` runs standalone or inside an active `WriteSession`
- **THEN** standalone calls SHALL open an isolated `WriteSession`, execute `add-repository-script` or `set-repository-script`, publish and invalidate `"Corp"`, and return `action="created"` or `"updated"`
- **AND** active `WriteSession` calls SHALL reuse the caller's session without auto-publishing or polluting `SessionOverlay` object caches

#### Scenario: SCN-CLIENT-010-3 — Permission error during script check or provisioning raises RepositoryScriptPermissionError

- **GIVEN** an administrator lacking `manage-repository-scripts: write` or `publish-sessions` privileges
- **WHEN** `ensure_repository_script` or `delete_repository_script` is invoked
- **THEN** `ArodonataClient` SHALL discard any uncommitted session cleanly
- **AND** it SHALL raise `RepositoryScriptPermissionError` carrying `mgmt_name`, `domain_name`, `script_ref`, and `operation` without exposing `sid` or credentials

### Requirement: Route-Collection Repository Script Convenience Helpers

**ID**: REQ-CLIENT-011\
**Intent**: Standardize checking and provisioning the canonical route-collection script using configured settings defaults.\
**Non-goals**: Arbitrary custom script provisioning (`REQ-CLIENT-010`) or execution (`REQ-CLIENT-012`).

`ArodonataClient` SHALL expose `check_route_collection_script` and `ensure_route_collection_script` helpers wrapping `check_repository_script` and `ensure_repository_script` with `settings.cprid_repository_script_name` (or an explicit `script_name` override) and the canonical route-collection repository script body.

#### Scenario: SCN-CLIENT-011-1 — Host application checks and provisions the canonical route-collection script

- **WHEN** a host application calls `await client.check_route_collection_script("mds1", "Corp")` followed by `await client.ensure_route_collection_script("mds1", "Corp")`
- **THEN** `ArodonataClient` SHALL check and provision the canonical route-collection script body in `"Corp"` using `settings.cprid_repository_script_name` (default `"arodonata-collect-routes-v1"`)

### Requirement: Universal Application-Agnostic Repository Script Execution Facade

**ID**: REQ-CLIENT-012\
**Intent**: Allow downstream applications to run any pre-approved Check Point repository script via `run-script` with non-read-only sessions.\
**Non-goals**: Route-collection fallback policies (`REQ-TOPO-008`) or inline one-time script execution.

`ArodonataClient` SHALL expose traced async `run_repository_script(mgmt_name, script_name_or_uid, targets, *, domain=None, args=None, comments=None, timeout=None, script_timeout=None)` sending `run-script` with `script-type="repository"` and caller-supplied `args` verbatim (`str`) or space-joined (`Sequence[str]`) over a dedicated non-read-only session (or active `WriteSession`) without `publish` or `discard`.

#### Scenario: SCN-CLIENT-012-1 — Universal execution forwards application script name, targets, and args verbatim

- **WHEN** `await client.run_repository_script("mds1", "app-custom-diag", ["gw-01", "gw-02"], domain="Corp", args=["--mode", "fast"])` (or `args="--mode fast"`) is called
- **THEN** `ArodonataClient` SHALL invoke `run-script` with `{"script-name": "app-custom-diag", "script-type": "repository", "targets": ["gw-01", "gw-02"], "args": "--mode fast"}` (omitting `"script"` and `"script-base64"`, or passing `"uid"` for UUID targets)
- **AND** it SHALL poll `show-task`, Base64-decode per-target outputs into `RepositoryScriptExecutionOutcome`, and inject zero route-collection or VSX logic

#### Scenario: SCN-CLIENT-012-2 — Execution outside WriteSession uses a non-read-only session without publish or discard

- **WHEN** `run_repository_script` runs outside an active `WriteSession`
- **THEN** it SHALL authenticate a dedicated non-read-only session (`read_only=False`), execute `run-script` and `show-task`, and log out cleanly without calling `publish` or `discard`
- **AND** it SHALL never reuse the shared read-only `arodonata_sid_cache` session

#### Scenario: SCN-CLIENT-012-3 — Missing script or read-only session denial maps to typed script exceptions

- **WHEN** Check Point rejects `run-script` because the script is absent or because the caller lacks `run-repository-script` (or authenticated with `read-only: true`)
- **THEN** `run_repository_script` SHALL raise `RepositoryScriptNotFoundError` or `RepositoryScriptPermissionError` respectively without falling back to inline `"one time"` script execution

### Requirement: Coordinator-Delegated Cold-Cache Rulebase Warming in Client Change Reports

**ID**: REQ-CLIENT-013\
**Intent**: Route cold-cache rulebase warming during `ArodonataClient` change reports through `DomainSyncCoordinator` locks and sync stamps.\
**Non-goals**: Standalone `collect_change_report()` in-memory fallback (`REQ-REPORT-003`).

`ArodonataClient.collect_change_report()` and `ArodonataClient.build_change_report()` SHALL wire cold-cache rulebase placement fallback through `ArodonataClient.refresh_rulebases(..., mode="smart")` so any rulebase cache population triggered during report generation obeys `DomainSyncCoordinator` distributed locks, dirty-session checks, and `DomainSyncState` stamps.

#### Scenario: SCN-CLIENT-013-1 — Cold-cache report collection via ArodonataClient warms rulebase through coordinator

- **GIVEN** a session with rule changes on a domain whose `arodonata_rulebase_*` cache is empty and no `OwnedSession` handled placement
- **WHEN** `await client.collect_change_report(scopes)` runs
- **THEN** `ArodonataClient` SHALL invoke `refresh_rulebases(mgmt_name=mgmt_name, domains=[domain_name], mode="smart")` via `DomainSyncCoordinator` rather than performing an unlocked direct `replace_domain_rulebase` write

### Requirement: Client Facade API Reference Introspection with Management Version Inference

**ID**: REQ-CLIENT-014\
**Intent**: Infer target Check Point API versions automatically from configured management servers during API schema discovery and validation.\
**Non-goals**: Underlying offline API reference index behavior (`REQ-APIREF-001`..`REQ-APIREF-004`).

`ArodonataClient` SHALL expose `api_reference` (`ApiReferenceEngine`) and convenience methods `search_api_commands(...)`, `describe_api_command(...)`, and `validate_api_payload(...)`, automatically inferring target API `version` when `version=None` from `mgmt_name` (or the sole configured server's `api_version`), falling back to the index's `latest` version (`"v2.2"`).

#### Scenario: SCN-CLIENT-014-1 — Client facade infers target API version from configured management server

- **GIVEN** an `ArodonataClient` where `"corp-mds"` is configured with `api_version="1.9"`
- **WHEN** `client.describe_api_command("add-interface", mgmt_name="corp-mds")` is called with `version=None`
- **THEN** `ArodonataClient` SHALL resolve `version="v1.9"` automatically from `"corp-mds"` settings and return the `v1.9`-filtered schema for `add-interface`

### Requirement: Provider-Agnostic OpenTelemetry Instrumentation and Secret Redaction

**ID**: REQ-CLIENT-015\
**Intent**: Provide host-controlled OpenTelemetry tracing across client operations while ensuring secrets and SIDs never enter telemetry spans.\
**Non-goals**: `ARODONATA_TRACE_MODULES` settings parsing (`REQ-CONFIG-007`).

All major client, transport, login, lock, cache, and CPCRUD entry points SHALL be decorated with `@traced` and attach `arodonata.*`-namespaced span attributes (`span_attrs`) while recursively sanitizing mappings, nested lists/tuples, and chained exception causes (`__cause__` and `__context__`) so credentials, API keys, or unredacted session SIDs are never recorded.

#### Scenario: SCN-CLIENT-015-1 — Span attributes omit None values and never expose secrets

- **WHEN** `span_attrs(**attrs)` runs inside a `@traced` operation or an exception with a chained `__cause__` / `__context__` is recorded on a span
- **THEN** non-`None` attributes SHALL be recorded under `arodonata.<key>` with recursive secret and `sid` redaction across mappings, lists, and chained exception messages
- **AND** `@traced` and `span_attrs` SHALL operate as a zero-overhead no-op when no `TracerProvider` is configured by the host application

### Requirement: Domain Events and Framework-Agnostic SSE Stream Adapter

**ID**: REQ-CLIENT-016\
**Intent**: Convert internal async `DomainEvent` generators (`SyncProgressEvent`, `CPCRUDEvent`, `StagedSessionEvent`) into standards-compliant Server-Sent Events cleanly.\
**Non-goals**: HTTP framework routing (Starlette/FastAPI `StreamingResponse` wiring belongs to host applications).

`arodonata.core.events` and `arodonata.adapters.sse` SHALL define typed Pydantic v2 `DomainEvent` subclasses (`SyncProgressEvent`, `CPCRUDEvent`, `StagedSessionEvent`) and convert async event streams via `to_sse_event()` and `stream_as_sse()` into `SSEEvent` payloads formatted as `event:` / `data:` / `id:` wire strings.

#### Scenario: SCN-CLIENT-016-1 — Domain events serialize to SSEEvent and wire-formatted SSE chunks

- **WHEN** `to_sse_event(event)` or `stream_as_sse(events)` processes `SyncProgressEvent`, `CPCRUDEvent`, or `StagedSessionEvent` instances
- **THEN** `to_sse_event()` SHALL map `event.event_type` to `SSEEvent.event` and serialize `model_dump(mode="json")` into `SSEEvent.data`
- **AND** `SSEEvent.format()` / `stream_as_sse()` SHALL emit wire-format `event:` / `data:` chunks terminated by blank lines without owning HTTP server state

### Requirement: Extended Client Lifecycle, Streaming, Staged Session, and Service Properties Facade

**ID**: REQ-CLIENT-017\
**Intent**: Document and verify the full `ArodonataClient` facade surface so consumers rely on stable top-level methods and service accessors.\
**Non-goals**: Detailed semantics of underlying services covered in domain specs.

`ArodonataClient` SHALL expose full lifecycle, context, streaming, search, rulebase, reporting, staged-session, CLI, and API-reference methods alongside typed service properties (`db`, `cache`, `lock_port`, `api`, `amgmt`, `cpcrud`, `topology_service`, `script_service`, `api_reference`) delegating cleanly to their backing ports and domain services.

#### Scenario: SCN-CLIENT-017-1 — ArodonataClient exposes full public method and service-accessor contract

- **WHEN** a caller initializes `ArodonataClient` and inspects its service properties (`db`, `cache`, `lock_port`, `api`, `amgmt`, `cpcrud`, `topology_service`, `script_service`, `api_reference`)
- **AND** invokes `initialize()`, `user_context()`, `create_dedicated_session()`, `logout_sid()`, `invalidate_domain()`, `refresh_*`/`stream_refresh_*`, `search_objects()`, `get_cache_status()`, `get_layer_rulebase()`, `locate_rules()`, `filter_rulebase()`, `build_change_report_from_plan()`, `render_change_report()`, `publish_staged_session()`, `stream_publish_staged_session()`, `discard_staged_session()`, `set_gateway_cli()`, and `ensure_api_reference()`
- **THEN** all facade methods and service accessors SHALL resolve cleanly and delegate to their backing ports and services

### Requirement: Hexagonal Layer Boundaries, Segregated Cache Ports, and Shared Core Primitives

**ID**: REQ-CLIENT-018\
**Intent**: Enforce strict hexagonal import isolation, Interface Segregation on `CachePort`, and DRY core primitives and Check Point sentinel definitions.\
**Non-goals**: Behavioral changes to Management API pagination or cache schema migrations.

Hexagonal layers (`core`, `cpcrud`, `rulebase`, `reports`) SHALL obey AST-verified import boundaries, `CachePort` SHALL compose eight `@runtime_checkable` ISP sub-protocols matched to service consumers alongside `RulebaseRefreshPort`, and `arodonata.core.primitives` / `arodonata.core.models.sentinels` SHALL provide shared primitives and Check Point sentinel UIDs with backward-compatible re-exports.

#### Scenario: SCN-CLIENT-018-1 — Hexagonal layer import boundaries are enforced via AST across core, cpcrud, rulebase, and reports

- **WHEN** an AST boundary scan inspects every import statement (including relative, lazy, and `TYPE_CHECKING` imports) in `core`, `cpcrud`, `rulebase`, and `reports`
- **THEN** `core` SHALL have zero imports from `arodonata.adapters`, `arodonata.client`, `arodonata.mcp`, `arodonata.cpcrud`, `arodonata.reports`, `arodonata.rulebase`, `arodonata.testing`, `cpapi`, `aiohttp`, `sqlalchemy`, `sqlmodel`, `asyncpg`, or `aiosqlite`
- **AND** `cpcrud` SHALL not import `arodonata.adapters` or `arodonata.client`, `rulebase` SHALL not import `arodonata.cpcrud`, `arodonata.adapters`, or `arodonata.client`, and `reports` SHALL not import `arodonata.adapters`, `arodonata.client`, `arodonata.mcp`, or `arodonata.testing`

#### Scenario: SCN-CLIENT-018-2 — CachePort composes eight runtime-checkable ISP sub-protocols and RulebaseRefreshPort decouples TopologyService

- **WHEN** `SqlCacheAdapter`, `RulebaseRefreshService`, and narrowed service consumers (such as `AssetRefreshService`) are inspected at runtime
- **THEN** `SqlCacheAdapter` SHALL satisfy all eight `@runtime_checkable` sub-protocols (`DomainCachePort`, `SidCachePort`, `SyncStatePort`, `ObjectCachePort`, `ServiceCachePort`, `AssetCachePort`, `TopologyCachePort`, `RulebaseCachePort`) and `CachePort`
- **AND** `RulebaseRefreshService` SHALL satisfy `RulebaseRefreshPort`, consumers narrowed to a sub-protocol SHALL accept minimal sub-port doubles, and `TopologyService` constructed without `rulebase_refresh` SHALL log a warning and return cold package snapshots without failing

#### Scenario: SCN-CLIENT-018-3 — Canonical Check Point sentinels and core primitives resolve UID c476 as Policy Targets and preserve strict mask validation

- **WHEN** callers evaluate `arodonata.core.models.sentinels`, `arodonata.core.primitives`, legacy re-export paths, and strict CPCRUD `normalize_mask_length(..., strict=True)`
- **THEN** UID `6c488338-8eec-4103-ad21-cd461ac2c476` SHALL map strictly to `Policy Targets` (`type="Global"`) rather than `Drop`, and all moved helpers (`parse_cp_publish_timestamp`, `update_overlay_from_command`, `extract_policy_packages`, `PolicyPackageInfo`, sentinel normalizers) SHALL retain object identity at legacy import paths
- **AND** `mask_to_prefix_len` SHALL validate contiguous netmasks (accepting integral floats such as `24.0` and hostmasks only with `allow_hostmask=True`), while desired CPCRUD specs with invalid `mask_length4` or `subnet_mask` SHALL raise `ValidationError`
