# Spec Delta

## MODIFIED Requirements

### Requirement: Typed Read Facade and Domain Invalidation

**ID**: REQ-CLIENT-003\
**Intent**: Expose typed Pydantic v2 getters honoring isolated `WriteSession` overlays and immediate cache invalidation across injected or owned clients after publish.\
**Non-goals**: Low-level Check Point pagination (`REQ-TRANS-006`) or search query classification (`REQ-CACHE-013`).

`ArodonataClient` SHALL expose typed getters (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_address_ranges`, `get_dns_domains`, `get_groups`, `get_objects`, `get_services`, `get_object_by_uid`) with `cache_mode`/`cache_ttl`, scope `WriteSession` overlays by `(mgmt_name, domain, include_global)`, and invalidate domain freshness on `WriteSession` or `api_call` publish (including `DomainListRefreshTracker.invalidate(None)`).

#### Scenario: SCN-CLIENT-003-1 — Read helpers reflect active WriteSession overlay via contextvars

- **WHEN** `await client.get_hosts(mgmt_name, domain)` or `await client.get_services(mgmt_name, domain)` runs inside `async with client.write_session(mgmt_name, domain):` or for another domain / with `include_global=False`
- **THEN** the returned list SHALL include objects created or updated in that `WriteSession` only for matching `(mgmt_name, domain)` (and exclude Global overlays unless `include_global=True`) without mutating shared DB rows until `publish`

#### Scenario: SCN-CLIENT-003-2 — Publish via api_call invalidates domain freshness memos

- **WHEN** a `WriteSession` publishes (including with an injected external `AMgmtClient`) or `await client.api_call(mgmt_name, "publish", domain=domain)` succeeds, or `DomainListRefreshTracker.invalidate(None)` is called
- **THEN** `client.invalidate_domain(mgmt_name, domain)` SHALL execute automatically across coordinator scopes so the next `"smart"` or `"smart-fast"` read re-checks the domain head within `cache_ttl`, and `invalidate(None)` SHALL reset tracked domain-list memos cleanly

### Requirement: Entity Lookup, Group Expansion, and Composite Identifier Resolution

**ID**: REQ-CLIENT-005\
**Intent**: Allow consumers to locate and expand objects, services, groups, and cluster/VSX assets uniformly by UID, name, or composite ID with single-pass on-demand sync.\
**Non-goals**: Cross-domain disambiguation when `domain=None` (`REQ-CLIENT-006`).

`ArodonataClient.find_object()`, `ArodonataClient.get_group_members()`, `SearchService.search_objects()`, and `SearchService.query_objects()` SHALL resolve entities across `arodonata_objects`, `arodonata_services`, and `arodonata_assets` by UID, name, or composite ID, refreshing explicit non-default `obj_type` once in `smart`/`smart-fast`/`force` mode and isolating cluster members per domain.

#### Scenario: SCN-CLIENT-005-1 — find_object and get_group_members resolve across objects, services, and assets by UID, name, or composite ID

- **WHEN** `await client.find_object(mgmt_name, domain, name_or_uid, obj_type=..., cache_mode="smart" | "force")` or `await client.get_group_members(mgmt_name, domain, group_name_or_uid)` is called
- **AND** the target is a raw UID, object name, or composite ID (`"mds:General:hWebHost"`, `"mds:General:Cluster01"`, `"mds:VSX:VSX-Cluster-01"`)
- **THEN** `find_object` with explicit `domain` and non-default `obj_type` (e.g., `"application-site"`, `"service-other"`) SHALL refresh that type in `smart`/`smart-fast` mode and execute at most ONE refresh in `force` mode, returning `CPObject | CPService | Asset | None` with composite IDs
- **AND** `get_group_members` SHALL expand network groups, `service-group`, and domain-scoped cluster/VSX parent assets without wrong-domain member leakage or non-group shadowing

#### Scenario: SCN-CLIENT-005-2 — Structured query_objects and describe_objects expose composite ID fields

- **WHEN** `await client.describe_objects()` or `await client.query_objects(...)` is called
- **THEN** `describe_objects()` SHALL list `id`, `object_id`, `service_id`, `asset_id`, `parent_id`, and `parent_asset_id` among filterable fields
- **AND** `query_objects()` SHALL include those composite fields on returned items

### Requirement: Universal Application-Agnostic Repository Script Execution Facade

**ID**: REQ-CLIENT-012\
**Intent**: Allow downstream applications to run any pre-approved Check Point repository script via `run-script` with non-read-only sessions and full SID redaction.\
**Non-goals**: Route-collection fallback policies (`REQ-TOPO-008`) or inline one-time script execution.

`ArodonataClient` SHALL expose traced async `run_repository_script(mgmt_name, script_name_or_uid, targets, *, domain=None, args=None, comments=None, timeout=None, script_timeout=None)` executing `run-script` (`script-type="repository"`) over a dedicated non-read-only session (or active `WriteSession`) without `publish` or `discard`, redacting SIDs from all outputs and exception paths.

#### Scenario: SCN-CLIENT-012-1 — Universal execution forwards application script name, targets, and args verbatim

- **WHEN** `await client.run_repository_script("mds1", "app-custom-diag", ["gw-01", "gw-02"], domain="Corp", args=["--mode", "fast"])` (or `args="--mode fast"`) is called
- **THEN** `ArodonataClient` SHALL invoke `run-script` with `{"script-name": "app-custom-diag", "script-type": "repository", "targets": ["gw-01", "gw-02"], "args": "--mode fast"}` (omitting `"script"` and `"script-base64"`, or passing `"uid"` for UUID targets)
- **AND** it SHALL poll `show-task`, Base64-decode per-target outputs into `RepositoryScriptExecutionOutcome` with SID-redacted `stdout` and `status_description`, and inject zero route-collection or VSX logic

#### Scenario: SCN-CLIENT-012-2 — Execution outside WriteSession uses a non-read-only session without publish or discard

- **WHEN** `run_repository_script` runs outside an active `WriteSession`
- **THEN** it SHALL authenticate a dedicated non-read-only session (`read_only=False`), execute `run-script` and `show-task`, and log out cleanly without calling `publish` or `discard`
- **AND** it SHALL never reuse the shared read-only `arodonata_sid_cache` session

#### Scenario: SCN-CLIENT-012-3 — Missing script or read-only session denial maps to typed script exceptions

- **WHEN** Check Point rejects `run-script` because the script is absent or because the caller lacks `run-repository-script` (or authenticated with `read-only: true`), including inside an active `WriteSession` or exception containing a bare session SID
- **THEN** `run_repository_script` SHALL scrub all patterned and active/dedicated SIDs before raising `RepositoryScriptNotFoundError`, `RepositoryScriptPermissionError`, or other exceptions without falling back to inline `"one time"` script execution

### Requirement: Domain Events and Framework-Agnostic SSE Stream Adapter

**ID**: REQ-CLIENT-016\
**Intent**: Convert internal async `DomainEvent` generators (`SyncProgressEvent`, `CPCRUDEvent`, `StagedSessionEvent`) into standards-compliant Server-Sent Events cleanly.\
**Non-goals**: HTTP framework routing (Starlette/FastAPI `StreamingResponse` wiring belongs to host applications).

`arodonata.core.events` and `arodonata.adapters.sse` SHALL define typed Pydantic v2 `DomainEvent` subclasses (`SyncProgressEvent`, `CPCRUDEvent`, `StagedSessionEvent`) and convert async event streams via `to_sse_event()` and `stream_as_sse()` into `SSEEvent` payloads formatted as `event:` / `data:` / `id:` wire strings via `SSEEvent.encode()`.

#### Scenario: SCN-CLIENT-016-1 — Domain events serialize to SSEEvent and wire-formatted SSE chunks

- **WHEN** `to_sse_event(event)` or `stream_as_sse(events)` processes `SyncProgressEvent`, `CPCRUDEvent`, or `StagedSessionEvent` instances
- **THEN** `to_sse_event()` SHALL map `event.event_type` to `SSEEvent.event` and serialize `model_dump(mode="json")` into `SSEEvent.data`
- **AND** `SSEEvent.encode()` and `stream_as_sse()` SHALL emit wire-format `event:` / `data:` chunks terminated by blank lines without owning HTTP server state
