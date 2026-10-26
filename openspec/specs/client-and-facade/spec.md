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

`ArodonataClient` SHALL provide session and object mutation/lookup methods (`write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`) propagating `WriteSession`, `AuthContext`, and `UserContext` via `contextvars`, resolving `find_object` across cached `arodonata_objects` (`CPObject`), `arodonata_services` (`CPService`), and `arodonata_assets` (`Asset`) by UID, name, or composite identifier (`object_id`, `service_id`, `asset_id`, `id`), expanding `get_group_members` across network groups (`arodonata_objects`), service groups (`arodonata_services`), and cluster/VSX containers (`arodonata_assets`, including cross-domain Virtual Systems), auto-wrapping standalone object mutations in an isolated write session, stripping secret request fields from `SessionOverlay`, and masking secrets in `ApiCallResult`.

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
