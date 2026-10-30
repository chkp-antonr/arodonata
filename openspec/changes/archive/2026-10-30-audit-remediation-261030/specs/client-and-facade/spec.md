# Spec Delta

## MODIFIED Requirements

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

## ADDED Requirements

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
