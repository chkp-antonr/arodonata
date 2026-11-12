# Spec Delta: Client Facade, Ports/Adapters, and Telemetry

## ADDED Requirements

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
