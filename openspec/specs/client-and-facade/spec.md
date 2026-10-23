# Client Facade, Ports/Adapters, Helpers, and Telemetry Specification

## Purpose

Defines the primary composition root and developer facade (`ArodonataClient`), hexagonal architectural ports (`ApiPort`, `CachePort`) and adapters (`ASDKApiAdapter`, `PostgresCacheAdapter`), domain-organized helper functions (`arodonata.helpers`), and OpenTelemetry instrumentation (`telemetry.py`).

## Requirements

### Requirement: Hexagonal Composition Root and Lifecycle Management

`ArodonataClient` SHALL serve as the composition root wiring `ApiPort` (`ASDKApiAdapter`) and `CachePort` (`PostgresCacheAdapter`) into `CacheOrchestrationService`, managing background tasks (`schedule_startup_cleanup`, object cache warm-up), and cleaning up sessions and owned engines deterministically on `close()` / `__aexit__()`.

#### Scenario: Context manager initializes database and drains or cancels background work on close

- **WHEN** `async with ArodonataClient(...) as client:` enters and exits
- **THEN** `__aenter__` SHALL initialize the database schema and schedule startup session cleanup, and `__aexit__` (`close()`) SHALL cancel any running background object-cache warm-up tasks immediately, drain startup cleanup tasks up to the grace period, close the management client, and dispose of the SQLAlchemy engine ONLY if `client` auto-created it (`_owns_engine == True`)

#### Scenario: Automatic logout policy on client close

- **WHEN** `client.close(logout=None)` is called
- **THEN** the client SHALL automatically log out active Check Point sessions if it auto-created an in-memory database (`_owns_engine == True`), and preserve cached sessions in the database if an external persistent engine was provided

### Requirement: Typed Read Facade and Domain Invalidation

`ArodonataClient` SHALL expose typed async read helpers returning Pydantic v2 models (`get_domains`, `get_gateways`, `get_hosts`, `get_networks`, `get_groups`, `get_object_by_uid`, `get_access_rules`, `get_nat_rules`, `get_https_rules`, `get_threat_rules`) with per-call `cache_mode` and `cache_ttl` overrides, and invalidate cached freshness memos immediately whenever a publish occurs (`invalidate_domain`).

#### Scenario: Publish via api_call invalidates domain freshness memos

- **WHEN** `await client.api_call(mgmt_name, "publish", domain=domain)` succeeds
- **THEN** `client.invalidate_domain(mgmt_name, domain)` SHALL be invoked automatically so the next `smart` or `smart-fast` read re-checks the domain's published session head even within `cache_ttl`

### Requirement: User-Aware Domain Helper Functions

`arodonata.helpers` SHALL provide functional helpers for plugin and CLI consumers (`find_object`, `get_objects`, `get_group_members`, `get_gateways`, `refresh_assets`, `create_session`, `publish_session`, `discard_session`, `write_session`, `add_object`, `set_object`, `delete_object`) accepting an optional `UserContext` for audit logging.

#### Scenario: Context manager write_session publishes on success and discards on exception

- **WHEN** `async with write_session(client, mgmt_name, domain, ...)` is used
- **THEN** it SHALL open a session, auto-publish on clean exit (invalidating the domain cache memo), and automatically discard the session if an unhandled exception is raised inside the block

### Requirement: Provider-Agnostic OpenTelemetry Instrumentation and Secret Redaction

All major client, transport, login, lock, cache, and CPCRUD entry points SHALL be decorated with `@traced` and attach `arodonata.*`-namespaced span attributes (`span_attrs`) without ever recording credentials, API keys, or unredacted session SIDs.

#### Scenario: Span attributes omit None values and never expose secrets

- **WHEN** `span_attrs(**attrs)` is called inside a traced operation
- **THEN** non-`None` attributes SHALL be set on the current OpenTelemetry span under the `arodonata.<key>` namespace, operating as a zero-overhead no-op when no `TracerProvider` is configured by the host application
