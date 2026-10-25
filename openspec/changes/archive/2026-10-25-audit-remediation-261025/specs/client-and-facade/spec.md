# Spec Delta: Client Facade, Ports/Adapters, and Telemetry

## MODIFIED Requirements

### Requirement: User-Aware Domain Helper Functions

`ArodonataClient` SHALL provide built-in session and object mutation methods (`write_session`, `auth_context`, `add_object`, `set_object`, `delete_object`, `find_object`, `get_group_members`) that propagate `WriteSession`, `AuthContext`, and optional `UserContext` automatically via `contextvars`, auto-wrapping standalone `add_object`/`set_object`/`delete_object` calls outside a `write_session` in a dedicated isolated write session (or rejecting shared-SID execution), stripping secret request fields before updating `SessionOverlay`, and masking secrets in `ApiCallResult`.

#### Scenario: Context manager write_session publishes on success and discards on exception

- **WHEN** `async with client.write_session(mgmt_name, domain, auth=admin_auth)` is entered
- **THEN** it SHALL open an isolated write session, bind it to `contextvars` so nested mutations and reads use its SID and `SessionOverlay` (with secret request keys such as `one-time-password`, `shared-secret`, `password`, and `api-key` stripped from cached `raw_data`), auto-publish on clean exit (or discard before logout if `publish` returns `success=False`), and automatically shield `discard` and `logout_sid` on any unhandled `BaseException` (including `asyncio.CancelledError`)

#### Scenario: Standalone object mutation helpers never dirty the shared read-only SID cache

- **WHEN** `await client.add_object(...)`, `await client.set_object(...)`, or `await client.delete_object(...)` is called outside an active `async with client.write_session(...)` block and without an explicit `sid`
- **THEN** the helper SHALL execute inside a dedicated isolated session (never using the shared `arodonata_sid_cache` session) and `ApiCallResult.__repr__()` SHALL redact `sid` and secret payload fields

### Requirement: Provider-Agnostic OpenTelemetry Instrumentation and Secret Redaction

All major client, transport, login, lock, cache, and CPCRUD entry points SHALL be decorated with `@traced` and attach `arodonata.*`-namespaced span attributes (`span_attrs`) while recursively sanitizing mappings, nested lists/tuples, and chained exception causes (`__cause__` and `__context__`) so credentials, API keys, or unredacted session SIDs are never recorded.

#### Scenario: Span attributes omit None values and never expose secrets

- **WHEN** `span_attrs(**attrs)` is called inside a traced operation or an exception with a chained `__cause__` / `__context__` is recorded on a span
- **THEN** non-`None` attributes SHALL be set on the current OpenTelemetry span under the `arodonata.<key>` namespace with recursive secret/SID redaction applied to mappings, lists, and chained exception messages, operating as a zero-overhead no-op when no `TracerProvider` is configured by the host application
