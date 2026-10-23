# Configuration and Settings Specification

## Purpose

Defines explicit, type-safe configuration resolution for Arodonata (`ArodonataSettings`) and its MCP server (`ArodonataMCPSettings`), supporting both API-key multi-server topologies and single-server credential authentication, without ever reading `.env` files implicitly inside the library.

## Requirements

### Requirement: Explicit Settings Resolution Without Implicit File Loading

The library SHALL resolve configuration from explicit constructor keyword arguments and `os.environ` via `ArodonataSettings` (a `pydantic-settings` model) and SHALL NOT read `.env` files automatically on import or instantiation.

#### Scenario: Constructor keyword overrides environment variable

- **WHEN** `ArodonataSettings` is instantiated with a constructor keyword argument (e.g., `concurrent_limit=8`) while `ARODONATA_CONCURRENT_LIMIT=4` is set in `os.environ`
- **THEN** the resulting settings instance SHALL use `concurrent_limit == 8`

#### Scenario: Environment variable populates field by default

- **WHEN** `ArodonataSettings()` is instantiated without keyword arguments and `ARODONATA_SESSION_TIMEOUT=900` is present in `os.environ`
- **THEN** `settings.session_timeout` SHALL equal `900`

### Requirement: Positional Multi-Server Topology Configuration

The system SHALL support configuring multiple Check Point management servers via comma-separated `mgmt_names`, `mgmt_servers`, and `api_keys` (or `API_KEY_VARS`) matched by position.

#### Scenario: Valid positional server and API key resolution via API_KEY_VARS

- **WHEN** `MGMT_NAMES="mds1,sms2"`, `MGMT_SERVERS="10.0.0.1,10.0.0.2"`, and `API_KEY_VARS="KEY_MDS1,KEY_SMS2"` are set along with `KEY_MDS1="secret1"` and `KEY_SMS2="secret2"`
- **THEN** `ArodonataSettings` SHALL resolve `mgmt_names` to `["mds1", "sms2"]`, `mgmt_servers` to `["10.0.0.1", "10.0.0.2"]`, and pair `"mds1"` with `"secret1"` and `"sms2"` with `"secret2"`

#### Scenario: Precedence of API_KEYS vs API_KEY_VARS in library vs MCP CLI

- **WHEN** both `API_KEYS` and `API_KEY_VARS` are present in the environment
- **THEN** standard `ArodonataSettings()` SHALL prioritize `API_KEYS` over `API_KEY_VARS`, whereas the standalone `arodonata-mcp` CLI SHALL prioritize `API_KEY_VARS` over `API_KEYS`

#### Scenario: Mismatched server and key counts

- **WHEN** the number of entries in `mgmt_names`, `mgmt_servers`, and resolved API keys do not match
- **THEN** server registry validation SHALL raise `ConfigurationError` describing the count mismatch

### Requirement: Dual Authentication Mode Resolution

The system SHALL automatically resolve `auth_mode` to either `"api_key"` or `"credential"` based on provided credentials.

#### Scenario: Credential mode requires management IP

- **WHEN** `username` and `password` are provided without `mgmt_ip`
- **THEN** initialization SHALL raise `MissingConfigurationError` stating that `mgmt_ip` is required for credential-based authentication

#### Scenario: Credential mode auto-creates in-memory SQLite engine when engine is omitted

- **WHEN** `ArodonataClient(username="admin", password="secret", mgmt_ip="10.0.0.1")` is called with `engine=None`
- **THEN** the client SHALL automatically create and own an in-memory `sqlite+aiosqlite:///:memory:` engine and dispose of it upon `client.close()`

#### Scenario: API key mode requires explicit AsyncEngine

- **WHEN** `ArodonataClient(engine=None, settings=settings)` is called in `"api_key"` mode
- **THEN** initialization SHALL raise `MissingConfigurationError` requiring an explicit `AsyncEngine`

### Requirement: Separate Operational Timeout Budgets

The configuration SHALL maintain distinct timeout settings for TCP/TLS connection establishment (`connect_timeout`, default 30s), standard API calls (`api_timeout`, default 120s), login attempts (`login_timeout`, default 120s), long-running server tasks (`task_timeout`, default 900s), and rate-limiter slot acquisition (`rate_limit_slot_timeout`, default 90s).

#### Scenario: Default read timeout calculation on transport socket

- **WHEN** `ApiTransport` is configured from `ArodonataSettings`
- **THEN** the socket connect/handshake timeout SHALL be `connect_timeout`, a call with an explicit budget SHALL use `budget + 5` seconds as its socket read timeout, and calls without an explicit per-call budget (such as `show-task` polls) SHALL use `max(api_timeout, login_timeout) + 5` seconds

### Requirement: OpenTelemetry Module Span Gating Configuration

The system SHALL support hierarchical dotted-prefix span gating via `ARODONATA_TRACE_MODULES` (`trace_modules`) without owning or resetting the host application's global `TracerProvider` unless rules are explicitly configured.

#### Scenario: Empty trace_modules preserves host tracing rules

- **WHEN** `ArodonataClient` is initialized with `trace_modules=""` (the default)
- **THEN** it SHALL NOT call `set_trace_modules({})` or overwrite any existing process-global trace gating configuration set by the host application

#### Scenario: Explicit trace_modules applies longest-prefix rules

- **WHEN** `ARODONATA_TRACE_MODULES="arodonata:on,arodonata.api.client:off"` is configured
- **THEN** `trace_modules_rules` SHALL parse into `{"arodonata": True, "arodonata.api.client": False}` and apply to `@traced` spans
