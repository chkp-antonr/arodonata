# Configuration and Settings Specification

## Purpose

Defines explicit, type-safe configuration resolution for Arodonata (`ArodonataSettings`) and its MCP server (`ArodonataMCPSettings`), supporting static API-key multi-server topologies, static credential authentication, and dynamic/deferred authentication without ever reading `.env` files implicitly inside the library.

## Requirements

### Requirement: Explicit Settings Resolution Without Implicit File Loading

The library SHALL resolve configuration from explicit constructor keyword arguments and `os.environ` via `ArodonataSettings` without reading `.env` files automatically, anchor default `tls_known_hosts_path` to `~/.config/arodonata/tls_known_hosts.json` rather than the working directory, and mask all secret fields (`password`, `api_key`, `api_keys`, `mcp_tokens`, and `database_url` credentials) across `repr()`, `str()`, `model_dump()`, and `model_dump_json()`.

#### Scenario: Constructor keyword overrides environment variable

- **WHEN** `ArodonataSettings` is instantiated with a constructor keyword argument (e.g., `concurrent_limit=8`) while `ARODONATA_CONCURRENT_LIMIT=4` is set in `os.environ`
- **THEN** the resulting settings instance SHALL use `concurrent_limit == 8`

#### Scenario: Environment variable populates field by default

- **WHEN** `ArodonataSettings()` is instantiated without keyword arguments and `ARODONATA_SESSION_TIMEOUT=900` is present in `os.environ`
- **THEN** `settings.session_timeout` SHALL equal `900`

#### Scenario: Secrets and database URL passwords masked in repr and serialization

- **WHEN** `repr(settings)`, `settings.model_dump()`, or `settings.model_dump_json()` is called on an `ArodonataSettings` instance configured with `password`, `api_keys`, or `database_url="postgresql+asyncpg://user:secretpass@db.internal:5432/app"`
- **THEN** all passwords, API keys, and the password component of `database_url` SHALL be masked (`"***"`) unless an explicit secret getter is invoked internally

#### Scenario: Default TLS known-hosts path is independent of working directory

- **WHEN** `ArodonataSettings()` is instantiated without an explicit `tls_known_hosts_path` across different working directories
- **THEN** `tls_known_hosts_path` SHALL resolve to the same absolute user-scoped path (`~/.config/arodonata/tls_known_hosts.json`) so changing `os.getcwd()` never resets TOFU trust state

### Requirement: Positional Multi-Server Topology Configuration

The system SHALL support configuring multiple Check Point management servers via comma-separated `mgmt_names` and `mgmt_servers`, optionally paired by position with `api_keys` (or `API_KEY_VARS`), using a single consistent precedence order (`api_keys` keyword/env over `API_KEY_VARS`) across both library and CLI entry points.

#### Scenario: Valid positional server and API key resolution via API_KEY_VARS

- **WHEN** `MGMT_NAMES="mds1,sms2"`, `MGMT_SERVERS="10.0.0.1,10.0.0.2"`, and `API_KEY_VARS="KEY_MDS1,KEY_MDS2"` are set along with `KEY_MDS1="secret1"` and `KEY_MDS2="secret2"`
- **THEN** `ArodonataSettings` SHALL resolve `mgmt_names` to `["mds1", "sms2"]`, `mgmt_servers` to `["10.0.0.1", "10.0.0.2"]`, and pair `"mds1"` with `"secret1"` and `"sms2"` with `"secret2"`

#### Scenario: Precedence of API_KEYS vs API_KEY_VARS in library vs MCP CLI

- **WHEN** both `API_KEYS` and `API_KEY_VARS` are present in the environment
- **THEN** `ArodonataSettings` SHALL consistently prioritize explicit `API_KEYS` over `API_KEY_VARS` in both library and CLI modes

#### Scenario: Mismatched server and key counts

- **WHEN** static API keys are configured and the number of entries in `mgmt_names`, `mgmt_servers`, and resolved API keys do not match
- **THEN** server registry validation SHALL raise `ConfigurationError` describing the count mismatch

### Requirement: Authentication Mode and Default Engine Resolution

The system SHALL resolve `auth_mode` to `"api_key"`, `"credential"`, or `"dynamic"` (deferred credentials when servers are configured without static keys or passwords), and SHALL default `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) across all authentication modes.

#### Scenario: Credential mode requires management server IP or topology

- **WHEN** `username` and `password` are provided without `mgmt_ip` or `mgmt_servers`
- **THEN** initialization SHALL raise `MissingConfigurationError` stating that a target management server address is required

#### Scenario: Omitted engine auto-creates in-memory SQLite in any authentication mode

- **WHEN** `AMgmtClient` or `ArodonataClient` is initialized with `engine=None` in `"api_key"`, `"credential"`, or `"dynamic"` mode
- **THEN** the client SHALL automatically create and own an in-memory `sqlite+aiosqlite:///:memory:` engine and dispose of it upon `client.close()`

#### Scenario: Dynamic mode initializes cleanly without static credentials

- **WHEN** `MGMT_NAMES="mds1"` and `MGMT_SERVERS="10.0.0.1"` are configured without `api_keys` or `username`/`password`
- **THEN** `ArodonataSettings` SHALL resolve `auth_mode == "dynamic"` without raising `MissingConfigurationError`, deferring credential resolution to runtime `AuthContext` or `AuthProvider`

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
