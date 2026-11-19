# Configuration and Settings Specification

## Purpose

Defines explicit, type-safe configuration resolution for Arodonata (`ArodonataSettings`) and its MCP server (`ArodonataMCPSettings`), supporting static API-key multi-server topologies, static credential authentication, and dynamic/deferred authentication without ever reading `.env` files implicitly inside the library.

## Requirements

### Requirement: Explicit Settings Precedence Without Implicit Dotenv Loading

**ID**: REQ-CONFIG-001\
**Intent**: Keep library configuration deterministic and predictable across working directories without hidden `.env` side effects.\
**Non-goals**: Standalone test harness `.env.test` loading (`REQ-ITEST-003`) or MCP token validation (`REQ-MCP-001`).

`ArodonataSettings` SHALL resolve configuration from explicit constructor keyword arguments over `os.environ` without reading `.env` files automatically, compute derived concurrency and route-limit defaults, and anchor default `tls_known_hosts_path` to `~/.config/arodonata/tls_known_hosts.json` rather than the working directory.

#### Scenario: SCN-CONFIG-001-1 — Constructor keyword overrides environment variable

- **GIVEN** `ARODONATA_CONCURRENT_LIMIT=4` is set in `os.environ`
- **WHEN** `ArodonataSettings` is instantiated with `concurrent_limit=8` (and without `domain_sync_concurrency`, `route_collect_concurrency`, or `max_routes_per_gateway` overrides)
- **THEN** `settings.concurrent_limit` SHALL equal `8`
- **AND** default `domain_sync_concurrency` SHALL be capped at `min(2, max(1, concurrent_limit - 1)) == 2` unless overridden via constructor or `ARODONATA_DOMAIN_SYNC_CONCURRENCY`
- **AND** default `route_collect_concurrency` SHALL be capped at `min(4, max(1, concurrent_limit // 2)) == 4` unless overridden via constructor or `ARODONATA_ROUTE_COLLECT_CONCURRENCY`
- **AND** default `max_routes_per_gateway` SHALL equal `50000` unless overridden via constructor or `ARODONATA_MAX_ROUTES_PER_GATEWAY`

#### Scenario: SCN-CONFIG-001-2 — Environment variable populates field by default

- **GIVEN** `ARODONATA_SESSION_TIMEOUT=900` is present in `os.environ`
- **WHEN** `ArodonataSettings()` is instantiated without keyword arguments
- **THEN** `settings.session_timeout` SHALL equal `900`

#### Scenario: SCN-CONFIG-001-3 — Default TLS known-hosts path is independent of working directory

- **GIVEN** different process working directories (`os.getcwd()`)
- **WHEN** `ArodonataSettings()` is instantiated without an explicit `tls_known_hosts_path`
- **THEN** `tls_known_hosts_path` SHALL resolve to the same absolute user-scoped path (`~/.config/arodonata/tls_known_hosts.json`) so changing `os.getcwd()` never resets TOFU trust state

### Requirement: Positional Multi-Server Topology Configuration

**ID**: REQ-CONFIG-002\
**Intent**: Support multi-server and MDSM topologies consistently via positional lists across both library and CLI entry points.\
**Non-goals**: Runtime CMA failover resolution (`REQ-SESS-001`).

The system SHALL support configuring multiple Check Point management servers via comma-separated `mgmt_names` and `mgmt_servers`, optionally paired by position with `api_keys` (or `API_KEY_VARS`), using a single consistent precedence order (`api_keys` keyword/env over `API_KEY_VARS`) across both library and CLI entry points.

#### Scenario: SCN-CONFIG-002-1 — Valid positional server and API key resolution via API_KEY_VARS

- **GIVEN** `MGMT_NAMES="mds1,sms2"`, `MGMT_SERVERS="10.0.0.1,10.0.0.2"`, `API_KEY_VARS="KEY_MDS1,KEY_MDS2"`, `KEY_MDS1="secret1"`, and `KEY_MDS2="secret2"`
- **WHEN** `ArodonataSettings()` resolves the multi-server registry
- **THEN** `mgmt_names` SHALL resolve to `["mds1", "sms2"]` and `mgmt_servers` to `["10.0.0.1", "10.0.0.2"]`
- **AND** `"mds1"` SHALL pair with `"secret1"` and `"sms2"` SHALL pair with `"secret2"`

#### Scenario: SCN-CONFIG-002-2 — Precedence of API_KEYS vs API_KEY_VARS in library vs MCP CLI

- **GIVEN** both `API_KEYS` and `API_KEY_VARS` are present in the environment
- **WHEN** configuration is loaded in library or MCP CLI mode
- **THEN** `ArodonataSettings` SHALL consistently prioritize explicit `API_KEYS` over `API_KEY_VARS` in both modes

#### Scenario: SCN-CONFIG-002-3 — Mismatched server and key counts

- **GIVEN** static API keys whose count disagrees with the number of entries in `mgmt_names` and `mgmt_servers`
- **WHEN** `ArodonataSettings` validates the server registry
- **THEN** validation SHALL raise `ConfigurationError` describing the count mismatch

### Requirement: Authentication Mode and Default Engine Resolution

**ID**: REQ-CONFIG-003\
**Intent**: Support static API keys, static credentials, and deferred dynamic auth uniformly with an auto-owned SQLite default when no engine is supplied.\
**Non-goals**: Runtime session caching and credential eviction (`REQ-SESS-002`, `REQ-SESS-003`).

The system SHALL resolve `auth_mode` to `"api_key"`, `"credential"`, or `"dynamic"` (deferred credentials when servers are configured without static keys or passwords), and SHALL default `engine=None` to an auto-owned in-memory SQLite engine (`sqlite+aiosqlite:///:memory:`) across all authentication modes.

#### Scenario: SCN-CONFIG-003-1 — Credential mode requires management server IP or topology

- **GIVEN** `username` and `password` without `mgmt_ip` or `mgmt_servers`
- **WHEN** settings initialization validates server endpoints
- **THEN** initialization SHALL raise `MissingConfigurationError` stating that a target management server address is required

#### Scenario: SCN-CONFIG-003-2 — Omitted engine auto-creates in-memory SQLite in any authentication mode

- **GIVEN** `"api_key"`, `"credential"`, or `"dynamic"` authentication mode
- **WHEN** `AMgmtClient` or `ArodonataClient` is initialized with `engine=None`
- **THEN** the client SHALL create and own an in-memory `sqlite+aiosqlite:///:memory:` engine
- **AND** `client.close()` SHALL dispose of that auto-created engine

#### Scenario: SCN-CONFIG-003-3 — Dynamic mode initializes cleanly without static credentials

- **GIVEN** `MGMT_NAMES="mds1"` and `MGMT_SERVERS="10.0.0.1"` without `api_keys` or `username`/`password`
- **WHEN** `ArodonataSettings()` initializes
- **THEN** `auth_mode` SHALL resolve to `"dynamic"` without raising `MissingConfigurationError`, deferring credentials to runtime `AuthContext` or `AuthProvider`

### Requirement: Separate Operational Timeout Budgets

**ID**: REQ-CONFIG-004\
**Intent**: Isolate connect, standard RPC, login, task-poll, and rate-limiter wait budgets so slow operations do not starve fast calls.\
**Non-goals**: Transport resend prohibition and phase classification (`REQ-TRANS-007`).

The configuration SHALL maintain distinct timeout settings for TCP/TLS connection establishment (`connect_timeout`, default 30s), standard API calls (`api_timeout`, default 120s), login attempts (`login_timeout`, default 120s), long-running server tasks (`task_timeout`, default 900s), and rate-limiter slot acquisition (`rate_limit_slot_timeout`, default 90s).

#### Scenario: SCN-CONFIG-004-1 — Default read timeout calculation on transport socket

- **GIVEN** an HTTP transport configured from `ArodonataSettings`
- **WHEN** TCP/TLS connects and executes calls with or without an explicit per-call budget
- **THEN** the TCP/TLS connect and handshake timeout SHALL equal `connect_timeout`
- **AND** calls with an explicit per-call budget SHALL use `budget + 5` seconds as the socket read timeout
- **AND** calls without an explicit per-call budget (such as `show-task` polls) SHALL use `max(api_timeout, login_timeout) + 5` seconds

### Requirement: CPRID Repository Script Execution Configuration

**ID**: REQ-CONFIG-005\
**Intent**: Configure repository-script execution mode and script naming cleanly while keeping inline execution as the backward-compatible default.\
**Non-goals**: Script provisioning and execution behavior on management servers (`REQ-CLIENT-010`, `REQ-TOPO-008`).

`ArodonataSettings` SHALL resolve `cprid_script_mode` (`"inline" | "repository" | "auto"`, default `"inline"`, env alias `ARODONATA_CPRID_SCRIPT_MODE`) and `cprid_repository_script_name` (default `"arodonata-collect-routes-v1"`, env alias `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME`, rejecting blank strings) from constructor arguments and `os.environ` without implicitly loading `.env` files.

#### Scenario: SCN-CONFIG-005-1 — Default mode preserves backward-compatible inline execution

- **WHEN** `ArodonataSettings()` is instantiated without `cprid_script_mode` or `cprid_repository_script_name` overrides
- **THEN** `cprid_script_mode` SHALL equal `"inline"`
- **AND** `cprid_repository_script_name` SHALL equal `"arodonata-collect-routes-v1"`

#### Scenario: SCN-CONFIG-005-2 — Constructor and environment overrides resolve repository mode settings

- **GIVEN** `ARODONATA_CPRID_SCRIPT_MODE="repository"` and `ARODONATA_CPRID_REPOSITORY_SCRIPT_NAME="custom-routes-script"` in `os.environ`
- **WHEN** `ArodonataSettings()` loads from env or receives `ArodonataSettings(cprid_script_mode="auto", cprid_repository_script_name="corp-routes")`
- **THEN** explicit constructor arguments SHALL override `os.environ` without reading `.env` files from disk

#### Scenario: SCN-CONFIG-005-3 — Invalid mode or blank repository script name rejected on settings initialization

- **WHEN** `ArodonataSettings` receives an unsupported `cprid_script_mode` (e.g., `"ssh-only"`) or a blank/whitespace-only `cprid_repository_script_name`
- **THEN** settings validation SHALL fail immediately with `ValidationError`

### Requirement: Environment-Backed CPCRUD Naming Profile Configuration

**ID**: REQ-CONFIG-006\
**Intent**: Allow operators to standardize CPCRUD auto-naming prefixes and suffixes via environment variables without passing overrides on every call.\
**Non-goals**: Shorthand parsing and conflict resolution logic (`REQ-CPCRUD-002`, `REQ-CPCRUD-003`).

`ArodonataSettings` SHALL resolve a default `cpcrud_naming_prefixes` profile from explicit constructor arguments and `ARODONATA_CPCRUD_*` (falling back to `CPCRUD_*`) environment variables without loading `.env` files implicitly, covering host, network, range, group, service, and application-site formatting options.

#### Scenario: SCN-CONFIG-006-1 — Environment variables populate CPCRUD naming profile defaults

- **GIVEN** `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"`, `ARODONATA_CPCRUD_RANGE_SEPARATOR="_"`, and `ARODONATA_CPCRUD_RANGE_COMPRESS_OCTETS="true"` in `os.environ`
- **AND** `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_GROUP=""`, `ARODONATA_CPCRUD_AUTO_NAME_SUFFIX_GROUP="_Grp"`, `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_APP_SITE="Site_"`, and `ARODONATA_CPCRUD_APP_SITE_WILDCARD_MARKER="_"` in `os.environ`
- **WHEN** `ArodonataSettings()` is instantiated
- **THEN** `settings.cpcrud_naming_prefixes` SHALL reflect those configured prefixes, suffixes, range separator, compression flag, and wildcard marker without reading `.env` files

#### Scenario: SCN-CONFIG-006-2 — Secondary CPCRUD environment aliases are accepted when ARODONATA_CPCRUD variables are absent

- **GIVEN** `CPCRUD_AUTO_NAME_PREFIX_RANGE="Range_"` and `CPCRUD_RANGE_COMPRESS_OCTETS="true"` in `os.environ` without `ARODONATA_CPCRUD_*` counterparts
- **WHEN** `ArodonataSettings()` is instantiated
- **THEN** `cpcrud_naming_prefixes` SHALL resolve those `CPCRUD_*` values as fallback defaults while prioritizing `ARODONATA_CPCRUD_*` and explicit constructor arguments

#### Scenario: SCN-CONFIG-006-3 — CPCRUDService planning uses ArodonataSettings naming profile by default

- **GIVEN** an `ArodonataClient` configured with `settings.cpcrud_naming_prefixes`
- **WHEN** `client.cpcrud.plan(template)` runs without an explicit `naming_prefixes` argument or template `naming_prefixes` block
- **THEN** `CPCRUDService.plan()` SHALL apply `settings.cpcrud_naming_prefixes` when auto-naming newly created objects and services

### Requirement: OpenTelemetry Module Span Gating Configuration

**ID**: REQ-CONFIG-007\
**Intent**: Allow selective OpenTelemetry span filtering by module prefix without clobbering a host application's existing telemetry configuration.\
**Non-goals**: Span attribute sanitization and secret redaction (`REQ-CLIENT-015`).

The system SHALL support hierarchical dotted-prefix span gating via `ARODONATA_TRACE_MODULES` (`trace_modules`) without owning or resetting the host application's global `TracerProvider` unless rules are explicitly configured.

#### Scenario: SCN-CONFIG-007-1 — Empty trace_modules preserves host tracing rules

- **WHEN** `ArodonataClient` is initialized with `trace_modules=""` (the default)
- **THEN** it SHALL preserve and never overwrite any existing process-global trace gating configuration set by the host application

#### Scenario: SCN-CONFIG-007-2 — Explicit trace_modules applies longest-prefix rules

- **WHEN** `ARODONATA_TRACE_MODULES="arodonata:on,arodonata.api.client:off"` is configured
- **THEN** `trace_modules_rules` SHALL parse into `{"arodonata": True, "arodonata.api.client": False}` and apply to `@traced` spans

### Requirement: Secret and Database Credential Masking in Settings Representations

**ID**: REQ-CONFIG-008\
**Intent**: Prevent accidental credential leakage when settings objects are logged, printed, or serialized.\
**Non-goals**: Runtime `sid` redaction in call results, spans, and reports (`REQ-CLIENT-015`, `REQ-CPCRUD-011`).

`ArodonataSettings` SHALL mask all secret fields (`password`, `api_key`, `api_keys`, `mcp_tokens`, and `database_url` credentials) across `repr()`, `str()`, `model_dump()`, and `model_dump_json()` unless an explicit secret getter is invoked internally.

#### Scenario: SCN-CONFIG-008-1 — Secrets and database URL passwords masked in repr and serialization

- **GIVEN** an `ArodonataSettings` instance configured with `password`, `api_keys`, or `database_url="postgresql+asyncpg://user:secretpass@db.internal:5432/app"`
- **WHEN** `repr(settings)`, `str(settings)`, `settings.model_dump()`, or `settings.model_dump_json()` is called
- **THEN** all passwords, API keys, and the password component of `database_url` SHALL be masked (`"***"`)
