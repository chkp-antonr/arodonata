# Configuration Specification Delta

## ADDED Requirements

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

## MODIFIED Requirements

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

## REMOVED Requirements

### Requirement: Dual Authentication Mode Resolution

**Reason**: Replaced by `Authentication Mode and Default Engine Resolution` to support three authentication modes (`"api_key"`, `"credential"`, `"dynamic"`) and default `engine=None` to an auto-owned in-memory SQLite engine across all modes.

**Migration**: Pass `engine=None` for automatic in-memory SQLite or an explicit `AsyncEngine` for persistent storage; use `auth_mode="dynamic"` (by omitting static keys/passwords) when credentials are supplied per request via `AuthContext` or `AuthProvider`.
