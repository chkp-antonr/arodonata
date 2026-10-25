# Spec Delta: Configuration and Settings

## MODIFIED Requirements

### Requirement: Explicit Settings Resolution Without Implicit File Loading

The library SHALL resolve configuration from explicit constructor keyword arguments and `os.environ` via `ArodonataSettings` (a `pydantic-settings` model), SHALL NOT read `.env` files automatically on import or instantiation, SHALL anchor default `tls_known_hosts_path` to a deterministic user-scoped directory (`~/.config/arodonata/tls_known_hosts.json`) rather than the current working directory, and SHALL mask all secret fields (`password`, `api_key`, `api_keys`, `mcp_tokens`, and credentials embedded in `database_url`) across `repr()`, `str()`, `model_dump()`, and `model_dump_json()`.

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
