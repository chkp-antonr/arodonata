# Configuration Overview

Arodonata v2 uses `ArodonataSettings` (`src/arodonata/core/config.py`) built on `pydantic-settings` for type-safe configuration resolution.

## Core Design Principles

1. **No Implicit `.env` Loading**: `ArodonataSettings` reads from explicit constructor keyword arguments and `os.environ` (`env_file=None`). Host applications and CLIs control when `.env` files are loaded.
2. **Automatic Secret Redaction**: `api_key`, `api_keys`, `password`, and `database_url` passwords are automatically masked (`"***REDACTED***"`) in `__repr__()`, `__str__()`, `model_dump()`, and `model_dump_json()`.
3. **Dual Alias Support**: Every setting supports both prefixed `ARODONATA_*` environment variables and legacy `MGMT_*` / unprefixed aliases.

## `ArodonataSettings` Reference

### Server Topology & Authentication

| Field | Env Variable(s) | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `mgmt_names` | `ARODONATA_MGMT_NAMES`, `MGMT_NAMES` | `list[str]` (CSV/JSON) | `[]` | Logical names of management servers (positional match with `mgmt_servers`) |
| `mgmt_servers` | `ARODONATA_MGMT_SERVERS`, `MGMT_SERVERS` | `list[str]` (CSV/JSON) | `[]` | Target `host`, `host:port`, or `[ipv6]:port` addresses |
| `api_keys` | `ARODONATA_API_KEYS`, `API_KEYS` | `list[str]` (CSV/JSON) | `[]` | Positional API keys for each server in `mgmt_servers` |
| `api_key_vars` | `ARODONATA_API_KEY_VARS`, `API_KEY_VARS` | `list[str]` (CSV/JSON) | `[]` | Names of environment variables holding each server's API key |
| `mgmt_name` | `ARODONATA_MGMT_NAME`, `MGMT_NAME` | `str \| None` | `None` | Single-server logical name convenience fallback |
| `mgmt_ip` | `ARODONATA_MGMT_IP`, `MGMT_IP` | `str \| None` | `None` | Single-server IP/hostname convenience fallback |
| `mgmt_port` | `ARODONATA_MGMT_PORT`, `MGMT_PORT` | `int` | `443` | Default HTTPS port when omitted in `mgmt_servers` |
| `api_key` | `ARODONATA_API_KEY`, `MGMT_API_KEY` | `str \| None` | `None` | Single-server API key fallback |
| `username` | `ARODONATA_USERNAME`, `MGMT_USER`, `MGMT_USERNAME` | `str \| None` | `None` | Administrator username for `"credential"` auth mode |
| `password` | `ARODONATA_PASSWORD`, `MGMT_PASSWORD` | `str \| None` | `None` | Administrator password for `"credential"` auth mode |
| `auth_mode` | `ARODONATA_AUTH_MODE` | `"api_key" \| "credential" \| "dynamic"` | Auto-inferred | Inferred from configured keys/credentials (`dynamic` when neither is static) |

### Timeouts, Concurrency & Rate Limiting

| Field | Env Variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `connect_timeout` | `ARODONATA_CONNECT_TIMEOUT` | `float` | `30.0` | TCP/TLS handshake timeout in seconds |
| `api_timeout` | `ARODONATA_API_TIMEOUT` | `float` | `120.0` | Per-request Management API timeout budget in seconds |
| `login_timeout` | `ARODONATA_LOGIN_TIMEOUT` | `float` | `120.0` | Timeout budget for `login` requests in seconds |
| `task_timeout` | `ARODONATA_TASK_TIMEOUT` | `float` | `900.0` | Maximum polling duration (`TaskWaiter`) for async tasks (`publish`, `show-changes`, `revert-to-revision`) |
| `rate_limit_slot_timeout` | `ARODONATA_RATE_LIMIT_SLOT_TIMEOUT` | `float` | `90.0` | Maximum wait time to acquire a per-MDS-member concurrency slot |
| `session_timeout` | `ARODONATA_SESSION_TIMEOUT` | `int` | `600` | Check Point server-side `session-timeout` requested on `login` (seconds) |
| `session_expire_seconds` | `ARODONATA_SESSION_EXPIRE_SECONDS` | `int` | `540` | Local TTL in `arodonata_sid_cache` before proactive keepalive/re-login |
| `concurrent_limit` | `ARODONATA_CONCURRENT_LIMIT` | `int` (`1..20`) | `4` | Max concurrent API requests per MDS member IP (`domain_sync_concurrency = max(1, concurrent_limit - 1)`) |
| `login_throttle_window` | `ARODONATA_LOGIN_THROTTLE_WINDOW` | `float` | `70.0` | Cooldown window (seconds) enforced by `LoginGate` when Check Point throttles logins |
| `login_max_wait` | `ARODONATA_LOGIN_MAX_WAIT` | `float` | `900.0` | Maximum total wait time across throttled login retries |

### Storage, Cache & Telemetry

| Field | Env Variable | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `database_url` | `ARODONATA_DATABASE_URL` | `str` | `"sqlite+aiosqlite:///:memory:"` | SQLAlchemy async database URL (`sqlite+aiosqlite:///...` or `postgresql+asyncpg://...`) |
| `sqlite_busy_timeout_ms` | `ARODONATA_SQLITE_BUSY_TIMEOUT_MS` | `int` | `30000` | SQLite `PRAGMA busy_timeout` in milliseconds (WAL mode enabled automatically on file DBs) |
| `cache_ttl` | `ARODONATA_CACHE_TTL` | `int` | `300` | Freshness window (seconds) before `"smart"` / `"smart-fast"` probes `show-last-published-session` |
| `domain_list_ttl` | `ARODONATA_DOMAIN_LIST_TTL` | `int` | `3600` | TTL (seconds) for cached MDSM `show-domains` topology (`arodonata_domains`) |
| `max_incremental_changes` | `ARODONATA_MAX_INCREMENTAL_CHANGES` | `int` | `500` | Threshold of `show-changes` entries above which `"smart-fast"` falls back to full type reload |
| `tls_trust` | `ARODONATA_TLS_TRUST` | `"pinned" \| "tofu" \| "lab-memory"` | `"tofu"` | TLS peer certificate verification mode |
| `tls_known_hosts_path` | `ARODONATA_TLS_KNOWN_HOSTS_PATH` | `str` | `~/.config/arodonata/tls_known_hosts.json` | Path to persistent `0600` JSON trust store |
| `tls_fingerprints` | `ARODONATA_TLS_FINGERPRINTS` | `str` | `""` | Comma-separated pinned SHA-256 certificate fingerprints (`host:port=SHA256:...` or bare hex) |
| `cpcrud_schema_path` | `ARODONATA_CPCRUD_SCHEMA_PATH` | `str \| None` | `None` | Optional path override for `checkpoint_ops_schema.json` |
| `trace_modules` | `ARODONATA_TRACE_MODULES` | `str` | `""` | OpenTelemetry module span gating rules (e.g. `"+arodonata.core,-arodonata.adapters.storage"`) |
