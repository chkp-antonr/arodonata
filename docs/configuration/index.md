# Configuration Guide

All configuration is explicit: `arodonata` never reads a `.env` *file*
itself. The calling application resolves values (e.g. via `python-dotenv`)
and constructs a [`ArodonataSettings`](../api/arodonata/config/settings.md)
instance. `ArodonataSettings` is a pydantic-settings model, so **every**
field also accepts its environment variable directly (whatever the calling
application already has exported/loaded into `os.environ`) — `log_level`
isn't special in this regard, it's just one field among many.

## Settings reference

Each field is read from the environment variable in the second column (case-insensitive) or passed as a constructor keyword under its field name; a constructor keyword wins over the environment. Numeric defaults come from [`constants.py`](../api/arodonata/config/constants.md).

| Field | Env var | Type | Default | Description |
|---|---|---|---|---|
| `mgmt_names` | `MGMT_NAMES` | `str` | `""` | Comma-separated management server names. |
| `mgmt_servers` | `MGMT_SERVERS` | `str` | `""` | Comma-separated management server IPs/hosts, matched by position to `mgmt_names`. |
| `api_keys` | `API_KEYS` (or `API_KEY_VARS`) | `SecretStr` | `""` | Comma-separated **actual** API key values (not variable names), matched by position. Without `api_keys=` or `API_KEYS`, the keys are resolved from `API_KEY_VARS`; see [API keys](#api-keys) below. |
| `username` | `ARODONATA_USERNAME` | `str \| None` | `None` | Username for credential-based auth (alternative to `api_keys`). |
| `password` | `ARODONATA_PASSWORD` | `SecretStr \| None` | `None` | Password for credential-based auth. |
| `mgmt_ip` | `ARODONATA_MGMT_IP` | `str \| None` | `None` | Required when `username`/`password` are set. |
| `session_expire_seconds` | `ARODONATA_SESSION_EXPIRE` | `int` | `3600` | Maximum age in seconds of a cached session SID that a login may reuse; an older one is dropped and a fresh login is made. |
| `session_timeout` | `ARODONATA_SESSION_TIMEOUT` | `int` | `600` | Session timeout passed to the Check Point login API. |
| `concurrent_limit` | `ARODONATA_CONCURRENT_LIMIT` | `int` (1-20) | `4` | Max concurrent API requests per MDS member (logins and calls; per server for a SmartCenter). A listing takes a slot per page and releases it between pages, and waiters are served in arrival order within one client, so a wait is about one page per caller queued ahead; a task wait (publish, revert) holds its slot until the task is done. One cache-refresh call starts at most `concurrent_limit − 1` (at least one) domain refreshes per member; overlapping calls, other processes and long tasks can still use every slot. |
| `rate_limit_slot_timeout` | `ARODONATA_RATE_LIMIT_SLOT_TIMEOUT` | `int` | `90` | Seconds a caller waits for a free concurrency slot before giving up. A task wait holds its slot for the whole task, so keep this generous. |
| `asset_refresh_concurrency` | `ARODONATA_ASSET_REFRESH_CONCURRENCY` | `int` (1-20) | `4` | Domains `build_refresh_assets_cache` collects at once, and management servers it prepares and collects MDS assets for at once; `1` runs them one after another. Events of domains collected at once interleave. `concurrent_limit` still bounds the requests in flight per MDS member. |
| `api_timeout` | `ARODONATA_API_TIMEOUT` | `int` | `120` | Per-request API timeout in seconds. |
| `task_timeout` | `ARODONATA_TASK_TIMEOUT` | `int` | `900` | Seconds to wait for a server-side task (publish, install-policy, assign-global-assignment, revert-to-revision) after the call that started it has returned. Separate from `api_timeout`, so a long task is not cut short by a budget sized for one round trip. |
| `login_timeout` | `ARODONATA_LOGIN_TIMEOUT` | `int` | `120` | Per-attempt login timeout in seconds, separate from `api_timeout`. |
| `connect_timeout` | `ARODONATA_CONNECT_TIMEOUT` | `int` | `30` | Seconds for TCP connect plus TLS handshake to a Check Point server. See [TLS Verification](tls-verification.md#timeouts). |
| `tls_trust` | `ARODONATA_TLS_TRUST` | `str` | `"tofu"` | Certificate trust mode: `'tofu'` \| `'pinned'` \| `'lab-memory'` (lab runs only). See [TLS Verification](tls-verification.md). |
| `tls_fingerprints` | `ARODONATA_TLS_FINGERPRINTS` | `str` | `""` | Comma-separated SHA-256 fingerprints trusted at any address, from `api fingerprint -f json`. |
| `tls_known_hosts_path` | `ARODONATA_TLS_KNOWN_HOSTS_PATH` | `str` | `""` | Trust store file; empty means `${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json`. |
| `login_throttle_window` | `ARODONATA_LOGIN_THROTTLE_WINDOW` | `int` | `70` | Seconds to wait for Check Point's login rate limit to clear before retrying a throttled login. |
| `login_max_wait` | `ARODONATA_LOGIN_MAX_WAIT` | `int` | `900` | Total seconds one login may spend waiting out Check Point's per-MDS login rate limit before failing; also the timeout for acquiring the per-domain login lock. |
| `login_retry_backoff` | `ARODONATA_LOGIN_BACKOFF` | `int` | `5` | Backoff (seconds) between login retries. |
| `login_max_retries` | `ARODONATA_LOGIN_RETRIES` | `int` | `8` | Maximum login retry attempts. |
| `warm_object_cache_on_first_use` | `ARODONATA_WARM_OBJECT_CACHE_ON_FIRST_USE` | `bool` | `True` | When `get_domains` finds a management server's object cache empty, load every domain's objects in the background (`get_domains` returns the domain list at once). Set `false` where a full background load (hours on a large MDS) is unwanted. |
| `log_level` | `ARODONATA_LOG_LEVEL` | `str` | `"INFO"` | Logging level. |
| `cpcrud_on_name_conflict` | `ARODONATA_CPCRUD_ON_NAME_CONFLICT` | `str` | `"update"` | Name conflict policy: `'update'` \| `'error'`. |
| `cpcrud_on_ip_conflict` | `ARODONATA_CPCRUD_ON_IP_CONFLICT` | `str` | `"reuse"` | IP conflict policy: `'reuse'` \| `'error'` \| `'create_new'`. |
| `cpcrud_auto_name_prefix_host` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST` | `str` | `"Host_"` | Auto-generated name prefix for hosts on IP conflict. |
| `cpcrud_auto_name_prefix_network` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK` | `str` | `"Net_"` | Auto-generated name prefix for networks on IP conflict. |
| `cpcrud_auto_name_prefix_range` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE` | `str` | `"IPR_"` | Auto-generated name prefix for address ranges. |
| `cpcrud_auto_name_prefix_svc_tcp` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP` | `str` | `"TCP_"` | Auto-generated name prefix for TCP services. |
| `cpcrud_auto_name_prefix_svc_udp` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP` | `str` | `"UDP_"` | Auto-generated name prefix for UDP services. |
| `cpcrud_auto_name_prefix_svc_icmp` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP` | `str` | `"ICMP_"` | Auto-generated name prefix for ICMP services. |
| `cpcrud_refresh_mode` | `ARODONATA_CPCRUD_REFRESH_MODE` | `str` | `"invalidate"` | Post-publish cache refresh: `'invalidate'` \| `'force'`. |
| `cpcrud_schema_path` | `ARODONATA_CPCRUD_SCHEMA_PATH` | `str` | `""` | Optional override path to a `checkpoint_ops_schema.json`; empty uses the schema shipped inside the package (`arodonata/cpcrud/checkpoint_ops_schema.json`). |
| `trace_modules` | `ARODONATA_TRACE_MODULES` | `str` | `""` | Comma-separated `module:on\|off` OTEL span gating, longest dotted-prefix match. See [Tracing](#tracing) below. |

### API keys

`api_keys` is resolved in this order: an explicit `ArodonataSettings(api_keys=...)`, then the `API_KEYS` environment variable (the actual key values), then `API_KEY_VARS`, a comma-separated list of environment variable *names* whose values are the keys, matched by position to `mgmt_names`. So a bare `ArodonataSettings()` with only `API_KEY_VARS` set resolves the keys itself, and the keys can live in a separate, more tightly permissioned file than the server topology; see [Multi-Server Setup](multi-server.md). `arodonata-mcp` reverses the order of the two environment variables: there `API_KEY_VARS` wins over `API_KEYS`.

### Tracing

arodonata emits OpenTelemetry spans when the host application configures a
`TracerProvider` (e.g. MMP via `arlogi.otel.setup_tracing()`). Without one,
spans are free no-ops. arodonata never configures a provider itself; standalone
users install `arodonata[otel]` and call `arlogi.otel.setup_tracing()` themselves.

| Variable | Default | Description |
| --- | --- | --- |
| `ARODONATA_TRACE_MODULES` | `""` (all on) | Comma-separated `module:on\|off` span gating, longest dotted-prefix match. Example: `arodonata:on,arodonata.api.client:off` |

## CPCRUD Policy Configuration

The CPCRUD engine options can be configured globally on `ArodonataSettings` or overridden per environment variable:

```bash
# Global conflict policies
ARODONATA_CPCRUD_ON_NAME_CONFLICT=update
ARODONATA_CPCRUD_ON_IP_CONFLICT=reuse

# Auto-naming prefixes for IP conflict resolution
ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST=Host_
ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK=Net_

# Schema override (optional)
ARODONATA_CPCRUD_SCHEMA_PATH=/path/to/custom_schema.json
```

## Authentication modes

`ArodonataSettings.auth_mode` resolves automatically:

- **`api_key`** (default) — set `api_keys` (and `mgmt_names`/`mgmt_servers`).
- **`credential`** — set both `username` and `password`; `mgmt_ip` then
  becomes required, and omitting it raises `MissingConfigurationError`.

## Minimal `.env` for local development

```bash
DATABASE_URL=postgresql+asyncpg://cp_user:cp_password@localhost:5432/arodonata_cache
MGMT_NAMES=primary-mgmt
MGMT_SERVERS=192.168.10.10
API_KEY_VARS=PRIMARY_MGMT_KEY
PRIMARY_MGMT_KEY=your-primary-api-key-here
```

`DATABASE_URL` isn't an `ArodonataSettings` field: it's the application-level convention for the cache database URL. `API_KEY_VARS` names *which* environment variables hold the real keys, and `ArodonataSettings` resolves it when no `API_KEYS` is set, as described in [API keys](#api-keys) above and in [Multi-Server Setup](multi-server.md).

See [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md) for how
these settings affect login/session behavior.
