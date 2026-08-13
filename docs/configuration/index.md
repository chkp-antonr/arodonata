# Configuration Guide

All configuration is explicit: `arodonata` never reads a `.env` *file*
itself. The calling application resolves values (e.g. via `python-dotenv`)
and constructs a [`ArodonataSettings`](../api/arodonata/config/settings.md)
instance. `ArodonataSettings` is a pydantic-settings model, so **every**
field also accepts its environment variable directly (whatever the calling
application already has exported/loaded into `os.environ`) — `log_level`
isn't special in this regard, it's just one field among many.

## Settings reference

| Field | Type | Default | Description |
|---|---|---|---|
| `mgmt_names` | `str` | `""` | Comma-separated management server names. |
| `mgmt_servers` | `str` | `""` | Comma-separated management server IPs/hosts, matched by position to `mgmt_names`. |
| `api_keys` | `str` | `""` | Comma-separated **actual** API key values (not variable names), matched by position. |
| `username` | `str \| None` | `None` | Username for credential-based auth (alternative to `api_keys`). |
| `password` | `SecretStr \| None` | `None` | Password for credential-based auth. |
| `mgmt_ip` | `str \| None` | `None` | Required when `username`/`password` are set. |
| `session_expire_seconds` | `int` | see [`constants.py`](../api/arodonata/config/constants.md) | Cache freshness threshold in seconds. |
| `session_timeout` | `int` | see `constants.py` | Session timeout passed to the Check Point login API. |
| `concurrent_limit` | `int` (1-20) | see `constants.py` | Max concurrent API requests per server. |
| `api_timeout` | `int` | see `constants.py` | Per-request API timeout in seconds. |
| `login_retry_backoff` | `int` | see `constants.py` | Backoff (seconds) between login retries. |
| `login_max_retries` | `int` | see `constants.py` | Maximum login retry attempts. |
| `log_level` | `str` | `"INFO"` | Also settable via the `ARODONATA_LOG_LEVEL` environment variable. |
| `cpcrud_on_name_conflict` | `str` | `"update"` | Name conflict policy: `'update'` \| `'error'`. Settable via `ARODONATA_CPCRUD_ON_NAME_CONFLICT`. |
| `cpcrud_on_ip_conflict` | `str` | `"reuse"` | IP conflict policy: `'reuse'` \| `'error'` \| `'create_new'`. Settable via `ARODONATA_CPCRUD_ON_IP_CONFLICT`. |
| `cpcrud_auto_name_prefix_host` | `str` | `"Host_"` | Auto-generated name prefix for hosts on IP conflict (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST`). |
| `cpcrud_auto_name_prefix_network` | `str` | `"Net_"` | Auto-generated name prefix for networks on IP conflict (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK`). |
| `cpcrud_auto_name_prefix_range` | `str` | `"IPR_"` | Auto-generated name prefix for address ranges (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE`). |
| `cpcrud_auto_name_prefix_svc_tcp` | `str` | `"TCP_"` | Auto-generated name prefix for TCP services (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP`). |
| `cpcrud_auto_name_prefix_svc_udp` | `str` | `"UDP_"` | Auto-generated name prefix for UDP services (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP`). |
| `cpcrud_auto_name_prefix_svc_icmp` | `str` | `"ICMP_"` | Auto-generated name prefix for ICMP services (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP`). |
| `cpcrud_refresh_mode` | `str` | `"invalidate"` | Post-publish cache refresh: `'invalidate'` \| `'force'`. Settable via `ARODONATA_CPCRUD_REFRESH_MODE`. |
| `cpcrud_schema_path` | `str` | `""` | Optional override path to `checkpoint_ops_schema.json` (`ARODONATA_CPCRUD_SCHEMA_PATH`). |
| `trace_modules` | `str` | `""` | Comma-separated `module:on\|off` OTEL span gating, longest dotted-prefix match. Settable via `ARODONATA_TRACE_MODULES`. See [Tracing](#tracing) below. |

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

`DATABASE_URL` and `API_KEY_VARS` aren't `ArodonataSettings` fields — they're
this application-level convention for resolving *which* environment
variables hold the real secrets, described next in
[Multi-Server Setup](multi-server.md).

See [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md) for how
these settings affect login/session behavior.
