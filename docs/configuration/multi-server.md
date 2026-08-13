# Multi-Server Setup

`ArodonataSettings.mgmt_names`, `mgmt_servers`, and `api_keys` are all
comma-separated strings matched **by position** — the Nth name corresponds
to the Nth server and the Nth key:

```bash
MGMT_NAMES=primary-mgmt,backup-mgmt
MGMT_SERVERS=192.168.10.10,192.168.10.11
API_KEY_VARS=PRIMARY_MGMT_KEY,BACKUP_MGMT_KEY

PRIMARY_MGMT_KEY=your-primary-api-key-here
BACKUP_MGMT_KEY=your-backup-api-key-here
```

`API_KEY_VARS` is a convention used in this project's own scripts (not a
`ArodonataSettings` field): it names the environment variables that hold the
*actual* keys, so the keys themselves can live in a separate, more tightly
permissioned file (e.g. `.env.secrets`) than the server topology
(`.env`/`.env.dev`). The calling application resolves `API_KEY_VARS` into
real values before constructing `ArodonataSettings(api_keys=...)`:

```python
import os

api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)

settings = ArodonataSettings(
    mgmt_names=os.getenv("MGMT_NAMES", ""),
    mgmt_servers=os.getenv("MGMT_SERVERS", ""),
    api_keys=api_keys,
)
```

Once configured, [`ArodonataClient.get_mgmt_names()`](../api/arodonata/api/client.md)
returns the configured server names, and every helper method accepts an
optional `mgmt_names=[...]` filter to scope a query to a subset of them —
see [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md) for how
domain resolution layers on top of this for MDM servers.
