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

`API_KEY_VARS` names the environment variables that hold the *actual* keys, so the keys themselves can live in a separate, more tightly permissioned file (e.g. `.env.secrets`) than the server topology (`.env`/`.env.dev`). `ArodonataSettings` resolves it itself: once the environment above is loaded (e.g. by `python-dotenv`), a bare `ArodonataSettings()` picks up the names, the servers and the keys:

```python
settings = ArodonataSettings()  # MGMT_NAMES, MGMT_SERVERS, and the keys via API_KEY_VARS
```

`API_KEY_VARS` is only the fallback: an explicit `ArodonataSettings(api_keys=...)` or an `API_KEYS` environment variable (the key values themselves) wins over it. `arodonata-mcp` resolves `API_KEY_VARS` itself and gives it priority over `API_KEYS`; see [MCP Server](../mcp/index.md#standalone-server-for-a-team).

Once configured, [`ArodonataClient.get_mgmt_names()`](../api/arodonata/api/client.md) returns the configured server names. The fan-out getters (`get_domains`, `get_gateways`, `collect_gateways_and_servers`, `get_hosts`, `get_networks`, `get_groups`, `get_access_rules`/`get_nat_rules`/`get_https_rules`/`get_threat_rules`, `search_objects`, `refresh_objects`, `refresh_rulebases`) accept an optional `mgmt_names=[...]` filter to scope a query to a subset of them, and query every configured server without it. The single-server methods take one `mgmt_name` instead: `api_call`, `api_query` and `get_object_by_uid` require it, and `get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase` and `locate_rules` take `mgmt_name=None` to mean the first configured server — none of them fans out. See [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md) for how domain resolution layers on top of this for MDM servers.
