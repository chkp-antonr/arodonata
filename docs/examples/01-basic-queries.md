# Basic Queries

Fetches domains, hosts, and networks with three of the `ArodonataClient` read helpers. They read through the cache in the default `cache_mode="smart"`, so a domain with nothing cached yet is loaded from the management server on first use (pass `cache_mode="cache"` for cache-only reads). Settings come from a bare `ArodonataSettings()`, which reads `MGMT_NAMES`, `MGMT_SERVERS` and `API_KEY_VARS` from the environment loaded out of `.env.lib`/`.env.secrets`.

```python title="examples/01_basic_queries.py"
--8<-- "examples/01_basic_queries.py"
```

Run it:

```bash
uv run examples/01_basic_queries.py
```
