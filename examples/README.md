# Arodonata Examples

Runnable scripts demonstrating common `ArodonataClient` usage, narrated in
detail at [docs/examples/](../docs/examples/index.md) on the documentation
site.

| Script | What it covers |
|---|---|
| `01_basic_queries.py` | Domains, gateways, hosts, networks |
| `02_search.py` | Name-pattern search, IP lookup |
| `03_gateway_relationships.py` | Cluster topology (parent/member gateways) |
| `04_smart_refresh.py` | Populating/refreshing the cache — **run this first** |
| `05_rulebase_queries.py` | Access and NAT rulebase queries |
| `06_crud_operations.py` | Idempotent Policy-as-Code CRUD via `client.cpcrud.apply()` — see [README_CRUD.md](README_CRUD.md) |
| `07_crud_inverse.py` | Plan → apply → inverse → apply compensating-template round-trip |
| `07_session_basics.py` | Raw session management: baseline, publish, revert |
| `08_otel_smart_refresh.py` | Same as `04`, but with OTel tracing + a per-span timing breakdown |

## Setup

```bash
uv sync --dev
cp .env.example .env  # then fill in DATABASE_URL, MGMT_NAMES, MGMT_SERVERS, API_KEY_VARS
uv run examples/04_smart_refresh.py   # populate the cache first
uv run examples/01_basic_queries.py
```
