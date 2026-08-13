# Examples

Narrated walkthroughs of the runnable scripts in the top-level
[`examples/`](https://github.com/chkp-antonr/arodonata/tree/master/examples)
directory. Each page below embeds the actual current script contents via
`pymdownx.snippets`, so what you read here always matches what's in the
repo.

| Page | Script | Covers |
|---|---|---|
| [Basic Queries](01-basic-queries.md) | `01_basic_queries.py` | Domains, gateways, hosts, networks |
| [Search](02-search.md) | `02_search.py` | Name-pattern search, IP lookup |
| [Gateway Relationships](03-gateway-relationships.md) | `03_gateway_relationships.py` | Cluster topology |
| [Smart Refresh](04-smart-refresh.md) | `04_smart_refresh.py` | Populating/refreshing the cache — run this first |
| [Rulebase Queries](05-rulebase-queries.md) | `05_rulebase_queries.py` | Access and NAT rules |
| [Idempotent CPCRUD](06-crud-operations.md) | `06_crud_operations.py` | Idempotent Policy-as-Code object & rule CRUD |
| [Inverse Templates](07-crud-inverse.md) | `07_crud_inverse.py` | Plan → apply → inverse → apply compensating-template round-trip |
| [Session Basics](07-session-basics.md) | `07_session_basics.py` | Raw session management: baseline, publish, revert |
| [OTel-Traced Smart Refresh](08-otel-smart-refresh.md) | `08_otel_smart_refresh.py` | Same as Smart Refresh, with OTel tracing + a per-span timing breakdown |

Run [Smart Refresh](04-smart-refresh.md) first against a fresh database —
every other example reads from a cache that needs to be populated first.
