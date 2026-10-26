# Arodonata v2

**Arodonata v2 (`2.0.0`)** is an async-first Python 3.13+ library, declarative Policy-as-Code (`CPCRUD`) engine, auditable change report generator, and Streamable-HTTP Model Context Protocol (MCP) server for Check Point Security Management and Multi-Domain Security Management (MDSM).

> **Looking for Arodonata v1 (`1.16.0`)?**
> Legacy v1 remains frozen in this repository on branch [`master_v1`](https://github.com/chkp-antonr/arodonata/tree/master_v1) and tag [`v1.16.0`](https://github.com/chkp-antonr/arodonata/releases/tag/v1.16.0). All new projects and downstream integrations should target **Arodonata v2**.

## Quickstart

```python
import asyncio
from arodonata import ArodonataClient


async def main() -> None:
    # Reads ARODONATA_* / MGMT_* environment variables and initializes SQLite/PostgreSQL cache
    async with ArodonataClient() as client:
        domains = await client.get_domains()
        print(f"Discovered {len(domains)} domains: {[d.name for d in domains]}")

        # Smart cache-first read across hosts in Domain4
        hosts = await client.get_hosts(domain="Domain4", cache_mode="smart")
        print(f"Domain4 has {len(hosts)} cached hosts")

        # Multi-term search with recursive parent group resolution
        search = await client.search_objects("10.1.10.50, *.internal.corp", max_depth=2)
        for obj in search.objects:
            print(f"Matched {obj.type} {obj.name} ({obj.uid}) in {obj.domain_name}")


asyncio.run(main())
```

## Core Capability Matrix

| Capability | Primary Entry Point | Description |
| --- | --- | --- |
| **Unified Async Facade** | `ArodonataClient` | Single composition root wiring transport, SQL cache, distributed locks, rulebase numbering, CPCRUD, and change reports |
| **Database-Backed Cache** | `DatabaseManager`, `SqlCacheAdapter` | 15 `arodonata_*`-prefixed SQLModel tables on PostgreSQL (`asyncpg`) or SQLite (`aiosqlite`) with SHA-256 auto-migration and cross-process locks |
| **Smart & Incremental Sync** | `refresh_objects`, `stream_refresh_*` | Four cache modes (`cache`, `smart`, `smart-fast`, `force`) with `show-changes` incremental diffs and parallel per-MDS-member execution |
| **Search & Aggregation** | `search_objects`, `query_objects` | IP/CIDR/range/wildcard/exact search with recursive group membership traversal and SQL-free cross-domain aggregation (`list`, `count`, `describe`) |
| **Rulebase Introspection** | `get_package_rulebase`, `filter_rulebase` | Normalized 6-table rulebase cache with exact SmartConsole hierarchical numbering (`1`, `2.1`, `3`), reverse UID lookup (`locate_rules`), and local filtering |
| **Session Isolation & Overlay** | `client.write_session(...)` | Shared read-only `arodonata_sid_cache` sessions vs isolated `WriteSession` with `contextvars`-scoped `SessionOverlay` (read-your-own-writes before publish) |
| **Declarative CPCRUD** | `client.cpcrud` (`CPCRUDService`) | Offline JSON Schema validation, `HybridStateReader`, two-axis conflict policies (`on_name_conflict` × `on_ip_conflict`), staleness guard (`DomainStamp`), and rollback (`inverse`) |
| **Auditable Change Reports** | `build_change_report` | Collects object and rule diffs across sessions or date ranges (`SessionScope`, `RangeScope`) and renders self-contained HTML, Markdown, and JSON |
| **Consolidated MCP Server** | `arodonata-mcp`, `create_mcp_server` | Streamable-HTTP MCP server exposing 13 cache-aligned core tools + 5 tamper-proof HMAC-signed CPCRUD tools for AI agents and FastAPI host apps |
| **Observability & Security** | `@traced`, `redact_sid`, `TrustPolicy` | Provider-agnostic OpenTelemetry spans (`arlogi[otel]`), TOFU/pinned TLS fingerprint verification, and automatic `sid`/secret redaction everywhere |

## Documentation Map

- **Getting Started**: [Installation & Overview](getting-started/index.md), [Your First Script](getting-started/first-script.md), and [CPCRUD Quickstart](getting-started/cpcrud.md).
- **Downstream Integration Contract**: [Capabilities & Integration Guide (`CAPABILITIES.md`)](CAPABILITIES.md) — mandatory reading for host applications (e.g., FPCR v2).
- **Architecture Deep Dives**:
  - [Architecture Overview](architecture/index.md) & [Hexagonal Ports & Adapters](architecture/ports-and-adapters.md)
  - [Database Schema Reference (15 `arodonata_*` Tables)](architecture/database-schema.md)
  - [Caching, Incremental Sync & Search](architecture/caching-and-sync.md)
  - [Sessions, MDSM & `SessionOverlay`](architecture/sessions-and-mdm.md)
  - [CPCRUD Engine Internals](architecture/cpcrud.md)
- **User Guides & MCP**:
  - [Declarative CPCRUD Operations](user-guide/cpcrud.md)
  - [Auditable Change Reports](user-guide/change-report.md)
  - [Model Context Protocol (MCP) Server & Consolidated Tool Surface](mcp/index.md)
- **Configuration**: [Environment Variables & Settings](configuration/index.md), [Multi-Server Topology](configuration/multi-server.md), and [TLS Verification (`pinned` / `tofu` / `lab-memory`)](configuration/tls-verification.md).
- **Examples (`01`..`12`)**: [Runnable Examples Catalog](examples/index.md).
- **Development**: [Testing & Quality Gates (`./pytest.sh`)](development/testing.md) and [Changelog](CHANGELOG.md).
