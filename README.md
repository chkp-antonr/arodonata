# Arodonata v2

Async-first Python 3.13+ library, declarative Policy-as-Code (`CPCRUD`) engine, auditable change report generator, and Model Context Protocol (MCP) server for Check Point Security Management and Multi-Domain Security Management (MDSM).

> **Looking for Arodonata v1 (`1.16.0`)?**
> Legacy v1 remains available in this repository on branch [`master_v1`](https://github.com/chkp-antonr/arodonata/tree/master_v1) and tag [`v1.16.0`](https://github.com/chkp-antonr/arodonata/releases/tag/v1.16.0).

## Installation

### Arodonata v2 (PyPI / Default `master_v2`)

```bash
# Core SDK (SQLite cache included)
uv add arodonata
# or with optional extras (PostgreSQL, MCP server, OpenTelemetry):
uv add "arodonata[all]"
```

### Arodonata v1 (`1.16.0` from Git)

```bash
uv add "arodonata @ git+https://github.com/chkp-antonr/arodonata.git@v1.16.0"
# or track the v1 maintenance branch:
uv add "arodonata @ git+https://github.com/chkp-antonr/arodonata.git@master_v1"
```

## Quick Links

- **Runnable Examples (`examples/`)**: Progressive scripts (`01_basic_queries.py` through `12_mcp_embedded.py`) covering cache queries, search, gateway topology, smart/streaming sync, rulebases, sessions, `SessionOverlay`, CPCRUD, change reports, OpenTelemetry tracing, and embedded FastAPI MCP — see [examples/README.md](examples/README.md) and [examples/README_CRUD.md](examples/README_CRUD.md).
- **Architecture & Engineering Standards**: See [AGENTS.md](AGENTS.md) for Spec-Driven Development (`openspec/`), quality gates, and git workflow rules.

## Running Tests (`./pytest.sh`)

All test execution is unified through `./pytest.sh`:

```bash
# Fast offline unit tests (mandatory pre-PR quality gate; zero network access)
./pytest.sh
./pytest.sh unit

# Live Check Point MDSM/SMS integration buckets (require .env.test, .env.secrets, and .env.lab.<ARODONATA_LAB>)
./pytest.sh int-1      # Bucket 1: Auth, sessions, rate limiter, reads, search, rulebase & change-report reads
./pytest.sh int-2      # Bucket 2: Cache build, streaming sync events, and live CPCRUD (plan/apply/inverse)
./pytest.sh int-3      # Bucket 3: WriteSession overlay, publish, discard, revert, and login throttle recovery
./pytest.sh int-4      # Bucket 4: Multi-domain isolation (Domain4 vs Domain5 vs Global) & cache mode matrix
./pytest.sh int-5      # Bucket 5: Full rebuilds, 120-rule layer pagination, publish matrix, and session reports
./pytest.sh int-6      # Bucket 6: Bounded soak loop (repeated publish -> smart-fast -> revert cycles)
./pytest.sh int-7      # Bucket 7: Live MCP server and tool surface verification
./pytest.sh int-full   # All live integration buckets (b1..b7)
```
