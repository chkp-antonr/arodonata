# Arodonata v2

Async-first Python 3.13+ library, declarative Policy-as-Code (`CPCRUD`) engine, auditable change report generator, and Model Context Protocol (MCP) server for Check Point Security Management and Multi-Domain Security Management (MDSM).

> **Looking for Arodonata v1 (`1.16.0`)?**
> Legacy v1 remains available in this repository on branch [`master_v1`](https://github.com/chkp-antonr/arodonata/tree/master_v1) and tag [`v1.16.0`](https://github.com/chkp-antonr/arodonata/releases/tag/v1.16.0). All new projects and integrations should target **Arodonata v2 (`master_v2`)**.

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

## Documentation, NotebookLM Bundles & Portable HTML

- **Full Documentation (`docs/`)**:
  - [Overview & Quickstart](docs/index.md)
  - [Capabilities & Downstream Integration Guide (`CAPABILITIES.md`)](docs/CAPABILITIES.md)
  - [Database Schema Reference (15 `arodonata_*` Tables)](docs/architecture/database-schema.md)
  - [Consolidated MCP Server & Tools](docs/mcp/index.md)
  - [Architecture Overview](docs/architecture/index.md) · [Caching & Sync](docs/architecture/caching-and-sync.md) · [Sessions & `SessionOverlay`](docs/architecture/sessions-and-mdm.md) · [CPCRUD Engine](docs/architecture/cpcrud.md)
  - [Configuration Reference](docs/configuration/index.md) · [Multi-Server Setup](docs/configuration/multi-server.md) · [TLS Verification](docs/configuration/tls-verification.md)
- **Portable Single-File HTML Documentation**:
  - [`docs/_html/arodonata-v2-docs.html`](docs/_html/arodonata-v2-docs.html) — standalone offline HTML file with dark/light theme toggle, sidebar navigation across all 32 documentation pages, and interactive pan/zoom pre-rendered SVG Mermaid diagrams.
- **NotebookLM / LLM Context Bundles (`docs-notebooklm/`)**:
  - [`01-guide-and-concepts.md`](docs-notebooklm/01-guide-and-concepts.md) — complete narrative architecture, database schema, MCP server, and user guides.
  - [`02-api-reference.md`](docs-notebooklm/02-api-reference.md) — full public API reference extracted directly from `src/arodonata` via AST.
  - [`03-examples-and-recipes.md`](docs-notebooklm/03-examples-and-recipes.md) — all 12 runnable examples (`01`..`12`) with inline source code.
  - [`04-capabilities-db-mcp-and-openspec.md`](docs-notebooklm/04-capabilities-db-mcp-and-openspec.md) — downstream integration guide, SQLModel table definitions (`tables.py`), MCP tool specs, and all 10 OpenSpec system specifications.
- **Runnable Examples (`examples/`)**: Progressive scripts (`01_basic_queries.py` through `12_mcp_embedded.py`) — see [examples/README.md](examples/README.md) and [examples/README_CRUD.md](examples/README_CRUD.md).
- **Engineering Standards**: See [AGENTS.md](AGENTS.md) for Spec-Driven Development (`openspec/`), quality gates, and git workflow rules.

### Rebuilding Documentation Artifacts

```bash
# 1. Regenerate NotebookLM bundles (docs-notebooklm/01..04.md) and build-docs staging bundle
uv run python docs/scripts/build_notebooklm_docs.py

# 2. Build standalone portable HTML via global build-docs
node ~/.claude/docs-build/build-docs.js docs/_build_bundle/arodonata-v2-docs --out docs/_html
rm -rf docs/_build_bundle

# 3. Preview or build MkDocs Material site (with auto-generated mkdocstrings API reference)
uv run mkdocs serve
uv run mkdocs build
```

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
