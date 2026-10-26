# Getting Started

Arodonata v2 requires **Python 3.13+** and uses asynchronous I/O (`asyncio`, `aiohttp`, `SQLAlchemy 2.0+` async engine) across all operations.

## Installation

Install `arodonata` using `uv` (recommended) or `pip`:

```bash
# Core SDK (includes SQLite cache via aiosqlite, CPCRUD, rulebase, and change reports)
uv add arodonata

# Recommended: install with all optional extras (PostgreSQL asyncpg, MCP server, OpenTelemetry)
uv add "arodonata[all]"
```

### Optional Extras

You can install individual extras depending on your deployment environment:

| Extra | Command | Installed Packages | Purpose |
| --- | --- | --- | --- |
| `postgres` | `uv add "arodonata[postgres]"` | `asyncpg>=0.30.0` | PostgreSQL database cache & distributed locks |
| `mcp` | `uv add "arodonata[mcp]"` | `mcp>=1.2.0`, `starlette`, `uvicorn` | Standalone `arodonata-mcp` CLI and embeddable ASGI MCP server |
| `otel` | `uv add "arodonata[otel]"` | `arlogi[otel]>=0.1.0` | OpenTelemetry span export and structured trace correlation |
| `all` | `uv add "arodonata[all]"` | All of the above | Full production feature set |

## Minimal Environment Configuration

Arodonata never loads `.env` files implicitly on import; your application (or CLI) loads environment variables explicitly (for example via `python-dotenv` or container orchestration) or passes typed arguments to `ArodonataSettings`.

Create a `.env` file for a single management server or MDSM server:

```ini
# Management server topology
ARODONATA_MGMT_NAMES=mdsm-prod
ARODONATA_MGMT_SERVERS=192.0.2.10:443
ARODONATA_API_KEYS=your-checkpoint-api-key

# Persistent cache (SQLite file or PostgreSQL URL)
ARODONATA_DATABASE_URL=sqlite+aiosqlite:///./arodonata_cache.db
# Or PostgreSQL:
# ARODONATA_DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/arodonata

# TLS certificate verification mode: pinned | tofu | lab-memory
ARODONATA_TLS_TRUST=tofu
```

## Next Steps

1. **[Your First Script](first-script.md)** — Initialize `ArodonataClient`, query cached domains/objects/gateways, and use `WriteSession` with `SessionOverlay`.
2. **[CPCRUD Quickstart](cpcrud.md)** — Validate, plan, apply, and roll back declarative YAML/JSON policy templates.
3. **[MCP Server Guide](../mcp/index.md)** — Run `arodonata-mcp` or mount the consolidated MCP tool surface inside FastAPI.
