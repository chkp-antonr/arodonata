# Getting Started

## Requirements

- Python 3.13+
- A PostgreSQL 12+ database for the cache layer

## Package Flavors

Arodonata is available in two installation configurations depending on your use case:

- **`arodonata`**: Core library containing the asynchronous Check Point client, session pooling, PostgreSQL caching, and declarative CPCRUD engine. Use this when writing Python scripts, backend services, or automation pipelines.
- **`arodonata[mcp]`**: Core library plus streamable-HTTP Model Context Protocol (MCP) server support, including the `arodonata-mcp` CLI daemon and the `arodonata.mcp` ASGI integration. Use this when connecting LLM agents (Claude Code, Claude Desktop, Cursor, Antigravity) to your firewalls or embedding MCP tools into a FastAPI application.

## Install

=== "uv (recommended)"

    ```bash
    # Install core library
    uv add arodonata

    # OR install with MCP server support
    uv add "arodonata[mcp]"
    ```

=== "pip"

    ```bash
    # Install core library
    pip install arodonata

    # OR install with MCP server support
    pip install "arodonata[mcp]"
    ```

=== "pyproject.toml"

    Add to your project's `pyproject.toml`:

    ```toml
    [project]
    dependencies = [
        # Core library:
        "arodonata>=1.11.0",

        # OR if you need the MCP server / embedded ASGI tools:
        # "arodonata[mcp]>=1.11.0",
    ]
    ```

=== "requirements.txt"

    ```text
    arodonata>=1.11.0
    # or
    arodonata[mcp]>=1.11.0
    ```

For local development against a clone of this repository:

```bash
git clone https://github.com/chkp-antonr/arodonata.git
cd arodonata
uv sync --dev
```

## Configure your environment

Arodonata does not read `.env` files itself — the calling application resolves
configuration (e.g. via `python-dotenv`) and passes explicit values into
[`ArodonataSettings`](../api/arodonata/config/settings.md).
The calling app owns the database engine lifecycle and passes the engine directly to
`ArodonataClient`. Typical `.env` for local development:

```bash
# Database cache
DATABASE_URL=postgresql+asyncpg://cp_user:cp_password@localhost:5432/arodonata_cache

# Management server details (comma-separated, matched by position)
MGMT_NAMES=primary-mgmt,backup-mgmt
MGMT_SERVERS=192.168.10.10,192.168.10.11
API_KEY_VARS=PRIMARY_MGMT_KEY,BACKUP_MGMT_KEY

# Secrets — the actual key values, referenced by the variable names above
PRIMARY_MGMT_KEY=your-primary-api-key-here
BACKUP_MGMT_KEY=your-backup-api-key-here
```

See the [Configuration Guide](../configuration/index.md) for every setting.

## Next step

Continue to [Your First Script](first-script.md) for a minimal end-to-end
example, or jump to [Examples](../examples/index.md) for more complete
scripts.
