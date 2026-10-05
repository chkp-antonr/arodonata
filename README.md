# Arodonata

<div align="center">

[![Python Version](https://img.shields.io/badge/Python-3.13+-F50057.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
<br/>
[![License](https://img.shields.io/badge/License-MIT-00E676.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
<br/>
[![Type Safety](https://img.shields.io/badge/Type%20Safety-Strict-2979FF.svg?style=for-the-badge)](https://mypy.readthedocs.io/)
<br/>
[![Async](https://img.shields.io/badge/Async-Ready-D500F9.svg?style=for-the-badge)](https://docs.python.org/3/library/asyncio.html)
<br/>
**A high-performance, async-first Python library for Check Point security management operations with intelligent database caching (PostgreSQL or SQLite) and automatic session handling.**

[Key Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Documentation](#-documentation)

</div>

---

## 🚀 Overview

**Arodonata** — *Async, Reliable Operations* — is a production-grade Python library designed to simplify, accelerate, and scale automation against Check Point Security Management Servers.

Standard Check Point API client scripts often struggle with connection overhead, rate limits, session expiration, and slow response times when dealing with tens of thousands of security objects. **Arodonata** solves these bottlenecks by wrapping operations in an async-first engine coupled with an intelligent database-backed cache layer.

### Why Arodonata?

* ⚡ **High-Concurrency Execution**: An `asyncio` API over the Check Point SDK, whose blocking calls run in worker threads, so many domains and servers are queried in parallel while a per-MDS-member `RateLimiter` (`concurrent_limit`, default 4) keeps each server within its limits.
* 🔐 **Zero-Config Session Handling**: Transparent authentication, session pooling, and auto-recovery/re-login if a session expires.
* 💾 **Intelligent DB Caching**: Fast local caching via SQLAlchemy on **PostgreSQL** (JSONB, recommended) or **SQLite**.
* 🔄 **Smart Refresh (`show-changes`)**: Avoid full cache rebuilds. The cache tracks and pulls only incremental modifications from Check Point management logs.
* 🛡️ **Strict Type-Safety**: 100% type hints validated with **Pydantic v2** models, catching structural errors before runtime.

---

## ✨ Key Features

| Feature | Description | Benefit |
| :--- | :--- | :--- |
| **Async Core** | `asyncio` API; the synchronous Check Point SDK runs in worker threads | Parallel work across domains and servers without blocking the event loop |
| **Session Cache** | Automatic database-backed session token persistence | Bypasses repetitive logins, preserving firewall resources |
| **Multi-Domain (MDM)** | Native domain resolution and context propagation | Operates across complex tenant environments seamlessly |
| **Rate Limiting** | Active per-MDS-member request gating and database locks | Prevents overloading firewalls during large-scale tasks |
| **SSE Event Streams** | Live Server-Sent Events for background refresh tasks | Real-time monitoring of sync status and progress bars |
| **MCP Server** | Streamable-HTTP MCP endpoint with the Check Point show_* tool surface | Lets Claude and other MCP clients query policy through the cache |

---

## 📦 Installation

Arodonata requires **Python 3.13+** and a database for caching: **PostgreSQL 12+** (recommended) or **SQLite**.

Choose the package extra that fits your project:

* **`arodonata`**: Core library for Python automation, scripts, and applications (high-performance async client, session pooling, database caching, and declarative CPCRUD engine).
* **`arodonata[mcp]`**: Core library + Model Context Protocol (MCP) server support, including the `arodonata-mcp` CLI executable and `arodonata.mcp` ASGI integration for FastAPI/Starlette.

### Adding to Your Project

#### With `uv` (Recommended)

```bash
# Core library
uv add arodonata

# OR with MCP server support
uv add "arodonata[mcp]"
```

#### With Standard `pip`

```bash
# Core library
pip install arodonata

# OR with MCP server support
pip install "arodonata[mcp]"
```

#### In `pyproject.toml`

```toml
[project]
dependencies = [
    # Core library for Check Point automation & caching:
    "arodonata>=1.14.0",

    # OR if you need the MCP server / embedded ASGI tools:
    # "arodonata[mcp]>=1.14.0",
]
```

#### In `requirements.txt`

```text
arodonata>=1.14.0
# or
arodonata[mcp]>=1.14.0
```

### Local Development / Contributing

```bash
git clone https://github.com/chkp-antonr/arodonata.git
cd arodonata
uv sync --all-extras --dev
```

---

## ⚡ Quick Start

### 1. Set Up Your Environment

Create a `.env` file containing your database cache connection details and Check Point server coordinates:

```bash
# Database Configuration (PostgreSQL with JSONB recommended)
DATABASE_URL=postgresql+asyncpg://cp_user:cp_password@localhost:5432/arodonata_cache

# Management Server Details (supports multiple servers)
MGMT_NAMES=primary-mgmt,backup-mgmt
MGMT_SERVERS=192.168.10.10,192.168.10.11
API_KEY_VARS=PRIMARY_MGMT_KEY,BACKUP_MGMT_KEY

# Secrets (resolved at runtime from environment / secrets manager)
PRIMARY_MGMT_KEY=your-primary-api-key-here
BACKUP_MGMT_KEY=your-backup-api-key-here
```

### 2. Using `arodonata` in Python Projects

Use `ArodonataClient` directly in your application. The calling application manages the database engine lifecycle and passes the engine into the client:

```python
import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from arodonata import ArodonataClient, ArodonataSettings

async def main():
    # 1. Resolve database URL & configuration settings
    database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = create_async_engine(database_url)
    
    # Reads MGMT_NAMES, MGMT_SERVERS and API_KEY_VARS from the process environment
    # (load your .env first, e.g. with python-dotenv); each variable named in
    # API_KEY_VARS holds the key of the server at the same position.
    settings = ArodonataSettings()

    # 2. Initialize the client
    client = ArodonataClient(engine=engine, settings=settings)

    try:
        # 3. Enter async context manager for automatic session management
        async with client:
            servers = client.get_mgmt_names()
            print(f"Connected to management nodes: {servers}")

            # Query hosts from the primary server (a live, paged API query)
            if servers:
                target_server = servers[0]
                print(f"Retrieving hosts from {target_server}...")
                
                result = await client.api_query(
                    mgmt_name=target_server,
                    command="show-hosts",
                    details_level="standard"
                )

                if result.success:
                    print(f"Successfully retrieved {result.total} hosts:")
                    for host in result.objects[:5]:
                        print(f"  • {host.get('name')} -> {host.get('ip-address')}")
                else:
                    print(f"API Error: {result.message}")

    finally:
        # 4. Clean up connection pools
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Using `arodonata[mcp]` in Projects

When installed with the `[mcp]` extra, Arodonata can expose Check Point management operations to AI assistants and LLM agents (Claude Code, Claude Desktop, Cursor, Antigravity) via the Model Context Protocol over streamable HTTP.

#### Pattern A: Standalone Team Server (`arodonata-mcp`)

Run a dedicated MCP server for your team:

```bash
# Install with mcp extra
uv pip install "arodonata[mcp]"

# Launch the streamable-HTTP server
arodonata-mcp --host 0.0.0.0 --port 8765
```

The CLI loads `.env.lib` and `.env.secrets`, resolves credentials via `API_KEY_VARS`, verifies bearer tokens (`ARODONATA_MCP_TOKEN_VARS`), and provides DNS-rebinding protection.

#### Pattern B: Embedded in FastAPI / ASGI Applications (`arodonata.mcp`)

Embed Arodonata's MCP server into an existing FastAPI or Starlette application, and register custom application-specific tools alongside Check Point tools:

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine
from arodonata import ArodonataClient, ArodonataSettings
from arodonata.mcp import ArodonataMCPSettings, create_asgi_app, create_mcp_server

# Build engine, client, and MCP settings
engine = create_async_engine(database_url)
client = ArodonataClient(engine=engine, settings=settings)
mcp_settings = ArodonataMCPSettings(port=8000, path="/mcp")

# Create the MCP server and add your own custom tools
mcp_server = create_mcp_server(client, mcp_settings, name="firewall-assistant")

@mcp_server.tool()
async def acme_change_ticket(rule_uid: str) -> dict[str, str]:
    """Look up an internal change ticket that introduced a rule."""
    return {"rule_uid": rule_uid, "ticket": "CHG-0001"}

# Create mountable ASGI app
mcp_app = create_asgi_app(client, mcp_settings, server=mcp_server)

# Mount inside your FastAPI app
app = FastAPI(lifespan=lifespan)
app.mount("/", mcp_app)
```

See [examples/09_mcp_embedded.py](examples/09_mcp_embedded.py) for the complete runnable example.

---

## 🏛 Architecture

Arodonata employs a structured **Ports and Adapters** (Hexagonal) architecture to separate the business models from infrastructure/database implementations.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Client Application                              │
│         (manages SQLAlchemy AsyncEngine & environment config)          │
├────────────────────────────────────────────────────────────────────────┤
│                       Arodonata Core Framework                         │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────┐ │
│  │       API Layer       │  │       ASDK Core       │  │ Cache Layer │ │
│  │                       │  │                       │  │             │ │
│  │    ArodonataClient    │  │      AMgmtClient      │  │ CacheRepo   │ │
│  │    (High-Level Facade)│  │   (Low-Level Facade)  │  │ DbManager   │ │
│  └───────────┬───────────┘  └───────────┬───────────┘  └──────┬──────┘ │
│              │                          │                     │        │
│              └──────────────────────────┼─────────────────────┘        │
│                                         ▼                              │
│                                 [ ApiPort / CachePort ]                │
├────────────────────────────────────────────────────────────────────────┤
│                         External Infrastructure                        │
│          ┌───────────────────┬───────────────────┬──────────────┐      │
│          │   PostgreSQL DB   │  Check Point API  │  Python env  │      │
│          │  (Cache Storage)  │  (Remote Server)  │ (Pydantic v2)│      │
│          └───────────────────┴───────────────────┴──────────────┘      │
└────────────────────────────────────────────────────────────────────────┘
```

* **API Facade (`ArodonataClient`)**: Main developer entry point. Integrates database caching, rate-limiting, and network calls transparently.
* **ASDK Core (`AMgmtClient`)**: Manages individual sessions, keeps SIDs alive, and maps requests to the official Check Point API.
* **Cache Engine (`CacheRepository`)**: Manages object serializations, handles TTL checking, and stores entities as JSON columns (JSONB on PostgreSQL, JSON on SQLite).

---

## 🤖 MCP Server

Arodonata can serve any MCP client (Claude Code, Claude Desktop, Cursor, Antigravity, or your own agents) over streamable HTTP, exposing the Check Point `show_*` tool surface answered directly from Arodonata's cache with automatic session handling and rate limiting.

### Tool Capabilities

* **Cached Queries**: `show_hosts`, `show_networks`, `show_groups`, `show_gateways_and_servers`, `show_domains`, `show_object`.
* **Rulebases**: `show_access_rulebase`, `show_nat_rulebase`, `show_https_rulebase`, `show_threat_rulebase` with formats: `markdown` (clean table), `model_friendly`, or `raw` JSON.
* **Native & Sync Operations**: `arodonata_init` (server & domain overview), `search_objects` (cross-domain search), `refresh_objects` (object cache re-sync, mode `skip`/`check`/`force`/`incremental`, default `force`), `refresh_rulebases`, and `api_call` (read-only by default, gated write mode).
* **Live Compatibility**: ~40 live tools mirroring `@chkp/quantum-management-mcp`.
* **Declarative CPCRUD (Opt-In)**: `cpcrud_validate`, `cpcrud_plan`, `cpcrud_apply` (dry-run by default), `cpcrud_inverse` for reversible Policy-as-Code changes.

### Running the Server

```bash
# 1. Install with MCP support
uv pip install "arodonata[mcp]"

# 2. Launch the team server
arodonata-mcp --host 0.0.0.0 --port 8765
```

### Client Setup

#### Claude Code

```bash
claude mcp add --transport http arodonata http://127.0.0.1:8765/mcp --header "Authorization: Bearer ${DEMO_MCP_TOKEN}"
```

#### Claude Desktop

In your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "arodonata": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_BEARER_TOKEN"
      }
    }
  }
}
```

For full documentation on authentication modes (`static` vs `host`), TLS deployment, embedding in your own FastAPI application, and environment variables, see [docs/mcp/index.md](docs/mcp/index.md).

---

## 📖 Documentation

Complete, searchable documentation is built with MkDocs and served locally or via static hosting:

* **[Getting Started](docs/getting-started/index.md)** – Installation, environment variables, and a minimal first script.
* **[Core Architecture](docs/architecture/index.md)** – Ports and adapters, caching/sync, sessions, and multi-domain resolution.
* **[Configuration Guide](docs/configuration/index.md)** – Every `ArodonataSettings` field and multi-server setup.
* **[MCP Server](docs/mcp/index.md)** – Standalone and embedded streamable-HTTP MCP server, authentication, and the tool list.
* **[API Reference](docs/api/)** – Generated reference for every public class and function in `arodonata`.
* **[Examples](docs/examples/index.md)** – Runnable, narrated scripts covering queries, search, refresh, and rulebases.

### Local Doc Server

Run the local server to explore the documentation offline:

```bash
uv run mkdocs serve
```

Then visit `http://localhost:8000` in your web browser.

---

## 🤝 Contributing

We welcome pull requests! To get set up for local development:

1. Clone the repository:

    ```bash
    git clone https://github.com/chkp-antonr/arodonata
    cd arodonata
    ```

2. Install dependencies:

    ```bash
    uv sync --all-extras --dev
    ```

3. Format and check code quality:

    ```bash
    uv run ruff check --fix
    uv run ruff format .
    uv run mypy src/arodonata
    ```

4. Run unit tests:

    ```bash
    uv run pytest
    ```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

*Copyright (c) 2024-2026 Anton Razumov (<arazumov@checkpoint.com>)*
