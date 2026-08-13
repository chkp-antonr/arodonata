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
**A high-performance, async-first Python library for Check Point security management operations with intelligent PostgreSQL caching and automatic session handling.**

[Key Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Documentation](#-documentation)

</div>

---

## 🚀 Overview

**Arodonata** — *Async, Reliable Operations* — is a production-grade Python library designed to simplify, accelerate, and scale automation against Check Point Security Management Servers.

Standard Check Point API client scripts often struggle with connection overhead, rate limits, session expiration, and slow response times when dealing with tens of thousands of security objects. **Arodonata** solves these bottlenecks by wrapping operations in an async-first engine coupled with an intelligent database-backed cache layer.

### Why Arodonata?

* ⚡ **High-Concurrency Execution**: Fully asynchronous execution using `aiohttp` and `asyncio`, letting you execute thousands of queries simultaneously.
* 🔐 **Zero-Config Session Handling**: Transparent authentication, session pooling, and auto-recovery/re-login if a session expires.
* 💾 **Intelligent DB Caching**: Blazing-fast local caching powered by **PostgreSQL** (with JSONB support) and SQLAlchemy.
* 🔄 **Smart Refresh (`show-changes`)**: Avoid full cache rebuilds. The cache tracks and pulls only incremental modifications from Check Point management logs.
* 🛡️ **Strict Type-Safety**: 100% type hints validated with **Pydantic v2** models, catching structural errors before runtime.

---

## ✨ Key Features

| Feature | Description | Benefit |
| :--- | :--- | :--- |
| **Async Core** | Fully non-blocking network calls | Scales to enterprise deployments with zero thread overhead |
| **Session Cache** | Automatic database-backed session token persistence | Bypasses repetitive logins, preserving firewall resources |
| **Multi-Domain (MDM)** | Native domain resolution and context propagation | Operates across complex tenant environments seamlessly |
| **Rate Limiting** | Active per-server request gating and database locks | Prevents overloading firewalls during large-scale tasks |
| **SSE Event Streams** | Live Server-Sent Events for background refresh tasks | Real-time monitoring of sync status and progress bars |

---

## 📦 Installation

Arodonata requires **Python 3.13+** and a **PostgreSQL 12+** database for caching.

### Install with `uv` (Recommended)

```bash
# Install the core library
uv pip install arodonata

# Install with development tools
uv pip install -e ".[dev]"
```

### Install with Standard `pip`

```bash
pip install arodonata
```

---

## ⚡ Quick Start

### 1. Set Up Your Environment

Create a `.env` file containing your database cache connection details and Check Point server coordinates:

```bash
# Database Configuration
DATABASE_URL=postgresql+asyncpg://cp_user:cp_password@localhost:5432/arodonata_cache

# Management Server Details (supports multiple servers)
MGMT_NAMES=primary-mgmt,backup-mgmt
MGMT_SERVERS=192.168.10.10,192.168.10.11
API_KEY_VARS=PRIMARY_MGMT_KEY,BACKUP_MGMT_KEY

# Secrets (resolved at runtime)
PRIMARY_MGMT_KEY=your-primary-api-key-here
BACKUP_MGMT_KEY=your-backup-api-key-here
```

### 2. Write Your First Script

Using `arodonata` is straightforward. The application manages the database engine lifecycle and passes the engine directly to `ArodonataClient`:

```python
import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from arodonata import ArodonataClient, ArodonataSettings

async def main():
    # 1. Resolve database URL & configuration settings
    database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = create_async_engine(database_url)
    
    settings = ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt_srv"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=os.getenv("PRIMARY_MGMT_KEY", "mock-key"),
    )

    # 2. Initialize the client
    client = ArodonataClient(engine=engine, settings=settings)

    try:
        # 3. Enter async context manager for session management
        async with client:
            servers = client.get_mgmt_names()
            print(f"Connected to management nodes: {servers}")

            # Query hosts from the primary server
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
* **Cache Engine (`CacheRepository`)**: Manages object serializations, handles TTL checking, and stores entities as JSONB configurations in PostgreSQL.

---

## 📖 Documentation

Complete, searchable documentation is built with MkDocs and served locally or via static hosting:

* **[Getting Started](docs/getting-started/index.md)** – Installation, environment variables, and a minimal first script.
* **[Core Architecture](docs/architecture/index.md)** – Ports and adapters, caching/sync, sessions, and multi-domain resolution.
* **[Configuration Guide](docs/configuration/index.md)** – Every `ArodonataSettings` field and multi-server setup.
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
    uv sync --dev
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
