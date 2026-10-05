# Architecture Overview

Arodonata uses a **ports-and-adapters** (hexagonal) architecture: business logic in `arodonata.core` never imports a database driver or an HTTP client directly — it depends on `Port` protocols ([`ApiPort`](../api/arodonata/ports/api_port.md), [`CachePort`](../api/arodonata/ports/cache_port.md)), and concrete `arodonata.adapters` implementations are wired in at construction time. `ArodonataClient` (`arodonata.api.client`) is the composition root: it takes the application's SQLAlchemy `AsyncEngine` and builds the concrete `asdk` and `cache` classes itself.

```mermaid
flowchart TB
    subgraph App["Client Application"]
        A[Owns SQLAlchemy AsyncEngine + config]
    end

    subgraph Core["Arodonata Core Framework"]
        direction LR
        Client["ArodonataClient<br/>(high-level facade)"]
        ASDK["AMgmtClient<br/>(low-level facade)"]
        Cache["CacheRepository /<br/>DatabaseManager"]
        Client --> Ports
        ASDK --> Ports
        Cache --> Ports
        Ports["ApiPort / CachePort"]
    end

    subgraph Infra["External Infrastructure"]
        direction LR
        PG[(PostgreSQL)]
        CP[Check Point API]
        Py[Pydantic v2 models]
    end

    App --> Core
    Ports --> PG
    Ports --> CP
    Ports --> Py
```

- **[Ports & Adapters](ports-and-adapters.md)** — the facade classes and how
  the port/adapter boundary is drawn.
- **[Caching & Sync](caching-and-sync.md)** — smart refresh, `show-changes`,
  and how the object cache stays fresh.
- **[Sessions & Multi-Domain](sessions-and-mdm.md)** — login/session
  lifecycle and MDM domain resolution.
