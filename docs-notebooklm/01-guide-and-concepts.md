# Arodonata — Concepts & Guide

This document is a consolidated guide to the Arodonata library: what it does, how it's built, how to configure it, and how to use its main features. It's one of three companion documents (Guide, API Reference, Examples) meant to be uploaded together to an AI document-chat tool so you can ask questions like "which function do I use to fetch a host object?" or "how do I set up multi-server config?" and get grounded answers.


---

## Overview

*(source: `docs/index.md`)*

# Arodonata

**A high-performance, async-first Python library for Check Point security
management operations with intelligent PostgreSQL caching and automatic
session handling.**

Arodonata wraps the Check Point Management API in an async engine backed by a
database cache layer, so scripts that would otherwise re-authenticate and
re-query thousands of objects on every run instead read from a fast local
cache and only pull incremental changes.

## Where to start

<div class="grid cards" markdown>

- **[Getting Started](getting-started/index.md)**
  Install the library, configure your `.env`, and run your first script.

- **[Core Architecture](architecture/index.md)**
  How the ports-and-adapters layering, caching, and session management fit
  together.

- **[Configuration Guide](configuration/index.md)**
  Every `ArodonataSettings` field, environment variable, and multi-server
  setup pattern.

- **[API Reference](api/arodonata/index.md)**
  Generated reference for every public class and function in `arodonata`.

- **[CPCRUD Engine](user-guide/cpcrud.md)**
  Declarative Policy-as-Code object and rule management with zero-mutation idempotency.

- **[Examples](examples/index.md)**
  Runnable, narrated scripts covering queries, search, refresh, CPCRUD, and
  production patterns.

</div>

## Why Arodonata?

- **High-concurrency execution** — fully asynchronous via `aiohttp`/`asyncio`.
- **Idempotent CPCRUD Policy-as-Code** — Plan-then-Execute engine with conflict resolution for objects & rules.
- **Zero-config session handling** — transparent authentication, session
  pooling, and auto-recovery on session expiry.
- **Intelligent DB caching** — PostgreSQL + SQLAlchemy, with JSONB storage.
- **Smart refresh (`show-changes`)** — pulls only incremental changes
  instead of rebuilding the cache from scratch.
- **Strict type safety** — Pydantic v2 models throughout.

See the [Changelog](CHANGELOG.md) for recent changes.


---

## Getting Started — Overview

*(source: `docs/getting-started/index.md`)*

# Getting Started

## Requirements

- Python 3.13+
- A PostgreSQL 12+ database for the cache layer

## Install

=== "uv (recommended)"

    ```bash
    uv pip install arodonata
    ```

=== "pip"

    ```bash
    pip install arodonata
    ```

For local development against a clone of this repo:

```bash
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


---

## Getting Started — Your First Script

*(source: `docs/getting-started/first-script.md`)*

# Your First Script

This walks through the minimal script needed to connect to a management
server and query its hosts.

```python
import asyncio
import os

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings


async def main() -> None:
    # 1. Create the database engine — Arodonata manages the engine's lifecycle
    #    for you, but the calling app owns creating and disposing it.
    database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = create_async_engine(database_url)

    settings = ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=os.getenv("PRIMARY_MGMT_KEY", "mock-key"),
    )

    client = ArodonataClient(engine=engine, settings=settings)

    try:
        # 3. The async context manager owns session lifecycle (login,
        #    keepalive, cleanup on exit).
        async with client:
            for server_name in client.get_mgmt_names():
                hosts = await client.get_hosts(mgmt_names=[server_name])
                print(f"{server_name}: {len(hosts)} hosts")
                for host in hosts[:5]:
                    print(f"  {host.name} -> {host.ip_address}")
    finally:
        # 4. The engine is yours to dispose.
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
```

This queries `get_hosts()` straight from the cache — nothing is populated in
it yet on a fresh database, so the first run against an empty cache returns
an empty list. See
[`build_refresh_assets_cache`](../api/arodonata/api/client.md) and the
[Examples](../examples/index.md) section for how to populate it.


---

## Getting Started — CRUD Quickstart

*(source: `docs/getting-started/cpcrud.md`)*

# CPCRUD: Idempotent Object CRUD

`client.cpcrud` is an idempotent CRUD engine for Check Point objects and
rules. It takes a declarative YAML/dict **template**, resolves it against
live state (`plan()`), and applies it (`apply()`) — re-running the exact
same template is safe and converges to a no-op (`unchanged`/`reuse`, zero
`create`).

See [`CPCRUDService`](../api/arodonata/cpcrud/service.md) for the full API
surface, and [`examples/06_crud_operations.py`](https://github.com/chkp-antonr/arodonata/blob/master/examples/06_crud_operations.py)
/ [`examples/README_CRUD.md`](https://github.com/chkp-antonr/arodonata/blob/master/examples/README_CRUD.md)
for a runnable end-to-end script.

## Template format

A template is an envelope of management servers, each with domains, each
with a list of operations:

```yaml
management_servers:
  - mgmt_name: "10.192.15.140"
    domains:
      - name: "Domain4"
        operations:
          - type: "host"               # operation defaults to "add"
            data:
              name: "example-host-1"
              ip-address: "10.0.0.1"
              comments: "CPCRUD example host"
              color: "dark green"
              groups: ["Examples"]
            on_name_conflict: "error"
            on_ip_conflict: "error"

          - type: "access-rule"
            layer: "Network"
            position: "bottom"         # int (absolute), "top"/"bottom", or
                                        # {top|bottom|above|below: "rule-name"}
            data:
              name: "cpcrud-example-rule"
              source: ["example-host-1"]
              destination: ["any"]
              service: ["any"]
              action: "drop"
              comments: "CPCRUD example access rule"
```

`operation` defaults to `"add"` and can be omitted, as shown above. Rule
types (`access-rule`, `nat-rule`, `threat-prevention-rule`, `https-rule`)
additionally require `layer` (or `package` for NAT) and a `position` on
`add`.

## Operations and types

| `operation` | Meaning | Required fields |
|---|---|---|
| `add` (default) | Create if absent; conflict-policy governed if a match exists | `type`, `data` |
| `update` | Update an existing object/rule | `type`, `key`, `data` |
| `delete` | Delete an existing object/rule | `type`, `key` |
| `show` | Read-only lookup, no mutation | `type`, `key` |

Supported `type` values: `host`, `network`, `address-range`,
`network-group`, `tcp-service`, `udp-service`, `icmp-service`,
`service-group`, `access-rule`, `nat-rule`, `threat-prevention-rule`,
`https-rule`. Rule types need `layer` (or `package` for `nat-rule`); non-rule
types don't.

The full JSON Schema lives at `ops/checkpoint_ops_schema.json` and is what
`validate()` (see [Embedding in applications](#embedding-in-applications))
checks templates against.

## Conflict policies

Two independent policies govern `add` operations when a matching object
already exists:

| Policy | Values | Meaning |
|---|---|---|
| `on_name_conflict` | `update` (default), `error` | What to do when an object of the same name already exists |
| `on_ip_conflict` | `reuse` (default), `error`, `create_new` | What to do when another object already owns the requested IP |

Precedence, highest first: **per-operation** (`on_name_conflict`/
`on_ip_conflict` set directly on the operation) > **argument** passed to
`plan()`/`apply()` (`on_name_conflict=`/`on_ip_conflict=`) > **settings**
(`ARODONATA_CPCRUD_ON_NAME_CONFLICT`/`ARODONATA_CPCRUD_ON_IP_CONFLICT`) >
**built-in default** (`update`/`reuse`).

## Plan / apply / dry-run lifecycle

```python
plan = await client.cpcrud.plan(template)          # resolve against live state
async for event in client.cpcrud.apply(plan):       # or apply(template) directly
    ...                                              # SSEEvent per action, in-flight
report = event                                       # last yielded item is the ApplyReport
print(report.summary)                                # {"create": 2, "unchanged": 1, ...}
```

- `plan()` is read-only: it resolves names/IPs against cached+live state,
  applies conflict policy, and computes each action's `Outcome`
  (`create`/`update`/`reuse`/`unchanged`/`delete`/`conflict`/`error`) without
  writing anything.
- `apply()` accepts either a `Plan` (from `plan()`) or a template directly
  (in which case it plans first). It always yields `SSEEvent`s as it works,
  followed by a final `ApplyReport` as the last item.
- `apply(..., dry_run=True)` walks the plan and yields the same shape of
  events/report without calling any write API — useful for previewing what
  would happen.
- Other `apply()` flags: `force` (skip the "domain published since plan"
  staleness guard), `no_publish`/`discard` (control end-of-session publish
  behavior), `session_name`/`session_description` (label the dedicated
  session cpcrud opens per domain).

## Retrying partial failures

Some outcomes are retryable: `locked` (session lock held by someone else),
`error` (a write failed), and `skipped_dependency` (an action's dependency
failed first). After a pass, `ApplyReport.remaining` holds a `Plan` scoped to
just those actions (actions in domains whose plan went stale are excluded).

Pass `retry_remaining=N` to `apply()` to retry automatically, up to `N`
extra passes, invalidating each affected domain's cache before every retry:

```python
async for event in client.cpcrud.apply(template, retry_remaining=2):
    ...
report = event
```

Passes are merged with `fold_reports()`: the final report's `results` and
`summary` reflect the *last* attempt for each action, not a sum across
passes.

## Inverse templates

`client.cpcrud.inverse(plan, report=None)` builds a schema-valid template
that compensates an applied `Plan`:

- `create` → `delete` (keyed by uid from `report` when available, else by
  resolved name)
- `update` → `update` restoring each changed field's `before` value
- `delete` → `add` replaying the deleted object's `prior_state`
- `reuse`/`unchanged`/`conflict`/`error`/`show` → nothing (no-op, omitted)

Passing `report` scopes the inverse to only the actions that actually
executed in that report (apply-time outcomes like `locked` don't count).
Apply the inverse through the normal `plan()`/`apply()` pipeline — it
re-resolves, re-orders, and re-validates everything:

```python
plan = await client.cpcrud.plan(template)
events = [e async for e in client.cpcrud.apply(plan)]
report = events[-1]

inverse_template = client.cpcrud.inverse(plan, report)
events2 = [e async for e in client.cpcrud.apply(inverse_template)]
```

## Settings

All cpcrud settings live on [`ArodonataSettings`](../api/arodonata/config/settings.md)
and are configured by the calling application (arodonata does not read `.env`
files itself — see the [Configuration Guide](../configuration/index.md)).

| Env var | Field | Default | Description |
|---|---|---|---|
| `ARODONATA_CPCRUD_ON_NAME_CONFLICT` | `cpcrud_on_name_conflict` | `"update"` | Default name conflict policy: `update` \| `error` |
| `ARODONATA_CPCRUD_ON_IP_CONFLICT` | `cpcrud_on_ip_conflict` | `"reuse"` | Default IP conflict policy: `reuse` \| `error` \| `create_new` |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST` | `cpcrud_auto_name_prefix_host` | `"Host_"` | Naming prefix for auto-created host dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK` | `cpcrud_auto_name_prefix_network` | `"Net_"` | Naming prefix for auto-created network dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE` | `cpcrud_auto_name_prefix_range` | `"IPR_"` | Naming prefix for auto-created address-range dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP` | `cpcrud_auto_name_prefix_svc_tcp` | `"TCP_"` | Naming prefix for auto-created TCP service dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP` | `cpcrud_auto_name_prefix_svc_udp` | `"UDP_"` | Naming prefix for auto-created UDP service dependencies |
| `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP` | `cpcrud_auto_name_prefix_svc_icmp` | `"ICMP_"` | Naming prefix for auto-created ICMP service dependencies |
| `ARODONATA_CPCRUD_REFRESH_MODE` | `cpcrud_refresh_mode` | `"invalidate"` | Post-publish cache refresh: `invalidate` \| `force` |
| `ARODONATA_CPCRUD_SCHEMA_PATH` | `cpcrud_schema_path` | `""` (bundled schema) | Override path to `checkpoint_ops_schema.json` |

`cpcrud_refresh_mode` is also overridable per call via `apply(..., refresh=...)`.

## Embedding in applications

CPCRUD's public surface — `CPCRUDService.validate()`/`plan()`/`apply()`/
`inverse()`, reached via `client.cpcrud` — is the stable contract embedding
applications should rely on:

- `apply()` is an async generator: it always yields zero or more `SSEEvent`s
  first, then exactly one `ApplyReport` as its final item. Consume it with
  `[e async for e in client.cpcrud.apply(...)][-1]` to get just the report,
  or stream the `SSEEvent`s through to a UI/log as they arrive.
- `validate(template)` is synchronous and side-effect-free: it loads (if
  given a path/string) and schema-validates a template, returning a list of
  error strings (empty means valid). It never touches the network.
- `plan()` and `apply()` both accept a template as **either** a `str`/`Path`
  (loaded as YAML) **or** a plain `dict` already shaped like the schema —
  useful when a caller builds/mutates templates programmatically rather than
  from a file on disk.
- `apply()` also accepts a `Plan` object directly (as returned by `plan()`),
  so callers that need to inspect or log the plan before executing it can
  split the two steps instead of calling `apply()` with a template.


---

## Architecture — Overview

*(source: `docs/architecture/index.md`)*

# Architecture Overview

Arodonata uses a **ports-and-adapters** (hexagonal) architecture: business
logic in `arodonata.core` and `arodonata.api` never imports a database driver or
an HTTP client directly — it depends on `Port` protocols
([`ApiPort`](../api/arodonata/ports/api_port.md),
[`CachePort`](../api/arodonata/ports/cache_port.md)), and concrete
`arodonata.adapters` implementations are wired in at construction time.

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


---

## Architecture — Ports & Adapters

*(source: `docs/architecture/ports-and-adapters.md`)*

# Ports & Adapters

## Facades

- **[`ArodonataClient`](../api/arodonata/api/client.md)**
  (`src/arodonata/api/client.py`) — the main developer entry point. Wraps
  caching, rate limiting, and session management behind helper methods like
  `get_hosts()`, `get_networks()`, `get_access_rules()`.
- **[`AMgmtClient`](../api/arodonata/asdk/client.md)** (`src/arodonata/asdk/`) —
  the lower-level session-oriented client: login, keepalive, and raw
  `api-query`/`show-*` calls against a single management server.

## Ports

Defined in `src/arodonata/ports/`:

- **[`ApiPort`](../api/arodonata/ports/api_port.md)** — the interface the core
  framework calls to talk to *some* Check Point management API — real or
  mocked.
- **[`CachePort`](../api/arodonata/ports/cache_port.md)** — the interface for
  reading/writing cached objects, independent of the storage engine.

## Adapters

Defined in `src/arodonata/adapters/`:

- **[`asdk_adapter`](../api/arodonata/adapters/api/asdk_adapter.md)**
  (`adapters/api/asdk_adapter.py`) — implements `ApiPort` on top of
  `AMgmtClient`.
- **[`postgres_adapter`](../api/arodonata/adapters/cache/postgres_adapter.md)**
  (`adapters/cache/postgres_adapter.py`) — implements `CachePort` on top of
  SQLAlchemy async sessions against PostgreSQL.

Because `arodonata.core` and `arodonata.api` depend only on the port protocols,
swapping the cache backend or mocking the management API for tests (see
`tests/mock_api/`) never requires touching business logic.


---

## Architecture — Caching & Sync

*(source: `docs/architecture/caching-and-sync.md`)*

# Caching & Sync

## Why cache at all

Check Point management servers rate-limit and are slow to re-authenticate;
Arodonata avoids repeating full `show-*` queries by storing objects, gateways,
domains, and rulebases in PostgreSQL (`src/arodonata/cache/`) as JSONB-backed
rows via [`CacheRepository`](../api/arodonata/cache/repository.md).

## Populating the cache

- [`ArodonataClient.build_refresh_assets_cache()`](../api/arodonata/api/client.md)
  — full refresh of domains and gateways.
- [`ArodonataClient.refresh_objects()`](../api/arodonata/api/client.md) — refresh
  of hosts, networks, groups, and address ranges.
- [`ArodonataClient.refresh_rulebases()`](../api/arodonata/api/client.md) —
  refresh of access/NAT/HTTPS/threat rulebases.

Each of these is an async generator yielding `SSEEvent` progress updates
(`src/arodonata/api/schemas.py`), so a caller can stream progress to a UI or
log line-by-line instead of blocking until completion.

## Refresh modes

`refresh_objects()` takes a `mode` selecting how much work a refresh does
([`RefreshMode`](../api/arodonata/core/protocols.md)):

- **`skip`** — use the cache as-is, no API calls.
- **`check`** — probe each domain's `show-last-published-session` (session
  *uid* comparison; stored per domain in the `last_published_sessions`
  table) and fully reload only stale domains, via one atomic
  collect-then-swap transaction per domain.
- **`force`** — full atomic reload of every domain, unconditionally.
- **`incremental`** — same staleness probe as `check`, but a stale domain is
  caught up from Check Point's `show-changes` diff
  ([`change_processor.py`](../api/arodonata/core/change_processor.md),
  [`incremental_refresh.py`](../api/arodonata/core/incremental_refresh.md)):
  the diff is used only as a *change list* — every added or modified object
  is re-fetched in full (`show-object`, `details-level: full`) and converted
  by the same converter as a full reload, so its cache row is
  field-identical to what `force` would produce. Deletes are applied
  directly. Any unsafe condition (no baseline, truncated diff, more changes
  than the configurable cap — `ArodonataClient(max_incremental_changes=…)`,
  default 500 — parse anomalies, re-fetch failures) falls back to the atomic
  full reload. Only changes to cached object kinds (hosts, networks, address
  ranges, groups) are applied; a rules-only publish just advances the
  freshness baseline.

The same engine backs the `smart-fast` cache mode used by read helpers.

## Reading from the cache

Helper methods on `ArodonataClient` (`get_hosts`, `get_networks`, `get_groups`,
`get_domains`, `get_gateways`, `get_access_rules`, ...) always read from the
cache — they never make a live API call. For lower-level, filterable access,
[`CacheRepository`](../api/arodonata/cache/repository.md) exposes
`get_objects()`, `get_objects_by_type()`, `get_objects_by_ip()`, and
`get_rulebase()` directly.


---

## Architecture — Sessions & Multi-Domain Management

*(source: `docs/architecture/sessions-and-mdm.md`)*

# Sessions & Multi-Domain

## Session lifecycle

- **[`login_coordinator.py`](../api/arodonata/asdk/login_coordinator.md)** —
  handles initial login, and re-login/backoff if a session expires mid-use.
- **[`session_cleaner.py`](../api/arodonata/asdk/session_cleaner.md)** —
  background cleanup of stale sessions, so long-running processes don't leak
  SIDs on the management server.
- **[`rate_limiter.py`](../api/arodonata/asdk/rate_limiter.md)** — per-server
  concurrency gating (`ArodonataSettings.concurrent_limit`), so a burst of
  cache-refresh work doesn't overload a single management server.

Session and login retry behavior is configured through
`ArodonataSettings.session_expire_seconds`, `session_timeout`,
`login_retry_backoff`, and `login_max_retries` — see the
[Configuration Guide](../configuration/index.md).

## Multi-domain (MDM) resolution

Check Point Multi-Domain Management servers expose multiple domains behind
one management IP. Arodonata resolves and propagates domain context through
[`domain_service.py`](../api/arodonata/api/services/domain_service.md), so
every cache row and every helper-method result carries its owning
`mgmt_name`/`domain_name` pair — letting callers filter
(`client.get_hosts(domain_names=["Domain1"])`) without re-deriving domain
membership themselves.


---

## Architecture — CRUD Engine

*(source: `docs/architecture/cpcrud.md`)*

# Architecture: CPCRUD Engine

The **CPCRUD** (Check Point Policy-as-Code CRUD) engine is designed around a **Plan-then-Execute** architecture with strict separation of concerns between schema validation, live state resolution, conflict evaluation, action planning, and transactional execution.

---

## Architectural Component Overview

```mermaid
graph TD
    Client["ArodonataClient"] --> Service["CPCRUDService"]
    
    subgraph "Validation & Schema Layer"
        Service --> Schema["schema.py\n(Draft7Validator)"]
    end
    
    subgraph "Planning & State Resolution"
        Service --> Planner["planner.py\n(Planner)"]
        Planner --> StateReader["statereader.py\n(HybridStateReader)"]
        Planner --> RuleIdentity["rule_identity.py\n(Rule identity resolution)"]
        Planner --> Differ["differ.py\n(Field-level diffing)"]
    end
    
    subgraph "Execution & Transaction Layer"
        Service --> Executor["executor.py\n(Executor)"]
        Executor --> LoginCoord["LoginCoordinator\n(Per-mgmt/domain session pool)"]
        Executor --> PositionHelper["position_helper.py\n(Rule positioning helper)"]
    end
```

---

## Component Roles & Responsibilities

### 1. `CPCRUDService` (`src/arodonata/cpcrud/service.py`)

The public facade attached to `ArodonataClient.cpcrud`. Orchestrates `validate()`, `plan()`, and `apply()`. Exposes an `AsyncIterator[SSEEvent | ApplyReport]` interface for streamable execution logging.

### 2. Schema Layer (`src/arodonata/cpcrud/schema.py`)

Uses `jsonschema.Draft7Validator` against `checkpoint_ops_schema.json` to enforce strict syntax validation for incoming templates before any network calls are made.

### 3. `HybridStateReader` (`src/arodonata/cpcrud/statereader.py`)

Queries live management state via `ArodonataClient` read operations (or DB cache) to build `ObjectState` representations. It reads existing object fields, meta-info locks, and rulebase trees without modifying live session state.

### 4. `Planner` (`src/arodonata/cpcrud/planner.py`)

Core decision engine. Transforms normalized template operations into a deterministic `Plan` containing a list of `PlannedAction` items.

- Evaluates `NameConflictPolicy` (`UPDATE` | `ERROR`) and `IpConflictPolicy` (`REUSE` | `CREATE_NEW` | `ERROR`).
- Calculates field diffs via `differ.py`.
- Determines the exact outcome (`CREATE`, `UPDATE`, `REUSE`, `UNCHANGED`, `DELETE`, `CONFLICT`).
- Generates `DomainStamp` records for each target domain to track `last_publish_session` hashes.

### 5. `Executor` (`src/arodonata/cpcrud/executor.py`)

Performs live write operations.

- Obtains dedicated write sessions per `(mgmt_name, domain_name)` via `LoginCoordinator.acquire_write_session()`.
- Validates that domain session stamps have not drifted (`PLAN_STALE` check).
- Executes low-level API commands (`add-host`, `set-network`, `add-access-rule`, etc.).
- Publishes or discards write sessions atomically upon completion.

---

## Plan-then-Execute Sequence

The execution sequence ensures that no write actions take place until a complete plan has been computed and verified.

```mermaid
sequenceDiagram
    autonumber
    participant App as Application Code
    participant Service as CPCRUDService
    participant Planner as Planner
    participant StateReader as HybridStateReader
    participant Executor as Executor
    participant Mgmt as Check Point Management API

    App->>Service: plan(template)
    Service->>Planner: decide(doc)
    Planner->>StateReader: fetch_object_state() / fetch_rule_state()
    StateReader->>Mgmt: show-object / show-access-rulebase (Read-Only)
    Mgmt-->>StateReader: Object details / Rule list
    Planner->>Planner: Diff fields & calculate outcomes
    Planner-->>Service: Plan (with PlannedAction list & DomainStamps)
    Service-->>App: Plan object

    App->>Service: apply(plan)
    Service->>Executor: stream(plan)
    Executor->>Mgmt: Login write session (session_name)
    loop For each PlannedAction
        Executor->>Mgmt: add-*/set-*/delete-* API command
        Mgmt-->>Executor: Command result
        Executor-->>App: yield SSEEvent
    end
    Executor->>Mgmt: publish session
    Executor-->>Service: ApplyReport
    Service-->>App: yield ApplyReport
```

---

## Conflict & Drift Detection Architecture

### Domain Stamps & Stale Plan Safeguard

When a `Plan` is created, `Planner` records a `DomainStamp` for each target domain containing the `last_publish_session` UID.

During `apply()`, `Executor` re-checks the target domain's published session UID. If another administrator or script published changes in that domain while the plan was sitting unexecuted, `Executor` aborts execution with `PLAN_STALE` to prevent unintended policy overwrites.

### Field Diffing (`differ.py`)

When an object exists, `differ.py` compares the normalized desired attributes against `ObjectState.raw`.

- If no fields differ, the action outcome is set to `Outcome.UNCHANGED` and no API write is executed.
- If fields differ, the action outcome is set to `Outcome.UPDATE` with an explicit `changes` payload detailing old vs new values.

---

## Rule Positioning & Identity Resolution

Access and NAT rules in Check Point do not always have unique global names. `rule_identity.py` and `position_helper.py` handle rule identity and positional anchoring:

1. **Rule Matching (`RuleMatch`)**: Matches rules based on rule names, rule numbers, or signature match (source, destination, service, action).
2. **Positional Target**: `position_helper.py` converts abstract positioning options (`top`, `bottom`, `above`, `below`) into concrete Check Point API `position` structures required during rule creation or reordering.


---

## Configuration — Overview

*(source: `docs/configuration/index.md`)*

# Configuration Guide

All configuration is explicit: `arodonata` never reads a `.env` *file*
itself. The calling application resolves values (e.g. via `python-dotenv`)
and constructs a [`ArodonataSettings`](../api/arodonata/config/settings.md)
instance. `ArodonataSettings` is a pydantic-settings model, so **every**
field also accepts its environment variable directly (whatever the calling
application already has exported/loaded into `os.environ`) — `log_level`
isn't special in this regard, it's just one field among many.

## Settings reference

| Field | Type | Default | Description |
|---|---|---|---|
| `mgmt_names` | `str` | `""` | Comma-separated management server names. |
| `mgmt_servers` | `str` | `""` | Comma-separated management server IPs/hosts, matched by position to `mgmt_names`. |
| `api_keys` | `str` | `""` | Comma-separated **actual** API key values (not variable names), matched by position. |
| `username` | `str \| None` | `None` | Username for credential-based auth (alternative to `api_keys`). |
| `password` | `SecretStr \| None` | `None` | Password for credential-based auth. |
| `mgmt_ip` | `str \| None` | `None` | Required when `username`/`password` are set. |
| `session_expire_seconds` | `int` | see [`constants.py`](../api/arodonata/config/constants.md) | Cache freshness threshold in seconds. |
| `session_timeout` | `int` | see `constants.py` | Session timeout passed to the Check Point login API. |
| `concurrent_limit` | `int` (1-20) | see `constants.py` | Max concurrent API requests per server. |
| `api_timeout` | `int` | see `constants.py` | Per-request API timeout in seconds. |
| `login_retry_backoff` | `int` | see `constants.py` | Backoff (seconds) between login retries. |
| `login_max_retries` | `int` | see `constants.py` | Maximum login retry attempts. |
| `log_level` | `str` | `"INFO"` | Also settable via the `ARODONATA_LOG_LEVEL` environment variable. |
| `cpcrud_on_name_conflict` | `str` | `"update"` | Name conflict policy: `'update'` \| `'error'`. Settable via `ARODONATA_CPCRUD_ON_NAME_CONFLICT`. |
| `cpcrud_on_ip_conflict` | `str` | `"reuse"` | IP conflict policy: `'reuse'` \| `'error'` \| `'create_new'`. Settable via `ARODONATA_CPCRUD_ON_IP_CONFLICT`. |
| `cpcrud_auto_name_prefix_host` | `str` | `"Host_"` | Auto-generated name prefix for hosts on IP conflict (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST`). |
| `cpcrud_auto_name_prefix_network` | `str` | `"Net_"` | Auto-generated name prefix for networks on IP conflict (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK`). |
| `cpcrud_auto_name_prefix_range` | `str` | `"IPR_"` | Auto-generated name prefix for address ranges (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE`). |
| `cpcrud_auto_name_prefix_svc_tcp` | `str` | `"TCP_"` | Auto-generated name prefix for TCP services (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP`). |
| `cpcrud_auto_name_prefix_svc_udp` | `str` | `"UDP_"` | Auto-generated name prefix for UDP services (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP`). |
| `cpcrud_auto_name_prefix_svc_icmp` | `str` | `"ICMP_"` | Auto-generated name prefix for ICMP services (`ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP`). |
| `cpcrud_refresh_mode` | `str` | `"invalidate"` | Post-publish cache refresh: `'invalidate'` \| `'force'`. Settable via `ARODONATA_CPCRUD_REFRESH_MODE`. |
| `cpcrud_schema_path` | `str` | `""` | Optional override path to `checkpoint_ops_schema.json` (`ARODONATA_CPCRUD_SCHEMA_PATH`). |
| `trace_modules` | `str` | `""` | Comma-separated `module:on\|off` OTEL span gating, longest dotted-prefix match. Settable via `ARODONATA_TRACE_MODULES`. See [Tracing](#tracing) below. |

### Tracing

arodonata emits OpenTelemetry spans when the host application configures a
`TracerProvider` (e.g. MMP via `arlogi.otel.setup_tracing()`). Without one,
spans are free no-ops. arodonata never configures a provider itself; standalone
users install `arodonata[otel]` and call `arlogi.otel.setup_tracing()` themselves.

| Variable | Default | Description |
| --- | --- | --- |
| `ARODONATA_TRACE_MODULES` | `""` (all on) | Comma-separated `module:on\|off` span gating, longest dotted-prefix match. Example: `arodonata:on,arodonata.api.client:off` |

## CPCRUD Policy Configuration

The CPCRUD engine options can be configured globally on `ArodonataSettings` or overridden per environment variable:

```bash
# Global conflict policies
ARODONATA_CPCRUD_ON_NAME_CONFLICT=update
ARODONATA_CPCRUD_ON_IP_CONFLICT=reuse

# Auto-naming prefixes for IP conflict resolution
ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST=Host_
ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK=Net_

# Schema override (optional)
ARODONATA_CPCRUD_SCHEMA_PATH=/path/to/custom_schema.json
```

## Authentication modes

`ArodonataSettings.auth_mode` resolves automatically:

- **`api_key`** (default) — set `api_keys` (and `mgmt_names`/`mgmt_servers`).
- **`credential`** — set both `username` and `password`; `mgmt_ip` then
  becomes required, and omitting it raises `MissingConfigurationError`.

## Minimal `.env` for local development

```bash
DATABASE_URL=postgresql+asyncpg://cp_user:cp_password@localhost:5432/arodonata_cache
MGMT_NAMES=primary-mgmt
MGMT_SERVERS=192.168.10.10
API_KEY_VARS=PRIMARY_MGMT_KEY
PRIMARY_MGMT_KEY=your-primary-api-key-here
```

`DATABASE_URL` and `API_KEY_VARS` aren't `ArodonataSettings` fields — they're
this application-level convention for resolving *which* environment
variables hold the real secrets, described next in
[Multi-Server Setup](multi-server.md).

See [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md) for how
these settings affect login/session behavior.


---

## Configuration — Multi-Server Setup

*(source: `docs/configuration/multi-server.md`)*

# Multi-Server Setup

`ArodonataSettings.mgmt_names`, `mgmt_servers`, and `api_keys` are all
comma-separated strings matched **by position** — the Nth name corresponds
to the Nth server and the Nth key:

```bash
MGMT_NAMES=primary-mgmt,backup-mgmt
MGMT_SERVERS=192.168.10.10,192.168.10.11
API_KEY_VARS=PRIMARY_MGMT_KEY,BACKUP_MGMT_KEY

PRIMARY_MGMT_KEY=your-primary-api-key-here
BACKUP_MGMT_KEY=your-backup-api-key-here
```

`API_KEY_VARS` is a convention used in this project's own scripts (not a
`ArodonataSettings` field): it names the environment variables that hold the
*actual* keys, so the keys themselves can live in a separate, more tightly
permissioned file (e.g. `.env.secrets`) than the server topology
(`.env`/`.env.dev`). The calling application resolves `API_KEY_VARS` into
real values before constructing `ArodonataSettings(api_keys=...)`:

```python
import os

api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)

settings = ArodonataSettings(
    mgmt_names=os.getenv("MGMT_NAMES", ""),
    mgmt_servers=os.getenv("MGMT_SERVERS", ""),
    api_keys=api_keys,
)
```

Once configured, [`ArodonataClient.get_mgmt_names()`](../api/arodonata/api/client.md)
returns the configured server names, and every helper method accepts an
optional `mgmt_names=[...]` filter to scope a query to a subset of them —
see [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md) for how
domain resolution layers on top of this for MDM servers.


---

## User Guide — CRUD Operations

*(source: `docs/user-guide/cpcrud.md`)*

# CPCRUD — Idempotent Policy-as-Code Engine

The **CPCRUD** (Check Point Policy-as-Code CRUD) engine in `arodonata` provides declarative, conflict-aware, and idempotent object and rule operations across Check Point security management servers and multi-domain environments (MDM).

With `client.cpcrud`, you define desired security management state in YAML or JSON templates. The engine inspects live state, resolves conflicts, computes exact field-level diffs, and executes only the minimal required operations in dedicated session transactions.

---

## Key Features

- **Idempotent Execution**: Re-running the exact same template produces zero state mutations once applied (`outcome: unchanged` / `skipped`).
- **Plan-then-Execute Architecture**: Preview plan actions, field diffs, and potential conflicts before committing any changes.
- **Conflict Resolution Policies**: Configurable policies for handling name collisions (`on_name_conflict`) and IP address overlaps (`on_ip_conflict`).
- **Rulebase Aware**: Supports targeting rule layers (`layer`), packages (`package`), and positional anchoring (`position: top | bottom | above | below`).
- **Atomic Session Management**: Dedicated per-`(mgmt_name, domain_name)` write sessions with support for auto-publish, dry-runs, and instant transaction discarding.
- **Real-Time Streaming**: Asynchronous SSE (Server-Sent Events) streaming for fine-grained execution reporting.

---

## 3-Phase Lifecycle

The CPCRUD engine follows a structured three-phase pipeline:

```mermaid
flowchart LR
    A["YAML / JSON Template"] --> B["1. Validate\nvalidate()"]
    B --> C["2. Plan\nplan()"]
    C --> D["Planned Action Tree / Field Diffs"]
    D --> E["3. Apply\napply()"]
    E --> F["SSE Events & ApplyReport"]
```

### 1. Validation (`validate`)

Verifies template structure against `checkpoint_ops_schema.json` using `Draft7Validator`.

```python
errors = client.cpcrud.validate("path/to/template.yaml")
if errors:
    print("Schema errors found:", errors)
```

### 2. Planning (`plan`)

Queries live management state, evaluates conflict policies, diffs desired fields against existing objects, and produces a `Plan`.

```python
plan = await client.cpcrud.plan(
    "path/to/template.yaml",
    on_name_conflict="update",
    on_ip_conflict="reuse",
)
print(f"Actions to execute: {len(plan.actions)}")
for action in plan.actions:
    print(f"[{action.mgmt_name}:{action.domain_name}] {action.operation} {action.type} '{action.resolved_name}' -> {action.outcome.value}")
```

### 3. Execution (`apply`)

Opens dedicated write sessions, executes planned API commands, yields real-time `SSEEvent` items during execution, and returns an `ApplyReport`.

```python
async for event in client.cpcrud.apply("path/to/template.yaml"):
    if isinstance(event, ApplyReport):
        print("Final Summary:", event.summary)
    else:
        print(f"[{event.mgmt_name}:{event.domain}] {event.event_type}: {event.message}")
```

---

## Template Specification

Templates are written in YAML or JSON and structured hierarchically by Management Server, Domain, and Operation list.

### Basic Template Structure

```yaml
management_servers:
  - mgmt_name: "10.192.15.140"         # Target Management IP or Hostname
    domains:
      - name: "Domain4"                # Target Domain (or 'SMC' for single-domain)
        operations:
          - type: "host"
            data:
              name: "app-server-01"
              ip-address: "10.1.10.50"
              comments: "Production App Server"
              color: "dark green"
              groups: ["App-Servers"]
            on_name_conflict: "update" # 'update' (default) | 'error'
            on_ip_conflict: "reuse"    # 'reuse' (default) | 'create_new' | 'error'

          - type: "network"
            data:
              name: "Internal-Net"
              subnet: "10.1.0.0"
              mask-length: 16
              color: "blue"

          - type: "access-rule"
            layer: "Network"
            position: "bottom"
            data:
              name: "allow-app-access"
              source: ["app-server-01"]
              destination: ["any"]
              service: ["https", "http"]
              action: "accept"

          - type: "nat-rule"
            package: "Standard"
            position: "top"
            data:
              name: "app-server-nat"
              source: ["app-server-01"]
              destination: ["any"]
              service: ["any"]
              translated-source: "203.0.113.10"
              method: "hide"
```

---

## Supported Operation Types

| Operation Type | Key Data Fields | Description |
| :--- | :--- | :--- |
| `host` | `name`, `ip-address`, `comments`, `color`, `groups` | Check Point Host object |
| `network` | `name`, `subnet`, `mask-length` | Check Point Network object |
| `address-range` | `name`, `ip-address-first`, `ip-address-last` | Address range object |
| `network-group` | `name`, `members` | Host/network object group |
| `service-group` | `name`, `members` | Service object group |
| `tcp-service` | `name`, `port`, `comments` | TCP Service object |
| `udp-service` | `name`, `port`, `comments` | UDP Service object |
| `icmp-service` | `name`, `icmp-type`, `icmp-code` | ICMP Service object |
| `access-rule` | `name`, `source`, `destination`, `service`, `action` | Rule in Access Layer (requires `layer`) |
| `nat-rule` | `name`, `source`, `destination`, `translated-source`, etc. | NAT Rule (requires `package`) |
| `threat-prevention-rule` | `name`, `source`, `destination`, `service`, `action` | Threat Prevention rule (requires `layer`) |
| `https-rule` | `name`, `source`, `destination`, `service`, `action` | HTTPS Inspection rule (requires `layer`) |

Deletion isn't a separate `type` — set `operation: "delete"` on the object's
real `type` (e.g. `type: "host"`) with a `key` object instead of `data`
(e.g. `{"name": "..."}` or `{"uid": "..."}`).

---

## Conflict Resolution Policies

### Name Conflict Policy (`on_name_conflict`)

Controls behavior when an object with the same `name` already exists in the management server.

- **`update`** *(default)*: Compares desired fields with existing fields. If differences exist, issues an `update-*` API call (`outcome: update`). If fields match, skips execution (`outcome: unchanged`).
- **`error`**: Flagged as a conflict (`outcome: conflict`); execution aborts for that action.

### IP Conflict Policy (`on_ip_conflict`)

Controls behavior when another object shares the requested IP address or subnet.

- **`reuse`** *(default)*: Reuses the existing object matching the IP address (`outcome: reuse`).
- **`create_new`**: Creates a new object with auto-prefixed naming (e.g. `host_10.1.10.50`).
- **`error`**: Raises an IP conflict error and skips execution.

---

## Rule Positioning & Layer Targeting

For `access-rule` and `nat-rule` operations, CPCRUD supports explicit position placement relative to the whole layer, a specific section, or an existing rule.

```yaml
- type: "access-rule"
  layer: "Network"             # Target layer name
  position: "top"               # Top of the whole layer
  # or "bottom"                 # Bottom of the whole layer
  # or {top: "Section Name"}    # Top of a specific section (name or UID)
  # or {bottom: "Section Name"} # Bottom of a specific section
  # or {above: "rule-name-or-uid"}
  # or {below: "rule-name-or-uid"}
  # or a plain integer for an absolute 1-based rule number
  data:
    name: "sec-rule-01"
    source: ["any"]
    destination: ["any"]
    service: ["any"]
    action: "drop"
```

### Cleanup-rule-aware `bottom`

When you target `"bottom"` (whole layer) or `{bottom: "Section Name"}` (a section), CPCRUD checks the actual last rule in that scope first. If it has `source: Any`, `destination: Any`, **and** `service: Any` — regardless of its `action` or `name`, so this also catches an "accept any/any/any" rule, not just a "drop" cleanup rule — the new rule is inserted one position *above* it instead of literally at the bottom, so it never lands after an existing catch-all rule. If the last rule isn't a full any/any/any rule, `"bottom"` is used literally.

This cleanup-aware behavior applies to access/HTTPS/threat-prevention layers only. `nat-rule` positioning does not have it — NAT rulebases have no equivalent implicit cleanup rule — and section-relative positioning (`{top: ...}`/`{bottom: ...}`) is not supported for NAT rules at all; use `"top"`, `"bottom"`, an integer, or `{above: ...}`/`{below: ...}` instead.

---

## Execution Options & Session Handling

The `apply()` method accepts keyword arguments to fine-tune execution and transactional publishing:

```python
async for event in client.cpcrud.apply(
    template_path,
    dry_run=False,        # Preview mode without making live modifications
    force=False,          # Skip lock check warnings
    no_publish=False,     # Execute changes without publishing the session
    discard=False,        # Discard write session changes upon completion
    session_name="Deploy-App-Policy",
    session_description="Automated rollout via arodonata CPCRUD",
):
    ...
```

---

## Full Usage Example

```python
import asyncio
from pathlib import Path
from arodonata import ArodonataClient
from arodonata.cpcrud import ApplyReport

async def main():
    async with ArodonataClient(username="admin", password="password", mgmt_ip="10.192.15.140") as client:
        template_file = Path("crud_example.yaml")

        # 1. Validate
        errors = client.cpcrud.validate(template_file)
        if errors:
            print("Validation failed:", errors)
            return

        # 2. Plan
        plan = await client.cpcrud.plan(template_file)
        print(f"Generated plan with {len(plan.actions)} action(s):")
        for a in plan.actions:
            print(f"  - [{a.operation.upper()}] {a.type} '{a.resolved_name}' ({a.outcome.value})")

        # 3. Apply
        async for event in client.cpcrud.apply(plan):
            if isinstance(event, ApplyReport):
                print("Apply Complete Summary:", event.summary)

if __name__ == "__main__":
    asyncio.run(main())
```


---

## Development — Testing

*(source: `docs/development/testing.md`)*

# Testing

arodonata ships two test layers: an offline **unit suite** that anyone can run,
and a tiered **integration suite** that exercises a real Check Point
management server.

## Unit suite

```bash
uv run pytest
```

- Lives in `tests/unit/`, mirroring the `src/arodonata/` package tree one test
  module per source module.
- Fully offline — no credentials, no network, in-memory SQLite where a real
  database engine is needed.
- Coverage is enforced at **≥85%** (`--cov-fail-under`), with core logic
  (cache refresh coordinator, change processor, client facade, login
  coordinator, repository) held near 100%.
- Shared infrastructure: `tests/unit/doubles.py` provides protocol-satisfying
  `FakeApi`/`FakeCache` doubles for the ports; `tests/unit/conftest.py`
  neutralizes the distributed-lock manager.

This is what CI runs — integration tests are excluded from default runs by
the `-m "not integration"` marker expression.

## Integration suite

```bash
./pytest.sh int-fast     # ~3 min
./pytest.sh int-medium   # ~5 min  (fast + medium)
./pytest.sh int-full     # ~25 min (everything)
```

Tests live in `tests/integration/{fast,medium,full}/`; tier markers are
applied automatically from the directory path, and runs are cumulative.

| Tier | Contents |
|---|---|
| `fast` | Logins for every configured identity (API key + credential users), auth failures, SID lifecycle incl. stale-SID recovery, throttling, rate limiting, concurrent admins, live session naming |
| `medium` | Cache-first reads and search, single-domain cache builds and check-mode partial refresh, rulebase reads, first mutating tests: create→publish→verify→revert cycles |
| `full` | Cache-mode matrix (cache/smart/smart-fast/force) incl. live fallback triggers, multi-domain isolation, whole-server rebuilds with asset relationship phases, cross-user publish/discard/revert matrix, bounded soak |

### Configuration

The integration conftest loads `.env.test` then `.env.secrets` from the repo
root. See `.env.example` for the variable names; the important ones:

- `API_MGMT` — management server IP
- `APIKEY`, `USER_admin`, `USER_AntonR`, `USER_Eng1..4` — identities
- `TEST_DOMAIN_A`, `TEST_DOMAIN_B` — sandbox domains for mutating tests
- `DATABASE_URL` — SQLite path for the test cache (default `_tmp/`)

Missing variables **skip** the affected tests, so a machine without lab
access still runs everything else.

### Mutation safety

Tests that change server state are marked `cp_mutates` and confine
themselves to the sandbox domains, reverting to the pre-test revision when
they finish. Independently of that, the harness snapshots every domain's
last published revision to `_tmp/cp_baseline/baseline-<timestamp>.json`
**before any test runs** and reverts drifted domains at session end. After
a crashed run, restore manually:

```bash
uv run tests/integration/restore_baseline.py _tmp/cp_baseline/baseline-<timestamp>.json
```

The baseline files are never deleted automatically — they are your recovery
handle.

### Serial by design

Integration tests run serially (no `pytest-xdist`): the suite deliberately
exercises rate limits and session caps, so parallel workers would poison
each other's results.
