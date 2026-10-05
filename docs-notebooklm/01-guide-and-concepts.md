# Arodonata — Concepts & Guide

This document is a consolidated guide to the Arodonata library: what it does, how it's built, how to configure it, and how to use its main features. It's one of three companion documents (Guide, API Reference, Examples) meant to be uploaded together to an AI document-chat tool so you can ask questions like "which function do I use to fetch a host object?" or "how do I set up multi-server config?" and get grounded answers.


---

## Overview

*(source: `docs/index.md`)*

# Arodonata

**A high-performance, async-first Python library for Check Point security management operations with intelligent database caching and automatic session handling.**

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

- **[MCP Server](mcp/index.md)**
  Streamable-HTTP MCP server (`arodonata-mcp`), FastAPI/Starlette embedding, and cached Check Point tool surface.

- **[Examples](examples/index.md)**
  Runnable, narrated scripts covering queries, search, refresh, CPCRUD, and
  production patterns.

</div>

## Why Arodonata?

- **High-concurrency execution** — an `asyncio` API over the Check Point SDK, whose blocking calls run in worker threads; the `RateLimiter` bounds concurrency per MDS member (`concurrent_limit`, default 4).
- **Idempotent CPCRUD Policy-as-Code** — Plan-then-Execute engine with conflict resolution for objects & rules.
- **Zero-config session handling** — transparent authentication, session
  pooling, and auto-recovery on session expiry.
- **Intelligent DB caching** — PostgreSQL (JSONB) or SQLite via SQLAlchemy.
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
- A PostgreSQL 12+ (recommended) or SQLite database for the cache layer

## Package Flavors

Arodonata is available in two installation configurations depending on your use case:

- **`arodonata`**: Core library containing the asynchronous Check Point client, session pooling, database caching (PostgreSQL or SQLite), and declarative CPCRUD engine. Use this when writing Python scripts, backend services, or automation pipelines.
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
        "arodonata>=1.14.0",

        # OR if you need the MCP server / embedded ASGI tools:
        # "arodonata[mcp]>=1.14.0",
    ]
    ```

=== "requirements.txt"

    ```text
    arodonata>=1.14.0
    # or
    arodonata[mcp]>=1.14.0
    ```

For local development against a clone of this repository:

```bash
git clone https://github.com/chkp-antonr/arodonata.git
cd arodonata
uv sync --all-extras --dev
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
    # 1. Create the database engine — the calling app owns its lifecycle:
    #    it creates the engine here and disposes it at the end.
    database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = create_async_engine(database_url)

    # 2. Read MGMT_NAMES, MGMT_SERVERS and API_KEY_VARS from the process
    #    environment (load your .env first, e.g. with python-dotenv); each
    #    variable named in API_KEY_VARS holds one server's API key.
    settings = ArodonataSettings()

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

`get_hosts()` reads through the cache in the client's default `cache_mode="smart"`: a domain with nothing cached yet is loaded in full from the management server on first use, and a cached domain is reloaded only when it has been published since it was cached (checked at most once per TTL window). So the first run against a fresh database returns the server's hosts, it just takes longer. Pass `cache_mode="cache"` (to the call or to `ArodonataClient`) to read only what is already cached, without calling the API. To populate or refresh the cache up front, see [`refresh_objects`](../api/arodonata/api/client.md) and [Smart Refresh](../examples/04-smart-refresh.md).

## First run against a server

The first time the script connects to a management server, Arodonata trusts the certificate that server presents and records its SHA-256 fingerprint in a trust store, `${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json` by default (set `ARODONATA_TLS_KNOWN_HOSTS_PATH` to put it elsewhere, for example in a container with a read-only home).
You will see one WARNING per server, `TLS <host>:<port>: first contact, certificate <fingerprint> trusted and recorded in <path>`.
From then on a different certificate at that address is refused before anything is sent.
To pin fingerprints you took from the server yourself instead of trusting the first contact, see [TLS Verification](../configuration/tls-verification.md).


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
surface, and [`examples/06_crud_operations.py`](https://github.com/chkp-antonr/arodonata/blob/master_v1/examples/06_crud_operations.py)
/ [`examples/README_CRUD.md`](https://github.com/chkp-antonr/arodonata/blob/master_v1/examples/README_CRUD.md)
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
            position: "bottom"         # int (absolute), "top"/"bottom",
                                        # {top|bottom: "section name or uid"}, or
                                        # {above|below: "rule name or uid"}
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

The full JSON Schema ships with the package as `arodonata/cpcrud/checkpoint_ops_schema.json` (`src/arodonata/cpcrud/` in the repo) and is what `validate()` (see [Embedding in applications](#embedding-in-applications)) checks templates against.

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
- A lookup that fails while planning (an API or cache read error, not "not found") never reads as "absent": that operation becomes one `error` action with no command, message `lookup failed, nothing planned (re-plan to retry): …`. If the domain's head (its last published session) can't be read, every operation in that domain becomes such an `error` action, since the plan couldn't be checked for staleness later.
- `apply()` accepts either a `Plan` (from `plan()`) or a template directly
  (in which case it plans first). It always yields `SSEEvent`s as it works,
  followed by a final `ApplyReport` as the last item.
- `apply(..., dry_run=True)` walks the plan and yields the same shape of
  events/report without calling any write API — useful for previewing what
  would happen.
- Other `apply()` flags: `force` (skip the staleness guard, which otherwise refuses a domain with `plan_stale` when it was published since the plan or its head can't be read at apply), `no_publish`/`discard` (control end-of-session publish behavior), `session_name`/`session_description` (label the dedicated session cpcrud opens per domain).

## Retrying partial failures

Some outcomes are retryable: `locked` (session lock held by someone else), `error` (a write failed, or a delete was blocked because its where-used check failed or found references), and `skipped_dependency` (an action's dependency failed first). After a pass, `ApplyReport.remaining` holds a `Plan` scoped to just those actions (actions in domains whose plan went stale are excluded).

Pass `retry_remaining=N` to `apply()` to retry automatically, up to `N`
extra passes, invalidating each affected domain's cache before every retry:

```python
async for event in client.cpcrud.apply(template, retry_remaining=2):
    ...
report = event
```

A plan-time `error` (`lookup failed, nothing planned …`) carries no command, so `retry_remaining` replays it unchanged and it fails the same way on every pass; call `plan()` again to retry the lookup.

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
| `ARODONATA_CPCRUD_SCHEMA_PATH` | `cpcrud_schema_path` | `""` (schema shipped in the package) | Override path to `checkpoint_ops_schema.json` |

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


---

## Architecture — Ports & Adapters

*(source: `docs/architecture/ports-and-adapters.md`)*

# Ports & Adapters

## Facades

- **[`ArodonataClient`](../api/arodonata/api/client.md)**
  (`src/arodonata/api/client.py`) — the main developer entry point. Wraps
  caching, rate limiting, and session management behind helper methods like
  `get_hosts()`, `get_networks()`, `get_access_rules()`.
- **[`AMgmtClient`](../api/arodonata/asdk/client.md)** (`src/arodonata/asdk/`) — the lower-level session-oriented client: login, keepalive, and raw `api_call`/`api_query` calls against the management servers of its `ServerRegistry` (each call names its `mgmt_name`). `api_query` pages listings itself, one call per page (`asdk/pager.py`; `show-*-rulebase` by rules through `rulebase/pager.py`).

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

Check Point management servers rate-limit and are slow to re-authenticate; Arodonata avoids repeating full `show-*` queries by storing objects, gateways, domains, and rulebases in PostgreSQL or SQLite (`src/arodonata/cache/`) as JSON-backed rows via [`CacheRepository`](../api/arodonata/cache/repository.md).

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
  freshness baseline. The baseline stored is the domain's last-published
  session read before the diff, so a publish while the diff is applied is
  picked up by the next refresh.

The same engine backs the `smart-fast` cache mode used by read helpers for objects. Rule reads (`get_*_rules`) do not refresh objects: they use the rulebase sync state (see [Rulebase refresh](#rulebase-refresh)) and refresh only explicitly named domains, on the named management servers or, when none is named, on the first configured one (an application that omits the server is assumed to have one).

## Rulebase refresh

`refresh_rulebases` works per domain. It first reads the domain's last published session, refuses to continue while the shared API session holds unpublished changes or locks (`dirty session`, also with `force`), then reads `show-packages`, the NAT policy of every package with `nat-policy`, and every access, HTTPS and threat layer the packages, the layer listings and the rules' inline layers reach, each completely (pages of 100 with `from`/`to` continuity checked; empty trailing sections recovered). For a package whose global layer holds a place-holder, one more read of that global layer with `package` finds the parent rule and the domain layer nested under it. The domain's whole snapshot (rules, layers, sections, package layouts) and its sync state are then replaced in one transaction, so a domain is cached completely or not at all.

The sync state (`rulebase_sync_state`) records which published session the snapshot was built from, separately from the object cache's baseline. `mode='check'` and smart reads compare it with the domain's current last published session (session uid, publish time as fallback) and re-read only when it differs; `force` always re-reads. If the head cannot be read, `check` treats a domain that already has a usable snapshot (sync state `ok`, current format) as fresh and emits a warning; a domain without one is refreshed, and that refresh then fails on the unreadable head (or, with `force`, stores the snapshot unversioned so the next check re-reads it).

Failures keep the previous snapshot and mark the sync state `failed` with the error: a layer or listing error, an unreadable head (except with `force`), invalid credentials, or a dirty session. A command the server does not have (`generic_err_command_not_found`) leaves that rulebase type empty instead. A failed place-holder link is a warning: that package's place-holder is then numbered without the domain layer. Two refreshes of the same domain running at the same moment (for example a `refresh_rulebases` call and a smart read in another worker) can make the later commit fail on PostgreSQL with a duplicate key; that refresh then reports `domain_failed`, the snapshot written by the other one stays, and the next check refreshes normally.

Legacy rule getters (`get_*_rules`) read the same rows; place-holders are excluded. NAT rows keep the package name as `layer_name`. `sources`, `destinations` and `services` are stored as comma-joined names, so a name that itself contains a comma splits when the rule is read back; the exact values stay in `raw_data` with the layer's objects-dictionary.

Hierarchical numbers (`1`, `2`, `2.1`, `2.2.1`, section ranges `2.1-2.2`, `2.3`, `No Rules`) are not stored: `arodonata.rulebase.numbering.number_package` computes them from a snapshot (`CacheRepository.load_domain_rulebase_snapshot`), exactly as SmartConsole shows them for a package.

## Request concurrency

The `RateLimiter` caps requests in flight per MDS member (`concurrent_limit`, `ARODONATA_CONCURRENT_LIMIT`, default 4), because Check Point serves every domain of a member from one API server. The cap is keyed like the login gate, on the member hosting the domain (the domain row's `active_mds_ip`, else the configured server IP); the request itself still goes to the domain server. Logins, keepalives, session cleanup, system-domain calls and explicit-SID calls (`api_call_with_sid(..., domain=...)`) take a slot on that member; a call without a domain looks the member up by the server IP. A listing (`api_query`) is paged by arodonata itself, one call per page (`asdk/pager.py`): each page takes a slot and releases it, so short calls get in between the pages of long listings. Waiters for a member are served in arrival order within one client, and a release wakes the longest waiter at once; other processes and other clients find a freed slot by polling. Pages hold 300 objects unless the caller sets `limit` (at most 500). Every page is checked against the previous one (`from`, `to`, `total`, repeated uids). A repeated uid does not restart the listing: Check Point orders objects with equal names differently from one request to the next, so a swap at a page boundary repeats one object and hides the other; the repeat is dropped and a window of up to 10 objects on each side of the boundary is re-read in one request to recover the hidden one. A changed `total`, a page that does not continue the previous one (`from`/`to` break), or a final count of distinct objects other than `total` restarts the listing once from the caller's offset; a second failure reports it as failed (`paging_inconsistent`) instead of returning duplicates or gaps. Rulebase commands (`show-access/nat/https/threat-rulebase`) are paged differently, because Check Point counts their `from`/`to`/`total` in rules and returns a section split by a page boundary again on the next page: `api_query` reads them through `rulebase/pager.py` (pages of at most 100 rules, each page continuing the previous one, a split section merged into one entry with all its rules), with the same single restart before `paging_inconsistent`. A call that waits for a task (publish, revert) still holds its slot for the whole task. One `ensure` call refreshes at most `concurrent_limit − 1` (at least one) domains at once per member. A full refresh stores the last-published session read before its listing, so a publish during the listing is picked up by the next incremental refresh.

## Reading from the cache

Helper methods on `ArodonataClient` (`get_hosts`, `get_networks`, `get_groups`, `get_gateways`, `get_access_rules`, ...) always read from the cache — they never make a live API call (`get_domains` may re-read the domain list, see below). For lower-level, filterable access, [`CacheRepository`](../api/arodonata/cache/repository.md) exposes `get_objects()`, `get_objects_by_type()`, `get_objects_by_ip()`, and `get_rulebase()` directly.

`get_domains` refreshes only the domain list (one `show-domains` per management server), never the domains' objects: `cache_mode='cache'` reads the table as is, `smart`/`smart-fast` re-read the list when the table is empty or the domain-list TTL (one hour) has passed, and `force` re-reads it now. Without `mgmt_names` it reads every cached server and refreshes the first configured server's list. On first use, when a server's object cache is still empty, `get_domains` returns the list at once and starts loading every domain's objects in the background (once per server per client; `warm_object_cache_on_first_use`, on by default). Smart and smart-fast object reads of a domain being warmed wait for that domain's refresh instead of starting a second one (explicit `refresh_objects` or `search_objects(refresh='force')` calls are not coordinated and can reload the same domain in parallel; each domain is replaced atomically either way).

A scope's domains are refreshed concurrently: at most `concurrent_limit − 1` (at least one) domains at once per MDS member in one `ensure` call, members in parallel (the cap is per call in one process; see Request concurrency), so a multi-domain server warms several times faster than one domain after another. Each domain is still replaced atomically; the swaps of one client run one at a time, and SQLite connections wait up to 30 s for a busy database (instead of SQLite's default 5 s, unless the engine sets its own timeout) so concurrent refreshes and several processes on one file wait instead of failing with `database is locked`. If a domain fails, the others still run to the end and the first exception is then re-raised.

`close()` cancels a running warm-up at once. `ArodonataClient.object_cache_warm_up(mgmt_name)` reports it (`ObjectCacheWarmUp`: `running`, `finished`, `failed` or `cancelled`, with the refreshed and failed domain counts once it ended); MCP `arodonata_init` shows it per server.

The rulebase facade (`get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase`, `locate_rules`) reads the `rulebase_*` snapshots through `CachedRulebaseSource`, after refreshing the domain session-aware per `cache_mode`. A domain is ready when it has a sync state at the current cache format; a domain whose refreshes only ever failed is not ready, and the not-ready error names the last refresh error. A domain whose last refresh failed is served from its last good snapshot, with `status` and `last_error` set. Numbers reflect the snapshot's published session (`snapshot_session_uid`, published at `snapshot_published_at`), not necessarily an older session a caller is asking about.


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
- **[`rate_limiter.py`](../api/arodonata/asdk/rate_limiter.md)** — per-MDS-member
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

## Server identity per member

Each Gaia install, that is each MDS member (primary or secondary) and each SmartCenter, has its own self-signed API certificate, so the trusted identity is recorded per `host:port` and a standby member is a separate identity from the active one.
A domain server IP hosted on a member most likely presents that member's certificate.
When a new address presents a certificate that is already trusted for another address (in the trust store or in `ARODONATA_TLS_FINGERPRINTS`), it is accepted and, in `tofu` mode, recorded as `known-identity`; an unknown certificate at a new address is learned in `tofu` and refused in `pinned`.
Identity failures are never retried by the login, keepalive or task-wait paths.
See [TLS Verification](../configuration/tls-verification.md).


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
        Executor --> Session["Dedicated session\n(per domain per apply)"]
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

Queries live management state via `ArodonataClient` read operations, or the object cache for hosts, networks, address ranges and groups while the cache's freshness stamp equals the domain's current head, to build `ObjectState` representations. It reads existing object fields, meta-info locks, and rulebase trees without modifying live session state.

### 4. `Planner` (`src/arodonata/cpcrud/planner.py`)

Core decision engine. Transforms normalized template operations into a deterministic `Plan` containing a list of `PlannedAction` items.

- Evaluates `NameConflictPolicy` (`UPDATE` | `ERROR`) and `IpConflictPolicy` (`REUSE` | `CREATE_NEW` | `ERROR`).
- Calculates field diffs via `differ.py`.
- Determines the exact plan-time outcome (`CREATE`, `UPDATE`, `REUSE`, `UNCHANGED`, `DELETE`, `CONFLICT`, `ERROR`); apply adds `LOCKED`, `DRIFTED`, `SKIPPED_DEPENDENCY` and `PLAN_STALE`.
- Records a `DomainStamp` per target domain holding its `last_publish_session` UID (the domain's head session, read before its lookups); a domain whose head cannot be read gets no stamp and its operations become `ERROR`.

### 5. `Executor` (`src/arodonata/cpcrud/executor.py`)

Performs live write operations.

- Opens one dedicated write session per `(mgmt_name, domain_name)` for each apply via `ArodonataClient.create_dedicated_session()` and logs it out (`logout_sid`) when that domain is done, whether it published, discarded or failed.
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
    loop For each target domain
        Planner->>StateReader: get_last_publish_session()
        StateReader->>Mgmt: show-last-published-session (Read-Only)
        Mgmt-->>StateReader: Head session UID (the DomainStamp)
        Planner->>StateReader: object and rule lookups
        StateReader->>Mgmt: show-* and rulebase reads (Read-Only or object cache)
        Mgmt-->>StateReader: Object details / Rule list
        Planner->>Planner: Diff fields & calculate outcomes
    end
    Planner-->>Service: Plan (with PlannedAction list & DomainStamps)
    Service-->>App: Plan object

    App->>Service: apply(plan)
    Service->>Executor: stream(plan)
    loop For each target domain
        Executor->>StateReader: get_last_publish_session() unless force
        StateReader->>Mgmt: show-last-published-session
        Executor->>Mgmt: login dedicated session
        loop For each PlannedAction
            Executor->>Mgmt: add-*/set-*/delete-* API command
            Mgmt-->>Executor: Command result
            Executor-->>App: yield SSEEvent
        end
        Executor->>Mgmt: publish (or discard) session
        Executor->>Mgmt: logout session
    end
    Executor-->>Service: ApplyReport
    Service-->>App: yield ApplyReport
```

The planner's lookups are `get_by_name`, `find_by_ip`, `get_rule_by_key`, `find_rules_by_traffic` and their siblings on the `StateReader`. At apply, a domain whose head is not its stamp (or cannot be read) is `PLAN_STALE` and nothing is written there; otherwise the executor opens a dedicated session with `ArodonataClient.create_dedicated_session`.

---

## Conflict & Drift Detection Architecture

### Domain Stamps & Stale Plan Safeguard

When a `Plan` is created, `Planner` records a `DomainStamp` for each target domain containing the `last_publish_session` UID. It reads the stamp before the domain's lookups, so a publish while the domain is being planned leaves the plan stale instead of being stamped as already seen.

During `apply()`, `Executor` re-checks the target domain's published session UID. If another administrator or script published changes in that domain while the plan was sitting unexecuted, `Executor` aborts execution with `PLAN_STALE` to prevent unintended policy overwrites.

The stamps are read with `ArodonataClient.fetch_last_published_session`, which never stores them: the stored last-published session is the object cache's freshness stamp, and storing cpcrud's reads marked the cache fresh without refreshing it, so cpcrud's own changes (and a publish before the plan) did not reach the cache until a full refresh. After cpcrud publishes, `invalidate_domain` makes the next smart read through the client (`CacheRefreshCoordinator`) compare the stored stamp with the new head and refresh the domain. cpcrud's own cache-first lookups (`HybridStateReader`) do not refresh the cache: they use it for a domain only while its stored stamp is the head the planner just read for that domain, and otherwise look every object up live, so a row from before the last publish (an object deleted or changed since) is never trusted. Each `plan()` and each `apply()` gets its own reader, so the head one run read never decides a cache lookup of another (two concurrent plans of a domain, or an apply with `force` that reads no head).

A head that cannot be read (including a failed or timed-out `show-last-published-session`, which `fetch_last_published_session` logs and reports as no record) never reads as "no stamp": at plan time every operation of that domain becomes an `ERROR` that writes nothing and no lookup runs for it (a plan without a stamp cannot be checked for staleness; template errors in those operations, such as a missing layer, surface on the next plan), and at apply time the domain is `PLAN_STALE` ("could not read the domain's last published session …; re-plan or use force"); `force` skips the check as before. The stamp recorded after cpcrud's own publish is only reported, and is empty if it cannot be read.

### Failed Lookups

A lookup that decides whether something already exists never reads a failed call as "not found": the name lookup (`show-<type>`, except Check Point's own "object not found"), the IP lookup (`show-objects`), the service port listing (`show-services-tcp`/`-udp`), every rulebase read (each page of `show-*-rulebase`) and `where-used` raise `StateReadError` when the call fails, including `paging_inconsistent`. The planner turns that into one `ERROR` action for the whole operation, with `lookup failed, nothing planned (re-plan to retry): …` as its message; neither the operation's auto-created dependencies nor the groups it names are planned, and a failed lookup of a group it names stops the object the same way. Nothing is created, updated or deleted for it, actions that depend on it are skipped (`skipped_dependency`), and the other operations of the template run as usual. At apply time a failed `where-used` blocks the delete (`delete blocked: …`). A retry pass (`retry_remaining`) re-runs the plan without re-planning, so it reports the same error; plan again to retry the lookup. An exception from the transport (a timeout, an unreachable server, a certificate mismatch) during a lookup still aborts the whole plan, so nothing is written then either; the head read is the exception, since `fetch_last_published_session` reports any failure as no record, so the domain's operations become `ERROR` as described above. A NAT rule addressed by key in a package that cannot be read is now an `ERROR` instead of "not found" (a delete used to report "already absent").

### Field Diffing (`differ.py`)

When an object exists, `differ.py` compares the normalized desired attributes against `ObjectState.raw`.

- If no fields differ, the action outcome is set to `Outcome.UNCHANGED` and no API write is executed.
- If fields differ, the action outcome is set to `Outcome.UPDATE` with an explicit `changes` payload detailing old vs new values.

---

## Rule Positioning & Identity Resolution

Access and NAT rules in Check Point do not always have unique global names. `rule_identity.py` and `position_helper.py` handle rule identity and positional anchoring:

1. **Rule Matching (`RuleMatch`)**: An operation with a `key` matches by uid, then name, then rule number (`get_rule_by_key` / `get_nat_rule_by_key`). An `add` matches by traffic: access, HTTPS and threat-prevention rules by the order-independent (source, destination, service) tuple (action and name are not part of it), NAT rules by their positional (original source, destination, service, translated source, destination, service) tuple; when several rules match, the declared name wins, else the topmost.
2. **Positional Target**: `position_helper.py` converts abstract positioning options (`top`, `bottom`, `above`, `below`) into concrete Check Point API `position` structures required during rule creation or reordering. `"bottom"` and `{bottom: section}` are cleanup-aware: when the layer's (or section's) last rule is an any/any/any rule they anchor `{above: <cleanup rule uid>}`, the section's last rule being read from its layer (`StateReader.get_last_rule_in_section`); see [Cleanup-rule-aware `bottom`](../user-guide/cpcrud.md#cleanup-rule-aware-bottom).


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

Each field is read from the environment variable in the second column (case-insensitive) or passed as a constructor keyword under its field name; a constructor keyword wins over the environment. Numeric defaults come from [`constants.py`](../api/arodonata/config/constants.md).

| Field | Env var | Type | Default | Description |
|---|---|---|---|---|
| `mgmt_names` | `MGMT_NAMES` | `str` | `""` | Comma-separated management server names. |
| `mgmt_servers` | `MGMT_SERVERS` | `str` | `""` | Comma-separated management server IPs/hosts, matched by position to `mgmt_names`. |
| `api_keys` | `API_KEYS` (or `API_KEY_VARS`) | `SecretStr` | `""` | Comma-separated **actual** API key values (not variable names), matched by position. Without `api_keys=` or `API_KEYS`, the keys are resolved from `API_KEY_VARS`; see [API keys](#api-keys) below. |
| `username` | `ARODONATA_USERNAME` | `str \| None` | `None` | Username for credential-based auth (alternative to `api_keys`). |
| `password` | `ARODONATA_PASSWORD` | `SecretStr \| None` | `None` | Password for credential-based auth. |
| `mgmt_ip` | `ARODONATA_MGMT_IP` | `str \| None` | `None` | Required when `username`/`password` are set. |
| `session_expire_seconds` | `ARODONATA_SESSION_EXPIRE` | `int` | `3600` | Maximum age in seconds of a cached session SID that a login may reuse; an older one is dropped and a fresh login is made. |
| `session_timeout` | `ARODONATA_SESSION_TIMEOUT` | `int` | `600` | Session timeout passed to the Check Point login API. |
| `concurrent_limit` | `ARODONATA_CONCURRENT_LIMIT` | `int` (1-20) | `4` | Max concurrent API requests per MDS member (logins and calls; per server for a SmartCenter). A listing takes a slot per page and releases it between pages, and waiters are served in arrival order within one client, so a wait is about one page per caller queued ahead; a task wait (publish, revert) holds its slot until the task is done. One cache-refresh call starts at most `concurrent_limit − 1` (at least one) domain refreshes per member; overlapping calls, other processes and long tasks can still use every slot. |
| `rate_limit_slot_timeout` | `ARODONATA_RATE_LIMIT_SLOT_TIMEOUT` | `int` | `90` | Seconds a caller waits for a free concurrency slot before giving up. A task wait holds its slot for the whole task, so keep this generous. |
| `api_timeout` | `ARODONATA_API_TIMEOUT` | `int` | `120` | Per-request API timeout in seconds. |
| `task_timeout` | `ARODONATA_TASK_TIMEOUT` | `int` | `900` | Seconds to wait for a server-side task (publish, install-policy, assign-global-assignment, revert-to-revision) after the call that started it has returned. Separate from `api_timeout`, so a long task is not cut short by a budget sized for one round trip. |
| `login_timeout` | `ARODONATA_LOGIN_TIMEOUT` | `int` | `120` | Per-attempt login timeout in seconds, separate from `api_timeout`. |
| `connect_timeout` | `ARODONATA_CONNECT_TIMEOUT` | `int` | `30` | Seconds for TCP connect plus TLS handshake to a Check Point server. See [TLS Verification](tls-verification.md#timeouts). |
| `tls_trust` | `ARODONATA_TLS_TRUST` | `str` | `"tofu"` | Certificate trust mode: `'tofu'` \| `'pinned'` \| `'lab-memory'` (lab runs only). See [TLS Verification](tls-verification.md). |
| `tls_fingerprints` | `ARODONATA_TLS_FINGERPRINTS` | `str` | `""` | Comma-separated SHA-256 fingerprints trusted at any address, from `api fingerprint -f json`. |
| `tls_known_hosts_path` | `ARODONATA_TLS_KNOWN_HOSTS_PATH` | `str` | `""` | Trust store file; empty means `${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json`. |
| `login_throttle_window` | `ARODONATA_LOGIN_THROTTLE_WINDOW` | `int` | `70` | Seconds to wait for Check Point's login rate limit to clear before retrying a throttled login. |
| `login_max_wait` | `ARODONATA_LOGIN_MAX_WAIT` | `int` | `900` | Total seconds one login may spend waiting out Check Point's per-MDS login rate limit before failing; also the timeout for acquiring the per-domain login lock. |
| `login_retry_backoff` | `ARODONATA_LOGIN_BACKOFF` | `int` | `5` | Backoff (seconds) between login retries. |
| `login_max_retries` | `ARODONATA_LOGIN_RETRIES` | `int` | `8` | Maximum login retry attempts. |
| `warm_object_cache_on_first_use` | `ARODONATA_WARM_OBJECT_CACHE_ON_FIRST_USE` | `bool` | `True` | When `get_domains` finds a management server's object cache empty, load every domain's objects in the background (`get_domains` returns the domain list at once). Set `false` where a full background load (hours on a large MDS) is unwanted. |
| `log_level` | `ARODONATA_LOG_LEVEL` | `str` | `"INFO"` | Logging level. |
| `cpcrud_on_name_conflict` | `ARODONATA_CPCRUD_ON_NAME_CONFLICT` | `str` | `"update"` | Name conflict policy: `'update'` \| `'error'`. |
| `cpcrud_on_ip_conflict` | `ARODONATA_CPCRUD_ON_IP_CONFLICT` | `str` | `"reuse"` | IP conflict policy: `'reuse'` \| `'error'` \| `'create_new'`. |
| `cpcrud_auto_name_prefix_host` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_HOST` | `str` | `"Host_"` | Auto-generated name prefix for hosts on IP conflict. |
| `cpcrud_auto_name_prefix_network` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_NETWORK` | `str` | `"Net_"` | Auto-generated name prefix for networks on IP conflict. |
| `cpcrud_auto_name_prefix_range` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE` | `str` | `"IPR_"` | Auto-generated name prefix for address ranges. |
| `cpcrud_auto_name_prefix_svc_tcp` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_TCP` | `str` | `"TCP_"` | Auto-generated name prefix for TCP services. |
| `cpcrud_auto_name_prefix_svc_udp` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_UDP` | `str` | `"UDP_"` | Auto-generated name prefix for UDP services. |
| `cpcrud_auto_name_prefix_svc_icmp` | `ARODONATA_CPCRUD_AUTO_NAME_PREFIX_SVC_ICMP` | `str` | `"ICMP_"` | Auto-generated name prefix for ICMP services. |
| `cpcrud_refresh_mode` | `ARODONATA_CPCRUD_REFRESH_MODE` | `str` | `"invalidate"` | Post-publish cache refresh: `'invalidate'` \| `'force'`. |
| `cpcrud_schema_path` | `ARODONATA_CPCRUD_SCHEMA_PATH` | `str` | `""` | Optional override path to a `checkpoint_ops_schema.json`; empty uses the schema shipped inside the package (`arodonata/cpcrud/checkpoint_ops_schema.json`). |
| `trace_modules` | `ARODONATA_TRACE_MODULES` | `str` | `""` | Comma-separated `module:on\|off` OTEL span gating, longest dotted-prefix match. See [Tracing](#tracing) below. |

### API keys

`api_keys` is resolved in this order: an explicit `ArodonataSettings(api_keys=...)`, then the `API_KEYS` environment variable (the actual key values), then `API_KEY_VARS`, a comma-separated list of environment variable *names* whose values are the keys, matched by position to `mgmt_names`. So a bare `ArodonataSettings()` with only `API_KEY_VARS` set resolves the keys itself, and the keys can live in a separate, more tightly permissioned file than the server topology; see [Multi-Server Setup](multi-server.md). `arodonata-mcp` reverses the order of the two environment variables: there `API_KEY_VARS` wins over `API_KEYS`.

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

`DATABASE_URL` isn't an `ArodonataSettings` field: it's the application-level convention for the cache database URL. `API_KEY_VARS` names *which* environment variables hold the real keys, and `ArodonataSettings` resolves it when no `API_KEYS` is set, as described in [API keys](#api-keys) above and in [Multi-Server Setup](multi-server.md).

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

`API_KEY_VARS` names the environment variables that hold the *actual* keys, so the keys themselves can live in a separate, more tightly permissioned file (e.g. `.env.secrets`) than the server topology (`.env`/`.env.dev`). `ArodonataSettings` resolves it itself: once the environment above is loaded (e.g. by `python-dotenv`), a bare `ArodonataSettings()` picks up the names, the servers and the keys:

```python
settings = ArodonataSettings()  # MGMT_NAMES, MGMT_SERVERS, and the keys via API_KEY_VARS
```

`API_KEY_VARS` is only the fallback: an explicit `ArodonataSettings(api_keys=...)` or an `API_KEYS` environment variable (the key values themselves) wins over it. `arodonata-mcp` resolves `API_KEY_VARS` itself and gives it priority over `API_KEYS`; see [MCP Server](../mcp/index.md#standalone-server-for-a-team).

Once configured, [`ArodonataClient.get_mgmt_names()`](../api/arodonata/api/client.md) returns the configured server names. The fan-out getters (`get_domains`, `get_gateways`, `collect_gateways_and_servers`, `get_hosts`, `get_networks`, `get_groups`, `get_access_rules`/`get_nat_rules`/`get_https_rules`/`get_threat_rules`, `search_objects`, `refresh_objects`, `refresh_rulebases`) accept an optional `mgmt_names=[...]` filter to scope a query to a subset of them, and query every configured server without it. The single-server methods take one `mgmt_name` instead: `api_call`, `api_query` and `get_object_by_uid` require it, and `get_policy_packages`, `get_package_rulebase`, `get_layer_rulebase` and `locate_rules` take `mgmt_name=None` to mean the first configured server — none of them fans out. See [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md) for how domain resolution layers on top of this for MDM servers.


---

## Configuration — TLS Verification

*(source: `docs/configuration/tls-verification.md`)*

# TLS Verification

Arodonata verifies the identity of every Check Point management server it talks to, and bounds every network operation with a timeout.
This page covers what is verified, the three trust modes, the trust store, how to get and pin a fingerprint, certificate rotation, lab setup, timeouts and the limits of the model.

## What is verified, and why a fingerprint

On-premises management servers (SmartCenter and MDS) serve the Management API from Gaia's web server with `/web/conf/server.crt`.
That certificate is self-signed and unique per Gaia install, it is not issued by the ICA, and it has no usable hostname (the common name is the management IP at generation time and there is no subject alternative name).
There is no certificate authority to check it against and a hostname check would prove nothing, so Arodonata pins the certificate itself: the SHA-256 fingerprint of the server certificate presented at `host:port` must be the one that was trusted for that address.
Expiry is not checked either, because Check Point does not renew this certificate automatically and a pin keeps working after it expires.

The check runs in the connection, after the TLS handshake and before the first application byte, so a refused server never receives a login, an API key or a command.
The message of every refusal says "No request was sent."
Arodonata does not use cpapi's own fingerprint handling (`fingerprints.txt` in the working directory and an interactive prompt); it never reads or writes that file.

## Trust modes

`ARODONATA_TLS_TRUST` selects how a certificate that is not yet trusted for an address is treated.

| Mode | Behaviour |
|---|---|
| `tofu` (default) | Trust on first use. The first certificate seen at `host:port` is trusted and recorded in the [trust store](#the-trust-store); afterwards a different certificate is refused. Needs no configuration. |
| `pinned` | Nothing is learned and nothing is written. Only certificates recorded in the store or listed in `ARODONATA_TLS_FINGERPRINTS` are accepted; any other certificate is refused. |
| `lab-memory` | Like `tofu`, but the certificate is remembered in memory for the lifetime of the process only and nothing is written. Honoured only when `ARODONATA_LAB` is set; otherwise client construction fails with a configuration error. See [Lab setup](#lab-setup). |

In every mode a certificate whose fingerprint is already trusted for another address (in the store, or in `ARODONATA_TLS_FINGERPRINTS`) is accepted for a new address as well, and in `tofu` it is recorded for that address.
This is what lets every domain IP of a Multi-Domain server, which is served by a member's certificate, work after the member itself is trusted.

## The trust store

The store is a JSON file.
The default location is `${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json`; set `ARODONATA_TLS_KNOWN_HOSTS_PATH` to use another file (needed for a read-only home directory, a container or any host where the default directory is not writable).
A relative value is resolved against the current directory.

```json
{
  "version": 1,
  "hosts": {
    "192.0.2.10:443": {
      "sha256": "<64 lowercase hex digits>",
      "pem": "<the certificate in PEM form>",
      "first_seen": "2026-10-04T10:45:08+00:00",
      "source": "tofu"
    }
  }
}
```

- The key is `host:port` exactly as dialled, with the port always explicit (443 by default). IP addresses are normalised, IPv6 addresses are bracketed and host names are lowercased.
- `source` is `tofu` (learned on first use), `known-identity` (accepted for a new address because the same certificate was already trusted elsewhere) or `manual` (written by hand). A hand-written entry may omit `pem`; the certificate is then fetched from the server and must match `sha256`.
- The file is created with mode 0600 inside a directory created with mode 0700. Writes are atomic and serialised across processes with a lock file next to it (`<name>.lock`). A file system that cannot lock it (some network and FUSE mounts) is a trust-store error naming the lock file; point `ARODONATA_TLS_KNOWN_HOSTS_PATH` at a local file.
- A file owned by another user, or writable by everyone, is refused. A group-writable file works but logs a warning (once per file per process). A file that is not valid JSON or has a malformed entry is refused with an error naming the file and is never rewritten.
- In `tofu`, a store whose directory cannot be created or written is an error at the moment Arodonata would learn a certificate, before anything is sent. It never falls back to memory silently.

## Getting a fingerprint

Take the fingerprint from the management server, not from the machine that connects to it.
On the server, in expert mode or clish:

```bash
api fingerprint -f json
```

The value to use is the `fingerprint-sha256` key of the output.
The same value comes from:

```bash
cpopenssl x509 -in /web/conf/server.crt -noout -fingerprint -sha256
```

Two commands that look similar print something else and are rejected with a hint if pasted: `cp_conf finger` (and SmartConsole) show the ICA's fingerprint as words, and `fwm fingerprint` prints an MD5 of the ICA key.
Neither is the API certificate.
SHA-1 values (40 hex digits) are rejected as well; only SHA-256 is accepted.

## Pinning with ARODONATA_TLS_FINGERPRINTS

`ARODONATA_TLS_FINGERPRINTS` is a comma-separated list of SHA-256 fingerprints that are trusted at any address.
Each value may be in any case, with colons or spaces or neither, and with an optional `sha256:` or `SHA256 Fingerprint=` prefix, so the output of `openssl` can be pasted unchanged.

```bash
ARODONATA_TLS_TRUST=pinned
ARODONATA_TLS_FINGERPRINTS=AB:CD:...:EF,12:34:...:90
```

Fingerprints are public data, not secrets, so they may live in an ordinary env file.
An invalid value is a configuration error at startup, not a surprise at the first connection.

## Certificate rotation

The server certificate changes when an administrator regenerates or replaces it, when the management IP changes, and, on Endpoint management servers that serve the ICA-issued `sic_cert.pem` on port 443, when SIC renews it.
Arodonata then refuses the connection (see [What a mismatch looks like](#what-a-mismatch-looks-like)); an unexpected change is exactly what the check exists to catch, so confirm it on the management server first.

If the change is legitimate, either replace the `sha256` value of that host in the store file (keep the entry, do not delete it: a deleted entry would let `tofu` trust whatever answers next) or add the new fingerprint to `ARODONATA_TLS_FINGERPRINTS`, which takes precedence over the store.
After a store edit a running process needs no restart: the store is re-read on every check. A process that has not yet connected to that host accepts the new value at once. A process that has already connected to it anchors its next connection on the old certificate, so that one attempt is refused with "changed during the connection", and the attempt after it uses the new value. `ARODONATA_TLS_FINGERPRINTS` is read from the environment when the process starts, so a running process (for example `arodonata-mcp`) needs a restart after that value changes.

## What a mismatch looks like

The message names the address, both fingerprints in colon form and the way to check on the server, and says that no request was sent:

```text
TLS certificate of 192.0.2.10:443 does not match the trusted one. No request was sent.
  expected SHA-256:  AB:CD:...:EF (from /home/user/.local/state/arodonata/tls_known_hosts.json)
  presented SHA-256: 12:34:...:90
  presented SHA-1:   ...
Check on the management server: 'api fingerprint -f json', or 'cpopenssl x509 -in /web/conf/server.crt -noout -fingerprint -sha256'.
If the change is legitimate, replace the sha256 value of 192.0.2.10:443 in /home/user/.local/state/arodonata/tls_known_hosts.json (do not delete the entry), or add the new value to ARODONATA_TLS_FINGERPRINTS.
```

In `pinned` mode an unknown certificate is reported as "is not trusted" with the presented fingerprint.
These failures are never retried; the login, the keepalive and task polling all stop at once.

Logging: a first trust is a WARNING, a certificate accepted because it is already trusted elsewhere is INFO, and every refusal is logged once per address and presented fingerprint per process at ERROR with the full message.

Through the [MCP server](../mcp/index.md) the model receives the address, the presented and expected fingerprints, "No request was sent.", that the check is `api fingerprint -f json` on the management server, and that re-trusting is the operator's job on the MCP host, never a ready-to-run command.
The full detail is in the MCP server's log.
No MCP tool can change trust.

## Lab setup

For a lab, pin the servers instead of learning them: harvest each member's fingerprint once and put it in the lab's env file.

```bash
# .env.lab.<profile>
ARODONATA_TLS_TRUST=pinned
ARODONATA_TLS_FINGERPRINTS=<one SHA-256 per member, comma-separated>
```

Nothing is then written and nothing is learned.
`lab-memory` exists for a lab whose fingerprints have not been harvested yet: it reads the store if there is one, never creates a directory, file or lock file, and trusts each process's first contact.
It logs a WARNING when it starts and for each host it learns, and it refuses a certificate change within the process.
It works only when `ARODONATA_LAB` is set, so it cannot be switched on by accident in production.

## Timeouts

Before this feature the underlying cpapi had no socket timeout at all, so an unresponsive server could block a call forever.
Two timeouts now apply to every connection:

- `ARODONATA_CONNECT_TIMEOUT` (default 30 seconds) bounds the TCP connect and the TLS handshake. DNS resolution is not covered, because Arodonata dials IP addresses.
- The read timeout bounds each wait for the server's answer. A call with a budget of its own (an `api_call` with a timeout, and logins) gets that budget plus 5 seconds. Every other call, including `show-task` polls, gets `max(ARODONATA_API_TIMEOUT, ARODONATA_LOGIN_TIMEOUT) + 5` seconds, which is 125 seconds with the defaults.

`asyncio.wait_for` stays the overall deadline of a call.
Long operations such as publish and install-policy return a task ID at once and are then polled, so they are not affected by the read timeout.

A socket timeout (connect, handshake or read) raises `ApiTimeoutError` (a `TimeoutError`) whose `phase` is `connect` or `read`; it names the server and, when a request was under way, the command. The overall deadline of a call (`asyncio.wait_for`) still raises a plain `TimeoutError`; for logins its message is "Login timed out after <N>s" or "Credential login timed out after <N>s". `except TimeoutError` catches both.
A request that has been sent is never sent a second time after a read timeout; the message says the command may still have run on the server, so check the server before repeating a change.
For logins a timeout counts as "slow", not "unreachable", and one slow `show-task` poll no longer ends a publish or install wait.

## Security model and residuals

- **First contact in `tofu`.** The first certificate seen at an address is trusted without any outside confirmation. Anyone who can intercept that very first connection can be recorded as the server. Use `pinned` with fingerprints taken from the server where that matters.
- **New addresses.** A new address with an unknown certificate is learned in `tofu`, so a changed IP in `MGMT_SERVERS` is trusted on first contact like a new server.
- **`lab-memory`.** Each process trusts its first contact and forgets it on exit. Use it only for labs, and prefer pins.
- **Endpoint management.** Servers that present `sic_cert.pem` change certificate when SIC renews; expect a refusal and re-trust as described under [rotation](#certificate-rotation).
- **Re-send after a dropped connection.** When the server drops the connection after receiving a request (not after a timeout), cpapi sends the request again on a new connection. That connection is verified like every other, so the request only ever reaches the trusted server, but the command can run twice. This is an integrity issue, not an identity one; refusing every re-send is Backlog item 30.
- **The store is a trust root.** Whoever can write the store file can change who is trusted. Keep it owned by the service user with mode 0600.
- **Not covered.** The check authenticates the server, not the network path; DNS is not involved because IP addresses are dialled. The MCP server's own inbound TLS (`--ssl-certfile`) is a separate matter, see [MCP Server](../mcp/index.md#tls).

## Settings

| Variable | Default | Description |
|---|---|---|
| `ARODONATA_TLS_TRUST` | `tofu` | `tofu`, `pinned` or `lab-memory`. |
| `ARODONATA_TLS_FINGERPRINTS` | empty | Comma-separated SHA-256 fingerprints trusted at any address. |
| `ARODONATA_TLS_KNOWN_HOSTS_PATH` | empty (default location) | The trust store file. |
| `ARODONATA_CONNECT_TIMEOUT` | `30` | Seconds for TCP connect plus TLS handshake. |


---

## MCP Server

*(source: `docs/mcp/index.md`)*

# MCP Server

Arodonata can serve any MCP client over streamable HTTP, exposing the same `show_*` tools as Check Point's `@chkp/quantum-management-mcp` but answered from Arodonata's cache with automatic re-login, per-MDS login gating and rate limiting, across every configured management server and domain.
It ships as both a standalone command (`arodonata-mcp`) for a team to point clients at, and as a library (`arodonata.mcp`) for embedding the same tool set inside your own ASGI application.

## Install

```bash
uv pip install "arodonata[mcp]"
```

## Standalone server for a team

`arodonata-mcp` loads `.env.lib` then `.env.secrets` (override with `--env-file`, repeatable), builds an `ArodonataClient` from the library's usual environment variables (`DATABASE_URL`, `MGMT_NAMES`, `MGMT_SERVERS`, `API_KEY_VARS`, ...), and serves it over streamable HTTP with `uvicorn`.
It resolves API keys itself: `API_KEY_VARS` (a comma-separated list of environment variable names whose values are the actual API keys) takes priority, and a bare `API_KEYS` value is used when `API_KEY_VARS` is unset. This is the reverse of a bare `ArodonataSettings()`, where `API_KEYS` wins and `API_KEY_VARS` is the fallback (see [API keys](../configuration/index.md#api-keys)).

```bash
arodonata-mcp --host 0.0.0.0 --port 8765
```

Flags: `--env-file` (repeatable; default `.env.lib` then `.env.secrets`), `--host` (overrides `ARODONATA_MCP_HOST`), `--port` (overrides `ARODONATA_MCP_PORT`), `--ssl-certfile`, `--ssl-keyfile`, `--log-level` (one of `critical`, `error`, `warning`, `info`, `debug`; default `info`; below `debug` the SDK's per-request `Terminating session: None` line from `mcp.server.streamable_http` is hidden, its warnings and errors still show), `--shutdown-timeout` (overrides `ARODONATA_MCP_SHUTDOWN_TIMEOUT`). An invalid flag or an inconsistent configuration (for example a different number of `MGMT_NAMES`, `MGMT_SERVERS` and API keys) prints one `arodonata-mcp: configuration error: ...` line and exits with status 2.

The command refuses to start with `ARODONATA_MCP_AUTH_MODE=host` or `jwt` (exit code 2): `host` mode has no verifier at all and would serve every request anonymously if there is no authenticating host in front of it, and `jwt` is reserved and not implemented. See [Authentication](#authentication) below.

### Configuration

Every field below is read from an environment variable named `ARODONATA_MCP_<FIELD>` (case-insensitive), or passed as a constructor keyword to `ArodonataMCPSettings` when embedding.

| Variable | Default | Description |
|---|---|---|
| `ARODONATA_MCP_HOST` | `127.0.0.1` | Bind address. |
| `ARODONATA_MCP_PORT` | `8765` | Bind port (1-65535). |
| `ARODONATA_MCP_PATH` | `/mcp` | Streamable HTTP path; must start with `/`. |
| `ARODONATA_MCP_PUBLIC_URL` | `http://127.0.0.1:8765/mcp` | URL clients use; also the OAuth issuer/resource-server URL, and the basis for the default `ALLOWED_HOSTS`/`ALLOWED_ORIGINS` below. |
| `ARODONATA_MCP_STATELESS` | `true` | Streamable HTTP stateless mode. |
| `ARODONATA_MCP_JSON_RESPONSE` | `true` | Return plain JSON instead of SSE for tool responses. |
| `ARODONATA_MCP_LIVE_COMPAT` | `true` | Register the live `show_*` compatibility tools (see [Tools](#tools)). |
| `ARODONATA_MCP_CPCRUD` | `false` | Register the opt-in `cpcrud_*` tools. |
| `ARODONATA_MCP_ALLOW_WRITE_API` | `false` | Allow `api_call` to run non-`show-*` (write) commands. |
| `ARODONATA_MCP_AUTH_MODE` | `static` | `static` or `host`; `jwt` is reserved and rejected everywhere. See [Authentication](#authentication). |
| `ARODONATA_MCP_TOKEN_VARS` | `""` | Comma-separated environment variable names whose values are accepted bearer tokens (`auth_mode=static`). |
| `ARODONATA_MCP_JWT_ISSUER` | `""` | Reserved for the unimplemented `jwt` mode. |
| `ARODONATA_MCP_JWT_AUDIENCE` | `""` | Reserved for the unimplemented `jwt` mode. |
| `ARODONATA_MCP_JWT_JWKS_URL` | `""` | Reserved for the unimplemented `jwt` mode. |
| `ARODONATA_MCP_DEFAULT_LIMIT` | `50` | Default page size for list tools; `0` returns everything. |
| `ARODONATA_MCP_MAX_RESULT_CHARS` | `200000` | Truncate a tool's text result past this many characters, appending an offset/limit hint to resume. |
| `ARODONATA_MCP_SHUTDOWN_TIMEOUT` | `5` | Seconds Ctrl+C waits for open client connections (Claude Code keeps one open) and then for Check Point SDK calls stuck in network I/O; past it the server closes the connections and exits without waiting for the stuck calls, logging how many were left. |
| `ARODONATA_MCP_ALLOWED_HOSTS` | derived from `host`, `port` and `public_url` | Comma-separated Host header values accepted (DNS-rebinding protection); a request with an unlisted Host header gets HTTP 421. |
| `ARODONATA_MCP_ALLOWED_ORIGINS` | derived from `host`, `port` and `public_url` | Comma-separated Origin header values accepted; a request with an unlisted Origin gets HTTP 403 (a request with no Origin header, e.g. from a non-browser client, is accepted). |

### TLS

This section is about the MCP server's own inbound TLS, the connection from MCP clients to `arodonata-mcp`.
The connections from Arodonata to the Check Point management servers are verified separately, by certificate fingerprint; see [TLS Verification](../configuration/tls-verification.md).
`arodonata-mcp` checks the trust store at startup: with the default `tofu` mode and a store that cannot be created or written, a corrupt or unsafe store, `lab-memory` without `ARODONATA_LAB`, or an invalid `ARODONATA_TLS_TRUST` or fingerprint value, it exits with status 2 and a message naming the cause (for an unwritable store, a hint to set `ARODONATA_TLS_KNOWN_HOSTS_PATH` or use `pinned`).
When a tool hits an identity failure or a trust-store problem, the model gets the facts and "Operator action required on the MCP host; retrying will not help."; on a timeout it gets the server, the timeout and the phase (`connect` or `read`), and after a read timeout that the command may still have run on the server. No MCP tool can change trust.

For inbound TLS, either pass `--ssl-certfile`/`--ssl-keyfile` to `arodonata-mcp`, or terminate TLS at a reverse proxy in front of it. Binding to a non-loopback address without `--ssl-certfile` logs a warning: org policy requires TLS 1.2+ for all data in transit, and bearer tokens travel in the `Authorization` header on every request.

## Authentication

`ARODONATA_MCP_AUTH_MODE=static` (the default) checks the request's bearer token with a constant-time comparison against the values of the environment variables named in `ARODONATA_MCP_TOKEN_VARS`, resolved the same way `API_KEY_VARS` resolves API keys — i.e. from `.env.secrets` or the process environment, never written into `.env.lib`. The variable name (not the token value) is what appears as the caller's identity in logs and as the tool call's `client_id`, so give each caller or team its own named variable.

`ARODONATA_MCP_AUTH_MODE=host` disables Arodonata's own token verification entirely (`create_mcp_server` builds no `TokenVerifier`) so that an authenticating ASGI host in front of `create_asgi_app`'s mount point — your own middleware, an API gateway, a service mesh sidecar — is the sole authority. The standalone `arodonata-mcp` executable has no such host, so it refuses `auth_mode=host` at startup; this mode only makes sense when [embedding](#embedding-in-your-application).

`ARODONATA_MCP_AUTH_MODE=jwt` is reserved for a future JWT-against-an-identity-provider mode and is rejected everywhere it is read — by `arodonata-mcp` at startup, and by `create_mcp_server` — because the stub verifier raises `NotImplementedError` on every call.

## Embedding in your application

Call `create_mcp_server` to build the `MCPServer` yourself (so you can register application-specific tools alongside the Arodonata ones) and `create_asgi_app` to turn it into a mountable Starlette app. You own the `ArodonataClient` and its database engine: open the client before serving and close it after, and dispose the engine yourself.

```python title="examples/09_mcp_embedded.py"
--8<-- "examples/09_mcp_embedded.py"
```

Identity follows the client, not the caller: one `ArodonataClient` means one Check Point identity (one set of API keys/credentials) for every MCP caller that reaches it, regardless of which bearer token or host-level identity they authenticated with. Give each Check Point identity that needs different access its own `ArodonataClient` and its own mounted app.

## Tools

Every tool returns plain text, not MCP structured content. That text is JSON, except for the rulebase tools with `format="markdown"` (the default, a markdown table) or `format="model_friendly"` (compact structured text); rulebase tools return JSON only for `format="raw"`. List tools return an envelope alongside the page of objects: `from`/`to`/`total` (1-based, describing that page), `source` (`"cache"` or `"live"`) and `cache_age_seconds`. A failed Management API call comes back as an error result whose text is `"<code>: <message>"`, carrying the Check Point error code and message verbatim, except that a SID the message echoes is masked. Validation problems such as a missing or unknown `mgmt_name` come back as error results naming the configured servers, e.g. `"unknown mgmt_name '<name>'; configured servers: <names>"` or `"mgmt_name is required; configured servers: <names>"`. An unexpected server-side exception never reaches the caller as a message or traceback: it comes back as an error result whose text is `"internal error: <ExceptionClass>"`, with the exception logged server-side instead.

Cache-backed tools answer from Arodonata's local cache by default; pass `cache_mode='smart'` to re-sync stale domains first or `cache_mode='force'` for a full reload from the management server. Live tools always query the management server (through Arodonata's session cache and rate limiter) and take no `cache_mode`. Live list tools currently retrieve the full collection from the management server and page it locally, so `limit` bounds the response size but not the work done on the management server. `cpcrud_*` tools are opt-in (`ARODONATA_MCP_CPCRUD=true`); `api_call` can additionally run write commands when `ARODONATA_MCP_ALLOW_WRITE_API=true`.

### Native tools

| Tool | Backing | Notes |
|---|---|---|
| `arodonata_init` | cache | Call this first: lists configured management servers, whether each is MDS, their domains, and cache age. A server whose empty object cache is being loaded in the background carries `object_cache_warm_up` (`running` with `running_seconds`, or how it ended with the refreshed and failed domain counts), and the guidance says so while it runs. |
| `search_objects` | cache | Searches cached objects across servers/domains by name, IP or pattern, following group membership; returns `results` as a list of `{mgmt_name, domain, search_term, search_type, objects, memberships}`. |
| `refresh_objects` | live | Re-syncs the object cache from the management server(s); `mode='incremental'` pulls only changes since the last publish. |
| `refresh_rulebases` | live | Re-syncs cached access, NAT, HTTPS and threat rulebases per domain; `mode='check'` re-reads only domains with a new published session; accepts `include_global`; failures (including `dirty session` while the shared session holds unpublished changes) land in `errors`. |
| `api_call` | live | Runs any Management API command through Arodonata's session handling; only `show-*` commands unless writes are enabled. |

### Cached tools

| Tool | Backing | Notes |
|---|---|---|
| `show_hosts` | cache | `filter` matches the object name (wildcards allowed). |
| `show_networks` | cache | `filter` matches the subnet in CIDR notation (e.g. `10.0.0.0/24`). |
| `show_groups` | cache | `filter` matches the group name; includes member UIDs. |
| `show_gateways_and_servers` | cache | Gateways, clusters, cluster members and management servers; no `domain` parameter (gateways live in the asset cache, not the per-domain object cache) and always reports `cache_age_seconds: null`. |
| `show_domains` | cache | Domains of a Multi-Domain server; `include_global` adds the Global domain, which `show-domains` never lists: its UID and active MDS member come from `show-global-domain`. Always reports `cache_age_seconds: null` (the domain cache keeps no timestamp). |
| `show_object` | cache | Any object by UID. |

### Rulebase tools

| Tool | Backing | Notes |
|---|---|---|
| `show_access_rulebase` | cache/live | Addressed by `name` or `uid` (plus `package`); on the cache path `package` alone is enough (the package's SmartConsole numbering), the live path needs `name` or `uid`. |
| `show_nat_rulebase` | cache/live | Addressed by `package` only — NAT has no `name`/`uid`. |
| `show_https_rulebase` | cache/live | Addressed by `name` or `uid` (plus `package`); on the cache path `package` alone is enough (the package's SmartConsole numbering), the live path needs `name` or `uid`. |
| `show_threat_rulebase` | cache/live | Addressed by `name` or `uid` (plus `package`); on the cache path `package` alone is enough (the package's SmartConsole numbering), the live path needs `name` or `uid`. |

All four are cache-backed by default and switch to a live query when any of `filter`, `filter_settings`, `show_hits`, `hits_settings`, `use_object_dictionary`, `show_as_ranges`, `show_expiration_settings` or `order` is given (`order` is a list of objects, e.g. `[{"ASC": "name"}]`, as the Management API expects). `enabled_only=true` drops disabled rules (together with any inline layer they call) on the cache path, leaving the remaining rules' numbers unchanged; it is not one of the live-only parameters, so it does not force a live query, and the live path ignores it. `format` selects `raw` (API shape), `markdown` (default; a table with full, non-truncated cell values) or `model_friendly` (compact structured text). On the cache path a layer (by `name` or `uid`) is shown with layer-relative hierarchical numbers (`1`, `2.1`, ...): a header row per section with its rule range, place-holders marked, and inline layers expanded beneath the rule that calls them. Passing `package` shows that package's SmartConsole numbering instead (global layer, parent rule, `2.x`, `2.2.1`); `name`/`uid` then picks one ordered layer of it, and NAT is always shown this way. A call without `domain` reads the one cached domain holding the layer (or package); when several do, it fails listing the candidates as `domain/uid` so you can pass `domain` or `uid` (only `domain` when the `uid` you passed is held by several domains, as a Global layer is). Object references are rendered as names from the layers' objects dictionaries. `cache_age_seconds` (and the footer's age) is the age of that domain's last rulebase refresh; a domain whose last refresh failed is shown from its last good snapshot, with a note naming the error. `format='raw'` returns the numbered entries (`number`, `depth`, `layer` on each rule) plus an `objects-dictionary`, and the domain's rulebase sync `status` and `last_error`. The live path reads the whole layer and numbers its rows with section rows too, naming inline layers without expanding them. On both paths `limit`/`offset` slice the rendered rows, section rows included.

### Change report tool

| Tool | Backing | Notes |
|---|---|---|
| `change_report` | live (read-only) | Evidence of what policy sessions changed, as markdown: rules with SmartConsole numbers, objects and sections, added/modified/deleted. |

Parameters: `domain` (required; `""` for an SMS), `mgmt_name` (required when several servers are configured), `session_uids` (explicit sessions, published or not), a published range with `from_session` (exclusive) / `to_session` (inclusive) and/or `from_date` / `to_date` (ISO 8601 with a UTC offset), and `max_rules` (default 100). Give `session_uids`, a range, or both.

The tool is always registered, in the cached group, although it reads the live Management API: it reads `show-changes` and `show-object` (for member names) and numbers rules from the rulebase cache, which it may refresh first with a read-only rulebase read. There is no owned session in MCP, so unpublished sessions get provisional numbers, labelled as such. Caps: 20 sessions of a range (a warning names the `from_session` to continue from), at most 200 `show-object` name lookups per report, at most 200 object rows in the markdown, and `max_rules` rule rows.

The output is markdown only; HTML and JSON evidence are available through the library, see [Change Report](../user-guide/change-report.md). Output longer than `max_result_chars` is cut at the last complete line with the marker `…output truncated at <N> characters, full report via the library`.

### Live compatibility tools

Generated from the same manifest as the reference server's tool list, one tool per `show-*` Management API command not covered above: `show_objects`, `show_access_layers`, `show_packages`, `show_mdss`, `show_simple_gateways`, `show_simple_clusters`, `show_cluster_members`, `show_lsm_gateways`, `show_lsm_clusters`, `show_unused_objects`, `show_services_tcp`, `show_services_udp`, `show_services_icmp`, `show_service_groups`, `show_application_sites`, `show_application_site_groups`, `show_application_site_categories`, `show_wildcards`, `show_security_zones`, `show_tags`, `show_address_ranges`, `show_multicast_address_ranges`, `show_dynamic_objects`, `show_dns_domains`, `show_time_groups`, `show_access_point_names`, `show_vpn_communities_star`, `show_vpn_communities_meshed`, `show_vpn_communities_remote_access`, `show_access_layer`, `show_access_section`, `show_nat_section`, `show_access_rule`, `show_vpn_community_star`, `show_vpn_community_meshed`, `show_vpn_community_remote_access`, `show_simple_gateway`, `show_simple_cluster`, `show_cluster_member`, `show_lsm_gateway`, `show_lsm_cluster`, `where_used`. All of these are live; disable the whole set with `ARODONATA_MCP_LIVE_COMPAT=false`.

### CPCRUD tools (opt-in, `ARODONATA_MCP_CPCRUD=true`)

| Tool | Backing | Notes |
|---|---|---|
| `cpcrud_validate` | none | Validates a template (a YAML/JSON string or an object) against the schema; no network I/O. A string is always parsed as YAML/JSON content, never treated as a file path on the server. |
| `cpcrud_plan` | cache | Computes the idempotent change plan without touching the management server's policy. |
| `cpcrud_apply` | live | Applies a plan or template; `dry_run=true` (default) executes nothing. |
| `cpcrud_inverse` | none | Builds the compensating template that undoes a plan. |

### Prompts

| Prompt | Purpose |
|---|---|
| `show_gateways_prompt` | Guide showing installed policies per gateway. |
| `show_policies_prompt` | Guide walking packages → layers → rulebases. |
| `show_rule_prompt` | Guide finding one rule by reference. |
| `topology_visualization_prompt` | Guide producing an SVG topology diagram for a gateway. |
| `source_to_destination_prompt` | Guide determining possible paths between two endpoints. |

## Differences from the reference server

- Multi-server, unlike the reference server's one-host-per-process model: the `show_*` tools, `change_report` and `api_call` take an optional `mgmt_name` (required only when more than one server is configured); `search_objects`, `refresh_objects` and `refresh_rulebases` take an optional `mgmt_names` list and cover every configured server without it; `arodonata_init` takes no server and reports all of them; the `cpcrud_*` tools take no server parameter (a template names its servers itself).
- List envelopes carry `source` (`"cache"` or `"live"`) and `cache_age_seconds` alongside the objects, so a client can tell whether an answer came from the cache and how stale it is.
- Cache-backed tools (including the cache path of the `show_*_rulebase` tools) take `cache_mode`: `cache` reads the cache as-is, `smart` re-syncs stale domains first, `smart-fast` re-syncs incrementally, `force` does a full reload. For the `show_*_rulebase` tools, `smart`, `smart-fast` and `force` refresh the rulebases of the named `domain` only (session-aware); without `domain` the one cached domain holding the layer or package is resolved and refreshed the same way. Omit it for the server default. Live tools and `api_call` do not take `cache_mode`.
- Rulebase tools support `format` values `raw`, `markdown` and `model_friendly`; unlike the reference server's fixed-width padded table, cells always carry full, non-truncated values.
- `find_zero_hits_rules` and `simulate_packet` from the reference server are not ported in this version.
- HTTP only: no stdio transport.

## Client configuration

Claude Code:

```bash
claude mcp add --transport http arodonata https://mcp.example.com/mcp --header "Authorization: Bearer ${ARODONATA_TOKEN}"
```

Claude Desktop (custom connector), as a JSON entry under the connector's settings:

```json
{
  "url": "https://mcp.example.com/mcp",
  "headers": {
    "Authorization": "Bearer ${ARODONATA_TOKEN}"
  }
}
```


---

## User Guide — CRUD Operations

*(source: `docs/user-guide/cpcrud.md`)*

# CPCRUD — Idempotent Policy-as-Code Engine

The **CPCRUD** (Check Point Policy-as-Code CRUD) engine in `arodonata` provides declarative, conflict-aware, and idempotent object and rule operations across Check Point security management servers and multi-domain environments (MDM).

With `client.cpcrud`, you define desired security management state in YAML or JSON templates. The engine inspects live state, resolves conflicts, computes exact field-level diffs, and executes only the minimal required operations in dedicated session transactions.

---

## Key Features

- **Idempotent Execution**: Re-running the exact same template produces zero state mutations once applied (`outcome: unchanged` / `reuse`).
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

A lookup that fails (an API or cache read error) is never taken as "not found": the operation becomes one `error` action that writes nothing, with the message `lookup failed, nothing planned (re-plan to retry): …`. If a domain's head (its last published session) can't be read, every operation in that domain is planned as such an `error`, because the plan couldn't be checked for staleness at apply. These actions carry no command, so `retry_remaining` can't fix them; call `plan()` again.

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

Before writing to a domain, `apply()` re-reads its head. If the domain was published since the plan, or its head can't be read, every action in that domain gets `plan_stale` and nothing is written there (re-plan, or pass `force=True` to skip the check). A `delete` is blocked with `error` while the object still has references, or when its where-used check fails.

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
      - name: "Domain4"                # Target Domain ('SMC User' on a single-domain server)
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
- **`create_new`**: Creates the requested object under its own name despite the overlap (`outcome: create`); the IP conflict is recorded on the action.
- **`error`**: Nothing is raised; the action gets `outcome: conflict` with the message `ip conflict; policy=error`, and nothing is written for it.

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

When you target `"bottom"` (whole layer) or `{bottom: "Section Name"}` (a section), CPCRUD checks the actual last rule in that scope first (for a section, read from its layer). If it has `source: Any`, `destination: Any`, **and** `service: Any` — regardless of its `action` or `name`, so this also catches an "accept any/any/any" rule, not just a "drop" cleanup rule — the new rule is inserted one position *above* it instead of literally at the bottom, so it never lands after an existing catch-all rule. If the last rule isn't a full any/any/any rule, `"bottom"` is used literally. For a section ending in such a rule (typically a `Cleanup` section holding the cleanup rule), the new rule goes into that section just above it; without the check it would land after the drop rule and never match. The insert is anchored on the catch-all rule's uid (`position: {above: <uid>}`), not on its rule number, so several rules added at the same bottom in one apply keep their template order.

This cleanup-aware behavior applies to access/HTTPS/threat-prevention layers only. `nat-rule` positioning does not have it — NAT rulebases have no equivalent implicit cleanup rule — and section-relative positioning (`{top: ...}`/`{bottom: ...}`) is not supported for NAT rules at all; use `"top"`, `"bottom"`, an integer, or `{above: ...}`/`{below: ...}` instead.

---

## Execution Options & Session Handling

The `apply()` method accepts keyword arguments to fine-tune execution and transactional publishing:

```python
async for event in client.cpcrud.apply(
    template_path,
    dry_run=False,        # Preview mode without making live modifications
    force=False,          # Skip the plan-staleness guard (domain published since plan, or head unreadable)
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

## Change Report

*(source: `docs/user-guide/change-report.md`)*

# Change Report

## What it is

The change report is evidence of what Check Point policy sessions changed: the rules (with their SmartConsole numbers), the objects and the sections that were added, modified or deleted, grouped by management server > domain > session. Each session shows its name, uid and administrator.

One `ChangeReport` model feeds three formats: HTML (one self-contained file with inline CSS, no scripts and no external resources, meant to be attached to a change ticket), JSON (the `ChangeReport` itself, which can be stored and re-rendered later) and markdown (what the MCP tool returns). It is a library feature: there is no CLI. The MCP server exposes a markdown-only tool, see [MCP Server](../mcp/index.md).

## Install

HTML needs the `report` extra (Jinja2):

```bash
uv sync --extra report
# or, in another project
uv pip install 'arodonata[report]'
```

JSON and markdown need nothing extra. Requesting `html` without the extra raises an `ImportError` that names the extra.

## Quick start

```python
from pathlib import Path

from arodonata.reports.changes import RenderOptions, SessionScope

scope = SessionScope(mgmt_name="sms-1", domain="Domain5", session_uids=["<session uid>"])
options = RenderOptions(title="Change evidence **RITM0012345**", header_fields={"RITM": "RITM0012345"})

result = await client.build_change_report([scope], ["html", "json"], options)
Path("evidence.html").write_bytes(result.html)
```

`client.collect_change_report(scopes)` talks to the management server and returns a `ChangeReport`; `render_change_report(report, formats, options)` turns a report into the requested formats without any Check Point access; `client.build_change_report(scopes, formats, options)` does both. Only the requested formats are built. `ChangeReportResult` carries `report` (always set) and `html`, `json`, `markdown` (`None` unless requested).

The report is read-only: it uses `show-changes`, plus `show-object` for names and read-only rulebase reads for numbering. Nothing is written to the management server. A complete lab script is in [Change Report Evidence](../examples/10-change-report-evidence.md).

## Scopes

A report is built from a list of scopes. Scopes may mix management servers and domains; they are merged into one report and a session that several scopes name appears once.

- `SessionScope(mgmt_name=None, domain="", session_uids=[...], owned_session=None)`: explicit sessions, published or not. Each uid is fetched on its own with one `show-changes to-session=<uid>` request.
- `RangeScope(mgmt_name=None, domain="", from_session=None, to_session=None, from_date=None, to_date=None)`: the published sessions between bounds. `from_session` is exclusive and `to_session` is inclusive, as on the server. `from_date` and `to_date` are inclusive and exact, compared with each session's publish time, and must be timezone-aware.

`mgmt_name=None` means the first configured server (the library never fans out to all servers). `domain=""` is the value for an SMS (a server without domains).

Dates need care because the server accepts only offset-less local-time dates. The library converts your aware datetimes to the server's offset (read from the last published session), widens the server window, and then filters exactly on the publish time. A range given with `from_session` never sends dates to the server (the server refuses the combination), the dates are applied client-side instead. An empty window is an empty range, not an error; a `from_date` in the future returns nothing; a `to_date` close to now is not sent.

## Validation

Bad input fails early and loudly, everything else becomes a warning in the report.

Raised as `pydantic.ValidationError` when a scope is constructed:

- a naive datetime (no timezone)
- an empty `session_uids`
- a range without a lower bound (`from_session` or `from_date`)
- a range with only `to_session` (that is one session, use `SessionScope`) or only `to_date` (it would cover all history)
- `from_date` after `to_date`

Raised as `ChangeReportInputError` when collecting:

- an empty scope list
- an item that is not a `SessionScope` or `RangeScope`
- an unknown `mgmt_name`
- no configured server

Warnings are `ReportWarning` entries (`mgmt`, `domain`, `code`, `message`, `severity` of `info` or `warning`, optional `session_uid`) and are listed in every format:

| Code | Meaning |
|---|---|
| `domain_unavailable` | `show-changes` failed for the domain; the domain shows its error code and message, other domains continue |
| `session_not_found` | a requested session was not returned (unknown uid, another domain, or not visible to this administrator); it is skipped |
| `owned_session_not_used` | the owned session is no longer that unpublished session (published or discarded); numbering came from the cache (info) |
| `owned_session_error` | the owned session's SID could not be used (for example expired); numbering came from the cache |
| `owned_session_conflict` | one session was requested with different owned sessions; the first is used |
| `live_numbering_degraded` | the live read of the rulebase was incomplete, so the numbers are provisional and come from the cache |
| `numbering_failed` | numbering was unavailable (rules are listed as not placed), or the cache snapshot predates a published session (info) |
| `names_unresolved` | some object names could not be resolved and are shown as uids |
| `range_truncated` | a range had more sessions than the cap; the message names the `from_session` to continue from |

## Formats and options

`ReportFormat` is `"html"`, `"json"`, `"markdown"` or `"pdf"`. `pdf` is reserved: requesting it raises `UnsupportedFormat`; an unknown name raises `ValueError`, and passing a bare string instead of a list raises `TypeError`.

`RenderOptions` has `title`, `header_fields` (ordered key/value pairs shown in the header, for example a ticket number), `generated_by`, and the markdown limits `markdown_max_rules` and `markdown_max_objects`. `title` and the `header_fields` keys and values accept limited markdown: `**bold**`, `*italic*`, `` `code` `` and `[text](url)` with http, https or mailto links. Everything else is escaped, so a name cannot inject markup. Every string that comes from Check Point is escaped in all formats.

All times are UTC and labelled `UTC`.

## Owned session

An application that creates its own unpublished session (as the CPCRUD engine does) can pass it so that the pending rules are numbered exactly as SmartConsole shows them:

```python
from pydantic import SecretStr
from arodonata.reports.changes import OwnedSession, SessionScope

owned = OwnedSession(sid=SecretStr(sid), server_ip=server_ip)
scope = SessionScope(domain="Domain5", session_uids=[session_uid], owned_session=owned)
```

The SID is used strictly read-only: `show-session`, `show-packages` and the `show-*-rulebase` reads. It is never used to publish, discard or log out, the application keeps those. The first `show-session` verifies that the SID belongs to one of the scope's unpublished sessions. If the session has since been published or discarded, the report adds an info note (`owned_session_not_used`) and numbers from the cache instead. The SID is never logged, never appears in the report, the raw responses, JSON, HTML or markdown, and `repr()` of an `OwnedSession` masks it.

## Numbering labels

Rule numbers match SmartConsole (`1`, `2.6`, `2.2.1`, including the Global layer prefix). Each session carries one label that says where its numbers come from:

- `Numbering as of this session's publish`, or `Numbering as of publish of <session uid> at <time> UTC`: from the rulebase cache. `(Global packages)` is appended when the packages were numbered with Global layers.
- `Numbering read live in the owned session at <time> UTC`: exact numbers read through an owned session.
- `Provisional numbering: unpublished session; numbers are the last published policy plus in-layer positions`: an unpublished session without an owned session.
- `Numbering unavailable: <error>`: numbering failed; the rules are listed under "Not placed in a package".

Some rows carry a basis suffix in small text: `(before deletion)` for a deleted rule's pre-session number, `(at time of change)` for a rule that is not in the latest snapshot (or the live read), for example because it was moved or deleted later, so it is numbered from the session's own position, and `(provisional)`.

Numbers describe the latest rulebase snapshot, not necessarily the moment the session was published. If a published session is newer than the snapshot (or the same minute with another uid), the library re-reads the cache once; if the snapshot still predates the session, the numbers describe that snapshot and an info warning says so.

## Statuses and colours

- Added rule: green left bar and a `NEW` tag; modified: yellow bar with only the changed cells highlighted; deleted: strikethrough with a red `DELETED` tag, showing the pre-session content.
- Moved rule: the number cell is yellow. It reads `2.6 (was 2.4)` when the old number is known; otherwise the number carries `(moved)` and the rule's details show the old and new position within the section.
- Disabled rule: a first narrow column with a red ✗ and the whole row on light grey, combined with the change colours. A rule created and disabled in one session shows `NEW`, ✗ and grey.
- List cells (source, destination, service, ...): added items green, removed items red and struck through, an unchanged item whose object was itself modified in the same session yellow with a link to the object's detail. Changed scalar cells (action, track, name, ...) are yellow. A negated cell shows a `¬` marker (in markdown it is rendered `not (a, b)`).
- Under each layer's table, every modified rule has a detail table (`field | old | new`, lists `field | - removed | + added`) that the changed cells link to.
- Sections that contain changes appear as header rows with their rule range, for example `FPCR_UAT_Section_4 (2.1-2.2)`.
- Objects are listed per session: added and deleted objects in a short table, modified objects with their changed fields. Changes that are neither rules, sections nor ordinary objects are listed as "Other changes", and internal objects are counted in `Hidden internal changes: N (see JSON)`.

Markdown has no colour: it uses the markers `[+]` added, `[-]` deleted, `[~]` modified and `[x]` disabled, `~~strikethrough~~` for deleted and removed items, `+name` for added items and `name*` for items modified in the session.

## Limitations

- Numbering of unpublished sessions without an owned session. `show-changes` gives a modified rule a `position` only when the session moved it, and that position counts within the rule's section, not within the layer. Wherever the rule is in the rulebase cache (or in the live read through an owned session) its number is used. Otherwise, in a layer without sections the row shows prefix + position; in a layer with sections the row has no number and reads `– (position N in its section)`, under a "Section not known (or before the first section)" header.
- A move is detected by `position` being present, so a move to another section is detected too. The management API refuses to move a rule to another layer; a SmartConsole cut and paste across layers shows as a delete and an add.
- Auto-generated NAT rules are not reported as rules; their changes appear on the object's `nat-settings`.
- Threat Prevention exceptions are out of scope.
- Another administrator's unpublished session may be invisible to the API user; it then yields `session_not_found`.
- Group members and NAT references that `show-changes` returns as bare uids are named from the session's own entries first, then by read-only `show-object`, at most 200 lookups per report. Past the cap, or on a failed lookup, the uid is shown and a `names_unresolved` warning is added.
- Dates: see [Scopes](#scopes) for how aware datetimes are converted to the server's offset and filtered exactly on the publish time.

## Raw responses

`include_raw=True` (on `collect_change_report` and `build_change_report`) keeps one `RawResponse` per `show-changes` request per domain in `report.raw`, failed requests included (`success`, `code`, `message`). `response` is the merged, flattened page set that `api_query` returned (`{"changes": [...], "total": N}`), `None` on failure. HTML shows them in an appendix of `<details>` blocks; markdown never includes them; JSON carries them.

## Markdown truncation

`RenderOptions.markdown_max_rules` limits the number of rule rows (a rule in a shared inline layer counts once per package row), `markdown_max_objects` limits object, section and other-change rows. When a limit is reached the renderer stops that kind of row and appends one of:

```text
…and N more rules, full report via the library
…and N more objects, full report via the library
```

N counts rows. Session headers, warnings and the hidden-internal line are never truncated.

## Stored JSON

The JSON is `report.model_dump_json()`. Reading it back and rendering again needs no Check Point access:

```python
from arodonata.reports.changes import ChangeReport, render_change_report

report = ChangeReport.model_validate_json(path.read_bytes())
result = render_change_report(report, ["html"])
```

`format_version` is stored in the file; a report with a newer version than the installed library supports is refused with an error asking you to upgrade.


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
- `tests/unit/test_db_utils_postgres.py` is the one opt-in unit test: it runs against a real PostgreSQL database (in a throwaway schema) only when `ARODONATA_PG_TEST_URL` is set to a `postgresql+asyncpg://...` URL, and skips otherwise.

CI (`.github/workflows/ci.yml`, Python 3.13) runs `uv sync --all-extras --dev`, `uv run ruff check src/ tests/`, `uv run mypy src/` and `uv run pytest`, in that order; it does not run `ruff format --check` or `mkdocs build`. Run all four locally before pushing. `--all-extras` matters: the tests under `tests/unit/mcp` import the `mcp` extra and fail without it. Integration tests are excluded from default runs by the `-m "not integration"` marker expression.

## Integration suite

```bash
./pytest.sh int-1        # one bucket
./pytest.sh int-7        # ...
./pytest.sh int-full     # all seven, back-to-back (~2 h)
```

`int-full` pauses `BUCKET_PAUSE_SECONDS` (default `90`) between buckets so the next one does not open into Check Point's login rate-limit window; set `BUCKET_PAUSE_SECONDS=0` for a server that does not enforce one.

Tests live in `tests/integration/b1`..`b7`; the `bucket_N` marker is applied
automatically from the directory path. Buckets are sized for roughly equal
wall-clock time (~10–15 min each), **not** by topic, and each runs as its own
pytest session — its own run lock, baseline snapshot and restore — so they are
independent and can be run in any order or alone. `int-full` runs the seven
sessions back-to-back rather than one long session with a single restore at
the end.

| Bucket | Contents |
|---|---|
| `b1` | Logins for every configured identity (API key + credential users), auth failures, SID lifecycle incl. stale-SID recovery, rate limiting, concurrent admins, live session naming, cache-first reads and search, rulebase reads. Mutates nothing. |
| `b2` | Live CPCRUD create/update/delete with real publishes, single-domain cache builds and check-mode partial refresh |
| `b3` | create→publish→verify→revert cycles, plus throttling (deliberately drives the server into `err_too_many_requests`; sorts last within the bucket) |
| `b4` | Cache-mode matrix (cache/smart/smart-fast/force) incl. live fallback triggers, multi-domain isolation |
| `b5` | Whole-server rebuilds with asset relationship phases, cross-user/cross-domain publish/discard/revert matrix |
| `b6` | Bounded soak: repeated publish → smart-fast → revert cycles |
| `b7` | MCP server tools over a real client: init, cache-backed lists, live single-object and list tools, the live rulebase path, search, and the `api_call` write gate. Mutates nothing. The one topical bucket: MCP tests live here together rather than being spread for balance. |

Every bucket run prints its 15 slowest tests (`--durations=15`). The
assignment is an estimate — publishes, `revert-to-revision` and whole-server
rebuilds dominate, not test count — so when the numbers say a bucket is
lopsided, rebalance with a `git mv`; the marker follows the directory.

Only one integration run at a time: see [Contributing](https://github.com/chkp-antonr/arodonata/blob/master_v1/CONTRIBUTING.md)
for the run lock and the reasons behind it.

### Configuration

The integration conftest loads `.env.test` then `.env.secrets` from the repo root, then `.env.lab.<profile>` when a lab profile is selected; each file overrides values already in the environment. Select a profile by setting `ARODONATA_LAB=<profile>` (in the shell, or in `.env.test`/`.env.secrets`); without it the run uses the default lab from `.env.test`. A selected profile whose `.env.lab.<profile>` file does not exist is an error, not a fallback to the default lab. See `.env.example` for the variable names; the important ones:

- `API_MGMT` — management server IP
- `APIKEY`, `USER_admin`, `USER_AntonR`, `USER_Eng1..4` — identities
- `TEST_DOMAIN_A`, `TEST_DOMAIN_B` — sandbox domains for mutating tests
- `DATABASE_URL` — SQLite path for the test cache (default `_tmp/`)

Missing variables **skip** the affected tests, so a machine without lab
access still runs everything else.

Lab runs verify the server certificate like production does (see [TLS Verification](../configuration/tls-verification.md)).
Pin the lab servers instead of learning them: put `ARODONATA_TLS_TRUST=pinned` and `ARODONATA_TLS_FINGERPRINTS=<one SHA-256 per member>` in `.env.lab.<profile>`, taking each value from `api fingerprint -f json` on the member.
Fingerprints are public data, so they may live in that file.
`ARODONATA_TLS_TRUST=lab-memory` is for a lab whose fingerprints are not harvested yet: it trusts each process's first contact in memory, writes nothing (it only reads an existing store) and is honoured only when `ARODONATA_LAB` is set.

### Mutation safety

Tests that change server state are marked `cp_mutates` and confine
themselves to the sandbox domains, reverting to the pre-test revision when
they finish. Independently of that, the harness snapshots the last published revision of the sandbox domains (`TEST_DOMAIN_A`/`TEST_DOMAIN_B`, no other domain) to `_tmp/cp_baseline/baseline-<timestamp>.json` **before any test runs**; with neither set, no snapshot is taken (no mutating test can run). At session end, only if a `cp_mutates` test ran, it reverts the snapshotted domains that drifted. A failed snapshot aborts the whole session (exit code 5) before any test runs: no safety net, no run. After a crashed run, restore manually:

```bash
uv run tests/integration/restore_baseline.py _tmp/cp_baseline/baseline-<timestamp>.json
```

The baseline files are never deleted automatically — they are your recovery
handle.

### Serial by design

Integration tests run serially (no `pytest-xdist`): the suite deliberately
exercises rate limits and session caps, so parallel workers would poison
each other's results.
