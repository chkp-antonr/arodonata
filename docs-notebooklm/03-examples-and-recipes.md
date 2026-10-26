# Arodonata v2 — Runnable Examples & Recipes (01..12)

Worked examples showing common tasks with Arodonata v2: basic queries, multi-term search and structured cross-domain aggregation (`query_objects`), gateway/cluster/VSX relationships, paired streaming and batch smart refresh, rulebase queries and local filtering, session lifecycle, `WriteSession` + `SessionOverlay` read-your-own-writes isolation, declarative CPCRUD (`plan`/`apply`/`inverse`), auditable change reports (`OwnedSession` live numbering vs published cached numbering), OpenTelemetry tracing, and embedded FastAPI MCP servers.


---

*(source: `docs/examples/index.md`)*

# Arodonata v2 Examples

Progressive runnable scripts demonstrating `ArodonataClient` usage from basic cache-backed queries to advanced multi-user session overlays, declarative Policy-as-Code (`CPCRUD`), auditable change reports, OpenTelemetry tracing, and embedded MCP servers.

## Catalog Overview

| Script | Doc Page | Topic | Mutates Lab? |
| --- | --- | --- | --- |
| `01_basic_queries.py` | [01 — Basic Queries](01-basic-queries.md) | Discovers domains (`get_domains`) and queries cached hosts, networks, and services (`get_hosts`, `get_networks`, `get_services`) | No |
| `02_search_and_query.py` | [02 — Search & Structured Query](02-search-and-query.md) | Multi-term object search with recursive group memberships (`search_objects`), progressive disclosure (`describe_objects`), structured cross-domain aggregation (`query_objects`), and cache freshness (`get_cache_status`) | No |
| `03_gateway_relationships.py` | [03 — Gateway & VSX Topology](03-gateway-relationships.md) | Gateway, cluster, and VSX asset topology (`get_gateways`) linking cluster members and virtual systems via `parent_uid` and `member_uids` | No |
| `04_smart_refresh.py` | [04 — Smart & Streaming Refresh](04-smart-refresh.md) | Paired streaming (`stream_refresh_*`) and batch (`refresh_*`) cache synchronization across assets, objects, services, and rulebases — **run this first to warm a persistent DB** | No |
| `05_rulebase_queries.py` | [05 — Rulebase Queries](05-rulebase-queries.md) | Policy package discovery (`get_policy_packages`), hierarchical SmartConsole numbering (`get_package_rulebase`), reverse UID lookup (`locate_rules`), and local rule filtering (`filter_rulebase`) | No |
| `06_session_basics.py` | [06 — Session Lifecycle Basics](06-session-basics.md) | Low-level session lifecycle: capture baseline (`show-last-published-session`), `create_dedicated_session`, `add-host`, `publish`, and `revert-to-revision` | Yes (auto-reverted via `_session_guard.py`) |
| `07_context_and_overlay.py` | [07 — Contexts & Session Overlay](07-context-and-overlay.md) | Dynamic `auth_context`, `user_context`, and `write_session` with `SessionOverlay` read-your-own-writes isolation (discards on exit without publishing) | No (discards uncommitted session) |
| `08_cpcrud_operations.py` | [08 — CPCRUD Operations](08-cpcrud-operations.md) | Declarative Policy-as-Code (`client.cpcrud.validate`, `plan`, `apply`) applying `crud_example.yaml` twice to prove idempotency — see [CPCRUD User Guide](../user-guide/cpcrud.md) | Yes (auto-reverted via `_session_guard.py`) |
| `09_cpcrud_inverse.py` | [09 — CPCRUD Inverse Rollback](09-cpcrud-inverse.md) | Compensating rollback workflow: `plan` -> `apply` -> `inverse(plan, report)` -> `plan` -> `apply` | Yes (auto-reverted via `_session_guard.py`) |
| `10_change_report_evidence.py` | [10 — Change Report Evidence](10-change-report-evidence.md) | Auditable `ChangeReport` evidence: live unpublished numbering via `OwnedSession` vs published cached numbering rendered to HTML, Markdown, and JSON | Yes (auto-reverted via `_session_guard.py`) |
| `11_otel_tracing.py` | [11 — OpenTelemetry Tracing](11-otel-tracing.md) | Provider-agnostic OpenTelemetry instrumentation (`arlogi.otel.setup_tracing`) with a per-span timing breakdown from exported JSONL traces | No |
| `12_mcp_embedded.py` | [12 — Embedded FastAPI MCP](12-mcp-embedded.md) | Embedding Arodonata's MCP server (`create_mcp_server`, `create_asgi_app`) inside a FastAPI application with custom tools | No |
| `_session_guard.py` | — | Crash-safe baseline snapshot/restore context manager (`guarded_session`) and standalone CLI tool for manual testing | Helper / CLI |

## Setup & Execution

```bash
# 1. Install dependencies (including dev/example dependencies)
uv sync --all-extras

# 2. Configure environment files (.env.lib / .env.test / .env.secrets)
cp .env.example .env.lib

# 3. Warm the cache first (when using a persistent SQLite or PostgreSQL DATABASE_URL)
uv run examples/04_smart_refresh.py

# 4. Run read-only query, search, topology, rulebase, and overlay examples
uv run examples/01_basic_queries.py
uv run examples/02_search_and_query.py
uv run examples/03_gateway_relationships.py
uv run examples/05_rulebase_queries.py
uv run examples/07_context_and_overlay.py
uv run examples/11_otel_tracing.py

# 5. Run mutating lab examples (automatically snapshot and revert Domain4/Domain5 baseline)
ARODONATA_LAB=home uv run examples/06_session_basics.py
ARODONATA_LAB=home uv run examples/08_cpcrud_operations.py
ARODONATA_LAB=home uv run examples/09_cpcrud_inverse.py
ARODONATA_LAB=home uv run examples/10_change_report_evidence.py

# 6. Run the embedded FastAPI + MCP server on http://127.0.0.1:8000/mcp
uv run examples/12_mcp_embedded.py
```

## Crash-Safe Manual Testing with `_session_guard.py`

When experimenting manually in SmartConsole or with ad-hoc scripts against a lab domain:

```bash
# 1st invocation: snapshots and saves the current last-published session to examples/_tmp/session_guard_state.json
ARODONATA_LAB=home uv run examples/_session_guard.py 192.168.5.140 Domain4

# ... perform manual changes/publishes in Domain4 ...

# 2nd invocation: discards open sessions, reverts Domain4 to the saved baseline, and removes the state file
ARODONATA_LAB=home uv run examples/_session_guard.py 192.168.5.140 Domain4
```


---

*(source: `docs/examples/01-basic-queries.md`)*

# 01 — Basic Queries (`01_basic_queries.py`)

Demonstrates discovering domains (`client.get_domains()`) and querying cached hosts, networks, and services (`client.get_hosts()`, `client.get_networks()`, `client.get_services()`) using `ArodonataClient`.

## Source Code (`examples/01_basic_queries.py`)

```python title="examples/01_basic_queries.py"
"""Example 01 — Basic typed queries (`get_domains`, `get_hosts`, `get_networks`, `get_services`).

Run:
    uv run examples/01_basic_queries.py

Reads configuration from `.env.lib` and `.env.secrets` (or `.env`).
Demonstrates how `ArodonataClient` discovers domains and queries cached network and service
objects with `cache_mode="smart"`.
"""

from __future__ import annotations

import asyncio
import os
import time

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Query domains, hosts, networks, and services across configured management servers."""
    settings = ArodonataSettings()
    print(f"Using database: {settings.database_url or 'sqlite+aiosqlite:///:memory:'}")
    print(f"Management servers: {settings.mgmt_names}")

    t0 = time.perf_counter()
    async with ArodonataClient(settings=settings) as client:
        print("\n[Step 1/4] Discovering MDS domains (get_domains)...", flush=True)
        s0 = time.perf_counter()
        domains = await client.get_domains(include_global=True)
        print(f"Discovered domains ({len(domains)}) in {time.perf_counter() - s0:.2f}s:")
        for dom in domains[:10]:
            print(f"  - {dom.name} (mgmt={dom.mgmt_name}, active_ip={dom.active_ip}, global={dom.is_global})")

        target_domain = os.getenv("EXAMPLE_DOMAIN") or (domains[0].name if domains else None)
        if not target_domain:
            print("No domains found.")
            return

        print(f"\n[Step 2/4] Querying hosts in domain {target_domain!r} (get_hosts, cache_mode='smart')...", flush=True)
        s0 = time.perf_counter()
        hosts = await client.get_hosts(domain=target_domain, cache_mode="smart")
        print(f"Hosts ({len(hosts)}) in {time.perf_counter() - s0:.2f}s:")
        for host in hosts[:5]:
            print(f"  - {host.name}: {host.ipv4_address} (uid={host.uid})")

        print(
            f"\n[Step 3/4] Querying networks in domain {target_domain!r} (get_networks, cache_mode='smart')...",
            flush=True,
        )
        s0 = time.perf_counter()
        networks = await client.get_networks(domain=target_domain, cache_mode="smart")
        print(f"Networks ({len(networks)}) in {time.perf_counter() - s0:.2f}s:")
        for net in networks[:5]:
            print(f"  - {net.name}: {net.subnet4}/{net.mask_length4}")

        print(
            f"\n[Step 4/4] Querying services in domain {target_domain!r} (get_services, cache_mode='smart')...",
            flush=True,
        )
        s0 = time.perf_counter()
        services = await client.get_services(domain=target_domain, cache_mode="smart")
        print(f"Services ({len(services)}) in {time.perf_counter() - s0:.2f}s:")
        for svc in services[:5]:
            print(f"  - {svc.name} ({svc.type}): port={svc.port} proto={svc.protocol}")

    elapsed = time.perf_counter() - t0
    print(f"\nCompleted in {elapsed:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/02-search-and-query.md`)*

# 02 — Search & Structured Query (`02_search_and_query.py`)

Demonstrates multi-term object search with recursive parent group memberships (`client.search_objects()`, including `exact_match=True`), progressive-disclosure schema discovery (`client.describe_objects()`), SQL-free cross-domain aggregation (`client.query_objects()`), and cache freshness inspection (`client.get_cache_status()`).

## Source Code (`examples/02_search_and_query.py`)

```python title="examples/02_search_and_query.py"
"""Example 02 — Object search, group membership resolution, and structured `query_objects`.

Run:
    uv run examples/02_search_and_query.py

Demonstrates:
1. `client.search_objects(query, max_depth=2)` — classifies comma-separated search terms
   (IPv4, CIDR, range, wildcard, UID, name) and resolves parent group memberships recursively.
2. `client.describe_objects()` — progressive-disclosure schema and type counts across domains.
3. `client.query_objects()` — cross-domain filtering, grouping (`group_by`), and aggregation
   (`aggregate="count" | "list"`), including `scope_origin="local" | "global"`.
4. `client.get_cache_status()` — per-scope cache freshness and `cache_age_seconds`.
"""

from __future__ import annotations

import asyncio
import os
import time

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Run search_objects, describe_objects, query_objects, and get_cache_status."""
    settings = ArodonataSettings()
    t0 = time.perf_counter()

    async with ArodonataClient(settings=settings) as client:
        print("[Step 1/4] Resolving target domain (get_domains)...", flush=True)
        domains = await client.get_domains()
        target_domain = os.getenv("EXAMPLE_DOMAIN") or (domains[0].name if domains else None)

        # 1. Search objects by wildcard and IPv4/CIDR with recursive parent group resolution
        query_str = os.getenv("EXAMPLE_SEARCH_QUERY", "*host*, 10.0.0.0/8")
        print(
            f"\n[Step 2/4] Searching objects across all 5 types in {target_domain!r} "
            f"(search_objects={query_str!r}, max_depth=2, cache_mode='smart')...",
            flush=True,
        )
        s0 = time.perf_counter()
        search_res = await client.search_objects(
            query_str,
            domains=[target_domain] if target_domain else None,
            max_depth=2,
            cache_mode="smart",
        )
        print(
            f"Search query {query_str!r} matched {len(search_res.matches)} object(s) in {time.perf_counter() - s0:.2f}s:"
        )
        for match in search_res.matches[:5]:
            groups = search_res.memberships.get(match.uid, [])
            group_names = [f"{g.name} (depth={g.depth})" for g in groups]
            print(f"  - {match.name} ({match.type}, domain={match.domain_name}) -> groups={group_names}")

        # 2. Progressive-disclosure metadata via describe_objects
        print(
            "\n[Step 3/4] Inspecting cached schema & aggregating objects (describe_objects / query_objects)...",
            flush=True,
        )
        desc = await client.describe_objects(domain_name=target_domain)
        print(f"Cached summary: {desc['total_objects']} objects, {desc['total_services']} services")
        print(f"  Object types: {desc['object_types']}")
        print(f"  Groupable fields: {desc['groupable_fields']}")

        # 3. Structured cross-domain aggregation via query_objects
        grouped = await client.query_objects(
            domain_name=target_domain,
            group_by=["domain_name", "type"],
            aggregate="count",
        )
        print(f"\nGrouped counts (total={grouped['total']}):")
        for row in grouped.get("groups", [])[:10]:
            print(f"  - {row['domain_name']} / {row['type']}: {row['count']}")

        # 4. Inspect domain_sync_state freshness via get_cache_status
        print("\n[Step 4/4] Checking cache freshness (get_cache_status)...", flush=True)
        status = await client.get_cache_status(domain_name=target_domain)
        print(f"Cache status entries ({status['total_entries']}):")
        for entry in status["entries"][:5]:
            print(
                f"  - [{entry['scope']}:{entry['item_type']}] {entry['mgmt_name']}:{entry['domain_name']} "
                f"status={entry['status']} count={entry['object_count']} age={entry['cache_age_seconds']}s"
            )

    print(f"\nCompleted in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/03-gateway-relationships.md`)*

# 03 — Gateway & VSX Topology (`03_gateway_relationships.py`)

Demonstrates querying cached gateways, clusters, cluster members, and VSX virtual systems (`client.get_gateways()`) and traversing both UID (`id`, `parent_uid`, `member_uids`, `virtual_system_uids`) and human-readable composite identifiers (`asset_id`, `parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`, including cross-domain VSX links), along with `interfaces` and `network_security_blades`.

## Source Code (`examples/03_gateway_relationships.py`)

```python title="examples/03_gateway_relationships.py"
"""Example 03 — Gateway, cluster, and VSX asset topology (`get_gateways`, `refresh_assets`).

Run:
    uv run examples/03_gateway_relationships.py

Demonstrates how `AssetRefreshService` links cluster members and VSX virtual systems to their
parent cluster or VSX gateway via `parent_uid`, `parent_name`, `member_uids`, and
`virtual_system_uids`.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings, Asset  # noqa: E402


async def main() -> None:
    """Inspect standalone gateways, clusters, cluster members, and VSX systems."""
    settings = ArodonataSettings()
    target_domain = os.getenv("EXAMPLE_DOMAIN")
    t0 = time.perf_counter()

    async with ArodonataClient(settings=settings) as client:
        print(
            f"[Step 1/2] Fetching gateway/cluster/VSX assets for domain={target_domain!r} (get_gateways)...", flush=True
        )
        gateways = await client.get_gateways(domain=target_domain, cache_mode="smart")
        print("[Step 2/2] Resolving parent-child cluster & VSX topology...", flush=True)
        by_uid: dict[str, Asset] = {gw.uid: gw for gw in gateways}

        members_by_parent: dict[str, list[Asset]] = defaultdict(list)
        standalone: list[Asset] = []

        for gw in gateways:
            if gw.parent_uid:
                members_by_parent[gw.parent_uid].append(gw)
            elif not gw.member_uids and not gw.virtual_system_uids:
                standalone.append(gw)

        print(f"Total cached gateway/server assets: {len(gateways)}")
        print(f"Standalone gateways/servers: {len(standalone)}")
        for gw in standalone[:5]:
            print(f"  - {gw.name} ({gw.type}, ip={gw.ipv4_address}, domain={gw.domain_name})")

        print(f"\nClusters / VSX parents with linked members: {len(members_by_parent)}")
        for parent_uid, members in list(members_by_parent.items())[:5]:
            parent = by_uid.get(parent_uid)
            parent_label = f"{parent.name} ({parent.type})" if parent else parent_uid
            member_names = ", ".join(f"{m.name} ({m.ipv4_address or 'no-ip'})" for m in members)
            print(f"  - {parent_label}: {member_names}")

    print(f"\nCompleted in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/04-smart-refresh.md`)*

# 04 — Smart & Streaming Refresh (`04_smart_refresh.py`)

Demonstrates paired streaming (`stream_refresh_*`) and batch (`refresh_*`) cache synchronization across assets, objects, services, and rulebases, including SSE conversion via `arodonata.adapters.sse.to_sse_event`.

## Source Code (`examples/04_smart_refresh.py`)

```python title="examples/04_smart_refresh.py"
"""Example 04 — Paired batch & streaming cache synchronization (`refresh_*` and `stream_refresh_*`).

Run:
    uv run examples/04_smart_refresh.py

Run this script first against a persistent SQLite or PostgreSQL database (`DATABASE_URL`) to
warm the cache across all discovered domains. Demonstrates both streaming (`stream_refresh_*`)
and awaitable (`refresh_*`) synchronization methods and optional SSE wire formatting.
"""

from __future__ import annotations

import asyncio
import os
import time

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402
from arodonata.adapters.sse import to_sse_event  # noqa: E402


async def main() -> None:
    """Stream progress events while refreshing assets, objects, services, and rulebases."""
    settings = ArodonataSettings()
    target_domains = [os.environ["EXAMPLE_DOMAIN"]] if os.getenv("EXAMPLE_DOMAIN") else None
    t0 = time.perf_counter()

    async with ArodonataClient(settings=settings) as client:
        print("[Step 1/4] Streaming asset synchronization (gateways, clusters, VSX)...", flush=True)
        async for ev in client.stream_refresh_assets(domains=target_domains, mode="smart"):
            if ev.phase in ("started", "completed", "skipped", "failed"):
                print(f"  [{ev.phase}] {ev.message or f'{ev.mgmt_name}:{ev.domain} ({ev.item_type})'}")

        print("\n[Step 2/4] Streaming network object synchronization (hosts, networks, ranges, groups)...", flush=True)
        async for ev in client.stream_refresh_objects(domains=target_domains, mode="smart"):
            if ev.phase in ("started", "completed", "skipped", "failed"):
                print(f"  [{ev.phase}] {ev.message or f'{ev.mgmt_name}:{ev.domain} ({ev.item_type})'}")
                # Example of converting a domain event to an SSE frame for web endpoints:
                _sse_frame = to_sse_event(ev).encode()

        print("\n[Step 3/4] Batch refreshing services...", flush=True)
        svc_outcome = await client.refresh_services(domains=target_domains, mode="smart")
        print(
            f"  Services sync: refreshed={len(svc_outcome.refreshed_domains)}, "
            f"skipped={len(svc_outcome.skipped_domains)}, items={svc_outcome.total_items}"
        )

        print("\n[Step 4/4] Batch refreshing policy rulebases...", flush=True)
        rb_outcome = await client.refresh_rulebases(domains=target_domains, mode="smart")
        print(
            f"  Rulebases sync: refreshed={len(rb_outcome.refreshed_domains)}, "
            f"skipped={len(rb_outcome.skipped_domains)}, items={rb_outcome.total_items}"
        )

    print(f"\nCache warm-up completed in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/05-rulebase-queries.md`)*

# 05 — Rulebase Queries (`05_rulebase_queries.py`)

Demonstrates policy package discovery (`client.get_policy_packages()`), hierarchical SmartConsole numbering (`client.get_package_rulebase()`, `client.get_layer_rulebase()`), reverse UID lookup (`client.locate_rules()`), and local rulebase filtering (`client.filter_rulebase()`, including `output_format="cpcrud"`).

## Source Code (`examples/05_rulebase_queries.py`)

```python title="examples/05_rulebase_queries.py"
"""Example 05 — Rulebase introspection, hierarchical SmartConsole numbering, and local filtering.

Run:
    uv run examples/05_rulebase_queries.py

Demonstrates:
1. `client.get_policy_packages(mgmt_name, domain)` — list cached policy packages and layers.
2. `client.get_package_rulebase(mgmt_name, domain, package)` — hierarchical SmartConsole rule
   numbers (`1`, `2.1`, `2.2.1`) across ordered Global/Domain layers and inline sub-layers.
3. `client.locate_rules(mgmt_name, domain, rule_uids=[...])` — reverse lookup from rule UID to
   SmartConsole rule numbers across packages.
4. `client.filter_rulebase(...)` — local rulebase query evaluation (`src:`, `dst:`, `svc:`,
   `action:`, free text, CIDR containment) rendered in `markdown` or `model_friendly` format.
"""

from __future__ import annotations

import asyncio
import os
import time

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Inspect policy packages, numbered rulebases, rule locations, and local rule filtering."""
    settings = ArodonataSettings()
    t0 = time.perf_counter()

    async with ArodonataClient(settings=settings) as client:
        print("[Step 1/5] Resolving target domain (get_domains)...", flush=True)
        domains = await client.get_domains()
        if not domains:
            print("No domains discovered.")
            return

        dom = next((d for d in domains if d.name == os.getenv("EXAMPLE_DOMAIN")), domains[0])
        mgmt_name = dom.mgmt_name
        domain_name = dom.name

        print(f"[Step 2/5] Ensuring rulebase cache for {mgmt_name}:{domain_name} (refresh_rulebases)...", flush=True)
        await client.refresh_rulebases(mgmt_name=mgmt_name, domains=[domain_name], mode="smart")

        print(f"[Step 3/5] Listing policy packages in {domain_name} (get_policy_packages)...", flush=True)
        packages = await client.get_policy_packages(mgmt_name, domain_name, cache_mode="cache")
        if not packages:
            print(f"No policy packages cached in {domain_name}.")
            return

        pkg = packages[0]
        print(f"\nPolicy Package: {pkg.name} (uid={pkg.uid})")
        print(f"  Access layers: {[lay.layer_name for lay in pkg.access_layers]}")

        print(
            f"\n[Step 4/5] Computing hierarchical SmartConsole rule numbers for {pkg.name!r} (get_package_rulebase)...",
            flush=True,
        )
        pkg_rb = await client.get_package_rulebase(
            mgmt_name,
            domain_name,
            pkg.name,
            rulebase_type="access",
            cache_mode="cache",
        )
        for layer in pkg_rb.layers:
            print(f"\nLayer {layer.layer_name!r} (prefix={layer.prefix!r}, rules={len(layer.rules)}):")
            for nr in layer.rules[:5]:
                print(f"  #{nr.rule_number:<6} {nr.name or '(unnamed)':<28} action={nr.action} enabled={nr.enabled}")

        access_rules = await client.get_access_rules(mgmt_name, domain_name)
        if access_rules:
            sample = access_rules[0]
            locs = await client.locate_rules(
                mgmt_name,
                domain_name,
                rule_uids=[sample.uid],
                cache_mode="cache",
            )
            print(f"\nLocated rule UID {sample.uid}: {locs.rule_locations.get(sample.uid)}")

        print("\n[Step 5/5] Filtering rulebase locally (filter_rulebase)...", flush=True)
        filtered = await client.filter_rulebase(
            mgmt_name,
            domain_name,
            package=pkg.name,
            rulebase_type="access",
            filter_query=os.getenv("EXAMPLE_RULE_FILTER", "action:Accept"),
            output_format="markdown",
            cache_mode="cache",
        )
        print(f"\nFiltered rulebase ({filtered.matched_count}/{filtered.total_rules} matching rules):")
        print("\n".join(filtered.rendered_text.splitlines()[:15]))

    print(f"\nCompleted in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/06-session-basics.md`)*

# 06 — Session Lifecycle Basics (`06_session_basics.py`)

Demonstrates low-level Check Point session lifecycle operations (`create_dedicated_session`, `add-host`, `publish`, and crash-safe `revert-to-revision` via `_session_guard.py`).

## Source Code (`examples/06_session_basics.py`)

```python title="examples/06_session_basics.py"
"""Example 06 — Check Point session lifecycle basics: baseline, dedicated session, publish, and revert.

Run:
    uv run examples/06_session_basics.py

Demonstrates:
1. Reading the domain's current baseline revision (`show-last-published-session`).
2. Opening an isolated write session via `client.create_dedicated_session(mgmt_name, domain)`.
3. Creating a test host (`add-host`) and publishing (`publish` with `wait_for_task=True`).
4. Verifying that `show-last-published-session` moved to the newly published session UID.
5. Reverting the domain back to the saved baseline revision (`revert-to-revision`) via
   `_session_guard.guarded_session`.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


def _extract_iso_time(time_field: Any) -> str:
    if isinstance(time_field, dict):
        return str(time_field.get("iso-8601") or time_field)
    return str(time_field or "unknown")


async def main() -> None:
    """Run the baseline -> create_dedicated_session -> add-host -> publish -> revert cycle."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")
    host_name = f"example-session-host-{uuid.uuid4().hex[:6]}"

    async with ArodonataClient(settings=settings) as client:
        async with guarded_session(client, mgmt_name, domains=[domain]) as baseline:
            base_rev = baseline[domain]
            print(f"Step 1: Captured baseline on {mgmt_name}:{domain}:")
            print(f"  UID:  {base_rev['uid']}")
            print(f"  Name: {base_rev['name']}")
            print(f"  Time: {_extract_iso_time(base_rev['publish_time'])}")

            print(f"\nStep 2: Opening dedicated write session and creating host {host_name!r}...")
            sid, server_ip = await client.create_dedicated_session(
                mgmt_name,
                domain,
                session_name=f"example-06-{host_name[-6:]}",
                session_description="Example 06 dedicated write session",
            )
            try:
                add_res = await client.api_call(
                    mgmt_name,
                    "add-host",
                    {
                        "name": host_name,
                        "ipv4-address": "198.51.100.240",
                        "comments": "Created by examples/06_session_basics.py",
                    },
                    domain=domain,
                    sid=sid,
                    server_ip=server_ip,
                )
                assert add_res.success, f"add-host failed: {add_res.error_message}"
                print(f"  Created host {host_name} (uid={add_res.data.get('uid')})")

                print("\nStep 3: Publishing session...")
                pub_res = await client.api_call(
                    mgmt_name,
                    "publish",
                    {},
                    domain=domain,
                    sid=sid,
                    server_ip=server_ip,
                    wait_for_task=True,
                )
                assert pub_res.success, f"publish failed: {pub_res.error_message}"
                print("  Published successfully.")
            finally:
                await client.logout_sid(mgmt_name, sid, server_ip=server_ip)

            print("\nStep 4: Verifying show-last-published-session advanced...")
            after_res = await client.api_call(mgmt_name, "show-last-published-session", {}, domain=domain)
            assert after_res.success
            new_uid = after_res.data.get("uid")
            print(f"  Previous UID: {base_rev['uid']}")
            print(f"  Current UID:  {new_uid}")
            assert new_uid != base_rev["uid"]

            print("\nStep 5: Exiting guarded_session will automatically revert domain to baseline...")

        final_res = await client.api_call(mgmt_name, "show-last-published-session", {}, domain=domain)
        print(f"Step 6: Verified post-revert UID: {final_res.data.get('uid')}")


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/07-context-and-overlay.md`)*

# 07 — Contexts & Session Overlay (`07_context_and_overlay.py`)

Demonstrates runtime `auth_context`, `user_context`, and isolated `write_session` with `SessionOverlay` read-your-own-writes isolation (verifying that uncommitted objects appear immediately in `get_hosts()`, `find_object()`, and `search_objects()` before discarding cleanly on exit).

## Source Code (`examples/07_context_and_overlay.py`)

```python title="examples/07_context_and_overlay.py"
"""Example 07 — Dynamic `auth_context`, `user_context`, and `write_session` with `SessionOverlay`.

Run:
    uv run examples/07_context_and_overlay.py

Demonstrates Arodonata v2's context-aware multi-user and transactional features:
1. `with client.auth_context(username=..., password=...)` — dynamically overrides credentials
   per asyncio task without mutating client settings.
2. `with client.user_context(username=..., session_name=..., session_description=...)` —
   propagates operator attribution and Check Point session naming into `write_session` and logs.
3. `async with client.write_session(mgmt_name, domain, publish_on_exit=False)` — opens an
   isolated `WriteSession` backed by `SessionOverlay` so uncommitted `add_object` / `set_object` /
   `delete_object` mutations are immediately visible to `get_hosts`, `find_object`, and
   `search_objects` inside the context ("read-your-own-writes") while remaining invisible to
   other readers and the shared SQLite cache until published.
"""

from __future__ import annotations

import asyncio
import os
import uuid

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Demonstrate auth_context, user_context, and WriteSession SessionOverlay isolation."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")
    tag = uuid.uuid4().hex[:6]
    temp_host = f"overlay-demo-host-{tag}"

    async with ArodonataClient(settings=settings) as client:
        # Warm the host cache for the target domain
        await client.refresh_objects(mgmt_name=mgmt_name, domains=[domain], types=["host"], mode="smart")

        eng_password = os.getenv("USER_eng1") or os.getenv("USER_Eng1") or os.getenv("USER_admin", "")  # noqa: SIM112
        eng_user = "eng1" if (os.getenv("USER_eng1") or os.getenv("USER_Eng1")) else "admin"  # noqa: SIM112

        print(f"1. Entering auth_context(username={eng_user!r}) + user_context(session_name=' Ticket-700 ')...")
        with (
            client.auth_context(username=eng_user, password=eng_password),
            client.user_context(
                user_id=eng_user,
                username=eng_user,
                session_name=f"CHG-Overlay-{tag}",
                session_description="Read-your-own-writes SessionOverlay demo",
            ),
        ):
            # Use publish_on_exit=False and discard explicitly so the lab is never mutated
            async with client.write_session(
                mgmt_name,
                domain,
                publish_on_exit=False,
            ) as ws:
                print(f"2. Opened WriteSession (session_name={ws.session_name!r}, server_ip={ws.server_ip})")

                add_res = await client.add_object(
                    mgmt_name,
                    "host",
                    {
                        "name": temp_host,
                        "ipv4-address": "198.51.100.241",
                        "comments": "Uncommitted host in SessionOverlay",
                    },
                    domain=domain,
                )
                assert add_res.success, add_res.error_message
                print(f"3. Added uncommitted host {temp_host!r} inside WriteSession.")

                # Read-your-own-writes: find_object and search_objects see the uncommitted host!
                found = await client.find_object(mgmt_name, domain, temp_host, obj_type="host", cache_mode="cache")
                assert found is not None
                print(f"4. Inside WriteSession, find_object({temp_host!r}) -> {found.name} ({found.ipv4_address})")

                search_res = await client.search_objects(
                    "198.51.100.241",
                    mgmt_name=mgmt_name,
                    domains=[domain],
                    cache_mode="cache",
                )
                print(
                    f"5. Inside WriteSession, search_objects('198.51.100.241') matched: {[m.name for m in search_res.matches]}"
                )

                # Discard uncommitted changes before exiting so nothing is published
                disc = await client.api_call(
                    mgmt_name,
                    "discard",
                    {},
                    domain=domain,
                    sid=ws.sid,
                    server_ip=ws.server_ip,
                )
                assert disc.success
                ws.discarded = True
                print("6. Discarded WriteSession cleanly without publishing.")

        # Outside the WriteSession, the discarded host is not in the cache
        outside = await client.find_object(mgmt_name, domain, temp_host, obj_type="host", cache_mode="cache")
        print(f"7. Outside WriteSession, find_object({temp_host!r}) -> {outside}")


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/08-cpcrud-operations.md`)*

# 08 — CPCRUD Operations (`08_cpcrud_operations.py`)

Demonstrates offline JSON Schema validation (`client.cpcrud.validate()`), deterministic planning (`client.cpcrud.plan()`), and idempotent execution (`client.cpcrud.apply()`) using `examples/crud_example.yaml`.

## Declarative Template (`examples/crud_example.yaml`)

```yaml title="examples/crud_example.yaml"
# CPCRUD v2 example template: hosts, networks, TCP service, group, access rule, and NAT rule.
#
# Validated offline against `checkpoint_ops_schema.json` via `client.cpcrud.validate()`.
# Adjust `mgmt_name`, `domain`, `layer`, and `package` to match your target environment.

version: 1
mgmt_name: "mdsH5b"
domain: "Domain4"
on_name_conflict: "update"
on_ip_conflict: "reuse"

objects:
  - type: "host"
    name: "cpcrud-example-host-1"
    ipv4-address: "198.51.100.10"
    comments: "CPCRUD example host"
    color: "dark green"

  - type: "network"
    name: "cpcrud-example-net-1"
    subnet4: "198.51.100.0"
    mask-length4: 24
    comments: "CPCRUD example network"
    color: "blue"

services:
  - type: "service-tcp"
    name: "cpcrud-example-tcp-8443"
    port: "8443"
    comments: "CPCRUD example custom HTTPS port"

groups:
  - type: "group"
    name: "cpcrud-example-group"
    members:
      - "cpcrud-example-host-1"
      - "cpcrud-example-net-1"
    comments: "CPCRUD example group"

rules:
  - type: "access-rule"
    layer: "FPCR_UAT_Active Network"
    position: "bottom"
    name: "cpcrud-example-access-rule"
    source:
      - "cpcrud-example-host-1"
    destination:
      - "Any"
    service:
      - "cpcrud-example-tcp-8443"
    rule_action: "Drop"
    comments: "CPCRUD example access rule"

  - type: "nat-rule"
    package: "FPCR_UAT_Active"
    position: "top"
    name: "cpcrud-example-nat-rule"
    method: "hide"
    original-source: "cpcrud-example-host-1"
    original-destination: "Any"
    original-service: "Any"
    translated-source: "cpcrud-example-host-1"
    translated-destination: "Original"
    translated-service: "Original"
    comments: "CPCRUD example NAT rule"
```

## Source Code (`examples/08_cpcrud_operations.py`)

```python title="examples/08_cpcrud_operations.py"
"""Example 08 — Declarative CPCRUD operations (`validate`, `plan`, `apply`, and idempotency).

Run:
    uv run examples/08_cpcrud_operations.py

Demonstrates:
1. Loading `examples/crud_example.yaml` and validating it offline (`client.cpcrud.validate`).
2. Planning (`await client.cpcrud.plan`) and applying (`await client.cpcrud.apply`) the template.
3. Re-planning and re-applying the exact same template to prove idempotency (Pass 2 produces
   `unchanged` / `reuse` outcomes and zero `create` actions).
4. Wrapping execution in `_session_guard.guarded_session` so the lab domain is automatically
   reverted to its pre-run baseline revision on exit.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402

YAML_FILE = Path(__file__).parent / "crud_example.yaml"


async def main() -> None:
    """Validate, plan, and apply `examples/crud_example.yaml` twice to demonstrate idempotency."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")

    raw_template = yaml.safe_load(YAML_FILE.read_text(encoding="utf-8"))
    raw_template["mgmt_name"] = mgmt_name
    raw_template["domain"] = domain

    async with ArodonataClient(settings=settings) as client:
        # 1. Offline JSON Schema validation (zero network calls)
        print("[Step 1/4] Validating template against offline CPCRUD JSON Schema...", flush=True)
        errors = client.cpcrud.validate(raw_template)
        assert not errors, f"Template validation failed: {errors}"
        print("Template passed offline JSON Schema validation.")

        print(f"[Step 2/4] Capturing baseline revision on {mgmt_name}:{domain}...", flush=True)
        async with guarded_session(client, mgmt_name, domains=[domain]):
            for run in (1, 2):
                step_num = run + 1
                print(
                    f"[Step {step_num}/4] Planning and applying CPCRUD template (Run {run}/2)...",
                    flush=True,
                )
                plan = await client.cpcrud.plan(raw_template)
                print(f"\n--- Run {run}: Planned {len(plan.actions)} action(s) ---")
                for act in plan.actions:
                    print(
                        f"  plan:  [{act.mgmt_name}:{act.domain_name}] {act.outcome.value:9} {act.object_type} {act.name}"
                    )

                report = await client.cpcrud.apply(
                    plan,
                    session_name=f"cpcrud-example-run-{run}",
                )
                print(
                    f"Run {run} apply report: success={report.success} "
                    f"created={report.created_count} updated={report.updated_count} "
                    f"unchanged={report.unchanged_count} failed={report.failed_count}"
                )
                for res in report.results:
                    print(
                        f"  apply: [{res.mgmt_name}:{res.domain_name}] {res.outcome.value:9} {res.object_type} {res.name}"
                    )
            print(f"\nReverting {mgmt_name}:{domain} to baseline revision...", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/09-cpcrud-inverse.md`)*

# 09 — CPCRUD Inverse Rollback (`09_cpcrud_inverse.py`)

Demonstrates generating a compensating rollback template via `client.cpcrud.inverse(plan, report)` and applying it to restore the domain state.

## Source Code (`examples/09_cpcrud_inverse.py`)

```python title="examples/09_cpcrud_inverse.py"
"""Example 09 — CPCRUD compensating rollback template (`plan` -> `apply` -> `inverse` -> `apply`).

Run:
    uv run examples/09_cpcrud_inverse.py

Demonstrates how `client.cpcrud.inverse(plan, report)` builds a schema-valid compensating
template from the original `Plan` and `ApplyReport`:
- Created objects/services/groups/rules become `delete` operations keyed by `uid`.
- Updated objects/rules roll back to their captured `prior_state`.
- Deleted objects/rules are re-created from their captured `prior_state`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Plan, apply, generate an inverse rollback template, and apply the rollback."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")

    template: dict[str, Any] = {
        "version": 1,
        "mgmt_name": mgmt_name,
        "domain": domain,
        "objects": [
            {
                "type": "host",
                "name": "cpcrud-example-inverse-host",
                "ipv4-address": "198.51.100.19",
                "comments": "Created for CPCRUD inverse rollback demo",
            }
        ],
    }

    print(f"[Step 1/4] Capturing baseline revision on {mgmt_name}:{domain}...", flush=True)
    async with ArodonataClient(settings=settings) as client, guarded_session(client, mgmt_name, domains=[domain]):
        # 1. Plan ONCE and keep the Plan instance for inverse()
        print("[Step 2/4] Planning and applying forward CPCRUD template...", flush=True)
        plan = await client.cpcrud.plan(template)
        report = await client.cpcrud.apply(plan, session_name="cpcrud-inverse-forward")
        print(f"Forward apply: success={report.success} created={report.created_count}")
        for r in report.results:
            print(f"  forward: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.object_type} {r.name}")

        # 2. Generate compensating inverse template from (plan, report)
        print("\n[Step 3/4] Generating and validating compensating inverse template...", flush=True)
        inverse_template = client.cpcrud.inverse(plan, report)
        val_errors = client.cpcrud.validate(inverse_template)
        assert not val_errors, f"Inverse template failed schema validation: {val_errors}"

        # 3. Plan and apply the compensating template
        print("[Step 4/4] Planning and applying inverse rollback template...", flush=True)
        inv_plan = await client.cpcrud.plan(inverse_template)
        inv_report = await client.cpcrud.apply(inv_plan, session_name="cpcrud-inverse-rollback")
        print(f"\nInverse rollback: success={inv_report.success} deleted={inv_report.deleted_count}")
        for r in inv_report.results:
            print(f"  inverse: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.object_type} {r.name}")
        print(f"\nVerifying/reverting {mgmt_name}:{domain} baseline on exit...", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/10-change-report-evidence.md`)*

# 10 — Change Report Evidence (`10_change_report_evidence.py`)

Demonstrates collecting and rendering auditable `ChangeReport` evidence (`HTML`, `Markdown`, `JSON`), comparing live unpublished rulebase numbering (`OwnedSession`) against published cached numbering.

## Source Code (`examples/10_change_report_evidence.py`)

```python title="examples/10_change_report_evidence.py"
"""Example 10 — Auditable change report evidence (`OwnedSession` pending vs published HTML/Markdown/JSON).

Run:
    ARODONATA_LAB=home uv run examples/10_change_report_evidence.py

Demonstrates:
1. Creating a baseline setup session and a change session in a lab domain (`Domain5` by default).
2. Collecting and rendering a `ChangeReport` while the session is still unpublished using
   `OwnedSession(sid=..., server_ip=...)` (`numbering_source == "owned_session"`).
3. Publishing the session and rendering the final auditable bundle (`html`, `markdown`, `json`)
   to `examples/_tmp/`.
4. Reverting the domain to its original baseline via `_session_guard.guarded_session`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402
from arodonata.reports import (  # noqa: E402
    OwnedSession,
    RenderedReportBundle,
    RenderOptions,
    SessionScope,
)

OUT_DIR = Path(__file__).parent / "_tmp"


def _write_bundle(bundle: RenderedReportBundle, prefix: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if bundle.html is not None:
        (OUT_DIR / f"{prefix}.html").write_bytes(bundle.html)
    if bundle.markdown is not None:
        (OUT_DIR / f"{prefix}.md").write_text(bundle.markdown, encoding="utf-8")
    if bundle.json_text is not None:
        (OUT_DIR / f"{prefix}.json").write_text(bundle.json_text, encoding="utf-8")

    for sess in bundle.report.sessions:
        print(
            f"{prefix}: session={sess.session_name!r} state={sess.state} "
            f"numbering_source={sess.numbering_source} "
            f"rules={len(sess.rule_changes)} objects={len(sess.object_changes)}"
        )
    print(f"  -> wrote {OUT_DIR / prefix}.{{html,md,json}}")


async def main() -> None:
    """Create a sample firewall change, generate pending and published evidence reports, and revert."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("TEST_DOMAIN_B", "Domain5")
    tag = uuid.uuid4().hex[:6]
    options = RenderOptions(
        title="Evidence: **RITM-EXAMPLE** — *Firewall Policy Change*",
        header_fields={"RITM": "RITM-EXAMPLE", "Requester": "secops"},
    )

    print(f"[Step 1/5] Capturing baseline revision on {mgmt_name}:{domain}...", flush=True)
    async with ArodonataClient(settings=settings) as client, guarded_session(client, mgmt_name, domains=[domain]):
        print(f"[Step 2/5] Refreshing rulebase cache for {mgmt_name}:{domain}...", flush=True)
        await client.refresh_rulebases(mgmt_name=mgmt_name, domains=[domain], mode="force")
        packages = await client.get_policy_packages(mgmt_name, domain, cache_mode="cache")
        if not packages or not packages[0].access_layers:
            print(f"No policy package/access layer found in {domain}.")
            return
        layer_name = next(
            (lay.layer_name for lay in packages[0].access_layers if lay.layer_name != "Global"),
            packages[0].access_layers[0].layer_name,
        )

        print(
            f"[Step 3/5] Opening dedicated session on {mgmt_name}:{domain} and staging host + rule in {layer_name!r}...",
            flush=True,
        )
        sid, server_ip = await client.create_dedicated_session(
            mgmt_name,
            domain,
            session_name=f"ritm-example-{tag}",
            session_description="Change report evidence example",
        )
        try:
            s_info = await client.api_call(
                mgmt_name,
                "show-session",
                {},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )
            session_uid = str(s_info.data["uid"])

            host_name = f"cr-web-{tag}"
            rule_name = f"cr-allow-web-{tag}"
            await client.api_call(
                mgmt_name,
                "add-host",
                {"name": host_name, "ipv4-address": "198.51.100.245", "comments": "DMZ web server"},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )
            await client.api_call(
                mgmt_name,
                "add-access-rule",
                {
                    "layer": layer_name,
                    "position": "top",
                    "name": rule_name,
                    "source": "Any",
                    "destination": host_name,
                    "service": "https",
                    "action": "Accept",
                },
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )

            # 1. Pending session evidence numbered live via OwnedSession
            print("[Step 4/5] Building pending change report via OwnedSession...", flush=True)
            owned = OwnedSession(
                sid=sid,
                server_ip=server_ip,
                session_uid=session_uid,
                mgmt_name=mgmt_name,
                domain=domain,
            )
            pending_scope = SessionScope(
                mgmt_name=mgmt_name,
                domain=domain,
                session_uids=[session_uid],
                owned_sessions=owned,
            )
            pending_bundle = await client.build_change_report(
                [pending_scope],
                formats=("html", "markdown", "json"),
                options=options,
            )
            _write_bundle(pending_bundle, "evidence-1-pending")

            # 2. Publish the session and refresh rulebase cache
            print("[Step 5/5] Publishing session and building published change report...", flush=True)
            await client.api_call(
                mgmt_name,
                "publish",
                {},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
                wait_for_task=True,
            )
        finally:
            await client.logout_sid(mgmt_name, sid, server_ip=server_ip)

        await client.refresh_rulebases(mgmt_name=mgmt_name, domains=[domain], mode="force")
        pub_scope = SessionScope(
            mgmt_name=mgmt_name,
            domain=domain,
            session_uids=[session_uid],
        )
        pub_bundle = await client.build_change_report(
            [pub_scope],
            formats=("html", "markdown", "json"),
            options=options,
        )
        _write_bundle(pub_bundle, "evidence-2-published")
        print(f"Reverting {mgmt_name}:{domain} to baseline revision...", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/11-otel-tracing.md`)*

# 11 — OpenTelemetry Tracing (`11_otel_tracing.py`)

Demonstrates provider-agnostic OpenTelemetry span instrumentation (`arlogi.otel.setup_tracing` + `ARODONATA_TRACE_MODULES`) and per-span latency analysis from exported JSONL traces.

## Source Code (`examples/11_otel_tracing.py`)

```python title="examples/11_otel_tracing.py"
"""Example 11 — Provider-agnostic OpenTelemetry tracing with per-span timing breakdown.

Run:
    uv run examples/11_otel_tracing.py

Arodonata v2 is a provider-agnostic OpenTelemetry span producer (`opentelemetry-api` +
`arlogi.otel.traced`) and never owns or configures a global `TracerProvider`. When an application
or script configures tracing via `arlogi.otel.setup_tracing()`, all `@traced` methods across
`ArodonataClient`, `DomainSyncCoordinator`, `ObjectService`, `AMgmtClient`, and `ApiTransport`
automatically emit nested spans with sanitized attributes (never leaking SIDs or secrets).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arlogi.otel import setup_tracing, shutdown_tracing  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402
from arodonata.core.telemetry import set_trace_modules  # noqa: E402

TRACE_DIR = Path(__file__).parent / "_tmp" / "otel_traces"


def _iter_spans(trace_dir: Path) -> Iterator[dict[str, Any]]:
    """Yield every exported span dict across rotated JSONL trace files."""
    for file_path in sorted(trace_dir.glob("*.jsonl")):
        for line in file_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            for resource_span in payload.get("resourceSpans", []):
                for scope_span in resource_span.get("scopeSpans", []):
                    yield from scope_span.get("spans", [])


def _print_span_summary(trace_dir: Path) -> None:
    durations_ms: dict[str, list[float]] = {}
    for span in _iter_spans(trace_dir):
        start = int(span.get("startTimeUnixNano", 0))
        end = int(span.get("endTimeUnixNano", 0))
        durations_ms.setdefault(span.get("name", "?"), []).append(max(end - start, 0) / 1e6)

    if not durations_ms:
        print("  (no spans exported in TRACE_DIR)")
        return

    print(f"\n{'Span Name':<65} {'Count':>6} {'Total ms':>10} {'Avg ms':>10}")
    print("-" * 95)
    for name, values in sorted(durations_ms.items(), key=lambda kv: -sum(kv[1])):
        print(f"  {name:<63} {len(values):>6} {sum(values):>10.1f} {sum(values) / len(values):>10.1f}")


async def main() -> None:
    """Run asset and object refresh with OpenTelemetry JSONL trace export and summarize spans."""
    shutil.rmtree(TRACE_DIR, ignore_errors=True)
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    setup_tracing(service_name="arodonata-example-11", file_dir=TRACE_DIR)
    set_trace_modules({"arodonata": True})

    settings = ArodonataSettings(trace_modules="arodonata:on")
    target_domains = [os.environ["EXAMPLE_DOMAIN"]] if os.getenv("EXAMPLE_DOMAIN") else None
    t0 = time.perf_counter()

    try:
        async with ArodonataClient(settings=settings) as client:
            print("[Step 1/2] Refreshing assets with OpenTelemetry tracing active...", flush=True)
            await client.refresh_assets(domains=target_domains, mode="smart")

            print("[Step 2/2] Refreshing network objects with OpenTelemetry tracing active...", flush=True)
            await client.refresh_objects(domains=target_domains, types=["host", "network"], mode="smart")
    finally:
        shutdown_tracing()

    print(f"\nTotal wall time: {time.perf_counter() - t0:.2f}s")
    _print_span_summary(TRACE_DIR)


if __name__ == "__main__":
    asyncio.run(main())
```


---

*(source: `docs/examples/12-mcp-embedded.md`)*

# 12 — Embedded FastAPI MCP Server (`12_mcp_embedded.py`)

Demonstrates embedding Arodonata's Streamable-HTTP MCP server (`create_mcp_server`, `create_asgi_app`) inside a FastAPI application alongside custom host-defined MCP tools.

## Source Code (`examples/12_mcp_embedded.py`)

```python title="examples/12_mcp_embedded.py"
"""Example 12 — Embedding Arodonata's MCP server inside a FastAPI application (`create_asgi_app`).

Run:
    uv run examples/12_mcp_embedded.py

Then connect an MCP client to `http://127.0.0.1:8000/mcp`.
Demonstrates:
1. Creating an `ArodonataClient` and wiring it into `create_mcp_server(client, auth_mode="host")`.
2. Registering custom application-specific tools alongside Arodonata's built-in Check Point tools.
3. Wrapping the MCP server in `create_asgi_app` and mounting it inside a FastAPI lifespan.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request, Response  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings, user_context  # noqa: E402
from arodonata.mcp import ArodonataMCPSettings, create_asgi_app, create_mcp_server  # noqa: E402

settings = ArodonataSettings()
client = ArodonataClient(settings=settings)
mcp_settings = ArodonataMCPSettings(
    server_name="acme-firewall-assistant",
    auth_mode="host",
    port=8000,
    path="/mcp",
    live_compat=True,
    cpcrud=True,
)

mcp_server = create_mcp_server(client, mcp_settings=mcp_settings)


@mcp_server.tool(
    name="acme_change_ticket",
    description="Look up the ACME change ticket that introduced a firewall rule (demo stub).",
)
async def acme_change_ticket(rule_uid: str) -> dict[str, str]:
    """Return a demo change ticket reference for `rule_uid`."""
    return {"rule_uid": rule_uid, "ticket": "CHG-2026-0001"}


mcp_app = create_asgi_app(client, mcp_server=mcp_server, mcp_settings=mcp_settings)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize ArodonataClient and the Streamable-HTTP MCP router lifespan."""
    async with client, mcp_app.router.lifespan_context(mcp_app.starlette_app):
        yield


app = FastAPI(title="ACME Firewall Assistant (Arodonata v2 MCP)", lifespan=lifespan)

EXPECTED_HOST_API_KEY = os.environ.get("ACME_HOST_API_KEY", "acme-host-demo-token-0123456789abcdef")


@app.middleware("http")
async def host_authentication_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Enclosing ASGI host authentication middleware required when `auth_mode='host'` (`I18`)."""
    if request.url.path == "/healthz":
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    if auth_header != f"Bearer {EXPECTED_HOST_API_KEY}":
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    caller_id = request.headers.get("X-Client-ID", "acme-portal-user")
    with user_context(user_id=caller_id, client_id=caller_id):
        return await call_next(request)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


app.mount("/", mcp_app)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
```


---

### Helper used by mutating lab examples: `examples/_session_guard.py`

```python
"""Crash-safe session baseline guard for Arodonata v2 examples.

Snapshots the target domain(s)' last-published session before running example code and reverts
back to it afterward so examples leave the lab exactly as they found it. The baseline is
persisted to ``examples/_tmp/session_guard_state.json`` so that if a run crashes before its own
revert, the *next* run recovers by restoring that same recorded baseline first rather than
snapshotting an already-drifted state.

Library usage (scripted, e.g. ``08_cpcrud_operations.py``):
    from _session_guard import guarded_session

    async with guarded_session(client, mgmt_name, domains=["Domain4"]):
        ...  # apply templates, publish, etc.

Manual CLI usage (ad-hoc live testing):
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 1st call: saves baseline
    ... do manual testing ...
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 2nd call: reverts to baseline
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from arodonata import ArodonataClient, ArodonataSettings

log = logging.getLogger(__name__)

STATE_FILE = Path(__file__).parent / "_tmp" / "session_guard_state.json"


async def _last_published_session(client: ArodonataClient, mgmt_name: str, domain: str) -> dict[str, Any]:
    """Query ``show-last-published-session`` for ``(mgmt_name, domain)``."""
    result = await client.api_call(mgmt_name, "show-last-published-session", {}, domain=domain)
    if not result.success or not isinstance(result.data, dict):
        return {"uid": "", "name": "", "publish_time": ""}
    return {
        "uid": str(result.data.get("uid") or ""),
        "name": str(result.data.get("name") or ""),
        "publish_time": result.data.get("publish-time") or "",
    }


async def _discard_open_sessions(client: ArodonataClient, mgmt_name: str, domain: str) -> None:
    """Discard unpublished sessions holding changes or locks that would block ``revert-to-revision``."""
    result = await client.api_call(
        mgmt_name,
        "show-sessions",
        {"details-level": "full", "limit": 200},
        domain=domain,
    )
    if not result.success or not isinstance(result.data, dict):
        return
    objs = result.data.get("objects")
    if not isinstance(objs, list):
        return
    dirty_uids: list[str] = []
    for sess in objs:
        if not isinstance(sess, dict) or sess.get("state") == "published":
            continue
        uid = str(sess.get("uid") or "")
        changes = int(sess.get("changes") or 0)
        locks = int(sess.get("locks") or 0)
        if not uid or (changes == 0 and locks == 0):
            continue
        dirty_uids.append(uid)

    if not dirty_uids:
        return

    sid, server_ip = await client.create_dedicated_session(
        mgmt_name,
        domain,
        session_name="cp-guard-discard",
    )
    try:
        for uid in dirty_uids:
            if uid == sid:
                continue
            disc = await client.api_call(
                mgmt_name,
                "discard",
                {"uid": uid},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )
            if disc.success:
                log.info("[%s] discarded stale session uid=%.8s", domain, uid)
            else:
                log.warning("[%s] could not discard uid=%.8s: %s", domain, uid, disc.error_message)
    finally:
        await client.logout_sid(mgmt_name, sid, server_ip=server_ip)


async def _restore_to_baseline(
    client: ArodonataClient,
    mgmt_name: str,
    baseline: dict[str, dict[str, Any]],
) -> list[str]:
    """Revert every domain whose last-published revision drifted from ``baseline``."""
    reverted: list[str] = []
    for domain, rev in baseline.items():
        target_uid = str(rev.get("uid") or "")
        if not target_uid:
            continue
        await _discard_open_sessions(client, mgmt_name, domain)
        current = await _last_published_session(client, mgmt_name, domain)
        if current["uid"] == target_uid:
            continue

        sid, server_ip = await client.create_dedicated_session(
            mgmt_name,
            domain,
            session_name="cp-guard-revert",
        )
        try:
            result = await client.api_call(
                mgmt_name,
                "revert-to-revision",
                {"to-session": target_uid},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
                wait_for_task=True,
            )
        finally:
            await client.logout_sid(mgmt_name, sid, server_ip=server_ip)
        if not result.success:
            err_msg = (result.error_message or "").lower()
            if result.code == "err_validation_failed" and "current revision" in err_msg:
                continue
            raise RuntimeError(
                f"revert-to-revision failed for domain {domain!r}: {result.error_message} (code={result.code})"
            )
        client.invalidate_domain(mgmt_name, domain)
        log.warning("[%s] reverted to baseline %r (uid=%.8s)", domain, rev.get("name"), target_uid)
        reverted.append(domain)
    return reverted


@asynccontextmanager
async def guarded_session(
    client: ArodonataClient,
    mgmt_name: str,
    domains: list[str],
) -> AsyncIterator[dict[str, dict[str, Any]]]:
    """Snapshot ``domains`` before running work and revert back to baseline on exit."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        baseline: dict[str, dict[str, Any]] = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        log.warning(
            "Recovered baseline from previous unclean run (%s) -- restoring before continuing.",
            STATE_FILE,
        )
        await _restore_to_baseline(client, mgmt_name, baseline)
    else:
        baseline = {domain: await _last_published_session(client, mgmt_name, domain) for domain in domains}
        STATE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    try:
        yield baseline
    finally:
        reverted = await _restore_to_baseline(client, mgmt_name, baseline)
        log.warning("Reverted domains to baseline: %s", reverted or "none (no drift)")
        STATE_FILE.unlink(missing_ok=True)


async def _main() -> None:
    from dotenv import load_dotenv

    load_dotenv(".env.test", override=True)
    load_dotenv(".env.lib", override=True)
    load_dotenv(".env.secrets", override=True)
    if os.environ.get("ARODONATA_LAB"):
        load_dotenv(f".env.lab.{os.environ['ARODONATA_LAB']}", override=True)
    logging.basicConfig(level=logging.WARNING)

    settings = ArodonataSettings()
    mgmt_name = sys.argv[1] if len(sys.argv) > 1 else settings.mgmt_names[0]
    domains = sys.argv[2:] or [os.environ.get("EXAMPLE_DOMAIN") or os.environ.get("TEST_DOMAIN_A", "Domain4")]

    async with ArodonataClient(settings=settings) as client:
        if STATE_FILE.exists():
            baseline = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            print(f"Found saved baseline in {STATE_FILE} -- reverting {list(baseline)} to it now.")
            reverted = await _restore_to_baseline(client, mgmt_name, baseline)
            print(f"Reverted domains: {reverted or 'none (no drift)'}")
            STATE_FILE.unlink(missing_ok=True)
            print("Baseline file removed. Guard cycle complete.")
        else:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            baseline = {domain: await _last_published_session(client, mgmt_name, domain) for domain in domains}
            STATE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
            print(f"Saved baseline for {list(baseline)} to {STATE_FILE}.")
            print("Do your manual work now, then re-run this script (same args) to revert.")


if __name__ == "__main__":
    asyncio.run(_main())
```