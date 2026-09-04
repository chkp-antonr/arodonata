# Arodonata — Examples & Recipes

Worked examples showing common tasks with Arodonata: basic queries, search, gateway relationships, smart refresh, rulebase queries, CRUD operations (including inverse/rollback), session basics, and OpenTelemetry tracing. Each section pairs the explanation with the full, runnable example script (snippets resolved inline, matching what the docs site renders). Companion document to the Guide and the full API Reference.


---

*(source: `docs/examples/index.md`)*

# Examples

Narrated walkthroughs of the runnable scripts in the top-level
[`examples/`](https://github.com/chkp-antonr/arodonata/tree/master/examples)
directory. Each page below embeds the actual current script contents via
`pymdownx.snippets`, so what you read here always matches what's in the
repo.

| Page | Script | Covers |
|---|---|---|
| [Basic Queries](01-basic-queries.md) | `01_basic_queries.py` | Domains, gateways, hosts, networks |
| [Search](02-search.md) | `02_search.py` | Name-pattern search, IP lookup |
| [Gateway Relationships](03-gateway-relationships.md) | `03_gateway_relationships.py` | Cluster topology |
| [Smart Refresh](04-smart-refresh.md) | `04_smart_refresh.py` | Populating/refreshing the cache — run this first |
| [Rulebase Queries](05-rulebase-queries.md) | `05_rulebase_queries.py` | Access and NAT rules |
| [Idempotent CPCRUD](06-crud-operations.md) | `06_crud_operations.py` | Idempotent Policy-as-Code object & rule CRUD |
| [Inverse Templates](07-crud-inverse.md) | `07_crud_inverse.py` | Plan → apply → inverse → apply compensating-template round-trip |
| [Session Basics](07-session-basics.md) | `07_session_basics.py` | Raw session management: baseline, publish, revert |
| [OTel-Traced Smart Refresh](08-otel-smart-refresh.md) | `08_otel_smart_refresh.py` | Same as Smart Refresh, with OTel tracing + a per-span timing breakdown |

Run [Smart Refresh](04-smart-refresh.md) first against a fresh database —
every other example reads from a cache that needs to be populated first.


---

*(source: `docs/examples/01-basic-queries.md`)*

# Basic Queries

Fetches domains, gateways, hosts, and networks straight from the cache —
the four `ArodonataClient` helper methods used most often.

```python title="examples/01_basic_queries.py"
"""Query domains, hosts, and networks from the Arodonata cache.

Run: uv run examples/01_basic_queries.py
Requires: DATABASE_URL, MGMT_NAMES, MGMT_SERVERS, and API_KEY_VARS set in
your environment (see docs/configuration/index.md), with the cache already
populated (see docs/examples/04-smart-refresh.md for how to populate it).

Environment variables (examples/.env.lib):
    DATABASE_URL=sqlite+aiosqlite:///./_tmp/arodonata.db
    MGMT_NAMES=mgmt1
    MGMT_SERVERS=10.0.0.1
    API_KEY_VARS=MY_API_KEY_VAR
    ARODONATA_LOG_LEVEL=WARNING
"""

import asyncio
import os

# Load environment variables BEFORE importing arodonata modules
# This ensures logging configuration is picked up correctly
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import time

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings


async def main() -> None:
    print(f"Using database: {os.getenv('DATABASE_URL', 'sqlite+aiosqlite:///:memory:')}")

    # Settings automatically loaded from environment variables
    # The validator handles API_KEY_VARS indirection automatically!
    settings = ArodonataSettings()
    print(f"Management servers: {settings.mgmt_names_list}")

    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=settings)

    start_time = time.perf_counter()

    try:
        async with client:
            domains = await client.get_domains()
            print(f"Domains: {len(domains)}")
            for domain in domains[:5]:
                print(f"  {domain.name} (active_ip: {domain.active_ip}, server: {domain.mgmt_name})")

            hosts = await client.get_hosts()
            print(f"\nHosts: {len(hosts)}")
            for host in hosts[:5]:
                print(f"  {host.name}: {host.ip_address}")

            networks = await client.get_networks()
            print(f"\nNetworks: {len(networks)}")
            for net in networks[:5]:
                print(f"  {net.name}: {net.subnet4}/{net.subnet_mask}")
    finally:
        await engine.dispose()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/01_basic_queries.py
```


---

*(source: `docs/examples/02-search.md`)*

# Search

Two ways to find objects: `name_filter` wildcards on a helper method, and a
direct IP lookup through the cache repository.

```python title="examples/02_search.py"
"""Search for objects by name pattern and by IP address.

Run: uv run examples/02_search.py
"""

import asyncio
import os

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import time

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings


def _settings_from_env() -> ArodonataSettings:
    api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
    api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)
    return ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=api_keys,
    )


async def main() -> None:
    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=_settings_from_env())

    start_time = time.perf_counter()

    try:
        async with client:
            # Wildcard name search via a helper method's name_filter.
            web_hosts = await client.get_hosts(name_filter="web*")
            print(f"Hosts matching 'web*': {len(web_hosts)}")
            for host in web_hosts[:5]:
                print(f"  {host.name}: {host.ip_address}")

            # Direct IP lookup via the cache repository.
            ip_matches = await client.cache.get_objects_by_ip("127.0.0.1")
            print(f"\nObjects with IP 127.0.0.1: {len(ip_matches)}")
            for obj in ip_matches[:5]:
                print(f"  {obj.name} ({obj.type})")
    finally:
        await engine.dispose()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/02_search.py
```


---

*(source: `docs/examples/03-gateway-relationships.md`)*

# Gateway Relationships

Groups gateways by `parent_uid` to separate cluster members from standalone
gateways — see [Sessions & Multi-Domain](../architecture/sessions-and-mdm.md)
for how domain context flows through these results.

```python title="examples/03_gateway_relationships.py"
"""Inspect cluster topology: which gateways are cluster members vs. standalone.

Run: uv run examples/03_gateway_relationships.py
"""

import asyncio
import os

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import time
from collections import defaultdict

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings


def _settings_from_env() -> ArodonataSettings:
    api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
    api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)
    return ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=api_keys,
    )


async def main() -> None:
    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=_settings_from_env())

    start_time = time.perf_counter()

    try:
        async with client:
            gateways = await client.get_gateways()

            members_by_parent = defaultdict(list)
            standalone = []

            for gw in gateways:
                parent_uid = getattr(gw, "parent_uid", None)
                if parent_uid:
                    members_by_parent[parent_uid].append(gw)
                else:
                    standalone.append(gw)

            print(f"Standalone gateways: {len(standalone)}")
            for gw in standalone[:5]:
                print(f"  {gw.name} ({gw.type})")

            print(f"\nClusters with members: {len(members_by_parent)}")
            for parent_uid, members in list(members_by_parent.items())[:5]:
                names = ", ".join(m.name for m in members)
                print(f"  cluster {parent_uid}: {names}")
    finally:
        await engine.dispose()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/03_gateway_relationships.py
```


---

*(source: `docs/examples/04-smart-refresh.md`)*

# Smart Refresh

Populates the cache from a live management server and streams progress via
`SSEEvent`s. Run this once against a fresh database before any other
example — see [Caching & Sync](../architecture/caching-and-sync.md) for how
the underlying `show-changes` incremental refresh works.

By default the example uses a full refresh. For domains that are already
populated, `mode="check"` reloads only stale domains, and
`mode="incremental"` applies just the objects changed since the last
refresh (falling back to a full reload whenever that isn't safe):

```python
async for event in client.refresh_objects(mgmt_names=["mgmt1"], mode="incremental"):
    print(event.message)
```

```python title="examples/04_smart_refresh.py"
"""Populate/refresh the cache and stream progress events.

Run: uv run examples/04_smart_refresh.py

This is the script to run first against a fresh database — the other
example scripts assume the cache already has data in it.
"""

import asyncio
import os

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import time

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.api.schemas import SSEEventType


def _settings_from_env() -> ArodonataSettings:
    api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
    api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)
    return ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=api_keys,
    )


async def main() -> None:
    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=_settings_from_env())

    start_time = time.perf_counter()

    try:
        async with client:
            print("Refreshing domains and gateways...")
            async for event in client.build_refresh_assets_cache():
                if event.event_type == SSEEventType.LOG:
                    print(f"  {event.data.get('message', '')}")
                elif event.event_type == SSEEventType.COMPLETE:
                    print(f"  done: {event.data}")

            print("\nRefreshing objects (hosts/networks/groups)...")
            async for event in client.refresh_objects(mode="force"):
                data = event.data or {}
                if data.get("status") in {"type_fetched", "domain_complete", "domain_failed"}:
                    print(f"  {event.message}")
    finally:
        await engine.dispose()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/04_smart_refresh.py
```


---

*(source: `docs/examples/05-rulebase-queries.md`)*

# Rulebase Queries

Reads access and NAT rules from the cache, filtered to enabled access rules
only as an example of the `enabled_only` filter shared by all rulebase
helper methods.

```python title="examples/05_rulebase_queries.py"
"""Query access and NAT rulebases from the cache.

Run: uv run examples/05_rulebase_queries.py
"""

import asyncio
import os

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

import time

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings


def _settings_from_env() -> ArodonataSettings:
    api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
    api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)
    return ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=api_keys,
    )


async def main() -> None:
    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=_settings_from_env())

    start_time = time.perf_counter()

    try:
        async with client:
            access_rules = await client.get_access_rules(enabled_only=True)
            print(f"Enabled access rules: {len(access_rules)}")
            for rule in access_rules[:5]:
                print(f"  #{rule.rule_number}: {rule.name}")

            nat_rules = await client.get_nat_rules()
            print(f"\nNAT rules: {len(nat_rules)}")
            for nat_rule in nat_rules[:5]:
                print(f"  #{nat_rule.rule_number}: {nat_rule.name}")
    finally:
        await engine.dispose()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/05_rulebase_queries.py
```


---

*(source: `docs/examples/06-crud-operations.md`)*

# Idempotent CPCRUD

Applies a declarative YAML policy template via `client.cpcrud.apply()`
twice, wrapped in `_session_guard.guarded_session` so the target domain is
snapshotted and reverted afterward regardless of success or failure. On the
second run, everything that already matches the template's intent reports
`unchanged`/`reuse` — zero new `create`s — see [CPCRUD
Engine](../user-guide/cpcrud.md) for the full outcome model.

```python title="examples/06_crud_operations.py"
"""Idempotent CPCRUD example: apply a template twice via client.cpcrud.

Run: uv run examples/06_crud_operations.py (from the repo root)
Env (repo-root .env.test / .env.secrets): API_MGMT, USER_admin.

Wrapped in _session_guard.guarded_session so the target domain is snapshotted
before this runs and reverted back to that baseline afterward, regardless of
success or failure -- this example leaves the lab exactly as it found it.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session

from arodonata import ArodonataClient
from arodonata.cpcrud import ApplyReport

load_dotenv(".env.test", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

YAML_FILE = Path(__file__).parent / "crud_example.yaml"
MGMT_IP = os.environ["API_MGMT"]
DOMAIN = "Domain4"


async def main() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    client = ArodonataClient(engine=engine, username="admin", password=os.environ["USER_admin"], mgmt_ip=MGMT_IP)
    async with client:
        # Snapshots Domain4's current last-published session on entry, then reverts back to it
        # on exit (success or failure) -- see _session_guard.py. This example leaves the lab
        # exactly as it found it; run examples/_session_guard.py directly if you need the same
        # save/revert around manual (non-scripted) live testing instead.
        async with guarded_session(client, MGMT_IP, domains=[DOMAIN]):
            for run in (1, 2):
                events = [event async for event in client.cpcrud.apply(YAML_FILE)]
                report = events[-1]
                assert isinstance(report, ApplyReport), "apply() must end with an ApplyReport"
                print(f"Run {run} summary: {report.summary}")
                for r in report.results:
                    print(f"Run {run}: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.type} {r.name}")
            # idempotency: run 2 should be all unchanged/reuse, zero create
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/06_crud_operations.py
```


---

*(source: `docs/examples/07-crud-inverse.md`)*

# Inverse (Compensating) Templates

Demonstrates the plan → apply → inverse → apply round-trip: `plan()` once,
`apply()` that same `Plan` object, then `client.cpcrud.inverse(plan, report)`
builds a compensating template scoped to just the actions that actually ran,
and applying *that* restores prior state. See ["Inverse (compensating)
templates"](https://github.com/chkp-antonr/arodonata/blob/master/examples/README_CRUD.md#inverse-compensating-templates)
for why you must never re-`plan()` after `apply()` in this flow.

```python title="examples/07_crud_inverse.py"
"""Inverse (compensating) template example: plan -> apply -> inverse -> apply.

Run: uv run examples/07_crud_inverse.py (from the repo root)
Env (repo-root .env.test / .env.secrets): API_MGMT, USER_admin.

Wrapped in _session_guard.guarded_session so the target domain is snapshotted
before this runs and reverted back to that baseline afterward, regardless of
success or failure -- this example leaves the lab exactly as it found it.

Demonstrates the plan/apply/inverse flow documented in examples/README_CRUD.md's
"Inverse (compensating) templates" section: plan() ONCE, apply() that same Plan
object, then inverse(plan, report) -- never re-plan after applying, since state
has changed by then and a fresh plan() would resolve against the post-apply
state instead of the pre-apply intent the report describes.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session

from arodonata import ArodonataClient
from arodonata.cpcrud import ApplyReport

load_dotenv(".env.test", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

MGMT_IP = os.environ["API_MGMT"]
DOMAIN = "Domain4"

TEMPLATE = {
    "management_servers": [
        {
            "mgmt_name": MGMT_IP,
            "domains": [
                {
                    "name": DOMAIN,
                    "operations": [
                        {"type": "host", "data": {"name": "cpcrud-example-inverse-host", "ip-address": "10.0.0.9"}},
                    ],
                },
            ],
        },
    ]
}


async def main() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    client = ArodonataClient(engine=engine, username="admin", password=os.environ["USER_admin"], mgmt_ip=MGMT_IP)
    async with client:
        # Snapshots Domain4's current last-published session on entry, then reverts back to it
        # on exit (success or failure) -- see _session_guard.py. Belt-and-suspenders here: the
        # inverse apply below should already restore prior state on its own, but this guard is
        # the safety net if that round-trip doesn't fully clean up (e.g. a failure mid-script).
        async with guarded_session(client, MGMT_IP, domains=[DOMAIN]):
            # Plan ONCE and reuse this same Plan object for inverse() below -- do NOT re-plan
            # after apply(): the state has changed by then, so a fresh plan() would resolve
            # against the post-apply state instead of the pre-apply intent.
            plan = await client.cpcrud.plan(TEMPLATE)

            events = [event async for event in client.cpcrud.apply(plan)]
            report = events[-1]
            assert isinstance(report, ApplyReport), "apply() must end with an ApplyReport"
            print(f"Apply summary: {report.summary}")
            for r in report.results:
                print(f"apply:   [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.type} {r.name}")

            # Build the compensating template from the SAME plan plus the report of what
            # actually executed (scopes the inverse to just the actions that really ran, and
            # keys deletes by uid instead of name), then apply it to restore prior state.
            inverse_template = client.cpcrud.inverse(plan, report)
            restore_events = [event async for event in client.cpcrud.apply(inverse_template)]
            restored = restore_events[-1]
            assert isinstance(restored, ApplyReport), "apply() must end with an ApplyReport"
            print(f"Restored summary: {restored.summary}")
            for r in restored.results:
                print(f"restore: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.type} {r.name}")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/07_crud_inverse.py
```


---

*(source: `docs/examples/07-session-basics.md`)*

# Session Basics

A learning-oriented walkthrough of raw session management via `api_call()`
directly (no `cpcrud`): capture the current last-published session as a
baseline, create a host, publish, confirm the last-published session
changed, then revert to the saved baseline and confirm it's back — the same
save/revert pattern `cpcrud` examples use internally, shown here explicitly
step by step.

```python title="examples/07_session_basics.py"
"""Simple script to understand Check Point session management.

This script demonstrates:
1. Get current last published session (baseline)
2. Create a test host
3. Publish changes
4. Verify last published changed
5. Revert to saved baseline
6. Verify last published returned to original

Run: uv run examples/07_session_basics.py

Environment variables (examples/.env.lib):
    DATABASE_URL=sqlite+aiosqlite:///./_tmp/arodonata.db
    MGMT_NAMES=mgmt1
    MGMT_SERVERS=10.0.0.1
    API_KEY_VARS=MY_API_KEY_VAR
    ARODONATA_LOG_LEVEL=WARNING
"""

import asyncio
import os
import sys
from typing import Any

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings

# Configuration from environment variables
DOMAIN = "General"  # Default domain, can override if needed
MGMT_NAME: str = os.getenv("MGMT_NAMES", "").split(",")[0] if os.getenv("MGMT_NAMES") else ""

if not MGMT_NAME:
    print("ERROR: MGMT_NAMES not set in environment variables")
    print("Please set MGMT_NAMES in your .env.lib file")
    sys.exit(1)

TEST_HOST_NAME = "session-test-host"
TEST_HOST_IP = "192.168.250.250"


def _extract_time(time_field: Any) -> str:
    """Extract readable time from Check Point time field.

    Check Point returns time as a dict: {'posix': 123, 'iso-8601': '2026-07-22T20:29+0300'}
    """
    if not time_field:
        return "unknown"
    if isinstance(time_field, dict):
        iso_time = time_field.get("iso-8601", "")
        if iso_time:
            return iso_time
        return str(time_field)
    if isinstance(time_field, str):
        return time_field
    return str(time_field)


async def print_session_info(session_data: dict, title: str) -> None:
    """Print session information in a readable format."""
    print(f"\n{'=' * 60}")
    print(f"{title}")
    print(f"{'=' * 60}")

    if session_data:
        uid = session_data.get("uid", "unknown")
        name = session_data.get("name", "unknown")
        user_name = session_data.get("user-name", "unknown")
        changes = session_data.get("changes", 0)
        creation_time = _extract_time(session_data.get("creation-time"))
        publish_time = _extract_time(session_data.get("publish-time"))
        last_login = _extract_time(session_data.get("last-login-time"))
        state = session_data.get("state", "unknown")

        print(f"  UID:           {uid}")
        print(f"  Name:          {name}")
        print(f"  User:          {user_name}")
        print(f"  State:         {state}")
        print(f"  Changes:       {changes}")
        print(f"  Creation Time: {creation_time}")
        print(f"  Publish Time:  {publish_time}")
        if last_login != "unknown":
            print(f"  Last Login:    {last_login}")
    else:
        print("  ⚠ No session data available")


async def main() -> None:
    """Main session learning workflow."""
    print(f"Using database: {os.getenv('DATABASE_URL', 'sqlite+aiosqlite:///:memory:')}")
    print(f"Management server: {MGMT_NAME} (from MGMT_NAMES env var)")
    print(f"Domain: {DOMAIN}")

    # Load settings from environment
    settings = ArodonataSettings()

    # Create engine and client
    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=settings)

    try:
        async with client:
            # ============================================================
            # STEP 1: Get current last published session (BASELINE)
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 1: Get BASELINE (current last published session)")
            print(f"{'=' * 60}")

            baseline_result = await client.api_call(
                MGMT_NAME,
                "show-last-published-session",
                DOMAIN,
                payload={},
            )

            if baseline_result.success and baseline_result.data:
                baseline_session = baseline_result.data
                baseline_uid = baseline_session.get("uid", "")
                baseline_name = baseline_session.get("name", "unknown")

                await print_session_info(baseline_session, "CURRENT BASELINE (before any changes)")

                # Save baseline UID for later revert
                print(f"\n  ✓ Saved baseline UID: {baseline_uid[:16]}...")

            else:
                print(f"  ✗ Failed to get baseline: {baseline_result.message}")
                return

            # ============================================================
            # STEP 2: Create a test host
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 2: Create test host")
            print(f"{'=' * 60}")

            print(f"\n  Creating host: {TEST_HOST_NAME}")
            print(f"  IP Address: {TEST_HOST_IP}")

            create_result = await client.api_call(
                MGMT_NAME,
                "add-host",
                DOMAIN,
                payload={
                    "name": TEST_HOST_NAME,
                    "ip-address": TEST_HOST_IP,
                    "comments": "Test host for session learning",
                },
            )

            if create_result.success:
                print("  ✓ Host created successfully")
            else:
                print(f"  ✗ Failed to create host: {create_result.message}")
                return

            # ============================================================
            # STEP 3: Publish changes
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 3: Publish changes")
            print(f"{'=' * 60}")

            publish_result = await client.api_call(
                MGMT_NAME,
                "publish",
                DOMAIN,
                payload={},
                wait_for_task=True,
                timeout=300,  # 5 minutes timeout for publish
            )

            if publish_result.success:
                print("  ✓ Changes published successfully")
            else:
                print(f"  ✗ Failed to publish: {publish_result.message}")
                return

            # ============================================================
            # STEP 4: Verify last published CHANGED
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 4: Verify last published session changed")
            print(f"{'=' * 60}")

            await asyncio.sleep(2)  # Brief pause for propagation

            new_published_result = await client.api_call(
                MGMT_NAME,
                "show-last-published-session",
                DOMAIN,
                payload={},
            )

            if new_published_result.success and new_published_result.data:
                new_session = new_published_result.data
                new_uid = new_session.get("uid", "")

                await print_session_info(new_session, "NEW LAST PUBLISHED (after changes)")

                # Compare with baseline
                if new_uid != baseline_uid:
                    print("\n  ✓ Last published session CHANGED")
                    print(f"    Baseline UID: {baseline_uid[:16]}...")
                    print(f"    New UID:      {new_uid[:16]}...")
                else:
                    print("\n  ⚠ Last published session did NOT change (unexpected!)")
            else:
                print("  ✗ Failed to get new last published session")

            # ============================================================
            # STEP 5: REVERT to baseline
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 5: REVERT to baseline")
            print(f"{'=' * 60}")
            print(f"\n  Reverting to baseline: {baseline_name}")
            print("  This may take a couple of minutes...")

            # First discard any open sessions
            print("\n  Discarding open sessions...")
            discard_result = await client.api_call(
                MGMT_NAME,
                "discard",
                DOMAIN,
                payload={},
            )
            if discard_result.success:
                print("    ✓ Discarded open sessions")
            else:
                print(f"    Note: Discard returned: {discard_result.message[:100]}")

            # Now revert to baseline
            print("\n  Reverting to baseline session...")
            revert_result = await client.api_call(
                MGMT_NAME,
                "revert-to-revision",
                DOMAIN,
                payload={"to-session": baseline_uid},
                wait_for_task=True,
                timeout=300,  # 5 minutes timeout for revert
            )

            if revert_result.success:
                print("  ✓ Successfully reverted to baseline")
            else:
                print(f"  ✗ Failed to revert: {revert_result.message}")
                print("  ⚠ You may need to revert manually via SmartConsole")
                return

            # ============================================================
            # STEP 6: Verify last published RETURNED to baseline
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 6: Verify last published returned to baseline")
            print(f"{'=' * 60}")

            await asyncio.sleep(2)  # Brief pause for propagation

            final_published_result = await client.api_call(
                MGMT_NAME,
                "show-last-published-session",
                DOMAIN,
                payload={},
            )

            if final_published_result.success and final_published_result.data:
                final_session = final_published_result.data
                final_uid = final_session.get("uid", "")
                final_name = final_session.get("name", "unknown")

                await print_session_info(final_session, "FINAL LAST PUBLISHED (after revert)")

                # Verify we returned to baseline
                if final_uid == baseline_uid:
                    print("\n  ✅ SUCCESS: Last published returned to BASELINE!")
                    print(f"    Original UID: {baseline_uid[:16]}...")
                    print(f"    Current UID:  {final_uid[:16]}...")
                    print(f"    Session names match: {baseline_name == final_name}")
                else:
                    print("\n  ⚠ UNEXPECTED: Last published did NOT return to baseline")
                    print(f"    Expected UID: {baseline_uid[:16]}...")
                    print(f"    Got UID:      {final_uid[:16]}...")
            else:
                print("  ✗ Failed to get final last published session")

    finally:
        await engine.dispose()

    print(f"\n{'=' * 60}")
    print("SESSION LEARNING COMPLETED!")
    print(f"{'=' * 60}")
    print("\nYou now understand:")
    print("  1. How to get last published session (baseline)")
    print("  2. How to create objects")
    print("  3. How to publish changes")
    print("  4. How last published changes after publish")
    print("  5. How to revert to a specific session")
    print("  6. How to verify the revert worked")
    print("\nKey concepts:")
    print("  • last-published-session = current state")
    print("  • revert-to-revision needs logged-in session")
    print("  • revert takes time (can be several minutes)")
    print("  • revert returns to EXACT state - no cleanup needed!")
    print("  • Always verify operations completed successfully")


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/07_session_basics.py
```


---

*(source: `docs/examples/08-otel-smart-refresh.md`)*

# OTel-Traced Smart Refresh

Same cache refresh as [Smart Refresh](04-smart-refresh.md), but with
OpenTelemetry tracing enabled via `arlogi.otel.setup_tracing()` — arodonata
never owns a `TracerProvider` itself (see [Configuration
Guide](../configuration/index.md#tracing)), so a standalone script that
wants tracing sets one up itself, same as this example does. Prints the
same wall-clock total as `04_smart_refresh.py` for comparison, plus a
per-span-name timing breakdown read back from the exported trace files.

```python title="examples/08_otel_smart_refresh.py"
"""Same cache refresh as 04_smart_refresh.py, but with OTel tracing enabled.

Run: uv run examples/08_otel_smart_refresh.py

arodonata never owns a TracerProvider -- it's a provider-agnostic span
producer (depends on opentelemetry-api only; every @traced call is a no-op
if nothing configured a provider). A standalone script that wants tracing
sets one up itself, same as this example does via arlogi.otel.setup_tracing().
Inside a host application (e.g. one that already calls setup_tracing() for
its own FastAPI/SQLAlchemy tracing), arodonata's spans just nest into that
trace automatically -- no wiring needed on arodonata's side either way.

This prints the same wall-clock total as 04_smart_refresh.py for a direct
before/after comparison, plus a per-span-name timing breakdown read back
from the exported trace files -- the kind of login/transport/lock visibility
that motivated adding tracing in the first place (see docs/architecture).
"""

import asyncio
import json
import os
import shutil
import time
from pathlib import Path

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arlogi.otel import setup_tracing, shutdown_tracing
from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.api.schemas import SSEEventType

TRACE_DIR = Path(__file__).parent / "_tmp" / "otel_traces"


def _settings_from_env() -> ArodonataSettings:
    api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
    api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)
    return ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=api_keys,
    )


def _iter_spans(trace_dir: Path):
    """Yield every span dict across all rotated JSONL trace files."""
    for f in sorted(trace_dir.glob("*.jsonl")):
        for line in f.read_text().splitlines():
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
        print("  (no spans exported -- is arlogi[otel] installed? check TRACE_DIR)")
        return

    print(f"\n{'Span':<82} {'Count':>6} {'Total ms':>10} {'Avg ms':>10}")
    for name, values in sorted(durations_ms.items(), key=lambda kv: -sum(kv[1])):
        print(f"  {name:<80} {len(values):>6} {sum(values):>10.1f} {sum(values) / len(values):>10.1f}")


async def main() -> None:
    shutil.rmtree(TRACE_DIR, ignore_errors=True)
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    setup_tracing(service_name="arodonata-example", file_dir=TRACE_DIR)

    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=_settings_from_env())

    start_time = time.perf_counter()

    try:
        async with client:
            print("Refreshing domains and gateways...")
            async for event in client.build_refresh_assets_cache():
                if event.event_type == SSEEventType.LOG:
                    print(f"  {event.data.get('message', '')}")
                elif event.event_type == SSEEventType.COMPLETE:
                    print(f"  done: {event.data}")

            print("\nRefreshing objects (hosts/networks/groups)...")
            async for event in client.refresh_objects(mode="force"):
                data = event.data or {}
                if data.get("status") in {"type_fetched", "domain_complete", "domain_failed"}:
                    print(f"  {event.message}")
    finally:
        await engine.dispose()
        shutdown_tracing()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")
    _print_span_summary(TRACE_DIR)


if __name__ == "__main__":
    asyncio.run(main())
```

Run it:

```bash
uv run examples/08_otel_smart_refresh.py
```


---

### Helper used by the session example: `examples/_session_guard.py`

```python
"""Crash-safe session baseline guard for CPCRUD examples.

Snapshots the target domain(s)' last-published session before running example
code and reverts back to it afterward -- examples should leave the lab
exactly as they found it. The baseline is persisted to a state file so that
if a run crashes before its own revert, the *next* run recovers by restoring
that same recorded baseline first, rather than snapshotting an
already-drifted state as if it were the truth. The state file is removed
only after a verified, successful revert -- a second crash in a row still
recovers correctly on the third run.

Library usage (scripted, e.g. 06_crud_operations.py):
    from _session_guard import guarded_session

    async with guarded_session(client, mgmt_name, domains=["General"]):
        ...  # apply templates, publish, etc.
    # baseline is restored here regardless of success/failure

Manual usage (ad-hoc live testing, no script wrapping it):
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 1st call: saves baseline
    ... do your manual testing (SmartConsole, raw API calls, whatever) ...
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 2nd call: reverts to it

    The two calls are told apart by whether the state file already exists, not by a flag --
    the same detection `guarded_session` uses for crash recovery: no file means "nothing saved
    yet, save now"; a file whose recorded uid no longer matches the domain's current
    last-published session means real changes happened since it was saved, so revert to it. If
    you run the "after" call and nothing had changed, it's a no-op (mirrors
    `_restore_to_baseline`'s per-domain drift check) but the file is still cleaned up. Defaults
    to `$API_MGMT` and domain "Domain4" if not given.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

STATE_FILE = Path(__file__).parent / "_tmp" / "session_guard_state.json"


async def _last_published_session(client: Any, mgmt_name: str, domain: str) -> dict:
    result = await client.api_call(mgmt_name, "show-last-published-session", domain, payload={})
    if not result.success or not result.data:
        return {"uid": "", "name": "", "publish_time": ""}
    return {
        "uid": result.data.get("uid", ""),
        "name": result.data.get("name", ""),
        "publish_time": result.data.get("publish-time", ""),
    }


async def _discard_open_sessions(client: Any, mgmt_name: str, domain: str) -> None:
    """Discard unpublished sessions holding changes/locks (blocks revert)."""
    result = await client.api_call(mgmt_name, "show-sessions", domain, payload={"details-level": "full", "limit": 200})
    if not result.success or not result.data:
        return
    for s in result.data.get("objects", []):
        if s.get("state") == "published":
            continue
        uid = s.get("uid", "")
        if not uid or not (s.get("changes", 0) or s.get("locks", 0)):
            continue
        r = await client.api_call(mgmt_name, "discard", domain, payload={"uid": uid})
        if r.success:
            log.info("[%s] discarded stale session uid=%.8s", domain, uid)
        else:
            log.warning("[%s] could not discard uid=%.8s: %s", domain, uid, r.message)


async def _restore_to_baseline(client: Any, mgmt_name: str, baseline: dict[str, dict]) -> list[str]:
    """Revert every domain whose last published revision drifted from baseline."""
    reverted: list[str] = []
    for domain, rev in baseline.items():
        target_uid = rev.get("uid", "")
        if not target_uid:
            continue
        await _discard_open_sessions(client, mgmt_name, domain)
        current = await _last_published_session(client, mgmt_name, domain)
        if current["uid"] == target_uid:
            continue
        result = await client.api_call(
            mgmt_name,
            "revert-to-revision",
            domain,
            payload={"to-session": target_uid},
            wait_for_task=True,
        )
        if not result.success:
            # CP aborts when already at the target revision -- state is correct.
            if result.code == "err_validation_failed" and "current revision" in (result.message or ""):
                continue
            raise RuntimeError(
                f"revert-to-revision failed for domain {domain!r}: {result.message} (code={result.code})"
            )
        log.warning("[%s] reverted to baseline %r (uid=%.8s)", domain, rev.get("name"), target_uid)
        reverted.append(domain)
    return reverted


@asynccontextmanager
async def guarded_session(client: Any, mgmt_name: str, domains: list[str]):
    """Yield the active baseline; guarantee revert-or-record-for-recovery on exit.

    If a previous run's state file is still on disk, its recorded baseline is adopted as the
    current truth (a prior run crashed before reverting) and is restored *before* any new work
    runs, instead of being overwritten by a fresh snapshot of an already-drifted domain.
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        baseline = json.loads(STATE_FILE.read_text())
        log.warning(
            "Recovered baseline from a previous unclean run (%s) -- restoring it before continuing.",
            STATE_FILE,
        )
        await _restore_to_baseline(client, mgmt_name, baseline)
    else:
        baseline = {domain: await _last_published_session(client, mgmt_name, domain) for domain in domains}
        STATE_FILE.write_text(json.dumps(baseline, indent=2))

    try:
        yield baseline
    finally:
        reverted = await _restore_to_baseline(client, mgmt_name, baseline)
        log.warning("Reverted domains to baseline: %s", reverted or "none (no drift)")
        STATE_FILE.unlink(missing_ok=True)


async def _main() -> None:
    import os
    import sys

    from dotenv import load_dotenv
    from sqlalchemy.ext.asyncio import create_async_engine

    from arodonata import ArodonataClient

    load_dotenv(".env.test", override=True)
    load_dotenv(".env.secrets", override=True)
    logging.basicConfig(level=logging.WARNING)

    mgmt_ip = sys.argv[1] if len(sys.argv) > 1 else os.environ["API_MGMT"]
    domains = sys.argv[2:] or ["Domain4"]

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    client = ArodonataClient(engine=engine, username="admin", password=os.environ["USER_admin"], mgmt_ip=mgmt_ip)
    async with client:
        if STATE_FILE.exists():
            baseline = json.loads(STATE_FILE.read_text())
            print(f"Found saved baseline in {STATE_FILE} -- reverting {list(baseline)} to it now.")
            reverted = await _restore_to_baseline(client, mgmt_ip, baseline)
            print(f"Reverted domains: {reverted or 'none (no drift)'}")
            STATE_FILE.unlink(missing_ok=True)
            print("Baseline file removed. Guard cycle complete.")
        else:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            baseline = {domain: await _last_published_session(client, mgmt_ip, domain) for domain in domains}
            STATE_FILE.write_text(json.dumps(baseline, indent=2))
            print(f"Saved baseline for {list(baseline)} to {STATE_FILE}.")
            print("Do your manual work now, then re-run this script (same args) to revert.")
    await engine.dispose()


if __name__ == "__main__":
    import asyncio

    asyncio.run(_main())

```