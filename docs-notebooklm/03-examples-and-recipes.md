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

```python
--8 < --"examples/01_basic_queries.py"
```


---

*(source: `docs/examples/02-search-and-query.md`)*

# 02 — Search & Structured Query (`02_search_and_query.py`)

Demonstrates multi-term object search with recursive parent group memberships (`client.search_objects()`, including `exact_match=True`), progressive-disclosure schema discovery (`client.describe_objects()`), SQL-free cross-domain aggregation (`client.query_objects()`), and cache freshness inspection (`client.get_cache_status()`).

## Source Code (`examples/02_search_and_query.py`)

```python
--8 < --"examples/02_search_and_query.py"
```


---

*(source: `docs/examples/03-gateway-relationships.md`)*

# 03 — Gateway & VSX Topology (`03_gateway_relationships.py`)

Demonstrates querying cached gateways, clusters, cluster members, and VSX virtual systems (`client.get_gateways()`) and traversing both UID (`id`, `parent_uid`, `member_uids`, `virtual_system_uids`) and human-readable composite identifiers (`asset_id`, `parent_id`, `parent_asset_id`, `member_asset_ids`, `virtual_system_asset_ids`, including cross-domain VSX links), along with `interfaces` and `network_security_blades`.

## Source Code (`examples/03_gateway_relationships.py`)

```python
--8 < --"examples/03_gateway_relationships.py"
```


---

*(source: `docs/examples/04-smart-refresh.md`)*

# 04 — Smart & Streaming Refresh (`04_smart_refresh.py`)

Demonstrates paired streaming (`stream_refresh_*`) and batch (`refresh_*`) cache synchronization across assets, objects, services, and rulebases, including SSE conversion via `arodonata.adapters.sse.to_sse_event`.

## Source Code (`examples/04_smart_refresh.py`)

```python
--8 < --"examples/04_smart_refresh.py"
```


---

*(source: `docs/examples/05-rulebase-queries.md`)*

# 05 — Rulebase Queries (`05_rulebase_queries.py`)

Demonstrates policy package discovery (`client.get_policy_packages()`), hierarchical SmartConsole numbering (`client.get_package_rulebase()`, `client.get_layer_rulebase()`), reverse UID lookup (`client.locate_rules()`), and local rulebase filtering (`client.filter_rulebase()`, including `output_format="cpcrud"`).

## Source Code (`examples/05_rulebase_queries.py`)

```python
--8 < --"examples/05_rulebase_queries.py"
```


---

*(source: `docs/examples/06-session-basics.md`)*

# 06 — Session Lifecycle Basics (`06_session_basics.py`)

Demonstrates low-level Check Point session lifecycle operations (`create_dedicated_session`, `add-host`, `publish`, and crash-safe `revert-to-revision` via `_session_guard.py`).

## Source Code (`examples/06_session_basics.py`)

```python
--8 < --"examples/06_session_basics.py"
```


---

*(source: `docs/examples/07-context-and-overlay.md`)*

# 07 — Contexts & Session Overlay (`07_context_and_overlay.py`)

Demonstrates runtime `auth_context`, `user_context`, and isolated `write_session` with `SessionOverlay` read-your-own-writes isolation (verifying that uncommitted objects appear immediately in `get_hosts()`, `find_object()`, and `search_objects()` before discarding cleanly on exit).

## Source Code (`examples/07_context_and_overlay.py`)

```python
--8 < --"examples/07_context_and_overlay.py"
```


---

*(source: `docs/examples/08-cpcrud-operations.md`)*

# 08 — CPCRUD Operations (`08_cpcrud_operations.py`)

Demonstrates offline JSON Schema validation (`client.cpcrud.validate()`), deterministic planning (`client.cpcrud.plan()`), and idempotent execution (`client.cpcrud.apply()`) using `examples/crud_example.yaml`.

## Declarative Template (`examples/crud_example.yaml`)

```yaml
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

```python
--8 < --"examples/08_cpcrud_operations.py"
```


---

*(source: `docs/examples/09-cpcrud-inverse.md`)*

# 09 — CPCRUD Inverse Rollback (`09_cpcrud_inverse.py`)

Demonstrates generating a compensating rollback template via `client.cpcrud.inverse(plan, report)` and applying it to restore the domain state.

## Source Code (`examples/09_cpcrud_inverse.py`)

```python
--8 < --"examples/09_cpcrud_inverse.py"
```


---

*(source: `docs/examples/10-change-report-evidence.md`)*

# 10 — Change Report Evidence (`10_change_report_evidence.py`)

Demonstrates collecting and rendering auditable `ChangeReport` evidence (`HTML`, `Markdown`, `JSON`), comparing live unpublished rulebase numbering (`OwnedSession`) against published cached numbering.

## Source Code (`examples/10_change_report_evidence.py`)

```python
--8 < --"examples/10_change_report_evidence.py"
```


---

*(source: `docs/examples/11-otel-tracing.md`)*

# 11 — OpenTelemetry Tracing (`11_otel_tracing.py`)

Demonstrates provider-agnostic OpenTelemetry span instrumentation (`arlogi.otel.setup_tracing` + `ARODONATA_TRACE_MODULES`) and per-span latency analysis from exported JSONL traces.

## Source Code (`examples/11_otel_tracing.py`)

```python
--8 < --"examples/11_otel_tracing.py"
```


---

*(source: `docs/examples/12-mcp-embedded.md`)*

# 12 — Embedded FastAPI MCP Server (`12_mcp_embedded.py`)

Demonstrates embedding Arodonata's Streamable-HTTP MCP server (`create_mcp_server`, `create_asgi_app`) inside a FastAPI application alongside custom host-defined MCP tools.

## Source Code (`examples/12_mcp_embedded.py`)

```python
--8 < --"examples/12_mcp_embedded.py"
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