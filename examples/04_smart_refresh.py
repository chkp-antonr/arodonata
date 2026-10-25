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
