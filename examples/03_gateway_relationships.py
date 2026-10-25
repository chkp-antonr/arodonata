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
