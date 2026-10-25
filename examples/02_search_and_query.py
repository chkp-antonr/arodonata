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
