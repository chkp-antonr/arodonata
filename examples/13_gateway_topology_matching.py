"""Example 13 — Gateway interface topology caching & affected gateway candidate matching (`get_gateway_topology`, `find_affected_gateways`).

Run:
    uv run examples/13_gateway_topology_matching.py

Demonstrates:
1. Synchronizing and querying the gateway interface topology cache (`arodonata_gateway_topology`) via
   `client.get_gateway_topology(...)`.
2. Summarizing flat topology intervals per gateway interface (`TopologyService.summarize_gateway_interfaces`).
3. Discovering which policy-enforcing gateways (simple gateways, clusters, and VSX Virtual Systems),
   domains, policy packages, and access layers are affected by traffic between `sources` and `destinations`
   via `client.find_affected_gateways(sources, destinations, ...)`, excluding gateways where both endpoints
   reside behind the same interface (`src_interface == dst_interface`).
"""

from __future__ import annotations

import asyncio
import os
import time

from dotenv import load_dotenv

load_dotenv(".env.lib", override=False)
load_dotenv(".env.secrets", override=False)

from arodonata import ArodonataClient, ArodonataSettings, TopologyService  # noqa: E402


async def main() -> None:
    """Inspect cached gateway interface topology and locate candidate gateways for sample traffic flows."""
    settings = ArodonataSettings()
    raw_domain = os.getenv("EXAMPLE_DOMAIN")
    target_domain = raw_domain.strip() if raw_domain and raw_domain.strip() else None
    sample_sources = [
        s.strip() for s in os.getenv("EXAMPLE_FLOW_SOURCES", "10.0.0.0/8, 192.168.0.0/16").split(",") if s.strip()
    ]
    sample_destinations = [
        d.strip() for d in os.getenv("EXAMPLE_FLOW_DESTINATIONS", "172.16.0.0/12, 8.8.8.8").split(",") if d.strip()
    ]
    t0 = time.perf_counter()

    async with ArodonataClient(settings=settings) as client:
        print(
            f"[Step 1/3] Fetching gateway topology entries for domain={target_domain!r} (get_gateway_topology)...",
            flush=True,
        )
        entries = await client.get_gateway_topology(domain=target_domain, cache_mode="smart")
        print(f"  Cached topology intervals: {len(entries)}")

        print("\n[Step 2/3] Summarizing topology per gateway interface...", flush=True)
        summaries = TopologyService.summarize_gateway_interfaces(entries)
        print(f"  Policy-enforcing gateway interfaces: {len(summaries)}")
        for summary in summaries[:10]:
            cidrs_preview = ", ".join(summary.cidrs_and_ranges[:4])
            if len(summary.cidrs_and_ranges) > 4:
                cidrs_preview += f", ... (+{len(summary.cidrs_and_ranges) - 4} more)"
            dmz_tag = " [DMZ]" if summary.leads_to_dmz else ""
            print(
                f"  - {summary.gateway_asset_id} :: {summary.interface_name} "
                f"({summary.topology_zone}{dmz_tag}, sources={summary.source_types}): {cidrs_preview}"
            )

        print(
            f"\n[Step 3/3] Finding affected gateways for sources={sample_sources} -> destinations={sample_destinations}...",
            flush=True,
        )
        candidates = await client.find_affected_gateways(
            sources=sample_sources,
            destinations=sample_destinations,
            domain=target_domain,
            cache_mode="cache",
        )
        print(f"  Affected policy-enforcing gateways found: {len(candidates)}")
        for cand in candidates:
            print(
                f"  * {cand.gateway_asset_id} ({cand.gateway_type}, ip={cand.ipv4_address}) "
                f"policy={cand.installed_access_policy!r} packages={cand.policy_packages} layers={cand.access_layers}"
            )
            for flow in cand.matched_flows[:5]:
                print(
                    f"      {flow.source_query} ({flow.src_interface} [{flow.src_topology_zone}: {flow.src_matched_cidr}]) "
                    f"-> {flow.destination_query} ({flow.dst_interface} [{flow.dst_topology_zone}: {flow.dst_matched_cidr}]) "
                    f"[{flow.match_type}]"
                )

    print(f"\nCompleted in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
