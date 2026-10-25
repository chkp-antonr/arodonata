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
