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
