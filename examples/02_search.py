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
