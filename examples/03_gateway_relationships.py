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
