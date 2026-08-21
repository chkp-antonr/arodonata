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
