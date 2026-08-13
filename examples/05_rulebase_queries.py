"""Query access and NAT rulebases from the cache.

Run: uv run examples/05_rulebase_queries.py
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
            access_rules = await client.get_access_rules(enabled_only=True)
            print(f"Enabled access rules: {len(access_rules)}")
            for rule in access_rules[:5]:
                print(f"  #{rule.rule_number}: {rule.name}")

            nat_rules = await client.get_nat_rules()
            print(f"\nNAT rules: {len(nat_rules)}")
            for nat_rule in nat_rules[:5]:
                print(f"  #{nat_rule.rule_number}: {nat_rule.name}")
    finally:
        await engine.dispose()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
