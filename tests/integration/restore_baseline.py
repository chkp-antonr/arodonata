"""Manually restore CP to a saved baseline after a crashed test run.

Usage:
    uv run tests/integration/restore_baseline.py _tmp/cp_baseline/baseline-<ts>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine

_project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_project_root / "src"))
sys.path.insert(0, str(_project_root))

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402
from tests.integration.cp_revision import restore_to_baseline  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="baseline-<ts>.json to restore")
    args = parser.parse_args()

    for f in [_project_root / ".env.test", _project_root / ".env.secrets"]:
        if f.exists():
            load_dotenv(f, override=True)

    mgmt_ip = os.environ["API_MGMT"]
    api_key = os.environ["APIKEY"]
    baseline = json.loads(args.baseline.read_text())

    engine = create_async_engine("sqlite+aiosqlite:///_tmp/restore_baseline.db")
    settings = ArodonataSettings(mgmt_names=mgmt_ip, mgmt_servers=mgmt_ip, api_keys=api_key)
    try:
        async with ArodonataClient(engine=engine, settings=settings) as client:
            reverted = await restore_to_baseline(client, mgmt_ip, baseline)
    finally:
        await engine.dispose()

    print(f"Reverted domains: {reverted or 'none (no drift)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
