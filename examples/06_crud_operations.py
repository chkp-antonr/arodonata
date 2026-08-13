"""Idempotent CPCRUD example: apply a template twice via client.cpcrud.

Run: uv run examples/06_crud_operations.py (from the repo root)
Env (repo-root .env.test / .env.secrets): API_MGMT, USER_admin.

Wrapped in _session_guard.guarded_session so the target domain is snapshotted
before this runs and reverted back to that baseline afterward, regardless of
success or failure -- this example leaves the lab exactly as it found it.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session

from arodonata import ArodonataClient
from arodonata.cpcrud import ApplyReport

load_dotenv(".env.test", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

YAML_FILE = Path(__file__).parent / "crud_example.yaml"
MGMT_IP = os.environ["API_MGMT"]
DOMAIN = "Domain4"


async def main() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    client = ArodonataClient(engine=engine, username="admin", password=os.environ["USER_admin"], mgmt_ip=MGMT_IP)
    async with client:
        # Snapshots Domain4's current last-published session on entry, then reverts back to it
        # on exit (success or failure) -- see _session_guard.py. This example leaves the lab
        # exactly as it found it; run examples/_session_guard.py directly if you need the same
        # save/revert around manual (non-scripted) live testing instead.
        async with guarded_session(client, MGMT_IP, domains=[DOMAIN]):
            for run in (1, 2):
                events = [event async for event in client.cpcrud.apply(YAML_FILE)]
                report = events[-1]
                assert isinstance(report, ApplyReport), "apply() must end with an ApplyReport"
                print(f"Run {run} summary: {report.summary}")
                for r in report.results:
                    print(f"Run {run}: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.type} {r.name}")
            # idempotency: run 2 should be all unchanged/reuse, zero create
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
