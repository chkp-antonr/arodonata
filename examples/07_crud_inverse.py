"""Inverse (compensating) template example: plan -> apply -> inverse -> apply.

Run: uv run examples/07_crud_inverse.py (from the repo root)
Env (repo-root .env.test / .env.secrets): API_MGMT, USER_admin.

Wrapped in _session_guard.guarded_session so the target domain is snapshotted
before this runs and reverted back to that baseline afterward, regardless of
success or failure -- this example leaves the lab exactly as it found it.

Demonstrates the plan/apply/inverse flow documented in examples/README_CRUD.md's
"Inverse (compensating) templates" section: plan() ONCE, apply() that same Plan
object, then inverse(plan, report) -- never re-plan after applying, since state
has changed by then and a fresh plan() would resolve against the post-apply
state instead of the pre-apply intent the report describes.
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

MGMT_IP = os.environ["API_MGMT"]
DOMAIN = "Domain4"

TEMPLATE = {
    "management_servers": [
        {
            "mgmt_name": MGMT_IP,
            "domains": [
                {
                    "name": DOMAIN,
                    "operations": [
                        {"type": "host", "data": {"name": "cpcrud-example-inverse-host", "ip-address": "10.0.0.9"}},
                    ],
                },
            ],
        },
    ]
}


async def main() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    client = ArodonataClient(engine=engine, username="admin", password=os.environ["USER_admin"], mgmt_ip=MGMT_IP)
    async with client:
        # Snapshots Domain4's current last-published session on entry, then reverts back to it
        # on exit (success or failure) -- see _session_guard.py. Belt-and-suspenders here: the
        # inverse apply below should already restore prior state on its own, but this guard is
        # the safety net if that round-trip doesn't fully clean up (e.g. a failure mid-script).
        async with guarded_session(client, MGMT_IP, domains=[DOMAIN]):
            # Plan ONCE and reuse this same Plan object for inverse() below -- do NOT re-plan
            # after apply(): the state has changed by then, so a fresh plan() would resolve
            # against the post-apply state instead of the pre-apply intent.
            plan = await client.cpcrud.plan(TEMPLATE)

            events = [event async for event in client.cpcrud.apply(plan)]
            report = events[-1]
            assert isinstance(report, ApplyReport), "apply() must end with an ApplyReport"
            print(f"Apply summary: {report.summary}")
            for r in report.results:
                print(f"apply:   [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.type} {r.name}")

            # Build the compensating template from the SAME plan plus the report of what
            # actually executed (scopes the inverse to just the actions that really ran, and
            # keys deletes by uid instead of name), then apply it to restore prior state.
            inverse_template = client.cpcrud.inverse(plan, report)
            restore_events = [event async for event in client.cpcrud.apply(inverse_template)]
            restored = restore_events[-1]
            assert isinstance(restored, ApplyReport), "apply() must end with an ApplyReport"
            print(f"Restored summary: {restored.summary}")
            for r in restored.results:
                print(f"restore: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.type} {r.name}")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
