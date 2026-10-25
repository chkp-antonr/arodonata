"""Example 09 — CPCRUD compensating rollback template (`plan` -> `apply` -> `inverse` -> `apply`).

Run:
    uv run examples/09_cpcrud_inverse.py

Demonstrates how `client.cpcrud.inverse(plan, report)` builds a schema-valid compensating
template from the original `Plan` and `ApplyReport`:
- Created objects/services/groups/rules become `delete` operations keyed by `uid`.
- Updated objects/rules roll back to their captured `prior_state`.
- Deleted objects/rules are re-created from their captured `prior_state`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Plan, apply, generate an inverse rollback template, and apply the rollback."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")

    template: dict[str, Any] = {
        "version": 1,
        "mgmt_name": mgmt_name,
        "domain": domain,
        "objects": [
            {
                "type": "host",
                "name": "cpcrud-example-inverse-host",
                "ipv4-address": "198.51.100.19",
                "comments": "Created for CPCRUD inverse rollback demo",
            }
        ],
    }

    print(f"[Step 1/4] Capturing baseline revision on {mgmt_name}:{domain}...", flush=True)
    async with ArodonataClient(settings=settings) as client, guarded_session(client, mgmt_name, domains=[domain]):
        # 1. Plan ONCE and keep the Plan instance for inverse()
        print("[Step 2/4] Planning and applying forward CPCRUD template...", flush=True)
        plan = await client.cpcrud.plan(template)
        report = await client.cpcrud.apply(plan, session_name="cpcrud-inverse-forward")
        print(f"Forward apply: success={report.success} created={report.created_count}")
        for r in report.results:
            print(f"  forward: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.object_type} {r.name}")

        # 2. Generate compensating inverse template from (plan, report)
        print("\n[Step 3/4] Generating and validating compensating inverse template...", flush=True)
        inverse_template = client.cpcrud.inverse(plan, report)
        val_errors = client.cpcrud.validate(inverse_template)
        assert not val_errors, f"Inverse template failed schema validation: {val_errors}"

        # 3. Plan and apply the compensating template
        print("[Step 4/4] Planning and applying inverse rollback template...", flush=True)
        inv_plan = await client.cpcrud.plan(inverse_template)
        inv_report = await client.cpcrud.apply(inv_plan, session_name="cpcrud-inverse-rollback")
        print(f"\nInverse rollback: success={inv_report.success} deleted={inv_report.deleted_count}")
        for r in inv_report.results:
            print(f"  inverse: [{r.mgmt_name}:{r.domain_name}] {r.outcome.value:9} {r.object_type} {r.name}")
        print(f"\nVerifying/reverting {mgmt_name}:{domain} baseline on exit...", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
