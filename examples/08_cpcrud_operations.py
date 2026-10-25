"""Example 08 — Declarative CPCRUD operations (`validate`, `plan`, `apply`, and idempotency).

Run:
    uv run examples/08_cpcrud_operations.py

Demonstrates:
1. Loading `examples/crud_example.yaml` and validating it offline (`client.cpcrud.validate`).
2. Planning (`await client.cpcrud.plan`) and applying (`await client.cpcrud.apply`) the template.
3. Re-planning and re-applying the exact same template to prove idempotency (Pass 2 produces
   `unchanged` / `reuse` outcomes and zero `create` actions).
4. Wrapping execution in `_session_guard.guarded_session` so the lab domain is automatically
   reverted to its pre-run baseline revision on exit.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402

YAML_FILE = Path(__file__).parent / "crud_example.yaml"


async def main() -> None:
    """Validate, plan, and apply `examples/crud_example.yaml` twice to demonstrate idempotency."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")

    raw_template = yaml.safe_load(YAML_FILE.read_text(encoding="utf-8"))
    raw_template["mgmt_name"] = mgmt_name
    raw_template["domain"] = domain

    async with ArodonataClient(settings=settings) as client:
        # 1. Offline JSON Schema validation (zero network calls)
        print("[Step 1/4] Validating template against offline CPCRUD JSON Schema...", flush=True)
        errors = client.cpcrud.validate(raw_template)
        assert not errors, f"Template validation failed: {errors}"
        print("Template passed offline JSON Schema validation.")

        print(f"[Step 2/4] Capturing baseline revision on {mgmt_name}:{domain}...", flush=True)
        async with guarded_session(client, mgmt_name, domains=[domain]):
            for run in (1, 2):
                step_num = run + 1
                print(
                    f"[Step {step_num}/4] Planning and applying CPCRUD template (Run {run}/2)...",
                    flush=True,
                )
                plan = await client.cpcrud.plan(raw_template)
                print(f"\n--- Run {run}: Planned {len(plan.actions)} action(s) ---")
                for act in plan.actions:
                    print(
                        f"  plan:  [{act.mgmt_name}:{act.domain_name}] {act.outcome.value:9} {act.object_type} {act.name}"
                    )

                report = await client.cpcrud.apply(
                    plan,
                    session_name=f"cpcrud-example-run-{run}",
                )
                print(
                    f"Run {run} apply report: success={report.success} "
                    f"created={report.created_count} updated={report.updated_count} "
                    f"unchanged={report.unchanged_count} failed={report.failed_count}"
                )
                for res in report.results:
                    print(
                        f"  apply: [{res.mgmt_name}:{res.domain_name}] {res.outcome.value:9} {res.object_type} {res.name}"
                    )
            print(f"\nReverting {mgmt_name}:{domain} to baseline revision...", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
