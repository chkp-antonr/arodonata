"""Example 06 — Check Point session lifecycle basics: baseline, dedicated session, publish, and revert.

Run:
    uv run examples/06_session_basics.py

Demonstrates:
1. Reading the domain's current baseline revision (`show-last-published-session`).
2. Opening an isolated write session via `client.create_dedicated_session(mgmt_name, domain)`.
3. Creating a test host (`add-host`) and publishing (`publish` with `wait_for_task=True`).
4. Verifying that `show-last-published-session` moved to the newly published session UID.
5. Reverting the domain back to the saved baseline revision (`revert-to-revision`) via
   `_session_guard.guarded_session`.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


def _extract_iso_time(time_field: Any) -> str:
    if isinstance(time_field, dict):
        return str(time_field.get("iso-8601") or time_field)
    return str(time_field or "unknown")


async def main() -> None:
    """Run the baseline -> create_dedicated_session -> add-host -> publish -> revert cycle."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")
    host_name = f"example-session-host-{uuid.uuid4().hex[:6]}"

    async with ArodonataClient(settings=settings) as client:
        async with guarded_session(client, mgmt_name, domains=[domain]) as baseline:
            base_rev = baseline[domain]
            print(f"Step 1: Captured baseline on {mgmt_name}:{domain}:")
            print(f"  UID:  {base_rev['uid']}")
            print(f"  Name: {base_rev['name']}")
            print(f"  Time: {_extract_iso_time(base_rev['publish_time'])}")

            print(f"\nStep 2: Opening dedicated write session and creating host {host_name!r}...")
            sid, server_ip = await client.create_dedicated_session(
                mgmt_name,
                domain,
                session_name=f"example-06-{host_name[-6:]}",
                session_description="Example 06 dedicated write session",
            )
            try:
                add_res = await client.api_call(
                    mgmt_name,
                    "add-host",
                    {
                        "name": host_name,
                        "ipv4-address": "198.51.100.240",
                        "comments": "Created by examples/06_session_basics.py",
                    },
                    domain=domain,
                    sid=sid,
                    server_ip=server_ip,
                )
                assert add_res.success, f"add-host failed: {add_res.error_message}"
                print(f"  Created host {host_name} (uid={add_res.data.get('uid')})")

                print("\nStep 3: Publishing session...")
                pub_res = await client.api_call(
                    mgmt_name,
                    "publish",
                    {},
                    domain=domain,
                    sid=sid,
                    server_ip=server_ip,
                    wait_for_task=True,
                )
                assert pub_res.success, f"publish failed: {pub_res.error_message}"
                print("  Published successfully.")
            finally:
                await client.logout_sid(mgmt_name, sid, server_ip=server_ip)

            print("\nStep 4: Verifying show-last-published-session advanced...")
            after_res = await client.api_call(mgmt_name, "show-last-published-session", {}, domain=domain)
            assert after_res.success
            new_uid = after_res.data.get("uid")
            print(f"  Previous UID: {base_rev['uid']}")
            print(f"  Current UID:  {new_uid}")
            assert new_uid != base_rev["uid"]

            print("\nStep 5: Exiting guarded_session will automatically revert domain to baseline...")

        final_res = await client.api_call(mgmt_name, "show-last-published-session", {}, domain=domain)
        print(f"Step 6: Verified post-revert UID: {final_res.data.get('uid')}")


if __name__ == "__main__":
    asyncio.run(main())
