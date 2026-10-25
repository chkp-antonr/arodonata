"""Example 07 — Dynamic `auth_context`, `user_context`, and `write_session` with `SessionOverlay`.

Run:
    uv run examples/07_context_and_overlay.py

Demonstrates Arodonata v2's context-aware multi-user and transactional features:
1. `with client.auth_context(username=..., password=...)` — dynamically overrides credentials
   per asyncio task without mutating client settings.
2. `with client.user_context(username=..., session_name=..., session_description=...)` —
   propagates operator attribution and Check Point session naming into `write_session` and logs.
3. `async with client.write_session(mgmt_name, domain, publish_on_exit=False)` — opens an
   isolated `WriteSession` backed by `SessionOverlay` so uncommitted `add_object` / `set_object` /
   `delete_object` mutations are immediately visible to `get_hosts`, `find_object`, and
   `search_objects` inside the context ("read-your-own-writes") while remaining invisible to
   other readers and the shared SQLite cache until published.
"""

from __future__ import annotations

import asyncio
import os
import uuid

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Demonstrate auth_context, user_context, and WriteSession SessionOverlay isolation."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("EXAMPLE_DOMAIN") or os.getenv("TEST_DOMAIN_A", "Domain4")
    tag = uuid.uuid4().hex[:6]
    temp_host = f"overlay-demo-host-{tag}"

    async with ArodonataClient(settings=settings) as client:
        # Warm the host cache for the target domain
        await client.refresh_objects(mgmt_name=mgmt_name, domains=[domain], types=["host"], mode="smart")

        eng_password = os.getenv("USER_eng1") or os.getenv("USER_Eng1") or os.getenv("USER_admin", "")  # noqa: SIM112
        eng_user = "eng1" if (os.getenv("USER_eng1") or os.getenv("USER_Eng1")) else "admin"  # noqa: SIM112

        print(f"1. Entering auth_context(username={eng_user!r}) + user_context(session_name=' Ticket-700 ')...")
        with (
            client.auth_context(username=eng_user, password=eng_password),
            client.user_context(
                user_id=eng_user,
                username=eng_user,
                session_name=f"CHG-Overlay-{tag}",
                session_description="Read-your-own-writes SessionOverlay demo",
            ),
        ):
            # Use publish_on_exit=False and discard explicitly so the lab is never mutated
            async with client.write_session(
                mgmt_name,
                domain,
                publish_on_exit=False,
            ) as ws:
                print(f"2. Opened WriteSession (session_name={ws.session_name!r}, server_ip={ws.server_ip})")

                add_res = await client.add_object(
                    mgmt_name,
                    "host",
                    {
                        "name": temp_host,
                        "ipv4-address": "198.51.100.241",
                        "comments": "Uncommitted host in SessionOverlay",
                    },
                    domain=domain,
                )
                assert add_res.success, add_res.error_message
                print(f"3. Added uncommitted host {temp_host!r} inside WriteSession.")

                # Read-your-own-writes: find_object and search_objects see the uncommitted host!
                found = await client.find_object(mgmt_name, domain, temp_host, obj_type="host", cache_mode="cache")
                assert found is not None
                print(f"4. Inside WriteSession, find_object({temp_host!r}) -> {found.name} ({found.ipv4_address})")

                search_res = await client.search_objects(
                    "198.51.100.241",
                    mgmt_name=mgmt_name,
                    domains=[domain],
                    cache_mode="cache",
                )
                print(
                    f"5. Inside WriteSession, search_objects('198.51.100.241') matched: {[m.name for m in search_res.matches]}"
                )

                # Discard uncommitted changes before exiting so nothing is published
                disc = await client.api_call(
                    mgmt_name,
                    "discard",
                    {},
                    domain=domain,
                    sid=ws.sid,
                    server_ip=ws.server_ip,
                )
                assert disc.success
                ws.discarded = True
                print("6. Discarded WriteSession cleanly without publishing.")

        # Outside the WriteSession, the discarded host is not in the cache
        outside = await client.find_object(mgmt_name, domain, temp_host, obj_type="host", cache_mode="cache")
        print(f"7. Outside WriteSession, find_object({temp_host!r}) -> {outside}")


if __name__ == "__main__":
    asyncio.run(main())
