"""Bucket 1 — Concurrent multi-admin operations against the live MDSM.

Covers:
1. 5 distinct administrators (``admin``, ``AntonR``, ``Eng1``, ``Eng2``, ``Eng3``) open dedicated
   sessions in ``TEST_DOMAIN_A`` concurrently via ``asyncio.gather`` — each receives a distinct
   SID and ``user-name`` matches the owning administrator.
2. Concurrent read calls across all 5 clients complete without session cross-talk.
"""

from __future__ import annotations

import asyncio

from arodonata import ArodonataClient


async def test_five_concurrent_admins_distinct_sessions(
    admin_client: ArodonataClient,
    antonr_client: ArodonataClient,
    eng1_client: ArodonataClient,
    eng2_client: ArodonataClient,
    eng3_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify 5 administrators open isolated concurrent sessions without cross-talk."""
    clients: list[tuple[str, ArodonataClient]] = [
        ("admin", admin_client),
        ("AntonR", antonr_client),
        ("eng1", eng1_client),
        ("eng2", eng2_client),
        ("eng3", eng3_client),
    ]

    async def _probe_admin(expected_user: str, client: ArodonataClient) -> tuple[str, str, str]:
        sid, ip = await client.create_dedicated_session(
            mgmt_name,
            domain=test_domain_a,
            session_name=f"conc-{expected_user}",
        )
        try:
            res = await client.api_call(
                mgmt_name,
                "show-session",
                {},
                domain=test_domain_a,
                sid=sid,
                server_ip=ip,
            )
            assert res.success, f"{expected_user} show-session failed: {res.error_message}"
            return expected_user, res.data["user-name"], res.data["uid"]
        finally:
            await client.logout_sid(mgmt_name, sid, server_ip=ip)

    results = await asyncio.gather(*(_probe_admin(u, c) for u, c in clients))

    uids: set[str] = set()
    for expected_user, actual_user, uid in results:
        assert actual_user == expected_user
        uids.add(uid)
    assert len(uids) == 5, f"Expected 5 distinct session UIDs, got {uids}"
