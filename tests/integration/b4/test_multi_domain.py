"""Bucket 4 — Multi-domain isolation (`TEST_DOMAIN_A` vs `TEST_DOMAIN_B` vs `Global`).

Covers:
1. Publishing a host in ``TEST_DOMAIN_A`` does not leak into ``TEST_DOMAIN_B`` or trigger a
   refresh on ``TEST_DOMAIN_B``.
2. Concurrent ``refresh_objects(mode="force")`` across ``TEST_DOMAIN_A`` and ``TEST_DOMAIN_B``.
3. Domain-scoped cache reads return only rows belonging to that domain.
4. ``Global`` domain resolves its ``active_ip`` and supports ``create_dedicated_session``.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from arodonata import ArodonataClient
from tests.integration.cp_revision import (
    BaselineSnapshot,
    last_published_session,
    revert_domain_to,
)


@pytest.mark.cp_mutates
async def test_publish_in_a_invisible_in_b(
    antonr_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    test_domain_b: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify publishing in domain A leaves domain B untouched and un-refreshed."""
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a, test_domain_b],
        types=["host"],
        mode="force",
    )
    pre_b = await last_published_session(apikey_client, mgmt_name, test_domain_b)

    tag = uuid.uuid4().hex[:6]
    host_name = f"it-b4-dom-iso-{tag}"

    try:
        async with antonr_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"b4-iso-{tag}",
            publish_on_exit=True,
        ):
            res = await antonr_client.add_object(
                mgmt_name,
                "host",
                {"name": host_name, "ipv4-address": "198.51.100.216"},
                domain=test_domain_a,
            )
            assert res.success

        # Domain B must remain fresh on smart-fast check with cache_ttl=0
        outcome_b = await apikey_client.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_b],
            types=["host"],
            mode="smart-fast",
            cache_ttl=0.0,
        )
        assert f"{mgmt_name}:{test_domain_b}" in outcome_b.skipped_domains
        assert f"{mgmt_name}:{test_domain_b}" not in outcome_b.refreshed_domains

        # Domain A picks up the host via smart-fast
        hosts_a = await apikey_client.get_hosts(
            mgmt_name=mgmt_name,
            domain=test_domain_a,
            names=[host_name],
            cache_mode="smart-fast",
            cache_ttl=0.0,
        )
        assert len(hosts_a) == 1

        # Domain B never sees Domain A's host
        hosts_b = await apikey_client.get_hosts(
            mgmt_name=mgmt_name,
            domain=test_domain_b,
            names=[host_name],
            cache_mode="cache",
        )
        assert hosts_b == []

        post_b = await last_published_session(apikey_client, mgmt_name, test_domain_b)
        assert post_b.session_uid == pre_b.session_uid
    finally:
        base_a = cp_baseline_snapshot.domains[test_domain_a]
        await revert_domain_to(apikey_client, mgmt_name, base_a)
        await apikey_client.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            types=["host"],
            mode="force",
        )


async def test_concurrent_refresh_of_two_domains(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    test_domain_b: str,
) -> None:
    """Verify concurrent force refreshes of ``TEST_DOMAIN_A`` and ``TEST_DOMAIN_B`` succeed."""
    outcomes = await asyncio.gather(
        apikey_client.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            types=["host", "network"],
            mode="force",
        ),
        apikey_client.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_b],
            types=["host", "network"],
            mode="force",
        ),
    )
    assert f"{mgmt_name}:{test_domain_a}" in outcomes[0].refreshed_domains
    assert f"{mgmt_name}:{test_domain_b}" in outcomes[1].refreshed_domains


async def test_domain_scoped_reads_do_not_leak(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    test_domain_b: str,
) -> None:
    """Verify domain-scoped cache queries return only rows belonging to that domain."""
    for domain in (test_domain_a, test_domain_b):
        objs = await apikey_client.get_objects(
            mgmt_name=mgmt_name,
            domain=domain,
            types=["host"],
            cache_mode="smart",
        )
        assert objs, f"Expected cached hosts in {domain}"
        leaked = [o for o in objs if o.domain_name != domain]
        assert not leaked, f"Domain read for {domain} leaked rows from another domain: {leaked[:3]}"


async def test_global_domain_resolves_active_mds_and_creates_dedicated_session(
    apikey_client: ArodonataClient,
    mgmt_name: str,
) -> None:
    """Verify ``Global`` domain resolves its active IP and supports ``create_dedicated_session``."""
    resp = await apikey_client.api_call(
        mgmt_name,
        "show-global-domain",
        {"name": "Global", "details-level": "full"},
    )
    if not resp.success:
        pytest.skip(f"show-global-domain not supported on {mgmt_name}: {resp.error_message}")

    domains = await apikey_client.get_domains(
        mgmt_name=mgmt_name,
        include_global=True,
        cache_mode="force",
    )
    global_dom = next((d for d in domains if d.name == "Global"), None)
    assert global_dom is not None
    assert global_dom.is_global is True
    assert global_dom.active_ip

    session_name = f"it-b4-global-{uuid.uuid4().hex[:6]}"
    sid, server_ip = await apikey_client.create_dedicated_session(
        mgmt_name,
        "Global",
        session_name=session_name,
    )
    try:
        assert sid
        assert server_ip == global_dom.active_ip
        check = await apikey_client.api_call(
            mgmt_name,
            "show-session",
            {},
            domain="Global",
            sid=sid,
            server_ip=server_ip,
        )
        assert check.success
        assert check.data.get("name") == session_name
    finally:
        await apikey_client.logout_sid(mgmt_name, sid, server_ip=server_ip)
