"""Bucket 5 — Cross-user and cross-domain publish, discard, and revert matrix.

Covers:
1. A host published by ``admin_client`` in ``TEST_DOMAIN_A`` is visible to ``eng1_client`` via
   both live API call and ``cache_mode="smart-fast"``.
2. An uncommitted host added by ``eng2_client`` in ``TEST_DOMAIN_B`` is invisible to
   ``admin_client`` and vanishes after ``discard``.
3. Parallel publishes in ``TEST_DOMAIN_A`` (``admin_client``) and ``TEST_DOMAIN_B``
   (``eng1_client``) both succeed and revert cleanly.
4. Multi-object publish (2 hosts + 1 network) in a single session reverts atomically.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata import ArodonataClient
from tests.integration.cp_revision import BaselineSnapshot, revert_domain_to

pytestmark = pytest.mark.cp_mutates


def _unique(prefix: str = "it-b5-mat") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


async def _server_has_host(client: ArodonataClient, mgmt_name: str, domain: str, name: str) -> bool:
    res = await client.api_call(mgmt_name, "show-host", {"name": name}, domain=domain)
    return bool(res.success)


async def test_publish_visible_to_other_user(
    admin_client: ArodonataClient,
    eng1_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify a host published by admin is visible to eng1 via API and smart-fast cache."""
    host_name = _unique("it-b5-vis")

    await eng1_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )

    try:
        async with admin_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"b5-vis-{host_name[-6:]}",
            publish_on_exit=True,
        ):
            r = await admin_client.add_object(
                mgmt_name,
                "host",
                {"name": host_name, "ipv4-address": "198.51.100.221"},
                domain=test_domain_a,
            )
            assert r.success

        assert await _server_has_host(eng1_client, mgmt_name, test_domain_a, host_name)

        hosts = await eng1_client.get_hosts(
            mgmt_name=mgmt_name,
            domain=test_domain_a,
            names=[host_name],
            cache_mode="smart-fast",
            cache_ttl=0.0,
        )
        assert len(hosts) == 1
        assert hosts[0].name == host_name
    finally:
        base_a = cp_baseline_snapshot.domains[test_domain_a]
        await revert_domain_to(apikey_client, mgmt_name, base_a)
        await eng1_client.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            types=["host"],
            mode="force",
        )


async def test_discard_isolated_between_users(
    admin_client: ArodonataClient,
    eng2_client: ArodonataClient,
    mgmt_name: str,
    test_domain_b: str,
) -> None:
    """Verify eng2's uncommitted pending host is invisible to admin and vanishes on discard."""
    host_name = _unique("it-b5-disc")

    sid, server_ip = await eng2_client.create_dedicated_session(
        mgmt_name,
        test_domain_b,
        session_name=f"b5-disc-{host_name[-6:]}",
    )
    try:
        r = await eng2_client.api_call(
            mgmt_name,
            "add-host",
            {"name": host_name, "ipv4-address": "198.51.100.222"},
            domain=test_domain_b,
            sid=sid,
            server_ip=server_ip,
        )
        assert r.success

        assert not await _server_has_host(admin_client, mgmt_name, test_domain_b, host_name)

        d_res = await eng2_client.api_call(
            mgmt_name,
            "discard",
            {},
            domain=test_domain_b,
            sid=sid,
            server_ip=server_ip,
        )
        assert d_res.success
    finally:
        await eng2_client.logout_sid(mgmt_name, sid, server_ip=server_ip)

    assert not await _server_has_host(admin_client, mgmt_name, test_domain_b, host_name)


async def test_two_domain_publish_and_revert(
    admin_client: ArodonataClient,
    eng1_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    test_domain_b: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify admin publishing in A and eng1 publishing in B both land and revert cleanly."""
    host_a = _unique("it-b5-doma")
    host_b = _unique("it-b5-domb")

    try:
        async with admin_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"b5-doma-{host_a[-6:]}",
            publish_on_exit=True,
        ):
            r_a = await admin_client.add_object(
                mgmt_name,
                "host",
                {"name": host_a, "ipv4-address": "198.51.100.223"},
                domain=test_domain_a,
            )
            assert r_a.success

        async with eng1_client.write_session(
            mgmt_name,
            test_domain_b,
            session_name=f"b5-domb-{host_b[-6:]}",
            publish_on_exit=True,
        ):
            r_b = await eng1_client.add_object(
                mgmt_name,
                "host",
                {"name": host_b, "ipv4-address": "198.51.100.224"},
                domain=test_domain_b,
            )
            assert r_b.success

        assert await _server_has_host(apikey_client, mgmt_name, test_domain_a, host_a)
        assert await _server_has_host(apikey_client, mgmt_name, test_domain_b, host_b)
    finally:
        await revert_domain_to(apikey_client, mgmt_name, cp_baseline_snapshot.domains[test_domain_b])
        await revert_domain_to(apikey_client, mgmt_name, cp_baseline_snapshot.domains[test_domain_a])

    assert not await _server_has_host(apikey_client, mgmt_name, test_domain_a, host_a)
    assert not await _server_has_host(apikey_client, mgmt_name, test_domain_b, host_b)


async def test_revert_recovers_multiple_objects(
    admin_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify publishing 2 hosts and 1 network in one session is completely undone by revert."""
    h1 = _unique("it-b5-h1")
    h2 = _unique("it-b5-h2")
    net = _unique("it-b5-net")

    try:
        async with admin_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"b5-multi-{h1[-6:]}",
            publish_on_exit=True,
        ):
            assert (
                await admin_client.add_object(
                    mgmt_name,
                    "host",
                    {"name": h1, "ipv4-address": "198.51.100.225"},
                    domain=test_domain_a,
                )
            ).success
            assert (
                await admin_client.add_object(
                    mgmt_name,
                    "host",
                    {"name": h2, "ipv4-address": "198.51.100.226"},
                    domain=test_domain_a,
                )
            ).success
            assert (
                await admin_client.add_object(
                    mgmt_name,
                    "network",
                    {"name": net, "subnet": "198.51.100.0", "mask-length": 24},
                    domain=test_domain_a,
                )
            ).success

        assert await _server_has_host(apikey_client, mgmt_name, test_domain_a, h1)
        assert await _server_has_host(apikey_client, mgmt_name, test_domain_a, h2)
    finally:
        await revert_domain_to(apikey_client, mgmt_name, cp_baseline_snapshot.domains[test_domain_a])

    assert not await _server_has_host(apikey_client, mgmt_name, test_domain_a, h1)
    assert not await _server_has_host(apikey_client, mgmt_name, test_domain_a, h2)

    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host", "network"],
        mode="force",
    )
    remaining = await apikey_client.get_objects(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        names=[h1, h2, net],
        cache_mode="cache",
    )
    assert remaining == []
