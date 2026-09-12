"""Full tier: publish/discard/revert matrix across users and domains.

All mutating (cp_mutates); every test reverts the domains it touched to
their captured pre-test revisions.
"""

from __future__ import annotations

import uuid

import pytest

from ..cp_revision import discard_open_sessions, last_published_session

pytestmark = pytest.mark.cp_mutates


def _unique(prefix: str = "arodonata-test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _publish_host(client, mgmt_name: str, domain: str, name: str, ip: str) -> None:
    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, domain, session_name=f"arodonata-matrix-{name[-8:]}"
    )
    try:
        r = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="add-host",
            payload={"name": name, "ip-address": ip},
        )
        assert r.success, f"add-host failed: {r.message}"
        r = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="publish",
            wait_for_task=True,
        )
        assert r.success, f"publish failed: {r.message}"
    finally:
        await client.logout_sid(sid, server_ip, mgmt_name)


async def _revert(client, mgmt_name: str, domain: str, target_uid: str) -> None:
    await discard_open_sessions(client, mgmt_name, domain)
    r = await client.api_call(
        mgmt_name,
        "revert-to-revision",
        domain,
        payload={"to-session": target_uid},
        wait_for_task=True,
    )
    assert r.success, f"revert failed: {r.message}"


async def _visible(client, mgmt_name: str, domain: str, name: str) -> bool:
    r = await client.api_call(mgmt_name, "show-host", domain, payload={"name": name})
    return bool(r.success)


async def test_publish_visible_to_other_user(admin_client, eng1_client, test_domain_a):
    """A host admin publishes in A is visible to eng1 — via eng1's own login
    and via eng1's smart-fast cache read."""
    a_client, mgmt_name = admin_client
    e_client, _ = eng1_client
    host_name = _unique()

    pre = await last_published_session(a_client, mgmt_name, test_domain_a)
    assert pre["uid"]

    # eng1 baselines its cache BEFORE the publish.
    async for _ in e_client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"):
        pass

    await _publish_host(a_client, mgmt_name, test_domain_a, host_name, "10.255.249.3")
    try:
        assert await _visible(e_client, mgmt_name, test_domain_a, host_name), (
            "eng1 must see admin's published host via the API"
        )
        hosts = await e_client.get_hosts(
            name_filter=host_name,
            mgmt_names=[mgmt_name],
            domain_names=[test_domain_a],
            cache_mode="smart-fast",
            cache_ttl=0,
        )
        assert hosts, "eng1's smart-fast read must pick up admin's publish"
    finally:
        await _revert(a_client, mgmt_name, test_domain_a, pre["uid"])


async def test_discard_isolated_between_users(admin_client, eng2_client, test_domain_b):
    """eng2's unpublished pending host is invisible to admin and vanishes on
    discard."""
    a_client, mgmt_name = admin_client
    e_client, _ = eng2_client
    host_name = _unique()

    sid, server_ip = await e_client.create_dedicated_session(
        mgmt_name, test_domain_b, session_name="arodonata-matrix-pending"
    )
    try:
        r = await e_client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="add-host",
            payload={"name": host_name, "ip-address": "10.255.249.4"},
        )
        assert r.success, r.message

        # Admin (different session) must not see the pending object.
        assert not await _visible(a_client, mgmt_name, test_domain_b, host_name), (
            "Unpublished changes must be session-private"
        )

        r = await e_client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="discard",
        )
        assert r.success, r.message
    finally:
        await e_client.logout_sid(sid, server_ip, mgmt_name)

    assert not await _visible(a_client, mgmt_name, test_domain_b, host_name)


async def test_two_domain_publish_and_revert(admin_client, eng1_client, test_domain_a, test_domain_b):
    """admin publishes in A while eng1 publishes in B; both land; both revert."""
    a_client, mgmt_name = admin_client
    e_client, _ = eng1_client
    host_a = _unique()
    host_b = _unique()

    pre_a = await last_published_session(a_client, mgmt_name, test_domain_a)
    pre_b = await last_published_session(a_client, mgmt_name, test_domain_b)
    assert pre_a["uid"] and pre_b["uid"]

    await _publish_host(a_client, mgmt_name, test_domain_a, host_a, "10.255.249.5")
    try:
        await _publish_host(e_client, mgmt_name, test_domain_b, host_b, "10.255.249.6")
        try:
            assert await _visible(a_client, mgmt_name, test_domain_a, host_a)
            assert await _visible(a_client, mgmt_name, test_domain_b, host_b)
        finally:
            await _revert(a_client, mgmt_name, test_domain_b, pre_b["uid"])
    finally:
        await _revert(a_client, mgmt_name, test_domain_a, pre_a["uid"])

    assert not await _visible(a_client, mgmt_name, test_domain_a, host_a)
    assert not await _visible(a_client, mgmt_name, test_domain_b, host_b)


async def test_revert_recovers_multiple_objects(admin_client, test_domain_a):
    """One session publishes 2 hosts + 1 network; a single revert removes all
    three from the server and (after rebuild) from the cache."""
    client, mgmt_name = admin_client
    h1, h2, net = _unique(), _unique(), _unique("arodonata-net")

    pre = await last_published_session(client, mgmt_name, test_domain_a)
    assert pre["uid"]

    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, test_domain_a, session_name="arodonata-matrix-multi"
    )
    try:
        for command, payload in [
            ("add-host", {"name": h1, "ip-address": "10.255.249.7"}),
            ("add-host", {"name": h2, "ip-address": "10.255.249.8"}),
            ("add-network", {"name": net, "subnet": "10.255.248.0", "mask-length": 24}),
        ]:
            r = await client.api_call_with_sid(
                mgmt_name=mgmt_name,
                sid=sid,
                server_ip=server_ip,
                command=command,
                payload=payload,
            )
            assert r.success, f"{command} failed: {r.message}"
        r = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="publish",
            wait_for_task=True,
        )
        assert r.success, r.message
    finally:
        await client.logout_sid(sid, server_ip, mgmt_name)

    try:
        assert await _visible(client, mgmt_name, test_domain_a, h1)
        assert await _visible(client, mgmt_name, test_domain_a, h2)
    finally:
        await _revert(client, mgmt_name, test_domain_a, pre["uid"])

    for name in (h1, h2):
        assert not await _visible(client, mgmt_name, test_domain_a, name)

    async for _ in client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="force"):
        pass
    # Check exactly this test's objects (wildcards would catch stale cache
    # rows left by other tests' clients sharing the session DB).
    leftovers = []
    for name in (h1, h2, net):
        leftovers += await client.cache.get_objects(
            mgmt_names=[mgmt_name],
            domain_names=[test_domain_a],
            filters={"name": name},
        )
    assert not leftovers, f"Reverted objects survived the rebuild: {[o.name for o in leftovers]}"
