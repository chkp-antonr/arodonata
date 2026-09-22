"""Full tier: MDM multi-domain isolation between TEST_DOMAIN_A and TEST_DOMAIN_B."""

from __future__ import annotations

import asyncio
import uuid

import pytest

from ..cp_revision import last_published_session, revert_domain_to


async def _force_build(client, mgmt_name: str, domain: str) -> None:
    async for _ in client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[domain], mode="force"):
        pass


async def _publish_host(client, mgmt_name: str, domain: str, name: str, ip: str) -> None:
    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, domain, session_name=f"arodonata-full-{name[-8:]}"
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


@pytest.mark.cp_mutates
async def test_publish_in_a_invisible_in_b(admin_client, test_domain_a, test_domain_b):
    """A publish in domain A must not leak into domain B's cache or trigger
    a B refresh."""
    client, mgmt_name = admin_client
    host_name = f"arodonata-test-{uuid.uuid4().hex[:8]}"

    pre_a = await last_published_session(client, mgmt_name, test_domain_a)
    assert pre_a["uid"]
    pre_b_uid = (await last_published_session(client, mgmt_name, test_domain_b))["uid"]

    await _force_build(client, mgmt_name, test_domain_a)
    await _force_build(client, mgmt_name, test_domain_b)

    await _publish_host(client, mgmt_name, test_domain_a, host_name, "10.255.251.7")
    try:
        # B stays fresh: smart-fast on B refreshes nothing.
        from arodonata.core.cache_mode import CacheMode
        from arodonata.core.cache_policy import CachePolicy, RefreshScope

        coordinator = client._orchestration._coordinator
        outcome_b = await coordinator.ensure(
            RefreshScope(mgmt_names=[mgmt_name], domain_names=[test_domain_b]),
            CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
        )
        assert outcome_b.refreshed_domains == [], f"B must be untouched by A's publish: {outcome_b}"

        # A sees the host; B never does.
        hosts_a = await client.get_hosts(
            name_filter=host_name,
            mgmt_names=[mgmt_name],
            domain_names=[test_domain_a],
            cache_mode="smart-fast",
            cache_ttl=0,
        )
        assert hosts_a, "A must see its own published host"
        hosts_b = await client.get_hosts(
            name_filter=host_name,
            mgmt_names=[mgmt_name],
            domain_names=[test_domain_b],
            cache_mode="cache",
        )
        assert not hosts_b, "B's cache must not contain A's host"

        # B's server-side revision is unchanged.
        post_b_uid = (await last_published_session(client, mgmt_name, test_domain_b))["uid"]
        assert post_b_uid == pre_b_uid
    finally:
        await revert_domain_to(client, mgmt_name, test_domain_a, pre_a["uid"])


async def test_concurrent_refresh_of_two_domains(apikey_client, test_domain_a, test_domain_b):
    """Force refreshes of A and B (distinct domain servers) run concurrently."""
    client, mgmt_name = apikey_client

    async def build(domain: str) -> str:
        await _force_build(client, mgmt_name, domain)
        return domain

    done = await asyncio.gather(
        asyncio.wait_for(build(test_domain_a), timeout=900),
        asyncio.wait_for(build(test_domain_b), timeout=900),
    )
    assert sorted(done) == sorted([test_domain_a, test_domain_b])


async def test_domain_scoped_reads_do_not_leak(apikey_client, test_domain_a, test_domain_b):
    """Domain-scoped reads return only that domain's rows."""
    client, mgmt_name = apikey_client

    await _force_build(client, mgmt_name, test_domain_a)
    await _force_build(client, mgmt_name, test_domain_b)

    for domain in (test_domain_a, test_domain_b):
        objects = await client.cache.get_objects(mgmt_names=[mgmt_name], domain_names=[domain])
        assert objects, f"{domain} cache must not be empty after build"
        wrong = [o for o in objects if o.domain_name != domain]
        assert not wrong, f"Domain-scoped read for {domain} leaked: {wrong[:3]}"


async def test_global_domain_resolves_active_mds_and_creates_dedicated_session(apikey_client):
    """Global domain must resolve to its active MDS member and allow creating a dedicated session."""
    from arodonata import GLOBAL_DOMAIN_NAME

    client, mgmt_name = apikey_client

    # 1. Verify show-global-domain on the real MDM
    resp = await client.api_call(
        mgmt_name, "show-global-domain", payload={"name": GLOBAL_DOMAIN_NAME, "details-level": "full"}
    )
    if not resp.success:
        pytest.skip(f"show-global-domain not supported or refused on {mgmt_name}: {resp.message}")

    # 2. Populate domain cache (tests DomainService resolution of Global)
    domain_names = await client.populate_domain_cache(mgmt_name, include_global=True)
    assert GLOBAL_DOMAIN_NAME in domain_names

    cached = await client.cache.get_domain(f"{mgmt_name}:{GLOBAL_DOMAIN_NAME}")
    assert cached is not None
    assert cached.active_ip, "Global domain must have a non-empty active_ip"

    # 3. Create a dedicated session on Global (used for read-write operations)
    session_name = f"arodonata-global-{uuid.uuid4().hex[:8]}"
    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, GLOBAL_DOMAIN_NAME, session_name=session_name
    )
    try:
        assert sid, "Must receive a valid session ID"
        assert server_ip == cached.active_ip, "Dedicated session IP must match the resolved active_ip"

        # 4. Verify session is active on the server
        check = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="show-session",
            payload={"uid": sid},
        )
        assert check.success, f"show-session failed on {server_ip}: {check.message}"
    finally:
        await client.logout_sid(sid, server_ip, mgmt_name)

