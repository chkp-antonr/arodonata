"""Full tier: every cache mode exercised live, plus smart-fast fallback triggers.

Only test_smart_fast_falls_back_on_too_many_changes mutates CP (one
publish/revert cycle); everything else manipulates the local cache.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata.cache.models import CPObject
from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import CachePolicy, RefreshScope
from arodonata.core.cache_refresh_coordinator import CacheRefreshCoordinator
from arodonata.utils.helpers import utc_now_naive

from ..cp_revision import discard_open_sessions, last_published_session


def _phantom_host(mgmt_name: str, domain: str) -> CPObject:
    """A host that exists only in the local cache, never on the server."""
    uid = f"phantom-{uuid.uuid4().hex}"
    return CPObject(
        id=f"{mgmt_name}:{domain}:{uid}",
        uid=uid,
        name=f"arodonata-phantom-{uid[:8]}",
        type="host",
        mgmt_name=mgmt_name,
        domain_name=domain,
        ipv4_address="10.255.250.1",
        update_time=utc_now_naive(),
    )


async def _force_build(client, mgmt_name: str, domain: str) -> None:
    async for _ in client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[domain], mode="force"):
        pass


async def test_cache_mode_serves_cache_without_refresh(apikey_client, test_domain_a):
    """cache mode returns whatever the cache holds — even objects the server
    has never seen — proving no refresh/staleness check runs."""
    client, mgmt_name = apikey_client

    await _force_build(client, mgmt_name, test_domain_a)
    phantom = _phantom_host(mgmt_name, test_domain_a)
    await client.cache.upsert_objects([phantom])

    hosts = await client.get_hosts(
        name_filter=phantom.name,
        mgmt_names=[mgmt_name],
        domain_names=[test_domain_a],
        cache_mode="cache",
    )
    assert any(h.uid == phantom.uid for h in hosts), "cache mode must serve the phantom straight from the cache"


async def test_smart_fresh_serves_cache_via_uid_match(apikey_client, test_domain_a):
    """smart with ttl=0 re-checks staleness; a matching session uid means
    fresh, so nothing is reloaded (the phantom survives)."""
    client, mgmt_name = apikey_client

    await _force_build(client, mgmt_name, test_domain_a)
    phantom = _phantom_host(mgmt_name, test_domain_a)
    await client.cache.upsert_objects([phantom])

    coordinator = client._orchestration._coordinator
    outcome = await coordinator.ensure(
        RefreshScope(mgmt_names=[mgmt_name], domain_names=[test_domain_a]),
        CachePolicy(mode=CacheMode.SMART, ttl=0),
    )
    assert outcome.refreshed_domains == [], f"Fresh domain must not reload (got {outcome})"

    hosts = await client.get_hosts(
        name_filter=phantom.name,
        mgmt_names=[mgmt_name],
        domain_names=[test_domain_a],
        cache_mode="cache",
    )
    assert hosts, "No reload happened, so the phantom must survive"


async def test_smart_ttl_memo_skips_staleness_check(apikey_client, test_domain_a):
    """Within the TTL, smart serves the cache without even re-checking
    staleness (second ensure returns immediately with no refresh)."""
    client, mgmt_name = apikey_client

    await _force_build(client, mgmt_name, test_domain_a)
    coordinator = client._orchestration._coordinator

    first = await coordinator.ensure(
        RefreshScope(mgmt_names=[mgmt_name], domain_names=[test_domain_a]),
        CachePolicy(mode=CacheMode.SMART, ttl=300),
    )
    second = await coordinator.ensure(
        RefreshScope(mgmt_names=[mgmt_name], domain_names=[test_domain_a]),
        CachePolicy(mode=CacheMode.SMART, ttl=300),
    )
    assert first.refreshed_domains == []
    assert second.refreshed_domains == []
    assert second.fell_back is False


async def test_force_rebuilds_even_when_fresh(apikey_client, test_domain_a):
    """force rebuilds unconditionally — the phantom is wiped every time."""
    client, mgmt_name = apikey_client

    await _force_build(client, mgmt_name, test_domain_a)
    phantom = _phantom_host(mgmt_name, test_domain_a)
    await client.cache.upsert_objects([phantom])

    coordinator = client._orchestration._coordinator
    outcome = await coordinator.ensure(
        RefreshScope(mgmt_names=[mgmt_name], domain_names=[test_domain_a]),
        CachePolicy(mode=CacheMode.FORCE, ttl=None),
    )
    assert outcome.refreshed_domains == [(mgmt_name, test_domain_a)]

    hosts = await client.get_hosts(
        name_filter=phantom.name,
        mgmt_names=[mgmt_name],
        domain_names=[test_domain_a],
        cache_mode="cache",
    )
    assert not hosts, "force rebuild must remove cache-only phantoms"


async def test_smart_fast_falls_back_without_baseline(db_engine, test_domain_a):
    """smart-fast with objects present but no baseline row falls back to a
    full reload (live no-baseline trigger)."""
    import os

    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    from arodonata import ArodonataClient, ArodonataSettings

    mgmt_ip = os.environ.get("API_MGMT")
    api_key = os.environ.get("APIKEY")
    if not mgmt_ip or not api_key:
        pytest.skip("API_MGMT or APIKEY not set")

    # Fresh in-memory engine: cache has objects (seeded) but NO baseline row.
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    settings = ArodonataSettings(mgmt_names=mgmt_ip, mgmt_servers=mgmt_ip, api_keys=api_key)
    try:
        async with ArodonataClient(engine=engine, settings=settings) as client:
            if client._login_coordinator:
                client._login_coordinator._session_cleaner = None
            await client.cache.upsert_objects([_phantom_host(mgmt_ip, test_domain_a)])

            coordinator = client._orchestration._coordinator
            outcome = await coordinator.ensure(
                RefreshScope(mgmt_names=[mgmt_ip], domain_names=[test_domain_a]),
                CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
            )
            assert outcome.fell_back is True
            assert outcome.refreshed_domains == [(mgmt_ip, test_domain_a)]
    finally:
        await engine.dispose()


@pytest.mark.cp_mutates
async def test_smart_fast_falls_back_on_too_many_changes(admin_client, test_domain_a):
    """A diff larger than max_incremental_changes falls back to full reload
    (live trigger via a private coordinator with the limit set to zero)."""
    client, mgmt_name = admin_client

    pre = await last_published_session(client, mgmt_name, test_domain_a)
    assert pre["uid"], "need a revision to revert to"
    await _force_build(client, mgmt_name, test_domain_a)

    # Publish one real host so the diff is non-empty.
    suffix = uuid.uuid4().hex[:8]
    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, test_domain_a, session_name="arodonata-full-toomany"
    )
    try:
        r = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="add-host",
            payload={"name": f"arodonata-test-{suffix}", "ip-address": "10.255.252.9"},
        )
        assert r.success, r.message
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
        base = client._orchestration._coordinator
        strict = CacheRefreshCoordinator(cache=base._cache, api=base._api, object_service=base._object_service)
        strict.max_incremental_changes = 0

        outcome = await strict.ensure(
            RefreshScope(mgmt_names=[mgmt_name], domain_names=[test_domain_a]),
            CachePolicy(mode=CacheMode.SMART_FAST, ttl=0),
        )
        assert outcome.fell_back is True, f"1 change > limit 0 must fall back, got {outcome}"
    finally:
        await discard_open_sessions(client, mgmt_name, test_domain_a)
        r = await client.api_call(
            mgmt_name,
            "revert-to-revision",
            test_domain_a,
            payload={"to-session": pre["uid"]},
            wait_for_task=True,
        )
        assert r.success, f"revert failed: {r.message}"


@pytest.mark.cp_mutates
async def test_bulk_incremental_mode_applies_publish_without_full_reload(admin_client, test_domain_a):
    """After a small publish, mode="incremental" applies the change and
    writes the new host to the cache without triggering a full domain
    reload. Lab-only: requires the FPCR environment."""
    client, mgmt_name = admin_client

    pre = await last_published_session(client, mgmt_name, test_domain_a)
    assert pre["uid"], "need a revision to revert to"

    # 1. Baseline: force-refresh the domain so a last_published_sessions
    # stamp exists for the incremental staleness probe.
    await _force_build(client, mgmt_name, test_domain_a)

    # 2. Make a small change in the lab (create+publish one host).
    suffix = uuid.uuid4().hex[:8]
    host_name = f"arodonata-test-{suffix}"
    sid, server_ip = await client.create_dedicated_session(
        mgmt_name, test_domain_a, session_name="arodonata-incremental-matrix"
    )
    try:
        r = await client.api_call_with_sid(
            mgmt_name=mgmt_name,
            sid=sid,
            server_ip=server_ip,
            command="add-host",
            payload={"name": host_name, "ip-address": "10.255.252.10"},
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

    try:
        # 3. Incremental refresh must apply it without a full reload event.
        events = []
        async for e in client.refresh_objects(mgmt_names=[mgmt_name], domain_names=[test_domain_a], mode="incremental"):
            events.append(e)
        statuses = [e.data.get("status") for e in events if e.data]
        assert "domain_incremental" in statuses, f"expected an incremental apply, got statuses={statuses}"
        assert "refreshing_domain" not in statuses, f"must not fall back to a full reload, got statuses={statuses}"

        hosts = await client.get_hosts(
            name_filter=host_name,
            mgmt_names=[mgmt_name],
            domain_names=[test_domain_a],
            cache_mode="cache",
        )
        assert hosts, "incremental refresh must apply the newly published host to the cache"
    finally:
        await discard_open_sessions(client, mgmt_name, test_domain_a)
        r = await client.api_call(
            mgmt_name,
            "revert-to-revision",
            test_domain_a,
            payload={"to-session": pre["uid"]},
            wait_for_task=True,
        )
        assert r.success, f"revert failed: {r.message}"
