"""Bucket 4 — Cache mode matrix (`cache`, `smart`, `smart-fast`, `force`) and fallback triggers.

Covers:
1. ``cache`` mode serves cached objects directly without any server probe (phantom host survives).
2. ``smart`` mode with ``cache_ttl=0`` probes ``show-last-published-session``; when the published
   session UID matches, the domain is skipped and the phantom host survives.
3. ``smart`` mode within ``cache_ttl`` skips the server probe via TTL memo.
4. ``force`` mode rebuilds unconditionally and removes cache-only phantom hosts.
5. ``smart-fast`` without a baseline ``DomainSyncState`` falls back automatically to a full reload.
6. ``smart-fast`` when diff count exceeds ``max_incremental_changes`` falls back to a full reload.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.core.models.objects import CPObject
from tests.integration.cp_revision import BaselineSnapshot, revert_domain_to


def _phantom_host(mgmt_name: str, domain: str) -> CPObject:
    """Create a synthetic host that exists only in the local SQLite cache."""
    uid = f"phantom-{uuid.uuid4().hex[:12]}"
    return CPObject(
        id=f"{mgmt_name}:{domain}:{uid}",
        uid=uid,
        name=f"arodonata-phantom-{uid[:8]}",
        type="host",
        mgmt_name=mgmt_name,
        domain_name=domain,
        ipv4_address="198.51.100.250",
    )


async def test_cache_mode_serves_cache_without_refresh(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``cache_mode='cache'`` serves local SQLite rows without server probes."""
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    phantom = _phantom_host(mgmt_name, test_domain_a)
    await apikey_client.cache.upsert_objects([phantom])

    hosts = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        names=[phantom.name],
        cache_mode="cache",
    )
    assert any(h.uid == phantom.uid for h in hosts)


async def test_smart_fresh_serves_cache_via_uid_match(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``mode='smart'`` with ``cache_ttl=0`` skips reload when published UID matches."""
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    phantom = _phantom_host(mgmt_name, test_domain_a)
    await apikey_client.cache.upsert_objects([phantom])

    outcome = await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="smart",
        cache_ttl=0.0,
    )
    dom_label = f"{mgmt_name}:{test_domain_a}"
    assert dom_label in outcome.skipped_domains
    assert dom_label not in outcome.refreshed_domains

    hosts = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        names=[phantom.name],
        cache_mode="cache",
    )
    assert any(h.uid == phantom.uid for h in hosts)


async def test_smart_ttl_memo_skips_staleness_check(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``mode='smart'`` within ``cache_ttl`` skips the domain without reloading."""
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    first = await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="smart",
        cache_ttl=300.0,
    )
    second = await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="smart",
        cache_ttl=300.0,
    )
    dom_label = f"{mgmt_name}:{test_domain_a}"
    assert dom_label in first.skipped_domains
    assert dom_label in second.skipped_domains


async def test_force_rebuilds_even_when_fresh(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``mode='force'`` rebuilds unconditionally and removes cache-only phantom hosts."""
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    phantom = _phantom_host(mgmt_name, test_domain_a)
    await apikey_client.cache.upsert_objects([phantom])

    outcome = await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    assert f"{mgmt_name}:{test_domain_a}" in outcome.refreshed_domains

    hosts = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        names=[phantom.name],
        cache_mode="cache",
    )
    assert not hosts


async def test_smart_fast_falls_back_without_baseline(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``mode='smart-fast'`` falls back to full reload when no baseline sync state exists."""
    # Isolated in-memory client with a phantom host but no domain_sync_state row
    settings = ArodonataSettings(
        mgmt_names=apikey_client.settings.mgmt_names,
        mgmt_servers=apikey_client.settings.mgmt_servers,
        api_keys=apikey_client.settings.api_keys,
        tls_trust=apikey_client.settings.tls_trust,
        tls_fingerprints=apikey_client.settings.tls_fingerprints,
    )
    async with ArodonataClient(settings=settings) as isolated_client:
        phantom = _phantom_host(mgmt_name, test_domain_a)
        await isolated_client.cache.upsert_objects([phantom])

        outcome = await isolated_client.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            types=["host"],
            mode="smart-fast",
            cache_ttl=0.0,
        )
        assert f"{mgmt_name}:{test_domain_a}" in outcome.refreshed_domains
        # Full reload wiped the phantom host
        hosts = await isolated_client.get_hosts(
            mgmt_name=mgmt_name,
            domain=test_domain_a,
            names=[phantom.name],
            cache_mode="cache",
        )
        assert not hosts


@pytest.mark.cp_mutates
async def test_smart_fast_falls_back_on_too_many_changes(
    antonr_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify ``smart-fast`` falls back to full reload when diff exceeds ``max_incremental_changes``."""
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    phantom = _phantom_host(mgmt_name, test_domain_a)
    await apikey_client.cache.upsert_objects([phantom])

    tag = uuid.uuid4().hex[:6]
    pub_host = f"it-b4-toomany-{tag}"

    try:
        async with antonr_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"b4-toomany-{tag}",
            publish_on_exit=True,
        ):
            res = await antonr_client.add_object(
                mgmt_name,
                "host",
                {"name": pub_host, "ipv4-address": "198.51.100.215"},
                domain=test_domain_a,
            )
            assert res.success

        # Temporarily set max_incremental_changes = 0 so 1 change triggers full reload fallback
        orig_max = apikey_client.settings.max_incremental_changes
        apikey_client.settings.max_incremental_changes = 0
        try:
            events = [
                ev
                async for ev in apikey_client.stream_refresh_objects(
                    mgmt_name=mgmt_name,
                    domains=[test_domain_a],
                    types=["host"],
                    mode="smart-fast",
                    cache_ttl=0.0,
                )
            ]
        finally:
            apikey_client.settings.max_incremental_changes = orig_max

        assert any("exceeds max_incremental_changes" in e.message for e in events)
        # Because full reload ran, the phantom host was wiped while pub_host was fetched
        phantom_check = await apikey_client.get_hosts(
            mgmt_name=mgmt_name,
            domain=test_domain_a,
            names=[phantom.name],
            cache_mode="cache",
        )
        assert not phantom_check

        real_check = await apikey_client.get_hosts(
            mgmt_name=mgmt_name,
            domain=test_domain_a,
            names=[pub_host],
            cache_mode="cache",
        )
        assert len(real_check) == 1
    finally:
        base = cp_baseline_snapshot.domains[test_domain_a]
        await revert_domain_to(apikey_client, mgmt_name, base)
        await apikey_client.refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            types=["host"],
            mode="force",
        )
