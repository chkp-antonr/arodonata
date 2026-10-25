"""Bucket 3 — Publish, discard, ``SessionOverlay`` read-your-own-writes, ``smart-fast``, and revert.

Covers:
1. ``write_session`` with ``SessionOverlay``: adding a host inside ``write_session`` makes it
   immediately visible to ``get_hosts`` and ``find_object`` inside the context BEFORE ``publish``,
   while external readers still see only committed cache state.
2. Exception inside ``write_session`` automatically executes ``discard`` and clears the overlay.
3. Clean exit from ``write_session(publish_on_exit=True)`` publishes the session, invalidates
   the domain freshness memo, and ``get_hosts(cache_mode="smart-fast")`` picks up the newly
   published host incrementally via ``show-changes``.
4. ``revert_domain_to`` restores ``TEST_DOMAIN_A`` back to its baseline session UID and
   removes the published host on the server.
"""

from __future__ import annotations

import uuid

import pytest

from arodonata import ArodonataClient
from tests.integration.cp_revision import BaselineSnapshot, revert_domain_to

pytestmark = pytest.mark.cp_mutates


async def test_write_session_overlay_discard_on_exception(
    antonr_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``SessionOverlay`` read-your-own-writes and automatic ``discard`` on exception."""
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="smart",
    )

    tag = uuid.uuid4().hex[:6]
    temp_host = f"it-b3-discard-{tag}"

    with pytest.raises(RuntimeError, match="abort-before-publish"):
        async with antonr_client.write_session(
            mgmt_name,
            test_domain_a,
            session_name=f"b3-discard-{tag}",
            publish_on_exit=True,
        ) as ws:
            res = await antonr_client.add_object(
                mgmt_name,
                "host",
                {"name": temp_host, "ipv4-address": "198.51.100.210"},
                domain=test_domain_a,
            )
            assert res.success

            # Inside the WriteSession, SessionOverlay makes the uncommitted host visible
            found_inside = await antonr_client.find_object(
                mgmt_name,
                test_domain_a,
                temp_host,
                obj_type="host",
                cache_mode="cache",
            )
            assert found_inside is not None
            assert found_inside.name == temp_host

            # Raw SQLite cache (and live server outside the WriteSession) still does NOT contain the uncommitted host
            cached_outside = await apikey_client.cache.get_objects(
                mgmt_name=mgmt_name,
                domain_name=test_domain_a,
                types=["host"],
                names=[temp_host],
            )
            assert cached_outside == []

            raise RuntimeError("abort-before-publish")

    assert ws.discarded is True
    assert not ws.published

    # Verify the discarded host does not exist on the server
    show_res = await apikey_client.api_call(
        mgmt_name,
        "show-host",
        {"name": temp_host},
        domain=test_domain_a,
    )
    assert not show_res.success


async def test_publish_smart_fast_pickup_and_revert_to_baseline(
    antonr_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify publish -> ``smart-fast`` incremental pickup -> ``revert_domain_to`` baseline."""
    # Ensure host cache is synced at the baseline revision
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )

    tag = uuid.uuid4().hex[:6]
    pub_host = f"it-b3-pub-{tag}"

    # 1. Create and publish a host via write_session
    async with antonr_client.write_session(
        mgmt_name,
        test_domain_a,
        session_name=f"b3-pub-{tag}",
        publish_on_exit=True,
    ) as ws:
        add_res = await antonr_client.add_object(
            mgmt_name,
            "host",
            {"name": pub_host, "ipv4-address": "198.51.100.211", "comments": "B3 publish test"},
            domain=test_domain_a,
        )
        assert add_res.success
    assert ws.published is True

    # 2. Invalidate apikey_client's in-memory memo and run smart-fast incremental refresh
    apikey_client.invalidate_domain(mgmt_name, test_domain_a)
    hosts_after = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        names=[pub_host],
        cache_mode="smart-fast",
    )
    assert len(hosts_after) == 1
    assert hosts_after[0].name == pub_host
    assert hosts_after[0].ipv4_address == "198.51.100.211"

    # 3. Revert domain back to baseline revision
    base = cp_baseline_snapshot.domains[test_domain_a]
    reverted = await revert_domain_to(apikey_client, mgmt_name, base)
    assert reverted is True

    # 4. Force-refresh cache after revert and verify host is gone
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    hosts_reverted = await apikey_client.get_hosts(
        mgmt_name=mgmt_name,
        domain=test_domain_a,
        names=[pub_host],
        cache_mode="cache",
    )
    assert hosts_reverted == []
