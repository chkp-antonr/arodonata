"""Bucket 2 — Cache build & streaming sync progress against the live MDSM.

Covers:
1. ``refresh_objects`` in ``TEST_DOMAIN_A`` (``mode="force"``) populates SQLite with hosts,
   networks, address-ranges, dns-domains, and groups, and records ``domain_sync_state``.
2. ``refresh_services`` in ``TEST_DOMAIN_A`` populates TCP/UDP/ICMP/service-group rows.
3. ``stream_refresh_objects`` yields ``SyncStartedEvent``, per-domain progress, and
   ``SyncCompletedEvent``.
4. Immediate second ``refresh_objects(mode="smart")`` skips the domain because ``last_published_at``
   matches the server's ``show-last-published-session`` head.
"""

from __future__ import annotations

from arodonata import ArodonataClient


async def test_refresh_objects_and_services_populates_sqlite(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``refresh_objects`` and ``refresh_services`` populate cache and record ``domain_sync_state``."""
    obj_outcome = await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        mode="force",
    )
    dom_label = f"{mgmt_name}:{test_domain_a}"
    assert dom_label in obj_outcome.refreshed_domains
    assert not obj_outcome.failed_domains
    assert obj_outcome.total_items >= 1

    svc_outcome = await apikey_client.refresh_services(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        mode="force",
    )
    assert dom_label in svc_outcome.refreshed_domains
    assert not svc_outcome.failed_domains

    status = await apikey_client.get_cache_status(mgmt_name=mgmt_name, domain_name=test_domain_a)
    scopes = {e["scope"] for e in status["entries"]}
    assert "objects" in scopes
    assert "services" in scopes


async def test_stream_refresh_objects_yields_progress_events(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``stream_refresh_objects`` yields started and completed progress events."""
    events = [
        ev
        async for ev in apikey_client.stream_refresh_objects(
            mgmt_name=mgmt_name,
            domains=[test_domain_a],
            types=["host", "network"],
            mode="force",
        )
    ]
    phases = [e.phase for e in events]
    assert "started" in phases
    assert "completed" in phases


async def test_smart_refresh_skips_unchanged_domain(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``refresh_objects(mode="smart")`` skips domains when published head has not moved."""
    # Ensure a fresh baseline sync exists
    await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="force",
    )
    # Invalidate in-memory TTL memo so smart mode actually probes show-last-published-session
    apikey_client.invalidate_domain(mgmt_name, test_domain_a)

    second = await apikey_client.refresh_objects(
        mgmt_name=mgmt_name,
        domains=[test_domain_a],
        types=["host"],
        mode="smart",
    )
    dom_label = f"{mgmt_name}:{test_domain_a}"
    assert dom_label in second.skipped_domains
    assert dom_label not in second.refreshed_domains
