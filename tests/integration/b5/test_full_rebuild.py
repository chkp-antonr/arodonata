"""Full tier: whole-server rebuilds — objects, assets (with relationship
phases and distributed-lock renewal), and rulebases across all domains.

Non-mutating: only the local cache is rewritten.
"""

from __future__ import annotations

import pytest

from arodonata.api.schemas import SSEEventType

from ..cp_revision import last_published_session


async def test_refresh_objects_all_domains(apikey_client, all_domains):
    """An unfiltered object refresh covers every discovered domain."""
    client, mgmt_name = apikey_client

    events = [e async for e in client.refresh_objects(mgmt_names=[mgmt_name], mode="force")]
    assert events[-1].event_type == SSEEventType.COMPLETE, events[-1].message

    for d in all_domains:
        objects = await client.cache.get_objects(mgmt_names=[mgmt_name], domain_names=[d["name"]])
        assert objects, f"Domain {d['name']} must have cached objects"
        # A baseline row exists only for domains that have ever been
        # published (never-published domains have no last-published session).
        server_lps = await last_published_session(client, mgmt_name, d["name"])
        if server_lps["uid"]:
            cached_lps = await client.cache.get_last_published_session(mgmt_name, d["name"])
            assert cached_lps is not None, f"Published domain {d['name']} must have a baseline row"


async def test_build_refresh_assets_cache_full(apikey_client):
    """The full asset pipeline (delete-first, per-domain collection with lock
    renewal, cluster/VSX relationship phases) completes with stats."""
    client, mgmt_name = apikey_client

    events = [e async for e in client.build_refresh_assets_cache()]

    errors = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert not errors, f"Asset build errors: {[e.message for e in errors]}"
    complete = [e for e in events if e.event_type == SSEEventType.COMPLETE]
    assert complete, "Asset build must emit COMPLETE"
    stats = complete[-1].data or {}
    assert stats, "COMPLETE event must carry the stats payload"

    gateways = await client.get_gateways()
    if not gateways:
        pytest.skip("Lab has no gateway assets to assert on")
    gw = gateways[0]
    assert gw.uid and gw.name


async def test_cluster_members_have_parent_asset_ids(apikey_client):
    """Cluster member assets point at their cluster via parent_asset_id
    (skip-tolerant: only asserts when the lab actually has clusters)."""
    client, mgmt_name = apikey_client

    # Ensure the asset cache is built (independent of test order).
    async for _ in client.build_refresh_assets_cache():
        pass

    assets = await client.cache.get_assets()
    assert assets, "Asset cache must not be empty after a full build"

    clusters = [
        a
        for a in assets
        if "cluster" in str(getattr(a, "asset_type", "")).lower()
        or "cluster" in str((a.raw_data or {}).get("type", "")).lower()
    ]
    if not clusters:
        pytest.skip("Lab has no cluster assets")

    with_parent = [a for a in assets if getattr(a, "parent_asset_id", None)]
    assert with_parent, "Lab has clusters, so some assets must carry parent_asset_id after a full build"


async def test_rulebase_refresh_all_domains(apikey_client, all_domains):
    """Rulebase refresh without a domain filter covers every domain that has
    policy packages."""
    client, mgmt_name = apikey_client

    events = [e async for e in client.refresh_rulebases(mgmt_names=[mgmt_name], mode="force")]
    assert events[-1].event_type == SSEEventType.COMPLETE, events[-1].message
    errors = [e for e in events if e.event_type == SSEEventType.ERROR]
    assert not errors, f"Rulebase refresh errors: {[e.message for e in errors]}"

    rules_anywhere = await client.get_access_rules(mgmt_names=[mgmt_name], cache_mode="cache")
    if not rules_anywhere:
        pytest.skip("No domain on this lab has access rules")
    assert rules_anywhere[0].uid
