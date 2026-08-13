"""Unit tests for ClusterRelationshipManager.

Covers building cluster-member-name -> cluster-asset-id mappings from cached
CpmiGatewayCluster assets' raw_data, and applying those mappings as
parent_asset_id updates on cluster-member assets. The ArodonataClient's cache
is mocked; no database is touched.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.api.cluster_relationship_manager import ClusterRelationshipManager
from arodonata.cache.models import Asset


def make_manager(cache=None):
    client = MagicMock()
    client.cache = cache or AsyncMock()
    return ClusterRelationshipManager(client=client), client


def make_asset(*, asset_id, asset_type, name=None, raw_data=None, parent_asset_id=None, mgmt_name="mgmt1"):
    return Asset(
        asset_id=asset_id,
        name=name or asset_id,
        asset_type=asset_type,
        asset_uid=f"uid-{asset_id}",
        mgmt_name=mgmt_name,
        parent_asset_id=parent_asset_id,
        raw_data=raw_data,
    )


# --------------------------------------------------------------------------- #
# build_cluster_member_mappings
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_build_mappings_maps_member_names_to_cluster_asset_id():
    cluster = make_asset(
        asset_id="mgmt1::cluster1",
        asset_type="CpmiGatewayCluster",
        raw_data={"cluster-member-names": ["member1", "member2"]},
    )
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[cluster])
    manager = ClusterRelationshipManager(client=client)

    mapping = await manager.build_cluster_member_mappings("mgmt1")

    assert mapping == {
        "member1": "mgmt1::cluster1",
        "member2": "mgmt1::cluster1",
    }
    client.cache.get_assets.assert_awaited_once_with(mgmt_names=["mgmt1"])


@pytest.mark.asyncio
async def test_build_mappings_ignores_non_cluster_assets():
    non_cluster = make_asset(asset_id="mgmt1::host1", asset_type="host")
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[non_cluster])
    manager = ClusterRelationshipManager(client=client)

    mapping = await manager.build_cluster_member_mappings("mgmt1")

    assert mapping == {}


@pytest.mark.asyncio
async def test_build_mappings_skips_non_dict_raw_data():
    cluster = make_asset(asset_id="mgmt1::cluster1", asset_type="CpmiGatewayCluster", raw_data=None)
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[cluster])
    manager = ClusterRelationshipManager(client=client)

    mapping = await manager.build_cluster_member_mappings("mgmt1")

    assert mapping == {}


@pytest.mark.asyncio
async def test_build_mappings_skips_when_member_names_not_a_list():
    cluster = make_asset(
        asset_id="mgmt1::cluster1",
        asset_type="CpmiGatewayCluster",
        raw_data={"cluster-member-names": "not-a-list"},
    )
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[cluster])
    manager = ClusterRelationshipManager(client=client)

    mapping = await manager.build_cluster_member_mappings("mgmt1")

    assert mapping == {}


@pytest.mark.asyncio
async def test_build_mappings_skips_falsy_member_names():
    cluster = make_asset(
        asset_id="mgmt1::cluster1",
        asset_type="CpmiGatewayCluster",
        raw_data={"cluster-member-names": ["", "member1", None]},
    )
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[cluster])
    manager = ClusterRelationshipManager(client=client)

    mapping = await manager.build_cluster_member_mappings("mgmt1")

    assert mapping == {"member1": "mgmt1::cluster1"}


@pytest.mark.asyncio
async def test_build_mappings_covers_multiple_clusters():
    cluster1 = make_asset(
        asset_id="mgmt1::cluster1",
        asset_type="CpmiGatewayCluster",
        raw_data={"cluster-member-names": ["m1"]},
    )
    cluster2 = make_asset(
        asset_id="mgmt1::cluster2",
        asset_type="CpmiGatewayCluster",
        raw_data={"cluster-member-names": ["m2", "m3"]},
    )
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[cluster1, cluster2])
    manager = ClusterRelationshipManager(client=client)

    mapping = await manager.build_cluster_member_mappings("mgmt1")

    assert mapping == {
        "m1": "mgmt1::cluster1",
        "m2": "mgmt1::cluster2",
        "m3": "mgmt1::cluster2",
    }


@pytest.mark.asyncio
async def test_build_mappings_no_assets_returns_empty_dict():
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[])
    manager = ClusterRelationshipManager(client=client)

    mapping = await manager.build_cluster_member_mappings("mgmt1")

    assert mapping == {}


# --------------------------------------------------------------------------- #
# update_cluster_member_parent_asset_ids
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_update_returns_zero_when_no_cluster_member_assets():
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[make_asset(asset_id="mgmt1::host1", asset_type="host")])
    manager = ClusterRelationshipManager(client=client)

    updated = await manager.update_cluster_member_parent_asset_ids("mgmt1", {"member1": "mgmt1::cluster1"})

    assert updated == 0
    client.cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_sets_parent_asset_id_for_mapped_member():
    member = make_asset(
        asset_id="mgmt1::member1",
        asset_type="cluster-member",
        name="member1",
        parent_asset_id=None,
    )
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[member])
    manager = ClusterRelationshipManager(client=client)

    updated = await manager.update_cluster_member_parent_asset_ids("mgmt1", {"member1": "mgmt1::cluster1"})

    assert updated == 1
    assert member.parent_asset_id == "mgmt1::cluster1"
    client.cache.upsert_assets.assert_awaited_once_with([member])


@pytest.mark.asyncio
async def test_update_skips_member_already_pointing_at_correct_parent():
    member = make_asset(
        asset_id="mgmt1::member1",
        asset_type="cluster-member",
        name="member1",
        parent_asset_id="mgmt1::cluster1",
    )
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[member])
    manager = ClusterRelationshipManager(client=client)

    updated = await manager.update_cluster_member_parent_asset_ids("mgmt1", {"member1": "mgmt1::cluster1"})

    assert updated == 0
    client.cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_skips_member_with_no_mapping_entry():
    member = make_asset(asset_id="mgmt1::member1", asset_type="cluster-member", name="unmapped-member")
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[member])
    manager = ClusterRelationshipManager(client=client)

    updated = await manager.update_cluster_member_parent_asset_ids("mgmt1", {"member1": "mgmt1::cluster1"})

    assert updated == 0
    client.cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_multiple_members_only_bulk_updates_changed_ones():
    updated_member = make_asset(
        asset_id="mgmt1::member1", asset_type="cluster-member", name="member1", parent_asset_id=None
    )
    already_correct = make_asset(
        asset_id="mgmt1::member2",
        asset_type="cluster-member",
        name="member2",
        parent_asset_id="mgmt1::cluster1",
    )
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[updated_member, already_correct])
    manager = ClusterRelationshipManager(client=client)

    updated = await manager.update_cluster_member_parent_asset_ids(
        "mgmt1", {"member1": "mgmt1::cluster1", "member2": "mgmt1::cluster1"}
    )

    assert updated == 1
    client.cache.upsert_assets.assert_awaited_once_with([updated_member])


@pytest.mark.asyncio
async def test_update_swallows_exception_and_returns_zero():
    client = MagicMock()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(side_effect=RuntimeError("boom"))
    manager = ClusterRelationshipManager(client=client)

    updated = await manager.update_cluster_member_parent_asset_ids("mgmt1", {"member1": "mgmt1::cluster1"})

    assert updated == 0
