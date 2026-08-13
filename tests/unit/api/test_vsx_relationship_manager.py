"""Unit tests for VSXRelationshipManager.

Covers VSX/VS object discovery via the API-query seam, cross-domain
VS -> VSX asset-id mapping construction, and applying those mappings as
parent_asset_id updates on cached VS assets. Adapted from
.internal/tests_backup_v1/unit/test_vsx_relationship_manager.py (still
matches the current API) with added direct coverage for get_vsx_objects,
get_vs_objects, and update_vs_parent_asset_ids.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.api.schemas import ApiQueryResult
from arodonata.api.vsx_relationship_manager import VSXRelationshipManager


def _make_manager():
    client = MagicMock()
    return VSXRelationshipManager(client=client), client


def _vsx_obj(uid, name, vsx_gateway=None, vsid=0):
    return {"type": "vsx_slot_obj", "uid": uid, "name": name, "vsid": vsid, "vsxGateway": vsx_gateway}


def _vs_obj(uid, name, vsx_gateway, vsid=1):
    return {"type": "vs_slot_obj", "uid": uid, "name": name, "vsid": vsid, "vsxGateway": vsx_gateway}


def _asset(*, asset_id, asset_type, asset_uid="", domain_name="", name="", parent_asset_id=None):
    return SimpleNamespace(
        asset_id=asset_id,
        asset_type=asset_type,
        asset_uid=asset_uid,
        domain_name=domain_name,
        name=name,
        parent_asset_id=parent_asset_id,
    )


# --------------------------------------------------------------------------- #
# get_vsx_objects
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_vsx_objects_filters_by_type_and_vsid_zero():
    manager, client = _make_manager()
    # objects is typed list[dict], so use a stand-in result to exercise the
    # source's own isinstance() guard with a genuinely non-dict entry.
    objects = [
        _vsx_obj("vsx-uid", "vsx-a", vsid=0),
        {"type": "vsx_slot_obj", "uid": "wrong-vsid", "name": "vsx-b", "vsid": 1},
        {"type": "other", "uid": "x", "name": "y", "vsid": 0},
        "not-a-dict",
    ]
    client.api_query = AsyncMock(return_value=SimpleNamespace(success=True, objects=objects))

    result = await manager.get_vsx_objects("mgmt1", "domainA")

    assert result == [_vsx_obj("vsx-uid", "vsx-a", vsid=0)]


@pytest.mark.asyncio
async def test_get_vsx_objects_returns_empty_on_failed_response():
    manager, client = _make_manager()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))

    result = await manager.get_vsx_objects("mgmt1", "domainA")

    assert result == []


@pytest.mark.asyncio
async def test_get_vsx_objects_swallows_exception():
    manager, client = _make_manager()
    client.api_query = AsyncMock(side_effect=RuntimeError("boom"))

    result = await manager.get_vsx_objects("mgmt1", "domainA")

    assert result == []


# --------------------------------------------------------------------------- #
# get_vs_objects
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_vs_objects_filters_by_type_and_vsid_greater_than_zero():
    manager, client = _make_manager()
    objects = [
        _vs_obj("vs-uid", "vs-a", "vsx-gw", vsid=1),
        {"type": "vs_slot_obj", "uid": "vs-zero", "name": "vs-b", "vsid": 0, "vsxGateway": "vsx-gw"},
        {"type": "other", "uid": "x", "name": "y", "vsid": 1},
    ]
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=objects))

    result = await manager.get_vs_objects("mgmt1", "domainA")

    assert result == [_vs_obj("vs-uid", "vs-a", "vsx-gw", vsid=1)]


@pytest.mark.asyncio
async def test_get_vs_objects_returns_empty_on_failed_response():
    manager, client = _make_manager()
    client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))

    result = await manager.get_vs_objects("mgmt1", "domainA")

    assert result == []


@pytest.mark.asyncio
async def test_get_vs_objects_swallows_exception():
    manager, client = _make_manager()
    client.api_query = AsyncMock(side_effect=RuntimeError("boom"))

    result = await manager.get_vs_objects("mgmt1", "domainA")

    assert result == []


# --------------------------------------------------------------------------- #
# build_cross_domain_vsx_vs_mapping
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_simple_two_domain_mapping():
    manager, client = _make_manager()

    async def api_query(mgmt_name, command, domain, details_level, payload):
        class_name = payload["class-name"]
        if domain == "domainA" and class_name.endswith("CpmiVsxSlotObj"):
            return ApiQueryResult(success=True, objects=[_vsx_obj("vsx-uid-a", "vsx-a")])
        if domain == "domainA" and class_name.endswith("CpmiVsSlotObj"):
            return ApiQueryResult(success=True, objects=[_vs_obj("vs-uid-a", "vs-a", "vsx-uid-a")])
        if domain == "domainB" and class_name.endswith("CpmiVsxSlotObj"):
            return ApiQueryResult(success=True, objects=[_vsx_obj("vsx-uid-b", "vsx-b")])
        if domain == "domainB" and class_name.endswith("CpmiVsSlotObj"):
            return ApiQueryResult(success=True, objects=[_vs_obj("vs-uid-b", "vs-b", "vsx-uid-b")])
        return ApiQueryResult(success=True, objects=[])

    client.api_query = AsyncMock(side_effect=api_query)
    mapping = await manager.build_cross_domain_vsx_vs_mapping("mgmt1", ["domainA", "domainB"])
    assert mapping == {
        "vs-uid-a": "mgmt1:domainA:vsx-a",
        "domainA:vs-a": "mgmt1:domainA:vsx-a",
        "vs-uid-b": "mgmt1:domainB:vsx-b",
        "domainB:vs-b": "mgmt1:domainB:vsx-b",
    }


@pytest.mark.asyncio
async def test_vs_matches_vsx_via_gateway_uid_not_just_slot_uid():
    manager, client = _make_manager()

    async def api_query(mgmt_name, command, domain, details_level, payload):
        if payload["class-name"].endswith("CpmiVsxSlotObj"):
            return ApiQueryResult(success=True, objects=[_vsx_obj("vsx-slot-uid", "vsx-a", vsx_gateway="vsx-gw-uid")])
        return ApiQueryResult(success=True, objects=[_vs_obj("vs-uid-a", "vs-a", "vsx-gw-uid")])

    client.api_query = AsyncMock(side_effect=api_query)
    mapping = await manager.build_cross_domain_vsx_vs_mapping("mgmt1", ["domainA"])
    assert mapping["vs-uid-a"] == "mgmt1:domainA:vsx-a"
    assert mapping["domainA:vs-a"] == "mgmt1:domainA:vsx-a"


@pytest.mark.asyncio
async def test_domain_collection_error_is_logged_and_skipped():
    manager, client = _make_manager()

    async def get_vsx_objects(mgmt_name, domain):
        if domain == "badDomain":
            raise RuntimeError("boom")
        return [_vsx_obj("vsx-uid-a", "vsx-a")]

    async def get_vs_objects(mgmt_name, domain):
        if domain == "badDomain":
            raise RuntimeError("boom")
        return [_vs_obj("vs-uid-a", "vs-a", "vsx-uid-a")]

    manager.get_vsx_objects = AsyncMock(side_effect=get_vsx_objects)
    manager.get_vs_objects = AsyncMock(side_effect=get_vs_objects)
    mapping = await manager.build_cross_domain_vsx_vs_mapping("mgmt1", ["badDomain", "domainA"])
    assert mapping == {
        "vs-uid-a": "mgmt1:domainA:vsx-a",
        "domainA:vs-a": "mgmt1:domainA:vsx-a",
    }


@pytest.mark.asyncio
async def test_vs_object_missing_vsx_gateway_is_skipped():
    manager, client = _make_manager()

    async def api_query(mgmt_name, command, domain, details_level, payload):
        if payload["class-name"].endswith("CpmiVsxSlotObj"):
            return ApiQueryResult(success=True, objects=[_vsx_obj("vsx-uid-a", "vsx-a")])
        return ApiQueryResult(
            success=True,
            objects=[{"type": "vs_slot_obj", "uid": "vs-uid-orphan", "name": "vs-orphan", "vsid": 1}],
        )

    client.api_query = AsyncMock(side_effect=api_query)
    mapping = await manager.build_cross_domain_vsx_vs_mapping("mgmt1", ["domainA"])
    assert mapping == {}


@pytest.mark.asyncio
async def test_empty_domains_returns_empty_mapping():
    manager, client = _make_manager()
    client.api_query = AsyncMock()
    mapping = await manager.build_cross_domain_vsx_vs_mapping("mgmt1", [])
    assert mapping == {}
    client.api_query.assert_not_awaited()


@pytest.mark.asyncio
async def test_vsx_object_missing_uid_or_name_is_skipped():
    manager, client = _make_manager()

    async def api_query(mgmt_name, command, domain, details_level, payload):
        if payload["class-name"].endswith("CpmiVsxSlotObj"):
            return ApiQueryResult(
                success=True,
                objects=[{"type": "vsx_slot_obj", "uid": "", "name": "vsx-noid", "vsid": 0}],
            )
        return ApiQueryResult(success=True, objects=[_vs_obj("vs-uid-a", "vs-a", "vsx-gw")])

    client.api_query = AsyncMock(side_effect=api_query)
    mapping = await manager.build_cross_domain_vsx_vs_mapping("mgmt1", ["domainA"])
    assert mapping == {}


# --------------------------------------------------------------------------- #
# update_vs_parent_asset_ids
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_update_returns_zero_when_no_vs_assets_found():
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[_asset(asset_id="mgmt1::gw1", asset_type="simple-gateway")])

    updated = await manager.update_vs_parent_asset_ids("mgmt1", {})

    assert updated == 0
    client.cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_matches_vs_asset_via_uid_lookup():
    vs_asset = _asset(
        asset_id="mgmt1::domainA::vs1",
        asset_type="CpmiVsNetobj",
        asset_uid="vs-uid-a",
        domain_name="domainA",
        name="vs1",
        parent_asset_id=None,
    )
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[vs_asset])

    updated = await manager.update_vs_parent_asset_ids("mgmt1", {"vs-uid-a": "mgmt1:domainA:vsx-a"})

    assert updated == 1
    assert vs_asset.parent_asset_id == "mgmt1:domainA:vsx-a"
    client.cache.upsert_assets.assert_awaited_once_with([vs_asset])


@pytest.mark.asyncio
async def test_update_matches_vs_asset_via_domain_name_lookup_when_uid_absent():
    vs_asset = _asset(
        asset_id="mgmt1::domainA::vs1",
        asset_type="vs_slot_obj",
        asset_uid="unmapped-uid",
        domain_name="domainA",
        name="vs1",
        parent_asset_id=None,
    )
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[vs_asset])

    updated = await manager.update_vs_parent_asset_ids("mgmt1", {"domainA:vs1": "mgmt1:domainA:vsx-a"})

    assert updated == 1
    assert vs_asset.parent_asset_id == "mgmt1:domainA:vsx-a"


@pytest.mark.asyncio
async def test_update_skips_vs_asset_already_correct():
    vs_asset = _asset(
        asset_id="mgmt1::domainA::vs1",
        asset_type="CpmiVsNetobj",
        asset_uid="vs-uid-a",
        domain_name="domainA",
        name="vs1",
        parent_asset_id="mgmt1:domainA:vsx-a",
    )
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[vs_asset])

    updated = await manager.update_vs_parent_asset_ids("mgmt1", {"vs-uid-a": "mgmt1:domainA:vsx-a"})

    assert updated == 0
    client.cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_skips_vs_asset_with_no_mapping_match():
    vs_asset = _asset(
        asset_id="mgmt1::domainA::vs1",
        asset_type="CpmiVsNetobj",
        asset_uid="unmapped-uid",
        domain_name="domainA",
        name="unmapped-name",
        parent_asset_id=None,
    )
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[vs_asset])

    updated = await manager.update_vs_parent_asset_ids("mgmt1", {"vs-uid-a": "mgmt1:domainA:vsx-a"})

    assert updated == 0
    client.cache.upsert_assets.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_ignores_non_vs_assets():
    vs_asset = _asset(
        asset_id="mgmt1::domainA::vs1",
        asset_type="CpmiVsNetobj",
        asset_uid="vs-uid-a",
        domain_name="domainA",
        name="vs1",
        parent_asset_id=None,
    )
    other_asset = _asset(asset_id="mgmt1::gw1", asset_type="simple-gateway", asset_uid="gw-uid")
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[vs_asset, other_asset])

    updated = await manager.update_vs_parent_asset_ids("mgmt1", {"vs-uid-a": "mgmt1:domainA:vsx-a"})

    assert updated == 1
    client.cache.upsert_assets.assert_awaited_once_with([vs_asset])


@pytest.mark.asyncio
async def test_update_swallows_exception_and_returns_zero():
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(side_effect=RuntimeError("boom"))

    updated = await manager.update_vs_parent_asset_ids("mgmt1", {"vs-uid-a": "mgmt1:domainA:vsx-a"})

    assert updated == 0
