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


# --------------------------------------------------------------------------- #
# Real slot shapes (mdsNP2 lab, 2026-10-08)
# --------------------------------------------------------------------------- #
# A VS's own object (CpmiVsNetobj / CpmiVsClusterNetobj) carries no reference to
# its slot or its VSX, and its uid differs from the slot's uid and `vsUid`. Every
# slot lives in the VSX's domain, also for a VS created in another domain; the
# VS's own domain is in `targetCustomer` and the VSX gateway's uid in
# `vsxGateway`. So the VS is matched by `targetCustomer` and name.


def _lab_vsx_slot(domain):
    return {
        "type": "vsx_slot_obj",
        "uid": "9162f143-a9d2-48b7-b5d2-cdc0d144c61c",
        "name": "vsx1",
        "vsid": 0,
        "vsxGateway": "e9184e9d-473d-41c7-9887-4741946b0fdc",
        "vsUid": "{9162F143-A9D2-48B7-B5D2-CDC0D144C61C}",
        "domain": {"name": domain},
    }


def _lab_vs_slot(name, target_domain, slot_uid, vsid):
    """A VS slot as stored in the VSX's domain (domainA) for a VS in target_domain."""
    return {
        "type": "vs_slot_obj",
        "uid": slot_uid,
        "name": name,
        "vsid": vsid,
        "vsxGateway": "e9184e9d-473d-41c7-9887-4741946b0fdc",
        "vsUid": "{" + slot_uid.upper() + "}",
        "targetCustomer": target_domain,
        "domain": {"name": "domainA"},
    }


@pytest.mark.asyncio
async def test_vs_in_another_domain_and_vs_on_vsx_cluster_get_their_vsx():
    """VSX in domainA holds every slot; a VS in domainB, and a VSX-cluster VS in domainA."""
    manager, client = _make_manager()

    async def api_query(mgmt_name, command, domain, details_level, payload):
        if domain != "domainA":
            return ApiQueryResult(success=True, objects=[])
        if payload["class-name"].endswith("CpmiVsxSlotObj"):
            return ApiQueryResult(success=True, objects=[_lab_vsx_slot("domainA")])
        return ApiQueryResult(
            success=True,
            objects=[
                _lab_vs_slot("vs-cl", "domainA", "2b0d9469-e86e-e14e-ac05-d571e77996ac", 1),
                _lab_vs_slot("vs-b", "domainB", "6aa043d2-ef4e-744d-af76-64f123ea484e", 3),
            ],
        )

    client.api_query = AsyncMock(side_effect=api_query)
    vs_other_domain = _asset(
        asset_id="mgmt1:domainB:vs-b",
        asset_type="CpmiVsNetobj",
        asset_uid="6e52b534-d694-4c72-9938-73c36bff732e",
        domain_name="domainB",
        name="vs-b",
    )
    vs_on_cluster = _asset(
        asset_id="mgmt1:domainA:vs-cl",
        asset_type="CpmiVsClusterNetobj",
        asset_uid="d18a2b91-03ee-4e4b-9ae2-8c956a4944dd",
        domain_name="domainA",
        name="vs-cl",
    )
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[vs_other_domain, vs_on_cluster])

    mapping = await manager.build_cross_domain_vsx_vs_mapping("mgmt1", ["domainA", "domainB"])
    updated = await manager.update_vs_parent_asset_ids("mgmt1", mapping)

    assert updated == 2
    assert vs_other_domain.parent_asset_id == "mgmt1:domainA:vsx1"
    assert vs_on_cluster.parent_asset_id == "mgmt1:domainA:vsx1"


@pytest.mark.asyncio
async def test_update_warns_about_each_vs_left_without_a_vsx(caplog):
    vs_asset = _asset(
        asset_id="mgmt1:domainB:orphan",
        asset_type="CpmiVsClusterNetobj",
        asset_uid="netobj-uid",
        domain_name="domainB",
        name="orphan",
    )
    manager, client = _make_manager()
    client.cache = AsyncMock()
    client.cache.get_assets = AsyncMock(return_value=[vs_asset])

    with caplog.at_level("WARNING"):
        updated = await manager.update_vs_parent_asset_ids("mgmt1", {"domainA:other": "mgmt1:domainA:vsx1"})

    assert updated == 0
    assert any("mgmt1:domainB:orphan" in r.getMessage() and "no VSX" in r.getMessage() for r in caplog.records)
