"""Unit tests for `ArodonataClient` composite identifier resolution (`object_id`, `service_id`, `asset_id`, `id`)."""

from __future__ import annotations

import pytest

from arodonata import AmbiguousObjectError, ArodonataClient, ValidationError
from arodonata.core.config import ArodonataSettings
from arodonata.core.models.objects import CPObject
from tests.unit.test_client import FacadeFakeApi


@pytest.mark.asyncio
async def test_client_facade_composite_identifier_resolution() -> None:
    """`ArodonataClient.find_object` and `get_group_members` resolve objects, services, and assets by `object_id`, `service_id`, `asset_id`, and `id`."""
    fake_api = FacadeFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=300)

    async with ArodonataClient(settings, api=fake_api) as client:
        # Warm caches
        await client.get_hosts("mds1", "Corp")
        await client.get_groups("mds1", "Corp")
        await client.get_services("mds1", "Corp", types=["service-tcp"])
        await client.get_gateways("mds1", "Corp")

        obj = await client.find_object("mds1", "Corp", "mds1:Corp:host-base-1")
        assert obj is not None and obj.uid == "h-base-1" and obj.object_id == "mds1:Corp:host-base-1"

        obj_by_pk = await client.find_object("mds1", "Corp", "mds1:Corp:h-base-1")
        assert obj_by_pk is not None and obj_by_pk.name == "host-base-1"

        svc = await client.find_object("mds1", "Corp", "mds1:Corp:http", obj_type="service-tcp")
        assert svc is not None and svc.uid == "s-tcp-1" and svc.service_id == "mds1:Corp:http"

        gw = await client.find_object("mds1", "Corp", "mds1:Corp:corp-fw-01")
        assert gw is not None and gw.uid == "gw-1" and gw.asset_id == "mds1:Corp:corp-fw-01"

        members = await client.get_group_members("mds1", "Corp", "mds1:Corp:grp-base-1")
        assert [m.uid for m in members] == ["h-base-1"]

        # Blank input raises ValidationError
        with pytest.raises(ValidationError):
            await client.find_object("mds1", None, "   ")
        with pytest.raises(ValidationError):
            await client.get_group_members("mds1", None, "")

        # Seed Global and DMZ objects into cache directly
        await client.cache.replace_domain_objects(
            "mds1",
            "Global",
            [CPObject(uid="h-glob-1", name="global-ntp", type="host", mgmt_name="mds1", domain_name="Global")],
            types=["host"],
        )
        await client.cache.replace_domain_objects(
            "mds1",
            "DMZ",
            [CPObject(uid="h-dmz-dup", name="host-base-1", type="host", mgmt_name="mds1", domain_name="DMZ")],
            types=["host"],
        )

        # Cross-domain find_object (domain=None) finds Global objects without remote sync
        calls_before = len(fake_api.calls)
        glob_obj = await client.find_object("mds1", None, "global-ntp", cache_mode="smart")
        assert glob_obj is not None and glob_obj.domain_name == "Global"
        assert len(fake_api.calls) == calls_before

        # Cross-domain find_object raises AmbiguousObjectError when matching across Corp and DMZ
        with pytest.raises(AmbiguousObjectError) as exc_info:
            await client.find_object("mds1", None, "host-base-1", cache_mode="smart")
        assert {c["domain_name"] for c in exc_info.value.candidates} == {"Corp", "DMZ"}
        assert len(fake_api.calls) == calls_before


@pytest.mark.asyncio
async def test_client_facade_topology_and_find_affected_gateways() -> None:
    """`ArodonataClient` exposes `topology_service`, `refresh_topology`, `stream_refresh_topology`, `get_gateway_topology`, and `find_affected_gateways`."""
    fake_api = FacadeFakeApi()
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=300)

    async with ArodonataClient(settings, api=fake_api) as client:
        assert client.topology_service is not None

        # Seed rulebase packages/layers and synchronize topology via stream_refresh_topology
        await client.refresh_rulebases(mgmt_name="mds1", domains=["Corp"])
        events = [
            ev
            async for ev in client.stream_refresh_topology(
                mgmt_name="mds1",
                domains=["Corp"],
                mode="force",
            )
        ]
        assert any(ev.scope == "topology" for ev in events)

        topo_rows = await client.get_gateway_topology("mds1", "Corp", gateway="corp-fw-01", cache_mode="cache")
        assert len(topo_rows) == 3

        # 1. Traffic across eth1 (10.1.1.10) -> eth2 (10.2.2.20) matches corp-fw-01
        candidates = await client.find_affected_gateways(
            sources=["10.1.1.10"],
            destinations=["10.2.2.20"],
            mgmt_name="mds1",
            cache_mode="cache",
        )
        assert len(candidates) == 1
        cand = candidates[0]
        assert cand.gateway_name == "corp-fw-01"
        assert cand.domain_name == "Corp"
        assert cand.installed_access_policy == "Standard"
        assert cand.policy_packages == ["Standard"]
        assert cand.access_layers == ["Network"]
        assert len(cand.matched_flows) == 1
        assert cand.matched_flows[0].src_interface == "eth1"
        assert cand.matched_flows[0].dst_interface == "eth2"
        assert cand.matched_flows[0].match_type == "internal_to_internal"

        # 2. Traffic behind the same interface (eth1 -> eth1) is excluded
        same_if = await client.find_affected_gateways(
            sources=["10.1.1.10"],
            destinations=["10.1.1.50"],
            mgmt_name="mds1",
            cache_mode="cache",
        )
        assert same_if == []
