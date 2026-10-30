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
