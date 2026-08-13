"""Unit tests for DomainService.

Covers domain enumeration and cache population for both Smart Center and MDM
management servers, active-server IP extraction, and domain UID cache
lookups. The ASDK management client, cache repository, and ArodonataClient
API-call seam are all mocked; no network or database is touched.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.api.services.domain_service import DomainService


def make_service(*, mgmt=None, cache=None, api_client=None):
    mgmt = mgmt or AsyncMock()
    cache = cache or AsyncMock()
    api_client = api_client or AsyncMock()
    service = DomainService(mgmt_client=mgmt, cache=cache, api_client=api_client)
    return service, mgmt, cache, api_client


def make_server(*, is_mdm=None, server_ip="1.2.3.4"):
    return SimpleNamespace(is_mdm=is_mdm, server_ip=server_ip)


# --------------------------------------------------------------------------- #
# populate_domain_cache dispatch
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_populate_domain_cache_dispatches_to_smart_center_when_is_mdm_false():
    server = make_server(is_mdm=False)
    mgmt = AsyncMock()
    mgmt.get_server = AsyncMock(return_value=server)
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(return_value=ApiCallResult(success=False))
    service, _, _, _ = make_service(mgmt=mgmt, api_client=api_client)

    result = await service.populate_domain_cache("mgmt1")

    assert result == [""]
    api_client.api_call.assert_awaited_once()


@pytest.mark.asyncio
async def test_populate_domain_cache_dispatches_to_mdm_when_is_mdm_true():
    server = make_server(is_mdm=True)
    mgmt = AsyncMock()
    mgmt.get_server = AsyncMock(return_value=server)
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))
    service, _, _, _ = make_service(mgmt=mgmt, api_client=api_client)

    result = await service.populate_domain_cache("mgmt1")

    assert result == [""]
    api_client.api_query.assert_awaited_once()


@pytest.mark.asyncio
async def test_populate_domain_cache_defaults_to_mdm_when_server_missing():
    mgmt = AsyncMock()
    mgmt.get_server = AsyncMock(return_value=None)
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))
    service, _, _, _ = make_service(mgmt=mgmt, api_client=api_client)

    result = await service.populate_domain_cache("mgmt1")

    assert result == [""]
    api_client.api_query.assert_awaited_once()


@pytest.mark.asyncio
async def test_populate_domain_cache_passes_cache_mode_through():
    server = make_server(is_mdm=True)
    mgmt = AsyncMock()
    mgmt.get_server = AsyncMock(return_value=server)
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))
    service, _, _, _ = make_service(mgmt=mgmt, api_client=api_client)

    await service.populate_domain_cache("mgmt1", cache_mode="force")

    _, kwargs = api_client.api_query.call_args
    assert kwargs["cache_mode"] == "force"


# --------------------------------------------------------------------------- #
# _populate_smart_center_domain
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_smart_center_domain_returns_system_domain_when_host_call_fails():
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(return_value=ApiCallResult(success=False, message="down"))
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_smart_center_domain("mgmt1", make_server(is_mdm=False))

    assert result == [""]
    cache.upsert_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_smart_center_domain_returns_system_domain_when_data_missing():
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(return_value=ApiCallResult(success=True, data=None))
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_smart_center_domain("mgmt1", make_server(is_mdm=False))

    assert result == [""]
    cache.upsert_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_smart_center_domain_returns_system_domain_when_data_not_dict():
    # ApiCallResult.data is typed dict|None, but the service defensively guards
    # against unexpected shapes anyway; simulate via a stand-in result object.
    api_call_result = SimpleNamespace(success=True, data="not-a-dict", message="")
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(return_value=api_call_result)
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_smart_center_domain("mgmt1", make_server(is_mdm=False))

    assert result == [""]
    cache.upsert_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_smart_center_domain_returns_system_domain_when_uid_missing():
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(
        return_value=ApiCallResult(success=True, data={"domain": {"name": "SMC User", "uid": ""}, "uid": "srv-uid"})
    )
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_smart_center_domain("mgmt1", make_server(is_mdm=False))

    assert result == [""]
    cache.upsert_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_smart_center_domain_success_upserts_and_returns_both_domains():
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(
        return_value=ApiCallResult(
            success=True,
            data={"domain": {"name": "SMC User", "uid": "dom-uid-1"}, "uid": "srv-uid-1"},
        )
    )
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)
    server = make_server(is_mdm=False, server_ip="10.0.0.5")

    result = await service._populate_smart_center_domain("mgmt1", server, is_mdm=False)

    assert result == ["", "SMC User"]
    cache.upsert_domain.assert_awaited_once()
    saved_domain = cache.upsert_domain.await_args.args[0]
    assert saved_domain.domain_name == "SMC User"
    assert saved_domain.domain_uid == "dom-uid-1"
    assert saved_domain.active_ip == "10.0.0.5"
    assert saved_domain.mgmt_name == "mgmt1"
    assert saved_domain.is_mdm is False


@pytest.mark.asyncio
async def test_smart_center_domain_handles_none_server():
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(
        return_value=ApiCallResult(
            success=True,
            data={"domain": {"name": "SMC User", "uid": "dom-uid-1"}, "uid": "srv-uid-1"},
        )
    )
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_smart_center_domain("mgmt1", None, is_mdm=False)

    assert result == ["", "SMC User"]
    saved_domain = cache.upsert_domain.await_args.args[0]
    assert saved_domain.active_ip == ""


@pytest.mark.asyncio
async def test_smart_center_domain_swallows_exception_and_returns_partial_result():
    api_client = AsyncMock()
    api_client.api_call = AsyncMock(side_effect=RuntimeError("boom"))
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_smart_center_domain("mgmt1", make_server(is_mdm=False))

    assert result == [""]
    cache.upsert_domain.assert_not_awaited()


# --------------------------------------------------------------------------- #
# _populate_mdm_domains
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_mdm_domains_returns_system_domain_when_query_fails():
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=ApiQueryResult(success=False))
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_mdm_domains("mgmt1")

    assert result == [""]
    cache.upsert_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_mdm_domains_returns_system_domain_when_no_objects():
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=[]))
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_mdm_domains("mgmt1")

    assert result == [""]
    cache.upsert_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_mdm_domains_skips_non_dict_and_unnamed_entries():
    # `objects` is typed list[dict], so use a stand-in result to exercise the
    # service's own defensive isinstance() check with a genuinely non-dict entry.
    objects = [
        "not-a-dict",
        {"uid": "uid-no-name"},
        {"name": "domainA", "uid": "uid-a", "servers": []},
    ]
    query_result = SimpleNamespace(success=True, objects=objects)
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=query_result)
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_mdm_domains("mgmt1")

    assert result == ["", "domainA"]
    cache.upsert_domain.assert_awaited_once()


@pytest.mark.asyncio
async def test_mdm_domains_success_upserts_domain_with_active_ip():
    objects = [
        {
            "name": "domainA",
            "uid": "uid-a",
            "servers": [{"active": True, "ipv4-address": "192.168.1.1"}],
        },
    ]
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=objects))
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_mdm_domains("mgmt1", is_mdm=True)

    assert result == ["", "domainA"]
    saved_domain = cache.upsert_domain.await_args.args[0]
    assert saved_domain.domain_name == "domainA"
    assert saved_domain.domain_uid == "uid-a"
    assert saved_domain.active_ip == "192.168.1.1"
    assert saved_domain.is_mdm is True


@pytest.mark.asyncio
async def test_mdm_domains_multiple_domains_all_upserted():
    objects = [
        {"name": "domainA", "uid": "uid-a", "servers": []},
        {"name": "domainB", "uid": "uid-b", "servers": []},
    ]
    api_client = AsyncMock()
    api_client.api_query = AsyncMock(return_value=ApiQueryResult(success=True, objects=objects))
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache, api_client=api_client)

    result = await service._populate_mdm_domains("mgmt1")

    assert result == ["", "domainA", "domainB"]
    assert cache.upsert_domain.await_count == 2


# --------------------------------------------------------------------------- #
# _extract_active_server_ip
# --------------------------------------------------------------------------- #


def test_extract_active_ip_returns_ip_for_active_true_server():
    service, _, _, _ = make_service()
    domain_obj = {"servers": [{"active": True, "ipv4-address": "10.1.1.1"}]}
    assert service._extract_active_server_ip(domain_obj) == "10.1.1.1"


def test_extract_active_ip_skips_active_false_server():
    service, _, _, _ = make_service()
    domain_obj = {"servers": [{"active": False, "ipv4-address": "10.1.1.1"}]}
    assert service._extract_active_server_ip(domain_obj) == ""


def test_extract_active_ip_missing_active_key_returns_empty():
    service, _, _, _ = make_service()
    domain_obj = {"servers": [{"ipv4-address": "10.1.1.1"}]}
    assert service._extract_active_server_ip(domain_obj) == ""


def test_extract_active_ip_malformed_ipv4_address_returns_empty():
    service, _, _, _ = make_service()
    domain_obj = {"servers": [{"active": True, "ipv4-address": None}]}
    assert service._extract_active_server_ip(domain_obj) == ""


def test_extract_active_ip_empty_ipv4_address_string_returns_empty():
    service, _, _, _ = make_service()
    domain_obj = {"servers": [{"active": True, "ipv4-address": ""}]}
    assert service._extract_active_server_ip(domain_obj) == ""


def test_extract_active_ip_servers_not_a_list_returns_empty():
    service, _, _, _ = make_service()
    domain_obj = {"servers": "not-a-list"}
    assert service._extract_active_server_ip(domain_obj) == ""


def test_extract_active_ip_no_servers_key_returns_empty():
    service, _, _, _ = make_service()
    assert service._extract_active_server_ip({}) == ""


def test_extract_active_ip_non_dict_server_entries_are_skipped():
    service, _, _, _ = make_service()
    domain_obj = {"servers": ["not-a-dict", {"active": True, "ipv4-address": "10.2.2.2"}]}
    assert service._extract_active_server_ip(domain_obj) == "10.2.2.2"


def test_extract_active_ip_returns_first_active_match():
    service, _, _, _ = make_service()
    domain_obj = {
        "servers": [
            {"active": False, "ipv4-address": "10.0.0.1"},
            {"active": True, "ipv4-address": "10.0.0.2"},
            {"active": True, "ipv4-address": "10.0.0.3"},
        ]
    }
    assert service._extract_active_server_ip(domain_obj) == "10.0.0.2"


# --------------------------------------------------------------------------- #
# get_domain_uid
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_domain_uid_returns_empty_for_system_domain():
    cache = AsyncMock()
    service, _, _, _ = make_service(cache=cache)
    result = await service.get_domain_uid("mgmt1", "")
    assert result == ""
    cache.get_domain.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_domain_uid_returns_uid_from_cache_hit():
    cache = AsyncMock()
    cache.get_domain = AsyncMock(return_value=SimpleNamespace(domain_uid="uid-123"))
    service, _, _, _ = make_service(cache=cache)

    result = await service.get_domain_uid("mgmt1", "domainA")

    assert result == "uid-123"
    cache.get_domain.assert_awaited_once_with(mdm_dmn="mgmt1:domainA")


@pytest.mark.asyncio
async def test_get_domain_uid_returns_empty_on_cache_miss():
    cache = AsyncMock()
    cache.get_domain = AsyncMock(return_value=None)
    service, _, _, _ = make_service(cache=cache)

    result = await service.get_domain_uid("mgmt1", "domainA")

    assert result == ""
