"""Tests for the ASDK API adapter (ApiPort implementation).

Mocks the wrapped `AMgmtClient` with `unittest.mock.AsyncMock`; no network,
no real ASDK client. Covers ApiPort conformance, the query pipeline
(container-key guessing, response-shape extraction), show-changes payload
forwarding, and publish.
"""

from unittest.mock import AsyncMock

import pytest

from arodonata.adapters.api.asdk_adapter import ASDKApiAdapter
from arodonata.ports import ApiPort

# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_asdk_adapter_satisfies_api_port():
    adapter = ASDKApiAdapter(AsyncMock())
    assert isinstance(adapter, ApiPort)


def test_plain_object_does_not_satisfy_api_port():
    class NotAnAdapter:
        pass

    assert not isinstance(NotAnAdapter(), ApiPort)


# ---------------------------------------------------------------------------
# Container-key guessing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,expected_key",
    [
        ("show-access-layers", "access-layers"),
        ("show-nat-layers", "nat-layers"),
        ("show-https-layers", "https-layers"),
        ("show-threat-layers", "threat-layers"),
        ("show-hosts", "objects"),
        ("show-access-rulebase", "objects"),
    ],
)
def test_guess_container_key(command, expected_key):
    adapter = ASDKApiAdapter(AsyncMock())
    assert adapter._guess_container_key(command) == expected_key


# ---------------------------------------------------------------------------
# _extract_objects_from_data response-shape handling
# ---------------------------------------------------------------------------


def test_extract_objects_from_data_list_passthrough():
    adapter = ASDKApiAdapter(AsyncMock())
    data = [{"uid": "1"}, {"uid": "2"}]
    assert adapter._extract_objects_from_data(data, "objects") == data


def test_extract_objects_from_data_non_dict_non_list_returns_empty():
    adapter = ASDKApiAdapter(AsyncMock())
    assert adapter._extract_objects_from_data("not-a-container", "objects") == []
    assert adapter._extract_objects_from_data(None, "objects") == []


def test_extract_objects_from_data_uses_container_key_first():
    adapter = ASDKApiAdapter(AsyncMock())
    data = {"access-layers": [{"uid": "a"}], "objects": [{"uid": "b"}]}
    assert adapter._extract_objects_from_data(data, "access-layers") == [{"uid": "a"}]


def test_extract_objects_from_data_falls_back_to_objects_key():
    adapter = ASDKApiAdapter(AsyncMock())
    data = {"access-layers": [], "objects": [{"uid": "b"}]}
    assert adapter._extract_objects_from_data(data, "access-layers") == [{"uid": "b"}]


def test_extract_objects_from_data_falls_back_to_any_list_excluding_meta():
    adapter = ASDKApiAdapter(AsyncMock())
    data = {
        "from": 1,
        "to": 2,
        "total": 2,
        "meta-info": {"validation-state": "ok"},
        "rule-base": [{"uid": "r1"}],
    }
    assert adapter._extract_objects_from_data(data, "objects") == [{"uid": "r1"}]


def test_extract_objects_from_data_no_list_anywhere_returns_empty():
    adapter = ASDKApiAdapter(AsyncMock())
    data = {"from": 1, "to": 2, "total": 0}
    assert adapter._extract_objects_from_data(data, "objects") == []


def test_extract_objects_from_data_non_list_container_value_returns_empty():
    adapter = ASDKApiAdapter(AsyncMock())
    # container_key resolves to a non-list value and no other list is present.
    data = {"objects": "not-a-list"}
    assert adapter._extract_objects_from_data(data, "objects") == []


# ---------------------------------------------------------------------------
# query()
# ---------------------------------------------------------------------------


async def test_query_uses_guessed_container_key_and_forwards_params():
    mock_client = AsyncMock()
    mock_client.api_query = AsyncMock(
        return_value={
            "success": True,
            "data": {"access-layers": [{"uid": "l1"}]},
            "message": "OK",
            "code": "",
        }
    )
    adapter = ASDKApiAdapter(mock_client)

    result = await adapter.query(
        "mgmt1",
        "show-access-layers",
        domain="dmn1",
        payload={"limit": 50},
        details_level="full",
    )

    mock_client.api_query.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-access-layers",
        domain="dmn1",
        payload={"limit": 50},
        details_level="full",
        container_key="access-layers",
    )
    assert result.success is True
    assert result.objects == [{"uid": "l1"}]
    assert result.total == 1
    assert result.message == "OK"


async def test_query_explicit_container_key_overrides_guess():
    mock_client = AsyncMock()
    mock_client.api_query = AsyncMock(return_value={"success": True, "data": {"custom-key": [{"uid": "x"}]}})
    adapter = ASDKApiAdapter(mock_client)

    await adapter.query("mgmt1", "show-hosts", container_key="custom-key")

    assert mock_client.api_query.call_args.kwargs["container_key"] == "custom-key"


async def test_query_defaults_payload_and_domain():
    mock_client = AsyncMock()
    mock_client.api_query = AsyncMock(return_value={"success": True, "data": []})
    adapter = ASDKApiAdapter(mock_client)

    await adapter.query("mgmt1", "show-hosts")

    mock_client.api_query.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-hosts",
        domain="",
        payload={},
        details_level="standard",
        container_key="objects",
    )


async def test_query_data_as_list_extracts_directly():
    mock_client = AsyncMock()
    mock_client.api_query = AsyncMock(return_value={"success": True, "data": [{"uid": "1"}, {"uid": "2"}]})
    adapter = ASDKApiAdapter(mock_client)

    result = await adapter.query("mgmt1", "show-hosts")

    assert result.objects == [{"uid": "1"}, {"uid": "2"}]
    assert result.total == 2


async def test_query_missing_success_and_message_defaults():
    mock_client = AsyncMock()
    mock_client.api_query = AsyncMock(return_value={"data": []})
    adapter = ASDKApiAdapter(mock_client)

    result = await adapter.query("mgmt1", "show-hosts")

    assert result.success is False
    assert result.message == ""
    assert result.code == ""
    assert result.objects == []
    assert result.total == 0


async def test_query_missing_data_key_defaults_to_empty_list():
    mock_client = AsyncMock()
    mock_client.api_query = AsyncMock(return_value={"success": True})
    adapter = ASDKApiAdapter(mock_client)

    result = await adapter.query("mgmt1", "show-hosts")

    assert result.data == []
    assert result.objects == []


# ---------------------------------------------------------------------------
# show_changes()
# ---------------------------------------------------------------------------


async def test_show_changes_forwards_only_provided_fields():
    mock_client = AsyncMock()
    mock_client.api_call = AsyncMock(return_value={"changes": []})
    adapter = ASDKApiAdapter(mock_client)

    result = await adapter.show_changes("mgmt1", domain="dmn1", from_session="s1")

    mock_client.api_call.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-changes",
        domain="dmn1",
        payload={"from-session": "s1"},
    )
    assert result == {"changes": []}


async def test_show_changes_forwards_all_fields_when_provided():
    mock_client = AsyncMock()
    mock_client.api_call = AsyncMock(return_value={})
    adapter = ASDKApiAdapter(mock_client)

    await adapter.show_changes(
        "mgmt1",
        domain="dmn1",
        from_session="s1",
        from_date="2026-01-01",
        to_session="s2",
        to_date="2026-01-02",
    )

    mock_client.api_call.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-changes",
        domain="dmn1",
        payload={
            "from-session": "s1",
            "from-date": "2026-01-01",
            "to-session": "s2",
            "to-date": "2026-01-02",
        },
    )


async def test_show_changes_no_fields_sends_empty_payload():
    mock_client = AsyncMock()
    mock_client.api_call = AsyncMock(return_value={})
    adapter = ASDKApiAdapter(mock_client)

    await adapter.show_changes("mgmt1")

    mock_client.api_call.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-changes",
        domain="",
        payload={},
    )


# ---------------------------------------------------------------------------
# publish()
# ---------------------------------------------------------------------------


async def test_publish_forwards_mgmt_and_domain():
    mock_client = AsyncMock()
    mock_client.api_call = AsyncMock(return_value={"success": True})
    adapter = ASDKApiAdapter(mock_client)

    result = await adapter.publish("mgmt1", domain="dmn1")

    mock_client.api_call.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="publish",
        domain="dmn1",
        payload={},
    )
    assert result == {"success": True}


async def test_publish_defaults_domain_to_empty_string():
    mock_client = AsyncMock()
    mock_client.api_call = AsyncMock(return_value={})
    adapter = ASDKApiAdapter(mock_client)

    await adapter.publish("mgmt1")

    assert mock_client.api_call.call_args.kwargs["domain"] == ""
