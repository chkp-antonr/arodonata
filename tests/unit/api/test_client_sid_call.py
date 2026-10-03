from __future__ import annotations

from unittest.mock import AsyncMock

from tests.unit.api.client_test_helpers import make_client
from tests.unit.asdk.test_client import _make_client as make_mgmt

SID = "SIDSENTINEL-0123456789abcdef"


async def test_api_call_with_sid_non_dict_data_is_failure():
    mgmt = AsyncMock()
    mgmt.api_call_with_sid.return_value = {"success": True, "data": ["x"]}
    client = make_client(mgmt=mgmt)
    result = await client.api_call_with_sid("m1", SID, "192.0.2.1", "show-session")
    assert (result.success, result.code, result.data) == (False, "invalid_response", None)
    mgmt.api_call_with_sid.return_value = {"success": True, "data": "text error"}
    result = await client.api_call_with_sid("m1", SID, "192.0.2.1", "show-session")
    assert (result.success, result.code, result.message) == (False, "invalid_response", "text error")


async def test_api_call_with_sid_logs_no_sid_prefix(caplog):
    client, _, transport, _, _ = make_mgmt()
    transport.api_call.return_value = {"success": True, "data": {}}
    with caplog.at_level(1):
        await client.api_call_with_sid("m1", SID, "192.0.2.1", "show-session")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "Using explicit SID for 'm1' command 'show-session'" in text
    assert SID[:8] not in text


async def test_logout_sid_failure_logs_no_sid_prefix(caplog):
    client, _, transport, _, _ = make_mgmt()
    transport.logout.side_effect = RuntimeError(f"CP refused session {SID}")
    with caplog.at_level(1):
        assert await client.logout_sid(SID, "192.0.2.1", "m1") is False
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "Logout of explicit SID for 'm1' failed: RuntimeError" in text
    assert SID[:8] not in text


async def test_api_call_with_sid_forwards_the_domain():
    mgmt = AsyncMock()
    mgmt.api_call_with_sid.return_value = {"success": True, "data": {}}
    client = make_client(mgmt=mgmt)

    await client.api_call_with_sid("m1", SID, "192.0.2.1", "show-session", domain="Domain4")

    assert mgmt.api_call_with_sid.await_args.kwargs["domain"] == "Domain4"
