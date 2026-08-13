"""Unit tests for ApiTransport: response normalization, error parsing, and API calls."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arodonata.asdk.transport import ApiTransport


def _make_response(*, success=True, data=None, message="", status_code="", error_message=None):
    """Minimal fake mirroring the SDK APIResponse attrs read by the transport."""
    ns = SimpleNamespace(success=success, data=data, message=message, status_code=status_code)
    if error_message is not None:
        ns.error_message = error_message
    return ns


async def _fake_to_thread(func, *args, **kwargs):
    """Run the callable synchronously in-place (no real thread/wait)."""
    return func(*args, **kwargs)


def _patch_sdk(mock_client):
    """Patch APIClient/APIClientArgs/to_thread so ApiTransport uses mock_client."""
    return (
        patch("arodonata.asdk.transport.APIClient", return_value=mock_client),
        patch("arodonata.asdk.transport.APIClientArgs"),
        patch("arodonata.asdk.transport.asyncio.to_thread", side_effect=_fake_to_thread),
    )


# --------------------------------------------------------------------------
# _build_login_response - login-response normalization
# --------------------------------------------------------------------------


def test_build_login_response_success_extracts_sid():
    response = _make_response(success=True, data={"sid": "sid-123", "uid": "u1"})
    result = ApiTransport._build_login_response(response)
    assert result == {
        "success": True,
        "data": {"sid": "sid-123", "uid": "u1"},
        "sid": "sid-123",
        "message": "",
        "code": "",
    }


def test_build_login_response_failure_uses_data_message_and_code():
    response = _make_response(success=False, data={"message": "Wrong password", "code": "generic_err_wrong_password"})
    result = ApiTransport._build_login_response(response)
    assert result == {
        "success": False,
        "data": {"message": "Wrong password", "code": "generic_err_wrong_password"},
        "message": "Wrong password",
        "code": "generic_err_wrong_password",
    }


def test_build_login_response_failure_with_no_data_falls_back_to_defaults():
    response = _make_response(success=False, data=None)
    result = ApiTransport._build_login_response(response)
    assert result == {
        "success": False,
        "data": None,
        "message": "Unknown login error",
        "code": "",
    }


def test_build_login_response_success_but_missing_sid_treated_as_failure():
    """success=True but data lacks 'sid' should not be treated as a successful login."""
    response = _make_response(success=True, data={"message": "no sid here"})
    result = ApiTransport._build_login_response(response)
    assert result["success"] is False
    assert result["message"] == "no sid here"


# --------------------------------------------------------------------------
# _parse_code_and_message_from_error - nonstandard "code: X\nmessage: Y" parsing
# --------------------------------------------------------------------------


def test_parse_code_and_message_extracts_both_lines():
    code, message = ApiTransport._parse_code_and_message_from_error(
        "code: err_object_not_found\nmessage: Object not found"
    )
    assert code == "err_object_not_found"
    assert message == "Object not found"


def test_parse_code_and_message_returns_empty_when_no_code_marker_present():
    code, message = ApiTransport._parse_code_and_message_from_error("some plain error text")
    assert code == ""
    assert message == ""


def test_parse_code_and_message_only_takes_first_message_line():
    code, message = ApiTransport._parse_code_and_message_from_error("code: err_a\nmessage: first\nmessage: second")
    assert code == "err_a"
    assert message == "first"


# --------------------------------------------------------------------------
# _extract_code_and_message_from_errors - first parseable entry in data["errors"]
# --------------------------------------------------------------------------


def test_extract_code_and_message_skips_malformed_entries():
    data = {
        "errors": [
            "not a dict",
            {"no_message_key": "irrelevant"},
            {"message": "code: err_valid\nmessage: Valid error"},
        ]
    }
    code, message = ApiTransport._extract_code_and_message_from_errors(data)
    assert code == "err_valid"
    assert message == "Valid error"


def test_extract_code_and_message_accumulates_across_entries():
    data = {
        "errors": [
            {"message": "code: \nmessage: Only a message here, no code"},
            {"message": "code: err_found_later\nmessage: "},
        ]
    }
    code, message = ApiTransport._extract_code_and_message_from_errors(data)
    assert code == "err_found_later"
    assert message == "Only a message here, no code"


def test_extract_code_and_message_returns_empty_when_errors_not_a_list():
    assert ApiTransport._extract_code_and_message_from_errors({"errors": "oops"}) == ("", "")
    assert ApiTransport._extract_code_and_message_from_errors({}) == ("", "")


def test_extract_code_and_message_stops_at_first_code_found():
    """Break on the first entry that yields a code, even if later entries also have one."""
    data = {
        "errors": [
            {"message": "code: err_first\nmessage: first msg"},
            {"message": "code: err_second\nmessage: second msg"},
        ]
    }
    code, message = ApiTransport._extract_code_and_message_from_errors(data)
    assert code == "err_first"
    assert message == "first msg"


# --------------------------------------------------------------------------
# _convert_response_to_dict
# --------------------------------------------------------------------------


def test_convert_response_code_and_message_present_directly_in_data():
    transport = ApiTransport()
    response = _make_response(
        success=False,
        data={"code": "generic_err_invalid_parameter", "message": "Invalid parameter"},
    )
    result = transport._convert_response_to_dict(response)
    assert result == {
        "success": False,
        "data": {"code": "generic_err_invalid_parameter", "message": "Invalid parameter"},
        "message": "Invalid parameter",
        "code": "generic_err_invalid_parameter",
    }


def test_convert_response_code_missing_extracted_from_errors_list():
    transport = ApiTransport()
    response = _make_response(
        success=False,
        data={
            "message": "",
            "code": "",
            "errors": [{"message": "code: err_object_not_found\nmessage: Object not found"}],
        },
    )
    result = transport._convert_response_to_dict(response)
    assert result == {
        "success": False,
        "data": response.data,
        "message": "Object not found",
        "code": "err_object_not_found",
    }


def test_convert_response_falls_back_to_response_attributes():
    transport = ApiTransport()
    response = _make_response(
        success=False, data={"foo": "bar"}, message="Top level failure message", status_code="500"
    )
    result = transport._convert_response_to_dict(response)
    assert result == {
        "success": False,
        "data": {"foo": "bar"},
        "message": "Top level failure message",
        "code": "500",
    }


def test_convert_response_data_is_none():
    transport = ApiTransport()
    response = _make_response(success=False, data=None, message="Connection refused", status_code="503")
    result = transport._convert_response_to_dict(response)
    assert result == {
        "success": False,
        "data": None,
        "message": "Connection refused",
        "code": "503",
    }


def test_convert_response_success_with_no_message_or_code_falls_back_to_empty_defaults():
    transport = ApiTransport()
    response = _make_response(success=True, data={"uid": "abc-123"}, message="", status_code="")
    result = transport._convert_response_to_dict(response)
    assert result == {
        "success": True,
        "data": {"uid": "abc-123"},
        "message": "",
        "code": "",
    }


# --------------------------------------------------------------------------
# _client - APIClient context creation/close
# --------------------------------------------------------------------------


async def test_client_context_manager_creates_and_closes_apiclient():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.close_connection = MagicMock()

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2 as mock_args, p3:
        async with transport._client("10.0.0.1", 4434, "sid-abc") as client:
            assert client is mock_client
            mock_client.close_connection.assert_not_called()

    mock_args.assert_called_once_with(server="10.0.0.1", port=4434, sid="sid-abc", unsafe=True)
    mock_client.close_connection.assert_called_once()


async def test_client_context_manager_defaults_sid_to_none():
    transport = ApiTransport()
    mock_client = MagicMock()

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2 as mock_args, p3:
        async with transport._client("10.0.0.1", None):
            pass

    mock_args.assert_called_once_with(server="10.0.0.1", port=None, sid=None, unsafe=True)


async def test_client_context_manager_closes_connection_even_on_exception():
    transport = ApiTransport()
    mock_client = MagicMock()

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(ValueError, match="boom"):
        async with transport._client("10.0.0.1", None):
            raise ValueError("boom")

    mock_client.close_connection.assert_called_once()


# --------------------------------------------------------------------------
# api_call
# --------------------------------------------------------------------------


async def test_api_call_success_invokes_client_api_call_with_expected_args():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"uid": "u1"})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "sid-1"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.api_call(
            "10.0.0.1", "sid-1", "show-hosts", payload={"limit": 5}, wait_for_task=True, timeout=-1
        )

    mock_client.api_call.assert_called_once_with("show-hosts", {"limit": 5}, "sid-1", True, -1)
    assert result["success"] is True
    assert result["data"] == {"uid": "u1"}


async def test_api_call_defaults_payload_to_empty_dict():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "sid-1"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        await transport.api_call("10.0.0.1", "sid-1", "show-hosts")

    mock_client.api_call.assert_called_once_with("show-hosts", {}, "sid-1", True, -1)


async def test_api_call_failure_returns_error_result():
    transport = ApiTransport()
    mock_response = _make_response(success=False, data={"code": "generic_err", "message": "bad"})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "sid-1"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.api_call("10.0.0.1", "sid-1", "show-hosts")

    assert result["success"] is False
    assert result["code"] == "generic_err"


async def test_api_call_timeout_error_propagates():
    transport = ApiTransport()
    mock_client = MagicMock()

    p1, p2, p3 = _patch_sdk(mock_client)
    with (
        p1,
        p2,
        p3,
        patch("arodonata.asdk.transport.asyncio.wait_for", new=AsyncMock(side_effect=TimeoutError())),
        pytest.raises(TimeoutError),
    ):
        await transport.api_call("10.0.0.1", "sid-1", "show-hosts", timeout=5)


async def test_api_call_generic_exception_propagates():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.api_call.side_effect = RuntimeError("network down")

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(RuntimeError, match="network down"):
        await transport.api_call("10.0.0.1", "sid-1", "show-hosts")


# --------------------------------------------------------------------------
# api_query
# --------------------------------------------------------------------------


async def test_api_query_success_passes_expected_args():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"objects": [1, 2]})
    mock_client = MagicMock()
    mock_client.api_query.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.api_query(
            "10.0.0.1", "sid-1", "show-hosts", details_level="full", container_key="objects"
        )

    mock_client.api_query.assert_called_once_with("show-hosts", "full", "objects", False, {})
    assert result["success"] is True


async def test_api_query_none_response_raises_value_error():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.api_query.return_value = None

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(ValueError, match="API query returned None response"):
        await transport.api_query("10.0.0.1", "sid-1", "show-hosts")


async def test_api_query_failure_without_message_falls_back_to_error_message_attr():
    transport = ApiTransport()
    mock_response = _make_response(success=False, data=None, error_message="deep failure")
    mock_client = MagicMock()
    mock_client.api_query.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.api_query("10.0.0.1", "sid-1", "show-hosts")

    assert result["success"] is False
    assert result["message"] == "deep failure"


async def test_api_query_exception_propagates():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.api_query.side_effect = RuntimeError("boom")

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(RuntimeError, match="boom"):
        await transport.api_query("10.0.0.1", "sid-1", "show-hosts")


# --------------------------------------------------------------------------
# login_with_apikey
# --------------------------------------------------------------------------


async def test_login_with_apikey_success_returns_sid():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"sid": "sid-xyz"})
    mock_client = MagicMock()
    mock_client.login_with_api_key.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.login_with_apikey(
            "10.0.0.1", "a-very-long-api-key-1234", domain="dom1", session_name="n", session_description="d"
        )

    assert result["success"] is True
    assert result["sid"] == "sid-xyz"
    mock_client.login_with_api_key.assert_called_once_with(
        "a-very-long-api-key-1234",
        False,
        "dom1",
        False,
        {"domain": "dom1", "session-name": "n", "session-description": "d"},
    )


async def test_login_with_apikey_masks_short_api_key_without_error():
    """API keys <=8 chars take the '****' masking branch (still succeeds)."""
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"sid": "sid-short"})
    mock_client = MagicMock()
    mock_client.login_with_api_key.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.login_with_apikey("10.0.0.1", "short")

    assert result["success"] is True


async def test_login_with_apikey_none_response_raises_value_error():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.login_with_api_key.return_value = None

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(ValueError, match="API login returned None response"):
        await transport.login_with_apikey("10.0.0.1", "api-key")


async def test_login_with_apikey_timeout_wraps_with_custom_message():
    transport = ApiTransport()
    mock_client = MagicMock()

    p1, p2, p3 = _patch_sdk(mock_client)
    with (
        p1,
        p2,
        p3,
        patch("arodonata.asdk.transport.asyncio.wait_for", new=AsyncMock(side_effect=TimeoutError())),
        pytest.raises(TimeoutError, match="Login timed out after"),
    ):
        await transport.login_with_apikey("10.0.0.1", "api-key", timeout=5)


async def test_login_with_apikey_failure_returns_message_and_code():
    transport = ApiTransport()
    mock_response = _make_response(
        success=False, data={"message": "Invalid API key", "code": "generic_err_invalid_apikey"}
    )
    mock_client = MagicMock()
    mock_client.login_with_api_key.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.login_with_apikey("10.0.0.1", "api-key")

    assert result["success"] is False
    assert result["message"] == "Invalid API key"
    assert result["code"] == "generic_err_invalid_apikey"


# --------------------------------------------------------------------------
# login_with_credentials
# --------------------------------------------------------------------------


async def test_login_with_credentials_success_passes_expected_payload():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"sid": "sid-cred"})
    mock_client = MagicMock()
    mock_client.login.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.login_with_credentials(
            "10.0.0.1", "admin", "s3cr3t", domain="dom1", session_timeout=900
        )

    assert result["success"] is True
    mock_client.login.assert_called_once_with(
        "admin", "s3cr3t", False, "dom1", False, {"domain": "dom1", "session-timeout": 900}
    )


async def test_login_with_credentials_passes_session_name_and_description():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"sid": "sid-cred"})
    mock_client = MagicMock()
    mock_client.login.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        await transport.login_with_credentials(
            "10.0.0.1", "admin", "s3cr3t", session_name="my-session", session_description="a change"
        )

    mock_client.login.assert_called_once_with(
        "admin",
        "s3cr3t",
        False,
        None,
        False,
        {"session-name": "my-session", "session-description": "a change"},
    )


async def test_login_with_credentials_none_response_raises_value_error():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.login.return_value = None

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(ValueError, match="API credential login returned None response"):
        await transport.login_with_credentials("10.0.0.1", "admin", "pw")


async def test_login_with_credentials_timeout_wraps_with_custom_message():
    transport = ApiTransport()
    mock_client = MagicMock()

    p1, p2, p3 = _patch_sdk(mock_client)
    with (
        p1,
        p2,
        p3,
        patch("arodonata.asdk.transport.asyncio.wait_for", new=AsyncMock(side_effect=TimeoutError())),
        pytest.raises(TimeoutError, match="Credential login timed out after"),
    ):
        await transport.login_with_credentials("10.0.0.1", "admin", "pw", timeout=5)


async def test_login_with_credentials_failure_logs_and_returns_result():
    transport = ApiTransport()
    mock_response = _make_response(success=False, data={"message": "Wrong password", "code": "generic_err"})
    mock_client = MagicMock()
    mock_client.login.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.login_with_credentials("10.0.0.1", "admin", "wrong-pw")

    assert result["success"] is False
    assert result["message"] == "Wrong password"


# --------------------------------------------------------------------------
# logout
# --------------------------------------------------------------------------


async def test_logout_success():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.logout("10.0.0.1", "sid-1")

    mock_client.api_call.assert_called_once_with("logout")
    assert result["success"] is True


async def test_logout_exception_returns_failure_dict_instead_of_raising():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.api_call.side_effect = RuntimeError("conn refused")

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.logout("10.0.0.1", "sid-1")

    assert result == {"success": False, "message": "conn refused"}


# --------------------------------------------------------------------------
# keepalive / show_sessions / discard_session
# --------------------------------------------------------------------------


async def test_keepalive_calls_correct_command():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "test-sid"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2 as mock_args, p3:
        result = await transport.keepalive("10.0.0.1", "test-sid")

    mock_args.assert_called_once_with(server="10.0.0.1", port=None, sid="test-sid", unsafe=True)
    mock_client.api_call.assert_called_once_with("keepalive", {}, "test-sid")
    assert result["success"] is True


async def test_keepalive_failure_returns_error_result():
    transport = ApiTransport()
    mock_response = _make_response(success=False, data={"message": "session gone", "code": "generic_err"})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "test-sid"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.keepalive("10.0.0.1", "test-sid")

    assert result["success"] is False
    assert result["message"] == "session gone"


async def test_keepalive_exception_propagates():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.api_call.side_effect = RuntimeError("boom")

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(RuntimeError, match="boom"):
        await transport.keepalive("10.0.0.1", "test-sid")


async def test_show_sessions_calls_correct_command():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"objects": []})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "test-sid"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2 as mock_args, p3:
        await transport.show_sessions("10.0.0.1", "test-sid")

    mock_args.assert_called_once_with(server="10.0.0.1", port=None, sid="test-sid", unsafe=True)
    mock_client.api_call.assert_called_once_with("show-sessions", {"details-level": "full", "limit": 500}, "test-sid")


async def test_show_sessions_failure_returns_error_result():
    transport = ApiTransport()
    mock_response = _make_response(success=False, data={"message": "no permissions", "code": "err_forbidden"})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "test-sid"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.show_sessions("10.0.0.1", "test-sid")

    assert result["success"] is False
    assert result["message"] == "no permissions"


async def test_discard_session_sends_uid():
    transport = ApiTransport()
    mock_response = _make_response(success=True, data={})
    mock_client = MagicMock()
    mock_client.api_call.return_value = mock_response
    mock_client.sid = "test-sid"

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2 as mock_args, p3:
        await transport.discard_session("10.0.0.1", "test-sid", "target-uid-123")

    mock_args.assert_called_once_with(server="10.0.0.1", port=None, sid="test-sid", unsafe=True)
    mock_client.api_call.assert_called_once_with("discard", {"uid": "target-uid-123"}, "test-sid")


async def test_discard_session_exception_propagates():
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.api_call.side_effect = RuntimeError("discard failed")

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(RuntimeError, match="discard failed"):
        await transport.discard_session("10.0.0.1", "test-sid", "uid-1")
