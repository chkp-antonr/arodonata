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


def test_build_login_response_extracts_from_nested_html_503():
    html_503 = (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        "<html><head>\n<title>503 Service Unavailable</title>\n</head><body>\n"
        "<h1>Service Unavailable</h1>\n"
        "<p>The server is temporarily unable to service your request.</p>\n"
        "</body></html>\n"
    )
    response = _make_response(success=False, data={"errors": [{"message": html_503}]})
    result = ApiTransport._build_login_response(response)
    assert result["success"] is False
    assert result["code"] == "503"
    assert "503 Service Unavailable" in result["message"]
    assert "temporarily unable to service your request" in result["message"]


def test_build_login_response_falls_back_to_status_code_if_message_empty():
    response = _make_response(success=False, data={}, status_code="503")
    result = ApiTransport._build_login_response(response)
    assert result["success"] is False
    assert result["code"] == "503"
    assert result["message"] == "HTTP 503"


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
# _parse_html_error - extract code and message from HTML error pages
# --------------------------------------------------------------------------


def test_parse_html_error_returns_empty_for_plain_text():
    code, message = ApiTransport._parse_html_error("plain error message")
    assert code == ""
    assert message == ""


def test_parse_html_error_extracts_title_and_paragraph():
    html = "<html><head><title>502 Bad Gateway</title></head><body><p>Proxy error</p></body></html>"
    code, message = ApiTransport._parse_html_error(html)
    assert code == "502"
    assert message == "502 Bad Gateway: Proxy error"


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


def test_convert_response_to_dict_string_data_populates_message():
    transport = ApiTransport()
    response = _make_response(success=False, data="Service Unavailable Error", status_code="503")
    result = transport._convert_response_to_dict(response)
    assert result["success"] is False
    assert result["message"] == "Service Unavailable Error"
    assert result["code"] == "503"


def test_convert_response_to_dict_failure_without_code_defaults_to_error():
    transport = ApiTransport()
    response = _make_response(success=False, data="Something broke", status_code="")
    result = transport._convert_response_to_dict(response)
    assert result["success"] is False
    assert result["message"] == "Something broke"
    assert result["code"] == "error"


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

    # Self-managed polling: cpapi is never asked to wait (see task_waiter.py), so the
    # wait_for_task positional reaching the SDK is False even though the caller passed True.
    mock_client.api_call.assert_called_once_with("show-hosts", {"limit": 5}, "sid-1", False, -1)
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

    mock_client.api_call.assert_called_once_with("show-hosts", {}, "sid-1", False, -1)


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
# login timeout: its own budget, and a log line that says what it was
# --------------------------------------------------------------------------


def test_login_methods_default_to_the_login_timeout_constant():
    """A login is one round trip, so it does not inherit DEFAULT_API_TIMEOUT (int-4, 2026-09-13)."""
    import inspect

    from arodonata.config.constants import DEFAULT_LOGIN_TIMEOUT

    for method in (ApiTransport.login_with_apikey, ApiTransport.login_with_credentials):
        assert inspect.signature(method).parameters["timeout"].default == DEFAULT_LOGIN_TIMEOUT


@pytest.mark.parametrize(
    ("method_name", "sdk_attr", "args", "expected"),
    [
        ("login_with_apikey", "login_with_api_key", ("10.0.0.1", "a-very-long-api-key-1234"), "LOGIN (apikey)"),
        ("login_with_credentials", "login", ("10.0.0.1", "svc", "pw"), "LOGIN (credentials)"),
    ],
)
async def test_login_timeout_log_line_names_the_budget(caplog, method_name, sdk_attr, args, expected):
    """asyncio.wait_for's TimeoutError stringifies to "", so `- {e}` logged nothing useful."""
    transport = ApiTransport()
    mock_client = MagicMock()
    getattr(mock_client, sdk_attr).side_effect = TimeoutError()

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, caplog.at_level("ERROR"), pytest.raises(TimeoutError):
        await getattr(transport, method_name)(*args, domain="Domain4", timeout=7)

    errors = [r.message for r in caplog.records if r.levelname == "ERROR"]
    assert any(f"{expected} TIMEOUT" in m and "(timeout=7s)" in m and "Domain4" in m for m in errors), errors


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


async def test_login_with_credentials_accepts_secret_str():
    from pydantic import SecretStr

    transport = ApiTransport()
    mock_response = _make_response(success=True, data={"sid": "sid-cred"})
    mock_client = MagicMock()
    mock_client.login.return_value = mock_response

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        result = await transport.login_with_credentials("10.0.0.1", "admin", SecretStr("top-secret"), domain="dom1")

    assert result["success"] is True
    mock_client.login.assert_called_once_with("admin", "top-secret", False, "dom1", False, {"domain": "dom1"})


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


class TestTaskBudgetIsSeparateFromTheCallBudget:
    """A server-side task must not be bounded by the HTTP call's allowance.

    `publish`, `install-policy`, `assign-global-assignment` and
    `revert-to-revision` hand back a task id in seconds and then run for
    minutes. Charging both to one `timeout` means the poller inherits whatever
    is left of a budget sized for a round trip.

    The resulting failure is the dangerous kind rather than the loud kind: the
    client raises while the server finishes the work anyway, so the caller
    concludes nothing happened when everything did. Seen on mdsNP2 2026-09-22,
    where a deployment had lowered ARODONATA_API_TIMEOUT to 30 and a publish
    timed out at 0% after 29 s, then completed moments later.
    """

    @staticmethod
    def _transport_with_recorded_wait(recorded: dict[str, float]):
        from arodonata.asdk.transport import ApiTransport

        class _Waiter:
            async def wait(self, show_task, task_ids, timeout, context=""):  # noqa: ANN001
                recorded["timeout"] = timeout
                return []

        return ApiTransport(task_waiter=_Waiter())

    async def test_an_explicit_task_timeout_replaces_the_leftover_of_the_call_budget(self):
        recorded: dict[str, float] = {}
        transport = self._transport_with_recorded_wait(recorded)

        await transport._await_tasks(
            {"success": True, "data": {"task-id": "t1"}},
            server_ip="10.0.0.1",
            sid="sid",
            port=None,
            command="publish",
            timeout=30,
            elapsed=29.0,  # a round trip that nearly exhausted the call budget
            task_timeout=900,
        )

        assert recorded["timeout"] == 900.0, "the task must get its own allowance, not the 1 s left over from the call"

    async def test_without_a_task_timeout_the_old_total_budget_arithmetic_stands(self):
        """A caller that names only `timeout` asked for a total budget and still gets one.

        This is what `revert_domain_to`'s 900 s has always meant, and changing it
        would silently multiply that caller's worst case.
        """
        recorded: dict[str, float] = {}
        transport = self._transport_with_recorded_wait(recorded)

        await transport._await_tasks(
            {"success": True, "data": {"task-id": "t1"}},
            server_ip="10.0.0.1",
            sid="sid",
            port=None,
            command="publish",
            timeout=100,
            elapsed=40.0,
        )

        assert recorded["timeout"] == 60.0

    async def test_no_budget_at_all_still_means_unbounded(self):
        recorded: dict[str, float] = {}
        transport = self._transport_with_recorded_wait(recorded)

        await transport._await_tasks(
            {"success": True, "data": {"task-id": "t1"}},
            server_ip="10.0.0.1",
            sid="sid",
            port=None,
            command="publish",
            timeout=-1,
            elapsed=5.0,
        )

        assert recorded["timeout"] == -1.0


# --------------------------------------------------------------------------
# API key stays a SecretStr until the cpapi call
# --------------------------------------------------------------------------
#
# pytest's long traceback prints every frame's arguments, so a key passed as a
# plain str anywhere on the login path is printed in full whenever a login
# fails (it was, in a 2026-09-28 int-1 run). The transport is where it is
# finally unwrapped, inline in the cpapi call, so no frame of ours holds it.

_SECRET_KEY = "Zq9-very-secret-api-key-value"


async def test_login_with_apikey_accepts_secretstr_and_sends_the_plain_value():
    from pydantic import SecretStr

    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.login_with_api_key.return_value = _make_response(success=True, data={"sid": "s"})

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3:
        await transport.login_with_apikey("10.0.0.1", SecretStr(_SECRET_KEY))

    assert mock_client.login_with_api_key.call_args.args[0] == _SECRET_KEY


@pytest.mark.parametrize(
    ("method_name", "sdk_attr", "args"),
    [
        ("login_with_apikey", "login_with_api_key", ("10.0.0.1",)),
        ("login_with_credentials", "login", ("10.0.0.1", "svc")),
    ],
)
async def test_failed_login_traceback_does_not_contain_the_secret(method_name, sdk_attr, args):
    """Render every frame's locals, as pytest's long traceback does, and look for the secret.

    The mocked cpapi method's own frames are excluded: cpapi receives the plain
    value by necessity and is not ours to scrub. Every other frame -- ours and
    asyncio's -- must hold only the SecretStr.
    """
    import traceback

    from pydantic import SecretStr

    transport = ApiTransport()
    mock_client = MagicMock()
    getattr(mock_client, sdk_attr).side_effect = RuntimeError("boom")

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, pytest.raises(RuntimeError) as excinfo:
        await getattr(transport, method_name)(*args, SecretStr(_SECRET_KEY))

    stack = traceback.TracebackException.from_exception(excinfo.value, capture_locals=True).stack
    leaking = [
        f"{frame.filename}:{frame.lineno} {frame.name}"
        for frame in stack
        if "unittest/mock" not in frame.filename
        and any(_SECRET_KEY in value for value in (frame.locals or {}).values())
    ]
    assert leaking == []


async def test_apikey_login_log_lines_show_at_most_the_last_four_characters(caplog):
    from pydantic import SecretStr

    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.login_with_api_key.return_value = _make_response(success=True, data={"sid": "s"})

    p1, p2, p3 = _patch_sdk(mock_client)
    with p1, p2, p3, caplog.at_level(1):
        await transport.login_with_apikey("10.0.0.1", SecretStr(_SECRET_KEY))

    text = "\n".join(r.getMessage() for r in caplog.records)
    assert _SECRET_KEY[:4] not in text
    assert _SECRET_KEY not in text


# --------------------------------------------------------------------------
# SID never reaches a log line it should not (D20)
# --------------------------------------------------------------------------

LOG_SID = "SIDSENTINEL-0123456789abcdef"


def _log_text(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


async def _apikey_login_log(caplog, **kwargs) -> str:
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.login_with_api_key.return_value = _make_response(success=True, data={"sid": LOG_SID})
    p1, p2, p3 = _patch_sdk(mock_client)
    with caplog.at_level(1), p1, p2, p3:
        result = await transport.login_with_apikey("10.0.0.1", "a-very-long-api-key-1234", **kwargs)
    assert result["sid"] == LOG_SID
    return _log_text(caplog)


async def test_login_with_apikey_log_sid_false_logs_no_sid_prefix(caplog):
    text = await _apikey_login_log(caplog, log_sid=False)
    assert "LOGIN (apikey) SUCCESS" in text and LOG_SID[:8] not in text


async def test_login_with_apikey_default_still_logs_sid_prefix(caplog):
    assert f"SID={LOG_SID[:8]}..." in await _apikey_login_log(caplog)


@pytest.mark.parametrize("prefix_len", [8, 12, len(LOG_SID)])
async def test_api_call_failure_and_error_logs_redact_the_request_sid(caplog, prefix_len):
    echoed = LOG_SID[:prefix_len]
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.sid = LOG_SID
    mock_client.api_call.return_value = _make_response(
        success=False, data={"code": "generic_err_wrong_session_id", "message": f"session {echoed} expired"}
    )
    p1, p2, p3 = _patch_sdk(mock_client)
    with caplog.at_level(1), p1, p2, p3:
        await transport.api_call("10.0.0.1", LOG_SID, "show-hosts", wait_for_task=False)
    assert "API CALL FAILED" in _log_text(caplog) and LOG_SID[:8] not in _log_text(caplog)
    caplog.clear()
    mock_client.api_call.side_effect = RuntimeError(f"transport echoed {echoed}")
    with caplog.at_level(1), p1, p2, p3, pytest.raises(RuntimeError):
        await transport.api_call("10.0.0.1", LOG_SID, "show-hosts", wait_for_task=False)
    assert "API CALL ERROR" in _log_text(caplog) and LOG_SID[:8] not in _log_text(caplog)


async def test_logout_failure_and_error_logs_redact_the_request_sid(caplog):
    transport = ApiTransport()
    mock_client = MagicMock()
    mock_client.api_call.return_value = _make_response(
        success=False, data={"code": "generic_err", "message": f"bad session {LOG_SID}"}
    )
    p1, p2, p3 = _patch_sdk(mock_client)
    with caplog.at_level(1), p1, p2, p3:
        await transport.logout("10.0.0.1", LOG_SID)
    assert "LOGOUT FAILED" in _log_text(caplog) and LOG_SID[:8] not in _log_text(caplog)
    caplog.clear()
    mock_client.api_call.side_effect = RuntimeError(f"refused {LOG_SID[:10]}")
    with caplog.at_level(1), p1, p2, p3:
        await transport.logout("10.0.0.1", LOG_SID)
    assert "LOGOUT ERROR" in _log_text(caplog) and LOG_SID[:8] not in _log_text(caplog)
