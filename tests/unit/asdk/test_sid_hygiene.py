"""SID hygiene (Backlog #25, #2): an 8-character SID prefix only at DEBUG and below, never the full SID, and no SID in
a Check Point message the transport hands back."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from arodonata.asdk._sid import redact_sid, sid_prefix
from arodonata.asdk.transport import ApiTransport
from arodonata.cache.models import SIDCache

SID = "SIDSENTINEL-0123456789abcdef"
OTHER = "OTHERSID-fedcba9876543210"
SRC = Path(__file__).resolve().parents[3] / "src" / "arodonata"
INFO_AND_ABOVE = {"info", "success", "warning", "error", "exception", "critical"}


def test_sid_prefix_shows_the_first_8_characters():
    assert sid_prefix(SID) == "SID=[SIDSENTI...]"
    assert sid_prefix(SecretStr(SID)) == "SID=[SIDSENTI...]"


def test_sid_prefix_of_no_sid():
    assert sid_prefix(None) == "SID=[none]" and sid_prefix("") == "SID=[none]"


def test_redact_sid_removes_the_sid_and_its_long_prefixes():
    text = redact_sid(f"a {SID} b {SID[:12]} c {SID[:8]}", SID)
    assert SID[:8] not in text and text.count("***") == 3


def test_redact_sid_removes_any_sid_in_a_wrong_session_id_message():
    message = f"Wrong session id [{OTHER}]. Session may be expired. Please check session id and resend the request."
    text = redact_sid(message, SID)
    assert OTHER[:8] not in text and "Wrong session id [***]" in text


def _response(message: str) -> SimpleNamespace:
    return SimpleNamespace(
        success=False, data={"code": "generic_err_wrong_session_id", "message": message}, message="", status_code=""
    )


async def _fake_to_thread(func, *args, **kwargs):
    return func(*args, **kwargs)


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("api_call", ("show-hosts",)),
        ("logout", ()),
        ("keepalive", ()),
        ("show_sessions", ()),
        ("discard_session", ("session-uid",)),
    ],
)
async def test_transport_result_message_never_carries_a_sid(method, args):
    sdk = MagicMock()
    sdk.sid = SID
    sdk.api_call.return_value = _response(f"Wrong session id [{SID}]. Session may be expired (also {OTHER}).")
    with (
        patch("arodonata.asdk.transport.verified_api_client", return_value=sdk),
        patch("arodonata.asdk.transport.TrustPolicy"),
        patch("arodonata.asdk.transport.asyncio.to_thread", side_effect=_fake_to_thread),
    ):
        transport = ApiTransport()
        kwargs = {"wait_for_task": False} if method == "api_call" else {}
        result = await getattr(transport, method)("10.0.0.1", SID, *args, **kwargs)
    assert result["message"] and SID[:8] not in result["message"]


async def test_logout_exception_message_never_carries_the_sid():
    sdk = MagicMock()
    sdk.api_call.side_effect = RuntimeError(f"connection reset while sending {SID}")
    with (
        patch("arodonata.asdk.transport.verified_api_client", return_value=sdk),
        patch("arodonata.asdk.transport.TrustPolicy"),
        patch("arodonata.asdk.transport.asyncio.to_thread", side_effect=_fake_to_thread),
    ):
        result = await ApiTransport().logout("10.0.0.1", SID)
    assert result["success"] is False and SID[:8] not in result["message"]


def test_sid_cache_repr_hides_the_sid():
    row = SIDCache(mgmt_dmn_key="m:d", sid=SID, server_ip="10.0.0.1")
    assert SID[:8] not in repr(row)


def _sources() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text())) for p in sorted(SRC.rglob("*.py"))]


def _is_sid_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return "sid" in node.id.lower()
    if isinstance(node, ast.Attribute):
        return "sid" in node.attr.lower()
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        return "sid" in str(node.slice.value).lower()
    return False


def test_no_sid_slice_outside_the_helper():
    """A SID prefix is built by ``sid_prefix`` only, so its level rule is checked in one place."""
    found = [
        f"{path.relative_to(SRC)}:{node.lineno}"
        for path, tree in _sources()
        if path.name != "_sid.py"
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice) and _is_sid_expr(node.value)
    ]
    assert not found


def test_sid_prefix_only_in_log_calls_below_info():
    found = []
    for path, tree in _sources():
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in INFO_AND_ABOVE:
                continue
            if any(
                isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name) and inner.func.id == "sid_prefix"
                for inner in ast.walk(node)
            ):
                found.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not found
