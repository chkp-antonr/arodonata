"""Unit tests for ArodonataClient call/query/streaming operations.

Covers:
* ``api_call`` argument forwarding, timeout resolution, response-shape handling
  (dict / non-dict / string data), error propagation, and closed-client guard
* ``api_call_with_sid`` forwarding
* ``api_query`` container-key extraction, layer-key guessing, list fallbacks
* ``collect_gateways_and_servers`` streaming event generation
* end-to-end session management through a real ``AMgmtClient`` wired to fake
  transport / login-coordinator seams: SID reuse across calls, re-login after
  logout, and re-login on session expiry.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.api.client import ArodonataClient
from arodonata.api.schemas import ApiCallResult, ApiQueryResult, SSEEventType
from arodonata.config import ArodonataSettings

from .client_test_helpers import CLOSED_CLIENT_MATCH, make_client

# =========================================================================== #
# api_call
# =========================================================================== #


@pytest.mark.asyncio
async def test_api_call_forwards_arguments_and_wraps_result():
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {
        "success": True,
        "data": {"name": "web1"},
        "message": "ok",
        "code": "0",
    }
    client = make_client(mgmt=mgmt)

    result = await client.api_call(
        "mgmt1",
        "show-host",
        domain="domainA",
        details_level="full",
        payload={"name": "web1"},
        wait_for_task=False,
        timeout=55,
        cache_mode="refresh",
    )

    assert isinstance(result, ApiCallResult)
    assert result.success is True
    assert result.data == {"name": "web1"}
    assert result.message == "ok"
    assert result.code == "0"
    mgmt.api_call.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-host",
        domain="domainA",
        details_level="full",
        payload={"name": "web1"},
        wait_for_task=False,
        timeout=55,
        cache_mode="refresh",
    )


@pytest.mark.asyncio
async def test_api_call_uses_settings_timeout_when_default():
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {"success": True, "data": {}}
    settings = ArodonataSettings()
    client = ArodonataClient(
        engine=MagicMock(),
        settings=settings,
        _db=AsyncMock(),
        _cache=AsyncMock(),
        _mgmt=mgmt,
    )

    await client.api_call("mgmt1", "show-host")  # timeout defaults to -1

    _, kwargs = mgmt.api_call.call_args
    assert kwargs["timeout"] == settings.api_timeout


@pytest.mark.asyncio
async def test_api_call_non_dict_data_is_marked_failure():
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {"success": True, "data": ["not", "a", "dict"]}
    client = make_client(mgmt=mgmt)

    result = await client.api_call("mgmt1", "show-host")

    assert result.success is False
    assert result.data is None


@pytest.mark.asyncio
async def test_api_call_string_data_becomes_message_and_failure():
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {"success": True, "data": "boom error"}
    client = make_client(mgmt=mgmt)

    result = await client.api_call("mgmt1", "show-host")

    assert result.success is False
    assert result.data is None
    assert result.message == "boom error"


@pytest.mark.asyncio
async def test_api_call_none_data_yields_none():
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {"success": False, "data": None, "message": "nope"}
    client = make_client(mgmt=mgmt)

    result = await client.api_call("mgmt1", "show-host")

    assert result.success is False
    assert result.data is None
    assert result.message == "nope"


@pytest.mark.asyncio
async def test_api_call_missing_keys_use_defaults():
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {}  # nothing present
    client = make_client(mgmt=mgmt)

    result = await client.api_call("mgmt1", "show-host")

    assert result.success is False
    assert result.data is None
    assert result.message == ""
    assert result.code == ""


@pytest.mark.asyncio
async def test_api_call_propagates_transport_error():
    mgmt = AsyncMock()
    mgmt.api_call.side_effect = RuntimeError("transport exploded")
    client = make_client(mgmt=mgmt)

    with pytest.raises(RuntimeError, match="transport exploded"):
        await client.api_call("mgmt1", "show-host")


# =========================================================================== #
# api_call_with_sid
# =========================================================================== #


@pytest.mark.asyncio
async def test_api_call_with_sid_forwards_and_wraps():
    mgmt = AsyncMock()
    mgmt.api_call_with_sid.return_value = {"success": True, "data": {"x": 1}, "message": "", "code": ""}
    settings = ArodonataSettings()
    client = ArodonataClient(
        engine=MagicMock(),
        settings=settings,
        _db=AsyncMock(),
        _cache=AsyncMock(),
        _mgmt=mgmt,
    )

    result = await client.api_call_with_sid(
        "mgmt1", "sid-1", "10.0.0.1", "publish", payload={"p": 1}, wait_for_task=False, timeout=-1
    )

    assert isinstance(result, ApiCallResult)
    assert result.success is True
    assert result.data == {"x": 1}
    mgmt.api_call_with_sid.assert_awaited_once_with(
        mgmt_name="mgmt1",
        sid="sid-1",
        server_ip="10.0.0.1",
        command="publish",
        payload={"p": 1},
        wait_for_task=False,
        timeout=settings.api_timeout,
    )


# =========================================================================== #
# api_query
# =========================================================================== #


@pytest.mark.asyncio
async def test_api_query_extracts_container_key():
    mgmt = AsyncMock()
    mgmt.api_query.return_value = {
        "success": True,
        "data": {"objects": [{"name": "a"}, {"name": "b"}]},
    }
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-hosts")

    assert isinstance(result, ApiQueryResult)
    assert result.success is True
    assert len(result.objects) == 2
    assert result.total == 2


@pytest.mark.asyncio
async def test_api_query_forwards_all_arguments():
    mgmt = AsyncMock()
    mgmt.api_query.return_value = {"success": True, "data": {"objects": []}}
    client = make_client(mgmt=mgmt)

    await client.api_query(
        "mgmt1",
        "show-access-rulebase",
        domain="domainA",
        details_level="full",
        payload={"limit": 10},
        container_key="rulebase",
        cache_mode="refresh",
    )

    mgmt.api_query.assert_awaited_once_with(
        mgmt_name="mgmt1",
        command="show-access-rulebase",
        domain="domainA",
        details_level="full",
        payload={"limit": 10},
        container_key="rulebase",
        cache_mode="refresh",
    )


@pytest.mark.asyncio
async def test_api_query_guesses_layer_container_key():
    mgmt = AsyncMock()
    mgmt.api_query.return_value = {
        "success": True,
        "data": {"access-layers": [{"name": "Network"}]},
    }
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-access-layers")

    assert len(result.objects) == 1
    assert result.objects[0]["name"] == "Network"


@pytest.mark.asyncio
async def test_api_query_falls_back_to_any_list():
    mgmt = AsyncMock()
    mgmt.api_query.return_value = {
        "success": True,
        "data": {"total": 3, "meta-info": {"k": "v"}, "widgets": [{"n": 1}, {"n": 2}]},
    }
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-widgets")

    assert result.objects == [{"n": 1}, {"n": 2}]


@pytest.mark.asyncio
async def test_api_query_data_is_list():
    mgmt = AsyncMock()
    mgmt.api_query.return_value = {"success": True, "data": [{"n": 1}]}
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-things")

    assert result.objects == [{"n": 1}]
    assert result.total == 1


@pytest.mark.asyncio
async def test_api_query_no_list_found_yields_empty():
    mgmt = AsyncMock()
    mgmt.api_query.return_value = {"success": True, "data": {"total": 3, "from": 1, "to": 3}}
    client = make_client(mgmt=mgmt)

    result = await client.api_query("mgmt1", "show-nothing")

    assert result.objects == []
    assert result.total == 0


@pytest.mark.asyncio
async def test_api_query_reraises_validation_error(capsys):
    from pydantic import ValidationError

    mgmt = AsyncMock()
    # message must be a str; an int forces ApiQueryResult construction to fail.
    mgmt.api_query.return_value = {"success": True, "data": [], "message": 123}
    client = make_client(mgmt=mgmt)

    with pytest.raises(ValidationError):
        await client.api_query("mgmt1", "show-hosts")

    # the except branch prints a diagnostic before re-raising
    assert "[Validation Failed]" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_api_query_on_closed_client_raises():
    client = make_client()
    await client.close()
    with pytest.raises(RuntimeError, match=CLOSED_CLIENT_MATCH):
        await client.api_query("mgmt1", "show-hosts")


# =========================================================================== #
# collect_gateways_and_servers
# =========================================================================== #


@pytest.mark.asyncio
async def test_collect_gateways_yields_results_and_complete():
    client = make_client()
    client.get_mgmt_names = MagicMock(return_value=["mgmt1"])
    client.api_query = AsyncMock(
        return_value=ApiQueryResult(success=True, data=[], objects=[{"name": "gw1"}], message="", code="", total=1)
    )

    events = [e async for e in client.collect_gateways_and_servers()]
    types = [e.event_type for e in events]

    assert SSEEventType.LOG in types
    assert SSEEventType.RESULT in types
    assert events[-1].event_type == SSEEventType.COMPLETE
    result_event = next(e for e in events if e.event_type == SSEEventType.RESULT)
    assert result_event.data["count"] == 1


@pytest.mark.asyncio
async def test_collect_gateways_yields_error_on_unsuccessful_query():
    client = make_client()
    client.api_query = AsyncMock(
        return_value=ApiQueryResult(
            success=False, data=None, objects=[], message="denied", code="err_forbidden", total=0
        )
    )

    events = [e async for e in client.collect_gateways_and_servers(mgmt_names=["mgmt1"], domains=["d"])]
    error = next(e for e in events if e.event_type == SSEEventType.ERROR)
    assert error.data["error_message"] == "denied"
    assert error.data["error_code"] == "err_forbidden"


@pytest.mark.asyncio
async def test_collect_gateways_success_with_no_objects_yields_no_result():
    client = make_client()
    client.api_query = AsyncMock(
        return_value=ApiQueryResult(success=True, data=[], objects=[], message="", code="", total=0)
    )

    events = [e async for e in client.collect_gateways_and_servers(mgmt_names=["mgmt1"])]
    types = [e.event_type for e in events]

    assert SSEEventType.RESULT not in types
    assert SSEEventType.ERROR not in types
    assert events[-1].event_type == SSEEventType.COMPLETE


@pytest.mark.asyncio
async def test_collect_gateways_yields_error_on_exception():
    client = make_client()
    client.api_query = AsyncMock(side_effect=ValueError("kaboom"))

    events = [e async for e in client.collect_gateways_and_servers(mgmt_names=["mgmt1"])]
    error = next(e for e in events if e.event_type == SSEEventType.ERROR)
    assert "kaboom" in error.data["error_message"]
    assert events[-1].event_type == SSEEventType.COMPLETE


# =========================================================================== #
# End-to-end session management via a real AMgmtClient
# =========================================================================== #


class _FakeRegistry:
    def __init__(self):
        self._servers = {"mgmt1": SimpleNamespace(port=443)}

    def get_names(self):
        return list(self._servers)

    def get_server(self, name):
        return self._servers.get(name)


class _FakeRateLimiter:
    @asynccontextmanager
    async def acquire(self, server_ip, timeout=30):
        yield


class _FakeLoginCoordinator:
    """Simulates SID caching: returns a stable SID unless forced or evicted."""

    def __init__(self):
        self._sids: dict[tuple[str, str], str] = {}
        self._counter = 0
        self.logins: list[tuple[str, str, bool]] = []
        self._credential_username = None

    async def login(
        self,
        mgmt_name,
        domain="",
        force=False,
        *,
        cache_mode="auto",
        session_name=None,
        session_description=None,
        refresh_domain_ip=False,
    ):
        self.logins.append((mgmt_name, domain, force))
        key = (mgmt_name, domain)
        if force or key not in self._sids:
            self._counter += 1
            self._sids[key] = f"sid-{self._counter}"
        return self._sids[key], "10.0.0.1"

    async def logout(self, mgmt_name, domain=""):
        self._sids.pop((mgmt_name, domain), None)
        return True

    async def maintain_keepalives(self, exclude_key=None):
        return None

    async def close(self):
        return None


class _FakeTransport:
    def __init__(self, responses=None):
        self._responses = list(responses or [])
        self.calls: list[SimpleNamespace] = []

    async def api_call(self, *, server_ip, sid, command, payload, wait_for_task, timeout, port):
        self.calls.append(SimpleNamespace(sid=sid, command=command, server_ip=server_ip, port=port))
        if self._responses:
            return self._responses.pop(0)
        return {"success": True, "data": {}}


def _make_client_with_real_mgmt(transport):
    from arodonata.asdk import AMgmtClient

    coordinator = _FakeLoginCoordinator()
    mgmt = AMgmtClient(
        registry=_FakeRegistry(),
        transport=transport,
        rate_limiter=_FakeRateLimiter(),
        login_coordinator=coordinator,
    )
    client = ArodonataClient(
        engine=MagicMock(),
        settings=ArodonataSettings(),
        _db=AsyncMock(),
        _cache=AsyncMock(),
        _mgmt=mgmt,
    )
    return client, mgmt, coordinator


@pytest.mark.asyncio
async def test_session_sid_reused_across_calls():
    transport = _FakeTransport()
    client, _mgmt, coordinator = _make_client_with_real_mgmt(transport)
    try:
        await client.api_call("mgmt1", "show-hosts")
        await client.api_call("mgmt1", "show-networks")
    finally:
        await client.close()

    assert len(transport.calls) == 2
    assert transport.calls[0].sid == transport.calls[1].sid
    # neither call forced a fresh login
    assert all(force is False for *_ignore, force in coordinator.logins)


@pytest.mark.asyncio
async def test_session_relogin_after_logout():
    transport = _FakeTransport()
    client, _mgmt, _coordinator = _make_client_with_real_mgmt(transport)
    try:
        await client.api_call("mgmt1", "show-hosts")
        assert await client.logout("mgmt1") is True
        await client.api_call("mgmt1", "show-networks")
    finally:
        await client.close()

    assert len(transport.calls) == 2
    # logout evicted the cached SID, so the second call logs in fresh
    assert transport.calls[0].sid != transport.calls[1].sid


@pytest.mark.asyncio
async def test_session_relogin_on_session_expiry():
    transport = _FakeTransport(
        responses=[
            {"success": False, "code": "generic_err_session_expired"},
            {"success": True, "data": {"ok": True}},
        ]
    )
    client, _mgmt, coordinator = _make_client_with_real_mgmt(transport)
    try:
        result = await client.api_call("mgmt1", "show-hosts")
    finally:
        await client.close()

    assert result.success is True
    assert len(transport.calls) == 2
    # first attempt not forced, retry forced a fresh login with a new SID
    assert coordinator.logins[0][2] is False
    assert coordinator.logins[1][2] is True
    assert transport.calls[0].sid != transport.calls[1].sid
