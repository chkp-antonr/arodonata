"""Unit tests for AMgmtClient: facade delegation, retry/session-error handling, and lifecycle."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import SecretStr

from arodonata.asdk.client import AMgmtClient
from arodonata.asdk.server_registry import ServerConfig
from arodonata.config import FAILOVER_ERROR_CODES, SESSION_ERROR_CODES
from arodonata.core.exceptions import ApiTimeoutError, CertificateMismatchError


def _cm_rate_limiter():
    limiter = MagicMock()
    limiter.acquire.return_value.__aenter__ = AsyncMock(return_value=None)
    limiter.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return limiter


def _make_client(registry=None, transport=None, rate_limiter=None, login_coordinator=None):
    registry = registry if registry is not None else MagicMock()
    transport = transport if transport is not None else AsyncMock()
    rate_limiter = rate_limiter if rate_limiter is not None else _cm_rate_limiter()
    login_coordinator = login_coordinator if login_coordinator is not None else AsyncMock()

    # `_credential_username` is a plain property on the real LoginCoordinator; make sure
    # the mock exposes a concrete value rather than an auto-generated MagicMock attribute.
    if isinstance(login_coordinator, MagicMock) and not isinstance(
        login_coordinator._credential_username, (str, type(None))
    ):
        login_coordinator._credential_username = None
    login_coordinator.close = AsyncMock()
    login_coordinator.maintain_keepalives = AsyncMock()

    client = AMgmtClient(registry, transport, rate_limiter, login_coordinator)
    return client, registry, transport, rate_limiter, login_coordinator


# --------------------------------------------------------------------------
# Lifecycle: context manager, close(), _ensure_not_closed
# --------------------------------------------------------------------------


async def test_context_manager_returns_self_and_closes_on_exit():
    client, _, _, _, login_coordinator = _make_client()

    async with client as ctx:
        assert ctx is client

    login_coordinator.close.assert_awaited_once()


async def test_close_is_idempotent():
    client, _, _, _, login_coordinator = _make_client()

    await client.close()
    await client.close()

    login_coordinator.close.assert_awaited_once()


async def test_close_cancels_pending_background_tasks():
    client, _, _, _, login_coordinator = _make_client()

    async def _never_ends():
        await asyncio.sleep(100)

    task = asyncio.create_task(_never_ends())
    client._background_tasks.add(task)
    client._close_grace_seconds = 0.05  # a task that never ends waits out the grace, then is cancelled

    await client.close()

    assert task.cancelled() or task.done()
    login_coordinator.close.assert_awaited_once()


@pytest.mark.parametrize(
    "method_call",
    [
        lambda c: c.get_server("mgmt1"),
        lambda c: c.logout("mgmt1"),
        lambda c: c.api_call("mgmt1", "show-hosts"),
        lambda c: c.api_query("mgmt1", "show-hosts"),
        lambda c: c.create_dedicated_session("mgmt1"),
        lambda c: c.api_call_with_sid("mgmt1", "sid", "10.0.0.1", "show-hosts"),
    ],
)
async def test_async_methods_raise_after_close(method_call):
    client, _, _, _, _ = _make_client()
    await client.close()

    with pytest.raises(RuntimeError, match="AMgmtClient has been closed"):
        await method_call(client)


def test_get_mgmt_names_raises_after_close_sync():
    client, _, _, _, _ = _make_client()
    client._closed = True
    with pytest.raises(RuntimeError, match="AMgmtClient has been closed"):
        client.get_mgmt_names()


# --------------------------------------------------------------------------
# Facade delegation
# --------------------------------------------------------------------------


def test_get_mgmt_names_delegates_to_registry():
    registry = MagicMock()
    registry.get_names.return_value = ["mgmt1", "mgmt2"]
    client, _, _, _, _ = _make_client(registry=registry)

    assert client.get_mgmt_names() == ["mgmt1", "mgmt2"]
    registry.get_names.assert_called_once()


async def test_logout_delegates_to_login_coordinator():
    login_coordinator = AsyncMock()
    login_coordinator.logout.return_value = True
    client, _, _, _, _ = _make_client(login_coordinator=login_coordinator)

    result = await client.logout("mgmt1", domain="domA")

    assert result is True
    login_coordinator.logout.assert_awaited_once_with("mgmt1", "domA")


async def test_create_dedicated_session_delegates_to_login_coordinator():
    login_coordinator = AsyncMock()
    login_coordinator.create_dedicated_session.return_value = ("sid-ded", "10.0.0.1")
    client, _, _, _, _ = _make_client(login_coordinator=login_coordinator)

    result = await client.create_dedicated_session("mgmt1", domain="domA", session_name="n", session_description="d")

    assert result == ("sid-ded", "10.0.0.1")
    login_coordinator.create_dedicated_session.assert_awaited_once_with(
        "mgmt1", "domA", session_name="n", session_description="d"
    )


# --------------------------------------------------------------------------
# get_server: metadata fetch-and-cache behavior
# --------------------------------------------------------------------------


async def test_get_server_returns_none_when_not_in_registry():
    registry = MagicMock()
    registry.get_server.return_value = None
    client, _, _, _, _ = _make_client(registry=registry)

    assert await client.get_server("ghost") is None


async def test_get_server_skips_metadata_fetch_when_already_populated():
    server = ServerConfig(name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"), is_mdm=True, version="1.9")
    registry = MagicMock()
    registry.get_server.return_value = server
    client, _, _, _, _ = _make_client(registry=registry)
    client.api_call = AsyncMock()

    result = await client.get_server("mgmt1")

    assert result is server
    client.api_call.assert_not_called()


async def test_get_server_fetches_version_and_mdm_status_when_missing():
    server = ServerConfig(name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"))
    registry = MagicMock()
    registry.get_server.return_value = server
    registry.update_metadata = AsyncMock()

    client, _, _, _, _ = _make_client(registry=registry)

    async def fake_api_call(mgmt_name, command, **kwargs):
        if command == "show-api-versions":
            return {"success": True, "data": {"current-version": "1.9.1"}}
        if command == "show-domains":
            return {"success": True, "data": {"objects": [{"name": "domainA"}]}}
        raise AssertionError(f"unexpected command {command}")

    client.api_call = AsyncMock(side_effect=fake_api_call)

    result = await client.get_server("mgmt1")

    registry.update_metadata.assert_awaited_once_with("mgmt1", is_mdm=True, version="1.9.1")
    assert result is server


async def test_get_server_treats_empty_domains_response_as_not_mdm():
    server = ServerConfig(name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"))
    registry = MagicMock()
    registry.get_server.return_value = server
    registry.update_metadata = AsyncMock()
    client, _, _, _, _ = _make_client(registry=registry)

    async def fake_api_call(mgmt_name, command, **kwargs):
        if command == "show-api-versions":
            return {"success": True, "data": {"current-version": "1.9"}}
        if command == "show-domains":
            return {"success": True, "data": {"objects": []}}
        raise AssertionError

    client.api_call = AsyncMock(side_effect=fake_api_call)
    await client.get_server("mgmt1")

    registry.update_metadata.assert_awaited_once_with("mgmt1", is_mdm=False, version="1.9")


async def test_get_server_detects_mdm_via_list_response():
    server = ServerConfig(name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"))
    registry = MagicMock()
    registry.get_server.return_value = server
    registry.update_metadata = AsyncMock()
    client, _, _, _, _ = _make_client(registry=registry)

    async def fake_api_call(mgmt_name, command, **kwargs):
        if command == "show-api-versions":
            return {"success": True, "data": {"current-version": "1.9"}}
        if command == "show-domains":
            return {"success": True, "data": [{"name": "domainA"}]}
        raise AssertionError

    client.api_call = AsyncMock(side_effect=fake_api_call)
    await client.get_server("mgmt1")

    registry.update_metadata.assert_awaited_once_with("mgmt1", is_mdm=True, version="1.9")


async def test_get_server_command_not_found_means_not_mdm():
    server = ServerConfig(name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"))
    registry = MagicMock()
    registry.get_server.return_value = server
    registry.update_metadata = AsyncMock()
    client, _, _, _, _ = _make_client(registry=registry)

    async def fake_api_call(mgmt_name, command, **kwargs):
        if command == "show-api-versions":
            return {"success": False, "data": {}}
        if command == "show-domains":
            return {"success": False, "code": "generic_err_command_not_found"}
        raise AssertionError

    client.api_call = AsyncMock(side_effect=fake_api_call)
    await client.get_server("mgmt1")

    registry.update_metadata.assert_awaited_once_with("mgmt1", is_mdm=False, version=None)


# --------------------------------------------------------------------------
# api_call / api_query: session-management + retry via _execute_with_retry
# --------------------------------------------------------------------------


async def test_api_call_success_on_first_attempt_no_retry():
    login_coordinator = AsyncMock()
    login_coordinator.login.return_value = ("sid-1", "10.0.0.1")
    transport = AsyncMock()
    transport.api_call.return_value = {"success": True, "data": {}, "message": "", "code": ""}
    registry = MagicMock()
    registry.get_server.return_value = ServerConfig(
        name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"), port=4434
    )

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    result = await client.api_call("mgmt1", "show-hosts", payload={"limit": 1}, details_level="full")
    await client.close()

    assert result["success"] is True
    login_coordinator.login.assert_awaited_once_with(
        "mgmt1",
        "",
        force=False,
        refresh_domain_ip=False,
        cache_mode="auto",
        session_name=None,
        session_description=None,
    )
    transport.api_call.assert_awaited_once_with(
        server_ip="10.0.0.1",
        sid="sid-1",
        command="show-hosts",
        payload={"limit": 1, "details-level": "full"},
        wait_for_task=True,
        timeout=-1,
        task_timeout=-1,
        port=4434,
    )


async def test_api_call_retries_once_on_session_error_code():
    session_error_code = next(iter(SESSION_ERROR_CODES))
    login_coordinator = AsyncMock()
    login_coordinator.login.side_effect = [("sid-1", "10.0.0.1"), ("sid-2", "10.0.0.1")]
    transport = AsyncMock()
    transport.api_call.side_effect = [
        {"success": False, "data": {}, "message": "expired", "code": session_error_code},
        {"success": True, "data": {}, "message": "", "code": ""},
    ]
    registry = MagicMock()
    registry.get_server.return_value = None

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    result = await client.api_call("mgmt1", "show-hosts")
    await client.close()

    assert result["success"] is True
    assert login_coordinator.login.await_count == 2
    assert transport.api_call.await_count == 2
    second_call_kwargs = login_coordinator.login.await_args_list[1].kwargs
    assert second_call_kwargs["force"] is True


async def test_api_call_retries_on_failover_code_only_when_domain_set():
    failover_code = next(iter(FAILOVER_ERROR_CODES))
    login_coordinator = AsyncMock()
    login_coordinator.login.side_effect = [("sid-1", "10.0.0.1"), ("sid-2", "10.0.0.2")]
    transport = AsyncMock()
    transport.api_call.side_effect = [
        {"success": False, "data": {}, "message": "no perm", "code": failover_code},
        {"success": True, "data": {}, "message": "", "code": ""},
    ]
    registry = MagicMock()
    registry.get_server.return_value = None

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    result = await client.api_call("mgmt1", "show-hosts", domain="domA")
    await client.close()

    assert result["success"] is True
    assert login_coordinator.login.await_count == 2
    second_call_kwargs = login_coordinator.login.await_args_list[1].kwargs
    assert second_call_kwargs["refresh_domain_ip"] is True


async def test_api_call_does_not_retry_failover_code_without_domain():
    """Failover codes only trigger a retry when a domain is set (system-domain calls don't)."""
    failover_code = next(iter(FAILOVER_ERROR_CODES))
    login_coordinator = AsyncMock()
    login_coordinator.login.return_value = ("sid-1", "10.0.0.1")
    transport = AsyncMock()
    transport.api_call.return_value = {"success": False, "data": {}, "message": "no perm", "code": failover_code}
    registry = MagicMock()
    registry.get_server.return_value = None

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    result = await client.api_call("mgmt1", "show-hosts", domain="")
    await client.close()

    assert result["success"] is False
    login_coordinator.login.assert_awaited_once()
    transport.api_call.assert_awaited_once()


async def test_api_call_stops_after_max_attempts_even_if_still_failing():
    session_error_code = next(iter(SESSION_ERROR_CODES))
    login_coordinator = AsyncMock()
    login_coordinator.login.side_effect = [("sid-1", "10.0.0.1"), ("sid-2", "10.0.0.1")]
    transport = AsyncMock()
    transport.api_call.side_effect = [
        {"success": False, "data": {}, "message": "expired", "code": session_error_code},
        {"success": False, "data": {}, "message": "expired again", "code": session_error_code},
    ]
    registry = MagicMock()
    registry.get_server.return_value = None

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    result = await client.api_call("mgmt1", "show-hosts")
    await client.close()

    assert result["success"] is False
    assert transport.api_call.await_count == 2
    assert login_coordinator.login.await_count == 2


async def test_api_call_spawns_background_keepalive_task():
    login_coordinator = AsyncMock()
    login_coordinator.login.return_value = ("sid-1", "10.0.0.1")
    login_coordinator._credential_username = "svc-user"
    transport = AsyncMock()
    transport.api_call.return_value = {"success": True, "data": {}, "message": "", "code": ""}
    registry = MagicMock()
    registry.get_server.return_value = None

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    await client.api_call("mgmt1", "show-hosts", domain="domA")
    assert len(client._background_tasks) == 1

    # Let the background task actually run before it gets cancelled by close().
    await asyncio.sleep(0)

    await client.close()
    login_coordinator.maintain_keepalives.assert_awaited_once_with(exclude_key="mgmt1:domA:svc-user")


def _page(start: int, count: int, total: int) -> dict:
    items = [{"uid": f"u{start + i}"} for i in range(count)]
    return {
        "success": True,
        "data": {"objects": items, "from": start + 1, "to": start + count, "total": total},
        "message": "",
        "code": "",
    }


def _query_client(transport):
    login_coordinator = AsyncMock()
    login_coordinator.login.return_value = ("sid-1", "192.168.5.184")
    login_coordinator.mds_host = AsyncMock(return_value="192.168.5.170")
    registry = MagicMock()
    registry.get_server.return_value = None
    return _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)


async def test_api_query_reads_every_page_with_its_own_call():
    transport = AsyncMock()
    transport.api_call.side_effect = [_page(0, 300, 650), _page(300, 300, 650), _page(600, 50, 650)]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query("mgmt1", "show-hosts", details_level="full", payload={"filter": "x"})
    await client.close()

    assert result["success"] is True
    assert len(result["data"]) == 650
    calls = transport.api_call.await_args_list
    assert [c.kwargs["payload"] for c in calls] == [
        {"filter": "x", "limit": 300, "offset": 0, "details-level": "full"},
        {"filter": "x", "limit": 300, "offset": 300, "details-level": "full"},
        {"filter": "x", "limit": 300, "offset": 600, "details-level": "full"},
    ]
    assert all(c.kwargs["command"] == "show-hosts" for c in calls)
    assert all(c.kwargs["wait_for_task"] is False for c in calls)
    assert all(c.kwargs["server_ip"] == "192.168.5.184" for c in calls)


async def test_each_page_takes_and_releases_the_members_slot():
    transport = AsyncMock()
    transport.api_call.side_effect = [_page(0, 300, 400), _page(300, 100, 400)]
    client, _, _, limiter, _ = _query_client(transport)

    await client.api_query("home", "show-hosts", domain="Domain4")
    await client.close()

    assert [c.args[0] for c in limiter.acquire.call_args_list] == ["192.168.5.170", "192.168.5.170"]
    assert limiter.acquire.return_value.__aexit__.await_count == 2  # released after each page


async def test_a_session_error_mid_listing_retries_that_page_only():
    session_error_code = next(iter(SESSION_ERROR_CODES))
    transport = AsyncMock()
    transport.api_call.side_effect = [
        _page(0, 300, 700),
        _page(300, 300, 700),
        {"success": False, "data": None, "message": "expired", "code": session_error_code},
        _page(600, 100, 700),
    ]
    client, _, _, _, lc = _query_client(transport)

    result = await client.api_query("mgmt1", "show-hosts")
    await client.close()

    assert result["success"] is True
    assert [c.kwargs["payload"]["offset"] for c in transport.api_call.await_args_list] == [0, 300, 600, 600]
    assert [c.kwargs["force"] for c in lc.login.await_args_list] == [False, False, False, True]


@pytest.mark.parametrize(
    ("given", "sent"),
    [({}, 300), ({"limit": 50}, 50), ({"limit": 900}, 500), ({"limit": 0}, 300), ({"limit": -5}, 300)],
)
async def test_page_size_defaults_to_300_honours_the_callers_limit_and_caps_at_500(given, sent):
    transport = AsyncMock()
    transport.api_call.return_value = _page(0, 1, 1)
    client, _, _, _, _ = _query_client(transport)

    await client.api_query("mgmt1", "show-hosts", payload=given)
    await client.close()

    assert transport.api_call.await_args.kwargs["payload"]["limit"] == sent


async def test_the_slot_is_released_before_the_next_page_is_requested():
    events: list[str] = []
    limiter = MagicMock()

    async def _enter(*_):
        events.append("enter")

    async def _exit(*_):
        events.append("exit")
        return False

    limiter.acquire.return_value.__aenter__ = _enter
    limiter.acquire.return_value.__aexit__ = _exit
    pages = [_page(0, 300, 400), _page(300, 100, 400)]

    async def _api_call(**_):
        events.append("call")
        return pages.pop(0)

    transport = AsyncMock()
    transport.api_call.side_effect = _api_call
    client, *_ = _query_client(transport)
    client._rate_limiter = limiter

    await client.api_query("mgmt1", "show-hosts")
    await client.close()

    assert events == ["enter", "call", "exit", "enter", "call", "exit"]


async def test_the_callers_payload_is_not_mutated():
    transport = AsyncMock()
    transport.api_call.side_effect = [_page(5, 300, 400), _page(305, 95, 400)]
    client, _, _, _, _ = _query_client(transport)
    payload = {"limit": 300, "offset": 5, "filter": "web"}

    await client.api_query("mgmt1", "show-hosts", payload=payload)
    await client.close()

    assert payload == {"limit": 300, "offset": 5, "filter": "web"}
    assert transport.api_call.await_args_list[0].kwargs["payload"]["offset"] == 5


@pytest.mark.parametrize(
    "error",
    [
        CertificateMismatchError(
            "certificate mismatch",
            host="192.168.5.184",
            port=443,
            presented_sha256="bb" * 32,
            expected_sha256="aa" * 32,
        ),
        ApiTimeoutError(
            "read timed out", phase="read", host="192.168.5.184", port=443, timeout=125, command="show-hosts"
        ),
    ],
)
async def test_identity_and_timeout_errors_on_a_page_propagate_without_a_retry(error):
    transport = AsyncMock()
    transport.api_call.side_effect = [_page(0, 300, 400), error]
    client, _, _, _, lc = _query_client(transport)

    with pytest.raises(type(error)):
        await client.api_query("mgmt1", "show-hosts")
    await client.close()

    assert transport.api_call.await_count == 2
    assert lc.login.await_count == 2  # one per page, no forced re-login


async def test_the_transport_has_no_api_query_any_more():
    from arodonata.asdk.transport import ApiTransport

    assert not hasattr(ApiTransport, "api_query")


# --------------------------------------------------------------------------
# api_call_with_sid: explicit-SID path bypasses login coordinator entirely
# --------------------------------------------------------------------------


async def test_api_call_with_sid_bypasses_login_coordinator():
    transport = AsyncMock()
    transport.api_call.return_value = {"success": True, "data": {}, "message": "", "code": ""}
    registry = MagicMock()
    registry.get_server.return_value = ServerConfig(
        name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"), port=4434
    )
    login_coordinator = AsyncMock()

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    result = await client.api_call_with_sid("mgmt1", "explicit-sid", "10.0.0.1", "publish", payload={"a": 1})

    assert result["success"] is True
    login_coordinator.login.assert_not_called()
    transport.api_call.assert_awaited_once_with(
        server_ip="10.0.0.1",
        sid="explicit-sid",
        command="publish",
        payload={"a": 1},
        wait_for_task=True,
        timeout=-1,
        task_timeout=-1,
        port=4434,
    )


async def test_explicit_sid_call_takes_the_members_slot_when_given_the_domain():
    client, registry, transport, limiter, lc = _make_client()
    registry.get_server.return_value = MagicMock(port=None)
    lc.mds_host = AsyncMock(return_value="192.168.5.170")
    transport.api_call.return_value = {"success": True, "data": {}}

    await client.api_call_with_sid("home", "sid", "192.168.5.184", "show-session", domain="Domain4")

    lc.mds_host.assert_awaited_once_with("home", "Domain4")
    limiter.acquire.assert_called_once_with("192.168.5.170")
    assert transport.api_call.await_args.kwargs["server_ip"] == "192.168.5.184"


async def test_explicit_sid_call_without_domain_resolves_the_member_by_server_ip():
    client, registry, transport, limiter, lc = _make_client()
    registry.get_server.return_value = MagicMock(port=None)
    lc.mds_host = AsyncMock()
    lc.mds_host_for_ip = AsyncMock(return_value="192.168.5.170")
    transport.api_call.return_value = {"success": True, "data": {}}

    await client.api_call_with_sid("home", "sid", "192.168.5.184", "show-session")

    lc.mds_host.assert_not_awaited()
    lc.mds_host_for_ip.assert_awaited_once_with("home", "192.168.5.184")
    limiter.acquire.assert_called_once_with("192.168.5.170")
    assert transport.api_call.await_args.kwargs["server_ip"] == "192.168.5.184"


async def test_api_call_with_sid_defaults_payload_and_port():
    transport = AsyncMock()
    transport.api_call.return_value = {"success": True, "data": {}, "message": "", "code": ""}
    registry = MagicMock()
    registry.get_server.return_value = None

    client, _, _, _, _ = _make_client(registry=registry, transport=transport)

    await client.api_call_with_sid("mgmt1", "sid-1", "10.0.0.1", "discard")

    transport.api_call.assert_awaited_once_with(
        server_ip="10.0.0.1",
        sid="sid-1",
        command="discard",
        payload={},
        wait_for_task=True,
        timeout=-1,
        task_timeout=-1,
        port=None,
    )


# --------------------------------------------------------------------------
# logout_sid
# --------------------------------------------------------------------------


async def test_logout_sid_returns_true_on_success():
    transport = AsyncMock()
    transport.logout.return_value = {"success": True}
    registry = MagicMock()
    registry.get_server.return_value = ServerConfig(
        name="mgmt1", server_ip="10.0.0.1", api_key=SecretStr("k"), port=4434
    )
    client, _, _, _, _ = _make_client(registry=registry, transport=transport)

    result = await client.logout_sid("sid-1", "10.0.0.1", mgmt_name="mgmt1")

    assert result is True
    transport.logout.assert_awaited_once_with("10.0.0.1", "sid-1", port=4434)


async def test_logout_sid_returns_false_on_unsuccessful_response():
    transport = AsyncMock()
    transport.logout.return_value = {"success": False}
    client, _, _, _, _ = _make_client(transport=transport)

    result = await client.logout_sid("sid-1", "10.0.0.1")

    assert result is False


async def test_logout_sid_returns_false_on_exception():
    transport = AsyncMock()
    transport.logout.side_effect = RuntimeError("network error")
    client, _, _, _, _ = _make_client(transport=transport)

    result = await client.logout_sid("sid-1", "10.0.0.1")

    assert result is False


async def test_logout_sid_without_mgmt_name_skips_registry_lookup():
    transport = AsyncMock()
    transport.logout.return_value = {"success": True}
    registry = MagicMock()
    client, _, _, _, _ = _make_client(registry=registry, transport=transport)

    await client.logout_sid("sid-1", "10.0.0.1")

    registry.get_server.assert_not_called()
    transport.logout.assert_awaited_once_with("10.0.0.1", "sid-1", port=None)


async def test_close_lets_a_short_background_sweep_finish_instead_of_cancelling_it():
    """A keepalive sweep cancelled mid-query is what made SQLAlchemy log CancelledError tracebacks."""
    client, _, _, _, _ = _make_client()
    finished = asyncio.Event()

    async def short_sweep():
        await asyncio.sleep(0.05)
        finished.set()

    task = asyncio.create_task(short_sweep())
    client._background_tasks.add(task)

    await client.close()

    assert finished.is_set()
    assert not task.cancelled()


# --------------------------------------------------------------------------
# Session calls: slot on the MDS member (mds_host), request to the domain server
# --------------------------------------------------------------------------


async def test_session_call_takes_the_members_slot_and_calls_the_domain_server():
    client, registry, transport, limiter, lc = _make_client()
    registry.get_server.return_value = MagicMock(port=None)
    lc.login = AsyncMock(return_value=("sid", "192.168.5.184"))
    lc.mds_host = AsyncMock(return_value="192.168.5.170")
    transport.api_call.return_value = {"success": True, "data": {}}

    await client.api_call("home", "show-hosts", domain="Domain4")

    lc.mds_host.assert_awaited_with("home", "Domain4")
    limiter.acquire.assert_called_once_with("192.168.5.170")
    assert transport.api_call.await_args.kwargs["server_ip"] == "192.168.5.184"


async def test_failover_retry_takes_the_slot_of_the_new_member():
    client, registry, transport, limiter, lc = _make_client()
    registry.get_server.return_value = MagicMock(port=None)
    lc.login = AsyncMock(side_effect=[("sid", "192.168.5.184"), ("sid2", "192.168.5.194")])
    lc.mds_host = AsyncMock(side_effect=["192.168.5.170", "192.168.5.171"])
    code = next(iter(FAILOVER_ERROR_CODES))
    transport.api_call.side_effect = [{"success": False, "code": code}, {"success": True, "data": {}}]

    await client.api_call("home", "show-hosts", domain="Domain4")

    assert [c.args[0] for c in limiter.acquire.call_args_list] == ["192.168.5.170", "192.168.5.171"]


# --------------------------------------------------------------------------- #
# show-*-rulebase through api_query: paged by rules (Backlog #43)              #
# --------------------------------------------------------------------------- #
# Check Point counts from/to/total in RULES for rulebase commands, and a section split by a page boundary comes back
# on the next page with the same uid. Recorded shape: FPCR on mdmPrime and Domain4 `FPCR_UAT_Active Network` on the
# home lab (5 sections, 6 rules, Section_4 holds rules 4 and 5).


def _rule(n: int, **kw) -> dict:
    return {"type": "access-rule", "uid": f"r{n}", "rule-number": n, **kw}


def _section(name: str, rules: list[dict]) -> dict:
    numbers = [r["rule-number"] for r in rules]
    return {
        "type": "access-section",
        "uid": f"s-{name}",
        "name": name,
        "from": min(numbers),
        "to": max(numbers),
        "rulebase": rules,
    }


def _rb_page(items: list[dict], start: int, end: int, total: int) -> dict:
    return {
        "success": True,
        "data": {"uid": "layer-1", "name": "Network", "rulebase": items, "from": start, "to": end, "total": total},
        "message": "",
        "code": "",
    }


def _rules_in(items: list[dict]) -> list[str]:
    out: list[str] = []
    for item in items:
        if item.get("type", "").endswith("-section"):
            out += _rules_in(item.get("rulebase", []))
        else:
            out.append(item["uid"])
    return out


_FIVE_SECTIONS_SIX_RULES = [
    _section("S1", [_rule(1)]),
    _section("S2", [_rule(2)]),
    _section("S3", [_rule(3)]),
    _section("S4", [_rule(4), _rule(5)]),
    _section("Cleanup", [_rule(6)]),
]


async def test_rulebase_on_one_page_counts_rules_not_sections():
    transport = AsyncMock()
    transport.api_call.side_effect = [_rb_page(_FIVE_SECTIONS_SIX_RULES, 1, 6, 6)]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-access-rulebase", payload={"name": "Network"}, container_key="rulebase"
    )
    await client.close()

    assert result["success"] is True, result
    assert [i["name"] for i in result["data"]] == ["S1", "S2", "S3", "S4", "Cleanup"]
    assert _rules_in(result["data"]) == ["r1", "r2", "r3", "r4", "r5", "r6"]
    assert [c.kwargs["payload"] for c in transport.api_call.await_args_list] == [
        {"name": "Network", "limit": 100, "offset": 0, "details-level": "standard"}
    ]


async def test_rulebase_section_split_by_a_page_boundary_comes_once_with_all_its_rules():
    transport = AsyncMock()
    transport.api_call.side_effect = [
        _rb_page([_section("S1", [_rule(1)]), _section("S2", [_rule(2)])], 1, 2, 6),
        _rb_page([_section("S3", [_rule(3)]), _section("S4", [_rule(4)])], 3, 4, 6),
        _rb_page([_section("S4", [_rule(5)]), _section("Cleanup", [_rule(6)])], 5, 6, 6),
        _rb_page([_section("Cleanup", [_rule(6)])], 6, 6, 6),  # a full last page: re-read for trailing empty sections
    ]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-access-rulebase", payload={"name": "Network", "limit": 2}, container_key="rulebase"
    )
    await client.close()

    assert result["success"] is True, result
    assert [i["name"] for i in result["data"]] == ["S1", "S2", "S3", "S4", "Cleanup"]
    section_4 = result["data"][3]
    assert [r["uid"] for r in section_4["rulebase"]] == ["r4", "r5"]
    assert (section_4["from"], section_4["to"]) == (4, 5)
    assert _rules_in(result["data"]) == ["r1", "r2", "r3", "r4", "r5", "r6"]
    assert [c.kwargs["payload"]["offset"] for c in transport.api_call.await_args_list] == [0, 2, 4, 5]
    assert all(c.kwargs["payload"]["limit"] == 2 for c in transport.api_call.await_args_list)


async def test_flat_rulebase_on_several_pages():
    transport = AsyncMock()
    transport.api_call.side_effect = [_rb_page([_rule(1), _rule(2)], 1, 2, 3), _rb_page([_rule(3)], 3, 3, 3)]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-nat-rulebase", payload={"package": "Std", "limit": 2}, container_key="rulebase"
    )
    await client.close()

    assert result["success"] is True, result
    assert _rules_in(result["data"]) == ["r1", "r2", "r3"]


async def test_place_holder_and_inline_layer_rules_count_as_rules():
    items = [
        {"type": "place-holder", "uid": "p1", "rule-number": 1},
        _rule(2, action="Inner Layer", **{"inline-layer": "layer-2"}),
    ]
    transport = AsyncMock()
    transport.api_call.side_effect = [_rb_page(items, 1, 2, 2)]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-access-rulebase", payload={"uid": "layer-1"}, container_key="rulebase"
    )
    await client.close()

    assert result["success"] is True, result
    assert [i["uid"] for i in result["data"]] == ["p1", "r2"]


async def test_rulebase_that_changes_between_pages_restarts_once_then_fails():
    first = _rb_page([_section("S1", [_rule(1)]), _section("S2", [_rule(2)])], 1, 2, 6)
    grown = _rb_page([_section("S3", [_rule(3)]), _section("S4", [_rule(4)])], 3, 4, 7)
    transport = AsyncMock()
    transport.api_call.side_effect = [first, grown, first, grown]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-access-rulebase", payload={"name": "Network", "limit": 2}, container_key="rulebase"
    )
    await client.close()

    assert result["success"] is False
    assert result["code"] == "paging_inconsistent"
    assert "show-access-rulebase" in result["message"]
    assert transport.api_call.await_count == 4  # one restart


async def test_rulebase_failed_page_returns_its_code_without_a_restart():
    transport = AsyncMock()
    transport.api_call.side_effect = [
        {
            "success": False,
            "data": None,
            "message": "Requested object [x] not found",
            "code": "generic_err_object_not_found",
        }
    ]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query("mgmt1", "show-access-rulebase", payload={"name": "x"}, container_key="rulebase")
    await client.close()

    assert result["success"] is False
    assert result["code"] == "generic_err_object_not_found"
    assert transport.api_call.await_count == 1


async def test_rulebase_from_a_callers_offset():
    transport = AsyncMock()
    transport.api_call.side_effect = [
        _rb_page([_section("S3", [_rule(3)]), _section("S4", [_rule(4)])], 3, 4, 6),
        _rb_page([_section("S4", [_rule(5)]), _section("Cleanup", [_rule(6)])], 5, 6, 6),
        _rb_page([_section("Cleanup", [_rule(6)])], 6, 6, 6),
    ]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-access-rulebase", payload={"name": "Network", "limit": 2, "offset": 2}, container_key="rulebase"
    )
    await client.close()

    assert result["success"] is True, result
    assert _rules_in(result["data"]) == ["r3", "r4", "r5", "r6"]
    assert [c.kwargs["payload"]["offset"] for c in transport.api_call.await_args_list] == [2, 4, 5]


async def test_rulebase_page_size_is_capped_at_100():
    transport = AsyncMock()
    transport.api_call.side_effect = [_rb_page([_rule(1)], 1, 1, 1)]
    client, _, _, _, _ = _query_client(transport)

    await client.api_query(
        "mgmt1", "show-threat-rulebase", payload={"uid": "l", "limit": 500}, container_key="rulebase"
    )
    await client.close()

    assert transport.api_call.await_args_list[0].kwargs["payload"]["limit"] == 100


async def test_rulebase_empty_layer_returns_no_entries():
    empty = {"success": True, "data": {"rulebase": [], "total": 0}, "message": "", "code": ""}
    transport = AsyncMock()
    transport.api_call.side_effect = [empty]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query("mgmt1", "show-access-rulebase", payload={"uid": "l"}, container_key="rulebase")
    await client.close()

    assert result == {"success": True, "data": [], "message": "", "code": ""}


async def test_rulebase_of_only_empty_sections_keeps_them():
    empty = [{"type": "access-section", "uid": "s-a", "name": "A", "rulebase": []}]
    transport = AsyncMock()
    transport.api_call.side_effect = [
        {"success": True, "data": {"rulebase": empty, "total": 0}, "message": "", "code": ""}
    ]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query("mgmt1", "show-access-rulebase", payload={"uid": "l"}, container_key="rulebase")
    await client.close()

    assert result["success"] is True
    assert [i["name"] for i in result["data"]] == ["A"]


@pytest.mark.parametrize("limit", [1, 2])
async def test_rulebase_keeps_trailing_empty_sections_after_a_full_last_page(limit):
    """Check Point leaves trailing empty sections out of a full last page; the re-read must have room for them."""
    tail = {"type": "access-section", "uid": "s-tail", "name": "Tail", "rulebase": []}
    pages = (
        [_rb_page([_rule(1)], 1, 1, 2), _rb_page([_rule(2)], 2, 2, 2)]
        if limit == 1
        else [_rb_page([_rule(1), _rule(2)], 1, 2, 2)]
    )

    async def answer(**kwargs):
        payload = kwargs["payload"]
        if payload["offset"] == 1 and payload["limit"] >= 2:  # the trailing re-read, with room on the page
            return _rb_page([_rule(2), tail], 2, 2, 2)
        return pages.pop(0)

    transport = AsyncMock()
    transport.api_call.side_effect = answer
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-access-rulebase", payload={"uid": "l", "limit": limit}, container_key="rulebase"
    )
    await client.close()

    assert result["success"] is True, result
    assert [i["uid"] for i in result["data"]] == ["r1", "r2", "s-tail"]


async def test_rulebase_offset_past_the_end_returns_no_entries():
    transport = AsyncMock()
    transport.api_call.side_effect = [
        {"success": True, "data": {"rulebase": [], "total": 3}, "message": "", "code": ""}
    ]
    client, _, _, _, _ = _query_client(transport)

    result = await client.api_query(
        "mgmt1", "show-access-rulebase", payload={"uid": "l", "offset": 5}, container_key="rulebase"
    )
    await client.close()

    assert result == {"success": True, "data": [], "message": "", "code": ""}
    assert transport.api_call.await_count == 1
