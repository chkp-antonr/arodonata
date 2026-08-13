"""Unit tests for AMgmtClient: facade delegation, retry/session-error handling, and lifecycle."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import SecretStr

from arodonata.asdk.client import AMgmtClient
from arodonata.asdk.server_registry import ServerConfig
from arodonata.config import FAILOVER_ERROR_CODES, SESSION_ERROR_CODES


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


async def test_api_query_delegates_to_transport_api_query():
    login_coordinator = AsyncMock()
    login_coordinator.login.return_value = ("sid-1", "10.0.0.1")
    transport = AsyncMock()
    transport.api_query.return_value = {"success": True, "data": {"objects": []}, "message": "", "code": ""}
    registry = MagicMock()
    registry.get_server.return_value = None

    client, _, _, _, _ = _make_client(registry=registry, transport=transport, login_coordinator=login_coordinator)

    result = await client.api_query("mgmt1", "show-hosts", details_level="full", container_key="objects")
    await client.close()

    assert result["success"] is True
    transport.api_query.assert_awaited_once_with(
        server_ip="10.0.0.1",
        sid="sid-1",
        command="show-hosts",
        details_level="full",
        payload={},
        container_key="objects",
        port=None,
    )


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
        port=4434,
    )


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
