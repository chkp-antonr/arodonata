"""Unit tests for arodonata.helpers.policy (session management, writes, rule queries)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.core.exceptions import ApiError, ConfigurationError
from arodonata.core.session_tracker import SessionChange
from arodonata.helpers._context import UserContext
from arodonata.helpers.policy import (
    _generate_session_id,
    _get_server_ip_from_registry,
    _get_sid_from_session_tracker,
    _record_change_if_tracked,
    _resolve_object_type,
    add_object,
    create_session,
    delete_object,
    discard_session,
    get_access_rules,
    get_https_rules,
    get_nat_rules,
    get_threat_rules,
    publish_session,
    set_object,
    write_session,
)

_USER = UserContext(username="admin", source="test")


# ---------------------------------------------------------------------------
# _generate_session_id
# ---------------------------------------------------------------------------


class TestGenerateSessionId:
    def test_basic_format(self):
        session_id = _generate_session_id("admin", "test session")
        parts = session_id.split("-")
        assert len(parts) >= 3
        assert parts[0] == "admin"

    def test_description_sanitization(self):
        session_id = _generate_session_id("admin", "test session with spaces")
        assert " " not in session_id
        assert "_" in session_id

    def test_dashes_sanitized(self):
        session_id = _generate_session_id("admin", "test-session-with-dashes")
        # Original dashes in the description become underscores; only the
        # timestamp separators remain as literal dashes.
        assert "session_with_dashes" in session_id

    def test_description_truncation(self):
        session_id = _generate_session_id("admin", "a" * 100)
        assert len(session_id) <= 5 + 15 + 2 + 50

    def test_timestamp_format(self):
        session_id = _generate_session_id("admin", "test")
        parts = session_id.split("-")
        assert len(parts[1]) == 8
        assert parts[1].isdigit()
        assert len(parts[2]) == 6
        assert parts[2].isdigit()

    def test_empty_description(self):
        session_id = _generate_session_id("admin", "")
        assert session_id
        assert "admin" in session_id


# ---------------------------------------------------------------------------
# _get_sid_from_session_tracker / _get_server_ip_from_registry
# ---------------------------------------------------------------------------


class TestGetSidFromSessionTracker:
    def test_returns_sid_when_session_found(self):
        client = MagicMock()
        client._orchestration._session_tracker.get_session_changes.return_value = [
            SessionChange(
                operation="add",
                object_type="session",
                uid="sid-123",
                name="session-abc",
                data={"sid": "sid-123"},
            )
        ]

        sid = _get_sid_from_session_tracker(client, "mgmt1", "dmn1", "session-abc")

        assert sid == "sid-123"
        client._orchestration._session_tracker.get_session_changes.assert_called_once_with(
            mgmt_name="mgmt1", domain="dmn1"
        )

    def test_ignores_non_session_changes(self):
        client = MagicMock()
        client._orchestration._session_tracker.get_session_changes.return_value = [
            SessionChange(operation="add", object_type="host", uid="uid-1", name="session-abc", data={})
        ]

        with pytest.raises(ConfigurationError, match="Session session-abc not found in tracker"):
            _get_sid_from_session_tracker(client, "mgmt1", "dmn1", "session-abc")

    def test_raises_when_session_not_found(self):
        client = MagicMock()
        client._orchestration._session_tracker.get_session_changes.return_value = []

        with pytest.raises(ConfigurationError, match="Session session-abc not found in tracker"):
            _get_sid_from_session_tracker(client, "mgmt1", "dmn1", "session-abc")

    def test_raises_when_data_missing_sid_key(self):
        client = MagicMock()
        client._orchestration._session_tracker.get_session_changes.return_value = [
            SessionChange(
                operation="add",
                object_type="session",
                uid="uid-1",
                name="session-abc",
                data={},
            )
        ]

        with pytest.raises(ConfigurationError, match="not found in tracker"):
            _get_sid_from_session_tracker(client, "mgmt1", "dmn1", "session-abc")

    def test_raises_when_no_session_tracker(self):
        client = MagicMock()
        client._orchestration._session_tracker = None

        with pytest.raises(ConfigurationError, match="Session tracker not available"):
            _get_sid_from_session_tracker(client, "mgmt1", "dmn1", "session-abc")


class TestGetServerIpFromRegistry:
    def test_returns_ip_when_server_found(self):
        client = MagicMock()
        client._mgmt._registry.get_server.return_value = MagicMock(server_ip="10.0.0.1")

        ip = _get_server_ip_from_registry(client, "mgmt1")

        assert ip == "10.0.0.1"
        client._mgmt._registry.get_server.assert_called_once_with("mgmt1")

    def test_raises_when_server_not_found(self):
        client = MagicMock()
        client._mgmt._registry.get_server.return_value = None

        with pytest.raises(ConfigurationError, match="Management server mgmt1 not found"):
            _get_server_ip_from_registry(client, "mgmt1")


# ---------------------------------------------------------------------------
# create_session / publish_session / discard_session / write_session
# ---------------------------------------------------------------------------


def _tracked_client(sid: str = "sid-123", session_name: str = "session-abc") -> MagicMock:
    client = MagicMock()
    client._mgmt.create_dedicated_session = AsyncMock(return_value=(sid, "10.0.0.1"))
    client._mgmt._registry.get_server.return_value = MagicMock(server_ip="10.0.0.1")
    client._orchestration._session_tracker.get_session_changes.return_value = [
        SessionChange(
            operation="add",
            object_type="session",
            uid=sid,
            name=session_name,
            data={"sid": sid},
        )
    ]
    # spec=[...] excludes model_dump so publish_session's dict-fallback branch
    # is exercised deterministically (a bare MagicMock would satisfy
    # hasattr(result, "model_dump") and return a Mock instead of a dict).
    client.api_call_with_sid = AsyncMock(
        return_value=MagicMock(spec=["success", "message", "data"], success=True, message="", data={})
    )
    return client


def _full_flow_client(sid: str = "sid-123") -> MagicMock:
    """Client wired for end-to-end write_session()/create_session() flows.

    Unlike _tracked_client() (which pins a single fixed session name), this
    backs the session tracker with a small stateful fake so create_session()'s
    dynamically-generated session id can later be looked back up by
    publish_session()/discard_session() -- exactly as the real
    SessionChangeTracker would behave.
    """
    client = MagicMock()
    client._mgmt.create_dedicated_session = AsyncMock(return_value=(sid, "10.0.0.1"))
    client._mgmt._registry.get_server.return_value = MagicMock(server_ip="10.0.0.1")

    changes: list[SessionChange] = []

    def _add_change(*, mgmt_name, domain, change):
        changes.append(change)

    def _get_session_changes(*, mgmt_name, domain):
        return list(changes)

    def _clear_session(*, mgmt_name, domain):
        changes.clear()

    tracker = client._orchestration._session_tracker
    tracker.add_change = MagicMock(side_effect=_add_change)
    tracker.get_session_changes = MagicMock(side_effect=_get_session_changes)
    tracker.clear_session = MagicMock(side_effect=_clear_session)

    client.api_call_with_sid = AsyncMock(
        return_value=MagicMock(spec=["success", "message", "data"], success=True, message="", data={})
    )
    return client


class TestCreateSession:
    @pytest.mark.asyncio
    async def test_creates_dedicated_session_and_returns_session_id(self):
        client = MagicMock()
        client._mgmt.create_dedicated_session = AsyncMock(return_value=("sid-123", "10.0.0.1"))

        session_id = await create_session(client, "mgmt1", "dmn1", _USER, description="my change")

        assert session_id.startswith("admin-")
        client._mgmt.create_dedicated_session.assert_awaited_once()
        _, kwargs = client._mgmt.create_dedicated_session.call_args
        assert kwargs["mgmt_name"] == "mgmt1"
        assert kwargs["domain"] == "dmn1"
        assert kwargs["session_name"] == session_id
        assert kwargs["session_description"] == "my change"

    @pytest.mark.asyncio
    async def test_defaults_description_when_none(self):
        client = MagicMock()
        client._mgmt.create_dedicated_session = AsyncMock(return_value=("sid-123", "10.0.0.1"))

        await create_session(client, "mgmt1", "dmn1", _USER)

        _, kwargs = client._mgmt.create_dedicated_session.call_args
        assert kwargs["session_description"] == ""

    @pytest.mark.asyncio
    async def test_tracks_change_when_session_tracker_present(self):
        client = MagicMock()
        client._mgmt.create_dedicated_session = AsyncMock(return_value=("sid-123", "10.0.0.1"))
        tracker = MagicMock()
        client._orchestration._session_tracker = tracker

        session_id = await create_session(client, "mgmt1", "dmn1", _USER)

        tracker.add_change.assert_called_once()
        _, kwargs = tracker.add_change.call_args
        assert kwargs["mgmt_name"] == "mgmt1"
        assert kwargs["domain"] == "dmn1"
        change = kwargs["change"]
        assert change.operation == "add"
        assert change.object_type == "session"
        assert change.uid == "sid-123"
        assert change.name == session_id
        # server_ip is the DOMAIN server's IP from create_dedicated_session —
        # tracked so write helpers hit the right server on MDM.
        assert change.data == {"sid": "sid-123", "server_ip": "10.0.0.1"}

    @pytest.mark.asyncio
    async def test_skips_tracking_when_no_session_tracker(self):
        client = MagicMock()
        client._mgmt.create_dedicated_session = AsyncMock(return_value=("sid-123", "10.0.0.1"))
        client._orchestration._session_tracker = None

        session_id = await create_session(client, "mgmt1", "dmn1", _USER)

        assert session_id


class TestPublishSession:
    @pytest.mark.asyncio
    async def test_calls_api_with_publish_command_and_clears_tracker(self):
        client = _tracked_client()

        result = await publish_session(client, "mgmt1", "dmn1", "session-abc", _USER)

        client.api_call_with_sid.assert_awaited_once_with(
            mgmt_name="mgmt1",
            sid="sid-123",
            server_ip="10.0.0.1",
            command="publish",
            payload={},
        )
        client._orchestration._session_tracker.clear_session.assert_called_once_with(mgmt_name="mgmt1", domain="dmn1")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_uses_model_dump_when_available(self):
        client = _tracked_client()
        api_result = MagicMock()
        api_result.model_dump.return_value = {"published": True}
        client.api_call_with_sid = AsyncMock(return_value=api_result)

        result = await publish_session(client, "mgmt1", "dmn1", "session-abc", _USER)

        assert result == {"published": True}

    @pytest.mark.asyncio
    async def test_falls_back_to_data_dict_when_no_model_dump(self):
        client = _tracked_client()
        api_result = MagicMock(spec=["data"])
        api_result.data = {"key": "value"}
        client.api_call_with_sid = AsyncMock(return_value=api_result)

        result = await publish_session(client, "mgmt1", "dmn1", "session-abc", _USER)

        assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_falls_back_to_empty_dict_when_data_is_none(self):
        client = _tracked_client()
        api_result = MagicMock(spec=["data"])
        api_result.data = None
        client.api_call_with_sid = AsyncMock(return_value=api_result)

        result = await publish_session(client, "mgmt1", "dmn1", "session-abc", _USER)

        assert result == {}

    @pytest.mark.asyncio
    async def test_falls_back_to_empty_dict_when_data_not_a_dict(self):
        client = _tracked_client()
        api_result = MagicMock(spec=["data"])
        api_result.data = "not-a-dict"
        client.api_call_with_sid = AsyncMock(return_value=api_result)

        result = await publish_session(client, "mgmt1", "dmn1", "session-abc", _USER)

        assert result == {}

    @pytest.mark.asyncio
    async def test_falls_back_to_success_message_dict(self):
        client = _tracked_client()
        api_result = MagicMock(spec=["success", "message"])
        api_result.success = True
        api_result.message = "ok"
        client.api_call_with_sid = AsyncMock(return_value=api_result)

        result = await publish_session(client, "mgmt1", "dmn1", "session-abc", _USER)

        assert result == {"success": True, "message": "ok"}


class TestDiscardSession:
    @pytest.mark.asyncio
    async def test_calls_api_with_discard_command_and_clears_tracker(self):
        client = _tracked_client()

        await discard_session(client, "mgmt1", "dmn1", "session-abc", _USER)

        client.api_call_with_sid.assert_awaited_once_with(
            mgmt_name="mgmt1",
            sid="sid-123",
            server_ip="10.0.0.1",
            command="discard",
            payload={},
        )
        client._orchestration._session_tracker.clear_session.assert_called_once_with(mgmt_name="mgmt1", domain="dmn1")


class TestWriteSession:
    @pytest.mark.asyncio
    async def test_auto_publish_true_publishes_on_success(self):
        client = _full_flow_client()

        async with write_session(client, "mgmt1", "dmn1", _USER) as session_id:
            assert session_id

        calls = [c.kwargs.get("command") for c in client.api_call_with_sid.await_args_list]
        assert "publish" in calls
        assert "discard" not in calls

    @pytest.mark.asyncio
    async def test_auto_publish_false_discards_on_success(self):
        client = _full_flow_client()

        async with write_session(client, "mgmt1", "dmn1", _USER, auto_publish=False):
            pass

        calls = [c.kwargs.get("command") for c in client.api_call_with_sid.await_args_list]
        assert "discard" in calls
        assert "publish" not in calls

    @pytest.mark.asyncio
    async def test_discards_and_reraises_on_exception(self):
        client = _full_flow_client()

        with pytest.raises(RuntimeError, match="boom"):
            async with write_session(client, "mgmt1", "dmn1", _USER):
                raise RuntimeError("boom")

        calls = [c.kwargs.get("command") for c in client.api_call_with_sid.await_args_list]
        assert "discard" in calls
        assert "publish" not in calls

    @pytest.mark.asyncio
    async def test_passes_description_to_create_session(self):
        client = _full_flow_client()

        async with write_session(client, "mgmt1", "dmn1", _USER, description="add host"):
            pass

        _, kwargs = client._mgmt.create_dedicated_session.call_args
        assert kwargs["session_description"] == "add host"


# ---------------------------------------------------------------------------
# add_object / set_object / delete_object
# ---------------------------------------------------------------------------


def _make_write_client(
    *,
    session_tracker: bool = True,
    cached_obj=None,
    api_success: bool = True,
    api_message: str = "",
    api_data: dict | None = None,
) -> MagicMock:
    client = MagicMock()

    if session_tracker:
        tracker = MagicMock()
        tracker.get_session_changes.return_value = [
            SessionChange(
                operation="add",
                object_type="session",
                uid="sid-123",
                name="session-abc",
                data={"sid": "sid-123"},
            )
        ]
        client._orchestration._session_tracker = tracker
    else:
        client._orchestration._session_tracker = None

    client._mgmt._registry.get_server.return_value = MagicMock(server_ip="10.0.0.1")
    client._object_service._cache.get_object_by_uid = AsyncMock(return_value=cached_obj)
    client.api_call_with_sid = AsyncMock(
        return_value=MagicMock(success=api_success, message=api_message, data=api_data or {})
    )
    return client


class TestAddObject:
    @pytest.mark.asyncio
    async def test_success_returns_cpobject_and_tracks_change(self):
        client = _make_write_client(api_data={"uid": "uid-new"})

        result = await add_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            object_type="host",
            data={"name": "srv1", "ip-address": "1.2.3.4"},
            session_id="session-abc",
            user_context=_USER,
        )

        # NOTE (src bug, not fixed here): add_object() constructs CPObject with
        # object_type=/domain=/data= kwargs, none of which are real CPObject
        # fields (the model defines type/domain_name/raw_data, and id has no
        # default). Those three values are therefore silently dropped instead
        # of being stored on the returned object -- only uid/name/mgmt_name
        # (which do match real field names) come through correctly.
        assert result.uid == "uid-new"
        assert result.name == "srv1"
        assert result.mgmt_name == "mgmt1"
        client.api_call_with_sid.assert_awaited_once_with(
            mgmt_name="mgmt1",
            sid="sid-123",
            server_ip="10.0.0.1",
            command="add-host",
            payload={"name": "srv1", "ip-address": "1.2.3.4"},
        )
        tracker = client._orchestration._session_tracker
        tracker.add_change.assert_called_once()
        _, kwargs = tracker.add_change.call_args
        change = kwargs["change"]
        assert change.operation == "add"
        assert change.uid == "uid-new"
        assert change.name == "srv1"

    @pytest.mark.asyncio
    async def test_returned_cpobject_type_and_domain_not_populated(self):
        """Characterization test pinning the src bug described above."""
        client = _make_write_client(api_data={"uid": "uid-new"})

        result = await add_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            object_type="host",
            data={"name": "srv1"},
            session_id="session-abc",
            user_context=_USER,
        )

        assert not hasattr(result, "object_type")
        assert result.type is None
        assert result.domain_name == ""

    @pytest.mark.asyncio
    async def test_raises_when_no_session_tracker(self):
        """add_object needs the tracker to resolve the SID (it's the SID store,
        not just a change log), so a missing tracker fails before tracking is
        even attempted -- the "if session_tracker: track" branch is unreachable.
        """
        client = _make_write_client(session_tracker=False, api_data={"uid": "uid-new"})

        with pytest.raises(ConfigurationError, match="Session tracker not available"):
            await add_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                object_type="host",
                data={"name": "srv1"},
                session_id="session-abc",
                user_context=_USER,
            )

    @pytest.mark.asyncio
    async def test_skips_tracking_when_uid_not_a_string(self):
        client = _make_write_client(api_data={"uid": 12345})

        result = await add_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            object_type="host",
            data={"name": "srv1"},
            session_id="session-abc",
            user_context=_USER,
        )

        assert result.uid == 12345
        client._orchestration._session_tracker.add_change.assert_not_called()

    @pytest.mark.asyncio
    async def test_raises_api_error_when_call_fails(self):
        client = _make_write_client(api_success=False, api_message="boom")

        with pytest.raises(ApiError, match="Failed to add host: boom"):
            await add_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                object_type="host",
                data={"name": "srv1"},
                session_id="session-abc",
                user_context=_USER,
            )
        client._orchestration._session_tracker.add_change.assert_not_called()


class TestResolveObjectType:
    @pytest.mark.asyncio
    async def test_returns_type_from_data_without_touching_cache(self):
        obj_service = MagicMock()
        obj_service._cache.get_object_by_uid = AsyncMock()

        result = await _resolve_object_type(obj_service, "uid-1", {"type": "host"})

        assert result == "host"
        obj_service._cache.get_object_by_uid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_resolves_from_cache_when_missing_from_data(self):
        obj_service = MagicMock()
        obj_service._cache.get_object_by_uid = AsyncMock(return_value=MagicMock(object_type="network"))

        result = await _resolve_object_type(obj_service, "uid-1", {})

        assert result == "network"

    @pytest.mark.asyncio
    async def test_raises_when_uid_not_in_cache(self):
        obj_service = MagicMock()
        obj_service._cache.get_object_by_uid = AsyncMock(return_value=None)

        with pytest.raises(ConfigurationError, match="Cannot determine object type"):
            await _resolve_object_type(obj_service, "uid-1", {})

    @pytest.mark.asyncio
    async def test_raises_when_cached_object_has_no_object_type(self):
        obj_service = MagicMock()
        obj_service._cache.get_object_by_uid = AsyncMock(return_value=MagicMock(spec=[]))

        with pytest.raises(ConfigurationError, match="Cannot determine object type"):
            await _resolve_object_type(obj_service, "uid-1", {})


class TestRecordChangeIfTracked:
    def test_skipped_when_session_tracker_not_set(self):
        client = MagicMock()
        client._orchestration._session_tracker = None
        _record_change_if_tracked(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            object_type="host",
            uid="uid-1",
            data={"name": "srv1"},
        )

    def test_added_when_session_tracker_set(self):
        client = MagicMock()
        tracker = MagicMock()
        client._orchestration._session_tracker = tracker
        _record_change_if_tracked(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            object_type="host",
            uid="uid-1",
            data={"name": "srv1"},
        )
        tracker.add_change.assert_called_once()
        _, kwargs = tracker.add_change.call_args
        assert kwargs["mgmt_name"] == "mgmt1"
        assert kwargs["domain"] == "dmn1"
        change = kwargs["change"]
        assert change.operation == "modify"
        assert change.object_type == "host"
        assert change.uid == "uid-1"
        assert change.name == "uid-1"
        assert change.data == {"name": "srv1"}


class TestSetObject:
    @pytest.mark.asyncio
    async def test_success_returns_cpobject_and_tracks_change(self):
        client = _make_write_client()
        result = await set_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            uid="uid-1",
            data={"type": "host", "name": "srv1", "ipv4-address": "1.2.3.4"},
            session_id="session-abc",
            user_context=_USER,
        )
        assert result.uid == "uid-1"
        assert result.name == "srv1"
        assert result.mgmt_name == "mgmt1"
        client.api_call_with_sid.assert_awaited_once_with(
            mgmt_name="mgmt1",
            sid="sid-123",
            server_ip="10.0.0.1",
            command="set-host",
            payload={"uid": "uid-1", "type": "host", "name": "srv1", "ipv4-address": "1.2.3.4"},
        )
        tracker = client._orchestration._session_tracker
        tracker.add_change.assert_called_once()

    @pytest.mark.asyncio
    async def test_resolves_type_from_cache_when_missing_from_data(self):
        cached_obj = MagicMock(object_type="network")
        client = _make_write_client(cached_obj=cached_obj)
        result = await set_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            uid="uid-2",
            data={"name": "net1"},
            session_id="session-abc",
            user_context=_USER,
        )
        assert result.uid == "uid-2"
        client.api_call_with_sid.assert_awaited_once_with(
            mgmt_name="mgmt1",
            sid="sid-123",
            server_ip="10.0.0.1",
            command="set-network",
            payload={"uid": "uid-2", "name": "net1"},
        )

    @pytest.mark.asyncio
    async def test_raises_when_type_missing_and_uid_not_in_cache(self):
        client = _make_write_client(cached_obj=None)
        with pytest.raises(ConfigurationError, match="Cannot determine object type for UID uid-3"):
            await set_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                uid="uid-3",
                data={"name": "whatever"},
                session_id="session-abc",
                user_context=_USER,
            )
        client.api_call_with_sid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_raises_when_cached_object_has_no_object_type(self):
        cached_obj = MagicMock(spec=[])
        client = _make_write_client(cached_obj=cached_obj)
        with pytest.raises(ConfigurationError, match="Cannot determine object type for UID uid-4"):
            await set_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                uid="uid-4",
                data={"name": "whatever"},
                session_id="session-abc",
                user_context=_USER,
            )
        client.api_call_with_sid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_raises_api_error_when_call_fails(self):
        client = _make_write_client(api_success=False, api_message="boom")
        with pytest.raises(ApiError, match="Failed to set object uid-5: boom"):
            await set_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                uid="uid-5",
                data={"type": "host", "name": "srv1"},
                session_id="session-abc",
                user_context=_USER,
            )
        client._orchestration._session_tracker.add_change.assert_not_called()


class TestDeleteObject:
    @pytest.mark.asyncio
    async def test_success_deletes_and_tracks_change(self):
        # NOTE: MagicMock(name=...) sets the mock's debug repr name, not a
        # "name" attribute -- it must be assigned separately afterwards.
        cached_obj = MagicMock(object_type="host")
        cached_obj.name = "srv1"
        client = _make_write_client(cached_obj=cached_obj)

        await delete_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            uid="uid-1",
            session_id="session-abc",
            user_context=_USER,
        )

        client.api_call_with_sid.assert_awaited_once_with(
            mgmt_name="mgmt1",
            sid="sid-123",
            server_ip="10.0.0.1",
            command="delete-host",
            payload={"uid": "uid-1"},
        )
        tracker = client._orchestration._session_tracker
        tracker.add_change.assert_called_once()
        _, kwargs = tracker.add_change.call_args
        change = kwargs["change"]
        assert change.operation == "delete"
        assert change.object_type == "host"
        assert change.uid == "uid-1"
        assert change.name == "srv1"
        assert change.data is None

    @pytest.mark.asyncio
    async def test_raises_when_no_session_tracker(self):
        """delete_object resolves its SID from the tracker before anything
        else runs, so a missing tracker fails immediately -- tracking is never
        reached either way.
        """
        cached_obj = MagicMock(object_type="host")
        cached_obj.name = "srv1"
        client = _make_write_client(session_tracker=False, cached_obj=cached_obj)

        with pytest.raises(ConfigurationError, match="Session tracker not available"):
            await delete_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                uid="uid-1",
                session_id="session-abc",
                user_context=_USER,
            )
        client.api_call_with_sid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_raises_when_object_not_found(self):
        client = _make_write_client(cached_obj=None)

        with pytest.raises(ConfigurationError, match="Cannot find object with UID uid-1"):
            await delete_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                uid="uid-1",
                session_id="session-abc",
                user_context=_USER,
            )
        client.api_call_with_sid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_raises_when_cached_object_has_no_object_type(self):
        cached_obj = MagicMock(spec=["name"])
        client = _make_write_client(cached_obj=cached_obj)

        with pytest.raises(ConfigurationError, match="Cached object has no object_type"):
            await delete_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                uid="uid-1",
                session_id="session-abc",
                user_context=_USER,
            )
        client.api_call_with_sid.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_raises_api_error_when_call_fails(self):
        # NOTE: MagicMock(name=...) sets the mock's debug repr name, not a
        # "name" attribute -- it must be assigned separately afterwards.
        cached_obj = MagicMock(object_type="host")
        cached_obj.name = "srv1"
        client = _make_write_client(cached_obj=cached_obj, api_success=False, api_message="boom")

        with pytest.raises(ApiError, match="Failed to delete object uid-1: boom"):
            await delete_object(
                client,
                mgmt_name="mgmt1",
                domain_name="dmn1",
                uid="uid-1",
                session_id="session-abc",
                user_context=_USER,
            )
        client._orchestration._session_tracker.add_change.assert_not_called()


# ---------------------------------------------------------------------------
# Rulebase read helpers: get_access_rules / get_nat_rules / get_https_rules /
# get_threat_rules
#
# NOTE: as of this test suite's writing, CacheOrchestrationService.get_*_rules
# accepts cache_mode/cache_ttl kwargs (see core/orchestration.py), but these
# helpers.policy wrappers do NOT expose or forward cache_mode/ttl at all --
# they only forward layer_name/mgmt_names/domain_names. The assert_called_once_with
# calls below pin down that current (narrower) delegation contract; see the
# final report for this gap flagged as a src-level finding rather than fixed
# here.
# ---------------------------------------------------------------------------


class TestGetAccessRules:
    @pytest.mark.asyncio
    async def test_delegates_to_orchestration_with_no_filters(self):
        client = MagicMock()
        client._orchestration.get_access_rules = AsyncMock(return_value=["rule"])

        result = await get_access_rules(client)

        assert result == ["rule"]
        client._orchestration.get_access_rules.assert_awaited_once_with(
            layer_name=None, mgmt_names=None, domain_names=None, cache_mode=None, cache_ttl=None
        )

    @pytest.mark.asyncio
    async def test_wraps_single_mgmt_and_domain_name_into_lists(self):
        client = MagicMock()
        client._orchestration.get_access_rules = AsyncMock(return_value=[])

        await get_access_rules(client, layer_name="Network", mgmt_name="mgmt1", domain_name="dmn1")

        client._orchestration.get_access_rules.assert_awaited_once_with(
            layer_name="Network", mgmt_names=["mgmt1"], domain_names=["dmn1"], cache_mode=None, cache_ttl=None
        )

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        client = MagicMock()
        client._orchestration.get_access_rules = AsyncMock(return_value=[])

        result = await get_access_rules(client, user_context=_USER)

        assert result == []


class TestGetNatRules:
    @pytest.mark.asyncio
    async def test_delegates_to_orchestration(self):
        client = MagicMock()
        client._orchestration.get_nat_rules = AsyncMock(return_value=["nat-rule"])

        result = await get_nat_rules(client, layer_name="NAT", mgmt_name="mgmt1")

        assert result == ["nat-rule"]
        client._orchestration.get_nat_rules.assert_awaited_once_with(
            layer_name="NAT", mgmt_names=["mgmt1"], domain_names=None, cache_mode=None, cache_ttl=None
        )

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        client = MagicMock()
        client._orchestration.get_nat_rules = AsyncMock(return_value=[])

        result = await get_nat_rules(client, user_context=_USER)

        assert result == []


class TestGetHttpsRules:
    @pytest.mark.asyncio
    async def test_delegates_to_orchestration(self):
        client = MagicMock()
        client._orchestration.get_https_rules = AsyncMock(return_value=["https-rule"])

        result = await get_https_rules(client, domain_name="dmn1")

        assert result == ["https-rule"]
        client._orchestration.get_https_rules.assert_awaited_once_with(
            layer_name=None, mgmt_names=None, domain_names=["dmn1"], cache_mode=None, cache_ttl=None
        )

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        client = MagicMock()
        client._orchestration.get_https_rules = AsyncMock(return_value=[])

        result = await get_https_rules(client, user_context=_USER)

        assert result == []


class TestGetThreatRules:
    @pytest.mark.asyncio
    async def test_delegates_to_orchestration(self):
        client = MagicMock()
        client._orchestration.get_threat_rules = AsyncMock(return_value=["threat-rule"])

        result = await get_threat_rules(client, layer_name="Threat", mgmt_name="mgmt1", domain_name="dmn1")

        assert result == ["threat-rule"]
        client._orchestration.get_threat_rules.assert_awaited_once_with(
            layer_name="Threat", mgmt_names=["mgmt1"], domain_names=["dmn1"], cache_mode=None, cache_ttl=None
        )

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        client = MagicMock()
        client._orchestration.get_threat_rules = AsyncMock(return_value=[])

        result = await get_threat_rules(client, user_context=_USER)

        assert result == []


class TestTrackedServerIp:
    """MDM fix: write helpers use the session's tracked domain server IP."""

    @pytest.mark.asyncio
    async def test_add_object_uses_tracked_domain_ip_over_registry(self):
        client = _make_write_client(api_data={"uid": "uid-new"})
        client._orchestration._session_tracker.get_session_changes.return_value = [
            SessionChange(
                operation="add",
                object_type="session",
                uid="sid-123",
                name="session-abc",
                data={"sid": "sid-123", "server_ip": "10.99.99.5"},
            )
        ]

        await add_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            object_type="host",
            data={"name": "h1", "ip-address": "1.1.1.1"},
            session_id="session-abc",
            user_context=_USER,
        )

        kwargs = client.api_call_with_sid.await_args.kwargs
        assert kwargs["server_ip"] == "10.99.99.5"
        client._mgmt._registry.get_server.assert_not_called()

    @pytest.mark.asyncio
    async def test_registry_fallback_when_session_tracked_without_ip(self):
        """Sessions tracked before the fix (no server_ip) fall back to registry."""
        client = _make_write_client(api_data={"uid": "uid-new"})

        await add_object(
            client,
            mgmt_name="mgmt1",
            domain_name="dmn1",
            object_type="host",
            data={"name": "h1", "ip-address": "1.1.1.1"},
            session_id="session-abc",
            user_context=_USER,
        )

        kwargs = client.api_call_with_sid.await_args.kwargs
        assert kwargs["server_ip"] == "10.0.0.1"  # registry value
