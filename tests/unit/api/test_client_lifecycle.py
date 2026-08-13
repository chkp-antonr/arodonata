"""Unit tests for ArodonataClient construction, context-manager lifecycle, and
resource management (close/cleanup), plus registry access, lazy service init,
simple property accessors, the thin logout/session passthroughs, and the
higher-level SSE refresh/search operation wrappers that the facade delegates to
its internal services.

All tests are offline: the ASDK/mgmt layer, cache, and database are mocked at
the client's internal seams. No network or real database is touched.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.api.client import ArodonataClient
from arodonata.api.schemas import SSEEventType
from arodonata.config import ArodonataSettings
from arodonata.core.exceptions import ClientError, MissingConfigurationError

from .client_test_helpers import (
    CLOSED_CLIENT_MATCH,
    install_object_service,
    make_client,
)


async def _agen(items):
    for item in items:
        yield item


def _fake_object(uid: str = "o1", mgmt: str = "mgmt1", domain: str = "domainA"):
    obj = MagicMock()
    obj.uid = uid
    obj.mgmt_name = mgmt
    obj.domain_name = domain
    obj.model_dump.return_value = {"uid": uid, "name": "web1"}
    return obj


# --------------------------------------------------------------------------- #
# Construction modes
# --------------------------------------------------------------------------- #


def test_settings_based_construction_uses_injected_components():
    settings = ArodonataSettings()
    db, cache, mgmt = AsyncMock(), AsyncMock(), AsyncMock()
    client = make_client(settings=settings, db=db, cache=cache, mgmt=mgmt)

    assert client.settings is settings
    assert client._db is db
    assert client._cache is cache
    assert client._mgmt is mgmt
    # injected _mgmt path leaves the login coordinator unset
    assert client._login_coordinator is None
    assert client._owns_engine is False
    assert client._closed is False


def test_default_cache_mode_and_ttl_are_stored():
    client = make_client()
    assert client._default_cache_mode == "smart"
    assert client._default_cache_ttl == 300


def test_custom_cache_mode_and_ttl_are_stored():
    client = make_client(cache_mode="force", cache_ttl=99)
    assert client._default_cache_mode == "force"
    assert client._default_cache_ttl == 99


def test_api_key_mode_without_engine_raises():
    with pytest.raises(MissingConfigurationError, match="engine is required for API key mode"):
        ArodonataClient(settings=ArodonataSettings())


def test_credential_mode_without_mgmt_ip_raises():
    with pytest.raises(MissingConfigurationError, match="mgmt_ip is required"):
        ArodonataClient(username="admin", password="secret")


@pytest.mark.asyncio
async def test_credential_mode_auto_creates_in_memory_engine():
    client = ArodonataClient(username="admin", password="secret", mgmt_ip="1.2.3.4")
    try:
        assert client._settings.auth_mode == "credential"
        assert client._owns_engine is True
        assert client._db.engine is not None
        assert str(client._db.engine.url) == "sqlite+aiosqlite:///:memory:"
        # A real ASDK stack is built in credential mode (no injected _mgmt).
        assert client._login_coordinator is not None
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_credential_args_override_existing_settings():
    base = ArodonataSettings()
    client = ArodonataClient(
        username="admin",
        password="secret",
        mgmt_ip="9.9.9.9",
        settings=base,
    )
    try:
        assert client._settings.auth_mode == "credential"
        assert client._settings.username == "admin"
        assert client._settings.mgmt_ip == "9.9.9.9"
        assert client._settings.password.get_secret_value() == "secret"
        # model_copy produces a new settings object, not the original.
        assert client._settings is not base
    finally:
        await client.close()


def test_engine_injection_marks_engine_as_not_owned():
    client = make_client()
    assert client._owns_engine is False


def test_construction_with_no_settings_builds_defaults():
    # settings omitted entirely (and no credentials) -> a default ArodonataSettings
    # is built internally.
    client = ArodonataClient(
        engine=MagicMock(),
        _db=AsyncMock(),
        _cache=AsyncMock(),
        _mgmt=AsyncMock(),
    )
    assert isinstance(client.settings, ArodonataSettings)
    assert client.settings.auth_mode == "api_key"


# --------------------------------------------------------------------------- #
# Context-manager lifecycle
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_aenter_initializes_db_and_returns_self():
    db = AsyncMock()
    client = make_client(db=db)
    result = await client.__aenter__()
    assert result is client
    db.initialize.assert_awaited_once()
    await client.close()


@pytest.mark.asyncio
async def test_aenter_aexit_full_cycle_closes_client():
    mgmt = AsyncMock()
    client = make_client(mgmt=mgmt)
    async with client as entered:
        assert entered is client
        assert client._closed is False
    assert client._closed is True
    mgmt.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_schedule_startup_cleanup_fires_task_when_coordinator_present():
    client = make_client()
    coordinator = MagicMock()
    coordinator.run_startup_cleanup = AsyncMock()
    client._login_coordinator = coordinator

    client.schedule_startup_cleanup()
    assert len(client._background_tasks) == 1
    task = next(iter(client._background_tasks))

    # wait for the scheduled task to finish, then give the done-callback a
    # bounded number of loop ticks to discard it from the tracking set
    await asyncio.wait_for(task, timeout=1)
    for _ in range(100):
        if not client._background_tasks:
            break
        await asyncio.sleep(0)

    coordinator.run_startup_cleanup.assert_awaited_once()
    assert len(client._background_tasks) == 0
    await client.close()


@pytest.mark.asyncio
async def test_schedule_startup_cleanup_is_noop_without_coordinator():
    client = make_client()  # injected _mgmt -> _login_coordinator is None
    client.schedule_startup_cleanup()
    assert len(client._background_tasks) == 0
    await client.close()


# --------------------------------------------------------------------------- #
# close() behavior
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_close_disposes_owned_engine():
    db = MagicMock()
    db.engine.dispose = AsyncMock()
    client = make_client(db=db)
    client._owns_engine = True

    await client.close()

    db.engine.dispose.assert_awaited_once()


@pytest.mark.asyncio
async def test_close_does_not_dispose_app_owned_engine():
    db = MagicMock()
    db.engine.dispose = AsyncMock()
    client = make_client(db=db)
    assert client._owns_engine is False

    await client.close()

    db.engine.dispose.assert_not_called()


@pytest.mark.asyncio
async def test_double_close_closes_mgmt_only_once():
    mgmt = AsyncMock()
    client = make_client(mgmt=mgmt)

    await client.close()
    await client.close()

    mgmt.close.assert_awaited_once()
    assert client._closed is True


@pytest.mark.asyncio
async def test_close_cancels_pending_background_tasks():
    client = make_client()

    async def _never() -> None:
        await asyncio.sleep(100)

    task = asyncio.create_task(_never())
    client._background_tasks.add(task)

    await client.close()

    assert task.done()
    assert task.cancelled()


# --------------------------------------------------------------------------- #
# Using a closed client
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_api_call_on_closed_client_raises():
    client = make_client()
    await client.close()
    # NOTE: source raises RuntimeError, not the ClientClosedError exception that
    # exists in core.exceptions. See report.
    with pytest.raises(RuntimeError, match=CLOSED_CLIENT_MATCH):
        await client.api_call("mgmt1", "show-hosts")


@pytest.mark.asyncio
async def test_get_mgmt_names_on_closed_client_raises():
    client = make_client()
    await client.close()
    with pytest.raises(RuntimeError, match=CLOSED_CLIENT_MATCH):
        client.get_mgmt_names()


@pytest.mark.asyncio
async def test_cache_property_on_closed_client_raises():
    client = make_client()
    await client.close()
    with pytest.raises(RuntimeError, match=CLOSED_CLIENT_MATCH):
        _ = client.cache


@pytest.mark.asyncio
async def test_settings_property_still_accessible_after_close():
    settings = ArodonataSettings()
    client = make_client(settings=settings)
    await client.close()
    # settings does not guard on _closed
    assert client.settings is settings


# --------------------------------------------------------------------------- #
# Registry access + simple accessors
# --------------------------------------------------------------------------- #


def test_get_mgmt_names_delegates_to_mgmt():
    mgmt = MagicMock()
    mgmt.get_mgmt_names.return_value = ["mgmt1", "mgmt2"]
    client = make_client(mgmt=mgmt)
    assert client.get_mgmt_names() == ["mgmt1", "mgmt2"]
    mgmt.get_mgmt_names.assert_called_once_with()


@pytest.mark.asyncio
async def test_get_server_delegates_to_mgmt():
    mgmt = AsyncMock()
    sentinel = object()
    mgmt.get_server.return_value = sentinel
    client = make_client(mgmt=mgmt)
    result = await client.get_server("mgmt1")
    assert result is sentinel
    mgmt.get_server.assert_awaited_once_with("mgmt1")


def test_cache_property_returns_repository():
    cache = AsyncMock()
    client = make_client(cache=cache)
    assert client.cache is cache


# --------------------------------------------------------------------------- #
# Lazy ObjectService initialization
# --------------------------------------------------------------------------- #


def test_object_service_is_memoized():
    # The refresh coordinator built in __init__ already triggers the lazy
    # property, so the instance exists on a fully constructed client; the
    # contract we assert here is that repeated access returns the same object.
    from arodonata.cache.object_service import ObjectService

    client = make_client()
    first = client._object_service
    second = client._object_service
    assert first is second
    assert isinstance(first, ObjectService)


def test_object_service_lazy_on_bare_instance():
    # On a bare instance (no __init__), the property builds on first access.
    from arodonata.cache.object_service import ObjectService

    client = ArodonataClient.__new__(ArodonataClient)
    client._db = AsyncMock()
    assert not hasattr(client, "_object_service_instance")
    svc = client._object_service
    assert isinstance(svc, ObjectService)
    assert client._object_service is svc


# --------------------------------------------------------------------------- #
# logout / session passthroughs
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_logout_delegates_to_mgmt():
    mgmt = AsyncMock()
    mgmt.logout.return_value = True
    client = make_client(mgmt=mgmt)
    assert await client.logout("mgmt1", "domainA") is True
    mgmt.logout.assert_awaited_once_with("mgmt1", "domainA")


@pytest.mark.asyncio
async def test_logout_sid_delegates_to_mgmt():
    mgmt = AsyncMock()
    mgmt.logout_sid.return_value = True
    client = make_client(mgmt=mgmt)
    assert await client.logout_sid("sid-1", "1.2.3.4", "mgmt1") is True
    mgmt.logout_sid.assert_awaited_once_with("sid-1", "1.2.3.4", "mgmt1")


@pytest.mark.asyncio
async def test_create_dedicated_session_delegates_to_mgmt():
    mgmt = AsyncMock()
    mgmt.create_dedicated_session.return_value = ("sid-9", "10.0.0.1")
    client = make_client(mgmt=mgmt)
    result = await client.create_dedicated_session("mgmt1", "domainA", session_name="s", session_description="d")
    assert result == ("sid-9", "10.0.0.1")
    mgmt.create_dedicated_session.assert_awaited_once_with(
        "mgmt1", "domainA", session_name="s", session_description="d"
    )


@pytest.mark.asyncio
async def test_clear_cache_delegates_to_cache_repository():
    cache = AsyncMock()
    client = make_client(cache=cache)
    await client.clear_cache()
    cache.clear_sessions.assert_awaited_once()


@pytest.mark.asyncio
async def test_clear_cache_on_closed_client_raises():
    client = make_client()
    await client.close()
    with pytest.raises(RuntimeError, match=CLOSED_CLIENT_MATCH):
        await client.clear_cache()


# --------------------------------------------------------------------------- #
# refresh_objects / refresh_rulebases (SSE wrappers around internal services)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_refresh_objects_wraps_service_progress():
    client = make_client()
    fake_service = MagicMock()
    fake_service.refresh_objects = MagicMock(return_value=_agen([{"count": 2, "message": "batch"}]))
    install_object_service(client, fake_service)

    events = [e async for e in client.refresh_objects(mode="force")]

    assert events[0].event_type == SSEEventType.START
    assert events[-1].event_type == SSEEventType.COMPLETE
    assert events[-1].data["total_results"] == 2


@pytest.mark.asyncio
async def test_refresh_objects_raises_when_object_service_missing():
    client = make_client()
    install_object_service(client, None)
    with pytest.raises(ClientError, match="Object service not initialized"):
        async for _ in client.refresh_objects():
            pass


@pytest.mark.asyncio
async def test_refresh_rulebases_wraps_service_progress():
    client = make_client()
    client._rulebase_refresh = MagicMock()
    client._rulebase_refresh.refresh_all = MagicMock(return_value=_agen([{"count": 5, "message": "layer"}]))

    events = [e async for e in client.refresh_rulebases(mode="check")]

    assert events[0].event_type == SSEEventType.START
    assert events[-1].event_type == SSEEventType.COMPLETE
    assert events[-1].data["total_results"] == 5


# --------------------------------------------------------------------------- #
# refresh wrapper delegations to AssetRefreshService / ObjectService
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_delegates():
    client = make_client()
    client._asset_refresh = MagicMock()

    def _fake(**_kwargs):
        return _agen([SimpleNamespace(event_type=SSEEventType.RESULT, data={"count": 1})])

    client._asset_refresh.build_refresh_assets_cache = _fake

    events = [e async for e in client.build_refresh_assets_cache(mgmt_names="mgmt1")]
    assert len(events) == 1
    assert events[0].data["count"] == 1


@pytest.mark.asyncio
async def test_build_refresh_assets_cache_raises_when_service_missing():
    client = make_client()
    client._asset_refresh = None
    with pytest.raises(RuntimeError, match="AssetRefreshService not initialized"):
        async for _ in client.build_refresh_assets_cache():
            pass


@pytest.mark.asyncio
async def test_refresh_domain_assets_delegates():
    client = make_client()
    client._asset_refresh = MagicMock()

    def _fake(**_kwargs):
        return _agen([SimpleNamespace(event_type=SSEEventType.RESULT, data={"count": 3})])

    client._asset_refresh.refresh_domain_assets = _fake

    events = [e async for e in client.refresh_domain_assets("mgmt1", "domainA")]
    assert events[0].data["count"] == 3


@pytest.mark.asyncio
async def test_refresh_domain_assets_raises_when_service_missing():
    client = make_client()
    client._asset_refresh = None
    with pytest.raises(RuntimeError, match="AssetRefreshService not initialized"):
        async for _ in client.refresh_domain_assets("mgmt1", "domainA"):
            pass


@pytest.mark.asyncio
async def test_refresh_last_published_session_delegates_to_object_service():
    client = make_client()
    svc = AsyncMock()
    svc.refresh_last_published_session.return_value = "the-record"
    install_object_service(client, svc)

    result = await client.refresh_last_published_session("mgmt1", "domainA")

    assert result == "the-record"
    svc.refresh_last_published_session.assert_awaited_once_with("mgmt1", "domainA")


# --------------------------------------------------------------------------- #
# search_objects
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("term", "cache_method"),
    [
        ("web-server", "get_objects_by_name"),
        ("127.0.0.1", "get_objects_by_ip"),
        ("192.168.1.0/24", "get_objects_by_subnet"),
        ("10.0.0.1-10.0.0.10", "get_objects_in_ip_range"),
    ],
)
@pytest.mark.asyncio
async def test_search_objects_dispatches_to_correct_cache_lookup(term, cache_method):
    client = make_client()
    svc = MagicMock()
    setattr(svc._cache, cache_method, AsyncMock(return_value=[_fake_object()]))
    install_object_service(client, svc)

    events = [e async for e in client.search_objects(term, max_depth=0)]
    types = [e.event_type for e in events]

    assert types[0] == SSEEventType.START
    assert types[-1] == SSEEventType.COMPLETE
    getattr(svc._cache, cache_method).assert_awaited()


@pytest.mark.asyncio
async def test_search_objects_by_range_parses_bounds():
    client = make_client()
    svc = MagicMock()
    svc._cache.get_objects_in_ip_range = AsyncMock(return_value=[_fake_object()])
    install_object_service(client, svc)

    _ = [e async for e in client.search_objects("10.0.0.1-10.0.0.10", max_depth=0)]

    _, kwargs = svc._cache.get_objects_in_ip_range.call_args
    assert kwargs["start_ip"] == "10.0.0.1"
    assert kwargs["end_ip"] == "10.0.0.10"


@pytest.mark.asyncio
async def test_search_objects_resolves_memberships_when_depth_positive():
    client = make_client()
    svc = MagicMock()
    svc._cache.get_objects_by_name = AsyncMock(return_value=[_fake_object()])
    node = SimpleNamespace(uid="g1", name="grp", domain="domainA", depth=1, children=[])
    svc._resolve_group_memberships = AsyncMock(return_value=[node])
    install_object_service(client, svc)

    events = [e async for e in client.search_objects("web-server", max_depth=2)]

    log_events = [e for e in events if e.event_type == SSEEventType.LOG and e.data.get("memberships")]
    assert log_events, "expected a domain log event carrying resolved memberships"
    assert log_events[0].data["memberships"]["o1"][0]["name"] == "grp"


@pytest.mark.asyncio
async def test_search_objects_no_memberships_leaves_dict_none():
    client = make_client()
    svc = MagicMock()
    svc._cache.get_objects_by_name = AsyncMock(return_value=[_fake_object()])
    svc._resolve_group_memberships = AsyncMock(return_value=[])  # no groups
    install_object_service(client, svc)

    events = [e async for e in client.search_objects("web-server", max_depth=2)]

    domain_logs = [e for e in events if e.event_type == SSEEventType.LOG and e.data.get("search_type")]
    assert domain_logs
    assert domain_logs[0].data["memberships"] is None


@pytest.mark.asyncio
async def test_search_objects_groups_multiple_objects():
    client = make_client()
    svc = MagicMock()
    objs = [
        _fake_object(uid="o1", mgmt="mgmt1", domain="domainA"),
        _fake_object(uid="o2", mgmt="mgmt1", domain="domainA"),
        _fake_object(uid="o3", mgmt="mgmt2", domain="domainB"),
    ]
    svc._cache.get_objects_by_name = AsyncMock(return_value=objs)
    install_object_service(client, svc)

    events = [e async for e in client.search_objects("web-server", max_depth=0)]
    domain_logs = [e for e in events if e.event_type == SSEEventType.LOG and e.data.get("search_type")]
    # domainA (2 objects) grouped together, domainB separate -> 2 domain logs
    assert len(domain_logs) == 2


@pytest.mark.asyncio
async def test_search_objects_raises_when_object_service_missing():
    client = make_client()
    install_object_service(client, None)
    with pytest.raises(ClientError, match="Object service not initialized"):
        async for _ in client.search_objects("web-server"):
            pass


@pytest.mark.asyncio
async def test_search_objects_with_refresh_invokes_refresh_objects():
    client = make_client()
    svc = MagicMock()
    svc._cache.get_objects_by_name = AsyncMock(return_value=[])
    svc.refresh_objects = MagicMock(return_value=_agen([{"count": 1, "message": "r"}]))
    install_object_service(client, svc)

    events = [e async for e in client.search_objects("web-server", refresh="force", max_depth=0)]

    # refresh_objects START is converted to LOG and RESULT/COMPLETE filtered out
    assert any(e.event_type == SSEEventType.START and "Searching" in (e.message or "") for e in events)
    svc.refresh_objects.assert_called_once()
