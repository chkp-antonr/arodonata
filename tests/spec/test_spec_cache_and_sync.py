"""Specification acceptance tests for `cache-and-sync` (`SCN-CACHE-*`)."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.errors import DirtySessionError
from arodonata.core.events import (
    DomainSyncCompletedEvent,
    DomainSyncSkippedEvent,
    DomainSyncStartedEvent,
    SyncCompletedEvent,
    SyncProgressEvent,
)
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo
from arodonata.core.services import (
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
)
from arodonata.core.services import (
    sync_coordinator as sync_coord_mod,
)


class _CacheSyncFakeApi:
    """In-memory `ApiPort` double driving coordinator and object sync scenarios."""

    def __init__(self) -> None:
        self.published_session: dict[str, Any] = {
            "uid": "sess-1",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
        }
        self.show_session_result = ApiCallResult(
            success=True,
            data={"locks": 0, "changes": 0, "number-of-published-changes": 0},
        )
        self.hosts: list[dict[str, Any]] = [
            {"uid": "h1", "name": "web-01", "type": "host", "ipv4-address": "10.1.1.10"},
            {"uid": "h2", "name": "db-01", "type": "host", "ipv4-address": "10.1.1.20"},
        ]
        self.app_sites: list[dict[str, Any]] = [
            {
                "uid": "app-1",
                "name": "Site_CorpDocs",
                "type": "application-site",
                "primary-category": "Custom_Application_Site",
                "url-list": ["docs.corp.example", "portal.corp.example"],
                "urls-defined-as-regular-expression": False,
            }
        ]
        self.objects_by_uid: dict[str, dict[str, Any]] = {}
        self.changes_result: ApiCallResult = ApiCallResult(success=True, data={"changes": []})
        self.commands: list[tuple[str, str, dict[str, Any]]] = []

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        req = dict(payload or {})
        self.commands.append(("call", command, req))
        if command == "show-last-published-session":
            return ApiCallResult(success=True, data=self.published_session)
        if command == "show-session":
            return self.show_session_result
        if command == "show-changes":
            return self.changes_result
        if command == "show-object":
            uid = str(req.get("uid") or "")
            if uid in self.objects_by_uid:
                return ApiCallResult(success=True, data={"object": self.objects_by_uid[uid]})
            return ApiCallResult(success=False, status_code=404, error_message="not found")
        return ApiCallResult(success=True, data={})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        self.commands.append(("query", command, dict(payload or {})))
        if command == "show-hosts":
            return ApiQueryResult(success=True, objects=list(self.hosts), total=len(self.hosts))
        if command == "show-application-sites":
            return ApiQueryResult(success=True, objects=list(self.app_sites), total=len(self.app_sites))
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        read_only: bool = False,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return ("sid-dedicated", "10.0.0.1")

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
        timeout: float = 5.0,
    ) -> Awaitable[bool]:
        async def _done() -> bool:
            return True

        return _done()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


async def _build_object_stack(
    *,
    max_incremental_changes: int = 500,
) -> tuple[DatabaseManager, SqlCacheAdapter, DomainSyncCoordinator, ObjectService, _CacheSyncFakeApi]:
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="test-key",
        max_incremental_changes=max_incremental_changes,
    )
    await cache.upsert_domains(
        [DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="dom-corp", domain_type="domain")],
    )
    api = _CacheSyncFakeApi()
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    obj_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
    return db, cache, coordinator, obj_service, api


@pytest.mark.spec("SCN-CACHE-002-2")
async def test_object_rename_updates_in_place_without_orphan_rows() -> None:
    """SCN-CACHE-002-2: Renaming a cached object across publish updates `name` and `object_id` on the same UID PK."""
    db, cache, _coord, obj_svc, api = await _build_object_stack()
    try:
        await obj_svc.refresh_objects(mgmt_name="mds1", domains=["Corp"], types=["host"], mode="force")
        initial = await cache.get_objects(mgmt_name="mds1", domain_name="Corp", types=["host"])
        assert {o.uid: o.object_id for o in initial} == {
            "h1": "mds1:Corp:web-01",
            "h2": "mds1:Corp:db-01",
        }

        # Rename h1 under a new published session
        api.published_session = {"uid": "sess-2", "publish-time": {"iso-8601": "2026-10-23T12:05:00Z"}}
        api.objects_by_uid["h1"] = {
            "uid": "h1",
            "name": "web-01-renamed",
            "type": "host",
            "ipv4-address": "10.1.1.10",
        }
        api.changes_result = ApiCallResult(
            success=True,
            data={
                "changes": [
                    {"modified-objects": [{"new-object": {"uid": "h1", "name": "web-01-renamed", "type": "host"}}]}
                ]
            },
        )
        await obj_svc.refresh_objects(
            mgmt_name="mds1", domains=["Corp"], types=["host"], mode="smart-fast", cache_ttl=0
        )

        after_inc = await cache.get_objects(mgmt_name="mds1", domain_name="Corp", types=["host"])
        assert len(after_inc) == 2
        h1_inc = next(o for o in after_inc if o.uid == "h1")
        assert h1_inc.id == "mds1:Corp:h1"
        assert h1_inc.uid == "h1"
        assert h1_inc.name == "web-01-renamed"
        assert h1_inc.object_id == "mds1:Corp:web-01-renamed"
        assert all(o.name != "web-01" for o in after_inc)

        # Also verify atomic full refresh updates the same PK cleanly
        api.hosts[0]["name"] = "web-01-v3"
        await obj_svc.refresh_objects(mgmt_name="mds1", domains=["Corp"], types=["host"], mode="force")
        after_force = await cache.get_objects(mgmt_name="mds1", domain_name="Corp", types=["host"])
        assert len(after_force) == 2
        h1_force = next(o for o in after_force if o.uid == "h1")
        assert h1_force.id == "mds1:Corp:h1"
        assert h1_force.name == "web-01-v3"
        assert h1_force.object_id == "mds1:Corp:web-01-v3"
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-005-1")
async def test_coordinator_verify_session_clean_fail_closed_and_progress_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-CACHE-005-1: Fail closed on `show-session` failure, plus started/completed/skipped events and DEBUG logs."""
    db, _cache, coord, _obj_svc, api = await _build_object_stack()
    debug_messages: list[str] = []

    def _capture_debug(msg: object, *args: object, **_kwargs: object) -> None:
        text = str(msg)
        if args:
            try:
                text = text % args
            except Exception:
                pass
        debug_messages.append(text)

    monkeypatch.setattr(sync_coord_mod.logger, "debug", _capture_debug)
    try:
        # 1. Fail closed when `show-session` returns HTTP 500 / success=False
        api.show_session_result = ApiCallResult(
            success=False,
            status_code=500,
            error_code="generic_err",
            error_message="backend unreachable",
        )
        with pytest.raises(DirtySessionError, match="Failed to verify session cleanliness"):
            await coord.verify_session_clean("mds1", "Corp")

        # 2. Clean session sync emits Started, Completed, SyncCompleted + DEBUG progress log
        api.show_session_result = ApiCallResult(
            success=True,
            data={"locks": 0, "changes": 0, "number-of-published-changes": 0},
        )
        events_1: list[SyncProgressEvent] = []

        async def _sync_noop(probe: Any, _emit: Any) -> int:
            from arodonata.core.models.domains import DomainSyncState

            await coord._cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name=probe.mgmt_name,
                    domain_name=probe.domain.name,
                    scope="objects",
                    item_type="host",
                    last_session_uid=probe.remote_session_uid,
                    last_published_at=probe.remote_published_at,
                    status="ok",
                    object_count=3,
                )
            )
            return 3

        async for ev in coord.stream_ensure(
            scope="objects",
            item_types=["host"],
            handler=_sync_noop,
            mgmt_name="mds1",
            domains=["Corp"],
            mode="smart",
        ):
            events_1.append(ev)

        assert any(isinstance(e, DomainSyncStartedEvent) and e.domain == "Corp" for e in events_1)
        assert any(isinstance(e, DomainSyncCompletedEvent) and e.processed == 3 for e in events_1)
        assert isinstance(events_1[-1], SyncCompletedEvent)
        assert any("Corp" in m or "sync" in m for m in debug_messages)

        # 3. Subsequent smart sync with unchanged published head emits DomainSyncSkippedEvent
        events_2: list[SyncProgressEvent] = []
        async for ev in coord.stream_ensure(
            scope="objects",
            item_types=["host"],
            handler=_sync_noop,
            mgmt_name="mds1",
            domains=["Corp"],
            mode="smart",
            cache_ttl=300,
        ):
            events_2.append(ev)

        assert any(isinstance(e, DomainSyncSkippedEvent) and e.domain == "Corp" for e in events_2)
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-005-2")
async def test_smart_fast_r82_wrapped_show_changes_and_max_changes_fallback() -> None:
    """SCN-CACHE-005-2: Unwrap R82+ `new-object`/`old-object` payloads and fall back when max_incremental_changes exceeded."""
    db, cache, _coord, obj_svc, api = await _build_object_stack(max_incremental_changes=2)
    try:
        await obj_svc.refresh_objects(mgmt_name="mds1", domains=["Corp"], types=["host"], mode="force")
        api.commands.clear()

        # Publish revision 2: modify h1 (R82 new-object wrapper) and delete h2 (R82 old-object wrapper)
        api.published_session = {"uid": "sess-2", "publish-time": {"iso-8601": "2026-10-23T12:10:00Z"}}
        api.objects_by_uid["h1"] = {
            "uid": "h1",
            "name": "web-01-edge",
            "type": "host",
            "ipv4-address": "10.1.1.99",
        }
        api.changes_result = ApiCallResult(
            success=True,
            data={
                "changes": [
                    {
                        "modified-objects": [{"new-object": {"uid": "h1", "name": "web-01-edge", "type": "host"}}],
                        "deleted-objects": [{"old-object": {"uid": "h2", "name": "db-01", "type": "host"}}],
                    }
                ]
            },
        )
        outcome = await obj_svc.refresh_objects(
            mgmt_name="mds1",
            domains=["Corp"],
            types=["host"],
            mode="smart-fast",
            cache_ttl=0,
        )
        assert outcome.refreshed_domains == ["mds1:Corp"]
        assert ("call", "show-changes", {"details-level": "standard", "from-session": "sess-1"}) in api.commands
        assert not any(kind == "query" and cmd == "show-hosts" for kind, cmd, _ in api.commands)

        hosts_after = await cache.get_objects(mgmt_name="mds1", domain_name="Corp", types=["host"])
        assert [h.uid for h in hosts_after] == ["h1"]
        assert hosts_after[0].ipv4_address == "10.1.1.99"
        sync_states = await cache.list_sync_states(mgmt_name="mds1", domain_name="Corp", scope="objects")
        assert len(sync_states) == 1
        assert sync_states[0].last_session_uid == "sess-2"

        # Publish revision 3 with 3 diffs > max_incremental_changes(2) -> full show-hosts fallback
        api.commands.clear()
        api.published_session = {"uid": "sess-3", "publish-time": {"iso-8601": "2026-10-23T12:20:00Z"}}
        api.hosts = [
            {"uid": "h1", "name": "web-01-edge", "type": "host", "ipv4-address": "10.1.1.99"},
            {"uid": "h3", "name": "app-03", "type": "host", "ipv4-address": "10.1.1.30"},
        ]
        api.changes_result = ApiCallResult(
            success=True,
            data={
                "changes": [
                    {
                        "added-objects": [
                            {"new-object": {"uid": "h3", "type": "host"}},
                            {"new-object": {"uid": "h4", "type": "host"}},
                            {"new-object": {"uid": "h5", "type": "host"}},
                        ]
                    }
                ]
            },
        )
        await obj_svc.refresh_objects(
            mgmt_name="mds1", domains=["Corp"], types=["host"], mode="smart-fast", cache_ttl=0
        )
        assert any(kind == "query" and cmd == "show-hosts" for kind, cmd, _ in api.commands)
        hosts_final = await cache.get_objects(mgmt_name="mds1", domain_name="Corp", types=["host"])
        assert {h.uid for h in hosts_final} == {"h1", "h3"}
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-006-2")
async def test_application_site_bulk_and_incremental_refresh() -> None:
    """SCN-CACHE-006-2: `show-application-sites` full sync and universal `show-object` incremental `smart-fast` update."""
    db, cache, _coord, obj_svc, api = await _build_object_stack()
    try:
        await obj_svc.refresh_objects(
            mgmt_name="mds1",
            domains=["Corp"],
            types=["application-site"],
            mode="force",
        )
        assert any(kind == "query" and cmd == "show-application-sites" for kind, cmd, _ in api.commands)
        states = await cache.list_sync_states(mgmt_name="mds1", domain_name="Corp", scope="objects")
        app_states = [s for s in states if s.item_type == "application-site"]
        assert len(app_states) == 1
        assert app_states[0].status == "ok"

        cached_apps = await cache.get_objects(mgmt_name="mds1", domain_name="Corp", types=["application-site"])
        assert len(cached_apps) == 1
        assert cached_apps[0].url_list == ["docs.corp.example", "portal.corp.example"]

        # Incremental smart-fast refresh uses universal `show-object` for single UID
        api.commands.clear()
        api.published_session = {"uid": "sess-2", "publish-time": {"iso-8601": "2026-10-23T12:15:00Z"}}
        api.objects_by_uid["app-1"] = {
            "uid": "app-1",
            "name": "Site_CorpDocs",
            "type": "application-site",
            "primary-category": "Custom_Application_Site",
            "url-list": ["docs.corp.example", r"\.corp\.example"],
            "urls-defined-as-regular-expression": True,
        }
        api.changes_result = ApiCallResult(
            success=True,
            data={
                "changes": [
                    {
                        "modified-objects": [
                            {"new-object": {"uid": "app-1", "name": "Site_CorpDocs", "type": "application-site"}}
                        ]
                    }
                ]
            },
        )
        await obj_svc.refresh_objects(
            mgmt_name="mds1",
            domains=["Corp"],
            types=["application-site"],
            mode="smart-fast",
            cache_ttl=0,
        )
        assert ("call", "show-object", {"uid": "app-1", "details-level": "full"}) in api.commands
        assert not any(kind == "query" and cmd == "show-application-sites" for kind, cmd, _ in api.commands)
        updated_apps = await cache.get_objects(mgmt_name="mds1", domain_name="Corp", types=["application-site"])
        assert updated_apps[0].urls_defined_as_regular_expression is True
        assert updated_apps[0].url_list == ["docs.corp.example", r"\.corp\.example"]
    finally:
        await db.close()
