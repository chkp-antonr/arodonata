"""Specification acceptance tests for `client-and-facade` (`SCN-CLIENT-*`) and `configuration` (`SCN-CONFIG-*`)."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import warnings
from collections.abc import Awaitable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient
from arodonata import client as client_mod
from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport, PooledSocketEntry, RawHttpResponse
from arodonata.adapters.sse import SSEEvent, stream_as_sse, to_sse_event
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    AmbiguousObjectError,
    RepositoryScriptPermissionError,
)
from arodonata.core.events import (
    CPCRUDActionEvent,
    DomainSyncCompletedEvent,
    StagedSessionEvent,
)
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo, SIDCacheEntry
from arodonata.core.models.objects import CPObject
from arodonata.core.telemetry import span_attrs, traced
from arodonata.mcp import cli as mcp_cli
from arodonata.reports.models import SessionScope
from arodonata.testing.replay_mock import FileReplayApiMock, ensure_enterprise_raw_dataset


def _make_der(seed: str = "spec-client") -> tuple[bytes, str]:
    der = f"der-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    return der, ":".join(digest[i : i + 2] for i in range(0, 64, 2))


class _ScriptedTransportServer:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.login_counter = 0

    async def sender(
        self,
        *,
        host: str,
        port: int,
        command: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        connect_timeout: float,
        read_timeout: float,
        reused_entry: PooledSocketEntry | None,
    ) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        payload = json.loads(body.decode("utf-8")) if body else {}
        self.calls.append(
            {
                "host": host,
                "command": command,
                "sid": headers.get("X-chkp-sid"),
                "payload": payload,
                "connect_timeout": connect_timeout,
                "read_timeout": read_timeout,
            }
        )
        if command == "login":
            self.login_counter += 1
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps(
                        {"sid": f"sid_client_{self.login_counter}", "uid": f"suid-{self.login_counter}"}
                    ).encode("utf-8"),
                ),
                reused_entry,
            )
        if command == "run-script":
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps({"task-id": "rs-1"}).encode("utf-8"),
                ),
                reused_entry,
            )
        if command == "show-task":
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps(
                        {"tasks": [{"task-id": "rs-1", "status": "succeeded", "progress-percentage": 100}]}
                    ).encode("utf-8"),
                ),
                reused_entry,
            )
        return RawHttpResponse(status=200, body=b'{"message":"OK"}'), reused_entry


def _build_scripted_amgmt_client(
    tmp_path: Path,
    server: _ScriptedTransportServer,
    *,
    settings: ArodonataSettings | None = None,
    engine: Any = None,
) -> tuple[ArodonataSettings, ApiTransport, TrustPolicy]:
    der, fp = _make_der()
    cfg = settings or ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="static-key",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp}",
    )
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp}",
    )
    transport = ApiTransport(
        settings=cfg,
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: der,
        request_sender=server.sender,
    )
    return cfg, transport, policy


@pytest.mark.spec("SCN-CLIENT-001-1")
async def test_client_context_manager_lifecycle_cleanup_and_engine_disposal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-CLIENT-001-1: `__aenter__` triggers startup cleanup; `__aexit__` cancels warmups and disposes owned engine only."""
    server = _ScriptedTransportServer()
    cfg_owned, transport_1, policy_1 = _build_scripted_amgmt_client(tmp_path, server)
    cleanup_calls: list[bool] = []

    async with ArodonataClient(cfg_owned, transport=transport_1, trust_policy=policy_1) as owned_client:
        assert owned_client.owns_engine is True
        assert owned_client.db.is_initialized is True
        assert owned_client.amgmt is not None

        scheduled_tasks: list[asyncio.Task[None]] = []
        orig_cleanup = owned_client.amgmt.session_cleaner.schedule_startup_cleanup

        def _spy_cleanup(*args: Any, **kwargs: Any) -> Any:
            cleanup_calls.append(True)
            tasks = orig_cleanup(*args, **kwargs)
            scheduled_tasks.extend(tasks)
            return tasks

        monkeypatch.setattr(owned_client.amgmt.session_cleaner, "schedule_startup_cleanup", _spy_cleanup)
        await owned_client.initialize(run_startup_cleanup=True)
        if scheduled_tasks:
            await asyncio.gather(*scheduled_tasks, return_exceptions=True)
        assert cleanup_calls == [True]

        # Schedule a warm-up task that stays pending so __aexit__ must cancel & clean it
        blocker = asyncio.Event()

        async def _slow_api_call(*args: Any, **kwargs: Any) -> ApiCallResult:
            await blocker.wait()
            return ApiCallResult(success=True, data={})

        assert owned_client.amgmt is not None
        monkeypatch.setattr(owned_client.amgmt, "api_call", _slow_api_call)
        task = owned_client.start_object_cache_warmup(mgmt_name="mds1", domains=["Corp"])
        assert task in owned_client.warmup_tasks

    assert owned_client.warmup_tasks == set()

    # External engine must NOT be disposed on __aexit__
    ext_db_path = tmp_path / "external_lifecycle.sqlite"
    ext_engine = create_async_engine(f"sqlite+aiosqlite:///{ext_db_path}")
    cfg_ext, transport_2, policy_2 = _build_scripted_amgmt_client(tmp_path, server)
    try:
        async with ArodonataClient(
            cfg_ext, engine=ext_engine, transport=transport_2, trust_policy=policy_2
        ) as ext_client:
            assert ext_client.owns_engine is False
        # External engine remains usable after client closes
        async with ext_engine.connect() as conn:
            res = await conn.exec_driver_sql("SELECT 1")
            assert res.scalar() == 1
    finally:
        await ext_engine.dispose()


@pytest.mark.spec("SCN-CLIENT-001-2")
async def test_close_logout_policy_uses_actual_db_url_over_settings_url(tmp_path: Path) -> None:
    """SCN-CLIENT-001-2 (FC-03): `close(logout=None)` inspects actual DB URL rather than `settings.database_url`."""
    server = _ScriptedTransportServer()
    now = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)

    # 1. External persistent engine while settings.database_url defaults to ":memory:" -> preserves cached SID
    ext_db = tmp_path / "persistent.sqlite"
    ext_engine = create_async_engine(f"sqlite+aiosqlite:///{ext_db}")
    cfg_mem, transport_1, policy_1 = _build_scripted_amgmt_client(
        tmp_path,
        server,
        settings=ArodonataSettings(
            mgmt_name="mds1",
            mgmt_ip="10.0.0.1",
            api_key="static-key",
            database_url="sqlite+aiosqlite:///:memory:",
            tls_trust="pinned",
            tls_fingerprints=f"10.0.0.1:443={_make_der()[1]}",
        ),
    )
    try:
        c_ext = ArodonataClient(cfg_mem, engine=ext_engine, transport=transport_1, trust_policy=policy_1)
        await c_ext.initialize()
        await c_ext.cache.upsert_sid(
            SIDCacheEntry(
                id="mds1:Corp:default",
                mgmt_name="mds1",
                domain_name="Corp",
                sid="sid_persisted_1",
                server_ip="10.0.0.1",
                last_used_at=now,
                expires_at=now + timedelta(seconds=300),
            )
        )
        await c_ext.close(logout=None)
        assert not any(c["command"] == "logout" and c["sid"] == "sid_persisted_1" for c in server.calls)
    finally:
        await ext_engine.dispose()

    # 2. Owned in-memory engine (engine=None, :memory:) -> automatically logs out cached SID
    server.calls.clear()
    cfg_owned, transport_2, policy_2 = _build_scripted_amgmt_client(tmp_path, server)
    c_owned = ArodonataClient(cfg_owned, engine=None, transport=transport_2, trust_policy=policy_2)
    await c_owned.initialize()
    await c_owned.cache.upsert_sid(
        SIDCacheEntry(
            id="mds1:Corp:default",
            mgmt_name="mds1",
            domain_name="Corp",
            sid="sid_ephemeral_1",
            server_ip="10.0.0.1",
            last_used_at=now,
            expires_at=now + timedelta(seconds=300),
        )
    )
    await c_owned.close(logout=None)
    assert any(c["command"] == "logout" and c["sid"] == "sid_ephemeral_1" for c in server.calls)


@pytest.mark.spec("SCN-CLIENT-002-2")
async def test_fire_and_forget_warmup_failure_logs_redacted_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """SCN-CLIENT-002-2: Background warm-up failure logs redacted WARNING and produces no unretrieved warnings."""

    class _FailingWarmupApi:
        async def api_call(self, *args: Any, **kwargs: Any) -> ApiCallResult:
            raise RuntimeError("Refresh failed with sid_secret_999")

        async def api_query(self, *args: Any, **kwargs: Any) -> ApiQueryResult:
            return ApiQueryResult(success=False, error_message="boom")

        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return ("s1", "10.0.0.1")

        def logout_sid(self, *args: Any, **kwargs: Any) -> Awaitable[bool]:
            async def _ok() -> bool:
                return True

            return _ok()

        async def close(self, *, logout: bool | None = None) -> None:
            return None

    logged_warnings: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        client_mod.logger,
        "warning",
        lambda msg, **kw: logged_warnings.append((str(msg), dict(kw))),
    )

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k")
    async with ArodonataClient(settings, api=_FailingWarmupApi()) as client:
        await client.cache.upsert_domains(
            [DomainInfo(id="mds1:Unreachable", mgmt_name="mds1", name="Unreachable", uid="d-u")]
        )
        task = client.start_object_cache_warmup(mgmt_name="mds1", domains=["Unreachable"])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            while not task.done():
                await asyncio.sleep(0.01)
            del task
            gc.collect()
            await asyncio.sleep(0)
        assert not [w for w in caught if "Task exception was never retrieved" in str(w.message)]

    assert any("background_object_cache_warmup_failed" in m for m, _kw in logged_warnings)
    statuses = client.get_warmup_status("mds1")
    assert any(st.status == "failed" for st in statuses)


@pytest.mark.spec("SCN-CLIENT-003-2")
async def test_api_call_publish_invalidates_domain_freshness_memo(tmp_path: Path) -> None:
    """SCN-CLIENT-003-2: `api_call(..., 'publish')` invalidates TTL memo so next smart read re-checks domain head."""
    server = _ScriptedTransportServer()
    cfg, transport, policy = _build_scripted_amgmt_client(
        tmp_path,
        server,
        settings=ArodonataSettings(
            mgmt_name="mds1",
            mgmt_ip="10.0.0.1",
            api_key="k",
            cache_ttl=300,
            tls_trust="pinned",
            tls_fingerprints=f"10.0.0.1:443={_make_der()[1]}",
        ),
    )
    async with ArodonataClient(cfg, transport=transport, trust_policy=policy) as client:
        assert client.amgmt is not None
        await client.cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="d1")])

        # First smart read checks show-last-published-session and sets memo
        await client.get_hosts("mds1", "Corp", cache_mode="smart")
        # Second smart read within TTL skips server checks
        calls_before = len(server.calls)
        await client.get_hosts("mds1", "Corp", cache_mode="smart")
        assert len(server.calls) == calls_before

        # Direct publish via dedicated sid on api_call must invalidate freshness memo immediately
        ded_sid, _ded_ip = await client.create_dedicated_session("mds1", "Corp")
        await client.api_call("mds1", "publish", {}, domain="Corp", sid=ded_sid)
        await client.get_hosts("mds1", "Corp", cache_mode="smart")
        cmds_after_publish = [c["command"] for c in server.calls[calls_before:]]
        assert "publish" in cmds_after_publish
        assert "show-last-published-session" in cmds_after_publish


@pytest.mark.spec("SCN-CLIENT-005-1")
async def test_get_group_members_expands_vsx_parent_including_cross_domain_virtual_systems() -> None:
    """SCN-CLIENT-005-1: `get_group_members` expands VSX parent asset including cross-domain Virtual Systems."""
    settings = ArodonataSettings(mgmt_name="mds", mgmt_ip="10.0.0.1", api_key="k")
    async with ArodonataClient(settings) as client:
        await client.cache.upsert_domains(
            [
                DomainInfo(id="mds:VSX", mgmt_name="mds", name="VSX", uid="dom-vsx"),
                DomainInfo(id="mds:Domain4", mgmt_name="mds", name="Domain4", uid="dom-4"),
            ]
        )
        vsx_parent = Asset(
            id="mds:VSX:vsx-uid-1",
            mgmt_name="mds",
            domain_name="VSX",
            uid="vsx-uid-1",
            name="VSX-Cluster-01",
            type="CpmiVsxClusterNetobj",
            asset_id="mds:VSX:VSX-Cluster-01",
            virtual_system_uids=["vs-uid-4"],
            virtual_system_asset_ids=["mds:Domain4:VS_Tenant_4"],
        )
        vs_child = Asset(
            id="mds:Domain4:vs-uid-4",
            mgmt_name="mds",
            domain_name="Domain4",
            uid="vs-uid-4",
            name="VS_Tenant_4",
            type="CpmiVsClusterNetobj",
            asset_id="mds:Domain4:VS_Tenant_4",
            parent_uid="vsx-uid-1",
            parent_name="VSX-Cluster-01",
            parent_id="mds:VSX:vsx-uid-1",
            parent_asset_id="mds:VSX:VSX-Cluster-01",
        )
        await client.cache.replace_domain_assets("mds", "VSX", [vsx_parent])
        await client.cache.replace_domain_assets("mds", "Domain4", [vs_child])

        members = await client.get_group_members("mds", "VSX", "mds:VSX:VSX-Cluster-01", cache_mode="cache")
        assert [m.uid for m in members] == ["vs-uid-4"]
        assert members[0].domain_name == "Domain4"


@pytest.mark.spec("SCN-CLIENT-005-2")
async def test_describe_objects_and_query_objects_filter_parent_ids() -> None:
    """SCN-CLIENT-005-2 (FC-09): `describe_objects` lists composite fields and `query_objects` filters parent_id/parent_asset_id."""
    settings = ArodonataSettings(mgmt_name="mds", mgmt_ip="10.0.0.1", api_key="k")
    async with ArodonataClient(settings) as client:
        await client.cache.upsert_domains([DomainInfo(id="mds:Domain4", mgmt_name="mds", name="Domain4", uid="d4")])
        await client.cache.replace_domain_assets(
            "mds",
            "Domain4",
            [
                Asset(
                    id="mds:Domain4:vs-1",
                    mgmt_name="mds",
                    domain_name="Domain4",
                    uid="vs-1",
                    name="VS_Alpha",
                    type="CpmiVsNetobj",
                    asset_id="mds:Domain4:VS_Alpha",
                    parent_uid="vsx-a",
                    parent_id="mds:VSX:vsx-a",
                    parent_asset_id="mds:VSX:VSX-Alpha",
                ),
                Asset(
                    id="mds:Domain4:vs-2",
                    mgmt_name="mds",
                    domain_name="Domain4",
                    uid="vs-2",
                    name="VS_Beta",
                    type="CpmiVsNetobj",
                    asset_id="mds:Domain4:VS_Beta",
                    parent_uid="vsx-b",
                    parent_id="mds:VSX:vsx-b",
                    parent_asset_id="mds:VSX:VSX-Beta",
                ),
            ],
        )

        desc = await client.describe_objects()
        for field_name in ("id", "object_id", "service_id", "asset_id", "parent_id", "parent_asset_id"):
            assert field_name in desc["filterable_fields"]

        by_pid = await client.query_objects(parent_id="mds:VSX:vsx-a", cache_mode="cache")
        assert len(by_pid["objects"]) == 1
        assert by_pid["objects"][0]["asset_id"] == "mds:Domain4:VS_Alpha"
        assert by_pid["objects"][0]["parent_id"] == "mds:VSX:vsx-a"

        by_pa_glob = await client.query_objects(parent_asset_id="*:VSX-Beta", cache_mode="cache")
        assert len(by_pa_glob["objects"]) == 1
        assert by_pa_glob["objects"][0]["asset_id"] == "mds:Domain4:VS_Beta"
        assert by_pa_glob["objects"][0]["parent_asset_id"] == "mds:VSX:VSX-Beta"


@pytest.mark.spec("SCN-CLIENT-006-2")
async def test_cross_domain_lookup_mds_cache_only_and_smc_probe() -> None:
    """SCN-CLIENT-006-2: Multi-domain MDS `domain=None` stays cache-only with `AmbiguousObjectError`; single SMC probes."""

    class _CounterApi:
        def __init__(self, domains: list[dict[str, Any]]) -> None:
            self.calls: list[str] = []
            self._domains = domains

        async def api_call(
            self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, **kw: Any
        ) -> ApiCallResult:
            self.calls.append(command)
            return ApiCallResult(success=True, data={})

        async def api_query(self, mgmt_name: str, command: str, **kw: Any) -> ApiQueryResult:
            self.calls.append(command)
            if command == "show-domains":
                return ApiQueryResult(success=True, objects=self._domains, total=len(self._domains))
            if command == "show-hosts":
                return ApiQueryResult(
                    success=True,
                    objects=[{"uid": "h-smc", "name": "smc-host", "type": "host", "ipv4-address": "10.0.0.5"}],
                    total=1,
                )
            return ApiQueryResult(success=True, objects=[], total=0)

        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return ("s1", "10.0.0.1")

        def logout_sid(self, *args: Any, **kwargs: Any) -> Awaitable[bool]:
            async def _ok() -> bool:
                return True

            return _ok()

        async def close(self, *, logout: bool | None = None) -> None:
            return None

    # 1. Multi-domain MDS (>1 non-global cached domains): zero remote syncs, raises AmbiguousObjectError
    mds_api = _CounterApi([])
    async with ArodonataClient(ArodonataSettings(mgmt_name="mds", mgmt_ip="10.0.0.1", api_key="k"), api=mds_api) as mds:
        await mds.cache.upsert_domains(
            [
                DomainInfo(id="mds:Corp", mgmt_name="mds", name="Corp", uid="d1"),
                DomainInfo(id="mds:DMZ", mgmt_name="mds", name="DMZ", uid="d2"),
            ]
        )
        await mds.cache.replace_domain_objects(
            "mds",
            "Corp",
            [CPObject(uid="g-c", name="SharedGrp", type="group", mgmt_name="mds", domain_name="Corp", members=[])],
            types=["group"],
        )
        await mds.cache.replace_domain_objects(
            "mds",
            "DMZ",
            [CPObject(uid="g-d", name="SharedGrp", type="group", mgmt_name="mds", domain_name="DMZ", members=[])],
            types=["group"],
        )
        mds_api.calls.clear()
        with pytest.raises(AmbiguousObjectError):
            await mds.get_group_members("mds", None, "SharedGrp", cache_mode="smart")
        assert mds_api.calls == []

    # 2. Cold single-domain SMC with cache_mode="smart" probes show-domains and finds host
    smc_api = _CounterApi([{"uid": "smc-dom", "name": "SMC User", "domain-type": "domain"}])
    async with ArodonataClient(ArodonataSettings(mgmt_name="smc", mgmt_ip="10.0.0.2", api_key="k"), api=smc_api) as smc:
        found = await smc.find_object("smc", None, "smc-host", cache_mode="smart")
        assert found is not None and found.name == "smc-host"
        assert "show-domains" in smc_api.calls


@pytest.mark.spec("SCN-CLIENT-007-1")
async def test_client_write_session_cancellation_shields_discard_and_strips_api_key(tmp_path: Path) -> None:
    """SCN-CLIENT-007-1: Cancelled `write_session` shields `discard` + `logout_sid`; overlay strips `api-key`."""
    server = _ScriptedTransportServer()
    cfg, transport, policy = _build_scripted_amgmt_client(tmp_path, server)
    entered = asyncio.Event()
    never = asyncio.Event()
    captured_overlay_obj: CPObject | None = None

    async with ArodonataClient(cfg, transport=transport, trust_policy=policy) as client:

        async def _worker() -> None:
            nonlocal captured_overlay_obj
            async with client.write_session("mds1", "Corp"):
                await client.add_object(
                    "mds1",
                    "host",
                    {
                        "name": "sec-host",
                        "ipv4-address": "10.0.0.7",
                        "api-key": "super-secret-api-key",
                        "password": "secret-password",
                    },
                    domain="Corp",
                )
                hosts = await client.get_hosts("mds1", "Corp", cache_mode="cache")
                captured_overlay_obj = next((h for h in hosts if h.name == "sec-host"), None)
                entered.set()
                await never.wait()

        t = asyncio.create_task(_worker())
        await entered.wait()
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    assert captured_overlay_obj is not None
    assert "api-key" not in captured_overlay_obj.raw_data
    assert "password" not in captured_overlay_obj.raw_data
    cmds = [c["command"] for c in server.calls]
    assert "discard" in cmds and "logout" in cmds
    assert cmds.index("discard") < cmds.index("logout")


@pytest.mark.spec("SCN-CLIENT-010-3")
async def test_repository_script_delete_and_ensure_permission_error_metadata() -> None:
    """SCN-CLIENT-010-3: `delete_repository_script`/`ensure_repository_script` permission error metadata & SID redaction."""

    class _PermErrorApi:
        async def api_call(
            self, mgmt_name: str, command: str, payload: dict[str, Any] | None = None, **kw: Any
        ) -> ApiCallResult:
            from arodonata.core.context import get_write_session

            ws = get_write_session()
            sid = str(kw.get("sid") or (ws.sid if ws is not None else ""))
            if command in ("delete-repository-script", "add-repository-script"):
                return ApiCallResult(
                    success=False,
                    status_code=403,
                    error_code="generic_err_no_permissions",
                    error_message=f'Denied for {{"sid": "{sid}"}}',
                )
            return ApiCallResult(
                success=False, status_code=404, error_code="generic_err_object_not_found", error_message="missing"
            )

        async def api_query(self, mgmt_name: str, command: str, **kw: Any) -> ApiQueryResult:
            return ApiQueryResult(success=True, objects=[], total=0)

        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return ("sid_perm_secret_42", "10.0.0.1")

        def logout_sid(self, *args: Any, **kwargs: Any) -> Awaitable[bool]:
            async def _ok() -> bool:
                return True

            return _ok()

        async def close(self, *, logout: bool | None = None) -> None:
            return None

    async with ArodonataClient(
        ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k"), api=_PermErrorApi()
    ) as client:
        with pytest.raises(RepositoryScriptPermissionError) as del_exc:
            await client.delete_repository_script("mds1", "collect-v1", domain="Corp")
        assert del_exc.value.mgmt_name == "mds1"
        assert del_exc.value.domain_name == "Corp"
        assert del_exc.value.script_ref == "collect-v1"
        assert del_exc.value.operation == "delete-repository-script"
        assert "sid_perm_secret_42" not in str(del_exc.value)
        assert REDACTED_PLACEHOLDER in str(del_exc.value)

        with pytest.raises(RepositoryScriptPermissionError) as ens_exc:
            await client.ensure_repository_script("mds1", "collect-v1", "#!/bin/sh\necho ok\n", domain="Corp")
        assert ens_exc.value.mgmt_name == "mds1"
        assert ens_exc.value.domain_name == "Corp"
        assert ens_exc.value.operation == "add-repository-script"
        assert "sid_perm_secret_42" not in str(ens_exc.value)


@pytest.mark.spec("SCN-CLIENT-012-2")
async def test_run_repository_script_uses_dedicated_rw_session_never_sid_cache(tmp_path: Path) -> None:
    """SCN-CLIENT-012-2: `run_repository_script` opens dedicated `read_only=False` session and ignores `arodonata_sid_cache`."""
    server = _ScriptedTransportServer()
    cfg, transport, policy = _build_scripted_amgmt_client(tmp_path, server)
    now = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    async with ArodonataClient(cfg, transport=transport, trust_policy=policy) as client:
        await client.cache.upsert_sid(
            SIDCacheEntry(
                id="mds1:Corp:default",
                mgmt_name="mds1",
                domain_name="Corp",
                sid="sid_readonly_cached",
                server_ip="10.0.0.1",
                last_used_at=now,
                expires_at=now + timedelta(seconds=300),
            )
        )
        res = await client.run_repository_script("mds1", "arodonata-collect-routes-v1", ["gw-01"], domain="Corp")
        assert res.success is True

    login_calls = [
        c
        for c in server.calls
        if c["command"] == "login" and c["payload"].get("session-name") == "arodonata-run-repo-script"
    ]
    run_calls = [c for c in server.calls if c["command"] == "run-script"]
    assert len(login_calls) == 1
    assert not login_calls[0]["payload"].get("read-only")
    assert len(run_calls) == 1
    assert run_calls[0]["sid"] != "sid_readonly_cached"
    assert run_calls[0]["sid"].startswith("sid_client_")


@pytest.mark.spec("SCN-CLIENT-013-1")
async def test_client_collect_change_report_cold_cache_warms_rulebase_through_coordinator() -> None:
    """SCN-CLIENT-013-1: `client.collect_change_report` warms cold rulebase cache via `DomainSyncCoordinator`."""
    dataset_dir = ensure_enterprise_raw_dataset()
    api_mock = FileReplayApiMock(dataset_dir)
    settings = ArodonataSettings(mgmt_name="mds", mgmt_ip="127.0.0.1", api_key="k")
    async with ArodonataClient(settings, api=api_mock) as client:
        sess_res = await api_mock.api_call(
            "mds", "show-sessions", {"limit": 1, "offset": 0, "view-published-sessions": True}, domain="Branch"
        )
        sessions_list = sess_res.data.get("objects") or []
        target_uid = sessions_list[0]["uid"]
        # Seed dirty-clean mock changes response on that session by performing an unpublished or published rule add
        sid, _ = await api_mock.create_dedicated_session("mds", "Branch")
        add_res = await api_mock.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": "Branch_Standard_Pkg Network",
                "position": "top",
                "name": "Rule_For_Report",
                "action": "Accept",
            },
            domain="Branch",
            sid=sid,
        )
        assert add_res.success is True
        pub = await api_mock.api_call("mds", "publish", {}, domain="Branch", sid=sid)
        assert pub.success is True
        await api_mock.logout_sid("mds", sid)
        latest = await api_mock.api_call("mds", "show-last-published-session", {}, domain="Branch")
        pub_uid = str(latest.data.get("uid") or target_uid)

        assert await client.cache.list_sync_states("mds", "Branch", scope="rulebase") == []
        report = await client.collect_change_report(
            [SessionScope(mgmt_name="mds", domain="Branch", session_uids=[pub_uid])]
        )
        assert len(report.sessions) == 1
        assert len(report.sessions[0].rule_changes) >= 1
        rb_states = await client.cache.list_sync_states("mds", "Branch", scope="rulebase")
        assert len(rb_states) >= 1
        assert rb_states[0].status == "ok"


@pytest.mark.spec("SCN-CLIENT-015-1")
async def test_otel_span_attrs_recursive_sanitization_chained_errors_and_noop(
    request: pytest.FixtureRequest,
) -> None:
    """SCN-CLIENT-015-1 (FC-02): Recursive dict/list/bytes sanitization, `__cause__`/`__context__` chaining, and no-op."""

    # 1. Zero-overhead no-op without recording span
    @traced
    def _noop_fn(x: int) -> int:
        span_attrs(sample="v", omitted=None)
        return x + 1

    assert _noop_fn(4) == 5

    # 2. Active TracerProvider records sanitized nested attrs and chained causes
    exporter = InMemorySpanExporter()
    proc = SimpleSpanProcessor(exporter)
    existing_provider = trace.get_tracer_provider()
    if hasattr(existing_provider, "add_span_processor"):
        existing_provider.add_span_processor(proc)
    else:
        provider = TracerProvider()
        provider.add_span_processor(proc)
        trace.set_tracer_provider(provider)
    request.addfinalizer(proc.shutdown)
    exporter.clear()

    @traced
    def _traced_op() -> None:
        span_attrs(
            safe="ok",
            empty_attr=None,
            nested={
                "token": "ok-visible",
                "api_key": "secret-nested-key",
                "password": "nested-password",
                "raw": b"secret-bytes-payload",
            },
            seq=[{"shared_secret": "shh-val"}, b"bytes-in-seq", "sid_12345_secret"],
        )
        try:
            try:
                raise RuntimeError("root api-key='raw-root-secret'")
            except RuntimeError as root_exc:
                raise ValueError("context password=ctx-secret") from root_exc
        except ValueError as chain_exc:
            try:
                raise RuntimeError("outer failure")
            except RuntimeError:
                raise chain_exc  # noqa: B904

    with pytest.raises(ValueError):
        _traced_op()

    spans = exporter.get_finished_spans()
    assert len(spans) >= 1
    sp = spans[-1]
    attrs = dict(sp.attributes or {})
    assert "arodonata.empty_attr" not in attrs
    assert attrs["arodonata.safe"] == "ok"
    nested_str = str(attrs["arodonata.nested"])
    assert "secret-nested-key" not in nested_str
    assert "nested-password" not in nested_str
    assert REDACTED_PLACEHOLDER in nested_str
    seq_str = str(attrs["arodonata.seq"])
    assert "shh-val" not in seq_str
    exc_events = [ev for ev in sp.events if ev.name == "exception"]
    assert exc_events


@pytest.mark.spec("SCN-CLIENT-016-1")
async def test_sse_adapter_serializes_domain_events_and_streams_wire_chunks() -> None:
    """SCN-CLIENT-016-1: `to_sse_event` and `stream_as_sse` format `SyncProgressEvent`, `CPCRUDEvent`, `StagedSessionEvent`."""
    ev1 = DomainSyncCompletedEvent(
        scope="objects", mgmt_name="mds", domain="Corp", processed=5, total=5, message="done"
    )
    ev2 = CPCRUDActionEvent(action_index=0, command="add-host", outcome="CREATE", message="created")
    ev3 = StagedSessionEvent(
        mgmt_name="mds",
        domain="Corp",
        session_uid="sess-u1",
        session_name="arodonata-cpcrud-staged",
        message="staged",
    )

    sse1 = to_sse_event(ev1)
    assert isinstance(sse1, SSEEvent)
    assert sse1.event == ev1.event_type
    assert sse1.data["domain"] == "Corp"

    async def _gen():
        for e in (ev1, ev2, ev3):
            yield e

    chunks = [chunk async for chunk in stream_as_sse(_gen())]
    assert len(chunks) == 3
    for idx, ev in enumerate((ev1, ev2, ev3)):
        assert isinstance(chunks[idx], SSEEvent)
        assert chunks[idx].event == ev.event_type
        wire = chunks[idx].encode()
        assert f"event: {ev.event_type}\n" in wire
        assert "data: {" in wire
        assert wire.endswith("\n\n")


@pytest.mark.spec("SCN-CLIENT-017-1")
async def test_client_facade_service_properties_and_methods_contract() -> None:
    """SCN-CLIENT-017-1: `ArodonataClient` exposes typed service properties and delegation methods."""
    settings = ArodonataSettings(mgmt_name="mds", mgmt_ip="10.0.0.1", api_key="k")
    async with ArodonataClient(settings) as client:
        assert client.db is not None
        assert client.cache is not None
        assert client.lock_port is not None
        assert client.api is not None
        assert client.amgmt is not None
        assert client.cpcrud is not None
        assert client.topology_service is not None
        assert client.script_service is not None
        assert client.api_reference is not None
        assert await client.ensure_api_reference() is client.api_reference

        called_gw: list[str] = []

        async def _gw_cli(target: str, cmd: str) -> str:
            called_gw.append(target)
            return ""

        client.set_gateway_cli(_gw_cli)
        client.invalidate_domain("mds", "Corp")
        status = await client.get_cache_status(mgmt_name="mds")
        assert isinstance(status, dict)


@pytest.mark.spec("SCN-CONFIG-002-2")
def test_api_keys_precedence_over_api_key_vars_in_mcp_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-CONFIG-002-2: `API_KEYS` takes precedence over `API_KEY_VARS` during MCP CLI startup."""
    monkeypatch.setenv("MGMT_NAMES", "mds1")
    monkeypatch.setenv("MGMT_SERVERS", "10.0.0.1")
    monkeypatch.setenv("API_KEYS", "explicit-inline-api-key")
    monkeypatch.setenv("API_KEY_VARS", "SECONDARY_VAR")
    monkeypatch.setenv("SECONDARY_VAR", "secondary-var-key")
    monkeypatch.setenv("ARODONATA_TLS_TRUST", "pinned")
    monkeypatch.setenv("ARODONATA_TLS_FINGERPRINTS", f"10.0.0.1:443={_make_der()[1]}")
    monkeypatch.setenv("ARODONATA_MCP_AUTH_MODE", "none")

    seen_settings: list[ArodonataSettings] = []

    def _fake_uvicorn(app: Any, **kwargs: Any) -> None:
        # Capture active settings from app state
        if hasattr(app, "state") and hasattr(app.state, "arodonata_client"):
            seen_settings.append(app.state.arodonata_client.settings)

    # Clear leftover mcp token env vars that might conflict
    rc = mcp_cli.run_cli(["--auth-mode", "none"], uvicorn_runner=_fake_uvicorn)
    assert rc == 0
    settings = ArodonataSettings()
    assert settings.servers["mds1"].api_key == "explicit-inline-api-key"


@pytest.mark.spec("SCN-CONFIG-003-2")
async def test_client_engine_none_disposes_across_all_three_auth_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """SCN-CONFIG-003-2: `engine=None` creates and disposes owned `:memory:` engine across api_key/credential/dynamic modes."""
    configs = [
        ("api_key", ArodonataSettings(mgmt_name="m1", mgmt_ip="10.0.0.1", api_key="secret")),
        ("credential", ArodonataSettings(mgmt_name="m1", mgmt_ip="10.0.0.1", username="admin", password="pw")),
        ("dynamic", ArodonataSettings(mgmt_name="m1", mgmt_ip="10.0.0.1")),
    ]
    for expected_mode, cfg in configs:
        assert cfg.auth_mode == expected_mode
        client = ArodonataClient(cfg, engine=None)
        assert client.owns_engine is True
        disposed_flag = [False]
        orig_close = client.db.close

        async def _spy_close(_orig: Any = orig_close, _flag: list[bool] = disposed_flag) -> None:
            await _orig()
            _flag[0] = True

        monkeypatch.setattr(client.db, "close", _spy_close)
        await client.initialize(run_startup_cleanup=False)
        await client.close(logout=False)
        assert disposed_flag[0] is True


@pytest.mark.spec("SCN-CONFIG-004-1")
async def test_transport_execute_and_show_task_socket_read_timeout_calculation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-CONFIG-004-1: `ApiTransport` and `show-task` compute `read_timeout = max(api_timeout, login_timeout) + 5`."""
    recorded_timeouts: list[aiohttp.ClientTimeout] = []

    class _FakeResp:
        status = 200
        headers: dict[str, str] = {}

        async def __aenter__(self) -> _FakeResp:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def read(self) -> bytes:
            return b'{"message":"OK"}'

    class _FakeSession:
        closed = False

        def post(
            self, url: str, *, headers: Any = None, data: Any = None, timeout: Any = None, allow_redirects: Any = None
        ) -> _FakeResp:
            recorded_timeouts.append(timeout)
            return _FakeResp()

        async def close(self) -> None:
            self.closed = True

    cfg = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="k",
        connect_timeout=12.0,
        api_timeout=40.0,
        login_timeout=75.0,
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={_make_der()[1]}",
    )
    policy = TrustPolicy(
        mode="pinned", known_hosts_path=tmp_path / "known.json", pinned_fingerprints=cfg.tls_fingerprints
    )
    transport = ApiTransport(settings=cfg, trust_policy=policy)
    monkeypatch.setattr(transport, "_ensure_aiohttp_session", lambda: asyncio.sleep(0, result=_FakeSession()))
    try:
        # 1. No explicit timeout -> max(40, 75) + 5 = 80s
        await transport.execute("10.0.0.1", "show-task", {"task-id": "t1"}, timeout=None)
        assert len(recorded_timeouts) == 1
        assert recorded_timeouts[0].sock_connect == 12.0
        assert recorded_timeouts[0].sock_read == 80.0

        # 2. Explicit budget -> budget + 5 = 25s
        await transport.execute("10.0.0.1", "show-hosts", {}, timeout=20.0)
        assert recorded_timeouts[1].sock_read == 25.0
    finally:
        await transport.close()


@pytest.mark.spec("SCN-CONFIG-009-1")
def test_operational_timeout_cache_and_version_settings_fields() -> None:
    """SCN-CONFIG-009-1: Extended `ArodonataSettings` operational/tuning fields validate defaults and overrides."""
    from pydantic import ValidationError as PydanticValidationError

    defaults = ArodonataSettings(mgmt_names="m1,m2", mgmt_servers="10.0.0.1,10.0.0.2", api_keys="k1,k2")
    assert defaults.mgmt_port == 443
    assert defaults.api_version is None
    assert defaults.session_expire_seconds == 540
    assert defaults.login_throttle_window == 70.0
    assert defaults.login_max_wait == 900.0
    assert defaults.domain_list_ttl == 3600
    assert defaults.max_incremental_changes == 500
    assert defaults.sqlite_busy_timeout_ms == 30000
    assert defaults.cpcrud_schema_path is None
    assert defaults.topology_confidence_weights is not None

    custom = ArodonataSettings(
        mgmt_names="m1,m2",
        mgmt_servers="10.0.0.1,10.0.0.2",
        api_keys="k1,k2",
        api_version="2.0",
        api_versions="1.9",
        mgmt_port=8443,
        session_expire_seconds=300,
        login_throttle_window=45.0,
        login_max_wait=120.0,
        domain_list_ttl=60,
        max_incremental_changes=50,
        sqlite_busy_timeout_ms=5000,
        cpcrud_schema_path="/tmp/custom_schema.json",
    )
    assert custom.servers["m1"].api_version == "1.9"
    assert custom.servers["m2"].api_version == "2.0"
    assert custom.mgmt_port == 8443
    assert custom.cpcrud_schema_path == "/tmp/custom_schema.json"

    with pytest.raises(PydanticValidationError):
        ArodonataSettings(mgmt_name="m1", mgmt_ip="10.0.0.1", api_key="k", max_incremental_changes=0)
