"""Wave 5 regression tests: CPCRUD virtual overlay coherency, rulebase shared BFS, and decomposition parity."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from arodonata import cpcrud as cpcrud_pkg
from arodonata import reports as reports_pkg
from arodonata import rulebase as rulebase_pkg
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter
from arodonata.core.events import DomainSyncProgressEvent, SyncProgressEvent
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import RulebasePackageLayerEntry
from arodonata.core.models.services import CPService
from arodonata.cpcrud import executor as executor_mod
from arodonata.cpcrud import planner as planner_mod
from arodonata.cpcrud import state_reader as state_reader_mod
from arodonata.cpcrud.executor import Executor, resolve_allowlisted_command
from arodonata.cpcrud.models import Outcome
from arodonata.cpcrud.planner import LOOKUP_ERROR_PREFIX, Planner
from arodonata.cpcrud.state_reader import HybridStateReader, StateLookupError, normalize_mask_length
from arodonata.reports import collector as reports_collector_mod
from arodonata.reports import renderer as reports_renderer_mod
from arodonata.reports.collector import collect_change_report, is_bare_uid
from arodonata.reports.renderer import build_change_report, render_change_report
from arodonata.rulebase import collector as rulebase_collector_mod
from arodonata.rulebase import refresh as rulebase_refresh_mod
from arodonata.rulebase.models import PolicyPackageInfo
from arodonata.rulebase.refresh import RulebaseRefreshService

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _REPO_ROOT / "src" / "arodonata"


class _OverlayFakeApi:
    """Minimal `ApiPort` double supporting head stamps, cold lookups, and `dns-domain` leading-dot checks."""

    def __init__(self, *, dns_domains: dict[str, dict[str, Any]] | None = None) -> None:
        self.published_uid = "pub-wave5-1"
        self.published_iso = "2026-11-19T12:00:00Z"
        self.dns_domains = dict(dns_domains or {})

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
        if command == "show-last-published-session":
            return ApiCallResult(
                success=True,
                data={"uid": self.published_uid, "publish-time": {"iso-8601": self.published_iso}},
            )
        if command == "show-dns-domain":
            target = str(req.get("name") or req.get("uid") or "")
            if target in self.dns_domains:
                return ApiCallResult(success=True, data=dict(self.dns_domains[target]))
        if command == "show-access-rulebase":
            return ApiCallResult(
                success=True,
                data={
                    "uid": "layer-net",
                    "name": str(req.get("name") or "Network"),
                    "total": 0,
                    "to": 0,
                    "rulebase": [],
                },
            )
        return ApiCallResult(
            success=False,
            status_code=404,
            error_code="generic_err_object_not_found",
            error_message="Requested object not found",
        )

    async def api_query(self, *args: Any, **kwargs: Any) -> ApiQueryResult:
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
        return "sid-wave5", "10.0.0.1"

    async def logout_sid(self, *args: Any, **kwargs: Any) -> bool:
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        return None


async def _seed_all_fresh(
    cache: SqlCacheAdapter,
    *,
    objects: list[CPObject] | None = None,
    services: list[CPService] | None = None,
    session_uid: str = "pub-wave5-1",
    cold_object_types: set[str] | None = None,
) -> None:
    pub_at = datetime(2026, 11, 19, 12, 0, 0)
    if objects:
        await cache.upsert_objects(objects)
    if services:
        await cache.upsert_services(services)
    for obj_type in ("host", "network", "address-range", "dns-domain", "group", "application-site"):
        if cold_object_types and obj_type in cold_object_types:
            continue
        await cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="objects",
                item_type=obj_type,
                last_session_uid=session_uid,
                last_published_at=pub_at,
                status="ok",
            )
        )
    for svc_type in ("service-tcp", "service-udp", "service-icmp", "service-icmp6", "service-other", "service-group"):
        await cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="services",
                item_type=svc_type,
                last_session_uid=session_uid,
                last_published_at=pub_at,
                status="ok",
            )
        )


@pytest.mark.asyncio
@pytest.mark.spec("SCN-CPCRUD-003-6")
async def test_planner_group_and_service_group_update_overlay_coherency_and_rename() -> None:
    """SCN-CPCRUD-003-6: Group and service-group UPDATEs update the virtual overlay for downstream template steps."""
    db = DatabaseManager(engine="sqlite+aiosqlite:///:memory:")
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        await _seed_all_fresh(
            cache,
            objects=[
                CPObject(
                    uid="u-h1", name="H1", type="host", mgmt_name="mds1", domain_name="Corp", ipv4_address="10.0.0.1"
                ),
                CPObject(
                    uid="u-h2", name="H2", type="host", mgmt_name="mds1", domain_name="Corp", ipv4_address="10.0.0.2"
                ),
                CPObject(
                    uid="u-h3", name="H3", type="host", mgmt_name="mds1", domain_name="Corp", ipv4_address="10.0.0.3"
                ),
                CPObject(
                    uid="u-h4", name="H4", type="host", mgmt_name="mds1", domain_name="Corp", ipv4_address="10.0.0.4"
                ),
                CPObject(
                    uid="u-grp",
                    name="grp-web",
                    type="group",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    members=["u-h1", "u-h2"],
                    comments="initial",
                    raw_data={
                        "uid": "u-grp",
                        "name": "grp-web",
                        "type": "group",
                        "members": [{"uid": "u-h1", "name": "H1"}, {"uid": "u-h2", "name": "H2"}],
                        "comments": "initial",
                    },
                ),
            ],
            services=[
                CPService(
                    uid="u-s1", name="TCP_80", type="service-tcp", mgmt_name="mds1", domain_name="Corp", port="80"
                ),
                CPService(
                    uid="u-s2", name="TCP_443", type="service-tcp", mgmt_name="mds1", domain_name="Corp", port="443"
                ),
                CPService(
                    uid="u-sg",
                    name="sg-app",
                    type="service-group",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    members=["u-s1"],
                    raw_data={
                        "uid": "u-sg",
                        "name": "sg-app",
                        "type": "service-group",
                        "members": [{"uid": "u-s1", "name": "TCP_80"}],
                    },
                ),
            ],
        )

        api = _OverlayFakeApi()
        planner = Planner(api=api, cache=cache)
        plan = await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "operations": [
                    {
                        "id": "g-upd-1",
                        "type": "group",
                        "operation": "set",
                        "name": "grp-web",
                        "new-name": "grp-web-v2",
                        "members": {"add": ["H3"], "remove": ["H1"]},
                        "comments": "updated",
                    },
                    {
                        "id": "g-upd-2",
                        "type": "group",
                        "operation": "set",
                        "name": "grp-web-v2",
                        "members": {"add": ["H3", "H4"]},
                        "comments": "updated",
                    },
                    {
                        "id": "g-noop",
                        "type": "group",
                        "operation": "present",
                        "name": "grp-web-v2",
                        "members": ["H2", "H3", "H4"],
                        "comments": "updated",
                    },
                    {
                        "id": "sg-upd-1",
                        "type": "service-group",
                        "operation": "set",
                        "name": "sg-app",
                        "new-name": "sg-app-v2",
                        "members": {"add": ["TCP_443"], "remove": ["TCP_80"]},
                    },
                    {
                        "id": "sg-upd-2",
                        "type": "service-group",
                        "operation": "set",
                        "name": "sg-app-v2",
                        "members": {"add": ["TCP_443", "TCP_8443"]},
                    },
                    {
                        "id": "rule-uses-renamed",
                        "type": "access-rule",
                        "layer": "Network",
                        "name": "Allow App",
                        "source": ["grp-web"],
                        "destination": ["Any"],
                        "service": ["sg-app"],
                        "action": "Accept",
                    },
                    {
                        "id": "g-stale-old-name",
                        "type": "group",
                        "operation": "set",
                        "name": "grp-web",
                        "comments": "should-fail",
                    },
                ],
            }
        )

        by_id = {a.action_id: a for a in plan.actions}

        assert by_id["g-upd-1"].outcome == Outcome.UPDATE
        assert by_id["g-upd-1"].resolved_name == "grp-web-v2"

        # Step 2 sees post-Step-1 overlay: H3 already added, comments already updated -> only H4 is added!
        assert by_id["g-upd-2"].outcome == Outcome.UPDATE
        assert by_id["g-upd-2"].payload["members"] == {"add": ["H4"]}
        assert "comments" not in by_id["g-upd-2"].payload
        assert by_id["g-upd-2"].prior_state is not None
        assert by_id["g-upd-2"].prior_state["members"] == ["H2", "H3"]

        # Step 3 sees full post-Step-2 group state and plans UNCHANGED.
        assert by_id["g-noop"].outcome == Outcome.UNCHANGED

        # Old name is tombstoned by rename, so strict set on old name fails closed.
        assert by_id["g-stale-old-name"].outcome == Outcome.ERROR

        # Service-group update + follow-up delta work identically.
        assert by_id["sg-upd-1"].outcome == Outcome.UPDATE
        assert by_id["sg-upd-1"].resolved_name == "sg-app-v2"
        assert by_id["sg-upd-2"].outcome == Outcome.UPDATE
        assert by_id["sg-upd-2"].payload["members"] == {"add": ["TCP_8443"]}
        assert by_id["sg-upd-2"].prior_state is not None
        assert by_id["sg-upd-2"].prior_state["members"] == ["TCP_443"]

        # Downstream rule resolves renamed group & service-group and records depends_on.
        assert by_id["rule-uses-renamed"].outcome == Outcome.CREATE
        assert by_id["rule-uses-renamed"].payload["source"] == ["grp-web-v2"]
        assert by_id["rule-uses-renamed"].payload["service"] == ["sg-app-v2"]
        assert "g-upd-1" in by_id["rule-uses-renamed"].depends_on
        assert "sg-upd-1" in by_id["rule-uses-renamed"].depends_on
    finally:
        await db.close()


@pytest.mark.asyncio
@pytest.mark.spec("SCN-CPCRUD-003-6")
async def test_planner_object_service_update_delete_overlay_coherency_and_wire_names() -> None:
    """SCN-CPCRUD-003-6: Object/service updates, deletes, DNS leading-dot reads, and CREATE->UPDATE/DELETE wire IDs."""
    db = DatabaseManager(engine="sqlite+aiosqlite:///:memory:")
    await db.initialize()
    try:
        cache = SqlCacheAdapter(db)
        await _seed_all_fresh(
            cache,
            cold_object_types={"dns-domain"},
            objects=[
                CPObject(
                    uid="u-h-old",
                    name="H_Old",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.0.0.1",
                ),
                CPObject(
                    uid="u-site-1",
                    name="Site_1",
                    type="application-site",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    primary_category="Custom_Application_Site",
                    url_list=["example.org"],
                    urls_defined_as_regular_expression=False,
                    raw_data={
                        "uid": "u-site-1",
                        "name": "Site_1",
                        "type": "application-site",
                        "primary-category": "Custom_Application_Site",
                        "url-list": ["example.org"],
                        "urls-defined-as-regular-expression": False,
                    },
                ),
            ],
            services=[
                CPService(
                    uid="u-s8080",
                    name="S_8080",
                    type="service-tcp",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    port="8080",
                    protocol="TCP",
                ),
                CPService(
                    uid="u-sicmp",
                    name="S_ICMP",
                    type="service-icmp",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    icmp_type=8,
                    icmp_code=0,
                ),
            ],
        )

        # Keep dns-domain slice cold in cache so live-API leading-dot retry is also exercised.
        api = _OverlayFakeApi(
            dns_domains={
                ".legacy.example": {
                    "uid": "u-dns-legacy",
                    "name": ".legacy.example",
                    "type": "dns-domain",
                    "is-sub-domain": True,
                }
            }
        )
        planner = Planner(api=api, cache=cache)

        plan = await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "on_ip_conflict": "reuse",
                "operations": [
                    # 1. Host IP update frees 10.0.0.1 and claims 10.0.0.2
                    {"id": "h-upd", "type": "host", "operation": "set", "name": "H_Old", "ipv4-address": "10.0.0.2"},
                    {
                        "id": "h-reuse-new-ip",
                        "type": "host",
                        "operation": "present",
                        "name": "H_Alias",
                        "ipv4-address": "10.0.0.2",
                    },
                    {
                        "id": "h-reclaim-old-ip",
                        "type": "host",
                        "operation": "present",
                        "name": "H_Free",
                        "ipv4-address": "10.0.0.1",
                    },
                    # 2. Application-site url-list + signature update reflected in follow-up value conflict & repeat
                    {
                        "id": "site-upd",
                        "type": "application-site",
                        "operation": "set",
                        "name": "Site_1",
                        "url-list": {"add": ["sub.example.org"]},
                        "application-signature": "sig-v2",
                    },
                    {
                        "id": "site-reuse",
                        "type": "application-site",
                        "operation": "present",
                        "name": "Site_Alias",
                        "url-list": ["example.org", "sub.example.org"],
                        "urls-defined-as-regular-expression": False,
                    },
                    {
                        "id": "site-noop",
                        "type": "application-site",
                        "operation": "present",
                        "name": "Site_1",
                        "url-list": ["example.org", "sub.example.org"],
                        "application-signature": "sig-v2",
                    },
                    # 3. Service port & ICMP updates reflected in overlay
                    {
                        "id": "svc-upd",
                        "type": "service-tcp",
                        "operation": "set",
                        "name": "S_8080",
                        "port": "8443",
                        "session-timeout": 60,
                    },
                    {
                        "id": "svc-reuse-new-port",
                        "type": "service-tcp",
                        "operation": "present",
                        "name": "S_Alias",
                        "port": "8443",
                    },
                    {
                        "id": "svc-free-old-port",
                        "type": "service-tcp",
                        "operation": "present",
                        "name": "S_Reclaim",
                        "port": "8080",
                    },
                    {
                        "id": "icmp-upd",
                        "type": "service-icmp",
                        "operation": "set",
                        "name": "S_ICMP",
                        "icmp-type": 13,
                        "icmp-code": 0,
                    },
                    {
                        "id": "icmp-reuse",
                        "type": "service-icmp",
                        "operation": "present",
                        "name": "S_ICMP_Alias",
                        "icmp-type": 13,
                        "icmp-code": 0,
                    },
                    # 4. Delete host, service, and live leading-dot dns-domain
                    {"id": "h-del", "type": "host", "operation": "absent", "name": "H_Old"},
                    {"id": "h-del-repeat", "type": "host", "operation": "absent", "name": "H_Old"},
                    {"id": "h-set-deleted", "type": "host", "operation": "set", "name": "H_Old", "comments": "dead"},
                    {
                        "id": "h-create-reclaimed",
                        "type": "host",
                        "operation": "present",
                        "name": "H_PostDel",
                        "ipv4-address": "10.0.0.2",
                    },
                    {"id": "dns-del", "type": "dns-domain", "operation": "absent", "name": "legacy.example"},
                    {
                        "id": "dns-set-deleted",
                        "type": "dns-domain",
                        "operation": "set",
                        "name": "legacy.example",
                        "comments": "dead",
                    },
                    # 5. Same-template CREATE -> UPDATE -> DELETE uses wire "name" (no "planned:" UID)
                    {
                        "id": "fresh-create",
                        "type": "host",
                        "operation": "add",
                        "name": "H_Fresh",
                        "ipv4-address": "10.2.0.1",
                    },
                    {"id": "fresh-upd", "type": "host", "operation": "set", "name": "H_Fresh", "comments": "v2"},
                    {"id": "fresh-del", "type": "host", "operation": "absent", "name": "H_Fresh"},
                ],
            }
        )

        by_id = {a.action_id: a for a in plan.actions}

        assert by_id["h-upd"].outcome == Outcome.UPDATE
        assert by_id["h-reuse-new-ip"].outcome == Outcome.REUSE
        assert by_id["h-reuse-new-ip"].resolved_name == "H_Old"
        assert by_id["h-reclaim-old-ip"].outcome == Outcome.CREATE

        assert by_id["site-upd"].outcome == Outcome.UPDATE
        assert by_id["site-reuse"].outcome == Outcome.REUSE
        assert by_id["site-reuse"].resolved_name == "Site_1"
        assert by_id["site-noop"].outcome == Outcome.UNCHANGED

        assert by_id["svc-upd"].outcome == Outcome.UPDATE
        assert by_id["svc-reuse-new-port"].outcome == Outcome.REUSE
        assert by_id["svc-reuse-new-port"].resolved_name == "S_8080"
        assert by_id["svc-free-old-port"].outcome == Outcome.CREATE
        assert by_id["icmp-upd"].outcome == Outcome.UPDATE
        assert by_id["icmp-reuse"].outcome == Outcome.REUSE
        assert by_id["icmp-reuse"].resolved_name == "S_ICMP"

        assert by_id["h-del"].outcome == Outcome.DELETE
        assert by_id["h-del-repeat"].outcome == Outcome.UNCHANGED
        assert by_id["h-set-deleted"].outcome == Outcome.ERROR
        assert by_id["h-create-reclaimed"].outcome == Outcome.CREATE

        assert by_id["dns-del"].outcome == Outcome.DELETE
        assert by_id["dns-del"].name == ".legacy.example"
        assert by_id["dns-set-deleted"].outcome == Outcome.ERROR

        assert by_id["fresh-create"].outcome == Outcome.CREATE
        assert by_id["fresh-upd"].outcome == Outcome.UPDATE
        assert by_id["fresh-upd"].payload == {"name": "H_Fresh", "comments": "v2"}
        assert by_id["fresh-del"].outcome == Outcome.DELETE
        assert by_id["fresh-del"].payload == {"name": "H_Fresh"}
    finally:
        await db.close()


class _BfsParityFakeApi:
    """`ApiPort` double exercising Global placeholder package-context re-fetch and inline layers."""

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
        if command == "show-packages":
            return ApiCallResult(
                success=True,
                data={
                    "packages": [
                        {
                            "uid": "pkg-1",
                            "name": "Corp_Pkg",
                            "nat-policy": False,
                            "access-layers": [
                                {"uid": "layer-global", "name": "Shared_Global", "position": 1},
                                {"uid": "layer-dom", "name": "Corp Network", "position": 2},
                            ],
                        }
                    ]
                },
            )
        if command in ("show-access-layers", "show-https-layers", "show-threat-layers"):
            return ApiCallResult(success=True, data={"objects": []})
        if command == "show-access-rulebase":
            target = req.get("uid") or req.get("name")
            pkg_ctx = req.get("package")
            if target == "layer-global":
                ph: dict[str, Any] = {"uid": "r-ph", "name": "PH", "type": "place-holder", "rule-number": 1}
                obj_dict: list[dict[str, Any]] = []
                if pkg_ctx:
                    ph["domain-layer"] = "layer-dom"
                    obj_dict.append({"uid": "layer-dom", "name": "Corp Network", "type": "access-layer"})
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "layer-global",
                        "name": "Shared_Global",
                        "total": 1,
                        "to": 1,
                        "objects-dictionary": obj_dict,
                        "rulebase": [ph],
                    },
                )
            if target == "layer-dom":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "layer-dom",
                        "name": "Corp Network",
                        "total": 1,
                        "to": 1,
                        "objects-dictionary": [{"uid": "layer-inline", "name": "Inline_Sub", "type": "access-layer"}],
                        "rulebase": [
                            {
                                "uid": "r-dom-1",
                                "name": "Inspect",
                                "type": "access-rule",
                                "rule-number": 1,
                                "action": "Apply Layer",
                                "inline-layer": "layer-inline",
                            }
                        ],
                    },
                )
            if target == "layer-inline":
                return ApiCallResult(
                    success=True,
                    data={
                        "uid": "layer-inline",
                        "name": "Inline_Sub",
                        "total": 1,
                        "to": 1,
                        "rulebase": [
                            {
                                "uid": "r-inl-1",
                                "name": "Allow Inline",
                                "type": "access-rule",
                                "rule-number": 1,
                                "action": "Accept",
                            }
                        ],
                    },
                )
        return ApiCallResult(success=False, status_code=404, error_message="Not found")

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
        if command == "show-packages":
            res = await self.api_call(mgmt_name, command, payload, domain=domain)
            pkgs = res.data.get("packages", []) if isinstance(res.data, dict) else []
            return ApiQueryResult(success=True, objects=pkgs, total=len(pkgs))
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
        return "sid", "10.0.0.1"

    async def logout_sid(self, *args: Any, **kwargs: Any) -> bool:
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.asyncio
@pytest.mark.spec("SCN-RULE-001-2", "SCN-RULE-003-1")
async def test_rulebase_shared_bfs_produces_identical_slice_and_snapshot_models_and_events() -> None:
    """Verify shared `_traverse_rulebase_layers` produces identical layers, rules, and progress events."""
    api = _BfsParityFakeApi()
    slice_events: list[SyncProgressEvent] = []
    full_events: list[SyncProgressEvent] = []

    async def _emit_slice(ev: SyncProgressEvent) -> None:
        slice_events.append(ev)

    async def _emit_full(ev: SyncProgressEvent) -> None:
        full_events.append(ev)

    pkg_info = PolicyPackageInfo(
        uid="pkg-1",
        name="Corp_Pkg",
        mgmt_name="mds1",
        domain_name="Corp",
        access_layers=[
            RulebasePackageLayerEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                package_uid="pkg-1",
                package_name="Corp_Pkg",
                rulebase_type="access",
                layer_uid="layer-global",
                layer_name="Shared_Global",
                position=1,
            ),
            RulebasePackageLayerEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                package_uid="pkg-1",
                package_name="Corp_Pkg",
                rulebase_type="access",
                layer_uid="layer-dom",
                layer_name="Corp Network",
                position=2,
            ),
        ],
    )

    slice_snap, replaced_uids, _ = await rulebase_refresh_mod.collect_package_rulebase_slice(
        api, "mds1", "Corp", pkg_info, rulebase_type="access", emit=_emit_slice
    )
    full_snap = await rulebase_refresh_mod.collect_domain_rulebase_snapshot(api, "mds1", "Corp", emit=_emit_full)

    assert set(replaced_uids) == {"layer-global", "layer-dom", "layer-inline"}
    assert [
        (layer.uid, layer.parent_layer_uid, layer.parent_rule_uid, layer.is_global) for layer in slice_snap.layers
    ] == [(layer.uid, layer.parent_layer_uid, layer.parent_rule_uid, layer.is_global) for layer in full_snap.layers]
    assert ("layer-global", None, None, True) in [
        (layer.uid, layer.parent_layer_uid, layer.parent_rule_uid, layer.is_global) for layer in full_snap.layers
    ]
    assert [
        (r.layer_uid, r.uid, r.placeholder_domain_layer_uid, r.inline_layer_uid) for r in slice_snap.access_rules
    ] == [(r.layer_uid, r.uid, r.placeholder_domain_layer_uid, r.inline_layer_uid) for r in full_snap.access_rules]
    assert [e.message for e in slice_events if isinstance(e, DomainSyncProgressEvent)] == [
        e.message for e in full_events if isinstance(e, DomainSyncProgressEvent)
    ]


@pytest.mark.spec("SCN-CLIENT-018-1")
def test_wave5_compat_imports_logger_traced_parity_and_loc_limits() -> None:
    """Verify backward-compatible shims, logger names, 10 @traced span names, and <=700 LOC module bounds."""
    assert cpcrud_pkg.Planner is planner_mod.Planner is Planner
    assert cpcrud_pkg.LOOKUP_ERROR_PREFIX == planner_mod.LOOKUP_ERROR_PREFIX == LOOKUP_ERROR_PREFIX
    assert cpcrud_pkg.Executor is executor_mod.Executor is Executor
    assert executor_mod.resolve_allowlisted_command is resolve_allowlisted_command
    assert cpcrud_pkg.HybridStateReader is state_reader_mod.HybridStateReader is HybridStateReader
    assert cpcrud_pkg.StateLookupError is state_reader_mod.StateLookupError is StateLookupError
    assert cpcrud_pkg.normalize_mask_length is state_reader_mod.normalize_mask_length is normalize_mask_length

    assert rulebase_pkg.RulebaseRefreshService is rulebase_refresh_mod.RulebaseRefreshService is RulebaseRefreshService
    assert (
        rulebase_pkg.collect_domain_rulebase_snapshot
        is rulebase_refresh_mod.collect_domain_rulebase_snapshot
        is rulebase_collector_mod.collect_domain_rulebase_snapshot
    )
    assert reports_pkg.collect_change_report is reports_collector_mod.collect_change_report is collect_change_report
    assert reports_pkg.is_bare_uid is reports_collector_mod.is_bare_uid is is_bare_uid
    assert reports_pkg.build_change_report is reports_renderer_mod.build_change_report is build_change_report
    assert reports_pkg.render_change_report is reports_renderer_mod.render_change_report is render_change_report

    assert reports_collector_mod.logger.name == "arodonata.reports.collector"

    expected_traced = [
        (Planner.decide, "arodonata.cpcrud.planner", "Planner.decide"),
        (Executor.apply, "arodonata.cpcrud.executor", "Executor.apply"),
        (Executor.publish_staged_session, "arodonata.cpcrud.executor", "Executor.publish_staged_session"),
        (Executor.discard_staged_session, "arodonata.cpcrud.executor", "Executor.discard_staged_session"),
        (
            RulebaseRefreshService.refresh_rulebases,
            "arodonata.rulebase.refresh",
            "RulebaseRefreshService.refresh_rulebases",
        ),
        (
            RulebaseRefreshService.refresh_policy_packages,
            "arodonata.rulebase.refresh",
            "RulebaseRefreshService.refresh_policy_packages",
        ),
        (
            RulebaseRefreshService.refresh_package_rulebase,
            "arodonata.rulebase.refresh",
            "RulebaseRefreshService.refresh_package_rulebase",
        ),
        (collect_change_report, "arodonata.reports.collector", "collect_change_report"),
        (render_change_report, "arodonata.reports.renderer", "render_change_report"),
        (build_change_report, "arodonata.reports.renderer", "build_change_report"),
    ]
    for fn, mod_name, qual_name in expected_traced:
        assert hasattr(fn, "__wrapped__"), f"{mod_name}.{qual_name} missing @traced wrapper"
        assert fn.__module__ == mod_name
        assert fn.__qualname__ == qual_name

    refactored_files = [
        "cpcrud/_state_reader_common.py",
        "cpcrud/_state_reader_objects.py",
        "cpcrud/_state_reader_services.py",
        "cpcrud/state_reader.py",
        "cpcrud/_planner_helpers.py",
        "cpcrud/_planner_diff.py",
        "cpcrud/_planner_entity_steps.py",
        "cpcrud/_planner_rule_steps.py",
        "cpcrud/planner.py",
        "cpcrud/_executor_helpers.py",
        "cpcrud/_executor_pass.py",
        "cpcrud/_executor_staged.py",
        "cpcrud/executor.py",
        "rulebase/collector.py",
        "rulebase/refresh.py",
        "reports/_collector_diffs.py",
        "reports/_collector_changes.py",
        "reports/collector.py",
        "reports/_renderer_formatting.py",
        "reports/_renderer_html.py",
        "reports/_renderer_markdown.py",
        "reports/renderer.py",
    ]
    for rel_path in refactored_files:
        line_count = len((_SRC_ROOT / rel_path).read_text(encoding="utf-8").splitlines())
        assert line_count <= 700, f"{rel_path} exceeds 700 LOC ({line_count})"
