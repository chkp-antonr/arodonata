"""Specification acceptance tests for `cpcrud`, `change-reports`, and `rulebase-and-numbering`."""

from __future__ import annotations

from collections.abc import Awaitable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from arodonata import ArodonataClient
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.errors import AmbiguousLayerName, ChangeReportInputError
from arodonata.core.events import DomainSyncFailedEvent, StagedSessionEvent
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo, DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    ThreatRuleEntry,
)
from arodonata.core.models.services import CPService
from arodonata.core.services import DomainService, DomainSyncCoordinator
from arodonata.cpcrud.executor import Executor
from arodonata.cpcrud.inverse import build_inverse_template
from arodonata.cpcrud.models import (
    ActionResult,
    ApplyReport,
    DomainStamp,
    NamingPrefixes,
    Outcome,
    Plan,
    PlannedAction,
)
from arodonata.cpcrud.planner import LOOKUP_ERROR_PREFIX, Planner
from arodonata.cpcrud.rule_identity import NAT_ANY_OBJECT_UID, NAT_ORIGINAL_OBJECT_UID
from arodonata.reports import ChangeReport, RenderedReportBundle, collect_change_report, render_change_report
from arodonata.reports.models import (
    FieldDiff,
    ObjectChangeEntry,
    RangeScope,
    RenderOptions,
    SessionChangeReport,
    SessionScope,
)
from arodonata.rulebase import (
    CachedRulebaseSource,
    RulebaseRefreshService,
    collect_domain_rulebase_snapshot,
    extract_policy_packages,
    filter_numbered_rulebase,
    format_rules_markdown,
    format_rules_model_friendly,
    number_package_rulebase,
    rule_to_cpcrud_operation,
)


class _SpecFakeApi:
    """Flexible in-memory `ApiPort` double for CPCRUD, Reports, and Rulebase spec tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None, str | None]] = []
        self.head_uid = "pub-head-1"
        self.head_iso = "2026-10-24T08:00:00Z"
        self.head_readable = True
        self.show_session_overrides: dict[str, ApiCallResult] = {}
        self.show_changes_data: dict[str, dict[str, Any]] = {}
        self.sessions_by_uid: dict[str, dict[str, Any]] = {}
        self.sessions_list: list[dict[str, Any]] = []
        self.objects_by_uid: dict[str, dict[str, Any]] = {}
        self.objects_by_name: dict[str, dict[str, Any]] = {}
        self.fail_queries: dict[str, ApiQueryResult] = {}
        self.fail_calls: dict[str, ApiCallResult] = {}
        self.services_by_cmd: dict[str, list[dict[str, Any]]] = {}
        self.packages: list[dict[str, Any]] = []
        self.rulebase_by_cmd_target: dict[tuple[str, str], dict[str, Any]] = {}
        self.logged_out_sids: list[str] = []

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
        self.calls.append((mgmt_name, command, req, domain, sid))
        if command in self.fail_calls:
            return self.fail_calls[command]
        if command == "show-last-published-session":
            if not self.head_readable:
                return ApiCallResult(success=False, status_code=503, error_message="head unreachable")
            return ApiCallResult(success=True, data={"uid": self.head_uid, "publish-time": {"iso-8601": self.head_iso}})
        if command == "show-session":
            req_uid = str(req.get("uid") or "")
            if req_uid and req_uid in self.show_session_overrides:
                return self.show_session_overrides[req_uid]
            if not req_uid and sid in self.show_session_overrides:
                return self.show_session_overrides[sid]
            uid_val = str(req_uid or "uid-staged-1")
            return ApiCallResult(
                success=True,
                data={
                    "uid": uid_val,
                    "user-name": "admin",
                    "application": "arodonata",
                    "state": "open",
                    "locks": 0,
                    "changes": 0,
                    "number-of-published-changes": 0,
                },
            )
        if command == "show-sessions":
            return ApiCallResult(
                success=True, data={"objects": list(self.sessions_list), "total": len(self.sessions_list)}
            )
        if command == "show-changes":
            to_sess = str(req.get("to-session") or "")
            return ApiCallResult(success=True, data=self.show_changes_data.get(to_sess, {"changes": []}))
        if command == "show-object":
            uid = str(req.get("uid") or "")
            if uid in self.objects_by_uid:
                return ApiCallResult(success=True, data={"object": self.objects_by_uid[uid]})
            return ApiCallResult(success=False, status_code=404, error_message="not found")
        if command == "show-host":
            name = str(req.get("name") or "")
            if name in self.objects_by_name:
                return ApiCallResult(success=True, data=self.objects_by_name[name])
            return ApiCallResult(
                success=False,
                status_code=404,
                error_code="generic_err_object_not_found",
                error_message="Requested object not found",
            )
        if command in ("show-access-rulebase", "show-nat-rulebase"):
            target = str(req.get("name") or req.get("uid") or req.get("package") or "")
            data = self.rulebase_by_cmd_target.get((command, target), {"rulebase": [], "to": 0, "total": 0})
            return ApiCallResult(success=True, data=data)
        if command == "where-used":
            return ApiCallResult(
                success=True,
                data={"used-directly": {"objects": [], "access-control-rules": []}, "used-indirectly": {"objects": []}},
            )
        if command == "take-over-session":
            return ApiCallResult(success=True, data={"uid": req.get("uid")})
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
        req = dict(payload or {})
        self.calls.append((mgmt_name, f"query:{command}", req, domain, sid))
        if command in self.fail_queries:
            return self.fail_queries[command]
        if command in self.services_by_cmd:
            items = self.services_by_cmd[command]
            return ApiQueryResult(success=True, objects=items, total=len(items))
        if command == "show-sessions":
            return ApiQueryResult(success=True, objects=list(self.sessions_list), total=len(self.sessions_list))
        if command == "show-packages":
            objs = list(self.packages) if domain in (None, "Corp", "OnlyDomain") else []
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
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
        return ("sid_spec_rw_secret", "10.0.0.1")

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
        timeout: float = 5.0,
    ) -> Awaitable[bool]:
        async def _done() -> bool:
            self.logged_out_sids.append(sid)
            return True

        return _done()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


# ==============================================================================
# CPCRUD Scenarios
# ==============================================================================


@pytest.mark.spec("SCN-CPCRUD-003-2")
async def test_cpcrud_service_naming_prefixes_and_existing_auto_name_diff() -> None:
    """SCN-CPCRUD-003-2 (FC-06): UDP_/ICMP_ auto-naming + diffing existing auto-named entities on create_new."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = _SpecFakeApi()
    try:
        # Existing hosts/services cause IP/port conflicts:
        # - 10.1.1.5 owned by "LegacyHost", and "H_10.1.1.5" ALSO already exists with different comments!
        await cache.replace_domain_objects(
            "mds1",
            "Corp",
            [
                CPObject(
                    uid="h-legacy",
                    name="LegacyHost",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.1.1.5",
                ),
                CPObject(
                    uid="h-auto",
                    name="H_10.1.1.5",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.1.1.5",
                    raw_data={"comments": "old auto comment"},
                ),
            ],
            types=["host"],
        )
        await cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="objects",
                item_type="host",
                last_session_uid="pub-head-1",
                last_published_at=datetime(2026, 10, 24, 8, 0, 0),
                status="ok",
                object_count=2,
            )
        )
        # Seed existing custom TCP 8080 and ICMP 8/0 services
        await cache.replace_domain_services(
            "mds1",
            "Corp",
            [
                CPService(
                    uid="s-u-old",
                    name="ExistingUdp",
                    type="service-udp",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    port="5353",
                ),
                CPService(
                    uid="s-i-old",
                    name="ExistingIcmp",
                    type="service-icmp",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    icmp_type=8,
                    icmp_code=0,
                    raw_data={"icmp-type": 8, "icmp-code": 0},
                ),
            ],
            types=["service-udp", "service-icmp"],
        )
        for stype in ("service-udp", "service-icmp"):
            await cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    scope="services",
                    item_type=stype,
                    last_session_uid="pub-head-1",
                    last_published_at=datetime(2026, 10, 24, 8, 0, 0),
                    status="ok",
                    object_count=1,
                )
            )

        planner = Planner(
            api=api,
            cache=cache,
            default_mgmt_name="mds1",
            default_naming_prefixes=NamingPrefixes(host="H_", udp="UDP_", icmp="ICMP_"),
        )

        tmpl = {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "on_ip_conflict": "create_new",
            "on_name_conflict": "update",
            "objects": [
                {
                    "operation": "present",
                    "type": "host",
                    "name": "WantAliasHost",
                    "ipv4-address": "10.1.1.5",
                    "comments": "updated auto comment",
                },
            ],
            "services": [
                {"operation": "present", "type": "service-udp", "name": "WantNewUdp", "port": "5353"},
                {"operation": "present", "type": "service-icmp", "name": "WantNewIcmp", "icmp-type": 8, "icmp-code": 0},
            ],
        }
        plan = await planner.decide(tmpl)
        host_act = next(a for a in plan.actions if a.object_type == "host")
        udp_act = next(a for a in plan.actions if a.object_type == "service-udp")
        icmp_act = next(a for a in plan.actions if a.object_type == "service-icmp")

        # FC-06: existing auto-name H_10.1.1.5 was NOT blindly returned as UNCHANGED!
        assert host_act.outcome == Outcome.UPDATE
        assert host_act.command == "set-host"
        assert "comments" in host_act.diffs
        assert udp_act.outcome == Outcome.CREATE and udp_act.name == "UDP_5353"
        assert icmp_act.outcome == Outcome.CREATE and icmp_act.name == "ICMP_8_0"

        # Under on_name_conflict="error", differing auto-named object emits ERROR instead of silent UNCHANGED
        tmpl_err = dict(tmpl, on_name_conflict="error")
        plan_err = await planner.decide(tmpl_err)
        host_err = next(a for a in plan_err.actions if a.object_type == "host")
        assert host_err.outcome == Outcome.ERROR
    finally:
        await db.close()


@pytest.mark.spec("SCN-CPCRUD-003-3")
async def test_planner_lookup_failures_emit_error_and_skip_dependents() -> None:
    """SCN-CPCRUD-003-3: `paging_inconsistent`, service, rulebase, and `where-used` lookup failures emit ERROR + SKIPPED_DEPENDENCY."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = _SpecFakeApi()
    try:
        # 1. show-objects paging_inconsistent -> host action ERROR, dependent access-rule SKIPPED_DEPENDENCY
        api.fail_queries["show-objects"] = ApiQueryResult(
            success=False, error_message="paging gap", code="paging_inconsistent"
        )
        api.fail_queries["show-services-tcp"] = ApiQueryResult(
            success=False, error_message="svc lookup down", code="api_error"
        )
        api.fail_calls["show-access-rulebase"] = ApiCallResult(
            success=False, status_code=500, error_message="rulebase read error"
        )
        api.fail_calls["where-used"] = ApiCallResult(success=False, status_code=500, error_message="where-used error")
        api.objects_by_name["Old_Host_To_Delete"] = {
            "uid": "h-old-del",
            "name": "Old_Host_To_Delete",
            "type": "host",
            "ipv4-address": "10.9.9.9",
        }

        planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")
        plan = await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "operations": [
                    {"operation": "present", "type": "host", "name": "Web_1", "ipv4-address": "10.1.1.10"},
                    {"operation": "present", "type": "service-tcp", "name": "TCP_8443", "port": "8443"},
                    {
                        "operation": "present",
                        "type": "access-rule",
                        "layer": "Network",
                        "name": "Rule_Need_Host",
                        "source": ["Web_1"],
                        "destination": ["Any"],
                        "service": ["TCP_8443"],
                        "action": "Accept",
                    },
                    {"operation": "delete", "type": "host", "name": "Old_Host_To_Delete", "check_where_used": True},
                ],
            }
        )
        host_act = next(a for a in plan.actions if a.object_type == "host" and a.operation == "present")
        svc_act = next(a for a in plan.actions if a.object_type == "service-tcp")
        rule_act = next(a for a in plan.actions if a.object_type == "access-rule")
        del_act = next(a for a in plan.actions if a.operation == "delete")

        assert host_act.outcome == Outcome.ERROR and LOOKUP_ERROR_PREFIX in (host_act.error or host_act.message)
        assert svc_act.outcome == Outcome.ERROR
        assert rule_act.outcome == Outcome.SKIPPED_DEPENDENCY
        assert del_act.outcome == Outcome.ERROR  # failed show-objects or where-used refuses delete
    finally:
        await db.close()


@pytest.mark.spec("SCN-CPCRUD-006-1")
async def test_application_site_validation_and_absent_present_plan_rejection() -> None:
    """SCN-CPCRUD-006-1: Static validator rejects `add` without url-list/signature, allows `present`, and Planner rejects absent `present`."""
    async with ArodonataClient(
        ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k"), api=_SpecFakeApi()
    ) as client:
        # Valid add with url-list passes
        assert (
            client.cpcrud.validate(
                {
                    "domain": "Corp",
                    "objects": [
                        {
                            "operation": "add",
                            "type": "application-site",
                            "name": "App_Good",
                            "primary-category": "Custom_Application_Site",
                            "url-list": [r"\.example\.com"],
                            "urls-defined-as-regular-expression": True,
                        }
                    ],
                }
            )
            == []
        )

        # `add` omitting both url-list and application-signature fails static validation
        add_errs = client.cpcrud.validate(
            {
                "domain": "Corp",
                "objects": [
                    {
                        "operation": "add",
                        "type": "application-site",
                        "name": "App_NoUrl",
                        "primary-category": "Custom_Application_Site",
                    }
                ],
            }
        )
        assert add_errs

        # `present` metadata update omitting both passes static validate(), then Planner rejects absent target
        present_tmpl = {
            "mgmt_name": "mds1",
            "domain": "Corp",
            "objects": [
                {
                    "operation": "present",
                    "type": "application-site",
                    "name": "App_Absent_Meta",
                    "description": "only metadata",
                }
            ],
        }
        assert client.cpcrud.validate(present_tmpl) == []
        plan = await client.cpcrud.plan(present_tmpl)
        assert plan.actions[0].outcome == Outcome.ERROR
        assert "url-list" in (plan.actions[0].error or plan.actions[0].message)


@pytest.mark.spec("SCN-CPCRUD-008-2")
async def test_nat_rule_omitted_translated_fields_normalize_against_original_uid() -> None:
    """SCN-CPCRUD-008-2: Omitted `translated-*` fields normalize idempotently against `NAT_ORIGINAL_OBJECT_UID`."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = _SpecFakeApi()
    api.rulebase_by_cmd_target[("show-nat-rulebase", "Standard")] = {
        "uid": "pkg-std",
        "name": "Standard",
        "rulebase": [
            {
                "uid": "nat-r1",
                "type": "nat-rule",
                "rule-number": 1,
                "enabled": True,
                "method": "static",
                "original-source": {"uid": "h-srv", "name": "Srv_10.1.1.1"},
                "original-destination": {"uid": NAT_ANY_OBJECT_UID, "name": "Any"},
                "original-service": {"uid": NAT_ANY_OBJECT_UID, "name": "Any"},
                "translated-source": {"uid": "h-nat", "name": "Nat_192.0.2.1"},
                "translated-destination": {"uid": NAT_ORIGINAL_OBJECT_UID, "name": "Original"},
                "translated-service": {"uid": NAT_ORIGINAL_OBJECT_UID, "name": "Original"},
                "install-on": [{"name": "Policy Targets"}],
            }
        ],
        "objects-dictionary": [
            {"uid": "h-srv", "name": "Srv_10.1.1.1"},
            {"uid": "h-nat", "name": "Nat_192.0.2.1"},
            {"uid": NAT_ANY_OBJECT_UID, "name": "Any"},
            {"uid": NAT_ORIGINAL_OBJECT_UID, "name": "Original"},
        ],
        "to": 1,
        "total": 1,
    }
    try:
        await cache.replace_domain_objects(
            "mds1",
            "Corp",
            [
                CPObject(
                    uid="h-srv",
                    name="Srv_10.1.1.1",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.1.1.1",
                ),
                CPObject(
                    uid="h-nat",
                    name="Nat_192.0.2.1",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="192.0.2.1",
                ),
            ],
            types=["host"],
        )
        await cache.upsert_sync_state(
            DomainSyncState(
                mgmt_name="mds1",
                domain_name="Corp",
                scope="objects",
                item_type="host",
                last_session_uid="pub-head-1",
                status="ok",
                object_count=2,
            )
        )
        planner = Planner(api=api, cache=cache, default_mgmt_name="mds1")
        plan = await planner.decide(
            {
                "mgmt_name": "mds1",
                "domain": "Corp",
                "operations": [
                    {
                        "operation": "present",
                        "type": "nat-rule",
                        "package": "Standard",
                        "method": "static",
                        "original-source": "Srv_10.1.1.1",
                        "translated-source": "Nat_192.0.2.1",
                    }
                ],
            }
        )
        assert len(plan.actions) == 1
        assert plan.actions[0].outcome == Outcome.UNCHANGED
    finally:
        await db.close()


@pytest.mark.spec("SCN-CPCRUD-010-1")
async def test_executor_apply_refuses_unreadable_head_with_zero_writes() -> None:
    """SCN-CPCRUD-010-1: `apply(plan, force=False)` refuses unreadable stamp or pre-apply probe error cleanly."""
    api = _SpecFakeApi()
    executor = Executor(api=api)

    # 1. Plan built with unreadable DomainStamp
    unreadable_plan = Plan(
        domain_stamps={
            "mds1:Corp": DomainStamp(
                mgmt_name="mds1", domain_name="Corp", last_published_session_uid=None, readable=False
            )
        },
        actions=[
            PlannedAction(
                action_id="a1",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="add",
                object_type="host",
                name="H1",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "H1", "ipv4-address": "10.0.0.1"},
            )
        ],
    )
    rep1 = await executor.apply(unreadable_plan, force=False)
    assert rep1.results[0].outcome == Outcome.PLAN_STALE
    assert not any(c[1] in ("add-host", "publish") for c in api.calls)

    # 2. Plan readable at plan time, pre-apply show-last-published-session becomes unreadable
    api.head_readable = False
    readable_plan = Plan(
        domain_stamps={
            "mds1:Corp": DomainStamp(
                mgmt_name="mds1",
                domain_name="Corp",
                last_session_uid="pub-head-1",
                last_published_at=datetime(2026, 10, 24, 8, 0, 0),
                readable=True,
            )
        },
        actions=unreadable_plan.actions,
    )
    rep2 = await executor.apply(readable_plan, force=False)
    assert rep2.results[0].outcome == Outcome.PLAN_STALE
    assert not any(c[1] in ("add-host", "publish") for c in api.calls)


@pytest.mark.spec("SCN-CPCRUD-011-1")
async def test_keep_session_defaults_staged_name_registers_internally_and_emits_event() -> None:
    """SCN-CPCRUD-011-1: `keep_session=True` defaults session_name to `arodonata-cpcrud-staged`, registers in `Executor._staged_sessions`, and emits `StagedSessionEvent`."""
    api = _SpecFakeApi()
    executor = Executor(api=api)
    plan = Plan(
        domain_stamps={
            "mds1:Corp": DomainStamp(
                mgmt_name="mds1",
                domain_name="Corp",
                last_session_uid="pub-head-1",
                last_published_at=datetime(2026, 10, 24, 8, 0, 0),
                readable=True,
            )
        },
        actions=[
            PlannedAction(
                action_id="a1",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="add",
                object_type="host",
                name="H_Staged",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "H_Staged", "ipv4-address": "10.0.0.99"},
            )
        ],
    )
    events = [ev async for ev in executor.stream_apply(plan, no_publish=True, keep_session=True)]
    staged_events = [e for e in events if isinstance(e, StagedSessionEvent)]
    assert len(staged_events) == 1
    assert executor.last_report is not None
    assert len(executor.last_report.staged_sessions) == 1
    staged = executor.last_report.staged_sessions[0]
    assert staged.session_name == "arodonata-cpcrud-staged"
    assert "sid_spec_rw_secret" not in repr(staged)
    assert ("mds1", "Corp", staged.session_uid) in executor._staged_sessions


@pytest.mark.spec("SCN-CPCRUD-011-4")
async def test_staged_adoption_refuses_foreign_smartconsole_discarded_and_omits_force_disconnect() -> None:
    """SCN-CPCRUD-011-4: Refuses SmartConsole, foreign, mismatched, and discarded sessions; omits disconnect when force_disconnect=False."""
    api = _SpecFakeApi()
    executor = Executor(api=api)

    api.show_session_overrides = {
        "sc-uid": ApiCallResult(success=True, data={"uid": "sc-uid", "application": "SmartConsole", "state": "open"}),
        "foreign-uid": ApiCallResult(
            success=True,
            data={"uid": "foreign-uid", "user-name": "other_admin", "application": "web_api", "state": "open"},
        ),
        "discarded-uid": ApiCallResult(
            success=True,
            data={
                "uid": "discarded-uid",
                "name": "arodonata-cpcrud-staged",
                "application": "arodonata",
                "state": "discarded",
            },
        ),
        "blank-app-uid": ApiCallResult(
            success=True,
            data={
                "uid": "blank-app-uid",
                "name": "arodonata-cpcrud-staged",
                "application": "",
                "user-name": "admin",
                "state": "open",
            },
        ),
    }

    for bad_uid in ("sc-uid", "foreign-uid", "discarded-uid"):
        api.calls.clear()
        api.logged_out_sids.clear()
        res = await executor.publish_staged_session("mds1", "Corp", session_uid=bad_uid)
        assert res.success is False
        assert not any(c[1] in ("take-over-session", "switch-session", "publish") for c in api.calls)
        assert "sid_spec_rw_secret" in api.logged_out_sids

    # Mismatched expected_session_name refused cleanly
    res_mismatch = await executor.discard_staged_session(
        "mds1",
        "Corp",
        session_uid="blank-app-uid",
        expected_session_name="wrong-ticket",
    )
    assert res_mismatch.success is False

    # Eligible empty-application session adopts non-disruptively with force_disconnect=False (no disconnect-active-session key)
    api.calls.clear()
    res_ok = await executor.publish_staged_session(
        "mds1",
        "Corp",
        session_uid="blank-app-uid",
        force_disconnect=False,
        allow_stale=True,
    )
    assert res_ok.success is True
    takeover_calls = [c for c in api.calls if c[1] == "take-over-session"]
    assert len(takeover_calls) == 1
    assert takeover_calls[0][2] == {"uid": "blank-app-uid"}
    assert "disconnect-active-session" not in (takeover_calls[0][2] or {})


@pytest.mark.spec("SCN-CPCRUD-012-1")
def test_inverse_template_reverses_only_succeeded_actions_from_mixed_report() -> None:
    """SCN-CPCRUD-012-1: `inverse(plan, report)` skips ERROR/SKIPPED_DEPENDENCY/PLAN_STALE and deletes CREATE by concrete created_uid."""
    plan = Plan(
        actions=[
            PlannedAction(
                action_id="a-ok-create",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="add",
                object_type="host",
                name="H_Created",
                target_uid="planned:H_Created",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "H_Created", "ipv4-address": "10.0.0.1"},
            ),
            PlannedAction(
                action_id="a-err",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="add",
                object_type="host",
                name="H_Failed",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "H_Failed", "ipv4-address": "10.0.0.2"},
            ),
            PlannedAction(
                action_id="a-skip",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="host",
                name="H_Skipped",
                target_uid="uid-skip",
                outcome=Outcome.UPDATE,
                command="set-host",
                payload={"uid": "uid-skip", "comments": "x"},
                prior_state={"uid": "uid-skip", "comments": "old"},
            ),
            PlannedAction(
                action_id="a-stale",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="delete",
                object_type="host",
                name="H_Stale",
                target_uid="uid-stale",
                outcome=Outcome.DELETE,
                command="delete-host",
                payload={"uid": "uid-stale"},
                prior_state={"uid": "uid-stale", "name": "H_Stale", "ipv4-address": "10.0.0.3"},
            ),
        ]
    )
    report = ApplyReport(
        results=[
            ActionResult(
                action_id="a-ok-create",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="add",
                object_type="host",
                planned_outcome=Outcome.CREATE,
                command="add-host",
                outcome=Outcome.CREATE,
                success=True,
                target_uid="real-uid-created-99",
            ),
            ActionResult(
                action_id="a-err",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="add",
                object_type="host",
                planned_outcome=Outcome.CREATE,
                command="add-host",
                outcome=Outcome.ERROR,
                success=False,
                error="failed",
            ),
            ActionResult(
                action_id="a-skip",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="host",
                planned_outcome=Outcome.UPDATE,
                command="set-host",
                outcome=Outcome.SKIPPED_DEPENDENCY,
                success=False,
                error="skipped",
            ),
            ActionResult(
                action_id="a-stale",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="delete",
                object_type="host",
                planned_outcome=Outcome.DELETE,
                command="delete-host",
                outcome=Outcome.PLAN_STALE,
                success=False,
                error="stale",
            ),
        ]
    )
    inv = build_inverse_template(plan, report)
    ops = inv["operations"]
    assert len(ops) == 1
    assert ops[0]["operation"] == "delete"
    assert ops[0]["uid"] == "real-uid-created-99"


@pytest.mark.spec("SCN-CPCRUD-013-1")
async def test_cpcrud_service_validate_schema_path_and_plan_overrides() -> None:
    """SCN-CPCRUD-013-1: `CPCRUDService.validate(schema_path=...)` and `plan(...)` conflict/prefix/validate_schema overrides."""
    from arodonata.cpcrud import validator as val_mod

    bundled_schema = Path(val_mod.__file__).with_name("checkpoint_ops_schema.json")
    async with ArodonataClient(
        ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k"), api=_SpecFakeApi()
    ) as client:
        tmpl_schema = {
            "domain": "Corp",
            "objects": [{"operation": "present", "type": "host", "name": "H_Custom", "ipv4-address": "10.2.2.2"}],
        }
        assert client.cpcrud.validate(tmpl_schema, schema_path=bundled_schema) == []

        plan = await client.cpcrud.plan(
            {"mgmt_name": "mds1", **tmpl_schema},
            on_name_conflict="update",
            on_ip_conflict="create_new",
            naming_prefixes=NamingPrefixes(host_prefix="CUSTOM_"),
            validate_schema=False,
        )
        assert len(plan.actions) == 1
        assert plan.actions[0].outcome == Outcome.CREATE
        assert plan.actions[0].name == "H_Custom"


# ==============================================================================
# Change Reports Scenarios
# ==============================================================================


@pytest.mark.spec("SCN-REPORT-001-1")
async def test_show_changes_wire_payload_and_session_uid_filtering() -> None:
    """SCN-REPORT-001-1: `show-changes` sends `to-session` without `from-session` and filters multi-session entries."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = _SpecFakeApi()
    api.show_changes_data["sess-target"] = {
        "changes": [
            {
                "session": {"uid": "sess-unrelated"},
                "added-objects": [{"uid": "o-other", "name": "OtherHost", "type": "host"}],
            },
            {
                "session": {"uid": "sess-target"},
                "added-objects": [
                    {"uid": "o-target", "name": "TargetHost", "type": "host", "ipv4-address": "10.9.9.9"}
                ],
            },
        ]
    }
    try:
        report = await collect_change_report(
            api, cache, [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-target"])]
        )
        ch_calls = [c for c in api.calls if c[1] == "show-changes"]
        assert len(ch_calls) == 1
        assert ch_calls[0][2] == {"to-session": "sess-target", "details-level": "full"}
        assert "from-session" not in (ch_calls[0][2] or {})
        names = [oc.name for oc in report.sessions[0].object_changes]
        assert "TargetHost" in names
        assert "OtherHost" not in names
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-001-2")
async def test_range_scope_widens_utc_dates_or_omits_dates_when_from_session_set() -> None:
    """SCN-REPORT-001-2: `show-sessions` widens `from`/`to` dates by +/-1 UTC day, and omits dates with `from_session`."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = _SpecFakeApi()
    t_from = datetime(2026, 10, 10, 12, 0, 0, tzinfo=UTC)
    t_to = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)
    api.sessions_list = [
        {"uid": "s1", "state": "published", "publish-time": {"iso-8601": "2026-10-11T10:00:00Z"}},
    ]
    api.show_changes_data["s1"] = {"changes": []}
    try:
        # 1. Date range -> +/-1 day UTC widening on wire payload
        await collect_change_report(
            api, cache, [RangeScope(mgmt_name="mds1", domain="Corp", from_date=t_from, to_date=t_to)]
        )
        s_calls_1 = [c for c in api.calls if c[1] == "query:show-sessions"]
        assert len(s_calls_1) == 1
        assert str(s_calls_1[0][2]["from"]).startswith("2026-10-09")
        assert str(s_calls_1[0][2]["to"]).startswith("2026-10-13")

        # 2. from_session set -> server date params omitted
        api.calls.clear()
        await collect_change_report(
            api, cache, [RangeScope(mgmt_name="mds1", domain="Corp", from_session="s0", to_session="s1")]
        )
        s_calls_2 = [c for c in api.calls if c[1] == "query:show-sessions"]
        assert len(s_calls_2) == 1
        assert "from" not in (s_calls_2[0][2] or {})
        assert "to" not in (s_calls_2[0][2] or {})
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-002-3")
async def test_service_and_application_site_field_diffs_and_summary_fields() -> None:
    """SCN-REPORT-002-3 (FC-07): TCP/UDP/ICMP/other services and `application-site` emit FieldDiff & summary_fields."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = _SpecFakeApi()
    api.show_changes_data["sess-svc-diff"] = {
        "changes": [
            {
                "added-objects": [
                    {"uid": "s-tcp", "name": "TCP_8443", "type": "service-tcp", "port": "8443", "protocol": "HTTP"},
                    {"uid": "s-icmp", "name": "ICMP_Echo", "type": "service-icmp", "icmp-type": 8, "icmp-code": 0},
                    {"uid": "s-oth", "name": "Proto_47", "type": "service-other", "ip-protocol": 47},
                ],
                "modified-objects": [
                    {
                        "old-object": {
                            "uid": "app-1",
                            "name": "Site_Corp",
                            "type": "application-site",
                            "primary-category": "General",
                            "url-list": ["old.example.com"],
                            "urls-defined-as-regular-expression": False,
                            "description": "old desc",
                        },
                        "new-object": {
                            "uid": "app-1",
                            "name": "Site_Corp",
                            "type": "application-site",
                            "primary-category": "Custom",
                            "url-list": ["old.example.com", r"\.corp\.example"],
                            "urls-defined-as-regular-expression": True,
                            "description": "new desc",
                        },
                    }
                ],
            }
        ]
    }
    try:
        report = await collect_change_report(
            api, cache, [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-svc-diff"])]
        )
        entries = {oc.name: oc for oc in report.sessions[0].object_changes}
        assert entries["TCP_8443"].summary_fields["port"] == "8443"
        assert entries["ICMP_Echo"].summary_fields["icmp-type"] == 8
        assert entries["Proto_47"].summary_fields["ip-protocol"] == 47
        app_entry = entries["Site_Corp"]
        assert app_entry.summary_fields["primary-category"] == "Custom"
        assert app_entry.summary_fields["urls-defined-as-regular-expression"] is True
        diff_names = {d.field_name for d in app_entry.field_diffs}
        assert {"url-list", "primary-category", "urls-defined-as-regular-expression", "description"}.issubset(
            diff_names
        )
        url_diff = next(d for d in app_entry.field_diffs if d.field_name == "url-list")
        assert url_diff.added_items == [r"\.corp\.example"]
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-003-5")
async def test_cold_cache_report_coordinator_warming_and_standalone_live_fallback() -> None:
    """SCN-REPORT-003-5: Coordinator-backed warming avoids double-fetch; standalone fallback skips CachePort writes."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = _SpecFakeApi()
    api.packages = [
        {
            "uid": "pkg-1",
            "name": "Standard",
            "access-layers": [{"uid": "layer-1", "name": "Standard Network"}],
            "nat-policy": False,
        }
    ]
    api.rulebase_by_cmd_target[("show-access-rulebase", "layer-1")] = {
        "uid": "layer-1",
        "name": "Standard Network",
        "rulebase": [
            {"uid": "r1", "type": "access-rule", "rule-number": 1, "name": "Rule_1", "action": {"name": "Accept"}}
        ],
        "to": 1,
        "total": 1,
    }
    api.show_changes_data["s-rule"] = {
        "changes": [
            {
                "added-rules": [
                    {"new-object": {"uid": "r1", "name": "Rule_1", "type": "access-rule", "layer": "Standard Network"}}
                ]
            }
        ]
    }
    try:
        # 1. With refresh_rulebase_fn (simulating ArodonataClient coordinator): runs once without live snapshot double-fetch
        warm_calls: list[tuple[str, str]] = []

        async def _fake_refresh(mgmt: str, dom: str) -> None:
            warm_calls.append((mgmt, dom))

        await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-rule"])],
            refresh_rulebase_fn=_fake_refresh,
        )
        assert warm_calls == [("mds1", "Corp")]
        assert not any(c[1] == "show-access-rulebase" for c in api.calls)

        # 2. Standalone without refresh_rulebase_fn: live fallback numbers Rule_1 without writing CachePort
        api.calls.clear()
        report2 = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-rule"])],
        )
        assert any(c[1] == "show-access-rulebase" for c in api.calls)
        assert report2.sessions[0].rule_changes[0].rule_number == "1"
        assert report2.sessions[0].numbering_source == "live_published"
        assert (await cache.get_domain_rulebase_packages("mds1", "Corp")).package_layers == []
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-005-1")
def test_render_change_report_html_bundle_and_symmetric_markdown_object_field_diffs() -> None:
    """SCN-REPORT-005-1: `render_change_report` returns `RenderedReportBundle` (`bytes` HTML + symmetric Markdown object Field Diffs)."""
    from arodonata.reports.models import RuleChangeEntry

    report = ChangeReport(
        title="**Release** Report",
        header_fields={"Ticket": "`CHG-42`"},
        sessions=[
            SessionChangeReport(
                mgmt_name="mds1",
                domain_name="Corp",
                session_uid="s-1",
                rule_changes=[
                    RuleChangeEntry(
                        uid="r-mod-1",
                        name="Allow_Web",
                        rule_number="1",
                        layer_name="Network",
                        operation="modified",
                        action="Accept",
                    )
                ],
                object_changes=[
                    ObjectChangeEntry(
                        uid="app-1",
                        name="Site_Corp",
                        object_type="application-site",
                        operation="modified",
                        field_diffs=[
                            FieldDiff(
                                field_name="url-list",
                                old_value="old.example",
                                new_value="old.example, new.example",
                                added_items=["new.example"],
                                removed_items=[],
                            )
                        ],
                    )
                ],
            )
        ],
    )
    bundle = render_change_report(
        report,
        formats=["html", "md"],
        options=RenderOptions(
            title="**Release** Report", header_fields={"Ticket": "`CHG-42`"}, include_field_diffs=True
        ),
    )
    assert isinstance(bundle, RenderedReportBundle)
    assert isinstance(bundle.html, bytes)
    html_text = bundle.html.decode("utf-8")
    assert "MODIFIED" in html_text
    assert "<script" not in html_text.lower()
    assert "<strong>Release</strong>" in html_text
    assert "Field Diffs" in html_text
    assert bundle.markdown is not None
    assert "#### Field Diffs for Object Site_Corp (application-site)" in bundle.markdown
    assert "| url-list |" in bundle.markdown


@pytest.mark.spec("SCN-REPORT-005-3")
def test_change_report_rejects_future_format_version_json() -> None:
    """SCN-REPORT-005-3: `ChangeReport.model_validate_json` rejects unsupported future `format_version`."""
    with pytest.raises(ChangeReportInputError, match="Unsupported ChangeReport format_version=999"):
        ChangeReport.model_validate_json('{"format_version": 999}')


# ==============================================================================
# Rulebase Scenarios
# ==============================================================================


@pytest.mark.spec("SCN-RULE-001-1")
async def test_rulebase_refresh_fails_closed_on_show_session_error_with_redacted_last_error() -> None:
    """SCN-RULE-001-1: Fail closed on `show-session` API failure with SID-redacted `last_error` in sync state."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = _SpecFakeApi()
    api.fail_calls["show-session"] = ApiCallResult(
        success=False,
        status_code=500,
        error_message='session error {"sid": "sid_leak_token_77"}',
    )
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k")
    await cache.upsert_domains([DomainInfo(id="mds1:Corp", mgmt_name="mds1", name="Corp", uid="d1")])
    dom_svc = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coord = DomainSyncCoordinator(settings=settings, api=api, cache=cache, lock_port=lock_port, domain_service=dom_svc)
    rb_svc = RulebaseRefreshService(settings=settings, api=api, cache=cache, coordinator=coord)
    try:
        events = [ev async for ev in rb_svc.stream_refresh_rulebases(mgmt_name="mds1", domains=["Corp"], mode="force")]
        fail_evs = [e for e in events if isinstance(e, DomainSyncFailedEvent)]
        assert len(fail_evs) == 1
        assert "sid_leak_token_77" not in fail_evs[0].error
        states = await cache.list_sync_states(mgmt_name="mds1", domain_name="Corp", scope="rulebase")
        assert len(states) == 1
        assert states[0].status == "failed"
        assert states[0].last_error is not None
        assert "sid_leak_token_77" not in states[0].last_error
    finally:
        await db.close()


@pytest.mark.spec("SCN-RULE-004-3")
async def test_automatic_domain_resolution_ambiguity_and_cold_cache_layer_lookup() -> None:
    """SCN-RULE-004-3 (FC-10): `get_package_rulebase` ambiguity error + cold-cache `get_layer_rulebase`/`filter_rulebase` resolution."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = _SpecFakeApi()
    api.packages = [
        {
            "uid": "pkg-cold",
            "name": "Cold_Pkg",
            "access-layers": [{"uid": "layer-cold", "name": "Cold_Layer"}],
            "nat-policy": False,
        }
    ]
    api.rulebase_by_cmd_target[("show-access-rulebase", "layer-cold")] = {
        "uid": "layer-cold",
        "name": "Cold_Layer",
        "rulebase": [
            {"uid": "r-c1", "type": "access-rule", "rule-number": 1, "name": "Allow_Cold", "action": {"name": "Accept"}}
        ],
        "to": 1,
        "total": 1,
    }
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k")
    await cache.upsert_domains(
        [DomainInfo(id="mds1:OnlyDomain", mgmt_name="mds1", name="OnlyDomain", uid="d-only", domain_type="domain")]
    )
    dom_svc = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coord = DomainSyncCoordinator(settings=settings, api=api, cache=cache, lock_port=lock_port, domain_service=dom_svc)
    rb_refresh = RulebaseRefreshService(settings=settings, api=api, cache=cache, coordinator=coord)
    src = CachedRulebaseSource(cache=cache, refresh_service=rb_refresh)
    try:
        # 1. Cold-cache `get_layer_rulebase(domain_name=None, cache_mode="smart")` resolves & refreshes automatically (FC-10)
        layer_rb = await src.get_layer_rulebase("mds1", None, "Cold_Layer", cache_mode="smart")
        assert layer_rb.domain_name == "OnlyDomain"
        assert layer_rb.flat_rules[0].name == "Allow_Cold"

        # 2. Cold-cache `filter_rulebase(layer=..., domain_name=None)` also works without DomainNotFoundError
        filtered = await src.filter_rulebase(
            "mds1", None, layer="Cold_Layer", filter_query="Allow_Cold", cache_mode="smart"
        )
        assert filtered.matched_count == 1

        # 3. Duplicate package name across two cached domains raises AmbiguousLayerName
        await cache.upsert_domains(
            [DomainInfo(id="mds1:SecondDom", mgmt_name="mds1", name="SecondDom", uid="d-two", domain_type="domain")]
        )
        await cache.replace_domain_rulebase(
            DomainRulebaseSnapshot(
                mgmt_name="mds1",
                domain_name="SecondDom",
                package_layers=[
                    RulebasePackageLayerEntry(
                        mgmt_name="mds1",
                        domain_name="SecondDom",
                        package_uid="pkg-2",
                        package_name="Cold_Pkg",
                        rulebase_type="access",
                        layer_uid="l2",
                        layer_name="Cold_Layer",
                        position=1,
                    )
                ],
                layers=[
                    RulebaseLayerEntry(
                        mgmt_name="mds1", domain_name="SecondDom", uid="l2", name="Cold_Layer", rulebase_type="access"
                    )
                ],
            )
        )
        with pytest.raises(AmbiguousLayerName) as amb:
            await src.get_package_rulebase("mds1", None, "Cold_Pkg", cache_mode="cache")
        assert len(amb.value.candidates) == 2
    finally:
        await db.close()


@pytest.mark.spec("SCN-RULE-005-1")
def test_rule_to_cpcrud_operation_supports_https_and_threat_rules() -> None:
    """SCN-RULE-005-1: `rule_to_cpcrud_operation` converts Access, NAT, HTTPS, and Threat rules to flat dicts."""
    https_rule = HttpsRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="l-https",
        layer_name="HTTPS_Layer",
        uid="h-r1",
        name="Inspect_Outbound",
        position=1,
        action="Inspect",
        site_category=["Finance"],
        certificate="corp-ca",
        install_on=["Policy Targets"],
    )
    threat_rule = ThreatRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="l-threat",
        layer_name="Threat_Layer",
        uid="t-r1",
        name="Protect_DMZ",
        position=1,
        action="Detect",
        protected_scope=["DMZ_Net"],
        install_on=["Policy Targets"],
    )
    nat_rule = NatRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        package_uid="pkg-1",
        package_name="Standard",
        uid="n-r1",
        position=1,
        method="static",
        original_source="Host_10.1.1.1",
        translated_destination=NAT_ORIGINAL_OBJECT_UID,
    )

    op_https = rule_to_cpcrud_operation(https_rule, layer="HTTPS_Layer")
    op_threat = rule_to_cpcrud_operation(threat_rule, layer="Threat_Layer")
    op_nat = rule_to_cpcrud_operation(nat_rule, package="Standard")

    assert op_https["type"] == "https-rule"
    assert op_https["site-category"] == ["Finance"]
    assert op_https["certificate"] == "corp-ca"
    assert "key" not in op_https and "data" not in op_https

    assert op_threat["type"] == "threat-rule"
    assert op_threat["protected-scope"] == ["DMZ_Net"]
    assert op_nat["type"] == "nat-rule"
    assert op_nat["translated-destination"] == "Original"


@pytest.mark.spec("SCN-RULE-006-1")
async def test_public_rulebase_formatting_and_package_helpers() -> None:
    """SCN-RULE-006-1: Public `arodonata.rulebase` exports extract packages and format snapshots offline."""
    snap = DomainRulebaseSnapshot(
        mgmt_name="mds1",
        domain_name="Corp",
        package_layers=[
            RulebasePackageLayerEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                package_uid="pkg-1",
                package_name="Corp_Pkg",
                rulebase_type="access",
                layer_uid="layer-1",
                layer_name="Corp Network",
                position=1,
            )
        ],
        layers=[
            RulebaseLayerEntry(
                mgmt_name="mds1", domain_name="Corp", uid="layer-1", name="Corp Network", rulebase_type="access"
            )
        ],
        sections=[
            RulebaseSectionEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                layer_uid="layer-1",
                layer_name="Corp Network",
                rulebase_type="access",
                uid="sec-1",
                name="Main",
                position=1,
                from_rule=1,
                to_rule=1,
                rule_uids=["r1"],
            )
        ],
        access_rules=[
            AccessRuleEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                layer_uid="layer-1",
                layer_name="Corp Network",
                section_uid="sec-1",
                section_name="Main",
                uid="r1",
                name="Allow_DNS",
                position=1,
                action="Accept",
                service=["domain-udp"],
            )
        ],
    )
    pkgs = extract_policy_packages(snap)
    assert len(pkgs) == 1 and pkgs[0].name == "Corp_Pkg"

    numbered = number_package_rulebase(snap, "Corp_Pkg", rulebase_type="access")
    res_md = filter_numbered_rulebase(numbered, filter_query="Allow_DNS", output_format="markdown")
    assert "Allow_DNS" in res_md.rendered_text
    assert "| 1 |" in format_rules_markdown("Corp_Pkg", "access", numbered.flat_rules)
    assert "Allow_DNS" in format_rules_model_friendly("Corp_Pkg", "access", numbered.flat_rules)
    assert callable(collect_domain_rulebase_snapshot)
