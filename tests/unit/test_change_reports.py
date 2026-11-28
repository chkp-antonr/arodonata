"""Unit tests for Check Point change reports (`reports/`)."""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter
from arodonata.core.context import AuthContext
from arodonata.core.errors import ChangeReportInputError, UnsupportedFormat
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
)
from arodonata.reports.collector import collect_change_report
from arodonata.reports.models import (
    CURRENT_FORMAT_VERSION,
    ChangeReport,
    OwnedSession,
    RangeScope,
    RenderOptions,
    SessionScope,
)
from arodonata.reports.renderer import build_change_report, render_change_report


class FakeReportsApi:
    """In-memory `ApiPort` double for change report collection and placement tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None, str | None]] = []
        self.sessions_by_uid: dict[str, dict[str, Any]] = {}
        self.sessions_list_by_domain: dict[str, list[dict[str, Any]]] = {}
        self.changes_by_session: dict[str, dict[str, Any]] = {}
        self.objects_by_uid: dict[str, dict[str, Any]] = {}
        self.fail_sessions: set[str] = set()
        self.fail_show_changes_sessions: set[str] = set()
        self.fail_show_object_uids: set[str] = set()
        self.live_packages: list[dict[str, Any]] = []
        self.live_rulebase_pages: dict[tuple[str, str], dict[str, Any]] = {}
        self.fail_live_rulebase: bool = False

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
        self.calls.append((mgmt_name, command, payload, domain, sid))
        payload = payload or {}

        if command == "show-domains":
            return ApiCallResult(
                success=True,
                data={"objects": [{"uid": "d-corp", "name": "Corp"}, {"uid": "d-dmz", "name": "DMZ"}]},
            )
        if command == "show-global-domain":
            return ApiCallResult(success=False, error_message="not mds")

        if command == "show-session":
            uid = str(payload.get("uid") or "")
            if not uid and sid:
                uid = f"sid:{sid}"
            if uid in self.fail_sessions:
                return ApiCallResult(success=False, error_message=f"Session {uid} lookup failed")
            data = self.sessions_by_uid.get(uid)
            if data is None and sid:
                data = self.sessions_by_uid.get(f"sid:{sid}")
            if data is None:
                return ApiCallResult(success=False, error_message=f"Session {uid} not found")
            return ApiCallResult(success=True, data=data)

        if command == "show-sessions":
            dom = domain or "Global"
            offset = int(payload.get("offset", 0))
            limit = int(payload.get("limit", 100))
            all_sess = self.sessions_list_by_domain.get(dom, [])
            page = all_sess[offset : offset + limit]
            return ApiCallResult(
                success=True,
                data={"objects": page, "to": offset + len(page), "total": len(all_sess)},
            )

        if command == "show-changes":
            sess_uid = str(payload.get("to-session") or payload.get("from-session") or "")
            if sess_uid in self.fail_show_changes_sessions:
                return ApiCallResult(success=False, error_message="show-changes failed")
            data = self.changes_by_session.get(sess_uid, {"tasks": [{"task-details": [{"operations": {}}]}]})
            return ApiCallResult(success=True, data=data)

        if command == "show-object":
            obj_uid = str(payload.get("uid") or "")
            if obj_uid in self.fail_show_object_uids:
                return ApiCallResult(success=False, error_message="object not found")
            obj = self.objects_by_uid.get(obj_uid)
            if obj is None:
                return ApiCallResult(success=False, error_message="object not found")
            return ApiCallResult(success=True, data={"object": obj})

        if command == "show-packages":
            offset = int(payload.get("offset", 0))
            if offset > 0:
                return ApiCallResult(
                    success=True,
                    data={"packages": [], "to": len(self.live_packages), "total": len(self.live_packages)},
                )
            return ApiCallResult(
                success=True,
                data={
                    "packages": self.live_packages,
                    "to": len(self.live_packages),
                    "total": len(self.live_packages),
                },
            )

        if command.startswith("show-") and command.endswith("-rulebase"):
            if self.fail_live_rulebase:
                return ApiCallResult(success=False, error_message="live rulebase fetch failed")
            target = str(payload.get("uid") or payload.get("name") or payload.get("package") or "")
            page = self.live_rulebase_pages.get((command, target))
            if page is None:
                return ApiCallResult(success=True, data={"rulebase": [], "to": 0, "total": 0})
            return ApiCallResult(success=True, data=page)

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
        if command == "show-sessions":
            dom = domain or "Global"
            all_sess = self.sessions_list_by_domain.get(dom, [])
            return ApiQueryResult(success=True, objects=list(all_sess), total=len(all_sess))
        if command == "show-packages":
            return ApiQueryResult(success=True, objects=list(self.live_packages), total=len(self.live_packages))
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return "sid-unused", "10.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        async def _done() -> bool:
            return True

        return _done()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.asyncio
async def test_scope_validation_and_timezone_conversion() -> None:
    """`collect_change_report` validates scopes strictly and converts timezone-aware datetimes to UTC."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        # Empty scopes list
        with pytest.raises(ChangeReportInputError, match="at least one SessionScope or RangeScope"):
            await collect_change_report(api, cache, [])

        # Empty SessionScope
        with pytest.raises(ChangeReportInputError, match="at least one session UID"):
            SessionScope(mgmt_name="mds1", domain="Corp", session_uids=[])

        # RangeScope with no bounds
        with pytest.raises(ChangeReportInputError, match="requires at least one bound"):
            RangeScope(mgmt_name="mds1", domain="Corp")

        # Naive datetime rejected
        with pytest.raises(ChangeReportInputError, match="timezone-aware"):
            RangeScope(mgmt_name="mds1", domain="Corp", from_date=datetime(2026, 10, 23, 12, 0, 0))  # noqa: DTZ001

        # Inverted from_date > to_date rejected
        with pytest.raises(ChangeReportInputError, match="must not be after"):
            RangeScope(
                mgmt_name="mds1",
                domain="Corp",
                from_date=datetime(2026, 10, 23, 15, 0, 0, tzinfo=UTC),
                to_date=datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC),
            )
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-002-2")
@pytest.mark.asyncio
async def test_session_deduplication_range_filtering_and_partial_warnings() -> None:
    """Overlapping SessionScope and RangeScope deduplicate sessions, filter by exact UTC publish time, and emit warnings on partial errors."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        # Session 1 published at 2026-10-23T12:00:00Z (15:00+03:00)
        s1 = {
            "uid": "sess-1",
            "name": "CHG-101",
            "user-name": "alice",
            "description": "Add web host",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
            "changes": 2,
        }
        # Session 2 published at 2026-10-23T18:00:00Z (outside range)
        s2 = {
            "uid": "sess-2",
            "name": "CHG-102",
            "user-name": "bob",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T18:00:00Z"},
            "changes": 1,
        }
        api.sessions_by_uid["sess-1"] = s1
        api.sessions_by_uid["sess-2"] = s2
        api.sessions_list_by_domain["Corp"] = [s2, s1]
        api.fail_sessions.add("sess-bad")

        ref_uid_resolved = str(uuid.uuid4())
        api.objects_by_uid[ref_uid_resolved] = {
            "uid": ref_uid_resolved,
            "name": "grp-resolved-via-api",
            "type": "group",
        }

        api.changes_by_session["sess-1"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "added-objects": [
                                    {
                                        "uid": "h-new-1",
                                        "name": "web-01",
                                        "type": "host",
                                        "ipv4-address": "10.10.1.10",
                                        "groups": [ref_uid_resolved],
                                    }
                                ],
                                "modified-objects": [
                                    {
                                        "uid": "r-acc-1",
                                        "name": "Allow Web",
                                        "type": "access-rule",
                                        "layer": "Corp Network",
                                        "new-object": {
                                            "uid": "r-acc-1",
                                            "name": "Allow Web",
                                            "type": "access-rule",
                                            "enabled": False,
                                            "action": {"name": "Accept"},
                                            "source": [ref_uid_resolved],
                                        },
                                        "old-object": {
                                            "uid": "r-acc-1",
                                            "name": "Allow Web",
                                            "type": "access-rule",
                                            "enabled": True,
                                            "action": {"name": "Drop"},
                                            "source": [{"name": "Any"}],
                                        },
                                        "field-changes": [
                                            {
                                                "field-name": "action",
                                                "old-value": "Drop",
                                                "new-value": "Accept",
                                            }
                                        ],
                                    }
                                ],
                            }
                        }
                    ]
                }
            ]
        }

        # Seed cached rulebase snapshot so rule numbering works from cache
        await cache.replace_domain_rulebase(
            DomainRulebaseSnapshot(
                mgmt_name="mds1",
                domain_name="Corp",
                package_layers=[
                    RulebasePackageLayerEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_uid="pkg-1",
                        package_name="Standard",
                        rulebase_type="access",
                        layer_uid="l-1",
                        layer_name="Corp Network",
                        position=0,
                    )
                ],
                layers=[
                    RulebaseLayerEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        rulebase_type="access",
                        uid="l-1",
                        name="Corp Network",
                    )
                ],
                access_rules=[
                    AccessRuleEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        layer_uid="l-1",
                        layer_name="Corp Network",
                        uid="r-acc-1",
                        name="Allow Web",
                        position=1,
                        enabled=False,
                    )
                ],
            )
        )

        tz_plus_3 = timezone(timedelta(hours=3))
        report = await collect_change_report(
            api,
            cache,
            [
                SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-1", "sess-bad"]),
                RangeScope(
                    mgmt_name="mds1",
                    domain="Corp",
                    from_date=datetime(2026, 10, 23, 14, 0, 0, tzinfo=tz_plus_3),  # 11:00 UTC
                    to_date=datetime(2026, 10, 23, 16, 0, 0, tzinfo=tz_plus_3),  # 13:00 UTC
                ),
            ],
        )

        # sess-1 matched both SessionScope and RangeScope -> deduplicated (only 1 entry for sess-1; sess-2 excluded)
        assert [s.session_uid for s in report.sessions] == ["sess-1", "sess-bad"]
        sess_change = report.sessions[0]
        assert sess_change.domain_name == "Corp"
        assert "Numbering from cached rulebase snapshot" in sess_change.numbering_basis

        # Partial failure on sess-bad recorded as warning
        assert any(w.code == "session_fetch_failed" and w.session_uid == "sess-bad" for w in report.warnings)

        # Rule placement populated from cached rulebase snapshot
        assert len(sess_change.rule_changes) == 1
        rc = sess_change.rule_changes[0]
        assert rc.uid == "r-acc-1"
        assert rc.rule_number == "1"
        assert rc.enabled is False
        # Bare UID in rule source was resolved via show-object
        assert rc.source == ["grp-resolved-via-api"]
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-001-3")
@pytest.mark.asyncio
async def test_uid_resolution_cap_200_emits_warning() -> None:
    """When more than 200 bare UIDs require `show-object` lookup, lookup stops at 200 and emits `names_unresolved`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        api.sessions_by_uid["s-205"] = {
            "uid": "s-205",
            "name": "Bulk Session",
            "user-name": "admin",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
        }
        bare_uids = [str(uuid.uuid4()) for _ in range(205)]
        for u in bare_uids:
            api.objects_by_uid[u] = {"uid": u, "name": f"resolved-{u[:6]}", "type": "host"}

        api.changes_by_session["s-205"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "added-objects": [
                                    {
                                        "uid": "r-big",
                                        "name": "big-rule",
                                        "type": "access-rule",
                                        "layer": "Layer1",
                                        "source": bare_uids,
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }

        report = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-205"])],
        )

        show_obj_calls = [c for c in api.calls if c[1] == "show-object"]
        assert len(show_obj_calls) == 200
        assert any(w.code == "names_unresolved" for w in report.warnings)
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-003-2")
@pytest.mark.asyncio
async def test_live_owned_session_numbering_and_strict_sid_redaction() -> None:
    """Unpublished `OwnedSession` reads rulebase live without mutating/closing the session and completely redacts SID."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        secret_sid = "SUPER-SECRET-OWNED-SID-99999"
        owned = OwnedSession(sid=secret_sid, server_ip="10.1.0.1")

        # repr() of OwnedSession never leaks SID
        assert secret_sid not in repr(owned)

        # OwnedSession metadata returned when show-session is called
        api.sessions_by_uid["sess-live-1"] = {
            "uid": "sess-live-1",
            "name": "Draft Ticket 42",
            "user-name": "operator",
            "state": "open",
            "changes": 1,
        }
        api.sessions_by_uid[f"sid:{secret_sid}"] = api.sessions_by_uid["sess-live-1"]
        api.changes_by_session["sess-live-1"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "added-objects": [
                                    {
                                        "uid": "r-live-1",
                                        "name": "Draft Rule",
                                        "type": "access-rule",
                                        "layer": "LiveLayer",
                                        "enabled": True,
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        api.live_packages = [
            {
                "uid": "pkg-live",
                "name": "LivePkg",
                "access": True,
                "access-layers": [{"uid": "l-live", "name": "LiveLayer", "position": 1}],
            }
        ]
        api.live_rulebase_pages[("show-access-rulebase", "l-live")] = {
            "uid": "l-live",
            "name": "LiveLayer",
            "rulebase": [
                {
                    "uid": "r-live-1",
                    "name": "Draft Rule",
                    "type": "access-rule",
                    "rule-number": 1,
                    "enabled": True,
                }
            ],
            "to": 1,
            "total": 1,
        }

        report = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-live-1"], owned_sessions=owned)],
        )

        sess_rep = report.sessions[0]
        assert sess_rep.numbering_basis.startswith("Numbering read live in the owned session at ")
        assert sess_rep.rule_changes[0].rule_number == "1"

        # Never called publish, discard, or logout
        executed_commands = [c[1] for c in api.calls]
        assert "publish" not in executed_commands
        assert "discard" not in executed_commands
        assert "logout" not in executed_commands

        # Render HTML, Markdown, and JSON and verify secret_sid does not appear anywhere
        bundle = render_change_report(report, formats=("html", "markdown", "json"))
        assert bundle.html is not None
        assert bundle.markdown is not None
        assert bundle.json_text is not None

        assert secret_sid.encode("utf-8") not in bundle.html
        assert secret_sid not in bundle.markdown
        assert secret_sid not in bundle.json_text
        assert secret_sid not in repr(report)
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-003-1")
@pytest.mark.asyncio
async def test_object_only_session_skips_placement_and_omits_basis_banner() -> None:
    """When a session has zero `rule_changes`, placement is skipped (`not_applicable`) and no basis banner is rendered."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        owned = OwnedSession(sid="published-sid-111", server_ip="10.1.0.1")
        api.sessions_by_uid["sess-obj-only"] = {
            "uid": "sess-obj-only",
            "name": "Decom Host Cleanup",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
            "changes": 1,
        }
        api.changes_by_session["sess-obj-only"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "deleted-objects": [
                                    {
                                        "uid": "h-del-1",
                                        "name": "legacy-host-01",
                                        "type": "host",
                                        "ipv4-address": "10.99.0.10",
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }

        bundle = await build_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-obj-only"], owned_sessions=owned)],
            formats=("html", "markdown", "json"),
        )
        sess_rep = bundle.report.sessions[0]
        assert sess_rep.rule_changes == []
        assert len(sess_rep.object_changes) == 1
        assert sess_rep.numbering_source == "not_applicable"
        assert sess_rep.numbering_basis == ""
        assert bundle.report.warnings == []

        # Verify apply_session_rule_placement did not issue an extra show-session {} or show-packages call
        placement_show_session_calls = [c for c in api.calls if c[1] == "show-session" and not (c[2] or {}).get("uid")]
        assert placement_show_session_calls == []
        assert [c for c in api.calls if c[1] == "show-packages"] == []

        assert bundle.html is not None
        assert bundle.markdown is not None
        html_str = bundle.html.decode("utf-8")
        assert '<div class="basis-banner">' not in html_str
        assert "Numbering Basis" not in bundle.markdown
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-003-3")
@pytest.mark.asyncio
async def test_post_publish_clean_owned_session_numbers_live_and_warms_cache() -> None:
    """After `publish` (before `logout`), `OwnedSession` rotates to a clean working session (`changes == 0`, `locks == 0`) and numbers rules live in-memory without writing uncoordinated snapshots to CachePort (`C2`, `W6`)."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        post_pub_sid = "post-publish-live-sid-777"
        owned = OwnedSession(sid=post_pub_sid, server_ip="10.1.0.1")

        # Target session was just published
        api.sessions_by_uid["sess-pub-target"] = {
            "uid": "sess-pub-target",
            "name": "MMP Decom Rules",
            "user-name": "mmp-bot",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:05:00Z"},
            "changes": 1,
        }
        # Calling `show-session {}` with `post_pub_sid` after `publish` returns the newly rotated clean working session
        api.sessions_by_uid[f"sid:{post_pub_sid}"] = {
            "uid": "sess-rotated-clean-working",
            "state": "open",
            "changes": 0,
            "locks": 0,
            "number-of-published-changes": 0,
        }
        api.changes_by_session["sess-pub-target"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "modified-objects": [
                                    {
                                        "uid": "r-pub-1",
                                        "name": "Decom Rule 1",
                                        "type": "access-rule",
                                        "layer": "Corp Network",
                                        "new-object": {
                                            "uid": "r-pub-1",
                                            "name": "Decom Rule 1",
                                            "type": "access-rule",
                                            "enabled": False,
                                        },
                                        "old-object": {
                                            "uid": "r-pub-1",
                                            "name": "Decom Rule 1",
                                            "type": "access-rule",
                                            "enabled": True,
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        api.live_packages = [
            {
                "uid": "pkg-corp",
                "name": "Standard",
                "access": True,
                "access-layers": [{"uid": "l-corp", "name": "Corp Network", "position": 1}],
            }
        ]
        api.live_rulebase_pages[("show-access-rulebase", "l-corp")] = {
            "uid": "l-corp",
            "name": "Corp Network",
            "rulebase": [
                {
                    "uid": "r-pub-1",
                    "name": "Decom Rule 1",
                    "type": "access-rule",
                    "rule-number": 7,
                    "enabled": False,
                }
            ],
            "to": 1,
            "total": 1,
        }

        report = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-pub-target"], owned_sessions=owned)],
        )

        assert report.warnings == []
        sess_rep = report.sessions[0]
        assert sess_rep.numbering_source == "live_published"
        assert sess_rep.numbering_basis.startswith("Numbering read live after publish at ")
        assert sess_rep.rule_changes[0].rule_number == "1"
        assert sess_rep.rule_changes[0].package_name == "Standard"

        # C2: Verify placement did NOT write an uncoordinated/unstamped snapshot directly to cache
        unwarmed = await cache.get_domain_rulebase("mds1", "Corp")
        assert unwarmed.access_rules == []
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-003-4")
@pytest.mark.asyncio
async def test_dirty_unrelated_owned_session_emits_warning_and_falls_back_to_cache() -> None:
    """When `OwnedSession` points to a different session with uncommitted edits (`changes > 0`), placement emits `owned_session_not_used` and falls back to cache."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        owned = OwnedSession(sid="dirty-other-sid-222", server_ip="10.1.0.1")
        api.sessions_by_uid["sess-pub-1"] = {
            "uid": "sess-pub-1",
            "name": "Already Published",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
            "changes": 1,
        }
        # Unrelated session with dirty uncommitted changes (`changes: 3`)
        api.sessions_by_uid["sid:dirty-other-sid-222"] = {
            "uid": "sess-other-dirty",
            "state": "open",
            "changes": 3,
        }
        api.changes_by_session["sess-pub-1"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "added-objects": [
                                    {
                                        "uid": "r-added-1",
                                        "name": "Added Rule",
                                        "type": "access-rule",
                                        "layer": "Corp Network",
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }

        report = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-pub-1"], owned_sessions=owned)],
        )

        assert any(w.code == "owned_session_not_used" for w in report.warnings)
        assert report.sessions[0].numbering_source == "unnumbered"
        assert report.sessions[0].numbering_basis == "Numbering from cached rulebase snapshot (unavailable)"
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-012-1", "SCN-REPORT-001-3")
@pytest.mark.asyncio
async def test_cold_cache_fetches_live_published_rulebase_and_warms_cache_plus_bare_layer_uid() -> None:
    """When cache is cold and no `OwnedSession` is supplied, rule changes trigger an on-demand live published rulebase read and bare `layer_uid` resolves via `show-object`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        bare_layer_uid = str(uuid.uuid4())
        api.objects_by_uid[bare_layer_uid] = {
            "uid": bare_layer_uid,
            "name": "Resolved-Inline-Layer",
            "type": "access-layer",
        }
        api.sessions_by_uid["sess-cold-1"] = {
            "uid": "sess-cold-1",
            "name": "Cold Cache Session",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
            "changes": 1,
        }
        api.changes_by_session["sess-cold-1"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "modified-objects": [
                                    {
                                        "uid": "r-cold-1",
                                        "name": "Cold Cache Rule",
                                        "type": "access-rule",
                                        "layer": bare_layer_uid,
                                        "new-object": {
                                            "uid": "r-cold-1",
                                            "name": "Cold Cache Rule",
                                            "type": "access-rule",
                                            "layer": bare_layer_uid,
                                            "enabled": True,
                                        },
                                        "old-object": {
                                            "uid": "r-cold-1",
                                            "name": "Cold Cache Rule",
                                            "type": "access-rule",
                                            "layer": bare_layer_uid,
                                            "enabled": True,
                                        },
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        api.live_packages = [
            {
                "uid": "pkg-cold",
                "name": "ColdPkg",
                "access": True,
                "access-layers": [{"uid": bare_layer_uid, "name": "Resolved-Inline-Layer", "position": 1}],
            }
        ]
        api.live_rulebase_pages[("show-access-rulebase", bare_layer_uid)] = {
            "uid": bare_layer_uid,
            "name": "Resolved-Inline-Layer",
            "rulebase": [
                {
                    "uid": "r-cold-1",
                    "name": "Cold Cache Rule",
                    "type": "access-rule",
                    "rule-number": 3,
                    "enabled": True,
                }
            ],
            "to": 1,
            "total": 1,
        }

        report = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-cold-1"])],
        )

        sess_rep = report.sessions[0]
        assert sess_rep.numbering_source == "live_published"
        assert sess_rep.numbering_basis.startswith("Numbering read live from published rulebase at ")
        rc = sess_rep.rule_changes[0]
        assert rc.rule_number == "1"
        assert rc.layer_uid == bare_layer_uid
        assert rc.layer_name == "Resolved-Inline-Layer"

        # C2: Standalone collect_change_report without refresh_rulebase_fn numbers in-memory without writing uncoordinated snapshots to cache
        unwarmed = await cache.get_domain_rulebase("mds1", "Corp")
        assert unwarmed.access_rules == []
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_render_html_markdown_json_and_escaping() -> None:
    """`render_change_report` produces self-contained HTML, Markdown, and versioned JSON with strict HTML escaping."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        api.sessions_by_uid["s-xss"] = {
            "uid": "s-xss",
            "name": "<script>alert('xss')</script>",
            "user-name": "admin",
            "description": "Normal & <unsafe>",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
        }
        api.changes_by_session["s-xss"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "added-objects": [
                                    {
                                        "uid": "r-new",
                                        "name": "Rule <b>One</b>",
                                        "type": "access-rule",
                                        "layer": "Layer1",
                                        "enabled": True,
                                    }
                                ],
                                "deleted-objects": [
                                    {
                                        "uid": "r-del",
                                        "name": "Old Rule",
                                        "type": "access-rule",
                                        "layer": "Layer1",
                                        "enabled": False,
                                    }
                                ],
                                "modified-objects": [
                                    {
                                        "uid": "r-mod",
                                        "name": "Moved Disabled Rule",
                                        "type": "access-rule",
                                        "layer": "Layer1",
                                        "old-rule-number": "2",
                                        "new-rule-number": "5",
                                        "new-object": {
                                            "uid": "r-mod",
                                            "name": "Moved Disabled Rule",
                                            "type": "access-rule",
                                            "enabled": False,
                                            "comments": "Updated <img src=x onerror=alert(1)>",
                                        },
                                        "old-object": {
                                            "uid": "r-mod",
                                            "name": "Moved Disabled Rule",
                                            "type": "access-rule",
                                            "enabled": True,
                                            "comments": "Initial",
                                        },
                                        "field-changes": [
                                            {
                                                "field-name": "comments",
                                                "old-value": "Initial",
                                                "new-value": "Updated <img src=x onerror=alert(1)>",
                                            }
                                        ],
                                    }
                                ],
                            }
                        }
                    ]
                }
            ]
        }

        opts = RenderOptions(
            title="Change Report for **Corp**",
            header_fields={"Ticket": "[CHG-999](https://tickets.corp.local/999)", "Unsafe": "<script>bad()</script>"},
        )
        bundle = await build_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-xss"])],
            formats=("html", "markdown", "json"),
            options=opts,
        )
        assert bundle.html is not None
        assert bundle.markdown is not None
        assert bundle.json_text is not None
        html_str = bundle.html.decode("utf-8")

        # Self-contained HTML checks: inline <style>, zero <script>, escaped Check Point strings
        assert "<style>" in html_str
        assert "<script>" not in html_str
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_str
        assert "&lt;img src=x onerror=alert(1)&gt;" in html_str
        # Safe inline markdown rendered for title and header_fields while escaping raw HTML
        assert "<strong>Corp</strong>" in html_str
        assert '<a href="https://tickets.corp.local/999"' in html_str
        assert "&lt;script&gt;bad()&lt;/script&gt;" in html_str
        # Badges for NEW, DELETED, moved rule, and disabled rule (✗)
        assert "badge-new" in html_str
        assert "badge-deleted" in html_str
        assert "badge-moved" in html_str
        assert "disabled-marker" in html_str
        assert "✗" in html_str

        # Markdown output
        assert "# Change Report for **Corp**" in bundle.markdown
        assert "Moved Disabled Rule" in bundle.markdown

        # JSON output & round-trip validation
        parsed = json.loads(bundle.json_text)
        assert parsed["format_version"] == CURRENT_FORMAT_VERSION
        roundtrip = ChangeReport.model_validate_json(bundle.json_text)
        assert roundtrip.format_version == CURRENT_FORMAT_VERSION
        assert roundtrip.sessions[0].session_uid == "s-xss"

        # Unsupported format ("pdf") raises UnsupportedFormat
        with pytest.raises(UnsupportedFormat):
            render_change_report(bundle.report, formats=("pdf",))
    finally:
        await db.close()


@pytest.mark.spec("SCN-CACHE-012-1", "SCN-REPORT-001-4", "SCN-REPORT-003-4")
@pytest.mark.asyncio
async def test_case2_strict_cleanliness_cross_domain_and_concurrent_refresh_race_protection() -> None:
    """Verify C2 & W6:
    - Case 2 post-publish OwnedSession rejects missing `changes`, `locks > 0`, `number-of-published-changes > 0`,
      mismatched `OwnedSession.session_uid`, or wrong-domain SID (`owned_session_not_used`).
    - Unkeyed `OwnedSession(session_uid=None)` is NOT matched when `len(session_uids) > 1`.
    - `refresh_rulebase_fn` warms the cache via coordinator and a report never overwrites a newer stamped cached snapshot.
    """
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        api.sessions_by_uid["sess-pub-strict"] = {
            "uid": "sess-pub-strict",
            "name": "Strict Case 2",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:10:00Z"},
            "changes": 1,
        }
        api.changes_by_session["sess-pub-strict"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "added-objects": [
                                    {
                                        "uid": "r-strict-1",
                                        "name": "Strict Rule",
                                        "type": "access-rule",
                                        "layer": "Corp Network",
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }

        # 1. Missing `changes` key -> rejected (emits owned_session_not_used)
        sid_missing_changes = "sid-missing-changes"
        api.sessions_by_uid[f"sid:{sid_missing_changes}"] = {"uid": "rot-1", "state": "open", "locks": 0}
        rep_missing = await collect_change_report(
            api,
            cache,
            [
                SessionScope(
                    mgmt_name="mds1",
                    domain="Corp",
                    session_uids=["sess-pub-strict"],
                    owned_sessions=OwnedSession(sid=sid_missing_changes),
                )
            ],
        )
        assert any(w.code == "owned_session_not_used" for w in rep_missing.warnings)

        # 2. `locks > 0` -> rejected
        sid_locked = "sid-locked"
        api.sessions_by_uid[f"sid:{sid_locked}"] = {"uid": "rot-2", "state": "open", "changes": 0, "locks": 1}
        rep_locked = await collect_change_report(
            api,
            cache,
            [
                SessionScope(
                    mgmt_name="mds1",
                    domain="Corp",
                    session_uids=["sess-pub-strict"],
                    owned_sessions=OwnedSession(sid=sid_locked),
                )
            ],
        )
        assert any(w.code == "owned_session_not_used" for w in rep_locked.warnings)

        # 3. `number-of-published-changes > 0` -> rejected
        sid_pub_count = "sid-pub-count"
        api.sessions_by_uid[f"sid:{sid_pub_count}"] = {
            "uid": "rot-3",
            "state": "open",
            "changes": 0,
            "locks": 0,
            "number-of-published-changes": 2,
        }
        rep_pub_cnt = await collect_change_report(
            api,
            cache,
            [
                SessionScope(
                    mgmt_name="mds1",
                    domain="Corp",
                    session_uids=["sess-pub-strict"],
                    owned_sessions=OwnedSession(sid=sid_pub_count),
                )
            ],
        )
        assert any(w.code == "owned_session_not_used" for w in rep_pub_cnt.warnings)

        # 4. Wrong domain reported by show-session -> rejected
        sid_wrong_dom = "sid-wrong-dom"
        api.sessions_by_uid[f"sid:{sid_wrong_dom}"] = {
            "uid": "rot-4",
            "state": "open",
            "changes": 0,
            "locks": 0,
            "domain": {"name": "Branch"},
        }
        rep_wrong_dom = await collect_change_report(
            api,
            cache,
            [
                SessionScope(
                    mgmt_name="mds1",
                    domain="Corp",
                    session_uids=["sess-pub-strict"],
                    owned_sessions=OwnedSession(sid=sid_wrong_dom),
                )
            ],
        )
        assert any(w.code == "owned_session_not_used" for w in rep_wrong_dom.warnings)

        # 5. Unkeyed OwnedSession(session_uid=None) on multi-session scope -> resolve_owned_session returns None
        multi_scope = SessionScope(
            mgmt_name="mds1",
            domain="Corp",
            session_uids=["sess-pub-strict", "sess-other-2"],
            owned_sessions=OwnedSession(sid="unkeyed-sid"),
        )
        assert multi_scope.resolve_owned_session("sess-pub-strict") is None
        assert multi_scope.resolve_owned_session("sess-other-2") is None

        # 6. C2: Coordinator-delegated warming via refresh_rulebase_fn & protection of stamped cache
        warmed_called: list[tuple[str, str]] = []

        async def fake_refresh_rulebase(m: str, d: str) -> None:
            warmed_called.append((m, d))
            await cache.replace_domain_rulebase(
                DomainRulebaseSnapshot(
                    mgmt_name=m,
                    domain_name=d,
                    layers=[
                        RulebaseLayerEntry(
                            mgmt_name=m,
                            domain_name=d,
                            rulebase_type="access",
                            uid="layer-net-1",
                            name="Corp Network",
                        )
                    ],
                    access_rules=[
                        AccessRuleEntry(
                            mgmt_name=m,
                            domain_name=d,
                            layer_uid="layer-net-1",
                            layer_name="Corp Network",
                            uid="r-strict-1",
                            name="Strict Rule",
                            position=1,
                            enabled=True,
                        )
                    ],
                )
            )
            await cache.upsert_sync_state(
                DomainSyncState(
                    mgmt_name=m,
                    domain_name=d,
                    scope="rulebase",
                    item_type="*",
                    last_session_uid="pub-sess-000",
                    status="idle",
                )
            )

        rep_coord = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["sess-pub-strict"])],
            refresh_rulebase_fn=fake_refresh_rulebase,
        )
        assert warmed_called == [("mds1", "Corp")]
        assert rep_coord.sessions[0].numbering_source == "cache"
        assert "session pub-sess-000" in rep_coord.sessions[0].numbering_basis

        # Verify a subsequent Case 2 OwnedSession report does NOT overwrite the stamped cache
        clean_sid = "sid-clean-no-overwrite"
        api.sessions_by_uid[f"sid:{clean_sid}"] = {
            "uid": "rot-clean",
            "state": "open",
            "changes": 0,
            "locks": 0,
            "number-of-published-changes": 0,
        }
        api.live_packages = [
            {
                "uid": "pkg-transient",
                "name": "TransientPkg",
                "access": True,
                "access-layers": [{"uid": "l-trans", "name": "Corp Network", "position": 1}],
            }
        ]
        api.live_rulebase_pages[("show-access-rulebase", "l-trans")] = {
            "uid": "l-trans",
            "name": "Corp Network",
            "rulebase": [{"uid": "r-strict-1", "name": "Strict Rule", "type": "access-rule", "rule-number": 1}],
            "to": 1,
            "total": 1,
        }
        rep_case2 = await collect_change_report(
            api,
            cache,
            [
                SessionScope(
                    mgmt_name="mds1",
                    domain="Corp",
                    session_uids=["sess-pub-strict"],
                    owned_sessions=OwnedSession(sid=clean_sid),
                )
            ],
        )
        assert rep_case2.sessions[0].numbering_source == "live_published"
        # Cache still holds the coordinator's stamped snapshot (`layer-net-1`), NOT `l-trans`!
        cached_after = await cache.get_domain_rulebase("mds1", "Corp")
        assert [lyr.uid for lyr in cached_after.layers] == ["layer-net-1"]
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-002-1", "SCN-REPORT-002-2")
@pytest.mark.asyncio
async def test_snapshot_field_diffs_rules_partial_removal_sole_member_any_nat_merge_and_no_false_positive_group_diff() -> (
    None
):
    """Synthesize `FieldDiff` entries from `old-object` vs `new-object` snapshots for rules and objects:
    - Partial rule cell removal (`["t_grp_servers_G", "t_ar03_G"]` -> `["t_grp_servers_G"]`).
    - Sole-member replacement with `Any` + rule disable (`["t_h02_G"]` -> `["Any"]`, `enabled: True -> False`, `comments`).
    - NAT leg updates (`original-source`, `translated-destination`).
    - Explicit `field-changes` merge without duplicating covered fields.
    - Zero false-positive rule diffs when an unchanged referenced group has internal member edits.
    """
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        api.sessions_by_uid["s-decom"] = {
            "uid": "s-decom",
            "name": "MMP Decom Session",
            "user-name": "mmp-operator",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-31T10:00:00Z"},
            "changes": 4,
        }
        grp_clients_uid = str(uuid.uuid4())
        grp_servers_uid = str(uuid.uuid4())
        ar03_uid = str(uuid.uuid4())
        h01_uid = str(uuid.uuid4())
        h02_uid = str(uuid.uuid4())
        h03_uid = str(uuid.uuid4())
        any_uid = "97aeb369-9aea-11d5-bd16-0090272ccb30"

        api.changes_by_session["s-decom"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "changes": [
                                {
                                    "session": {"uid": "s-decom", "user-name": "mmp-operator"},
                                    "operations": {
                                        "modified-objects": [
                                            # Rule 1: Partial removal in destination + unchanged group in source whose internal members changed
                                            {
                                                "new-object": {
                                                    "uid": "r-partial",
                                                    "name": "Rule1_Clients_to_Servers",
                                                    "type": "access-rule",
                                                    "layer": "Network",
                                                    "enabled": True,
                                                    "action": {"uid": "act-1", "name": "Accept"},
                                                    "source": [
                                                        {
                                                            "uid": grp_clients_uid,
                                                            "name": "t_grp_clients_G",
                                                            "type": "group",
                                                            "members": [h02_uid, h03_uid],
                                                        }
                                                    ],
                                                    "destination": [
                                                        {
                                                            "uid": grp_servers_uid,
                                                            "name": "t_grp_servers_G",
                                                            "type": "group",
                                                        }
                                                    ],
                                                    "service": [{"uid": "svc-1", "name": "https"}],
                                                    "comments": "[DECOMM: t_ar03_G]",
                                                },
                                                "old-object": {
                                                    "uid": "r-partial",
                                                    "name": "Rule1_Clients_to_Servers",
                                                    "type": "access-rule",
                                                    "layer": "Network",
                                                    "enabled": True,
                                                    "action": {"uid": "act-1", "name": "Accept"},
                                                    "source": [
                                                        {
                                                            "uid": grp_clients_uid,
                                                            "name": "t_grp_clients_G",
                                                            "type": "group",
                                                            "members": [
                                                                {"uid": h01_uid, "name": "t_h01_G", "type": "host"},
                                                                {"uid": h02_uid, "name": "t_h02_G", "type": "host"},
                                                                {"uid": h03_uid, "name": "t_h03_G", "type": "host"},
                                                            ],
                                                        }
                                                    ],
                                                    "destination": [
                                                        {
                                                            "uid": grp_servers_uid,
                                                            "name": "t_grp_servers_G",
                                                            "type": "group",
                                                        },
                                                        {
                                                            "uid": ar03_uid,
                                                            "name": "t_ar03_G",
                                                            "type": "address-range",
                                                        },
                                                    ],
                                                    "service": [{"uid": "svc-1", "name": "https"}],
                                                    "comments": "",
                                                },
                                            },
                                            # Rule 2: Sole member replaced with Any + rule disabled
                                            {
                                                "new-object": {
                                                    "uid": "r-sole-any",
                                                    "name": "Rule3_Specific_Host_Traffic",
                                                    "type": "access-rule",
                                                    "layer": "Network",
                                                    "enabled": False,
                                                    "action": {"uid": "act-1", "name": "Accept"},
                                                    "source": [{"uid": any_uid, "name": "Any"}],
                                                    "destination": [{"uid": any_uid, "name": "Any"}],
                                                    "service": [{"uid": any_uid, "name": "Any"}],
                                                    "comments": "[DECOMM: t_h02_G]",
                                                },
                                                "old-object": {
                                                    "uid": "r-sole-any",
                                                    "name": "Rule3_Specific_Host_Traffic",
                                                    "type": "access-rule",
                                                    "layer": "Network",
                                                    "enabled": True,
                                                    "action": {"uid": "act-1", "name": "Accept"},
                                                    "source": [{"uid": any_uid, "name": "Any"}],
                                                    "destination": [
                                                        {"uid": h02_uid, "name": "t_h02_G", "type": "host"}
                                                    ],
                                                    "service": [{"uid": any_uid, "name": "Any"}],
                                                    "comments": "",
                                                },
                                            },
                                            # Rule 3: NAT rule leg updates + explicit field-changes merge
                                            {
                                                "new-object": {
                                                    "uid": "r-nat-1",
                                                    "name": "NAT_Rule_1",
                                                    "type": "nat-rule",
                                                    "package": "Standard",
                                                    "enabled": False,
                                                    "method": "static",
                                                    "original-source": {"uid": any_uid, "name": "Any"},
                                                    "translated-destination": {"uid": "h-nat-new", "name": "nat-new"},
                                                    "comments": "NAT updated",
                                                },
                                                "old-object": {
                                                    "uid": "r-nat-1",
                                                    "name": "NAT_Rule_1",
                                                    "type": "nat-rule",
                                                    "package": "Standard",
                                                    "enabled": True,
                                                    "method": "hide",
                                                    "original-source": {"uid": h02_uid, "name": "t_h02_G"},
                                                    "translated-destination": {"uid": "h-nat-old", "name": "nat-old"},
                                                    "comments": "",
                                                },
                                                "field-changes": [
                                                    {
                                                        "field-name": "method",
                                                        "old-value": "hide",
                                                        "new-value": "static",
                                                    }
                                                ],
                                            },
                                        ]
                                    },
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        report = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-decom"])],
        )
        sess = report.sessions[0]
        assert len(sess.rule_changes) == 3

        # 1. Partial removal in destination + NO false-positive source diff despite group member edit
        r_partial = next(r for r in sess.rule_changes if r.uid == "r-partial")
        partial_diffs = {d.field_name: d for d in r_partial.field_diffs}
        assert "source" not in partial_diffs
        assert "service" not in partial_diffs
        assert "destination" in partial_diffs
        assert partial_diffs["destination"].old_value == ["t_grp_servers_G", "t_ar03_G"]
        assert partial_diffs["destination"].new_value == ["t_grp_servers_G"]
        assert partial_diffs["destination"].removed_items == ["t_ar03_G"]
        assert partial_diffs["destination"].added_items == []
        assert "comments" in partial_diffs
        assert partial_diffs["comments"].old_value == ""
        assert partial_diffs["comments"].new_value == "[DECOMM: t_ar03_G]"

        # 2. Sole member replaced by Any + rule disabled
        r_sole = next(r for r in sess.rule_changes if r.uid == "r-sole-any")
        sole_diffs = {d.field_name: d for d in r_sole.field_diffs}
        assert "destination" in sole_diffs
        assert sole_diffs["destination"].old_value == ["t_h02_G"]
        assert sole_diffs["destination"].new_value == ["Any"]
        assert sole_diffs["destination"].removed_items == ["t_h02_G"]
        assert sole_diffs["destination"].added_items == ["Any"]
        assert "enabled" in sole_diffs
        assert sole_diffs["enabled"].old_value is True
        assert sole_diffs["enabled"].new_value is False
        assert "source" not in sole_diffs

        # 3. NAT rule leg updates + explicit field-changes merged without duplicating `method`
        r_nat = next(r for r in sess.rule_changes if r.uid == "r-nat-1")
        assert [d.field_name for d in r_nat.field_diffs].count("method") == 1
        nat_diffs = {d.field_name: d for d in r_nat.field_diffs}
        assert nat_diffs["method"].old_value == "hide"
        assert nat_diffs["method"].new_value == "static"
        assert nat_diffs["original-source"].old_value == "t_h02_G"
        assert nat_diffs["original-source"].new_value == "Any"
        assert nat_diffs["translated-destination"].old_value == "nat-old"
        assert nat_diffs["translated-destination"].new_value == "nat-new"
        assert nat_diffs["enabled"].old_value is True
        assert nat_diffs["enabled"].new_value is False
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-001-3", "SCN-REPORT-002-4")
@pytest.mark.asyncio
async def test_old_object_bare_uid_resolution_enriched_summaries_and_system_noise_filtering() -> None:
    """Verify Task 1.3:
    - Bare UUIDs appearing only in `old-object` (such as removed `group.members` UUIDs) resolve via
      recursive `{uid, name}` harvesting, `CachePort`, and bounded `show-object` calls.
    - `ObjectChangeEntry.summary` includes IPv6, CIDR masks, `address-range` bounds, `members`, and `comments`.
    - Background Check Point `"System"` maintenance non-rule objects are excluded by default and included
      when `RenderOptions.include_system_objects=True`, while `ChangeReport.raw_responses` stays unfiltered.
    """
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        # 1. Seed one removed member UID in CachePort and one in API show-object; one is nested in old-object rule dict
        uid_cached_member = str(uuid.uuid4())
        uid_api_member = str(uuid.uuid4())
        uid_nested_member = str(uuid.uuid4())
        uid_kept_member = str(uuid.uuid4())

        await cache.upsert_objects(
            [
                CPObject(
                    uid=uid_cached_member,
                    name="t_h01_cached_G",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.0.0.1",
                ),
                CPObject(
                    uid=uid_kept_member,
                    name="t_h03_kept_G",
                    type="host",
                    mgmt_name="mds1",
                    domain_name="Corp",
                    ipv4_address="10.0.0.3",
                ),
            ]
        )
        api.objects_by_uid[uid_api_member] = {
            "uid": uid_api_member,
            "name": "t_h02_api_G",
            "type": "host",
        }

        api.sessions_by_uid["s-sys"] = {
            "uid": "s-sys",
            "name": "Decom Group & System Noise",
            "user-name": "admin_user",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-31T11:00:00Z"},
            "changes": 6,
        }
        api.changes_by_session["s-sys"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "modified-objects": [
                                    # Rule with nested {uid, name} inside old-object.source
                                    {
                                        "new-object": {
                                            "uid": "r-nested",
                                            "name": "Rule_With_Nested_Dict",
                                            "type": "access-rule",
                                            "layer": "Network",
                                            "enabled": True,
                                            "source": [{"uid": uid_kept_member, "name": "t_h03_kept_G"}],
                                        },
                                        "old-object": {
                                            "uid": "r-nested",
                                            "name": "Rule_With_Nested_Dict",
                                            "type": "access-rule",
                                            "layer": "Network",
                                            "enabled": True,
                                            "source": [
                                                {"uid": uid_kept_member, "name": "t_h03_kept_G"},
                                                {"uid": uid_nested_member, "name": "t_h04_nested_G"},
                                            ],
                                        },
                                    },
                                    # Group with bare UUID strings in old-object.members and new-object.members
                                    {
                                        "new-object": {
                                            "uid": "grp-clients",
                                            "name": "t_grp_clients_G",
                                            "type": "group",
                                            "members": [uid_kept_member],
                                            "comments": "[DECOMM: t_h01_cached_G, t_h02_api_G, t_h04_nested_G]",
                                            "meta-info": {"last-modifier": "admin_user"},
                                        },
                                        "old-object": {
                                            "uid": "grp-clients",
                                            "name": "t_grp_clients_G",
                                            "type": "group",
                                            "members": [
                                                uid_cached_member,
                                                uid_api_member,
                                                uid_nested_member,
                                                uid_kept_member,
                                            ],
                                            "comments": "Client group",
                                            "meta-info": {"last-modifier": "admin_user"},
                                        },
                                    },
                                    # Address-range object with enriched summary
                                    {
                                        "new-object": {
                                            "uid": "ar-1",
                                            "name": "t_ar03_G",
                                            "type": "address-range",
                                            "ipv4-address-first": "10.20.0.10",
                                            "ipv4-address-last": "10.20.0.50",
                                            "comments": "Range comment",
                                            "meta-info": {"last-modifier": "admin_user"},
                                        },
                                        "old-object": {
                                            "uid": "ar-1",
                                            "name": "t_ar03_G",
                                            "type": "address-range",
                                            "ipv4-address-first": "10.20.0.1",
                                            "ipv4-address-last": "10.20.0.50",
                                            "comments": "Range comment",
                                            "meta-info": {"last-modifier": "admin_user"},
                                        },
                                    },
                                    # Network object with CIDR mask-length4 and IPv6 subnet6/mask-length6
                                    {
                                        "new-object": {
                                            "uid": "net-1",
                                            "name": "t_net_dual",
                                            "type": "network",
                                            "subnet4": "10.30.0.0",
                                            "mask-length4": 24,
                                            "subnet6": "2001:db8::",
                                            "mask-length6": 64,
                                            "meta-info": {"last-modifier": "admin_user"},
                                        }
                                    },
                                    # Background Check Point System maintenance objects
                                    {
                                        "new-object": {
                                            "uid": "sys-ips-1",
                                            "name": None,
                                            "type": "IpsProtectionUserSettings",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                        "old-object": {
                                            "uid": "sys-ips-1",
                                            "name": None,
                                            "type": "IpsProtectionUserSettings",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                    },
                                    {
                                        "new-object": {
                                            "uid": "sys-ca-1",
                                            "name": "DigiCert_Root_CA",
                                            "type": "cp-trusted-ca-certificate",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                        "old-object": {
                                            "uid": "sys-ca-1",
                                            "name": "DigiCert_Root_CA",
                                            "type": "cp-trusted-ca-certificate",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                    },
                                    {
                                        "new-object": {
                                            "uid": "sys-empty-type",
                                            "name": "",
                                            "type": "",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                        "old-object": {
                                            "uid": "sys-empty-type",
                                            "name": "",
                                            "type": "",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                    },
                                ]
                            }
                        }
                    ]
                }
            ]
        }

        # Default: include_system_objects=False
        report = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-sys"])],
        )
        sess = report.sessions[0]

        # Only non-System objects included, and no noisy system_objects_filtered warning emitted
        obj_uids = [o.uid for o in sess.object_changes]
        assert obj_uids == ["grp-clients", "ar-1", "net-1"]
        sys_warns = [w for w in report.warnings if w.code == "system_objects_filtered"]
        assert len(sys_warns) == 0

        # Verify show-object was called ONLY for uid_api_member (not for cached or nested-dict UIDs)
        show_obj_uids = [str((c[2] or {}).get("uid")) for c in api.calls if c[1] == "show-object"]
        assert show_obj_uids == [uid_api_member]

        # Verify group member diffs resolved all 3 removed bare UUIDs to names
        grp_entry = next(o for o in sess.object_changes if o.uid == "grp-clients")
        grp_diffs = {d.field_name: d for d in grp_entry.field_diffs}
        assert "members" in grp_diffs
        assert grp_diffs["members"].removed_items == ["t_h01_cached_G", "t_h02_api_G", "t_h04_nested_G"]
        assert grp_diffs["members"].new_value == ["t_h03_kept_G"]
        assert "members=[t_h03_kept_G]" in grp_entry.summary
        assert "comments=[DECOMM: t_h01_cached_G, t_h02_api_G, t_h04_nested_G]" in grp_entry.summary

        # Verify enriched summaries for address-range and network
        ar_entry = next(o for o in sess.object_changes if o.uid == "ar-1")
        assert "range=10.20.0.10-10.20.0.50" in ar_entry.summary
        assert "comments=Range comment" in ar_entry.summary
        ar_diffs = {d.field_name: d for d in ar_entry.field_diffs}
        assert ar_diffs["ipv4-address-first"].old_value == "10.20.0.1"
        assert ar_diffs["ipv4-address-first"].new_value == "10.20.0.10"

        net_entry = next(o for o in sess.object_changes if o.uid == "net-1")
        assert net_entry.operation == "added"
        assert "subnet4=10.30.0.0/24" in net_entry.summary
        assert "subnet6=2001:db8::/64" in net_entry.summary

        # Raw responses still preserve the unfiltered show-changes payload
        show_changes_raw = next(r for r in report.raw_responses if r.command == "show-changes")
        raw_mod_objs = show_changes_raw.response["tasks"][0]["task-details"][0]["operations"]["modified-objects"]
        assert len(raw_mod_objs) == 7

        # Opt-in: include_system_objects=True includes System objects
        report_with_sys = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-sys"])],
            options=RenderOptions(include_system_objects=True),
        )
        sys_uids = [o.uid for o in report_with_sys.sessions[0].object_changes]
        assert "sys-ips-1" in sys_uids
        assert "sys-ca-1" in sys_uids
        assert "sys-empty-type" in sys_uids
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-005-2")
@pytest.mark.asyncio
async def test_inline_cell_diffs_html_markdown_escaping_and_json_roundtrip() -> None:
    """Verify Tasks 2.1 and 2.2:
    - HTML renders `.diff-removed`, `.diff-added`, `.diff-arrow` inline inside `Rule Changes` and `Object Changes`
      cells with strict HTML escaping and zero `<script>` tags.
    - Markdown renders `[-name]`, `[+name]`, and `old -> new` inline inside `Rule Changes` and `Object Changes`
      table cells with pipe/newline/HTML escaping.
    - JSON round-trip (`ChangeReport.model_validate_json`) re-renders identical HTML and Markdown offline.
    """
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        api.sessions_by_uid["s-inline"] = {
            "uid": "s-inline",
            "name": "Inline Diff Evidence",
            "user-name": "operator",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-31T11:30:00Z"},
            "changes": 3,
        }
        h_keep_uid = str(uuid.uuid4())
        h_rem_uid = str(uuid.uuid4())
        any_uid = "97aeb369-9aea-11d5-bd16-0090272ccb30"

        api.changes_by_session["s-inline"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "modified-objects": [
                                    # Rule 1: Partial removal in destination + XSS/pipe characters in removed item
                                    {
                                        "new-object": {
                                            "uid": "r-inline-1",
                                            "name": "Rule_Partial",
                                            "type": "access-rule",
                                            "layer": "Network",
                                            "enabled": True,
                                            "action": {"name": "Accept"},
                                            "source": [{"uid": h_keep_uid, "name": "t_grp_clients_G"}],
                                            "destination": [{"uid": "srv-1", "name": "t_grp_servers_G"}],
                                            "service": [{"name": "https"}],
                                            "comments": "[DECOMM: t_ar03_G]",
                                        },
                                        "old-object": {
                                            "uid": "r-inline-1",
                                            "name": "Rule_Partial",
                                            "type": "access-rule",
                                            "layer": "Network",
                                            "enabled": True,
                                            "action": {"name": "Accept"},
                                            "source": [{"uid": h_keep_uid, "name": "t_grp_clients_G"}],
                                            "destination": [
                                                {"uid": "srv-1", "name": "t_grp_servers_G"},
                                                {"uid": "ar-3", "name": "t_ar03_G<script>|bad"},
                                            ],
                                            "service": [{"name": "https"}],
                                            "comments": "",
                                        },
                                    },
                                    # Rule 2: Sole member replaced by Any + rule disabled
                                    {
                                        "new-object": {
                                            "uid": "r-inline-2",
                                            "name": "Rule_Sole_Any",
                                            "type": "access-rule",
                                            "layer": "Network",
                                            "enabled": False,
                                            "action": {"name": "Drop"},
                                            "source": [{"uid": any_uid, "name": "Any"}],
                                            "destination": [{"uid": any_uid, "name": "Any"}],
                                            "service": [{"uid": any_uid, "name": "Any"}],
                                            "comments": "Replaced\nwith|Any",
                                        },
                                        "old-object": {
                                            "uid": "r-inline-2",
                                            "name": "Rule_Sole_Any",
                                            "type": "access-rule",
                                            "layer": "Network",
                                            "enabled": True,
                                            "action": {"name": "Accept"},
                                            "source": [{"uid": any_uid, "name": "Any"}],
                                            "destination": [{"uid": h_rem_uid, "name": "t_h02_G"}],
                                            "service": [{"uid": any_uid, "name": "Any"}],
                                            "comments": "Old comment",
                                        },
                                    },
                                    # Group: member removal with bare UUIDs
                                    {
                                        "new-object": {
                                            "uid": "grp-inline-1",
                                            "name": "t_grp_clients_G",
                                            "type": "group",
                                            "members": [h_keep_uid],
                                            "comments": "[DECOMM: t_h02_G]",
                                            "meta-info": {"last-modifier": "operator"},
                                        },
                                        "old-object": {
                                            "uid": "grp-inline-1",
                                            "name": "t_grp_clients_G",
                                            "type": "group",
                                            "members": [h_keep_uid, h_rem_uid],
                                            "comments": "Initial group",
                                            "meta-info": {"last-modifier": "operator"},
                                        },
                                    },
                                ]
                            }
                        }
                    ]
                }
            ]
        }

        bundle = await build_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-inline"])],
            formats=("html", "markdown", "json"),
        )
        assert bundle.html is not None
        assert bundle.markdown is not None
        assert bundle.json_text is not None

        html_str = bundle.html.decode("utf-8")
        md_str = bundle.markdown

        # HTML assertions: CSS classes, zero <script>, inline removed/added/arrow spans, XSS escaped
        assert ".diff-removed" in html_str
        assert ".diff-added" in html_str
        assert ".diff-arrow" in html_str
        assert "<script>" not in html_str
        assert 't_grp_servers_G, <span class="diff-removed">- t_ar03_G&lt;script&gt;|bad</span>' in html_str
        assert '<span class="diff-removed">- t_h02_G</span>, <span class="diff-added">+ Any</span>' in html_str
        assert (
            '<span class="diff-removed">✓</span><span class="diff-arrow">→</span>'
            '<span class="disabled-marker" title="Disabled">✗</span>' in html_str
        )
        assert (
            '<span class="diff-removed">Accept</span><span class="diff-arrow">→</span>'
            '<span class="diff-highlight">Drop</span>' in html_str
        )
        assert 'members=[t_grp_clients_G, <span class="diff-removed">- t_h02_G</span>]' in html_str

        # Markdown assertions: inline [-name], [+name], old -> new, pipe/newline/HTML escaped
        assert "t_grp_servers_G, [-t_ar03_G&lt;script&gt;\\|bad]" in md_str
        assert "[-t_h02_G], [+Any]" in md_str
        assert "| ✓ -> ✗ |" in md_str
        assert "| Accept -> Drop |" in md_str
        assert "Old comment -> Replaced with\\|Any" in md_str
        assert "members=[t_grp_clients_G, [-t_h02_G]]" in md_str

        # Offline JSON round-trip produces byte-for-byte identical HTML and Markdown
        reloaded = ChangeReport.model_validate_json(bundle.json_text)
        rerendered = render_change_report(reloaded, formats=("html", "markdown"))
        assert rerendered.html == bundle.html
        assert rerendered.markdown == bundle.markdown

        # Verify SmartConsole visual styling: dark-blue header CSS (#253245), yellow section rows (#eee8aa),
        # grouped section banner rows, shaded No. column, Track column, and XSS escaping in section names
        reloaded.sessions[0].rule_changes[0].section_name = "sect_A1_1_1<script>"
        reloaded.sessions[0].rule_changes[0].section_range = "1-2"
        reloaded.sessions[0].rule_changes[0].rule_number = "1"
        reloaded.sessions[0].rule_changes[0].track = "Log"
        reloaded.sessions[0].rule_changes[1].section_name = "sect_A1_1_1<script>"
        reloaded.sessions[0].rule_changes[1].section_range = "1-2"
        reloaded.sessions[0].rule_changes[1].rule_number = "2"
        reloaded.sessions[0].rule_changes[1].track = "Log"
        sc_html = render_change_report(reloaded, formats=("html",)).html
        assert sc_html is not None
        sc_html_str = sc_html.decode("utf-8")
        assert "#253245" in sc_html_str
        assert "#eee8aa" in sc_html_str
        assert "<th>No.</th>" in sc_html_str
        assert "<th>Services &amp; Applications</th>" in sc_html_str
        assert "<th>Track</th>" in sc_html_str
        assert sc_html_str.count('<tr class="section-row">') == 1
        assert "sect_A1_1_1&lt;script&gt; (1-2)" in sc_html_str
        assert "<script>" not in sc_html_str
        assert '<td class="col-num">1</td>' in sc_html_str
        assert '<span class="action-accept">●</span>Accept' in sc_html_str
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-001-3", "SCN-REPORT-002-4", "SCN-REPORT-005-2")
@pytest.mark.asyncio
async def test_review_fixes_multi_layer_sort_system_delete_track_uid_composite_diffs_and_bool_parsing() -> None:
    """Verify code-review fixes (#1-#10):
    - #1: Multi-layer + NAT rule sorting groups by `(package, rulebase_type, layer)` before rule number so section headers never interleave across layers.
    - #2: User deletion (`deleted-objects`) or modification without new `meta-info` of an object originally created by `System` (`old-object.meta-info.last-modifier == "System"`) is NOT filtered out.
    - #3 & #7: Bare UUID in `track` (`{"type": "<uuid>"}`) resolves via `show-object` into `rc.track` and renders in both HTML and Markdown `Track` columns (including inline `track` diff).
    - #4: Filtering background `System` objects logs at DEBUG level without emitting a user-facing `ReportWarning`.
    - #5: String `'false'` / `'true'` in `enabled` `field-changes` parses `'false'` as `False` (`✗ -> ✓`) rather than `True`.
    - #6 & #10: Modifying `subnet4` on a `/24` network preserves `/24` (`subnet4=10.0.0.0 -> 10.1.0.0/24`); modifying `ipv4-address-last` on an `address-range` renders inline inside `range=10.20.0.10-10.20.0.50 -> 10.20.0.60` without duplicating `ipv4-address-last=...`; and comments containing `, port=80` do not split into fake clauses.
    - #8: A rule comment containing literal `"diff-added"` with an unannotated scalar fallback diff still receives `<span class="diff-highlight">`.
    """
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        track_old_uid = str(uuid.uuid4())
        track_new_uid = str(uuid.uuid4())
        api.objects_by_uid[track_old_uid] = {"uid": track_old_uid, "name": "None", "type": "track"}
        api.objects_by_uid[track_new_uid] = {"uid": track_new_uid, "name": "Log", "type": "track"}

        await cache.replace_domain_rulebase(
            DomainRulebaseSnapshot(
                mgmt_name="mds1",
                domain_name="Corp",
                layers=[
                    RulebaseLayerEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_name="Standard",
                        rulebase_type="access",
                        uid="l-net",
                        name="Network",
                        position=1,
                    ),
                    RulebaseLayerEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_name="Standard",
                        rulebase_type="access",
                        uid="l-app",
                        name="AppControl",
                        position=2,
                    ),
                ],
                sections=[
                    RulebaseSectionEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        rulebase_type="access",
                        layer_uid="l-net",
                        layer_name="Network",
                        uid="sec-net",
                        name="NetSection",
                        position=1,
                        from_rule=1,
                        to_rule=3,
                    ),
                    RulebaseSectionEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        rulebase_type="access",
                        layer_uid="l-app",
                        layer_name="AppControl",
                        uid="sec-app",
                        name="AppSection",
                        position=1,
                        from_rule=1,
                        to_rule=2,
                    ),
                    RulebaseSectionEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        rulebase_type="nat",
                        layer_uid="pkg-std",
                        layer_name="Standard",
                        uid="sec-nat",
                        name="NatSection",
                        position=1,
                        from_rule=1,
                        to_rule=1,
                    ),
                ],
                access_rules=[
                    AccessRuleEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_name="Standard",
                        layer_uid="l-net",
                        layer_name="Network",
                        section_uid="sec-net",
                        section_name="NetSection",
                        uid="r-net-1",
                        name="NetRule1",
                        position=1,
                        enabled=True,
                    ),
                    AccessRuleEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_name="Standard",
                        layer_uid="l-net",
                        layer_name="Network",
                        section_uid="sec-net",
                        section_name="NetSection",
                        uid="r-net-3",
                        name="NetRule3",
                        position=3,
                        enabled=True,
                    ),
                    AccessRuleEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_name="Standard",
                        layer_uid="l-app",
                        layer_name="AppControl",
                        section_uid="sec-app",
                        section_name="AppSection",
                        uid="r-app-1",
                        name="AppRule1",
                        position=1,
                        enabled=True,
                    ),
                    AccessRuleEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_name="Standard",
                        layer_uid="l-app",
                        layer_name="AppControl",
                        section_uid="sec-app",
                        section_name="AppSection",
                        uid="r-app-2",
                        name="AppRule2",
                        position=2,
                        enabled=True,
                    ),
                ],
                nat_rules=[
                    NatRuleEntry(
                        mgmt_name="mds1",
                        domain_name="Corp",
                        package_uid="pkg-std",
                        package_name="Standard",
                        section_uid="sec-nat",
                        section_name="NatSection",
                        uid="r-nat-1",
                        name="NatRule1",
                        position=1,
                        enabled=True,
                    )
                ],
            )
        )

        api.sessions_by_uid["s-rev"] = {
            "uid": "s-rev",
            "name": "Review Fixes Session",
            "user-name": "operator",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-31T15:00:00Z"},
            "changes": 9,
        }
        api.changes_by_session["s-rev"] = {
            "tasks": [
                {
                    "task-details": [
                        {
                            "operations": {
                                "deleted-objects": [
                                    # #2: Deleted object whose old-object had last-modifier="System" must NOT be filtered
                                    {
                                        "uid": "obj-del-sys-created",
                                        "name": "Legacy_System_Created_Host",
                                        "type": "host",
                                        "old-object": {
                                            "uid": "obj-del-sys-created",
                                            "name": "Legacy_System_Created_Host",
                                            "type": "host",
                                            "ipv4-address": "10.99.0.1",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                    }
                                ],
                                "modified-objects": [
                                    # Rules out of layer order: Net#3, App#2, Nat#1, Net#1, App#1
                                    {
                                        "new-object": {
                                            "uid": "r-net-3",
                                            "name": "NetRule3",
                                            "type": "access-rule",
                                            "layer": "l-net",
                                            "enabled": True,
                                            # #3: Bare UUID in track dict
                                            "track": {"type": track_new_uid},
                                            # #8: Comment containing literal 'diff-added' substring
                                            "comments": "Contains literal diff-added token",
                                        },
                                        "old-object": {
                                            "uid": "r-net-3",
                                            "name": "NetRule3",
                                            "type": "access-rule",
                                            "layer": "l-net",
                                            "enabled": True,
                                            "track": {"type": track_old_uid},
                                            "comments": "Contains literal diff-added token",
                                        },
                                        "field-changes": [
                                            # #5: String boolean values in field-changes
                                            {
                                                "field-name": "enabled",
                                                "old-value": "false",
                                                "new-value": "true",
                                            },
                                            # #8: Explicit field-change where old_value is None -> unannotated fallback
                                            {
                                                "field-name": "comments",
                                                "old-value": None,
                                                "new-value": "Contains literal diff-added token",
                                            },
                                        ],
                                    },
                                    {
                                        "new-object": {
                                            "uid": "r-app-2",
                                            "name": "AppRule2",
                                            "type": "access-rule",
                                            "layer": "l-app",
                                            "enabled": True,
                                        }
                                    },
                                    {
                                        "new-object": {
                                            "uid": "r-nat-1",
                                            "name": "NatRule1",
                                            "type": "nat-rule",
                                            "package": "Standard",
                                            "enabled": True,
                                        }
                                    },
                                    {
                                        "new-object": {
                                            "uid": "r-net-1",
                                            "name": "NetRule1",
                                            "type": "access-rule",
                                            "layer": "l-net",
                                            "enabled": True,
                                        }
                                    },
                                    {
                                        "new-object": {
                                            "uid": "r-app-1",
                                            "name": "AppRule1",
                                            "type": "access-rule",
                                            "layer": "l-app",
                                            "enabled": True,
                                        }
                                    },
                                    # #6 & #10: Network object with subnet4 change on /24 and comment containing ', port=80'
                                    {
                                        "new-object": {
                                            "uid": "net-sub-diff",
                                            "name": "Corp_Subnet",
                                            "type": "network",
                                            "subnet4": "10.1.0.0",
                                            "mask-length4": 24,
                                            "comments": "Note: legacy, port=80, range=1-2",
                                            "meta-info": {"last-modifier": "operator"},
                                        },
                                        "old-object": {
                                            "uid": "net-sub-diff",
                                            "name": "Corp_Subnet",
                                            "type": "network",
                                            "subnet4": "10.0.0.0",
                                            "mask-length4": 24,
                                            "comments": "Note: legacy, port=80, range=1-2",
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                    },
                                    # #6 & #10: Address-range with ipv4-address-last modified
                                    {
                                        "new-object": {
                                            "uid": "ar-last-diff",
                                            "name": "Corp_Range",
                                            "type": "address-range",
                                            "ipv4-address-first": "10.20.0.10",
                                            "ipv4-address-last": "10.20.0.60",
                                        },
                                        "old-object": {
                                            "uid": "ar-last-diff",
                                            "name": "Corp_Range",
                                            "type": "address-range",
                                            "ipv4-address-first": "10.20.0.10",
                                            "ipv4-address-last": "10.20.0.50",
                                            # #2: old-object had System modifier, new-object omits meta-info -> NOT filtered
                                            "meta-info": {"last-modifier": "System"},
                                        },
                                    },
                                ],
                            }
                        }
                    ]
                }
            ]
        }

        bundle = await build_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-rev"])],
            formats=("html", "markdown", "json"),
        )
        assert bundle.html is not None
        assert bundle.markdown is not None
        html_str = bundle.html.decode("utf-8")
        md_str = bundle.markdown
        sess = bundle.report.sessions[0]

        # #1: Rules are grouped by layer first, then sorted by rule_number within each layer
        ordered_uids = [r.uid for r in sess.rule_changes]
        assert ordered_uids == ["r-net-1", "r-net-3", "r-app-1", "r-app-2", "r-nat-1"]
        # Each section header appears only ONCE in HTML (not split/repeated by interleaved rule numbers)
        assert html_str.count('<tr class="section-row">') == 3
        assert html_str.count("NetSection (1-2)") == 1
        assert html_str.count("AppSection (1-2)") == 1
        assert html_str.count("NatSection (1)") == 1

        # #2: Deleted System-created object and modified object without new meta-info are preserved
        obj_uids = [o.uid for o in sess.object_changes]
        assert "obj-del-sys-created" in obj_uids
        assert "net-sub-diff" in obj_uids
        assert "ar-last-diff" in obj_uids

        # #3 & #7: Bare UUID in track resolved to "Log" (and old_value resolved to "None"), rendered in HTML & Markdown
        r_net3 = next(r for r in sess.rule_changes if r.uid == "r-net-3")
        assert r_net3.track == "Log"
        track_diff = next(d for d in r_net3.field_diffs if d.field_name == "track")
        assert track_diff.old_value == "None"
        assert track_diff.new_value == "Log"
        assert '<span class="diff-removed">None</span><span class="diff-arrow">→</span>' in html_str
        assert "| Track |" in md_str
        assert "| None -> Log |" in md_str

        # #5: String "false" -> "true" in enabled diff rendered as ✗ -> ✓ (NOT ✓ -> ✓)
        assert '<span class="diff-removed">✗</span><span class="diff-arrow">→</span>✓' in html_str
        assert "| ✗ -> ✓ |" in md_str

        # #6 & #10: Composite subnet4=old->new/24 and range=first-old->new without losing /24 or duplicating clauses
        assert (
            'subnet4=<span class="diff-removed">10.0.0.0</span><span class="diff-arrow">→</span>'
            '<span class="diff-highlight">10.1.0.0</span>/24' in html_str
        )
        assert "subnet4=10.0.0.0 -> 10.1.0.0/24" in md_str
        assert (
            'range=10.20.0.10-<span class="diff-removed">10.20.0.50</span><span class="diff-arrow">→</span>'
            '<span class="diff-highlight">10.20.0.60</span>' in html_str
        )
        assert "range=10.20.0.10-10.20.0.50 -> 10.20.0.60" in md_str
        assert "ipv4-address-last=" not in html_str
        assert "ipv4-address-last=" not in md_str
        # Comment with ', port=80, range=1-2' stayed intact inside comments=...
        assert "comments=Note: legacy, port=80, range=1-2" in md_str

        # #8: Literal 'diff-added' in unannotated comment diff still gets wrapped in diff-highlight
        assert '<span class="diff-highlight">Contains literal diff-added token</span>' in html_str
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_placement_skips_refresh_on_empty_or_system_data_domain_and_avoids_double_live_fetch() -> None:
    """Verify R6:
    1. When `session_report.domain_name` is empty (`""`) or `"System Data"`, `apply_session_rule_placement`
       does not invoke `refresh_rulebase_fn` (preventing an accidental `domains=None` all-domain refresh).
    2. When `refresh_rulebase_fn` runs for a regular domain and the domain still has 0 rules,
       `collect_domain_rulebase_snapshot` is not called a second time.
    """
    from arodonata.reports.models import RuleChangeEntry, SessionChangeReport
    from arodonata.reports.placement import apply_session_rule_placement

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()

    try:
        refresh_calls: list[tuple[str, str]] = []

        async def _track_refresh(m_name: str, d_name: str) -> None:
            refresh_calls.append((m_name, d_name))

        # 1. "System Data" domain never calls refresh_rulebase_fn or show-packages
        sys_report = SessionChangeReport(
            mgmt_name="mds1",
            domain_name="System Data",
            session_uid="s-sysdata",
            session_name="System Session",
            user_name="admin",
            state="published",
            rule_changes=[
                RuleChangeEntry(
                    uid="r-sys-1",
                    name="SysRule",
                    rulebase_type="access",
                    operation="added",
                    layer_uid="l-1",
                    layer_name="Network",
                )
            ],
        )
        api.calls.clear()
        await apply_session_rule_placement(
            sys_report,
            api=api,
            cache=cache,
            warnings=[],
            refresh_rulebase_fn=_track_refresh,
        )
        assert refresh_calls == []
        assert api.calls == []
        assert sys_report.numbering_source == "unnumbered"

        # 2. Empty domain_name ("") never calls refresh_rulebase_fn
        empty_dom_report = SessionChangeReport(
            mgmt_name="mds1",
            domain_name="",
            session_uid="s-empty-dom",
            session_name="Empty Dom Session",
            user_name="admin",
            state="published",
            rule_changes=[
                RuleChangeEntry(
                    uid="r-emp-1",
                    name="EmpRule",
                    rulebase_type="access",
                    operation="added",
                    layer_uid="l-1",
                    layer_name="Network",
                )
            ],
        )
        await apply_session_rule_placement(
            empty_dom_report,
            api=api,
            cache=cache,
            warnings=[],
            refresh_rulebase_fn=_track_refresh,
        )
        assert refresh_calls == []

        # 3. Regular domain ("EmptyDomain") where refresh_rulebase_fn runs and finds 0 rules
        # does NOT trigger a redundant second live `collect_domain_rulebase_snapshot` (show-packages) call
        api.calls.clear()
        empty_cma_report = SessionChangeReport(
            mgmt_name="mds1",
            domain_name="EmptyDomain",
            session_uid="s-empty-cma",
            session_name="Empty CMA Session",
            user_name="admin",
            state="published",
            rule_changes=[
                RuleChangeEntry(
                    uid="r-cma-1",
                    name="CmaRule",
                    rulebase_type="access",
                    operation="deleted",
                    layer_uid="l-1",
                    layer_name="Network",
                )
            ],
        )
        await apply_session_rule_placement(
            empty_cma_report,
            api=api,
            cache=cache,
            warnings=[],
            refresh_rulebase_fn=_track_refresh,
        )
        assert refresh_calls == [("mds1", "EmptyDomain")]
        assert api.calls == []
        assert empty_cma_report.numbering_source == "unnumbered"
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-006-1", "SCN-REPORT-006-2", "SCN-REPORT-006-3")
@pytest.mark.asyncio
async def test_reports_range_bounds_owned_fallback_placement_diffs_and_safe_markup() -> None:
    """SCN-REPORT-006-1..3: Fail-closed RangeScope UIDs, OwnedSession fallback, nested placement, unordered diffs, dotted plan numbers, and safe inline markup."""
    from arodonata.core.models.rulebase import PolicyPackageInfo, RulebaseLayerEntry
    from arodonata.cpcrud.models import Outcome, Plan, PlannedAction
    from arodonata.reports._collector_changes import _filter_range_sessions
    from arodonata.reports._collector_diffs import _list_field_diff
    from arodonata.reports._renderer_formatting import _esc_md, render_safe_inline_markdown_md
    from arodonata.reports.models import RangeScope, RuleChangeEntry
    from arodonata.reports.placement import _apply_snapshot_locations_to_rules
    from arodonata.reports.plan_report import build_change_report_from_plan

    # 1. Missing RangeScope from_session / to_session UID fails closed (empty list)
    sessions = [
        {"uid": "s-1", "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"}},
        {"uid": "s-2", "publish-time": {"iso-8601": "2026-10-23T13:00:00Z"}},
    ]
    assert (
        _filter_range_sessions(sessions, RangeScope(mgmt_name="mds1", domain="Corp", from_session="missing-uid")) == []
    )
    assert _filter_range_sessions(sessions, RangeScope(mgmt_name="mds1", domain="Corp", to_session="missing-uid")) == []

    # 2. OwnedSession domain mismatch falls back to shared read-only session with warning
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = FakeReportsApi()
    try:
        api.sessions_by_uid["s-pub"] = {
            "uid": "s-pub",
            "name": "Pub1",
            "state": "published",
            "publish-time": {"iso-8601": "2026-10-23T12:00:00Z"},
            "changes": 0,
        }
        api.changes_by_session["s-pub"] = {"tasks": [{"task-details": [{"operations": {}}]}]}
        orig_api_call = api.api_call

        async def _fail_owned_sid_call(
            mgmt_name: str,
            command: str,
            payload: dict[str, Any] | None = None,
            **kwargs: Any,
        ) -> ApiCallResult:
            if kwargs.get("sid") == "expired-owned-sid":
                return ApiCallResult(
                    success=False, status_code=401, error_code="err_login_failed", error_message="expired"
                )
            return await orig_api_call(mgmt_name, command, payload, **kwargs)

        api.api_call = _fail_owned_sid_call  # type: ignore[method-assign]
        expired_owned = OwnedSession(sid="expired-owned-sid", domain="Corp", server_ip="10.0.0.1")
        rep = await collect_change_report(
            api,
            cache,
            [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-pub"], owned_sessions=expired_owned)],
        )
        assert any(w.code == "owned_session_error" for w in rep.warnings)
        assert len(rep.sessions) == 1
    finally:
        await db.close()

    # 3. Nested rule placement does not falsely mark in-place edit as MOVED
    snap = DomainRulebaseSnapshot(
        mgmt_name="mds1",
        domain_name="Corp",
        packages=[
            PolicyPackageInfo(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="pkg-1",
                name="Standard",
                access_layers=[
                    {
                        "mgmt_name": "mds1",
                        "domain_name": "Corp",
                        "package_uid": "pkg-1",
                        "package_name": "Standard",
                        "rulebase_type": "access",
                        "layer_uid": "l-parent",
                        "layer_name": "Parent",
                        "position": 1,
                    }
                ],
            )
        ],
        layers=[
            RulebaseLayerEntry(
                mgmt_name="mds1", domain_name="Corp", uid="l-parent", name="Parent", rulebase_type="access"
            ),
            RulebaseLayerEntry(
                mgmt_name="mds1", domain_name="Corp", uid="l-inline", name="Inline", rulebase_type="access"
            ),
        ],
        access_rules=[
            AccessRuleEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                layer_uid="l-parent",
                layer_name="Parent",
                uid="r-parent",
                name="InlineAnchor",
                position=2,
                inline_layer_uid="l-inline",
            ),
            AccessRuleEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                layer_uid="l-inline",
                layer_name="Inline",
                uid="r-child",
                name="ChildRule",
                position=3,
            ),
        ],
    )
    rc = RuleChangeEntry(
        uid="r-child",
        name="ChildRule",
        rulebase_type="access",
        operation="modified",
        layer_uid="l-inline",
        layer_name="Inline",
        old_rule_number="1",
    )
    _apply_snapshot_locations_to_rules([rc], snap)
    assert rc.rule_number == "1.1"
    assert rc.moved is False

    # 4. Reordered unordered Check Point list produces None FieldDiff
    assert _list_field_diff("source", ["Host_A", "Host_B"], ["Host_B", "Host_A"]) is None

    # 5. Dotted string rule_number preserved in build_change_report_from_plan
    plan = Plan(
        actions=[
            PlannedAction(
                action_id="a1",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="access-rule",
                name="SubRule",
                layer="Inline",
                outcome=Outcome.UPDATE,
                desired_spec={"rule_number": "2.1", "layer": "Inline"},
                payload={"comments": "updated"},
            )
        ]
    )
    plan_rep = build_change_report_from_plan(plan)
    assert plan_rep.sessions[0].rule_changes[0].rule_number == "2.1"

    # 6. Safe inline markdown neutralizes multiline backticks, unsafe hrefs, and CR/CRLF
    multiline_md = render_safe_inline_markdown_md("`line1\n<script>alert(1)</script>`")
    assert "<script>" not in multiline_md
    bad_href_md = render_safe_inline_markdown_md('[click](https://evil.example/a"onclick=alert(1))')
    assert "[click](https://evil.example" not in bad_href_md
    assert "\\[click\\]" in bad_href_md
    assert "\r" not in _esc_md("a\r\nb|c")
    assert "a b\\|c" == _esc_md("a\r\nb|c")


@pytest.mark.spec("SCN-REPORT-007-1")
def test_unified_object_summary_preserves_icmp_protocol_url_description_and_ipv6() -> None:
    """Verify unified object summary schema preserves omitted fields across modified diffs and dry-run plan reports."""
    from arodonata.cpcrud.models import FieldChange, Outcome, Plan, PlannedAction
    from arodonata.reports._renderer_formatting import _HTML_FMT, _MD_FMT, _render_object_details
    from arodonata.reports.models import FieldDiff, ObjectChangeEntry
    from arodonata.reports.plan_report import build_change_report_from_plan

    # 1. Modified service-icmp with summary missing summary_fields -> SUMMARY_SPLIT_RE + _render_object_details preserves icmp/description
    oc = ObjectChangeEntry(
        uid="icmp-1",
        name="ICMP_Echo",
        object_type="service-icmp",
        operation="modified",
        summary="icmp-type=8, icmp-code=0, ip-protocol=1, description=Ping check, comments=updated",
        summary_fields={},
        field_diffs=[FieldDiff(field_name="comments", old_value="old", new_value="updated")],
    )
    html_details = _render_object_details(oc, _HTML_FMT)
    md_details = _render_object_details(oc, _MD_FMT)
    assert "icmp-type=8" in html_details and "icmp-code=0" in html_details
    assert "ip-protocol=1" in html_details and "description=Ping check" in html_details
    assert "icmp-type=8" in md_details and "description=Ping check" in md_details

    # 2. Dry-run plan_report preserves IPv6 subnet/range, icmp, ip-protocol, url-regex, url-list, description
    plan = Plan(
        actions=[
            PlannedAction(
                action_id="p1",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="set",
                object_type="application-site",
                name="App_Portal",
                outcome=Outcome.UPDATE,
                prior_state={
                    "primary-category": "Custom",
                    "urls-defined-as-regular-expression": True,
                    "url-list": ["portal.example.com"],
                    "description": "Internal app",
                    "subnet6": "2001:db8::",
                    "mask-length6": 64,
                },
                payload={"comments": "new comment"},
                field_changes=[FieldChange(field="comments", old_value="", new_value="new comment")],
            )
        ]
    )
    rep = build_change_report_from_plan(plan)
    obj_entry = rep.sessions[0].object_changes[0]
    assert "primary-category=Custom" in obj_entry.summary
    assert "urls-defined-as-regular-expression=True" in obj_entry.summary
    assert "url-list=[portal.example.com]" in obj_entry.summary
    assert "description=Internal app" in obj_entry.summary
    assert "subnet6=2001:db8::/64" in obj_entry.summary


def test_report_redaction_and_markdown_injection_escaping() -> None:
    """DA-009/DA-010: Scrub SIDs/secrets from report entries and escape dangerous Markdown constructs."""
    from arodonata.reports.models import ChangeReport, FieldDiff, ObjectChangeEntry, SessionChangeReport
    from arodonata.reports.renderer import render_change_report

    fd = FieldDiff(
        field_name="password",
        old_value="old_secret_1234",
        new_value="X-chkp-sid: secret_sid_9876",
    )
    assert "old_secret_1234" not in str(fd.old_value)
    assert "secret_sid_9876" not in str(fd.new_value)

    obj_entry = ObjectChangeEntry(
        uid="uid-evil-`tick`",
        name="[click](https://evil.test)",
        object_type="host",
        operation="added",
        summary="ipv4-address=10.0.0.1 ![exfil](https://evil.test/x.png) comments=X-chkp-sid: leaked_sid_1234",
    )
    assert "leaked_sid_1234" not in (obj_entry.summary or "")

    rep = ChangeReport(
        sessions=[
            SessionChangeReport(
                mgmt_name="mds1",
                domain_name="Corp",
                session_uid="s1",
                object_changes=[obj_entry],
            )
        ],
    )
    bundle = render_change_report(rep, options=RenderOptions())
    md = bundle.markdown
    assert "[click](https://evil.test)" not in md
    assert "![exfil](https://evil.test/x.png)" not in md
    assert r"\[click\]" in md


@pytest.mark.spec("SCN-REPORT-008-1")
@pytest.mark.asyncio
async def test_unparsed_range_bound_fails_closed_and_invalid_owned_session_not_forwarded() -> None:
    """SCN-REPORT-008-1 (DA-025, DA-026): Unparsed range bounds fail closed with warning, invalidated OwnedSession stops propagating, and known_names redact SIDs."""
    from arodonata.core.errors import REDACTED_PLACEHOLDER
    from arodonata.core.models.common import ApiCallResult, ApiQueryResult
    from arodonata.reports.collector import collect_change_report
    from arodonata.reports.models import OwnedSession, RangeScope, SessionScope

    # 1. RangeScope bound lacking parseable timestamp fails closed + emits warning
    class _UnparsedRangeApi:
        async def api_query(self, mgmt: str, cmd: str, **kwargs: Any) -> ApiQueryResult:
            _ = (mgmt, cmd, kwargs)
            return ApiQueryResult(
                success=True,
                objects=[
                    {"uid": "s-bad-ts", "name": "NoTs"},
                    {"uid": "s-other", "name": "HasTs", "publish-time": {"iso-8601": "2026-04-01T10:00:00Z"}},
                ],
                total=2,
            )

        async def api_call(self, *args: Any, **kwargs: Any) -> ApiCallResult:
            return ApiCallResult(success=True, data={})

    db = DatabaseManager("sqlite+aiosqlite:///:memory:")
    await db.initialize()
    cache = SqlCacheAdapter(db)
    try:
        rep = await collect_change_report(
            api=_UnparsedRangeApi(),  # type: ignore[arg-type]
            cache=cache,  # type: ignore[arg-type]
            scopes=[RangeScope(mgmt_name="mds1", domains=["Corp"], from_session="s-bad-ts")],
        )
        assert rep.sessions == []
        assert any(w.code == "range_session_timestamp_missing" for w in rep.warnings)

        # 2. Invalidated OwnedSession SID is NOT passed to show-object, and resolved names are redacted
        owned_sid = "OwnedLeakedBareSid556677"
        calls_seen: list[tuple[str, str | None]] = []
        bare_uid = "11111111-1111-1111-1111-111111111111"

        class _OwnedFailApi:
            async def api_query(self, *args: Any, **kwargs: Any) -> ApiQueryResult:
                return ApiQueryResult(success=True, objects=[])

            async def api_call(self, mgmt: str, cmd: str, payload: Any = None, **kwargs: Any) -> ApiCallResult:
                _ = (mgmt, payload)
                sid_arg = kwargs.get("sid")
                calls_seen.append((cmd, sid_arg))
                if cmd == "show-session" and sid_arg == owned_sid:
                    return ApiCallResult(success=False, error_code="wrong_session_id", error_message="bad sid")
                if cmd == "show-session":
                    return ApiCallResult(
                        success=True,
                        data={"uid": "s-1", "name": "S1", "publish-time": {"iso-8601": "2026-04-01T10:00:00Z"}},
                    )
                if cmd == "show-changes" and sid_arg == owned_sid:
                    return ApiCallResult(success=False, error_code="wrong_session_id", error_message="bad sid")
                if cmd == "show-changes":
                    return ApiCallResult(
                        success=True,
                        data={
                            "changes": [
                                {
                                    "operations": {
                                        "added-objects": [
                                            {
                                                "uid": "g-wrap-1",
                                                "name": "Grp1",
                                                "type": "group",
                                                "members": [bare_uid],
                                            }
                                        ],
                                    }
                                }
                            ]
                        },
                    )
                if cmd == "show-object":
                    return ApiCallResult(
                        success=True,
                        data={"object": {"uid": bare_uid, "name": f"Host_{owned_sid}", "type": "host"}},
                    )
                return ApiCallResult(success=True, data={})

        rep2 = await collect_change_report(
            api=_OwnedFailApi(),  # type: ignore[arg-type]
            cache=cache,  # type: ignore[arg-type]
            scopes=[
                SessionScope(
                    mgmt_name="mds1",
                    domain="Corp",
                    session_uids=["s-1"],
                    owned_sessions=OwnedSession(mgmt_name="mds1", domain="Corp", sid=owned_sid),
                )
            ],
        )
        assert not any(cmd == "show-object" and sid == owned_sid for cmd, sid in calls_seen)
        assert len(rep2.sessions) == 1
        assert owned_sid not in str(rep2.sessions[0].resolved_names)
        assert REDACTED_PLACEHOLDER in str(rep2.sessions[0].resolved_names)
        assert owned_sid not in str(rep2.sessions[0].object_changes)
    finally:
        await db.close()


@pytest.mark.spec("SCN-REPORT-008-2")
def test_render_safe_inline_markdown_md_blocks_nested_links_and_images_in_bold_and_italic() -> None:
    """SCN-REPORT-008-2 (DA-018): Escape nested `[` / `]` inside `**bold**` and `*italic*` Markdown spans."""
    from arodonata.reports._renderer_formatting import render_safe_inline_markdown_md

    bold_js = render_safe_inline_markdown_md("**[click](javascript:alert(1))**")
    italic_img = render_safe_inline_markdown_md("*![beacon](https://example.invalid/x.png)*")
    assert bold_js == r"**\[click\](javascript:alert(1))**"
    assert italic_img == r"*!\[beacon\](https://example.invalid/x.png)*"
    assert "[click]" not in bold_js
    assert "![beacon]" not in italic_img


@pytest.mark.spec("SCN-REPORT-009-1")
async def test_range_scope_to_session_omits_date_filter_and_owned_session_context_disables_cleanly() -> None:
    """DA-029, DA-030, DA-042: RangeScope(to_session=...) omits server date bounds and failed OwnedSession stays disabled."""
    from datetime import UTC, datetime

    show_sessions_payloads: list[dict[str, Any]] = []
    calls_by_cmd: list[tuple[str, str | None]] = []

    class _ReportFakeApi:
        async def api_query(
            self, _m: str, cmd: str, payload: dict[str, Any] | None = None, **_k: Any
        ) -> ApiQueryResult:
            if cmd == "show-sessions":
                show_sessions_payloads.append(dict(payload or {}))
                return ApiQueryResult(
                    success=True,
                    objects=[
                        {"uid": "s-1", "publish-time": {"posix": 1700000000000}, "changes": 1},
                        {"uid": "s-2", "publish-time": {"posix": 1700100000000}, "changes": 1},
                    ],
                    total=2,
                )
            return ApiQueryResult(success=True, objects=[], total=0)

        async def api_call(self, _m: str, cmd: str, _p: dict[str, Any] | None = None, **kw: Any) -> ApiCallResult:
            calls_by_cmd.append((cmd, kw.get("sid")))
            if cmd == "show-session" and kw.get("sid") is not None:
                return ApiCallResult(
                    success=False, status_code=400, error_code="err_session_expired", error_message="bad sid"
                )
            if cmd == "show-session":
                return ApiCallResult(
                    success=True, data={"uid": "s-owned", "user-name": "admin", "locks": 0, "changes": 1}
                )
            if cmd == "show-changes":
                return ApiCallResult(
                    success=True,
                    data={
                        "changes": [
                            {
                                "changes": [
                                    {
                                        "uid": "chg-1",
                                        "type": "host",
                                        "action": "Modify",
                                        "changed-fields": [
                                            {"name": "groups", "new-value": ["bare-uid-1", "bare-uid-2"]}
                                        ],
                                    }
                                ]
                            }
                        ]
                    },
                )
            if cmd == "show-object":
                uid = str((_p or {}).get("uid") or "")
                return ApiCallResult(success=True, data={"object": {"uid": uid, "name": f"Obj-{uid}"}})
            return ApiCallResult(success=True, data={})

    class _MinRepCache:
        async def get_object_by_uid(self, *_a: Any) -> None:
            return None

        async def get_service_by_uid(self, *_a: Any) -> None:
            return None

        async def get_rulebase_snapshot(self, *_a: Any, **_k: Any) -> None:
            return None

    owned = OwnedSession(
        sid="owned-bad-sid", server_ip="10.0.0.1", session_uid="s-owned", mgmt_name="mds1", domain="Corp"
    )
    report = await collect_change_report(
        _ReportFakeApi(),  # type: ignore[arg-type]
        _MinRepCache(),  # type: ignore[arg-type]
        [
            RangeScope(
                mgmt_name="mds1",
                domain="Corp",
                to_session="s-1",
                from_date=datetime(2023, 11, 14, tzinfo=UTC),
                to_date=datetime(2023, 11, 15, tzinfo=UTC),
            ),
            SessionScope(
                mgmt_name="mds1",
                domain="Corp",
                session_uids=["s-owned"],
                owned_sessions=[owned],
            ),
        ],
    )
    assert show_sessions_payloads
    assert "from" not in show_sessions_payloads[0]
    assert "to" not in show_sessions_payloads[0]
    # Once show-session rejected owned-bad-sid, neither show-changes nor show-object nor placement uses it again
    assert ("show-changes", "owned-bad-sid") not in calls_by_cmd
    assert ("show-object", "owned-bad-sid") not in calls_by_cmd
    assert len([w for w in report.warnings if w.code == "owned_session_error"]) == 1


@pytest.mark.spec("SCN-REPORT-010-1")
def test_scn_report_010_1_markdown_backslash_before_delimiter_neutralization() -> None:
    """SCN-REPORT-010-1: backslash-first Markdown escaping blocks link/code/table-split bypasses across reports and rulebase."""
    from arodonata.core.primitives import escape_markdown_cell, escape_markdown_code
    from arodonata.reports._renderer_formatting import _esc_md, _esc_md_code, render_safe_inline_markdown_md
    from arodonata.rulebase.filter import _esc_rule_code, _esc_rule_md

    # Both reports and rulebase delegate to shared primitives
    payload_link = r"\[phish\](https://evil.example/steal)"
    payload_pipe = r"a\|b"
    payload_code = r"\`injected\`"
    for fn in (escape_markdown_cell, _esc_md, _esc_rule_md):
        assert fn(payload_link) == r"\\\[phish\\\](https://evil.example/steal)"
        assert fn(payload_pipe) == r"a\\\|b"
        assert fn(payload_code) == r"\\\`injected\\\`"
        # Preserve existing non-backslash pipe & CRLF normalization
        assert fn("a\r\nb|c") == "a b\\|c"

    # Inline safe markdown escapes literal backslashes before brackets in bold/italic/plain/unsafe-link branches
    assert "**\\[phish\\]" not in render_safe_inline_markdown_md(r"**\[phish\](https://evil.example/steal)**")
    assert r"\\\[phish\\\]" in render_safe_inline_markdown_md(r"**\[phish\](https://evil.example/steal)**")
    assert r"\\\[click\\\]" in render_safe_inline_markdown_md(r"\[click\](javascript:alert(1))")

    # Code-span helper preserves unrelated Windows backslashes while hardening backslash-before-pipe
    for code_fn in (escape_markdown_code, _esc_md_code, _esc_rule_code):
        assert code_fn(r"C:\path\file") == r"C:\path\file"
        assert code_fn(r"a\|b") == r"a\\\|b"
        assert code_fn("a|b") == r"a\|b"


@pytest.mark.spec("SCN-REPORT-010-2")
@pytest.mark.asyncio
async def test_scn_report_010_2_owned_session_404_preservation_partial_package_warm_and_warning_code() -> None:
    """SCN-REPORT-010-2: show-object 404 keeps healthy OwnedSession alive, partial slice triggers full warm, and WarningCode includes timestamp warning."""
    from typing import get_args

    from arodonata.core.models.rulebase import (
        DomainRulebaseSnapshot,
        RulebasePackageLayerEntry,
    )
    from arodonata.reports.models import RuleChangeEntry, SessionChangeReport, WarningCode
    from arodonata.reports.placement import apply_session_rule_placement

    # 1. WarningCode Literal includes range_session_timestamp_missing
    assert "range_session_timestamp_missing" in get_args(WarningCode)

    # 2. show-object 404 on OwnedSession retries read-only WITHOUT disabling healthy OwnedSession
    uid_404 = "00000000-0000-0000-0000-000000000404"
    uid_unpub = "00000000-0000-0000-0000-000000000002"
    calls: list[tuple[str, str | None, str | None]] = []

    class _Owned404Api:
        async def api_query(self, *_a: Any, **_kw: Any) -> Any:
            from arodonata.core.models.common import ApiQueryResult

            return ApiQueryResult(success=True, items=[], total=0)

        async def api_call(self, _m: str, cmd: str, payload: dict[str, Any] | None = None, **kw: Any) -> Any:
            from arodonata.core.models.common import ApiCallResult

            sid = kw.get("sid")
            uid = str((payload or {}).get("uid") or "")
            calls.append((cmd, sid, uid))
            if cmd == "show-session":
                return ApiCallResult(
                    success=True,
                    data={"uid": "s-live", "user-name": "admin", "locks": 1, "changes": 2},
                )
            if cmd == "show-changes":
                return ApiCallResult(
                    success=True,
                    data={
                        "changes": [
                            {
                                "modified-objects": [
                                    {
                                        "uid": "00000000-0000-0000-0000-000000000099",
                                        "type": "access-rule",
                                        "layer": "Network",
                                        "source": [uid_404, uid_unpub],
                                    }
                                ]
                            }
                        ]
                    },
                )
            if cmd == "show-object":
                if uid == uid_404 and sid == "owned-good-sid":
                    return ApiCallResult(
                        success=False,
                        status_code=404,
                        error_code="generic_err_object_not_found",
                        error_message=f"Requested object [{uid_404}] not found",
                    )
                if uid == uid_404 and sid is None:
                    return ApiCallResult(success=True, data={"object": {"uid": uid_404, "name": "RecoveredPublished"}})
                if uid == uid_unpub and sid == "owned-good-sid":
                    return ApiCallResult(success=True, data={"object": {"uid": uid_unpub, "name": "UnpubObj"}})
                return ApiCallResult(success=False, status_code=404, error_code="generic_err_object_not_found")
            if cmd == "show-packages":
                return ApiCallResult(success=True, data={"packages": []})
            return ApiCallResult(success=True, data={})

    class _MinCache:
        async def get_object_by_uid(self, *_a: Any) -> None:
            return None

        async def get_service_by_uid(self, *_a: Any) -> None:
            return None

        async def get_domain_rulebase(self, *_a: Any) -> DomainRulebaseSnapshot:
            return DomainRulebaseSnapshot(mgmt_name="mds1", domain_name="Corp")

        async def get_sync_state(self, *_a: Any) -> None:
            return None

    owned = OwnedSession(
        sid="owned-good-sid", server_ip="10.0.0.1", session_uid="s-live", mgmt_name="mds1", domain="Corp"
    )
    report = await collect_change_report(
        _Owned404Api(),  # type: ignore[arg-type]
        _MinCache(),  # type: ignore[arg-type]
        [SessionScope(mgmt_name="mds1", domain="Corp", session_uids=["s-live"], owned_sessions=[owned])],
    )
    assert ("show-object", None, uid_404) in calls
    assert ("show-object", "owned-good-sid", uid_unpub) in calls
    assert [w for w in report.warnings if w.code == "owned_session_error"] == []

    # 3. Partial package snapshot (sync_state is None for "*") triggers refresh_rulebase_fn, and failure preserves partial cache
    from arodonata.core.models.rulebase import RulebaseLayerEntry

    partial_snap = DomainRulebaseSnapshot(
        mgmt_name="mds1",
        domain_name="Corp",
        layers=[
            RulebaseLayerEntry(mgmt_name="mds1", domain_name="Corp", uid="l-1", name="Network", rulebase_type="access")
        ],
        package_layers=[
            RulebasePackageLayerEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                package_uid="pkg-1",
                package_name="Standard",
                rulebase_type="access",
                layer_uid="l-1",
                layer_name="Network",
                position=1,
            )
        ],
    )

    class _PartialCache:
        async def get_domain_rulebase(self, *_a: Any) -> DomainRulebaseSnapshot:
            return partial_snap

        async def get_sync_state(self, *_a: Any) -> None:
            return None

    warm_calls: list[tuple[str, str]] = []

    async def _failing_warm(mgmt: str, dom: str) -> None:
        warm_calls.append((mgmt, dom))
        raise RuntimeError("transient warm failure")

    sess_rep = SessionChangeReport(
        mgmt_name="mds1",
        domain_name="Corp",
        session_uid="s-part",
        state="published",
        rule_changes=[RuleChangeEntry(uid="r-part-1", name="R1", operation="added", rulebase_type="access")],
    )
    await apply_session_rule_placement(
        sess_rep,
        api=_Owned404Api(),  # type: ignore[arg-type]
        cache=_PartialCache(),  # type: ignore[arg-type]
        warnings=[],
        refresh_rulebase_fn=_failing_warm,
    )
    assert warm_calls == [("mds1", "Corp")]
    assert sess_rep.numbering_source == "cache"
