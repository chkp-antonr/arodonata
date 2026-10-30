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
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
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


@pytest.mark.asyncio
async def test_post_publish_clean_owned_session_numbers_live_and_warms_cache() -> None:
    """After `publish` (before `logout`), `OwnedSession` rotates to a clean working session (`changes == 0`) and numbers rules live without warnings."""
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

        # Verify SQLite rulebase cache was warmed by post-publish live read
        warmed = await cache.get_domain_rulebase("mds1", "Corp")
        assert len(warmed.access_rules) == 1
        assert warmed.access_rules[0].uid == "r-pub-1"
    finally:
        await db.close()


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

        # Verify cache was warmed so a second call hits cache
        warmed = await cache.get_domain_rulebase("mds1", "Corp")
        assert len(warmed.access_rules) == 1
        assert warmed.access_rules[0].uid == "r-cold-1"
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
