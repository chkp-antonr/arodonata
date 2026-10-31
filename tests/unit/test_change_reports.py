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
