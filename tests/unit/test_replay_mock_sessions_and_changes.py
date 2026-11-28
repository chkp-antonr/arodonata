"""Unit tests for stateful session lifecycle, overlay isolation, locks, and `show-changes`."""

from __future__ import annotations

from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter
from arodonata.core.errors import SessionError
from arodonata.reports.collector import collect_change_report
from arodonata.reports.models import OwnedSession, RangeScope, SessionScope
from arodonata.testing.replay_mock import FileReplayApiMock


@pytest.mark.spec("SCN-ITEST-007-2", "SCN-ITEST-009-1", "SCN-ITEST-009-2")
@pytest.mark.asyncio
async def test_session_overlay_isolation_and_read_only_enforcement() -> None:
    """Uncommitted edits stay isolated to the owning `sid`; read-only sessions reject writes."""
    api = FileReplayApiMock()

    sid_a, _ = await api.create_dedicated_session("mds", "Branch", session_name="writer-a")
    sid_b, _ = await api.create_dedicated_session("mds", "Branch", session_name="writer-b")
    ro_login = await api.api_call("mds", "login", {"domain": "Branch", "read-only": True}, domain="Branch")
    assert ro_login.success
    sid_ro = str(ro_login.data["sid"])

    # Read-only session rejects mutations and publish/discard
    for cmd, pl in (
        ("add-host", {"name": "RO_Host", "ipv4-address": "10.99.99.1"}),
        ("set-host", {"name": "H_Branch_001_Server", "comments": "ro edit"}),
        ("delete-host", {"name": "H_Branch_001_Server"}),
        ("set-session", {"new-name": "ro-renamed"}),
        ("publish", {}),
        ("discard", {}),
    ):
        ro_res = await api.api_call("mds", cmd, pl, domain="Branch", sid=sid_ro)
        assert not ro_res.success
        assert ro_res.status_code == 400
        assert ro_res.error_code == "err_validation_failed"

    # Writer A adds a host and creates an access rule
    add_res = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Iso_Test_01", "ipv4-address": "10.200.1.10"},
        domain="Branch",
        sid=sid_a,
    )
    assert add_res.success
    host_uid = str(add_res.data["uid"])

    edit_res = await api.api_call(
        "mds",
        "set-host",
        {"uid": "uid-br-host-srv-001", "comments": "uncommitted-a"},
        domain="Branch",
        sid=sid_a,
    )
    assert edit_res.success

    # Writer A sees its own uncommitted changes
    show_a_new = await api.api_call("mds", "show-host", {"uid": host_uid}, domain="Branch", sid=sid_a)
    assert show_a_new.success
    assert show_a_new.data["name"] == "H_Iso_Test_01"

    show_a_edit = await api.api_call("mds", "show-host", {"uid": "uid-br-host-srv-001"}, domain="Branch", sid=sid_a)
    assert show_a_edit.success
    assert show_a_edit.data["comments"] == "uncommitted-a"

    # Writer B, read-only SID, and sid=None only see published baseline
    for other_sid in (sid_b, sid_ro, None):
        other_new = await api.api_call("mds", "show-host", {"uid": host_uid}, domain="Branch", sid=other_sid)
        assert not other_new.success
        assert other_new.status_code == 404

        other_edit = await api.api_call(
            "mds",
            "show-host",
            {"uid": "uid-br-host-srv-001"},
            domain="Branch",
            sid=other_sid,
        )
        assert other_edit.success
        assert other_edit.data.get("comments", "") != "uncommitted-a"

    # Publish from Writer A commits atomically for everyone
    pub_res = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_a, wait_for_task=True)
    assert pub_res.success

    for reader_sid in (sid_b, sid_ro, None):
        seen = await api.api_call("mds", "show-host", {"uid": host_uid}, domain="Branch", sid=reader_sid)
        assert seen.success
        assert seen.data["ipv4-address"] == "10.200.1.10"


@pytest.mark.spec("SCN-ITEST-009-2")
@pytest.mark.asyncio
async def test_cross_session_uid_locks_and_release_paths() -> None:
    """Modifying an entity, rule, or section locks its UID against other open sessions until publish/discard/logout."""
    api = FileReplayApiMock()

    sid_a, _ = await api.create_dedicated_session("mds", "Branch")
    sid_b, _ = await api.create_dedicated_session("mds", "Branch")

    # 1. Entity lock released on discard
    res = await api.api_call(
        "mds",
        "set-host",
        {"uid": "uid-br-host-srv-001", "comments": "lock-1"},
        domain="Branch",
        sid=sid_a,
    )
    assert res.success

    conflict = await api.api_call(
        "mds",
        "set-host",
        {"uid": "uid-br-host-srv-001", "comments": "conflict"},
        domain="Branch",
        sid=sid_b,
    )
    assert not conflict.success
    assert conflict.status_code == 400
    assert conflict.error_code == "generic_err_object_locked"
    assert "locked" in (conflict.error_message or "").lower()

    del_conflict = await api.api_call(
        "mds",
        "delete-host",
        {"uid": "uid-br-host-srv-001"},
        domain="Branch",
        sid=sid_b,
    )
    assert not del_conflict.success
    assert del_conflict.status_code == 400
    assert del_conflict.error_code == "generic_err_object_locked"

    disc = await api.api_call("mds", "discard", {}, domain="Branch", sid=sid_a)
    assert disc.success

    retry_b = await api.api_call(
        "mds",
        "set-host",
        {"uid": "uid-br-host-srv-001", "comments": "acquired-by-b"},
        domain="Branch",
        sid=sid_b,
    )
    assert retry_b.success

    # 2. Published rule and section locks released on logout and publish
    sec_res = await api.api_call(
        "mds",
        "add-access-section",
        {"layer": "Branch_Standard_Pkg Network", "name": "Temp Section", "position": "bottom"},
        domain="Branch",
        sid=sid_a,
    )
    assert sec_res.success
    sec_uid = str(sec_res.data["uid"])

    pub_b = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_b)
    assert pub_b.success
    pub_a = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_a)
    assert pub_a.success

    # sid_a edits the published section and published rule #1
    sec_edit = await api.api_call(
        "mds",
        "set-access-section",
        {"layer": "Branch_Standard_Pkg Network", "uid": sec_uid, "new-name": "Temp Section Edited"},
        domain="Branch",
        sid=sid_a,
    )
    assert sec_edit.success

    rule_edit = await api.api_call(
        "mds",
        "set-access-rule",
        {"layer": "Branch_Standard_Pkg Network", "rule-number": 1, "comments": "locked-rule-by-a"},
        domain="Branch",
        sid=sid_a,
    )
    assert rule_edit.success

    sec_conflict = await api.api_call(
        "mds",
        "set-access-section",
        {"layer": "Branch_Standard_Pkg Network", "uid": sec_uid, "new-name": "Hijack"},
        domain="Branch",
        sid=sid_b,
    )
    assert not sec_conflict.success
    assert sec_conflict.status_code == 400
    assert sec_conflict.error_code == "generic_err_object_locked"

    rule_conflict = await api.api_call(
        "mds",
        "delete-access-rule",
        {"layer": "Branch_Standard_Pkg Network", "rule-number": 1},
        domain="Branch",
        sid=sid_b,
    )
    assert not rule_conflict.success
    assert rule_conflict.status_code == 400
    assert rule_conflict.error_code == "generic_err_object_locked"

    # logout sid_a with uncommitted edits -> transitions to disconnected and preserves section/rule locks
    sess_a_uid = str((await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_a)).data["uid"])
    out_a = await api.logout_sid("mds", sid_a)
    assert out_a is True

    sid_c, _ = await api.create_dedicated_session("mds", "Branch")
    still_locked = await api.api_call(
        "mds",
        "set-access-section",
        {"layer": "Branch_Standard_Pkg Network", "uid": sec_uid, "new-name": "StillLocked"},
        domain="Branch",
        sid=sid_c,
    )
    assert not still_locked.success
    assert still_locked.error_code == "generic_err_object_locked"

    # Explicit discard of the disconnected session releases uncommitted edits & locks
    disc_disconnected = await api.api_call(
        "mds",
        "discard",
        {"uid": sess_a_uid},
        domain="Branch",
        sid=sid_c,
    )
    assert disc_disconnected.success
    edit_c = await api.api_call(
        "mds",
        "set-host",
        {"uid": "uid-br-host-srv-001", "comments": "after-pub-and-logout"},
        domain="Branch",
        sid=sid_c,
    )
    assert edit_c.success
    sec_after = await api.api_call(
        "mds",
        "delete-access-section",
        {"layer": "Branch_Standard_Pkg Network", "uid": sec_uid},
        domain="Branch",
        sid=sid_c,
    )
    assert sec_after.success
    rule_after = await api.api_call(
        "mds",
        "set-access-rule",
        {"layer": "Branch_Standard_Pkg Network", "rule-number": 1, "comments": "unlocked-rule"},
        domain="Branch",
        sid=sid_c,
    )
    assert rule_after.success


@pytest.mark.asyncio
async def test_session_lifecycle_takeover_switch_and_continue_session() -> None:
    """Verify `set-session`, `take-over-session`, `switch-session`, `continue-last-session`, and `logout_sid`."""
    api = FileReplayApiMock()

    sid_1, _ = await api.create_dedicated_session("mds", "Branch", session_name="draft-initial")
    s1_info = await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_1)
    assert s1_info.success
    sess_1_uid = str(s1_info.data["uid"])

    # Update session metadata via set-session
    upd = await api.api_call(
        "mds",
        "set-session",
        {
            "new-name": "draft-renamed",
            "description": "Stateful test session",
            "comments": "Audit ticket #123",
            "color": "blue",
            "tags": ["mmp", "decom"],
        },
        domain="Branch",
        sid=sid_1,
    )
    assert upd.success
    assert upd.data["name"] == "draft-renamed"
    assert upd.data["description"] == "Stateful test session"
    assert upd.data["comments"] == "Audit ticket #123"
    assert upd.data["color"] == "blue"
    assert upd.data["tags"] == ["mmp", "decom"]

    # Stage an uncommitted object
    add_res = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Takeover_Keep", "ipv4-address": "10.200.2.10"},
        domain="Branch",
        sid=sid_1,
    )
    assert add_res.success

    # Disconnect with continue-session-in-smartconsole -> overlay persists and can be resumed via continue-last-session
    disc_logout = await api.api_call(
        "mds",
        "logout",
        {"continue-session-in-smartconsole": True},
        domain="Branch",
        sid=sid_1,
    )
    assert disc_logout.success

    resumed_login = await api.api_call(
        "mds",
        "login",
        {"domain": "Branch", "user": "admin", "continue-last-session": True},
        domain="Branch",
    )
    assert resumed_login.success
    assert resumed_login.data["uid"] == sess_1_uid
    sid_resumed = str(resumed_login.data["sid"])

    # Old disconnected sid_1 is invalid
    old_check = await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_1)
    assert not old_check.success
    assert old_check.status_code == 401
    assert old_check.error_code == "generic_err_invalid_session_id"

    # Resumed SID sees uncommitted host
    seen_resumed = await api.api_call("mds", "show-host", {"name": "H_Takeover_Keep"}, domain="Branch", sid=sid_resumed)
    assert seen_resumed.success

    # Another session takes over sess_1_uid -> old sid_resumed invalidated, detached initial_uid discardable
    sid_2, _ = await api.create_dedicated_session("mds", "Branch", session_name="helper-init")
    helper_info = await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_2)
    detached_uid = str(helper_info.data["uid"])

    takeover = await api.api_call(
        "mds",
        "take-over-session",
        {"uid": sess_1_uid, "disconnect-active-session": True},
        domain="Branch",
        sid=sid_2,
    )
    assert takeover.success
    assert takeover.data["uid"] == sess_1_uid

    # Discarding the detached initial session UID succeeds cleanly
    disc_detached = await api.api_call("mds", "discard", {"uid": detached_uid}, domain="Branch", sid=sid_2)
    assert disc_detached.success

    # Old owner sid_resumed is invalidated
    kicked = await api.api_call("mds", "show-host", {"name": "H_Takeover_Keep"}, domain="Branch", sid=sid_resumed)
    assert not kicked.success
    assert kicked.status_code == 401
    assert kicked.error_code == "generic_err_invalid_session_id"

    # sid_2 sees staged host and can switch to a new session via switch-session
    seen_s2 = await api.api_call("mds", "show-host", {"name": "H_Takeover_Keep"}, domain="Branch", sid=sid_2)
    assert seen_s2.success

    sid_3, _ = await api.create_dedicated_session("mds", "Branch", session_name="target-switch")
    s3_info = await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_3)
    s3_uid = str(s3_info.data["uid"])

    sw = await api.api_call("mds", "switch-session", {"uid": s3_uid}, domain="Branch", sid=sid_2)
    assert sw.success
    assert sw.data["uid"] == s3_uid

    # Verify unpublished sessions listing via show-sessions view-published-sessions=False
    open_list = await api.api_call(
        "mds",
        "show-sessions",
        {"view-published-sessions": False},
        domain="Branch",
        sid=sid_2,
    )
    assert open_list.success
    open_uids = {s["uid"] for s in open_list.data["objects"]}
    assert sess_1_uid in open_uids
    assert s3_uid in open_uids

    # Take back sess_1_uid and discard via discard {} -> number-of-discarded-changes reflects discarded edits
    back = await api.api_call("mds", "take-over-session", {"uid": sess_1_uid}, domain="Branch", sid=sid_2)
    assert back.success
    disc_res = await api.api_call("mds", "discard", {}, domain="Branch", sid=sid_2)
    assert disc_res.success
    assert disc_res.data["number-of-discarded-changes"] == 1


@pytest.mark.spec("SCN-ITEST-010-1")
@pytest.mark.asyncio
async def test_concurrent_publish_rebase_and_atomic_conflict_failure() -> None:
    """Disjoint concurrent sessions rebase cleanly on publish; conflicting concurrent edits fail atomically."""
    api = FileReplayApiMock()

    # Non-conflicting disjoint sessions
    sid_a, _ = await api.create_dedicated_session("mds", "Branch")
    sid_b, _ = await api.create_dedicated_session("mds", "Branch")

    r1 = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Rebase_A", "ipv4-address": "10.201.1.1"},
        domain="Branch",
        sid=sid_a,
    )
    r2 = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Rebase_B", "ipv4-address": "10.201.1.2"},
        domain="Branch",
        sid=sid_b,
    )
    assert r1.success and r2.success

    assert (await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_a)).success
    pub_b = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_b)
    assert pub_b.success

    # Both hosts exist in published state
    assert (await api.api_call("mds", "show-host", {"name": "H_Rebase_A"}, domain="Branch")).success
    assert (await api.api_call("mds", "show-host", {"name": "H_Rebase_B"}, domain="Branch")).success

    # Conflicting concurrent adds (same name from two sessions started against same base snapshot)
    sid_c, _ = await api.create_dedicated_session("mds", "Branch")
    sid_d, _ = await api.create_dedicated_session("mds", "Branch")

    c_pre = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Rebase_Pre", "ipv4-address": "10.201.2.1"},
        domain="Branch",
        sid=sid_c,
    )
    c_dup = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Conflict_Name", "ipv4-address": "10.201.2.2"},
        domain="Branch",
        sid=sid_c,
    )
    d_dup = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Conflict_Name", "ipv4-address": "10.201.2.3"},
        domain="Branch",
        sid=sid_d,
    )
    assert c_pre.success and c_dup.success and d_dup.success

    assert (await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_d)).success

    # sid_c's publish must fail on H_Conflict_Name without committing H_Rebase_Pre either!
    pub_c = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_c)
    assert not pub_c.success
    assert pub_c.status_code in (400, 409)

    assert not (await api.api_call("mds", "show-host", {"name": "H_Rebase_Pre"}, domain="Branch")).success
    published_dup = await api.api_call("mds", "show-host", {"name": "H_Conflict_Name"}, domain="Branch")
    assert published_dup.success
    assert published_dup.data["ipv4-address"] == "10.201.2.3"


@pytest.mark.spec("SCN-ITEST-010-1", "SCN-REPORT-003-3")
@pytest.mark.asyncio
async def test_post_publish_rotation_show_changes_and_collect_change_report() -> None:
    """Verify post-publish rotation, async/sync `show-changes`, and `collect_change_report` with `OwnedSession`."""
    api = FileReplayApiMock()
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)

    try:
        sid, _ = await api.create_dedicated_session(
            "mds",
            "Branch",
            session_name="mmp-change-report-test",
            session_description="Testing staged and published change reports",
        )
        sess_res = await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid)
        assert sess_res.success
        staged_uid = str(sess_res.data["uid"])

        # Perform object + rule mutations in staged session
        add_host = await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Report_New", "ipv4-address": "10.202.1.50"},
            domain="Branch",
            sid=sid,
        )
        assert add_host.success
        host_uid = str(add_host.data["uid"])

        add_rule = await api.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": "Branch_Standard_Pkg Network",
                "position": "top",
                "name": "Report Allow Top",
                "source": [host_uid],
                "destination": ["Any"],
                "service": ["Any"],
                "action": "Accept",
            },
            domain="Branch",
            sid=sid,
        )
        assert add_rule.success
        rule_uid = str(add_rule.data["uid"])

        # Direct show-changes check: only tasks[], never duplicated top-level changes[], and wait_for_task=False returns task-id
        async_ch = await api.api_call(
            "mds",
            "show-changes",
            {"to-session": staged_uid},
            domain="Branch",
            sid=sid,
            wait_for_task=False,
        )
        assert async_ch.success
        assert "task-id" in async_ch.data
        assert "tasks" not in async_ch.data

        poll_task = await api.api_call(
            "mds", "show-task", {"task-id": async_ch.data["task-id"]}, domain="Branch", sid=sid
        )
        assert poll_task.success
        assert poll_task.data["tasks"][0]["status"] == "succeeded"

        sync_ch = await api.api_call(
            "mds",
            "show-changes",
            {"to-session": staged_uid},
            domain="Branch",
            sid=sid,
            wait_for_task=True,
        )
        assert sync_ch.success
        assert "tasks" in sync_ch.data
        assert "changes" not in sync_ch.data

        # Case 1: Staged OwnedSession report
        staged_report = await collect_change_report(
            api,
            cache,
            [
                SessionScope(
                    mgmt_name="mds",
                    domain="Branch",
                    session_uids=[staged_uid],
                    owned_sessions=OwnedSession(sid=sid, session_uid=staged_uid, server_ip="127.0.0.1"),
                )
            ],
        )
        assert len(staged_report.sessions) == 1
        st_sess = staged_report.sessions[0]
        assert st_sess.numbering_source == "owned_session"
        assert {o.name for o in st_sess.object_changes if o.operation == "added"} >= {"H_Report_New"}
        added_rules = [r for r in st_sess.rule_changes if r.uid == rule_uid]
        assert len(added_rules) == 1
        assert added_rules[0].rule_number == "1"
        assert added_rules[0].source == ["H_Report_New"]

        # Publish synchronously -> caller sid rotates onto fresh open clean WorkSession
        pub_res = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid, wait_for_task=True)
        assert pub_res.success
        assert pub_res.data["uid"] == staged_uid

        rotated_sess = await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid)
        assert rotated_sess.success
        assert rotated_sess.data["uid"] != staged_uid
        assert rotated_sess.data["state"] == "open"
        assert rotated_sess.data["changes"] == 0
        assert rotated_sess.data["locks"] == 0
        assert rotated_sess.data["number-of-published-changes"] == 0
        assert "publish-time" not in rotated_sess.data

        # show-last-published-session & show-sessions reflect published session
        last_pub = await api.api_call("mds", "show-last-published-session", {}, domain="Branch", sid=sid)
        assert last_pub.success
        assert last_pub.data["uid"] == staged_uid
        assert last_pub.data["published-changes"] >= 2

        pub_list = await api.api_call(
            "mds",
            "show-sessions",
            {"view-published-sessions": True},
            domain="Branch",
            sid=sid,
        )
        assert pub_list.success
        assert any(s["uid"] == staged_uid for s in pub_list.data["objects"])

        # Case 2: Post-publish OwnedSession report before logout uses live_published!
        pub_report = await collect_change_report(
            api,
            cache,
            [
                SessionScope(
                    mgmt_name="mds",
                    domain="Branch",
                    session_uids=[staged_uid],
                    owned_sessions=OwnedSession(sid=sid, session_uid=staged_uid, server_ip="127.0.0.1"),
                )
            ],
        )
        assert len(pub_report.sessions) == 1
        assert pub_report.sessions[0].numbering_source == "live_published"
        assert pub_report.sessions[0].rule_changes[0].rule_number == "1"

        # RangeScope query over published revisions also finds staged_uid
        from datetime import UTC, datetime, timedelta

        pub_dt = datetime.fromisoformat(last_pub.data["publish-time"]["iso-8601"].replace("Z", "+00:00"))
        range_report = await collect_change_report(
            api,
            cache,
            [
                RangeScope(
                    mgmt_name="mds",
                    domain="Branch",
                    from_date=pub_dt - timedelta(minutes=5),
                    to_date=pub_dt + timedelta(minutes=5),
                )
            ],
        )
        assert any(s.session_uid == staged_uid for s in range_report.sessions)
        assert UTC is not None
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_fast_path_publish_does_not_clobber_concurrent_domain_generation_writes() -> None:
    """Out-of-band `_domain_data` mutations (e.g. assign-global-policy / gateway interfaces) survive concurrent publish."""
    api = FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")

    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Gen_Keep", "ipv4-address": "10.231.1.1"},
            domain="Branch",
            sid=sid,
        )
    ).success

    # Out-of-band mutations on Branch that do not bump published_session_uid
    mds_sid, _ = await api.create_dedicated_session("mds", "System Data")
    assert (
        await api.api_call(
            "mds",
            "assign-global-policy",
            {"dependent-domains": ["Branch"], "global-domains": ["Global"]},
            domain="System Data",
            sid=mds_sid,
            wait_for_task=True,
        )
    ).success
    api.update_gateway_interfaces(
        "Branch",
        "br-spb-gw-01",
        [{"name": "eth9", "ipv4-address": "10.231.9.1", "ipv4-mask-length": 24}],
    )

    pub_res = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid, wait_for_task=True)
    assert pub_res.success

    # Both the session host addition and concurrent package/gateway writes remain intact
    assert (await api.api_call("mds", "show-host", {"name": "H_Gen_Keep"}, domain="Branch")).success
    pkg = (await api.api_call("mds", "show-package", {"name": "Branch_Standard_Pkg"}, domain="Branch")).data
    assert "global-policy-assigned-at" in pkg
    gw = (await api.api_call("mds", "show-simple-gateway", {"name": "br-spb-gw-01"}, domain="Branch")).data
    assert gw["interfaces"][0]["name"] == "eth9"


@pytest.mark.spec("SCN-ITEST-010-1")
@pytest.mark.asyncio
async def test_publish_by_explicit_uid_async_revision_and_system_data_guard() -> None:
    """Explicit `publish {"uid": ...}` targets the named session; `System Data` rejects domain mutations."""
    api = FileReplayApiMock()
    helper_sid, _ = await api.create_dedicated_session("mds", "Branch", session_name="helper")
    target_sid, _ = await api.create_dedicated_session("mds", "Branch", session_name="target")

    target_sess_uid = str((await api.api_call("mds", "show-session", {}, domain="Branch", sid=target_sid)).data["uid"])
    helper_sess_uid = str((await api.api_call("mds", "show-session", {}, domain="Branch", sid=helper_sid)).data["uid"])

    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Helper_Stays", "ipv4-address": "10.232.1.1"},
            domain="Branch",
            sid=helper_sid,
        )
    ).success
    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Target_Pubs", "ipv4-address": "10.232.2.2"},
            domain="Branch",
            sid=target_sid,
        )
    ).success

    # Async publish of target_sess_uid from helper_sid returns task-id only (no top-level uid),
    # puts revision in show-task, rotates target_sid, and leaves helper's session staged.
    async_pub = await api.api_call(
        "mds",
        "publish",
        {"uid": target_sess_uid},
        domain="Branch",
        sid=helper_sid,
        wait_for_task=False,
    )
    assert async_pub.success
    assert "task-id" in async_pub.data
    assert "uid" not in async_pub.data

    task_res = await api.api_call("mds", "show-task", {"task-id": async_pub.data["task-id"]}, sid=helper_sid)
    assert task_res.success
    assert task_res.data["tasks"][0]["task-details"][0]["revision"] == target_sess_uid

    assert (await api.api_call("mds", "show-host", {"name": "H_Target_Pubs"}, domain="Branch")).success
    target_after = await api.api_call("mds", "show-session", {}, domain="Branch", sid=target_sid)
    assert target_after.data["uid"] != target_sess_uid
    helper_after = await api.api_call("mds", "show-session", {}, domain="Branch", sid=helper_sid)
    assert helper_after.data["uid"] == helper_sess_uid
    assert helper_after.data["changes"] == 1
    assert not (await api.api_call("mds", "show-host", {"name": "H_Helper_Stays"}, domain="Branch")).success

    # Unknown UID -> 404
    missing_pub = await api.api_call("mds", "publish", {"uid": "nonexistent-sess-uid"}, domain="Branch", sid=helper_sid)
    assert not missing_pub.success
    assert missing_pub.status_code == 404

    # System Data session cannot execute object/rule CRUD in Branch or System Data
    mds_sid, _ = await api.create_dedicated_session("mds", "System Data")
    bad_local = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Sys_Illegal", "ipv4-address": "10.232.3.3"},
        domain="Branch",
        sid=mds_sid,
    )
    assert not bad_local.success
    assert bad_local.status_code == 400
    assert bad_local.error_code == "err_validation_failed"

    bad_sys = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Sys_Direct", "ipv4-address": "10.232.4.4"},
        domain="System Data",
        sid=mds_sid,
    )
    assert not bad_sys.success
    assert bad_sys.status_code == 400
    assert bad_sys.error_code == "err_validation_failed"
    assert "System Data" not in api._domain_data


@pytest.mark.asyncio
async def test_take_over_session_disconnect_flag_and_create_dedicated_session_error() -> None:
    """`take-over-session` honors `disconnect-active-session`; failed login raises `SessionError`."""
    api = FileReplayApiMock()

    # SmartConsole session requires disconnect-active-session=True when active
    sc_login = await api.api_call(
        "mds",
        "login",
        {"user": "admin", "password": "pw", "domain": "Branch", "application": "SmartConsole"},
        domain="Branch",
    )
    assert sc_login.success
    sc_sid = str(sc_login.data["sid"])
    sc_uid = str(sc_login.data["uid"])

    taker_sid, _ = await api.create_dedicated_session("mds", "Branch")
    blocked = await api.api_call(
        "mds",
        "take-over-session",
        {"uid": sc_uid},
        domain="Branch",
        sid=taker_sid,
    )
    assert not blocked.success
    assert blocked.status_code == 400
    assert blocked.error_code == "err_validation_failed"

    forced = await api.api_call(
        "mds",
        "take-over-session",
        {"uid": sc_uid, "disconnect-active-session": True},
        domain="Branch",
        sid=taker_sid,
    )
    assert forced.success
    stale_sc = await api.api_call("mds", "show-hosts", {"limit": 1}, domain="Branch", sid=sc_sid)
    assert not stale_sc.success
    assert stale_sc.status_code == 401
    assert stale_sc.error_code == "generic_err_invalid_session_id"

    # Same-admin WEB_API session takeover without disconnect keeps prior SID valid on a rotated session
    web_sid, _ = await api.create_dedicated_session("mds", "Branch", session_name="staged-web")
    web_uid = str((await api.api_call("mds", "show-session", {}, domain="Branch", sid=web_sid)).data["uid"])
    adopter_sid, _ = await api.create_dedicated_session("mds", "Branch")
    non_disruptive = await api.api_call(
        "mds",
        "take-over-session",
        {"uid": web_uid},
        domain="Branch",
        sid=adopter_sid,
    )
    assert non_disruptive.success
    prior_after = await api.api_call("mds", "show-session", {}, domain="Branch", sid=web_sid)
    assert prior_after.success
    assert prior_after.data["uid"] != web_uid

    # Failed login in create_dedicated_session raises SessionError instead of returning empty SID
    with pytest.raises(SessionError):
        await api.create_dedicated_session("mds", "NoSuchDomain")


@pytest.mark.spec("SCN-ITEST-019-1")
@pytest.mark.asyncio
async def test_wave8_emulator_track_wire_types_rollback_readonly_and_lazy_baseline() -> None:
    """Verify Wave 8 emulator fixes: per-rulebase track wire types, failed set-host rollback, read_only switch/discard, and lazy in-memory baseline."""
    from arodonata.testing._emulator_rulebase_fields import LOG_TRACK_UID, normalize_track

    # 1. Per-rulebase track wire types
    assert normalize_track("Log", rule_kind="access") == {"type": LOG_TRACK_UID}
    assert normalize_track("Log", rule_kind="https") == "Log"
    https_err = normalize_track({"type": "Log"}, rule_kind="https")
    assert hasattr(https_err, "success") and not https_err.success  # type: ignore[union-attr]
    threat_err = normalize_track({"type": "Log"}, rule_kind="threat")
    assert hasattr(threat_err, "success") and not threat_err.success  # type: ignore[union-attr]

    api = FileReplayApiMock()

    # 2. Failed set-group with new-name + invalid member rolls back name without partial rename
    sid_w, _ = await api.create_dedicated_session("mds", "Branch", session_name="rollback-test")
    added = await api.api_call(
        "mds",
        "add-group",
        {"name": "G_Orig_RB"},
        domain="Branch",
        sid=sid_w,
    )
    assert added.success
    bad_set = await api.api_call(
        "mds",
        "set-group",
        {"name": "G_Orig_RB", "new-name": "G_Renamed_Should_Rollback", "members": {"add": ["nonexistent-uid-999"]}},
        domain="Branch",
        sid=sid_w,
    )
    assert not bad_set.success
    still_orig = await api.api_call("mds", "show-group", {"name": "G_Orig_RB"}, domain="Branch", sid=sid_w)
    assert still_orig.success
    assert not (
        await api.api_call("mds", "show-group", {"name": "G_Renamed_Should_Rollback"}, domain="Branch", sid=sid_w)
    ).success

    # 3. read_only session cannot switch-session or discard
    ro_login = await api.api_call("mds", "login", {"domain": "Branch", "read-only": True}, domain="Branch")
    assert ro_login.success
    sid_ro = str(ro_login.data["sid"])
    w_uid = str((await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_w)).data["uid"])

    sw_err = await api.api_call("mds", "switch-session", {"uid": w_uid}, domain="Branch", sid=sid_ro)
    assert not sw_err.success
    assert sw_err.status_code == 400

    disc_err = await api.api_call("mds", "discard", {"uid": w_uid}, domain="Branch", sid=sid_ro)
    assert not disc_err.success
    assert disc_err.status_code == 400

    # 4. Lazy in-memory _initial_domain_data snapshot before first mutation (without disk reload)
    assert "Branch" not in api._initial_domain_data
    pub = await api.api_call("mds", "publish", {}, domain="Branch", sid=sid_w)
    assert pub.success
    assert "Branch" in api._initial_domain_data
    # Initial baseline must NOT contain G_Orig_RB (captured before publish mutated _domain_data["Branch"])
    baseline_names = {
        o.get("name")
        for o in api._initial_domain_data["Branch"].get("show-groups", {}).get("objects", [])
        if isinstance(o, dict)
    }
    assert "G_Orig_RB" not in baseline_names


@pytest.mark.spec("SCN-ITEST-021-2")
@pytest.mark.asyncio
async def test_switch_session_rotation_readonly_disconnect_guard_and_zero_disk_direct_baselines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-ITEST-021-2 (DA-035, DA-045): Switch-session rotates aliased SIDs, read-only disconnect fails, zero-disk reset."""
    api = FileReplayApiMock()

    # 1. handle_switch_session rotates other active SIDs already bound to target_ws
    sid_a, _ = await api.create_dedicated_session("mds", "Branch", session_name="shared-ws")
    sid_b, _ = await api.create_dedicated_session("mds", "Branch", session_name="other-ws")
    ws_target_uid = str((await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_a)).data["uid"])

    # Alias sid_b onto sid_a's work session via switch-session -> sid_a must rotate onto a fresh open session
    sw = await api.api_call("mds", "switch-session", {"uid": ws_target_uid}, domain="Branch", sid=sid_b)
    assert sw.success
    sess_a_after = await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_a)
    assert sess_a_after.success
    assert str(sess_a_after.data["uid"]) != ws_target_uid
    assert (await api.api_call("mds", "show-session", {}, domain="Branch", sid=sid_b)).data["uid"] == ws_target_uid

    # 2. Read-only session cannot disconnect another active session
    ro_login = await api.api_call("mds", "login", {"domain": "Branch", "read-only": True}, domain="Branch")
    assert ro_login.success
    sid_ro = str(ro_login.data["sid"])
    disc_res = await api.api_call("mds", "disconnect", {"uid": ws_target_uid}, domain="Branch", sid=sid_ro)
    assert not disc_res.success
    assert disc_res.status_code == 400
    assert disc_res.error_code == "err_validation_failed"

    # 3. Direct domain mutations (assign-global-assignment, update_gateway_interfaces, bump_published_session)
    #    capture clean baselines in memory so subsequent reset()/restore_state() performs zero disk reads
    api2 = FileReplayApiMock()
    disk_loads: list[str] = []
    orig_load = api2._load_domain_files

    def _spy_load(dom_name: str) -> dict[str, Any]:
        disk_loads.append(dom_name)
        return orig_load(dom_name)

    monkeypatch.setattr(api2, "_load_domain_files", _spy_load)

    sys_sid, _ = await api2.create_dedicated_session("mds", "System Data")
    ga_res = await api2.api_call(
        "mds",
        "assign-global-assignment",
        {"dependent-domain": "Branch", "global-domains": ["Global"]},
        domain="System Data",
        sid=sys_sid,
        wait_for_task=True,
    )
    assert ga_res.success
    api2.update_gateway_interfaces("DC_Spine", "dc-gw-spine-01", [])
    api2.bump_published_session("DC_Spine", new_session_uid="bumped-head-1")
    api2.reset()
    assert disk_loads == []


@pytest.mark.spec("SCN-ITEST-022-2")
@pytest.mark.asyncio
async def test_scn_itest_022_2_http_400_on_malformed_cmd_and_verify_install_policy_guards() -> None:
    """SCN-ITEST-022-2: JSON 400 on malformed command names, verify-policy mutating contract, and session/domain guards."""
    import aiohttp

    from arodonata.core.primitives import READONLY_EXACT_COMMANDS, is_readonly_command
    from arodonata.testing._emulator_models import is_mutating_command
    from arodonata.testing.mock_server import CheckPointReplayHttpServer

    # 1. Core primitives & emulator mutating classification parity (DA-045)
    assert "verify-policy" not in READONLY_EXACT_COMMANDS
    assert is_readonly_command("verify-policy") is False
    assert is_mutating_command("install-policy") is True

    # 2. HTTP server returns JSON HTTP 400 (err_validation_failed) on malformed commands
    server = CheckPointReplayHttpServer(host="127.0.0.1", port=0)
    await server.start()
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as http_sess:
            login_resp = await http_sess.post(
                f"{server.base_url}/login",
                json={"api-key": "test-key", "domain": "Branch"},
            )
            assert login_resp.status == 200
            sid = (await login_resp.json())["sid"]

            bad_resp = await http_sess.post(
                f"{server.base_url}/INVALID_CMD!",
                headers={"X-chkp-sid": sid},
                json={},
            )
            assert bad_resp.status == 400
            bad_body = await bad_resp.json()
            assert bad_body["code"] == "err_validation_failed"
    finally:
        await server.stop()

    # 3. verify-policy / install-policy enforce read-only, cross-domain, clean-session, and open-session guards
    api = FileReplayApiMock()
    ro_login = await api.api_call("mds", "login", {"api-key": "test-key", "domain": "Branch", "read-only": True})
    assert ro_login.success
    ro_sid = ro_login.data["sid"]
    rw_sid, _ = await api.create_dedicated_session("mds", "Branch")
    other_sid, _ = await api.create_dedicated_session("mds", "Regional")

    pkg_res = await api.api_call("mds", "show-packages", {}, domain="Branch", sid=rw_sid)
    pkg_name = pkg_res.data["objects"][0]["name"]

    for cmd, extra in (("verify-policy", {}), ("install-policy", {"targets": ["all"]})):
        ro_res = await api.api_call("mds", cmd, {"policy-package": pkg_name, **extra}, domain="Branch", sid=ro_sid)
        assert not ro_res.success and ro_res.status_code in (400, 403)

        cross_res = await api.api_call(
            "mds", cmd, {"policy-package": pkg_name, **extra}, domain="Branch", sid=other_sid
        )
        assert not cross_res.success and cross_res.status_code == 400

    # Dirty session (uncommitted host add) MUST be blocked until discard/publish
    add_res = await api.api_call(
        "mds", "add-host", {"name": "H_Dirty_Guard", "ipv4-address": "10.98.0.1"}, domain="Branch", sid=rw_sid
    )
    assert add_res.success
    dirty_vp = await api.api_call("mds", "verify-policy", {"policy-package": pkg_name}, domain="Branch", sid=rw_sid)
    assert not dirty_vp.success and dirty_vp.status_code == 400

    await api.api_call("mds", "discard", {}, domain="Branch", sid=rw_sid)
    clean_vp = await api.api_call("mds", "verify-policy", {"policy-package": pkg_name}, domain="Branch", sid=rw_sid)
    assert clean_vp.success

    # Disconnected session must also be blocked
    await api.api_call("mds", "disconnect", {}, domain="Branch", sid=rw_sid)
    disc_ip = await api.api_call(
        "mds", "install-policy", {"policy-package": pkg_name, "targets": ["all"]}, domain="Branch", sid=rw_sid
    )
    assert not disc_ip.success and disc_ip.status_code == 401
