"""Unit tests for 12-type stateful CRUD, referential integrity, rulebases, and MDSM Global security."""

from __future__ import annotations

import pytest

from arodonata.rulebase.pager import fetch_paged_rulebase
from arodonata.testing._emulator_models import ANY_UID, ORIGINAL_UID
from arodonata.testing.replay_mock import FileReplayApiMock


@pytest.mark.asyncio
async def test_all_12_entity_types_crud_groups_rename_and_unused_cleanup() -> None:
    """Exercise add/show/set/delete across all 12 ENTITY_SPECS types, groups sync, renames, and unused pruning."""
    api = FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")

    type_payloads: list[tuple[str, dict[str, object], dict[str, object], tuple[str, object]]] = [
        (
            "host",
            {"name": "Crud_Host_01", "ipv4-address": "10.210.1.10"},
            {"ipv4-address": "10.210.1.11", "comments": "updated host"},
            ("ipv4-address", "10.210.1.11"),
        ),
        (
            "network",
            {"name": "Crud_Net_01", "subnet4": "10.210.2.0", "mask-length4": 24},
            {"subnet-mask": "255.255.254.0"},
            ("mask-length4", 23),
        ),
        (
            "address-range",
            {"name": "Crud_Range_01", "ipv4-address-first": "10.210.3.10", "ipv4-address-last": "10.210.3.20"},
            {"ipv4-address-last": "10.210.3.30"},
            ("ipv4-address-last", "10.210.3.30"),
        ),
        (
            "dns-domain",
            {"name": ".crud.example.internal", "is-sub-domain": True},
            {"comments": "internal dns"},
            ("comments", "internal dns"),
        ),
        (
            "application-site",
            {"name": "Crud_App_01", "url-list": ["app.example.internal"]},
            {"primary-category": "Custom_Apps", "comments": "updated app"},
            ("primary-category", "Custom_Apps"),
        ),
        (
            "group",
            {"name": "Crud_Grp_01", "members": []},
            {"comments": "updated group"},
            ("comments", "updated group"),
        ),
        (
            "service-tcp",
            {"name": "Crud_TCP_8443", "port": "8443"},
            {"port": "8444"},
            ("port", "8444"),
        ),
        (
            "service-udp",
            {"name": "Crud_UDP_5514", "port": "5514"},
            {"port": "5515"},
            ("port", "5515"),
        ),
        (
            "service-icmp",
            {"name": "Crud_ICMP_8", "icmp-type": 8},
            {"icmp-type": 13},
            ("icmp-type", 13),
        ),
        (
            "service-icmp6",
            {"name": "Crud_ICMP6_128", "icmp-type": 128},
            {"icmp-type": 129},
            ("icmp-type", 129),
        ),
        (
            "service-other",
            {"name": "Crud_Proto_47", "ip-protocol": 47},
            {"ip-protocol": 50},
            ("ip-protocol", 50),
        ),
        (
            "service-group",
            {"name": "Crud_SvcGrp_01", "members": []},
            {"comments": "updated svc group"},
            ("comments", "updated svc group"),
        ),
    ]

    created: list[tuple[str, str, str]] = []
    for obj_type, add_pl, set_pl, (check_k, check_v) in type_payloads:
        added = await api.api_call("mds", f"add-{obj_type}", dict(add_pl), domain="Branch", sid=sid)
        assert added.success, f"add-{obj_type} failed: {added.error_message}"
        uid = str(added.data["uid"])

        shown = await api.api_call("mds", f"show-{obj_type}", {"uid": uid}, domain="Branch", sid=sid)
        assert shown.success
        assert shown.data["type"] == obj_type

        edited = await api.api_call("mds", f"set-{obj_type}", {"uid": uid, **set_pl}, domain="Branch", sid=sid)
        assert edited.success
        assert edited.data[check_k] == check_v

        created.append((obj_type, uid, str(edited.data["name"])))

    # Network mask-length4 -> subnet-mask sync check
    net_check = await api.api_call("mds", "show-network", {"name": "Crud_Net_01"}, domain="Branch", sid=sid)
    assert net_check.success
    assert net_check.data["subnet-mask"] == "255.255.254.0"

    # set-if-exists updates existing object in place instead of failing duplicate
    dup_err = await api.api_call(
        "mds",
        "add-host",
        {"name": "Crud_Host_01", "ipv4-address": "10.210.1.99"},
        domain="Branch",
        sid=sid,
    )
    assert not dup_err.success

    upserted = await api.api_call(
        "mds",
        "add-host",
        {"name": "Crud_Host_01", "ipv4-address": "10.210.1.12", "set-if-exists": True},
        domain="Branch",
        sid=sid,
    )
    assert upserted.success
    assert upserted.data["ipv4-address"] == "10.210.1.12"

    # Group + host reverse `groups` sync & new-name rename propagation into group and objects-dictionary
    host_uid = created[0][1]
    grp_uid = next(u for t, u, _ in created if t == "group")
    svc_uid = next(u for t, u, _ in created if t == "service-tcp")
    svcgrp_uid = next(u for t, u, _ in created if t == "service-group")

    assert (
        await api.api_call(
            "mds",
            "set-group",
            {"uid": grp_uid, "members": {"add": [host_uid]}},
            domain="Branch",
            sid=sid,
        )
    ).success
    host_with_grp = await api.api_call("mds", "show-host", {"uid": host_uid}, domain="Branch", sid=sid)
    assert host_with_grp.success
    assert any(g.get("uid") == grp_uid for g in host_with_grp.data.get("groups", []))

    assert (
        await api.api_call(
            "mds",
            "set-service-group",
            {"uid": svcgrp_uid, "members": [svc_uid]},
            domain="Branch",
            sid=sid,
        )
    ).success

    # Reference group in rulebase then rename host to verify objects-dictionary + group member rename propagation
    rule_res = await api.api_call(
        "mds",
        "add-access-rule",
        {
            "layer": "Branch_Standard_Pkg Network",
            "position": "top",
            "name": "Rule Referencing Host",
            "source": [host_uid],
            "destination": ["Any"],
            "service": [svcgrp_uid],
            "action": "Accept",
        },
        domain="Branch",
        sid=sid,
    )
    assert rule_res.success
    rule_uid = str(rule_res.data["uid"])

    renamed = await api.api_call(
        "mds",
        "set-host",
        {"uid": host_uid, "new-name": "Crud_Host_Renamed"},
        domain="Branch",
        sid=sid,
    )
    assert renamed.success
    assert renamed.data["name"] == "Crud_Host_Renamed"

    grp_after_rename = await api.api_call("mds", "show-group", {"uid": grp_uid}, domain="Branch", sid=sid)
    assert grp_after_rename.success
    assert any(m.get("name") == "Crud_Host_Renamed" for m in grp_after_rename.data["members"])

    rb_after_rename = await api.api_call(
        "mds",
        "show-access-rulebase",
        {"name": "Branch_Standard_Pkg Network", "offset": 0, "limit": 5},
        domain="Branch",
        sid=sid,
    )
    assert rb_after_rename.success
    dict_names = {d["uid"]: d["name"] for d in rb_after_rename.data.get("objects-dictionary", [])}
    assert dict_names.get(host_uid) == "Crud_Host_Renamed"

    # Unused objects includes unreferenced Crud_Range_01 but NOT referenced host_uid/grp_uid
    unused_res = await api.api_query("mds", "show-unused-objects", domain="Branch", sid=sid)
    assert unused_res.success
    unused_uids = {o["uid"] for o in unused_res.objects}
    range_uid = next(u for t, u, _ in created if t == "address-range")
    assert range_uid in unused_uids
    assert host_uid not in unused_uids

    # Delete rule & unlink group before deleting all created objects cleanly
    assert (await api.api_call("mds", "delete-access-rule", {"uid": rule_uid}, domain="Branch", sid=sid)).success
    assert (
        await api.api_call(
            "mds",
            "set-group",
            {"uid": grp_uid, "members": {"remove": [host_uid]}},
            domain="Branch",
            sid=sid,
        )
    ).success
    assert (
        await api.api_call("mds", "set-service-group", {"uid": svcgrp_uid, "members": []}, domain="Branch", sid=sid)
    ).success

    # delete-unused-objects removes unused objects (leaving none of our unused created ones), then delete remaining if any
    del_unused = await api.api_call("mds", "delete-unused-objects", {}, domain="Branch", sid=sid)
    assert del_unused.success
    assert del_unused.data["deleted-count"] >= len(created)

    for obj_type, uid, _ in created:
        chk = await api.api_call("mds", f"show-{obj_type}", {"uid": uid}, domain="Branch", sid=sid)
        assert not chk.success
        assert chk.status_code == 404


@pytest.mark.asyncio
async def test_referential_integrity_blocks_delete_until_unlinked() -> None:
    """Deleting objects referenced in groups, Access rules, NAT rules, or cross-domain rules fails until unlinked."""
    api = FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")

    h_res = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Ref_Target", "ipv4-address": "10.211.1.10"},
        domain="Branch",
        sid=sid,
    )
    assert h_res.success
    h_uid = str(h_res.data["uid"])

    g_res = await api.api_call(
        "mds", "add-group", {"name": "G_Ref_Holder", "members": [h_uid]}, domain="Branch", sid=sid
    )
    assert g_res.success
    g_uid = str(g_res.data["uid"])

    a_res = await api.api_call(
        "mds",
        "add-access-rule",
        {
            "layer": "Branch_Standard_Pkg Network",
            "position": "bottom",
            "name": "Ref Access Rule",
            "source": [h_uid],
            "destination": ["Any"],
            "service": ["Any"],
            "action": "Drop",
        },
        domain="Branch",
        sid=sid,
    )
    assert a_res.success
    a_uid = str(a_res.data["uid"])

    n_res = await api.api_call(
        "mds",
        "add-nat-rule",
        {
            "package": "Branch_Standard_Pkg",
            "position": "bottom",
            "method": "static",
            "original-source": h_uid,
            "translated-source": "203.0.113.55" if False else "Original",
            "comments": "Ref NAT rule",
        },
        domain="Branch",
        sid=sid,
    )
    assert n_res.success
    n_uid = str(n_res.data["uid"])

    # Blocked while referenced in all 3 places
    blocked = await api.api_call("mds", "delete-host", {"uid": h_uid}, domain="Branch", sid=sid)
    assert not blocked.success
    assert blocked.status_code == 400
    assert blocked.error_code == "generic_err_object_cannot_be_deleted"
    assert blocked.data.get("blocking-errors")

    # Remove group ref -> still blocked by Access + NAT rules
    assert (
        await api.api_call("mds", "set-group", {"uid": g_uid, "members": {"remove": [h_uid]}}, domain="Branch", sid=sid)
    ).success
    still_blocked_1 = await api.api_call("mds", "delete-host", {"uid": h_uid}, domain="Branch", sid=sid)
    assert not still_blocked_1.success
    assert still_blocked_1.error_code == "generic_err_object_cannot_be_deleted"

    # Remove Access rule ref -> still blocked by NAT rule
    assert (await api.api_call("mds", "delete-access-rule", {"uid": a_uid}, domain="Branch", sid=sid)).success
    still_blocked_2 = await api.api_call("mds", "delete-host", {"uid": h_uid}, domain="Branch", sid=sid)
    assert not still_blocked_2.success
    assert still_blocked_2.error_code == "generic_err_object_cannot_be_deleted"

    # Remove NAT rule -> delete succeeds cleanly
    assert (
        await api.api_call(
            "mds", "delete-nat-rule", {"package": "Branch_Standard_Pkg", "uid": n_uid}, domain="Branch", sid=sid
        )
    ).success
    deleted = await api.api_call("mds", "delete-host", {"uid": h_uid}, domain="Branch", sid=sid)
    assert deleted.success

    # Cross-domain Global referential integrity: Global session cannot delete uid-glob-host-001 while local domains reference it
    glob_sid, _ = await api.create_dedicated_session("mds", "Global")
    glob_blocked = await api.api_call("mds", "delete-host", {"uid": "uid-glob-host-001"}, domain="Global", sid=glob_sid)
    assert not glob_blocked.success
    assert glob_blocked.status_code == 400
    assert glob_blocked.error_code == "generic_err_object_cannot_be_deleted"


@pytest.mark.asyncio
async def test_access_and_nat_rule_section_positioning_cells_and_read_consistency() -> None:
    """Verify rule/section CRUD, positioning, cell Any/Original rules, empty-section paging, and live read views."""
    api = FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")

    h1 = (
        await api.api_call(
            "mds", "add-host", {"name": "H_Pos_1", "ipv4-address": "10.212.1.1"}, domain="Branch", sid=sid
        )
    ).data["uid"]
    h2 = (
        await api.api_call(
            "mds", "add-host", {"name": "H_Pos_2", "ipv4-address": "10.212.1.2"}, domain="Branch", sid=sid
        )
    ).data["uid"]

    # Add two sections (one left intentionally empty at the bottom to test pager recovery)
    sec_work = (
        await api.api_call(
            "mds",
            "add-access-section",
            {"layer": "Branch_Standard_Pkg Network", "name": "Work Section", "position": "bottom"},
            domain="Branch",
            sid=sid,
        )
    ).data["uid"]
    sec_empty = (
        await api.api_call(
            "mds",
            "add-access-section",
            {"layer": "Branch_Standard_Pkg Network", "name": "Trailing Empty Section", "position": "bottom"},
            domain="Branch",
            sid=sid,
        )
    ).data["uid"]

    # Test top, bottom, section top/bottom, above, below, and numeric new-position
    r_top = (
        await api.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": "Branch_Standard_Pkg Network",
                "position": "top",
                "name": "R_Top",
                "source": ["Any"],
                "destination": [h1],
                "service": ["Any"],
                "action": "Accept",
            },
            domain="Branch",
            sid=sid,
        )
    ).data
    assert r_top["rule-number"] == 1

    # Adding h1 to source strips Any; removing h1 reverts source back to [ANY_UID]
    r_top_mod = await api.api_call(
        "mds",
        "set-access-rule",
        {"uid": r_top["uid"], "source": {"add": [h1]}},
        domain="Branch",
        sid=sid,
    )
    assert r_top_mod.success
    assert [s["uid"] if isinstance(s, dict) else s for s in r_top_mod.data["source"]] == [h1]

    r_top_reverted = await api.api_call(
        "mds",
        "set-access-rule",
        {"uid": r_top["uid"], "source": {"remove": [h1]}, "enabled": False, "comments": "emptied-cell"},
        domain="Branch",
        sid=sid,
    )
    assert r_top_reverted.success
    assert [s["uid"] if isinstance(s, dict) else s for s in r_top_reverted.data["source"]] == [ANY_UID]
    assert r_top_reverted.data["enabled"] is False

    r_sec_1 = (
        await api.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": "Branch_Standard_Pkg Network",
                "position": {"bottom": "Work Section"},
                "name": "R_Sec_First",
                "source": [h1],
                "destination": [h2],
                "service": ["Any"],
                "action": "Accept",
            },
            domain="Branch",
            sid=sid,
        )
    ).data
    r_sec_0 = (
        await api.api_call(
            "mds",
            "add-access-rule",
            {
                "layer": "Branch_Standard_Pkg Network",
                "position": {"above": r_sec_1["uid"]},
                "name": "R_Sec_Above",
                "source": [h2],
                "destination": ["Any"],
                "service": ["Any"],
                "action": "Drop",
            },
            domain="Branch",
            sid=sid,
        )
    ).data
    assert (
        r_sec_0["rule-number"]
        < (await api.api_call("mds", "show-access-rule", {"uid": r_sec_1["uid"]}, domain="Branch", sid=sid)).data[
            "rule-number"
        ]
    )

    # Move R_Sec_First above R_Sec_Above with {"above": ...}, then move it to rule-number 2 with new-position=2
    assert (
        await api.api_call(
            "mds",
            "set-access-rule",
            {"uid": r_sec_1["uid"], "new-position": {"below": r_sec_0["uid"]}},
            domain="Branch",
            sid=sid,
        )
    ).success
    moved_num = await api.api_call(
        "mds",
        "set-access-rule",
        {"uid": r_sec_1["uid"], "new-position": 2},
        domain="Branch",
        sid=sid,
    )
    assert moved_num.success
    assert moved_num.data["rule-number"] == 2

    # NAT rule & section CRUD + Original/Any sentinel normalization
    nat_sec = (
        await api.api_call(
            "mds",
            "add-nat-section",
            {"package": "Branch_Standard_Pkg", "name": "NAT Custom Section", "position": "bottom"},
            domain="Branch",
            sid=sid,
        )
    ).data["uid"]
    nat_add = await api.api_call(
        "mds",
        "add-nat-rule",
        {
            "package": "Branch_Standard_Pkg",
            "position": {"top": "NAT Custom Section"},
            "method": "static",
            "original-source": h1,
            "translated-source": "Original",
            "original-destination": "Any",
            "translated-destination": "Original",
        },
        domain="Branch",
        sid=sid,
    )
    assert nat_add.success
    nat_uid = str(nat_add.data["uid"])
    assert nat_add.data["original-destination"]["uid"] == ANY_UID
    assert nat_add.data["translated-source"]["uid"] == ORIGINAL_UID

    nat_show = await api.api_call(
        "mds",
        "show-nat-rule",
        {"package": "Branch_Standard_Pkg", "uid": nat_uid},
        domain="Branch",
        sid=sid,
    )
    assert nat_show.success

    nat_set = await api.api_call(
        "mds",
        "set-nat-rule",
        {"package": "Branch_Standard_Pkg", "uid": nat_uid, "translated-destination": h2, "new-position": "top"},
        domain="Branch",
        sid=sid,
    )
    assert nat_set.success
    assert nat_set.data["rule-number"] == 1
    assert nat_set.data["translated-destination"]["uid"] == h2

    # Live read consistency: where-used (direct + indirect), show-objects filter, and use-object-dictionary=False
    wu_h2 = await api.api_call(
        "mds",
        "where-used",
        {"uid": h2, "indirect": True},
        domain="Branch",
        sid=sid,
    )
    assert wu_h2.success
    assert len(wu_h2.data["used-directly"]["access-control-rules"]) >= 1
    assert len(wu_h2.data["used-directly"]["nat-rules"]) >= 1

    so = await api.api_call(
        "mds",
        "show-objects",
        {"filter": "10.212.1", "type": "host", "ip-only": True},
        domain="Branch",
        sid=sid,
    )
    assert so.success
    assert {o["uid"] for o in so.data["objects"]} == {h1, h2}

    so_name = await api.api_call(
        "mds",
        "show-objects",
        {"filter": "H_Pos_", "type": "host", "ip-only": False},
        domain="Branch",
        sid=sid,
    )
    assert so_name.success
    assert {o["uid"] for o in so_name.data["objects"]} == {h1, h2}

    inline_rb = await api.api_call(
        "mds",
        "show-access-rulebase",
        {"name": "Branch_Standard_Pkg Network", "use-object-dictionary": False, "offset": 0, "limit": 5},
        domain="Branch",
        sid=sid,
    )
    assert inline_rb.success
    assert inline_rb.data["objects-dictionary"] == []
    first_node = inline_rb.data["rulebase"][0]
    first_rule = first_node["rulebase"][0] if "rulebase" in first_node else first_node
    assert isinstance(first_rule["destination"][0], dict)
    assert first_rule["destination"][0]["name"] == "H_Pos_1"

    # Pager compatibility with empty trailing section across page boundary (limit=10 covers chunk boundaries)
    paged = await fetch_paged_rulebase(
        api,
        "mds",
        "Branch",
        rulebase_type="access",
        layer_uid="uid-layer-branch-security",
        layer_name="Branch_Standard_Pkg Network",
        limit=10,
        sid=sid,
    )
    assert any(s.uid == sec_empty for s in paged.sections)

    # Cleanup sections deletes cleanly
    assert (
        await api.api_call(
            "mds",
            "delete-access-section",
            {"layer": "Branch_Standard_Pkg Network", "uid": sec_work},
            domain="Branch",
            sid=sid,
        )
    ).success
    assert (
        await api.api_call(
            "mds", "delete-nat-section", {"package": "Branch_Standard_Pkg", "uid": nat_sec}, domain="Branch", sid=sid
        )
    ).success


@pytest.mark.asyncio
async def test_mdsm_global_visibility_shadowing_write_protection_and_global_assignment() -> None:
    """Verify Global visibility + local shadowing, Global write rejection, and async/sync global assignment."""
    api = FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")

    # 1. Local domain reads Global host and resolves domain metadata as Global
    g_host = await api.api_call("mds", "show-host", {"uid": "uid-glob-host-001"}, domain="Branch", sid=sid)
    assert g_host.success
    assert g_host.data["domain"]["name"] == "Global"

    g_obj = await api.api_call("mds", "show-object", {"uid": "uid-glob-grp-branches"}, domain="Branch", sid=sid)
    assert g_obj.success
    assert g_obj.data["object"]["domain"]["name"] == "Global"

    # show-objects includes Global host unless shadowed by same (type, name) local host
    so_before = await api.api_call(
        "mds",
        "show-objects",
        {"filter": "H_Global_DNS_001", "type": "host"},
        domain="Branch",
        sid=sid,
    )
    assert so_before.success
    assert any(o["uid"] == "uid-glob-host-001" for o in so_before.data["objects"])

    shadow_add = await api.api_call(
        "mds",
        "add-host",
        {"name": "H_Global_DNS_001", "ipv4-address": "10.99.99.99", "ignore-warnings": True},
        domain="Branch",
        sid=sid,
    )
    assert shadow_add.success
    so_after = await api.api_call(
        "mds",
        "show-objects",
        {"filter": "H_Global_DNS_001", "type": "host"},
        domain="Branch",
        sid=sid,
    )
    assert so_after.success
    assert [o["domain"]["name"] for o in so_after.data["objects"]] == ["Branch"]

    # Bulk show-hosts remains strictly local-domain scoped (excludes Global objects)
    local_hosts = await api.api_call("mds", "show-hosts", {"limit": 500}, domain="Branch", sid=sid)
    assert local_hosts.success
    assert all(o["uid"] != "uid-glob-host-001" for o in local_hosts.data["objects"])

    # 2. Local domain session cannot mutate or delete any Global object or group or service
    for cmd, pl in (
        ("set-host", {"uid": "uid-glob-host-001", "comments": "illegal edit"}),
        ("delete-host", {"uid": "uid-glob-host-001"}),
        ("set-group", {"uid": "uid-glob-grp-branches", "comments": "illegal edit"}),
        ("delete-group", {"uid": "uid-glob-grp-branches"}),
        ("set-service-udp", {"uid": "uid-global-svc-udp-53", "comments": "illegal edit"}),
        ("delete-service-udp", {"uid": "uid-global-svc-udp-53"}),
    ):
        rej = await api.api_call("mds", cmd, pl, domain="Branch", sid=sid)
        assert not rej.success
        assert rej.status_code == 400
        assert rej.error_code == "generic_err_object_read_only"

    # 3. show-global-assignments, show-global-assignment, assign-global-assignment, assign-global-policy
    ga_all = await api.api_call("mds", "show-global-assignments", {}, domain="System Data")
    assert ga_all.success
    assert ga_all.data["total"] >= 1

    ga_branch = await api.api_call(
        "mds",
        "show-global-assignment",
        {"dependent-domain": "Branch", "global-domain": "Global"},
        domain="System Data",
    )
    assert ga_branch.success
    before_ts = ga_branch.data["assignment-up-to-date"]["posix"]

    # Local session cannot invoke assign-global-policy targeting Global on System Data if domain mismatch,
    # whereas System Data session completes both sync and async global assignment cleanly
    mds_sid, _ = await api.create_dedicated_session("mds", "System Data")
    async_assign = await api.api_call(
        "mds",
        "assign-global-policy",
        {"dependent-domains": ["Branch"], "global-domains": ["Global"]},
        domain="System Data",
        sid=mds_sid,
        wait_for_task=False,
    )
    assert async_assign.success
    assert "task-id" in async_assign.data

    polled = await api.api_call(
        "mds", "show-task", {"task-id": async_assign.data["task-id"]}, domain="System Data", sid=mds_sid
    )
    assert polled.success
    assert polled.data["tasks"][0]["status"] == "succeeded"

    sync_assign = await api.api_call(
        "mds",
        "assign-global-assignment",
        {"dependent-domain": "Branch", "global-domain": "Global"},
        domain="System Data",
        sid=mds_sid,
        wait_for_task=True,
    )
    assert sync_assign.success
    assert sync_assign.data["tasks"][0]["status"] == "succeeded"

    ga_branch_after = await api.api_call(
        "mds",
        "show-global-assignment",
        {"dependent-domain": "Branch", "global-domain": "Global"},
        domain="System Data",
    )
    assert ga_branch_after.success
    assert ga_branch_after.data["assignment-status"] == "assigned"
    assert ga_branch_after.data["assignment-up-to-date"]["posix"] > before_ts


@pytest.mark.asyncio
async def test_invalid_rule_number_validation_and_sequential_global_publish_deltas() -> None:
    """Non-numeric `rule-number` returns 400 cleanly; sequential Global publishes record isolated deltas."""
    api = FileReplayApiMock()
    sid, _ = await api.create_dedicated_session("mds", "Branch")

    for cmd in ("show-access-rule", "set-access-rule", "delete-access-rule"):
        for bad_num in ("not-an-int", True):
            res = await api.api_call(
                "mds",
                cmd,
                {"layer": "Branch_Standard_Pkg Network", "rule-number": bad_num},
                domain="Branch",
                sid=sid,
            )
            assert not res.success
            assert res.status_code == 400
            assert res.error_code == "err_validation_failed"

    # Two sequential Global publishes produce isolated per-session deltas
    g_sid, _ = await api.create_dedicated_session("mds", "Global", session_name="glob-1")
    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Glob_Seq_1", "ipv4-address": "10.254.1.1"},
            domain="Global",
            sid=g_sid,
        )
    ).success
    pub1 = await api.api_call("mds", "publish", {}, domain="Global", sid=g_sid)
    assert pub1.success

    assert (
        await api.api_call(
            "mds",
            "add-host",
            {"name": "H_Glob_Seq_2", "ipv4-address": "10.254.1.2"},
            domain="Global",
            sid=g_sid,
        )
    ).success
    pub2 = await api.api_call("mds", "publish", {}, domain="Global", sid=g_sid)
    assert pub2.success
    pub2_uid = str(pub2.data["uid"])

    chg = await api.api_call(
        "mds",
        "show-changes",
        {"to-session": pub2_uid},
        domain="Global",
        sid=g_sid,
        wait_for_task=True,
    )
    assert chg.success
    added_names = [
        item["name"]
        for task in chg.data["tasks"]
        for detail in task.get("task-details", [])
        for blk in detail.get("changes", [])
        for item in blk.get("added-objects", [])
    ]
    assert "H_Glob_Seq_2" in added_names
    assert "H_Glob_Seq_1" not in added_names
