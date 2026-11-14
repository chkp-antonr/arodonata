"""Unit tests for Check Point `where-used` and `use-object-dictionary=False` in `FileReplayApiMock`."""

from __future__ import annotations

import pytest

from arodonata.testing.replay_mock import FileReplayApiMock


@pytest.mark.asyncio
async def test_file_replay_mock_where_used_direct_and_indirect() -> None:
    """`where-used` returns direct access/NAT rule refs and resolves upward indirect group memberships."""
    mock = FileReplayApiMock()

    # 1. Host directly referenced by access rule and NAT rule in Perimeter
    direct_res = await mock.api_call(
        "mds1",
        "where-used",
        {"uid": "uid-perimeter-bulk-host-001", "indirect": True, "indirect-max-depth": 3},
        domain="Perimeter",
    )
    assert direct_res.success is True
    used_direct = direct_res.data["used-directly"]
    assert used_direct["access-control-rules"]
    assert used_direct["nat-rules"]
    first_acc = used_direct["access-control-rules"][0]
    assert first_acc["rule"]["uid"] == "uid-arule-perimeter-0001"
    assert first_acc["package"]["name"] == "Perimeter_Edge_Pkg"
    assert first_acc["layer"]["uid"] == "uid-layer-perimeter-security"
    assert "source" in first_acc["rule-columns"]
    first_nat = used_direct["nat-rules"][0]
    assert first_nat["rule"]["uid"] == "uid-nrule-perimeter-001"
    assert first_nat["package"]["name"] == "Perimeter_Edge_Pkg"

    # 2. Multi-level indirect group membership + rule resolution
    perim_files = mock._domain_data["Perimeter"]
    perim_files["show-groups"]["objects"].append(
        {
            "uid": "uid-perim-parent-grp-2",
            "name": "G_Perimeter_Parent_L2",
            "type": "group",
            "members": ["uid-perimeter-bulk-grp-001"],
        }
    )
    perim_files["show-access-rulebase"]["uid-layer-perimeter-security"]["rulebase"][0]["rulebase"].append(
        {
            "uid": "uid-arule-perimeter-indirect-test",
            "name": "Perimeter_Indirect_Group_Rule",
            "type": "access-rule",
            "rule-number": 999,
            "enabled": True,
            "source": ["uid-perim-parent-grp-2"],
            "destination": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
            "service": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
        }
    )

    ind_res = await mock.api_call(
        "mds1",
        "where-used",
        {"uid": "uid-perimeter-bulk-host-071", "indirect": True, "indirect-max-depth": 2},
        domain="Perimeter",
    )
    assert ind_res.success is True
    direct_grp_uids = {g["uid"] for g in ind_res.data["used-directly"]["objects"]}
    indirect_grp_uids = {g["uid"] for g in ind_res.data["used-indirectly"]["objects"]}
    indirect_rule_uids = {r["rule"]["uid"] for r in ind_res.data["used-indirectly"]["access-control-rules"]}
    assert "uid-perimeter-bulk-grp-001" in direct_grp_uids
    assert "uid-perim-parent-grp-2" in indirect_grp_uids
    assert "uid-arule-perimeter-indirect-test" in indirect_rule_uids

    # 3. Missing object returns 404
    missing_res = await mock.api_call(
        "mds1",
        "where-used",
        {"uid": "uid-does-not-exist", "indirect": True},
        domain="Perimeter",
    )
    assert missing_res.success is False
    assert missing_res.status_code == 404


@pytest.mark.asyncio
async def test_file_replay_mock_rulebase_inlines_objects_when_use_object_dictionary_false() -> None:
    """`show-access-rulebase` and `show-nat-rulebase` inline object dicts when `use-object-dictionary=False`."""
    mock = FileReplayApiMock()

    # Lookup access layer by name with use-object-dictionary=False and pagination past 100
    acc_res = await mock.api_call(
        "mds1",
        "show-access-rulebase",
        {
            "name": "Perimeter_Edge_Pkg Network",
            "details-level": "full",
            "use-object-dictionary": False,
            "limit": 500,
        },
        domain="Perimeter",
    )
    assert acc_res.success is True
    assert acc_res.data["total"] == 105
    assert acc_res.data["to"] == 105
    assert acc_res.data["objects-dictionary"] == []
    first_rule = acc_res.data["rulebase"][0]["rulebase"][0]
    assert isinstance(first_rule["source"][0], dict)
    assert first_rule["source"][0]["uid"] == "uid-perimeter-bulk-host-001"
    assert first_rule["source"][0]["name"]
    assert isinstance(first_rule["destination"][0], dict)
    assert isinstance(first_rule["service"][0], dict)
    assert isinstance(first_rule["action"], dict)
    assert isinstance(first_rule["track"]["type"], dict)
    assert first_rule["track"]["name"] == "Log"

    # Lookup NAT rulebase by package name with use-object-dictionary=False
    nat_res = await mock.api_call(
        "mds1",
        "show-nat-rulebase",
        {"package": "Perimeter_Edge_Pkg", "use-object-dictionary": False, "limit": 50},
        domain="Perimeter",
    )
    assert nat_res.success is True
    assert nat_res.data["total"] == 12
    assert nat_res.data["objects-dictionary"] == []
    first_nat = nat_res.data["rulebase"][0]["rulebase"][0]
    assert isinstance(first_nat["original-source"], dict)
    assert first_nat["original-source"]["uid"] == "uid-perimeter-bulk-host-001"
    assert isinstance(first_nat["translated-source"], dict)
