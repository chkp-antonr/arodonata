"""Unit tests for extended stateful Check Point emulator handlers in `arodonata.testing`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from arodonata.rulebase.pager import parse_access_rule_entry, parse_https_rule_entry, parse_threat_rule_entry
from arodonata.testing.dataset_generator import ensure_enterprise_raw_dataset
from arodonata.testing.replay_mock import FileReplayApiMock


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _build_extended_dataset(tmp_path: Path) -> Path:
    """Create a deterministic enterprise dataset enriched with inline layers, HTTPS/Threat rules, and SMS hosts."""
    dataset_dir = ensure_enterprise_raw_dataset(tmp_path / "dataset")
    branch_dir = dataset_dir / "domains" / "Branch"

    # Append deterministic hosts
    hosts_payload = _read_json(branch_dir / "show-hosts.json")
    hosts_payload["objects"].extend(
        [
            {
                "uid": "host-br-01",
                "name": "srv-branch-01",
                "type": "host",
                "ipv4-address": "10.20.1.10",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
            {
                "uid": "host-br-unused",
                "name": "srv-unused-99",
                "type": "host",
                "ipv4-address": "10.20.1.99",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
        ]
    )
    hosts_payload["total"] = len(hosts_payload["objects"])
    _write_json(branch_dir / "show-hosts.json", hosts_payload)

    # Append deterministic networks for Threat & HTTPS tests
    nets_payload = _read_json(branch_dir / "show-networks.json")
    nets_payload["objects"].extend(
        [
            {
                "uid": "net-br-threat",
                "name": "net-threat-scope",
                "type": "network",
                "subnet4": "10.30.0.0",
                "mask-length4": 16,
                "subnet-mask": "255.255.0.0",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
            {
                "uid": "net-br-https",
                "name": "net-https-dst",
                "type": "network",
                "subnet4": "10.40.0.0",
                "mask-length4": 16,
                "subnet-mask": "255.255.0.0",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
        ]
    )
    nets_payload["total"] = len(nets_payload["objects"])
    _write_json(branch_dir / "show-networks.json", nets_payload)

    # Append gateways and SmartCenter checkpoint-host fixture
    gws_payload = _read_json(branch_dir / "show-gateways-and-servers.json")
    gws_payload["objects"].extend(
        [
            {
                "uid": "gw-br-01",
                "name": "fw-branch-01",
                "type": "simple-gateway",
                "ipv4-address": "10.20.0.1",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
            {
                "uid": "gw-br-02",
                "name": "fw-branch-02",
                "type": "simple-gateway",
                "ipv4-address": "10.20.0.2",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
        ]
    )
    gws_payload["total"] = len(gws_payload["objects"])
    _write_json(branch_dir / "show-gateways-and-servers.json", gws_payload)

    _write_json(
        branch_dir / "show-checkpoint-hosts.json",
        {
            "objects": [
                {
                    "uid": "sms-br-01",
                    "name": "sms-branch",
                    "type": "checkpoint-host",
                    "domain": {"uid": "uid-dom-smc-user", "name": "SMC User", "domain-type": "domain"},
                }
            ]
        },
    )

    pkgs_payload = _read_json(branch_dir / "show-packages.json")
    pkgs_payload["packages"].append(
        {
            "uid": "pkg-br-std",
            "name": "Branch_Standard",
            "nat-policy": True,
            "access-layers": [
                {"uid": "lyr-br-parent", "name": "Branch_Parent_Layer", "position": 1},
            ],
            "https-layers": [
                {"uid": "lyr-br-https", "name": "Branch_HTTPS", "position": 1},
            ],
            "threat-layers": [
                {"uid": "lyr-br-threat", "name": "Branch_Threat", "position": 1},
            ],
        }
    )
    _write_json(branch_dir / "show-packages.json", pkgs_payload)

    lyrs_payload = _read_json(branch_dir / "show-access-layers.json")
    lyrs_payload["access-layers"].extend(
        [
            {
                "uid": "lyr-br-parent",
                "name": "Branch_Parent_Layer",
                "type": "access-layer",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
            {
                "uid": "lyr-br-inline",
                "name": "Inline_App_SubLayer",
                "type": "access-layer",
                "domain": {"uid": "uid-dom-branch", "name": "Branch"},
            },
        ]
    )
    _write_json(branch_dir / "show-access-layers.json", lyrs_payload)

    rb_payload = _read_json(branch_dir / "show-access-rulebase.json")
    rb_payload["Branch_Parent_Layer"] = {
        "uid": "lyr-br-parent",
        "name": "Branch_Parent_Layer",
        "total": 1,
        "from": 1,
        "to": 1,
        "rulebase": [
            {
                "uid": "rule-br-inline-1",
                "name": "Delegate_To_Inline",
                "type": "access-rule",
                "rule-number": 1,
                "enabled": True,
                "source": ["host-br-01"],
                "destination": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                "service": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                "action": "6c488338-8eec-4103-ad21-cd461ac2c475",
                "inline-layer": "lyr-br-inline",
                "track": {"type": "598ead32-aa42-4615-90ed-f51a5928d41d"},
                "install-on": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
            }
        ],
        "objects-dictionary": [],
    }
    rb_payload["Inline_App_SubLayer"] = {
        "uid": "lyr-br-inline",
        "name": "Inline_App_SubLayer",
        "total": 1,
        "from": 1,
        "to": 1,
        "rulebase": [
            {
                "uid": "rule-inline-child-1",
                "name": "Allow_Child_App",
                "type": "access-rule",
                "rule-number": 1,
                "enabled": True,
                "source": ["host-br-01"],
                "destination": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                "service": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                "action": "6c488338-8eec-4103-ad21-cd461ac2c472",
                "track": {"type": "598ead32-aa42-4615-90ed-f51a5928d41d"},
                "install-on": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
            }
        ],
        "objects-dictionary": [],
    }
    _write_json(branch_dir / "show-access-rulebase.json", rb_payload)

    _write_json(
        branch_dir / "show-https-layers.json",
        {
            "https-layers": [
                {
                    "uid": "lyr-br-https",
                    "name": "Branch_HTTPS",
                    "type": "https-layer",
                    "domain": {"uid": "uid-dom-branch", "name": "Branch"},
                }
            ]
        },
    )
    _write_json(
        branch_dir / "show-https-rulebase.json",
        {
            "Branch_HTTPS": {
                "uid": "lyr-br-https",
                "name": "Branch_HTTPS",
                "total": 1,
                "from": 1,
                "to": 1,
                "rulebase": [
                    {
                        "uid": "hr-br-1",
                        "name": "Inspect_Branch_Traffic",
                        "type": "https-rule",
                        "rule-number": 1,
                        "enabled": True,
                        "source": ["host-br-01"],
                        "destination": ["net-br-https"],
                        "service": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                        "action": "Inspect",
                        "certificate": "OutboundCA",
                        "track": {"type": "598ead32-aa42-4615-90ed-f51a5928d41d"},
                        "install-on": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                    }
                ],
                "objects-dictionary": [],
            }
        },
    )
    _write_json(
        branch_dir / "show-threat-layers.json",
        {
            "threat-layers": [
                {
                    "uid": "lyr-br-threat",
                    "name": "Branch_Threat",
                    "type": "threat-layer",
                    "domain": {"uid": "uid-dom-branch", "name": "Branch"},
                }
            ]
        },
    )
    _write_json(
        branch_dir / "show-threat-rulebase.json",
        {
            "Branch_Threat": {
                "uid": "lyr-br-threat",
                "name": "Branch_Threat",
                "total": 1,
                "from": 1,
                "to": 1,
                "rulebase": [
                    {
                        "uid": "tr-br-1",
                        "name": "Protect_Branch_Subnets",
                        "type": "threat-rule",
                        "rule-number": 1,
                        "enabled": True,
                        "protected-scope": ["net-br-threat"],
                        "source": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                        "destination": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                        "service": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                        "action": "Optimized",
                        "track": {"type": "598ead32-aa42-4615-90ed-f51a5928d41d"},
                        "install-on": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                    }
                ],
                "objects-dictionary": [],
            }
        },
    )
    return dataset_dir


@pytest.mark.asyncio
async def test_inline_layer_roundtrip_and_crud(tmp_path: Path) -> None:
    """Confirm `inline-layer` is preserved in rulebases, `objects-dictionary`, and add/set/show-access-rule."""
    mock = FileReplayApiMock(dataset_dir=_build_extended_dataset(tmp_path))

    rb_res = await mock.api_call("mds-main", "show-access-rulebase", {"name": "Branch_Parent_Layer"}, domain="Branch")
    assert rb_res.success
    data = rb_res.data
    dict_uids = {entry["uid"]: entry for entry in data["objects-dictionary"]}
    assert "lyr-br-inline" in dict_uids
    assert dict_uids["lyr-br-inline"]["name"] == "Inline_App_SubLayer"
    first_rule = data["rulebase"][0]
    assert first_rule["inline-layer"] == "lyr-br-inline"
    parsed_access = parse_access_rule_entry(
        raw_rule=first_rule,
        mgmt_name="mds-main",
        domain_name="Branch",
        layer_uid="lyr-br-parent",
        layer_name="Branch_Parent_Layer",
        position=1,
        obj_dict=dict_uids,
    )
    assert parsed_access.inline_layer_uid == "lyr-br-inline"
    assert parsed_access.inline_layer_name == "Inline_App_SubLayer"

    rb_inlined = await mock.api_call(
        "mds-main",
        "show-access-rulebase",
        {"name": "Branch_Parent_Layer", "use-object-dictionary": False},
        domain="Branch",
    )
    assert rb_inlined.success
    assert rb_inlined.data["rulebase"][0]["inline-layer"]["uid"] == "lyr-br-inline"
    assert rb_inlined.data["rulebase"][0]["inline-layer"]["name"] == "Inline_App_SubLayer"

    login = await mock.api_call("mds-main", "login", {"user": "admin", "password": "secret"}, domain="Branch")
    sid = login.data["sid"]

    add_res = await mock.api_call(
        "mds-main",
        "add-access-rule",
        {
            "layer": "Branch_Parent_Layer",
            "position": "bottom",
            "name": "Created_Inline_Rule",
            "source": ["srv-branch-01"],
            "action": "Inner Layer",
            "inline-layer": "Inline_App_SubLayer",
        },
        domain="Branch",
        sid=sid,
    )
    assert add_res.success
    created_uid = add_res.data["uid"]
    assert add_res.data["inline-layer"]["uid"] == "lyr-br-inline"

    show_res = await mock.api_call(
        "mds-main",
        "show-access-rule",
        {"layer": "Branch_Parent_Layer", "uid": created_uid},
        domain="Branch",
        sid=sid,
    )
    assert show_res.success
    assert show_res.data["inline-layer"]["name"] == "Inline_App_SubLayer"

    clear_res = await mock.api_call(
        "mds-main",
        "set-access-rule",
        {"layer": "Branch_Parent_Layer", "uid": created_uid, "action": "Accept", "inline-layer": ""},
        domain="Branch",
        sid=sid,
    )
    assert clear_res.success
    assert "inline-layer" not in clear_res.data


@pytest.mark.asyncio
async def test_https_and_threat_layers_rulebases_crud_and_where_used(tmp_path: Path) -> None:
    """Confirm HTTPS and Threat layers, rulebases, show/set rule handlers, unused checks, and where-used."""
    mock = FileReplayApiMock(dataset_dir=_build_extended_dataset(tmp_path))

    https_layers = await mock.api_call("mds-main", "show-https-layers", {}, domain="Branch")
    threat_layers = await mock.api_call("mds-main", "show-threat-layers", {}, domain="Branch")
    assert https_layers.success and https_layers.data["https-layers"][0]["name"] == "Branch_HTTPS"
    assert threat_layers.success and threat_layers.data["threat-layers"][0]["name"] == "Branch_Threat"

    https_rb = await mock.api_call("mds-main", "show-https-rulebase", {"name": "Branch_HTTPS"}, domain="Branch")
    threat_rb = await mock.api_call("mds-main", "show-threat-rulebase", {"name": "Branch_Threat"}, domain="Branch")
    assert https_rb.success and https_rb.data["total"] == 1
    assert https_rb.data["rulebase"][0]["action"] == "Inspect"
    assert threat_rb.success and threat_rb.data["total"] == 1
    threat_dict = {entry["uid"]: entry for entry in threat_rb.data["objects-dictionary"]}
    assert threat_rb.data["rulebase"][0]["protected-scope"] == ["net-br-threat"]
    parsed_https = parse_https_rule_entry(
        raw_rule=https_rb.data["rulebase"][0],
        mgmt_name="mds-main",
        domain_name="Branch",
        layer_uid="lyr-br-https",
        layer_name="Branch_HTTPS",
        position=1,
        obj_dict={entry["uid"]: entry for entry in https_rb.data["objects-dictionary"]},
    )
    assert parsed_https.action == "Inspect"
    assert parsed_https.destination == ["net-https-dst"]
    parsed_threat = parse_threat_rule_entry(
        raw_rule=threat_rb.data["rulebase"][0],
        mgmt_name="mds-main",
        domain_name="Branch",
        layer_uid="lyr-br-threat",
        layer_name="Branch_Threat",
        position=1,
        obj_dict=threat_dict,
    )
    assert parsed_threat.action == "Optimized"
    assert parsed_threat.protected_scope == ["net-threat-scope"]

    # net-br-https and net-br-threat must NOT be reported unused and MUST appear in where-used
    unused = await mock.api_call("mds-main", "show-unused-objects", {"limit": 500}, domain="Branch")
    assert unused.success
    unused_names = {obj["name"] for obj in unused.data["objects"]}
    assert "srv-unused-99" in unused_names
    assert "srv-branch-01" not in unused_names
    assert "net-threat-scope" not in unused_names
    assert "net-https-dst" not in unused_names

    wu_https = await mock.api_call("mds-main", "where-used", {"uid": "net-br-https"}, domain="Branch")
    assert wu_https.success
    assert len(wu_https.data["used-directly"]["https-rules"]) == 1
    assert wu_https.data["used-directly"]["https-rules"][0]["rule"]["uid"] == "hr-br-1"

    wu_threat = await mock.api_call("mds-main", "where-used", {"uid": "net-br-threat"}, domain="Branch")
    assert wu_threat.success
    assert len(wu_threat.data["used-directly"]["threat-prevention-rules"]) == 1
    assert wu_threat.data["used-directly"]["threat-prevention-rules"][0]["rule"]["uid"] == "tr-br-1"

    login = await mock.api_call("mds-main", "login", {"user": "admin", "password": "secret"}, domain="Branch")
    sid = login.data["sid"]

    show_hr = await mock.api_call(
        "mds-main", "show-https-rule", {"layer": "lyr-br-https", "uid": "hr-br-1"}, domain="Branch", sid=sid
    )
    assert show_hr.success and show_hr.data["name"] == "Inspect_Branch_Traffic"

    set_hr = await mock.api_call(
        "mds-main",
        "set-https-rule",
        {"layer": "lyr-br-https", "uid": "hr-br-1", "action": "Bypass", "destination": ["Any"]},
        domain="Branch",
        sid=sid,
    )
    assert set_hr.success and set_hr.data["action"] == "Bypass"
    assert set_hr.data["destination"][0]["name"] == "Any"

    show_tr = await mock.api_call(
        "mds-main", "show-threat-rule", {"layer": "lyr-br-threat", "uid": "tr-br-1"}, domain="Branch", sid=sid
    )
    assert show_tr.success and show_tr.data["name"] == "Protect_Branch_Subnets"

    set_tr = await mock.api_call(
        "mds-main",
        "set-threat-rule",
        {"layer": "lyr-br-threat", "uid": "tr-br-1", "protected-scope": ["Any"]},
        domain="Branch",
        sid=sid,
    )
    assert set_tr.success
    assert set_tr.data["protected-scope"][0]["name"] == "Any"

    pub = await mock.api_call("mds-main", "publish", {}, domain="Branch", sid=sid)
    assert pub.success

    # After emptying references and publishing, net-br-https and net-br-threat become unused
    unused_after = await mock.api_call("mds-main", "show-unused-objects", {"limit": 500}, domain="Branch")
    unused_after_names = {obj["name"] for obj in unused_after.data["objects"]}
    assert {"srv-unused-99", "net-threat-scope", "net-https-dst"} <= unused_after_names


@pytest.mark.asyncio
async def test_verify_install_policy_checkpoint_host_and_snapshot_rollback(tmp_path: Path) -> None:
    """Confirm verify-policy, install-policy + show-task, show-checkpoint-host, and full snapshot rollback."""
    mock = FileReplayApiMock(dataset_dir=_build_extended_dataset(tmp_path))

    # show-checkpoint-host resolves SmartCenter host even when called against System Data
    ch_res = await mock.api_call(
        "sms-branch",
        "show-checkpoint-host",
        {"name": "sms-branch", "details-level": "full"},
        domain="System Data",
    )
    assert ch_res.success
    assert ch_res.data["name"] == "sms-branch"
    assert ch_res.data["domain"]["name"] == "SMC User"

    missing_ch = await mock.api_call(
        "mds-main",
        "show-checkpoint-host",
        {"name": "does-not-exist"},
        domain="System Data",
    )
    assert not missing_ch.success and missing_ch.status_code == 404

    snap = mock.snapshot_state()
    baseline_call_count = len(mock.call_log)
    baseline_verify_count = mock.command_counts.get("verify-policy", 0)

    # Async verify-policy -> show-task
    vp_res = await mock.api_call(
        "mds-main",
        "verify-policy",
        {"policy-package": "Branch_Standard"},
        domain="Branch",
        wait_for_task=False,
    )
    assert vp_res.success
    vp_tid = vp_res.data["task-id"]
    vp_task = await mock.api_call(
        "mds-main", "show-task", {"task-id": vp_tid, "details-level": "full"}, domain="Branch"
    )
    assert vp_task.success
    assert vp_task.data["tasks"][0]["status"] == "succeeded"
    assert vp_task.data["tasks"][0]["task-details"][0]["errors"] == []

    # Async install-policy -> show-task with installed-targets & task-details
    ip_res = await mock.api_call(
        "mds-main",
        "install-policy",
        {
            "policy-package": "Branch_Standard",
            "targets": ["fw-branch-01", "fw-branch-02"],
            "access": True,
            "threat-prevention": False,
        },
        domain="Branch",
        wait_for_task=False,
    )
    assert ip_res.success
    ip_tid = ip_res.data["task-id"]
    ip_task = await mock.api_call(
        "mds-main", "show-task", {"task-id": ip_tid, "details-level": "full"}, domain="Branch"
    )
    assert ip_task.success
    t_info = ip_task.data["tasks"][0]
    assert t_info["status"] == "succeeded"
    assert t_info["installed-targets"] == ["fw-branch-01", "fw-branch-02"]
    assert {d["gatewayName"] for d in t_info["task-details"]} == {"fw-branch-01", "fw-branch-02"}

    # Missing package must fail cleanly
    bad_pkg = await mock.api_call(
        "mds-main", "verify-policy", {"policy-package": "Missing_Pkg"}, domain="Branch", wait_for_task=False
    )
    assert not bad_pkg.success and bad_pkg.status_code == 404

    # Restore snapshot and verify tasks + counters + call_log roll back completely
    mock.restore_state(snap)
    assert len(mock.call_log) == baseline_call_count
    assert mock.command_counts.get("verify-policy", 0) == baseline_verify_count
    gone_vp = await mock.api_call("mds-main", "show-task", {"task-id": vp_tid}, domain="Branch")
    gone_ip = await mock.api_call("mds-main", "show-task", {"task-id": ip_tid}, domain="Branch")
    assert not gone_vp.success and gone_vp.status_code == 404
    assert not gone_ip.success and gone_ip.status_code == 404
