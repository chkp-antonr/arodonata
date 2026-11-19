"""End-to-end replay tests for incremental CPCRUD diffs, naming profiles, `show-changes`, and `inverse()`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.cpcrud import expand_group_expression, parse_object_expression
from arodonata.reports import SessionScope, collect_change_report
from arodonata.testing import FileReplayApiMock, ensure_enterprise_raw_dataset


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _build_incremental_replay_dataset(tmp_path: Path) -> tuple[Path, str]:
    dataset_dir = ensure_enterprise_raw_dataset(tmp_path / "dataset")
    branch_dir = dataset_dir / "domains" / "Branch"

    # Seed initial host, gateway, and application-site
    hosts = _read_json(branch_dir / "show-hosts.json")
    hosts["objects"].append(
        {
            "uid": "h-old-5",
            "name": "Host_10.0.0.5",
            "type": "host",
            "ipv4-address": "10.0.0.5",
            "domain": {"uid": "uid-dom-branch", "name": "Branch"},
        }
    )
    hosts["total"] = len(hosts["objects"])
    _write_json(branch_dir / "show-hosts.json", hosts)

    gws = _read_json(branch_dir / "show-gateways-and-servers.json")
    gws["objects"].append(
        {
            "uid": "gw-br-01",
            "name": "fw-branch-01",
            "type": "simple-gateway",
            "ipv4-address": "10.20.0.1",
            "domain": {"uid": "uid-dom-branch", "name": "Branch"},
        }
    )
    gws["total"] = len(gws["objects"])
    _write_json(branch_dir / "show-gateways-and-servers.json", gws)

    _write_json(
        branch_dir / "show-application-sites.json",
        {
            "objects": [
                {
                    "uid": "site-cc-1",
                    "name": "Site__chinacloudapi.cn",
                    "type": "application-site",
                    "primary-category": "Custom_Application_Site",
                    "url-list": [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"],
                    "urls-defined-as-regular-expression": True,
                    "domain": {"uid": "uid-dom-branch", "name": "Branch"},
                }
            ],
            "from": 1,
            "to": 1,
            "total": 1,
        },
    )

    # Seed Access rule
    acc_rb = _read_json(branch_dir / "show-access-rulebase.json")
    layer_name = next(iter(acc_rb.keys()))
    acc_rb[layer_name]["rulebase"].insert(
        0,
        {
            "uid": "ar-incr-1",
            "name": "Allow App",
            "type": "access-rule",
            "rule-number": 1,
            "enabled": True,
            "source": ["h-old-5"],
            "destination": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
            "service": ["site-cc-1"],
            "action": "6c488338-8eec-4103-ad21-cd461ac2c472",
            "track": {"type": "598ead32-aa42-4615-90ed-f51a5928d41d"},
            "install-on": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
        },
    )
    _write_json(branch_dir / "show-access-rulebase.json", acc_rb)

    # Seed HTTPS & Threat layers and rules
    pkgs = _read_json(branch_dir / "show-packages.json")
    pkgs["packages"][0]["https-layers"] = [{"uid": "lyr-br-https", "name": "Branch_HTTPS", "position": 1}]
    pkgs["packages"][0]["threat-layers"] = [{"uid": "lyr-br-threat", "name": "Branch_Threat", "position": 1}]
    _write_json(branch_dir / "show-packages.json", pkgs)

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
                        "uid": "hr-incr-1",
                        "name": "Inspect Outbound",
                        "type": "https-rule",
                        "rule-number": 1,
                        "enabled": True,
                        "source": ["h-old-5"],
                        "destination": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                        "service": ["97aeb369-9aea-11d5-bd16-0090272ccb30"],
                        "site-category": ["Social Networking"],
                        "action": "Inspect",
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
                        "uid": "tr-incr-1",
                        "name": "Protect Corp",
                        "type": "threat-rule",
                        "rule-number": 1,
                        "enabled": True,
                        "protected-scope": ["h-old-5"],
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

    return dataset_dir, layer_name


@pytest.mark.spec("SCN-CPCRUD-009-7")
@pytest.mark.asyncio
async def test_cpcrud_incremental_plan_apply_show_changes_and_inverse_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full end-to-end replay (`plan -> apply -> show-changes -> inverse`) across `application-site` and rules."""
    monkeypatch.setenv("ARODONATA_CPCRUD_AUTO_NAME_PREFIX_RANGE", "Range_")
    monkeypatch.setenv("ARODONATA_CPCRUD_RANGE_SEPARATOR", "_")
    monkeypatch.setenv("ARODONATA_CPCRUD_RANGE_COMPRESS_OCTETS", "true")
    monkeypatch.setenv("ARODONATA_CPCRUD_AUTO_NAME_PREFIX_GROUP", "")
    monkeypatch.setenv("ARODONATA_CPCRUD_AUTO_NAME_SUFFIX_GROUP", "_Grp")
    monkeypatch.setenv("ARODONATA_CPCRUD_AUTO_NAME_PREFIX_APP_SITE", "Site_")
    monkeypatch.setenv("ARODONATA_CPCRUD_APP_SITE_WILDCARD_MARKER", "_")

    dataset_dir, access_layer_name = _build_incremental_replay_dataset(tmp_path)
    api_mock = FileReplayApiMock(dataset_dir)
    settings = ArodonataSettings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'incr_replay.sqlite'}",
        mgmt_name="mds",
        mgmt_ip="127.0.0.1",
        api_key="mock-key",
    )
    prefixes = settings.cpcrud_naming_prefixes

    group_objs, group_spec = expand_group_expression("AppAccess(10.1.1.1, 10.1.1.2-9)", prefixes=prefixes)
    assert group_spec["name"] == "AppAccess_Grp"
    assert [o["name"] for o in group_objs] == ["Host_10.1.1.1", "Range_10.1.1.2_9"]

    async with ArodonataClient(settings=settings, api=api_mock) as client:
        template: dict[str, Any] = {
            "version": 1,
            "mgmt_name": "mds",
            "domain": "Branch",
            "objects": [
                *group_objs,
                parse_object_expression("10.1.1.10-20", prefixes=prefixes),
                {
                    "operation": "set",
                    "type": "application-site",
                    "name": "Site__chinacloudapi.cn",
                    "url-list": {"add": [r"\.partner\.cn"], "remove": [r"\/chinacloudapi\.cn"]},
                },
            ],
            "groups": [group_spec],
            "rules": [
                {
                    "operation": "set",
                    "type": "access-rule",
                    "layer": access_layer_name,
                    "name": "Allow App",
                    "source": {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]},
                    "destination": {"add": ["Range_10.1.1.2_9"], "remove": ["Any"]},
                },
                {
                    "operation": "set",
                    "type": "https-rule",
                    "layer": "Branch_HTTPS",
                    "name": "Inspect Outbound",
                    "site-category": {"add": ["Finance"], "remove": ["Social Networking"]},
                },
                {
                    "operation": "set",
                    "type": "threat-rule",
                    "layer": "Branch_Threat",
                    "name": "Protect Corp",
                    "protected-scope": {"add": ["AppAccess_Grp"], "remove": ["Host_10.0.0.5"]},
                    "install-on": {"add": ["fw-branch-01"], "remove": ["Any"]},
                },
            ],
        }

        assert client.cpcrud.validate(template) == []
        plan = await client.cpcrud.plan(template)
        assert not plan.has_errors

        apply_report = await client.cpcrud.apply(plan)
        assert apply_report.success
        published_uid = next(iter(apply_report.published_sessions.values()))

        # Verify updated objects and rules via live emulator calls
        site_after = await api_mock.api_call(
            "mds", "show-application-site", {"name": "Site__chinacloudapi.cn"}, domain="Branch"
        )
        assert site_after.success
        assert site_after.data["url-list"] == [r"\.chinacloudapi\.cn", r"\.partner\.cn"]

        acc_after = await api_mock.api_call(
            "mds", "show-access-rule", {"layer": access_layer_name, "name": "Allow App"}, domain="Branch"
        )
        assert acc_after.success
        assert [x["name"] for x in acc_after.data["source"]] == ["Host_10.1.1.1"]
        assert [x["name"] for x in acc_after.data["destination"]] == ["Range_10.1.1.2_9"]

        https_after = await api_mock.api_call(
            "mds", "show-https-rule", {"layer": "Branch_HTTPS", "name": "Inspect Outbound"}, domain="Branch"
        )
        assert https_after.success
        assert https_after.data["site-category"] == ["Finance"]

        threat_after = await api_mock.api_call(
            "mds", "show-threat-rule", {"layer": "Branch_Threat", "name": "Protect Corp"}, domain="Branch"
        )
        assert threat_after.success
        assert [x["name"] for x in threat_after.data["protected-scope"]] == ["AppAccess_Grp"]
        assert [x["name"] for x in threat_after.data["install-on"]] == ["fw-branch-01"]

        # Verify `show-changes` + `collect_change_report` captures modified app-site and modified rules
        change_report = await collect_change_report(
            api_mock,
            client._cache,
            [SessionScope(mgmt_name="mds", domain="Branch", session_uids=[published_uid])],
        )
        assert len(change_report.sessions) == 1
        sess_rep = change_report.sessions[0]
        mod_obj_names = {oc.name: oc for oc in sess_rep.object_changes}
        assert "Site__chinacloudapi.cn" in mod_obj_names
        assert mod_obj_names["Site__chinacloudapi.cn"].operation == "modified"
        mod_rule_names = {rc.name: rc for rc in sess_rep.rule_changes}
        assert {"Allow App", "Inspect Outbound", "Protect Corp"} <= set(mod_rule_names.keys())
        assert mod_rule_names["Allow App"].source == ["Host_10.1.1.1"]
        assert mod_rule_names["Allow App"].destination == ["Range_10.1.1.2_9"]

        # Apply compensating inverse template and confirm baseline restoration
        inv_tpl = client.cpcrud.inverse(plan, apply_report)
        assert client.cpcrud.validate(inv_tpl) == []
        inv_plan = await client.cpcrud.plan(inv_tpl)
        assert not inv_plan.has_errors
        inv_report = await client.cpcrud.apply(inv_plan)
        assert inv_report.success

        site_reverted = await api_mock.api_call(
            "mds", "show-application-site", {"name": "Site__chinacloudapi.cn"}, domain="Branch"
        )
        assert site_reverted.data["url-list"] == [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"]

        acc_reverted = await api_mock.api_call(
            "mds", "show-access-rule", {"layer": access_layer_name, "name": "Allow App"}, domain="Branch"
        )
        assert [x["name"] for x in acc_reverted.data["source"]] == ["Host_10.0.0.5"]
        assert [x["name"] for x in acc_reverted.data["destination"]] == ["Any"]

        https_reverted = await api_mock.api_call(
            "mds", "show-https-rule", {"layer": "Branch_HTTPS", "name": "Inspect Outbound"}, domain="Branch"
        )
        assert https_reverted.data["site-category"] == ["Social Networking"]

        threat_reverted = await api_mock.api_call(
            "mds", "show-threat-rule", {"layer": "Branch_Threat", "name": "Protect Corp"}, domain="Branch"
        )
        assert [x["name"] for x in threat_reverted.data["protected-scope"]] == ["Host_10.0.0.5"]
        assert [x["name"] for x in threat_reverted.data["install-on"]] == ["Any"]

        grp_reverted = await api_mock.api_call("mds", "show-group", {"name": "AppAccess_Grp"}, domain="Branch")
        assert not grp_reverted.success


@pytest.mark.spec("SCN-CPCRUD-009-7")
@pytest.mark.asyncio
async def test_emulator_direct_incremental_set_application_site_and_empty_guard(tmp_path: Path) -> None:
    """Direct `set-application-site` calls with `{add, remove}` mutate `url-list` and reject empty removal."""
    dataset_dir, _ = _build_incremental_replay_dataset(tmp_path)
    api_mock = FileReplayApiMock(dataset_dir)
    sid, _ = await api_mock.create_dedicated_session("mds", "Branch", session_name="direct-app-site")

    upd = await api_mock.api_call(
        "mds",
        "set-application-site",
        {"name": "Site__chinacloudapi.cn", "url-list": {"add": [r"\.gov\.cn"], "remove": [r"\/chinacloudapi\.cn"]}},
        domain="Branch",
        sid=sid,
    )
    assert upd.success
    assert upd.data["url-list"] == [r"\.chinacloudapi\.cn", r"\.gov\.cn"]

    bad_empty = await api_mock.api_call(
        "mds",
        "set-application-site",
        {"name": "Site__chinacloudapi.cn", "url-list": {"remove": [r"\.chinacloudapi\.cn", r"\.gov\.cn"]}},
        domain="Branch",
        sid=sid,
    )
    assert not bad_empty.success
    assert bad_empty.status_code == 400
