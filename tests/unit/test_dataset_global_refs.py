"""Unit tests verifying Enterprise Raw Dataset v1.1.0 Global cross-domain references and invariants."""

from __future__ import annotations

import json
from pathlib import Path

from arodonata.testing.dataset_generator import (
    DATASET_VERSION,
    DEFAULT_DATASET_DIR,
    USER_DOMAINS,
    ensure_enterprise_raw_dataset,
)


def test_dataset_v110_global_refs_and_assignments() -> None:
    """Dataset v1.1.0 includes `show-global-assignments.json` and Global refs in rule #104 across user domains."""
    root = ensure_enterprise_raw_dataset()
    assert root == Path(DEFAULT_DATASET_DIR)

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["version"] == DATASET_VERSION == "1.1.0"
    assert manifest["counts"]["total_domains"] == 10
    assert manifest["counts"]["total_assets"] == 284
    assert manifest["counts"]["policy_enforcing_gateways"] == 276
    assert manifest["counts"]["total_access_rules"] == 1050
    assert manifest["counts"]["total_nat_rules"] == 120

    ga_payload = json.loads((root / "mds" / "show-global-assignments.json").read_text(encoding="utf-8"))
    assert ga_payload["total"] == len(USER_DOMAINS) == 9
    assert {obj["dependent-domain"]["name"] for obj in ga_payload["objects"]} == set(USER_DOMAINS)
    for obj in ga_payload["objects"]:
        assert obj["global-domain"]["name"] == "Global"
        assert obj["global-access-policy"] == "Global_Standard_Pkg"
        assert obj["assignment-status"] == "assigned"

    expected_global_uids = {
        "uid-glob-grp-branches",
        "uid-glob-host-001",
        "uid-glob-grp-dc",
        "uid-global-svc-udp-53",
        "uid-global-svc-tcp-53",
    }
    for dom in USER_DOMAINS:
        d_slug = dom.lower()
        rb_path = root / "domains" / dom / "show-access-rulebase.json"
        rb_data = json.loads(rb_path.read_text(encoding="utf-8"))
        layer_payload = next(iter(rb_data.values()))
        assert layer_payload["total"] == 105

        dict_by_uid = {entry["uid"]: entry for entry in layer_payload["objects-dictionary"]}
        for g_uid in expected_global_uids:
            assert g_uid in dict_by_uid
            assert dict_by_uid[g_uid]["domain"] == {
                "uid": "uid-dom-global",
                "name": "Global",
                "domain-type": "global domain",
            }

        sec3_rules = layer_payload["rulebase"][2]["rulebase"]
        rule_104 = next(r for r in sec3_rules if r["uid"] == f"uid-arule-{d_slug}-0104")
        assert rule_104["rule-number"] == 104
        assert "uid-glob-grp-branches" in rule_104["source"]
        assert set(rule_104["destination"]) == {"uid-glob-host-001", "uid-glob-grp-dc"}
        assert set(rule_104["service"]) == {"uid-global-svc-udp-53", "uid-global-svc-tcp-53"}

    # Perimeter Rule #1 fixtures remain untouched for backward-compatible where-used assertions
    perim_rb = json.loads((root / "domains" / "Perimeter" / "show-access-rulebase.json").read_text(encoding="utf-8"))
    perim_layer = perim_rb["uid-layer-perimeter-security"]
    perim_rule_1 = perim_layer["rulebase"][0]["rulebase"][0]
    assert perim_rule_1["uid"] == "uid-arule-perimeter-0001"
    assert perim_rule_1["source"] == ["uid-perimeter-bulk-host-001"]
