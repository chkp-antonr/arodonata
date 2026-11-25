"""Unit tests for incremental list-cell diffs and safety guards (`src/arodonata/cpcrud/differ.py`)."""

from __future__ import annotations

import pytest

from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    ThreatRuleEntry,
)
from arodonata.cpcrud.differ import DiffSafetyError, compute_object_diff, compute_rule_diff
from arodonata.cpcrud.rule_identity import NAT_ANY_OBJECT_UID


@pytest.mark.spec("SCN-CPCRUD-007-1", "SCN-CPCRUD-007-2")
def test_compute_object_diff_application_site_incremental_url_list_and_empty_guard() -> None:
    """`application-site.url-list` computes merged post-delta payloads and blocks empty removal without signature."""
    site = CPObject.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "site-1",
            "name": "Site__chinacloudapi.cn",
            "type": "application-site",
            "primary-category": "Custom_Application_Site",
            "url-list": [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"],
            "urls-defined-as-regular-expression": True,
        },
    )

    diffs, payload = compute_object_diff(
        {
            "type": "application-site",
            "name": "Site__chinacloudapi.cn",
            "url-list": {"add": [r"\.partner\.cn"], "remove": [r"\/chinacloudapi\.cn"]},
        },
        site,
    )
    assert payload == {"url-list": [r"\.chinacloudapi\.cn", r"\.partner\.cn"]}
    assert diffs["url-list"].old_value == [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"]
    assert diffs["url-list"].new_value == [r"\.chinacloudapi\.cn", r"\.partner\.cn"]
    assert diffs["url-list"].added_items == [r"\.partner\.cn"]
    assert diffs["url-list"].removed_items == [r"\/chinacloudapi\.cn"]

    # Idempotent add (already present) and remove (not present) -> empty diff
    idem_diffs, idem_payload = compute_object_diff(
        {
            "type": "application-site",
            "name": "Site__chinacloudapi.cn",
            "url-list": {"add": [r"\/chinacloudapi\.cn"], "remove": ["nonexistent.example"]},
        },
        site,
    )
    assert idem_diffs == {}
    assert idem_payload == {}

    # Removing every remaining URL without application-signature fails closed
    with pytest.raises(DiffSafetyError, match="empty url-list"):
        compute_object_diff(
            {
                "type": "application-site",
                "name": "Site__chinacloudapi.cn",
                "url-list": {"remove": [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"]},
            },
            site,
        )

    # Emptying url-list is permitted when application-signature is supplied
    sig_diffs, sig_payload = compute_object_diff(
        {
            "type": "application-site",
            "name": "Site__chinacloudapi.cn",
            "url-list": {"remove": [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"]},
            "application-signature": "http-header:X-Partner",
        },
        site,
    )
    assert sig_payload["url-list"] == []
    assert sig_payload["application-signature"] == "http-header:X-Partner"
    assert sig_diffs["url-list"].removed_items == [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"]


def test_compute_rule_diff_incremental_cells_and_name_resolutions() -> None:
    """Rule list cells support `{add, remove}` across Access, HTTPS, Threat, and NAT rules with `name_resolutions`."""
    access_rule = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-1",
        layer_name="Network",
        uid="ar-1",
        name="Allow App",
        position=1,
        source=["Host_10.0.0.5"],
        destination=["Net_10.2.0.0_16"],
        service=["TCP_80"],
        install_on=["fw-1"],
        raw_data={
            "source": ["uid-h5"],
            "destination": ["uid-net2"],
            "service": ["uid-tcp80"],
            "install-on": ["uid-fw1"],
        },
    )
    obj_dict = {
        "uid-h5": {"name": "Host_10.0.0.5"},
        "uid-net2": {"name": "Net_10.2.0.0_16"},
        "uid-tcp80": {"name": "TCP_80"},
        "uid-fw1": {"name": "fw-1"},
    }

    diffs, payload = compute_rule_diff(
        {
            "source": {"add": ["Requested_New_Host"], "remove": ["Host_10.0.0.5"]},
            "service": {"add": ["TCP_8443"]},
            "install-on": {"add": ["fw-2"]},
        },
        access_rule,
        rulebase_type="access",
        obj_dict=obj_dict,
        name_resolutions={"Requested_New_Host": "Host_10.1.1.1"},
    )

    assert payload == {
        "source": {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]},
        "service": {"add": ["TCP_8443"]},
        "install-on": {"add": ["fw-2"]},
    }
    assert diffs["source"].old_value == ["Host_10.0.0.5"]
    assert diffs["source"].new_value == {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}
    assert diffs["source"].added_items == ["Host_10.1.1.1"]
    assert diffs["source"].removed_items == ["Host_10.0.0.5"]
    assert diffs["service"].added_items == ["TCP_8443"]
    assert diffs["install-on"].added_items == ["fw-2"]

    # Idempotent delta yields no diff
    idem_diffs, idem_payload = compute_rule_diff(
        {
            "source": {"add": ["Host_10.0.0.5"], "remove": ["Missing_Obj"]},
        },
        access_rule,
        rulebase_type="access",
        obj_dict=obj_dict,
    )
    assert idem_diffs == {}
    assert idem_payload == {}

    # HTTPS site-category and Threat protected-scope
    https_rule = HttpsRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-h",
        layer_name="HTTPS",
        uid="hr-1",
        name="Inspect",
        position=1,
        site_category=["Social Networking"],
    )
    h_diffs, h_payload = compute_rule_diff(
        {"site-category": {"add": ["Finance"], "remove": ["Social Networking"]}},
        https_rule,
        rulebase_type="https",
    )
    assert h_payload == {"site-category": {"add": ["Finance"], "remove": ["Social Networking"]}}
    assert h_diffs["site-category"].added_items == ["Finance"]
    assert h_diffs["site-category"].removed_items == ["Social Networking"]

    threat_rule = ThreatRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-t",
        layer_name="Threat",
        uid="tr-1",
        name="Protect",
        position=1,
        protected_scope=["Net_10.3.0.0_16"],
    )
    t_diffs, t_payload = compute_rule_diff(
        {"protected_scope": {"add": ["Net_10.4.0.0_16"]}},
        threat_rule,
        rulebase_type="threat",
    )
    assert t_payload == {"protected-scope": {"add": ["Net_10.4.0.0_16"]}}
    assert t_diffs["protected-scope"].added_items == ["Net_10.4.0.0_16"]

    nat_rule = NatRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        package_uid="pkg-1",
        package_name="Standard",
        uid="nr-1",
        position=1,
        install_on=["gw-1"],
    )
    n_diffs, n_payload = compute_rule_diff(
        {"install_on": {"add": ["gw-2"]}},
        nat_rule,
        rulebase_type="nat",
    )
    assert n_payload == {"install-on": {"add": ["gw-2"]}}
    assert n_diffs["install-on"].added_items == ["gw-2"]


@pytest.mark.spec("SCN-CPCRUD-009-2", "SCN-CPCRUD-009-3", "SCN-CPCRUD-009-4")
def test_compute_rule_diff_anti_any_widening_and_any_collision_guards() -> None:
    """Removing every item raises `DiffSafetyError`; adding to `"Any"` requires explicit `"remove": ["Any"]`."""
    rule_with_specifics = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-1",
        layer_name="Network",
        uid="ar-spec",
        name="Specific",
        position=1,
        source=["Host_10.1.1.1"],
        destination=["Any"],
        service=["TCP_443"],
        raw_data={"destination": [NAT_ANY_OBJECT_UID]},
    )

    # 1. Emptying source via remove -> DiffSafetyError
    with pytest.raises(DiffSafetyError, match="widens to 'Any'"):
        compute_rule_diff(
            {"source": {"remove": ["Host_10.1.1.1"]}},
            rule_with_specifics,
            rulebase_type="access",
        )

    # 2. Adding to destination when it is "Any" without removing "Any" -> DiffSafetyError
    with pytest.raises(DiffSafetyError, match="include 'Any' in 'remove'"):
        compute_rule_diff(
            {"destination": {"add": ["Net_10.2.0.0_16"]}},
            rule_with_specifics,
            rulebase_type="access",
        )

    # Explicitly removing "Any" while adding a specific object succeeds cleanly (stripping "Any" on wire)
    diffs, payload = compute_rule_diff(
        {"destination": {"add": ["Net_10.2.0.0_16"], "remove": ["Any"]}},
        rule_with_specifics,
        rulebase_type="access",
    )
    assert payload == {"destination": {"add": ["Net_10.2.0.0_16"]}}
    assert diffs["destination"].added_items == ["Net_10.2.0.0_16"]
    assert diffs["destination"].removed_items == ["Any"]

    # Adding "Any" via incremental delta is rejected
    with pytest.raises(DiffSafetyError, match="Cannot include 'Any' in incremental 'add'"):
        compute_rule_diff(
            {"source": {"add": ["Any"]}},
            rule_with_specifics,
            rulebase_type="access",
        )

    # 4. Anti-Any-widening also applies to Threat protected-scope and HTTPS site-category
    with pytest.raises(DiffSafetyError, match="widens to 'Any'"):
        compute_rule_diff(
            {"protected-scope": {"remove": ["Net_Scope"]}},
            ThreatRuleEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                layer_uid="lyr-t",
                layer_name="Threat",
                uid="tr-1",
                position=1,
                protected_scope=["Net_Scope"],
            ),
            rulebase_type="threat",
        )
    with pytest.raises(DiffSafetyError, match="widens to 'Any'"):
        compute_rule_diff(
            {"site-category": {"remove": ["Social Networking"]}},
            HttpsRuleEntry(
                mgmt_name="mds1",
                domain_name="Corp",
                layer_uid="lyr-h",
                layer_name="HTTPS",
                uid="hr-1",
                position=1,
                site_category=["Social Networking"],
            ),
            rulebase_type="https",
        )


def test_compute_url_list_case_folding_and_mixed_uid_group_members() -> None:
    """Non-regex `url-list` matches case-insensitively and mixed UID/name `group.members` preserves kept names."""
    static_site = CPObject.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "site-static-1",
            "name": "Site_Static",
            "type": "application-site",
            "primary-category": "Custom_Application_Site",
            "url-list": ["HTTPS://Partner.Example.com", "https://keep.example.com"],
            "urls-defined-as-regular-expression": False,
        },
    )
    idem_diffs, idem_payload = compute_object_diff(
        {
            "type": "application-site",
            "name": "Site_Static",
            "url-list": ["https://partner.example.com", "https://keep.example.com"],
        },
        static_site,
    )
    assert idem_diffs == {}
    assert idem_payload == {}

    rem_diffs, rem_payload = compute_object_diff(
        {"type": "application-site", "name": "Site_Static", "url-list": {"remove": ["https://partner.example.com"]}},
        static_site,
    )
    assert rem_payload == {"url-list": ["https://keep.example.com"]}
    assert rem_diffs["url-list"].removed_items == ["HTTPS://Partner.Example.com"]

    grp = CPObject.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "grp-mixed",
            "name": "grpMixed",
            "type": "group",
            "members": [
                {"uid": "u-host-1", "name": "Host_1"},
                {"uid": "u-host-2", "name": "Host_2"},
            ],
        },
    )
    grp_diffs, _ = compute_object_diff(
        {"type": "group", "name": "grpMixed", "members": ["u-host-1", "Host_3"]},
        grp,
    )
    assert grp_diffs["members"].added_items == ["Host_3"]
    assert grp_diffs["members"].removed_items == ["Host_2"]


@pytest.mark.spec("SCN-CPCRUD-014-1")
def test_track_wire_encoding_and_subfield_diffs() -> None:
    """SCN-CPCRUD-014-1: Access rules encode track as object with sub-fields; HTTPS/Threat encode as string."""
    from arodonata.core.models.rulebase import AccessRuleEntry, NatRuleEntry
    from arodonata.cpcrud._planner_helpers import _build_add_rule_payload, _build_prior_rule_state

    # 1. Access rule add payload coerces string track -> {"type": "Log"} while HTTPS/Threat coerce dict -> "Log"
    acc_add = _build_add_rule_payload(
        rb_type="access",
        spec={"layer": "Network", "source": ["Any"], "destination": ["Any"], "service": ["Any"], "track": "Log"},
        layer="Network",
        package="Standard",
        position="top",
    )
    assert acc_add["track"] == {"type": "Log"}

    https_add = _build_add_rule_payload(
        rb_type="https",
        spec={
            "layer": "HTTPS",
            "source": ["Any"],
            "destination": ["Any"],
            "service": ["Any"],
            "track": {"type": "Log"},
        },
        layer="HTTPS",
        package="Standard",
        position="top",
    )
    assert https_add["track"] == "Log"

    threat_add = _build_add_rule_payload(
        rb_type="threat",
        spec={"layer": "Threat", "track": {"type": "Detailed Log"}},
        layer="Threat",
        package="Standard",
        position="top",
    )
    assert threat_add["track"] == "Detailed Log"

    # 2. Access rule TrackSettingsForRequest sub-field diff (accounting=True) and prior_state preservation
    existing_acc = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-1",
        layer_name="Network",
        uid="ar-1",
        position=1,
        track="Log",
        raw_data={"track": {"type": {"name": "Log"}, "accounting": False, "per-session": False}},
    )
    acc_diffs, acc_upd = compute_rule_diff(
        {"track": {"type": "Log", "accounting": True}},
        existing_acc,
        rulebase_type="access",
    )
    assert "track" in acc_diffs
    assert acc_upd["track"] == {"type": "Log", "accounting": True}

    prior = _build_prior_rule_state(existing_acc, rulebase_type="access", layer="Network", package="Standard")
    assert isinstance(prior["track"], dict)
    assert prior["track"]["accounting"] is False

    # 3. HTTPS rule track diff emits plain string wire value
    existing_https = HttpsRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-h",
        layer_name="HTTPS",
        uid="hr-1",
        position=1,
        track="None",
    )
    https_diffs, https_upd = compute_rule_diff(
        {"track": {"type": "Log"}},
        existing_https,
        rulebase_type="https",
    )
    assert "track" in https_diffs
    assert https_upd["track"] == "Log"

    # 4. NAT diff and existing_nat_traffic_tuple honor raw_data['_resolved_objects'] (DA-056)
    from arodonata.cpcrud.rule_identity import existing_nat_traffic_tuple

    nat_rule = NatRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        package_uid="pkg-1",
        package_name="Standard",
        uid="nr-1",
        position=1,
        method="hide",
        original_source="uid-host-1",
        raw_data={
            "method": "hide",
            "original-source": "uid-host-1",
            "_resolved_objects": {"uid-host-1": {"uid": "uid-host-1", "name": "Host_A"}},
        },
    )
    nat_diffs, _ = compute_rule_diff({"original-source": "Host_A"}, nat_rule, rulebase_type="nat")
    assert nat_diffs == {}
    assert existing_nat_traffic_tuple(nat_rule)[0] == "Host_A"


@pytest.mark.spec("SCN-CPCRUD-014-2")
def test_fail_closed_rule_defaults_match_across_add_and_identity() -> None:
    """SCN-CPCRUD-014-2: Omitted rule actions default fail-closed per rulebase type identically in add and matching."""
    from arodonata.cpcrud._planner_helpers import _build_add_rule_payload
    from arodonata.cpcrud.rule_identity import desired_access_traffic_tuple

    for rb_type, expected in (("access", "Drop"), ("https", "Inspect"), ("threat", "Optimized")):
        spec = {"action": "present", "source": ["Any"], "destination": ["Any"], "service": ["Any"]}
        add_payload = _build_add_rule_payload(
            rb_type=rb_type,  # type: ignore[arg-type]
            spec=spec,
            layer="L1",
            package="P1",
            position="top",
        )
        assert add_payload["action"] == expected
        assert desired_access_traffic_tuple(spec, rulebase_type=rb_type)[3] == expected
