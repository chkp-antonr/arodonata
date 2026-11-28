"""Unit tests for CPCRUD offline template validation (`src/arodonata/cpcrud/validator.py`)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.core.errors import ConfigurationError
from arodonata.cpcrud.validator import load_cpcrud_schema, parse_template_input, validate_template


class NeverCalledApi:
    """`ApiPort` double that fails immediately if any network method is called."""

    async def api_call(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("validate() must not perform any network api_call")

    async def api_query(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("validate() must not perform any network api_query")

    async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
        raise AssertionError("validate() must not open a session")

    async def logout_sid(self, *args: Any, **kwargs: Any) -> bool:
        raise AssertionError("validate() must not call logout_sid")

    async def close(self, *, logout: bool | None = None) -> None:
        return None


def test_validate_template_valid_single_and_multi_target_yaml_and_dict() -> None:
    """`validate_template` accepts valid single-domain and multi-target templates in dict, YAML, and JSON formats."""
    single_dict: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "on_name_conflict": "update",
        "on_ip_conflict": "reuse",
        "naming_prefixes": {
            "host": "Host_",
            "network": "Net_",
            "address_range": "IPR_",
            "service_tcp": "TCP_",
            "service_udp": "UDP_",
            "service_icmp": "ICMP_",
        },
        "objects": [
            {"type": "host", "name": "web-01", "ipv4-address": "10.10.1.10"},
            {"type": "network", "name": "net-app", "subnet4": "10.10.2.0", "mask-length4": 24},
            {
                "type": "address-range",
                "name": "rng-pool",
                "ipv4-address-first": "10.10.3.10",
                "ipv4-address-last": "10.10.3.20",
            },
            {"type": "dns-domain", "name": ".example.com", "is-sub-domain": True},
        ],
        "services": [
            {"type": "service-tcp", "name": "tcp-8443", "port": "8443"},
            {"type": "service-udp", "name": "udp-5353", "port": 5353},
            {"type": "service-icmp", "name": "icmp-echo", "icmp-type": 8, "icmp-code": 0},
        ],
        "groups": [
            {"type": "group", "name": "grp-web", "members": ["web-01", "net-app"]},
            {"type": "service-group", "name": "svc-grp-web", "members": ["tcp-8443"]},
        ],
        "rules": [
            {
                "type": "access-rule",
                "layer": "Network",
                "name": "Allow Web",
                "position": {"bottom": "App Section"},
                "source": ["grp-web"],
                "destination": ["Any"],
                "service": ["svc-grp-web"],
                "rule_action": "Accept",
                "track": "Log",
            },
            {
                "type": "nat-rule",
                "package": "Standard",
                "position": "bottom",
                "method": "hide",
                "original-source": "grp-web",
                "original-destination": "Any",
                "original-service": "Any",
                "translated-source": "web-01",
                "translated-destination": "Original",
                "translated-service": "Original",
            },
        ],
    }
    assert validate_template(single_dict) == []

    multi_yaml = """
version: 1
targets:
  - mgmt_name: mds1
    domain: Corp
    objects:
      - type: host
        name: h1
        ip-address: 192.0.2.10
    operations:
      - operation: delete
        type: host
        name: old-host
"""
    assert validate_template(multi_yaml) == []


@pytest.mark.spec("SCN-CPCRUD-001-1")
def test_validate_template_offline_errors_and_service_method(tmp_path: Path) -> None:
    """`CPCRUDService.validate` returns structured errors on invalid templates without touching API or DB."""
    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret")
    client = ArodonataClient(settings, api=NeverCalledApi())

    invalid_template: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "on_name_conflict": "invalid_policy",
        "objects": [
            {"type": "unknown-object-type", "name": "bad-obj"},
        ],
        "unknown_top_key": True,
    }
    errors = client.cpcrud.validate(invalid_template)
    assert len(errors) >= 2
    assert any("on_name_conflict" in err for err in errors)
    assert any("objects[0]" in err or "unknown_top_key" in err for err in errors)

    # Empty or non-mapping YAML strings return parse errors
    assert client.cpcrud.validate("   ") == ["Template string is empty."]
    assert "Template root must be a mapping/object" in client.cpcrud.validate("- item1\n- item2")[0]
    assert "Failed to parse YAML/JSON template" in client.cpcrud.validate("key: [unclosed")[0]

    # Custom schema_path override works
    custom_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["custom_required_field"],
        "properties": {"custom_required_field": {"type": "string"}},
        "additionalProperties": False,
    }
    schema_file = tmp_path / "custom_schema.json"
    schema_file.write_text(json.dumps(custom_schema), encoding="utf-8")

    assert client.cpcrud.validate({"custom_required_field": "ok"}, schema_path=schema_file) == []
    custom_errs = client.cpcrud.validate({}, schema_path=schema_file)
    assert len(custom_errs) == 1
    assert "custom_required_field" in custom_errs[0]

    # Missing schema file raises ConfigurationError
    with pytest.raises(ConfigurationError, match="not found"):
        load_cpcrud_schema(tmp_path / "does_not_exist.json")


def test_parse_template_input_rejects_non_dict_or_str() -> None:
    """`parse_template_input` rejects unsupported input types cleanly."""
    parsed, errs = parse_template_input(12345)  # type: ignore[arg-type]
    assert parsed is None
    assert len(errs) == 1
    assert "got int" in errs[0]


def test_validate_template_application_site_in_objects_services_and_operations() -> None:
    """`validate_template` accepts `application-site` in `objects`, `services`, and `operations` and rejects missing `url-list`/`application-signature`."""
    valid_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            {
                "type": "application-site",
                "name": "Site_baidu.com",
                "primary-category": "Custom_Application_Site",
                "url-list": [r"\/baidu\.com", r"\.baidu\.com"],
                "urls-defined-as-regular-expression": True,
                "description": "Baidu regex site",
                "additional-categories": ["Search_Engines"],
            }
        ],
        "services": [
            {
                "type": "application-site",
                "name": "Site_example_svc",
                "primary_category": "Custom_Application_Site",
                "url_list": ["example.org"],
                "urls_defined_as_regular_expression": False,
            }
        ],
        "operations": [
            {
                "operation": "add",
                "type": "application-site",
                "name": "Site_sig_custom",
                "primary-category": "Custom_Application_Site",
                "application-signature": "http-header:X-Custom",
            },
            {
                "operation": "delete",
                "type": "application-site",
                "name": "Site_old",
            },
        ],
    }
    assert validate_template(valid_tpl) == []

    # R5: action="present" (default) without url-list/application-signature is allowed by static validation
    # so existing application-site objects can be updated (comments/description/color) or checked for presence.
    present_update_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            {
                "type": "application-site",
                "name": "Site_existing",
                "description": "Updated description only",
                "comments": "Updated comments",
            }
        ],
    }
    assert validate_template(present_update_tpl) == []

    # Explicit action="add" without url-list/application-signature is rejected by static validation.
    missing_urls_add_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            {
                "action": "add",
                "type": "application-site",
                "name": "Site_empty",
                "primary-category": "Custom_Application_Site",
            }
        ],
    }
    errs = validate_template(missing_urls_add_tpl)
    assert len(errs) == 1
    assert "objects[0]" in errs[0]
    assert "url-list" in errs[0]


def test_validate_template_incremental_url_list_and_rule_cell_deltas_and_field_change_defaults() -> None:
    """`validate_template` accepts `{"add": ..., "remove": ...}` on `url-list` and all 6 rule list cells, rejecting invalid delta dicts."""
    from arodonata.cpcrud.models import FieldChange

    fc = FieldChange(field="source", old_value=["Any"], new_value=["Host_1"])
    assert fc.added_items == []
    assert fc.removed_items == []

    valid_incremental_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            {
                "operation": "set",
                "type": "application-site",
                "name": "Site__chinacloudapi.cn",
                "url-list": {"add": [r"\.partner\.cn"], "remove": [r"\/chinacloudapi\.cn"]},
            }
        ],
        "services": [
            {
                "operation": "update",
                "type": "application-site",
                "name": "Site_svc",
                "url_list": {"add": ["extra.example.com"]},
            }
        ],
        "rules": [
            {
                "operation": "set",
                "type": "access-rule",
                "layer": "Network",
                "name": "Allow App",
                "source": {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]},
                "destination": {"add": ["Net_10.2.0.0_16"]},
                "service": {"remove": ["TCP_80"]},
                "install_on": {"add": ["gw-1"]},
            },
            {
                "operation": "set",
                "type": "threat-rule",
                "layer": "Threat Layer",
                "name": "Threat Scope",
                "protected-scope": {"add": ["Net_10.3.0.0_16"], "remove": ["Net_Old"]},
                "install-on": {"remove": ["gw-old"]},
            },
            {
                "operation": "set",
                "type": "https-rule",
                "layer": "HTTPS Layer",
                "name": "HTTPS Inspect",
                "site_category": {"add": ["Finance"], "remove": ["Social Networking"]},
                "site-category": {"add": ["Banking"]},
                "protected_scope": {"add": ["Any"]},
            },
        ],
    }
    assert validate_template(valid_incremental_tpl) == []

    # Empty {} or unknown keys inside {add, remove} must be rejected
    invalid_delta_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            {
                "operation": "set",
                "type": "application-site",
                "name": "Site_bad",
                "url-list": {},
            }
        ],
        "rules": [
            {
                "operation": "set",
                "type": "access-rule",
                "layer": "Network",
                "name": "Bad Rule",
                "source": {"add": ["Host_1"], "bogus": ["x"]},
            }
        ],
    }
    bad_errs = validate_template(invalid_delta_tpl)
    assert len(bad_errs) >= 2
    assert any("objects[0].url-list" in e for e in bad_errs)
    assert any("rules[0].source" in e for e in bad_errs)

    # action="add" on application-site with only remove (and no application-signature) fails semantic validation
    add_only_remove_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            {
                "action": "add",
                "type": "application-site",
                "name": "Site_empty_add",
                "url-list": {"remove": ["old.example.com"]},
            }
        ],
    }
    sem_errs = validate_template(add_only_remove_tpl)
    assert len(sem_errs) == 1
    assert "url-list" in sem_errs[0]

    # Explicit action="add" on a rule with incremental {add, remove} cell deltas fails semantic validation
    add_rule_delta_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "rules": [
            {
                "operation": "add",
                "type": "access-rule",
                "layer": "Network",
                "name": "Bad Add Rule",
                "source": {"add": ["Host_1"]},
            }
        ],
    }
    rule_sem_errs = validate_template(add_rule_delta_tpl)
    assert len(rule_sem_errs) == 1
    assert "rules[0]" in rule_sem_errs[0]


@pytest.mark.spec("SCN-CPCRUD-014-2", "SCN-CPCRUD-014-3")
def test_schema_empty_list_and_semantic_default_type_and_is_cleanup_rule() -> None:
    """SCN-CPCRUD-014-2/3: Schema rejects empty list cells, infers omitted type, accepts check_where_used, and is_cleanup_rule checks Any/Any/Any."""
    from arodonata.core.models.rulebase import AccessRuleEntry
    from arodonata.cpcrud.differ import DiffSafetyError, compute_rule_diff
    from arodonata.cpcrud.position_helper import is_cleanup_rule

    # 1. Empty list replacement rejected by schema and compute_rule_diff
    empty_src_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "rules": [{"type": "access-rule", "layer": "Network", "name": "R1", "source": []}],
    }
    assert validate_template(empty_src_tpl) != []

    existing_acc = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-1",
        layer_name="Network",
        uid="ar-1",
        position=1,
        source=["Host_1"],
        install_on=[],
    )
    with pytest.raises(DiffSafetyError, match="empty"):
        compute_rule_diff({"source": []}, existing_acc, rulebase_type="access")

    # install-on incremental delta does NOT coerce unset install-on to 'Any'
    inst_diffs, inst_upd = compute_rule_diff({"install-on": {"add": ["GW1"]}}, existing_acc, rulebase_type="access")
    assert inst_upd["install-on"] == {"add": ["GW1"]}
    assert inst_diffs["install-on"].old_value == []

    # 2. Omitted type in rules/groups still enforces add+delta/remove semantic checks and operation > action precedence
    omitted_type_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "rules": [{"operation": "add", "layer": "Network", "name": "R2", "source": {"add": ["H1"]}}],
        "groups": [{"operation": "add", "name": "G1", "members": {"remove": ["H1"]}}],
    }
    sem_errs = validate_template(omitted_type_tpl)
    assert len(sem_errs) == 2

    # 3. check_where_used is accepted on ObjectOperation
    cwu_tpl: dict[str, Any] = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [{"operation": "delete", "type": "host", "name": "H_del", "check_where_used": True}],
    }
    assert validate_template(cwu_tpl) == []

    # 4. is_cleanup_rule returns False when rule named *cleanup* has narrow traffic
    narrow_cleanup = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-1",
        layer_name="Network",
        uid="ar-narrow",
        name="Pre-cleanup checks",
        position=1,
        source=["Host_1"],
        destination=["Any"],
        service=["Any"],
    )
    assert is_cleanup_rule(narrow_cleanup) is False

    real_cleanup = AccessRuleEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        layer_uid="lyr-1",
        layer_name="Network",
        uid="ar-clean",
        name="Cleanup rule",
        position=2,
        source=["Any"],
        destination=["Any"],
        service=["Any"],
    )
    assert is_cleanup_rule(real_cleanup) is True


@pytest.mark.spec("SCN-CPCRUD-018-1")
def test_validate_template_rejects_blank_whitespace_and_duplicate_operation_ids() -> None:
    """DA-005: Blank, whitespace-only, and duplicate explicit operation IDs fail validation."""
    errs_blank = validate_template(
        {"objects": [{"id": "   ", "type": "host", "name": "h1", "ipv4-address": "1.2.3.4"}]}
    )
    assert errs_blank

    errs_dup = validate_template(
        {
            "objects": [
                {"id": "op-1", "type": "host", "name": "h1", "ipv4-address": "1.2.3.4"},
            ],
            "services": [
                {"id": " op-1 ", "type": "service-tcp", "name": "tcp-80", "port": "80"},
            ],
        }
    )
    assert any("duplicate operation id" in e for e in errs_dup)
