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
