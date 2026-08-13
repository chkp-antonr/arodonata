# tests/unit/cpcrud/test_schema.py
import copy

from arodonata.cpcrud.schema import normalize_operations, validate_template

_BASE = {
    "management_servers": [
        {
            "mgmt_name": "m1",
            "domains": [
                {
                    "name": "General",
                    "operations": [
                        {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}},
                    ],
                }
            ],
        }
    ]
}


def test_valid_template_no_errors():
    assert validate_template(copy.deepcopy(_BASE)) == []


def test_operation_defaults_to_add():
    doc = normalize_operations(copy.deepcopy(_BASE))
    op = doc["management_servers"][0]["domains"][0]["operations"][0]
    assert op["operation"] == "add"


def test_per_op_policy_fields_accepted():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"][0]["on_ip_conflict"] = "error"
    assert validate_template(doc) == []


def test_legacy_duplicates_rejected():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"][0]["duplicates"] = "return_error"
    errors = validate_template(doc)
    assert any("duplicates" in e or "Additional properties" in e for e in errors)


def test_bad_policy_value_rejected():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"][0]["on_name_conflict"] = "nuke"
    errors = validate_template(doc)
    assert errors


def test_operation_defaults_to_add_and_validates():
    doc = {
        "management_servers": [
            {
                "mgmt_name": "m",
                "domains": [
                    {
                        "name": "d",
                        "operations": [
                            {"type": "host", "data": {"name": "h1", "ip-address": "10.0.0.1"}},
                        ],
                    }
                ],
            }
        ]
    }
    assert validate_template(doc) == []  # valid without 'operation'
    normalized = normalize_operations(doc)
    assert normalized["management_servers"][0]["domains"][0]["operations"][0]["operation"] == "add"
    assert "operation" not in doc["management_servers"][0]["domains"][0]["operations"][0]  # input not mutated


def test_tcp_service_add_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "add", "type": "tcp-service", "data": {"name": "TCP_8080", "port": "8080"}},
    ]
    assert validate_template(doc) == []


def test_tcp_service_port_range_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "add", "type": "tcp-service", "data": {"name": "TCP_2000-2026", "port": "2000-2026"}},
    ]
    assert validate_template(doc) == []


def test_tcp_service_add_missing_port_rejected():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "add", "type": "tcp-service", "data": {"name": "TCP_8080"}},
    ]
    assert validate_template(doc) != []


def test_udp_service_update_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "update", "type": "udp-service", "key": {"name": "UDP_53"}, "data": {"comments": "dns"}},
    ]
    assert validate_template(doc) == []


def test_icmp_service_add_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "add", "type": "icmp-service", "data": {"name": "ICMP_8", "icmp-type": 8}},
    ]
    assert validate_template(doc) == []


def test_icmp_service_with_code_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "add", "type": "icmp-service", "data": {"name": "ICMP_8_0", "icmp-type": 8, "icmp-code": 0}},
    ]
    assert validate_template(doc) == []


def test_service_group_add_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {
            "operation": "add",
            "type": "service-group",
            "data": {"name": "Web-Services", "members": ["TCP_80", "TCP_443"]},
        },
    ]
    assert validate_template(doc) == []


def test_service_group_delete_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "delete", "type": "service-group", "key": {"name": "Web-Services"}},
    ]
    assert validate_template(doc) == []


def test_unknown_service_field_rejected():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "add", "type": "tcp-service", "data": {"name": "TCP_8080", "port": "8080", "bogus-field": 1}},
    ]
    assert validate_template(doc) != []


def test_threat_rule_update_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {
            "operation": "update",
            "type": "threat-prevention-rule",
            "layer": "Threat Prevention",
            "key": {"name": "r1"},
            "data": {"comments": "updated"},
        },
    ]
    assert validate_template(doc) == []


def test_threat_rule_delete_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "delete", "type": "threat-prevention-rule", "layer": "Threat Prevention", "key": {"name": "r1"}},
    ]
    assert validate_template(doc) == []


def test_threat_rule_show_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "show", "type": "threat-prevention-rule", "layer": "Threat Prevention", "key": {"name": "r1"}},
    ]
    assert validate_template(doc) == []


def test_https_rule_update_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {
            "operation": "update",
            "type": "https-rule",
            "layer": "HTTPS",
            "key": {"name": "r1"},
            "data": {"comments": "updated"},
        },
    ]
    assert validate_template(doc) == []


def test_https_rule_delete_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "delete", "type": "https-rule", "layer": "HTTPS", "key": {"name": "r1"}},
    ]
    assert validate_template(doc) == []


def test_https_rule_show_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {"operation": "show", "type": "https-rule", "layer": "HTTPS", "key": {"name": "r1"}},
    ]
    assert validate_template(doc) == []


def test_access_rule_add_with_section_relative_position_valid():
    doc = copy.deepcopy(_BASE)
    doc["management_servers"][0]["domains"][0]["operations"] = [
        {
            "operation": "add",
            "type": "access-rule",
            "layer": "Network",
            "position": {"bottom": "Web Section"},
            "data": {"name": "r1", "source": ["any"], "destination": ["any"], "service": ["any"], "action": "accept"},
        },
    ]
    assert validate_template(doc) == []
