"""Tests for extractors.objects.ObjectExtractor.

Covers common-field extraction, per-type dispatch (host/network/group/
service-group/address-range), member-UID extraction from dict and list raw
shapes, unknown types falling back to common fields only, and the optional
comments/color/tags handling.
"""

from arodonata.extractors.base import ExtractionContext
from arodonata.extractors.objects import ObjectExtractor


def _ctx(mgmt="mgmt1", domain=""):
    return ExtractionContext(mgmt_name=mgmt, domain_name=domain)


def test_extract_host_object():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "123abc",
        "name": "test-host",
        "type": "host",
        "ipv4-address": "192.168.1.10",
        "comments": "Test host",
    }

    result = extractor.extract(raw_data, _ctx("mgmt1", "dmn1"))

    assert result["uid"] == "123abc"
    assert result["name"] == "test-host"
    assert result["type"] == "host"
    assert result["ipv4_address"] == "192.168.1.10"
    assert result["mgmt_name"] == "mgmt1"
    assert result["domain_name"] == "dmn1"
    assert result["comments"] == "Test host"
    assert result["raw_data"] == raw_data


def test_extract_network_object():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "456def",
        "name": "test-network",
        "type": "network",
        "subnet4": "192.168.1.0",
        "subnet-mask": "255.255.255.0",
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["subnet4"] == "192.168.1.0"
    assert result["subnet_mask"] == "255.255.255.0"


def test_extract_group_with_members_as_dict_container():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "789ghi",
        "name": "test-group",
        "type": "group",
        "members": {"objects": [{"uid": "111"}, {"uid": "222"}]},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["members"] == "111,222"


def test_extract_service_group_with_members():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "aaa111",
        "name": "test-service-group",
        "type": "service-group",
        "members": {"objects": [{"uid": "333"}, {"uid": "444"}]},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["type"] == "service-group"
    assert result["members"] == "333,444"


def test_extract_group_with_members_as_plain_list():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "bbb222",
        "name": "test-group-list",
        "type": "group",
        "members": [{"uid": "555"}, {"uid": "666"}],
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["members"] == "555,666"


def test_extract_group_members_dict_without_objects_key_yields_empty_members():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "ccc999",
        "name": "empty-group",
        "type": "group",
        "members": {"unexpected-key": []},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["members"] == ""


def test_extract_group_members_missing_defaults_to_dict_branch_empty():
    extractor = ObjectExtractor()
    raw_data = {"uid": "ddd000", "name": "no-members-group", "type": "group"}

    result = extractor.extract(raw_data, _ctx())

    # `members` defaults to {} (a dict) so the dict branch runs and yields "".
    assert result["members"] == ""


def test_extract_group_members_non_dict_non_list_skips_extraction():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "eee111",
        "name": "weird-group",
        "type": "group",
        "members": "not-a-container",
    }

    result = extractor.extract(raw_data, _ctx())

    assert "members" not in result


def test_extract_group_members_filters_non_dict_items():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "fff222",
        "name": "mixed-group",
        "type": "group",
        "members": {"objects": [{"uid": "777"}, "not-a-dict", {"uid": "888"}]},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["members"] == "777,888"


def test_extract_address_range_object():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "ccc333",
        "name": "test-range",
        "type": "address-range",
        "ipv4-address-first": "10.0.0.1",
        "ipv4-address-last": "10.0.0.100",
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["ipv4_address_first"] == "10.0.0.1"
    assert result["ipv4_address_last"] == "10.0.0.100"


def test_extract_unknown_type_falls_back_to_common_fields_only():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "ddd444",
        "name": "test-unknown",
        "type": "access-role",
        "comments": "Unrecognized type",
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["type"] == "access-role"
    assert result["comments"] == "Unrecognized type"
    assert "ipv4_address" not in result
    assert "subnet4" not in result
    assert "members" not in result


def test_extract_missing_type_defaults_to_empty_string():
    extractor = ObjectExtractor()
    raw_data = {"uid": "no-type-uid", "name": "no-type"}

    result = extractor.extract(raw_data, _ctx())

    assert result["type"] == ""
    assert result["uid"] == "no-type-uid"


def test_extract_missing_uid_and_name_default_to_empty_string():
    extractor = ObjectExtractor()
    result = extractor.extract({"type": "host"}, _ctx())

    assert result["uid"] == ""
    assert result["name"] == ""


def test_extract_common_optional_fields_color_and_tags_list():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "eee555",
        "name": "test-host-common",
        "type": "host",
        "ipv4-address": "192.168.1.20",
        "color": "red",
        "tags": ["prod", "web"],
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["color"] == "red"
    assert result["tags"] == "prod,web"


def test_extract_common_optional_fields_tags_non_list_string():
    extractor = ObjectExtractor()
    raw_data = {
        "uid": "fff666",
        "name": "test-host-tags-str",
        "type": "host",
        "tags": "single-tag",
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["tags"] == "single-tag"


def test_extract_common_optional_fields_tags_falsy_non_list():
    extractor = ObjectExtractor()
    raw_data = {"uid": "ggg777", "name": "falsy-tags", "type": "host", "tags": 0}

    result = extractor.extract(raw_data, _ctx())

    assert result["tags"] == ""


def test_extract_common_optional_fields_absent_when_not_in_raw_data():
    extractor = ObjectExtractor()
    raw_data = {"uid": "hhh888", "name": "no-optionals", "type": "host"}

    result = extractor.extract(raw_data, _ctx())

    assert "comments" not in result
    assert "color" not in result
    assert "tags" not in result
