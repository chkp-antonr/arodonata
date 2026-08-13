"""Tests for extractors.rulebases: Access/NAT/HTTPS/Threat rule extractors.

Covers full-field extraction per rule type, the shared
`_extract_names_or_uids` / `_extract_action` / `_extract_track` helpers
(including dict/list/missing raw shapes and objects_map-based UID
resolution), and the HTTPS/Threat extractors' reuse of AccessRuleExtractor
helpers.
"""

from arodonata.extractors.base import ExtractionContext
from arodonata.extractors.rulebases import (
    AccessRuleExtractor,
    HTTPSRuleExtractor,
    NATRuleExtractor,
    ThreatRuleExtractor,
)


def _ctx(objects_map=None):
    return ExtractionContext(mgmt_name="mgmt1", domain_name="", objects_map=objects_map)


# ---------------------------------------------------------------------------
# AccessRuleExtractor.extract - full happy path
# ---------------------------------------------------------------------------


def test_access_rule_extractor_full_fields():
    extractor = AccessRuleExtractor()
    raw_data = {
        "uid": "uid-001",
        "rule-number": 1,
        "name": "Allow Web Traffic",
        "enabled": True,
        "source": [{"uid": "any", "name": "Any"}],
        "destination": [{"uid": "any", "name": "Any"}],
        "service": [{"uid": "http", "name": "HTTP"}, {"uid": "https", "name": "HTTPS"}],
        "action": {"accept": True},
        "track": {"type": "Log"},
        "layer": {"uid": "layer-001", "name": "Network"},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["uid"] == "uid-001"
    assert result["rule_number"] == 1
    assert result["name"] == "Allow Web Traffic"
    assert result["enabled"] is True
    assert result["sources"] == "any"
    assert result["destinations"] == "any"
    assert result["services"] == "http,https"
    assert result["action"] == "accept"
    assert result["track"] == "Log"
    assert result["layer_name"] == "Network"
    assert result["mgmt_name"] == "mgmt1"
    assert result["domain_name"] == ""
    assert result["raw_data"] == raw_data


def test_access_rule_extractor_defaults_for_missing_fields():
    extractor = AccessRuleExtractor()
    result = extractor.extract({}, _ctx())

    assert result["uid"] == ""
    assert result["rule_number"] == 0
    assert result["name"] == ""
    assert result["enabled"] is True
    assert result["sources"] == ""
    assert result["destinations"] == ""
    assert result["services"] == ""
    assert result["action"] == "accept"
    assert result["track"] == ""
    assert result["layer_name"] == ""


def test_access_rule_extractor_layer_as_plain_string():
    extractor = AccessRuleExtractor()
    result = extractor.extract({"layer": "Network"}, _ctx())
    assert result["layer_name"] == "Network"


def test_access_rule_extractor_layer_as_neither_str_nor_dict():
    extractor = AccessRuleExtractor()
    result = extractor.extract({"layer": None}, _ctx())
    assert result["layer_name"] == ""


# ---------------------------------------------------------------------------
# _extract_names_or_uids
# ---------------------------------------------------------------------------


def test_extract_names_or_uids_dict_container_form():
    extractor = AccessRuleExtractor()
    items = {"objects": [{"uid": "u1", "name": "n1"}]}
    assert extractor._extract_names_or_uids(items, _ctx()) == ["u1"]


def test_extract_names_or_uids_dict_items_prefer_uid_over_name():
    extractor = AccessRuleExtractor()
    items = [{"uid": "u1", "name": "n1"}, {"name": "n2"}]
    assert extractor._extract_names_or_uids(items, _ctx()) == ["u1", "n2"]


def test_extract_names_or_uids_non_list_non_dict_returns_empty():
    extractor = AccessRuleExtractor()
    assert extractor._extract_names_or_uids("not-a-container", _ctx()) == []


def test_extract_names_or_uids_plain_uid_string_resolved_via_objects_map():
    extractor = AccessRuleExtractor()
    context = _ctx(objects_map={"uid-123": "resolved-name"})
    assert extractor._extract_names_or_uids(["uid-123"], context) == ["resolved-name"]


def test_extract_names_or_uids_plain_uid_string_falls_back_to_uid_when_unmapped():
    extractor = AccessRuleExtractor()
    context = _ctx(objects_map={"other-uid": "other-name"})
    assert extractor._extract_names_or_uids(["uid-123"], context) == ["uid-123"]


def test_extract_names_or_uids_plain_uid_string_no_context():
    extractor = AccessRuleExtractor()
    assert extractor._extract_names_or_uids(["uid-123"], None) == ["uid-123"]


def test_extract_names_or_uids_context_without_objects_map():
    extractor = AccessRuleExtractor()
    context = _ctx(objects_map=None)
    assert extractor._extract_names_or_uids(["uid-123"], context) == ["uid-123"]


# ---------------------------------------------------------------------------
# _extract_action
# ---------------------------------------------------------------------------


def test_extract_action_empty_string_defaults_to_accept():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action("") == "accept"


def test_extract_action_plain_string_lowercased():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action("DROP") == "drop"


def test_extract_action_string_matching_known_uid():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action("6c488338-8eec-4103-ad21-cd461ac2c472") == "Accept"
    assert extractor._extract_action("6c488338-8eec-4103-ad21-cd461ac2c473") == "Drop"


def test_extract_action_dict_with_inline_name():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"name": "Custom Action"}) == "Custom Action"


def test_extract_action_dict_accept_key():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"accept": True}) == "accept"


def test_extract_action_dict_drop_key():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"drop": True}) == "drop"


def test_extract_action_dict_reject_key():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"reject": True}) == "reject"


def test_extract_action_dict_ask_key():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"ask": True}) == "ask"


def test_extract_action_dict_uid_matching_known_map():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"uid": "6c488338-8eec-4103-ad21-cd461ac2c473"}) == "Drop"


def test_extract_action_dict_unmapped_uid_defaults_to_accept():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"uid": "unknown-uid"}) == "accept"


def test_extract_action_dict_empty_defaults_to_accept():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({}) == "accept"


def test_extract_action_neither_dict_nor_string_defaults_to_accept():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action(None) == "accept"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _extract_track
# ---------------------------------------------------------------------------


def test_extract_track_string_returned_directly():
    extractor = AccessRuleExtractor()
    assert extractor._extract_track("Log") == "Log"


def test_extract_track_dict_returns_type():
    extractor = AccessRuleExtractor()
    assert extractor._extract_track({"type": "Alert"}) == "Alert"


def test_extract_track_dict_missing_type_returns_empty():
    extractor = AccessRuleExtractor()
    assert extractor._extract_track({}) == ""


def test_extract_track_neither_dict_nor_string_returns_empty():
    extractor = AccessRuleExtractor()
    assert extractor._extract_track(None) == ""  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# NATRuleExtractor
# ---------------------------------------------------------------------------


def test_nat_rule_extractor_full_fields():
    extractor = NATRuleExtractor()
    raw_data = {
        "uid": "uid-002",
        "rule-number": 1,
        "name": "Hide NAT",
        "enabled": True,
        "original-source": "192.168.1.0",
        "original-destination": "any",
        "original-service": "any",
        "translated-source": "10.0.0.1",
        "translated-destination": "original",
        "translated-service": "original",
        "layer": {"uid": "layer-002", "name": "NAT"},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["uid"] == "uid-002"
    assert result["original_source"] == "192.168.1.0"
    assert result["original_destination"] == "any"
    assert result["original_service"] == "any"
    assert result["translated_source"] == "10.0.0.1"
    assert result["translated_destination"] == "original"
    assert result["translated_service"] == "original"
    assert result["layer_name"] == "NAT"
    assert result["mgmt_name"] == "mgmt1"


def test_nat_rule_extractor_dict_values_prefer_name_over_uid():
    extractor = NATRuleExtractor()
    raw_data = {"original-source": {"name": "net1", "uid": "u1"}}
    result = extractor.extract(raw_data, _ctx())
    assert result["original_source"] == "net1"


def test_nat_rule_extractor_dict_value_falls_back_to_uid_when_no_name():
    extractor = NATRuleExtractor()
    raw_data = {"original-source": {"uid": "u1"}}
    result = extractor.extract(raw_data, _ctx())
    assert result["original_source"] == "u1"


def test_nat_rule_extractor_dict_value_without_name_or_uid_stringifies():
    extractor = NATRuleExtractor()
    raw_data = {"original-source": {"foo": "bar"}}
    result = extractor.extract(raw_data, _ctx())
    assert result["original_source"] == str({"foo": "bar"})


def test_nat_rule_extractor_none_value_becomes_empty_string():
    extractor = NATRuleExtractor()
    raw_data = {"original-source": None}
    result = extractor.extract(raw_data, _ctx())
    assert result["original_source"] == ""


def test_nat_rule_extractor_layer_as_string():
    extractor = NATRuleExtractor()
    result = extractor.extract({"layer": "NAT-Layer"}, _ctx())
    assert result["layer_name"] == "NAT-Layer"


def test_nat_rule_extractor_layer_missing_defaults_to_empty():
    extractor = NATRuleExtractor()
    result = extractor.extract({}, _ctx())
    assert result["layer_name"] == ""


def test_nat_rule_extractor_layer_neither_str_nor_dict():
    extractor = NATRuleExtractor()
    result = extractor.extract({"layer": 123}, _ctx())
    assert result["layer_name"] == ""


# ---------------------------------------------------------------------------
# HTTPSRuleExtractor
# ---------------------------------------------------------------------------


def test_https_rule_extractor_full_fields():
    extractor = HTTPSRuleExtractor()
    raw_data = {
        "uid": "uid-003",
        "rule-number": 1,
        "name": "Inspect HTTPS",
        "enabled": True,
        "source": [{"uid": "any"}],
        "destination": [{"uid": "any"}],
        "track": {"type": "Inspect"},
        "layer": {"uid": "layer-003", "name": "CVD"},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["uid"] == "uid-003"
    assert result["sources"] == "any"
    assert result["destinations"] == "any"
    assert result["track"] == "Inspect"
    assert result["layer_name"] == "CVD"
    assert result["mgmt_name"] == "mgmt1"


def test_https_rule_extractor_layer_as_string_and_missing():
    extractor = HTTPSRuleExtractor()
    assert extractor.extract({"layer": "CVD-Layer"}, _ctx())["layer_name"] == "CVD-Layer"
    assert extractor.extract({}, _ctx())["layer_name"] == ""


def test_https_rule_extractor_layer_neither_str_nor_dict():
    extractor = HTTPSRuleExtractor()
    result = extractor.extract({"layer": 123}, _ctx())
    assert result["layer_name"] == ""


# ---------------------------------------------------------------------------
# ThreatRuleExtractor
# ---------------------------------------------------------------------------


def test_threat_rule_extractor_full_fields():
    extractor = ThreatRuleExtractor()
    raw_data = {
        "uid": "uid-004",
        "rule-number": 1,
        "name": "Block SQL Injection",
        "enabled": True,
        "track": {"type": "Alert"},
        "protections": [{"name": "SQL Injection"}, {"name": "Cross-Site Scripting"}],
        "layer": {"uid": "layer-004", "name": "Threat"},
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["uid"] == "uid-004"
    assert result["track"] == "Alert"
    assert result["protections"] == "SQL Injection,Cross-Site Scripting"
    assert result["layer_name"] == "Threat"
    assert result["mgmt_name"] == "mgmt1"


def test_threat_rule_extractor_no_protections_yields_empty_string():
    extractor = ThreatRuleExtractor()
    result = extractor.extract({}, _ctx())
    assert result["protections"] == ""


def test_threat_rule_extractor_protections_non_list_returns_empty():
    extractor = ThreatRuleExtractor()
    assert extractor._extract_protections("not-a-list") == []  # type: ignore[arg-type]


def test_threat_rule_extractor_protections_filters_non_dict_items():
    extractor = ThreatRuleExtractor()
    protections = [{"name": "SQLi"}, "not-a-dict", {"name": "XSS"}]
    assert extractor._extract_protections(protections) == ["SQLi", "XSS"]


def test_threat_rule_extractor_layer_as_string_and_missing():
    extractor = ThreatRuleExtractor()
    assert extractor.extract({"layer": "Threat-Layer"}, _ctx())["layer_name"] == "Threat-Layer"
    assert extractor.extract({"layer": 123}, _ctx())["layer_name"] == ""
