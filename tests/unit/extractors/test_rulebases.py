"""Tests for extractors.rulebases: Access/NAT/HTTPS/Threat rule extractors.

Covers full-field extraction per rule type, the shared
`resolve_ref` / `_extract_names_or_uids` / `_extract_action` / `_extract_track`
helpers (uid -> name through the layer's objects map, uid fallback)
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
        "action": "6c488338-8eec-4103-ad21-cd461ac2c472",
        "track": {"type": "Log"},
    }

    result = extractor.extract(raw_data, _ctx(objects_map={"6c488338-8eec-4103-ad21-cd461ac2c472": "Accept"}))

    assert result["uid"] == "uid-001"
    assert result["rule_number"] == 1
    assert result["name"] == "Allow Web Traffic"
    assert result["enabled"] is True
    assert result["sources"] == "any"
    assert result["destinations"] == "any"
    assert result["services"] == "http,https"
    assert result["action"] == "Accept"
    assert result["track"] == "Log"
    assert "layer_name" not in result
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
    assert result["action"] == "Accept"
    assert result["track"] == ""
    assert "layer_name" not in result


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
# _extract_action / _extract_track
# ---------------------------------------------------------------------------

ACCEPT = "6c488338-8eec-4103-ad21-cd461ac2c472"
LOG = "598ead32-aa42-4615-90ed-f51a5928d41d"
DICT = {ACCEPT: "Accept", LOG: "Log", "ea28da66-c5ed-11e2-bc66-aa5c6188709b": "Inner Layer"}


def test_extract_action_uid_string_resolved_via_objects_map():
    assert AccessRuleExtractor()._extract_action(ACCEPT, _ctx(objects_map=DICT)) == "Accept"


def test_unresolved_action_falls_back_to_uid():
    assert AccessRuleExtractor()._extract_action("1234-unknown", _ctx(objects_map=DICT)) == "1234-unknown"


def test_extract_action_dict_prefers_name_then_resolved_uid():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action({"uid": ACCEPT, "name": "Accept"}, _ctx()) == "Accept"
    assert extractor._extract_action({"uid": ACCEPT}, _ctx(objects_map=DICT)) == "Accept"
    assert extractor._extract_action({"uid": "x"}, _ctx(objects_map=DICT)) == "x"


def test_extract_action_missing_is_treated_as_accept():
    extractor = AccessRuleExtractor()
    assert extractor._extract_action("", _ctx()) == "Accept"
    assert extractor._extract_action({}, _ctx()) == "Accept"
    assert extractor._extract_action(None, _ctx()) == "Accept"


def test_extract_track_type_uid_resolved_via_objects_map():
    extractor = AccessRuleExtractor()
    assert extractor._extract_track({"type": LOG}, _ctx(objects_map=DICT)) == "Log"
    assert extractor._extract_track({"type": {"uid": LOG, "name": "Log"}}, _ctx()) == "Log"
    assert extractor._extract_track(LOG, _ctx(objects_map=DICT)) == "Log"
    assert extractor._extract_track({"type": "unmapped"}, _ctx(objects_map=DICT)) == "unmapped"
    assert extractor._extract_track({}, _ctx()) == ""
    assert extractor._extract_track(None, _ctx()) == ""


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
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["uid"] == "uid-002"
    assert result["original_source"] == "192.168.1.0"
    assert result["original_destination"] == "any"
    assert result["original_service"] == "any"
    assert result["translated_source"] == "10.0.0.1"
    assert result["translated_destination"] == "original"
    assert result["translated_service"] == "original"
    assert "layer_name" not in result
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
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["uid"] == "uid-003"
    assert result["sources"] == "any"
    assert result["destinations"] == "any"
    assert result["track"] == "Inspect"
    assert "layer_name" not in result
    assert result["mgmt_name"] == "mgmt1"


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
    }

    result = extractor.extract(raw_data, _ctx())

    assert result["uid"] == "uid-004"
    assert result["track"] == "Alert"
    assert result["protections"] == "SQL Injection,Cross-Site Scripting"
    assert "layer_name" not in result
    assert result["mgmt_name"] == "mgmt1"


def test_threat_rule_extractor_no_protections_yields_empty_string():
    extractor = ThreatRuleExtractor()
    result = extractor.extract({}, _ctx())
    assert result["protections"] == ""


def test_threat_rule_extractor_protections_non_list_returns_empty():
    extractor = ThreatRuleExtractor()
    assert extractor._extract_protections("not-a-list") == []  # type: ignore[arg-type]


def test_threat_rule_extractor_protections_keep_uid_strings_and_drop_other_types():
    extractor = ThreatRuleExtractor()
    assert extractor._extract_protections([{"name": "SQLi"}, "uid-x", 5, {"name": "XSS"}]) == ["SQLi", "uid-x", "XSS"]


def test_nat_fields_resolved_to_names():
    raw = {
        "uid": "n1",
        "rule-number": 1,
        "original-source": "u-src",
        "original-destination": {"uid": "u-dst"},
        "original-service": "97aeb369-9aea-11d5-bd16-0090272ccb30",
        "translated-source": "u-hide",
        "translated-destination": "u-unknown",
        "translated-service": {"uid": "u-svc", "name": "Original"},
    }
    names = {"u-src": "net_in", "u-dst": "srv", "97aeb369-9aea-11d5-bd16-0090272ccb30": "Any", "u-hide": "gw_hide"}
    out = NATRuleExtractor().extract(raw, _ctx(objects_map=names))
    assert (out["original_source"], out["original_destination"], out["original_service"]) == ("net_in", "srv", "Any")
    assert (out["translated_source"], out["translated_destination"], out["translated_service"]) == (
        "gw_hide",
        "u-unknown",
        "Original",
    )


def test_threat_protections_resolved_to_names():
    raw = {"uid": "t1", "rule-number": 1, "protections": ["p-1", {"uid": "p-2", "name": "Named"}, "p-3"]}
    out = ThreatRuleExtractor().extract(raw, _ctx(objects_map={"p-1": "Optimized"}))
    assert out["protections"] == "Optimized,Named,p-3"
