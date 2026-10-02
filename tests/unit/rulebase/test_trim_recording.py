"""trim_recording: Gate L recordings become fixtures holding only what the cache, numbering and refresh read."""

from __future__ import annotations

from tests.unit.rulebase.trim_recording import trim_errors, trim_layer, trim_packages, trim_session


def test_trim_packages_keeps_layout_fields_only():
    raw = [
        {
            "uid": "p",
            "name": "P",
            "type": "package",
            "access": True,
            "nat-policy": False,
            "meta-info": {"creator": "someone"},
            "installation-targets": "all",
            "color": "black",
            "access-layers": [
                {
                    "uid": "l",
                    "name": "L",
                    "type": "access-layer",
                    "color": "black",
                    "domain": {"uid": "d", "name": "D", "domain-type": "domain", "icon": "x"},
                }
            ],
            "https-inspection-layers": {
                "inbound-https-layer": {"uid": "h", "name": "H", "type": "https-layer", "meta-info": {}}
            },
        }
    ]
    assert trim_packages(raw) == [
        {
            "uid": "p",
            "name": "P",
            "type": "package",
            "access": True,
            "nat-policy": False,
            "access-layers": [
                {
                    "uid": "l",
                    "name": "L",
                    "type": "access-layer",
                    "domain": {"uid": "d", "name": "D", "domain-type": "domain"},
                }
            ],
            "https-inspection-layers": {"inbound-https-layer": {"uid": "h", "name": "H", "type": "https-layer"}},
        }
    ]


def test_trim_session_keeps_counts_and_state_only():
    raw = {
        "uid": "s",
        "type": "session",
        "state": "open",
        "changes": 1,
        "locks": 2,
        "in-work": True,
        "expired-session": False,
        "user-name": "someone",
        "ip-address": "10.0.0.1",
        "email": "x@y",
        "phone-number": "1",
    }
    assert trim_session(raw) == {
        "uid": "s",
        "type": "session",
        "state": "open",
        "changes": 1,
        "locks": 2,
        "in-work": True,
        "expired-session": False,
    }


def test_trim_errors_keeps_command_payload_code_message():
    raw = {
        "x": {"command": "c", "payload": {"a": 1}, "success": False, "code": "k", "message": "m", "data": {"big": 1}}
    }
    assert trim_errors(raw) == {"x": {"command": "c", "payload": {"a": 1}, "code": "k", "message": "m"}}


def test_trim_layer_keeps_nat_fields():
    raw = {
        "uid": "n",
        "rulebase": [
            {
                "uid": "r",
                "type": "nat-rule",
                "rule-number": 1,
                "auto-generated": True,
                "method": "hide",
                "original-source": "a",
                "translated-source": "b",
                "meta-info": {},
            }
        ],
    }
    rule = trim_layer(raw)["rulebase"][0]
    assert rule == {
        "uid": "r",
        "type": "nat-rule",
        "rule-number": 1,
        "auto-generated": True,
        "method": "hide",
        "original-source": "a",
        "translated-source": "b",
    }
