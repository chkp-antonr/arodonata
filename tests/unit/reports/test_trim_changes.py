from __future__ import annotations

import json

from tests.unit.reports.trim_changes import field_names, rewrite_ipv4, trim_recording


def _wrapped(entry: dict) -> dict:
    return {"tasks": [{"task-details": [{"from": 1, "to": 1, "total": 1, "changes": [entry]}]}]}


ENTRY = {
    "session": {
        "session-uid": "s1",
        "session-name": "n",
        "user-name": "jdoe",
        "published": False,
        "connected-server": "x",
        "domain-info": {"uid": "d", "name": "Domain5", "domain-type": "domain"},
    },
    "operations": {
        "added-objects": [
            {
                "uid": "h1",
                "name": "h1",
                "type": "host",
                "ipv4-address": "10.250.0.11",
                "meta-info": {"creator": "jdoe"},
                "icon": "x",
                "available-actions": {},
            }
        ],
        "modified-objects": [
            {
                "old-object": {
                    "uid": "r1",
                    "type": "access-rule",
                    "source": [
                        {
                            "uid": "h1",
                            "name": "h1",
                            "type": "host",
                            "ipv4-address": "10.250.0.11",
                            "comments": "c",
                            "domain": {"uid": "d"},
                        }
                    ],
                },
                "new-object": {"uid": "r1", "type": "access-rule", "source": []},
            }
        ],
        "deleted-objects": [],
    },
}


def test_task_wrapped_and_flat_recordings_trim_to_flat_changes():
    for recording in (_wrapped(ENTRY), {"changes": [ENTRY], "total": 1}):
        out = trim_recording(recording)
        assert out["total"] == 1 and len(out["changes"]) == 1


def test_session_keys_kept_and_user_name_placeholder():
    session = trim_recording(_wrapped(ENTRY))["changes"][0]["session"]
    assert session == {
        "session-uid": "s1",
        "session-name": "n",
        "published": False,
        "user-name": "admin",
        "domain-info": {"uid": "d", "name": "Domain5", "domain-type": "domain"},
    }


def test_bodies_drop_bookkeeping_and_nested_refs_keep_key_fields():
    out = trim_recording(_wrapped(ENTRY))["changes"][0]["operations"]
    assert out["added-objects"][0] == {"uid": "h1", "name": "h1", "type": "host", "ipv4-address": "192.0.2.1"}
    assert out["modified-objects"][0]["old-object"]["source"] == [
        {"uid": "h1", "name": "h1", "type": "host", "ipv4-address": "192.0.2.1"}
    ]


def test_ipv4_literals_rewritten_stably_into_documentation_ranges():
    text = rewrite_ipv4('["10.250.0.11", "10.250.0.11", "192.0.2.7", "8.8.8.8"]')
    assert json.loads(text) == ["192.0.2.1", "192.0.2.1", "192.0.2.7", "192.0.2.2"]


def test_field_names_collects_rule_keys_from_rulebase_and_changes(tmp_path):
    rb = tmp_path / "rb.json"
    rb.write_text(
        json.dumps(
            {
                "rulebase": [
                    {
                        "type": "access-section",
                        "rulebase": [{"uid": "r", "type": "access-rule", "vpn": [], "meta-info": {}}],
                    }
                ]
            }
        )
    )
    ch = tmp_path / "ch.json"
    ch.write_text(json.dumps(_wrapped(ENTRY)))
    assert field_names([rb, ch]) == {"access-rule": ["source", "type", "uid", "vpn"]}
