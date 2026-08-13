"""Tests for ChangeProcessor (parsing show-changes API responses)."""

from arodonata.core.change_processor import ChangeProcessor, ChangeType, ObjectChange


def _change(uid, obj_type="host", change_type="add", name="n", **extra):
    return {
        "uid": uid,
        "type": obj_type,
        "change-type": change_type,
        "name": name,
        **extra,
    }


def test_parse_changes_maps_all_change_types():
    processor = ChangeProcessor()
    response = {
        "success": True,
        "data": {
            "changes": [
                _change("uid-001", "host", "add", "new-host"),
                _change("uid-002", "network", "set", "updated-network"),
                _change("uid-003", "group", "delete", "deleted-group"),
            ]
        },
    }

    changes = processor.parse_changes(response)

    assert len(changes) == 3
    assert changes[0].change_type == ChangeType.ADD
    assert changes[1].change_type == ChangeType.UPDATE  # "set" -> UPDATE
    assert changes[2].change_type == ChangeType.DELETE
    assert changes[0].object_type == "host"
    assert changes[1].name == "updated-network"


def test_parse_changes_preserves_raw_data():
    processor = ChangeProcessor()
    response = {"data": {"changes": [_change("u1", ipv4_address="192.168.1.10", color="red")]}}

    changes = processor.parse_changes(response)

    assert changes[0].raw_data["ipv4_address"] == "192.168.1.10"
    assert changes[0].raw_data["color"] == "red"


def test_parse_changes_empty_list():
    assert ChangeProcessor().parse_changes({"data": {"changes": []}}) == []


def test_parse_changes_missing_data_field():
    assert ChangeProcessor().parse_changes({"success": True}) == []


def test_parse_changes_non_list_changes_returns_empty():
    # data.changes present but not a list -> defensive empty return.
    assert ChangeProcessor().parse_changes({"data": {"changes": {"oops": 1}}}) == []


def test_parse_changes_skips_non_dict_entries():
    processor = ChangeProcessor()
    response = {"data": {"changes": ["not-a-dict", _change("u1")]}}

    changes = processor.parse_changes(response)

    assert len(changes) == 1
    assert changes[0].uid == "u1"


def test_parse_changes_skips_unknown_change_type():
    processor = ChangeProcessor()
    response = {
        "data": {
            "changes": [
                _change("u1", change_type="add"),
                _change("r1", change_type="rename"),  # unmodeled -> dropped
            ]
        }
    }

    changes = processor.parse_changes(response)

    assert [c.uid for c in changes] == ["u1"]


def test_parse_changes_defaults_missing_fields():
    processor = ChangeProcessor()
    # change-type present/known but other fields missing -> empty-string defaults.
    changes = processor.parse_changes({"data": {"changes": [{"change-type": "add"}]}})

    assert len(changes) == 1
    assert changes[0].uid == ""
    assert changes[0].object_type == ""
    assert changes[0].name == ""


def test_group_by_object_type():
    processor = ChangeProcessor()
    changes = [
        ObjectChange("u1", "host", ChangeType.ADD, "h1", {}),
        ObjectChange("u2", "network", ChangeType.UPDATE, "n1", {}),
        ObjectChange("u3", "host", ChangeType.DELETE, "h2", {}),
    ]

    grouped = processor.group_by_object_type(changes)

    assert [c.uid for c in grouped["host"]] == ["u1", "u3"]
    assert [c.uid for c in grouped["network"]] == ["u2"]


def test_filter_by_change_type():
    processor = ChangeProcessor()
    changes = [
        ObjectChange("u1", "host", ChangeType.ADD, "h1", {}),
        ObjectChange("u2", "network", ChangeType.UPDATE, "n1", {}),
        ObjectChange("u3", "host", ChangeType.DELETE, "h2", {}),
    ]

    assert [c.uid for c in processor.filter_by_change_type(changes, ChangeType.ADD)] == ["u1"]
    assert [c.uid for c in processor.filter_by_change_type(changes, ChangeType.DELETE)] == ["u3"]


def test_get_adds_and_updates_excludes_deletes():
    processor = ChangeProcessor()
    changes = [
        ObjectChange("u1", "host", ChangeType.ADD, "h1", {}),
        ObjectChange("u2", "network", ChangeType.UPDATE, "n1", {}),
        ObjectChange("u3", "host", ChangeType.DELETE, "h2", {}),
    ]

    non_deletes = processor.get_adds_and_updates(changes)

    assert {c.uid for c in non_deletes} == {"u1", "u2"}
    assert all(c.change_type != ChangeType.DELETE for c in non_deletes)


# ---------------------------------------------------------------------------
# Real CP response shape: task-wrapped, session-grouped operations
# (captured live from R81 show-changes; see integration medium tier)
# ---------------------------------------------------------------------------


def _real_response(operations: dict, more_sessions: list[dict] | None = None) -> dict:
    """Build a show-changes response in the real task-wrapped CP shape."""
    changes = [{"session": {"session-uid": "s-1", "session-name": "probe"}, "operations": operations}]
    for ops in more_sessions or []:
        changes.append({"session": {"session-uid": "s-n"}, "operations": ops})
    return {
        "data": {
            "tasks": [
                {
                    "task-id": "t-1",
                    "status": "succeeded",
                    "task-details": [
                        {
                            "limit": 10,
                            "offset": 0,
                            "from": 1,
                            "to": len(changes),
                            "total": len(changes),
                            "changes": changes,
                        }
                    ],
                }
            ]
        }
    }


def test_parse_real_shape_added_objects():
    response = _real_response(
        {
            "added-objects": [
                {
                    "uid": "u-add",
                    "name": "hostX",
                    "type": "host",
                    "ipv4-address": "10.0.0.9",
                }
            ]
        }
    )
    changes = ChangeProcessor().parse_changes(response)
    assert len(changes) == 1
    c = changes[0]
    assert (c.uid, c.name, c.object_type) == ("u-add", "hostX", "host")
    assert c.change_type == ChangeType.ADD
    assert c.raw_data["ipv4-address"] == "10.0.0.9"


def test_parse_real_shape_modified_and_deleted_objects():
    response = _real_response(
        {
            "modified-objects": [{"uid": "u-mod", "name": "n1", "type": "network"}],
            "deleted-objects": [{"uid": "u-del", "name": "g1", "type": "group"}],
        }
    )
    changes = ChangeProcessor().parse_changes(response)
    by_uid = {c.uid: c for c in changes}
    assert by_uid["u-mod"].change_type == ChangeType.UPDATE
    assert by_uid["u-del"].change_type == ChangeType.DELETE


def test_parse_real_shape_multiple_sessions_accumulate():
    response = _real_response(
        {"added-objects": [{"uid": "u1", "name": "a", "type": "host"}]},
        more_sessions=[{"deleted-objects": [{"uid": "u2", "name": "b", "type": "host"}]}],
    )
    changes = ChangeProcessor().parse_changes(response)
    assert {c.uid for c in changes} == {"u1", "u2"}


def test_parse_real_shape_skips_entries_without_uid_or_non_dict():
    response = _real_response(
        {
            "added-objects": [
                {"name": "no-uid", "type": "host"},
                "not-a-dict",
                {"uid": "u-ok", "name": "ok", "type": "host"},
            ]
        }
    )
    changes = ChangeProcessor().parse_changes(response)
    assert [c.uid for c in changes] == ["u-ok"]


def test_parse_real_shape_empty_operations_yields_no_changes():
    response = _real_response({})
    assert ChangeProcessor().parse_changes(response) == []


def test_parse_legacy_flat_shape_still_supported():
    """The pre-existing flat data["changes"] shape keeps parsing (unit fixtures)."""
    response = {"data": {"changes": [{"change-type": "add", "uid": "u-legacy", "type": "host", "name": "l1"}]}}
    changes = ChangeProcessor().parse_changes(response)
    assert len(changes) == 1
    assert changes[0].uid == "u-legacy"
    assert changes[0].change_type == ChangeType.ADD
