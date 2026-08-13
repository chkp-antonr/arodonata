# tests/unit/cpcrud/test_inverse.py
from arodonata.cpcrud.inverse import build_inverse_template
from arodonata.cpcrud.models import ActionResult, ApplyReport, Outcome, Plan, PlannedAction
from arodonata.cpcrud.schema import validate_template


def _act(**kw):
    base = dict(id="act-0001", operation="add", type="host", mgmt_name="m", domain_name="d")
    return PlannedAction(**{**base, **kw})


def test_create_inverts_to_delete_by_name():
    plan = Plan(actions=[_act(outcome=Outcome.CREATE, resolved_name="h1")])
    tpl = build_inverse_template(plan)
    ops = tpl["management_servers"][0]["domains"][0]["operations"]
    assert ops == [{"operation": "delete", "type": "host", "key": {"name": "h1"}}]
    assert validate_template(tpl) == []


def test_create_inverts_to_delete_by_uid_when_report_given():
    plan = Plan(actions=[_act(outcome=Outcome.CREATE, resolved_name="h1")])
    report = ApplyReport(results=[ActionResult(action_id="act-0001", outcome=Outcome.CREATE, uid="u-9")])
    tpl = build_inverse_template(plan, report)
    op = tpl["management_servers"][0]["domains"][0]["operations"][0]
    assert op["key"] == {"uid": "u-9"}


def test_update_inverts_with_before_values():
    plan = Plan(
        actions=[
            _act(
                operation="update",
                outcome=Outcome.UPDATE,
                resolved_name="h1",
                key={"name": "h1"},
                changes={"color": {"before": "red", "after": "blue"}, "comments": {"before": None, "after": "x"}},
            )
        ]
    )
    op = build_inverse_template(plan)["management_servers"][0]["domains"][0]["operations"][0]
    assert op["operation"] == "update" and op["data"]["color"] == "red"
    assert "comments" not in op["data"]  # before=None -> field wasn't set; cannot restore, skip
    assert validate_template(build_inverse_template(plan)) == []


def test_delete_inverts_to_add_from_prior_state():
    plan = Plan(
        actions=[
            _act(
                operation="delete",
                outcome=Outcome.DELETE,
                resolved_name="h1",
                prior_state={
                    "uid": "u-1",
                    "name": "h1",
                    "ipv4-address": "10.0.0.1",
                    "color": "red",
                    "meta-info": {"lock": "unlocked"},
                    "domain": {"name": "d"},
                },
            )
        ]
    )
    tpl = build_inverse_template(plan)
    op = tpl["management_servers"][0]["domains"][0]["operations"][0]
    assert op["operation"] == "add" and op["type"] == "host"
    assert op["data"] == {"name": "h1", "ip-address": "10.0.0.1", "color": "red"}
    assert validate_template(tpl) == []


def test_rule_delete_inverts_to_add_with_position():
    plan = Plan(
        actions=[
            _act(
                operation="delete",
                type="access-rule",
                outcome=Outcome.DELETE,
                layer="Network",
                resolved_name="r1",
                prior_state={
                    "name": "r1",
                    "source": ["Any"],
                    "destination": ["Any"],
                    "service": ["Any"],
                    "action": "Drop",
                    "enabled": True,
                    "_rule_number": 7,
                },
            )
        ]
    )
    tpl = build_inverse_template(plan)
    op = tpl["management_servers"][0]["domains"][0]["operations"][0]
    assert op["operation"] == "add" and op["layer"] == "Network" and op["position"] == 7
    assert op["data"]["action"] == "Drop"
    assert validate_template(tpl) == []


def test_delete_with_minimal_prior_state_stub_does_not_crash():
    # theoretical edge case: a corrupted cache row leaves prior_state as a 2-key stub --
    # nothing restorable survives stripping, so the action is skipped rather than emitting
    # a schema-invalid add (e.g. a host missing its required ip-address).
    plan = Plan(
        actions=[
            _act(
                operation="delete", outcome=Outcome.DELETE, resolved_name="h1", prior_state={"uid": "u-1", "name": "h1"}
            )
        ]
    )
    tpl = build_inverse_template(plan)
    assert tpl["management_servers"] == []
    assert validate_template(tpl) == []


def test_noops_failures_and_report_filtered_actions_are_omitted():
    plan = Plan(
        actions=[
            _act(id="act-0001", outcome=Outcome.UNCHANGED),
            _act(id="act-0002", outcome=Outcome.REUSE),
            _act(id="act-0003", outcome=Outcome.ERROR),
            _act(id="act-0004", outcome=Outcome.CREATE, resolved_name="h4"),
        ]
    )
    report = ApplyReport(results=[ActionResult(action_id="act-0004", outcome=Outcome.LOCKED)])
    assert build_inverse_template(plan)["management_servers"][0]["domains"][0]["operations"] != []
    # with report: act-0004 never executed (locked) -> nothing to invert
    tpl = build_inverse_template(plan, report)
    assert tpl["management_servers"] == []


def test_multi_domain_grouping_preserved():
    plan = Plan(
        actions=[
            _act(id="act-0001", outcome=Outcome.CREATE, resolved_name="a"),
            _act(id="act-0002", outcome=Outcome.CREATE, resolved_name="b", domain_name="d2"),
        ]
    )
    tpl = build_inverse_template(plan)
    domains = tpl["management_servers"][0]["domains"]
    assert [d["name"] for d in domains] == ["d", "d2"]
