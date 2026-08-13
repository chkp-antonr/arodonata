from arodonata.cpcrud.models import (
    ActionResult,
    ApplyReport,
    DomainStamp,
    FieldDiff,
    IpConflictPolicy,
    NameConflictPolicy,
    ObjectMatch,
    Outcome,
    Plan,
    PlannedAction,
)


def test_fielddiff_has_changes():
    assert not FieldDiff().has_changes
    assert FieldDiff(changes={"ip-address": {"before": "1.1.1.1", "after": "2.2.2.2"}}).has_changes


def test_planned_action_to_result_and_plan_actions():
    action = PlannedAction(
        id="act-0001",
        operation="add",
        type="host",
        outcome=Outcome.CREATE,
        mgmt_name="m1",
        domain_name="d1",
        resolved_name="h1",
        resolved_uid="uid-1",
        matches=[ObjectMatch(name="h1", uid="uid-1", where_used_total=0)],
        command="add-host",
        payload={"name": "h1", "ip-address": "10.0.0.1"},
    )
    result = action.to_result()
    assert result.outcome == Outcome.CREATE
    assert result.name == "h1"
    assert result.matches[0].name == "h1"
    plan = Plan(actions=[action])
    assert len(plan.actions) == 1


def test_enums():
    assert NameConflictPolicy("update") is NameConflictPolicy.UPDATE
    assert IpConflictPolicy("create_new") is IpConflictPolicy.CREATE_NEW
    assert Outcome("unchanged") is Outcome.UNCHANGED


def test_v2_outcomes_exist():
    assert Outcome.CREATE == "create"
    assert Outcome.UNCHANGED == "unchanged"
    assert Outcome.LOCKED == "locked"
    assert Outcome.DRIFTED == "drifted"
    assert Outcome.SKIPPED_DEPENDENCY == "skipped_dependency"
    assert Outcome.PLAN_STALE == "plan_stale"
    assert IpConflictPolicy.CREATE_NEW == "create_new"


def test_plan_is_single_with_stamps():
    action = PlannedAction(
        id="act-0001",
        operation="add",
        type="host",
        mgmt_name="m1",
        domain_name="d1",
        resolved_name="h1",
    )
    plan = Plan(
        actions=[action],
        stamps=[DomainStamp(mgmt_name="m1", domain_name="d1", last_publish_session="uid-1")],
        template_hash="abc",
    )
    assert plan.actions[0].depends_on == []
    assert plan.stamps[0].last_publish_session == "uid-1"


def test_apply_report_summary_and_remaining():
    report = ApplyReport(
        results=[ActionResult(action_id="act-0001", outcome=Outcome.LOCKED, message="locked")],
        published_domains=[],
        remaining=Plan(actions=[], stamps=[], template_hash=""),
        summary={"locked": 1},
    )
    assert report.summary["locked"] == 1
    assert report.remaining is not None


def test_layer_info_shape():
    from arodonata.cpcrud.models import LayerInfo

    layer = LayerInfo(uid="u1", name="Network", type="access")
    assert layer.parent_layer_uid is None
    inline = LayerInfo(uid="u2", name="AppControl", type="access", parent_layer_uid="u1")
    assert inline.parent_layer_uid == "u1"


def test_section_info_shape():
    from arodonata.cpcrud.models import SectionInfo

    section = SectionInfo(uid="s1", name="Web Section", layer_uid="u1")
    assert section.layer_uid == "u1"


def test_rule_match_shape():
    from arodonata.cpcrud.models import RuleMatch

    match = RuleMatch(uid="r1", name="Allow-Web", rule_number=5, raw={"source": []})
    assert match.rule_number == 5
    assert match.raw == {"source": []}


def test_planned_action_carries_rule_fields():
    action = PlannedAction(
        id="act-0001",
        operation="add",
        type="access-rule",
        mgmt_name="m",
        domain_name="d",
        layer="Network",
        position={"bottom": "Web Section"},
        package=None,
    )
    assert action.layer == "Network"
    assert action.position == {"bottom": "Web Section"}
    assert action.package is None


def test_planned_action_layer_position_package_default_none():
    action = PlannedAction(id="act-0001", operation="add", type="host", mgmt_name="m", domain_name="d")
    assert action.layer is None
    assert action.position is None
    assert action.package is None
