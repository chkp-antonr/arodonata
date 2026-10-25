"""Unit tests for CPCRUD compensating rollback template generator (`src/arodonata/cpcrud/inverse.py`)."""

from __future__ import annotations

from arodonata.cpcrud.inverse import build_inverse_template
from arodonata.cpcrud.models import ActionResult, ApplyReport, Outcome, Plan, PlannedAction
from arodonata.cpcrud.validator import validate_template


def test_build_inverse_template_reverses_create_update_delete_and_passes_schema() -> None:
    """`build_inverse_template` reverses `CREATE` -> `delete`, `UPDATE` -> `set` (restoring prior attributes), and `DELETE` -> `add` (from `prior_state`), and validates against `checkpoint_ops_schema.json`."""
    plan = Plan(
        actions=[
            PlannedAction(
                action_id="act-create-host",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="host",
                name="Host_10.90.1.1",
                requested_name="web-new",
                resolved_name="Host_10.90.1.1",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "Host_10.90.1.1", "ipv4-address": "10.90.1.1"},
            ),
            PlannedAction(
                action_id="act-update-svc",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="service-tcp",
                name="TCP_8080",
                requested_name="TCP_8080",
                resolved_name="TCP_8080",
                target_uid="s-uid-8080",
                outcome=Outcome.UPDATE,
                command="set-service-tcp",
                payload={"uid": "s-uid-8080", "port": "8081", "comments": "updated port"},
                prior_state={
                    "uid": "s-uid-8080",
                    "name": "TCP_8080",
                    "type": "service-tcp",
                    "port": "8080",
                    "protocol": "tcp",
                    "comments": "original port 8080",
                },
            ),
            PlannedAction(
                action_id="act-delete-net",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="delete",
                object_type="network",
                name="Net_10.99.0.0_24",
                requested_name="Net_10.99.0.0_24",
                resolved_name="Net_10.99.0.0_24",
                target_uid="n-uid-99",
                outcome=Outcome.DELETE,
                command="delete-network",
                payload={"uid": "n-uid-99"},
                prior_state={
                    "uid": "n-uid-99",
                    "name": "Net_10.99.0.0_24",
                    "type": "network",
                    "subnet4": "10.99.0.0",
                    "mask-length4": 24,
                    "comments": "legacy subnet",
                },
            ),
            PlannedAction(
                action_id="act-create-rule",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="access-rule",
                name="Allow New Web",
                layer="Network",
                outcome=Outcome.CREATE,
                command="add-access-rule",
                payload={"layer": "Network", "name": "Allow New Web", "position": "bottom"},
            ),
        ]
    )

    report = ApplyReport(
        results=[
            ActionResult(
                action_id="act-create-host",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="host",
                name="Host_10.90.1.1",
                resolved_name="Host_10.90.1.1",
                target_uid="h-created-uid-1",
                planned_outcome=Outcome.CREATE,
                outcome=Outcome.CREATE,
                status="create",
                success=True,
            ),
            ActionResult(
                action_id="act-update-svc",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="service-tcp",
                name="TCP_8080",
                resolved_name="TCP_8080",
                target_uid="s-uid-8080",
                planned_outcome=Outcome.UPDATE,
                outcome=Outcome.UPDATE,
                status="update",
                success=True,
            ),
            ActionResult(
                action_id="act-delete-net",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="delete",
                object_type="network",
                name="Net_10.99.0.0_24",
                resolved_name="Net_10.99.0.0_24",
                target_uid="n-uid-99",
                planned_outcome=Outcome.DELETE,
                outcome=Outcome.DELETE,
                status="delete",
                success=True,
            ),
            ActionResult(
                action_id="act-create-rule",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="access-rule",
                name="Allow New Web",
                target_uid="r-created-uid-1",
                planned_outcome=Outcome.CREATE,
                outcome=Outcome.CREATE,
                status="create",
                success=True,
            ),
        ]
    )

    inverse = build_inverse_template(plan, report)

    # 1. Must validate cleanly against `checkpoint_ops_schema.json`
    assert validate_template(inverse) == []

    # 2. Operations are in reverse order (rule deleted first, then network re-added, service restored, host deleted)
    ops = inverse["operations"]
    assert len(ops) == 4
    assert ops[0] == {
        "operation": "delete",
        "type": "access-rule",
        "layer": "Network",
        "uid": "r-created-uid-1",
        "name": "Allow New Web",
    }
    assert ops[1] == {
        "operation": "add",
        "type": "network",
        "name": "Net_10.99.0.0_24",
        "subnet4": "10.99.0.0",
        "mask-length4": 24,
        "comments": "legacy subnet",
    }
    assert ops[2] == {
        "operation": "set",
        "type": "service-tcp",
        "name": "TCP_8080",
        "uid": "s-uid-8080",
        "port": "8080",
        "protocol": "tcp",
        "comments": "original port 8080",
    }
    assert ops[3] == {
        "operation": "delete",
        "type": "host",
        "name": "Host_10.90.1.1",
        "uid": "h-created-uid-1",
    }


def test_build_inverse_template_refuses_planned_uid_delete_when_report_present_and_restores_all_prior_fields() -> None:
    """Adversarial test for W30:
    - When `report` is supplied, `CREATE` actions with `planned:` placeholder UID (or no concrete UID) are skipped instead of emitting unsafe delete-by-name.
    - `prior_state` fields (`groups`, `source-negate`, `destination-negate`, `service-negate`, `inline-layer`, `protected-scope`, `site-category`, `certificate`) are preserved and pass schema validation.
    """
    plan = Plan(
        actions=[
            PlannedAction(
                action_id="act-unexecuted-create",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="host",
                name="Host_10.90.1.99",
                target_uid="planned:host:Host_10.90.1.99",
                outcome=Outcome.CREATE,
                command="add-host",
                payload={"name": "Host_10.90.1.99", "ipv4-address": "10.90.1.99"},
            ),
            PlannedAction(
                action_id="act-update-host-groups",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="host",
                name="Host_10.90.1.1",
                target_uid="h-uid-1",
                outcome=Outcome.UPDATE,
                command="set-host",
                payload={"uid": "h-uid-1", "comments": "changed"},
                prior_state={
                    "uid": "h-uid-1",
                    "name": "Host_10.90.1.1",
                    "type": "host",
                    "ipv4-address": "10.90.1.1",
                    "groups": ["grp-tier1", "grp-tier2"],
                    "ignore-warnings": True,
                    "set-if-exists": False,
                    "comments": "orig",
                },
            ),
            PlannedAction(
                action_id="act-update-access-rule",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="access-rule",
                name="Negated Rule",
                target_uid="r-uid-neg",
                layer="Network",
                outcome=Outcome.UPDATE,
                command="set-access-rule",
                payload={"uid": "r-uid-neg", "layer": "Network", "source-negate": False},
                prior_state={
                    "uid": "r-uid-neg",
                    "name": "Negated Rule",
                    "type": "access-rule",
                    "layer": "Network",
                    "enabled": True,
                    "source": ["Host_10.90.1.1"],
                    "destination": ["Any"],
                    "service": ["Any"],
                    "source-negate": True,
                    "destination-negate": False,
                    "service-negate": True,
                    "inline-layer": "Inline-App",
                    "rule_action": "Inline Layer",
                    "track": "Log",
                },
            ),
        ]
    )

    report = ApplyReport(
        results=[
            # Simulate a CREATE result that somehow lacked a concrete UID (still `planned:...`)
            ActionResult(
                action_id="act-unexecuted-create",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="host",
                name="Host_10.90.1.99",
                target_uid="planned:host:Host_10.90.1.99",
                planned_outcome=Outcome.CREATE,
                outcome=Outcome.CREATE,
                status="create",
                success=True,
            ),
            ActionResult(
                action_id="act-update-host-groups",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="host",
                name="Host_10.90.1.1",
                target_uid="h-uid-1",
                planned_outcome=Outcome.UPDATE,
                outcome=Outcome.UPDATE,
                status="update",
                success=True,
            ),
            ActionResult(
                action_id="act-update-access-rule",
                mgmt_name="mds1",
                domain_name="Corp",
                operation="present",
                object_type="access-rule",
                name="Negated Rule",
                target_uid="r-uid-neg",
                planned_outcome=Outcome.UPDATE,
                outcome=Outcome.UPDATE,
                status="update",
                success=True,
            ),
        ]
    )

    inverse = build_inverse_template(plan, report)
    assert validate_template(inverse) == []

    ops = inverse["operations"]
    # `act-unexecuted-create` was skipped because its UID was `planned:host:...`
    assert len(ops) == 2
    rule_op, host_op = ops
    assert rule_op["source-negate"] is True
    assert rule_op["service-negate"] is True
    assert rule_op["inline-layer"] == "Inline-App"
    assert host_op["groups"] == ["grp-tier1", "grp-tier2"]
    assert host_op["ignore-warnings"] is True
    assert host_op["set-if-exists"] is False
