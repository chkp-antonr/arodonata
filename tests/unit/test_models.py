"""Unit tests for human-readable composite identifiers on CPObject, GroupMembershipNode, CPService, and Asset."""

from __future__ import annotations

from arodonata.core.models import Asset, CPObject, CPService, GroupMembershipNode


def test_cp_object_and_group_membership_node_composite_ids() -> None:
    """Verify CPObject and GroupMembershipNode auto-populate id and object_id."""
    obj = CPObject(uid="u-1", name="hWebHost", type="host", mgmt_name="mds", domain_name="General")
    assert obj.id == "mds:General:u-1"
    assert obj.object_id == "mds:General:hWebHost"

    node = GroupMembershipNode(
        uid="g-1",
        name="grp-web",
        mgmt_name="mds",
        domain_name="General",
        depth=1,
        parent_uids=["g-parent"],
        parent_object_ids=["mds:General:grp-parent"],
    )
    assert node.id == "mds:General:g-1"
    assert node.object_id == "mds:General:grp-web"
    assert node.parent_object_ids == ["mds:General:grp-parent"]


def test_cp_service_and_asset_composite_ids() -> None:
    """Verify CPService and Asset auto-populate service_id, asset_id, parent_id, and parent_asset_id."""
    svc = CPService.from_cp_dict(
        "mds",
        "General",
        {"uid": "s-1", "name": "tcp-443", "type": "service-tcp", "port": "443"},
    )
    assert svc.id == "mds:General:s-1"
    assert svc.service_id == "mds:General:tcp-443"

    member = Asset(
        uid="m-1",
        name="gw-node-1",
        type="cluster-member",
        mgmt_name="mds",
        domain_name="General",
        parent_uid="c-1",
        parent_name="gw-cluster",
    )
    assert member.id == "mds:General:m-1"
    assert member.asset_id == "mds:General:gw-node-1"
    assert member.parent_id == "mds:General:c-1"
    assert member.parent_asset_id == "mds:General:gw-cluster"
