"""Tests for arodonata.models.domains Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arodonata.models import Domain, Gateway, Group, Host, Network


class TestDomain:
    def test_construction_with_typical_fields(self):
        domain = Domain(
            uid="uid-d1",
            name="Domain1",
            active_mds="mds1",
            active_ip="1.2.3.4",
            active_server="server1",
            mgmt_name="mgmt1",
        )
        assert domain.uid == "uid-d1"
        assert domain.name == "Domain1"
        assert domain.is_mdm is False
        assert domain.standby_ips == []
        assert domain.standby_servers == []

    def test_standby_lists_can_be_populated(self):
        domain = Domain(
            uid="uid-d1",
            name="Domain1",
            active_mds="mds1",
            active_ip="1.2.3.4",
            active_server="server1",
            standby_ips=["1.2.3.5"],
            standby_servers=["server2"],
            mgmt_name="mgmt1",
            is_mdm=True,
        )
        assert domain.standby_ips == ["1.2.3.5"]
        assert domain.standby_servers == ["server2"]
        assert domain.is_mdm is True

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            Domain(uid="uid-d1", name="Domain1")  # type: ignore[call-arg]

    def test_raw_data_default_and_override(self):
        domain = Domain(
            uid="uid-d1",
            name="Domain1",
            active_mds="mds1",
            active_ip="1.2.3.4",
            active_server="server1",
            mgmt_name="mgmt1",
        )
        assert domain.raw_data == {}

        raw_data = {"custom": "value"}
        domain2 = Domain(
            uid="uid-d1",
            name="Domain1",
            active_mds="mds1",
            active_ip="1.2.3.4",
            active_server="server1",
            mgmt_name="mgmt1",
            raw_data=raw_data,
        )
        assert domain2.raw_data == raw_data

    def test_extra_field_ignored(self):
        domain = Domain(
            uid="uid-d1",
            name="Domain1",
            active_mds="mds1",
            active_ip="1.2.3.4",
            active_server="server1",
            mgmt_name="mgmt1",
            unknown_field="ignored",
        )
        assert not hasattr(domain, "unknown_field")


class TestGateway:
    def test_construction_and_defaults(self):
        gw = Gateway(
            uid="uid-gw1",
            name="gw1",
            type="simple-gateway",
            ip_address="10.0.0.1",
            mgmt_name="mgmt1",
        )
        assert gw.ssh_ip == ""
        assert gw.domain_name == ""
        assert gw.parent_uid is None

    def test_parent_uid_can_be_set(self):
        gw = Gateway(
            uid="uid-gw1",
            name="gw1",
            type="simple-gateway",
            ip_address="10.0.0.1",
            mgmt_name="mgmt1",
            parent_uid="uid-parent",
        )
        assert gw.parent_uid == "uid-parent"


class TestHost:
    def test_construction_with_defaults(self):
        host = Host(uid="uid-h1", name="host1", mgmt_name="mgmt1")
        assert host.ip_address == ""
        assert host.domain_name == ""

    def test_construction_with_ip(self):
        host = Host(uid="uid-h1", name="host1", ip_address="10.0.0.5", mgmt_name="mgmt1")
        assert host.ip_address == "10.0.0.5"

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            Host(uid="uid-h1")  # type: ignore[call-arg]


class TestNetwork:
    def test_construction_with_defaults(self):
        net = Network(uid="uid-n1", name="net1", mgmt_name="mgmt1")
        assert net.subnet4 == ""
        assert net.subnet_mask == ""

    def test_construction_with_subnet(self):
        net = Network(
            uid="uid-n1",
            name="net1",
            subnet4="192.168.1.0",
            subnet_mask="255.255.255.0",
            mgmt_name="mgmt1",
        )
        assert net.subnet4 == "192.168.1.0"
        assert net.subnet_mask == "255.255.255.0"


class TestGroup:
    def test_construction_with_defaults(self):
        group = Group(uid="uid-g1", name="group1", mgmt_name="mgmt1")
        assert group.member_uids == []

    def test_construction_with_members(self):
        group = Group(
            uid="uid-g1",
            name="group1",
            member_uids=["uid-h1", "uid-h2"],
            mgmt_name="mgmt1",
        )
        assert group.member_uids == ["uid-h1", "uid-h2"]

    def test_mutable_default_not_shared_between_instances(self):
        group1 = Group(uid="uid-g1", name="group1", mgmt_name="mgmt1")
        group2 = Group(uid="uid-g2", name="group2", mgmt_name="mgmt1")
        group1.member_uids.append("uid-h1")
        assert group2.member_uids == []
