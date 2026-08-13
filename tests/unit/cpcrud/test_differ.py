from arodonata.cpcrud.differ import diff_object
from arodonata.cpcrud.models import ObjectState


def _host(raw):
    return ObjectState(uid=raw.get("uid", "u"), name=raw.get("name", "n"), type="host", raw=raw)


def test_identical_host_no_changes():
    desired = {"name": "h1", "ip-address": "10.0.0.1", "comments": "c", "groups": ["A", "B"]}
    existing = _host({"uid": "u1", "name": "h1", "ipv4-address": "10.0.0.1", "comments": "c", "groups": ["B", "A"]})
    assert not diff_object("host", desired, existing).has_changes  # order-agnostic groups


def test_ip_change_detected():
    desired = {"name": "h1", "ip-address": "10.0.0.2"}
    existing = _host({"uid": "u1", "name": "h1", "ipv4-address": "10.0.0.1"})
    d = diff_object("host", desired, existing)
    assert d.has_changes
    assert d.changes["ip-address"] == {"before": "10.0.0.1", "after": "10.0.0.2"}


def test_network_mask_length_vs_dotted():
    desired = {"name": "n1", "subnet": "192.168.1.0", "mask-length": 24}
    existing = ObjectState(
        uid="u",
        name="n1",
        type="network",
        raw={"uid": "u", "name": "n1", "subnet4": "192.168.1.0", "subnet-mask": "255.255.255.0"},
    )
    assert not diff_object("network", desired, existing).has_changes


def test_nat_settings_compared_after_transformation():
    existing = ObjectState(
        uid="u1",
        name="h1",
        type="host",
        raw={
            "ipv4-address": "10.0.0.1",
            "nat-settings": {"method": "hide", "install-on": "gw-01", "auto-rule": True},
        },
    )
    desired = {"ip-address": "10.0.0.1", "nat-settings": {"method": "hide", "gateway": "gw-01"}}
    assert diff_object("host", desired, existing).has_changes is False


def test_dict_shaped_groups_no_change():
    # The Management API (details-level "full") returns "groups" as a list of nested
    # objects, not bare strings. The template's desired side is always plain names.
    desired = {"name": "h1", "ip-address": "10.0.0.1", "groups": ["Examples"]}
    existing = _host(
        {
            "uid": "u1",
            "name": "h1",
            "ipv4-address": "10.0.0.1",
            "groups": [
                {"name": "Examples", "uid": "some-uid", "type": "group", "domain": {"name": "SMC User"}},
            ],
        }
    )
    assert diff_object("host", desired, existing).has_changes is False


def test_dict_shaped_groups_change_detected():
    desired = {"name": "h1", "ip-address": "10.0.0.1", "groups": ["Other"]}
    existing = _host(
        {
            "uid": "u1",
            "name": "h1",
            "ipv4-address": "10.0.0.1",
            "groups": [
                {"name": "Examples", "uid": "some-uid", "type": "group", "domain": {"name": "SMC User"}},
            ],
        }
    )
    d = diff_object("host", desired, existing)
    assert d.has_changes
    assert "groups" in d.changes


def test_crud_example_yaml_host_groups_idempotent():
    # Mirrors examples/crud_example.yaml's "example-host-1" entry: desired groups=["Examples"],
    # applied a second time against the live API state (dict-shaped "groups") must be a no-op.
    desired = {
        "name": "example-host-1",
        "ip-address": "10.0.0.1",
        "comments": "CPCRUD example host",
        "color": "dark green",
        "groups": ["Examples"],
    }
    existing = _host(
        {
            "uid": "u1",
            "name": "example-host-1",
            "ipv4-address": "10.0.0.1",
            "comments": "CPCRUD example host",
            "color": "dark green",
            "groups": [
                {"name": "Examples", "uid": "some-uid", "type": "group", "domain": {"name": "SMC User"}},
            ],
        }
    )
    assert diff_object("host", desired, existing).has_changes is False


def test_icmp_type_int_vs_str_no_spurious_change():
    desired = {"name": "h1", "icmp-type": 8}
    existing = ObjectState(uid="u", name="h1", type="icmp-service", raw={"icmp-type": "8"})
    assert diff_object("icmp-service", desired, existing).has_changes is False


def test_icmp_type_real_change_detected():
    desired = {"name": "h1", "icmp-type": 8}
    existing = ObjectState(uid="u", name="h1", type="icmp-service", raw={"icmp-type": "0"})
    d = diff_object("icmp-service", desired, existing)
    assert d.has_changes
    assert d.changes["icmp-type"] == {"before": "0", "after": 8}
