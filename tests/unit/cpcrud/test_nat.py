"""NAT settings transformation (MMP semantics)."""

from arodonata.cpcrud.nat import transform_nat_settings


def test_none_passthrough():
    assert transform_nat_settings("host", None) is None
    assert transform_nat_settings("host", {}) is None


def test_hide_gateway_maps_to_install_on_and_auto_rule():
    out = transform_nat_settings("host", {"method": "hide", "gateway": "gw-01"})
    assert out == {"method": "hide", "install-on": "gw-01", "auto-rule": True}


def test_static_host_uses_ipv4_address():
    out = transform_nat_settings("host", {"method": "static", "ip-address": "1.2.3.4"})
    assert out == {"method": "static", "ipv4-address": "1.2.3.4", "auto-rule": True}


def test_static_network_uses_ip_address():
    out = transform_nat_settings("network", {"method": "static", "ipv4-address": "1.2.3.0"})
    assert out == {"method": "static", "ip-address": "1.2.3.0", "auto-rule": True}


def test_existing_auto_rule_not_overridden():
    out = transform_nat_settings("host", {"method": "hide", "gateway": "gw", "auto-rule": False})
    assert out["auto-rule"] is False


def test_input_not_mutated():
    src = {"method": "hide", "gateway": "gw"}
    transform_nat_settings("host", src)
    assert src == {"method": "hide", "gateway": "gw"}
