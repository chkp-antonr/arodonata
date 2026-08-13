"""Naming-convention matching (FPCR conventions)."""

import pytest

from arodonata.cpcrud.naming import DEFAULT_PREFIXES, NamingPrefixes, matches_convention


@pytest.mark.parametrize(
    ("otype", "name", "expected"),
    [
        ("host", "Host_10.0.0.5", True),
        ("host", "global_Host_10.0.0.5", True),
        ("host", "ipr_10.0.0.5", True),  # legacy host convention
        ("host", "web-srv-01", False),
        ("network", "Net_192.168.1.0_24", True),
        ("network", "global_Net_10.0.0.0_8", True),
        ("network", "LAN-Segment", False),
        ("address-range", "IPR_10.0.0.1-10.0.0.9", True),
        ("address-range", "Range One", False),
        ("network-group", "AnyName", False),  # no convention for groups
    ],
)
def test_matches_convention(otype, name, expected):
    assert matches_convention(otype, name) is expected


def test_defaults_match_legacy_behavior():
    assert matches_convention("host", "Host_10.0.0.1")
    assert matches_convention("network", "global_Net_10.0.0.0_24")
    assert matches_convention("address-range", "IPR_10.0.0.1-10.0.0.9")
    assert not matches_convention("host", "web-server-1")


def test_from_settings_and_custom_prefix():
    class FakeSettings:
        cpcrud_auto_name_prefix_host = "H-"
        cpcrud_auto_name_prefix_network = "N-"
        cpcrud_auto_name_prefix_range = "R-"
        cpcrud_auto_name_prefix_svc_tcp = "T-"
        cpcrud_auto_name_prefix_svc_udp = "U-"
        cpcrud_auto_name_prefix_svc_icmp = "I-"

    p = NamingPrefixes.from_settings(FakeSettings())
    assert p.host == "H-"
    assert matches_convention("host", "H-10.0.0.1", p)
    assert not matches_convention("host", "Host_10.0.0.1", p)


def test_none_prefixes_uses_defaults():
    assert matches_convention("host", "Host_10.0.0.1", None)
    assert DEFAULT_PREFIXES.host == "Host_"
