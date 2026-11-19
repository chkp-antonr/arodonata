"""Unit tests for CPCRUD `NamingPrefixes` formatting profiles and schema validation."""

from __future__ import annotations

import pytest

from arodonata import NamingPrefixes as RootNamingPrefixes
from arodonata.cpcrud import NamingPrefixes, validate_template
from arodonata.cpcrud.models import NamingPrefixes as ModelsNamingPrefixes


@pytest.mark.spec("SCN-CPCRUD-002-2")
def test_naming_prefixes_legacy_defaults_preserved() -> None:
    """Default `NamingPrefixes()` preserves all backward-compatible formatting outputs."""
    assert NamingPrefixes is ModelsNamingPrefixes
    assert NamingPrefixes is RootNamingPrefixes

    prefixes = NamingPrefixes()
    assert prefixes.format_host("10.1.1.1") == "Host_10.1.1.1"
    assert prefixes.format_network("10.1.1.0", 24) == "Net_10.1.1.0_24"
    assert prefixes.format_address_range("10.1.1.1", "10.1.1.9") == "IPR_10.1.1.1-10.1.1.9"
    assert prefixes.format_group("WebServers") == "grpWebServers"
    assert prefixes.format_group("grpWebServers") == "grpWebServers"
    assert prefixes.format_tcp(443) == "TCP_443"
    assert prefixes.format_udp("53") == "UDP_53"
    assert prefixes.format_icmp(8) == "ICMP_8"
    assert prefixes.format_icmp(8, 0) == "ICMP_8_0"
    assert prefixes.format_app_site("example.com") == "Site_example.com"
    assert prefixes.format_app_site("chinacloudapi.cn", is_wildcard=True) == "Site__chinacloudapi.cn"


@pytest.mark.spec("SCN-CPCRUD-002-1", "SCN-CPCRUD-002-3", "SCN-CPCRUD-002-4")
def test_naming_prefixes_customer_profile_range_group_and_app_site() -> None:
    """Customer profile supports compressed same-/24 ranges, group suffixes, and wildcard markers."""
    profile = NamingPrefixes(
        address_range="Range_",
        range_separator="_",
        compress_range_same_subnet=True,
        group="",
        group_suffix="_Grp",
        app_site="Site_",
        app_site_wildcard_marker="_",
    )

    # Same /24 subnet compresses last octet
    assert profile.format_address_range("10.1.1.1", "10.1.1.9") == "Range_10.1.1.1_9"
    # Distinct /24 prefixes keep full end IPv4
    assert profile.format_address_range("10.1.1.1", "10.1.2.9") == "Range_10.1.1.1_10.1.2.9"
    # Group suffix without double suffixing
    assert profile.format_group("AppAccess") == "AppAccess_Grp"
    assert profile.format_group("AppAccess_Grp") == "AppAccess_Grp"
    # Wildcard application site strips `*` and applies marker cleanly
    assert profile.format_app_site("*chinacloudapi.cn") == "Site__chinacloudapi.cn"
    assert profile.format_app_site("*.chinacloudapi.cn") == "Site__chinacloudapi.cn"
    assert profile.format_app_site("chinacloudapi.cn", is_wildcard=True) == "Site__chinacloudapi.cn"
    assert profile.format_app_site("chinacloudapi.cn", is_wildcard=False) == "Site_chinacloudapi.cn"
    assert "*" not in profile.format_app_site("*.chinacloudapi.cn")


def test_naming_prefixes_from_mapping_and_schema_validation() -> None:
    """`from_mapping` normalizes kebab-case and `service_*` aliases and passes template schema validation."""
    mapped = NamingPrefixes.from_mapping(
        {
            "host": "H_",
            "network": "N_",
            "address-range": "Range_",
            "range-separator": "_",
            "compress-range-same-subnet": True,
            "group": "",
            "group-suffix": "_Grp",
            "service-tcp": "T_",
            "service_udp": "U_",
            "service-icmp": "I_",
            "app-site": "App_",
            "app-site-wildcard-marker": "Wild_",
        }
    )
    assert mapped.format_host("192.0.2.1") == "H_192.0.2.1"
    assert mapped.format_network("192.0.2.0", 24) == "N_192.0.2.0_24"
    assert mapped.format_address_range("192.0.2.10", "192.0.2.20") == "Range_192.0.2.10_20"
    assert mapped.format_group("DMZ") == "DMZ_Grp"
    assert mapped.format_tcp(8443) == "T_8443"
    assert mapped.format_udp(5353) == "U_5353"
    assert mapped.format_icmp(8) == "I_8"
    assert mapped.format_app_site("*.example.org") == "App_Wild_example.org"

    template = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "naming_prefixes": {
            "address_range": "Range_",
            "range_separator": "_",
            "compress_range_same_subnet": True,
            "group": "",
            "group_suffix": "_Grp",
            "app_site": "Site_",
            "app_site_wildcard_marker": "_",
        },
        "objects": [{"type": "host", "name": "H_1", "ipv4-address": "10.1.1.1"}],
    }
    assert validate_template(template) == []
