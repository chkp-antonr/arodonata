"""Unit tests for domain_servers: reading a domain's server layout out of show-domains / show-mdss."""

from __future__ import annotations

from arodonata.asdk.domain_servers import DomainServers, extract_domain_servers, mds_ip_map


def test_active_server_is_the_first_active_entry_with_an_address():
    layout = extract_domain_servers(
        {
            "servers": [
                {"name": "srv-standby", "ipv4-address": "10.0.0.2", "active": False, "multi-domain-server": "mds2"},
                {"name": "srv-active", "ipv4-address": "10.0.0.9", "active": True, "multi-domain-server": "mds1"},
                {"name": "srv-noaddr", "ipv4-address": "", "active": True, "multi-domain-server": "mds3"},
            ]
        }
    )

    assert layout.active_ip == "10.0.0.9"
    assert layout.active_server == "srv-active"
    assert layout.active_mds == "mds1"
    assert layout.standby_ips == ("10.0.0.2",)
    assert layout.standby_servers == ("srv-standby",)
    assert layout.standby_mdss == ("mds2",)


def test_multi_domain_server_may_be_an_object():
    """The API reference does not pin the shape; tolerate {name, uid} as well as a name."""
    layout = extract_domain_servers(
        {
            "servers": [
                {
                    "name": "s",
                    "ipv4-address": "10.0.0.9",
                    "active": True,
                    "multi-domain-server": {"name": "mds1", "uid": "u"},
                }
            ]
        }
    )
    assert layout.active_mds == "mds1"


def test_missing_or_garbage_servers_yield_an_empty_layout():
    assert extract_domain_servers({}) == DomainServers()
    assert extract_domain_servers({"servers": "nope"}) == DomainServers()
    assert extract_domain_servers({"servers": ["nope", {"active": True}]}) == DomainServers()


def test_mds_ip_map_skips_members_without_a_name_or_address():
    members = [
        {"name": "mds1", "ipv4-address": "10.1.1.1"},
        {"name": "mds2"},
        "garbage",
        {"ipv4-address": "10.3.3.3"},
    ]
    assert mds_ip_map(members) == {"mds1": "10.1.1.1"}
