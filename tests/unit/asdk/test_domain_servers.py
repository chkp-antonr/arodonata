"""Unit tests for domain_servers: reading a domain's server layout out of show-domains / show-mdss."""

from __future__ import annotations

from arodonata.asdk.domain_servers import (
    DomainServers,
    GlobalDomainMdss,
    extract_domain_servers,
    extract_global_domain_mdss,
    mds_ip_map,
)


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


class TestGlobalDomainMdss:
    """`show-global-domain` reports Global's members without addresses.

    Verified against mdsNP2 (R82) on 2026-09-22. The implicit Global domain has
    no domain server of its own, so each entry names only the MDS member and
    whether it is the active one:

        {"name": "", "ipv4-address": "", "multi-domain-server": "mdsNP2", "active": false}
        {                               "multi-domain-server": "mdsNP1", "active": true }

    `extract_domain_servers` cannot read this - it skips any entry without an
    `ipv4-address`, which here is all of them.
    """

    def test_the_active_member_is_the_one_flagged_active(self):
        layout = extract_global_domain_mdss(
            {
                "servers": [
                    {"name": "", "ipv4-address": "", "multi-domain-server": "mdsNP2", "active": False},
                    {"multi-domain-server": "mdsNP1", "active": True},
                ]
            }
        )
        assert layout.active_mds == "mdsNP1"
        assert layout.standby_mdss == ("mdsNP2",)

    def test_entries_without_an_address_are_kept_unlike_a_regular_domain(self):
        """The regression this exists to prevent: reusing the domain parser here."""
        servers = {"servers": [{"multi-domain-server": "mdsNP1", "active": True}]}
        assert extract_domain_servers(servers) == DomainServers()
        assert extract_global_domain_mdss(servers).active_mds == "mdsNP1"

    def test_a_member_reference_may_be_an_object_rather_than_a_name(self):
        layout = extract_global_domain_mdss(
            {"servers": [{"multi-domain-server": {"name": "mdsNP1", "uid": "u"}, "active": True}]}
        )
        assert layout.active_mds == "mdsNP1"

    def test_no_active_member_leaves_the_layout_empty_rather_than_guessing(self):
        """A caller must fall back deliberately, not be handed an arbitrary member."""
        layout = extract_global_domain_mdss(
            {
                "servers": [
                    {"multi-domain-server": "mdsNP1", "active": False},
                    {"multi-domain-server": "mdsNP2", "active": False},
                ]
            }
        )
        assert layout.active_mds == ""
        assert layout.standby_mdss == ("mdsNP1", "mdsNP2")

    def test_missing_or_garbage_servers_yield_an_empty_layout(self):
        assert extract_global_domain_mdss({}) == GlobalDomainMdss()
        assert extract_global_domain_mdss({"servers": "nope"}) == GlobalDomainMdss()
        assert extract_global_domain_mdss({"servers": ["nope", {"active": True}]}) == GlobalDomainMdss()
