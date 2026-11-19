"""Unit tests for CPCRUD shorthand expression parsing (`src/arodonata/cpcrud/expressions.py`)."""

from __future__ import annotations

import pytest

from arodonata.core.errors import ValidationError
from arodonata.cpcrud import (
    NamingPrefixes,
    expand_group_expression,
    normalize_wildcard_domain,
    parse_app_site_expression,
    parse_group_expression,
    parse_object_expression,
    parse_range_token,
    parse_service_expression,
    validate_template,
    wildcard_domain_to_cp_regex_urls,
)


@pytest.mark.spec("SCN-CPCRUD-002-1", "SCN-CPCRUD-002-4")
def test_parse_object_expression_hosts_networks_ranges_and_domains() -> None:
    """Hosts, CIDRs, full/compressed ranges, and `.domain` expressions parse under default and customer profiles."""
    default_prefixes = NamingPrefixes()
    custom_prefixes = NamingPrefixes(
        address_range="Range_",
        range_separator="_",
        compress_range_same_subnet=True,
        group="",
        group_suffix="_Grp",
        app_site="Site_",
        app_site_wildcard_marker="_",
    )

    # Hosts (IPv4, prefixed IPv4, IPv6)
    assert parse_object_expression("10.1.1.1") == {
        "type": "host",
        "name": "Host_10.1.1.1",
        "ipv4-address": "10.1.1.1",
    }
    assert parse_object_expression("Host_10.1.1.2") == {
        "type": "host",
        "name": "Host_10.1.1.2",
        "ipv4-address": "10.1.1.2",
    }
    assert parse_object_expression("2001:db8::1") == {
        "type": "host",
        "name": "Host_2001_db8__1",
        "ipv6-address": "2001:db8::1",
    }

    # Networks (CIDR and Net_* prefixed)
    assert parse_object_expression("10.1.1.0/24") == {
        "type": "network",
        "name": "Net_10.1.1.0_24",
        "subnet4": "10.1.1.0",
        "mask-length4": 24,
    }
    assert parse_object_expression("Net_10.2.0.0_16") == {
        "type": "network",
        "name": "Net_10.2.0.0_16",
        "subnet4": "10.2.0.0",
        "mask-length4": 16,
    }

    # Ranges (full, compressed shorthand, prefixed)
    assert parse_range_token("10.1.1.1-9") == ("10.1.1.1", "10.1.1.9")
    assert parse_range_token("10.1.1.1-10.1.1.9") == ("10.1.1.1", "10.1.1.9")
    assert parse_range_token("Range_10.1.1.1_9", prefixes=custom_prefixes) == ("10.1.1.1", "10.1.1.9")
    assert parse_range_token("IPR_10.1.1.1-10.1.2.9", prefixes=default_prefixes) == ("10.1.1.1", "10.1.2.9")

    assert parse_object_expression("10.1.1.1-9", prefixes=default_prefixes) == {
        "type": "address-range",
        "name": "IPR_10.1.1.1-10.1.1.9",
        "ipv4-address-first": "10.1.1.1",
        "ipv4-address-last": "10.1.1.9",
    }
    assert parse_object_expression("10.1.1.1-9", prefixes=custom_prefixes) == {
        "type": "address-range",
        "name": "Range_10.1.1.1_9",
        "ipv4-address-first": "10.1.1.1",
        "ipv4-address-last": "10.1.1.9",
    }
    assert parse_object_expression("10.1.1.1-10.1.2.9", prefixes=custom_prefixes) == {
        "type": "address-range",
        "name": "Range_10.1.1.1_10.1.2.9",
        "ipv4-address-first": "10.1.1.1",
        "ipv4-address-last": "10.1.2.9",
    }

    # DNS domain
    assert parse_object_expression(".abc.com") == {
        "type": "dns-domain",
        "name": ".abc.com",
        "is_sub_domain": True,
    }


@pytest.mark.spec("SCN-CPCRUD-002-3")
def test_parse_app_site_expressions_wildcards_and_multi_domain() -> None:
    """Wildcard `*domain`, `*.domain`, and `SiteName(*d1, *.d2)` produce Check Point-safe names and regex URLs."""
    assert normalize_wildcard_domain("*chinacloudapi.cn") == "chinacloudapi.cn"
    assert normalize_wildcard_domain("*.chinacloudapi.cn") == "chinacloudapi.cn"
    assert wildcard_domain_to_cp_regex_urls("*chinacloudapi.cn") == [
        r"\/chinacloudapi\.cn",
        r"\.chinacloudapi\.cn",
    ]
    assert wildcard_domain_to_cp_regex_urls("*.my-app.example.com") == [
        r"\/my-app\.example\.com",
        r"\.my-app\.example\.com",
    ]

    expected = {
        "type": "application-site",
        "name": "Site__chinacloudapi.cn",
        "primary-category": "Custom_Application_Site",
        "urls-defined-as-regular-expression": True,
        "url-list": [r"\/chinacloudapi\.cn", r"\.chinacloudapi\.cn"],
    }
    assert parse_app_site_expression("*chinacloudapi.cn") == expected
    assert parse_app_site_expression("*.chinacloudapi.cn") == expected
    assert parse_object_expression("*chinacloudapi.cn") == expected
    assert parse_object_expression("*.chinacloudapi.cn") == expected

    multi = parse_app_site_expression("Site_ChinaCloud(*chinacloudapi.cn, *.partner.cn)")
    assert multi == {
        "type": "application-site",
        "name": "Site_ChinaCloud",
        "primary-category": "Custom_Application_Site",
        "urls-defined-as-regular-expression": True,
        "url-list": [
            r"\/chinacloudapi\.cn",
            r"\.chinacloudapi\.cn",
            r"\/partner\.cn",
            r"\.partner\.cn",
        ],
    }
    assert parse_object_expression("Site_ChinaCloud(*chinacloudapi.cn, *.partner.cn)") == multi

    plain_site = parse_app_site_expression("Site_Static(https://portal.example.com, api.example.com)")
    assert plain_site == {
        "type": "application-site",
        "name": "Site_Static",
        "primary-category": "Custom_Application_Site",
        "urls-defined-as-regular-expression": False,
        "url-list": ["https://portal.example.com", "api.example.com"],
    }


def test_parse_service_and_group_expressions_and_validate_template() -> None:
    """Service and inline group expressions produce valid CPCRUD template dicts accepted by `validate_template`."""
    custom_prefixes = NamingPrefixes(
        address_range="Range_",
        range_separator="_",
        compress_range_same_subnet=True,
        group="",
        group_suffix="_Grp",
    )

    tcp_svc = parse_service_expression("tcp/8443")
    udp_svc = parse_service_expression("5353/udp")
    tcp_rng = parse_service_expression("TCP_8080-8090")
    icmp_svc = parse_service_expression("icmp/8/0")
    icmp_short = parse_service_expression("ICMP_8")

    assert tcp_svc == {"type": "service-tcp", "name": "TCP_8443", "port": "8443"}
    assert udp_svc == {"type": "service-udp", "name": "UDP_5353", "port": "5353"}
    assert tcp_rng == {"type": "service-tcp", "name": "TCP_8080-8090", "port": "8080-8090"}
    assert icmp_svc == {"type": "service-icmp", "name": "ICMP_8_0", "icmp-type": 8, "icmp-code": 0}
    assert icmp_short == {"type": "service-icmp", "name": "ICMP_8", "icmp-type": 8}

    objs, grp = expand_group_expression(
        "AppAccess(10.1.1.1, 10.1.1.0/24, 10.1.1.2-9, Existing_Host)",
        prefixes=custom_prefixes,
    )
    assert grp == {
        "type": "group",
        "name": "AppAccess_Grp",
        "members": ["Host_10.1.1.1", "Net_10.1.1.0_24", "Range_10.1.1.2_9", "Existing_Host"],
    }
    assert [o["name"] for o in objs] == ["Host_10.1.1.1", "Net_10.1.1.0_24", "Range_10.1.1.2_9"]

    # Already-suffixed group expression avoids double suffixing
    assert parse_group_expression("AppAccess_Grp(10.1.1.1)", prefixes=custom_prefixes) == {
        "type": "group",
        "name": "AppAccess_Grp",
        "members": ["Host_10.1.1.1"],
    }

    # Schema compatibility check for all generated dicts
    template = {
        "version": 1,
        "mgmt_name": "mds1",
        "domain": "Corp",
        "objects": [
            *objs,
            parse_object_expression(".abc.com", prefixes=custom_prefixes),
            parse_object_expression("*chinacloudapi.cn", prefixes=custom_prefixes),
        ],
        "services": [tcp_svc, udp_svc, tcp_rng, icmp_svc, icmp_short],
        "groups": [grp],
    }
    assert validate_template(template) == []


@pytest.mark.parametrize(
    ("fn", "bad_input"),
    [
        (parse_range_token, ""),
        (parse_range_token, "Net_10.1.1.0_24"),
        (parse_range_token, "Host_10.1.1.1"),
        (parse_range_token, "10.1.1.0/24"),
        (parse_range_token, "10.1.1.10-5"),
        (parse_range_token, "10.1.1.1-256"),
        (parse_range_token, "10.1.2.1-10.1.1.1"),
        (normalize_wildcard_domain, ""),
        (normalize_wildcard_domain, "*"),
        (normalize_wildcard_domain, "*localhost"),
        (normalize_wildcard_domain, "sub.*.example.com"),
        (parse_app_site_expression, "SiteName()"),
        (parse_app_site_expression, "SiteName(*a.com, plain.com)"),
        (parse_app_site_expression, "Bad*Name(*a.com)"),
        (parse_service_expression, "tcp/0"),
        (parse_service_expression, "tcp/70000"),
        (parse_service_expression, "tcp/9000-8000"),
        (parse_service_expression, "icmp/300"),
        (parse_service_expression, "sctp/80"),
        (parse_group_expression, "EmptyGroup()"),
        (parse_group_expression, "Group(10.1.1.1, )"),
        (parse_object_expression, ""),
        (parse_object_expression, "10.1.1.5/24"),
        (parse_object_expression, ".invalid_single_label"),
        (parse_object_expression, "not_an_ip_or_expr"),
    ],
)
def test_expression_parsers_reject_invalid_inputs(fn: object, bad_input: str) -> None:
    """All invalid shorthand expressions raise `ValidationError` cleanly."""
    with pytest.raises(ValidationError):
        fn(bad_input)  # type: ignore[operator]


def test_nested_inline_groups_and_site_group_disambiguation() -> None:
    """Nested inline groups preserve leaf member specs and `Site_*` host groups are not misrouted."""
    nested_objs, outer_grp = expand_group_expression("Outer(Inner(10.1.1.1), 10.2.2.2)")
    assert outer_grp == {"type": "group", "name": "grpOuter", "members": ["grpInner", "Host_10.2.2.2"]}
    assert [o["name"] for o in nested_objs] == ["Host_10.1.1.1", "grpInner", "Host_10.2.2.2"]
    assert nested_objs[1] == {"type": "group", "name": "grpInner", "members": ["Host_10.1.1.1"]}

    # Parenthesized Site_* containing IP hosts must parse as a group, not an application-site
    grp_default = parse_object_expression("Site_A_Servers(10.1.1.1, 10.1.1.2)")
    assert grp_default == {"type": "group", "name": "grpSite_A_Servers", "members": ["Host_10.1.1.1", "Host_10.1.1.2"]}

    custom_pref = NamingPrefixes(app_site="App_", group="", group_suffix="_Grp")
    grp_custom = parse_object_expression("Site_A_Servers(10.1.1.1, 10.1.1.2)", prefixes=custom_pref)
    assert grp_custom == {"type": "group", "name": "Site_A_Servers_Grp", "members": ["Host_10.1.1.1", "Host_10.1.1.2"]}

    # Explicit URL scheme or configured app_site prefix with domain/URL arguments still parses as application-site
    site_url = parse_object_expression("PortalSite(https://portal.example.com)")
    assert site_url["type"] == "application-site"
    assert site_url["url-list"] == ["https://portal.example.com"]
