"""Data-only description of the live ``show_*`` tools (mirrors @chkp/quantum-management-mcp)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ParamKind = Literal["str", "int", "bool", "list_str", "list_dict", "dict"]


@dataclass(frozen=True)
class ParamSpec:
    name: str
    kind: ParamKind
    description: str = ""
    default: Any = None


@dataclass(frozen=True)
class CompatTool:
    name: str
    command: str
    kind: Literal["list", "single"]
    container_key: str = "objects"
    params: tuple[ParamSpec, ...] = ()
    description: str = ""


P = ParamSpec
_MEMBERSHIP = P("show_membership", "bool", "Include the groups each object belongs to (extra server work).")
_DEREF = P("dereference_group_members", "bool", "Expand group members to full objects instead of UIDs.")
_AS_RANGES = P("show_as_ranges", "bool", "Show address objects as IP ranges.")
_ORDER = P("order", "list_dict", 'Sort, e.g. [{"ASC": "name"}]')
_DOMAINS_TO_PROCESS = P(
    "domains_to_process", "str", "'ALL_DOMAINS_ON_THIS_SERVER' or 'CURRENT_DOMAIN'; System Domain only."
)
_LOCAL_ONLY = P("show_only_local_domain", "bool", "Exclude objects inherited from a Global domain.")
_FILTER = P("filter", "str", "Free-text search over name, IP, comments.")

LIST_COMMON: tuple[ParamSpec, ...] = (_FILTER, _ORDER, _DOMAINS_TO_PROCESS, _LOCAL_ONLY)
NAME_OR_UID: tuple[ParamSpec, ...] = (P("name", "str", "Object name."), P("uid", "str", "Object UID."))


def _list(name: str, command: str, description: str, *extra: ParamSpec, container_key: str = "objects") -> CompatTool:
    return CompatTool(name, command, "list", container_key, LIST_COMMON + extra, description)


def _single(name: str, command: str, description: str, *extra: ParamSpec) -> CompatTool:
    return CompatTool(name, command, "single", "objects", NAME_OR_UID + extra, description)


MANIFEST: tuple[CompatTool, ...] = (
    _list(
        "show_objects",
        "show-objects",
        "Search all object types.",
        P("type", "str", "Object type, e.g. host, group, service-tcp."),
        P("ip_only", "bool"),
        _MEMBERSHIP,
        _DEREF,
    ),
    _list("show_access_layers", "show-access-layers", "List access layers.", container_key="access-layers"),
    _list(
        "show_packages",
        "show-packages",
        "List policy packages; details_level='full' shows layers and install targets.",
        P("show_installation_targets", "bool"),
        container_key="packages",
    ),
    _list("show_mdss", "show-mdss", "List Multi-Domain Server members.", P("show_domains", "bool")),
    _list("show_simple_gateways", "show-simple-gateways", "List simple gateways.", _MEMBERSHIP),
    _list("show_simple_clusters", "show-simple-clusters", "List simple clusters.", _MEMBERSHIP),
    _list("show_cluster_members", "show-cluster-members", "List cluster members.", _MEMBERSHIP),
    _list("show_lsm_gateways", "show-lsm-gateways", "List LSM gateways.", _MEMBERSHIP),
    _list("show_lsm_clusters", "show-lsm-clusters", "List LSM clusters.", _MEMBERSHIP),
    _list("show_unused_objects", "show-unused-objects", "List objects not referenced anywhere.", _MEMBERSHIP, _DEREF),
    _list("show_services_tcp", "show-services-tcp", "List TCP services.", _MEMBERSHIP),
    _list("show_services_udp", "show-services-udp", "List UDP services.", _MEMBERSHIP),
    _list("show_services_icmp", "show-services-icmp", "List ICMP services.", _MEMBERSHIP),
    _list(
        "show_service_groups",
        "show-service-groups",
        "List service groups.",
        _MEMBERSHIP,
        _DEREF,
        _AS_RANGES,
    ),
    _list("show_application_sites", "show-application-sites", "List application/site objects.", _MEMBERSHIP),
    _list(
        "show_application_site_groups",
        "show-application-site-groups",
        "List application/site groups.",
        _MEMBERSHIP,
        _DEREF,
    ),
    _list("show_application_site_categories", "show-application-site-categories", "List application categories."),
    _list("show_wildcards", "show-wildcards", "List wildcard objects."),
    _list("show_security_zones", "show-security-zones", "List security zones.", _MEMBERSHIP),
    _list("show_tags", "show-tags", "List tags."),
    _list("show_address_ranges", "show-address-ranges", "List address ranges."),
    _list(
        "show_multicast_address_ranges",
        "show-multicast-address-ranges",
        "List multicast address ranges.",
        _MEMBERSHIP,
    ),
    _list("show_dynamic_objects", "show-dynamic-objects", "List dynamic objects.", _MEMBERSHIP),
    _list("show_dns_domains", "show-dns-domains", "List DNS domain objects.", _MEMBERSHIP),
    _list("show_time_groups", "show-time-groups", "List time groups."),
    _list("show_access_point_names", "show-access-point-names", "List access point names."),
    _list("show_vpn_communities_star", "show-vpn-communities-star", "List star VPN communities."),
    _list("show_vpn_communities_meshed", "show-vpn-communities-meshed", "List meshed VPN communities."),
    _list(
        "show_vpn_communities_remote_access",
        "show-vpn-communities-remote-access",
        "List remote-access VPN communities.",
    ),
    _single("show_access_layer", "show-access-layer", "Get one access layer."),
    _single(
        "show_access_section",
        "show-access-section",
        "Get one access section.",
        P("layer", "str", "Layer name or UID."),
    ),
    _single("show_nat_section", "show-nat-section", "Get one NAT section.", P("package", "str", "Policy package.")),
    _single(
        "show_access_rule",
        "show-access-rule",
        "Get one access rule by name, uid or rule_number within a layer.",
        P("layer", "str", "Layer name or UID (required)."),
        P("rule_number", "int"),
        P("package", "str"),
        _AS_RANGES,
        P("show_hits", "bool"),
        P("hits_settings", "dict", "{from_date, to_date, target}"),
        P("show_expiration_settings", "bool"),
    ),
    _single("show_vpn_community_star", "show-vpn-community-star", "Get one star VPN community."),
    _single("show_vpn_community_meshed", "show-vpn-community-meshed", "Get one meshed VPN community."),
    _single(
        "show_vpn_community_remote_access", "show-vpn-community-remote-access", "Get one remote-access VPN community."
    ),
    _single(
        "show_simple_gateway",
        "show-simple-gateway",
        "Get one simple gateway; details_level='full' includes interfaces and installed policy.",
    ),
    _single("show_simple_cluster", "show-simple-cluster", "Get one simple cluster.", P("limit_interfaces", "int")),
    _single(
        "show_cluster_member", "show-cluster-member", "Get one cluster member by UID.", P("limit_interfaces", "int")
    ),
    _single("show_lsm_gateway", "show-lsm-gateway", "Get one LSM gateway.", P("show_statuses", "bool")),
    _single("show_lsm_cluster", "show-lsm-cluster", "Get one LSM cluster.", P("show_statuses", "bool")),
    _single(
        "where_used",
        "where-used",
        "Where an object is referenced (rules, groups, NAT).",
        _DEREF,
        _MEMBERSHIP,
        P("indirect", "bool", "Follow indirect references."),
        P("indirect_max_depth", "int"),
    ),
)
