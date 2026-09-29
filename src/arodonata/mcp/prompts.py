"""Guidance prompts, adapted from the reference server to Arodonata tool names."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._sdk import MCPServer

if TYPE_CHECKING:
    from .registry import ToolOptions

_INIT = "Call arodonata_init first to learn the configured management servers (mgmt_name) and their domains. "

GATEWAYS = _INIT + (
    "Show the installed policies per gateway. Call show_gateways_and_servers with details_level='full'; the installed "
    "policy is in each gateway's 'policy' field. For one gateway use show_simple_gateway or show_simple_cluster with details_level='full'."
)
POLICIES = _INIT + (
    "To list policies call show_packages with details_level='full'; each package lists its access layers. Call show_access_layer "
    "with details_level='full' for a layer, then show_access_rulebase with the layer name to see its rules (default markdown format). "
    "Use show_nat_rulebase with the package name for NAT, show_threat_rulebase for threat prevention, show_https_rulebase for HTTPS inspection."
)
RULE = _INIT + (
    "Show details for rule {rule_ref}. A rule lives in an access layer of a package: if you know them, call show_access_rulebase "
    "(filter by name) or show_access_rule with layer and rule_number/uid. Otherwise find the package and layer with show_packages and "
    "show_access_layers first. If several packages or layers match, ask the user which one."
)
TOPOLOGY = _INIT + (
    "Create a visual topology diagram of gateway '{gateway_name}': interfaces with IPs, masks and security zones; networks behind each "
    "interface; allowed traffic flows from policy. Gather data with show_simple_gateway (details_level='full'), show_security_zones, "
    "show_access_layers and show_access_rulebase; resolve objects with show_object, show_networks and show_hosts (cache-backed). "
    "Produce an SVG showing physical topology and logical policy flows."
)
PATH = _INIT + (
    "Determine the possible paths from '{source}' to '{destination}'. Use search_objects to resolve both endpoints across domains, "
    "show_access_rulebase to find matching access rules (add filter/filter_settings with search_mode='packet' for a live packet-mode "
    "match), show_nat_rulebase for NAT that changes the flow, and show_gateways_and_servers for the gateways on the path. Explain the "
    "decision with object and rule references, and draw the path if useful."
)


def register_prompts(server: MCPServer, opts: ToolOptions) -> list[str]:
    names: list[str] = []

    def show_gateways_prompt() -> str:
        """Guide showing the installed policies per gateway."""
        return GATEWAYS

    def show_policies_prompt() -> str:
        """Guide walking policy packages, their layers and their rulebases."""
        return POLICIES

    def show_rule_prompt(rule_ref: str) -> str:
        """Guide finding one rule by reference (name, number or uid) in its package and layer."""
        return RULE.format(rule_ref=rule_ref)

    def topology_visualization_prompt(gateway_name: str) -> str:
        """Guide producing an SVG topology diagram of one gateway's interfaces, networks and policy flows."""
        return TOPOLOGY.format(gateway_name=gateway_name)

    def source_to_destination_prompt(source: str, destination: str) -> str:
        """Guide determining the possible paths and matching rules between two endpoints."""
        return PATH.format(source=source, destination=destination)

    for fn in (
        show_gateways_prompt,
        show_policies_prompt,
        show_rule_prompt,
        topology_visualization_prompt,
        source_to_destination_prompt,
    ):
        server.prompt(name=opts.name(fn.__name__), description=(fn.__doc__ or fn.__name__.replace("_", " ")))(fn)
        names.append(opts.name(fn.__name__))
    return names
