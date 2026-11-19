"""Gateway topology extraction, live route collection, diagnostics, reconciliation, and matching."""

from arodonata.core.services.topology._shared import (
    EXCLUDED_GATEWAY_TYPES,
    POLICY_GATEWAY_TYPES,
    is_policy_enforcing_gateway,
)
from arodonata.core.services.topology.route_executor import execute_gateway_cli
from arodonata.core.services.topology.route_parsers import (
    decode_cprid_task_output,
    parse_clish_show_route,
    parse_combined_cli_routes,
    parse_combined_cli_routes_with_status,
    parse_ip_route_show,
    routes_to_topology_entries,
)
from arodonata.core.services.topology.route_scripts import (
    CLISH_SKIPPED_LARGE_TABLE_MARKER,
    DEFAULT_CLISH_SKIP_THRESHOLD,
    DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME,
    ROUTE_LIMIT_MARKER,
    AutoScriptModeResolver,
    ParsedCliRoute,
    RepositoryScriptArgsCallable,
    build_route_collection_repository_script,
    build_route_collection_script,
    format_route_collection_repository_args,
    resolve_gateway_cli_targets,
)
from arodonata.core.services.topology.service import TopologyService

__all__ = [
    "AutoScriptModeResolver",
    "CLISH_SKIPPED_LARGE_TABLE_MARKER",
    "DEFAULT_CLISH_SKIP_THRESHOLD",
    "DEFAULT_ROUTE_COLLECT_REPOSITORY_SCRIPT_NAME",
    "EXCLUDED_GATEWAY_TYPES",
    "POLICY_GATEWAY_TYPES",
    "ParsedCliRoute",
    "ROUTE_LIMIT_MARKER",
    "RepositoryScriptArgsCallable",
    "TopologyService",
    "build_route_collection_repository_script",
    "build_route_collection_script",
    "decode_cprid_task_output",
    "execute_gateway_cli",
    "format_route_collection_repository_args",
    "is_policy_enforcing_gateway",
    "parse_clish_show_route",
    "parse_combined_cli_routes",
    "parse_combined_cli_routes_with_status",
    "parse_ip_route_show",
    "resolve_gateway_cli_targets",
    "routes_to_topology_entries",
]
