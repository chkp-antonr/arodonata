"""Core domain services for Arodonata v2 (`DomainService`, `DomainSyncCoordinator`,
`ObjectService`, `ServiceCacheService`, `AssetRefreshService`, `SearchService`).

Strictly depends on `ApiPort`, `CachePort`, and `LockPort` protocols without transport or ORM imports.
"""

from arodonata.core.services.asset_service import (
    AssetRefreshService,
    ClusterRelationshipManager,
    VSXRelationshipManager,
)
from arodonata.core.services.domain_service import (
    SYSTEM_DOMAIN_KEY,
    DomainListRefreshTracker,
    DomainService,
    parse_domain_dict,
)
from arodonata.core.services.object_service import (
    OBJECT_TYPE_TO_SHOW_COMMAND,
    ObjectService,
    extract_changes_from_show_changes,
    resolve_object_query_command,
)
from arodonata.core.services.route_collector import (
    ParsedCliRoute,
    build_route_collection_script,
    decode_cprid_task_output,
    execute_gateway_cli,
    parse_clish_show_route,
    parse_combined_cli_routes,
    parse_ip_route_show,
    resolve_gateway_cli_targets,
    routes_to_topology_entries,
)
from arodonata.core.services.search_service import (
    ClassifiedSearchTerm,
    SearchService,
    SearchTermKind,
    classify_search_term,
    matches_classified_term,
)
from arodonata.core.services.service_cache import (
    SERVICE_TYPE_TO_SHOW_COMMAND,
    ServiceCacheService,
    resolve_service_query_command,
)
from arodonata.core.services.sync_coordinator import (
    DomainProbeResult,
    DomainSyncCoordinator,
    DomainSyncHandler,
    parse_cp_publish_timestamp,
)
from arodonata.core.services.topology_service import (
    EXCLUDED_GATEWAY_TYPES,
    POLICY_GATEWAY_TYPES,
    TopologyService,
    is_policy_enforcing_gateway,
)

__all__ = [
    "AssetRefreshService",
    "ClassifiedSearchTerm",
    "ClusterRelationshipManager",
    "DomainListRefreshTracker",
    "DomainProbeResult",
    "DomainService",
    "DomainSyncCoordinator",
    "DomainSyncHandler",
    "EXCLUDED_GATEWAY_TYPES",
    "OBJECT_TYPE_TO_SHOW_COMMAND",
    "ObjectService",
    "POLICY_GATEWAY_TYPES",
    "ParsedCliRoute",
    "SERVICE_TYPE_TO_SHOW_COMMAND",
    "SYSTEM_DOMAIN_KEY",
    "SearchService",
    "SearchTermKind",
    "ServiceCacheService",
    "TopologyService",
    "VSXRelationshipManager",
    "build_route_collection_script",
    "classify_search_term",
    "decode_cprid_task_output",
    "execute_gateway_cli",
    "extract_changes_from_show_changes",
    "is_policy_enforcing_gateway",
    "matches_classified_term",
    "parse_clish_show_route",
    "parse_combined_cli_routes",
    "parse_cp_publish_timestamp",
    "parse_domain_dict",
    "parse_ip_route_show",
    "resolve_gateway_cli_targets",
    "resolve_object_query_command",
    "resolve_service_query_command",
    "routes_to_topology_entries",
]
