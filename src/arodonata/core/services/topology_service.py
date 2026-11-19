"""Backward-compatible re-export shim for `arodonata.core.services.topology`."""

from arodonata.core.services.topology._shared import (
    _PROCESS_TOPOLOGY_REGISTRIES as _PROCESS_TOPOLOGY_REGISTRIES,
)
from arodonata.core.services.topology._shared import (
    EXCLUDED_GATEWAY_TYPES,
    POLICY_GATEWAY_TYPES,
    is_policy_enforcing_gateway,
)
from arodonata.core.services.topology._shared import (
    TOPOLOGY_OBJECT_LOOKUP_CONCURRENCY as TOPOLOGY_OBJECT_LOOKUP_CONCURRENCY,
)
from arodonata.core.services.topology._shared import (
    _ExpandedPolicyRule as _ExpandedPolicyRule,
)
from arodonata.core.services.topology._shared import (
    _InterfaceMatch as _InterfaceMatch,
)
from arodonata.core.services.topology._shared import (
    _LoopTopologyState as _LoopTopologyState,
)
from arodonata.core.services.topology._shared import (
    _NormalizedInterface as _NormalizedInterface,
)
from arodonata.core.services.topology._shared import (
    _ProcessTopologyRegistry as _ProcessTopologyRegistry,
)
from arodonata.core.services.topology._shared import (
    _ResolvedEndpointInterval as _ResolvedEndpointInterval,
)
from arodonata.core.services.topology._shared import (
    _run_single_flight as _run_single_flight,
)
from arodonata.core.services.topology._shared import (
    _TopologyServiceCachePort as _TopologyServiceCachePort,
)
from arodonata.core.services.topology._shared import (
    logger as logger,
)
from arodonata.core.services.topology.normalizer import (
    _extract_anti_spoofing_mode as _extract_anti_spoofing_mode,
)
from arodonata.core.services.topology.normalizer import (
    _extract_policy_candidates_from_raw as _extract_policy_candidates_from_raw,
)
from arodonata.core.services.topology.normalizer import (
    _extract_raw_routes as _extract_raw_routes,
)
from arodonata.core.services.topology.normalizer import (
    _extract_timestamp_posix as _extract_timestamp_posix,
)
from arodonata.core.services.topology.normalizer import (
    _extract_vpn_domain_refs as _extract_vpn_domain_refs,
)
from arodonata.core.services.topology.normalizer import (
    _normalize_gateway_interfaces as _normalize_gateway_interfaces,
)
from arodonata.core.services.topology.normalizer import (
    _normalize_interface as _normalize_interface,
)
from arodonata.core.services.topology.normalizer import (
    _parse_route_destination as _parse_route_destination,
)
from arodonata.core.services.topology.normalizer import (
    _parse_route_nexthop_and_interface as _parse_route_nexthop_and_interface,
)
from arodonata.core.services.topology.service import TopologyService

__all__ = [
    "EXCLUDED_GATEWAY_TYPES",
    "POLICY_GATEWAY_TYPES",
    "TopologyService",
    "is_policy_enforcing_gateway",
]
