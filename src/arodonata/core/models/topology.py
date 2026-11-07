"""Gateway interface topology, live routing reconciliation, annotations, and candidate matching models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.models.common import to_naive_utc, utc_now

TopologySourceType = Literal[
    "interface_connected",
    "interface_specific",
    "vs_static_route",
    "external_interface",
    "connected_route",
    "gaia_static_route",
    "clish_route",
    "bgp_route",
    "ospf_route",
    "manual",
]

STATIC_TOPOLOGY_SOURCES: frozenset[str] = frozenset(
    {
        "interface_connected",
        "interface_specific",
        "vs_static_route",
        "external_interface",
    }
)

LIVE_ROUTE_SOURCES: frozenset[str] = frozenset(
    {
        "connected_route",
        "gaia_static_route",
        "clish_route",
        "bgp_route",
        "ospf_route",
    }
)

AntiSpoofingMode = Literal["prevent", "detect", "off", "unknown"]

TopologyZone = Literal["internal", "external"]

FlowMatchType = Literal[
    "internal_to_internal",
    "internal_to_external",
    "external_to_internal",
]

TopologyDiagnosticCode = Literal[
    "not_defined",
    "routing_defined_without_routes",
    "anti_spoofing_detect_or_off",
    "unresolved_specific",
    "empty_specific",
    "missing_ip_mask",
    "no_interfaces",
    "one_arm_topology",
]

TopologyDiagnosticSeverity = Literal["warning", "info"]

TopologyDiscrepancyType = Literal[
    "stale_in_topology",
    "missing_in_topology",
    "interface_mismatch",
    "default_route_mismatch",
    "cluster_member_drift",
    "resolved_by_routing",
]

AnnotationDisposition = Literal[
    "confirmed",
    "standby_dynamic",
    "ignore",
    "manual",
]


class ConfidenceDelta(BaseModel):
    """Single signed evidence delta contributing to an endpoint or traffic flow confidence score."""

    model_config = ConfigDict(extra="ignore")

    code: str
    delta: float
    detail: str = ""


class GatewayTopologyEntry(BaseModel):
    """Normalized IPv4 interval behind a specific Check Point gateway/cluster/VS interface."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str = ""
    mgmt_name: str
    domain_name: str
    gateway_id: str = ""
    gateway_asset_id: str = ""
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    interface_name: str
    interface_ipv4: str | None = None
    interface_mask_length: int | None = None
    topology_zone: TopologyZone = "internal"
    leads_to_dmz: bool = False
    anti_spoofing_mode: AntiSpoofingMode = "unknown"
    source_type: TopologySourceType
    source_ref: str = ""
    cidr_or_range: str
    ip_first_int: int
    ip_last_int: int
    prefix_len: int = 32
    installed_access_policy: str | None = None
    policy_packages: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.gateway_id:
            self.gateway_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_uid}"
        if not self.gateway_asset_id:
            self.gateway_asset_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_name}"
        if not self.id:
            self.id = (
                f"{self.mgmt_name}:{self.domain_name}:{self.gateway_uid}:"
                f"{self.interface_name}:{self.source_type}:{self.cidr_or_range}"
            )
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class GatewayInterfaceSummary(BaseModel):
    """Aggregated topology view for a single gateway interface."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    gateway_id: str
    gateway_asset_id: str
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    interface_name: str
    interface_ipv4: str | None = None
    interface_mask_length: int | None = None
    topology_zone: TopologyZone
    leads_to_dmz: bool = False
    anti_spoofing_mode: AntiSpoofingMode = "unknown"
    source_types: list[str] = Field(default_factory=list)
    cidrs_and_ranges: list[str] = Field(default_factory=list)


class TrafficFlowMatch(BaseModel):
    """Evidence of a `(source, destination)` pair traversing two distinct interfaces on a gateway."""

    model_config = ConfigDict(extra="ignore")

    source_query: str
    destination_query: str
    source_cidr_or_range: str
    destination_cidr_or_range: str
    src_interface: str
    dst_interface: str
    src_topology_zone: TopologyZone
    dst_topology_zone: TopologyZone
    src_matched_cidr: str
    dst_matched_cidr: str
    src_source_type: str
    dst_source_type: str
    src_source_ref: str = ""
    dst_source_ref: str = ""
    match_type: FlowMatchType
    src_confidence: float = 1.0
    dst_confidence: float = 1.0
    confidence: float = 1.0
    is_standby_path: bool = False
    confidence_factors: list[ConfidenceDelta] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AffectedGatewayCandidate(BaseModel):
    """Policy-enforcing gateway/cluster/VS candidate positioned on the path between sources and destinations."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    gateway_id: str
    gateway_asset_id: str
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    ipv4_address: str | None = None
    parent_id: str | None = None
    parent_asset_id: str | None = None
    installed_access_policy: str | None = None
    policy_packages: list[str] = Field(default_factory=list)
    access_layers: list[str] = Field(default_factory=list)
    match_types: list[str] = Field(default_factory=list)
    matched_sources: list[str] = Field(default_factory=list)
    matched_destinations: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    is_standby_path: bool = False
    confidence_factors: list[ConfidenceDelta] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    matched_flows: list[TrafficFlowMatch] = Field(default_factory=list)


class GatewayCliTarget(BaseModel):
    """Target node specification for executing CLI commands via SSH DI or Check Point `cprid` `run-script`."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    gateway_id: str = ""
    gateway_asset_id: str = ""
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    node_uid: str
    node_name: str
    node_ipv4: str | None = None
    vsid: int | None = None
    vs_name: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.gateway_id:
            self.gateway_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_uid}"
        if not self.gateway_asset_id:
            self.gateway_asset_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_name}"


class GatewayCliResult(BaseModel):
    """Result of executing a CLI command/script on a gateway node."""

    model_config = ConfigDict(extra="ignore")

    success: bool = True
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    executor: Literal["ssh", "cprid"] = "ssh"
    error_message: str | None = None


class GatewayRouteCollectionStatus(BaseModel):
    """Per-gateway execution summary from `collect_gateway_routes`."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    gateway_id: str = ""
    gateway_asset_id: str = ""
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    success: bool
    executor: str = ""
    routes_collected: int = 0
    member_drift_detected: bool = False
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.gateway_id:
            self.gateway_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_uid}"
        if not self.gateway_asset_id:
            self.gateway_asset_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_name}"


class RouteCollectionOutcome(BaseModel):
    """Aggregated outcome of `collect_gateway_routes` across target gateways."""

    model_config = ConfigDict(extra="ignore")

    total_gateways: int = 0
    succeeded_gateways: int = 0
    failed_gateways: int = 0
    total_routes: int = 0
    gateways: list[GatewayRouteCollectionStatus] = Field(default_factory=list)


class TopologyDiagnostic(BaseModel):
    """Completeness, trust, or topology mode diagnostic for a gateway or interface."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    gateway_id: str = ""
    gateway_asset_id: str = ""
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    interface_name: str | None = None
    code: TopologyDiagnosticCode
    severity: TopologyDiagnosticSeverity = "warning"
    behind_mode: str = ""
    anti_spoofing_mode: AntiSpoofingMode = "unknown"
    specific_network_ref: str | None = None
    message: str

    def model_post_init(self, __context: Any) -> None:
        if not self.gateway_id:
            self.gateway_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_uid}"
        if not self.gateway_asset_id:
            self.gateway_asset_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_name}"


class TopologyDiscrepancy(BaseModel):
    """Discrepancy between SmartConsole static topology, live routing tables, and cluster members."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    gateway_id: str = ""
    gateway_asset_id: str = ""
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    discrepancy_type: TopologyDiscrepancyType
    severity: TopologyDiagnosticSeverity = "warning"
    interface_name: str
    routed_interface_name: str | None = None
    cidr_or_range: str
    static_sources: list[str] = Field(default_factory=list)
    route_sources: list[str] = Field(default_factory=list)
    annotation_disposition: str | None = None
    suppressed_by_annotation: bool = False
    confidence_delta: float = 0.0
    member_details: dict[str, list[str]] = Field(default_factory=dict)
    message: str

    def model_post_init(self, __context: Any) -> None:
        if not self.gateway_id:
            self.gateway_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_uid}"
        if not self.gateway_asset_id:
            self.gateway_asset_id = f"{self.mgmt_name}:{self.domain_name}:{self.gateway_name}"


class TopologyReconciliationReport(BaseModel):
    """Combined static topology diagnostics and static-vs-live route reconciliation report."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str | None = None
    domain_name: str | None = None
    gateway_count: int = 0
    diagnostics: list[TopologyDiagnostic] = Field(default_factory=list)
    discrepancies: list[TopologyDiscrepancy] = Field(default_factory=list)


class TopologyAnnotation(BaseModel):
    """Persistent administrator override, standby route marker, or IPAM metadata annotation."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str = ""
    mgmt_name: str
    domain_name: str
    gateway_uid: str
    gateway_name: str = ""
    interface_name: str = "*"
    cidr_or_range: str = "*"
    trust_static_topology: bool | None = None
    disposition: AnnotationDisposition | None = None
    topology_zone: TopologyZone | None = None
    zone: str = ""
    site: str = ""
    comment: str = ""
    custom_metadata: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        self.interface_name = (self.interface_name or "*").strip() or "*"
        self.cidr_or_range = (self.cidr_or_range or "*").strip() or "*"
        if not self.id:
            self.id = (
                f"{self.mgmt_name}:{self.domain_name}:{self.gateway_uid}:{self.interface_name}:{self.cidr_or_range}"
            )
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class ExportedTopologyPrefix(BaseModel):
    """Enriched gateway/interface prefix record for IPAM export and reconciliation."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    gateway_id: str
    gateway_asset_id: str
    gateway_uid: str
    gateway_name: str
    gateway_type: str
    interface_name: str
    interface_ipv4: str | None = None
    interface_mask_length: int | None = None
    cidr_or_range: str
    prefix_len: int
    topology_zone: TopologyZone
    leads_to_dmz: bool = False
    source_types: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    anti_spoofing_mode: AntiSpoofingMode = "unknown"
    disposition: AnnotationDisposition | None = None
    is_standby_path: bool = False
    confidence: float = 1.0
    confidence_factors: list[ConfidenceDelta] = Field(default_factory=list)
    zone: str = ""
    site: str = ""
    comment: str = ""
    custom_metadata: dict[str, Any] = Field(default_factory=dict)
