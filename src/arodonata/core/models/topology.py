"""Gateway interface topology and affected gateway candidate matching models."""

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
    "gaia_static_route",
    "clish_route",
    "bgp_route",
    "ospf_route",
]

TopologyZone = Literal["internal", "external"]

FlowMatchType = Literal[
    "internal_to_internal",
    "internal_to_external",
    "external_to_internal",
]


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
    source_type: TopologySourceType
    source_ref: str = ""
    cidr_or_range: str
    ip_first_int: int
    ip_last_int: int
    prefix_len: int = 32
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
    matched_flows: list[TrafficFlowMatch] = Field(default_factory=list)
