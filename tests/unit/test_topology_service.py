"""Unit tests for `TopologyService`: interface topology extraction, group expansion, VS static routes, and affected gateway candidate matching."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import AuthContext
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
)
from arodonata.core.services import (
    AssetRefreshService,
    DomainService,
    DomainSyncCoordinator,
    ObjectService,
    SearchService,
    TopologyService,
)


class TopologyFakeApi:
    """In-memory `ApiPort` double for `TopologyService` unit tests."""

    def __init__(self) -> None:
        self.gateways_by_domain: dict[str, list[dict[str, Any]]] = {
            "Corp": [
                # Cluster object (policy-enforcing) with interfaces omitted in summary to test on-demand detail call
                {
                    "uid": "cl-corp-1",
                    "name": "corp-perimeter-cluster",
                    "type": "CpmiGatewayCluster",
                    "ipv4-address": "10.10.0.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Perimeter_Pkg",
                    },
                },
                # Cluster member (must be skipped!)
                {
                    "uid": "cm-corp-1a",
                    "name": "corp-perimeter-1a",
                    "type": "cluster-member",
                    "ipv4-address": "10.10.0.2",
                    "interfaces": [
                        {
                            "interface-name": "eth1",
                            "ipv4-address": "10.99.99.2",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        }
                    ],
                },
                # Management host (must be skipped!)
                {
                    "uid": "mgmt-host-1",
                    "name": "mds-corp",
                    "type": "checkpoint-host",
                    "ipv4-address": "10.0.0.1",
                },
                # Unrelated branch gateway (has internal 192.168.50.0/24 on eth1 and external on eth0)
                {
                    "uid": "gw-branch-1",
                    "name": "branch-gw-01",
                    "type": "simple-gateway",
                    "ipv4-address": "192.168.50.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Branch_Pkg",
                    },
                    "interfaces": [
                        {
                            "interface-name": "eth0",
                            "ipv4-address": "198.51.100.2",
                            "ipv4-mask-length": 29,
                            "topology": {
                                "leads-to-internet": True,
                                "ip-address-behind-this-interface": "not defined",
                            },
                        },
                        {
                            "interface-name": "eth1",
                            "ipv4-address": "192.168.50.1",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        },
                    ],
                },
            ],
            "DC": [
                # Physical VSX host VS0 (must be skipped!)
                {
                    "uid": "vsx-dc-1",
                    "name": "dc-vsx-chassis",
                    "type": "CpmiVsxNetobj",
                    "ipv4-address": "172.16.0.10",
                    "interfaces": [
                        {
                            "interface-name": "eth0",
                            "ipv4-address": "172.16.0.10",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        }
                    ],
                },
                # Core internal gateway with two internal interfaces and one routing-defined interface
                {
                    "uid": "gw-dc-core",
                    "name": "dc-core-gw",
                    "type": "simple-gateway",
                    "ipv4-address": "10.20.0.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Core_Pkg",
                    },
                    "interfaces": [
                        {
                            "interface-name": "bond0.10",
                            "ipv4-address": "10.10.1.254",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                            },
                        },
                        {
                            "interface-name": "bond0.20",
                            "ipv4-address": "10.20.0.1",
                            "ipv4-mask-length": 24,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "specific",
                                "specific-network": "G_DC_Apps",
                            },
                        },
                        {
                            "interface-name": "bond0.99",
                            "ipv4-address": "10.99.0.1",
                            "ipv4-mask-length": 30,
                            "topology": {
                                "leads-to-internet": False,
                                "ip-address-behind-this-interface": "network defined by routing",
                            },
                        },
                    ],
                },
            ],
            "TenantVS": [
                # VSX Virtual System with static routes via CpmiVsSlotObj in DC domain
                {
                    "uid": "vs-tenant-1",
                    "name": "vsx1_VS_Tenant",
                    "type": "CpmiVsNetobj",
                    "ipv4-address": "10.50.0.1",
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "Tenant_VS_Policy",
                    },
                }
            ],
        }

        self.cluster_details_by_uid: dict[str, dict[str, Any]] = {
            "cl-corp-1": {
                "uid": "cl-corp-1",
                "name": "corp-perimeter-cluster",
                "type": "simple-cluster",
                "interfaces": {
                    "objects": [
                        {
                            "name": "eth0",
                            "ipv4-address": "203.0.113.5",
                            "ipv4-mask-length": 29,
                            "topology": "external",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "not defined",
                                "interface-leads-to-dmz": False,
                            },
                        },
                        {
                            "name": "eth1",
                            "ipv4-address": "10.10.1.1",
                            "ipv4-network-mask": "255.255.255.0",
                            "topology": "internal",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                                "interface-leads-to-dmz": False,
                            },
                        },
                        {
                            "name": "eth2",
                            "ipv4-address": "172.16.1.1",
                            "ipv4-mask-length": 24,
                            "topology": "internal",
                            "topology-settings": {
                                "ip-address-behind-this-interface": "specific",
                                "specific-network": "G_Global_DMZ",
                                "interface-leads-to-dmz": True,
                            },
                        },
                    ]
                },
            }
        }

        self.generic_objects_by_class: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("DC", "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj"): [
                {
                    "uid": "slot0-dc",
                    "name": "dc-vsx-chassis",
                    "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsxSlotObj",
                    "vsid": 0,
                    "vsxGateway": "vsx-dc-1",
                }
            ],
            ("DC", "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj"): [
                {
                    "uid": "slot1-tenant",
                    "name": "vsx1_VS_Tenant",
                    "class-name": "com.checkpoint.objects.vsx_classes.dummy.CpmiVsSlotObj",
                    "vsid": 1,
                    "vsxGateway": "slot0-dc",
                    "targetCustomer": "TenantVS",
                    "interfaces_installed": [
                        {
                            "officialname": "wrp128",
                            "ipaddr": "192.168.100.2",
                            "netmask": "255.255.255.252",
                        },
                        {
                            "officialname": "eth1.50",
                            "ipaddr": "10.50.0.1",
                            "netmask": "255.255.255.0",
                        },
                    ],
                    "routes_installed": [
                        {
                            "dest": "172.16.80.0",
                            "mask": "255.255.255.0",
                            "nexthop": "10.50.0.254",
                        },
                        {
                            "dest": "0.0.0.0",
                            "mask": "0.0.0.0",
                            "nexthop": "192.168.100.1",
                        },
                    ],
                }
            ],
        }

        self.objects_by_domain_and_cmd: dict[tuple[str, str], list[dict[str, Any]]] = {
            ("Global", "show-networks"): [
                {
                    "uid": "g-net-dmz",
                    "name": "N_Global_DMZ_Sub",
                    "type": "network",
                    "subnet4": "172.16.10.0",
                    "mask-length4": 24,
                }
            ],
            ("Global", "show-groups"): [
                {
                    "uid": "g-grp-dmz",
                    "name": "G_Global_DMZ",
                    "type": "group",
                    "members": ["g-net-dmz"],
                }
            ],
            ("Corp", "show-hosts"): [
                {
                    "uid": "corp-h-1",
                    "name": "H_Corp_Workstation_1",
                    "type": "host",
                    "ipv4-address": "10.10.1.25",
                }
            ],
            ("DC", "show-hosts"): [
                {
                    "uid": "dc-h-1",
                    "name": "H_App_Server_1",
                    "type": "host",
                    "ipv4-address": "10.20.1.5",
                }
            ],
            ("DC", "show-networks"): [
                {
                    "uid": "dc-n-1",
                    "name": "N_App_Net",
                    "type": "network",
                    "subnet4": "10.20.2.0",
                    "mask-length4": 24,
                }
            ],
            ("DC", "show-address-ranges"): [
                {
                    "uid": "dc-r-1",
                    "name": "R_App_Pool",
                    "type": "address-range",
                    "ipv4-address-first": "10.20.3.10",
                    "ipv4-address-last": "10.20.3.20",
                }
            ],
            ("DC", "show-groups"): [
                # Nested group with a deliberate cycle (`dc-g-parent` <-> `dc-g-child`) to test cycle protection
                {
                    "uid": "dc-g-parent",
                    "name": "G_DC_Apps",
                    "type": "group",
                    "members": ["dc-h-1", "dc-n-1", "dc-g-child"],
                },
                {
                    "uid": "dc-g-child",
                    "name": "G_DC_Apps_Sub",
                    "type": "group",
                    "members": ["dc-r-1", "dc-g-parent"],
                },
            ],
        }

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        if command == "show-last-published-session":
            return ApiCallResult(
                success=True,
                data={"uid": f"sess-{domain}", "publish-time": {"iso-8601": "2026-11-03T12:00:00Z"}},
            )
        if command == "show-session":
            return ApiCallResult(success=True, data={"locks": 0, "changes": 0, "number-of-published-changes": 0})
        if command == "show-simple-cluster" and payload:
            uid = str(payload.get("uid") or "")
            if uid in self.cluster_details_by_uid:
                return ApiCallResult(success=True, data=self.cluster_details_by_uid[uid])
        return ApiCallResult(success=True, data={})

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        dom = domain or "Corp"
        if command == "show-gateways-and-servers":
            objs = self.gateways_by_domain.get(dom, [])
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
        if command == "show-generic-objects" and payload:
            cls_name = str(payload.get("class-name") or "")
            objs = self.generic_objects_by_class.get((dom, cls_name), [])
            return ApiQueryResult(success=True, objects=objs, total=len(objs))
        objs = self.objects_by_domain_and_cmd.get((dom, command), [])
        return ApiQueryResult(success=True, objects=objs, total=len(objs))

    async def create_dedicated_session(
        self,
        mgmt_name: str,
        domain: str | None = None,
        *,
        auth: AuthContext | None = None,
        session_name: str | None = None,
        session_description: str | None = None,
    ) -> tuple[str, str]:
        return "ded-sid", "10.0.0.1"

    def logout_sid(
        self,
        mgmt_name: str,
        sid: str,
        *,
        server_ip: str | None = None,
    ) -> Awaitable[bool]:
        async def _noop() -> bool:
            return True

        return _noop()

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.asyncio
async def test_topology_extraction_group_expansion_vs_routes_and_candidate_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `TopologyService` extracts connected/specific/VS-routed/external intervals, skips VS0 & members, emits warnings on routing-defined interfaces, and matches affected gateways."""
    from arodonata.core.services import topology_service as topo_mod

    warning_calls: list[tuple[str, dict[str, Any]]] = []
    orig_warning = topo_mod.logger.warning

    def _spy_warning(msg: str, *args: Any, **kwargs: Any) -> None:
        warning_calls.append((msg, kwargs))
        orig_warning(msg, *args, **kwargs)

    monkeypatch.setattr(topo_mod.logger, "warning", _spy_warning)

    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d-global", name="Global", active_ip="10.0.0.1", is_global=True),
            DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d-dc", name="DC", active_ip="10.2.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(
                mgmt_name="mds1",
                uid="d-tenant",
                name="TenantVS",
                active_ip="10.3.0.1",
                active_mds_ip="10.0.0.1",
            ),
        ]
    )

    # Seed a cached rulebase snapshot in DC to test policy package & access layer enrichment
    await cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="DC",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="DC",
                    package_uid="pkg-core-uid",
                    package_name="Core_Pkg",
                    rulebase_type="access",
                    layer_uid="layer-net-uid",
                    layer_name="Core_Pkg Network",
                    position=1,
                    raw_data={"installation-targets": ["dc-core-gw"]},
                )
            ],
            layers=[
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="DC",
                    uid="layer-net-uid",
                    name="Core_Pkg Network",
                    rulebase_type="access",
                )
            ],
        )
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    object_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )
    search_service = SearchService(
        cache=cache,
        object_service=object_service,
        asset_service=asset_service,
    )

    # 1. Refresh topology across all domains
    outcome = await topology_service.refresh_topology(mgmt_name="mds1", mode="force")
    assert set(outcome.refreshed_domains) == {"mds1:Corp", "mds1:DC", "mds1:TenantVS"}

    # Verify structured warning was emitted for bond0.99 ("network defined by routing") on dc-core-gw
    assert any(
        "mds1:DC:dc-core-gw :: bond0.99" in msg
        and kw.get("gateway_name") == "dc-core-gw"
        and kw.get("interface_name") == "bond0.99"
        and kw.get("behind_mode") == "network defined by routing"
        for msg, kw in warning_calls
    )

    # Verify SearchService.get_cache_status includes "topology" scope
    status = await search_service.get_cache_status(mgmt_name="mds1", scope="topology")
    assert status["total_entries"] == 3
    assert "topology" in status["by_scope"]

    # 2. Verify target filtering: cluster-member ("cm-corp-1a"), checkpoint-host ("mgmt-host-1"),
    # and physical VSX ("vsx-dc-1") must NOT have any entries in arodonata_gateway_topology
    all_entries = await topology_service.get_gateway_topology(mgmt_name="mds1", cache_mode="cache")
    indexed_gw_uids = {e.gateway_uid for e in all_entries}
    assert indexed_gw_uids == {"cl-corp-1", "gw-branch-1", "gw-dc-core", "vs-tenant-1"}
    assert "cm-corp-1a" not in indexed_gw_uids
    assert "vsx-dc-1" not in indexed_gw_uids
    assert "mgmt-host-1" not in indexed_gw_uids

    # 3. Verify on-demand cluster detail fallback & Global group expansion on "cl-corp-1"
    corp_cl_entries = await topology_service.get_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        gateway="corp-perimeter-cluster",
        cache_mode="cache",
    )
    corp_by_if = {(e.interface_name, e.cidr_or_range): e for e in corp_cl_entries}
    assert ("eth0", "0.0.0.0/0") in corp_by_if
    assert corp_by_if[("eth0", "0.0.0.0/0")].topology_zone == "external"
    assert corp_by_if[("eth0", "0.0.0.0/0")].source_type == "external_interface"
    assert ("eth1", "10.10.1.0/24") in corp_by_if
    assert corp_by_if[("eth1", "10.10.1.0/24")].source_type == "interface_connected"
    assert ("eth2", "172.16.10.0/24") in corp_by_if
    assert corp_by_if[("eth2", "172.16.10.0/24")].source_type == "interface_specific"
    assert corp_by_if[("eth2", "172.16.10.0/24")].leads_to_dmz is True

    # 4. Verify recursive group expansion with cycle protection on "gw-dc-core"
    dc_entries = await topology_service.get_gateway_topology(
        mgmt_name="mds1",
        domain="DC",
        gateway="dc-core-gw",
        cache_mode="cache",
    )
    dc_cidrs_by_if = {(e.interface_name, e.cidr_or_range): e.source_type for e in dc_entries}
    assert dc_cidrs_by_if == {
        ("bond0.10", "10.10.1.0/24"): "interface_connected",
        ("bond0.20", "10.20.1.5/32"): "interface_specific",
        ("bond0.20", "10.20.2.0/24"): "interface_specific",
        ("bond0.20", "10.20.3.10-10.20.3.20"): "interface_specific",
    }

    # 5. Verify VS static route extraction on "vs-tenant-1" in TenantVS domain
    vs_entries = await topology_service.get_gateway_topology(
        mgmt_name="mds1",
        domain="TenantVS",
        gateway="vsx1_VS_Tenant",
        cache_mode="cache",
    )
    vs_by_if_cidr = {(e.interface_name, e.cidr_or_range): e for e in vs_entries}
    assert ("eth1.50", "10.50.0.0/24") in vs_by_if_cidr
    assert ("eth1.50", "172.16.80.0/24") in vs_by_if_cidr
    assert vs_by_if_cidr[("eth1.50", "172.16.80.0/24")].source_type == "vs_static_route"
    assert vs_by_if_cidr[("eth1.50", "172.16.80.0/24")].topology_zone == "internal"
    assert ("wrp128", "0.0.0.0/0") in vs_by_if_cidr
    assert vs_by_if_cidr[("wrp128", "0.0.0.0/0")].source_type == "vs_static_route"
    assert vs_by_if_cidr[("wrp128", "0.0.0.0/0")].topology_zone == "external"

    summaries = topology_service.summarize_gateway_interfaces(vs_entries)
    sum_by_if = {s.interface_name: s for s in summaries}
    assert sum_by_if["wrp128"].topology_zone == "external"
    assert sum_by_if["eth1.50"].topology_zone == "internal"
    assert "172.16.80.0/24" in sum_by_if["eth1.50"].cidrs_and_ranges

    # 6. Test `find_affected_gateways`:
    # Flow 1: 10.10.1.25 -> 10.20.2.50
    # - On `dc-core-gw` (DC): 10.10.1.25 is on `bond0.10` (internal), 10.20.2.50 is on `bond0.20` (internal)
    #   -> MATCH (`internal_to_internal`, `bond0.10 -> bond0.20`, package `Core_Pkg`, layer `Core_Pkg Network`)
    # - On `corp-perimeter-cluster` (Corp): 10.10.1.25 is on `eth1` (internal), 10.20.2.50 is not behind any
    #   internal interface so falls back to `eth0` (external)
    #   -> MATCH (`internal_to_external`, `eth1 -> eth0`, package `Perimeter_Pkg`)
    # - On `branch-gw-01` (Corp): neither 10.10.1.25 nor 10.20.2.50 is behind `eth1` (192.168.50.0/24),
    #   so BOTH fall back to `eth0` (external == external)
    #   -> EXCLUDED!
    # - On `vsx1_VS_Tenant` (TenantVS): neither is behind `eth1.50`, so both fall back to `wrp128` (external == external)
    #   -> EXCLUDED!
    candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["10.20.2.50"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert [c.gateway_name for c in candidates] == ["dc-core-gw", "corp-perimeter-cluster"]

    dc_cand = candidates[0]
    assert dc_cand.domain_name == "DC"
    assert dc_cand.installed_access_policy == "Core_Pkg"
    assert dc_cand.policy_packages == ["Core_Pkg"]
    assert dc_cand.access_layers == ["Core_Pkg Network"]
    assert dc_cand.match_types == ["internal_to_internal"]
    assert dc_cand.matched_sources == ["10.10.1.25"]
    assert dc_cand.matched_destinations == ["10.20.2.50"]
    assert len(dc_cand.matched_flows) == 1
    assert dc_cand.matched_flows[0].src_interface == "bond0.10"
    assert dc_cand.matched_flows[0].dst_interface == "bond0.20"

    corp_cand = candidates[1]
    assert corp_cand.domain_name == "Corp"
    assert corp_cand.installed_access_policy == "Perimeter_Pkg"
    assert corp_cand.policy_packages == ["Perimeter_Pkg"]
    assert corp_cand.match_types == ["internal_to_external"]
    assert corp_cand.matched_sources == ["10.10.1.25"]
    assert corp_cand.matched_destinations == ["10.20.2.50"]
    assert corp_cand.matched_flows[0].src_interface == "eth1"
    assert corp_cand.matched_flows[0].dst_interface == "eth0"

    # 7. Test same-interface exclusion: 10.10.1.10 -> 10.10.1.99
    # Both sit behind `eth1` on `corp-perimeter-cluster` and `bond0.10` on `dc-core-gw`,
    # and both fall back to external on `branch-gw-01` and `vsx1_VS_Tenant` -> ZERO affected gateways!
    same_if_candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.10"],
        destinations=["10.10.1.99"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert same_if_candidates == []

    # 8. Test VS static route matching and external_to_internal flow:
    # 8.8.8.8 -> 172.16.80.45 (routed via static route on `eth1.50` of `vsx1_VS_Tenant`, external via `wrp128`)
    vs_candidates = await topology_service.find_affected_gateways(
        sources=["8.8.8.8"],
        destinations=["172.16.80.45"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert len(vs_candidates) == 1
    vs_cand = vs_candidates[0]
    assert vs_cand.gateway_name == "vsx1_VS_Tenant"
    assert vs_cand.domain_name == "TenantVS"
    assert vs_cand.parent_asset_id == "mds1:DC:dc-vsx-chassis"
    assert vs_cand.installed_access_policy == "Tenant_VS_Policy"
    assert vs_cand.match_types == ["external_to_internal"]
    assert vs_cand.matched_flows[0].src_interface == "wrp128"
    assert vs_cand.matched_flows[0].dst_interface == "eth1.50"
    assert vs_cand.matched_flows[0].dst_source_type == "vs_static_route"

    # 9. Test resolving by Check Point object/group name ("H_Corp_Workstation_1" -> "N_Global_DMZ_Sub")
    # Also verify domain-scoped name isolation (T7): "H_App_Server_1" is defined only in "DC", so it must
    # NOT resolve on "Corp" gateways!
    named_candidates = await topology_service.find_affected_gateways(
        sources=["H_Corp_Workstation_1"],
        destinations=["N_Global_DMZ_Sub"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert {c.gateway_name for c in named_candidates} == {"corp-perimeter-cluster"}
    assert named_candidates[0].matched_flows[0].src_interface == "eth1"
    assert named_candidates[0].matched_flows[0].dst_interface == "eth2"
    assert named_candidates[0].matched_flows[0].match_type == "internal_to_internal"

    cross_domain_isolated = await topology_service.find_affected_gateways(
        sources=["H_App_Server_1"],
        destinations=["N_Global_DMZ_Sub"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    assert cross_domain_isolated == []

    # 10. Test broad CIDR / Any (0.0.0.0/0) multi-interface and external fallback matching (T1):
    # From 10.10.1.25 (behind `eth1` on `corp-perimeter-cluster` and `bond0.10` on `dc-core-gw`,
    # and external on `branch-gw-01` and `vsx1_VS_Tenant`) to 0.0.0.0/0:
    # - On `dc-core-gw` (no external interface): matches `bond0.10` -> `bond0.20` (`internal_to_internal`).
    # - On `corp-perimeter-cluster`: matches `eth1` -> `eth2` (`internal_to_internal`) AND `eth1` -> `eth0` (`internal_to_external`).
    # - On `branch-gw-01`: matches `eth0` (`external`) -> `eth1` (`internal`, `192.168.50.0/24`) while `eth0` -> `eth0` (`external_to_external`) is excluded!
    # - On `vsx1_VS_Tenant`: matches `wrp128` (`external`) -> `eth1.50` (`internal`, `10.50.0.0/24` / `172.16.80.0/24`) while `wrp128` -> `wrp128` (`external_to_external`) is excluded!
    any_dst_candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["0.0.0.0/0"],
        mgmt_name="mds1",
        cache_mode="cache",
    )
    by_gw = {c.gateway_name: c for c in any_dst_candidates}
    assert set(by_gw.keys()) == {"dc-core-gw", "corp-perimeter-cluster", "branch-gw-01", "vsx1_VS_Tenant"}
    assert {(f.src_interface, f.dst_interface, f.match_type) for f in by_gw["dc-core-gw"].matched_flows} == {
        ("bond0.10", "bond0.20", "internal_to_internal")
    }
    assert {
        (f.src_interface, f.dst_interface, f.match_type) for f in by_gw["corp-perimeter-cluster"].matched_flows
    } == {
        ("eth1", "eth2", "internal_to_internal"),
        ("eth1", "eth0", "internal_to_external"),
    }
    assert {(f.src_interface, f.dst_interface, f.match_type) for f in by_gw["branch-gw-01"].matched_flows} == {
        ("eth0", "eth1", "external_to_internal")
    }
    assert {(f.src_interface, f.dst_interface, f.match_type) for f in by_gw["vsx1_VS_Tenant"].matched_flows} == {
        ("wrp128", "eth1.50", "external_to_internal")
    }

    await db.close()


@pytest.mark.asyncio
async def test_topology_cache_only_mode_never_calls_live_api_and_host_ckp_firewall_blade_filter() -> None:
    """Verify `cache_mode='cache'` does not trigger live detail API calls when topology table is cold (T2) and `CpmiHostCkp` requires `firewall=True` (T6)."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()
    api_calls: list[str] = []
    orig_api_call = api.api_call

    async def _spy_api_call(mgmt_name: str, command: str, *args: Any, **kwargs: Any) -> ApiCallResult:
        api_calls.append(command)
        return await orig_api_call(mgmt_name, command, *args, **kwargs)

    api.api_call = _spy_api_call  # type: ignore[method-assign]

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    object_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )

    # Seed cached assets in Corp:
    # 1) `corp-perimeter-cluster` with empty interfaces (normally triggers on-demand `show-simple-cluster`)
    # 2) `mgmt-host-ckp` (`CpmiHostCkp` with `firewall=False`, which must be excluded by `is_policy_enforcing_gateway`)
    # 3) `fw-host-ckp` (`CpmiHostCkp` with `firewall=True`, which must be included)
    await cache.replace_domain_assets(
        "mds1",
        "Corp",
        [
            Asset(
                uid="cl-corp-1",
                name="corp-perimeter-cluster",
                type="simple-cluster",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[],
            ),
            Asset(
                uid="host-mgmt-1",
                name="mgmt-host-ckp",
                type="CpmiHostCkp",
                mgmt_name="mds1",
                domain_name="Corp",
                network_security_blades={"firewall": False},
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "10.10.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.20.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
            Asset(
                uid="host-fw-1",
                name="fw-host-ckp",
                type="CpmiHostCkp",
                mgmt_name="mds1",
                domain_name="Corp",
                network_security_blades={"firewall": True},
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "10.10.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.20.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
        ],
    )

    # With cold `arodonata_gateway_topology` cache and `cache_mode="cache"`, `find_affected_gateways`
    # derives topology in-memory from cached assets/objects WITHOUT calling `show-simple-cluster`!
    candidates = await topology_service.find_affected_gateways(
        sources=["10.10.1.10"],
        destinations=["10.20.1.20"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert api_calls == []
    assert [c.gateway_name for c in candidates] == ["fw-host-ckp"]
    assert candidates[0].matched_sources == ["10.10.1.10"]
    assert candidates[0].matched_destinations == ["10.20.1.20"]

    await db.close()


@pytest.mark.asyncio
async def test_four_gateway_transit_topology_filters_matched_sources_and_destinations_in_input_order() -> None:
    """Verify 4-gateway topology (`GW1`, `GW2`, transit `GW3` + local networks, and `GW4` behind `GW3`) filters `matched_sources` and `matched_destinations` per gateway in strict input order."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    object_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )

    # Seed Check Point network/group objects in domain "Corp" for specific interface topologies and named endpoints:
    # - `N_GW1_Lan`: 10.1.0.0/24 (behind GW1 eth1)
    # - `N_GW2_Lan`: 10.2.0.0/24 (behind GW2 eth1)
    # - `G_Upstream_Branches`: group containing `N_GW1_Lan` and `N_GW2_Lan` (behind GW3 eth1)
    # - `N_GW3_Local`: 10.3.0.0/24 (behind GW3 eth2)
    # - `N_GW4_Lan`: 10.4.0.0/24 (behind GW3 eth3 and GW4 eth1)
    # - `H_GW2_Client`: host 10.2.0.20 (in GW2's LAN)
    await cache.upsert_objects(
        [
            CPObject(
                uid="obj-n-gw1",
                name="N_GW1_Lan",
                type="network",
                mgmt_name="mds1",
                domain_name="Corp",
                subnet4="10.1.0.0",
                mask_length4=24,
            ),
            CPObject(
                uid="obj-n-gw2",
                name="N_GW2_Lan",
                type="network",
                mgmt_name="mds1",
                domain_name="Corp",
                subnet4="10.2.0.0",
                mask_length4=24,
            ),
            CPObject(
                uid="obj-g-branches",
                name="G_Upstream_Branches",
                type="group",
                mgmt_name="mds1",
                domain_name="Corp",
                members=["obj-n-gw1", "obj-n-gw2"],
            ),
            CPObject(
                uid="obj-n-gw3",
                name="N_GW3_Local",
                type="network",
                mgmt_name="mds1",
                domain_name="Corp",
                subnet4="10.3.0.0",
                mask_length4=24,
            ),
            CPObject(
                uid="obj-n-gw4",
                name="N_GW4_Lan",
                type="network",
                mgmt_name="mds1",
                domain_name="Corp",
                subnet4="10.4.0.0",
                mask_length4=24,
            ),
            CPObject(
                uid="obj-h-gw2-client",
                name="H_GW2_Client",
                type="host",
                mgmt_name="mds1",
                domain_name="Corp",
                ipv4_address="10.2.0.20",
            ),
        ],
    )

    # Seed 4 gateways in domain "Corp":
    # - GW1: eth1 = 10.1.0.0/24 (internal connected), eth0 = external (0.0.0.0/0)
    # - GW2: eth1 = 10.2.0.0/24 (internal connected), eth0 = external (0.0.0.0/0)
    # - GW3 (transit + own local networks):
    #     eth1 = specific `G_Upstream_Branches` (10.1.0.0/24, 10.2.0.0/24)
    #     eth2 = 10.3.0.0/24 (internal connected, GW3's own local subnet)
    #     eth3 = specific `N_GW4_Lan` (10.4.0.0/24, leading to GW4)
    # - GW4 (behind GW3):
    #     eth0 = external (0.0.0.0/0, pointing upstream toward GW3)
    #     eth1 = 10.4.0.0/24 (internal connected)
    await cache.replace_domain_assets(
        "mds1",
        "Corp",
        [
            Asset(
                uid="uid-gw1",
                name="GW1",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "172.31.1.1",
                        "ipv4-mask-length": 30,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.1.0.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
            Asset(
                uid="uid-gw2",
                name="GW2",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "172.31.2.1",
                        "ipv4-mask-length": 30,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.2.0.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
            Asset(
                uid="uid-gw3",
                name="GW3",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[
                    {
                        "name": "eth1",
                        "ipv4-address": "172.31.0.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_Upstream_Branches",
                        },
                    },
                    {
                        "name": "eth2",
                        "ipv4-address": "10.3.0.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                    {
                        "name": "eth3",
                        "ipv4-address": "172.31.34.1",
                        "ipv4-mask-length": 30,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "N_GW4_Lan",
                        },
                    },
                ],
            ),
            Asset(
                uid="uid-gw4",
                name="GW4",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "172.31.34.2",
                        "ipv4-mask-length": 30,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.4.0.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
        ],
    )

    # Case A: Multi-branch & transit flow with all 4 gateways affected, testing per-gateway filtering and input order:
    # Sources (in deliberate order, plus duplicate to verify deduplication):
    #   ["10.3.0.30", "H_GW2_Client", "10.1.0.10", "10.3.0.30"]
    #   - "10.3.0.30" is in GW3's own local subnet (10.3.0.0/24 on GW3 eth2)
    #   - "H_GW2_Client" (10.2.0.20) is in GW2's subnet (10.2.0.0/24 on GW2 eth1, GW3 eth1)
    #   - "10.1.0.10" is in GW1's subnet (10.1.0.0/24 on GW1 eth1, GW3 eth1)
    # Destinations (in deliberate order):
    #   ["10.4.0.40", "10.3.0.99", "10.1.0.99"]
    #   - "10.4.0.40" is behind GW4 eth1 (and GW3 eth3)
    #   - "10.3.0.99" is behind GW3 eth2 (same subnet as source "10.3.0.30"!)
    #   - "10.1.0.99" is behind GW1 eth1 (same subnet as source "10.1.0.10"!)
    #
    # Expected per gateway:
    # - GW1:
    #   - "10.1.0.10" (eth1) -> "10.4.0.40" (eth0) and "10.3.0.99" (eth0) [internal_to_external]
    #   - "10.3.0.30" (eth0) -> "10.1.0.99" (eth1) and "H_GW2_Client" (eth0) -> "10.1.0.99" (eth1) [external_to_internal]
    #   - "10.1.0.10" -> "10.1.0.99" is same-interface (eth1 == eth1) -> excluded!
    #   - All 3 unique sources and all 3 destinations participate in cross-interface flows on GW1.
    # - GW2:
    #   - Only "H_GW2_Client" is on eth1 (internal); "10.3.0.30" and "10.1.0.10" are on eth0 (external).
    #   - All 3 destinations ("10.4.0.40", "10.3.0.99", "10.1.0.99") are on eth0 (external).
    #   - Therefore ONLY "H_GW2_Client" (eth1) -> ("10.4.0.40", "10.3.0.99", "10.1.0.99") (eth0) crosses GW2!
    #   - `matched_sources` on GW2 MUST be `["H_GW2_Client"]` (excluding "10.3.0.30" and "10.1.0.10").
    #   - `matched_destinations` on GW2 MUST be `["10.4.0.40", "10.3.0.99", "10.1.0.99"]`.
    # - GW3 (transit + local):
    #   - "10.3.0.30" is on eth2; "H_GW2_Client" and "10.1.0.10" are on eth1.
    #   - "10.4.0.40" is on eth3; "10.3.0.99" is on eth2; "10.1.0.99" is on eth1.
    #   - "10.3.0.30" (eth2) -> "10.4.0.40" (eth3) and "10.1.0.99" (eth1) [eth2 -> eth2 for 10.3.0.99 excluded].
    #   - "H_GW2_Client" (eth1) -> "10.4.0.40" (eth3) and "10.3.0.99" (eth2) [eth1 -> eth1 for 10.1.0.99 excluded].
    #   - "10.1.0.10" (eth1) -> "10.4.0.40" (eth3) and "10.3.0.99" (eth2) [eth1 -> eth1 for 10.1.0.99 excluded].
    #   - `matched_sources` on GW3 MUST be `["10.3.0.30", "H_GW2_Client", "10.1.0.10"]` (in exact input order).
    #   - `matched_destinations` on GW3 MUST be `["10.4.0.40", "10.3.0.99", "10.1.0.99"]` (in exact input order).
    # - GW4:
    #   - All 3 sources are on eth0 (external).
    #   - Only "10.4.0.40" is on eth1 (internal); "10.3.0.99" and "10.1.0.99" are on eth0 (external).
    #   - `matched_sources` on GW4 MUST be `["10.3.0.30", "H_GW2_Client", "10.1.0.10"]`.
    #   - `matched_destinations` on GW4 MUST be `["10.4.0.40"]` (excluding "10.3.0.99" and "10.1.0.99").
    candidates_all = await topology_service.find_affected_gateways(
        sources=["10.3.0.30", "H_GW2_Client", "10.1.0.10", "10.3.0.30"],
        destinations=["10.4.0.40", "10.3.0.99", "10.1.0.99"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    by_gw_all = {c.gateway_name: c for c in candidates_all}
    assert set(by_gw_all.keys()) == {"GW1", "GW2", "GW3", "GW4"}

    assert by_gw_all["GW1"].matched_sources == ["10.3.0.30", "H_GW2_Client", "10.1.0.10"]
    assert by_gw_all["GW1"].matched_destinations == ["10.4.0.40", "10.3.0.99", "10.1.0.99"]

    assert by_gw_all["GW2"].matched_sources == ["H_GW2_Client"]
    assert by_gw_all["GW2"].matched_destinations == ["10.4.0.40", "10.3.0.99", "10.1.0.99"]

    assert by_gw_all["GW3"].matched_sources == ["10.3.0.30", "H_GW2_Client", "10.1.0.10"]
    assert by_gw_all["GW3"].matched_destinations == ["10.4.0.40", "10.3.0.99", "10.1.0.99"]
    assert by_gw_all["GW3"].match_types == ["internal_to_internal"]

    assert by_gw_all["GW4"].matched_sources == ["10.3.0.30", "H_GW2_Client", "10.1.0.10"]
    assert by_gw_all["GW4"].matched_destinations == ["10.4.0.40"]

    # Case B: Subset of gateways affected (GW2 is NOT affected at all; GW1 only matches 1 source;
    # GW4 only matches 1 destination; GW3 transits both sources to their respective cross-interface destinations,
    # and destination ordering in `matched_destinations` strictly preserves input order even when the first
    # source only matches the second destination):
    # Sources: ["10.3.0.30", "10.1.0.10"]
    #   - "10.3.0.30" (GW3 eth2)
    #   - "10.1.0.10" (GW1 eth1, GW3 eth1)
    # Destinations: ["10.3.0.99", "10.4.0.40"]
    #   - "10.3.0.99" (GW3 eth2) -> Note: for first source "10.3.0.30", "10.3.0.99" is on the SAME interface (eth2 == eth2),
    #     so "10.3.0.30" only matches the SECOND destination "10.4.0.40" (eth3), whereas second source "10.1.0.10" (eth1)
    #     matches BOTH "10.3.0.99" (eth2) and "10.4.0.40" (eth3).
    #     `matched_destinations` on GW3 MUST still be `["10.3.0.99", "10.4.0.40"]` (input order, NOT flow-discovery order!).
    #   - On GW2: both sources and both destinations fall back to eth0 (external == external) -> GW2 is EXCLUDED!
    #   - On GW1: only "10.1.0.10" is on eth1; both destinations are on eth0 -> `matched_sources=["10.1.0.10"]`, `matched_destinations=["10.3.0.99", "10.4.0.40"]`.
    #   - On GW4: both sources are on eth0; only "10.4.0.40" is on eth1 ("10.3.0.99" is on eth0) -> `matched_sources=["10.3.0.30", "10.1.0.10"]`, `matched_destinations=["10.4.0.40"]`.
    candidates_sub = await topology_service.find_affected_gateways(
        sources=["10.3.0.30", "10.1.0.10"],
        destinations=["10.3.0.99", "10.4.0.40"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    by_gw_sub = {c.gateway_name: c for c in candidates_sub}
    assert set(by_gw_sub.keys()) == {"GW1", "GW3", "GW4"}
    assert "GW2" not in by_gw_sub

    assert by_gw_sub["GW1"].matched_sources == ["10.1.0.10"]
    assert by_gw_sub["GW1"].matched_destinations == ["10.3.0.99", "10.4.0.40"]

    assert by_gw_sub["GW3"].matched_sources == ["10.3.0.30", "10.1.0.10"]
    assert by_gw_sub["GW3"].matched_destinations == ["10.3.0.99", "10.4.0.40"]

    assert by_gw_sub["GW4"].matched_sources == ["10.3.0.30", "10.1.0.10"]
    assert by_gw_sub["GW4"].matched_destinations == ["10.4.0.40"]

    # Case C: Traffic between GW1 ("10.1.0.10") and GW2 ("H_GW2_Client"):
    # - On GW1: "10.1.0.10" (eth1) -> "H_GW2_Client" (eth0) -> AFFECTED
    # - On GW2: "10.1.0.10" (eth0) -> "H_GW2_Client" (eth1) -> AFFECTED
    # - On GW3: both "10.1.0.10" and "H_GW2_Client" sit behind eth1 (`G_Upstream_Branches`, `src_interface == dst_interface == "eth1"`) -> EXCLUDED!
    # - On GW4: both sit behind eth0 (`external == external`) -> EXCLUDED!
    candidates_branch_to_branch = await topology_service.find_affected_gateways(
        sources=["10.1.0.10"],
        destinations=["H_GW2_Client"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert {c.gateway_name for c in candidates_branch_to_branch} == {"GW1", "GW2"}
    for cand in candidates_branch_to_branch:
        assert cand.matched_sources == ["10.1.0.10"]
        assert cand.matched_destinations == ["H_GW2_Client"]

    await db.close()


@pytest.mark.asyncio
async def test_multi_package_domain_resolves_only_single_last_installed_gateway_policy() -> None:
    """Verify multi-package domains resolve only the single last-installed policy per gateway/cluster (ignoring `installation-targets: 'all'`) and enrich `get_gateway_topology` entries."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    object_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )

    # Seed 3 policy packages in domain "AME-BR" all having installation-targets="all"
    await cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="AME-BR",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="AME-BR",
                    package_uid="pkg-bre-ext",
                    package_name="BR-BRE-EXT",
                    rulebase_type="access",
                    layer_uid="layer-bre-ext",
                    layer_name="BR-BRE-EXT Network",
                    position=1,
                    raw_data={"installation-targets": "all"},
                ),
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="AME-BR",
                    package_uid="pkg-bre-vpn",
                    package_name="BR-BRE-VPN",
                    rulebase_type="access",
                    layer_uid="layer-bre-vpn",
                    layer_name="BR-BRE-VPN Network",
                    position=1,
                    raw_data={"installation-targets": "all"},
                ),
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="AME-BR",
                    package_uid="pkg-spo-ext",
                    package_name="BR-SPO-EXT",
                    rulebase_type="access",
                    layer_uid="layer-spo-ext",
                    layer_name="BR-SPO-EXT Network",
                    position=1,
                    raw_data={"installation-targets": "all"},
                ),
            ],
        )
    )

    # Seed 2 clusters in "AME-BR":
    # 1. `BR-BRE-EXT-FW-CL-01`: has top-level `policy.access-policy-name = "BR-BRE-EXT"`
    # 2. `BR-BRE-VPN-FW-CL-01`: has no top-level `access-policy-name`, but has 2 cluster members with
    #    different installation timestamps (member B installed `BR-BRE-VPN` more recently than member A's `BR-SPO-EXT`)
    await cache.replace_domain_assets(
        "mds1",
        "AME-BR",
        [
            Asset(
                uid="cl-bre-ext",
                name="BR-BRE-EXT-FW-CL-01",
                type="CpmiGatewayCluster",
                mgmt_name="mds1",
                domain_name="AME-BR",
                raw_data={
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "BR-BRE-EXT",
                        "access-policy-installation-date": {"posix": 1739446673991},
                    }
                },
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "198.51.100.1",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.60.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
            Asset(
                uid="cl-bre-vpn",
                name="BR-BRE-VPN-FW-CL-01",
                type="CpmiGatewayCluster",
                mgmt_name="mds1",
                domain_name="AME-BR",
                member_uids=["cm-vpn-a", "cm-vpn-b"],
                raw_data={},
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "198.51.100.2",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.60.2.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                ],
            ),
            Asset(
                uid="cm-vpn-a",
                name="BR-BRE-VPN-FW-01A",
                type="cluster-member",
                mgmt_name="mds1",
                domain_name="AME-BR",
                parent_uid="cl-bre-vpn",
                raw_data={
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "BR-SPO-EXT",
                        "access-policy-installation-date": {"posix": 1700000000000},
                    }
                },
            ),
            Asset(
                uid="cm-vpn-b",
                name="BR-BRE-VPN-FW-01B",
                type="cluster-member",
                mgmt_name="mds1",
                domain_name="AME-BR",
                parent_uid="cl-bre-vpn",
                raw_data={
                    "policy": {
                        "access-policy-installed": True,
                        "access-policy-name": "BR-BRE-VPN",
                        "access-policy-installation-date": {"posix": 1750000000000},
                    }
                },
            ),
        ],
    )

    candidates = await topology_service.find_affected_gateways(
        sources=["10.60.1.10", "10.60.2.10"],
        destinations=["8.8.8.8"],
        mgmt_name="mds1",
        domain="AME-BR",
        cache_mode="cache",
    )
    by_gw = {c.gateway_name: c for c in candidates}
    assert set(by_gw.keys()) == {"BR-BRE-EXT-FW-CL-01", "BR-BRE-VPN-FW-CL-01"}

    # Each cluster must have ONLY its own single last-installed policy package, NOT all 3 domain packages!
    assert by_gw["BR-BRE-EXT-FW-CL-01"].installed_access_policy == "BR-BRE-EXT"
    assert by_gw["BR-BRE-EXT-FW-CL-01"].policy_packages == ["BR-BRE-EXT"]
    assert by_gw["BR-BRE-EXT-FW-CL-01"].access_layers == ["BR-BRE-EXT Network"]

    assert by_gw["BR-BRE-VPN-FW-CL-01"].installed_access_policy == "BR-BRE-VPN"
    assert by_gw["BR-BRE-VPN-FW-CL-01"].policy_packages == ["BR-BRE-VPN"]
    assert by_gw["BR-BRE-VPN-FW-CL-01"].access_layers == ["BR-BRE-VPN Network"]

    # Also store topology entries and verify `get_gateway_topology` enriches `installed_access_policy` and `policy_packages`
    dom_assets = await cache.get_assets(mgmt_name="mds1", domain_name="AME-BR")
    extracted_entries, _ = await topology_service._extract_domain_topology_entries(
        mgmt_name="mds1",
        domain_name="AME-BR",
        assets=dom_assets,
        objects=[],
        allow_live_detail=False,
    )
    await cache.replace_domain_topology("mds1", "AME-BR", extracted_entries)

    topo_rows = await topology_service.get_gateway_topology(
        mgmt_name="mds1",
        domain="AME-BR",
        cache_mode="cache",
    )
    assert len(topo_rows) == 4
    rows_by_gw: dict[str, list[Any]] = {}
    for row in topo_rows:
        rows_by_gw.setdefault(row.gateway_name, []).append(row)

    for row in rows_by_gw["BR-BRE-EXT-FW-CL-01"]:
        assert row.installed_access_policy == "BR-BRE-EXT"
        assert row.policy_packages == ["BR-BRE-EXT"]

    for row in rows_by_gw["BR-BRE-VPN-FW-CL-01"]:
        assert row.installed_access_policy == "BR-BRE-VPN"
        assert row.policy_packages == ["BR-BRE-VPN"]

    await db.close()


@pytest.mark.asyncio
async def test_stream_refresh_topology_emits_assets_objects_and_per_gateway_progress_events() -> None:
    """Verify `stream_refresh_topology` yields `assets`, `objects`, and per-gateway `topology` progress events."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d-global", name="Global", active_ip="10.0.0.1", is_global=True),
            DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d-dc", name="DC", active_ip="10.2.0.1", active_mds_ip="10.0.0.1"),
        ]
    )

    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    object_service = ObjectService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
    )
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )

    events = [
        ev
        async for ev in topology_service.stream_refresh_topology(
            mgmt_name="mds1",
            domains=["Corp", "DC"],
            mode="force",
        )
    ]

    scopes = {ev.scope for ev in events}
    assert scopes == {"assets", "objects", "topology"}

    gw_progress_events = [
        ev
        for ev in events
        if ev.scope == "topology" and ev.event_type == "domain_sync_progress" and ev.details.get("gateway_name")
    ]
    gw_names_seen = {ev.details["gateway_name"] for ev in gw_progress_events}
    assert gw_names_seen == {"corp-perimeter-cluster", "branch-gw-01", "dc-core-gw"}

    by_gw_ev = {ev.details["gateway_name"]: ev for ev in gw_progress_events}
    assert by_gw_ev["corp-perimeter-cluster"].details["installed_access_policy"] == "Perimeter_Pkg"
    assert by_gw_ev["branch-gw-01"].details["installed_access_policy"] == "Branch_Pkg"
    assert by_gw_ev["dc-core-gw"].details["installed_access_policy"] == "Core_Pkg"

    await db.close()


def test_normalize_interface_leads_to_specific_network_and_cpmi_routes() -> None:
    """Verify `leads-to-specific-network` dict and CPMI `destination`/`nextHop` route formats are parsed."""
    from arodonata.core.services.topology_service import (
        _normalize_interface,
        _parse_route_destination,
        _parse_route_nexthop_and_interface,
    )

    nif = _normalize_interface(
        {
            "name": "eth2.14",
            "ipv4-address": "",
            "topology": {
                "leads-to-internet": False,
                "ip-address-behind-this-interface": "specific",
                "leads-to-specific-network": {
                    "uid": "b8c03a85-a092-485f-83c4-7601a5da1e1e",
                    "name": "n192.168",
                    "type": "network",
                    "subnet4": "192.168.0.0",
                    "mask-length4": 16,
                },
            },
        }
    )
    assert nif is not None
    assert nif.specific_network_uid == "b8c03a85-a092-485f-83c4-7601a5da1e1e"
    assert nif.specific_network_ref == "n192.168"
    assert nif.specific_inline_cidr == "192.168.0.0/16"

    route_dict = {
        "destination": {"ipaddr": "10.192.11.142", "netmask": "255.255.255.255"},
        "nextHop": "10.192.13.4",
        "interfaceName": "eth0",
    }
    dest_net = _parse_route_destination(route_dict)
    assert str(dest_net) == "10.192.11.142/32"
    nh_ip, explicit_if = _parse_route_nexthop_and_interface(route_dict)
    assert str(nh_ip) == "10.192.13.4"
    assert explicit_if == "eth0"


def test_topology_confidence_weights_and_cli_route_parsers() -> None:
    """Verify `TopologyConfidenceWeights` overrides, `vsenv` bash script generation, Base64 `cprid` decoding, and `ip route` / `clish` parsers."""
    import base64

    from arodonata.core.config import TopologyConfidenceWeights
    from arodonata.core.services.route_collector import (
        build_route_collection_script,
        decode_cprid_task_output,
        parse_combined_cli_routes,
    )

    weights = TopologyConfidenceWeights(route_connected=0.8, conflict_missing_in_live_routes=-0.4)
    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="secret",
        topology_confidence_weights=weights,
    )
    assert settings.topology_confidence_weights.route_connected == 0.8
    assert settings.topology_confidence_weights.conflict_missing_in_live_routes == -0.4

    # 1. Non-VSX and VSX script generation
    non_vs_script = build_route_collection_script(vsid=None)
    assert "vsenv" not in non_vs_script
    assert "ip -4 route show" in non_vs_script

    vs_script = build_route_collection_script(vsid=3)
    assert "vsid=3" in vs_script
    assert 'vsenv "$vsid" >/dev/null 2>&1 </dev/null' in vs_script
    assert "CTX%05d" in vs_script
    assert "_vs_error=context not switched" in vs_script

    # 2. Base64 cprid `run-script` response decoding
    raw_stdout = (
        "===ARODONATA_IP_ROUTE_START===\n"
        "default via 203.0.113.1 dev eth0 proto static\n"
        "10.10.1.0/24 dev eth1 proto kernel scope link src 10.10.1.1\n"
        "10.88.0.0/16 via 10.10.1.254 dev eth1 proto bgp metric 20\n"
        "10.89.0.0/16 via 10.10.1.253 dev eth1 proto ospf\n"
        "===ARODONATA_IP_ROUTE_END===\n"
        "===ARODONATA_CLISH_ROUTE_START===\n"
        "C 10.10.1.0/24 is directly connected, eth1\n"
        "S 10.77.0.0/16 via 10.10.1.254, eth1, cost 0, age 100\n"
        "B 10.88.0.0/16 via 10.10.1.254, eth1, cost 20, age 50\n"
        "O 10.90.0.0/16 via 10.10.1.252, eth1, cost 10, age 30\n"
        "===ARODONATA_CLISH_ROUTE_END===\n"
    )
    b64_msg = base64.b64encode(raw_stdout.encode("utf-8")).decode("ascii")
    ok, decoded, err = decode_cprid_task_output(
        {
            "tasks": [
                {
                    "status": "succeeded",
                    "task-details": [{"statusDescription": " succeeded", "responseMessage": b64_msg}],
                }
            ]
        }
    )
    assert ok is True
    assert err == ""
    assert decoded.strip() == raw_stdout.strip()

    parsed = parse_combined_cli_routes(decoded)
    by_cidr = {(r.interface_name, str(r.destination)): r.source_type for r in parsed}
    assert by_cidr[("eth0", "0.0.0.0/0")] == "gaia_static_route"
    assert by_cidr[("eth1", "10.10.1.0/24")] == "connected_route"
    assert by_cidr[("eth1", "10.88.0.0/16")] == "bgp_route"
    assert by_cidr[("eth1", "10.89.0.0/16")] == "ospf_route"
    assert by_cidr[("eth1", "10.77.0.0/16")] == "gaia_static_route"
    assert by_cidr[("eth1", "10.90.0.0/16")] == "ospf_route"


@pytest.mark.asyncio
async def test_topology_diagnostics_internal_only_and_one_arm_and_targeted_gateway_refresh() -> None:
    """Verify `get_topology_diagnostics` (internal-only = 0 warnings, one-arm = info, detect/not_defined/routing/unresolved/empty/missing_ip_mask = warning) and targeted per-gateway refresh."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    domain_service.tracker.mark_refreshed("mds1")
    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
        ]
    )
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(settings=settings, api=api, cache=cache, coordinator=coordinator)
    object_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )

    await cache.upsert_objects(
        [
            CPObject(
                uid="grp-empty",
                name="G_Empty_Group",
                type="group",
                mgmt_name="mds1",
                domain_name="Corp",
                members=[],
            ),
            CPObject(
                uid="net-valid",
                name="N_Valid_10_55",
                type="network",
                mgmt_name="mds1",
                domain_name="Corp",
                subnet4="10.55.0.0",
                mask_length4=24,
            ),
        ]
    )

    await cache.replace_domain_assets(
        "mds1",
        "Corp",
        [
            # 1. Pure internal segmentation gateway (NO external interface, well-defined Prevent interfaces) -> ZERO warnings!
            Asset(
                uid="gw-internal-clean",
                name="internal-seg-gw",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[
                    {
                        "name": "eth1",
                        "ipv4-address": "10.1.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                    {
                        "name": "eth2",
                        "ipv4-address": "10.1.2.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "N_Valid_10_55",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "prevent"},
                    },
                ],
            ),
            # 2. One-arm gateway (single external interface, e.g. Cisco ACI service graph) -> `one_arm_topology` (`info`)
            Asset(
                uid="gw-one-arm",
                name="aci-one-arm-gw",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "172.20.0.10",
                        "ipv4-mask-length": 24,
                        "topology": "external",
                    }
                ],
            ),
            # 3. Gateway with multiple static topology issues
            Asset(
                uid="gw-issues",
                name="issues-gw",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[
                    {
                        "name": "eth0",
                        "ipv4-address": "",
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "network defined by the interface ip and net mask"
                        },
                    },
                    {
                        "name": "eth1",
                        "ipv4-address": "10.10.1.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {"ip-address-behind-this-interface": "not defined"},
                    },
                    {
                        "name": "eth2",
                        "ipv4-address": "10.10.2.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {"ip-address-behind-this-interface": "network defined by routing"},
                    },
                    {
                        "name": "eth3",
                        "ipv4-address": "10.10.3.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_Missing_Object",
                        },
                    },
                    {
                        "name": "eth4",
                        "ipv4-address": "10.10.4.1",
                        "ipv4-mask-length": 24,
                        "topology": "internal",
                        "topology-settings": {
                            "ip-address-behind-this-interface": "specific",
                            "specific-network": "G_Empty_Group",
                        },
                        "anti-spoofing": True,
                        "anti-spoofing-settings": {"action": "detect"},
                    },
                ],
            ),
            # 4. Gateway with zero interfaces
            Asset(
                uid="gw-no-ifs",
                name="empty-gw",
                type="simple-gateway",
                mgmt_name="mds1",
                domain_name="Corp",
                interfaces=[],
            ),
        ],
    )

    all_diags = await topology_service.get_topology_diagnostics(
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    by_gw_codes: dict[str, set[tuple[str | None, str, str]]] = {}
    for d in all_diags:
        by_gw_codes.setdefault(d.gateway_name, set()).add((d.interface_name, d.code, d.severity))

    # Internal-only gateway must NOT appear in diagnostics at all
    assert "internal-seg-gw" not in by_gw_codes
    # One-arm gateway must have only `one_arm_topology` (`info`)
    assert by_gw_codes["aci-one-arm-gw"] == {("eth0", "one_arm_topology", "info")}
    # Empty gateway must have `no_interfaces` (`warning`)
    assert by_gw_codes["empty-gw"] == {(None, "no_interfaces", "warning")}
    # `issues-gw` must report all expected interface warnings
    assert by_gw_codes["issues-gw"] == {
        ("eth0", "missing_ip_mask", "warning"),
        ("eth1", "not_defined", "warning"),
        ("eth2", "routing_defined_without_routes", "warning"),
        ("eth3", "unresolved_specific", "warning"),
        ("eth4", "empty_specific", "warning"),
        ("eth4", "anti_spoofing_detect_or_off", "warning"),
    }

    # `min_severity="warning"` filters out `one_arm_topology` (`info`)
    warn_only = await topology_service.get_topology_diagnostics(
        mgmt_name="mds1",
        domain="Corp",
        min_severity="warning",
        cache_mode="cache",
    )
    assert all(d.severity == "warning" for d in warn_only)
    assert all(d.code != "one_arm_topology" for d in warn_only)

    await db.close()


@pytest.mark.asyncio
async def test_live_route_collection_reconciliation_annotations_and_confidence_scoring() -> None:
    """Verify SSH DI + `cprid` fallback route collection, cluster drift, reconciliation, annotations, IPAM export, and delta confidence scoring via `ArodonataClient`."""
    import base64

    from arodonata.client import ArodonataClient
    from arodonata.core.models.topology import (
        GatewayCliResult,
        GatewayCliTarget,
        TopologyAnnotation,
    )

    api = TopologyFakeApi()
    # Configure `run-script` fallback on `api` for `branch-gw-01`
    branch_cli_out = (
        "__ARODONATA_IP_ROUTE_START__\n"
        "default via 198.51.100.1 dev eth0 proto static\n"
        "192.168.50.0/24 dev eth1 proto kernel scope link src 192.168.50.1\n"
        "192.168.60.0/24 via 192.168.50.254 dev eth1 proto static\n"
        "__ARODONATA_IP_ROUTE_END__\n"
    )
    orig_api_call = api.api_call

    async def _custom_api_call(
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ApiCallResult:
        if command == "run-script":
            b64 = base64.b64encode(branch_cli_out.encode("utf-8")).decode("ascii")
            return ApiCallResult(
                success=True,
                data={
                    "tasks": [
                        {
                            "status": "succeeded",
                            "task-details": [{"statusDescription": "succeeded", "responseMessage": b64}],
                        }
                    ]
                },
            )
        return await orig_api_call(mgmt_name, command, payload, **kwargs)

    api.api_call = _custom_api_call  # type: ignore[method-assign]

    # Add a second cluster member to `Corp` so we can test cluster member drift on `corp-perimeter-cluster`
    api.gateways_by_domain["Corp"].append(
        {
            "uid": "cm-corp-1b",
            "name": "corp-perimeter-1b",
            "type": "cluster-member",
            "ipv4-address": "10.10.0.3",
        }
    )
    api.gateways_by_domain["Corp"][0]["cluster-member-names"] = ["corp-perimeter-1a", "corp-perimeter-1b"]
    # Add a second network to `G_Global_DMZ` (`172.16.20.0/24`) that is NOT in live routes (to test `stale_in_topology` + `standby_dynamic`)
    # and a network `172.16.30.0/24` that is in `G_Global_DMZ` on `eth2` in static topology, but routed via `eth1` in live routes (`interface_mismatch`)
    api.objects_by_domain_and_cmd[("Global", "show-networks")].extend(
        [
            {
                "uid": "g-net-dmz-stale",
                "name": "N_Global_DMZ_Stale",
                "type": "network",
                "subnet4": "172.16.20.0",
                "mask-length4": 24,
            },
            {
                "uid": "g-net-dmz-moved",
                "name": "N_Global_DMZ_Moved",
                "type": "network",
                "subnet4": "172.16.30.0",
                "mask-length4": 24,
            },
        ]
    )
    api.objects_by_domain_and_cmd[("Global", "show-groups")][0]["members"] = [
        "g-net-dmz",
        "g-net-dmz-stale",
        "g-net-dmz-moved",
    ]

    # SSH callback: handles `corp-perimeter-1a`, `corp-perimeter-1b`, `dc-core-gw`, and VSX parent `dc-vsx-chassis` (for `vsx1_VS_Tenant`),
    # while returning `success=False` for `branch-gw-01` to trigger `cprid` `run-script` fallback!
    ssh_calls: list[tuple[str, int | None]] = []

    async def _ssh_callback(target: GatewayCliTarget, script: str, timeout: float = 30.0) -> GatewayCliResult:
        ssh_calls.append((target.node_name, target.vsid))
        if target.node_name == "branch-gw-01":
            return GatewayCliResult(
                success=False,
                exit_code=255,
                stderr="SSH connection refused",
                executor="ssh",
                error_message="SSH connection refused",
            )
        if target.node_name == "corp-perimeter-1a":
            return GatewayCliResult(
                success=True,
                stdout=(
                    "__ARODONATA_IP_ROUTE_START__\n"
                    "default via 203.0.113.1 dev eth0 proto static\n"
                    "10.10.1.0/24 dev eth1 proto kernel scope link src 10.10.1.1\n"
                    "172.16.10.0/24 via 172.16.1.254 dev eth2 proto static\n"
                    "172.16.30.0/24 via 10.10.1.254 dev eth1 proto ospf\n"
                    "10.200.0.0/24 via 10.10.1.250 dev eth1 proto bgp\n"
                    "__ARODONATA_IP_ROUTE_END__\n"
                ),
                executor="ssh",
            )
        if target.node_name == "corp-perimeter-1b":
            # Member 1b is missing `10.200.0.0/24` -> triggers `cluster_member_drift`!
            return GatewayCliResult(
                success=True,
                stdout=(
                    "__ARODONATA_IP_ROUTE_START__\n"
                    "default via 203.0.113.1 dev eth0 proto static\n"
                    "10.10.1.0/24 dev eth1 proto kernel scope link src 10.10.1.1\n"
                    "172.16.10.0/24 via 172.16.1.254 dev eth2 proto static\n"
                    "172.16.30.0/24 via 10.10.1.254 dev eth1 proto ospf\n"
                    "__ARODONATA_IP_ROUTE_END__\n"
                ),
                executor="ssh",
            )
        if target.node_name == "dc-core-gw":
            return GatewayCliResult(
                success=True,
                stdout=(
                    "__ARODONATA_IP_ROUTE_START__\n"
                    "10.10.1.0/24 dev bond0.10 proto kernel scope link src 10.10.1.254\n"
                    "10.20.1.5/32 via 10.20.0.254 dev bond0.20 proto static\n"
                    "10.20.2.0/24 via 10.20.0.254 dev bond0.20 proto static\n"
                    "10.99.50.0/24 via 10.99.0.2 dev bond0.99 proto bgp\n"
                    "__ARODONATA_IP_ROUTE_END__\n"
                ),
                executor="ssh",
            )
        if target.node_name == "dc-vsx-chassis" and target.vsid == 1:
            assert "CTX%05d" in script
            return GatewayCliResult(
                success=True,
                stdout=(
                    "===ARODONATA_IP_ROUTE_START===\n"
                    "default via 192.168.100.1 dev wrp128 proto static\n"
                    "10.50.0.0/24 dev eth1.50 proto kernel scope link src 10.50.0.1\n"
                    "172.16.80.0/24 via 10.50.0.254 dev eth1.50 proto static\n"
                    "===ARODONATA_IP_ROUTE_END===\n"
                ),
                executor="ssh",
            )
        return GatewayCliResult(success=True, stdout="", executor="ssh")

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=0)
    client = ArodonataClient(settings=settings, api=api, gateway_cli=_ssh_callback)
    await client.initialize(run_startup_cleanup=False)
    client.domain_service.tracker.mark_refreshed("mds1")
    await client.cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d-global", name="Global", active_ip="10.0.0.1", is_global=True),
            DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(mgmt_name="mds1", uid="d-dc", name="DC", active_ip="10.2.0.1", active_mds_ip="10.0.0.1"),
            DomainInfo(
                mgmt_name="mds1",
                uid="d-tenant",
                name="TenantVS",
                active_ip="10.3.0.1",
                active_mds_ip="10.0.0.1",
            ),
        ]
    )

    # 1. Refresh static topology across all domains and collect live routes
    await client.refresh_topology(mgmt_name="mds1", mode="force")
    route_outcome = await client.collect_gateway_routes(mgmt_name="mds1", fallback_to_cprid=True)
    assert route_outcome.total_gateways == 4
    assert route_outcome.succeeded_gateways == 4
    assert route_outcome.failed_gateways == 0

    status_by_gw = {s.gateway_name: s for s in route_outcome.gateways}
    # `branch-gw-01` failed over from SSH to `cprid`
    assert "cprid" in status_by_gw["branch-gw-01"].executor
    # `corp-perimeter-cluster` detected member route drift (`10.200.0.0/24` only on `corp-perimeter-1a`)
    assert status_by_gw["corp-perimeter-cluster"].member_drift_detected is True
    # `vsx1_VS_Tenant` executed on physical VSX parent `dc-vsx-chassis` with `vsid=1`
    assert ("dc-vsx-chassis", 1) in ssh_calls

    # 2. Verify static refresh preserves live routes (`source_types=STATIC_TOPOLOGY_SOURCES`)
    await client.refresh_topology(mgmt_name="mds1", domains=["Corp"], gateways=["branch-gw-01"], mode="force")
    branch_entries = await client.get_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        gateway="branch-gw-01",
        cache_mode="cache",
    )
    branch_sources = {e.source_type for e in branch_entries}
    assert "interface_connected" in branch_sources
    assert "gaia_static_route" in branch_sources

    # 3. Reconcile gateway topology in `Corp` and `DC`
    corp_report = await client.reconcile_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    disc_by_type_cidr = {(d.discrepancy_type, d.cidr_or_range): d for d in corp_report.discrepancies}
    # `172.16.20.0/24` is in `G_Global_DMZ` on `eth2` but absent from live routes -> `stale_in_topology`
    assert ("stale_in_topology", "172.16.20.0/24") in disc_by_type_cidr
    assert disc_by_type_cidr[("stale_in_topology", "172.16.20.0/24")].confidence_delta < 0
    # `172.16.30.0/24` is in `G_Global_DMZ` on `eth2`, but routed via `eth1` in OSPF -> `interface_mismatch`
    assert ("interface_mismatch", "172.16.30.0/24") in disc_by_type_cidr
    assert disc_by_type_cidr[("interface_mismatch", "172.16.30.0/24")].interface_name == "eth2"
    assert disc_by_type_cidr[("interface_mismatch", "172.16.30.0/24")].routed_interface_name == "eth1"
    # `10.200.0.0/24` is in BGP on `eth1` (missing in static topology + drifted across cluster members)
    assert ("missing_in_topology", "10.200.0.0/24") in disc_by_type_cidr
    assert ("cluster_member_drift", "10.200.0.0/24") in disc_by_type_cidr

    dc_report = await client.reconcile_gateway_topology(
        mgmt_name="mds1",
        domain="DC",
        cache_mode="cache",
    )
    dc_disc_by_type_cidr = {(d.discrepancy_type, d.cidr_or_range): d for d in dc_report.discrepancies}
    # `bond0.99` on `dc-core-gw` was `"network defined by routing"` and now has `10.99.50.0/24` via BGP -> `resolved_by_routing`
    assert ("resolved_by_routing", "10.99.50.0/24") in dc_disc_by_type_cidr
    assert dc_disc_by_type_cidr[("resolved_by_routing", "10.99.50.0/24")].severity == "info"

    # 4. Test Evidence Delta Confidence Scoring before annotations:
    # Query `10.10.1.25 -> 172.16.30.10` on `corp-perimeter-cluster`:
    # - Static topology says `172.16.30.0/24` is on `eth2` (`+0.40` prevent - `0.50` conflict = `0.0`),
    #   whereas live OSPF route says `172.16.30.0/24` is on `eth1` (`+0.50` dynamic - `0.10` conflict = `0.40`).
    # - Because `10.10.1.25` is ALSO on `eth1`, live routing places both source and destination on `eth1` (`eth1 == eth1`),
    #   so `corp-perimeter-cluster` does NOT route between distinct interfaces for `10.10.1.25 -> 172.16.30.10`!
    mismatch_cands = await client.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["172.16.30.10"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert [c.gateway_name for c in mismatch_cands] == []

    # Query `10.10.1.25 -> 172.16.20.10` (`stale_in_topology` on `eth2`):
    # - `eth1` (`10.10.1.0/24`) has connected route (`+0.65`) + connected topology (`+0.50`) -> clamped `1.0`.
    # - `eth2` (`172.16.20.0/24`) has specific prevent (`+0.40`) + missing in live routes (`-0.35`) -> `0.05`.
    stale_cands = await client.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["172.16.20.10"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert len(stale_cands) == 1
    assert stale_cands[0].gateway_name == "corp-perimeter-cluster"
    assert stale_cands[0].confidence == pytest.approx(0.05)
    assert stale_cands[0].warnings

    # Filtering with `min_confidence=0.5` drops the low-confidence stale path
    high_conf_cands = await client.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["172.16.20.10"],
        mgmt_name="mds1",
        domain="Corp",
        min_confidence=0.5,
        cache_mode="cache",
    )
    assert high_conf_cands == []

    # 5. Upsert persistent `TopologyAnnotation` records:
    # - Mark `172.16.20.0/24` on `eth2` as `standby_dynamic` (BGP failover prefix) with IPAM zone/site metadata
    # - Add a `manual` prefix `10.250.0.0/24` on `eth2`
    saved_anns = await client.upsert_topology_annotations(
        [
            TopologyAnnotation(
                mgmt_name="mds1",
                domain_name="Corp",
                gateway_uid="cl-corp-1",
                gateway_name="corp-perimeter-cluster",
                interface_name="eth2",
                cidr_or_range="172.16.20.0/24",
                disposition="standby_dynamic",
                zone="DMZ-DR",
                site="FRA-DC2",
                comment="BGP standby range active during secondary ISP failover",
            ),
            TopologyAnnotation(
                mgmt_name="mds1",
                domain_name="Corp",
                gateway_uid="cl-corp-1",
                gateway_name="corp-perimeter-cluster",
                interface_name="eth2",
                cidr_or_range="10.250.0.0/24",
                disposition="manual",
                zone="Partner-Extranet",
                site="FRA-DC1",
                comment="Manual static NAT behind partner router",
            ),
        ]
    )
    assert len(saved_anns) == 2

    # Now `10.10.1.25 -> 172.16.20.10` is marked `is_standby_path=True` with boosted confidence (`0.40 + 0.35 = 0.75`)
    standby_cands = await client.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["172.16.20.10"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert len(standby_cands) == 1
    assert standby_cands[0].is_standby_path is True
    assert standby_cands[0].confidence == pytest.approx(0.75)

    # Excluding standby paths (`include_standby=False`) filters it out
    active_only_cands = await client.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["172.16.20.10"],
        mgmt_name="mds1",
        domain="Corp",
        include_standby=False,
        cache_mode="cache",
    )
    assert active_only_cands == []

    # Manual prefix `10.250.0.0/24` on `eth2` is matched with `admin_manual` delta (`0.60`)
    manual_cands = await client.find_affected_gateways(
        sources=["10.10.1.25"],
        destinations=["10.250.0.55"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert len(manual_cands) == 1
    assert manual_cands[0].matched_flows[0].dst_interface == "eth2"
    assert manual_cands[0].matched_flows[0].dst_source_type == "manual"
    assert manual_cands[0].confidence == pytest.approx(0.60)

    # 6. Export prefixes for IPAM comparison and verify annotations survive topology resync
    await client.refresh_topology(mgmt_name="mds1", domains=["Corp"], mode="force")
    exported = await client.export_topology_prefixes(
        mgmt_name="mds1",
        domain="Corp",
        gateway="corp-perimeter-cluster",
        cache_mode="cache",
    )
    exp_by_if_cidr = {(p.interface_name, p.cidr_or_range): p for p in exported}
    assert ("eth2", "172.16.20.0/24") in exp_by_if_cidr
    assert exp_by_if_cidr[("eth2", "172.16.20.0/24")].zone == "DMZ-DR"
    assert exp_by_if_cidr[("eth2", "172.16.20.0/24")].site == "FRA-DC2"
    assert exp_by_if_cidr[("eth2", "172.16.20.0/24")].is_standby_path is True
    assert ("eth2", "10.250.0.0/24") in exp_by_if_cidr
    assert exp_by_if_cidr[("eth2", "10.250.0.0/24")].disposition == "manual"

    deleted_count = await client.delete_topology_annotations(
        mgmt_name="mds1",
        domain="Corp",
        gateway_uid="cl-corp-1",
    )
    assert deleted_count == 2
    assert await client.get_topology_annotations(mgmt_name="mds1", domain="Corp") == []

    # 7. Verify MCP tools (`locate_gateways` and `cache_control(scope="topology")`)
    import json

    from arodonata.mcp import ArodonataMCPSettings, create_mcp_server

    mcp_server = create_mcp_server(client, mcp_settings=ArodonataMCPSettings())
    locate_res = await mcp_server.call_tool(
        "locate_gateways",
        {
            "sources": ["10.10.1.25"],
            "destinations": ["172.16.20.10"],
            "mgmt_name": "mds1",
            "domain": "Corp",
            "min_confidence": 0.0,
            "include_standby": True,
            "cache_mode": "cache",
        },
    )
    locate_payload = json.loads(locate_res.content[0].text)  # type: ignore[union-attr]
    assert locate_payload["total"] == 1
    assert locate_payload["min_confidence"] == 0.0
    assert locate_payload["include_standby"] is True
    assert locate_payload["topology_warnings"]
    assert locate_payload["gateways"][0]["gateway_name"] == "corp-perimeter-cluster"

    cc_res = await mcp_server.call_tool(
        "cache_control",
        {
            "action": "refresh",
            "mgmt_name": "mds1",
            "domain": "Corp",
            "scope": "topology",
            "gateways": ["branch-gw-01"],
            "collect_routes": True,
            "mode": "force",
        },
    )
    cc_payload = json.loads(cc_res.content[0].text)  # type: ignore[union-attr]
    assert cc_payload["scope"] == "topology"
    assert "mds1:Corp" in cc_payload["refreshed_domains"]

    await client.close()


@pytest.mark.asyncio
async def test_claude_review_regression_fixes() -> None:
    """Verify all fixes from `/claude-review` (longest-prefix match, anti-spoofing spoof-tracking, orphan route pruning, external interface routes, dynamic vsid resolution, and `trust_static_topology=False`)."""
    from arodonata.client import ArodonataClient
    from arodonata.core.models.topology import (
        GatewayCliResult,
        GatewayCliTarget,
        TopologyAnnotation,
    )
    from arodonata.core.services.route_collector import (
        build_route_collection_script,
        parse_combined_cli_routes,
        resolve_gateway_cli_targets,
    )
    from arodonata.core.services.topology_service import _extract_anti_spoofing_mode

    # 1. Anti-Spoofing extraction must ignore `spoof-tracking: none` when `action: prevent`
    assert (
        _extract_anti_spoofing_mode(
            {
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent", "spoof-tracking": "none"},
            }
        )
        == "prevent"
    )
    assert (
        _extract_anti_spoofing_mode(
            {
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "detect", "spoof-tracking": "log"},
            }
        )
        == "detect"
    )

    # 2. `proto routed` and Clish IS-IS `I` route code parsing
    cli_sample = (
        "===ARODONATA_IP_ROUTE_START===\n"
        "10.70.0.0/16 via 10.10.1.254 dev eth1 proto routed\n"
        "===ARODONATA_IP_ROUTE_END===\n"
        "===ARODONATA_CLISH_ROUTE_START===\n"
        "I 10.71.0.0/16 via 10.10.1.253, eth1, cost 10, age 20\n"
        "===ARODONATA_CLISH_ROUTE_END===\n"
    )
    parsed_routes = parse_combined_cli_routes(cli_sample)
    by_dest = {str(r.destination): r.source_type for r in parsed_routes}
    assert by_dest["10.70.0.0/16"] == "clish_route"
    assert by_dest["10.71.0.0/16"] == "clish_route"

    # 3. Dynamic `vsx stat -l` VSID resolution without silent `vsid=1` fallback
    vs_no_vsid = Asset(
        uid="vs-custom-name",
        name="Tenant_Finance_VS",
        type="CpmiVsNetobj",
        mgmt_name="mds1",
        domain_name="TenantVS",
        parent_uid="vsx-dc-1",
        raw_data={"name": "Tenant_Finance_VS"},
    )
    vsx_parent = Asset(
        uid="vsx-dc-1",
        name="dc-vsx-chassis",
        type="vsx-gateway",
        mgmt_name="mds1",
        domain_name="DC",
        ipv4_address="10.20.0.10",
    )
    targets = resolve_gateway_cli_targets(vs_no_vsid, [vs_no_vsid, vsx_parent])
    assert len(targets) == 1
    assert targets[0].vsid is None
    assert targets[0].vs_name == "Tenant_Finance_VS"
    dyn_script = build_route_collection_script(vsid=targets[0].vsid, vs_name=targets[0].vs_name)
    assert "vsx stat -l" in dyn_script
    assert "ARODONATA_VSID_RESOLVED" in dyn_script

    # 4. Longest-Prefix Match before confidence + external interface connected routes + orphan pruning + trust_static_topology=False
    api = TopologyFakeApi()
    api.objects_by_domain_and_cmd.setdefault(("Corp", "show-networks"), []).append(
        {
            "uid": "net-10-super",
            "name": "N_10_Supernet",
            "type": "network",
            "subnet4": "10.0.0.0",
            "mask-length4": 8,
        }
    )
    api.gateways_by_domain["Corp"] = [
        {
            "uid": "gw-lpm",
            "name": "lpm-core-gw",
            "type": "simple-gateway",
            "ipv4-address": "10.10.0.10",
            "policy": {"access-policy-installed": True, "access-policy-name": "Perimeter_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "203.0.113.10",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": "eth1",
                    "ipv4-address": "10.1.1.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "N_10_Supernet",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "prevent", "spoof-tracking": "none"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": "10.2.1.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by routing",
                    },
                },
            ],
        },
        {
            "uid": "gw-decommissioned",
            "name": "old-branch-gw",
            "type": "simple-gateway",
            "ipv4-address": "10.10.0.99",
            "policy": {"access-policy-installed": True, "access-policy-name": "Branch_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "198.51.100.99",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": "eth1",
                    "ipv4-address": "10.99.99.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                },
            ],
        },
    ]

    async def _ssh_cb(target: GatewayCliTarget, script: str, timeout: float = 30.0) -> GatewayCliResult:
        if target.node_name == "lpm-core-gw":
            # `eth0` has both default route and connected WAN subnet `203.0.113.0/24`
            # `eth1` has summary route `10.0.0.0/8` (matches Prevent static `N_10_Supernet` -> conf 0.95)
            # `eth2` has more specific BGP route `10.50.0.0/16` (routing-defined interface -> conf 0.40 with conflict penalty)
            return GatewayCliResult(
                success=True,
                stdout=(
                    "===ARODONATA_IP_ROUTE_START===\n"
                    "default via 203.0.113.1 dev eth0 proto static\n"
                    "203.0.113.0/24 dev eth0 proto kernel scope link src 203.0.113.10\n"
                    "10.1.1.0/24 dev eth1 proto kernel scope link src 10.1.1.1\n"
                    "10.0.0.0/8 via 10.1.1.254 dev eth1 proto static\n"
                    "10.2.1.0/24 dev eth2 proto kernel scope link src 10.2.1.1\n"
                    "10.50.0.0/16 via 10.2.1.254 dev eth2 proto bgp\n"
                    "===ARODONATA_IP_ROUTE_END===\n"
                ),
                executor="ssh",
            )
        return GatewayCliResult(
            success=True,
            stdout=(
                "===ARODONATA_IP_ROUTE_START===\n"
                "default via 198.51.100.1 dev eth0 proto static\n"
                "10.99.99.0/24 dev eth1 proto kernel scope link src 10.99.99.1\n"
                "===ARODONATA_IP_ROUTE_END===\n"
            ),
            executor="ssh",
        )

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=300)
    client = ArodonataClient(settings=settings, api=api, gateway_cli=_ssh_cb)
    await client.initialize(run_startup_cleanup=False)
    client.domain_service.tracker.mark_refreshed("mds1")
    await client.cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d-global", name="Global", active_ip="10.0.0.1", is_global=True),
            DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
        ]
    )

    # Multi-domain `refresh_topology(..., collect_routes=True)`
    await client.refresh_topology(mgmt_name="mds1", domains=["Corp"], collect_routes=True, mode="force")

    # Verify `DomainSyncState(scope="topology", item_type="routes")` was persisted
    route_sync_state = await client.cache.get_sync_state("mds1", "Corp", "topology", "routes")
    assert route_sync_state is not None
    assert route_sync_state.status == "ok"
    assert route_sync_state.object_count == 2

    # Verify WAN connected route `203.0.113.0/24` on external `eth0` did NOT trigger `missing_in_topology`
    rec = await client.reconcile_gateway_topology(mgmt_name="mds1", domain="Corp", cache_mode="cache")
    disc_cidrs = {(d.discrepancy_type, d.cidr_or_range) for d in rec.discrepancies if d.gateway_name == "lpm-core-gw"}
    assert ("missing_in_topology", "203.0.113.0/24") not in disc_cidrs

    # Verify Longest-Prefix Match: traffic from `10.1.1.10` (`eth1` `/24`) to `10.50.1.10` MUST resolve
    # destination to `eth2` (`10.50.0.0/16`, conf=0.40) and NOT `eth1` (`10.0.0.0/8`, conf=0.95)!
    cands = await client.find_affected_gateways(
        sources=["10.1.1.10"],
        destinations=["10.50.1.10"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert len(cands) == 1
    assert cands[0].gateway_name == "lpm-core-gw"
    assert cands[0].matched_flows[0].src_interface == "eth1"
    assert cands[0].matched_flows[0].dst_interface == "eth2"
    assert cands[0].matched_flows[0].dst_matched_cidr == "10.50.0.0/16"
    # Before `trust_static_topology=False`, `eth2` has `0.50 (bgp) - 0.10 (conflict with N_10_Supernet on eth1) = 0.40`
    assert cands[0].confidence == pytest.approx(0.40)

    # Now set `trust_static_topology=False` on `eth1`:
    # - The `-0.10` conflict penalty on `eth2` is suppressed, raising `eth2` confidence to `0.50`!
    await client.upsert_topology_annotations(
        TopologyAnnotation(
            mgmt_name="mds1",
            domain_name="Corp",
            gateway_uid="gw-lpm",
            gateway_name="lpm-core-gw",
            interface_name="eth1",
            cidr_or_range="*",
            trust_static_topology=False,
        )
    )
    cands_untrusted = await client.find_affected_gateways(
        sources=["10.1.1.10"],
        destinations=["10.50.1.10"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert len(cands_untrusted) == 1
    assert cands_untrusted[0].confidence == pytest.approx(0.50)

    # Verify orphan `LIVE_ROUTE_SOURCES` pruning when `old-branch-gw` is removed from `Corp`
    api.gateways_by_domain["Corp"] = [api.gateways_by_domain["Corp"][0]]
    await client.refresh_topology(mgmt_name="mds1", domains=["Corp"], mode="force")
    remaining_entries = await client.get_gateway_topology(mgmt_name="mds1", domain="Corp", cache_mode="cache")
    assert all(e.gateway_uid != "gw-decommissioned" for e in remaining_entries)
    # While `lpm-core-gw` still retains its live routes!
    assert any(e.gateway_uid == "gw-lpm" and e.source_type == "bgp_route" for e in remaining_entries)

    await client.close()


@pytest.mark.asyncio
async def test_stage2_vpn_domain_policy_rule_evidence_one_arm_aci_inference_and_policy_reconciliation() -> None:
    """Verify Stage 2 capabilities:
    1. `vpn-domain` (`encryption-domain`) extraction (`source_type="vpn_domain"`) and `vpn_encryption_domain` (`+0.45`) scoring.
    2. `policy_rule_evidence` (`+0.25`) bonus on cross-interface L3 gateways from cached Access Control and NAT rules.
    3. `include_policy_inferred` (`match_type="policy_inferred"`) for one-arm Cisco ACI service-graph gateways and incomplete-topology gateways.
    4. `reconcile_gateway_topology(..., check_policy=True)` reporting `policy_topology_mismatch` for gateway-targeted rules (`install_on`).
    """
    from arodonata.client import ArodonataClient
    from arodonata.core.config import TopologyConfidenceWeights

    # Verify Stage 2 weight defaults and backward-compatible alias synchronization
    default_weights = TopologyConfidenceWeights()
    assert default_weights.policy_rule_evidence == pytest.approx(0.25)
    assert default_weights.vpn_encryption_domain == pytest.approx(0.45)
    custom_weights = TopologyConfidenceWeights(policy_rule_match=0.33, vpn_domain_match=0.48)
    assert custom_weights.policy_rule_evidence == pytest.approx(0.33)
    assert custom_weights.vpn_encryption_domain == pytest.approx(0.48)

    api = TopologyFakeApi()
    api.objects_by_domain_and_cmd[("Corp", "show-networks")] = [
        {
            "uid": "net-vpn-1",
            "name": "N_VPN_Inside_10_77",
            "type": "network",
            "subnet4": "10.77.0.0",
            "mask-length4": 16,
        },
        {
            "uid": "net-aci-epg-web",
            "name": "N_ACI_EPG_Web",
            "type": "network",
            "subnet4": "10.160.10.0",
            "mask-length4": 24,
        },
        {
            "uid": "net-aci-epg-app",
            "name": "N_ACI_EPG_App",
            "type": "network",
            "subnet4": "10.160.20.0",
            "mask-length4": 24,
        },
        {
            "uid": "net-nat-pool",
            "name": "N_NAT_DMZ_Server",
            "type": "network",
            "subnet4": "172.16.80.0",
            "mask-length4": 24,
        },
        {
            "uid": "net-orphan-branch",
            "name": "N_Orphan_Branch_99",
            "type": "network",
            "subnet4": "10.199.250.0",
            "mask-length4": 24,
        },
    ]
    api.objects_by_domain_and_cmd[("Corp", "show-groups")] = [
        {
            "uid": "grp-vpn-dom",
            "name": "G_Corp_VPN_Domain",
            "type": "group",
            "members": ["net-vpn-1"],
        }
    ]
    api.gateways_by_domain["Corp"] = [
        # 1. L3 gateway with `vpn-domain` group on `eth1` (specific + vpn_domain) and NAT/Access rules
        {
            "uid": "gw-vpn-l3",
            "name": "corp-vpn-gw",
            "type": "simple-gateway",
            "ipv4-address": "10.77.0.1",
            "vpn-domain": {"uid": "grp-vpn-dom", "name": "G_Corp_VPN_Domain"},
            "policy": {"access-policy-installed": True, "access-policy-name": "VPN_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "198.51.100.5",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                },
                {
                    "name": "eth1",
                    "ipv4-address": "10.77.1.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "specific",
                        "specific-network": "G_Corp_VPN_Domain",
                    },
                    "anti-spoofing": True,
                    "anti-spoofing-settings": {"action": "detect"},
                },
                {
                    "name": "eth2",
                    "ipv4-address": "172.16.80.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                    },
                },
            ],
        },
        # 2. One-arm Cisco ACI service-graph gateway (single external interface `eth1`)
        {
            "uid": "gw-aci-onearm",
            "name": "corp-aci-service-gw",
            "type": "simple-gateway",
            "ipv4-address": "10.160.0.10",
            "policy": {"access-policy-installed": True, "access-policy-name": "ACI_PBR_Pkg"},
            "interfaces": [
                {
                    "name": "eth1",
                    "ipv4-address": "10.160.0.10",
                    "ipv4-mask-length": 24,
                    "topology": "external",
                }
            ],
        },
        # 3. Incomplete-topology gateway (interfaces all `network defined by routing` without collected routes)
        {
            "uid": "gw-incomplete-routing",
            "name": "corp-uncollected-routing-gw",
            "type": "simple-gateway",
            "ipv4-address": "10.170.0.1",
            "policy": {"access-policy-installed": True, "access-policy-name": "ACI_PBR_Pkg"},
            "interfaces": [
                {
                    "name": "eth0",
                    "ipv4-address": "10.170.1.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "network defined by routing",
                    },
                },
                {
                    "name": "eth1",
                    "ipv4-address": "10.170.2.1",
                    "ipv4-mask-length": 24,
                    "topology": "internal",
                    "topology-settings": {
                        "ip-address-behind-this-interface": "not defined",
                    },
                },
            ],
        },
    ]

    settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret", cache_ttl=300)
    client = ArodonataClient(settings=settings, api=api)
    await client.initialize(run_startup_cleanup=False)
    client.domain_service.tracker.mark_refreshed("mds1")
    await client.cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d-global", name="Global", active_ip="10.0.0.1", is_global=True),
            DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp", active_ip="10.1.0.1", active_mds_ip="10.0.0.1"),
        ]
    )

    # Seed rulebase snapshot for `Corp`:
    # - `VPN_Pkg`:
    #   - Access rule #1: `N_VPN_Inside_10_77` -> `N_NAT_DMZ_Server` (install_on=["Policy Targets"])
    #   - NAT rule #1: original `N_VPN_Inside_10_77` -> `198.51.100.200`, translated `Original` -> `N_NAT_DMZ_Server`
    #   - Mismatched Access rule #2: `N_Orphan_Branch_99` -> `N_ACI_EPG_Web` explicitly installed on `corp-vpn-gw` (`install_on=["gw-vpn-l3"]`)
    # - `ACI_PBR_Pkg`:
    #   - Access rule #1: `N_ACI_EPG_Web` -> `N_ACI_EPG_App` (install_on=["corp-aci-service-gw", "corp-uncollected-routing-gw"])
    #   - Generic Cleanup rule #2: `Any` -> `Any` (must be ignored by policy inference!)
    await client.cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="Corp",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="pkg-vpn",
                    package_name="VPN_Pkg",
                    rulebase_type="access",
                    layer_uid="layer-vpn-net",
                    layer_name="VPN_Network",
                    position=1,
                ),
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="pkg-aci",
                    package_name="ACI_PBR_Pkg",
                    rulebase_type="access",
                    layer_uid="layer-aci-net",
                    layer_name="ACI_Network",
                    position=1,
                ),
            ],
            layers=[
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="layer-vpn-net",
                    name="VPN_Network",
                    rulebase_type="access",
                ),
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    uid="layer-aci-net",
                    name="ACI_Network",
                    rulebase_type="access",
                ),
            ],
            access_rules=[
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    layer_uid="layer-vpn-net",
                    layer_name="VPN_Network",
                    uid="rule-vpn-dmz",
                    name="Allow_VPN_to_DMZ",
                    position=1,
                    rule_number="1",
                    enabled=True,
                    action="Accept",
                    source=["N_VPN_Inside_10_77"],
                    destination=["N_NAT_DMZ_Server"],
                    install_on=["Policy Targets"],
                ),
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    layer_uid="layer-vpn-net",
                    layer_name="VPN_Network",
                    uid="rule-vpn-orphan",
                    name="Stale_Orphan_Rule",
                    position=2,
                    rule_number="2",
                    enabled=True,
                    action="Accept",
                    source=["N_Orphan_Branch_99"],
                    destination=["N_ACI_EPG_Web"],
                    install_on=["gw-vpn-l3"],
                ),
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    layer_uid="layer-vpn-net",
                    layer_name="VPN_Network",
                    uid="rule-vpn-one-side-orphan",
                    name="Stale_OneSide_Drop_Rule",
                    position=3,
                    rule_number="3",
                    enabled=True,
                    action="Drop",
                    source=["N_Orphan_Branch_99"],
                    destination=["Any"],
                    install_on=["gw-vpn-l3"],
                ),
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    layer_uid="layer-aci-net",
                    layer_name="ACI_Network",
                    uid="rule-aci-epg",
                    name="Allow_EPG_Web_to_App",
                    position=1,
                    rule_number="1",
                    enabled=True,
                    action="Accept",
                    source=["N_ACI_EPG_Web"],
                    destination=["N_ACI_EPG_App"],
                    install_on=["corp-aci-service-gw", "corp-uncollected-routing-gw"],
                ),
                AccessRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    layer_uid="layer-aci-net",
                    layer_name="ACI_Network",
                    uid="rule-aci-any",
                    name="Cleanup_Any",
                    position=2,
                    rule_number="2",
                    enabled=True,
                    action="Accept",
                    source=["Any"],
                    destination=["Any"],
                    install_on=["Policy Targets"],
                ),
            ],
            nat_rules=[
                NatRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="pkg-vpn",
                    package_name="VPN_Pkg",
                    uid="nat-vpn-dmz-vip",
                    name="NAT_DMZ_VIP",
                    position=1,
                    rule_number="1",
                    enabled=True,
                    original_source="N_VPN_Inside_10_77",
                    original_destination="198.51.100.200",
                    translated_source="Original",
                    translated_destination="N_NAT_DMZ_Server",
                    install_on=["Policy Targets"],
                ),
                NatRuleEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="pkg-vpn",
                    package_name="VPN_Pkg",
                    uid="nat-inbound-dnat-gw",
                    name="Inbound_DNAT_To_DMZ",
                    position=2,
                    rule_number="2",
                    enabled=True,
                    original_source="N_ACI_EPG_Web",
                    original_destination="198.51.100.200",
                    translated_source="Original",
                    translated_destination="N_NAT_DMZ_Server",
                    install_on=["gw-vpn-l3"],
                ),
            ],
        ),
    )

    await client.refresh_topology(mgmt_name="mds1", domains=["Corp"], mode="force")

    # 1. Verify `vpn_domain` entry was extracted and persisted on `corp-vpn-gw` `eth1`
    vpn_entries = await client.get_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        gateway="corp-vpn-gw",
        source_types=["vpn_domain"],
        cache_mode="cache",
    )
    assert len(vpn_entries) == 1
    assert vpn_entries[0].interface_name == "eth1"
    assert vpn_entries[0].cidr_or_range == "10.77.0.0/16"
    assert vpn_entries[0].source_ref == "G_Corp_VPN_Domain"

    # 2. Verify L3 candidate `corp-vpn-gw` receives both `vpn_encryption_domain` (+0.45) and `policy_rule_evidence` (+0.25)
    #    On `eth1`: `topology_specific_detect` (0.15) + `vpn_encryption_domain` (0.45) = 0.60
    #    On `eth2`: `topology_connected` (0.50)
    #    Base flow confidence = min(0.60, 0.50) = 0.50
    #    Plus `policy_rule_evidence` (+0.25) from `Allow_VPN_to_DMZ` -> 0.75!
    l3_cands = await client.find_affected_gateways(
        sources=["10.77.5.10"],
        destinations=["172.16.80.25"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert [c.gateway_name for c in l3_cands] == ["corp-vpn-gw"]
    l3_cand = l3_cands[0]
    factor_codes = {d.code for d in l3_cand.confidence_factors}
    assert "vpn_encryption_domain" in factor_codes
    assert "policy_rule_evidence" in factor_codes
    assert l3_cand.confidence == pytest.approx(0.75)

    # Verify NAT rule `original_destination` (`198.51.100.200`) also grants `policy_rule_evidence` (+0.25)
    nat_cands = await client.find_affected_gateways(
        sources=["10.77.5.10"],
        destinations=["198.51.100.200"],
        mgmt_name="mds1",
        domain="Corp",
        cache_mode="cache",
    )
    assert [c.gateway_name for c in nat_cands] == ["corp-vpn-gw"]
    assert any(d.code == "policy_rule_evidence" for d in nat_cands[0].confidence_factors)
    # eth1 (0.60) -> eth0 external fallback (0.30) + policy_rule_evidence (0.25) = 0.55
    assert nat_cands[0].confidence == pytest.approx(0.55)

    # 3. Verify one-arm Cisco ACI gateway (`corp-aci-service-gw`) and incomplete-topology gateway (`corp-uncollected-routing-gw`)
    #    are discovered with `match_type="policy_inferred"` when querying `N_ACI_EPG_Web` (`10.160.10.15`) -> `N_ACI_EPG_App` (`10.160.20.25`)
    aci_cands = await client.find_affected_gateways(
        sources=["10.160.10.15"],
        destinations=["10.160.20.25"],
        mgmt_name="mds1",
        domain="Corp",
        include_policy_inferred=True,
        cache_mode="cache",
    )
    assert {c.gateway_name for c in aci_cands} == {"corp-aci-service-gw", "corp-uncollected-routing-gw"}
    aci_gw = next(c for c in aci_cands if c.gateway_name == "corp-aci-service-gw")
    assert aci_gw.match_types == ["policy_inferred"]
    assert aci_gw.matched_flows[0].match_type == "policy_inferred"
    assert aci_gw.matched_flows[0].src_matched_cidr == "10.160.10.0/24"
    assert aci_gw.matched_flows[0].dst_matched_cidr == "10.160.20.0/24"
    assert any(d.code == "policy_rule_evidence" for d in aci_gw.confidence_factors)
    # One-arm external `eth1` (0.30) + `policy_rule_evidence` (0.25) = 0.55
    assert aci_gw.confidence == pytest.approx(0.55)

    # When `include_policy_inferred=False`, neither one-arm nor incomplete-topology gateway is returned
    aci_disabled = await client.find_affected_gateways(
        sources=["10.160.10.15"],
        destinations=["10.160.20.25"],
        mgmt_name="mds1",
        domain="Corp",
        include_policy_inferred=False,
        cache_mode="cache",
    )
    assert aci_disabled == []

    # Unrelated traffic (`10.160.99.1 -> 10.160.99.2`) covered only by `Cleanup_Any` (`Any -> Any`) MUST NOT match!
    any_only = await client.find_affected_gateways(
        sources=["10.160.99.1"],
        destinations=["10.160.99.2"],
        mgmt_name="mds1",
        domain="Corp",
        include_policy_inferred=True,
        cache_mode="cache",
    )
    assert any_only == []

    # 4. Verify `reconcile_gateway_topology(..., check_policy=True)` reports `policy_topology_mismatch`
    #    for `Stale_Orphan_Rule` explicitly targeting `corp-vpn-gw` (`gw-vpn-l3`)
    rec_no_pol = await client.reconcile_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        check_policy=False,
        cache_mode="cache",
    )
    assert [d for d in rec_no_pol.discrepancies if d.discrepancy_type == "policy_topology_mismatch"] == []

    rec_with_pol = await client.reconcile_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        check_policy=True,
        cache_mode="cache",
    )
    pol_mismatches = [d for d in rec_with_pol.discrepancies if d.discrepancy_type == "policy_topology_mismatch"]
    # `Stale_Orphan_Rule` and `Stale_OneSide_Drop_Rule` are reported, while `Inbound_DNAT_To_DMZ` is NOT flagged
    # because its translated destination `N_NAT_DMZ_Server` (`172.16.80.25/32`) overlaps `eth2` (`172.16.80.0/24`).
    assert len(pol_mismatches) == 2
    by_cidr = {d.cidr_or_range: d for d in pol_mismatches}
    assert set(by_cidr.keys()) == {
        "10.199.250.0/24 -> 10.160.10.0/24",
        "10.199.250.0/24 -> Any",
    }
    assert by_cidr["10.199.250.0/24 -> 10.160.10.0/24"].gateway_name == "corp-vpn-gw"
    assert by_cidr["10.199.250.0/24 -> 10.160.10.0/24"].interface_name == "policy"
    assert "Stale_Orphan_Rule" in by_cidr["10.199.250.0/24 -> 10.160.10.0/24"].message
    assert "Stale_OneSide_Drop_Rule" in by_cidr["10.199.250.0/24 -> Any"].message
    assert all("Inbound_DNAT_To_DMZ" not in d.message for d in pol_mismatches)

    # Verify wildcard annotation `interface_name="policy", cidr_or_range="*"` suppresses `policy_topology_mismatch`
    await client.upsert_topology_annotations(
        {
            "mgmt_name": "mds1",
            "domain_name": "Corp",
            "gateway_uid": "gw-vpn-l3",
            "interface_name": "policy",
            "cidr_or_range": "*",
            "disposition": "ignore",
            "comment": "Accepted policy exceptions on corp-vpn-gw",
        }
    )
    rec_suppressed = await client.reconcile_gateway_topology(
        mgmt_name="mds1",
        domain="Corp",
        check_policy=True,
        cache_mode="cache",
    )
    pol_suppressed = [d for d in rec_suppressed.discrepancies if d.discrepancy_type == "policy_topology_mismatch"]
    assert len(pol_suppressed) == 2
    assert all(d.suppressed_by_annotation is True and d.severity == "info" for d in pol_suppressed)

    # Verify `_extract_vpn_domain_refs` ignores stale `vpn-domain` when `vpn-domain-type` is `addresses_behind_gw`
    from arodonata.core.services.topology_service import _extract_vpn_domain_refs

    assert _extract_vpn_domain_refs(
        {
            "vpn-settings": {
                "vpn-domain-type": "addresses_behind_gw",
                "vpn-domain": {"uid": "grp-vpn-dom", "name": "G_Corp_VPN_Domain"},
            }
        }
    ) == (None, None)

    # Verify plain IPv4/CIDR `find_affected_gateways` on Domains without cached policy rules skips loading `arodonata_objects`
    get_objects_calls = 0
    orig_get_objects = client._cache.get_objects

    async def _counting_get_objects(*args: Any, **kwargs: Any) -> list[CPObject]:
        nonlocal get_objects_calls
        get_objects_calls += 1
        return await orig_get_objects(*args, **kwargs)

    client._cache.get_objects = _counting_get_objects  # type: ignore[method-assign]
    try:
        # Clear cached rulebase snapshot on Corp so neither endpoints nor rulebase need CPObject expansion
        await client._cache.replace_domain_rulebase(
            DomainRulebaseSnapshot(mgmt_name="mds1", domain_name="Corp"),
        )
        get_objects_calls = 0

        ip_only_hits = await client.find_affected_gateways(
            sources=["10.77.5.10"],
            destinations=["172.16.80.25"],
            mgmt_name="mds1",
            domain="Corp",
            cache_mode="cache",
        )
        assert [c.gateway_name for c in ip_only_hits] == ["corp-vpn-gw"]
        assert get_objects_calls == 0
    finally:
        client._cache.get_objects = orig_get_objects  # type: ignore[method-assign]

    await client.close()


@pytest.mark.asyncio
async def test_route_collection_vsx_node_serialization_coalescing_route_cap_and_package_snapshot() -> None:
    """Verify `collect_gateway_routes` serializes CLI per physical VSX node while parallelizing independent gateways, coalesces duplicate calls, enforces `max_routes_per_gateway`, and avoids full `get_domain_rulebase` loads."""
    import asyncio

    from arodonata.core.services.route_collector import (
        CLISH_SKIPPED_LARGE_TABLE_MARKER,
        ROUTE_LIMIT_MARKER,
        build_route_collection_script,
        parse_combined_cli_routes,
    )

    # 1. Verify bash script and parser route cap + clish skip marker handling (single kernel dump pass)
    capped_script = build_route_collection_script(vsid=None, max_routes=150)
    assert capped_script.count("ip -4 route show") == 1
    assert ROUTE_LIMIT_MARKER in capped_script
    assert CLISH_SKIPPED_LARGE_TABLE_MARKER in capped_script

    synthetic_stdout = (
        "===ARODONATA_IP_ROUTE_START===\n"
        + "\n".join(f"10.120.{i // 256}.{i % 256}/32 via 10.10.0.254 dev eth1 proto bgp" for i in range(120))
        + f"\n{ROUTE_LIMIT_MARKER}=100\n"
        + "===ARODONATA_IP_ROUTE_END===\n"
        + f"===ARODONATA_CLISH_ROUTE_START===\n{CLISH_SKIPPED_LARGE_TABLE_MARKER}\n===ARODONATA_CLISH_ROUTE_END===\n"
    )
    parsed_capped = parse_combined_cli_routes(synthetic_stdout, max_routes=100)
    assert len(parsed_capped) == 100

    # 2. Seed a physical VSX host (`vsx-chassis-1`) with 3 Virtual Systems + 1 independent simple gateway (`gw-indep-1`)
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    lock_port = SqlLockAdapter(db)
    api = TopologyFakeApi()

    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="secret",
        concurrent_limit=6,
        route_collect_concurrency=3,
        max_routes_per_gateway=100,
    )
    domain_service = DomainService(settings=settings, api=api, cache=cache, lock_port=lock_port)
    coordinator = DomainSyncCoordinator(
        settings=settings,
        api=api,
        cache=cache,
        lock_port=lock_port,
        domain_service=domain_service,
    )
    asset_service = AssetRefreshService(settings=settings, api=api, cache=cache, coordinator=coordinator)
    object_service = ObjectService(settings=settings, api=api, cache=cache, coordinator=coordinator)
    topology_service = TopologyService(
        settings=settings,
        api=api,
        cache=cache,
        coordinator=coordinator,
        asset_service=asset_service,
        object_service=object_service,
    )

    vsx_parent = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {"uid": "uid-vsx-host-1", "name": "vsx-chassis-1", "type": "CpmiVsxNetobj", "ipv4-address": "192.0.2.10"},
    )
    vs_assets = [
        Asset.from_cp_dict(
            "mds1",
            "Corp",
            {
                "uid": f"uid-vs-{idx}",
                "name": f"corp-vs-{idx}",
                "type": "CpmiVsNetobj",
                "ipv4-address": f"10.10.{idx}.1",
                "virtual-system-id": idx,
                "interfaces": [{"name": "eth1", "ipv4-address": f"10.10.{idx}.1", "ipv4-mask-length": 24}],
            },
        ).model_copy(
            update={
                "parent_uid": vsx_parent.uid,
                "parent_id": vsx_parent.id,
                "parent_asset_id": vsx_parent.asset_id,
            }
        )
        for idx in (1, 2, 3)
    ]
    indep_gw = Asset.from_cp_dict(
        "mds1",
        "Corp",
        {
            "uid": "uid-gw-indep",
            "name": "gw-indep-1",
            "type": "simple-gateway",
            "ipv4-address": "192.0.2.50",
            "interfaces": [{"name": "eth1", "ipv4-address": "10.90.0.1", "ipv4-mask-length": 24}],
        },
    )
    await cache.replace_domain_assets("mds1", "Corp", [vsx_parent, *vs_assets, indep_gw])
    await cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="Corp",
            package_layers=[
                RulebasePackageLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Corp",
                    package_uid="pkg-corp",
                    package_name="Corp_Standard",
                    rulebase_type="access",
                    layer_uid="layer-1",
                    layer_name="Network",
                    position=0,
                    raw_data={
                        "installation-targets": [
                            {"uid": "uid-vs-1", "name": "corp-vs-1"},
                            {"uid": "uid-vs-2", "name": "corp-vs-2"},
                            {"uid": "uid-vs-3", "name": "corp-vs-3"},
                            {"uid": "uid-gw-indep", "name": "gw-indep-1"},
                        ]
                    },
                )
            ],
        )
    )

    active_by_node: dict[str, int] = {"uid-vsx-host-1": 0, "uid-gw-indep": 0}
    max_by_node: dict[str, int] = {"uid-vsx-host-1": 0, "uid-gw-indep": 0}
    active_total = 0
    max_total = 0
    cli_invocations = 0

    async def _fake_cli(target: Any, _script: str) -> str:
        nonlocal active_total, max_total, cli_invocations
        cli_invocations += 1
        nk = str(target.node_uid)
        active_by_node[nk] = active_by_node.get(nk, 0) + 1
        active_total += 1
        max_by_node[nk] = max(max_by_node.get(nk, 0), active_by_node[nk])
        max_total = max(max_total, active_total)
        try:
            await asyncio.sleep(0.03)
            if nk == "uid-gw-indep":
                # Emit >100 routes + limit marker to verify truncation warning
                many = "\n".join(
                    f"172.20.{i // 256}.{i % 256}/32 via 10.90.0.254 dev eth1 proto bgp" for i in range(110)
                )
                return (
                    f"===ARODONATA_IP_ROUTE_START===\n{many}\n{ROUTE_LIMIT_MARKER}=100\n===ARODONATA_IP_ROUTE_END===\n"
                    f"===ARODONATA_CLISH_ROUTE_START===\n{CLISH_SKIPPED_LARGE_TABLE_MARKER}\n===ARODONATA_CLISH_ROUTE_END===\n"
                )
            vsid = target.vsid or 1
            return (
                f"===ARODONATA_IP_ROUTE_START===\n10.200.{vsid}.0/24 via 10.10.{vsid}.254 dev eth1 proto static\n"
                f"===ARODONATA_IP_ROUTE_END===\n"
            )
        finally:
            active_by_node[nk] -= 1
            active_total -= 1

    full_rulebase_calls = 0
    pkg_rulebase_calls = 0
    orig_full_rb = cache.get_domain_rulebase
    orig_pkg_rb = cache.get_domain_rulebase_packages

    async def _spy_full_rb(*args: Any, **kwargs: Any) -> DomainRulebaseSnapshot:
        nonlocal full_rulebase_calls
        full_rulebase_calls += 1
        return await orig_full_rb(*args, **kwargs)

    async def _spy_pkg_rb(*args: Any, **kwargs: Any) -> DomainRulebaseSnapshot:
        nonlocal pkg_rulebase_calls
        pkg_rulebase_calls += 1
        return await orig_pkg_rb(*args, **kwargs)

    cache.get_domain_rulebase = _spy_full_rb  # type: ignore[method-assign]
    cache.get_domain_rulebase_packages = _spy_pkg_rb  # type: ignore[method-assign]
    try:
        # Fire two identical collect_gateway_routes calls concurrently -> coalesced into one flight!
        out_a, out_b = await asyncio.gather(
            topology_service.collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateway_cli=_fake_cli),
            topology_service.collect_gateway_routes(mgmt_name="mds1", domain="Corp", gateway_cli=_fake_cli),
        )
    finally:
        cache.get_domain_rulebase = orig_full_rb  # type: ignore[method-assign]
        cache.get_domain_rulebase_packages = orig_pkg_rb  # type: ignore[method-assign]

    assert out_a.total_gateways == 4
    assert out_b.total_gateways == 4
    # Coalesced: 4 gateways total, NOT 8
    assert cli_invocations == 4
    # Physical VSX host serialized strictly to 1 command at a time, while independent gateway ran in parallel!
    assert max_by_node["uid-vsx-host-1"] == 1
    assert max_total == 2
    # Zero full rulebase reloads, and lightweight package snapshot queried only once for "Corp"
    assert full_rulebase_calls == 0
    assert pkg_rulebase_calls == 1

    by_gw = {g.gateway_name: g for g in out_a.gateways}
    assert by_gw["gw-indep-1"].routes_collected == 100
    assert any("max_routes_per_gateway=100" in w for w in by_gw["gw-indep-1"].warnings)
    assert any("skipped clish" in w for w in by_gw["gw-indep-1"].warnings)

    # 3. Exact `max_routes_per_gateway` (100 unique routes, no marker) must NOT emit a false truncation warning
    async def _exact_100_cli(_target: Any, _script: str) -> str:
        exact_100 = "\n".join(f"172.21.{i // 256}.{i % 256}/32 via 10.90.0.254 dev eth1 proto bgp" for i in range(100))
        return f"===ARODONATA_IP_ROUTE_START===\n{exact_100}\n===ARODONATA_IP_ROUTE_END===\n"

    exact_out = await topology_service.collect_gateway_routes(
        mgmt_name="mds1",
        domain="Corp",
        gateways=["gw-indep-1"],
        gateway_cli=_exact_100_cli,
    )
    assert exact_out.gateways[0].routes_collected == 100
    assert not any("was truncated" in w for w in exact_out.gateways[0].warnings)

    # 4. Single-flight waiter cancellation: `asyncio.timeout` around a coalesced waiter raises `TimeoutError`
    # promptly while the in-flight owner finishes undisturbed; and cancelling the owner lets a live waiter take over.
    owner_entered = asyncio.Event()
    release_owner = asyncio.Event()

    async def _slow_cli(_target: Any, _script: str) -> str:
        owner_entered.set()
        await release_owner.wait()
        return "===ARODONATA_IP_ROUTE_START===\n10.222.0.0/24 via 10.90.0.254 dev eth1 proto static\n===ARODONATA_IP_ROUTE_END===\n"

    owner_task = asyncio.create_task(
        topology_service.collect_gateway_routes(
            mgmt_name="mds1",
            domain="Corp",
            gateways=["gw-indep-1"],
            gateway_cli=_slow_cli,
        )
    )
    await asyncio.wait_for(owner_entered.wait(), timeout=2.0)

    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.02):
            await topology_service.collect_gateway_routes(
                mgmt_name="mds1",
                domain="Corp",
                gateways=["gw-indep-1"],
                gateway_cli=_slow_cli,
            )

    assert not owner_task.done()
    release_owner.set()
    completed_owner = await owner_task
    assert completed_owner.succeeded_gateways == 1

    # Owner cancelled -> uncancelled waiter takes over and completes
    attempt = 0
    first_owner_entered = asyncio.Event()

    async def _takeover_cli(_target: Any, _script: str) -> str:
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            first_owner_entered.set()
            await asyncio.sleep(10.0)
        return "===ARODONATA_IP_ROUTE_START===\n10.223.0.0/24 via 10.90.0.254 dev eth1 proto static\n===ARODONATA_IP_ROUTE_END===\n"

    doomed_owner = asyncio.create_task(
        topology_service.collect_gateway_routes(
            mgmt_name="mds1",
            domain="Corp",
            gateways=["gw-indep-1"],
            gateway_cli=_takeover_cli,
        )
    )
    await asyncio.wait_for(first_owner_entered.wait(), timeout=2.0)
    surviving_waiter = asyncio.create_task(
        topology_service.collect_gateway_routes(
            mgmt_name="mds1",
            domain="Corp",
            gateways=["gw-indep-1"],
            gateway_cli=_takeover_cli,
        )
    )
    await asyncio.sleep(0.01)
    doomed_owner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await doomed_owner
    takeover_out = await asyncio.wait_for(surviving_waiter, timeout=2.0)
    assert takeover_out.succeeded_gateways == 1
    assert attempt == 2

    await db.close()
