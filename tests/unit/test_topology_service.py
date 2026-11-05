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
    DomainRulebaseSnapshot,
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
