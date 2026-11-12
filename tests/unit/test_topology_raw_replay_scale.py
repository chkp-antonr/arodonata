"""End-to-end enterprise raw-replay scale test suite (`test_topology_raw_replay_scale.py`).

Exercises:
- Step 1: Cold `refresh_topology(..., collect_routes=True)` from raw JSON and CLI files via
  `FileReplayApiMock` and `FileReplayCliMock` into `SqlCacheAdapter`, including VSX `CpmiVsSlotObj`
  cross-domain merging, `vsx stat -l` dynamic VSID resolution, `show-simple-cluster` on-demand
  detail fallback, and `cprid` `run-script` + `show-task` Base64 fallback.
- Step 2: `cache_mode="smart"` and `cache_mode="cache"` verification confirming zero
  `show-gateways-and-servers` or SSH calls when `show-last-published-session` is unchanged.
- Step 3: `get_topology_diagnostics` and `reconcile_gateway_topology` across all planted anomalies
  (`not_defined`, `routing_defined_without_routes`, `anti_spoofing_detect_or_off`, `one_arm_topology`,
  internal-only gateways without `external`, `stale_in_topology`, `missing_in_topology`,
  `interface_mismatch`, `cluster_member_drift`, `default_route_mismatch`, `resolved_by_routing`).
- Step 4: Persistent administrator `TopologyAnnotation` overrides (`standby_dynamic`, `ignore`,
  `manual`, `confirmed`, `trust_static_topology=False`, `zone`, `site`, `comment`) and
  `export_topology_prefixes`.
- Step 5: 9-hop cross-domain chain (`Branch -> Regional -> WAN_Core -> Perimeter -> Transit ->
  DC_Spine -> VS Tier-1 -> VS Tier-2 -> DB_Seg`), parallel ECMP legs, standby BGP path filtering
  (`include_standby=True` vs `False`), `/8`..`/32` LPM matryoshka on `lpm-matryoshka-gw`, and
  `22 x 22` batch query checking sub-second latency and input order preservation.
- Step 6: Targeted single-gateway refresh (`refresh_topology(gateways=["ix-transit-gw-02"], collect_routes=True)`)
  after mutating raw API/CLI data, verifying via mock counters that only that gateway was queried
  and the routing graph updated.
- Standalone HTTPS Mock Server (`CheckPointReplayHttpServer`): real `ArodonataClient` (`AMgmtClient`
  + `ApiTransport`) over loopback HTTPS syncing domains, objects, gateways, rulebases, and `cprid`
  routes.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from arodonata import (
    AMgmtClient,
    ArodonataClient,
    ArodonataSettings,
    TopologyAnnotation,
)
from arodonata.adapters.checkpoint.task_waiter import TaskWaiter
from arodonata.testing import (
    CheckPointReplayHttpServer,
    FileReplayApiMock,
    FileReplayCliMock,
    ensure_enterprise_raw_dataset,
)


@pytest.mark.asyncio
async def test_enterprise_topology_raw_replay_scale_pipeline(tmp_path: Path) -> None:
    """Execute the 6-step enterprise raw-replay topology pipeline from disk fixtures."""
    dataset_dir = ensure_enterprise_raw_dataset()
    cli_mock = FileReplayCliMock(dataset_dir)
    api_mock = FileReplayApiMock(dataset_dir, cli_mock=cli_mock)

    db_path = tmp_path / "enterprise_topology_scale.sqlite"
    settings = ArodonataSettings(
        database_url=f"sqlite+aiosqlite:///{db_path}",
        mgmt_name="mds",
        mgmt_ip="127.0.0.1",
        mgmt_port=443,
        api_key="mock-key",
    )

    async with ArodonataClient(
        settings=settings,
        api=api_mock,
        gateway_cli=cli_mock,
    ) as client:
        # ==================================================================
        # STEP 1: Cold Sync from Raw Fixtures (`refresh_topology` + routes)
        # ==================================================================
        domains = await client.get_domains(mgmt_name="mds", include_global=True, cache_mode="force")
        assert len(domains) == 10
        domain_names = {d.name for d in domains}
        assert domain_names == {
            "Global",
            "Branch",
            "Regional",
            "WAN_Core",
            "Perimeter",
            "Transit",
            "DC_Spine",
            "DC_Pod",
            "DB_Seg",
            "Partner_DMZ",
        }

        cold_outcome = await client.topology_service.refresh_topology(
            mgmt_name="mds",
            collect_routes=True,
            include_global=True,
            mode="smart",
        )
        assert len(cold_outcome.refreshed_domains) == 10
        assert not cold_outcome.failed_domains

        # Verify SQL cache population: 284 total assets (276 policy-enforcing gateways) & ONLY gateway-referenced
        # `"specific"` / `vpn-domain` objects resolved on demand (ZERO bulk `show-hosts` or `show-dns-domains`!)
        cached_assets = await client.cache.get_assets(mgmt_name="mds")
        assert len(cached_assets) == 284
        assert api_mock.command_counts["show-hosts"] == 0
        assert api_mock.command_counts["show-dns-domains"] == 0
        assert api_mock.command_counts["show-networks"] == 0
        assert api_mock.command_counts["show-groups"] == 0
        cached_objects = await client.cache.get_objects(mgmt_name="mds")
        assert 0 < len(cached_objects) < 250
        assert await client.cache.list_sync_states(mgmt_name="mds", scope="objects") == []

        # Verify on-demand `show-simple-cluster` fallback was triggered for `perim-edge-cluster`
        assert ("Perimeter", "show-simple-cluster", "uid-perim-edge-cluster") in api_mock.gateway_detail_queries

        # Verify `cprid` `run-script` + `show-task` fallback was triggered for `br-reg-gw-138..140`
        assert api_mock.api_call_counts[("Branch", "run-script")] == 3
        assert api_mock.api_call_counts[("Branch", "show-task")] == 3

        # Verify `dc-vs-tier2-app` resolved its VSID=12 dynamically via `vsx stat -l` on `dc-vsx-chassis-01`
        assert cli_mock.cli_call_counts[("dc-vsx-chassis-01", 12)] == 1

        # ==================================================================
        # STEP 2: Smart Cache & Cache-Only Mode Verification
        # ==================================================================
        api_mock.reset_counters()

        smart_outcome = await client.topology_service.refresh_topology(
            mgmt_name="mds",
            collect_routes=True,
            include_global=True,
            mode="smart",
        )
        assert smart_outcome.refreshed_domains == []
        assert len(smart_outcome.skipped_domains) == 10
        # Zero `show-gateways-and-servers`, zero gateway detail queries, and zero SSH/cprid calls!
        assert api_mock.command_counts["show-gateways-and-servers"] == 0
        assert api_mock.command_counts["show-hosts"] == 0
        assert api_mock.command_counts["show-networks"] == 0
        assert api_mock.command_counts["show-groups"] == 0
        assert api_mock.command_counts["run-script"] == 0
        assert len(api_mock.gateway_detail_queries) == 0
        assert sum(cli_mock.cli_call_counts.values()) == 0
        assert sum(cli_mock.node_call_counts.values()) == 0

        # Verify `cache_mode="cache"` makes zero API calls at all (not even `show-last-published-session`)
        api_mock.reset_counters()
        cached_topo = await client.topology_service.get_gateway_topology(mgmt_name="mds", cache_mode="cache")
        assert len(cached_topo) > 1000
        assert sum(api_mock.command_counts.values()) == 0
        assert sum(cli_mock.node_call_counts.values()) == 0

        # ==================================================================
        # STEP 3: Topology Diagnostics & Static-vs-Live Reconciliation
        # ==================================================================
        all_diags = await client.topology_service.get_topology_diagnostics(
            mgmt_name="mds",
            min_severity="info",
            cache_mode="cache",
        )
        diag_by_gw_if_code = {(d.gateway_name, d.interface_name, d.code): d for d in all_diags}

        # Verify planted anomalies on `anomaly-audit-gw` (`Transit`)
        assert ("anomaly-audit-gw", "eth2", "anti_spoofing_detect_or_off") in diag_by_gw_if_code
        assert ("anomaly-audit-gw", "eth3", "not_defined") in diag_by_gw_if_code
        assert ("anomaly-audit-gw", "eth4", "routing_defined_without_routes") in diag_by_gw_if_code

        # Verify 10 One-Arm gateways (`partner-onearm-gw-01..10` in `Partner_DMZ`) emit `one_arm_topology` (`info`)
        for oa_idx in range(1, 11):
            oa_key = (f"partner-onearm-gw-{oa_idx:02d}", "eth0", "one_arm_topology")
            assert oa_key in diag_by_gw_if_code
            assert diag_by_gw_if_code[oa_key].severity == "info"

        # Verify internal-only segmentation gateways (`db-seg-internal-fw-01..15` in `DB_Seg`) emit ZERO warnings
        db_seg_warnings = [d for d in all_diags if d.domain_name == "DB_Seg" and d.severity == "warning"]
        assert db_seg_warnings == []

        # Verify Static-vs-Live Reconciliation (`reconcile_gateway_topology`)
        recon_report = await client.topology_service.reconcile_gateway_topology(
            mgmt_name="mds",
            cache_mode="cache",
        )
        assert recon_report.gateway_count == 276
        disc_by_gw_type_cidr = {
            (d.gateway_name, d.discrepancy_type, d.cidr_or_range): d for d in recon_report.discrepancies
        }

        # 1. `default_route_mismatch` on `anomaly-audit-gw` (`eth0` static external vs `eth5` live 0.0.0.0/0)
        def_mismatch = disc_by_gw_type_cidr.get(("anomaly-audit-gw", "default_route_mismatch", "0.0.0.0/0"))
        assert def_mismatch is not None
        assert def_mismatch.interface_name == "eth0"
        assert def_mismatch.routed_interface_name == "eth5"
        assert def_mismatch.severity == "warning"

        # 2. `stale_in_topology` on `partner-b2b-cluster` (`172.30.2.0/24` on `eth1`) & `wan-core-bgp-standby` (`10.220.0.0/16` on `eth2`)
        assert ("partner-b2b-cluster", "stale_in_topology", "172.30.2.0/24") in disc_by_gw_type_cidr
        assert ("wan-core-bgp-standby", "stale_in_topology", "10.220.0.0/16") in disc_by_gw_type_cidr

        # 3. `missing_in_topology` on `partner-b2b-cluster` (`172.30.5.0/24` on `eth1`)
        assert ("partner-b2b-cluster", "missing_in_topology", "172.30.5.0/24") in disc_by_gw_type_cidr

        # 4. `interface_mismatch` on `partner-b2b-cluster` (`172.30.3.0/24`: static `eth1` vs routed `eth2`)
        if_mismatch = disc_by_gw_type_cidr.get(("partner-b2b-cluster", "interface_mismatch", "172.30.3.0/24"))
        assert if_mismatch is not None
        assert if_mismatch.interface_name == "eth1"
        assert if_mismatch.routed_interface_name == "eth2"

        # 5. `resolved_by_routing` on `partner-b2b-cluster` (`172.30.4.0/24` on `eth2`, `severity="info"`)
        resolved_disc = disc_by_gw_type_cidr.get(("partner-b2b-cluster", "resolved_by_routing", "172.30.4.0/24"))
        assert resolved_disc is not None
        assert resolved_disc.severity == "info"

        # 6. `cluster_member_drift` on `partner-b2b-cluster` (`172.30.6.0/24` on `eth2`, present only on `partner-b2b-1a`)
        drift_disc = disc_by_gw_type_cidr.get(("partner-b2b-cluster", "cluster_member_drift", "172.30.6.0/24"))
        assert drift_disc is not None
        assert drift_disc.member_details.get("present_on_members") == ["partner-b2b-1a"]

        # ==================================================================
        # STEP 4: Administrator Overrides (`TopologyAnnotation`) & IPAM Export
        # ==================================================================
        annotations: list[TopologyAnnotation] = [
            # Mark `wan-core-bgp-standby` `eth2` `10.220.0.0/16` as `standby_dynamic`
            TopologyAnnotation(
                mgmt_name="mds",
                domain_name="WAN_Core",
                gateway_uid="uid-wan-core-bgp-standby",
                gateway_name="wan-core-bgp-standby",
                interface_name="eth2",
                cidr_or_range="10.220.0.0/16",
                disposition="standby_dynamic",
                zone="WAN-Backbone-Standby",
                site="Frankfurt-POP2",
                comment="Secondary BGP path active only during primary fiber cut",
            ),
            # Suppress stale prefix `172.30.2.0/24` on `partner-b2b-cluster` with `ignore`
            TopologyAnnotation(
                mgmt_name="mds",
                domain_name="Partner_DMZ",
                gateway_uid="uid-partner-b2b-cluster",
                gateway_name="partner-b2b-cluster",
                interface_name="eth1",
                cidr_or_range="172.30.2.0/24",
                disposition="ignore",
                zone="Partner-Deprecated",
                site="Amsterdam-DMZ",
                comment="Decommissioned partner subnet pending SmartConsole cleanup",
            ),
            # Inject a manual prefix `10.254.99.0/24` onto `anomaly-audit-gw` `eth3`
            TopologyAnnotation(
                mgmt_name="mds",
                domain_name="Transit",
                gateway_uid="uid-anomaly-audit-gw",
                gateway_name="anomaly-audit-gw",
                interface_name="eth3",
                cidr_or_range="10.254.99.0/24",
                disposition="manual",
                zone="Audit-Lab-Manual",
                site="Zurich-Lab",
                comment="Manually pinned air-gapped enclave subnet",
            ),
            # Confirm active partner prefix `172.30.1.0/24` on `partner-b2b-cluster` `eth1`
            TopologyAnnotation(
                mgmt_name="mds",
                domain_name="Partner_DMZ",
                gateway_uid="uid-partner-b2b-cluster",
                gateway_name="partner-b2b-cluster",
                interface_name="eth1",
                cidr_or_range="172.30.1.0/24",
                disposition="confirmed",
                zone="Partner-B2B-Prod",
                site="Amsterdam-DMZ",
                comment="Verified B2B extranet peer",
            ),
            # Set `trust_static_topology=False` on `anomaly-audit-gw` `eth1`
            TopologyAnnotation(
                mgmt_name="mds",
                domain_name="Transit",
                gateway_uid="uid-anomaly-audit-gw",
                gateway_name="anomaly-audit-gw",
                interface_name="eth1",
                cidr_or_range="*",
                trust_static_topology=False,
                zone="Untrusted-Static",
                site="Zurich-Lab",
                comment="Do not trust static topology on eth1",
            ),
        ]
        # Add 25 IPAM metadata annotations across Branch gateways (`br-spb-gw-01` and `br-reg-gw-002..025`)
        for b_idx in range(1, 26):
            gw_name = "br-spb-gw-01" if b_idx == 1 else f"br-reg-gw-{b_idx:03d}"
            annotations.append(
                TopologyAnnotation(
                    mgmt_name="mds",
                    domain_name="Branch",
                    gateway_uid=f"uid-branch-gw-{b_idx:03d}",
                    gateway_name=gw_name,
                    interface_name="eth1",
                    cidr_or_range=f"10.11.{b_idx}.0/24",
                    disposition="confirmed",
                    zone="Branch-Campus-LAN",
                    site=f"Branch-Site-{b_idx:03d}",
                    comment=f"Confirmed IPAM allocation for {gw_name}",
                )
            )

        saved_anns = await client.topology_service.upsert_topology_annotations(annotations)
        assert len(saved_anns) == 30

        # Export prefixes excluding ignored (`include_ignored=False`)
        exported = await client.topology_service.export_topology_prefixes(
            mgmt_name="mds",
            include_ignored=False,
            cache_mode="cache",
        )
        exp_map = {(e.gateway_name, e.interface_name, e.cidr_or_range): e for e in exported}

        # 1. Ignored prefix `172.30.2.0/24` on `partner-b2b-cluster` must be absent when `include_ignored=False`
        assert ("partner-b2b-cluster", "eth1", "172.30.2.0/24") not in exp_map
        exported_with_ignored = await client.topology_service.export_topology_prefixes(
            mgmt_name="mds",
            domain="Partner_DMZ",
            gateway="partner-b2b-cluster",
            include_ignored=True,
            cache_mode="cache",
        )
        assert any(e.cidr_or_range == "172.30.2.0/24" and e.disposition == "ignore" for e in exported_with_ignored)

        # 2. Manual prefix `10.254.99.0/24` on `anomaly-audit-gw` `eth3` is synthesized with `admin_manual` delta (`0.6`)
        manual_exp = exp_map.get(("anomaly-audit-gw", "eth3", "10.254.99.0/24"))
        assert manual_exp is not None
        assert manual_exp.disposition == "manual"
        assert manual_exp.confidence == pytest.approx(0.6)
        assert any(f.code == "admin_manual" for f in manual_exp.confidence_factors)
        assert manual_exp.zone == "Audit-Lab-Manual"
        assert manual_exp.site == "Zurich-Lab"

        # 3. Standby BGP prefix `10.220.0.0/16` on `wan-core-bgp-standby` `eth2` has `is_standby_path=True`
        standby_exp = exp_map.get(("wan-core-bgp-standby", "eth2", "10.220.0.0/16"))
        assert standby_exp is not None
        assert standby_exp.is_standby_path is True
        assert standby_exp.disposition == "standby_dynamic"
        assert standby_exp.zone == "WAN-Backbone-Standby"

        # 4. Branch IPAM annotations are preserved
        spb_exp = exp_map.get(("br-spb-gw-01", "eth1", "10.11.1.0/24"))
        assert spb_exp is not None
        assert spb_exp.zone == "Branch-Campus-LAN"
        assert spb_exp.site == "Branch-Site-001"

        # ==================================================================
        # STEP 5: 9-Hop Chain, ECMP, Standby Filtering, LPM Matryoshka, & 22x22 Batch
        # ==================================================================
        # 5A. 9-Hop Cross-Domain Chain (`10.11.1.25` in Branch -> `10.220.77.50` in DB_Seg)
        chain_with_standby = await client.topology_service.find_affected_gateways(
            sources=["10.11.1.25"],
            destinations=["10.220.77.50"],
            mgmt_name="mds",
            include_standby=True,
            cache_mode="cache",
        )
        chain_gw_names = {c.gateway_name for c in chain_with_standby}
        expected_9_hop_gateways = {
            "br-spb-gw-01",  # Hop 1: Branch (internal_to_external)
            "reg-nw-cluster",  # Hop 2: Regional (7-level nested group G_Reg_NW_L1_Root)
            "wan-core-ecmp-a",  # Hop 3a: WAN_Core ECMP Leg A (internal_to_internal)
            "wan-core-ecmp-b",  # Hop 3b: WAN_Core ECMP Leg B (internal_to_internal)
            "wan-core-bgp-standby",  # Hop 3c: WAN_Core Standby BGP (is_standby_path=True)
            "perim-edge-cluster",  # Hop 4: Perimeter (on-demand show-simple-cluster + Global groups)
            "ix-transit-gw-01",  # Hop 5: Transit (IS-IS clish routes)
            "dc-vsx-spine-vs01",  # Hop 6: DC_Spine (VSX CpmiVsSlotObj + vs_static_route)
            "dc-vs-tier1-web",  # Hop 7: DC_Pod (Virtual System vsid=11)
            "dc-vs-tier2-app",  # Hop 8: DC_Pod (Virtual System resolved via vsx stat -l -> vsid=12)
            "db-seg-internal-fw-01",  # Hop 9: DB_Seg (internal-only gateway eth1 -> eth2)
        }
        assert expected_9_hop_gateways.issubset(chain_gw_names)

        # Verify Standby BGP filtering (`include_standby=False`)
        chain_active_only = await client.topology_service.find_affected_gateways(
            sources=["10.11.1.25"],
            destinations=["10.220.77.50"],
            mgmt_name="mds",
            include_standby=False,
            cache_mode="cache",
        )
        active_gw_names = {c.gateway_name for c in chain_active_only}
        assert "wan-core-bgp-standby" not in active_gw_names
        assert "wan-core-ecmp-a" in active_gw_names
        assert "wan-core-ecmp-b" in active_gw_names

        # 5B. Longest-Prefix Match (LPM) Matryoshka (`/8`, `/12`, `/16`, `/22`, `/24`, `/28`, `/32`)
        # on `lpm-matryoshka-gw` (`Transit` domain): source `198.51.100.200` (external `eth0`) -> nested destinations
        lpm_cases = [
            ("10.70.5.20", "eth7", "10.70.5.20/32"),  # /32 host
            ("10.70.5.18", "eth6", "10.70.5.16/28"),  # /28 subnet
            ("10.70.5.100", "eth5", "10.70.5.0/24"),  # /24 subnet
            ("10.70.6.10", "eth4", "10.70.4.0/22"),  # /22 supernet
            ("10.70.200.1", "eth3", "10.70.0.0/16"),  # /16 supernet
            ("10.65.1.1", "eth2", "10.64.0.0/12"),  # /12 supernet
            ("10.99.1.1", "eth1", "10.0.0.0/8"),  # /8 supernet
        ]
        for target_ip, expected_if, expected_cidr in lpm_cases:
            lpm_res = await client.topology_service.find_affected_gateways(
                sources=["198.51.100.200"],
                destinations=[target_ip],
                mgmt_name="mds",
                domain="Transit",
                cache_mode="cache",
            )
            mat_cand = next((c for c in lpm_res if c.gateway_name == "lpm-matryoshka-gw"), None)
            assert mat_cand is not None, f"Missing lpm-matryoshka-gw for {target_ip}"
            flow = mat_cand.matched_flows[0]
            assert flow.src_interface == "eth0"
            assert flow.dst_interface == expected_if
            assert flow.dst_matched_cidr == expected_cidr

        # 5C. High-cardinality 22 x 22 batch query (nested groups, address ranges, networks, and IPs)
        # Warm `address-range` in `Branch` for `cache_mode="cache"` (`R_Branch_001_DHCP` is not attached to a gateway interface)
        await client.object_service.refresh_objects(mgmt_name="mds", domains=["Branch"], types=["address-range"])
        batch_sources = [
            "G_Reg_NW_L1_Root",  # 7-level nested group in Regional
            "R_Branch_001_DHCP",  # Address range 10.11.1.100-10.11.1.199
            *[f"10.11.{i}.25" for i in range(1, 21)],
        ]
        batch_destinations = [
            "N_DC_DB_Vault_Sub",  # 10.220.77.0/24
            "G_Global_DC_Supernet",  # Global group -> 10.220.0.0/16
            *[f"10.218.{p}.10" for p in range(21, 41)],
        ]
        assert len(batch_sources) == 22
        assert len(batch_destinations) == 22

        t0 = time.perf_counter()
        batch_candidates = await client.topology_service.find_affected_gateways(
            sources=batch_sources,
            destinations=batch_destinations,
            mgmt_name="mds",
            cache_mode="cache",
        )
        elapsed = time.perf_counter() - t0
        assert elapsed < 5.0, f"Batch 22x22 lookup took {elapsed:.3f}s (expected < 5.0s)"
        assert len(batch_candidates) >= 25

        # Verify strict input order preservation in `matched_sources` and `matched_destinations`
        src_index = {term: idx for idx, term in enumerate(batch_sources)}
        dst_index = {term: idx for idx, term in enumerate(batch_destinations)}
        for cand in batch_candidates:
            src_positions = [src_index[s] for s in cand.matched_sources]
            dst_positions = [dst_index[d] for d in cand.matched_destinations]
            assert src_positions == sorted(src_positions)
            assert dst_positions == sorted(dst_positions)

        # ==================================================================
        # STEP 6: Targeted Single-Gateway Refresh (`gateways=["ix-transit-gw-02"]`)
        # ==================================================================
        api_mock.reset_counters()

        # Mutate `ix-transit-gw-02` in `Transit` domain to add `eth2` (`10.199.88.1/24`) and a live route
        updated_ifs = [
            {
                "name": "eth0",
                "ipv4-address": "172.25.100.2",
                "ipv4-mask-length": 24,
                "topology": "external",
            },
            {
                "name": "eth1",
                "ipv4-address": "10.80.2.1",
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
                "ipv4-address": "10.199.88.1",
                "ipv4-mask-length": 24,
                "topology": "internal",
                "topology-settings": {
                    "ip-address-behind-this-interface": "network defined by the interface ip and net mask",
                },
                "anti-spoofing": True,
                "anti-spoofing-settings": {"action": "prevent"},
            },
        ]
        api_mock.update_gateway_interfaces("Transit", "ix-transit-gw-02", updated_ifs)
        api_mock.update_gateway_cli_stdout(
            "ix-transit-gw-02",
            (
                "===ARODONATA_IP_ROUTE_START===\n"
                "default via 172.25.100.254 dev eth0 proto static\n"
                "10.80.2.0/24 dev eth1 proto kernel scope link src 10.80.2.1\n"
                "10.199.88.0/24 dev eth2 proto kernel scope link src 10.199.88.1\n"
                "===ARODONATA_IP_ROUTE_END===\n"
            ),
        )

        targeted_outcome = await client.topology_service.refresh_topology(
            mgmt_name="mds",
            gateways=["ix-transit-gw-02"],
            collect_routes=True,
            mode="force",
        )
        assert targeted_outcome.refreshed_domains == ["mds:Transit"]
        assert not targeted_outcome.failed_domains

        # Verify ONLY `ix-transit-gw-02` (`uid-ix-transit-02`) was queried via API and SSH!
        assert api_mock.command_counts["show-gateways-and-servers"] == 0
        assert api_mock.gateway_detail_queries == [("Transit", "show-simple-gateway", "uid-ix-transit-02")]
        assert list(cli_mock.node_call_counts.keys()) == ["ix-transit-gw-02"]
        assert cli_mock.node_call_counts["ix-transit-gw-02"] == 1

        # Verify routing graph immediately reflects `eth1` (`10.80.2.0/24`) -> `eth2` (`10.199.88.0/24`)
        post_update_hops = await client.topology_service.find_affected_gateways(
            sources=["10.80.2.10"],
            destinations=["10.199.88.42"],
            mgmt_name="mds",
            domain="Transit",
            cache_mode="cache",
        )
        updated_cand = next((c for c in post_update_hops if c.gateway_name == "ix-transit-gw-02"), None)
        assert updated_cand is not None
        updated_flow = updated_cand.matched_flows[0]
        assert updated_flow.src_interface == "eth1"
        assert updated_flow.dst_interface == "eth2"
        assert updated_flow.match_type == "internal_to_internal"


@pytest.mark.asyncio
async def test_standalone_https_mock_server_with_real_arodonata_client(tmp_path: Path) -> None:
    """Verify `CheckPointReplayHttpServer` serves `ArodonataClient` (`AMgmtClient` + `ApiTransport`) over real HTTPS."""
    dataset_dir = ensure_enterprise_raw_dataset()
    cli_mock = FileReplayCliMock(dataset_dir)
    api_mock = FileReplayApiMock(dataset_dir, cli_mock=cli_mock)

    async with CheckPointReplayHttpServer(
        dataset_dir=dataset_dir,
        api_mock=api_mock,
        host="127.0.0.1",
        port=0,
    ) as server:
        assert server.port > 0
        assert server.fingerprint

        db_path = tmp_path / "https_loopback.sqlite"
        settings = ArodonataSettings(
            database_url=f"sqlite+aiosqlite:///{db_path}",
            mgmt_name="mds",
            mgmt_ip="127.0.0.1",
            mgmt_port=server.port,
            username="admin",
            password="mock-password",
            tls_trust="pinned",
            tls_fingerprints=f"127.0.0.1:{server.port}={server.fingerprint}",
        )
        fast_waiter = TaskWaiter(task_timeout=10.0, initial_delay=0.01, max_delay=0.05)
        real_api = AMgmtClient(settings=settings, task_waiter=fast_waiter)

        async with ArodonataClient(
            settings=settings,
            api=real_api,
            gateway_cli=cli_mock,
        ) as client:
            # 1. Discover all 10 MDSM domains over HTTPS (with dynamic CMA IP rewriting to 127.0.0.1)
            domains = await client.get_domains(mgmt_name="mds", include_global=True, cache_mode="force")
            assert len(domains) == 10
            assert all(d.active_ip == "127.0.0.1" for d in domains)

            # 2. Refresh topology & live routes across `Branch` and `Transit` over real HTTPS
            #    (including `cprid` `run-script` + `show-task` polling over HTTPS for `br-reg-gw-138..140`!)
            topo_outcome = await client.topology_service.refresh_topology(
                mgmt_name="mds",
                domains=["Branch", "Transit"],
                collect_routes=True,
                mode="force",
            )
            assert set(topo_outcome.refreshed_domains) == {"mds:Branch", "mds:Transit"}
            assert not topo_outcome.failed_domains

            # 3. Refresh rulebases (`show-packages`, `show-access-rulebase`, `show-nat-rulebase`) over HTTPS
            rb_outcome = await client.rulebase_refresh.refresh_rulebases(
                mgmt_name="mds",
                domains=["Branch", "Transit"],
                mode="force",
            )
            assert set(rb_outcome.refreshed_domains) == {"mds:Branch", "mds:Transit"}
            branch_rb = await client.cache.get_domain_rulebase("mds", "Branch")
            assert len(branch_rb.access_rules) == 105
            assert len(branch_rb.nat_rules) == 12
            assert len(branch_rb.sections) >= 3

            # 4. Query affected gateways from cache populated over HTTPS
            hops = await client.topology_service.find_affected_gateways(
                sources=["10.11.1.25"],
                destinations=["10.220.77.50"],
                mgmt_name="mds",
                cache_mode="cache",
            )
            hop_names = {h.gateway_name for h in hops}
            assert "br-spb-gw-01" in hop_names
            assert "ix-transit-gw-01" in hop_names
            spb_hop = next(h for h in hops if h.gateway_name == "br-spb-gw-01")
            assert spb_hop.installed_access_policy == "Branch_Standard_Pkg"
            assert spb_hop.access_layers == ["Branch_Standard_Pkg Network"]
