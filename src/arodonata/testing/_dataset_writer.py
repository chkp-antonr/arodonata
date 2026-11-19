"""Disk writer and manifest assembly for the enterprise raw replay dataset."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ._dataset_common import (
    ALL_DOMAINS,
    DATASET_VERSION,
    POLICY_GW_TYPES,
    USER_DOMAINS,
    DatasetBuildContext,
    encode_task_payload,
    write_json,
    write_text,
)


def write_dataset_and_manifest(
    ctx: DatasetBuildContext,
    root: Path,
    *,
    seed: int,
    total_access_rules: int,
    total_nat_rules: int,
) -> dict[str, Any]:
    """Write MDS, per-domain, CLI, task, and manifest JSON files to `root` and return manifest."""
    for subdir in ("mds", "domains", "cli", "tasks"):
        shutil.rmtree(root / subdir, ignore_errors=True)

    write_json(
        root / "mds" / "show-domains.json",
        {
            "objects": ctx.domains_raw,
            "from": 1,
            "to": len(ctx.domains_raw),
            "total": len(ctx.domains_raw),
        },
    )
    write_json(
        root / "mds" / "show-global-domain.json",
        ctx.global_domain_raw,
    )
    write_json(
        root / "mds" / "show-mdss.json",
        {
            "objects": [
                {
                    "uid": "uid-mds-primary",
                    "name": "mds-ent-primary",
                    "type": "mds",
                    "ipv4-address": "10.250.0.10",
                },
                {
                    "uid": "uid-mds-standby",
                    "name": "mds-ent-standby",
                    "type": "mds",
                    "ipv4-address": "10.250.0.11",
                },
            ],
            "from": 1,
            "to": 2,
            "total": 2,
        },
    )
    global_assignments_raw: list[dict[str, Any]] = [
        {
            "uid": f"uid-ga-{dom.lower()}",
            "name": f"Global_to_{dom}",
            "type": "global-assignment",
            "global-domain": {
                "uid": "uid-dom-global",
                "name": "Global",
                "domain-type": "global domain",
            },
            "dependent-domain": {
                "uid": f"uid-dom-{dom.lower()}",
                "name": dom,
                "domain-type": "domain",
            },
            "global-access-policy": "Global_Standard_Pkg",
            "global-threat-prevention-policy": "",
            "manage-protection-actions": False,
            "assignment-status": "assigned",
            "assignment-up-to-date": {
                "posix": 1794139200000,
                "iso-8601": "2026-11-08T10:00:00Z",
            },
        }
        for dom in USER_DOMAINS
    ]
    write_json(
        root / "mds" / "show-global-assignments.json",
        {
            "objects": global_assignments_raw,
            "from": 1 if global_assignments_raw else 0,
            "to": len(global_assignments_raw),
            "total": len(global_assignments_raw),
        },
    )

    total_assets_count = 0
    policy_enforcing_count = 0
    total_objects_count = 0
    total_services_count = 0

    for dom in ALL_DOMAINS:
        dom_dir = root / "domains" / dom
        sess_info = ctx.domain_sessions[dom]
        write_json(dom_dir / "show-last-published-session.json", sess_info["last_published"])
        write_json(dom_dir / "show-session.json", sess_info["current_session"])
        write_json(
            dom_dir / "show-sessions.json",
            {
                "objects": [sess_info["last_published"]],
                "from": 1,
                "to": 1,
                "total": 1,
            },
        )

        gws = ctx.gateways_by_domain[dom]
        total_assets_count += len(gws)
        policy_enforcing_count += sum(1 for g in gws if str(g.get("type", "")) in POLICY_GW_TYPES)
        write_json(
            dom_dir / "show-gateways-and-servers.json",
            {
                "objects": gws,
                "from": 1 if gws else 0,
                "to": len(gws),
                "total": len(gws),
            },
        )
        write_json(dom_dir / "show-simple-gateway.json", ctx.simple_gw_details[dom])
        write_json(dom_dir / "show-simple-cluster.json", ctx.simple_cl_details[dom])
        write_json(dom_dir / "show-generic-objects.json", ctx.generic_by_class[dom])
        write_json(dom_dir / "show-generic-object.json", ctx.generic_by_uid[dom])

        for cmd_name, items in (
            ("show-hosts", ctx.hosts_by_domain[dom]),
            ("show-networks", ctx.networks_by_domain[dom]),
            ("show-address-ranges", ctx.ranges_by_domain[dom]),
            ("show-groups", ctx.groups_by_domain[dom]),
            ("show-dns-domains", ctx.dns_domains_by_domain[dom]),
        ):
            total_objects_count += len(items)
            write_json(
                dom_dir / f"{cmd_name}.json",
                {
                    "objects": items,
                    "from": 1 if items else 0,
                    "to": len(items),
                    "total": len(items),
                },
            )

        for svc_cmd, svc_items in (
            ("show-services-tcp", ctx.services_tcp_by_domain[dom]),
            ("show-services-udp", ctx.services_udp_by_domain[dom]),
            ("show-services-icmp", ctx.services_icmp_by_domain[dom]),
            ("show-service-groups", ctx.service_groups_by_domain[dom]),
        ):
            total_services_count += len(svc_items)
            write_json(
                dom_dir / f"{svc_cmd}.json",
                {
                    "objects": svc_items,
                    "from": 1 if svc_items else 0,
                    "to": len(svc_items),
                    "total": len(svc_items),
                },
            )

        pkgs = ctx.packages_by_domain[dom]
        write_json(
            dom_dir / "show-packages.json",
            {
                "packages": pkgs,
                "objects": pkgs,
                "from": 1 if pkgs else 0,
                "to": len(pkgs),
                "total": len(pkgs),
            },
        )
        layers = ctx.access_layers_by_domain[dom]
        write_json(
            dom_dir / "show-access-layers.json",
            {
                "access-layers": layers,
                "objects": layers,
                "from": 1 if layers else 0,
                "to": len(layers),
                "total": len(layers),
            },
        )
        write_json(dom_dir / "show-access-rulebase.json", ctx.access_rulebases_by_domain[dom])
        write_json(dom_dir / "show-nat-rulebase.json", ctx.nat_rulebases_by_domain[dom])

    for (node_name, vsid), stdout_text in sorted(ctx.cli_outputs.items(), key=lambda x: (x[0][0], x[0][1] or 0)):
        suffix = f"__vs_{vsid}" if vsid is not None else "__vs_none"
        write_text(root / "cli" / f"{node_name}{suffix}.txt", stdout_text)
        task_id = f"task-{node_name}-{vsid if vsid is not None else 0}"
        write_json(
            root / "tasks" / f"{node_name}{suffix}.json",
            encode_task_payload(task_id, node_name, stdout_text),
        )

    for chassis_name, stat_text in sorted(ctx.vsx_stat_outputs.items()):
        write_text(root / "cli" / f"{chassis_name}__vsx_stat_l.txt", stat_text)

    manifest = {
        "version": DATASET_VERSION,
        "seed": seed,
        "domains": list(ALL_DOMAINS),
        "user_domains": list(USER_DOMAINS),
        "counts": {
            "total_domains": len(ALL_DOMAINS),
            "user_domains": len(USER_DOMAINS),
            "total_assets": total_assets_count,
            "policy_enforcing_gateways": policy_enforcing_count,
            "total_network_objects": total_objects_count,
            "total_service_objects": total_services_count,
            "total_access_rules": total_access_rules,
            "total_nat_rules": total_nat_rules,
            "total_cli_targets": len(ctx.cli_outputs),
        },
        "cprid_fallback_gateways": [
            "br-reg-gw-138",
            "br-reg-gw-139",
            "br-reg-gw-140",
        ],
        "nine_hop_chain": [
            {"hop": 1, "domain": "Branch", "gateway": "br-spb-gw-01"},
            {"hop": 2, "domain": "Regional", "gateway": "reg-nw-cluster"},
            {
                "hop": 3,
                "domain": "WAN_Core",
                "gateways_ecmp": ["wan-core-ecmp-a", "wan-core-ecmp-b"],
                "standby": "wan-core-bgp-standby",
            },
            {"hop": 4, "domain": "Perimeter", "gateway": "perim-edge-cluster"},
            {"hop": 5, "domain": "Transit", "gateway": "ix-transit-gw-01"},
            {"hop": 6, "domain": "DC_Spine", "gateway": "dc-vsx-spine-vs01"},
            {"hop": 7, "domain": "DC_Pod", "gateway": "dc-vs-tier1-web"},
            {"hop": 8, "domain": "DC_Pod", "gateway": "dc-vs-tier2-app"},
            {"hop": 9, "domain": "DB_Seg", "gateway": "db-seg-internal-fw-01"},
        ],
    }
    write_json(root / "manifest.json", manifest)
    return manifest
