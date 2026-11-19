"""MDSM domain metadata, Global domain objects, and domain service builders."""

from __future__ import annotations

from ._dataset_common import ALL_DOMAINS, USER_DOMAINS, DatasetBuildContext


def populate_mdsm_domains_and_sessions(ctx: DatasetBuildContext) -> None:
    """Populate MDSM domains, Global domain metadata, and baseline published/current sessions."""
    for idx, dom_name in enumerate(USER_DOMAINS, start=1):
        cma_ip = f"10.250.1.{10 + idx}"
        standby_ip = f"10.250.2.{10 + idx}"
        ctx.domains_raw.append(
            {
                "uid": f"uid-dom-{dom_name.lower()}",
                "name": dom_name,
                "type": "domain",
                "domain-type": "domain",
                "servers": [
                    {
                        "name": f"{dom_name.lower()}-cma-primary",
                        "ipv4-address": cma_ip,
                        "multi-domain-server": {
                            "uid": "uid-mds-primary",
                            "name": "mds-ent-primary",
                            "ipv4-address": "10.250.0.10",
                        },
                        "active": True,
                    },
                    {
                        "name": f"{dom_name.lower()}-cma-standby",
                        "ipv4-address": standby_ip,
                        "multi-domain-server": {
                            "uid": "uid-mds-standby",
                            "name": "mds-ent-standby",
                            "ipv4-address": "10.250.0.11",
                        },
                        "active": False,
                    },
                ],
            }
        )

    ctx.global_domain_raw = {
        "uid": "uid-dom-global",
        "name": "Global",
        "type": "global",
        "domain-type": "global domain",
        "servers": [
            {
                "name": "global-cma-primary",
                "ipv4-address": "10.250.0.10",
                "multi-domain-server": {
                    "uid": "uid-mds-primary",
                    "name": "mds-ent-primary",
                    "ipv4-address": "10.250.0.10",
                },
                "active": True,
            }
        ],
    }

    for idx, dom_name in enumerate(ALL_DOMAINS):
        pub_iso = f"2026-11-08T1{idx}:00:00Z"
        pub_posix = 1794139200000 + idx * 3600000
        sess_uid = f"sess-pub-{dom_name.lower()}-001"
        ctx.domain_sessions[dom_name] = {
            "last_published": {
                "uid": sess_uid,
                "name": f"AutoPublish-{dom_name}",
                "user-name": "admin",
                "publish-time": {"posix": pub_posix, "iso-8601": pub_iso},
                "last-modify-time": {"posix": pub_posix, "iso-8601": pub_iso},
                "changes": 0,
                "locks": 0,
                "number-of-published-changes": 12,
            },
            "current_session": {
                "uid": f"sess-ro-{dom_name.lower()}",
                "user-name": "ro-automation",
                "locks": 0,
                "changes": 0,
                "number-of-published-changes": 0,
            },
        }


def populate_global_and_services(ctx: DatasetBuildContext) -> None:
    """Populate Global network/group/host objects plus TCP/UDP/ICMP/service-group/DNS fixtures across all domains."""
    ctx.networks_by_domain["Global"].extend(
        [
            {
                "uid": "uid-glob-net-branches",
                "name": "N_Global_All_Branches",
                "type": "network",
                "subnet4": "10.11.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-glob-net-dc-vault",
                "name": "N_Global_DC_Vault_Super",
                "type": "network",
                "subnet4": "10.220.0.0",
                "mask-length4": 16,
            },
            {
                "uid": "uid-glob-net-rfc1918-10",
                "name": "N_Global_RFC1918_10",
                "type": "network",
                "subnet4": "10.0.0.0",
                "mask-length4": 8,
            },
        ]
    )
    ctx.groups_by_domain["Global"].extend(
        [
            {
                "uid": "uid-glob-grp-branches",
                "name": "G_Global_Branch_Supernet",
                "type": "group",
                "members": ["uid-glob-net-branches"],
            },
            {
                "uid": "uid-glob-grp-dc",
                "name": "G_Global_DC_Supernet",
                "type": "group",
                "members": ["uid-glob-net-dc-vault"],
            },
        ]
    )
    for p_idx in range(1, 81):
        ctx.hosts_by_domain["Global"].append(
            {
                "uid": f"uid-glob-host-{p_idx:03d}",
                "name": f"H_Global_DNS_{p_idx:03d}",
                "type": "host",
                "ipv4-address": f"10.253.0.{p_idx}",
            }
        )

    for dom in ALL_DOMAINS:
        d_slug = dom.lower()
        for port in (22, 53, 80, 443, 1521, 3306, 5432, 6379, 8080, 8443, 9092, 9200):
            ctx.services_tcp_by_domain[dom].append(
                {
                    "uid": f"uid-{d_slug}-svc-tcp-{port}",
                    "name": f"TCP_{port}" if dom == "Global" else f"SVC_{dom}_TCP_{port}",
                    "type": "service-tcp",
                    "port": str(port),
                }
            )
        for uport in (53, 123, 161, 500, 514, 1812, 4500):
            ctx.services_udp_by_domain[dom].append(
                {
                    "uid": f"uid-{d_slug}-svc-udp-{uport}",
                    "name": f"UDP_{uport}" if dom == "Global" else f"SVC_{dom}_UDP_{uport}",
                    "type": "service-udp",
                    "port": str(uport),
                }
            )
        ctx.services_icmp_by_domain[dom].append(
            {
                "uid": f"uid-{d_slug}-svc-icmp-echo",
                "name": "icmp-proto" if dom == "Global" else f"ICMP_{dom}_Echo",
                "type": "service-icmp",
                "icmp-type": 8,
            }
        )
        ctx.service_groups_by_domain[dom].append(
            {
                "uid": f"uid-{d_slug}-svc-grp-web",
                "name": "G_Web_Services" if dom == "Global" else f"G_{dom}_App_Services",
                "type": "service-group",
                "members": [
                    f"uid-{d_slug}-svc-tcp-80",
                    f"uid-{d_slug}-svc-tcp-443",
                    f"uid-{d_slug}-svc-tcp-8443",
                ],
            }
        )
        ctx.dns_domains_by_domain[dom].append(
            {
                "uid": f"uid-{d_slug}-dns-corp",
                "name": f".{d_slug}.enterprise.internal",
                "type": "dns-domain",
                "is-sub-domain": True,
            }
        )
