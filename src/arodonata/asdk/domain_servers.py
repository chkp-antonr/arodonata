"""Read a domain's server layout out of `show-domains`, and member IPs out of `show-mdss`.

One place for parsing that LoginCoordinator and DomainService used to duplicate,
extended to read which Multi-Domain Server member hosts each domain server. That
member is the machine Check Point rate-limits logins on (asdk/login_gate.py), and
domains move between members on failover, so callers re-read this whenever a
domain's active server is re-resolved. Pure functions; no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DomainServers:
    """A domain's servers as `show-domains` (details-level full) reports them."""

    active_ip: str = ""
    active_server: str = ""  # the active domain server's object name
    active_mds: str = ""  # the MDS member hosting it (`multi-domain-server`)
    standby_ips: tuple[str, ...] = ()
    standby_servers: tuple[str, ...] = ()
    standby_mdss: tuple[str, ...] = ()


def _name_of(value: Any) -> str:
    """`multi-domain-server` may be a name or a {name, uid} object; the reference does not say which."""
    if isinstance(value, dict):
        return str(value.get("name") or "")
    return value if isinstance(value, str) else ""


def extract_domain_servers(domain_obj: dict[str, Any]) -> DomainServers:
    """Split a domain's `servers` list into the active server and the standbys.

    The active server is the first entry with `active: true` and a non-empty
    `ipv4-address` -- the rule the two former `_extract_active_server_ip`
    methods applied. Every other entry with an address is a standby. Entries
    that are not dicts, or have no address, are ignored.
    """
    servers = domain_obj.get("servers", [])
    if not isinstance(servers, list):
        return DomainServers()

    active_ip = active_server = active_mds = ""
    standby_ips: list[str] = []
    standby_servers: list[str] = []
    standby_mdss: list[str] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        ip = server.get("ipv4-address", "")
        if not isinstance(ip, str) or not ip:
            continue
        name = str(server.get("name") or "")
        mds = _name_of(server.get("multi-domain-server"))
        if server.get("active") is True and not active_ip:
            active_ip, active_server, active_mds = ip, name, mds
        else:
            standby_ips.append(ip)
            standby_servers.append(name)
            standby_mdss.append(mds)

    return DomainServers(
        active_ip=active_ip,
        active_server=active_server,
        active_mds=active_mds,
        standby_ips=tuple(standby_ips),
        standby_servers=tuple(standby_servers),
        standby_mdss=tuple(standby_mdss),
    )


def mds_ip_map(mds_objects: list[Any]) -> dict[str, str]:
    """{member name: ipv4-address} from `show-mdss` objects; entries missing either are skipped."""
    result: dict[str, str] = {}
    for obj in mds_objects:
        if not isinstance(obj, dict):
            continue
        name = obj.get("name")
        ip = obj.get("ipv4-address")
        if isinstance(name, str) and name and isinstance(ip, str) and ip:
            result[name] = ip
    return result


__all__ = ["DomainServers", "extract_domain_servers", "mds_ip_map"]
