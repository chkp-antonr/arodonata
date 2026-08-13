"""Object naming conventions (from FPCR ObjectMatcher), prefix-configurable."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel


class NamingPrefixes(BaseModel):
    model_config = {"frozen": True}
    host: str = "Host_"
    network: str = "Net_"
    range: str = "IPR_"
    svc_tcp: str = "TCP_"
    svc_udp: str = "UDP_"
    svc_icmp: str = "ICMP_"

    @classmethod
    def from_settings(cls, settings: Any) -> NamingPrefixes:
        return cls(
            host=getattr(settings, "cpcrud_auto_name_prefix_host", "Host_"),
            network=getattr(settings, "cpcrud_auto_name_prefix_network", "Net_"),
            range=getattr(settings, "cpcrud_auto_name_prefix_range", "IPR_"),
            svc_tcp=getattr(settings, "cpcrud_auto_name_prefix_svc_tcp", "TCP_"),
            svc_udp=getattr(settings, "cpcrud_auto_name_prefix_svc_udp", "UDP_"),
            svc_icmp=getattr(settings, "cpcrud_auto_name_prefix_svc_icmp", "ICMP_"),
        )


DEFAULT_PREFIXES = NamingPrefixes()

_IP = r"\d{1,3}(\.\d{1,3}){3}"


def _patterns(p: NamingPrefixes) -> dict[str, re.Pattern[str]]:
    e = re.escape
    return {
        "host": re.compile(rf"^(global_)?({e(p.host)}{_IP}|ipr_.+)$", re.IGNORECASE),
        "network": re.compile(rf"^(global_)?{e(p.network)}{_IP}_\d{{1,2}}$", re.IGNORECASE),
        "address-range": re.compile(rf"^(global_)?{e(p.range)}{_IP}-{_IP}$", re.IGNORECASE),
    }


def matches_convention(object_type: str, name: str, prefixes: NamingPrefixes | None = None) -> bool:
    pattern = _patterns(prefixes or DEFAULT_PREFIXES).get(object_type)
    return bool(pattern and pattern.match(name))
