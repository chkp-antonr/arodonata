"""NAT settings transformation (ported from MMP cpcrud object_manager)."""

from __future__ import annotations

from typing import Any

_IPV4_FIELD = {"host": "ipv4-address", "address-range": "ipv4-address", "network": "ip-address"}


def transform_nat_settings(object_type: str, nat_settings: dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalize template NAT settings to the CP API shape. Returns None when empty."""
    if not nat_settings:
        return None
    out = dict(nat_settings)  # never mutate the template
    if "gateway" in out:
        out["install-on"] = out.pop("gateway")
    if out.get("method") and "auto-rule" not in out:
        out["auto-rule"] = True
    target = _IPV4_FIELD.get(object_type)
    if target == "ipv4-address" and "ip-address" in out:
        out["ipv4-address"] = out.pop("ip-address")
    elif target == "ip-address" and "ipv4-address" in out:
        out["ip-address"] = out.pop("ipv4-address")
    return out
