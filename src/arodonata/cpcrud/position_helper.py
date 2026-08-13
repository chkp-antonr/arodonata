"""Resolve a schema-validated rule_position value into the exact apply-time API position (spec §9)."""

from __future__ import annotations

from typing import Any


def _is_cleanup_rule(rule_raw: dict[str, Any]) -> bool:
    """source=Any and destination=Any and service=Any, regardless of action/name."""

    def _is_any(field: Any) -> bool:
        if not field:
            return False
        for item in field:
            name = item.get("name") if isinstance(item, dict) else item
            if name != "Any":
                return False
        return True

    return _is_any(rule_raw.get("source")) and _is_any(rule_raw.get("destination")) and _is_any(rule_raw.get("service"))


async def _bottom_with_cleanup_check(
    reader: Any,
    scope_uid: str,
    layer_type: str,
    fallback: dict[str, Any],
    *,
    mgmt: str,
    domain: str,
) -> dict[str, Any]:
    last = await reader.get_last_rule(scope_uid, layer_type, mgmt=mgmt, domain=domain)
    if last is not None and _is_cleanup_rule(last.raw):
        return {"position": last.rule_number}  # one above the cleanup rule
    return fallback


async def resolve_position(
    reader: Any,
    position: Any,
    layer_scope_uid: str,
    layer_type: str,
    *,
    mgmt: str,
    domain: str,
) -> dict[str, Any]:
    """Resolve `position` (already schema-validated) into the exact API position payload fragment."""
    if isinstance(position, int):
        return {"position": position}

    if isinstance(position, str):
        if position == "bottom":
            return await _bottom_with_cleanup_check(
                reader,
                layer_scope_uid,
                layer_type,
                {"position": "bottom"},
                mgmt=mgmt,
                domain=domain,
            )
        return {"position": position}  # "top"

    # dict form: {top|bottom|above|below: "name-or-section"}
    ((key, value),) = position.items()
    if key in ("above", "below"):
        return {"position": {key: value}}

    # top/bottom are section-relative here (rule-relative above/below already handled above)
    from arodonata.core.exceptions import ConfigurationError

    section = await reader.get_section(value, layer_scope_uid, layer_type, mgmt=mgmt, domain=domain)
    if section is None:
        raise ConfigurationError(
            f"Section {value!r} not found in layer scope {layer_scope_uid!r} -- "
            "fix the section name/uid or create it first."
        )
    if key == "top":
        return {"position": {"top": section.uid}}
    # bottom: cleanup-aware, scoped to the section itself
    return await _bottom_with_cleanup_check(
        reader,
        section.uid,
        layer_type,
        {"position": {"bottom": section.uid}},
        mgmt=mgmt,
        domain=domain,
    )


def resolve_nat_position(position: Any) -> dict[str, Any]:
    """NAT counterpart to `resolve_position`: package-scoped, no layer/section concept.

    Cleanup-aware `bottom` is deliberately NOT extended here -- spec section 9 defines it in
    terms of a layer's implicit cleanup action, a concept that doesn't exist for NAT rulebases
    (no implicit "cleanup" NAT rule). NAT rulebases do have their own `nat-section` objects, but
    no StateReader method resolves a NAT section to a scope the way `get_section` does for
    access/https/threat-prevention layers -- building that is out of scope for this fix, so a
    section-relative NAT position is a hard, non-silent error rather than a silent guess (same
    philosophy as `resolve_position`'s missing-section error above).
    """
    if isinstance(position, (int, str)):
        return {"position": position}  # int rule-number, "top", or plain "bottom"

    ((key, value),) = position.items()
    if key in ("above", "below"):
        return {"position": {key: value}}

    from arodonata.core.exceptions import ConfigurationError

    raise ConfigurationError(
        f"Section-relative NAT position {position!r} is not supported -- "
        "NAT section resolution isn't implemented; use top/bottom/an integer/above/below instead."
    )
