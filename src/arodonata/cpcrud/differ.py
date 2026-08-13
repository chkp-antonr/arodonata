"""Field-level diff between desired (template) and existing (API) object state."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Any

from .models import FieldDiff, ObjectState
from .nat import transform_nat_settings

# desired field name -> tuple of possible existing (API) field aliases
_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "ip-address": ("ipv4-address", "ipv6-address", "ip-address"),
    "subnet": ("subnet4", "subnet"),
    "mask-length": ("mask-length4", "mask-length", "subnet-mask"),
    "ip-address-first": ("ipv4-address-first", "ip-address-first"),
    "ip-address-last": ("ipv4-address-last", "ip-address-last"),
}

_IGNORED_DESIRED = {"name", "type", "new-name", "ignore-warnings", "ignore-errors"}


def _mask_to_dotted(mask_length: int) -> str:
    return str(IPv4Address((0xFFFFFFFF << (32 - mask_length)) & 0xFFFFFFFF))


def _dotted_to_length(dotted: str) -> int | None:
    try:
        bits = bin(int(IPv4Address(dotted))).count("1")
        return bits
    except Exception:
        return None


def _existing_value(existing_raw: dict[str, Any], desired_field: str) -> Any:
    for alias in _FIELD_ALIASES.get(desired_field, (desired_field,)):
        if alias in existing_raw:
            return existing_raw[alias]
    return None


def _normalize_item(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("name") or item.get("uid") or item)
    return str(item)


def _normalize(value: Any) -> Any:
    if isinstance(value, list):
        return frozenset(_normalize_item(v) for v in value)
    return value


def _equal(desired_field: str, desired_val: Any, existing_val: Any) -> bool:
    if desired_field == "mask-length":
        if isinstance(existing_val, str) and isinstance(desired_val, int):
            length = _dotted_to_length(existing_val)
            return length == desired_val
        if isinstance(desired_val, str) and isinstance(existing_val, int):
            length = _dotted_to_length(desired_val)
            return length == existing_val
    if isinstance(desired_val, int) and isinstance(existing_val, str) and existing_val.lstrip("-").isdigit():
        return desired_val == int(existing_val)
    if isinstance(existing_val, int) and isinstance(desired_val, str) and desired_val.lstrip("-").isdigit():
        return existing_val == int(desired_val)
    return _normalize(desired_val) == _normalize(existing_val)


def diff_object(object_type: str, desired: dict[str, Any], existing: ObjectState) -> FieldDiff:
    """Compare desired (template) fields against existing (API) object. Returns FieldDiff."""
    changes: dict[str, dict[str, Any]] = {}
    existing_raw = existing.raw
    for field, desired_val in desired.items():
        if field in _IGNORED_DESIRED:
            continue
        if field == "nat-settings":
            desired_val = transform_nat_settings(object_type, desired_val)
        existing_val = _existing_value(existing_raw, field)
        # Skip fields the template didn't actually intend to set vs absent on existing only when
        # the desired value is the default; here any desired field that differs is a change.
        if not _equal(field, desired_val, existing_val):
            changes[field] = {"before": existing_val, "after": desired_val}
    return FieldDiff(changes=changes)
