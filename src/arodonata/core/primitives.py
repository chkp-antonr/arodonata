"""Shared pure core primitives for UUID matching, composite IDs, string sequences, and IPv4 bounds."""

from __future__ import annotations

import html
import ipaddress
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from arodonata.core.errors import ValidationError

if TYPE_CHECKING:
    from arodonata.core.models.objects import CPObject

UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

MAX_IPV4_INT: Final[int] = 4294967295

READONLY_EXACT_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "where-used",
        "keepalive",
    }
)

_COMMAND_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def is_readonly_command(command: str) -> bool:
    """Return `True` if `command` is a read-only Check Point Web API command (`C8`)."""
    clean = command.strip().lower().lstrip("/")
    return clean.startswith("show-") or clean in READONLY_EXACT_COMMANDS


def validate_command_name(command: str) -> str:
    """Validate and normalize a Check Point Web API command name against `^[a-z0-9]+(-[a-z0-9]+)*$`."""
    if not isinstance(command, str):
        raise ValidationError(f"Invalid Check Point API command type: {type(command).__name__}")
    if command != command.strip():
        raise ValidationError(
            f"Invalid Check Point Web API command {command!r}: leading or trailing whitespace is forbidden."
        )
    raw = command
    if raw.startswith("/web_api/"):
        raw = raw.removeprefix("/web_api/")
    elif raw.startswith("web_api/"):
        raw = raw.removeprefix("web_api/")
    if not raw or not _COMMAND_NAME_RE.fullmatch(raw):
        raise ValidationError(
            f"Invalid Check Point Web API command {command!r}: must match '^[a-z0-9]+(-[a-z0-9]+)*$'."
        )
    return raw


def format_host_attr_for_url(host: str) -> str:
    """Wrap raw IPv6 literal in brackets `[...]` for URL/key construction."""
    cleaned = host.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        return cleaned
    try:
        addr = ipaddress.ip_address(cleaned)
        if addr.version == 6:
            return f"[{addr.compressed}]"
    except ValueError:
        if ":" in cleaned:
            return f"[{cleaned}]"
    return cleaned


def is_uuid(value: Any) -> bool:
    """Return `True` if `value` is a canonical 8-4-4-4-12 hexadecimal UUID string."""
    if not isinstance(value, str):
        return False
    return bool(UUID_RE.fullmatch(value.strip()))


def format_composite_id(*parts: str | int) -> str:
    """Join key segments into a colon-delimited composite cache identifier."""
    return ":".join(str(part) for part in parts)


def parse_composite_id(
    composite_id: str,
    *,
    expected_parts: int = 3,
) -> tuple[str, ...] | None:
    """Split a colon-delimited composite identifier into `expected_parts` non-empty segments."""
    if not isinstance(composite_id, str) or expected_parts < 1:
        return None
    raw = composite_id.strip()
    parts = [raw] if expected_parts == 1 else [segment.strip() for segment in raw.split(":", expected_parts - 1)]
    if len(parts) != expected_parts or any(not segment for segment in parts):
        return None
    return tuple(parts)


def normalize_str_sequence(
    value: Sequence[str] | str | None,
    *,
    split_csv: bool = True,
    lowercase: bool = False,
    deduplicate: bool = False,
) -> list[str]:
    """Normalize a string, CSV string, or sequence of strings into a clean list of non-empty tokens."""
    if value is None:
        return []
    raw_items: Sequence[Any]
    if isinstance(value, str):
        raw_items = value.split(",") if split_csv else [value]
    else:
        raw_items = [str(item) for item in value]

    cleaned: list[str] = []
    for item in raw_items:
        token = str(item).strip()
        if not token:
            continue
        if lowercase:
            token = token.lower()
        cleaned.append(token)
    if deduplicate:
        return list(dict.fromkeys(cleaned))
    return cleaned


def mask_to_prefix_len(
    mask_val: str | int | float | None,
    *,
    allow_hostmask: bool = False,
    allow_prefix_int: bool = True,
) -> int | None:
    """Convert a dotted-quad netmask or prefix length (`0..32`) into an integer prefix length.

    By default only contiguous IPv4 netmasks (e.g. `'255.255.255.0'`) and prefix lengths `0..32`
    are accepted; wildcard/hostmasks such as `'0.0.0.255'` return `None` unless `allow_hostmask=True`.
    Integral floats (e.g. `24.0`) are accepted when `allow_prefix_int=True`.
    """
    if mask_val is None or mask_val == "" or isinstance(mask_val, bool):
        return None
    if isinstance(mask_val, int):
        return mask_val if allow_prefix_int and 0 <= mask_val <= 32 else None
    if isinstance(mask_val, float):
        if not allow_prefix_int or not mask_val.is_integer():
            return None
        plen = int(mask_val)
        return plen if 0 <= plen <= 32 else None
    clean = str(mask_val).strip()
    if not clean:
        return None
    if clean.isdigit():
        if not allow_prefix_int:
            return None
        plen = int(clean)
        return plen if 0 <= plen <= 32 else None
    try:
        mask_int = int(ipaddress.IPv4Address(clean))
    except ValueError:
        return None
    inv = MAX_IPV4_INT ^ mask_int
    if (inv & (inv + 1)) == 0:
        return 32 - inv.bit_length()
    if allow_hostmask and (mask_int & (mask_int + 1)) == 0:
        return 32 - mask_int.bit_length()
    return None


def prefix_len_to_mask(prefix_len: int | str | None) -> str | None:
    """Convert an integer prefix length (`0..32`) into a dotted-quad IPv4 subnet mask string."""
    if prefix_len is None or isinstance(prefix_len, bool):
        return None
    try:
        plen = int(prefix_len)
    except (TypeError, ValueError):
        return None
    if plen < 0 or plen > 32:
        return None
    mask_int = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
    return ".".join(str((mask_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def effective_range_prefix_len(ip_first_int: int, ip_last_int: int) -> int:
    """Compute an effective specificity (`0..32`) from an IPv4 integer interval span."""
    span = max(0, ip_last_int - ip_first_int)
    if span == 0:
        return 32
    bits = span.bit_length()
    return max(0, 32 - bits)


def object_ipv4_bounds(obj: CPObject) -> tuple[int, int] | None:
    """Return `(min_ip_int, max_ip_int)` for a `host`, `network`, or `address-range` `CPObject`."""
    if obj.ipv4_address:
        try:
            val = int(ipaddress.IPv4Address(obj.ipv4_address.strip()))
            return val, val
        except ValueError:
            return None

    if obj.subnet4:
        mask_part: str | int | None = obj.mask_length4 if obj.mask_length4 is not None else obj.subnet_mask
        if mask_part is not None:
            plen = mask_to_prefix_len(mask_part)
            if plen is None:
                return None
            cidr_str = f"{obj.subnet4.strip()}/{plen}"
        else:
            cidr_str = obj.subnet4.strip()
        try:
            net = ipaddress.IPv4Network(cidr_str, strict=False)
            return int(net.network_address), int(net.broadcast_address)
        except ValueError:
            return None

    if obj.ipv4_address_first and obj.ipv4_address_last:
        try:
            first_int = int(ipaddress.IPv4Address(obj.ipv4_address_first.strip()))
            last_int = int(ipaddress.IPv4Address(obj.ipv4_address_last.strip()))
            return min(first_int, last_int), max(first_int, last_int)
        except ValueError:
            return None

    return None


def parse_cidr_or_range_bounds(cidr_or_range: str) -> tuple[int, int, int] | None:
    """Parse a CIDR (`10.0.0.0/24`), single IPv4 (`10.0.0.1`), or range (`10.0.0.1-10.0.0.10`) into `(lo, hi, prefix_len)`."""
    clean = cidr_or_range.strip()
    if not clean or clean == "*":
        return None
    if clean.lower() == "default" or clean == "0.0.0.0/0":
        return 0, MAX_IPV4_INT, 0
    if "-" in clean and "/" not in clean:
        parts = clean.split("-", 1)
        try:
            ip1 = ipaddress.IPv4Address(parts[0].strip())
            ip2 = ipaddress.IPv4Address(parts[1].strip())
            lo = min(int(ip1), int(ip2))
            hi = max(int(ip1), int(ip2))
            return lo, hi, effective_range_prefix_len(lo, hi)
        except ValueError:
            return None
    try:
        net = ipaddress.IPv4Network(clean, strict=False) if "/" in clean else ipaddress.IPv4Network(f"{clean}/32")
        return int(net.network_address), int(net.broadcast_address), net.prefixlen
    except ValueError:
        return None


def escape_markdown_cell(val: Any) -> str:
    """Escape HTML tags, newlines, backslashes, pipes, and Markdown link/code delimiters in table cells."""
    if val is None:
        return ""
    raw = ", ".join(str(x) for x in val) if isinstance(val, list) else str(val)
    escaped = html.escape(raw, quote=False)
    return (
        escaped.replace("\\", "\\\\")
        .replace("\r\n", " ")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("|", "\\|")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("`", "\\`")
    )


def escape_markdown_code(val: Any) -> str:
    """Neutralize newlines, backticks, and GFM table pipes inside inline Markdown code spans without mangling paths."""
    if val is None:
        return ""
    cleaned = str(val).replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("`", "'")
    return re.sub(r"(\\*)\|", lambda m: (m.group(1) * 2) + r"\|", cleaned)


__all__ = [
    "MAX_IPV4_INT",
    "READONLY_EXACT_COMMANDS",
    "UUID_RE",
    "effective_range_prefix_len",
    "escape_markdown_cell",
    "escape_markdown_code",
    "format_composite_id",
    "format_host_attr_for_url",
    "is_readonly_command",
    "is_uuid",
    "mask_to_prefix_len",
    "normalize_str_sequence",
    "object_ipv4_bounds",
    "parse_cidr_or_range_bounds",
    "parse_composite_id",
    "prefix_len_to_mask",
    "validate_command_name",
]
