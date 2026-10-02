"""Column specs per rulebase (SmartConsole-like), report order, object key fields and compare allowlists (spec 4).

Field names are pinned by test_column_fields_exist_in_recordings (fixtures/rule_field_names.json, plan decision 1).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from .model import Cell, RulebaseKind, RuleChange

ColumnKind = Literal["list", "ref", "scalar", "track", "enabled", "number"]


@dataclass(frozen=True)
class Column:
    key: str
    title: str
    field: str | None  # API field; None for structural columns and Threat "Protection/Site"
    kind: ColumnKind
    negate_field: str | None = None
    default_names: tuple[str, ...] = ("Any",)
    structural: bool = False  # enabled marker and number: never hidden


RULEBASE_ORDER: tuple[RulebaseKind, ...] = ("access", "nat", "threat", "https")  # report order (D9), not RULEBASE_TYPES
RULEBASE_TITLES: dict[RulebaseKind, str] = {
    "access": "Access Control",
    "nat": "NAT",
    "threat": "Threat Prevention",
    "https": "HTTPS Inspection",
}


def _list(key: str, title: str, *, negate: bool = True, default: tuple[str, ...] = ("Any",)) -> Column:
    return Column(key, title, key, "list", f"{key}-negate" if negate else None, default)


_ENABLED = Column("enabled", "", None, "enabled", structural=True)
_NUMBER = Column("number", "No.", None, "number", structural=True)
_NAME = Column("name", "Name", "name", "scalar")
_ACTION = Column("action", "Action", "action", "ref", default_names=())
_TRACK = Column("track", "Track", "track", "track", default_names=())
_INSTALL_ON = _list("install-on", "Install On", negate=False, default=("Policy Targets",))
_COMMENTS = Column("comments", "Comments", "comments", "scalar")

COLUMNS: dict[RulebaseKind, tuple[Column, ...]] = {
    "access": (
        _ENABLED,
        _NUMBER,
        _NAME,
        _list("source", "Source"),
        _list("destination", "Destination"),
        _list("vpn", "VPN", negate=False),
        _list("service", "Services & Applications"),
        _list("content", "Content"),
        _ACTION,
        _TRACK,
        _INSTALL_ON,
        _list("time", "Time", negate=False),
        _COMMENTS,
    ),
    "nat": (
        _ENABLED,
        _NUMBER,
        _list("original-source", "Original Source", negate=False),
        _list("original-destination", "Original Destination", negate=False),
        _list("original-service", "Original Services", negate=False),
        _list("translated-source", "Translated Source", negate=False, default=("Original",)),
        _list("translated-destination", "Translated Destination", negate=False, default=("Original",)),
        _list("translated-service", "Translated Services", negate=False, default=("Original",)),
        _INSTALL_ON,
        _COMMENTS,
    ),
    "threat": (
        _ENABLED,
        _NUMBER,
        _NAME,
        _list("protected-scope", "Protected Scope"),
        _list("source", "Source"),
        _list("destination", "Destination"),
        Column("protection", "Protection/Site", None, "scalar"),
        _list("service", "Services"),
        _ACTION,
        _TRACK,
        _INSTALL_ON,
        _COMMENTS,
    ),
    "https": (
        _ENABLED,
        _NUMBER,
        _NAME,
        _list("source", "Source"),
        _list("destination", "Destination"),
        _list("service", "Services"),
        _list("site-category", "Category/Custom App"),
        _ACTION,
        _TRACK,
        _list("blade", "Blade", negate=False),
        Column("certificate", "Certificate", "certificate", "ref", default_names=()),
        _INSTALL_ON,
        _COMMENTS,
    ),
}

OBJECT_KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("ipv4-address", "ipv6-address"),
    "network": ("subnet4", "mask-length4", "subnet6", "mask-length6"),
    "address-range": ("ipv4-address-first", "ipv4-address-last", "ipv6-address-first", "ipv6-address-last"),
    "service-tcp": ("port",),
    "service-udp": ("port",),
    "service-icmp": ("icmp-type",),
    "group": (),
    "service-group": (),
    "application-site-group": (),
    "time": (),
    "dns-domain": (),
    "application-site": (),
}
OBJECT_COMPARE_FIELDS: tuple[str, ...] = ("name", "comments", "tags", "color")
IGNORED_FIELDS = frozenset({"uid", "meta-info", "icon", "available-actions", "read-only", "domain"})
_DEFAULT_CELL = Cell(default=True)


def is_internal_type(obj_type: str) -> bool:
    """CamelCase CP bookkeeping types (AccessPolicy, NatRulebase, ...); real API types are kebab-case."""
    return obj_type[:1].isupper()


def data_columns(kind: RulebaseKind) -> tuple[Column, ...]:
    return tuple(c for c in COLUMNS[kind] if not c.structural)


def key_value(obj_type: str, body: dict[str, Any]) -> str:
    """The value shown for an added or deleted object (address, subnet, range, port, ICMP type)."""

    def get(key: str) -> str:
        value = body.get(key)
        return "" if value is None else str(value)

    if obj_type == "host":
        return get("ipv4-address") or get("ipv6-address")
    if obj_type == "network":
        if get("subnet4"):
            return f"{get('subnet4')}/{get('mask-length4')}"
        return f"{get('subnet6')}/{get('mask-length6')}" if get("subnet6") else ""
    if obj_type == "address-range":
        first, last = get("ipv4-address-first"), get("ipv4-address-last")
        if not first:
            first, last = get("ipv6-address-first"), get("ipv6-address-last")
        return f"{first} - {last}" if first else ""
    if obj_type in ("service-tcp", "service-udp"):
        return get("port")
    if obj_type == "service-icmp":
        return get("icmp-type")
    return ""


def visible_columns(kind: RulebaseKind, rules: Iterable[RuleChange]) -> list[str]:
    """Column keys of one table: structural columns always; a data column when any row's cell is not default."""
    rows = list(rules)
    return [
        c.key for c in COLUMNS[kind] if c.structural or any(not r.cells.get(c.key, _DEFAULT_CELL).default for r in rows)
    ]
