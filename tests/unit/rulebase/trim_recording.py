"""Trim a recorded show-*-rulebase response into a unit-test fixture.

Usage (from the repo root):

    uv run python -m tests.unit.rulebase.trim_recording [--packages|--session|--errors] <recording.json> <fixture.json>

Keeps only what the cache and numbering read (spec "Fixture trimming"): top-level uid, name, from, to, total,
rulebase and objects-dictionary; per item uid, name, type, rule-number, from/to, domain, inline-layer, action,
track type, source/destination/service (+ negate flags), enabled, comments, NAT fields (auto-generated, method,
original-*/translated-*) and the nested rulebase; dictionary
entries reduced to uid, name, type, domain. Drops meta-info (creator names), available-actions, icon, color and
addresses. `--packages` trims show-packages objects to blade flags and layer references, `--session` trims
show-session to the dirty-session guard fields, `--errors` trims recorded error probes to command, payload, code
and message.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

TOP_KEYS = ("uid", "name", "from", "to", "total")
ITEM_KEYS = (
    "uid",
    "name",
    "type",
    "rule-number",
    "from",
    "to",
    "domain",
    "inline-layer",
    "action",
    "track",
    "source",
    "source-negate",
    "destination",
    "destination-negate",
    "service",
    "service-negate",
    "enabled",
    "comments",
    "auto-generated",
    "method",
    "original-source",
    "original-destination",
    "original-service",
    "translated-source",
    "translated-destination",
    "translated-service",
)
DICT_KEYS = ("uid", "name", "type", "domain")
DOMAIN_KEYS = ("uid", "name", "domain-type")
PACKAGE_KEYS = (
    "uid",
    "name",
    "type",
    "domain",
    "access",
    "threat-prevention",
    "nat-policy",
    "https-inspection-policy",
    "qos",
    "desktop-security",
)
PACKAGE_LAYER_KEYS = ("uid", "name", "type", "domain")
SESSION_KEYS = ("uid", "type", "state", "changes", "locks", "in-work", "expired-session")
ERROR_KEYS = ("command", "payload", "code", "message")


def _domain(value: Any) -> Any:
    return {k: value[k] for k in DOMAIN_KEYS if k in value} if isinstance(value, dict) else value


def trim_item(item: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {k: item[k] for k in ITEM_KEYS if k in item}
    if "domain" in out:
        out["domain"] = _domain(out["domain"])
    if isinstance(out.get("track"), dict):
        out["track"] = {"type": out["track"].get("type")}
    if "rulebase" in item:
        out["rulebase"] = [trim_item(child) for child in item["rulebase"]]
    return out


def trim_layer(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {k: data[k] for k in TOP_KEYS if k in data}
    out["rulebase"] = [trim_item(item) for item in data.get("rulebase", [])]
    out["objects-dictionary"] = [
        {k: (_domain(o[k]) if k == "domain" else o[k]) for k in DICT_KEYS if k in o}
        for o in data.get("objects-dictionary", [])
    ]
    return out


def _layer_ref(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    out = {k: value[k] for k in PACKAGE_LAYER_KEYS if k in value}
    if "domain" in out:
        out["domain"] = _domain(out["domain"])
    return out


def trim_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """show-packages objects: blade flags and the layer references `parse_packages` reads; no targets, no meta-info."""
    out = []
    for pkg in packages:
        item: dict[str, Any] = {k: pkg[k] for k in PACKAGE_KEYS if k in pkg}
        if "domain" in item:
            item["domain"] = _domain(item["domain"])
        for key in ("access-layers", "threat-layers"):
            if key in pkg:
                item[key] = [_layer_ref(layer) for layer in pkg[key] or []]
        if "https-inspection-layers" in pkg:
            item["https-inspection-layers"] = {
                k: _layer_ref(v) for k, v in (pkg["https-inspection-layers"] or {}).items()
            }
        out.append(item)
    return out


def trim_session(data: dict[str, Any]) -> dict[str, Any]:
    """show-session: the dirty-session guard's fields only (no user, address, e-mail or phone)."""
    return {k: data[k] for k in SESSION_KEYS if k in data}


def trim_errors(errors: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Recorded error probes: command, payload, code and message per label."""
    return {label: {k: e[k] for k in ERROR_KEYS if k in e} for label, e in errors.items()}


TRIMMERS = {"--packages": trim_packages, "--session": trim_session, "--errors": trim_errors}


def main(argv: list[str]) -> int:
    trimmer: Any = trim_layer
    if argv and argv[0] in TRIMMERS:
        trimmer, argv = TRIMMERS[argv[0]], argv[1:]
    source, target = Path(argv[0]), Path(argv[1])
    target.write_text(json.dumps(trimmer(json.loads(source.read_text())), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
