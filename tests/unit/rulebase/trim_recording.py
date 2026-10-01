"""Trim a recorded show-*-rulebase response into a unit-test fixture.

Usage (from the repo root):

    uv run python -m tests.unit.rulebase.trim_recording <recording.json> <fixture.json>

Keeps only what the cache and numbering read (spec "Fixture trimming"): top-level uid, name, from, to, total,
rulebase and objects-dictionary; per item uid, name, type, rule-number, from/to, domain, inline-layer, action,
track type, source/destination/service (+ negate flags), enabled, comments and the nested rulebase; dictionary
entries reduced to uid, name, type, domain. Drops meta-info (creator names), available-actions, icon, color and
addresses.
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
)
DICT_KEYS = ("uid", "name", "type", "domain")
DOMAIN_KEYS = ("uid", "name", "domain-type")


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


def main(argv: list[str]) -> int:
    source, target = Path(argv[0]), Path(argv[1])
    target.write_text(json.dumps(trim_layer(json.loads(source.read_text())), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
