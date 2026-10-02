"""Trim a recorded show-changes response into a change-report unit-test fixture.

Usage (from the repo root):

    uv run python -m tests.unit.reports.trim_changes <recording.json> <fixture.json> [--keep-types t1,t2] [--internal-sample N]
    uv run python -m tests.unit.reports.trim_changes --field-names <fixture.json> <recording.json>...

Output is api_query's merged shape ``{"changes": [...], "total": N}`` (plan decision 6), from a task-wrapped or an
already flat recording. Keeps the session's session-uid, session-name, session-description, published,
publish-time and domain-info and sets user-name to "admin"; drops meta-info, available-actions, icon and ip-address
everywhere; reduces nested reference objects to uid, name, type plus their key fields; rewrites IPv4 literals into
192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (one stable address per distinct literal). ``--keep-types`` keeps
only those types, plus the first N CamelCase (internal) entries per operation with ``--internal-sample N``.
``--field-names`` writes ``{rule type: sorted top-level keys}`` from rulebase and show-changes recordings (key names
only; plan decision 1).
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Collection, Iterator
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"
SESSION_KEYS = ("session-uid", "session-name", "session-description", "published", "publish-time", "domain-info")
DROP_KEYS = frozenset({"meta-info", "available-actions", "icon", "ip-address"})
REF_KEYS = ("uid", "name", "type")
KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("ipv4-address", "ipv6-address"),
    "network": ("subnet4", "mask-length4", "subnet6", "mask-length6"),
    "address-range": ("ipv4-address-first", "ipv4-address-last", "ipv6-address-first", "ipv6-address-last"),
    "service-tcp": ("port",),
    "service-udp": ("port",),
    "service-icmp": ("icmp-type",),
}
RULE_TYPES = frozenset({"access-rule", "nat-rule", "threat-rule", "https-rule"})
OPERATIONS = ("added-objects", "modified-objects", "deleted-objects")
IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")


def load_changes(name: str) -> list[dict[str, Any]]:
    """The session entries of a trimmed fixture (tests)."""
    return list(json.loads((FIXTURES / name).read_text())["changes"])


def _flat_changes(recording: Any) -> list[dict[str, Any]]:
    data = recording.get("data", recording) if isinstance(recording, dict) else {}
    if isinstance(data, dict) and isinstance(data.get("changes"), list):
        return list(data["changes"])
    return [
        c for t in (data.get("tasks") or []) for td in (t.get("task-details") or []) for c in (td.get("changes") or [])
    ]


def _trim_nested(value: Any) -> Any:
    if isinstance(value, dict) and "uid" in value:
        keep = REF_KEYS + KEY_FIELDS.get(str(value.get("type")), ())
        return {k: value[k] for k in keep if k in value}
    if isinstance(value, dict):
        return {k: _trim_nested(v) for k, v in value.items() if k not in DROP_KEYS}
    if isinstance(value, list):
        return [_trim_nested(v) for v in value]
    return value


def trim_body(body: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in body.items():
        if key in DROP_KEYS:
            continue
        if key == "domain" and isinstance(value, dict):
            out[key] = {k: value[k] for k in ("uid", "name", "domain-type") if k in value}
        else:
            out[key] = _trim_nested(value)
    return out


def trim_entry(
    entry: dict[str, Any], keep_types: Collection[str] | None = None, internal_sample: int = 0
) -> dict[str, Any]:
    meta = entry.get("session") or {}
    session = {k: meta[k] for k in SESSION_KEYS if k in meta}
    session["user-name"] = "admin"
    operations: dict[str, list[dict[str, Any]]] = {}
    for kind in OPERATIONS:
        kept: list[dict[str, Any]] = []
        internal = 0
        for item in (entry.get("operations") or {}).get(kind) or []:
            body = item.get("new-object", item) if kind == "modified-objects" else item
            obj_type = str(body.get("type") or "")
            if keep_types is not None and obj_type not in keep_types:
                if not (obj_type[:1].isupper() and internal < internal_sample):
                    continue
                internal += 1
            if kind == "modified-objects":
                kept.append({k: trim_body(v) for k, v in item.items() if k in ("old-object", "new-object")})
            else:
                kept.append(trim_body(item))
        operations[kind] = kept
    return {"session": session, "operations": operations}


def rewrite_ipv4(text: str) -> str:
    mapping: dict[str, str] = {}

    def sub(match: re.Match[str]) -> str:
        literal = match.group(0)
        if literal.startswith(tuple(f"{net}." for net in DOC_NETS)):
            return literal
        if literal not in mapping:
            i = len(mapping)
            mapping[literal] = f"{DOC_NETS[(i // 254) % 3]}.{i % 254 + 1}"
        return mapping[literal]

    return IPV4.sub(sub, text)


def trim_recording(
    recording: Any, keep_types: Collection[str] | None = None, internal_sample: int = 0
) -> dict[str, Any]:
    changes = [trim_entry(e, keep_types, internal_sample) for e in _flat_changes(recording)]
    return json.loads(rewrite_ipv4(json.dumps({"changes": changes, "total": len(changes)})))


def _rulebase_rules(items: list[Any]) -> Iterator[dict[str, Any]]:
    for item in items:
        if isinstance(item, dict) and str(item.get("type", "")).endswith("section"):
            yield from _rulebase_rules(item.get("rulebase") or [])
        elif isinstance(item, dict):
            yield item


def _bodies(recording: Any) -> Iterator[dict[str, Any]]:
    if isinstance(recording, dict) and isinstance(recording.get("rulebase"), list):
        yield from _rulebase_rules(recording["rulebase"])
        return
    for entry in _flat_changes(recording):
        for kind in OPERATIONS:
            for item in (entry.get("operations") or {}).get(kind) or []:
                for body in (item.get("old-object"), item.get("new-object")) if "new-object" in item else (item,):
                    if isinstance(body, dict):
                        yield body


def field_names(paths: Collection[Path | str]) -> dict[str, list[str]]:
    seen: dict[str, set[str]] = {}
    for path in paths:
        for body in _bodies(json.loads(Path(path).read_text())):
            if body.get("type") in RULE_TYPES:
                seen.setdefault(str(body["type"]), set()).update(k for k in body if k not in DROP_KEYS)
    return {t: sorted(keys) for t, keys in sorted(seen.items())}


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--field-names":
        out, *sources = argv[1:]
        Path(out).write_text(json.dumps(field_names(sources), indent=1) + "\n")
        return 0
    src, out, *opts = argv
    keep = None
    sample = 0
    for i, opt in enumerate(opts):
        if opt == "--keep-types":
            keep = set(opts[i + 1].split(","))
        if opt == "--internal-sample":
            sample = int(opts[i + 1])
    trimmed = trim_recording(json.loads(Path(src).read_text()), keep, sample)
    Path(out).write_text(json.dumps(trimmed, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
