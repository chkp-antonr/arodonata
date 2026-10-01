"""Test doubles that serve recorded or synthetic rulebases the way the pager assumes CP pages them.

``page_by_rule_offset`` is the pager's assumption (``offset``/``limit`` count rules; a section that spans a page
boundary repeats on both pages, carrying only its in-page children and in-page ``from``/``to``). Gate L (L2)
checks it against the lab. ``page_by_top_level_offset`` is a deliberately wrong server (offset counts top-level
entries), used to prove the pager refuses it.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from arodonata.api.schemas import ApiCallResult, ApiQueryResult

FIXTURES = Path(__file__).parent / "fixtures"
CP_DEFAULT_LIMIT = 50

# show-*-layers / show-packages -> the key their objects live under (cpapi pages only when told this key).
LISTING_KEYS = {
    "show-access-layers": "access-layers",
    "show-https-layers": "https-layers",
    "show-threat-layers": "threat-layers",
    "show-packages": "packages",
}


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


def flatten_rules(rulebase: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every non-section item, in order, sections flattened away."""
    out: list[dict[str, Any]] = []
    for item in rulebase:
        if str(item.get("type", "")).endswith("-section"):
            out.extend(flatten_rules(item.get("rulebase", [])))
        else:
            out.append(item)
    return out


def _sectioned(layer: dict[str, Any]) -> list[tuple[dict[str, Any] | None, dict[str, Any]]]:
    pairs: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    for item in layer.get("rulebase", []):
        if str(item.get("type", "")).endswith("-section"):
            meta = {k: v for k, v in item.items() if k != "rulebase"}
            pairs.extend((meta, rule) for rule in item.get("rulebase", []))
        else:
            pairs.append((None, item))
    return pairs


def _page(
    layer: dict[str, Any], pairs: list[tuple[dict[str, Any] | None, dict[str, Any]]], total: int
) -> dict[str, Any]:
    rulebase: list[dict[str, Any]] = []
    for meta, rule in pairs:
        if meta is not None and rulebase and rulebase[-1].get("uid") == meta.get("uid"):
            rulebase[-1]["rulebase"].append(copy.deepcopy(rule))
            rulebase[-1]["to"] = rule["rule-number"]
        elif meta is not None:
            rulebase.append(
                {**meta, "from": rule["rule-number"], "to": rule["rule-number"], "rulebase": [copy.deepcopy(rule)]}
            )
        else:
            rulebase.append(copy.deepcopy(rule))
    numbers = [rule["rule-number"] for _, rule in pairs]
    return {
        **{k: layer[k] for k in ("uid", "name") if k in layer},
        "rulebase": rulebase,
        "objects-dictionary": copy.deepcopy(layer.get("objects-dictionary", [])),
        "from": numbers[0] if numbers else 0,
        "to": numbers[-1] if numbers else 0,
        "total": total,
    }


def page_by_rule_offset(layer: dict[str, Any], limit: int | None, offset: int) -> dict[str, Any]:
    pairs = _sectioned(layer)
    size = CP_DEFAULT_LIMIT if limit is None else limit
    return _page(layer, pairs[offset : offset + size], len(pairs))


def page_by_top_level_offset(layer: dict[str, Any], limit: int | None, offset: int) -> dict[str, Any]:
    size = CP_DEFAULT_LIMIT if limit is None else limit
    top = layer.get("rulebase", [])[offset : offset + size]
    return _page(layer, _sectioned({"rulebase": top}), len(_sectioned(layer)))


def make_layer(
    uid: str, name: str, n_rules: int, *, rules_per_section: int = 0, rule_type: str = "access-rule"
) -> dict[str, Any]:
    """A synthetic layer of ``n_rules`` rules, optionally grouped into sections of ``rules_per_section``."""
    rules = [
        {
            "uid": f"{uid}-r{n}",
            "name": f"{name} rule {n}",
            "type": rule_type,
            "rule-number": n,
            "enabled": True,
            "source": [],
            "destination": [],
            "service": [],
            "action": "",
            "track": {"type": ""},
        }
        for n in range(1, n_rules + 1)
    ]
    rulebase: list[dict[str, Any]]
    if not rules_per_section:
        rulebase = rules
    else:
        section_type = rule_type.replace("-rule", "-section")
        chunks = [rules[j : j + rules_per_section] for j in range(0, len(rules), rules_per_section)]
        rulebase = [
            {
                "uid": f"{uid}-s{i}",
                "name": f"{name} section {i}",
                "type": section_type,
                "from": chunk[0]["rule-number"],
                "to": chunk[-1]["rule-number"],
                "rulebase": chunk,
            }
            for i, chunk in enumerate(chunks)
        ]
    return {
        "uid": uid,
        "name": name,
        "rulebase": rulebase,
        "objects-dictionary": [],
        "from": 1 if n_rules else 0,
        "to": n_rules,
        "total": n_rules,
    }


class FakeRulebaseClient:
    """``api_call``/``api_query`` double for RulebaseRefreshService and the pager.

    ``layers`` maps ``(command, key)`` to a full layer, where key is the payload's ``uid``, ``name`` or ``package``.
    ``api_call`` pages it with ``page`` (default ``page_by_rule_offset``) and serves at most 50 rules when the
    payload has no ``limit``, like CP. ``listings`` maps a listing command to its objects; ``api_query`` behaves
    like cpapi ``gen_api_query``: with a ``container_key`` that is not the response's key it stops after page 1
    (50 objects).
    """

    def __init__(self, page: Any = page_by_rule_offset) -> None:
        self.page = page
        self.layers: dict[tuple[str, str], dict[str, Any]] = {}
        self.listings: dict[str, list[dict[str, Any]]] = {}
        self.call_failures: dict[tuple[str, str], ApiCallResult] = {}
        self.query_failures: dict[str, ApiQueryResult] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.query_calls: list[dict[str, Any]] = []

    def add_layer(self, command: str, layer: dict[str, Any], key: str | None = None) -> None:
        self.layers[(command, key or layer["name"])] = layer

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: Any = None,
        payload: dict[str, Any] | None = None,
        **_: Any,
    ) -> ApiCallResult:
        body = dict(payload or {})
        self.calls.append((command, body))
        key = str(body.get("uid") or body.get("name") or body.get("package") or "")
        if (command, key) in self.call_failures:
            return self.call_failures[(command, key)]
        layer = self.layers.get((command, key))
        if layer is None:
            return ApiCallResult(success=False, code="generic_err_object_not_found", message=f"{key} not found")
        return ApiCallResult(success=True, data=self.page(layer, body.get("limit"), int(body.get("offset", 0))))

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        container_key: str = "objects",
        **_: Any,
    ) -> ApiQueryResult:
        self.query_calls.append(
            {
                "mgmt_name": mgmt_name,
                "command": command,
                "domain": domain,
                "details_level": details_level,
                "container_key": container_key,
            }
        )
        if command in self.query_failures:
            return self.query_failures[command]
        objects = self.listings.get(command, [])
        if container_key != LISTING_KEYS.get(command):
            objects = objects[:CP_DEFAULT_LIMIT]  # cpapi stops after page 1 when the key is not in the response
        return ApiQueryResult(success=True, data=list(objects), objects=list(objects), total=len(objects))
