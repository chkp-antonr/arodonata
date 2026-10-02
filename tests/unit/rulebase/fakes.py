"""Test doubles that serve recorded or synthetic rulebases the way CP pages them.

``page_by_rule_offset`` is CP's paging (``offset``/``limit`` count rules; a section that spans a page boundary
repeats on both pages, carrying only its in-page children and in-page ``from``/``to``; a full last page omits
trailing empty sections). Gate L (L2 and Run B) verified it against the lab and test_fakes.py compares it with the
recorded pages. ``page_by_top_level_offset`` is a deliberately wrong server (offset counts top-level
entries), used to prove the pager refuses it.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from arodonata.api.schemas import ApiCallResult, ApiQueryResult
from arodonata.cache.models import LastPublishedSession
from arodonata.rulebase.model import DomainRulebaseSnapshot
from arodonata.rulebase.parse import find_parent_rule, link_placeholder, parse_layer_response, parse_packages

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


def _entries(layer: dict[str, Any]) -> list[tuple[dict[str, Any] | None, dict[str, Any] | None]]:
    """(section meta | None, rule | None) in layer order; an empty section is (meta, None)."""
    out: list[tuple[dict[str, Any] | None, dict[str, Any] | None]] = []
    for item in layer.get("rulebase", []):
        if str(item.get("type", "")).endswith("-section"):
            meta = {k: v for k, v in item.items() if k != "rulebase"}
            children = item.get("rulebase", [])
            if not children:
                out.append((meta, None))
            out.extend((meta, rule) for rule in children)
        else:
            out.append((None, item))
    return out


def _page(
    layer: dict[str, Any], picked: list[tuple[dict[str, Any] | None, dict[str, Any] | None]], total: int
) -> dict[str, Any]:
    rulebase: list[dict[str, Any]] = []
    for meta, rule in picked:
        if rule is None:
            rulebase.append({**copy.deepcopy(meta or {}), "rulebase": []})
        elif meta is not None and rulebase and rulebase[-1].get("uid") == meta.get("uid") and rulebase[-1]["rulebase"]:
            rulebase[-1]["rulebase"].append(copy.deepcopy(rule))
            rulebase[-1]["to"] = rule["rule-number"]
        elif meta is not None:
            rulebase.append(
                {**meta, "from": rule["rule-number"], "to": rule["rule-number"], "rulebase": [copy.deepcopy(rule)]}
            )
        else:
            rulebase.append(copy.deepcopy(rule))
    numbers = [rule["rule-number"] for _, rule in picked if rule is not None]
    return {
        **{k: layer[k] for k in ("uid", "name") if k in layer},
        "rulebase": rulebase,
        "objects-dictionary": copy.deepcopy(layer.get("objects-dictionary", [])),
        "from": numbers[0] if numbers else 0,
        "to": numbers[-1] if numbers else 0,
        "total": total,
    }


def page_by_rule_offset(layer: dict[str, Any], limit: int | None, offset: int) -> dict[str, Any]:
    """CP's paging as recorded in Gate L: ``offset``/``limit`` count rules; a section spanning a page boundary
    repeats with its in-page children and in-page ``from``/``to``; an empty section is served on the page where it
    sits before or between that page's rules, and after the page's last rule only when the page has room for more
    rules (so a full last page omits trailing empty sections)."""
    entries = _entries(layer)
    size = CP_DEFAULT_LIMIT if limit is None else limit
    total = sum(1 for _, rule in entries if rule is not None)
    in_page = max(0, min(size, total - offset))
    picked: list[tuple[dict[str, Any] | None, dict[str, Any] | None]] = []
    before = 0
    for meta, rule in entries:
        if rule is not None:
            before += 1
            if offset < before <= offset + size:
                picked.append((meta, rule))
        elif total == 0 or (
            in_page and (offset <= before < offset + in_page or (before == offset + in_page and in_page < size))
        ):
            picked.append((meta, None))
    return _page(layer, picked, total)


def page_by_top_level_offset(layer: dict[str, Any], limit: int | None, offset: int) -> dict[str, Any]:
    size = CP_DEFAULT_LIMIT if limit is None else limit
    top = layer.get("rulebase", [])[offset : offset + size]
    total = sum(1 for _, rule in _entries(layer) if rule is not None)
    return _page(layer, _entries({"rulebase": top}), total)


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
        self.session: dict[str, Any] = {"uid": "sess", "changes": 0, "locks": 0}
        self.domains: list[str] = ["Domain4"]

    def add_layer(
        self, command: str, layer: dict[str, Any], key: str | None = None, *, package: str | None = None
    ) -> None:
        """Serve ``layer`` under ``key`` (NAT packages), else under both its name and its uid; with ``package``,
        under ``<uid>@<package>`` and ``<name>@<package>`` (a global layer read with ``package``)."""
        if package:
            self.layers[(command, f"{layer['uid']}@{package}")] = layer
            self.layers[(command, f"{layer['name']}@{package}")] = layer
            return
        if key:
            self.layers[(command, key)] = layer
            return
        self.layers[(command, layer["name"])] = layer
        if layer.get("uid"):
            self.layers[(command, layer["uid"])] = layer

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
        if command == "show-session":
            failure = self.call_failures.get((command, ""))
            return failure or ApiCallResult(success=True, data=dict(self.session))
        target = body.get("uid") or body.get("name")
        key = (
            f"{target}@{body['package']}"
            if target and body.get("package")
            else str(target or body.get("package") or "")
        )
        layer = self.layers.get((command, key))
        names = {key, *(str(layer[k]) for k in ("name", "uid") if layer and layer.get(k))}
        for name in names:
            if (command, name) in self.call_failures:
                return self.call_failures[(command, name)]
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

    def get_mgmt_names(self) -> list[str]:
        return ["m1"]

    async def get_domains(self, mgmt_names: list[str] | None = None, include_global: bool = False) -> list[Any]:
        return [SimpleNamespace(name=d) for d in self.domains]


class FakeHeadService:
    """``read_last_published_session`` double. Records the call into ``client.calls`` so order can be asserted."""

    def __init__(
        self,
        client: FakeRulebaseClient | None = None,
        uid: str = "sess-1",
        published: datetime = datetime(2026, 10, 1, 6, 53),
    ) -> None:
        self.client, self.uid, self.published = client, uid, published
        self.error: BaseException | None = None

    async def read_last_published_session(self, mgmt_name: str, domain_name: str) -> LastPublishedSession:
        if self.client is not None:
            self.client.calls.append(("show-last-published-session", {}))
        if self.error is not None:
            raise self.error
        return LastPublishedSession(
            id=f"{mgmt_name}:{domain_name}",
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            published_time=self.published,
            uid=self.uid,
        )


ACCESS = "show-access-rulebase"


def domain4_fake() -> FakeRulebaseClient:
    """Domain4 after the Global assignment, package FPCR_UAT_Active only, every read from Gate L recordings
    (the AppControl layer is synthetic: 2 rules)."""
    client = FakeRulebaseClient()
    pkg = next(p for p in load_fixture("packages_domain4_after_assign.json") if p["name"] == "FPCR_UAT_Active")
    client.listings["show-packages"] = [pkg]
    for name in (
        "global_layer_no_package.json",
        "domain_layer_fpcr_uat_active_network.json",
        "inline_layer_fpcr_uat_active_inline.json",
    ):
        client.add_layer(ACCESS, load_fixture(name))
    client.add_layer(ACCESS, load_fixture("global_layer_with_package.json"), package="FPCR_UAT_Active")
    app = next(layer for layer in pkg["access-layers"] if layer["name"].endswith("AppControl"))
    client.add_layer(ACCESS, make_layer(app["uid"], app["name"], 2))
    client.add_layer("show-threat-rulebase", load_fixture("threat_ips_empty.json"))
    client.add_layer("show-threat-rulebase", load_fixture("threat_fpcr_uat_active.json"))
    client.add_layer("show-https-rulebase", load_fixture("https_inbound_empty.json"))
    client.add_layer("show-https-rulebase", load_fixture("https_outbound.json"))
    client.add_layer("show-nat-rulebase", load_fixture("nat_fpcr_uat_active.json"), key="FPCR_UAT_Active")
    ref = lambda entry: {k: entry[k] for k in ("uid", "name", "domain") if k in entry}  # noqa: E731
    client.listings["show-access-layers"] = [ref(e) for e in pkg["access-layers"]]
    client.listings["show-threat-layers"] = [ref(e) for e in pkg["threat-layers"]]
    client.listings["show-https-layers"] = [ref(e) for e in pkg["https-inspection-layers"].values()]
    return client


def domain4_snapshot(mgmt_name: str = "m1", domain_name: str = "Domain4") -> DomainRulebaseSnapshot:
    """Domain4 after the Global assignment, package FPCR_UAT_Active only, from Gate L recordings: global layer with
    the place-holder linked to FPCR_UAT_Active Network, its inline layer, a synthetic 2-rule AppControl layer, NAT,
    threat (IPS empty, TP one rule) and HTTPS (inbound empty, outbound two rules). Canonical order (Phase 2)."""
    pkg = next(p for p in load_fixture("packages_domain4_after_assign.json") if p["name"] == "FPCR_UAT_Active")
    app = next(layer for layer in pkg["access-layers"] if layer["name"].endswith("AppControl"))
    layers = [
        parse_layer_response(load_fixture("global_layer_no_package.json"), "access", layer_domain_type="global domain"),
        parse_layer_response(
            load_fixture("domain_layer_fpcr_uat_active_network.json"), "access", layer_domain_type="domain"
        ),
        parse_layer_response(load_fixture("inline_layer_fpcr_uat_active_inline.json"), "access"),
        parse_layer_response(make_layer(app["uid"], app["name"], 2), "access", layer_domain_type="domain"),
        parse_layer_response(load_fixture("nat_fpcr_uat_active.json"), "nat", layer_name="FPCR_UAT_Active"),
        parse_layer_response(load_fixture("threat_ips_empty.json"), "threat", layer_domain_type="domain"),
        parse_layer_response(load_fixture("threat_fpcr_uat_active.json"), "threat", layer_domain_type="domain"),
        parse_layer_response(load_fixture("https_inbound_empty.json"), "https", layer_domain_type="domain"),
        parse_layer_response(load_fixture("https_outbound.json"), "https", layer_domain_type="domain"),
    ]
    nat_uid = next(layer.layer_uid for layer in layers if layer.rulebase_type == "nat")
    [layout] = parse_packages([pkg], nat_layer_uids={pkg["uid"]: nat_uid})
    glb = next(o for o in layout.layers if o.layer_domain_type == "global domain")
    global_layer = next(layer for layer in layers if layer.layer_uid == glb.layer_uid)
    placeholder = next(i for i in global_layer.items if i.kind == "place-holder")
    parent = find_parent_rule(load_fixture("global_layer_with_package.json"), "access", placeholder.rule_number)
    assert parent is not None
    layout = link_placeholder(layout, "access", glb.layer_uid, placeholder.uid, parent)
    return DomainRulebaseSnapshot(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        session_uid="sess-1",
        session_published_time=datetime(2026, 10, 1, 6, 53),
        refreshed_at=datetime(2026, 10, 1, 7, 0),
        packages=(layout,),
        layers=tuple(sorted(layers, key=lambda layer: (layer.rulebase_type, layer.layer_uid))),
    )
