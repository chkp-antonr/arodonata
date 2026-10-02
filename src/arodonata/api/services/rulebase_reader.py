"""Rulebase read pipeline shared by the cache refresh and the change report's live source (cache v2 2.8).

Per domain: show-packages and NAT per package, every layer of each type (package layers, listing, inline closure),
then the global place-holder links per package. ``caller`` is anything with the RulebaseCaller methods: the
ArodonataClient (cache refresh, shared session) or a SidCaller (live read inside an app-owned session).
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any, Literal, Protocol

from ...config import GLOBAL_DOMAIN_NAME
from ...core.exceptions import InvalidCredentialsError
from ...logger import lazy_logger
from ...rulebase.model import RULEBASE_COMMANDS, LayerSnapshot, PackageLayout, RulebaseType
from ...rulebase.pager import UNSUPPORTED_CODES, RulebaseFetchError, fetch_full_rulebase
from ...rulebase.parse import find_parent_rule, link_placeholder, parse_layer_response, parse_packages

log = lazy_logger("arodonata.api.services.rulebase_reader")

DetailsLevel = Literal["uid", "standard", "full"]
LAYER_TYPES: tuple[RulebaseType, ...] = ("access", "https", "threat")
LISTINGS: dict[RulebaseType, tuple[str, str]] = {
    "access": ("show-access-layers", "access-layers"),
    "https": ("show-https-layers", "https-layers"),
    "threat": ("show-threat-layers", "threat-layers"),
}


class RulebaseCaller(Protocol):
    """What read_domain calls. ArodonataClient satisfies it structurally (mypy-checked through its uses)."""

    async def api_call(self, *, mgmt_name: str, domain: str, command: str, payload: dict[str, Any]) -> Any: ...

    async def api_query(
        self, *, mgmt_name: str, domain: str, command: str, details_level: DetailsLevel, container_key: str
    ) -> Any: ...  # result has .success .objects .code .message


class DomainReadFailed(Exception):
    """A domain read step failed: nothing is replaced (cache) / the live numbers cannot be trusted."""


def _without_type(layouts: list[PackageLayout], rulebase_type: RulebaseType) -> list[PackageLayout]:
    return [
        PackageLayout(
            layout.package_uid,
            layout.package_name,
            tuple(o for o in layout.layers if o.rulebase_type != rulebase_type),
        )
        for layout in layouts
    ]


async def _list(
    caller: RulebaseCaller, mgmt_name: str, domain: str, command: str, key: str, details: DetailsLevel
) -> list[Any] | None:
    """A complete listing, or None when the server has no such command (the type is empty)."""
    result = await caller.api_query(
        mgmt_name=mgmt_name, domain=domain, command=command, details_level=details, container_key=key
    )
    if result.success:
        return list(result.objects)
    if result.code in UNSUPPORTED_CODES:
        log().debug(f"{command} unsupported on {mgmt_name}:{domain} ({result.code}); type cached empty")
        return None
    raise DomainReadFailed(f"{command} failed: {result.code}: {result.message}")


async def _fetch(
    caller: RulebaseCaller, mgmt_name: str, domain: str, rulebase_type: RulebaseType, target: dict[str, Any]
) -> dict[str, Any] | None:
    """One complete layer (NAT: package), or None when the command is unsupported."""
    try:
        return await fetch_full_rulebase(
            caller,
            mgmt_name,
            domain,
            RULEBASE_COMMANDS[rulebase_type],
            {**target, "details-level": "full", "use-object-dictionary": True},
        )
    except RulebaseFetchError as exc:
        if exc.code in UNSUPPORTED_CODES:
            return None
        raise DomainReadFailed(f"{rulebase_type} {target}: {exc}") from exc


async def _fetch_closure(
    caller: RulebaseCaller,
    mgmt_name: str,
    domain: str,
    rulebase_type: RulebaseType,
    targets: list[tuple[dict[str, Any], str]],
    layers: dict[str, LayerSnapshot],
) -> bool:
    """Fetch every target layer once (by uid, else by name) and every inline layer they reach.

    Returns False when the type's command is unsupported.
    """
    queue = list(targets)
    while queue:
        target, domain_type = queue.pop(0)
        if target.get("uid") and target["uid"] in layers:
            continue
        log().debug(f"Fetching {rulebase_type} layer {target.get('name') or target.get('uid')} of {mgmt_name}:{domain}")
        data = await _fetch(caller, mgmt_name, domain, rulebase_type, target)
        if data is None:
            return False
        snapshot = parse_layer_response(data, rulebase_type, layer_domain_type=domain_type)
        if snapshot.layer_uid in layers:
            continue
        layers[snapshot.layer_uid] = snapshot
        queue += [
            ({"uid": i.inline_layer_uid}, "")
            for i in snapshot.items
            if i.inline_layer_uid and i.inline_layer_uid not in layers
        ]
    return True


def _listing_target(rulebase_type: RulebaseType, entry: Any) -> tuple[dict[str, Any], str]:
    if isinstance(entry, dict) and entry.get("uid"):
        target: dict[str, Any] = {"uid": str(entry["uid"])}
    elif isinstance(entry, dict) and entry.get("name"):
        target = {"name": str(entry["name"])}
    else:
        raise DomainReadFailed(f"invalid {rulebase_type} layer listing entry: {entry!r}")
    domain_info = entry.get("domain")
    return target, str((domain_info.get("domain-type") if isinstance(domain_info, dict) else "") or "")


async def _link_placeholders(
    caller: RulebaseCaller,
    mgmt_name: str,
    domain: str,
    layouts: list[PackageLayout],
    layers: dict[str, LayerSnapshot],
    warnings: list[str],
) -> list[PackageLayout]:
    """Per package and global ordered layer with a place-holder: one read with ``package`` to find the parent
    rule and the domain layer under it. A failed link is a per-package warning; the place-holder is then
    numbered without descent."""
    linked: list[PackageLayout] = []
    for layout in layouts:
        for ordered in [o for o in layout.layers if o.layer_domain_type == "global domain"]:
            snapshot = layers.get(ordered.layer_uid)
            placeholder = next((i for i in snapshot.items if i.kind == "place-holder"), None) if snapshot else None
            if placeholder is None:
                continue
            label = f"Package {layout.package_name}: place-holder link of {ordered.layer_name}"
            try:
                data = await fetch_full_rulebase(
                    caller,
                    mgmt_name,
                    domain,
                    RULEBASE_COMMANDS[ordered.rulebase_type],
                    {"uid": ordered.layer_uid, "package": layout.package_name, "details-level": "standard"},
                )
            except InvalidCredentialsError:
                raise
            except Exception as exc:  # RulebaseFetchError or a transport error; CancelledError is not an Exception
                warnings.append(f"{label} failed ({exc}); numbered without the domain layer")
                continue
            parent = find_parent_rule(data, ordered.rulebase_type, placeholder.rule_number)
            if parent is None:
                warnings.append(
                    f"{label}: no domain parent rule at {placeholder.rule_number}; numbered without the domain layer"
                )
                continue
            layout = link_placeholder(layout, ordered.rulebase_type, ordered.layer_uid, placeholder.uid, parent)
        linked.append(layout)
    return linked


async def _read_nat(
    caller: RulebaseCaller,
    mgmt_name: str,
    domain: str,
    packages_raw: list[Any],
    layers: dict[str, LayerSnapshot],
) -> dict[str, str]:
    """NAT policy per package into ``layers``; package uid -> NAT layer uid (empty when NAT is unsupported)."""
    nat_uids: dict[str, str] = {}
    for pkg in packages_raw:
        if not isinstance(pkg, dict) or not pkg.get("nat-policy") or not pkg.get("uid"):
            continue
        name = str(pkg.get("name") or "")
        data = await _fetch(caller, mgmt_name, domain, "nat", {"package": name})
        if data is None:
            for uid in [uid for uid, layer in layers.items() if layer.rulebase_type == "nat"]:
                del layers[uid]
            return {}
        nat = parse_layer_response({**data, "uid": data.get("uid") or pkg["uid"]}, "nat", layer_name=name)
        nat_uids[str(pkg["uid"])] = nat.layer_uid
        layers[nat.layer_uid] = nat
    return nat_uids


async def read_domain(
    caller: RulebaseCaller,
    mgmt_name: str,
    domain: str,
    warnings: list[str],
    *,
    packages: Collection[str] | None = None,
) -> tuple[list[PackageLayout], dict[str, LayerSnapshot]]:
    """Read a domain's rulebases completely. With ``packages``, only those packages (and their NAT), no
    ``show-*-layers`` listings: targets are the selected packages' ordered layers, their inline closure and the
    place-holder links (the change report's package-scoped live read, D25)."""
    layers: dict[str, LayerSnapshot] = {}
    packages_raw = await _list(caller, mgmt_name, domain, "show-packages", "packages", "full") or []
    if packages is not None:
        wanted = set(packages)
        packages_raw = [p for p in packages_raw if isinstance(p, dict) and p.get("name") in wanted]
    nat_uids = await _read_nat(caller, mgmt_name, domain, packages_raw, layers)
    layouts = parse_packages(packages_raw, nat_layer_uids=nat_uids)

    for rulebase_type in LAYER_TYPES:
        targets = [
            ({"uid": o.layer_uid}, o.layer_domain_type)
            for layout in layouts
            for o in layout.layers
            if o.rulebase_type == rulebase_type
        ]
        listing: list[Any] | None = []
        if packages is None:
            command, key = LISTINGS[rulebase_type]
            listing = await _list(caller, mgmt_name, domain, command, key, "standard")
            if listing is not None:
                targets += [_listing_target(rulebase_type, entry) for entry in listing]
        if listing is None or not await _fetch_closure(caller, mgmt_name, domain, rulebase_type, targets, layers):
            layouts = _without_type(layouts, rulebase_type)
            for uid in [uid for uid, layer in layers.items() if layer.rulebase_type == rulebase_type]:
                del layers[uid]

    if domain != GLOBAL_DOMAIN_NAME:
        layouts = await _link_placeholders(caller, mgmt_name, domain, layouts, layers, warnings)
        for rulebase_type in LAYER_TYPES:
            nested = [
                ({"uid": o.domain_layer_uid}, "domain")
                for layout in layouts
                for o in layout.layers
                if o.rulebase_type == rulebase_type and o.domain_layer_uid
            ]
            if nested:
                await _fetch_closure(caller, mgmt_name, domain, rulebase_type, nested, layers)
    return layouts, layers


__all__ = ["DetailsLevel", "DomainReadFailed", "RulebaseCaller", "read_domain"]
