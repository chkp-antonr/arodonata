"""Read contract over rulebase snapshots: SmartConsole-numbered packages and layers, and rule positions.

The builders are pure (a ``DomainRulebaseSnapshot`` in, numbered results out). ``CachedRulebaseSource`` adds the cache
reads and the readiness rule; a live source can wrap the same builders.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from .model import (
    RULEBASE_CACHE_FORMAT,
    RULEBASE_TYPES,
    DomainRulebaseSnapshot,
    LayerSnapshot,
    OrderedLayer,
    PackageLayout,
    RulebaseType,
)
from .numbering import NumberedEntry, number_layer, number_package


@dataclass(frozen=True)
class RulePosition:
    package_name: str
    rulebase_type: RulebaseType
    ordered_layer_position: int
    ordered_layer_name: str
    number: str  # SmartConsole number in that package
    section_name: str | None
    section_range: str | None
    layer_uid: str  # layer that physically holds the rule
    layer_name: str


@dataclass(frozen=True)
class LayerPosition:
    """Where a layer appears in a package's numbering; a rule at in-layer position n there is ``prefix + str(n)``."""

    package_name: str
    rulebase_type: RulebaseType
    ordered_layer_position: int
    ordered_layer_name: str
    prefix: str  # "" for an ordered layer, "2." under Global's parent rule 2, "2.2." for the inline layer of rule 2.2


@dataclass(frozen=True)
class RuleLocations:
    snapshot_session_uid: str | None
    snapshot_published_at: datetime | None
    snapshot_refreshed_at: datetime | None
    status: str
    last_error: str | None
    rules: dict[str, list[RulePosition]]  # rule uid -> every position ([] when unknown)
    layers: dict[str, list[LayerPosition]]  # layer uid -> every position ([] when unknown)


@dataclass(frozen=True)
class PackageRulebase:
    mgmt_name: str
    domain_name: str
    package_name: str
    rulebase_type: RulebaseType
    snapshot_session_uid: str | None
    snapshot_published_at: datetime | None  # publish time of snapshot_session_uid
    snapshot_refreshed_at: datetime | None
    status: str  # sync-state status: 'ok' | 'unversioned' | 'failed'
    last_error: str | None  # set when status == 'failed' (served from the last good snapshot)
    layers: tuple[tuple[OrderedLayer, tuple[NumberedEntry, ...]], ...]
    layer_names: Mapping[str, str]  # layer_uid -> layer_name, every layer visited
    layer_dictionaries: Mapping[str, tuple[dict[str, str], ...]]  # layer_uid -> trimmed objects_dictionary


@dataclass(frozen=True)
class LayerRulebase:
    mgmt_name: str
    domain_name: str
    rulebase_type: RulebaseType
    layer_uid: str
    layer_name: str
    snapshot_session_uid: str | None
    snapshot_published_at: datetime | None
    snapshot_refreshed_at: datetime | None
    status: str
    last_error: str | None
    entries: tuple[NumberedEntry, ...]
    layer_names: Mapping[str, str]
    layer_dictionaries: Mapping[str, tuple[dict[str, str], ...]]


class RulebaseCacheNotReady(Exception):
    """The domain has no usable rulebase snapshot (no sync state, or an older cache format)."""


class RulebaseNotFound(LookupError):
    """The layer or package is not in the domain's snapshot."""


class AmbiguousLayerName(Exception):
    """A layer (or package) name matches several layers; candidates are (domain_name, uid)."""

    def __init__(self, name: str, candidates: tuple[tuple[str, str], ...]) -> None:
        listed = ", ".join(f"{domain}/{uid}" for domain, uid in candidates)
        super().__init__(f"{name!r} matches several layers: {listed}")
        self.name = name
        self.candidates = candidates


class RulebaseSource(Protocol):
    """Numbered rulebases of one domain, whatever they are read from.

    A cached source reports the sync-state status (``ok`` | ``unversioned`` | ``failed``) with ``snapshot_*`` fields
    describing the cached snapshot. A live source reports status ``live``, with ``snapshot_*`` describing what it
    read (the head session it read at, that session's publish time, and the read time as ``snapshot_refreshed_at``).
    """

    async def packages(self, mgmt_name: str, domain_name: str) -> list[PackageLayout]: ...
    async def package_rulebase(
        self, mgmt_name: str, domain_name: str, package: str, rulebase_type: RulebaseType
    ) -> PackageRulebase: ...
    async def layer_rulebase(
        self, mgmt_name: str, domain_name: str, layer: str, rulebase_type: RulebaseType
    ) -> LayerRulebase: ...
    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str,
        rule_uids: Collection[str] = (),
        rulebase_type: RulebaseType | None = None,
        *,
        layer_uids: Collection[str] = (),
    ) -> RuleLocations: ...


class RulebaseDomainIndex(Protocol):
    """Which domains hold a layer or package; used only to resolve the facade's domainless calls."""

    async def find_layer_domains(
        self, mgmt_name: str, layer: str, rulebase_type: RulebaseType
    ) -> list[tuple[str, str]]: ...
    async def find_package_domains(self, mgmt_name: str, package: str) -> list[tuple[str, str]]: ...


def check_uid_collections(**collections: Collection[str]) -> None:
    """Reject a bare ``str`` passed as a collection of uids (it would be iterated per character).

    Raises:
        TypeError: One of the arguments is a ``str``.
    """
    for name, value in collections.items():
        if isinstance(value, str):
            raise TypeError(f"{name} must be a collection of uids, not a str (wrap a single uid: [{value!r}])")


def _by_uid(snapshot: DomainRulebaseSnapshot) -> dict[str, LayerSnapshot]:
    return {layer.layer_uid: layer for layer in snapshot.layers}


def _visited(
    entries: Sequence[NumberedEntry], layers: Mapping[str, LayerSnapshot]
) -> tuple[dict[str, str], dict[str, tuple[dict[str, str], ...]]]:
    """Names and trimmed dictionaries of every layer the entries live in or point to (inline / domain layers)."""
    uids: list[str] = []
    for entry in entries:
        for uid in (entry.layer_uid, entry.inline_layer_uid):
            if uid and uid in layers and uid not in uids:
                uids.append(uid)
    return {u: layers[u].layer_name for u in uids}, {u: layers[u].objects_dictionary for u in uids}


def _ordered(layout: PackageLayout, rulebase_type: RulebaseType) -> list[OrderedLayer]:
    return sorted((o for o in layout.layers if o.rulebase_type == rulebase_type), key=lambda o: o.position)


def resolve_layer(snapshot: DomainRulebaseSnapshot, layer: str, rulebase_type: RulebaseType) -> LayerSnapshot:
    """A layer of the given type by uid, else by name.

    Raises:
        RulebaseNotFound: No layer with that uid or name.
        AmbiguousLayerName: The name matches several layers.
    """
    of_type = [lyr for lyr in snapshot.layers if lyr.rulebase_type == rulebase_type]
    matches = [lyr for lyr in of_type if lyr.layer_uid == layer] or [lyr for lyr in of_type if lyr.layer_name == layer]
    if not matches:
        raise RulebaseNotFound(
            f"{rulebase_type} layer {layer!r} is not cached for {snapshot.mgmt_name}/{snapshot.domain_name}"
        )
    if len(matches) > 1:
        raise AmbiguousLayerName(layer, tuple((snapshot.domain_name, lyr.layer_uid) for lyr in matches))
    return matches[0]


def package_rulebase_from_snapshot(
    snapshot: DomainRulebaseSnapshot,
    package: str,
    rulebase_type: RulebaseType,
    *,
    status: str = "ok",
    last_error: str | None = None,
) -> PackageRulebase:
    """A package's SmartConsole numbering for one rulebase type (one entry list per ordered layer).

    Raises:
        RulebaseNotFound: No package with that name or uid.
    """
    layout = next((p for p in snapshot.packages if package in (p.package_name, p.package_uid)), None)
    if layout is None:
        raise RulebaseNotFound(f"package {package!r} is not cached for {snapshot.mgmt_name}/{snapshot.domain_name}")
    layers = _by_uid(snapshot)
    ordered = _ordered(layout, rulebase_type)
    numbered = number_package(layout, rulebase_type, layers)
    names, dictionaries = _visited([e for entries in numbered for e in entries], layers)
    return PackageRulebase(
        mgmt_name=snapshot.mgmt_name,
        domain_name=snapshot.domain_name,
        package_name=layout.package_name,
        rulebase_type=rulebase_type,
        snapshot_session_uid=snapshot.session_uid,
        snapshot_published_at=snapshot.session_published_time,
        snapshot_refreshed_at=snapshot.refreshed_at,
        status=status,
        last_error=last_error,
        layers=tuple((o, tuple(entries)) for o, entries in zip(ordered, numbered, strict=True)),
        layer_names=names,
        layer_dictionaries=dictionaries,
    )


def layer_rulebase_from_snapshot(
    snapshot: DomainRulebaseSnapshot,
    layer: str,
    rulebase_type: RulebaseType,
    *,
    status: str = "ok",
    last_error: str | None = None,
) -> LayerRulebase:
    """One layer numbered without package context (layer-relative numbers, inline layers expanded)."""
    target = resolve_layer(snapshot, layer, rulebase_type)
    layers = _by_uid(snapshot)
    entries = tuple(number_layer(target.layer_uid, layers))
    names, dictionaries = _visited(entries, layers)
    names.setdefault(target.layer_uid, target.layer_name)
    dictionaries.setdefault(target.layer_uid, target.objects_dictionary)
    return LayerRulebase(
        mgmt_name=snapshot.mgmt_name,
        domain_name=snapshot.domain_name,
        rulebase_type=rulebase_type,
        layer_uid=target.layer_uid,
        layer_name=target.layer_name,
        snapshot_session_uid=snapshot.session_uid,
        snapshot_published_at=snapshot.session_published_time,
        snapshot_refreshed_at=snapshot.refreshed_at,
        status=status,
        last_error=last_error,
        entries=entries,
        layer_names=names,
        layer_dictionaries=dictionaries,
    )


def locate_rules_in_snapshot(
    snapshot: DomainRulebaseSnapshot,
    rule_uids: Collection[str] = (),
    rulebase_type: RulebaseType | None = None,
    *,
    layer_uids: Collection[str] = (),
    status: str = "ok",
    last_error: str | None = None,
) -> RuleLocations:
    """Every position of each rule uid and each layer uid in every package's numbering.

    A rule position is its SmartConsole number (shared and inline layers give several). A layer position is the
    prefix its rules get there: ``""`` for an ordered layer, ``"<n>."`` for a layer reached through rule ``n`` (an
    inline layer, or the domain layer under Global's parent rule). Unknown uids map to ``[]``.
    """
    rules: dict[str, list[RulePosition]] = {uid: [] for uid in rule_uids}
    layer_positions: dict[str, list[LayerPosition]] = {uid: [] for uid in layer_uids}
    layers = _by_uid(snapshot)
    for layout in snapshot.packages:
        for rt in (rulebase_type,) if rulebase_type else RULEBASE_TYPES:
            for ordered, entries in zip(_ordered(layout, rt), number_package(layout, rt, layers), strict=True):

                def at(
                    prefix: str, layout: PackageLayout = layout, ordered: OrderedLayer = ordered, rt: RulebaseType = rt
                ) -> LayerPosition:
                    return LayerPosition(layout.package_name, rt, ordered.position, ordered.layer_name, prefix)

                if ordered.layer_uid in layer_positions:
                    layer_positions[ordered.layer_uid].append(at(""))
                ranges: dict[str, str] = {}
                for entry in entries:
                    if entry.kind == "section":
                        ranges[entry.uid] = entry.range
                        continue
                    if entry.inline_layer_uid in layer_positions and entry.kind in ("rule", "parent-rule"):
                        layer_positions[entry.inline_layer_uid].append(at(f"{entry.number}."))
                    if entry.uid in rules:
                        rules[entry.uid].append(
                            RulePosition(
                                package_name=layout.package_name,
                                rulebase_type=rt,
                                ordered_layer_position=ordered.position,
                                ordered_layer_name=ordered.layer_name,
                                number=entry.number,
                                section_name=entry.section_name,
                                section_range=ranges.get(entry.section_uid) if entry.section_uid else None,
                                layer_uid=entry.layer_uid,
                                layer_name=entry.layer_name,
                            )
                        )
    return RuleLocations(
        snapshot_session_uid=snapshot.session_uid,
        snapshot_published_at=snapshot.session_published_time,
        snapshot_refreshed_at=snapshot.refreshed_at,
        status=status,
        last_error=last_error,
        rules=rules,
        layers=layer_positions,
    )


class CachedRulebaseSource:
    """RulebaseSource (and RulebaseDomainIndex) over the rulebase cache. Never calls the API.

    Readable = a sync row with ``format_version >= RULEBASE_CACHE_FORMAT`` (Phase 2 writes that version only together
    with the domain's complete snapshot). Status is not checked: a ``failed`` domain is served from its last good
    snapshot with ``status``/``last_error`` exposed; a domain whose refreshes only ever failed has format 0.
    """

    def __init__(self, cache: Any) -> None:
        self._cache = cache

    @staticmethod
    def _is_ready(state: Any) -> bool:
        return state is not None and state.format_version >= RULEBASE_CACHE_FORMAT

    async def _ready(self, mgmt_name: str, domain_name: str) -> Any:
        state = await self._cache.get_rulebase_sync_state(mgmt_name, domain_name)
        return state if self._is_ready(state) else None

    async def _read(self, mgmt_name: str, domain_name: str) -> tuple[DomainRulebaseSnapshot | None, Any]:
        snapshot = await self._cache.load_domain_rulebase_snapshot(mgmt_name, domain_name)
        return snapshot, await self._cache.get_rulebase_sync_state(mgmt_name, domain_name)

    async def _snapshot(self, mgmt_name: str, domain_name: str) -> tuple[DomainRulebaseSnapshot, str, str | None]:
        # Two reads: a refresh landing between them would label the snapshot with another refresh's status. A failed
        # refresh leaves refreshed_at alone, so only a newer snapshot changes it; then both are read once more.
        snapshot, state = await self._read(mgmt_name, domain_name)
        if snapshot is not None and state is not None and state.refreshed_at != snapshot.refreshed_at:
            snapshot, state = await self._read(mgmt_name, domain_name)
        if snapshot is None or not self._is_ready(state):
            failed = f"; last refresh failed: {state.last_error}" if state is not None and state.last_error else ""
            raise RulebaseCacheNotReady(
                f"no rulebase snapshot cached for {mgmt_name}/{domain_name}; run refresh_rulebases for that domain"
                f"{failed}"
            )
        return snapshot, str(state.status), state.last_error

    async def packages(self, mgmt_name: str, domain_name: str) -> list[PackageLayout]:
        snapshot, _, _ = await self._snapshot(mgmt_name, domain_name)
        return list(snapshot.packages)

    async def package_rulebase(
        self, mgmt_name: str, domain_name: str, package: str, rulebase_type: RulebaseType
    ) -> PackageRulebase:
        snapshot, status, last_error = await self._snapshot(mgmt_name, domain_name)
        return package_rulebase_from_snapshot(snapshot, package, rulebase_type, status=status, last_error=last_error)

    async def layer_rulebase(
        self, mgmt_name: str, domain_name: str, layer: str, rulebase_type: RulebaseType
    ) -> LayerRulebase:
        snapshot, status, last_error = await self._snapshot(mgmt_name, domain_name)
        return layer_rulebase_from_snapshot(snapshot, layer, rulebase_type, status=status, last_error=last_error)

    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str,
        rule_uids: Collection[str] = (),
        rulebase_type: RulebaseType | None = None,
        *,
        layer_uids: Collection[str] = (),
    ) -> RuleLocations:
        check_uid_collections(rule_uids=rule_uids, layer_uids=layer_uids)
        snapshot, status, last_error = await self._snapshot(mgmt_name, domain_name)
        return locate_rules_in_snapshot(
            snapshot, rule_uids, rulebase_type, layer_uids=layer_uids, status=status, last_error=last_error
        )

    # ---- RulebaseDomainIndex ----

    async def find_layer_domains(
        self, mgmt_name: str, layer: str, rulebase_type: RulebaseType
    ) -> list[tuple[str, str]]:
        rows = await self._cache.find_rulebase_layers(mgmt_name, layer, rulebase_type)
        return [row for row in rows if await self._ready(mgmt_name, row[0])]

    async def find_package_domains(self, mgmt_name: str, package: str) -> list[tuple[str, str]]:
        rows = await self._cache.find_rulebase_packages(mgmt_name, package)
        return [row for row in rows if await self._ready(mgmt_name, row[0])]
