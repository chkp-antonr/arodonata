"""Pure: SessionChanges + RuleLocations -> numbered RulebaseBlocks (spec 5.2 as amended by D27).

show-changes gives ``position`` only for rules the session moved (and for added and deleted rules), counted within
the rule's section (lab F1/F2). Numbers therefore come from ``locations`` (cache or live) or ``prior`` (the cache's
pre-session state of an unpublished session) wherever the rule is there; a position becomes a number only in a layer
without sections, otherwise the placement carries ``section_position``. Per rule: (1) in locations — for basis
provisional only when unmoved; (2) positional with the session's position; (3) in an inline layer created in the
session: the parent's number + "." + position; (4) deleted: its prior (else locations) number, else positional with the
pre-session layer/position, else the deleted parent; (5) otherwise "Not placed in a package".
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from ...rulebase.source import LayerPosition, RuleLocations, RulePosition
from .columns import RULEBASE_ORDER, visible_columns
from .model import (
    LayerBlock,
    NumberBasis,
    ObjectChange,
    PackageBlock,
    RulebaseBlock,
    RuleChange,
    RulePlacement,
    SectionHeader,
    SessionChanges,
)

_LAST = (sys.maxsize,)
_UNKNOWN = "Section not known (or before the first section)"


def number_key(number: str | None) -> tuple[int, ...]:
    """'2.2.1' -> (2, 2, 1); None (or a non-numeric number) sorts last."""
    if not number:
        return _LAST
    try:
        return tuple(int(part) for part in number.split("."))
    except ValueError:
        return _LAST


@dataclass(frozen=True)
class _Placed:
    rule: RuleChange
    package: str | None  # None = not placed in a package
    layer_position: int
    layer_name: str
    number: str | None
    basis: NumberBasis
    section_uid: str | None = None
    section_name: str | None = None
    section_range: str | None = None
    section_position: int | None = None  # number unknown: the position within its section (D27)


class _Placer:
    def __init__(
        self,
        session: SessionChanges,
        locations: RuleLocations | None,
        basis: NumberBasis,
        prior: RuleLocations | None,
    ) -> None:
        self.locations = locations
        self.prior = prior
        self.basis = basis
        self.by_inline = {r.inline_layer_uid: r for r in session.rules if r.inline_layer_uid}
        self.memo: dict[str, list[_Placed]] = {}

    @staticmethod
    def positions(source: RuleLocations | None, uid: str) -> list[RulePosition]:
        return list(source.rules.get(uid, [])) if source else []

    def layer_positions(self, layer_uid: str | None) -> list[LayerPosition]:
        if not layer_uid:
            return []
        for source in (self.locations, self.prior):
            if source is not None and source.layers.get(layer_uid):
                return list(source.layers[layer_uid])
        return []

    def place(self, rule: RuleChange, path: frozenset[str] = frozenset()) -> list[_Placed]:
        if rule.uid not in self.memo:
            self.memo[rule.uid] = self._place(rule, path | {rule.uid})
        return self.memo[rule.uid]

    @staticmethod
    def _from_rule(rule: RuleChange, p: RulePosition, basis: NumberBasis) -> _Placed:
        return _Placed(
            rule,
            p.package_name,
            p.ordered_layer_position,
            p.ordered_layer_name,
            p.number,
            basis,
            p.section_uid,
            p.section_name,
            p.section_range,
        )

    @staticmethod
    def _from_layer(rule: RuleChange, lp: LayerPosition, position: int, basis: NumberBasis) -> _Placed:
        if lp.has_sections:  # the position counts within an unknown section: no number (D27)
            return _Placed(
                rule, lp.package_name, lp.ordered_layer_position, lp.ordered_layer_name, None, basis,
                section_position=position,
            )  # fmt: skip
        return _Placed(
            rule, lp.package_name, lp.ordered_layer_position, lp.ordered_layer_name, f"{lp.prefix}{position}", basis
        )

    @staticmethod
    def _unplaced(rule: RuleChange) -> list[_Placed]:
        return [_Placed(rule, None, 0, "", None, "none")]

    def _positional(
        self, rule: RuleChange, layer: str | None, position: int, basis: NumberBasis, path: frozenset[str]
    ) -> list[_Placed]:
        layers = self.layer_positions(layer)
        if layers:
            return [self._from_layer(rule, lp, position, basis) for lp in layers]
        parent = self.by_inline.get(layer) if layer else None  # an inline layer created (or deleted) in the session
        if parent is None or parent.uid in path:
            return []
        child_basis: NumberBasis = "before-deletion" if basis == "before-deletion" else "provisional"
        return [
            _Placed(rule, p.package, p.layer_position, p.layer_name, f"{p.number}.{position}", child_basis)
            for p in self.place(parent, path)
            if p.number
        ]

    def _place(self, rule: RuleChange, path: frozenset[str]) -> list[_Placed]:
        if self.locations is None:
            return self._unplaced(rule)
        if rule.status == "deleted":
            return self._deleted(rule, path)
        cached = self.positions(self.locations, rule.uid)
        if cached and (self.basis != "provisional" or not rule.moved):
            return [self._from_rule(rule, p, self.basis) for p in cached]
        basis: NumberBasis = "provisional" if self.basis == "provisional" else "at-time-of-change"
        if rule.position is not None:
            return self._positional(rule, rule.layer_uid, rule.position, basis, path) or self._unplaced(rule)
        return self._unplaced(rule)

    def _deleted(self, rule: RuleChange, path: frozenset[str]) -> list[_Placed]:
        cached = self.positions(self.prior, rule.uid) or self.positions(self.locations, rule.uid)
        if cached:
            return [self._from_rule(rule, p, "before-deletion") for p in cached]
        if rule.old_layer_uid and rule.old_position is not None:
            return self._positional(rule, rule.old_layer_uid, rule.old_position, "before-deletion", path) or (
                self._unplaced(rule)
            )
        return self._unplaced(rule)


def _previous_number(placer: _Placer, rule: RuleChange, placed: _Placed) -> str | None:
    """A moved rule's number before the session: from prior, else positional in a section-less layer."""
    if not rule.moved or placed.package is None:
        return None
    before = next(
        (p.number for p in placer.positions(placer.prior, rule.uid) if p.package_name == placed.package), None
    )
    if before is not None or rule.old_position is None:
        return before
    lp = next((x for x in placer.layer_positions(rule.old_layer_uid) if x.package_name == placed.package), None)
    return f"{lp.prefix}{rule.old_position}" if lp is not None and not lp.has_sections else None


def _nat_layer(rule: RuleChange, placer: _Placer) -> RuleChange:
    """A nat-rule body names its NAT rulebase in ``package``; the cache's NAT layer uid wins when they differ."""
    cached = placer.positions(placer.locations, rule.uid) if rule.rulebase == "nat" else []
    if cached and cached[0].layer_uid != rule.layer_uid:
        return rule.model_copy(update={"layer_uid": cached[0].layer_uid})
    return rule


def _with_sections(
    placed: list[tuple[_Placed, RulePlacement]], sections: dict[str, ObjectChange], used: set[str]
) -> list[RulePlacement | SectionHeader]:
    rows: list[RulePlacement | SectionHeader] = []
    current: str | None = None
    for p, placement in placed:
        if p.section_uid is None and p.section_position is not None and current != _UNKNOWN:
            rows.append(SectionHeader(uid=None, name=_UNKNOWN, range=None))  # a position within an unknown section
            current = _UNKNOWN
        if p.section_uid is not None and p.section_uid != current:
            change = sections.get(p.section_uid)
            rows.append(
                SectionHeader(
                    uid=p.section_uid,
                    name=p.section_name or "",
                    range=p.section_range,
                    status=change.status if change else None,
                    changes=list(change.changes) if change else [],
                )
            )
            used.add(p.section_uid)
            current = p.section_uid
        rows.append(placement)  # a placement without a section joins the run before it
    return rows


def _anchored(placer: _Placer, rules: list[RuleChange]) -> list[tuple[_Placed, RulePlacement]]:
    out: list[tuple[_Placed, RulePlacement]] = []
    for rule in rules:
        for k, p in enumerate(placer.place(rule), start=1):
            placement = RulePlacement(
                rule_uid=rule.uid,
                anchor=f"{rule.anchor_base}-p{k}",
                number=p.number,
                previous_number=_previous_number(placer, rule, p),
                basis=p.basis,
                section_uid=p.section_uid,
                section_name=p.section_name,
                section_range=p.section_range,
                section_position=p.section_position,
            )
            out.append((p, placement))
    return out


def _package_blocks(
    placed: list[tuple[_Placed, RulePlacement]], sections: dict[str, ObjectChange], used: set[str]
) -> list[PackageBlock]:
    packages: list[PackageBlock] = []
    for package in sorted({str(p.package) for p, _ in placed}):
        layers: list[LayerBlock] = []
        for position, name in sorted({(p.layer_position, p.layer_name) for p, _ in placed if p.package == package}):
            in_layer = sorted(
                (
                    (p, rp)
                    for p, rp in placed
                    if (p.package, p.layer_position, p.layer_name) == (package, position, name)
                ),
                key=lambda x: (
                    number_key(x[1].number),
                    0 if x[0].rule.status == "deleted" else 1,
                    x[1].section_position or 0,
                ),
            )
            layers.append(
                LayerBlock(
                    ordered_layer_name=name,
                    ordered_layer_position=position,
                    rows=_with_sections(in_layer, sections, used),
                )
            )
        packages.append(PackageBlock(package_name=package, layers=layers))
    return packages


def place_session(
    session: SessionChanges,
    locations: RuleLocations | None,
    *,
    basis: NumberBasis,
    prior: RuleLocations | None = None,
) -> SessionChanges:
    """Number every rule of the session and group it: rulebase (RULEBASE_ORDER) > package > ordered layer > number.

    ``prior`` is the cache's pre-session state of an unpublished session (deleted rules, previous numbers).
    """
    placer = _Placer(session, locations if basis != "none" else None, basis, prior)
    sections = {o.uid: o for o in session.sections}
    used: set[str] = set()
    blocks: list[RulebaseBlock] = []
    for kind in RULEBASE_ORDER:
        rules = [r for r in session.rules if r.rulebase == kind]
        if not rules:
            continue
        anchored = _anchored(placer, rules)
        blocks.append(
            RulebaseBlock(
                rulebase=kind,
                packages=_package_blocks([(p, rp) for p, rp in anchored if p.package is not None], sections, used),
                unplaced=[rp for p, rp in anchored if p.package is None],
                columns=visible_columns(kind, rules),
            )
        )
    return session.model_copy(
        update={
            "rules": [_nat_layer(r, placer) for r in session.rules],
            "rulebases": blocks,
            "sections": [o for o in session.sections if o.uid not in used],
        }
    )
