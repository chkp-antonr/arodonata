"""Bare-uid names (group members, NAT references): the session's own entries first, then read-only show-object
through the shared session (at most NAME_LOOKUP_CAP per report), else the uid itself (spec 4, D26)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ...logger import lazy_logger
from .model import CellItem, FieldChange, NamedRef, ObjectChange, ReportWarning, SessionChanges

if TYPE_CHECKING:
    from ...api.client import ArodonataClient

log = lazy_logger("arodonata.reports.changes.names")

NAME_LOOKUP_CAP = 200


@dataclass
class NameBudget:
    """show-object lookups left for the whole report."""

    remaining: int = NAME_LOOKUP_CAP

    def take(self, wanted: int) -> int:
        granted = max(0, min(wanted, self.remaining))
        self.remaining -= granted
        return granted


def known_names(value: Any, into: dict[str, str] | None = None) -> dict[str, str]:
    """uid -> name of every object body or dereferenced reference anywhere in a session entry."""
    names = {} if into is None else into
    if isinstance(value, dict):
        uid, name = value.get("uid"), value.get("name")
        if isinstance(uid, str) and isinstance(name, str) and name and name != uid:
            names.setdefault(uid, name)
        for v in value.values():
            known_names(v, names)
    elif isinstance(value, list):
        for v in value:
            known_names(v, names)
    return names


def _field_refs(changes: list[FieldChange]) -> list[NamedRef]:
    return [r for c in changes for r in (*c.added, *c.removed)]


def unresolved_uids(session: SessionChanges) -> set[str]:
    out: set[str] = set()
    for rule in session.rules:
        out |= {i.uid for c in rule.cells.values() for i in c.items or [] if i.name == i.uid}
        out |= {r.uid for r in _field_refs(rule.changes) if r.name == r.uid}
    for obj in (*session.sections, *session.objects, *session.other, *session.internal):
        out |= {r.uid for r in _field_refs(obj.changes) if r.name == r.uid}
    return out


def apply_names(session: SessionChanges, names: dict[str, str]) -> SessionChanges:
    """Replace unresolved names (name == uid) found in ``names``."""
    if not names:
        return session

    def item(i: CellItem) -> CellItem:
        return i.model_copy(update={"name": names[i.uid]}) if i.name == i.uid and i.uid in names else i

    def nref(r: NamedRef) -> NamedRef:
        return r.model_copy(update={"name": names[r.uid]}) if r.name == r.uid and r.uid in names else r

    def change(c: FieldChange) -> FieldChange:
        return c.model_copy(update={"added": [nref(r) for r in c.added], "removed": [nref(r) for r in c.removed]})

    def obj(o: ObjectChange) -> ObjectChange:
        return o.model_copy(update={"changes": [change(c) for c in o.changes]})

    rules = [
        r.model_copy(
            update={
                "cells": {
                    k: c.model_copy(update={"items": [item(i) for i in c.items]}) if c.items else c
                    for k, c in r.cells.items()
                },
                "changes": [change(c) for c in r.changes],
            }
        )
        for r in session.rules
    ]
    return session.model_copy(
        update={
            "rules": rules,
            "sections": [obj(o) for o in session.sections],
            "objects": [obj(o) for o in session.objects],
            "other": [obj(o) for o in session.other],
            "internal": [obj(o) for o in session.internal],
        }
    )


async def _lookup(client: ArodonataClient, mgmt: str, domain: str, uid: str) -> str | None:
    try:
        res = await client.api_call(mgmt, "show-object", domain=domain, details_level="standard", payload={"uid": uid})
    except Exception as exc:
        log().debug(f"show-object {uid} on {mgmt}:{domain} raised {type(exc).__name__}")
        return None
    if not res.success or not isinstance(res.data, dict):
        return None
    inner = res.data.get("object")
    name = (inner if isinstance(inner, dict) else res.data).get("name")
    return str(name) if name else None


async def resolve_names(
    client: ArodonataClient,
    mgmt: str,
    domain: str,
    built: list[tuple[SessionChanges, dict[str, Any]]],
    budget: NameBudget,
    concurrency: int,
) -> tuple[list[SessionChanges], ReportWarning | None]:
    """Names for one domain's sessions; one names_unresolved warning with the count of uids left as uids."""
    sessions = [apply_names(s, known_names(e)) for s, e in built]
    missing = sorted(set().union(*(unresolved_uids(s) for s in sessions))) if sessions else []
    if not missing:
        return sessions, None
    granted = budget.take(len(missing))
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(uid: str) -> tuple[str, str | None]:
        async with semaphore:
            return uid, await _lookup(client, mgmt, domain, uid)

    found = {uid: name for uid, name in await asyncio.gather(*(one(u) for u in missing[:granted])) if name}
    unresolved = len(missing) - len(found)
    sessions = [apply_names(s, found) for s in sessions]
    if not unresolved:
        return sessions, None
    return sessions, ReportWarning(
        mgmt=mgmt,
        domain=domain,
        code="names_unresolved",
        message=f"{unresolved} object names could not be resolved (lookup failed or over the {NAME_LOOKUP_CAP} cap); "
        "shown as uids",
    )
