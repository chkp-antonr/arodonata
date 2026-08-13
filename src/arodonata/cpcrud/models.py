"""Pydantic models and enums for CPCRUD (v2 shapes)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class NameConflictPolicy(StrEnum):
    UPDATE = "update"
    ERROR = "error"


class IpConflictPolicy(StrEnum):
    REUSE = "reuse"
    CREATE_NEW = "create_new"
    ERROR = "error"


class Outcome(StrEnum):
    # plan-time outcomes
    CREATE = "create"
    UPDATE = "update"
    REUSE = "reuse"
    UNCHANGED = "unchanged"
    DELETE = "delete"
    CONFLICT = "conflict"
    ERROR = "error"
    # apply-time outcomes
    LOCKED = "locked"
    DRIFTED = "drifted"
    SKIPPED_DEPENDENCY = "skipped_dependency"
    PLAN_STALE = "plan_stale"


class ObjectMatch(BaseModel):
    name: str
    uid: str
    type: str = ""
    where_used_total: int = 0
    matches_convention: bool = False
    lock: str | None = None  # meta-info.lock when read live


class ConflictInfo(BaseModel):
    axis: Literal["name", "ip", "lock"]
    policy: str
    requested: dict[str, Any] = Field(default_factory=dict)
    candidates: list[ObjectMatch] = Field(default_factory=list)


class FieldDiff(BaseModel):
    changes: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)


class CPCRUDResult(BaseModel):
    """Per-action view used in SSE events and legacy-style summaries."""

    operation: str
    type: str
    outcome: Outcome
    name: str
    uid: str | None = None
    matches: list[ObjectMatch] = Field(default_factory=list)
    changes: dict[str, dict[str, Any]] | None = None
    conflict: ConflictInfo | None = None
    message: str = ""


class PlannedAction(BaseModel):
    id: str
    depends_on: list[str] = Field(default_factory=list)
    operation: str  # add | update | delete | show
    type: str
    mgmt_name: str
    domain_name: str
    desired: dict[str, Any] = Field(default_factory=dict)
    key: dict[str, Any] | None = None
    outcome: Outcome = Outcome.CREATE
    resolved_uid: str | None = None
    resolved_name: str = ""
    matches: list[ObjectMatch] = Field(default_factory=list)
    changes: dict[str, dict[str, Any]] | None = None
    conflict: ConflictInfo | None = None
    command: str | None = None
    payload: dict[str, Any] | None = None
    auto_created: bool = False
    warnings: list[str] = Field(default_factory=list)
    layer: str | None = None  # access/https/threat-prevention rules
    position: Any | None = None  # schema-validated rule_position value, unresolved
    package: str | None = None  # nat-rule only
    message: str = ""
    prior_state: dict[str, Any] | None = None  # full pre-delete object/rule body; inverse-template source

    def to_result(self) -> CPCRUDResult:
        return CPCRUDResult(
            operation=self.operation,
            type=self.type,
            outcome=self.outcome,
            name=self.resolved_name,
            uid=self.resolved_uid,
            matches=self.matches,
            changes=self.changes,
            conflict=self.conflict,
            message=self.message,
        )


class DomainStamp(BaseModel):
    mgmt_name: str
    domain_name: str
    last_publish_session: str  # uid of show-last-published-session; "" if unknown


class Plan(BaseModel):
    actions: list[PlannedAction] = Field(default_factory=list)
    stamps: list[DomainStamp] = Field(default_factory=list)
    template_hash: str = ""

    def domains(self) -> list[tuple[str, str]]:
        """Distinct (mgmt_name, domain_name) pairs in action order."""
        seen: list[tuple[str, str]] = []
        for a in self.actions:
            pair = (a.mgmt_name, a.domain_name)
            if pair not in seen:
                seen.append(pair)
        return seen


class ActionResult(BaseModel):
    action_id: str
    outcome: Outcome
    type: str = ""
    name: str = ""
    mgmt_name: str = ""
    domain_name: str = ""
    uid: str | None = None
    locking_session: dict[str, Any] | None = None
    message: str = ""


class ApplyReport(BaseModel):
    results: list[ActionResult] = Field(default_factory=list)
    published_domains: list[DomainStamp] = Field(default_factory=list)
    remaining: Plan | None = None
    summary: dict[str, int] = Field(default_factory=dict)


class ObjectState(BaseModel):
    """Actual state of an existing object, as returned by show-<type>."""

    uid: str
    name: str
    type: str
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def lock(self) -> str | None:
        meta = self.raw.get("meta-info")
        if isinstance(meta, dict):
            return meta.get("lock")
        return None


class LayerInfo(BaseModel):
    uid: str
    name: str
    type: str  # "access" | "https" | "threat-prevention"  (NAT has no layer concept -- package only)
    parent_layer_uid: str | None = None  # set for an inline (Application Control) sub-layer


class SectionInfo(BaseModel):
    uid: str
    name: str
    layer_uid: str  # the owning layer -- critical when a package holds >1 layer


class RuleMatch(BaseModel):
    uid: str
    name: str
    rule_number: int
    raw: dict[str, Any] = Field(default_factory=dict)
