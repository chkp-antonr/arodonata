"""Domain models for the declarative CPCRUD policy-as-code engine (`src/arodonata/cpcrud/models.py`)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from arodonata.core.config import NamingPrefixes
from arodonata.core.errors import REDACTED_PLACEHOLDER, sanitize_mapping
from arodonata.core.models.common import to_naive_utc, utc_now

NameConflictPolicy = Literal["update", "error"]
IpConflictPolicy = Literal["reuse", "create_new", "error"]


class Outcome(StrEnum):
    """Outcome of a planned or executed CPCRUD action."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REUSE = "reuse"
    UNCHANGED = "unchanged"
    ERROR = "error"
    SKIPPED = "skipped"
    SKIPPED_DEPENDENCY = "skipped_dependency"
    PLAN_STALE = "plan_stale"


class ConflictPolicy(BaseModel):
    """Two-axis conflict resolution configuration (`on_name_conflict` x `on_ip_conflict`)."""

    model_config = ConfigDict(extra="ignore")

    on_name_conflict: NameConflictPolicy = "update"
    on_ip_conflict: IpConflictPolicy = "reuse"


class DomainStamp(BaseModel):
    """Snapshot of a domain's `show-last-published-session` head captured BEFORE planning lookups."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str = ""
    last_session_uid: str | None = None
    last_published_at: datetime | None = None
    readable: bool = True
    error: str | None = None
    captured_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        self.last_published_at = to_naive_utc(self.last_published_at)
        self.captured_at = to_naive_utc(self.captured_at) or utc_now()

    @property
    def key(self) -> str:
        """Canonical `(mgmt_name, domain_name)` lookup key."""
        return f"{self.mgmt_name}:{self.domain_name}"


class FieldChange(BaseModel):
    """Field-level difference computed by `differ.py` during planning."""

    model_config = ConfigDict(extra="ignore")

    field: str
    old_value: Any = None
    new_value: Any = None
    added_items: list[str] = Field(default_factory=list)
    removed_items: list[str] = Field(default_factory=list)


class PlannedAction(BaseModel):
    """A single deterministic action produced by `Planner`."""

    model_config = ConfigDict(extra="ignore")

    action_id: str
    mgmt_name: str
    domain_name: str = ""
    operation: str  # "present", "absent", "add", "set", "delete"
    object_type: str  # e.g. "host", "network", "service-tcp", "group", "access-rule", "nat-rule"
    name: str = ""
    requested_name: str = ""
    resolved_name: str = ""
    target_uid: str | None = None
    layer: str | None = None
    package: str | None = None
    outcome: Outcome
    status: str = ""
    command: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    diffs: dict[str, FieldChange] = Field(default_factory=dict)
    prior_state: dict[str, Any] | None = None
    desired_spec: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    message: str = ""
    error: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.requested_name and self.name:
            self.requested_name = self.name
        if not self.resolved_name and self.name:
            self.resolved_name = self.name
        if not self.status:
            self.status = str(self.outcome.value)

    @property
    def is_write_action(self) -> bool:
        """Return `True` if this action mutates Check Point state (`CREATE`, `UPDATE`, `DELETE`)."""
        return self.outcome in (Outcome.CREATE, Outcome.UPDATE, Outcome.DELETE)


class Plan(BaseModel):
    """Deterministic multi-domain execution plan produced by `CPCRUDService.plan()`."""

    model_config = ConfigDict(extra="ignore")

    created_at: datetime = Field(default_factory=utc_now)
    domain_stamps: dict[str, DomainStamp] = Field(default_factory=dict)
    actions: list[PlannedAction] = Field(default_factory=list)
    name_resolutions: dict[str, str] = Field(default_factory=dict)
    template: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        self.created_at = to_naive_utc(self.created_at) or utc_now()

    @property
    def has_errors(self) -> bool:
        """Return `True` if any planned action has `Outcome.ERROR` or `Outcome.SKIPPED_DEPENDENCY`."""
        return any(a.outcome in (Outcome.ERROR, Outcome.SKIPPED_DEPENDENCY) for a in self.actions)

    @property
    def write_actions(self) -> list[PlannedAction]:
        """Return all planned actions that perform API writes (`CREATE`, `UPDATE`, `DELETE`)."""
        return [a for a in self.actions if a.is_write_action]


class ActionResult(BaseModel):
    """Execution result of a single `PlannedAction` during `apply()`."""

    model_config = ConfigDict(extra="ignore")

    action_id: str
    mgmt_name: str
    domain_name: str = ""
    operation: str
    object_type: str
    name: str = ""
    resolved_name: str = ""
    target_uid: str | None = None
    planned_outcome: Outcome
    outcome: Outcome
    status: str = ""
    success: bool = True
    command: str | None = None
    response_data: dict[str, Any] = Field(default_factory=dict)
    prior_state: dict[str, Any] | None = None
    message: str = ""
    error: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.status:
            self.status = str(self.outcome.value)
        if self.response_data:
            self.response_data = sanitize_mapping(self.response_data)


class StagedSessionInfo(BaseModel):
    """Metadata for a dedicated write session left open when `apply(no_publish=True, keep_session=True)` runs.

    Redacts `sid` in `repr()`, `str()`, and serialized JSON while keeping `.sid` accessible programmatically.
    """

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str = ""
    server_ip: str
    session_uid: str | None = None
    session_name: str | None = None
    _sid: str = PrivateAttr(default="")

    def __init__(self, *, sid: str = "", **data: Any) -> None:
        super().__init__(**data)
        self._sid = sid

    @property
    def sid(self) -> str:
        """Return the raw session identifier for external workflow continuation (never included in `repr()`)."""
        return self._sid

    def clear_sid(self) -> None:
        """Clear the active SID after logout while preserving session provenance."""
        self._sid = ""

    def __repr__(self) -> str:
        sid_state = REDACTED_PLACEHOLDER if self._sid else None
        return (
            f"StagedSessionInfo(mgmt_name={self.mgmt_name!r}, domain_name={self.domain_name!r}, "
            f"server_ip={self.server_ip!r}, session_uid={self.session_uid!r}, "
            f"session_name={self.session_name!r}, sid={sid_state!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class ApplyReport(BaseModel):
    """Final execution report returned by `CPCRUDService.apply()`."""

    model_config = ConfigDict(extra="ignore")

    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)
    results: list[ActionResult] = Field(default_factory=list)
    published_domains: list[str] = Field(default_factory=list)
    published_sessions: dict[str, str] = Field(default_factory=dict)
    staged_sessions: list[StagedSessionInfo] = Field(default_factory=list)
    stale_domains: list[str] = Field(default_factory=list)
    retry_passes: int = 0
    retry_reports: list[ApplyReport] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        self.started_at = to_naive_utc(self.started_at) or utc_now()
        self.completed_at = to_naive_utc(self.completed_at) or utc_now()

    @property
    def success(self) -> bool:
        """Return `True` if no action ended in `ERROR` or `PLAN_STALE` and all results succeeded."""
        if self.stale_domains:
            return False
        return all(
            r.success and r.outcome not in (Outcome.ERROR, Outcome.PLAN_STALE, Outcome.SKIPPED_DEPENDENCY)
            for r in self.results
        )

    @property
    def has_failures(self) -> bool:
        """Return `True` if any action failed, was skipped due to dependency, or encountered a stale plan."""
        return not self.success

    @property
    def created_count(self) -> int:
        """Number of actions that succeeded with `Outcome.CREATE`."""
        return sum(1 for r in self.results if r.success and r.outcome == Outcome.CREATE)

    @property
    def updated_count(self) -> int:
        """Number of actions that succeeded with `Outcome.UPDATE`."""
        return sum(1 for r in self.results if r.success and r.outcome == Outcome.UPDATE)

    @property
    def deleted_count(self) -> int:
        """Number of actions that succeeded with `Outcome.DELETE`."""
        return sum(1 for r in self.results if r.success and r.outcome == Outcome.DELETE)

    @property
    def unchanged_count(self) -> int:
        """Number of actions with `Outcome.UNCHANGED` or `Outcome.REUSE`."""
        return sum(1 for r in self.results if r.outcome in (Outcome.UNCHANGED, Outcome.REUSE))

    @property
    def failed_count(self) -> int:
        """Number of actions that failed or were aborted due to error/stale plan."""
        return sum(
            1
            for r in self.results
            if not r.success or r.outcome in (Outcome.ERROR, Outcome.PLAN_STALE, Outcome.SKIPPED_DEPENDENCY)
        )


__all__ = [
    "ActionResult",
    "ApplyReport",
    "ConflictPolicy",
    "DomainStamp",
    "FieldChange",
    "IpConflictPolicy",
    "NameConflictPolicy",
    "NamingPrefixes",
    "Outcome",
    "Plan",
    "PlannedAction",
    "StagedSessionInfo",
]
