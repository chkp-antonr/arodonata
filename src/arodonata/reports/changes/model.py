"""The change report: one JSON-serialisable model, the single source for every renderer (spec 3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, model_validator

FORMAT_VERSION = 1
ChangeStatus = Literal["added", "modified", "deleted"]
ItemStatus = Literal["added", "removed", "unchanged", "modified"]
RulebaseKind = Literal["access", "nat", "threat", "https"]
NumberBasis = Literal["snapshot", "live", "provisional", "before-deletion", "at-time-of-change", "none"]


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


UtcDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReportWarning(_Model):
    """codes: domain_unavailable, session_not_found, owned_session_not_used, owned_session_error,
    owned_session_conflict, live_numbering_degraded, numbering_failed, names_unresolved, range_truncated"""

    mgmt: str
    domain: str
    code: str
    message: str
    severity: Literal["info", "warning"] = "warning"
    session_uid: str | None = None


class RequestedScope(_Model):
    """What the caller asked for; never a SID."""

    kind: Literal["session", "range"]
    mgmt_name: str
    domain: str
    session_uids: list[str] = Field(default_factory=list)
    from_session: str | None = None
    to_session: str | None = None
    from_date: UtcDatetime | None = None
    to_date: UtcDatetime | None = None
    owned_session_supplied: bool = False


class RawResponse(_Model):
    mgmt: str
    domain: str
    request: dict[str, Any]
    success: bool
    code: str = ""
    message: str = ""
    response: dict[str, Any] | None = None  # api_query's merged, flattened data; None on failure


class NumberingInfo(_Model):
    source: Literal["cache", "live", "none"]
    snapshot_session_uid: str | None = None
    snapshot_published_at: UtcDatetime | None = None
    snapshot_refreshed_at: UtcDatetime | None = None
    status: str = "none"  # cache sync status, "live", "failed", "none"
    last_error: str | None = None  # codes only on the live path
    provisional: bool = False
    global_packages: bool = False


class NamedRef(_Model):
    uid: str
    name: str  # == uid when unresolved


class CellItem(_Model):
    uid: str
    name: str
    status: ItemStatus = "unchanged"
    anchor: str | None = None  # object detail anchor when status == "modified"


class Cell(_Model):
    items: list[CellItem] | None = None  # list columns
    text: str | None = None  # scalar columns
    changed: bool = False
    negated: bool = False
    default: bool = False  # Any/empty and unchanged -> column may hide


class FieldChange(_Model):
    field: str  # top-level field, or "parent.sub" for one nested level
    old: str | None = None
    new: str | None = None
    removed: list[NamedRef] = Field(default_factory=list)
    added: list[NamedRef] = Field(default_factory=list)


class RuleChange(_Model):
    uid: str
    type: str
    rulebase: RulebaseKind
    name: str = ""
    status: ChangeStatus
    enabled: bool  # new value; pre-session value for deleted
    enabled_changed: bool = False
    layer_uid: str | None
    position: int | None
    old_layer_uid: str | None = None
    old_position: int | None = None
    moved: bool = False
    inline_layer_uid: str | None = None
    cells: dict[str, Cell]
    changes: list[FieldChange] = Field(default_factory=list)
    other_fields: list[str] = Field(default_factory=list)
    anchor_base: str  # "r-<session uid>-<rule uid>"


class RulePlacement(_Model):
    kind: Literal["rule"] = "rule"
    rule_uid: str
    anchor: str  # "<anchor_base>-p<k>"
    number: str | None
    previous_number: str | None = None
    basis: NumberBasis
    section_uid: str | None = None
    section_name: str | None = None
    section_range: str | None = None
    section_position: int | None = None  # D27: number unknown, the session's position within its section


class SectionHeader(_Model):
    kind: Literal["section"] = "section"
    uid: str | None
    name: str
    range: str | None
    status: ChangeStatus | None = None
    changes: list[FieldChange] = Field(default_factory=list)  # plan decision 3: a rename's old -> new


class LayerBlock(_Model):
    ordered_layer_name: str
    ordered_layer_position: int
    rows: list[Annotated[RulePlacement | SectionHeader, Field(discriminator="kind")]]


class PackageBlock(_Model):
    package_name: str
    layers: list[LayerBlock]


class RulebaseBlock(_Model):
    rulebase: RulebaseKind
    packages: list[PackageBlock]
    unplaced: list[RulePlacement] = Field(default_factory=list)
    columns: list[str]


class ObjectChange(_Model):
    uid: str
    type: str
    name: str
    status: ChangeStatus
    category: Literal["object", "section", "other"]
    internal: bool = False
    key_value: str = ""
    changes: list[FieldChange] = Field(default_factory=list)
    other_fields: list[str] = Field(default_factory=list)
    anchor: str  # "o-<session uid>-<object uid>"


class SessionChanges(_Model):
    uid: str
    name: str
    description: str = ""
    user_name: str = ""
    published: bool
    published_at: UtcDatetime | None
    numbering: NumberingInfo
    rules: list[RuleChange]
    rulebases: list[RulebaseBlock]
    sections: list[ObjectChange]
    objects: list[ObjectChange]
    other: list[ObjectChange]
    internal: list[ObjectChange]


class DomainError(_Model):
    code: str
    message: str


class DomainChanges(_Model):
    domain: str
    display_name: str
    unavailable: DomainError | None = None
    sessions: list[SessionChanges]


class MgmtChanges(_Model):
    mgmt_name: str
    domains: list[DomainChanges]


class ChangeReport(_Model):
    format_version: int = FORMAT_VERSION
    generated_at: UtcDatetime
    arodonata_version: str
    requested: list[RequestedScope]
    servers: list[MgmtChanges]
    warnings: list[ReportWarning] = Field(default_factory=list)
    raw: list[RawResponse] | None = None

    @model_validator(mode="before")
    @classmethod
    def _supported_version(cls, data: Any) -> Any:
        version = data.get("format_version", FORMAT_VERSION) if isinstance(data, dict) else FORMAT_VERSION
        if isinstance(version, int) and version > FORMAT_VERSION:
            raise ValueError(
                f"change report format_version {version} is newer than the supported {FORMAT_VERSION}; "
                "upgrade arodonata to read it"
            )
        return data
