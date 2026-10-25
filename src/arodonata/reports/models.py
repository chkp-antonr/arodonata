"""Domain models for auditable session change reports (`arodonata.reports.models`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    ChangeReportInputError,
    redact_sid,
    sanitize_mapping,
)
from arodonata.core.models.common import to_naive_utc, utc_now
from arodonata.core.models.rulebase import RulebaseType

CURRENT_FORMAT_VERSION = 1

ChangeOperation = Literal["added", "modified", "deleted", "moved"]
ReportFormat = Literal["html", "json", "markdown"]
WarningCode = Literal[
    "session_fetch_failed",
    "changes_fetch_failed",
    "names_unresolved",
    "owned_session_not_used",
    "owned_session_error",
    "rulebase_numbering_warning",
    "partial_failure",
]


class OwnedSession(BaseModel):
    """Caller-supplied live unpublished write session (`sid`, `server_ip`) for live rulebase numbering.

    Strictly redacts `sid` from `repr()`, `str()`, and JSON serialization (`exclude=True`).
    """

    model_config = ConfigDict(extra="ignore")

    sid: str = Field(repr=False, exclude=True)
    server_ip: str = ""
    session_uid: str | None = None
    mgmt_name: str | None = None
    domain: str | None = None

    @model_validator(mode="after")
    def _validate_sid(self) -> OwnedSession:
        if not self.sid or not self.sid.strip():
            raise ChangeReportInputError("OwnedSession.sid must be a non-empty string.")
        return self

    def __repr__(self) -> str:
        return (
            f"OwnedSession(server_ip={self.server_ip!r}, session_uid={self.session_uid!r}, "
            f"mgmt_name={self.mgmt_name!r}, domain={self.domain!r}, sid={REDACTED_PLACEHOLDER!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class SessionScope(BaseModel):
    """Explicit Check Point session UID collection scope."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain: str | None = None
    session_uids: list[str] = Field(default_factory=list)
    owned_sessions: dict[str, OwnedSession] | list[OwnedSession] | OwnedSession | None = Field(
        default=None,
        repr=False,
        exclude=True,
    )

    @model_validator(mode="after")
    def _validate_scope(self) -> SessionScope:
        if not self.mgmt_name or not self.mgmt_name.strip():
            raise ChangeReportInputError("SessionScope.mgmt_name must not be empty.")
        cleaned = [u.strip() for u in self.session_uids if isinstance(u, str) and u.strip()]
        if not cleaned:
            raise ChangeReportInputError("SessionScope.session_uids must contain at least one session UID.")
        self.session_uids = cleaned
        return self

    def resolve_owned_session(self, session_uid: str) -> OwnedSession | None:
        """Return an `OwnedSession` matching `session_uid` if supplied on this scope."""
        if self.owned_sessions is None:
            return None
        if isinstance(self.owned_sessions, OwnedSession):
            if self.owned_sessions.session_uid in (None, "", session_uid):
                return self.owned_sessions
            return None
        if isinstance(self.owned_sessions, dict):
            if session_uid in self.owned_sessions:
                return self.owned_sessions[session_uid]
            if "*" in self.owned_sessions and len(self.session_uids) == 1:
                return self.owned_sessions["*"]
            return None
        if isinstance(self.owned_sessions, list):
            for item in self.owned_sessions:
                if item.session_uid == session_uid:
                    return item
            if len(self.owned_sessions) == 1 and len(self.session_uids) == 1:
                only = self.owned_sessions[0]
                if only.session_uid in (None, "", session_uid):
                    return only
        return None


def _require_timezone_aware(dt: datetime | None, field_name: str) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ChangeReportInputError(
            f"RangeScope.{field_name} must be timezone-aware (got naive datetime {dt.isoformat()!r})."
        )
    return dt.astimezone(UTC)


class RangeScope(BaseModel):
    """Published session and/or date range collection scope."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain: str | None = None
    from_date: datetime | None = None
    to_date: datetime | None = None
    from_session: str | None = None
    to_session: str | None = None

    @model_validator(mode="after")
    def _validate_range(self) -> RangeScope:
        if not self.mgmt_name or not self.mgmt_name.strip():
            raise ChangeReportInputError("RangeScope.mgmt_name must not be empty.")
        self.from_date = _require_timezone_aware(self.from_date, "from_date")
        self.to_date = _require_timezone_aware(self.to_date, "to_date")
        if self.from_session is not None:
            self.from_session = self.from_session.strip() or None
        if self.to_session is not None:
            self.to_session = self.to_session.strip() or None

        has_any_bound = any(b is not None for b in (self.from_date, self.to_date, self.from_session, self.to_session))
        if not has_any_bound:
            raise ChangeReportInputError(
                "RangeScope requires at least one bound (from_date, to_date, from_session, or to_session)."
            )
        if self.from_date is not None and self.to_date is not None and self.from_date > self.to_date:
            raise ChangeReportInputError(
                f"RangeScope.from_date ({self.from_date.isoformat()}) must not be after "
                f"to_date ({self.to_date.isoformat()})."
            )
        return self


ReportScope = SessionScope | RangeScope


class FieldDiff(BaseModel):
    """Per-field before/after diff for a modified rule or object."""

    model_config = ConfigDict(extra="ignore")

    field_name: str
    old_value: Any = None
    new_value: Any = None
    added_items: list[str] = Field(default_factory=list)
    removed_items: list[str] = Field(default_factory=list)


class RuleChangeEntry(BaseModel):
    """A single added, modified, moved, or deleted rule within a session."""

    model_config = ConfigDict(extra="ignore")

    uid: str
    name: str = ""
    operation: ChangeOperation = "modified"
    rulebase_type: RulebaseType = "access"
    package_uid: str | None = None
    package_name: str | None = None
    layer_uid: str = ""
    layer_name: str = ""
    section_uid: str | None = None
    section_name: str | None = None
    section_range: str | None = None
    rule_number: str | None = None
    old_rule_number: str | None = None
    moved: bool = False
    enabled: bool = True
    action: str | None = None
    method: str | None = None
    source: list[str] = Field(default_factory=list)
    destination: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    source_negate: bool = False
    destination_negate: bool = False
    service_negate: bool = False
    original_source: str | None = None
    original_destination: str | None = None
    original_service: str | None = None
    translated_source: str | None = None
    translated_destination: str | None = None
    translated_service: str | None = None
    track: str | None = None
    install_on: list[str] = Field(default_factory=list)
    comments: str = ""
    field_diffs: list[FieldDiff] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ObjectChangeEntry(BaseModel):
    """A single added, modified, or deleted network/service/policy object in a session."""

    model_config = ConfigDict(extra="ignore")

    uid: str
    name: str = ""
    object_type: str = "object"
    operation: ChangeOperation = "modified"
    summary: str = ""
    field_diffs: list[FieldDiff] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ReportWarning(BaseModel):
    """Structured warning recorded when a partial failure, fallback, or lookup cap occurs."""

    model_config = ConfigDict(extra="ignore")

    code: WarningCode | str
    message: str
    mgmt_name: str | None = None
    domain: str | None = None
    session_uid: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _sanitize(self) -> ReportWarning:
        self.message = redact_sid(self.message)
        self.details = sanitize_mapping(self.details)
        return self


class RawResponse(BaseModel):
    """Sanitized raw API response preserved in `ChangeReport` for auditability (never contains SIDs)."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain: str | None = None
    session_uid: str | None = None
    command: str
    payload: dict[str, Any] = Field(default_factory=dict)
    response: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _sanitize(self) -> RawResponse:
        self.payload = sanitize_mapping(self.payload)
        self.response = sanitize_mapping(self.response)
        return self


class SessionChangeReport(BaseModel):
    """Auditable change evidence for a single Check Point management session."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    session_uid: str
    session_name: str = ""
    description: str = ""
    user_name: str = ""
    state: str = "published"
    published_at: datetime | None = None
    last_modify_time: datetime | None = None
    locks: int = 0
    changes_count: int = 0
    numbering_basis: str = "Numbering from cached rulebase snapshot"
    numbering_source: Literal["owned_session", "cache", "unnumbered"] = "cache"
    rule_changes: list[RuleChangeEntry] = Field(default_factory=list)
    object_changes: list[ObjectChangeEntry] = Field(default_factory=list)
    resolved_names: dict[str, str] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        self.published_at = to_naive_utc(self.published_at)
        self.last_modify_time = to_naive_utc(self.last_modify_time)


class RenderOptions(BaseModel):
    """Formatting options for `render_change_report` and `build_change_report`."""

    model_config = ConfigDict(extra="ignore")

    title: str = "Check Point Policy Change Report"
    header_fields: dict[str, str] = Field(default_factory=dict)
    include_object_changes: bool = True
    include_field_diffs: bool = True
    include_warnings: bool = True


class ChangeReport(BaseModel):
    """Top-level auditable session change report model supporting round-trip JSON serialization."""

    model_config = ConfigDict(extra="ignore")

    format_version: int = CURRENT_FORMAT_VERSION
    generated_at: datetime = Field(default_factory=utc_now)
    title: str = "Check Point Policy Change Report"
    header_fields: dict[str, str] = Field(default_factory=dict)
    sessions: list[SessionChangeReport] = Field(default_factory=list)
    warnings: list[ReportWarning] = Field(default_factory=list)
    raw_responses: list[RawResponse] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_format_version(self) -> ChangeReport:
        self.generated_at = to_naive_utc(self.generated_at) or utc_now()
        if self.format_version > CURRENT_FORMAT_VERSION or self.format_version < 1:
            raise ChangeReportInputError(
                f"Unsupported ChangeReport format_version={self.format_version} "
                f"(installed library supports up to format_version={CURRENT_FORMAT_VERSION})."
            )
        return self


class RenderedReportBundle(BaseModel):
    """Container returned by `render_change_report` and `build_change_report`."""

    model_config = ConfigDict(extra="ignore")

    report: ChangeReport
    html: bytes | None = None
    markdown: str | None = None
    json_text: str | None = None

    def __getitem__(self, key: str) -> bytes | str:
        norm = key.strip().lower()
        if norm == "html" and self.html is not None:
            return self.html
        if norm in ("markdown", "md") and self.markdown is not None:
            return self.markdown
        if norm == "json" and self.json_text is not None:
            return self.json_text
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        norm = key.strip().lower()
        if norm == "html":
            return self.html is not None
        if norm in ("markdown", "md"):
            return self.markdown is not None
        if norm == "json":
            return self.json_text is not None
        return False


__all__ = [
    "CURRENT_FORMAT_VERSION",
    "ChangeOperation",
    "ChangeReport",
    "FieldDiff",
    "ObjectChangeEntry",
    "OwnedSession",
    "RangeScope",
    "RawResponse",
    "RenderOptions",
    "RenderedReportBundle",
    "ReportFormat",
    "ReportScope",
    "ReportWarning",
    "RuleChangeEntry",
    "SessionChangeReport",
    "SessionScope",
    "WarningCode",
]
