"""Change-report inputs: which sessions of which management servers and domains (validated at construction)."""

from __future__ import annotations

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

_SCOPE_CONFIG = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


class ChangeReportInputError(ValueError):
    """Invalid input found when collecting: empty scope list, a non-scope item, unknown mgmt_name, no server."""


class OwnedSession(BaseModel):
    """An app-owned session's SID, used read-only to number its unpublished rules. Never serialised or logged."""

    model_config = _SCOPE_CONFIG

    sid: SecretStr
    server_ip: str

    def __repr__(self) -> str:
        return f"OwnedSession(server_ip={self.server_ip!r}, sid=**********)"

    __str__ = __repr__


class SessionScope(BaseModel):
    """Explicit sessions of one domain, each fetched on its own (published or not)."""

    model_config = _SCOPE_CONFIG

    mgmt_name: str | None = None  # None -> first configured server
    domain: str = ""  # "" on an SMS
    session_uids: list[str] = Field(min_length=1)
    owned_session: OwnedSession | None = None

    @field_validator("session_uids")
    @classmethod
    def _dedupe(cls, uids: list[str]) -> list[str]:
        return list(dict.fromkeys(uids))


class RangeScope(BaseModel):
    """Published sessions of one domain between bounds: from_session exclusive, to_session inclusive (server
    semantics); dates inclusive and exact (applied client-side on the publish time)."""

    model_config = _SCOPE_CONFIG

    mgmt_name: str | None = None
    domain: str = ""
    from_session: str | None = None
    to_session: str | None = None
    from_date: AwareDatetime | None = None
    to_date: AwareDatetime | None = None

    @model_validator(mode="after")
    def _bounds(self) -> RangeScope:
        if self.from_session is None and self.from_date is None:
            if self.to_session is not None and self.to_date is None:
                raise ValueError("a to_session-only range is one session: use SessionScope for one session")
            if self.to_date is not None:
                raise ValueError("a to_date-only range would cover all history: give from_date or from_session")
            raise ValueError("a range needs a lower bound: from_session or from_date")
        if self.from_date is not None and self.to_date is not None and self.from_date > self.to_date:
            raise ValueError("from_date is after to_date")
        return self


Scope = SessionScope | RangeScope
