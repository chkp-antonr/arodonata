"""Common domain types, constants, and API result models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal, overload

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import redact_sid, sanitize_mapping

CacheMode = Literal["cache", "smart", "smart-fast", "force"]
SyncScope = Literal["domains", "objects", "services", "assets", "rulebase"]
SyncStatus = Literal["idle", "syncing", "ok", "failed"]

DEFAULT_OBJECT_TYPES: tuple[str, ...] = (
    "host",
    "network",
    "address-range",
    "group",
    "dns-domain",
)

DEFAULT_SERVICE_TYPES: tuple[str, ...] = (
    "service-tcp",
    "service-udp",
    "service-icmp",
    "service-group",
)


def utc_now() -> datetime:
    """Return current naive UTC datetime (tzinfo=None)."""
    return datetime.now(UTC).replace(tzinfo=None)


@overload
def to_naive_utc(dt: datetime) -> datetime: ...
@overload
def to_naive_utc(dt: None) -> None: ...


def to_naive_utc(dt: datetime | None) -> datetime | None:
    """Convert any datetime to naive UTC (tzinfo=None).

    Aware datetimes are converted to UTC and stripped of tzinfo;
    naive datetimes are assumed to already be in UTC and returned as-is.
    """
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


class ApiCallResult(BaseModel):
    """Typed result of a single Check Point Management API call."""

    model_config = ConfigDict(extra="ignore")

    success: bool
    status_code: int = 200
    data: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    error_code: str | None = None
    task_id: str | None = None

    def __repr__(self) -> str:
        safe_data = sanitize_mapping(self.data) if isinstance(self.data, dict) else self.data
        safe_err = redact_sid(self.error_message) if self.error_message else None
        return (
            f"ApiCallResult(success={self.success!r}, status_code={self.status_code!r}, "
            f"data={safe_data!r}, error_message={safe_err!r}, "
            f"error_code={self.error_code!r}, task_id={self.task_id!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class ApiQueryResult(BaseModel):
    """Typed result of a paginated Check Point Management API query."""

    model_config = ConfigDict(extra="ignore")

    success: bool
    objects: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    error_message: str | None = None
    code: str | None = None
