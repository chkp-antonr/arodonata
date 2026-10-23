"""Common domain types, constants, and API result models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

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
    """Return current timezone-aware UTC datetime."""
    return datetime.now(UTC)


class ApiCallResult(BaseModel):
    """Typed result of a single Check Point Management API call."""

    model_config = ConfigDict(extra="ignore")

    success: bool
    status_code: int = 200
    data: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    error_code: str | None = None
    task_id: str | None = None


class ApiQueryResult(BaseModel):
    """Typed result of a paginated Check Point Management API query."""

    model_config = ConfigDict(extra="ignore")

    success: bool
    objects: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    error_message: str | None = None
    code: str | None = None
