"""Typed domain progress events for synchronization and CPCRUD workflows.

Strictly decoupled from HTTP/SSE transport (`SSEEvent` lives in `arodonata.adapters.sse`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import REDACTED_PLACEHOLDER, sanitize_mapping
from arodonata.core.models.common import SyncScope, utc_now

SyncPhase = Literal["started", "probing", "syncing", "completed", "skipped", "failed"]
CPCRUDPhase = Literal[
    "started",
    "action_started",
    "action_completed",
    "action_failed",
    "staged_session",
    "published",
    "completed",
    "failed",
]


class DomainEvent(BaseModel):
    """Base model for all domain progress events."""

    model_config = ConfigDict(extra="ignore")

    event_type: str = "domain_event"
    timestamp: datetime = Field(default_factory=utc_now)
    mgmt_name: str | None = None
    domain: str | None = None
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)

    def safe_details(self) -> dict[str, Any]:
        """Return `details` scrubbed of any sensitive keys or session identifiers."""
        return sanitize_mapping(self.details)


class SyncProgressEvent(DomainEvent):
    """Typed progress event emitted during `stream_refresh_*` synchronization operations."""

    event_type: str = "sync_progress"
    scope: SyncScope = "objects"
    phase: SyncPhase = "syncing"
    item_type: str = "*"
    processed: int = 0
    total: int | None = None
    error: str | None = None


class SyncStartedEvent(SyncProgressEvent):
    """Emitted when a multi-domain synchronization run begins."""

    event_type: str = "sync_started"
    phase: SyncPhase = "started"


class DomainSyncStartedEvent(SyncProgressEvent):
    """Emitted when synchronization begins for a specific `(mgmt_name, domain)`."""

    event_type: str = "domain_sync_started"
    phase: SyncPhase = "syncing"


class DomainSyncProgressEvent(SyncProgressEvent):
    """Emitted as object/service/asset/rulebase pages are fetched for a domain."""

    event_type: str = "domain_sync_progress"
    phase: SyncPhase = "syncing"


class DomainSyncSkippedEvent(SyncProgressEvent):
    """Emitted when a domain or item_type slice is already fresh and skipped."""

    event_type: str = "domain_sync_skipped"
    phase: SyncPhase = "skipped"


class DomainSyncCompletedEvent(SyncProgressEvent):
    """Emitted when a domain or item_type slice completes synchronization."""

    event_type: str = "domain_sync_completed"
    phase: SyncPhase = "completed"


class DomainSyncFailedEvent(SyncProgressEvent):
    """Emitted when synchronization of a domain fails (e.g. InvalidCredentialsError or dirty session)."""

    event_type: str = "domain_sync_failed"
    phase: SyncPhase = "failed"


class SyncCompletedEvent(SyncProgressEvent):
    """Emitted when an entire synchronization run completes across all target domains."""

    event_type: str = "sync_completed"
    phase: SyncPhase = "completed"


class CPCRUDEvent(DomainEvent):
    """Typed progress event emitted during `cpcrud.stream_apply()`."""

    event_type: str = "cpcrud_progress"
    phase: CPCRUDPhase = "action_completed"
    action_id: str | None = None
    operation: str | None = None
    object_type: str | None = None
    object_name: str | None = None
    outcome: str | None = None
    error: str | None = None


class CPCRUDStartedEvent(CPCRUDEvent):
    """Emitted when a CPCRUD plan execution begins."""

    event_type: str = "cpcrud_started"
    phase: CPCRUDPhase = "started"


class CPCRUDActionEvent(CPCRUDEvent):
    """Emitted before or after an individual planned action executes."""

    event_type: str = "cpcrud_action"


class StagedSessionEvent(CPCRUDEvent):
    """Emitted when `apply(..., no_publish=True, keep_session=True)` leaves a write session staged."""

    event_type: str = "cpcrud_staged_session"
    phase: CPCRUDPhase = "staged_session"
    server_ip: str = ""
    session_uid: str | None = None
    session_name: str | None = None
    sid: str | None = Field(default=None, repr=False, exclude=True)

    def __repr__(self) -> str:
        sid_state = REDACTED_PLACEHOLDER if self.sid else None
        return (
            f"StagedSessionEvent(mgmt_name={self.mgmt_name!r}, domain={self.domain!r}, "
            f"server_ip={self.server_ip!r}, session_uid={self.session_uid!r}, "
            f"session_name={self.session_name!r}, sid={sid_state!r})"
        )


class CPCRUDDomainPublishedEvent(CPCRUDEvent):
    """Emitted when a domain's dedicated write session is published during CPCRUD apply."""

    event_type: str = "cpcrud_domain_published"
    phase: CPCRUDPhase = "published"
    session_uid: str | None = None


class CPCRUDCompletedEvent(CPCRUDEvent):
    """Emitted when `cpcrud.stream_apply()` finishes."""

    event_type: str = "cpcrud_completed"
    phase: CPCRUDPhase = "completed"
    succeeded_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
