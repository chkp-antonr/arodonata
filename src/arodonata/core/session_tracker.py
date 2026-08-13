"""Session change tracker for in-memory change tracking."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


@dataclass
class SessionChange:
    """A change within the current unpublished session."""

    operation: Literal["add", "modify", "delete"]
    object_type: str
    uid: str
    name: str
    data: dict[str, Any] | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC).replace(tzinfo=None))


class SessionChangeTracker:
    """Tracks in-memory changes for the current unpublished session.

    Changes are NOT persisted to cache until publish is called.
    """

    def __init__(self) -> None:
        # Key: "mgmt_name:domain_name", Value: list[SessionChange]
        self._changes_by_session: dict[str, list[SessionChange]] = {}

    def add_change(
        self,
        mgmt_name: str,
        domain: str,
        change: SessionChange,
    ) -> None:
        """Track a change for a session.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
            change: SessionChange to track.
        """
        session_key = f"{mgmt_name}:{domain}"

        if session_key not in self._changes_by_session:
            self._changes_by_session[session_key] = []

        self._changes_by_session[session_key].append(change)

    def get_session_changes(
        self,
        mgmt_name: str,
        domain: str,
    ) -> list[SessionChange]:
        """Get all tracked changes for current session.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.

        Returns:
            List of SessionChange objects (empty if no changes).
        """
        session_key = f"{mgmt_name}:{domain}"
        return self._changes_by_session.get(session_key, [])

    def clear_session(self, mgmt_name: str, domain: str) -> None:
        """Clear tracked changes for a session.

        Called after publish or discard.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
        """
        session_key = f"{mgmt_name}:{domain}"
        self._changes_by_session.pop(session_key, None)

    def has_changes(self, mgmt_name: str, domain: str) -> bool:
        """Check if session has any tracked changes.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.

        Returns:
            True if session has changes, False otherwise.
        """
        return len(self.get_session_changes(mgmt_name, domain)) > 0
