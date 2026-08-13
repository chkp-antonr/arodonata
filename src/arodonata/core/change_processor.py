"""Change processor for parsing show-changes API responses."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ChangeType(StrEnum):
    """Type of object change."""

    ADD = "add"
    UPDATE = "set"  # Check Point API uses "set" for updates
    DELETE = "delete"


@dataclass
class ObjectChange:
    """Represents a single object change from show-changes API."""

    uid: str
    object_type: str
    change_type: ChangeType
    name: str
    raw_data: dict[str, Any]


class ChangeProcessor:
    """Process show-changes API responses.

    Parses the response and provides methods for filtering/grouping changes.
    """

    # Mapping of the real CP operations arrays to change types.
    _OPERATION_KEYS: tuple[tuple[str, ChangeType], ...] = (
        ("added-objects", ChangeType.ADD),
        ("modified-objects", ChangeType.UPDATE),
        ("deleted-objects", ChangeType.DELETE),
    )

    def parse_changes(self, api_response: dict[str, Any]) -> list[ObjectChange]:
        """Parse changes from show-changes API response.

        Supports both response shapes:
        - Real CP (R80+): task-wrapped and session-grouped —
          data.tasks[].task-details[].changes[].operations.{added,modified,
          deleted}-objects[], where each entry is the full object.
        - Legacy/flat: data.changes[] with per-entry "change-type" fields
          (used by older fixtures and kept for compatibility).

        Args:
            api_response: Raw API response from show-changes command.

        Returns:
            List of ObjectChange objects.
        """
        data = api_response.get("data", {})
        if not isinstance(data, dict):
            return []

        changes: list[ObjectChange] = []
        for entry in self._iter_change_entries(data):
            operations = entry.get("operations")
            if isinstance(operations, dict):
                changes.extend(self._parse_operations(operations))
            else:
                legacy = self._parse_legacy_entry(entry)
                if legacy is not None:
                    changes.append(legacy)
        return changes

    def _iter_change_entries(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Yield change entries from both the task-wrapped and flat shapes."""
        entries: list[dict[str, Any]] = []
        tasks = data.get("tasks")
        if isinstance(tasks, list):
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                for detail in task.get("task-details") or []:
                    if not isinstance(detail, dict):
                        continue
                    raw = detail.get("changes")
                    if isinstance(raw, list):
                        entries.extend(e for e in raw if isinstance(e, dict))
        flat = data.get("changes")
        if isinstance(flat, list):
            entries.extend(e for e in flat if isinstance(e, dict))
        return entries

    def _parse_operations(self, operations: dict[str, Any]) -> list[ObjectChange]:
        """Parse one session's operations dict from the real CP shape."""
        parsed: list[ObjectChange] = []
        for key, change_type in self._OPERATION_KEYS:
            objects = operations.get(key)
            if not isinstance(objects, list):
                continue
            for obj in objects:
                if not isinstance(obj, dict) or not obj.get("uid"):
                    continue
                parsed.append(
                    ObjectChange(
                        uid=obj.get("uid", ""),
                        object_type=obj.get("type", ""),
                        change_type=change_type,
                        name=obj.get("name", ""),
                        raw_data=obj,
                    )
                )
        return parsed

    def _parse_legacy_entry(self, change: dict[str, Any]) -> ObjectChange | None:
        """Parse one flat-shape entry; None for unknown change types."""
        try:
            change_type = ChangeType(change.get("change-type", ""))
        except ValueError:
            return None
        return ObjectChange(
            uid=change.get("uid", ""),
            object_type=change.get("type", ""),
            change_type=change_type,
            name=change.get("name", ""),
            raw_data=change,
        )

    def group_by_object_type(self, changes: list[ObjectChange]) -> dict[str, list[ObjectChange]]:
        """Group changes by object type.

        Args:
            changes: List of ObjectChange objects.

        Returns:
            Dictionary mapping object type to list of changes.
        """
        groups: dict[str, list[ObjectChange]] = {}
        for change in changes:
            obj_type = change.object_type
            if obj_type not in groups:
                groups[obj_type] = []
            groups[obj_type].append(change)
        return groups

    def filter_by_change_type(self, changes: list[ObjectChange], change_type: ChangeType) -> list[ObjectChange]:
        """Filter changes by change type.

        Args:
            changes: List of ObjectChange objects.
            change_type: Change type to filter by.

        Returns:
            Filtered list of changes.
        """
        return [c for c in changes if c.change_type == change_type]

    def get_adds_and_updates(self, changes: list[ObjectChange]) -> list[ObjectChange]:
        """Get only adds and updates (excluding deletes).

        Args:
            changes: List of ObjectChange objects.

        Returns:
            List of changes with type ADD or UPDATE.
        """
        return [c for c in changes if c.change_type in (ChangeType.ADD, ChangeType.UPDATE)]
