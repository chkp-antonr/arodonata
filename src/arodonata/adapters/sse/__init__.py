"""Server-Sent Events (`SSEEvent`) adapter converting core `DomainEvent` models at the HTTP boundary."""

from __future__ import annotations

import json
from collections.abc import AsyncIterable, AsyncIterator
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import redact_sid, sanitize_mapping
from arodonata.core.events import DomainEvent


class SSEEvent(BaseModel):
    """Server-Sent Event wire model."""

    model_config = ConfigDict(extra="ignore")

    event: str = "message"
    data: dict[str, Any] = Field(default_factory=dict)
    id: str | None = None
    retry: int | None = None

    def encode(self) -> str:
        """Serialize the event into a standard SSE wire frame (`event: ...\\ndata: ...\\n\\n`)."""
        lines: list[str] = []
        if self.id is not None:
            lines.append(f"id: {redact_sid(self.id)}")
        if self.event:
            lines.append(f"event: {self.event}")
        if self.retry is not None:
            lines.append(f"retry: {self.retry}")
        safe_payload = sanitize_mapping(self.data)
        serialized = json.dumps(safe_payload, default=str, ensure_ascii=False)
        for line in serialized.splitlines() or ["{}"]:
            lines.append(f"data: {line}")
        return "\n".join(lines) + "\n\n"


def to_sse_event(domain_event: DomainEvent, *, event_id: str | None = None) -> SSEEvent:
    """Convert a typed `DomainEvent` (`SyncProgressEvent` or `CPCRUDEvent`) into an `SSEEvent`."""
    dumped = domain_event.model_dump(mode="json", exclude_none=True)
    dumped["details"] = domain_event.safe_details()
    if "message" in dumped and isinstance(dumped["message"], str):
        dumped["message"] = redact_sid(dumped["message"])
    if "error" in dumped and isinstance(dumped["error"], str):
        dumped["error"] = redact_sid(dumped["error"])
    sanitized = sanitize_mapping(dumped)
    return SSEEvent(
        event=domain_event.event_type,
        data=sanitized,
        id=event_id,
    )


async def stream_as_sse(events: AsyncIterable[DomainEvent]) -> AsyncIterator[SSEEvent]:
    """Convert an async stream of `DomainEvent` instances into `SSEEvent` items."""
    index = 0
    async for ev in events:
        index += 1
        yield to_sse_event(ev, event_id=str(index))


__all__ = [
    "SSEEvent",
    "stream_as_sse",
    "to_sse_event",
]
