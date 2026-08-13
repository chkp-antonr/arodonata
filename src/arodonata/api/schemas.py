"""Public API response schemas for Arodonata library.

These Pydantic models provide type-safe response handling
and validation for API operations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class SSEEventType(StrEnum):
    """Server-Sent Event types for streaming operations."""

    START = "start"
    LOG = "log"
    COMPLETE = "complete"
    RESULT = "result"
    WARNING = "warning"
    ERROR = "error"


class ApiCallResult(BaseModel):
    """Result of an API call operation."""

    success: bool = Field(description="Whether the call succeeded")
    data: dict[str, Any] | None = Field(default=None, description="Response data from API")
    message: str = Field(default="", description="Error or status message")
    code: str = Field(default="", description="Error code if failed")

    @property
    def has_data(self) -> bool:
        """Check if result has data."""
        return self.data is not None and len(self.data) > 0


class ApiQueryResult(BaseModel):
    """Result of an API query operation."""

    success: bool = Field(description="Whether the query succeeded")
    data: list[dict[str, Any]] | dict[str, Any] | None = Field(
        default=None, description="Response data from API (list for success, dict for errors)"
    )
    objects: list[dict[str, Any]] = Field(default_factory=list, description="Query result objects")
    message: str = Field(default="", description="Error or status message")
    code: str = Field(default="", description="Error code if failed")
    total: int = Field(default=0, description="Total number of results")
    res_obj: dict[str, Any] | None = Field(
        default=None, description="The raw response object when data cannot be processed normally"
    )

    @model_validator(mode="before")
    @classmethod
    def handle_response_data(cls, values: Any) -> Any:
        """Handle cases where data is a list, dict, or error response.

        For successful responses with list data, store in objects for easier access.
        For error responses with dict data, extract error details into code/message.
        """
        if isinstance(values, dict):
            data = values.get("data")

            # Handle error responses where data is a dict with error details
            if isinstance(data, dict):
                # Extract error code/message from data dict if not already set
                if not values.get("code"):
                    values["code"] = data.get("code", "")
                if not values.get("message"):
                    values["message"] = data.get("message", "")
                # Store error dict in res_obj for reference
                if not values.get("res_obj"):
                    values["res_obj"] = {"error_data": data}

            # Handle successful responses where data is a list
            elif isinstance(data, list) and not values.get("objects"):
                # Store the list as objects for easier access
                values["objects"] = data
                values["total"] = len(data)
                # Also store the raw response in res_obj for reference
                if not values.get("res_obj"):
                    values["res_obj"] = {"data": data}

        return values

    @property
    def has_objects(self) -> bool:
        """Check if result has objects."""
        return len(self.objects) > 0


class SSEEvent(BaseModel):
    """Server-Sent Event for streaming operations."""

    event_type: SSEEventType = Field(description="Type of event")
    data: dict[str, Any] = Field(default_factory=dict, description="Event payload")
    message: str | None = Field(default=None, description="Optional status or log message")
    asset_id: str | None = Field(default=None, description="Optional asset identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Event timestamp",
    )
    mgmt_name: str | None = Field(default=None, description="Management server name")
    domain: str | None = Field(default=None, description="Domain name")

    def to_sse_format(self) -> str:
        """Format as Server-Sent Event string."""
        return f"event: {self.event_type.value}\ndata: {self.model_dump_json()}\n\n"


class ResultEvent(SSEEvent):
    """Result data event."""

    event_type: SSEEventType = SSEEventType.RESULT
    result_type: str = Field(default="", description="Type of result (asset, gateway, etc)")
    count: int = Field(default=0, ge=0)


class ErrorEvent(SSEEvent):
    """Error event."""

    event_type: SSEEventType = SSEEventType.ERROR
    error_code: str = Field(default="")
    error_message: str = Field(default="")


class CompleteEvent(SSEEvent):
    """Collection complete event."""

    event_type: SSEEventType = SSEEventType.COMPLETE
    total_results: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0)


__all__ = [
    "SSEEventType",
    "ApiCallResult",
    "ApiQueryResult",
    "SSEEvent",
    "ResultEvent",
    "ErrorEvent",
    "CompleteEvent",
]
