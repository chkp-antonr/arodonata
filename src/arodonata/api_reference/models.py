"""Pydantic v2 models and TypedDict definitions for the Check Point API Reference Engine."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiValidationIssue(BaseModel):
    """Single validation error or warning reported by `validate_payload`."""

    model_config = ConfigDict(extra="allow")

    code: Literal[
        "unknown_command",
        "unsupported_command_version",
        "unknown_field",
        "unsupported_field_version",
        "missing_required_field",
        "missing_alternative_group",
        "conflicting_alternatives",
        "invalid_type",
        "invalid_enum_value",
    ]
    message: str
    field: str | None = None
    allowed_values: list[str] = Field(default_factory=list)
    supported_versions: list[str] = Field(default_factory=list)


class ApiPayloadValidationResult(BaseModel):
    """Structured result returned by `validate_payload`."""

    model_config = ConfigDict(extra="allow")

    valid: bool
    command: str
    target_version: str
    error_count: int = 0
    errors: list[ApiValidationIssue] = Field(default_factory=list)
    suggestions: list[dict[str, Any]] = Field(default_factory=list)


__all__ = [
    "ApiPayloadValidationResult",
    "ApiValidationIssue",
]
