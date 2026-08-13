"""Common base models for arodonata."""

from typing import Any

from pydantic import BaseModel, Field


class BaseModelWithRaw(BaseModel):
    """Base model with raw_data field."""

    raw_data: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "ignore"}
