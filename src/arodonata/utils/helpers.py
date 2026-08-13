"""Utility functions for Arodonata library."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from typing import Any

from ..logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Datetime Utilities
# =============================================================================


def utc_now_naive() -> datetime:
    """Get current time as naive UTC datetime.

    Returns:
        Current time with timezone info removed (database-compatible).

    Example:
        >>> now = utc_now_naive()
        >>> now.tzinfo is None
        True
    """
    return datetime.now(UTC).replace(tzinfo=None)


def to_db_datetime(dt: datetime | None) -> datetime | None:
    """Convert datetime to naive UTC for database storage.

    Args:
        dt: Datetime to convert (can be aware or naive).

    Returns:
        Naive UTC datetime, or None if input is None.

    Example:
        >>> from datetime import timezone, timedelta
        >>> dt = datetime(2025, 1, 1, tzinfo=timezone(timedelta(hours=2)))
        >>> result = to_db_datetime(dt)
        >>> result.tzinfo is None
        True
    """
    if dt is None:
        return None
    if isinstance(dt, str):
        # Parse string datetime if needed
        # Check Point API returns format like "2024-01-01 12:00:00"
        try:
            dt = datetime.fromisoformat(dt)
        except (ValueError, TypeError):
            return None
    if dt.tzinfo is None:
        # Already naive, assume UTC
        return dt
    # Convert to UTC and remove timezone info
    return dt.astimezone(UTC).replace(tzinfo=None)


def get_caller_name(levels: int = 2) -> str:
    """Get the name of the calling function/method.

    Args:
        levels: Number of frames to go back in the call stack.
                Default 2 returns the caller of the function that called get_caller_name.

    Returns:
        String in format "module.class.method" or "module.function"
    """
    frame = inspect.currentframe()
    try:
        for _ in range(levels):
            if frame is not None:
                frame = frame.f_back

        if frame is None:
            return "<unknown>"

        # Get function/method name
        code = frame.f_code
        func_name = code.co_name

        # Try to get class name if it's a method
        local_vars = frame.f_locals
        if "self" in local_vars:
            cls = type(local_vars["self"])
            return f"{cls.__module__}.{cls.__name__}.{func_name}"
        elif "cls" in local_vars:
            cls = local_vars["cls"]
            return f"{cls.__module__}.{cls.__name__}.{func_name}"

        # Just a function
        module = frame.f_globals.get("__name__", "<module>")
        return f"{module}.{func_name}"

    finally:
        del frame


def normalize_input_to_list(
    value: str | list[str] | set[str] | None,
) -> list[str]:
    """Normalize various input types to a list of strings.

    Args:
        value: Input that could be a string, list, set, or None.
               Strings are split by comma.

    Returns:
        List of non-empty stripped strings.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, set):
        return list(value)
    return list(value)


def make_composite_key(*parts: str) -> str:
    """Create a composite key from parts.

    Args:
        *parts: String parts to join with colon separator.

    Returns:
        Colon-separated composite key.
    """
    return ":".join(parts)


def parse_composite_key(key: str) -> list[str]:
    """Parse a composite key into parts.

    Args:
        key: Colon-separated composite key.

    Returns:
        List of string parts.
    """
    return key.split(":")


def safe_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely navigate nested dict structure.

    Args:
        data: Dictionary to navigate.
        *keys: Keys to traverse in order.
        default: Value to return if any key is missing.

    Returns:
        Value at the nested key path, or default if not found.
    """
    result: Any = data
    for key in keys:
        if not isinstance(result, dict):
            return default
        result = result.get(key)
        if result is None:
            return default
    return result


__all__ = [
    "get_caller_name",
    "normalize_input_to_list",
    "make_composite_key",
    "parse_composite_key",
    "safe_get",
    "extract_data_from_response",
    "extract_objects_from_response",
    "utc_now_naive",
    "to_db_datetime",
]


# =============================================================================
# Response Extraction Utilities
# =============================================================================


def extract_data_from_response(response: Any) -> Any:
    """Extract data from API response with robust handling of various response types.

    This function handles:
    - Pydantic v2 models (using model_dump())
    - Objects with .data attribute (ApiCallResult, ApiQueryResult)
    - Raw dictionaries
    - None or missing responses

    Args:
        response: API response object from arodonata (ApiCallResult, ApiQueryResult,
                  or raw dict).

    Returns:
        Extracted data, typically a dict for single objects or the raw data type.
        Returns None if response is falsy or has no data attribute.

    Examples:
        >>> from arodonata.utils import extract_data_from_response
        >>> result = await client.api_call("mgmt1", "show-host", {"name": "my-host"})
        >>> data = extract_data_from_response(result)
        >>> print(data.get("ip-address"))

    """
    if not response:
        logger.debug("Empty or None response provided")
        return None

    # Handle Pydantic models (ApiCallResult, ApiQueryResult)
    if hasattr(response, "data"):
        data = response.data
        if data is None:
            return None

        # Handle Pydantic v2 models with model_dump
        if hasattr(data, "model_dump"):
            try:
                return data.model_dump()
            except Exception as e:
                logger.warning("Failed to model_dump response data: %s", e)
                return data

        # Handle Pydantic v1 models with dict()
        if hasattr(data, "dict"):
            try:
                return data.dict()
            except Exception as e:
                logger.warning("Failed to dict() response data: %s", e)
                return data

        return data

    # Handle raw dicts
    if isinstance(response, dict):
        return response.get("data", response)

    logger.debug("Unknown response type: %s", type(response).__name__)
    return None


def _normalize_object_to_dict(obj: Any) -> dict[str, Any]:
    """Helper to convert a single object to dictionary."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()  # type: ignore[no-any-return]
    if hasattr(obj, "dict"):
        return obj.dict()  # type: ignore[no-any-return]
    return obj  # type: ignore[no-any-return]


def _extract_from_data_attr(data: Any) -> list[dict[str, Any]]:
    """Helper to extract objects from a data attribute or dictionary."""
    if hasattr(data, "objects") and data.objects:
        if isinstance(data.objects, list):
            return [_normalize_object_to_dict(obj) for obj in data.objects]

    if hasattr(data, "object") and data.object:
        return [_normalize_object_to_dict(data.object)]

    if isinstance(data, dict):
        if "objects" in data and data["objects"]:
            objects = data["objects"]
            if isinstance(objects, list):
                return [_normalize_object_to_dict(obj) for obj in objects]
        if "object" in data and data["object"]:
            return [_normalize_object_to_dict(data["object"])]

    if isinstance(data, list):
        return [_normalize_object_to_dict(obj) for obj in data]

    return []


def extract_objects_from_response(response: Any) -> list[dict[str, Any]]:
    """Extract objects from API response in a consistent format.

    Handles various response structures from Check Point API:
    - response.data.objects (list of objects)
    - response.data.object (single object, returned as list)
    - response.data (direct dict/list)
    - Objects with model_dump() for Pydantic serialization

    Args:
        response: API response object (ApiCallResult, ApiQueryResult, or raw dict).

    Returns:
        List of object dictionaries. Empty list if:
        - Response is falsy or failed
        - No objects found
        - Response structure is unrecognized

    Examples:
        >>> from arodonata.utils import extract_objects_from_response
        >>> result = await client.api_call("mgmt1", "show-hosts")
        >>> hosts = extract_objects_from_response(result)
        >>> for host in hosts:
        ...     print(host.get("name"), host.get("ip-address"))

    """
    if not response:
        logger.debug("Empty or None response provided")
        return []

    # Check success flag for ApiCallResult/ApiQueryResult
    if hasattr(response, "success") and not response.success:
        logger.debug("Response indicates failure: %s", getattr(response, "message", ""))
        return []

    # Handle responses with .data attribute
    if hasattr(response, "data"):
        result = _extract_from_data_attr(response.data)
        if result:
            return result
        logger.debug("Response.data present but no objects found")
        return []

    # Handle raw dict responses (without .data attribute)
    if isinstance(response, dict):
        result = _extract_from_data_attr(response)
        if result:
            return result
        if "data" in response:
            result_nested = _extract_from_data_attr(response["data"])
            if result_nested:
                return result_nested

    logger.debug("No objects extracted from response type: %s", type(response).__name__)
    return []
