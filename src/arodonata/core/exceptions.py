"""Custom exceptions for Arodonata library.

Provides a hierarchy of exceptions for proper error handling
throughout the library.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


class ArodonataError(Exception):
    """Base exception for all Arodonata errors."""

    def __init__(self, message: str, *args: object) -> None:
        self.message = message
        super().__init__(message, *args)


# Configuration Errors
class ConfigurationError(ArodonataError):
    """Configuration-related errors."""

    pass


class MissingConfigurationError(ConfigurationError):
    """Required configuration is missing."""

    pass


# Connection Errors
class ConnectionError(ArodonataError):
    """Connection-related errors."""

    pass


class DatabaseConnectionError(ConnectionError):
    """Database connection failed."""

    pass


class ApiConnectionError(ConnectionError):
    """API connection failed."""

    pass


class ServerUnreachableError(ApiConnectionError):
    """A management or domain server never answered at the address we used.

    Distinct from every other login failure because the remedy is different: a
    server that *answers* with a refusal (throttling, "Database revision is in
    progress") clears on its own, so backing off and retrying the same address is
    right. A server that answers nothing may simply not live at that address any
    more -- Check Point's `show-domains` reports a domain's active server, and
    that is exactly the value that can go stale. Retrying it cannot help; asking
    where the domain moved can.

    Carries `server_ip` so the log and the resulting AuthenticationError can name
    the address that went silent.
    """

    def __init__(self, message: str, *args: object, server_ip: str = "") -> None:
        self.server_ip = server_ip
        super().__init__(message, *args)


# Authentication Errors
class AuthenticationError(ArodonataError):
    """Authentication-related errors."""

    pass


class SessionExpiredError(AuthenticationError):
    """Session has expired and needs relogin."""

    pass


class InvalidCredentialsError(AuthenticationError):
    """Credentials are invalid."""

    pass


# API Errors
class ApiError(ArodonataError):
    """API operation errors."""

    def __init__(
        self,
        message: str,
        *args: object,
        err_code: str | int | None = None,
        err_message: str | None = None,
    ) -> None:
        self.err_code = err_code
        self.err_message = err_message
        super().__init__(message, *args)


class ApiCallError(ApiError):
    """API call failed."""

    pass


class ApiQueryError(ApiError):
    """API query failed."""

    pass


class ThrottlingError(ApiError):
    """API request was throttled."""

    pass


# Task Errors (self-managed show-task polling, asdk/task_waiter.py)
class TaskTimeoutError(ArodonataError, TimeoutError):
    """A Check Point task did not finish within the caller's timeout budget.

    Deliberately subclasses the builtin ``TimeoutError``: before self-managed
    polling, a task timeout surfaced as a bare ``TimeoutError`` from
    ``asyncio.wait_for``, so every existing ``except TimeoutError`` handler in a
    consuming application must keep catching this unchanged. What is new is only
    the message and the two attributes -- the task-id, last observed status and
    progress that the old bare ``TimeoutError`` never carried.
    """

    def __init__(
        self,
        message: str,
        *args: object,
        task_ids: Sequence[str] = (),
        statuses: Sequence[Any] = (),
    ) -> None:
        self.task_ids = list(task_ids)
        self.statuses = list(statuses)
        super().__init__(message, *args)


class TaskPollError(ApiCallError):
    """``show-task`` failed more times in a row than the waiter tolerates.

    Subclasses ``ApiCallError`` so broad handlers keep working. cpapi raised its
    own ``APIException`` here, which nothing in the compatibility contract names.
    """

    def __init__(
        self,
        message: str,
        *args: object,
        task_ids: Sequence[str] = (),
        err_code: str | int | None = None,
        err_message: str | None = None,
    ) -> None:
        self.task_ids = list(task_ids)
        super().__init__(message, *args, err_code=err_code, err_message=err_message)


# Cache Errors
class CacheError(ArodonataError):
    """Cache-related errors."""

    pass


class CacheNotInitializedError(CacheError):
    """Cache not initialized."""

    pass


# Client Errors
class ClientError(ArodonataError):
    """Client-related errors."""

    pass


class ClientClosedError(ClientError):
    """Client has been closed and cannot be used."""

    pass


class ServerNotFoundError(ClientError):
    """Management server not found in configuration."""

    pass


__all__ = [
    "ArodonataError",
    "ConfigurationError",
    "MissingConfigurationError",
    "ConnectionError",
    "DatabaseConnectionError",
    "ApiConnectionError",
    "ServerUnreachableError",
    "AuthenticationError",
    "SessionExpiredError",
    "InvalidCredentialsError",
    "ApiError",
    "ApiCallError",
    "ApiQueryError",
    "ThrottlingError",
    "TaskTimeoutError",
    "TaskPollError",
    "CacheError",
    "CacheNotInitializedError",
    "ClientError",
    "ClientClosedError",
    "ServerNotFoundError",
]
