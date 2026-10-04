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


class PublishedHeadError(Exception):
    """``show-last-published-session`` could not tell where a domain's head is (failed call, exception, no timestamp)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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


# TLS identity and socket timeouts (asdk/tls.py)
class ServerIdentityError(ArodonataError):
    """A Check Point server's TLS certificate is not the one trusted for that address. Nothing was sent.

    Never retried: a different certificate does not fix itself. Deliberately not an ``OSError`` (cpapi would
    re-send), an ``ApiConnectionError`` (login would re-resolve the domain) or an ``AuthenticationError`` (login
    would wrap and retry it).
    """

    def __init__(
        self,
        message: str,
        *args: object,
        host: str = "",
        port: int = 0,
        presented_sha256: str = "",
        presented_sha1: str = "",
        expected_sha256: str = "",
        source: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.presented_sha256 = presented_sha256
        self.presented_sha1 = presented_sha1
        self.expected_sha256 = expected_sha256
        self.source = source
        super().__init__(message, *args)


class CertificateMismatchError(ServerIdentityError):
    """The server presented a different certificate than the one recorded or pinned for it."""


class UnknownServerCertificateError(ServerIdentityError):
    """``ARODONATA_TLS_TRUST=pinned`` and the presented certificate is not trusted anywhere."""


class TrustStoreError(ConfigurationError):
    """The TLS trust store cannot be read, is unsafe (owner/permissions), is corrupt, or cannot be written."""


class ApiTimeoutError(ArodonataError, TimeoutError):
    """A socket connect or read to a Check Point server timed out. The request is never re-sent after a timeout.

    (cpapi may already have re-sent it once after a dropped connection, before the timeout: Backlog #30.)
    A ``TimeoutError`` subclass like ``TaskTimeoutError``, so existing ``except TimeoutError`` handlers keep working.
    Every field has a default, so the error can be unpickled (the built-in reduce restores the fields).
    """

    def __init__(
        self,
        message: str,
        *args: object,
        phase: str = "",
        host: str = "",
        port: int = 0,
        timeout: float = 0.0,
        command: str = "",
    ) -> None:
        self.phase = phase
        self.host = host
        self.port = port
        self.timeout = timeout
        self.command = command
        super().__init__(message, *args)


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
    "PublishedHeadError",
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
