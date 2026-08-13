"""Custom exceptions for Arodonata library.

Provides a hierarchy of exceptions for proper error handling
throughout the library.
"""

from __future__ import annotations


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
    "AuthenticationError",
    "SessionExpiredError",
    "InvalidCredentialsError",
    "ApiError",
    "ApiCallError",
    "ApiQueryError",
    "ThrottlingError",
    "CacheError",
    "CacheNotInitializedError",
    "ClientError",
    "ClientClosedError",
    "ServerNotFoundError",
]
