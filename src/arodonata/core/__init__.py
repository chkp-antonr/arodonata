"""Core domain layer - protocols, models, and exceptions.

This module contains the foundational abstractions and domain models
for the Arodonata library.
"""

from .cache_mode import CacheMode
from .cache_policy import CachePolicy
from .cache_refresh_coordinator import CacheRefreshCoordinator
from .change_processor import ChangeProcessor, ChangeType, ObjectChange
from .exceptions import (
    ApiCallError,
    ApiConnectionError,
    ApiError,
    ApiQueryError,
    ArodonataError,
    AuthenticationError,
    CacheError,
    CacheNotInitializedError,
    ClientClosedError,
    ClientError,
    ConfigurationError,
    ConnectionError,
    DatabaseConnectionError,
    InvalidCredentialsError,
    MissingConfigurationError,
    ServerNotFoundError,
    ServerUnreachableError,
    SessionExpiredError,
    TaskPollError,
    TaskTimeoutError,
    ThrottlingError,
)
from .orchestration import CacheOrchestrationService
from .protocols import (
    IApiTransport,
    ICacheRepository,
    ILoginCoordinator,
    IRateLimiter,
    IServerRegistry,
    RawApiResponse,
    RefreshMode,
    ServerConfig,
    SIDRecord,
)
from .session_tracker import SessionChange, SessionChangeTracker

__all__ = [
    # Core types
    "CacheMode",
    "CachePolicy",
    "CacheRefreshCoordinator",
    "SessionChangeTracker",
    "SessionChange",
    "CacheOrchestrationService",
    "ChangeProcessor",
    "ChangeType",
    "ObjectChange",
    # Protocols
    "ICacheRepository",
    "IApiTransport",
    "IServerRegistry",
    "IRateLimiter",
    "ILoginCoordinator",
    "RawApiResponse",
    "ServerConfig",
    "SIDRecord",
    "RefreshMode",
    # Exceptions
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
