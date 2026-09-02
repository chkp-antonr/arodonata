"""Arodonata - Check Point API Operations Library.

A comprehensive Python library for Check Point management and monitoring operations
with async support, automatic session management, and intelligent caching.

Example:
    from sqlalchemy.ext.asyncio import create_async_engine
    from arodonata import ArodonataClient, ArodonataSettings

    # Main app creates engine from its own database config
    engine = create_async_engine("postgresql+asyncpg://...")

    # Arodonata settings contain only mgmt server config
    settings = ArodonataSettings(
        mgmt_names="mgmt1,mgmt2",
        mgmt_servers="10.0.0.1,10.0.0.2",
        api_keys="actual_key1,actual_key2",
    )

    client = ArodonataClient(engine=engine, settings=settings)
    async with client:
        result = await client.api_call("mgmt1", "show-hosts")
        print(result.data)

    await engine.dispose()
"""

__version__ = "1.7.0"
__author__ = "Anton Razumov"
__license__ = "MIT"

# Main public API
from .api import (
    ApiCallResult,
    ApiQueryResult,
    ArodonataClient,
    SSEEvent,
    SSEEventType,
)

# Cache access
from .cache import Asset, CacheRepository, CPObject, DatabaseManager, Domain, SIDCache

# Configuration
from .config import GLOBAL_DOMAIN_NAME, ArodonataSettings

# Exceptions
from .core import (
    ApiCallError,
    ApiError,
    ArodonataError,
    AuthenticationError,
    CacheError,
    ClientClosedError,
    ClientError,
    ConfigurationError,
    MissingConfigurationError,
    RefreshMode,
    ServerNotFoundError,
    SessionExpiredError,
)

# Utilities
from .db_utils import safe_init_table
from .utils import extract_data_from_response, extract_objects_from_response

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    # Main API
    "ArodonataClient",
    "ArodonataSettings",
    "GLOBAL_DOMAIN_NAME",
    # Response types
    "ApiCallResult",
    "ApiQueryResult",
    "SSEEvent",
    "SSEEventType",
    # Cache
    "DatabaseManager",
    "CacheRepository",
    "SIDCache",
    "Asset",
    "CPObject",
    "Domain",
    # Exceptions
    "ArodonataError",
    "ConfigurationError",
    "MissingConfigurationError",
    "ApiError",
    "ApiCallError",
    "AuthenticationError",
    "SessionExpiredError",
    "CacheError",
    "ClientError",
    "ClientClosedError",
    "ServerNotFoundError",
    # Enums
    "RefreshMode",
    # Utilities
    "extract_data_from_response",
    "extract_objects_from_response",
    "safe_init_table",
]
