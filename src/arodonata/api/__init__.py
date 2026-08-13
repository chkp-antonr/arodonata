"""Public API layer - main entry point for applications.

This module exports the main client for Arodonata.

Example:
    from sqlalchemy.ext.asyncio import create_async_engine
    from arodonata import ArodonataClient, ArodonataSettings

    settings = ArodonataSettings()
    engine = create_async_engine(settings.database_url, ...)

    client = ArodonataClient(engine=engine, settings=settings)
    async with client:
        result = await client.api_call("mgmt1", "show-hosts")

    await engine.dispose()
"""

from ..core import CacheMode

# V2: Export typed models for convenience
from ..models import Domain, Gateway, Group, Host, Network
from .client import ArodonataClient
from .schemas import (
    ApiCallResult,
    ApiQueryResult,
    CompleteEvent,
    ErrorEvent,
    ResultEvent,
    SSEEvent,
    SSEEventType,
)

__all__ = [
    "ArodonataClient",
    "ApiCallResult",
    "ApiQueryResult",
    "SSEEvent",
    "SSEEventType",
    "ResultEvent",
    "ErrorEvent",
    "CompleteEvent",
    # V2 models
    "Domain",
    "Gateway",
    "Host",
    "Network",
    "Group",
    "CacheMode",
]
