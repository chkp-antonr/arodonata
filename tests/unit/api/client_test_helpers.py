"""Shared helpers for the ArodonataClient facade test files.

Canonical construction and seam-injection utilities used by
``test_client_lifecycle.py``, ``test_client_api_call.py``, and
``test_client_cache_mode.py``. Keeping them here means each private-attribute
coupling to the source module lives in exactly one place.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

from arodonata.api.client import ArodonataClient
from arodonata.config import ArodonataSettings

# Message fragment raised by ArodonataClient._ensure_open on a closed client.
# NOTE: the source currently raises RuntimeError (not the exported
# ClientClosedError) — reported upstream as a source inconsistency. If the
# wording changes, update this one constant.
CLOSED_CLIENT_MATCH = "has been closed"


def make_client(
    *,
    engine: object | None = None,
    settings: ArodonataSettings | None = None,
    db: object | None = None,
    cache: object | None = None,
    mgmt: object | None = None,
    **kwargs: Any,
) -> ArodonataClient:
    """Build a ArodonataClient with every heavy dependency injected as a double.

    Defaults produce an API-key-mode client whose db/cache/mgmt are mocks, so
    construction and delegation can be exercised without any real backend.
    Extra ``kwargs`` (e.g. ``cache_mode``, ``cache_ttl``) are forwarded to the
    ArodonataClient constructor.
    """
    return ArodonataClient(
        engine=engine or MagicMock(),
        settings=settings or ArodonataSettings(),
        _db=db or AsyncMock(),
        _cache=cache or AsyncMock(),
        _mgmt=mgmt or AsyncMock(),
        **kwargs,
    )


def install_object_service(client: ArodonataClient, svc: object) -> None:
    """Install a test double as the client's ObjectService.

    This is the ONE place in the test suite coupled to the private
    ``_object_service_instance`` memoization attribute behind the lazy
    ``ArodonataClient._object_service`` property — no public injection seam
    exists for the ObjectService.
    """
    client._object_service_instance = svc


def coordinator_default_policy(client: ArodonataClient):
    """Return the refresh coordinator's default CachePolicy.

    This is the ONE place in the test suite coupled to the private
    ``_orchestration._coordinator`` chain — the default policy has no public
    accessor on the client facade.
    """
    return client._orchestration._coordinator.default_policy
