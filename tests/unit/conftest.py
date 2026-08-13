"""Pytest configuration for unit tests.

Mocks the distributed_lock manager so decorated methods run without a database.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture(scope="function", autouse=True)
def mock_lock_manager():
    """Mock the lock manager to avoid database initialization in unit tests."""
    mock_lock_context = MagicMock()
    mock_lock_context.renew_if_needed = AsyncMock()

    mock_manager = MagicMock()
    mock_manager.initialize = AsyncMock()
    mock_manager.acquire_lock = AsyncMock(return_value=mock_lock_context)
    mock_manager.release_lock = AsyncMock()
    mock_manager.DEFAULT_TTL_ASSET_REFRESH = 300

    async def _get_mock_lock_manager(*args, **kwargs):
        return mock_manager

    with patch("arodonata.cache.lock_manager._get_global_lock_manager", _get_mock_lock_manager):
        yield mock_manager


_otel_state: dict[str, object] = {}


@pytest.fixture
def otel_spans():
    """Shared in-memory TracerProvider (set up once, reused for the whole
    session); cleared per test. A fresh TracerProvider per test does NOT
    work here: arlogi's @traced resolves trace.get_tracer() once at
    decoration time, and OpenTelemetry's ProxyTracer permanently caches the
    first real TracerProvider it observes — swapping the global provider
    after that has no effect on already-decorated production methods.
    """
    from arlogi.otel.decorator import set_trace_modules
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    if "exporter" not in _otel_state:
        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _otel_state["exporter"] = exporter

    exporter = _otel_state["exporter"]
    exporter.clear()
    yield exporter
    set_trace_modules(None)
