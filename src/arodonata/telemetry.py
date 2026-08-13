"""Span attribute helper for arodonata OTEL instrumentation.

arodonata is a provider-agnostic span producer: it depends on opentelemetry-api
only and never configures a TracerProvider. Without a provider every call here
is a no-op. Never pass credentials, full SIDs, or customer payloads.
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace


def span_attrs(**attrs: Any) -> None:
    """Set arodonata.*-namespaced attributes on the current span; None skipped."""
    span = trace.get_current_span()
    for key, value in attrs.items():
        if value is not None:
            span.set_attribute(f"arodonata.{key}", value)
