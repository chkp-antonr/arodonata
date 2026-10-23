"""Provider-agnostic OpenTelemetry instrumentation, module gating, and attribute sanitization."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from arlogi.otel import set_trace_modules, traced
from opentelemetry import trace

from arodonata.core.errors import ConfigurationError, is_sensitive_key, redact_sid

__all__ = [
    "apply_trace_modules",
    "parse_trace_modules",
    "set_trace_modules",
    "span_attrs",
    "traced",
]

_TRUE_TOKENS: frozenset[str] = frozenset({"on", "true", "1", "yes", "enabled"})
_FALSE_TOKENS: frozenset[str] = frozenset({"off", "false", "0", "no", "disabled"})


def parse_trace_modules(spec: str) -> dict[str, bool]:
    """Parse comma-separated `module.prefix:on|off` rules into a boolean dictionary.

    Example:
        `"arodonata:on,arodonata.api.client:off"` -> `{"arodonata": True, "arodonata.api.client": False}`
    """
    if not spec or not spec.strip():
        return {}

    rules: dict[str, bool] = {}
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ConfigurationError(
                f"Invalid trace_modules entry {part!r}: expected '<module_prefix>:<on|off>' format."
            )
        prefix, state_raw = part.split(":", 1)
        module_prefix = prefix.strip()
        state_token = state_raw.strip().lower()
        if not module_prefix:
            raise ConfigurationError(f"Invalid trace_modules entry {part!r}: module prefix cannot be empty.")
        if state_token in _TRUE_TOKENS:
            rules[module_prefix] = True
        elif state_token in _FALSE_TOKENS:
            rules[module_prefix] = False
        else:
            raise ConfigurationError(
                f"Invalid trace_modules state {state_raw!r} for {module_prefix!r}: expected 'on' or 'off'."
            )
    return rules


def apply_trace_modules(spec_or_rules: str | dict[str, bool] | None) -> dict[str, bool]:
    """Apply module span gating rules ONLY when non-empty rules are provided.

    When `spec_or_rules` is empty (`""`, `None`, or `{}`), this function intentionally
    does NOT call `set_trace_modules({})` so any existing process-global trace rules
    configured by the host application are preserved.
    """
    if spec_or_rules is None:
        return {}
    rules = parse_trace_modules(spec_or_rules) if isinstance(spec_or_rules, str) else dict(spec_or_rules)
    if rules:
        set_trace_modules(rules)
    return rules


def _coerce_span_value(value: Any) -> bool | str | bytes | int | float | Sequence[bool | str | bytes | int | float]:
    """Coerce an attribute value into an OpenTelemetry-compatible primitive or sequence."""
    if isinstance(value, (bool, int, float, bytes)):
        return value
    if isinstance(value, str):
        return redact_sid(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        coerced_items: list[bool | str | bytes | int | float] = []
        for item in value:
            if isinstance(item, (bool, int, float, bytes)):
                coerced_items.append(item)
            else:
                coerced_items.append(redact_sid(str(item)))
        return coerced_items
    return redact_sid(str(value))


def span_attrs(**attrs: Any) -> None:
    """Attach `arodonata.<key>` attributes to the current recording OpenTelemetry span.

    - `None` values are omitted.
    - Sensitive keys (`sid`, `api_key`, `password`, `token`, `secret`, etc.) are never recorded.
    - String values are scrubbed via `redact_sid`.
    - Operates as a zero-overhead no-op when no recording span is active.
    """
    span = trace.get_current_span()
    if not span.is_recording():
        return

    for key, value in attrs.items():
        if value is None:
            continue
        if is_sensitive_key(key):
            continue
        namespaced_key = key if key.startswith("arodonata.") else f"arodonata.{key}"
        span.set_attribute(namespaced_key, _coerce_span_value(value))
