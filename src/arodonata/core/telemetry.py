"""Provider-agnostic OpenTelemetry instrumentation, module gating, and attribute sanitization."""

from __future__ import annotations

import contextlib
import functools
import inspect
from collections.abc import Callable, Sequence
from typing import Any, overload

from arlogi.otel import set_trace_modules
from arlogi.otel import traced as _arlogi_traced
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


def _sanitize_exception_chain(exc: BaseException, seen: set[int] | None = None) -> None:
    """Recursively scrub SID/secret patterns from `exc.args`, `__cause__`, and `__context__` in-place."""
    if seen is None:
        seen = set()
    obj_id = id(exc)
    if obj_id in seen:
        return
    seen.add(obj_id)

    if exc.args:
        new_args = tuple(redact_sid(arg) if isinstance(arg, str) else arg for arg in exc.args)
        if new_args != exc.args:
            with contextlib.suppress(Exception):
                exc.args = new_args
    if hasattr(exc, "message") and isinstance(exc.message, str):
        with contextlib.suppress(Exception):
            exc.message = redact_sid(exc.message)

    if exc.__cause__ is not None:
        _sanitize_exception_chain(exc.__cause__, seen)
    if exc.__context__ is not None:
        _sanitize_exception_chain(exc.__context__, seen)


@overload
def traced[**P, R](func: Callable[P, R]) -> Callable[P, R]: ...
@overload
def traced[**P, R](
    *, name: str | None = None, attrs: dict[str, Any] | None = None
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def traced[**P, R](
    func: Callable[P, R] | None = None,
    *,
    name: str | None = None,
    attrs: dict[str, Any] | None = None,
) -> Any:
    """Wrap a function in `@arlogi.otel.traced` while scrubbing chained `__cause__`/`__context__` exceptions."""

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        if inspect.isasyncgenfunction(fn):

            @functools.wraps(fn)
            async def agen_sanitized(*args: Any, **kwargs: Any) -> Any:
                try:
                    async for item in fn(*args, **kwargs):
                        yield item
                except Exception as exc:
                    _sanitize_exception_chain(exc)
                    raise

            target: Any = agen_sanitized
        elif inspect.isgeneratorfunction(fn):

            @functools.wraps(fn)
            def gen_sanitized(*args: Any, **kwargs: Any) -> Any:
                try:
                    yield from fn(*args, **kwargs)
                except Exception as exc:
                    _sanitize_exception_chain(exc)
                    raise

            target = gen_sanitized
        elif inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_sanitized(*args: P.args, **kwargs: P.kwargs) -> R:
                try:
                    return await fn(*args, **kwargs)  # type: ignore[no-any-return]
                except Exception as exc:
                    _sanitize_exception_chain(exc)
                    raise

            target = async_sanitized
        else:

            @functools.wraps(fn)
            def sync_sanitized(*args: P.args, **kwargs: P.kwargs) -> R:
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:
                    _sanitize_exception_chain(exc)
                    raise

            target = sync_sanitized

        if name is not None or attrs is not None:
            return _arlogi_traced(name=name, attrs=attrs)(target)
        return _arlogi_traced(target)

    return decorate(func) if func is not None else decorate
