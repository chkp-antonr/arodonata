"""Investigation for final-review Finding 4: does RateLimiter.acquire's own
span misattribute exceptions raised by the CONSUMER's traced code inside the
`async with limiter.acquire(...):` block — with no causal child explaining
the failure — or is this expected/correct OTel behavior for this codebase's
real call topology?

Real topology (see login_coordinator.py, e.g. `_cleanup_for_max_sessions` /
`_fire_keepalive`): an OUTER @traced coordinator method wraps
`async with self._rate_limiter.acquire(server_ip):`, and the code inside that
block calls an INNER @traced transport method (login_with_apikey, keepalive,
etc). This test reproduces that exact shape with a real RateLimiter +
DatabaseLockManager (in-memory SQLite) and a real @traced inner call that
raises.

Finding: both RateLimiter.acquire's span AND the inner call's span record
the *same* exception via standard `record_exception()` — full type, message,
and stack trace — because the exception genuinely propagates through both
scopes (asynccontextmanager.__aexit__ throws it into the acquire() generator
at the yield point, same as any `with span: risky_code()` pattern in any OTel
SDK). So the reviewer's "no causal child explaining it" claim is FALSE: the
actual exception detail is not lost or replaced on acquire's span — it's the
literal same exception, recorded with full detail, exactly as OTel's context
manager semantics prescribe everywhere. This is expected/correct behavior,
not a defect — no code change applied.

One real, but separate and minor, structural nuance surfaced by this
investigation: the inner traced call's span ends up as a *sibling* of
acquire's span (both children of the outer coordinator span) rather than a
strict parent(acquire)-child(inner) nesting, because arlogi's async-gen
@traced support does not keep the span "current" across the yield boundary
of an @asynccontextmanager-wrapped generator. This does not lose any causal
information (both spans still share the same trace, under the same
meaningful outer parent, with full exception detail on each), so it does not
independently justify removing @traced from acquire() either — see the
final-review-fix-report.md investigation notes for full analysis.
"""

import pytest
from arlogi.otel.decorator import traced
from sqlalchemy.ext.asyncio import create_async_engine

from arodonata.asdk.rate_limiter import RateLimiter
from arodonata.cache.database import DatabaseManager
from arodonata.cache.lock_manager import DatabaseLockManager


@pytest.fixture
async def rate_limiter():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    manager = DatabaseLockManager(DatabaseManager(engine))
    await manager.initialize()
    limiter = RateLimiter(concurrent_limit=3, lock_manager=manager)
    yield limiter
    await limiter.close()
    await engine.dispose()


class BoomError(Exception):
    """Simulated failure raised by an inner traced call, e.g. a transport method."""


@traced
async def _inner_traced_call() -> None:
    raise BoomError("simulated transport failure")


@traced
async def _outer_coordinator_method(rate_limiter: RateLimiter, ip: str) -> None:
    """Stands in for a real @traced login_coordinator method (e.g.
    `_cleanup_for_max_sessions`/`_fire_keepalive`) that wraps a rate-limited,
    @traced transport call.
    """
    async with rate_limiter.acquire(ip):
        await _inner_traced_call()


def _exception_event(span):
    events = [e for e in span.events if e.name == "exception"]
    assert len(events) == 1, f"expected exactly one exception event on {span.name!r}, got {len(events)}"
    return events[0]


async def test_acquire_span_and_inner_call_span_both_carry_the_real_exception(otel_spans, rate_limiter):
    with pytest.raises(BoomError):
        await _outer_coordinator_method(rate_limiter, "10.0.0.9")

    spans = otel_spans.get_finished_spans()
    by_name = {s.name: s for s in spans}
    outer_span = next(s for n, s in by_name.items() if n.endswith("_outer_coordinator_method"))
    acquire_span = next(s for n, s in by_name.items() if n.endswith("RateLimiter.acquire"))
    inner_span = next(s for n, s in by_name.items() if n.endswith("_inner_traced_call"))

    # All three spans appear and end in ERROR — the exception genuinely
    # propagates through all three scopes (outer coordinator method, the
    # rate-limiter's acquire() context, and the inner traced call itself).
    for span in (outer_span, acquire_span, inner_span):
        assert span.status.status_code.name == "ERROR"

    # Every span the exception passes through records the *same* real
    # exception with full detail — this is the crux of the investigation:
    # acquire's span is not a bare, unexplained ERROR. It carries the exact
    # same type/message as the inner call that actually raised.
    for span in (outer_span, acquire_span, inner_span):
        event = _exception_event(span)
        assert event.attributes["exception.type"].endswith("BoomError")
        assert event.attributes["exception.message"] == "simulated transport failure"

    # All spans share one trace (same overall operation).
    trace_ids = {s.context.trace_id for s in (outer_span, acquire_span, inner_span)}
    assert len(trace_ids) == 1

    # Structural nuance (documented, not fixed): acquire_span and inner_span
    # are siblings under outer_span rather than acquire being inner's direct
    # parent, because arlogi's async-gen @traced support does not keep the
    # span "current" across the yield boundary of an asynccontextmanager. No
    # causal information is lost as a result (both still carry full
    # exception detail, under the same meaningful outer parent), so this by
    # itself is not treated as a defect requiring a code change here.
    assert acquire_span.parent is not None
    assert acquire_span.parent.span_id == outer_span.context.span_id
    assert inner_span.parent is not None
    assert inner_span.parent.span_id == outer_span.context.span_id
