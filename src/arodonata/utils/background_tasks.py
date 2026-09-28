"""Shut down a client's background tasks without cutting them off mid-operation."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

# How long close() waits for background work (keepalive sweeps, startup cleanup)
# to finish on its own before cancelling it. The work is short -- a cache query
# and, at most, a few keepalive round trips -- so close() almost never waits.
DEFAULT_CLOSE_GRACE_SECONDS = 5.0


async def drain_background_tasks(tasks: Iterable[asyncio.Task[None]], grace: float) -> None:
    """Wait up to `grace` seconds for `tasks` to finish, then cancel the rest.

    Cancelling straight away interrupts a task wherever it happens to be: a
    keepalive sweep holding a pooled SQLite connection then fails the pool's
    rollback, and SQLAlchemy logs a CancelledError traceback. Waiting first lets
    such work release its resources normally.

    Never raises for the tasks' own failures: background work is best effort
    and must not break close().
    """
    pending = [t for t in tasks if not t.done()]
    finished = [t for t in tasks if t.done()]
    if pending and grace > 0:
        _done, still_running = await asyncio.wait(pending, timeout=grace)
        pending = list(still_running)
    for t in pending:
        t.cancel()
    await asyncio.gather(*finished, *pending, return_exceptions=True)
