"""Readiness gate for the integration suite: is the lab's API answering at all?

The lab's Check Point management server idles between runs and can take a
minute or two to answer its first request afterwards (a 2026-09-27 b1 run spent
142 s in fixture setup before the first test). When it does not answer, every
test in the bucket fails the same way -- 45 red items and no line saying "the
server is down". This gate runs once per session, before anything touches the
lab or the cache DB, and turns that into one decision: wait for the server to
wake within a budget, or refuse to start the run with a message naming the
server and the last error.

The probe sends `show-api-versions` without a session. The lab refuses that
("Missing header: [X-chkp-sid]"), but the refusal is a Check Point JSON error
body produced by the API server itself -- proof that the server is up and
processing requests, which is all the gate needs. No login is involved: the lab
allows about three logins per minute per user, and the baseline snapshot needs
all of them, so a login-based probe would spend the allowance before the first
test. See `answered_by_api` for what counts as an answer.

Tunables (read by the conftest fixture, not here):

    ARODONATA_TEST_READY_WAIT   total seconds to wait for a first answer
                                (default DEFAULT_READY_WAIT_SECONDS; 0 = one probe)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from arodonata.asdk.transport import ApiTransport

log = logging.getLogger(__name__)

# 180 s is a little over the longest wake-up seen so far (~110 s of a 142 s setup).
DEFAULT_READY_WAIT_SECONDS = 180
# One probe's own HTTP timeout. Short on purpose: a probe that hangs for the
# client's default 120 s would eat most of the budget in one attempt.
PROBE_TIMEOUT_SECONDS = 10
PROBE_INTERVAL_SECONDS = 10

Probe = Callable[[], Awaitable[None]]


class LabNotReady(RuntimeError):
    """The lab API did not answer within the readiness budget."""


def answered_by_api(response: dict[str, Any]) -> bool:
    """Whether a transport response came from the Check Point API server itself.

    True for a successful call and for a Check Point JSON error body (a dict
    with a string ``code`` such as ``generic_err_missing_required_header``):
    both are produced by the API server, so either proves it is up. False for
    anything else -- notably an HTML error page, which cpapi wraps as
    ``{"errors": [{"message": <html>}]}`` with no ``code``: that is the gateway
    answering for a CPM that is still down, the state the gate must wait through.
    """
    if response.get("success"):
        return True
    data = response.get("data")
    return isinstance(data, dict) and isinstance(data.get("code"), str) and bool(data["code"])


def api_versions_probe(mgmt_ip: str, port: int | None = None) -> Probe:
    """Probe that sends `show-api-versions` to `mgmt_ip` with no session header.

    Raises on a transport failure (socket refused, TLS, HTTP timeout) and on
    any answer that did not come from the API server (see `answered_by_api`),
    so `wait_until_ready` treats both as "not ready yet". Nothing is logged in,
    nothing is mutated.
    """
    transport = ApiTransport()

    async def _probe() -> None:
        response = await transport.api_call(
            mgmt_ip,
            sid=None,  # type: ignore[arg-type]  # no header at all; "" would send an empty one
            command="show-api-versions",
            wait_for_task=False,
            timeout=PROBE_TIMEOUT_SECONDS,
            port=port,
        )
        if not answered_by_api(response):
            raise LabNotReady(
                f"show-api-versions was not answered by the API server: {response.get('message') or response}"
            )

    return _probe


async def wait_until_ready(
    *,
    probe: Probe,
    budget: float = DEFAULT_READY_WAIT_SECONDS,
    interval: float = PROBE_INTERVAL_SECONDS,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> float:
    """Poll `probe` until it returns; give up once the next probe would land past `budget`.

    Probes run at t = 0, interval, 2*interval, ... while t <= budget, so the
    budget is the latest moment a probe may start, and ``budget=0`` means
    exactly one probe. Returns how many seconds passed before the first
    successful probe (0.0 for a server that answered at once).

    Raises `LabNotReady`, chained onto the last probe failure, when no probe
    succeeded within the budget.
    """
    from arodonata.asdk.tls import TrustPolicy
    from arodonata.config import ArodonataSettings

    TrustPolicy.from_settings(ArodonataSettings()).preflight()
    started = clock()
    attempt = 0
    while True:
        attempt += 1
        elapsed = clock() - started
        try:
            await probe()
        except Exception as exc:  # noqa: BLE001 -- any failure means "not ready yet"
            # A bare TimeoutError has an empty str(); always name the type.
            last_error = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            if elapsed + interval > budget:
                raise LabNotReady(
                    f"lab API did not answer within {budget:g} s ({attempt} probes); last error: {last_error}"
                ) from exc
            log.warning(
                "Lab API not ready after %.0f s (probe %d: %s); retrying in %gs", elapsed, attempt, last_error, interval
            )
            await sleep(interval)
            continue
        return elapsed
