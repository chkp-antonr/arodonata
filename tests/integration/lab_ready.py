"""Wait for the live Check Point management server's Web API to become ready.

After an MDS / SMS VM starts (or ``api restart`` runs), Apache comes up before
the Java API backend finishes initializing. During that window ``POST /web_api/*``
either fails at the TCP layer or returns an HTML 503 page (parsed by
``ApiTransport`` into ``ApiCallResult(success=False, status_code=503, data={"raw_text": ...})``).

Once the backend is alive, even an unauthenticated ``show-api-versions`` call
returns a JSON body with either ``current-version`` (if unauthenticated calls are
allowed) or a structured Check Point error ``{"code": "generic_err_...", "message": "..."}``.
Either proves the API daemon is ready to accept ``login``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

from arlogi import get_logger

from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport
from arodonata.core.config import ArodonataSettings, TlsTrustMode
from arodonata.core.errors import ServerIdentityError

logger = get_logger(__name__)

ProbeFn = Callable[[str], Awaitable[dict[str, Any] | None]]


class LabNotReady(RuntimeError):
    """The management server did not answer Web API calls within the deadline."""


def answered_by_api(response: dict[str, Any] | None) -> bool:
    """Return True if *response* came from the Check Point Web API daemon (not Apache 503)."""
    if not isinstance(response, dict):
        return False
    if "current-version" in response:
        return True
    code = response.get("code")
    return isinstance(code, str) and not code.startswith("http_")


async def api_versions_probe(
    server_ip: str,
    *,
    trust_policy: TrustPolicy | None = None,
    connect_timeout: float = 10.0,
) -> dict[str, Any] | None:
    """Send one unauthenticated ``show-api-versions`` call with a short timeout using Arodonata v2 ``ApiTransport``."""
    settings = ArodonataSettings(
        mgmt_ip=server_ip,
        connect_timeout=connect_timeout,
        api_timeout=connect_timeout,
        login_timeout=connect_timeout,
    )
    if trust_policy is None:
        raw_mode = settings.tls_trust
        mode: TlsTrustMode = raw_mode if raw_mode in ("pinned", "tofu", "lab-memory") else "tofu"
        trust_policy = TrustPolicy(
            mode=mode,
            known_hosts_path=settings.tls_known_hosts_path,
            pinned_fingerprints=settings.tls_fingerprints,
        )

    transport = ApiTransport(settings=settings, trust_policy=trust_policy)
    try:
        res = await transport.execute(
            server_ip,
            "show-api-versions",
            {},
            timeout=connect_timeout,
        )
        if res.data and isinstance(res.data, dict):
            return res.data
        return None
    except ServerIdentityError:
        # Configuration / MITM error — waiting will not fix a wrong fingerprint.
        raise
    except Exception as exc:
        logger.debug("lab_ready_probe_err", server=server_ip, error=str(exc))
        return None
    finally:
        await transport.close()


async def wait_until_ready(
    server_ip: str,
    *,
    timeout: float = 300.0,
    interval: float = 5.0,
    probe: ProbeFn | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> float:
    """Poll *server_ip* until the Web API daemon responds; return elapsed seconds."""
    if probe is None:
        probe = api_versions_probe
    start = monotonic()
    deadline = start + timeout
    attempt = 0

    while True:
        attempt += 1
        resp = await probe(server_ip)
        if answered_by_api(resp):
            elapsed = monotonic() - start
            if attempt > 1:
                logger.info("lab_ready", server=server_ip, attempts=attempt, elapsed_s=round(elapsed, 1))
            return elapsed

        now = monotonic()
        if now >= deadline:
            raise LabNotReady(
                f"Check Point Web API on {server_ip} not ready after {timeout:.0f}s ({attempt} attempts, last={resp!r})"
            )

        remaining = deadline - now
        logger.info(
            "lab_waiting_for_api",
            server=server_ip,
            attempt=attempt,
            remaining_s=round(remaining, 0),
        )
        await sleep(min(interval, remaining))
