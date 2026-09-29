"""Snapshot and restore CP management revisions for integration tests.

Baseline = the last published session (revision) per domain, captured
before any test runs. restore_to_baseline() reverts every drifted domain
back to it. Adapted from FPCR's proven cp_setup/revision.py.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

BASELINE_DIR = Path("_tmp/cp_baseline")

# `revert-to-revision` on a real MDS routinely runs for minutes, longer still
# over 100 ms+ regional latency. The client's default API timeout (120 s) is
# far too short: a client-side timeout does not stop the server-side revert,
# it just leaves the suite reporting "restore failed" while the server refuses
# every login with "Database revision is in progress".
REVERT_TIMEOUT_SECONDS = 900


async def last_published_session(client: Any, mgmt_name: str, domain: str = "") -> dict:
    """Return {uid, name, publish_time} of the domain's last published session.

    A domain that has never been published returns an empty uid — there is
    nothing to revert to, and restore_to_baseline() skips empty uids.
    """
    result = await client.api_call(mgmt_name, "show-last-published-session", domain, payload={})
    if not result.success or not result.data:
        if result.code == "generic_err_object_not_found":
            log.warning("[%s] no published session — baseline empty for this domain", domain)
            return {"uid": "", "name": "", "publish_time": ""}
        raise RuntimeError(
            f"show-last-published-session failed for domain {domain!r}: {result.message} (code={result.code})"
        )
    return {
        "uid": result.data.get("uid", ""),
        "name": result.data.get("name", ""),
        "publish_time": result.data.get("publish-time", ""),
    }


def _label(domain: str) -> str:
    """Human name for a domain key: the MDS level is stored as "" (older baseline files have it)."""
    return domain or "global"


async def snapshot_baseline(
    client: Any,
    mgmt_name: str,
    domains: list[str],
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> dict[str, dict]:
    """Capture {domain: last_published_session} for exactly `domains`.

    `domains` is the set the mutating tests write to -- TEST_DOMAIN_A and
    TEST_DOMAIN_B. Nothing is discovered and the MDS level is never captured:
    the teardown revert walks this snapshot, so anything captured here is
    something a revert could undo, including changes the suite did not make
    (another project's domain, a standby server added mid-run). Blanks and
    duplicates are dropped, so an unset or repeated B costs nothing.

    Raises on any failure -- the test session must abort rather than run
    without a safety net.

    Each domain is one login, which may wait out Check Point's login throttle,
    so every domain logs its position and elapsed seconds (read it live with
    ``-o log_cli=true``): a 2026-09-27 run once spent 26 minutes here silently.
    """
    wanted = list(dict.fromkeys(d for d in domains if d))
    started = time.monotonic()
    log.info("baseline snapshot: %d domains on %s (%d logins ahead)", len(wanted), mgmt_name, len(wanted))
    baseline: dict[str, dict] = {}
    for position, domain in enumerate(wanted, start=1):
        if position > 1:
            await sleep(2)  # Pace domain logins to respect Check Point MDS rate limits
        step_started = time.monotonic()
        baseline[domain] = await last_published_session(client, mgmt_name, domain)
        log.info(
            "[%s] baseline captured (%d/%d, took %.1f s): %r",
            domain,
            position,
            len(wanted),
            time.monotonic() - step_started,
            baseline[domain]["name"],
        )
    log.info("baseline snapshot complete: %d domains in %.1f s", len(wanted), time.monotonic() - started)
    return baseline


def write_baseline_file(baseline: dict[str, dict]) -> Path:
    """Write the baseline JSON; the file is never auto-deleted."""
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = BASELINE_DIR / f"baseline-{ts}.json"
    path.write_text(json.dumps(baseline, indent=2))
    return path


async def discard_open_sessions(client: Any, mgmt_name: str, domain: str = "") -> None:
    """Discard unpublished sessions holding changes/locks (blocks revert).

    Failures are logged and ignored so the restore still proceeds.
    """
    result = await client.api_call(mgmt_name, "show-sessions", domain, payload={"details-level": "full", "limit": 200})
    if not result.success or not result.data:
        return
    for s in result.data.get("objects", []):
        if s.get("state") == "published":
            continue
        uid = s.get("uid", "")
        if not uid or not (s.get("changes", 0) or s.get("locks", 0)):
            continue
        r = await client.api_call(mgmt_name, "discard", domain, payload={"uid": uid})
        if r.success:
            log.info("[%s] discarded session uid=%.8s", domain, uid)
        else:
            log.warning("[%s] could not discard uid=%.8s: %s", domain, uid, r.message)


async def revert_domain_to(
    client: Any,
    mgmt_name: str,
    domain: str,
    target_uid: str,
    *,
    context: str = "",
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> bool:
    """Discard open sessions, then revert `domain` to `target_uid`.

    The single revert implementation for the whole integration suite: it is
    the only place that knows a revert needs REVERT_TIMEOUT_SECONDS rather
    than the client's default API timeout. Call this instead of issuing
    `revert-to-revision` directly — a unit test enforces that.

    Args:
        context: Free text added to the failure message (e.g. "cycle 3"),
            so a failure names which revert died.
        sleep: How to wait for CPM to settle (10 s after a revert, 15 s while
            running tasks block one). Injected so unit tests do not wait.

    Returns:
        True when a revert happened, False when CP reports the domain is
        already at that revision (the desired end state, not a failure).

    Raises:
        RuntimeError: on any other revert failure.
    """
    for attempt in range(1, 6):
        await discard_open_sessions(client, mgmt_name, domain)
        result = await client.api_call(
            mgmt_name,
            "revert-to-revision",
            domain,
            payload={"to-session": target_uid},
            wait_for_task=True,
            timeout=REVERT_TIMEOUT_SECONDS,
        )
        if result.success:
            log.info("[%s] revert successful; pausing 10s for CPM to settle...", _label(domain))
            await sleep(10)
            return True

        # CP aborts a revert to the current revision — the state is already correct.
        if result.code == "err_validation_failed" and "current revision" in (result.message or ""):
            log.info("[%s] already at target revision — no revert needed.", domain)
            return False

        # If CP blocks the revert because background tasks are running, wait and retry.
        tasks_running = False
        msg = result.message or ""
        raw_data = str(result.data) if result.data else ""
        if "other tasks are in progress" in msg or "Some tasks are currently running" in msg:
            tasks_running = True
        elif "other tasks are in progress" in raw_data or "Some tasks are currently running" in raw_data:
            tasks_running = True

        if tasks_running and attempt < 5:
            log.warning(
                "[%s] revert blocked because tasks are running (attempt %d/5); waiting 15s...",
                domain,
                attempt,
            )
            await sleep(15)
            continue

        break

    where = f" ({context})" if context else ""
    msg = result.message
    if not msg and isinstance(result.data, dict):
        tasks = result.data.get("tasks", [])
        if tasks:
            parts = []
            for t in tasks:
                t_name = t.get("task-name") or t.get("task-id") or "task"
                t_status = t.get("status")
                t_comments = t.get("comments") or t.get("status-description") or ""
                t_details = t.get("task-details")
                detail_str = f" - details: {t_details}" if t_details else ""
                parts.append(f"{t_name}: status={t_status}, comments={t_comments}{detail_str}")
            msg = "; ".join(parts)
    raise RuntimeError(
        f"revert-to-revision failed for domain {domain!r}{where}: {msg or 'no error message'} (code={result.code})"
    )


async def restore_to_baseline(
    client: Any,
    mgmt_name: str,
    baseline: dict[str, dict],
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> list[str]:
    """Revert every domain whose last published revision drifted from baseline.

    Returns the list of reverted domain names ("" = global). Raises on the
    first revert failure.
    """
    reverted: list[str] = []
    total = len(baseline)
    for position, (domain, rev) in enumerate(baseline.items(), start=1):
        target_uid = rev.get("uid", "")
        if not target_uid:
            log.info("[%s] (%d/%d) no baseline revision, nothing to restore", _label(domain), position, total)
            continue
        current = await last_published_session(client, mgmt_name, domain)
        if current["uid"] == target_uid:
            log.info("[%s] (%d/%d) at baseline, no revert needed", _label(domain), position, total)
            continue
        log.warning(
            "[%s] (%d/%d) drifted from baseline (%r -> %r), reverting...",
            _label(domain),
            position,
            total,
            rev.get("name"),
            current["name"],
        )

        if await revert_domain_to(client, mgmt_name, domain, target_uid, context="baseline restore", sleep=sleep):
            log.warning("[%s] reverted to baseline %r (uid=%.8s)", domain, rev.get("name"), target_uid)
            reverted.append(domain)
    return reverted
