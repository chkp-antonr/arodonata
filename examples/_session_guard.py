"""Crash-safe session baseline guard for CPCRUD examples.

Snapshots the target domain(s)' last-published session before running example
code and reverts back to it afterward -- examples should leave the lab
exactly as they found it. The baseline is persisted to a state file so that
if a run crashes before its own revert, the *next* run recovers by restoring
that same recorded baseline first, rather than snapshotting an
already-drifted state as if it were the truth. The state file is removed
only after a verified, successful revert -- a second crash in a row still
recovers correctly on the third run.

Library usage (scripted, e.g. 06_crud_operations.py):
    from _session_guard import guarded_session

    async with guarded_session(client, mgmt_name, domains=["General"]):
        ...  # apply templates, publish, etc.
    # baseline is restored here regardless of success/failure

Manual usage (ad-hoc live testing, no script wrapping it):
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 1st call: saves baseline
    ... do your manual testing (SmartConsole, raw API calls, whatever) ...
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 2nd call: reverts to it

    The two calls are told apart by whether the state file already exists, not by a flag --
    the same detection `guarded_session` uses for crash recovery: no file means "nothing saved
    yet, save now"; a file whose recorded uid no longer matches the domain's current
    last-published session means real changes happened since it was saved, so revert to it. If
    you run the "after" call and nothing had changed, it's a no-op (mirrors
    `_restore_to_baseline`'s per-domain drift check) but the file is still cleaned up. Defaults
    to `$API_MGMT` and domain "Domain4" if not given.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

STATE_FILE = Path(__file__).parent / "_tmp" / "session_guard_state.json"


async def _last_published_session(client: Any, mgmt_name: str, domain: str) -> dict:
    result = await client.api_call(mgmt_name, "show-last-published-session", domain, payload={})
    if not result.success or not result.data:
        return {"uid": "", "name": "", "publish_time": ""}
    return {
        "uid": result.data.get("uid", ""),
        "name": result.data.get("name", ""),
        "publish_time": result.data.get("publish-time", ""),
    }


async def _discard_open_sessions(client: Any, mgmt_name: str, domain: str) -> None:
    """Discard unpublished sessions holding changes/locks (blocks revert)."""
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
            log.info("[%s] discarded stale session uid=%.8s", domain, uid)
        else:
            log.warning("[%s] could not discard uid=%.8s: %s", domain, uid, r.message)


async def _restore_to_baseline(client: Any, mgmt_name: str, baseline: dict[str, dict]) -> list[str]:
    """Revert every domain whose last published revision drifted from baseline."""
    reverted: list[str] = []
    for domain, rev in baseline.items():
        target_uid = rev.get("uid", "")
        if not target_uid:
            continue
        await _discard_open_sessions(client, mgmt_name, domain)
        current = await _last_published_session(client, mgmt_name, domain)
        if current["uid"] == target_uid:
            continue
        result = await client.api_call(
            mgmt_name,
            "revert-to-revision",
            domain,
            payload={"to-session": target_uid},
            wait_for_task=True,
        )
        if not result.success:
            # CP aborts when already at the target revision -- state is correct.
            if result.code == "err_validation_failed" and "current revision" in (result.message or ""):
                continue
            raise RuntimeError(
                f"revert-to-revision failed for domain {domain!r}: {result.message} (code={result.code})"
            )
        log.warning("[%s] reverted to baseline %r (uid=%.8s)", domain, rev.get("name"), target_uid)
        reverted.append(domain)
    return reverted


@asynccontextmanager
async def guarded_session(client: Any, mgmt_name: str, domains: list[str]):
    """Yield the active baseline; guarantee revert-or-record-for-recovery on exit.

    If a previous run's state file is still on disk, its recorded baseline is adopted as the
    current truth (a prior run crashed before reverting) and is restored *before* any new work
    runs, instead of being overwritten by a fresh snapshot of an already-drifted domain.
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        baseline = json.loads(STATE_FILE.read_text())
        log.warning(
            "Recovered baseline from a previous unclean run (%s) -- restoring it before continuing.",
            STATE_FILE,
        )
        await _restore_to_baseline(client, mgmt_name, baseline)
    else:
        baseline = {domain: await _last_published_session(client, mgmt_name, domain) for domain in domains}
        STATE_FILE.write_text(json.dumps(baseline, indent=2))

    try:
        yield baseline
    finally:
        reverted = await _restore_to_baseline(client, mgmt_name, baseline)
        log.warning("Reverted domains to baseline: %s", reverted or "none (no drift)")
        STATE_FILE.unlink(missing_ok=True)


async def _main() -> None:
    import os
    import sys

    from dotenv import load_dotenv
    from sqlalchemy.ext.asyncio import create_async_engine

    from arodonata import ArodonataClient

    load_dotenv(".env.test", override=True)
    load_dotenv(".env.secrets", override=True)
    logging.basicConfig(level=logging.WARNING)

    mgmt_ip = sys.argv[1] if len(sys.argv) > 1 else os.environ["API_MGMT"]
    domains = sys.argv[2:] or ["Domain4"]

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    client = ArodonataClient(engine=engine, username="admin", password=os.environ["USER_admin"], mgmt_ip=mgmt_ip)
    async with client:
        if STATE_FILE.exists():
            baseline = json.loads(STATE_FILE.read_text())
            print(f"Found saved baseline in {STATE_FILE} -- reverting {list(baseline)} to it now.")
            reverted = await _restore_to_baseline(client, mgmt_ip, baseline)
            print(f"Reverted domains: {reverted or 'none (no drift)'}")
            STATE_FILE.unlink(missing_ok=True)
            print("Baseline file removed. Guard cycle complete.")
        else:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            baseline = {domain: await _last_published_session(client, mgmt_ip, domain) for domain in domains}
            STATE_FILE.write_text(json.dumps(baseline, indent=2))
            print(f"Saved baseline for {list(baseline)} to {STATE_FILE}.")
            print("Do your manual work now, then re-run this script (same args) to revert.")
    await engine.dispose()


if __name__ == "__main__":
    import asyncio

    asyncio.run(_main())
