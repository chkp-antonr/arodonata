"""Crash-safe session baseline guard for Arodonata v2 examples.

Snapshots the target domain(s)' last-published session before running example code and reverts
back to it afterward so examples leave the lab exactly as they found it. The baseline is
persisted to ``examples/_tmp/session_guard_state.json`` so that if a run crashes before its own
revert, the *next* run recovers by restoring that same recorded baseline first rather than
snapshotting an already-drifted state.

Library usage (scripted, e.g. ``08_cpcrud_operations.py``):
    from _session_guard import guarded_session

    async with guarded_session(client, mgmt_name, domains=["Domain4"]):
        ...  # apply templates, publish, etc.

Manual CLI usage (ad-hoc live testing):
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 1st call: saves baseline
    ... do manual testing ...
    uv run examples/_session_guard.py [mgmt_ip] [domain ...]   # 2nd call: reverts to baseline
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from arodonata import ArodonataClient, ArodonataSettings

log = logging.getLogger(__name__)

STATE_FILE = Path(__file__).parent / "_tmp" / "session_guard_state.json"


async def _last_published_session(client: ArodonataClient, mgmt_name: str, domain: str) -> dict[str, Any]:
    """Query ``show-last-published-session`` for ``(mgmt_name, domain)``."""
    result = await client.api_call(mgmt_name, "show-last-published-session", {}, domain=domain)
    if not result.success or not isinstance(result.data, dict):
        return {"uid": "", "name": "", "publish_time": ""}
    return {
        "uid": str(result.data.get("uid") or ""),
        "name": str(result.data.get("name") or ""),
        "publish_time": result.data.get("publish-time") or "",
    }


async def _discard_open_sessions(client: ArodonataClient, mgmt_name: str, domain: str) -> None:
    """Discard unpublished sessions holding changes or locks that would block ``revert-to-revision``."""
    result = await client.api_call(
        mgmt_name,
        "show-sessions",
        {"details-level": "full", "limit": 200},
        domain=domain,
    )
    if not result.success or not isinstance(result.data, dict):
        return
    objs = result.data.get("objects")
    if not isinstance(objs, list):
        return
    dirty_uids: list[str] = []
    for sess in objs:
        if not isinstance(sess, dict) or sess.get("state") == "published":
            continue
        uid = str(sess.get("uid") or "")
        changes = int(sess.get("changes") or 0)
        locks = int(sess.get("locks") or 0)
        if not uid or (changes == 0 and locks == 0):
            continue
        dirty_uids.append(uid)

    if not dirty_uids:
        return

    sid, server_ip = await client.create_dedicated_session(
        mgmt_name,
        domain,
        session_name="cp-guard-discard",
    )
    try:
        for uid in dirty_uids:
            if uid == sid:
                continue
            disc = await client.api_call(
                mgmt_name,
                "discard",
                {"uid": uid},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )
            if disc.success:
                log.info("[%s] discarded stale session uid=%.8s", domain, uid)
            else:
                log.warning("[%s] could not discard uid=%.8s: %s", domain, uid, disc.error_message)
    finally:
        await client.logout_sid(mgmt_name, sid, server_ip=server_ip)


async def _restore_to_baseline(
    client: ArodonataClient,
    mgmt_name: str,
    baseline: dict[str, dict[str, Any]],
) -> list[str]:
    """Revert every domain whose last-published revision drifted from ``baseline``."""
    reverted: list[str] = []
    for domain, rev in baseline.items():
        target_uid = str(rev.get("uid") or "")
        if not target_uid:
            continue
        await _discard_open_sessions(client, mgmt_name, domain)
        current = await _last_published_session(client, mgmt_name, domain)
        if current["uid"] == target_uid:
            continue

        sid, server_ip = await client.create_dedicated_session(
            mgmt_name,
            domain,
            session_name="cp-guard-revert",
        )
        try:
            result = await client.api_call(
                mgmt_name,
                "revert-to-revision",
                {"to-session": target_uid},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
                wait_for_task=True,
            )
        finally:
            await client.logout_sid(mgmt_name, sid, server_ip=server_ip)
        if not result.success:
            err_msg = (result.error_message or "").lower()
            if result.code == "err_validation_failed" and "current revision" in err_msg:
                continue
            raise RuntimeError(
                f"revert-to-revision failed for domain {domain!r}: {result.error_message} (code={result.code})"
            )
        client.invalidate_domain(mgmt_name, domain)
        log.warning("[%s] reverted to baseline %r (uid=%.8s)", domain, rev.get("name"), target_uid)
        reverted.append(domain)
    return reverted


@asynccontextmanager
async def guarded_session(
    client: ArodonataClient,
    mgmt_name: str,
    domains: list[str],
) -> AsyncIterator[dict[str, dict[str, Any]]]:
    """Snapshot ``domains`` before running work and revert back to baseline on exit."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        baseline: dict[str, dict[str, Any]] = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        log.warning(
            "Recovered baseline from previous unclean run (%s) -- restoring before continuing.",
            STATE_FILE,
        )
        await _restore_to_baseline(client, mgmt_name, baseline)
    else:
        baseline = {domain: await _last_published_session(client, mgmt_name, domain) for domain in domains}
        STATE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    try:
        yield baseline
    finally:
        reverted = await _restore_to_baseline(client, mgmt_name, baseline)
        log.warning("Reverted domains to baseline: %s", reverted or "none (no drift)")
        STATE_FILE.unlink(missing_ok=True)


async def _main() -> None:
    from dotenv import load_dotenv

    load_dotenv(".env.test", override=True)
    load_dotenv(".env.lib", override=True)
    load_dotenv(".env.secrets", override=True)
    if os.environ.get("ARODONATA_LAB"):
        load_dotenv(f".env.lab.{os.environ['ARODONATA_LAB']}", override=True)
    logging.basicConfig(level=logging.WARNING)

    settings = ArodonataSettings()
    mgmt_name = sys.argv[1] if len(sys.argv) > 1 else settings.mgmt_names[0]
    domains = sys.argv[2:] or [os.environ.get("EXAMPLE_DOMAIN") or os.environ.get("TEST_DOMAIN_A", "Domain4")]

    async with ArodonataClient(settings=settings) as client:
        if STATE_FILE.exists():
            baseline = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            print(f"Found saved baseline in {STATE_FILE} -- reverting {list(baseline)} to it now.")
            reverted = await _restore_to_baseline(client, mgmt_name, baseline)
            print(f"Reverted domains: {reverted or 'none (no drift)'}")
            STATE_FILE.unlink(missing_ok=True)
            print("Baseline file removed. Guard cycle complete.")
        else:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            baseline = {domain: await _last_published_session(client, mgmt_name, domain) for domain in domains}
            STATE_FILE.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
            print(f"Saved baseline for {list(baseline)} to {STATE_FILE}.")
            print("Do your manual work now, then re-run this script (same args) to revert.")


if __name__ == "__main__":
    asyncio.run(_main())
