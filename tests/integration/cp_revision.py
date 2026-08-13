"""Snapshot and restore CP management revisions for integration tests.

Baseline = the last published session (revision) per domain, captured
before any test runs. restore_to_baseline() reverts every drifted domain
back to it. Adapted from FPCR's proven cp_setup/revision.py.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

BASELINE_DIR = Path("_tmp/cp_baseline")


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


async def discover_domain_names(client: Any, mgmt_name: str) -> list[str]:
    """Domain names on an MDM server; [] on an SMS."""
    result = await client.api_call(mgmt_name, "show-domains", payload={"details-level": "standard", "limit": 200})
    if not result.success or not result.data:
        return []
    return [o["name"] for o in result.data.get("objects", []) if isinstance(o, dict) and o.get("name")]


async def snapshot_baseline(client: Any, mgmt_name: str) -> dict[str, dict]:
    """Capture {domain: last_published_session} for global + every domain.

    Raises on any failure — the test session must abort rather than run
    without a safety net.
    """
    baseline: dict[str, dict] = {"": await last_published_session(client, mgmt_name, "")}
    for domain in await discover_domain_names(client, mgmt_name):
        baseline[domain] = await last_published_session(client, mgmt_name, domain)
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


async def restore_to_baseline(client: Any, mgmt_name: str, baseline: dict[str, dict]) -> list[str]:
    """Revert every domain whose last published revision drifted from baseline.

    Returns the list of reverted domain names ("" = global). Raises on the
    first revert failure.
    """
    reverted: list[str] = []
    for domain, rev in baseline.items():
        target_uid = rev.get("uid", "")
        if not target_uid:
            continue
        current = await last_published_session(client, mgmt_name, domain)
        if current["uid"] == target_uid:
            continue

        await discard_open_sessions(client, mgmt_name, domain)
        result = await client.api_call(
            mgmt_name,
            "revert-to-revision",
            domain,
            payload={"to-session": target_uid},
            wait_for_task=True,
        )
        if not result.success:
            # CP aborts when already at the target revision — state is correct.
            if result.code == "err_validation_failed" and "current revision" in (result.message or ""):
                log.info("[%s] already at baseline — no revert needed.", domain)
                continue
            raise RuntimeError(
                f"revert-to-revision failed for domain {domain!r}: {result.message} (code={result.code})"
            )
        log.warning("[%s] reverted to baseline %r (uid=%.8s)", domain, rev.get("name"), target_uid)
        reverted.append(domain)
    return reverted
