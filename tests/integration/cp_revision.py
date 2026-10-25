"""Check Point domain revision snapshot & revert helpers for integration tests.

Used by the session-scoped ``cp_baseline_snapshot`` fixture to guarantee that
any test mutations in ``TEST_DOMAIN_A`` / ``TEST_DOMAIN_B`` are rolled back via
Check Point's native ``revert-to-revision`` command at the end of the run —
and by tests that need an explicit per-test restore point.

On MDSM R81.20/R82, ``revert-to-revision`` restores all objects, services,
groups, and access/NAT rulebases in the target domain to the exact state at
the target published session. Only the audit log retains the revert event.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from arlogi import get_logger

if TYPE_CHECKING:
    from arodonata import ArodonataClient

logger = get_logger(__name__)

REVERT_TIMEOUT_SECONDS = 900.0
REVERT_LOCK_RETRIES = 6
REVERT_LOCK_BACKOFF_SECONDS = 5.0


@dataclass(frozen=True)
class DomainBaseline:
    """Captured baseline state for a single Check Point domain."""

    domain: str
    session_uid: str
    session_name: str | None = None
    published_iso: str | None = None


@dataclass
class BaselineSnapshot:
    """Session-wide baseline across all sandbox domains."""

    mgmt_name: str
    mgmt_ip: str
    captured_at: str
    domains: dict[str, DomainBaseline] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot metadata for JSON persistence."""
        return {
            "mgmt_name": self.mgmt_name,
            "mgmt_ip": self.mgmt_ip,
            "captured_at": self.captured_at,
            "domains": {
                d: {
                    "domain": b.domain,
                    "session_uid": b.session_uid,
                    "session_name": b.session_name,
                    "published_iso": b.published_iso,
                }
                for d, b in self.domains.items()
            },
        }


async def last_published_session(
    client: ArodonataClient,
    mgmt_name: str,
    domain: str,
) -> DomainBaseline:
    """Return the most recently published session in ``domain``."""
    res = await client.api_call(
        mgmt_name,
        "show-sessions",
        {"view-published-sessions": True, "limit": 5, "details-level": "standard"},
        domain=domain,
    )
    if not res.success:
        raise RuntimeError(f"show-sessions (published) failed in {domain}: {res.error_code} {res.error_message}")
    objects: list[dict[str, Any]] = res.data.get("objects") or []
    if not objects:
        raise RuntimeError(
            f"Domain {domain!r} has zero published sessions — cannot establish a revert baseline. "
            f"Publish at least one session in {domain!r} on the lab before running integration tests."
        )
    head = objects[0]
    pub_time = (head.get("publish-time") or {}).get("iso-8601")
    return DomainBaseline(
        domain=domain,
        session_uid=head["uid"],
        session_name=head.get("name"),
        published_iso=pub_time,
    )


async def find_named_session(
    client: ArodonataClient,
    mgmt_name: str,
    domain: str,
    session_name: str,
) -> DomainBaseline:
    """Locate a published session by its ``name`` field (scans up to 200 recent sessions)."""
    res = await client.api_call(
        mgmt_name,
        "show-sessions",
        {"view-published-sessions": True, "limit": 200, "details-level": "standard"},
        domain=domain,
    )
    if not res.success:
        raise RuntimeError(f"show-sessions failed in {domain}: {res.error_code} {res.error_message}")
    for obj in res.data.get("objects") or []:
        if obj.get("name") == session_name:
            pub_time = (obj.get("publish-time") or {}).get("iso-8601")
            return DomainBaseline(
                domain=domain,
                session_uid=obj["uid"],
                session_name=session_name,
                published_iso=pub_time,
            )
    raise RuntimeError(f"Named revision {session_name!r} not found in domain {domain!r}")


async def snapshot_baseline(
    client: ArodonataClient,
    mgmt_name: str,
    mgmt_ip: str,
    domains: list[str],
    revision_name: str | None = None,
) -> BaselineSnapshot:
    """Capture the baseline session UID for each domain."""
    snap = BaselineSnapshot(
        mgmt_name=mgmt_name,
        mgmt_ip=mgmt_ip,
        captured_at=datetime.now(UTC).isoformat(),
    )
    for dom in domains:
        if revision_name:
            base = await find_named_session(client, mgmt_name, dom, revision_name)
        else:
            base = await last_published_session(client, mgmt_name, dom)
        snap.domains[dom] = base
        logger.info(
            "cp_baseline_captured",
            domain=dom,
            session_uid=base.session_uid,
            session_name=base.session_name,
            published_iso=base.published_iso,
        )
    return snap


def write_baseline_file(snap: BaselineSnapshot, path: Path) -> None:
    """Persist baseline snapshot to disk so a crashed test run can be manually reverted."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snap.to_dict(), indent=2) + "\n", encoding="utf-8")


async def discard_open_sessions(
    client: ArodonataClient,
    mgmt_name: str,
    domain: str,
) -> int:
    """Discard any open (unpublished) work sessions holding changes/locks in ``domain``.

    ``revert-to-revision`` fails if another session in the domain holds locks or
    unpublished changes. We only touch sessions that actually hold ``changes > 0``
    or ``locks > 0`` — idle cached read-only sessions are left alone.
    """
    res = await client.api_call(
        mgmt_name,
        "show-sessions",
        {"view-published-sessions": False, "limit": 100, "details-level": "standard"},
        domain=domain,
    )
    if not res.success:
        logger.warning("show_open_sessions_failed", domain=domain, error=res.error_message)
        return 0

    dirty_uids: list[tuple[str, int, int]] = []
    for sess in res.data.get("objects") or []:
        changes = sess.get("changes", 0) or 0
        locks = sess.get("locks", 0) or 0
        if changes == 0 and locks == 0:
            continue
        uid = sess.get("uid")
        if not uid:
            continue
        dirty_uids.append((str(uid), int(changes), int(locks)))

    if not dirty_uids:
        return 0

    sid, server_ip = await client.create_dedicated_session(
        mgmt_name,
        domain,
        session_name="cp-discard-open",
        session_description="Arodonata harness discard open sessions",
    )
    discarded = 0
    try:
        for uid, changes, locks in dirty_uids:
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
                discarded += 1
                logger.info("discarded_open_session", domain=domain, session_uid=uid, changes=changes, locks=locks)
            else:
                logger.warning("discard_open_session_failed", domain=domain, session_uid=uid, error=disc.error_message)
    finally:
        await client.logout_sid(mgmt_name, sid, server_ip=server_ip)
    return discarded


async def revert_domain_to(
    client: ArodonataClient,
    mgmt_name: str,
    baseline: DomainBaseline,
    *,
    force: bool = False,
) -> bool:
    """Revert ``baseline.domain`` to ``baseline.session_uid`` if anything was published since.

    Returns ``True`` if a revert task was executed, ``False`` if the domain was
    already at ``baseline.session_uid`` (no-op).
    """
    await discard_open_sessions(client, mgmt_name, baseline.domain)

    if not force:
        current = await last_published_session(client, mgmt_name, baseline.domain)
        if current.session_uid == baseline.session_uid:
            logger.info(
                "cp_baseline_unchanged_skip_revert",
                domain=baseline.domain,
                session_uid=baseline.session_uid,
            )
            return False

    logger.info(
        "cp_revert_starting",
        domain=baseline.domain,
        to_session=baseline.session_uid,
        session_name=baseline.session_name,
    )
    res = None
    for attempt in range(1, REVERT_LOCK_RETRIES + 1):
        sid, server_ip = await client.create_dedicated_session(
            mgmt_name,
            baseline.domain,
            session_name="cp-revert-baseline",
            session_description=f"Arodonata revert to {baseline.session_uid}",
        )
        try:
            res = await client.api_call(
                mgmt_name,
                "revert-to-revision",
                {"to-session": baseline.session_uid},
                domain=baseline.domain,
                sid=sid,
                server_ip=server_ip,
                wait_for_task=True,
                timeout=REVERT_TIMEOUT_SECONDS,
            )
        finally:
            await client.logout_sid(mgmt_name, sid, server_ip=server_ip)
        if res.success:
            break
        err_text = f"{res.error_code or ''} {res.error_message or ''} {res.data}"
        # MDSM briefly holds a domain database lock right after a publish/discard
        # finishes; discard any newly-visible open sessions and retry.
        if "lock" in err_text.lower() and attempt < REVERT_LOCK_RETRIES:
            logger.warning(
                "cp_revert_locked_retrying",
                domain=baseline.domain,
                attempt=attempt,
                error=err_text,
            )
            await discard_open_sessions(client, mgmt_name, baseline.domain)
            await asyncio.sleep(REVERT_LOCK_BACKOFF_SECONDS)
            continue
        break

    assert res is not None
    if not res.success:
        raise RuntimeError(
            f"revert-to-revision to {baseline.session_uid} in {baseline.domain} failed: "
            f"{res.error_code} {res.error_message} data={res.data}"
        )
    client.invalidate_domain(mgmt_name, baseline.domain)
    logger.info("cp_revert_complete", domain=baseline.domain, to_session=baseline.session_uid)
    return True


async def restore_to_baseline(
    client: ArodonataClient,
    snap: BaselineSnapshot,
    *,
    domains: list[str] | None = None,
    force: bool = False,
) -> dict[str, bool]:
    """Revert all (or selected) domains in ``snap`` back to their captured session UIDs."""
    targets = domains if domains is not None else list(snap.domains.keys())
    outcomes: dict[str, bool] = {}
    errors: list[str] = []
    for dom in targets:
        base = snap.domains[dom]
        try:
            outcomes[dom] = await revert_domain_to(client, snap.mgmt_name, base, force=force)
        except Exception as exc:
            logger.error("cp_revert_failed", domain=dom, error=str(exc))
            errors.append(f"{dom}: {exc}")
    if errors:
        raise RuntimeError("Failed to revert domain(s) to baseline: " + "; ".join(errors))
    return outcomes
