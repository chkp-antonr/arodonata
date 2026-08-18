"""Session cleanup logic for Check Point management API sessions.

Enumerates active sessions via show-sessions, then discards stale
disconnected API sessions according to age/changes criteria.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from arlogi.otel.decorator import traced

from ..logger import lazy_logger
from ..telemetry import span_attrs

if TYPE_CHECKING:
    from .rate_limiter import RateLimiter
    from .server_registry import ServerRegistry
    from .transport import ApiTransport

log = lazy_logger("arodonata.asdk.session_cleaner")


@dataclass
class CleanupResult:
    """Result of a session cleanup operation."""

    discarded: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


# CP reports 'Management API' for mgmt_cli sessions and 'WEB_API' for HTTPS API sessions.
# Both are programmatic; only GUI applications (SmartConsole, etc.) must never be touched.
_API_APPLICATIONS: frozenset[str] = frozenset({"Management API", "WEB_API"})

# Sessions whose name/description contains this marker (case-insensitive) are known
# to be disposable automated-test sessions -- see ArodonataClient.api_call()'s
# session_name/session_description params. They get a much shorter discard grace
# period than real work, instead of waiting on the normal read-write/changes rules.
_TEST_SESSION_MARKER = "pytest"
_TEST_SESSION_MAX_AGE_MINUTES = 10

# CP timestamp dicts use 'posix-millis' (ms) or 'posix' (s or ms depending on build).
# Values > 1e10 are already milliseconds; smaller values are seconds.
_MS_THRESHOLD = 10_000_000_000


class SessionCleaner:
    """Cleans up stale disconnected API sessions on Check Point management servers.

    Only processes sessions where application is a known programmatic API type
    ('Management API' or 'WEB_API') to avoid
    touching SmartConsole operator sessions.

    Example:
        cleaner = SessionCleaner(transport, rate_limiter, registry)
        result = await cleaner.cleanup_stale_sessions(
            "mgmt1", "", system_sid, "10.0.0.1"
        )
        print(f"Discarded {result.discarded} sessions")
    """

    def __init__(
        self,
        transport: ApiTransport,
        rate_limiter: RateLimiter,
        registry: ServerRegistry,
    ) -> None:
        self._transport = transport
        self._rate_limiter = rate_limiter
        self._registry = registry

    @staticmethod
    def is_max_sessions_error(error_msg: str) -> bool:
        """Return True if the error indicates the max-sessions limit was hit."""
        return "maximum number of active sessions" in error_msg

    @staticmethod
    def _extract_posix_millis(session: dict[str, Any], key: str) -> int:
        """Extract a posix timestamp in milliseconds from a CP session field dict."""
        val = session.get(key)
        if not isinstance(val, dict):
            return 0
        millis = val.get("posix-millis")
        if millis:
            return int(millis)
        raw = val.get("posix")
        if not raw:
            return 0
        raw = int(raw)
        return raw if raw > _MS_THRESHOLD else raw * 1000

    def _age_minutes(self, posix_millis: int) -> float:
        """Compute age in minutes from a posix-millis timestamp."""
        created = datetime.fromtimestamp(posix_millis / 1000, UTC)
        return (datetime.now(UTC) - created).total_seconds() / 60

    def _get_session_decision(self, session: Any) -> tuple[str, str | None, int, float, bool] | None:
        """Classify one session for cleanup.

        Returns (uid, app, changes, age_min, should_discard) or None if the
        session should be skipped (caller increments result.skipped).
        """
        if not isinstance(session, dict):
            return None

        uid = session.get("uid")
        if not uid:
            return None

        app = session.get("application")
        if app not in _API_APPLICATIONS:
            return None

        conn_mode = session.get("connection-mode")
        if conn_mode == "connected":
            return None

        if session.get("tasks"):
            return None

        raw_changes = session.get("changes", session.get("number-of-changes", 0))
        changes = sum(raw_changes.values()) if isinstance(raw_changes, dict) else int(raw_changes or 0)

        posix_millis = (
            self._extract_posix_millis(session, "last-logout-time")
            or self._extract_posix_millis(session, "last-login-time")
            or self._extract_posix_millis(session, "creation-time")
        )
        if not posix_millis:
            return None

        age_min = self._age_minutes(posix_millis)
        in_work = session.get("in-work") or session.get("in-use")

        name = (session.get("name") or "") + (session.get("description") or "")
        if _TEST_SESSION_MARKER in name.lower():
            # Known-disposable automated-test session (see ArodonataClient.api_call()'s
            # session_name/session_description) -- don't make it wait out the real-work
            # thresholds below just because it happens to hold pending changes.
            should_discard = age_min > _TEST_SESSION_MAX_AGE_MINUTES
        elif conn_mode == "read write" or in_work:
            # Real pending changes get more grace than an idle read-write session
            # (4320min/72h) before being treated as abandoned -- but must still be
            # reclaimed eventually. Without this fallback, a session with changes > 0
            # was NEVER discarded regardless of age, letting real-work sessions with
            # pending changes accumulate indefinitely and hold their locks forever.
            should_discard = (changes == 0 and age_min > 4320) or (changes > 0 and age_min > 10080)
        else:
            should_discard = (changes == 0 and age_min > 60) or (changes > 0 and age_min > 1440)

        return uid, app, changes, age_min, should_discard

    async def _process_session(
        self,
        session: Any,
        result: CleanupResult,
        system_sid: str,
        server_ip: str,
        port: int | None,
    ) -> None:
        """Evaluate and optionally discard one session. Mutates result in place."""
        decision = self._get_session_decision(session)
        if decision is None:
            result.skipped += 1
            return

        uid, app, changes, age_min, should_discard = decision
        conn_mode = session.get("connection-mode") if isinstance(session, dict) else None
        in_work = session.get("in-work") or session.get("in-use") if isinstance(session, dict) else None
        log().debug(
            f"  uid={uid} app={app!r} conn={conn_mode!r} in-work={in_work} "
            f"changes={changes} age={age_min:.1f}min → discard={should_discard}"
        )

        if not should_discard:
            result.skipped += 1
            return

        try:
            async with self._rate_limiter.acquire(server_ip):
                discard_response = await self._transport.discard_session(server_ip, system_sid, uid, port)
            if discard_response.get("success"):
                result.discarded += 1
                log().info(f"Discarded session uid={uid} (changes={changes}, age={age_min:.1f}min)")
            else:
                msg = f"Discard failed uid={uid}: {discard_response.get('message')}"
                log().warning(msg)
                result.errors.append(msg)
        except Exception as e:
            msg = f"Discard error uid={uid}: {e}"
            log().warning(msg)
            result.errors.append(msg)

    @traced
    async def cleanup_stale_sessions(
        self,
        mgmt_name: str,
        domain: str,
        system_sid: str,
        server_ip: str,
        port: int | None = None,
    ) -> CleanupResult:
        """Discard stale disconnected Management API sessions.

        Calls show-sessions, filters to Management API sessions only, then
        discards those that are disconnected and meet the age/changes criteria:
          - marked as a test session (name/description contains "pytest") and
            age > 10 min → discard, regardless of changes
          - 0 changes AND age > 60 min → discard
          - >0 changes AND age > 24h  → discard (abandoned with unpublished work)
          - read-write/in-work session, 0 changes AND age > 72h → discard
          - read-write/in-work session, >0 changes AND age > 7 days → discard

        Args:
            mgmt_name: Management server name (for logging).
            domain: Domain name (for logging).
            system_sid: Already-authenticated SID to use for show-sessions/discard.
            server_ip: Management server IP address.
            port: Optional port number.

        Returns:
            CleanupResult with counts of discarded/skipped/errored sessions.
        """
        result = CleanupResult()

        try:
            response = await self._transport.show_sessions(server_ip, system_sid, port)
        except Exception as e:
            log().error(f"show-sessions failed for '{mgmt_name}': {e}")
            result.errors.append(f"show-sessions failed: {e}")
            return result

        if not response.get("success"):
            log().warning(f"show-sessions unsuccessful for '{mgmt_name}': {response.get('message')}")
            return result

        data = response.get("data") or {}
        sessions: list[Any] = data.get("objects", []) if isinstance(data, dict) else []
        span_attrs(mgmt_name=mgmt_name, domain=domain or "system", sessions=len(sessions))

        log().debug(f"Session cleanup for '{mgmt_name}:{domain}': evaluating {len(sessions)} sessions")

        for session in sessions:
            await self._process_session(session, result, system_sid, server_ip, port)

        log().info(
            f"Session cleanup complete for '{mgmt_name}:{domain}': "
            f"discarded={result.discarded}, skipped={result.skipped}, "
            f"errors={len(result.errors)}"
        )
        span_attrs(
            **{
                "cleanup.discarded": result.discarded,
                "cleanup.skipped": result.skipped,
                "cleanup.errors": len(result.errors),
            }
        )
        return result


__all__ = ["CleanupResult", "SessionCleaner"]
