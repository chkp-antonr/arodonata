"""Verified keep-alive connection pool for Check Point Management Web API sockets."""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

KEEPALIVE_IDLE_LIMIT_SECONDS: float = 10.0
MAX_KEEPALIVE_REQUESTS_PER_SOCKET: int = 95
NON_POOLABLE_SESSION_COMMANDS: frozenset[str] = frozenset(
    {
        "login",
        "logout",
        "keepalive",
        "publish",
        "discard",
        "continue-session",
        "switch-session",
        "take-over-session",
        "disconnect",
    }
)


def is_readonly_poolable_command(command: str) -> bool:
    """Return `True` if `command` is a read-only `show-*` command eligible for connection reuse."""
    normalized = command.strip().lower()
    return normalized.startswith("show-")


def derive_session_pool_scope(sid: str) -> str:
    """Derive a non-reversible pool scope tag from `sid` so raw SIDs never appear in memory keys or repr()."""
    if not sid:
        return ""
    digest = hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]
    return f"s:{digest}"


def is_poolable_command(command: str, *, session_scope: str | None = None) -> bool:
    """Return `True` if `command` is eligible for keep-alive connection reuse in `VerifiedConnectionPool`."""
    normalized = command.strip().lower()
    if not normalized or normalized in NON_POOLABLE_SESSION_COMMANDS:
        return False
    if normalized.startswith("show-"):
        return True
    return bool(session_scope)


@dataclass
class PooledSocketEntry:
    """Represents a fingerprint-verified keep-alive connection in `VerifiedConnectionPool`."""

    host: str
    port: int
    fingerprint: str
    protocol: Any
    last_used_at: float
    request_count: int = 1
    pool_scope: str = ""

    def is_usable(self, now: float, max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS) -> bool:
        """Return `True` if the connection is still open and within the idle and request limits."""
        if now - self.last_used_at > max_idle_seconds:
            return False
        if self.request_count >= MAX_KEEPALIVE_REQUESTS_PER_SOCKET:
            return False
        if bool(getattr(self.protocol, "should_close", False)):
            return False
        is_conn = getattr(self.protocol, "is_connected", None)
        if callable(is_conn):
            return bool(is_conn())
        transport = getattr(self.protocol, "transport", None)
        if transport is not None and hasattr(transport, "is_closing"):
            return not bool(transport.is_closing())
        return True

    def close(self) -> None:
        """Close the underlying protocol/transport."""
        close_fn = getattr(self.protocol, "close", None)
        if callable(close_fn):
            close_fn()
        else:
            transport = getattr(self.protocol, "transport", None)
            if transport is not None and hasattr(transport, "close"):
                transport.close()


class VerifiedConnectionPool:
    """Pools fingerprint-verified keep-alive connections per `(server_ip, port, scope)` for up to 10s idle.

    Reuses connections for read-only `show-*` commands under shared scope (`""`) and for
    non-boundary commands under dedicated `session_scope` tags; session-boundary commands
    and un-scoped mutations bypass pooling and close idle sockets before connecting.
    """

    def __init__(
        self,
        *,
        max_idle_seconds: float = KEEPALIVE_IDLE_LIMIT_SECONDS,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_idle_seconds = float(max_idle_seconds)
        self._monotonic = monotonic_fn
        self._pool: dict[tuple[str, int, str], deque[PooledSocketEntry]] = defaultdict(deque)
        self._reuse_count: int = 0
        self._fresh_count: int = 0

    @property
    def max_idle_seconds(self) -> float:
        """Maximum idle duration in seconds (default 10.0s)."""
        return self._max_idle_seconds

    @property
    def reuse_count(self) -> int:
        """Total number of requests that reused a pooled verified connection."""
        return self._reuse_count

    @property
    def fresh_count(self) -> int:
        """Total number of requests that opened a fresh connection."""
        return self._fresh_count

    def evict_expired(self, host: str | None = None, port: int | None = None) -> int:
        """Close and remove any pooled connections idle for more than `max_idle_seconds`."""
        now = self._monotonic()
        closed_count = 0
        if host is not None and port is not None:
            target_port = int(port)
            keys = [k for k in self._pool if k[0] == host and k[1] == target_port]
        else:
            keys = list(self._pool.keys())
        for key in keys:
            queue = self._pool.get(key)
            if not queue:
                continue
            kept: deque[PooledSocketEntry] = deque()
            while queue:
                entry = queue.popleft()
                if entry.is_usable(now, self._max_idle_seconds):
                    kept.append(entry)
                else:
                    entry.close()
                    closed_count += 1
            if kept:
                self._pool[key] = kept
            else:
                self._pool.pop(key, None)
        return closed_count

    def acquire_for_command(
        self,
        host: str,
        port: int,
        command: str,
        *,
        session_scope: str | None = None,
    ) -> PooledSocketEntry | None:
        """Acquire a pooled verified connection for `(host, port, scope)` if eligible.

        Always evicts expired connections first. For non-pooled commands, closes idle sockets
        before returning `None` so a fresh TLS-verified connection is established cleanly.
        """
        target_port = int(port)
        self.evict_expired(host, target_port)
        scope = session_scope or ""
        if not is_poolable_command(command, session_scope=scope or None):
            if scope:
                self.close_scope(host, target_port, scope)
            self.close_scope(host, target_port, "")
            self._fresh_count += 1
            return None

        key = (host, target_port, scope)
        queue = self._pool.get(key)
        now = self._monotonic()
        while queue:
            entry = queue.popleft()
            if entry.is_usable(now, self._max_idle_seconds):
                if not queue:
                    self._pool.pop(key, None)
                entry.last_used_at = now
                entry.request_count += 1
                self._reuse_count += 1
                return entry
            entry.close()

        self._pool.pop(key, None)
        if scope:
            # Close idle shared read-only sockets on this host before opening a dedicated connection.
            self.close_scope(host, target_port, "")
        self._fresh_count += 1
        return None

    def release_after_command(
        self,
        entry: PooledSocketEntry,
        command: str,
        *,
        should_close: bool = False,
        session_scope: str | None = None,
    ) -> bool:
        """Return a healthy verified connection to the pool if eligible, else close it."""
        eff_scope = entry.pool_scope if session_scope is None else session_scope
        entry.pool_scope = eff_scope
        now = self._monotonic()
        if (
            should_close
            or not is_poolable_command(command, session_scope=eff_scope or None)
            or not entry.is_usable(now, self._max_idle_seconds)
        ):
            entry.close()
            return False
        entry.last_used_at = now
        self._pool[(entry.host, int(entry.port), eff_scope)].append(entry)
        return True

    def close_scope(self, host: str, port: int, session_scope: str = "") -> int:
        """Close all pooled connections for `(host, port, session_scope)`."""
        key = (host, int(port), session_scope)
        queue = self._pool.pop(key, None)
        if not queue:
            return 0
        count = 0
        while queue:
            entry = queue.popleft()
            entry.close()
            count += 1
        return count

    def close_session_scope(self, session_scope: str) -> int:
        """Close all pooled connections associated with `session_scope` across all hosts."""
        if not session_scope:
            return 0
        total = 0
        for host, port, scope in list(self._pool.keys()):
            if scope == session_scope:
                total += self.close_scope(host, port, scope)
        return total

    def close_host(self, host: str, port: int) -> int:
        """Close all pooled connections across all scopes for `(host, port)`."""
        target_port = int(port)
        total = 0
        for h, p, scope in list(self._pool.keys()):
            if h == host and p == target_port:
                total += self.close_scope(h, p, scope)
        return total

    def close_all(self) -> int:
        """Close all pooled connections across all hosts and scopes."""
        total = 0
        for h, p, scope in list(self._pool.keys()):
            total += self.close_scope(h, p, scope)
        return total

    def pooled_count(
        self,
        host: str | None = None,
        port: int | None = None,
        *,
        session_scope: str | None = None,
    ) -> int:
        """Return the number of currently pooled idle connections."""
        target_port = int(port) if port is not None else None
        total = 0
        for (h, p, s), queue in self._pool.items():
            if host is not None and h != host:
                continue
            if target_port is not None and p != target_port:
                continue
            if session_scope is not None and s != session_scope:
                continue
            total += len(queue)
        return total


@dataclass(frozen=True)
class _TransportPoolContext:
    """Per-request command and derived session scope propagated via `ContextVar` to the connector."""

    command: str
    session_scope: str = ""


_transport_pool_ctx: ContextVar[_TransportPoolContext | None] = ContextVar(
    "arodonata_transport_pool_ctx",
    default=None,
)


__all__ = [
    "KEEPALIVE_IDLE_LIMIT_SECONDS",
    "MAX_KEEPALIVE_REQUESTS_PER_SOCKET",
    "NON_POOLABLE_SESSION_COMMANDS",
    "PooledSocketEntry",
    "VerifiedConnectionPool",
    "_TransportPoolContext",
    "_transport_pool_ctx",
    "derive_session_pool_scope",
    "is_poolable_command",
    "is_readonly_poolable_command",
]
