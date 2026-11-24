"""Per-client sliding-window tool quota management for the Arodonata MCP server (`arodonata.mcp.quota`)."""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from arodonata.mcp.config import ArodonataMCPSettings

QuotaBucket = Literal["general", "live"]


@dataclass(frozen=True, slots=True)
class QuotaDecision:
    """Outcome of evaluating a single MCP tool invocation against a client's sliding-window quota."""

    allowed: bool
    client_id: str
    bucket: QuotaBucket
    limit: int
    remaining: int
    retry_after_seconds: float


class MCPToolQuotaManager:
    """Asyncio-safe per-client sliding-window rate limiter for MCP tool calls.

    Tracks general tool invocations and stricter live/mutating tool invocations separately
    per `client_id` (defaulting to `"anonymous"` when unauthenticated). All state updates
    occur synchronously without yielding across `await` boundaries, ensuring atomic window
    accounting in single-threaded asyncio event loops. Setting a limit to `0` disables
    enforcement for that bucket.
    """

    def __init__(
        self,
        *,
        rate_limit_per_minute: int = 120,
        live_rate_limit_per_minute: int = 30,
        window_seconds: float = 60.0,
        monotonic_fn: Callable[[], float] = time.monotonic,
        max_tracked_clients: int = 4096,
    ) -> None:
        if rate_limit_per_minute < 0:
            raise ValueError("rate_limit_per_minute must be >= 0.")
        if live_rate_limit_per_minute < 0:
            raise ValueError("live_rate_limit_per_minute must be >= 0.")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0.")
        if max_tracked_clients < 1:
            raise ValueError("max_tracked_clients must be >= 1.")

        self._general_limit = int(rate_limit_per_minute)
        self._live_limit = int(live_rate_limit_per_minute)
        self._window_seconds = float(window_seconds)
        self._monotonic = monotonic_fn
        self._max_tracked_clients = int(max_tracked_clients)
        self._clients: OrderedDict[str, tuple[deque[float], deque[float]]] = OrderedDict()

    @classmethod
    def from_settings(
        cls,
        mcp_settings: ArodonataMCPSettings,
        *,
        monotonic_fn: Callable[[], float] = time.monotonic,
    ) -> MCPToolQuotaManager:
        """Construct an `MCPToolQuotaManager` configured from `ArodonataMCPSettings`."""
        return cls(
            rate_limit_per_minute=mcp_settings.tool_rate_limit_per_minute,
            live_rate_limit_per_minute=mcp_settings.live_tool_rate_limit_per_minute,
            monotonic_fn=monotonic_fn,
        )

    @property
    def rate_limit_per_minute(self) -> int:
        """Configured per-client general tool calls allowed per window (`0` = unlimited)."""
        return self._general_limit

    @property
    def live_rate_limit_per_minute(self) -> int:
        """Configured per-client live/mutating tool calls allowed per window (`0` = unlimited)."""
        return self._live_limit

    @property
    def window_seconds(self) -> float:
        """Sliding window length in seconds."""
        return self._window_seconds

    def _get_buckets(self, client_id: str) -> tuple[deque[float], deque[float]]:
        buckets = self._clients.get(client_id)
        if buckets is None:
            buckets = (deque(), deque())
            self._clients[client_id] = buckets
        else:
            self._clients.move_to_end(client_id)
        while len(self._clients) > self._max_tracked_clients:
            self._clients.popitem(last=False)
        return buckets

    def check_and_consume(
        self,
        client_id: str | None,
        *,
        is_live: bool = False,
    ) -> QuotaDecision:
        """Check per-client quotas and consume a slot if permitted."""
        clean_cid = client_id.strip() if isinstance(client_id, str) and client_id.strip() else "anonymous"
        if self._general_limit == 0 and (not is_live or self._live_limit == 0):
            return QuotaDecision(
                allowed=True,
                client_id=clean_cid,
                bucket="live" if is_live else "general",
                limit=0,
                remaining=-1,
                retry_after_seconds=0.0,
            )

        general_dq, live_dq = self._get_buckets(clean_cid)

        now = float(self._monotonic())
        cutoff = now - self._window_seconds

        while general_dq and general_dq[0] <= cutoff:
            general_dq.popleft()
        while live_dq and live_dq[0] <= cutoff:
            live_dq.popleft()

        # Validate both buckets before mutating either so a live rejection never consumes general quota.
        if is_live and self._live_limit > 0 and len(live_dq) >= self._live_limit:
            retry_after = max(0.001, round((live_dq[0] + self._window_seconds) - now, 3))
            return QuotaDecision(
                allowed=False,
                client_id=clean_cid,
                bucket="live",
                limit=self._live_limit,
                remaining=0,
                retry_after_seconds=retry_after,
            )

        if self._general_limit > 0 and len(general_dq) >= self._general_limit:
            retry_after = max(0.001, round((general_dq[0] + self._window_seconds) - now, 3))
            return QuotaDecision(
                allowed=False,
                client_id=clean_cid,
                bucket="general",
                limit=self._general_limit,
                remaining=0,
                retry_after_seconds=retry_after,
            )

        if self._general_limit > 0:
            general_dq.append(now)
        if is_live and self._live_limit > 0:
            live_dq.append(now)

        if is_live and self._live_limit > 0:
            live_rem = max(0, self._live_limit - len(live_dq))
            if self._general_limit > 0:
                gen_rem = max(0, self._general_limit - len(general_dq))
                remaining = min(live_rem, gen_rem)
            else:
                remaining = live_rem
            return QuotaDecision(
                allowed=True,
                client_id=clean_cid,
                bucket="live",
                limit=self._live_limit,
                remaining=remaining,
                retry_after_seconds=0.0,
            )

        remaining = max(0, self._general_limit - len(general_dq)) if self._general_limit > 0 else -1
        return QuotaDecision(
            allowed=True,
            client_id=clean_cid,
            bucket="general",
            limit=self._general_limit,
            remaining=remaining,
            retry_after_seconds=0.0,
        )

    def check_and_consume_live_only(self, client_id: str | None, *, cost: int = 1) -> QuotaDecision:
        """Check and consume `cost` slots from the `live` quota bucket after `general` was already charged."""
        eff_cost = max(1, int(cost))
        clean_cid = client_id.strip() if isinstance(client_id, str) and client_id.strip() else "anonymous"
        if self._live_limit == 0:
            return QuotaDecision(
                allowed=True,
                client_id=clean_cid,
                bucket="live",
                limit=0,
                remaining=-1,
                retry_after_seconds=0.0,
            )

        _general_dq, live_dq = self._get_buckets(clean_cid)
        now = float(self._monotonic())
        cutoff = now - self._window_seconds
        while live_dq and live_dq[0] <= cutoff:
            live_dq.popleft()

        if len(live_dq) + eff_cost > self._live_limit:
            oldest = live_dq[0] if live_dq else now
            retry_after = max(0.001, round((oldest + self._window_seconds) - now, 3))
            return QuotaDecision(
                allowed=False,
                client_id=clean_cid,
                bucket="live",
                limit=self._live_limit,
                remaining=max(0, self._live_limit - len(live_dq)),
                retry_after_seconds=retry_after,
            )

        for _ in range(eff_cost):
            live_dq.append(now)
        return QuotaDecision(
            allowed=True,
            client_id=clean_cid,
            bucket="live",
            limit=self._live_limit,
            remaining=max(0, self._live_limit - len(live_dq)),
            retry_after_seconds=0.0,
        )

    def live_bucket_count(self, client_id: str | None) -> int:
        """Return the number of active (non-expired) slots in `client_id`'s `live` quota bucket."""
        clean_cid = client_id.strip() if isinstance(client_id, str) and client_id.strip() else "anonymous"
        buckets = self._clients.get(clean_cid)
        if buckets is None:
            return 0
        _general_dq, live_dq = buckets
        cutoff = float(self._monotonic()) - self._window_seconds
        while live_dq and live_dq[0] <= cutoff:
            live_dq.popleft()
        return len(live_dq)

    def rollback_consumed(self, client_id: str | None, *, general: int = 0, live: int = 0) -> None:
        """Roll back up to `general` and `live` most-recently consumed slots for `client_id`."""
        clean_cid = client_id.strip() if isinstance(client_id, str) and client_id.strip() else "anonymous"
        buckets = self._clients.get(clean_cid)
        if buckets is None:
            return
        general_dq, live_dq = buckets
        for _ in range(max(0, int(general))):
            if general_dq:
                general_dq.pop()
        for _ in range(max(0, int(live))):
            if live_dq:
                live_dq.pop()


__all__ = [
    "MCPToolQuotaManager",
    "QuotaBucket",
    "QuotaDecision",
]
