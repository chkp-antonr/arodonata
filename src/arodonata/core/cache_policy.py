"""Value objects for cache refresh policy resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from arodonata.core.cache_mode import CacheMode


class Clock(Protocol):
    """Injectable time source (keeps staleness logic deterministic in tests)."""

    def now(self) -> datetime: ...


class SystemClock:
    """Default wall-clock implementation (naive UTC, matches cache timestamps)."""

    def now(self) -> datetime:
        return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class CachePolicy:
    """What a caller wants for a single read: a mode and an optional freshness TTL."""

    mode: CacheMode
    ttl: int | None = None

    @classmethod
    def resolve(
        cls,
        mode: CacheMode | str | None,
        ttl: int | None,
        default: CachePolicy,
    ) -> CachePolicy:
        """Merge a per-call (mode, ttl) with the client default.

        A None call arg falls back to the default's value for that field.
        """
        if mode is None:
            resolved_mode = default.mode
        else:
            resolved_mode = CacheMode(mode)
        resolved_ttl = ttl if ttl is not None else default.ttl
        return cls(mode=resolved_mode, ttl=resolved_ttl)


@dataclass(frozen=True)
class RefreshScope:
    """The management servers / domains a read touches (None = all in scope)."""

    mgmt_names: list[str] | None = None
    domain_names: list[str] | None = None


@dataclass
class RefreshOutcome:
    """Result of a coordinator.ensure() call, for logging/telemetry and tests."""

    mode_used: CacheMode
    refreshed_domains: list[tuple[str, str]] = field(default_factory=list)
    fell_back: bool = False
    skipped_reason: str | None = None
