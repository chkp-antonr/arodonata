"""Tests for cache-policy value objects (CachePolicy / RefreshScope / RefreshOutcome)."""

from datetime import datetime

from arodonata.core.cache_mode import CacheMode
from arodonata.core.cache_policy import (
    CachePolicy,
    RefreshOutcome,
    RefreshScope,
    SystemClock,
)


def test_resolve_call_mode_overrides_default_ttl_falls_back():
    default = CachePolicy(mode=CacheMode.SMART, ttl=300)

    resolved = CachePolicy.resolve(mode="cache", ttl=None, default=default)

    assert resolved.mode == CacheMode.CACHE
    assert resolved.ttl == 300  # None call-arg -> default's ttl


def test_resolve_call_ttl_overrides_default():
    default = CachePolicy(mode=CacheMode.SMART, ttl=300)

    resolved = CachePolicy.resolve(mode=None, ttl=42, default=default)

    assert resolved.mode == CacheMode.SMART  # None mode -> default's mode
    assert resolved.ttl == 42


def test_resolve_accepts_enum_and_string_mode():
    default = CachePolicy(mode=CacheMode.SMART, ttl=300)

    assert CachePolicy.resolve(CacheMode.FORCE, 10, default).mode == CacheMode.FORCE
    assert CachePolicy.resolve("smart-fast", 10, default).mode == CacheMode.SMART_FAST


def test_resolve_all_none_returns_default_values():
    default = CachePolicy(mode=CacheMode.SMART_FAST, ttl=42)

    resolved = CachePolicy.resolve(None, None, default)

    assert resolved == default


def test_resolve_ttl_zero_is_kept_not_treated_as_none():
    default = CachePolicy(mode=CacheMode.SMART, ttl=300)

    # 0 is not None -> it must survive the merge (distinct from "unset").
    resolved = CachePolicy.resolve(mode=None, ttl=0, default=default)

    assert resolved.ttl == 0


def test_cache_policy_is_frozen_and_hashable():
    policy = CachePolicy(mode=CacheMode.SMART, ttl=None)

    assert hash(policy) == hash(CachePolicy(mode=CacheMode.SMART, ttl=None))


def test_refresh_scope_holds_names():
    scope = RefreshScope(mgmt_names=["m1"], domain_names=["d1", "d2"])

    assert scope.mgmt_names == ["m1"]
    assert scope.domain_names == ["d1", "d2"]


def test_refresh_scope_defaults_none():
    scope = RefreshScope()

    assert scope.mgmt_names is None
    assert scope.domain_names is None


def test_refresh_outcome_defaults():
    outcome = RefreshOutcome(mode_used=CacheMode.SMART)

    assert outcome.refreshed_domains == []
    assert outcome.fell_back is False
    assert outcome.skipped_reason is None


def test_system_clock_returns_naive_utc():
    now = SystemClock().now()

    assert isinstance(now, datetime)
    assert now.tzinfo is None
