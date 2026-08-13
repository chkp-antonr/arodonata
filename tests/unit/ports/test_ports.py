"""Tests that the shared doubles satisfy the current CachePort/ApiPort protocols."""

from arodonata.ports import ApiPort, CachePort
from tests.unit.doubles import FakeApi, FakeCache


def test_fake_cache_satisfies_cache_port():
    fake = FakeCache()
    assert isinstance(fake, CachePort)


def test_fake_api_satisfies_api_port():
    fake = FakeApi()
    assert isinstance(fake, ApiPort)
