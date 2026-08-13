"""Tests for the Postgres cache adapter (CachePort implementation).

Mocks the wrapped `CacheRepository` with `unittest.mock.AsyncMock`; no real
database. Covers CachePort conformance and pass-through delegation for every
adapter method, including the `get_rulebase` model-class mapping/filter
construction.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.adapters.cache.postgres_adapter import PostgresCacheAdapter
from arodonata.cache.models import RulebaseAccess, RulebaseHTTPS, RulebaseNAT, RulebaseThreat
from arodonata.ports import CachePort

# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_postgres_adapter_satisfies_cache_port():
    adapter = PostgresCacheAdapter(MagicMock())
    assert isinstance(adapter, CachePort)


def test_plain_object_does_not_satisfy_cache_port():
    class NotAnAdapter:
        pass

    assert not isinstance(NotAnAdapter(), CachePort)


# ---------------------------------------------------------------------------
# get_objects
# ---------------------------------------------------------------------------


async def test_get_objects_without_filters_delegates_with_none_defaults():
    mock_repo = AsyncMock()
    mock_repo.get_objects = AsyncMock(return_value=[])
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_objects()

    mock_repo.get_objects.assert_awaited_once_with(
        object_type=None,
        mgmt_names=None,
        domain_names=None,
        filters=None,
    )
    assert result == []


async def test_get_objects_with_filters_delegates_verbatim():
    mock_repo = AsyncMock()
    expected = [{"uid": "1"}]
    mock_repo.get_objects = AsyncMock(return_value=expected)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_objects(
        object_type="host",
        mgmt_names=["mgmt1"],
        domain_names=["dmn1"],
        filters={"name": "srv1"},
    )

    mock_repo.get_objects.assert_awaited_once_with(
        object_type="host",
        mgmt_names=["mgmt1"],
        domain_names=["dmn1"],
        filters={"name": "srv1"},
    )
    assert result is expected


# ---------------------------------------------------------------------------
# get_object_by_uid
# ---------------------------------------------------------------------------


async def test_get_object_by_uid_found():
    mock_repo = AsyncMock()
    obj = MagicMock()
    mock_repo.get_object_by_uid = AsyncMock(return_value=obj)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_object_by_uid("uid1", "mgmt1", "dmn1")

    mock_repo.get_object_by_uid.assert_awaited_once_with(uid="uid1", mgmt_name="mgmt1", domain_name="dmn1")
    assert result is obj


async def test_get_object_by_uid_not_found_returns_none():
    mock_repo = AsyncMock()
    mock_repo.get_object_by_uid = AsyncMock(return_value=None)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_object_by_uid("missing", "mgmt1", "dmn1")

    assert result is None


# ---------------------------------------------------------------------------
# upsert_objects
# ---------------------------------------------------------------------------


async def test_upsert_objects_returns_count():
    mock_repo = AsyncMock()
    mock_repo.upsert_objects = AsyncMock(return_value=3)
    adapter = PostgresCacheAdapter(mock_repo)

    objects = [MagicMock(), MagicMock(), MagicMock()]
    result = await adapter.upsert_objects(objects)

    mock_repo.upsert_objects.assert_awaited_once_with(objects)
    assert result == 3


async def test_upsert_objects_empty_list_returns_zero():
    mock_repo = AsyncMock()
    mock_repo.upsert_objects = AsyncMock(return_value=0)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.upsert_objects([])

    assert result == 0


# ---------------------------------------------------------------------------
# delete_object
# ---------------------------------------------------------------------------


async def test_delete_object_found_returns_one():
    mock_repo = AsyncMock()
    mock_repo.delete_object = AsyncMock(return_value=1)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.delete_object("uid1", "mgmt1", "dmn1")

    mock_repo.delete_object.assert_awaited_once_with("uid1", "mgmt1", "dmn1")
    assert result == 1


async def test_delete_object_absent_returns_zero():
    mock_repo = AsyncMock()
    mock_repo.delete_object = AsyncMock(return_value=0)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.delete_object("missing", "mgmt1", "dmn1")

    assert result == 0


# ---------------------------------------------------------------------------
# get_domains / get_gateways / get_last_published_session
# ---------------------------------------------------------------------------


async def test_get_domains_delegates_to_repository():
    mock_repo = AsyncMock()
    domains = [MagicMock(domain_name="dmn1")]
    mock_repo.get_domains = AsyncMock(return_value=domains)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_domains(mgmt_names=["mgmt1"])

    mock_repo.get_domains.assert_awaited_once_with(mgmt_names=["mgmt1"])
    assert result == domains


async def test_get_gateways_delegates_to_repository_get_assets():
    mock_repo = AsyncMock()
    gateways = [MagicMock()]
    mock_repo.get_assets = AsyncMock(return_value=gateways)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_gateways(mgmt_names=["mgmt1"])

    mock_repo.get_assets.assert_awaited_once_with(mgmt_names=["mgmt1"])
    assert result == gateways


async def test_get_last_published_session_delegates():
    mock_repo = AsyncMock()
    session = MagicMock()
    mock_repo.get_last_published_session = AsyncMock(return_value=session)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_last_published_session("mgmt1", "dmn1")

    mock_repo.get_last_published_session.assert_awaited_once_with(mgmt_name="mgmt1", domain_name="dmn1")
    assert result is session


async def test_get_last_published_session_none_when_absent():
    mock_repo = AsyncMock()
    mock_repo.get_last_published_session = AsyncMock(return_value=None)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_last_published_session("mgmt1", "dmn1")

    assert result is None


# ---------------------------------------------------------------------------
# get_rulebase
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rulebase_type,model_class",
    [
        ("access", RulebaseAccess),
        ("nat", RulebaseNAT),
        ("https", RulebaseHTTPS),
        ("threat", RulebaseThreat),
    ],
)
async def test_get_rulebase_maps_type_to_model_class(rulebase_type, model_class):
    mock_repo = AsyncMock()
    mock_repo.get_rulebase = AsyncMock(return_value=[])
    adapter = PostgresCacheAdapter(mock_repo)

    await adapter.get_rulebase(rulebase_type)

    mock_repo.get_rulebase.assert_awaited_once_with(
        model_class=model_class,
        mgmt_names=None,
        domain_names=None,
        filters=None,
    )


async def test_get_rulebase_unknown_type_returns_empty_without_calling_repo():
    mock_repo = AsyncMock()
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_rulebase("bogus-type")

    assert result == []
    mock_repo.get_rulebase.assert_not_called()


async def test_get_rulebase_builds_filters_from_layer_name_and_enabled_only():
    mock_repo = AsyncMock()
    mock_repo.get_rulebase = AsyncMock(return_value=[])
    adapter = PostgresCacheAdapter(mock_repo)

    await adapter.get_rulebase(
        "access",
        layer_name="Network",
        mgmt_names=["mgmt1"],
        domain_names=["dmn1"],
        enabled_only=True,
    )

    mock_repo.get_rulebase.assert_awaited_once_with(
        model_class=RulebaseAccess,
        mgmt_names=["mgmt1"],
        domain_names=["dmn1"],
        filters={"layer_name": "Network", "enabled": True},
    )


async def test_get_rulebase_enabled_only_false_is_included_in_filters():
    mock_repo = AsyncMock()
    mock_repo.get_rulebase = AsyncMock(return_value=[])
    adapter = PostgresCacheAdapter(mock_repo)

    await adapter.get_rulebase("nat", enabled_only=False)

    mock_repo.get_rulebase.assert_awaited_once_with(
        model_class=RulebaseNAT,
        mgmt_names=None,
        domain_names=None,
        filters={"enabled": False},
    )


async def test_get_rulebase_returns_repository_result():
    mock_repo = AsyncMock()
    rules = [MagicMock(), MagicMock()]
    mock_repo.get_rulebase = AsyncMock(return_value=rules)
    adapter = PostgresCacheAdapter(mock_repo)

    result = await adapter.get_rulebase("threat")

    assert result == rules
