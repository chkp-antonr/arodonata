"""Unit tests for arodonata.helpers.objects (cache-first network-object helpers)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from arodonata.cache.models import CPObject
from arodonata.cache.object_service import GroupNode, SearchResult, SearchType
from arodonata.helpers._context import UserContext
from arodonata.helpers.objects import find_object, get_group_members, get_objects

_USER = UserContext(username="admin", source="test")


def _make_object(uid: str, name: str, obj_type: str) -> CPObject:
    return CPObject(
        id=f"mgmt1:dmn1:{uid}",
        uid=uid,
        name=name,
        type=obj_type,
        mgmt_name="mgmt1",
        domain_name="dmn1",
    )


class TestFindObject:
    """Tests for find_object() across cache_mode dispatch."""

    @pytest.mark.asyncio
    async def test_cache_mode_queries_db_only(self):
        host = _make_object("uid-host", "srv1", "host")
        mock_client = MagicMock()
        mock_client._object_service._fetch_objects_from_db = AsyncMock(return_value=[host])

        result = await find_object(mock_client, "srv1", cache_mode="cache")

        assert result is not None
        assert result.uid == "uid-host"
        mock_client._object_service._fetch_objects_from_db.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cache_mode_filters_by_object_type(self):
        host = _make_object("uid-host", "srv1", "host")
        network = _make_object("uid-net", "srv1", "network")
        mock_client = MagicMock()
        mock_client._object_service._fetch_objects_from_db = AsyncMock(return_value=[network, host])

        result = await find_object(mock_client, "srv1", object_type="host", cache_mode="cache")

        assert result is not None
        assert result.uid == "uid-host"

    @pytest.mark.asyncio
    async def test_cache_mode_returns_none_when_type_mismatch(self):
        network = _make_object("uid-net", "srv1", "network")
        mock_client = MagicMock()
        mock_client._object_service._fetch_objects_from_db = AsyncMock(return_value=[network])

        result = await find_object(mock_client, "srv1", object_type="host", cache_mode="cache")

        assert result is None

    @pytest.mark.asyncio
    async def test_cache_mode_returns_none_when_no_results(self):
        mock_client = MagicMock()
        mock_client._object_service._fetch_objects_from_db = AsyncMock(return_value=[])

        result = await find_object(mock_client, "srv1", cache_mode="cache")

        assert result is None

    @pytest.mark.asyncio
    async def test_smart_mode_uses_search_objects(self):
        host = _make_object("uid-host", "srv1", "host")

        async def fake_search_objects(**kwargs):
            yield SearchResult(search_term="srv1", search_type=SearchType.NAME, objects=[host])

        mock_client = MagicMock()
        mock_client._object_service.search_objects = fake_search_objects

        result = await find_object(mock_client, "srv1", cache_mode="smart")

        assert result is not None
        assert result.uid == "uid-host"

    @pytest.mark.asyncio
    async def test_smart_mode_filters_by_object_type(self):
        host = _make_object("uid-host", "srv1", "host")
        network = _make_object("uid-net", "srv1", "network")

        async def fake_search_objects(**kwargs):
            yield SearchResult(search_term="srv1", search_type=SearchType.NAME, objects=[network, host])

        mock_client = MagicMock()
        mock_client._object_service.search_objects = fake_search_objects

        result = await find_object(mock_client, "srv1", object_type="host", cache_mode="smart")

        assert result is not None
        assert result.uid == "uid-host"

    @pytest.mark.asyncio
    async def test_smart_mode_returns_none_when_no_results(self):
        async def fake_search_objects(**kwargs):
            return
            yield  # pragma: no cover - makes this an async generator

        mock_client = MagicMock()
        mock_client._object_service.search_objects = fake_search_objects

        result = await find_object(mock_client, "srv1", cache_mode="smart")

        assert result is None

    @pytest.mark.asyncio
    async def test_force_mode_with_results_triggers_refresh_and_research(self):
        host = _make_object("uid-host", "srv1", "host")
        refreshed_host = _make_object("uid-host", "srv1", "host")

        search_calls = []

        async def fake_search_objects(**kwargs):
            search_calls.append(kwargs)
            if len(search_calls) == 1:
                yield SearchResult(search_term="srv1", search_type=SearchType.NAME, objects=[host])
            else:
                yield SearchResult(search_term="srv1", search_type=SearchType.NAME, objects=[refreshed_host])

        refresh_calls = []

        async def fake_refresh_objects(**kwargs):
            refresh_calls.append(kwargs)
            yield {"message": "refreshing"}

        mock_client = MagicMock()
        mock_client._object_service.search_objects = fake_search_objects
        mock_client._object_service.refresh_objects = fake_refresh_objects

        result = await find_object(mock_client, "srv1", cache_mode="force")

        assert result is not None
        assert result.uid == "uid-host"
        assert len(search_calls) == 2
        assert len(refresh_calls) == 1
        assert refresh_calls[0]["mode"] == "force"

    @pytest.mark.asyncio
    async def test_force_mode_without_initial_results_skips_refresh(self):
        async def fake_search_objects(**kwargs):
            yield SearchResult(search_term="srv1", search_type=SearchType.NAME, objects=[])

        mock_client = MagicMock()
        mock_client._object_service.search_objects = fake_search_objects
        mock_client._object_service.refresh_objects = AsyncMock()

        result = await find_object(mock_client, "srv1", cache_mode="force")

        assert result is None
        mock_client._object_service.refresh_objects.assert_not_called()

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        mock_client = MagicMock()
        mock_client._object_service._fetch_objects_from_db = AsyncMock(return_value=[])

        result = await find_object(mock_client, "srv1", cache_mode="cache", user_context=_USER)

        assert result is None

    @pytest.mark.asyncio
    async def test_defaults_to_smart_mode(self):
        host = _make_object("uid-host", "srv1", "host")

        async def fake_search_objects(**kwargs):
            yield SearchResult(search_term="srv1", search_type=SearchType.NAME, objects=[host])

        mock_client = MagicMock()
        mock_client._object_service.search_objects = fake_search_objects
        mock_client._object_service._fetch_objects_from_db = AsyncMock(
            side_effect=AssertionError("cache-only path should not run in smart mode")
        )

        result = await find_object(mock_client, "srv1")

        assert result is not None
        assert result.uid == "uid-host"


class TestGetObjects:
    """Tests for get_objects() cache_mode dispatch."""

    @pytest.mark.asyncio
    async def test_cache_mode_reads_cache_directly(self):
        host = _make_object("uid-host", "srv1", "host")
        mock_client = MagicMock()
        mock_client._object_service._cache.get_objects = AsyncMock(return_value=[host])
        mock_client._object_service.refresh_objects = AsyncMock()

        result = await get_objects(mock_client, "host", cache_mode="cache")

        assert result == [host]
        mock_client._object_service.refresh_objects.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_mode_passes_filters_mgmt_and_domain(self):
        mock_client = MagicMock()
        mock_client._object_service._cache.get_objects = AsyncMock(return_value=[])

        await get_objects(
            mock_client,
            "host",
            filters={"name": "srv*"},
            mgmt_name="mgmt1",
            domain_name="dmn1",
            cache_mode="cache",
        )

        mock_client._object_service._cache.get_objects.assert_awaited_once_with(
            object_type="host",
            mgmt_names=["mgmt1"],
            domain_names=["dmn1"],
            filters={"name": "srv*"},
        )

    @pytest.mark.asyncio
    async def test_force_mode_refreshes_before_reading_cache(self):
        host = _make_object("uid-host", "srv1", "host")

        refresh_calls = []

        async def fake_refresh_objects(**kwargs):
            refresh_calls.append(kwargs)
            yield {"message": "refreshing"}

        mock_client = MagicMock()
        mock_client._object_service.refresh_objects = fake_refresh_objects
        mock_client._object_service._cache.get_objects = AsyncMock(return_value=[host])

        result = await get_objects(mock_client, "host", mgmt_name="mgmt1", cache_mode="force")

        assert result == [host]
        assert len(refresh_calls) == 1
        assert refresh_calls[0]["mgmt_names"] == ["mgmt1"]
        assert refresh_calls[0]["mode"] == "force"

    @pytest.mark.asyncio
    async def test_smart_mode_reads_cache_without_refresh(self):
        """Unlike find_object, get_objects treats "smart" the same as reading cache."""
        host = _make_object("uid-host", "srv1", "host")
        mock_client = MagicMock()
        mock_client._object_service.refresh_objects = AsyncMock()
        mock_client._object_service._cache.get_objects = AsyncMock(return_value=[host])

        result = await get_objects(mock_client, "host", cache_mode="smart")

        assert result == [host]
        mock_client._object_service.refresh_objects.assert_not_called()

    @pytest.mark.asyncio
    async def test_defaults_to_smart_mode(self):
        mock_client = MagicMock()
        mock_client._object_service.refresh_objects = AsyncMock()
        mock_client._object_service._cache.get_objects = AsyncMock(return_value=[])

        result = await get_objects(mock_client, "host")

        assert result == []
        mock_client._object_service.refresh_objects.assert_not_called()

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        mock_client = MagicMock()
        mock_client._object_service._cache.get_objects = AsyncMock(return_value=[])

        result = await get_objects(mock_client, "host", cache_mode="cache", user_context=_USER)

        assert result == []

    @pytest.mark.asyncio
    async def test_no_mgmt_or_domain_name_passes_none_lists(self):
        mock_client = MagicMock()
        mock_client._object_service._cache.get_objects = AsyncMock(return_value=[])

        await get_objects(mock_client, "host", cache_mode="cache")

        mock_client._object_service._cache.get_objects.assert_awaited_once_with(
            object_type="host",
            mgmt_names=None,
            domain_names=None,
            filters=None,
        )


class TestGetGroupMembers:
    """Tests for get_group_members() async iterator."""

    @pytest.mark.asyncio
    async def test_yields_dict_per_tree_node(self):
        tree = [
            GroupNode(uid="uid-1", name="host1", domain="dmn1", depth=0),
            GroupNode(uid="uid-2", name="host2", domain="dmn1", depth=1),
        ]
        mock_client = MagicMock()
        mock_client._object_service._resolve_group_memberships = AsyncMock(return_value=tree)

        nodes = [node async for node in get_group_members(mock_client, "group-uid", "mgmt1", "dmn1")]

        assert nodes == [
            {"uid": "uid-1", "name": "host1", "domain": "dmn1", "depth": 0},
            {"uid": "uid-2", "name": "host2", "domain": "dmn1", "depth": 1},
        ]

    @pytest.mark.asyncio
    async def test_force_mode_refreshes_before_resolving(self):
        refresh_calls = []

        async def fake_refresh_objects(**kwargs):
            refresh_calls.append(kwargs)
            yield {"message": "refreshing"}

        mock_client = MagicMock()
        mock_client._object_service.refresh_objects = fake_refresh_objects
        mock_client._object_service._resolve_group_memberships = AsyncMock(return_value=[])

        nodes = [
            node async for node in get_group_members(mock_client, "group-uid", "mgmt1", "dmn1", cache_mode="force")
        ]

        assert nodes == []
        assert len(refresh_calls) == 1
        assert refresh_calls[0]["mgmt_names"] == ["mgmt1"]
        assert refresh_calls[0]["domain_names"] == ["dmn1"]
        assert refresh_calls[0]["mode"] == "force"

    @pytest.mark.asyncio
    async def test_smart_mode_skips_refresh(self):
        mock_client = MagicMock()
        mock_client._object_service.refresh_objects = AsyncMock()
        mock_client._object_service._resolve_group_memberships = AsyncMock(return_value=[])

        nodes = [
            node async for node in get_group_members(mock_client, "group-uid", "mgmt1", "dmn1", cache_mode="smart")
        ]

        assert nodes == []
        mock_client._object_service.refresh_objects.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_mode_skips_refresh(self):
        mock_client = MagicMock()
        mock_client._object_service.refresh_objects = AsyncMock()
        mock_client._object_service._resolve_group_memberships = AsyncMock(return_value=[])

        nodes = [
            node async for node in get_group_members(mock_client, "group-uid", "mgmt1", "dmn1", cache_mode="cache")
        ]

        assert nodes == []
        mock_client._object_service.refresh_objects.assert_not_called()

    @pytest.mark.asyncio
    async def test_resolves_using_given_uid_and_scope(self):
        mock_client = MagicMock()
        mock_client._object_service._resolve_group_memberships = AsyncMock(return_value=[])

        _ = [node async for node in get_group_members(mock_client, "group-uid", "mgmt1", "dmn1")]

        mock_client._object_service._resolve_group_memberships.assert_awaited_once_with(
            obj_uid="group-uid",
            mgmt_name="mgmt1",
            domain_name="dmn1",
        )

    @pytest.mark.asyncio
    async def test_logs_when_user_context_provided(self):
        mock_client = MagicMock()
        mock_client._object_service._resolve_group_memberships = AsyncMock(return_value=[])

        nodes = [
            node async for node in get_group_members(mock_client, "group-uid", "mgmt1", "dmn1", user_context=_USER)
        ]

        assert nodes == []
