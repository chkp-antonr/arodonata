"""Unit tests for `HybridStateReader` (`src/arodonata/cpcrud/state_reader.py`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService
from arodonata.cpcrud.models import DomainStamp
from arodonata.cpcrud.state_reader import HybridStateReader, StateLookupError, normalize_mask_length


class ReaderFakeApi:
    """Configurable `ApiPort` double for `HybridStateReader` unit tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any] | None, str | None]] = []
        self.queries: list[tuple[str, str, str | None]] = []
        self.fail_api_call: bool = False
        self.paging_inconsistent: bool = False

    async def api_call(
        self,
        mgmt_name: str,
        command: str,
        payload: dict[str, Any] | None = None,
        *,
        domain: str | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        wait_for_task: bool = True,
        timeout: float | None = None,
    ) -> ApiCallResult:
        self.calls.append((mgmt_name, command, payload, domain))
        if self.fail_api_call:
            return ApiCallResult(
                success=False,
                status_code=500,
                error_code="generic_err",
                error_message="Backend API timeout",
            )
        if command == "show-host" and payload and payload.get("name") == "live-host-1":
            return ApiCallResult(
                success=True,
                data={
                    "uid": "h-live-1",
                    "name": "live-host-1",
                    "type": "host",
                    "ipv4-address": "10.20.1.1",
                },
            )
        if command == "show-service-tcp" and payload and payload.get("name") == "live-tcp-9000":
            return ApiCallResult(
                success=True,
                data={
                    "uid": "s-live-9000",
                    "name": "live-tcp-9000",
                    "type": "service-tcp",
                    "port": "9000",
                    "protocol": "tcp",
                },
            )
        return ApiCallResult(
            success=False,
            status_code=404,
            error_code="generic_err_object_not_found",
            error_message="Requested object [not_found] not found",
        )

    async def api_query(
        self,
        mgmt_name: str,
        command: str,
        *,
        domain: str | None = None,
        details_level: str = "standard",
        payload: dict[str, Any] | None = None,
        sid: str | None = None,
        server_ip: str | None = None,
        limit: int = 300,
    ) -> ApiQueryResult:
        self.queries.append((mgmt_name, command, domain))
        if self.paging_inconsistent:
            return ApiQueryResult(
                success=False,
                code="paging_inconsistent",
                error_message="Concurrent publish detected during pagination",
            )
        if command == "show-hosts":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "h-live-1",
                        "name": "live-host-1",
                        "type": "host",
                        "ipv4-address": "10.20.1.1",
                    }
                ],
                total=1,
            )
        if command == "show-services-tcp":
            return ApiQueryResult(
                success=True,
                objects=[
                    {
                        "uid": "s-live-9000",
                        "name": "live-tcp-9000",
                        "type": "service-tcp",
                        "port": "9000",
                        "protocol": "tcp",
                    }
                ],
                total=1,
            )
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
        return "sid", "10.0.0.1"

    async def logout_sid(self, *args: Any, **kwargs: Any) -> bool:
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.asyncio
async def test_hybrid_state_reader_uses_cache_when_stamp_matches_and_falls_back_when_stale() -> None:
    """`HybridStateReader` reads from `arodonata_objects` / `arodonata_services` when `domain_sync_state` matches `DomainStamp`, and falls back to live API calls otherwise."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = ReaderFakeApi()

    pub_at = datetime(2026, 10, 24, 8, 0, 0, tzinfo=UTC)
    stamp = DomainStamp(
        mgmt_name="mds1",
        domain_name="Corp",
        last_session_uid="sess-pub-100",
        last_published_at=pub_at,
        readable=True,
    )

    # Seed cache with a host and a service-tcp, and mark only ("objects", "host") as fresh matching stamp
    await cache.upsert_objects(
        [
            CPObject(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="h-cached-1",
                name="cached-host-1",
                type="host",
                ipv4_address="10.10.1.1",
            )
        ]
    )
    await cache.upsert_services(
        [
            CPService(
                mgmt_name="mds1",
                domain_name="Corp",
                uid="s-cached-8080",
                name="cached-tcp-8080",
                type="service-tcp",
                port="8080",
            )
        ]
    )
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="Corp",
            scope="objects",
            item_type="host",
            last_session_uid="sess-pub-100",
            last_published_at=pub_at,
            status="ok",
        )
    )
    # Service slice has an older session UID -> stale!
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="Corp",
            scope="services",
            item_type="service-tcp",
            last_session_uid="sess-pub-099",
            last_published_at=pub_at,
            status="ok",
        )
    )

    reader = HybridStateReader(api=api, cache=cache, domain_stamps={stamp.key: stamp})

    # 1. Host slice matches stamp -> served from SQLite cache with ZERO live API calls
    host = await reader.get_object_by_name("mds1", "Corp", "host", "cached-host-1")
    assert host is not None and host.uid == "h-cached-1"
    hosts_by_ip = await reader.find_host_by_ip("mds1", "Corp", "10.10.1.1")
    assert [h.name for h in hosts_by_ip] == ["cached-host-1"]
    assert api.calls == []
    assert api.queries == []

    # 2. Service slice has mismatched session UID -> falls back to live API calls
    svc = await reader.get_service_by_name("mds1", "Corp", "service-tcp", "live-tcp-9000")
    assert svc is not None and svc.uid == "s-live-9000"
    assert len(api.calls) == 1 and api.calls[0][1] == "show-service-tcp"

    svcs_by_port = await reader.find_service_by_port("mds1", "Corp", "service-tcp", "9000")
    assert [s.name for s in svcs_by_port] == ["live-tcp-9000"]
    assert len(api.queries) == 1 and api.queries[0][1] == "show-services-tcp"

    await db.close()


@pytest.mark.asyncio
async def test_hybrid_state_reader_raises_state_lookup_error_on_api_or_paging_failure() -> None:
    """`HybridStateReader` raises `StateLookupError` on API errors or `paging_inconsistent`."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)
    api = ReaderFakeApi()

    stamp = DomainStamp(
        mgmt_name="mds1",
        domain_name="Corp",
        last_session_uid="sess-pub-100",
        readable=True,
    )
    reader = HybridStateReader(api=api, cache=cache, domain_stamps={stamp.key: stamp})

    api.fail_api_call = True
    with pytest.raises(StateLookupError, match="Backend API timeout"):
        await reader.get_object_by_name("mds1", "Corp", "host", "any-host")

    api.fail_api_call = False
    api.paging_inconsistent = True
    with pytest.raises(StateLookupError, match="Concurrent publish detected"):
        await reader.find_host_by_ip("mds1", "Corp", "10.20.1.1")

    await db.close()


def test_normalize_mask_length_handles_prefix_and_dotted_quad() -> None:
    """`normalize_mask_length` converts prefix ints/strings and dotted-quad subnet masks."""
    assert normalize_mask_length(24) == 24
    assert normalize_mask_length("16") == 16
    assert normalize_mask_length(None, "255.255.255.0") == 24
    assert normalize_mask_length(None, "255.255.255.252") == 30
    assert normalize_mask_length(None, "invalid-mask") is None
