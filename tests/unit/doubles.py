"""Shared test doubles for the unit suite.

These are canonical, protocol-satisfying fakes for the two ports used across
`arodonata`: `CachePort` and `ApiPort`. Import them from here rather than
redefining ad-hoc fakes in individual test modules, so every test in the
suite exercises the same structural contract.

Sourced from the retired suite (`.internal/tests_backup_v1/unit/v2/test_ports.py`)
and updated to match the current protocol definitions in
`src/arodonata/ports/cache_port.py` and `src/arodonata/ports/api_port.py`.
"""

from typing import Any, Literal

from arodonata.api.schemas import ApiQueryResult
from arodonata.cache.models import CPObject, Domain, LastPublishedSession


class FakeCache:
    """Minimal in-memory-free double satisfying `CachePort`."""

    async def get_objects(
        self,
        object_type: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[CPObject]:
        return []

    async def get_object_by_uid(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str,
    ) -> CPObject | None:
        return None

    async def upsert_objects(self, objects: list[CPObject]) -> int:
        return len(objects)

    async def replace_domain_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        objects: list[CPObject],
    ) -> tuple[int, int]:
        return 0, len(objects)

    async def delete_object(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str,
    ) -> int:
        return 0

    async def get_domains(self, mgmt_names: list[str] | None = None) -> list[Domain]:
        return []

    async def get_gateways(self, mgmt_names: list[str] | None = None) -> list[Any]:
        return []

    async def get_last_published_session(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> LastPublishedSession | None:
        return None

    async def get_rulebase(
        self,
        rulebase_type: str,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
    ) -> list[Any]:
        return []


class FakeApi:
    """Minimal double satisfying `ApiPort`."""

    async def query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        payload: dict[str, Any] | None = None,
        details_level: Literal["uid", "standard", "full"] = "standard",
        container_key: str | None = None,
    ) -> ApiQueryResult:
        return ApiQueryResult(success=True, data=[], objects=[], message="", code="", total=0)

    async def show_changes(
        self,
        mgmt_name: str,
        domain: str = "",
        from_session: str | None = None,
        from_date: str | None = None,
        to_session: str | None = None,
        to_date: str | None = None,
    ) -> Any:
        return None

    async def publish(self, mgmt_name: str, domain: str = "") -> Any:
        return None

    def get_mgmt_names(self) -> list[str]:
        return []
