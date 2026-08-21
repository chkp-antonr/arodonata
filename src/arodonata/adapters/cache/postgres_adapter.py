"""PostgreSQL cache adapter implementing CachePort protocol."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from arodonata.cache.models import CPObject, Domain, LastPublishedSession
    from arodonata.cache.repository import CacheRepository
    from arodonata.models.domains import Gateway


class PostgresCacheAdapter:
    """PostgreSQL cache adapter wrapping CacheRepository.

    Implements CachePort protocol for cache operations.
    """

    def __init__(self, repository: "CacheRepository") -> None:
        """Initialize adapter with cache repository.

        Args:
            repository: CacheRepository instance to wrap.
        """
        self._repo = repository

    async def get_objects(
        self,
        object_type: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list["CPObject"]:
        """Query objects from cache with optional filters."""
        return await self._repo.get_objects(
            object_type=object_type,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            filters=filters,
        )

    async def get_object_by_uid(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str,
    ) -> "CPObject | None":
        """Get single object by UID."""
        return await self._repo.get_object_by_uid(
            uid=uid,
            mgmt_name=mgmt_name,
            domain_name=domain_name,
        )

    async def upsert_objects(
        self,
        objects: list["CPObject"],
    ) -> int:
        """Insert or update objects. Returns count of upserted objects."""
        return await self._repo.upsert_objects(objects)

    async def replace_domain_objects(
        self,
        mgmt_name: str,
        domain_name: str,
        objects: list["CPObject"],
    ) -> tuple[int, int]:
        """Atomically replace all objects for a domain in one transaction."""
        return await self._repo.replace_domain_objects(mgmt_name, domain_name, objects)

    async def delete_object(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str,
    ) -> int:
        """Delete a single object by UID. Returns count deleted (0 if absent)."""
        return await self._repo.delete_object(uid, mgmt_name, domain_name)

    async def get_domains(
        self,
        mgmt_names: list[str] | None = None,
    ) -> list["Domain"]:
        """Get cached domains."""
        return await self._repo.get_domains(mgmt_names=mgmt_names)

    async def get_gateways(
        self,
        mgmt_names: list[str] | None = None,
    ) -> list["Gateway"]:
        """Get cached gateways and servers."""
        return await self._repo.get_assets(mgmt_names=mgmt_names)  # type: ignore[return-value]

    async def get_last_published_session(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> "LastPublishedSession | None":
        """Get last published session for smart refresh."""
        return await self._repo.get_last_published_session(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
        )

    async def get_rulebase(
        self,
        rulebase_type: str,
        layer_name: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        enabled_only: bool | None = None,
    ) -> list[Any]:
        """Get rulebase rules from cache.

        Args:
            rulebase_type: Type of rulebase ("access", "nat", "https", "threat").
            layer_name: Optional layer name filter.
            mgmt_names: Optional list of management server names to filter.
            domain_names: Optional list of domain names to filter.
            enabled_only: If True, only return enabled rules.

        Returns:
            List of rule cache models.
        """
        from arodonata.cache.models import (
            RulebaseAccess,
            RulebaseHTTPS,
            RulebaseNAT,
            RulebaseThreat,
        )

        # Map rulebase_type to model class
        model_map = {
            "access": RulebaseAccess,
            "nat": RulebaseNAT,
            "https": RulebaseHTTPS,
            "threat": RulebaseThreat,
        }

        model_class = model_map.get(rulebase_type)
        if model_class is None:
            return []

        # Build filters
        filters: dict[str, Any] = {}
        if layer_name:
            filters["layer_name"] = layer_name
        if enabled_only is not None:
            filters["enabled"] = enabled_only

        # Delegate to repository
        # Note: This assumes repository has a generic get_rulebase method
        # For now, implement basic filtering here
        return await self._repo.get_rulebase(
            model_class=model_class,
            mgmt_names=mgmt_names,
            domain_names=domain_names,
            filters=filters if filters else None,
        )
