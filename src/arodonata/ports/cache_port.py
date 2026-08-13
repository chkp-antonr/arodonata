"""CachePort protocol interface for cache operations."""

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from arodonata.cache.models import CPObject, Domain, LastPublishedSession


@runtime_checkable
class CachePort(Protocol):
    """Port for cache operations - structural interface.

    Any class with these methods satisfies this protocol - no inheritance needed.
    """

    async def get_objects(
        self,
        object_type: str | None = None,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list["CPObject"]:
        """Query objects from cache with optional filters."""
        ...

    async def get_object_by_uid(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str,
    ) -> "CPObject | None":
        """Get single object by UID."""
        ...

    async def upsert_objects(
        self,
        objects: list["CPObject"],
    ) -> int:
        """Insert or update objects. Returns count of upserted objects."""
        ...

    async def delete_object(
        self,
        uid: str,
        mgmt_name: str,
        domain_name: str,
    ) -> int:
        """Delete a single object by UID. Returns count deleted (0 if absent)."""
        ...

    async def get_domains(
        self,
        mgmt_names: list[str] | None = None,
    ) -> list["Domain"]:
        """Get cached domains."""
        ...

    async def get_gateways(
        self,
        mgmt_names: list[str] | None = None,
    ) -> list[Any]:
        """Get cached gateways and servers."""
        ...

    async def get_last_published_session(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> "LastPublishedSession | None":
        """Get last published session for smart refresh."""
        ...

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
            List of rule objects (type depends on cache implementation).
        """
        ...
