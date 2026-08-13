"""ApiPort protocol interface for Check Point API operations."""

from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from arodonata.api.schemas import ApiQueryResult


@runtime_checkable
class ApiPort(Protocol):
    """Port for Check Point API operations - structural interface."""

    async def query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        payload: dict[str, Any] | None = None,
        details_level: Literal["uid", "standard", "full"] = "standard",
        container_key: str | None = None,
    ) -> "ApiQueryResult":
        """Execute paginated API query."""
        ...

    async def show_changes(
        self,
        mgmt_name: str,
        domain: str = "",
        from_session: str | None = None,
        from_date: str | None = None,
        to_session: str | None = None,
        to_date: str | None = None,
    ) -> Any:
        """Get changes for smart refresh."""
        ...

    async def publish(
        self,
        mgmt_name: str,
        domain: str = "",
    ) -> Any:
        """Publish the current session on the management server."""
        ...

    def get_mgmt_names(self) -> list[str]:
        """Get list of configured management server names."""
        ...
