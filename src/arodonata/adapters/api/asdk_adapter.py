"""ASDK API adapter wrapping AMgmtClient."""

from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from arodonata.api.schemas import ApiQueryResult
    from arodonata.asdk.client import AMgmtClient


class ASDKApiAdapter:
    """Check Point API adapter wrapping AMgmtClient.

    Implements ApiPort protocol.
    """

    def __init__(self, client: "AMgmtClient") -> None:
        """Initialize adapter with ASDK client.

        Args:
            client: AMgmtClient instance to wrap.
        """
        self._client = client

    def _guess_container_key(self, command: str) -> str:
        """Guess container key for specific commands.

        Args:
            command: API command name.

        Returns:
            Guessed container key.
        """
        container_key_map = {
            "show-access-layers": "access-layers",
            "show-nat-layers": "nat-layers",
            "show-https-layers": "https-layers",
            "show-threat-layers": "threat-layers",
        }
        return container_key_map.get(command, "objects")

    def _extract_objects_from_data(self, data: Any, container_key: str) -> list[Any]:
        """Extract objects list from response data.

        Args:
            data: Response data (dict or list).
            container_key: Preferred container key.

        Returns:
            List of objects.
        """
        if isinstance(data, list):
            return data

        if not isinstance(data, dict):
            return []

        # Try specified container_key first
        objects = data.get(container_key, [])

        # Try 'objects' if different
        if not objects and container_key != "objects":
            objects = data.get("objects", [])

        # Ultimate fallback: find any list
        if not objects:
            for key, val in data.items():
                if isinstance(val, list) and key not in ("meta-info", "from", "to", "total"):
                    objects = val
                    break

        return objects if isinstance(objects, list) else []

    async def query(
        self,
        mgmt_name: str,
        command: str,
        domain: str = "",
        payload: dict[str, Any] | None = None,
        details_level: Literal["uid", "standard", "full"] = "standard",
        container_key: str | None = None,
    ) -> "ApiQueryResult":
        """Execute paginated query via ASDK."""
        from arodonata.api.schemas import ApiQueryResult

        container_key = container_key or self._guess_container_key(command)

        response = await self._client.api_query(
            mgmt_name=mgmt_name,
            command=command,
            domain=domain,
            payload=payload or {},
            details_level=details_level,
            container_key=container_key,
        )
        data = response.get("data", [])
        objects = self._extract_objects_from_data(data, container_key)

        return ApiQueryResult(
            success=response.get("success", False),
            data=data,
            objects=objects if isinstance(objects, list) else [],
            message=response.get("message", ""),
            code=response.get("code", ""),
            total=len(objects) if isinstance(objects, list) else 0,
        )

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
        payload = {}
        if from_session:
            payload["from-session"] = from_session
        if from_date:
            payload["from-date"] = from_date
        if to_session:
            payload["to-session"] = to_session
        if to_date:
            payload["to-date"] = to_date

        return await self._client.api_call(
            mgmt_name=mgmt_name,
            command="show-changes",
            domain=domain,
            payload=payload,
        )

    async def publish(
        self,
        mgmt_name: str,
        domain: str = "",
    ) -> Any:
        """Publish the current session via ASDK."""
        return await self._client.api_call(
            mgmt_name=mgmt_name,
            command="publish",
            domain=domain,
            payload={},
        )

    def get_mgmt_names(self) -> list[str]:
        """Get list of configured management server names."""
        return self._client.get_mgmt_names()
