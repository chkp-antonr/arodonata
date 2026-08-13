"""User context models for session tracking."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UserContext:
    """User information for session tracking.

    Authentication is handled separately by ArodonataClient.
    This is only for tracking who made what changes.
    """

    username: str
    source: str  # "webui", "api", "cli"

    @classmethod
    def from_fastapi_user(cls, user: dict) -> UserContext:
        """Create from FastAPI request state (WebUI/API).

        Args:
            user: User dict from JWT token claims.

        Returns:
            UserContext instance.
        """
        return cls(
            username=user.get("username", "unknown"),
            source="api" if user.get("is_api_call") else "webui",
        )

    @classmethod
    def from_cli(cls) -> UserContext:
        """Create from CLI environment.

        Returns:
            UserContext with OS username.
        """
        import getpass

        return cls(
            username=getpass.getuser(),
            source="cli",
        )
