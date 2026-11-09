"""Enterprise raw dataset generator, file-backed replay mocks, and HTTPS mock server (`arodonata.testing`)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from arodonata.testing.dataset_generator import (
    ALL_DOMAINS,
    DATASET_VERSION,
    DEFAULT_DATASET_DIR,
    DEFAULT_SEED,
    USER_DOMAINS,
    ensure_enterprise_raw_dataset,
    generate_enterprise_raw_dataset,
)
from arodonata.testing.replay_mock import FileReplayApiMock, FileReplayCliMock

if TYPE_CHECKING:
    from arodonata.testing.mock_server import CheckPointReplayHttpServer


def __getattr__(name: str) -> Any:
    if name == "CheckPointReplayHttpServer":
        from arodonata.testing.mock_server import CheckPointReplayHttpServer

        return CheckPointReplayHttpServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ALL_DOMAINS",
    "DATASET_VERSION",
    "DEFAULT_DATASET_DIR",
    "DEFAULT_SEED",
    "USER_DOMAINS",
    "CheckPointReplayHttpServer",
    "FileReplayApiMock",
    "FileReplayCliMock",
    "ensure_enterprise_raw_dataset",
    "generate_enterprise_raw_dataset",
]
