from __future__ import annotations

from collections.abc import Callable

from arlogi import LoggerFactory, LoggerProtocol, setup_logging
from arlogi import get_logger as arlogi_get_logger

from .config import ArodonataSettings


def _ensure_initialized() -> None:
    """Ensure arlogi is initialized with ARODONATA_LOG_LEVEL if not already set up.

    This only runs if arlogi hasn't been initialized yet, allowing the main
    application to override configuration if called before this.
    """
    if not LoggerFactory._initialized:
        # Pydantic settings will pick up ARODONATA_LOG_LEVEL automatically
        settings = ArodonataSettings()
        # Default module levels to reduce noise from external libraries
        module_levels: dict[str, str | int] = {
            "sqlalchemy": "WARNING",
            "sqlalchemy.engine": "WARNING",
            "sqlalchemy.pool": "WARNING",
            "httpcore": "WARNING",
            "httpx": "WARNING",
            "urllib3": "WARNING",
            "asyncio": "WARNING",
        }
        setup_logging(level=settings.log_level, module_levels=module_levels)


def get_logger(name: str) -> LoggerProtocol:
    """Get a logger instance, ensuring arodonata defaults are applied."""
    _ensure_initialized()
    return arlogi_get_logger(name)


def lazy_logger(name: str) -> Callable[[], LoggerProtocol]:
    """Create a lazy logger function for a module.

    Args:
        name: Logger name (usually __name__).

    Returns:
        A function that returns a LoggerProtocol instance when called.
    """
    _logger: LoggerProtocol | None = None

    def log() -> LoggerProtocol:
        nonlocal _logger
        if _logger is None:
            _logger = get_logger(name)
        return _logger

    return log
