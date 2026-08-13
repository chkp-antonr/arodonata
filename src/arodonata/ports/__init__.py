"""Protocol interfaces for Port/Adapter architecture."""

from .api_port import ApiPort
from .cache_port import CachePort

__all__ = ["CachePort", "ApiPort"]
