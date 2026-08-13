"""Base extractor classes and types."""

from dataclasses import dataclass


@dataclass
class ExtractionContext:
    """Context information for object extraction."""

    mgmt_name: str
    domain_name: str
    objects_map: dict[str, str] | None = None


class BaseExtractor:
    """Base class for all extractors."""
