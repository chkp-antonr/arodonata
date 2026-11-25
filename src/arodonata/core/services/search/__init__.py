"""Modular cache-first search, group resolution, and structured query package (`arodonata.core.services.search`)."""

from arodonata.core.services.search.service import SearchService
from arodonata.core.services.search.terms import (
    ClassifiedSearchTerm,
    SearchTermKind,
    classify_search_term,
    matches_classified_term,
)

__all__ = [
    "ClassifiedSearchTerm",
    "SearchService",
    "SearchTermKind",
    "classify_search_term",
    "matches_classified_term",
]
