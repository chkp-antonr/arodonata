"""Backward-compatible re-export shim for `arodonata.core.services.search` (`SearchService`)."""

from arodonata.core.services.search import (
    ClassifiedSearchTerm,
    SearchService,
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
