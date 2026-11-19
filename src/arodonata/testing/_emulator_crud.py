"""Backward-compatible re-export facade for stateful emulator CRUD, lookup, and slicing helpers."""

from __future__ import annotations

from ._emulator_entity_crud import _normalize_subnet_fields, handle_entity_crud
from ._emulator_lookup import (
    collect_blocking_references,
    delete_unused_objects,
    filter_show_objects,
    find_effective_object,
    find_in_scope,
    find_unused_objects,
)
from ._emulator_projection import (
    build_objects_dictionary,
    extract_ref_uids,
    inline_rule_objects,
    make_object_summary,
    paginate_items,
    project_details_level,
    slice_rulebase_with_sections,
)
from ._emulator_projection import (
    inline_rule_objects as _inline_rule_objects,
)
from ._emulator_projection import (
    iter_flat_rule_entries as _iter_flat_rule_entries,
)
from ._emulator_rulebase_crud import handle_rulebase_crud
from ._emulator_rulebase_tree import parse_rule_number

__all__ = [
    "_inline_rule_objects",
    "_iter_flat_rule_entries",
    "_normalize_subnet_fields",
    "build_objects_dictionary",
    "collect_blocking_references",
    "delete_unused_objects",
    "extract_ref_uids",
    "filter_show_objects",
    "find_effective_object",
    "find_in_scope",
    "find_unused_objects",
    "handle_entity_crud",
    "handle_rulebase_crud",
    "inline_rule_objects",
    "make_object_summary",
    "paginate_items",
    "parse_rule_number",
    "project_details_level",
    "slice_rulebase_with_sections",
]
