"""Declarative Check Point Policy-as-Code CRUD engine (`src/arodonata/cpcrud/`)."""

from arodonata.cpcrud.differ import (
    compute_object_diff,
    compute_rule_diff,
    compute_service_diff,
    resolve_member_reference,
)
from arodonata.cpcrud.executor import Executor
from arodonata.cpcrud.inverse import build_inverse_template
from arodonata.cpcrud.models import (
    ActionResult,
    ApplyReport,
    ConflictPolicy,
    DomainStamp,
    FieldChange,
    IpConflictPolicy,
    NameConflictPolicy,
    NamingPrefixes,
    Outcome,
    Plan,
    PlannedAction,
    StagedSessionInfo,
)
from arodonata.cpcrud.planner import LOOKUP_ERROR_PREFIX, Planner
from arodonata.cpcrud.position_helper import is_cleanup_rule, resolve_rule_position
from arodonata.cpcrud.rule_identity import (
    NAT_ANY_OBJECT_UID,
    NAT_ORIGINAL_OBJECT_UID,
    desired_access_traffic_tuple,
    desired_nat_traffic_tuple,
    existing_access_traffic_tuple,
    existing_nat_traffic_tuple,
    match_rule,
    normalize_any_sentinel,
    normalize_nat_original_sentinel,
    normalize_nat_traffic_ref,
    normalize_traffic_list,
)
from arodonata.cpcrud.service import CPCRUDService
from arodonata.cpcrud.state_reader import (
    OBJECT_ITEM_TYPES,
    SERVICE_ITEM_TYPES,
    HybridStateReader,
    StateLookupError,
    is_not_found_error,
    normalize_mask_length,
)
from arodonata.cpcrud.validator import (
    load_cpcrud_schema,
    parse_template_input,
    validate_template,
)

__all__ = [
    "ActionResult",
    "ApplyReport",
    "CPCRUDService",
    "ConflictPolicy",
    "DomainStamp",
    "Executor",
    "FieldChange",
    "HybridStateReader",
    "IpConflictPolicy",
    "LOOKUP_ERROR_PREFIX",
    "NAT_ANY_OBJECT_UID",
    "NAT_ORIGINAL_OBJECT_UID",
    "NameConflictPolicy",
    "NamingPrefixes",
    "OBJECT_ITEM_TYPES",
    "Outcome",
    "Plan",
    "PlannedAction",
    "Planner",
    "SERVICE_ITEM_TYPES",
    "StagedSessionInfo",
    "StateLookupError",
    "build_inverse_template",
    "compute_object_diff",
    "compute_rule_diff",
    "compute_service_diff",
    "desired_access_traffic_tuple",
    "desired_nat_traffic_tuple",
    "existing_access_traffic_tuple",
    "existing_nat_traffic_tuple",
    "is_cleanup_rule",
    "is_not_found_error",
    "load_cpcrud_schema",
    "match_rule",
    "normalize_any_sentinel",
    "normalize_mask_length",
    "normalize_nat_original_sentinel",
    "normalize_nat_traffic_ref",
    "normalize_traffic_list",
    "parse_template_input",
    "resolve_member_reference",
    "resolve_rule_position",
    "validate_template",
]
