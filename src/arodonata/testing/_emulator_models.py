"""Shared models, constants, and error builders for the stateful Check Point replay emulator."""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from arodonata.core.errors import REDACTED_PLACEHOLDER, is_sensitive_key, redact_sid, sanitize_mapping
from arodonata.core.models.common import ApiCallResult

ANY_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"
ORIGINAL_UID = "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c"
ACCEPT_UID = "6c488338-8eec-4103-ad21-cd461ac2c472"
DROP_UID = "6c488338-8eec-4103-ad21-cd461ac2c473"
DROP_UID_ALT = "6c488338-8eec-4103-ad21-cd461ac2c476"
REJECT_UID = "6c488338-8eec-4103-ad21-cd461ac2c474"
APPLY_LAYER_UID = "6c488338-8eec-4103-ad21-cd461ac2c475"
LOG_TRACK_UID = "598ead32-aa42-4615-90ed-f51a5928d41d"
NONE_TRACK_UID = "29e53e3d-23bf-48fe-b6b1-d59bd88036f1"
NONE_TRACK_UID_ALT = "29e53e3d-23bf-48fe-b6b1-d59bd88036f9"

GLOBAL_DOMAIN_UID = "uid-dom-global"
GLOBAL_DOMAIN_META: dict[str, Any] = {
    "uid": GLOBAL_DOMAIN_UID,
    "name": "Global",
    "domain-type": "global domain",
}

BUILTIN_SENTINELS: dict[str, dict[str, Any]] = {
    ANY_UID: {"uid": ANY_UID, "name": "Any", "type": "CpmiAnyObject"},
    ORIGINAL_UID: {"uid": ORIGINAL_UID, "name": "Original", "type": "CpmiAnyObject"},
    ACCEPT_UID: {"uid": ACCEPT_UID, "name": "Accept", "type": "RulebaseAction"},
    DROP_UID: {"uid": DROP_UID, "name": "Drop", "type": "RulebaseAction"},
    DROP_UID_ALT: {"uid": DROP_UID_ALT, "name": "Drop", "type": "RulebaseAction"},
    REJECT_UID: {"uid": REJECT_UID, "name": "Reject", "type": "RulebaseAction"},
    APPLY_LAYER_UID: {"uid": APPLY_LAYER_UID, "name": "Apply Layer", "type": "RulebaseAction"},
    LOG_TRACK_UID: {"uid": LOG_TRACK_UID, "name": "Log", "type": "Track"},
    NONE_TRACK_UID: {"uid": NONE_TRACK_UID, "name": "None", "type": "Track"},
    NONE_TRACK_UID_ALT: {"uid": NONE_TRACK_UID_ALT, "name": "None", "type": "Track"},
}

SENTINEL_NAME_TO_UID: dict[str, str] = {
    "any": ANY_UID,
    "original": ORIGINAL_UID,
}

ACTION_NAME_TO_UID: dict[str, str] = {
    "accept": ACCEPT_UID,
    "drop": DROP_UID,
    "reject": REJECT_UID,
    "apply layer": APPLY_LAYER_UID,
    "inner layer": APPLY_LAYER_UID,
}

ACTION_UID_TO_NAME: dict[str, str] = {
    ACCEPT_UID: "Accept",
    DROP_UID: "Drop",
    DROP_UID_ALT: "Drop",
    REJECT_UID: "Reject",
}

TRACK_NAME_TO_UID: dict[str, str] = {
    "log": LOG_TRACK_UID,
    "none": NONE_TRACK_UID,
}

TRACK_UID_TO_NAME: dict[str, str] = {
    LOG_TRACK_UID: "Log",
    NONE_TRACK_UID: "None",
    NONE_TRACK_UID_ALT: "None",
}

_MUTATING_NON_PREFIX_COMMANDS: frozenset[str] = frozenset(
    {
        "publish",
        "discard",
        "assign-global-assignment",
        "assign-global-policy",
    }
)


def is_mutating_command(command: str) -> bool:
    """Return True when `command` mutates management database or session state."""
    cmd = str(command or "").strip()
    if cmd in _MUTATING_NON_PREFIX_COMMANDS:
        return True
    return cmd.startswith(("add-", "set-", "delete-"))


def format_timestamp(posix_ms: int) -> dict[str, Any]:
    """Build a Check Point API `{posix, iso-8601}` timestamp object."""
    dt = datetime.fromtimestamp(posix_ms / 1000.0, tz=UTC)
    return {
        "posix": posix_ms,
        "iso-8601": dt.strftime("%Y-%m-%dT%H:%M:%S+0000"),
    }


def format_domain_meta(domain_name: str, existing: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build deterministic domain metadata dict matching dataset fixtures."""
    if isinstance(existing, Mapping) and existing.get("name"):
        return dict(existing)
    if domain_name == "Global":
        return dict(GLOBAL_DOMAIN_META)
    slug = domain_name.lower().replace(" ", "-")
    dom_type = "mds" if domain_name == "System Data" else "domain"
    return {
        "uid": f"uid-dom-{slug}",
        "name": domain_name,
        "domain-type": dom_type,
    }


@dataclass(frozen=True)
class EntitySpec:
    """Declarative specification for a CRUD-managed Check Point entity type."""

    obj_type: str
    plural_show: str
    is_service: bool = False
    is_group: bool = False
    ip_fields: tuple[str, ...] = ()
    text_fields: tuple[str, ...] = ("name", "comments")
    default_fields: tuple[tuple[str, Any], ...] = ()

    @property
    def singular_show(self) -> str:
        return f"show-{self.obj_type}"

    @property
    def add_cmd(self) -> str:
        return f"add-{self.obj_type}"

    @property
    def set_cmd(self) -> str:
        return f"set-{self.obj_type}"

    @property
    def delete_cmd(self) -> str:
        return f"delete-{self.obj_type}"


ENTITY_SPECS: tuple[EntitySpec, ...] = (
    EntitySpec(
        obj_type="host",
        plural_show="show-hosts",
        ip_fields=("ipv4-address", "ipv6-address"),
        text_fields=("name", "ipv4-address", "ipv6-address", "comments"),
    ),
    EntitySpec(
        obj_type="network",
        plural_show="show-networks",
        ip_fields=("subnet4", "subnet6"),
        text_fields=("name", "subnet4", "subnet6", "subnet-mask", "comments"),
    ),
    EntitySpec(
        obj_type="address-range",
        plural_show="show-address-ranges",
        ip_fields=("ipv4-address-first", "ipv4-address-last", "ipv6-address-first", "ipv6-address-last"),
        text_fields=("name", "ipv4-address-first", "ipv4-address-last", "comments"),
    ),
    EntitySpec(
        obj_type="dns-domain",
        plural_show="show-dns-domains",
        text_fields=("name", "comments"),
        default_fields=(("is-sub-domain", True),),
    ),
    EntitySpec(
        obj_type="application-site",
        plural_show="show-application-sites",
        text_fields=("name", "primary-category", "description", "comments"),
        default_fields=(("primary-category", "Custom_Application_Site"), ("urls-defined-as-regular-expression", False)),
    ),
    EntitySpec(
        obj_type="group",
        plural_show="show-groups",
        is_group=True,
        text_fields=("name", "comments"),
    ),
    EntitySpec(
        obj_type="service-tcp",
        plural_show="show-services-tcp",
        is_service=True,
        text_fields=("name", "port", "protocol", "comments"),
    ),
    EntitySpec(
        obj_type="service-udp",
        plural_show="show-services-udp",
        is_service=True,
        text_fields=("name", "port", "protocol", "comments"),
    ),
    EntitySpec(
        obj_type="service-icmp",
        plural_show="show-services-icmp",
        is_service=True,
        text_fields=("name", "icmp-type", "comments"),
    ),
    EntitySpec(
        obj_type="service-icmp6",
        plural_show="show-services-icmp6",
        is_service=True,
        text_fields=("name", "icmp-type", "comments"),
    ),
    EntitySpec(
        obj_type="service-other",
        plural_show="show-services-other",
        is_service=True,
        text_fields=("name", "ip-protocol", "comments"),
    ),
    EntitySpec(
        obj_type="service-group",
        plural_show="show-service-groups",
        is_service=True,
        is_group=True,
        text_fields=("name", "comments"),
    ),
)

OBJ_TYPE_TO_SPEC: dict[str, EntitySpec] = {spec.obj_type: spec for spec in ENTITY_SPECS}
PLURAL_SHOW_TO_SPEC: dict[str, EntitySpec] = {spec.plural_show: spec for spec in ENTITY_SPECS}
SINGULAR_SHOW_TO_SPEC: dict[str, EntitySpec] = {spec.singular_show: spec for spec in ENTITY_SPECS}

CMD_TO_ENTITY_ACTION: dict[str, tuple[EntitySpec, str]] = {}
for _spec in ENTITY_SPECS:
    CMD_TO_ENTITY_ACTION[_spec.singular_show] = (_spec, "show")
    CMD_TO_ENTITY_ACTION[_spec.add_cmd] = (_spec, "add")
    CMD_TO_ENTITY_ACTION[_spec.set_cmd] = (_spec, "set")
    CMD_TO_ENTITY_ACTION[_spec.delete_cmd] = (_spec, "delete")

GROUP_SPEC_TYPES: frozenset[str] = frozenset(spec.obj_type for spec in ENTITY_SPECS if spec.is_group)


@dataclass
class MutationRecord:
    """Recorded staged mutation for publish-time rebase replay."""

    command: str
    domain: str
    payload: dict[str, Any]
    assigned_uid: str | None = None


@dataclass
class PublishedDelta:
    """Immutable change delta emitted when a work session is published."""

    session_uid: str
    session_name: str
    domain: str
    user_name: str
    publish_time_posix: int
    publish_time_iso: str
    changes: dict[str, Any]


@dataclass
class WorkSession:
    """In-memory Check Point work session with optional isolated staging overlay."""

    uid: str
    domain: str
    user_name: str
    name: str
    description: str
    application: str
    read_only: bool
    state: str
    base_published_uid: str
    created_time_posix: int
    last_modify_posix: int
    base_domain_gen: int = 0
    domain_meta: dict[str, Any] = field(default_factory=dict)
    base_snapshot: dict[str, dict[str, Any]] | None = None
    overlay_data: dict[str, dict[str, Any]] | None = None
    locked_uids: set[str] = field(default_factory=set)
    mutation_records: list[MutationRecord] = field(default_factory=list)
    published_time_posix: int | None = None
    published_changes: int = 0
    changes_count: int = 0
    comments: str = ""
    color: str = ""
    tags: list[Any] = field(default_factory=list)

    def to_checkpoint_dict(self) -> dict[str, Any]:
        """Serialize session metadata in Check Point `show-session` JSON shape."""
        created_ts = format_timestamp(self.created_time_posix)
        modified_ts = format_timestamp(self.last_modify_posix)
        data: dict[str, Any] = {
            "uid": self.uid,
            "name": self.name,
            "type": "session",
            "domain": dict(self.domain_meta) if self.domain_meta else format_domain_meta(self.domain),
            "user-name": self.user_name,
            "application": self.application,
            "description": self.description,
            "state": self.state,
            "read-only": self.read_only,
            "locks": len(self.locked_uids),
            "changes": self.changes_count,
            "number-of-published-changes": self.published_changes if self.state == "published" else 0,
            "last-login-was-at": dict(created_ts),
            "last-modify-time": dict(modified_ts),
            "ip-address": "127.0.0.1",
            "meta-info": {
                "lock": "unlocked",
                "validation-state": "ok",
                "creator": self.user_name,
                "creation-time": dict(created_ts),
                "last-modifier": self.user_name,
                "last-modify-time": dict(modified_ts),
            },
        }
        if self.comments:
            data["comments"] = self.comments
        if self.color:
            data["color"] = self.color
        if self.tags:
            data["tags"] = copy.deepcopy(self.tags)
        if self.state == "published" and self.published_time_posix is not None:
            data["publish-time"] = format_timestamp(self.published_time_posix)
        return data


@dataclass
class SidBinding:
    """Mapping between a secret session token (`sid`) and its attached `WorkSession`."""

    sid: str
    sid_ref: str
    mgmt_name: str
    domain: str
    user_name: str
    session_uid: str
    read_only: bool = False
    active: bool = True

    def __repr__(self) -> str:
        return (
            f"SidBinding(sid_ref={self.sid_ref!r}, mgmt_name={self.mgmt_name!r}, "
            f"domain={self.domain!r}, session_uid={self.session_uid!r}, "
            f"read_only={self.read_only!r}, active={self.active!r})"
        )


@dataclass
class ReplayStateSnapshot:
    """In-memory snapshot of full emulator state for fast test isolation."""

    domain_copies: dict[str, dict[str, Any]]
    dirty_domains: set[str]
    work_sessions: dict[str, WorkSession]
    sid_bindings: dict[str, SidBinding]
    published_session_by_domain: dict[str, str]
    published_deltas: dict[str, list[PublishedDelta]]
    tasks: dict[str, dict[str, Any]]
    show_global_assignments: list[dict[str, Any]]
    counters: dict[str, int]
    cli_overrides: dict[tuple[str, int], str]
    fail_ssh_nodes: set[str]
    call_log: list[dict[str, Any]]
    domain_generations: dict[str, int] = field(default_factory=dict)
    allow_one_time_script: bool = True
    allow_repository_script: bool = True
    manage_repository_scripts: str = "write"


def sanitize_call_payload(
    payload: Mapping[str, Any] | None,
    *,
    known_sids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Deep-sanitize an API request payload so secrets and SIDs never enter call logs."""
    if not payload:
        return {}
    clean = sanitize_mapping(copy.deepcopy(dict(payload)), known_sids=known_sids)
    for key in list(clean.keys()):
        if is_sensitive_key(str(key)):
            clean[key] = REDACTED_PLACEHOLDER
    return clean


def summarize_payload(
    command: str,
    payload: Mapping[str, Any] | None,
    *,
    known_sids: Iterable[str] | None = None,
) -> str:
    """Produce a concise, SID-safe summary string for a request payload."""
    clean = sanitize_call_payload(payload, known_sids=known_sids)
    if not clean:
        return "{}"
    priority_keys = (
        "uid",
        "name",
        "new-name",
        "type",
        "layer",
        "package",
        "rule-number",
        "position",
        "new-position",
        "to-session",
        "from-session",
        "limit",
        "offset",
        "filter",
    )
    parts: list[str] = []
    seen: set[str] = set()
    for key in priority_keys:
        if key in clean and len(parts) < 5:
            parts.append(f"{key}={redact_sid(repr(clean[key]), known_sids=known_sids)}")
            seen.add(key)
    for key, val in clean.items():
        if key in seen or len(parts) >= 5:
            continue
        if isinstance(val, (list, dict)):
            parts.append(f"{key}=<{type(val).__name__}:{len(val)}>")
        else:
            parts.append(f"{key}={redact_sid(repr(val), known_sids=known_sids)}")
    extra = len(clean) - len(parts)
    suffix = f", +{extra}" if extra > 0 else ""
    return f"{command}({', '.join(parts)}{suffix})"


def cp_ok(
    data: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    task_id: str | None = None,
) -> ApiCallResult:
    """Create a successful `ApiCallResult`."""
    return ApiCallResult(
        success=True,
        status_code=status_code,
        data=data or {},
        task_id=task_id,
    )


def cp_error(
    code: str,
    message: str,
    *,
    status_code: int = 400,
    blocking_errors: list[dict[str, Any]] | None = None,
    errors: list[dict[str, Any]] | None = None,
    warnings: list[dict[str, Any]] | None = None,
) -> ApiCallResult:
    """Create a failed `ApiCallResult` formatted compatibly with `ApiTransport`."""
    data: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    full_message = message
    if blocking_errors:
        data["blocking-errors"] = blocking_errors
        detail_msgs = [str(item.get("message", "")).strip() for item in blocking_errors if item.get("message")]
        if detail_msgs:
            full_message = f"{message} ({'; '.join(detail_msgs)})"
    if errors:
        data["errors"] = errors
    if warnings:
        data["warnings"] = warnings
    return ApiCallResult(
        success=False,
        status_code=status_code,
        data=data,
        error_code=code,
        error_message=full_message,
    )
