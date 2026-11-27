"""Contextvars propagation for authentication, operator metadata, and WriteSession overlays."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    MissingConfigurationError,
    ServerIdentityError,
    SessionError,
    TransportError,
    is_sensitive_key,
)
from arodonata.core.models.common import ApiCallResult
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService

if TYPE_CHECKING:
    from arodonata.core.ports import ApiPort

SYSTEM_DOMAIN_KEY = "System Data"

SERVICE_COMMAND_TYPES: frozenset[str] = frozenset(
    {
        "service-tcp",
        "service-udp",
        "service-icmp",
        "service-icmp6",
        "service-other",
        "service-dce-rpc",
        "service-rpc",
        "service-sctp",
        "service-gtp",
        "service-citrix-tcp",
        "service-compound-tcp",
        "service-group",
    }
)

NON_OVERLAY_MUTATION_TARGETS: frozenset[str] = frozenset(
    {
        "access-rule",
        "access-section",
        "access-layer",
        "nat-rule",
        "nat-section",
        "https-rule",
        "https-section",
        "https-layer",
        "threat-rule",
        "threat-exception",
        "threat-layer",
        "package",
        "domain",
        "administrator",
        "session",
        "trust",
        "repository-script",
        "api-key",
        "md-permissions-profile",
        "domain-permissions-profile",
    }
)


def normalize_domain_key(domain: str | None) -> str:
    """Normalize `domain=None` or whitespace-only domain strings to `'System Data'`."""
    if not domain or not domain.strip():
        return SYSTEM_DOMAIN_KEY
    return domain.strip()


_AUTH_IDENTITY_HMAC_KEY = b"arodonata-v2-auth-identity-hmac-key"


class AuthContext(BaseModel):
    """Runtime authentication credentials propagated via `contextvars`."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    api_key: str | None = Field(default=None, repr=False)
    user_id: str | None = None

    @field_serializer("password", "api_key")
    def _mask_secret_field(self, value: str | None) -> str | None:
        """Mask secret fields during Pydantic serialization without hiding Python attributes."""
        return REDACTED_PLACEHOLDER if value else value

    def model_post_init(self, __context: Any) -> None:
        has_key = bool(self.api_key)
        has_user_pass = bool(self.username and self.password)
        if not has_key and not has_user_pass:
            raise MissingConfigurationError("AuthContext requires either api_key or both username and password.")

    @property
    def identity_key(self) -> str:
        """Stable non-secret HMAC-SHA256 identifier bound to the resolved credentials (`C4`)."""
        mode = "api_key" if self.api_key else "credential"
        secret_material = self.api_key or f"{self.username or ''}:{self.password or ''}"
        msg = f"{mode}|{self.user_id or ''}|{self.username or ''}|{secret_material}".encode()
        digest = hmac.new(_AUTH_IDENTITY_HMAC_KEY, msg, hashlib.sha256).hexdigest()[:24]
        principal = self.user_id or self.username or "api_key"
        return f"{principal}:{digest}"

    def __repr__(self) -> str:
        pw = REDACTED_PLACEHOLDER if self.password else None
        key = REDACTED_PLACEHOLDER if self.api_key else None
        return f"AuthContext(username={self.username!r}, user_id={self.user_id!r}, password={pw!r}, api_key={key!r})"

    def __str__(self) -> str:
        return self.__repr__()


class UserContext(BaseModel):
    """Operator and session attribution context propagated via `contextvars`."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    user_id: str
    username: str | None = None
    session_name: str | None = None
    session_description: str | None = None
    client_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class SessionOverlay:
    """In-memory read-your-own-writes overlay for an active `WriteSession`.

    Tracks uncommitted object and service creations, updates, and deletions so read
    methods within the same `WriteSession` context reflect uncommitted state without
    mutating the shared database cache prior to `publish`.
    """

    def __init__(self, mgmt_name: str, domain_name: str) -> None:
        self.mgmt_name = mgmt_name
        self.domain_name = domain_name
        self._upserted_objects: dict[str, CPObject] = {}
        self._deleted_object_uids: set[str] = set()
        self._deleted_object_names: set[tuple[str, str]] = set()

        self._upserted_services: dict[str, CPService] = {}
        self._deleted_service_uids: set[str] = set()
        self._deleted_service_names: set[tuple[str, str]] = set()

    @property
    def upserted_objects(self) -> dict[str, CPObject]:
        """Return a shallow copy of upserted `CPObject` instances keyed by UID."""
        return dict(self._upserted_objects)

    @property
    def deleted_object_uids(self) -> set[str]:
        """Return a copy of deleted object UID tombstones."""
        return set(self._deleted_object_uids)

    @property
    def upserted_services(self) -> dict[str, CPService]:
        """Return a shallow copy of upserted `CPService` instances keyed by UID."""
        return dict(self._upserted_services)

    @property
    def deleted_service_uids(self) -> set[str]:
        """Return a copy of deleted service UID tombstones."""
        return set(self._deleted_service_uids)

    def record_object_upsert(self, obj: CPObject) -> None:
        """Record an uncommitted object creation or update in this session."""
        # Remove any prior upserted entry with the same (type, name) if UID changed
        stale_uids = [
            uid
            for uid, existing in self._upserted_objects.items()
            if existing.type == obj.type and existing.name == obj.name and uid != obj.uid
        ]
        for stale_uid in stale_uids:
            del self._upserted_objects[stale_uid]

        self._upserted_objects[obj.uid] = obj
        self._deleted_object_uids.discard(obj.uid)
        self._deleted_object_names.discard((obj.type, obj.name))

    def record_object_delete(
        self,
        *,
        uid: str | None = None,
        name: str | None = None,
        obj_type: str | None = None,
    ) -> None:
        """Record an uncommitted object deletion in this session."""
        if uid:
            existing = self._upserted_objects.pop(uid, None)
            if existing is not None:
                self._deleted_object_names.add((existing.type, existing.name))
            self._deleted_object_uids.add(uid)
        if name:
            matched_uids = [
                u
                for u, existing in self._upserted_objects.items()
                if existing.name == name and (obj_type is None or existing.type == obj_type)
            ]
            for matched_uid in matched_uids:
                removed = self._upserted_objects.pop(matched_uid)
                self._deleted_object_uids.add(removed.uid)
                self._deleted_object_names.add((removed.type, removed.name))
            if obj_type:
                self._deleted_object_names.add((obj_type, name))
            else:
                self._deleted_object_names.add(("*", name))

    def record_service_upsert(self, svc: CPService) -> None:
        """Record an uncommitted service creation or update in this session."""
        stale_uids = [
            uid
            for uid, existing in self._upserted_services.items()
            if existing.type == svc.type and existing.name == svc.name and uid != svc.uid
        ]
        for stale_uid in stale_uids:
            del self._upserted_services[stale_uid]

        self._upserted_services[svc.uid] = svc
        self._deleted_service_uids.discard(svc.uid)
        self._deleted_service_names.discard((svc.type, svc.name))

    def record_service_delete(
        self,
        *,
        uid: str | None = None,
        name: str | None = None,
        svc_type: str | None = None,
    ) -> None:
        """Record an uncommitted service deletion in this session."""
        if uid:
            existing = self._upserted_services.pop(uid, None)
            if existing is not None:
                self._deleted_service_names.add((existing.type, existing.name))
            self._deleted_service_uids.add(uid)
        if name:
            matched_uids = [
                u
                for u, existing in self._upserted_services.items()
                if existing.name == name and (svc_type is None or existing.type == svc_type)
            ]
            for matched_uid in matched_uids:
                removed = self._upserted_services.pop(matched_uid)
                self._deleted_service_uids.add(removed.uid)
                self._deleted_service_names.add((removed.type, removed.name))
            if svc_type:
                self._deleted_service_names.add((svc_type, name))
            else:
                self._deleted_service_names.add(("*", name))

    def _is_object_deleted(self, obj: CPObject) -> bool:
        return (
            obj.uid in self._deleted_object_uids
            or (obj.type, obj.name) in self._deleted_object_names
            or ("*", obj.name) in self._deleted_object_names
        )

    def _is_service_deleted(self, svc: CPService) -> bool:
        return (
            svc.uid in self._deleted_service_uids
            or (svc.type, svc.name) in self._deleted_service_names
            or ("*", svc.name) in self._deleted_service_names
        )

    def apply_to_objects(
        self,
        cached_objects: Sequence[CPObject],
        *,
        types: Sequence[str] | None = None,
    ) -> list[CPObject]:
        """Merge uncommitted object creations, updates, and deletions onto `cached_objects`."""
        allowed_types = set(types) if types is not None else None
        merged: list[CPObject] = []
        seen_uids: set[str] = set()
        upserted_by_name: dict[tuple[str, str], CPObject] = {
            (o.type, o.name): o for o in self._upserted_objects.values()
        }

        for item in cached_objects:
            if allowed_types is not None and item.type not in allowed_types:
                continue
            if self._is_object_deleted(item):
                continue
            replacement = self._upserted_objects.get(item.uid) or upserted_by_name.get((item.type, item.name))
            if replacement is not None:
                if allowed_types is None or replacement.type in allowed_types:
                    merged.append(replacement)
                    seen_uids.add(replacement.uid)
                seen_uids.add(item.uid)
            else:
                merged.append(item)
                seen_uids.add(item.uid)

        for uid, upserted in self._upserted_objects.items():
            if uid in seen_uids:
                continue
            if allowed_types is not None and upserted.type not in allowed_types:
                continue
            merged.append(upserted)
            seen_uids.add(uid)

        return merged

    def apply_to_services(
        self,
        cached_services: Sequence[CPService],
        *,
        types: Sequence[str] | None = None,
    ) -> list[CPService]:
        """Merge uncommitted service creations, updates, and deletions onto `cached_services`."""
        allowed_types = set(types) if types is not None else None
        merged: list[CPService] = []
        seen_uids: set[str] = set()
        upserted_by_name: dict[tuple[str, str], CPService] = {
            (s.type, s.name): s for s in self._upserted_services.values()
        }

        for item in cached_services:
            if allowed_types is not None and item.type not in allowed_types:
                continue
            if self._is_service_deleted(item):
                continue
            replacement = self._upserted_services.get(item.uid) or upserted_by_name.get((item.type, item.name))
            if replacement is not None:
                if allowed_types is None or replacement.type in allowed_types:
                    merged.append(replacement)
                    seen_uids.add(replacement.uid)
                seen_uids.add(item.uid)
            else:
                merged.append(item)
                seen_uids.add(item.uid)

        for uid, upserted in self._upserted_services.items():
            if uid in seen_uids:
                continue
            if allowed_types is not None and upserted.type not in allowed_types:
                continue
            merged.append(upserted)
            seen_uids.add(uid)

        return merged

    def lookup_object_by_uid(self, uid: str) -> tuple[bool, CPObject | None]:
        """Check whether `uid` is overridden or deleted in this overlay.

        Returns:
            `(True, None)` if deleted in the overlay,
            `(True, obj)` if created/updated in the overlay,
            `(False, None)` if untouched by the overlay.
        """
        if uid in self._deleted_object_uids:
            return True, None
        if uid in self._upserted_objects:
            return True, self._upserted_objects[uid]
        return False, None

    def lookup_service_by_uid(self, uid: str) -> tuple[bool, CPService | None]:
        """Check whether service `uid` is overridden or deleted in this overlay."""
        if uid in self._deleted_service_uids:
            return True, None
        if uid in self._upserted_services:
            return True, self._upserted_services[uid]
        return False, None

    def apply_to_single_object(self, obj: CPObject) -> CPObject | None:
        """Apply uncommitted updates/deletions to a single `CPObject` without appending unrelated entities."""
        if self._is_object_deleted(obj):
            return None
        if obj.uid in self._upserted_objects:
            return self._upserted_objects[obj.uid]
        for replacement in self._upserted_objects.values():
            if replacement.type == obj.type and replacement.name == obj.name:
                return replacement if replacement.uid == obj.uid else None
        return obj

    def apply_to_single_service(self, svc: CPService) -> CPService | None:
        """Apply uncommitted updates/deletions to a single `CPService` without appending unrelated entities."""
        if self._is_service_deleted(svc):
            return None
        if svc.uid in self._upserted_services:
            return self._upserted_services[svc.uid]
        for replacement in self._upserted_services.values():
            if replacement.type == svc.type and replacement.name == svc.name:
                return replacement if replacement.uid == svc.uid else None
        return svc

    def clear(self) -> None:
        """Discard all uncommitted overlay state (called on publish or discard)."""
        self._upserted_objects.clear()
        self._deleted_object_uids.clear()
        self._deleted_object_names.clear()
        self._upserted_services.clear()
        self._deleted_service_uids.clear()
        self._deleted_service_names.clear()


class WriteSession:
    """Isolated write session handle bound to `contextvars` with an in-memory `SessionOverlay`."""

    def __init__(
        self,
        *,
        mgmt_name: str,
        domain_name: str,
        sid: str,
        server_ip: str,
        session_uid: str | None = None,
        session_name: str | None = None,
        auth: AuthContext | None = None,
        user: UserContext | None = None,
        overlay: SessionOverlay | None = None,
    ) -> None:
        self.mgmt_name = mgmt_name
        self.domain_name = domain_name
        self._sid = sid
        self.server_ip = server_ip
        self.session_uid = session_uid
        self.session_name = session_name
        self.auth = auth
        self.user = user
        self.overlay = overlay if overlay is not None else SessionOverlay(mgmt_name, domain_name)
        self.published: bool = False
        self.discarded: bool = False

    @property
    def sid(self) -> str:
        """Return the raw session identifier for transport calls (never included in repr)."""
        return self._sid

    def matches_scope(self, mgmt_name: str | None = None, domain_name: str | None = None) -> bool:
        """Return True if this write session targets the specified `(mgmt_name, domain_name)`."""
        if mgmt_name is not None and self.mgmt_name != mgmt_name:
            return False
        return not (domain_name is not None and self.domain_name != domain_name)

    def __repr__(self) -> str:
        return (
            f"WriteSession(mgmt_name={self.mgmt_name!r}, domain_name={self.domain_name!r}, "
            f"server_ip={self.server_ip!r}, session_uid={self.session_uid!r}, "
            f"sid={REDACTED_PLACEHOLDER!r}, published={self.published!r}, discarded={self.discarded!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


_current_auth_context: ContextVar[AuthContext | None] = ContextVar("arodonata_auth_context", default=None)
_current_user_context: ContextVar[UserContext | None] = ContextVar("arodonata_user_context", default=None)
_current_write_session: ContextVar[WriteSession | None] = ContextVar("arodonata_write_session", default=None)


def get_auth_context() -> AuthContext | None:
    """Return the active `AuthContext` bound in the current execution context, if any."""
    return _current_auth_context.get()


@contextmanager
def auth_context(
    auth: AuthContext | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
    api_key: str | None = None,
    user_id: str | None = None,
) -> Iterator[AuthContext]:
    """Bind an `AuthContext` to the current `contextvars` scope."""
    resolved = (
        auth
        if auth is not None
        else AuthContext(username=username, password=password, api_key=api_key, user_id=user_id)
    )
    token = _current_auth_context.set(resolved)
    try:
        yield resolved
    finally:
        _current_auth_context.reset(token)


def get_user_context() -> UserContext | None:
    """Return the active `UserContext` bound in the current execution context, if any."""
    return _current_user_context.get()


@contextmanager
def user_context(
    user: UserContext | None = None,
    *,
    user_id: str | None = None,
    username: str | None = None,
    session_name: str | None = None,
    session_description: str | None = None,
    client_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> Iterator[UserContext]:
    """Bind a `UserContext` to the current `contextvars` scope."""
    if user is not None:
        resolved = user
    else:
        if not user_id:
            raise MissingConfigurationError("user_context requires user_id when UserContext is not passed.")
        resolved = UserContext(
            user_id=user_id,
            username=username,
            session_name=session_name,
            session_description=session_description,
            client_id=client_id,
            extra=extra or {},
        )
    token = _current_user_context.set(resolved)
    try:
        yield resolved
    finally:
        _current_user_context.reset(token)


def get_write_session(
    mgmt_name: str | None = None,
    domain_name: str | None = None,
) -> WriteSession | None:
    """Return the active `WriteSession` if one is bound and matches `(mgmt_name, domain_name)`."""
    ws = _current_write_session.get()
    if ws is None or ws.published or ws.discarded:
        return None
    if not ws.matches_scope(mgmt_name=mgmt_name, domain_name=domain_name):
        return None
    return ws


@contextmanager
def write_session_context(session: WriteSession) -> Iterator[WriteSession]:
    """Bind a `WriteSession` to the current `contextvars` scope."""
    token = _current_write_session.set(session)
    try:
        yield session
    finally:
        _current_write_session.reset(token)


async def shielded_best_effort(awaitable: Awaitable[Any]) -> None:
    """Await a cleanup coroutine under `asyncio.shield`, propagating cancellation and TLS identity failures."""
    try:
        await asyncio.shield(awaitable)
    except ServerIdentityError:
        raise
    except Exception:
        pass


@asynccontextmanager
async def run_write_session_lifecycle(
    ws: WriteSession,
    *,
    api_call_fn: Callable[..., Awaitable[ApiCallResult]],
    logout_fn: Callable[..., Awaitable[Any]],
    domain: str | None = None,
    publish_on_exit: bool = True,
    on_domain_invalidated: Callable[[str, str | None], None] | None = None,
) -> AsyncIterator[WriteSession]:
    """Bind `ws` to `contextvars`, auto-discard on error, auto-publish on clean exit, and always log out."""
    mgmt_name = ws.mgmt_name
    dom_key = ws.domain_name
    try:
        with write_session_context(ws):
            try:
                yield ws
            except BaseException:
                if not ws.discarded and not ws.published:
                    await shielded_best_effort(
                        api_call_fn(
                            mgmt_name,
                            "discard",
                            {},
                            domain=domain,
                            sid=ws.sid,
                            server_ip=ws.server_ip,
                        )
                    )
                    ws.discarded = True
                    ws.overlay.clear()
                raise

            if publish_on_exit and not ws.published and not ws.discarded:
                try:
                    pub_res = await api_call_fn(
                        mgmt_name,
                        "publish",
                        {},
                        domain=domain,
                        sid=ws.sid,
                        server_ip=ws.server_ip,
                        wait_for_task=True,
                    )
                except BaseException as pub_exc:
                    should_discard = isinstance(pub_exc, asyncio.CancelledError) or (
                        isinstance(pub_exc, TransportError) and not pub_exc.request_sent
                    )
                    if should_discard and not ws.discarded and not ws.published:
                        await shielded_best_effort(
                            api_call_fn(
                                mgmt_name,
                                "discard",
                                {},
                                domain=domain,
                                sid=ws.sid,
                                server_ip=ws.server_ip,
                            )
                        )
                        ws.discarded = True
                        ws.overlay.clear()
                    raise
                if not pub_res.success:
                    await shielded_best_effort(
                        api_call_fn(
                            mgmt_name,
                            "discard",
                            {},
                            domain=domain,
                            sid=ws.sid,
                            server_ip=ws.server_ip,
                        )
                    )
                    ws.discarded = True
                    ws.overlay.clear()
                    raise SessionError(
                        f"Failed to publish WriteSession on {mgmt_name!r} ({dom_key!r}): "
                        f"{pub_res.error_message or 'publish failed'}",
                        known_sids=[ws.sid],
                    )
                ws.published = True
                ws.overlay.clear()
                if on_domain_invalidated is not None:
                    on_domain_invalidated(mgmt_name, domain)
    finally:
        ws.overlay.clear()
        await shielded_best_effort(logout_fn(mgmt_name, ws.sid, server_ip=ws.server_ip))


@asynccontextmanager
async def open_api_write_session(
    api: ApiPort,
    mgmt_name: str,
    domain: str | None = None,
    *,
    auth: AuthContext | None = None,
    user: UserContext | None = None,
    session_name: str | None = None,
    session_description: str | None = None,
    publish_on_exit: bool = True,
    on_domain_invalidated: Callable[[str, str | None], None] | None = None,
) -> AsyncIterator[WriteSession]:
    """Open an isolated `WriteSession` directly against an `ApiPort` with discard/publish/logout lifecycle."""
    dom_key = normalize_domain_key(domain)
    resolved_user = user or get_user_context()
    eff_name = session_name or (resolved_user.session_name if resolved_user else None)
    eff_desc = session_description or (resolved_user.session_description if resolved_user else None)

    sid, server_ip = await api.create_dedicated_session(
        mgmt_name,
        domain,
        auth=auth,
        session_name=eff_name,
        session_description=eff_desc,
    )
    ws = WriteSession(
        mgmt_name=mgmt_name,
        domain_name=dom_key,
        sid=sid,
        server_ip=server_ip,
        session_name=eff_name,
        auth=auth,
        user=resolved_user,
        overlay=SessionOverlay(mgmt_name, dom_key),
    )
    async with run_write_session_lifecycle(
        ws,
        api_call_fn=api.api_call,
        logout_fn=api.logout_sid,
        domain=domain,
        publish_on_exit=publish_on_exit,
        on_domain_invalidated=on_domain_invalidated,
    ) as bound_ws:
        yield bound_ws


def update_overlay_from_command(
    overlay: SessionOverlay,
    command: str,
    payload: dict[str, Any] | None,
    result: ApiCallResult,
) -> None:
    """Update `SessionOverlay` when `add-*`, `set-*`, or `delete-*` succeeds inside a `WriteSession`."""
    if not result.success:
        return
    clean = command.strip().lower().lstrip("/")
    if not clean.startswith(("add-", "set-", "delete-")):
        return

    verb, _, target_type = clean.partition("-")
    if not target_type or target_type in NON_OVERLAY_MUTATION_TARGETS:
        return

    is_service = target_type in SERVICE_COMMAND_TYPES or target_type.startswith("service-")
    req_data = payload or {}
    resp_data = result.data if isinstance(result.data, dict) else {}

    if verb in ("add", "set"):
        merged_raw = {k: v for k, v in req_data.items() if not is_sensitive_key(k)}
        for k, v in resp_data.items():
            if not is_sensitive_key(k):
                merged_raw[k] = v
        if "type" not in merged_raw or not merged_raw.get("type"):
            merged_raw["type"] = target_type
        uid = str(merged_raw.get("uid") or "")
        name = str(merged_raw.get("name") or req_data.get("new-name") or "")
        if not uid and not name:
            return
        if not uid:
            uid = f"overlay:{target_type}:{name}"
            merged_raw["uid"] = uid

        if is_service:
            svc = CPService.from_cp_dict(overlay.mgmt_name, overlay.domain_name, merged_raw)
            overlay.record_service_upsert(svc)
        else:
            obj = CPObject.from_cp_dict(overlay.mgmt_name, overlay.domain_name, merged_raw)
            overlay.record_object_upsert(obj)
        return

    if verb == "delete":
        uid_val = req_data.get("uid") or resp_data.get("uid")
        name_val = req_data.get("name") or resp_data.get("name")
        uid_str = str(uid_val) if isinstance(uid_val, str) and uid_val else None
        name_str = str(name_val) if isinstance(name_val, str) and name_val else None
        if is_service:
            overlay.record_service_delete(uid=uid_str, name=name_str, svc_type=target_type)
        else:
            overlay.record_object_delete(uid=uid_str, name=name_str, obj_type=target_type)


__all__ = [
    "NON_OVERLAY_MUTATION_TARGETS",
    "SERVICE_COMMAND_TYPES",
    "SYSTEM_DOMAIN_KEY",
    "AuthContext",
    "SessionOverlay",
    "UserContext",
    "WriteSession",
    "auth_context",
    "get_auth_context",
    "get_user_context",
    "get_write_session",
    "normalize_domain_key",
    "open_api_write_session",
    "run_write_session_lifecycle",
    "update_overlay_from_command",
    "user_context",
    "write_session_context",
]
