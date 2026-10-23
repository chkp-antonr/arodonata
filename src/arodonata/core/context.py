"""Contextvars propagation for authentication, operator metadata, and WriteSession overlays."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import REDACTED_PLACEHOLDER, MissingConfigurationError
from arodonata.core.models.objects import CPObject
from arodonata.core.models.services import CPService


class AuthContext(BaseModel):
    """Runtime authentication credentials propagated via `contextvars`."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    username: str | None = None
    password: str | None = Field(default=None, repr=False)
    api_key: str | None = Field(default=None, repr=False)
    user_id: str | None = None

    def model_post_init(self, __context: Any) -> None:
        has_key = bool(self.api_key)
        has_user_pass = bool(self.username and self.password)
        if not has_key and not has_user_pass:
            raise MissingConfigurationError("AuthContext requires either api_key or both username and password.")

    @property
    def identity_key(self) -> str:
        """Stable non-secret identifier for the authenticated principal."""
        if self.user_id:
            return self.user_id
        if self.username:
            return self.username
        return "api_key_principal"

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
