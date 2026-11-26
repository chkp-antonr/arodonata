"""Domain, session cache, and synchronization state models."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import REDACTED_PLACEHOLDER, redact_sid
from arodonata.core.models.common import ApiCallResult, SyncScope, SyncStatus, to_naive_utc, utc_now
from arodonata.core.primitives import format_composite_id


class DomainInfo(BaseModel):
    """Check Point Management / MDSM domain metadata."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    uid: str
    name: str
    domain_type: str = "domain"
    active_ip: str | None = None
    active_mds_ip: str | None = None
    standby_ips: list[str] = Field(default_factory=list)
    servers: list[dict[str, Any]] = Field(default_factory=list)
    is_global: bool = False
    raw_data: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = format_composite_id(self.mgmt_name, self.name)
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class SIDCacheEntry(BaseModel):
    """Shared read-only Check Point session identifier entry with SID-safe repr()."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    sid: str = Field(repr=False, exclude=True)
    server_ip: str
    tls_identity_host: str | None = None
    session_uid: str | None = None
    auth_identity: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    last_used_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = (
                format_composite_id(self.mgmt_name, self.domain_name, self.auth_identity)
                if self.auth_identity
                else format_composite_id(self.mgmt_name, self.domain_name)
            )
        self.created_at = to_naive_utc(self.created_at) or utc_now()
        self.last_used_at = to_naive_utc(self.last_used_at) or utc_now()
        self.expires_at = to_naive_utc(self.expires_at)

    def __repr__(self) -> str:
        return (
            f"SIDCacheEntry(id={self.id!r}, mgmt_name={self.mgmt_name!r}, "
            f"domain_name={self.domain_name!r}, server_ip={self.server_ip!r}, "
            f"sid={REDACTED_PLACEHOLDER!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class DomainSyncState(BaseModel):
    """Per-(mgmt_name, domain_name, scope, item_type) synchronization state."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    scope: SyncScope
    item_type: str = "*"
    last_published_at: datetime | None = None
    last_session_uid: str | None = None
    synced_at: datetime | None = None
    status: SyncStatus = "idle"
    object_count: int = 0
    last_error: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = self.make_id(self.mgmt_name, self.domain_name, self.scope, self.item_type)
        self.last_published_at = to_naive_utc(self.last_published_at)
        self.synced_at = to_naive_utc(self.synced_at)
        if self.last_error:
            self.last_error = redact_sid(self.last_error)

    @staticmethod
    def make_id(mgmt_name: str, domain_name: str, scope: str, item_type: str = "*") -> str:
        """Build the canonical composite primary key for domain_sync_state."""
        return format_composite_id(mgmt_name, domain_name, scope, item_type)


class RefreshOutcome(BaseModel):
    """Summary outcome returned by `refresh_objects`, `refresh_services`, `refresh_assets`, and `refresh_rulebases`."""

    model_config = ConfigDict(extra="ignore")

    scope: SyncScope
    refreshed_domains: list[str] = Field(default_factory=list)
    skipped_domains: list[str] = Field(default_factory=list)
    failed_domains: dict[str, str] = Field(default_factory=dict)
    total_items: int = 0

    def model_post_init(self, __context: Any) -> None:
        if self.failed_domains:
            self.failed_domains = {k: redact_sid(v) for k, v in self.failed_domains.items()}


WarmupTaskStatus = Literal["running", "completed", "failed", "cancelled"]


class WarmupStatusEntry(BaseModel):
    """Structured status record for background object/service cache warm-up flights."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domains: list[str] = Field(default_factory=list)
    types: list[str] = Field(default_factory=list)
    include_global: bool = False
    include_services: bool = False
    status: WarmupTaskStatus = "running"
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    refreshed_domains: list[str] = Field(default_factory=list)
    failed_domains: dict[str, str] = Field(default_factory=dict)
    error: str | None = None

    def model_post_init(self, __context: Any) -> None:
        self.started_at = to_naive_utc(self.started_at) or utc_now()
        self.completed_at = to_naive_utc(self.completed_at)


def parse_domain_entry(
    mgmt_name: str,
    raw: dict[str, Any],
    *,
    mds_ip_by_name: dict[str, str] | None = None,
    default_host: str | None = None,
    now_fn: Callable[[], datetime] | None = None,
    fallback_uid: bool = False,
) -> DomainInfo:
    """Convert a raw Check Point `show-domains` / `show-domain` / `show-global-domain` dict into `DomainInfo`."""
    uid = str(raw.get("uid") or "")
    name = str(raw.get("name") or "")
    dom_type = str(raw.get("type") or raw.get("domain-type") or "domain")
    is_global = dom_type in ("global", "global-domain") or name == "Global" or bool(raw.get("is_global"))

    servers_raw = raw.get("servers")
    servers_list: list[dict[str, Any]] = (
        [s for s in servers_raw if isinstance(s, dict)] if isinstance(servers_raw, list) else []
    )

    active_ip: str | None = raw.get("active_ip") or raw.get("active-ip")
    active_mds_ip: str | None = raw.get("active_mds_ip") or raw.get("active-mds-ip")
    standby_ips: list[str] = []

    for srv in servers_list:
        srv_ip = srv.get("ipv4-address") or srv.get("ipv6-address") or srv.get("ip")
        mds_obj = srv.get("multi-domain-server")
        mds_ip: str | None = None
        if isinstance(mds_obj, dict):
            mds_ip = mds_obj.get("ipv4-address") or mds_obj.get("ipv6-address") or mds_obj.get("ip")
            if not mds_ip and mds_ip_by_name and isinstance(mds_obj.get("name"), str):
                mds_ip = mds_ip_by_name.get(mds_obj["name"])
        elif isinstance(mds_obj, str) and mds_ip_by_name:
            mds_ip = mds_ip_by_name.get(mds_obj)
        elif isinstance(srv.get("multi-domain-server-ip"), str):
            mds_ip = srv.get("multi-domain-server-ip")

        if bool(srv.get("active")):
            if isinstance(srv_ip, str) and srv_ip:
                active_ip = srv_ip
            if isinstance(mds_ip, str) and mds_ip:
                active_mds_ip = mds_ip
        elif isinstance(srv_ip, str) and srv_ip:
            standby_ips.append(srv_ip)

    if active_ip is None and is_global and active_mds_ip:
        active_ip = active_mds_ip

    if active_ip is None and servers_list:
        first_srv = servers_list[0]
        first_ip = first_srv.get("ipv4-address") or first_srv.get("ipv6-address") or first_srv.get("ip")
        if isinstance(first_ip, str) and first_ip:
            active_ip = first_ip
        first_mds = first_srv.get("multi-domain-server")
        if active_mds_ip is None and isinstance(first_mds, dict):
            mds_candidate = first_mds.get("ipv4-address") or first_mds.get("ipv6-address") or first_mds.get("ip")
            if isinstance(mds_candidate, str) and mds_candidate:
                active_mds_ip = mds_candidate
        elif active_mds_ip is None and isinstance(first_mds, str) and mds_ip_by_name:
            mds_candidate = mds_ip_by_name.get(first_mds)
            if mds_candidate:
                active_mds_ip = mds_candidate

    if active_ip is None and default_host:
        active_ip = default_host
    if active_mds_ip is None:
        active_mds_ip = active_ip or default_host

    kwargs: dict[str, Any] = {}
    if now_fn is not None:
        kwargs["updated_at"] = now_fn()

    return DomainInfo(
        id=f"{mgmt_name}:{name}",
        mgmt_name=mgmt_name,
        uid=uid or (f"domain:{mgmt_name}:{name}" if fallback_uid else ""),
        name=name,
        domain_type="global" if is_global else dom_type,
        active_ip=active_ip,
        active_mds_ip=active_mds_ip,
        standby_ips=standby_ips,
        servers=servers_list,
        is_global=is_global,
        raw_data=dict(raw),
        **kwargs,
    )


def parse_domain_dict(
    mgmt_name: str,
    raw: dict[str, Any],
    *,
    default_host: str | None = None,
    mds_ip_by_name: dict[str, str] | None = None,
    now_fn: Callable[[], datetime] = utc_now,
) -> DomainInfo:
    """Convert a raw Check Point `show-domains` / `show-domain` / `show-global-domain` dict with domain fallbacks."""
    return parse_domain_entry(
        mgmt_name,
        raw,
        default_host=default_host,
        mds_ip_by_name=mds_ip_by_name,
        now_fn=now_fn,
        fallback_uid=True,
    )


_RBAC_DETAILS_LEVEL_TOKENS: tuple[str, ...] = (
    "err_forbidden",
    "forbidden",
    "permission",
    "not authorized",
    "unauthorized",
    "not allowed",
    "details-level",
    "details_level",
    "privileges",
)


def is_rbac_or_details_level_rejected(res: ApiCallResult) -> bool:
    """Return `True` if `show-domains` with `details-level=full` was rejected due to RBAC / permissions."""
    if res.status_code in (401, 403):
        return True
    err_lower = (res.error_message or "").lower()
    code_lower = (res.error_code or "").lower()
    return any(tok in err_lower or tok in code_lower for tok in _RBAC_DETAILS_LEVEL_TOKENS)
