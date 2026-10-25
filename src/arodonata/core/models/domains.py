"""Domain, session cache, and synchronization state models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import REDACTED_PLACEHOLDER
from arodonata.core.models.common import SyncScope, SyncStatus, to_naive_utc, utc_now


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
            self.id = f"{self.mgmt_name}:{self.name}"
        self.updated_at = to_naive_utc(self.updated_at) or utc_now()


class SIDCacheEntry(BaseModel):
    """Shared read-only Check Point session identifier entry with SID-safe repr()."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    mgmt_name: str
    domain_name: str
    sid: str = Field(repr=False)
    server_ip: str
    session_uid: str | None = None
    auth_identity: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    last_used_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"{self.mgmt_name}:{self.domain_name}"
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

    @staticmethod
    def make_id(mgmt_name: str, domain_name: str, scope: str, item_type: str = "*") -> str:
        """Build the canonical composite primary key for domain_sync_state."""
        return f"{mgmt_name}:{domain_name}:{scope}:{item_type}"


class RefreshOutcome(BaseModel):
    """Summary outcome returned by `refresh_objects`, `refresh_services`, `refresh_assets`, and `refresh_rulebases`."""

    model_config = ConfigDict(extra="ignore")

    scope: SyncScope
    refreshed_domains: list[str] = Field(default_factory=list)
    skipped_domains: list[str] = Field(default_factory=list)
    failed_domains: dict[str, str] = Field(default_factory=dict)
    total_items: int = 0
