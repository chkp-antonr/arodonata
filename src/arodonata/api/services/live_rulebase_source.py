"""Live rulebase reads inside an app-owned session (the change report's unpublished-session numbering, spec 5.3).

The SID is unwrapped only inside SidCaller, used only for SID_READ_COMMANDS (never publish, discard or logout: the
app owns the session), and scrubbed — the full value and any 8+ character prefix — from every message and exception
before anything leaves this module. Takes ``sid``/``server_ip``, never an OwnedSession, so api/services never imports
arodonata.reports.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Collection
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import SecretStr

from ...logger import lazy_logger
from ...rulebase.model import DomainRulebaseSnapshot, PackageLayout, RulebaseType
from ...rulebase.source import (
    LayerRulebase,
    PackageRulebase,
    RuleLocations,
    check_uid_collections,
    layer_rulebase_from_snapshot,
    locate_rules_in_snapshot,
    package_rulebase_from_snapshot,
)
from ..schemas import ApiCallResult, ApiQueryResult
from .rulebase_reader import DetailsLevel, read_domain

if TYPE_CHECKING:
    from ..client import ArodonataClient

SID_READ_COMMANDS = frozenset(
    {
        "show-session",
        "show-changes",
        "show-packages",
        "show-package",
        "show-access-rulebase",
        "show-nat-rulebase",
        "show-threat-rulebase",
        "show-https-rulebase",
        "show-access-layers",
        "show-threat-layers",
        "show-https-layers",
    }
)
PAGE_SIZE = 500
log = lazy_logger("arodonata.api.services.live_rulebase_source")


def _naive_utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class SidCallError(RuntimeError):
    """A call through an owned session raised; the message is scrubbed of the SID."""


class SidCaller:
    """RulebaseCaller bound to one app-owned SID (read-only). The SID is domain-bound: ``domain`` is ignored."""

    def __init__(self, client: ArodonataClient, mgmt_name: str, sid: SecretStr, server_ip: str) -> None:
        self._client = client
        self._mgmt = mgmt_name
        self._sid = sid
        self._server_ip = server_ip

    def __repr__(self) -> str:
        return f"SidCaller(mgmt_name={self._mgmt!r}, server_ip={self._server_ip!r})"

    def scrub(self, text: str) -> str:
        """Remove the SID and every prefix of it of 8 or more characters."""
        secret = self._sid.get_secret_value()
        if not secret or not text:
            return text
        text = text.replace(secret, "***")
        for n in range(len(secret) - 1, 7, -1):
            text = text.replace(secret[:n], "***")
        return text

    async def api_call(self, *, mgmt_name: str, domain: str, command: str, payload: dict[str, Any]) -> ApiCallResult:
        if command not in SID_READ_COMMANDS:
            raise ValueError(f"{command!r} is not allowed through an owned session (read-only)")
        try:
            result = await self._client.api_call_with_sid(
                self._mgmt, self._sid.get_secret_value(), self._server_ip, command, payload=dict(payload)
            )
        except Exception as exc:
            raise SidCallError(f"{command} raised {type(exc).__name__}: {self.scrub(str(exc))}") from None
        return result.model_copy(update={"message": self.scrub(result.message)})

    async def api_query(
        self, *, mgmt_name: str, domain: str, command: str, details_level: DetailsLevel, container_key: str
    ) -> ApiQueryResult:
        """api_call_with_sid has no paging: pages with details-level/limit/offset until total; any failed page fails
        the whole query."""
        items: list[dict[str, Any]] = []
        offset = 0
        while True:
            page = await self.api_call(
                mgmt_name=mgmt_name,
                domain=domain,
                command=command,
                payload={"details-level": details_level, "limit": PAGE_SIZE, "offset": offset},
            )
            if not page.success:
                return ApiQueryResult(success=False, code=page.code, message=page.message)
            data = page.data or {}
            objects = [o for o in data.get(container_key) or [] if isinstance(o, dict)]
            items += objects
            total = int(data.get("total", len(items)) or 0)
            if not objects or len(items) >= total:
                return ApiQueryResult(success=True, data=items, objects=items, total=len(items))
            offset += len(objects)


class LiveRulebaseSource:
    """RulebaseSource read once inside one app-owned session (status "live").

    ``snapshot_session_uid`` is the owned session's uid and ``snapshot_published_at`` is None (the session is not
    published); ``snapshot_refreshed_at`` is the read time, naive UTC like the cache. ``warnings`` holds the read's
    warnings (a failed place-holder link or layer page); any warning means the numbers may be wrong.
    """

    def __init__(
        self,
        client: ArodonataClient,
        mgmt_name: str,
        domain_name: str,
        sid: SecretStr,
        server_ip: str,
        *,
        session_uid: str,
        packages: Collection[str] | None,
        clock: Callable[[], datetime] = _naive_utcnow,
    ) -> None:
        self._caller = SidCaller(client, mgmt_name, sid, server_ip)
        self._mgmt = mgmt_name
        self._domain = domain_name
        self._session_uid = session_uid
        self._packages = set(packages) if packages is not None else None
        self._clock = clock
        self._snapshot: DomainRulebaseSnapshot | None = None
        self._lock = asyncio.Lock()
        self.warnings: list[str] = []

    def __repr__(self) -> str:
        return (
            f"LiveRulebaseSource(mgmt_name={self._mgmt!r}, domain_name={self._domain!r}, session={self._session_uid})"
        )

    def _check(self, mgmt_name: str, domain_name: str) -> None:
        if (mgmt_name, domain_name) != (self._mgmt, self._domain):
            raise ValueError(f"this live source reads {self._mgmt}/{self._domain}, not {mgmt_name}/{domain_name}")

    async def _read(self, mgmt_name: str, domain_name: str) -> DomainRulebaseSnapshot:
        self._check(mgmt_name, domain_name)
        async with self._lock:
            if self._snapshot is None:
                warnings: list[str] = []
                packages, layers = await read_domain(
                    self._caller, self._mgmt, self._domain, warnings, packages=self._packages
                )
                self.warnings = [self._caller.scrub(w) for w in warnings]
                self._snapshot = DomainRulebaseSnapshot(
                    mgmt_name=self._mgmt,
                    domain_name=self._domain,
                    session_uid=self._session_uid,
                    session_published_time=None,
                    refreshed_at=self._clock(),
                    packages=tuple(sorted(packages, key=lambda p: p.package_name)),
                    layers=tuple(sorted(layers.values(), key=lambda layer: (layer.rulebase_type, layer.layer_uid))),
                )
                log().debug(
                    f"Live rulebase read for owned session {self._session_uid} on {self._mgmt}:"
                    f"{self._domain}: {len(layers)} layers, {len(self.warnings)} warnings"
                )
            return self._snapshot

    async def packages(self, mgmt_name: str, domain_name: str) -> list[PackageLayout]:
        return list((await self._read(mgmt_name, domain_name)).packages)

    async def package_rulebase(
        self, mgmt_name: str, domain_name: str, package: str, rulebase_type: RulebaseType
    ) -> PackageRulebase:
        snapshot = await self._read(mgmt_name, domain_name)
        return package_rulebase_from_snapshot(snapshot, package, rulebase_type, status="live")

    async def layer_rulebase(
        self, mgmt_name: str, domain_name: str, layer: str, rulebase_type: RulebaseType
    ) -> LayerRulebase:
        snapshot = await self._read(mgmt_name, domain_name)
        return layer_rulebase_from_snapshot(snapshot, layer, rulebase_type, status="live")

    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str,
        rule_uids: Collection[str] = (),
        rulebase_type: RulebaseType | None = None,
        *,
        layer_uids: Collection[str] = (),
    ) -> RuleLocations:
        check_uid_collections(rule_uids=rule_uids, layer_uids=layer_uids)
        snapshot = await self._read(mgmt_name, domain_name)
        return locate_rules_in_snapshot(snapshot, rule_uids, rulebase_type, layer_uids=layer_uids, status="live")


__all__ = ["SID_READ_COMMANDS", "LiveRulebaseSource", "SidCallError", "SidCaller"]
