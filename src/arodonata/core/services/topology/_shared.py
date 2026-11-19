"""Shared loggers, constants, internal models, and synchronization primitives for topology modules."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from weakref import WeakKeyDictionary

import arlogi

from arodonata.core.errors import ServerIdentityError
from arodonata.core.models.assets import Asset
from arodonata.core.models.common import CacheMode
from arodonata.core.models.domains import RefreshOutcome
from arodonata.core.models.scripts import CpridScriptMode
from arodonata.core.models.topology import (
    AntiSpoofingMode,
    ConfidenceDelta,
    GatewayCliTarget,
    RouteCollectionOutcome,
    TopologyZone,
)
from arodonata.core.ports import (
    AssetCachePort,
    DomainCachePort,
    GatewayCliCallable,
    GatewayCliPort,
    ObjectCachePort,
    RulebaseCachePort,
    SyncStatePort,
    TopologyCachePort,
)
from arodonata.core.primitives import normalize_str_sequence
from arodonata.core.services.sync_coordinator import resolve_loop_state

# Shared logger instances preserved at canonical legacy logger names so monkeypatching methods on
# `topology_service.logger` (for example `monkeypatch.setattr(topology_service.logger, "warning", ...)`)
# intercepts log calls emitted across topology submodules. `route_logger` is exported as
# `route_collector.logger` for shim compatibility.
logger = arlogi.get_logger("arodonata.core.services.topology_service")
route_logger = arlogi.get_logger("arodonata.core.services.route_collector")

TOPOLOGY_OBJECT_LOOKUP_CONCURRENCY = 8
_TOPOLOGY_OBJECT_SYNC_TYPES: tuple[str, ...] = ("group", "network", "host", "address-range")

RepositoryScriptArgsCallable = Callable[[GatewayCliTarget, int | None], Sequence[str] | str | None]

POLICY_GATEWAY_TYPES: frozenset[str] = frozenset(
    {
        "simple-gateway",
        "gateway",
        "CpmiGatewayPlain",
        "CpmiHostCkp",
        "simple-cluster",
        "cluster",
        "CpmiGatewayCluster",
        "virtual-system",
        "vs-netobj",
        "CpmiVsNetobj",
        "CpmiVsClusterNetobj",
    }
)

EXCLUDED_GATEWAY_TYPES: frozenset[str] = frozenset(
    {
        "cluster-member",
        "vsx-cluster-member",
        "CpmiClusterMember",
        "CpmiVsxClusterMember",
        "vsx-gateway",
        "vsx-cluster",
        "CpmiVsxNetobj",
        "CpmiVsxClusterNetobj",
        "checkpoint-host",
        "mds",
        "interoperable-device",
    }
)


def is_policy_enforcing_gateway(asset: Asset) -> bool:
    """Return `True` if `asset` is a policy-enforcing gateway, cluster, or VSX Virtual System."""
    a_type = asset.type.strip()
    if a_type in EXCLUDED_GATEWAY_TYPES:
        return False
    if a_type == "CpmiHostCkp":
        # CpmiHostCkp is used for management hosts unless the firewall blade is explicitly enabled
        return asset.network_security_blades.get("firewall") is True
    if a_type in POLICY_GATEWAY_TYPES:
        return True
    lower_type = a_type.lower()
    if "member" in lower_type or "vsx" in lower_type or "checkpoint-host" in lower_type:
        return False
    return "gateway" in lower_type or "cluster" in lower_type or "virtual-system" in lower_type


def _normalize_gateway_filter_tokens(gateways: Sequence[str] | str | None) -> list[str]:
    """Normalize gateway filter tokens (UIDs, names, or composite IDs) into lowercase strings."""
    return normalize_str_sequence(gateways, lowercase=True)


def _matches_gateway_filter(asset: Asset, tokens: set[str]) -> bool:
    """Return `True` if `tokens` is empty or matches any canonical identifier of `asset`."""
    if not tokens:
        return True
    return bool(
        tokens.intersection(
            {
                asset.uid.lower(),
                asset.name.lower(),
                asset.id.lower(),
                asset.asset_id.lower(),
            }
        )
    )


@dataclass(frozen=True)
class _NormalizedInterface:
    """Internal normalized representation of a gateway/cluster/VS network interface."""

    interface_name: str
    ipv4_address: str | None
    mask_length: int | None
    is_external: bool
    leads_to_dmz: bool
    behind_mode: str
    specific_network_ref: str | None
    specific_network_uid: str | None
    specific_inline_cidr: str | None
    has_explicit_topology: bool
    anti_spoofing_mode: AntiSpoofingMode = "unknown"


@dataclass(frozen=True)
class _ResolvedEndpointInterval:
    """Resolved query IPv4 interval derived from a caller-supplied source or destination string."""

    query_raw: str
    cidr_or_range: str
    ip_first_int: int
    ip_last_int: int


@dataclass(frozen=True)
class _InterfaceMatch:
    """Resolution of a single query interval onto a gateway interface."""

    interface_name: str
    topology_zone: TopologyZone
    matched_cidr: str
    source_type: str
    source_ref: str
    confidence: float = 1.0
    is_standby_path: bool = False
    confidence_factors: tuple[ConfidenceDelta, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ExpandedPolicyRule:
    """Cached Access or NAT rule with resolved explicit IPv4 source and destination intervals."""

    rule_kind: str
    rule_uid: str
    rule_label: str
    package_names: tuple[str, ...]
    install_on_tokens: frozenset[str]
    is_gateway_specific_target: bool
    source_intervals: tuple[_ResolvedEndpointInterval, ...]
    destination_intervals: tuple[_ResolvedEndpointInterval, ...]


@dataclass(slots=True)
class _LoopTopologyState:
    """Event-loop-bound single-flight maps, semaphores, and physical node locks for `TopologyService`."""

    refresh_flights: dict[tuple[Any, ...], asyncio.Future[RefreshOutcome]] = field(default_factory=dict)
    route_collect_flights: dict[tuple[Any, ...], asyncio.Future[RouteCollectionOutcome]] = field(default_factory=dict)
    route_collect_sems: dict[tuple[str, int], asyncio.Semaphore] = field(default_factory=dict)
    route_node_locks: dict[tuple[str, str], asyncio.Lock] = field(default_factory=dict)


class _ProcessTopologyRegistry:
    """Process-wide synchronization state shared across `TopologyService` instances attached to the same DB engine."""

    def __init__(self) -> None:
        self._loop_states: WeakKeyDictionary[asyncio.AbstractEventLoop, _LoopTopologyState] = WeakKeyDictionary()
        self._fallback_loop_states: dict[int, _LoopTopologyState] = {}

    def state(self) -> _LoopTopologyState:
        """Return the event-loop-local `_LoopTopologyState` for the running loop."""
        return resolve_loop_state(self._loop_states, self._fallback_loop_states, _LoopTopologyState)


_PROCESS_TOPOLOGY_REGISTRIES: WeakKeyDictionary[Any, _ProcessTopologyRegistry] = WeakKeyDictionary()


async def _run_single_flight[T](
    flights: dict[tuple[Any, ...], asyncio.Future[T]],
    flight_key: tuple[Any, ...],
    *,
    can_coalesce: bool,
    is_reusable: Callable[[T], bool],
    clone_result: Callable[[T], T],
    work: Callable[[], Awaitable[T]],
) -> T:
    """Coalesce identical concurrent calls while preserving caller cancellation (`CancelledError`)."""
    loop = asyncio.get_running_loop()
    my_future: asyncio.Future[T] | None = None
    if can_coalesce:
        while True:
            existing = flights.get(flight_key)
            if existing is None:
                my_future = loop.create_future()
                flights[flight_key] = my_future
                break
            try:
                shared_outcome = await asyncio.shield(existing)
            except ServerIdentityError:
                raise
            except asyncio.CancelledError:
                cur_task = asyncio.current_task()
                if not existing.done() or (cur_task is not None and cur_task.cancelling() > 0):
                    raise
                continue
            except Exception:
                continue
            if is_reusable(shared_outcome):
                return clone_result(shared_outcome)

    try:
        outcome = await work()
        if my_future is not None and not my_future.done():
            my_future.set_result(outcome)
        return outcome
    except BaseException as exc:
        if my_future is not None and not my_future.done():
            my_future.set_exception(exc)
            my_future.exception()  # Mark retrieved so asyncio does not log unhandled future warnings
        raise
    finally:
        if my_future is not None and flights.get(flight_key) is my_future:
            flights.pop(flight_key, None)


class _TopologyServiceCachePort(
    DomainCachePort,
    ObjectCachePort,
    AssetCachePort,
    TopologyCachePort,
    RulebaseCachePort,
    SyncStatePort,
    Protocol,
):
    """Cache capabilities required by `TopologyService`."""


class _RefreshTopologyFn(Protocol):
    """Callback protocol matching `TopologyService.refresh_topology`."""

    async def __call__(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        collect_routes: bool = False,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
        cprid_script_mode: CpridScriptMode | None = None,
        repository_script_name: str | None = None,
        repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    ) -> RefreshOutcome: ...


class _CollectRoutesFn(Protocol):
    """Callback protocol matching `TopologyService.collect_gateway_routes`."""

    async def __call__(
        self,
        mgmt_name: str | None = None,
        domain: str | None = None,
        *,
        domains: Sequence[str] | str | None = None,
        gateways: Sequence[str] | str | None = None,
        include_global: bool = True,
        gateway_cli: GatewayCliPort | GatewayCliCallable | None = None,
        fallback_to_cprid: bool = True,
        timeout: float = 30.0,
        concurrency: int | None = None,
        cprid_script_mode: CpridScriptMode | None = None,
        repository_script_name: str | None = None,
        repository_script_args_fn: RepositoryScriptArgsCallable | None = None,
    ) -> RouteCollectionOutcome: ...
