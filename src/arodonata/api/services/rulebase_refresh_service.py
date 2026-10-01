"""Rulebase population and refresh service: per domain and type, every layer is read completely, then the type's rows are replaced in one transaction."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from sqlmodel import SQLModel

from ...cache.models import RulebaseAccess, RulebaseHTTPS, RulebaseNAT, RulebaseThreat
from ...core.domain_list_refresh import DOMAIN_LIST_REFRESH_TTL_SECONDS, DomainListRefreshTracker
from ...extractors.base import ExtractionContext
from ...extractors.rulebases import (
    AccessRuleExtractor,
    HTTPSRuleExtractor,
    NATRuleExtractor,
    ThreatRuleExtractor,
)
from ...logger import lazy_logger
from ...rulebase.pager import RulebaseFetchError, fetch_full_rulebase

if TYPE_CHECKING:
    from ...cache import CacheRepository
    from ...core.cache_policy import Clock
    from ..client import ArodonataClient

log = lazy_logger("arodonata.api.services.rulebase_refresh_service")


@dataclass(frozen=True)
class _TypeSpec:
    """How one rulebase type is listed and read."""

    rulebase_type: str  # "access" | "nat" | "https" | "threat"
    label: str  # for messages
    list_command: str
    container_key: str
    list_details_level: str
    rulebase_command: str
    target: str  # what one listing entry is: "layer" | "package"
    target_param: str  # payload key the entry's name goes into: "name" | "package"
    model_class: type[SQLModel]
    requires_flag: str | None = None  # entries without this flag set are not read (NAT: nat-policy)
    name_from_response: bool = True  # layer_name = the response's top-level name; NAT: the package name


_ACCESS = _TypeSpec(
    "access",
    "access",
    "show-access-layers",
    "access-layers",
    "standard",
    "show-access-rulebase",
    "layer",
    "name",
    RulebaseAccess,
)
_HTTPS = _TypeSpec(
    "https",
    "HTTPS",
    "show-https-layers",
    "https-layers",
    "standard",
    "show-https-rulebase",
    "layer",
    "name",
    RulebaseHTTPS,
)
_THREAT = _TypeSpec(
    "threat",
    "Threat",
    "show-threat-layers",
    "threat-layers",
    "standard",
    "show-threat-rulebase",
    "layer",
    "name",
    RulebaseThreat,
)
_NAT = _TypeSpec(
    "nat",
    "NAT",
    "show-packages",
    "packages",
    "full",
    "show-nat-rulebase",
    "package",
    "package",
    RulebaseNAT,
    requires_flag="nat-policy",
    name_from_response=False,
)
_SPECS = {spec.rulebase_type: spec for spec in (_ACCESS, _NAT, _HTTPS, _THREAT)}


class RulebaseRefreshService:
    """Service for refreshing rulebase cache from Check Point API."""

    def __init__(
        self,
        client: ArodonataClient,
        cache: CacheRepository,
        domain_list_refresh_ttl: int = DOMAIN_LIST_REFRESH_TTL_SECONDS,
        clock: Clock | None = None,
    ) -> None:
        """Initialize rulebase refresh service.

        Args:
            client: ArodonataClient instance for API calls.
            cache: Cache repository instance.
            domain_list_refresh_ttl: Seconds between opportunistic ("check"-mode)
                re-fetches of a management server's domain list ahead of
                `refresh_all`. "force" mode ignores this and always re-fetches.
                See `arodonata.core.domain_list_refresh`.
            clock: Injectable time source for the TTL memo (tests only;
                defaults to the real wall clock).
        """
        self._client = client
        self._cache = cache
        self._domain_list_refresh = DomainListRefreshTracker(ttl_seconds=domain_list_refresh_ttl, clock=clock)

        # Initialize extractors
        self._extractors: dict[str, Any] = {
            "access": AccessRuleExtractor(),
            "nat": NATRuleExtractor(),
            "https": HTTPSRuleExtractor(),
            "threat": ThreatRuleExtractor(),
        }

    def _extract_rules_recursive(
        self,
        rules_data: list[dict[str, Any]],
        extractor: Any,
        context: ExtractionContext,
        model_class: type[SQLModel],
        mgmt_name: str,
        domain: str,
        layer_name: str,
    ) -> list[Any]:
        """Recursively extract rules from rulebase data, including sections.

        Args:
            rules_data: List of rule/section objects from API.
            extractor: Rule extractor instance.
            context: Extraction context.
            model_class: Rulebase model class (e.g., RulebaseAccess).
            mgmt_name: Management name.
            domain: Domain name.
            layer_name: Layer name.

        Returns:
            List of extracted rule models.
        """
        extracted = []
        for item in rules_data:
            if not isinstance(item, dict):
                continue

            item_type = item.get("type")

            # If it's a section, recurse
            # Sections (access-section, nat-section, ...) hold their rules in a nested rulebase
            if str(item_type).endswith("-section") or "rulebase" in item:
                section_rules = item.get("rulebase", [])
                extracted.extend(
                    self._extract_rules_recursive(
                        section_rules, extractor, context, model_class, mgmt_name, domain, layer_name
                    )
                )
                continue

            # If it matches the expected rule type for the extractor
            # AccessRuleExtractor handles 'access-rule'
            # NATRuleExtractor handles 'nat-rule'
            # etc.
            rule_type_map = {
                AccessRuleExtractor: "access-rule",
                NATRuleExtractor: "nat-rule",
                HTTPSRuleExtractor: "https-rule",
                ThreatRuleExtractor: "threat-rule",
            }
            expected_type = rule_type_map.get(type(extractor))

            if item_type == expected_type:
                rule_dict = {**extractor.extract(item, context), "layer_name": layer_name}

                # Build ID: mgmt:domain:layer:uid
                rule_id = f"{mgmt_name}:{domain}:{layer_name}:{rule_dict['uid']}"
                rule_model = model_class(id=rule_id, **rule_dict)
                extracted.append(rule_model)

        return extracted

    def _validate_and_get_layer_name(self, layer: Any) -> str | None:
        """Validate layer object and extract layer name.

        Args:
            layer: Layer object from API response.

        Returns:
            Layer name if valid, None otherwise.
        """
        if not isinstance(layer, dict):
            log().warning(f"Invalid listing entry: {type(layer)} - {layer}")
            return None
        layer_name = layer.get("name")
        if not layer_name:
            log().warning("Invalid listing entry: no name")
            return None
        return layer_name

    def _rows_from_layer_response(
        self,
        data: dict[str, Any],
        rulebase_type: str,
        mgmt_name: str,
        domain: str,
        *,
        layer_name: str,
    ) -> list[SQLModel]:
        """Rule rows of one fully fetched layer, references resolved through its ``objects-dictionary``.

        Args:
            data: A complete ``show-*-rulebase`` response (``fetch_full_rulebase``).
            rulebase_type: "access", "nat", "https" or "threat".
            mgmt_name: Management server name.
            domain: Domain name.
            layer_name: The response's own top-level ``name`` (NAT: the package name).
        """
        objects_map = {
            str(obj["uid"]): str(obj["name"])
            for obj in data.get("objects-dictionary", [])
            if isinstance(obj, dict) and "uid" in obj and "name" in obj
        }
        return self._extract_rules_recursive(
            rules_data=data.get("rulebase", []),
            extractor=self._extractors[rulebase_type],
            context=ExtractionContext(mgmt_name=mgmt_name, domain_name=domain, objects_map=objects_map),
            model_class=_SPECS[rulebase_type].model_class,
            mgmt_name=mgmt_name,
            domain=domain,
            layer_name=layer_name,
        )

    @staticmethod
    def _type_failed(spec: _TypeSpec, scope: dict[str, str], error: str) -> dict[str, Any]:
        message = (
            f"{spec.label} rulebase refresh failed for {scope['mgmt_name']}:{scope['domain_name']}: {error}; "
            "cached rows kept"
        )
        log().warning(message)
        return {"message": message, "status": "domain_failed", "error": error, **scope}

    async def _refresh_type(self, spec: _TypeSpec, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Read every layer (NAT: every package with a NAT policy) of one type completely, then replace that type's
        rows for the domain in one transaction.

        Any per-layer failure (fetch error, invalid listing entry, extraction error) aborts the type with no
        replace, so the old rows stay and a ``domain_failed`` event is yielded: skipping a layer under a whole-type
        replace would silently drop its rows. A failed listing keeps the old rows and yields ``warning``.
        """
        scope = {"mgmt_name": mgmt_name, "domain_name": domain, "rulebase_type": spec.rulebase_type}
        try:
            listing = await self._client.api_query(
                mgmt_name=mgmt_name,
                domain=domain,
                command=spec.list_command,
                details_level=spec.list_details_level,  # type: ignore[arg-type]
                container_key=spec.container_key,
            )
            if not listing.success:
                message = (
                    f"{spec.list_command} failed for {mgmt_name}:{domain}: {listing.message}; "
                    f"cached {spec.label} rules kept"
                )
                log().warning(message)
                yield {"message": message, "status": "warning", **scope}
                return

            rows: list[SQLModel] = []
            for entry in listing.objects:
                entry_name = self._validate_and_get_layer_name(entry)
                if not entry_name:
                    yield self._type_failed(spec, scope, f"invalid {spec.target} listing entry: {entry!r}")
                    return
                if spec.requires_flag and not entry.get(spec.requires_flag):
                    continue
                yield {"message": f"Fetching {spec.label} rules for {spec.target}: {entry_name}"}
                try:
                    data = await fetch_full_rulebase(
                        self._client,
                        mgmt_name,
                        domain,
                        spec.rulebase_command,
                        {spec.target_param: entry_name, "details-level": "full", "use-object-dictionary": True},
                    )
                except RulebaseFetchError as exc:
                    yield self._type_failed(spec, scope, f"{spec.target} {entry_name}: {exc}")
                    return
                layer_name = str(data.get("name") or entry_name) if spec.name_from_response else entry_name
                try:
                    rows += self._rows_from_layer_response(
                        data, spec.rulebase_type, mgmt_name, domain, layer_name=layer_name
                    )
                except (AttributeError, TypeError, KeyError, ValueError) as exc:
                    yield self._type_failed(spec, scope, f"{spec.target} {entry_name}: {exc}")
                    return

            count = await self._cache.replace_domain_rulebase_type(spec.model_class, mgmt_name, domain, rows)
            log().debug(f"Saved {count} {spec.label} rules for {mgmt_name}:{domain}")
            yield {"message": f"Saved {count} {spec.label} rules for {mgmt_name}:{domain}", "count": count, **scope}
        except Exception as e:
            log().exception(f"Error refreshing {spec.label} rules for {mgmt_name}:{domain}: {e}")
            yield {"message": f"Error: {e}", "status": "error", **scope}

    async def refresh_all(
        self,
        mgmt_names: list[str] | None = None,
        domain_names: list[str] | None = None,
        mode: Literal["skip", "check", "force"] = "force",
        include_global: bool = False,
    ) -> AsyncGenerator[dict[str, Any]]:
        """Refresh all rulebases for specified managements and domains.

        Args:
            mgmt_names: Optional management server filter.
            domain_names: Optional domain filter.
            mode: Refresh mode (only "force" currently implemented for rules;
                affects only whether the domain *list* is re-fetched before
                resolving `target_domains` below - see
                `_ensure_domain_list_fresh`).
            include_global: When False (default), the synthetic "Global" domain
                is excluded so existing callers see today's behavior.

        Yields:
            Progress dictionaries.
        """
        if mode == "skip":
            yield {"message": "Rulebase refresh skipped", "status": "skipped"}
            return

        target_mgmt = mgmt_names or self._client.get_mgmt_names()

        for m_name in target_mgmt:
            # A domain created in SmartConsole after this mgmt's domains table was
            # last populated would otherwise stay invisible to `get_domains` below
            # forever - re-fetch it first (unconditionally for "force", at most
            # once per TTL for "check").
            await self._ensure_domain_list_fresh(m_name, mode)

            # Get domains for this mgmt
            domains = await self._client.get_domains(mgmt_names=[m_name], include_global=include_global)
            target_domains = [d.name for d in domains]
            if domain_names:
                target_domains = [d for d in target_domains if d in domain_names]

            for d_name in target_domains:
                yield {
                    "message": f"Refreshing rulebases for {m_name}:{d_name}",
                    "mgmt_name": m_name,
                    "domain_name": d_name,
                }

                # 1. Access Rulebases
                async for event in self.refresh_access_rulebases(m_name, d_name):
                    yield event

                # 2. NAT Rulebases
                async for event in self.refresh_nat_rulebases(m_name, d_name):
                    yield event

                # 3. HTTPS Rulebases
                async for event in self.refresh_https_rulebases(m_name, d_name):
                    yield event

                # 4. Threat Rulebases
                async for event in self.refresh_threat_rulebases(m_name, d_name):
                    yield event

    async def _ensure_domain_list_fresh(self, mgmt_name: str, mode: Literal["skip", "check", "force"]) -> None:
        """Re-fetch `mgmt_name`'s domain list from the API before `refresh_all`
        resolves which domains to refresh rulebases for.

        Mirrors `ObjectService._get_domains_to_refresh`'s fix for the identical
        underlying bug: a domain created in SmartConsole after the domains table
        was first seeded stayed invisible to every rulebase refresh forever,
        because this method previously never called `populate_domain_cache` at
        all - it only ever read whatever was already cached via
        `client.get_domains()`. "force" mode now always re-fetches
        unconditionally; "check" mode re-fetches at most once per
        `DOMAIN_LIST_REFRESH_TTL_SECONDS`, via the same `DomainListRefreshTracker`
        mechanism `ObjectService` uses, so repeated smart refreshes don't hammer
        `show-domains`.

        A failed or unavailable re-fetch is not fatal here - unlike
        `ObjectService`, this is purely an opportunistic freshening step ahead of
        the `client.get_domains()` cache read that follows, which already
        tolerates a merely-stale (or even still-empty) table the same as before
        this fix.
        """
        if mode != "force" and not self._domain_list_refresh.is_stale(mgmt_name):
            return

        if not hasattr(self._client, "_domain_service"):
            return

        try:
            await self._client._domain_service.populate_domain_cache(mgmt_name)
        except Exception as e:
            log().exception(f"Failed to refresh domain list for {mgmt_name}: {e}")
            return

        self._domain_list_refresh.mark_checked(mgmt_name)

    async def refresh_access_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh every access layer of a domain (atomic for the access type)."""
        async for event in self._refresh_type(_ACCESS, mgmt_name, domain):
            yield event

    async def refresh_nat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh the NAT rulebase of every package with ``nat-policy`` (rows keyed by package name)."""
        async for event in self._refresh_type(_NAT, mgmt_name, domain):
            yield event

    async def refresh_https_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh every HTTPS inspection layer of a domain (atomic for the HTTPS type)."""
        async for event in self._refresh_type(_HTTPS, mgmt_name, domain):
            yield event

    async def refresh_threat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh every threat prevention layer of a domain (atomic for the threat type)."""
        async for event in self._refresh_type(_THREAT, mgmt_name, domain):
            yield event


__all__ = ["RulebaseRefreshService"]
