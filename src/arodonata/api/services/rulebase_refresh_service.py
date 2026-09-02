"""Rulebase population and refresh service."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Any, Literal

from sqlmodel import SQLModel

from ...cache.models import RulebaseAccess, RulebaseHTTPS, RulebaseNAT, RulebaseThreat
from ...extractors.base import ExtractionContext
from ...extractors.rulebases import (
    AccessRuleExtractor,
    HTTPSRuleExtractor,
    NATRuleExtractor,
    ThreatRuleExtractor,
)
from ...logger import lazy_logger

if TYPE_CHECKING:
    from ...cache import CacheRepository
    from ..client import ArodonataClient

log = lazy_logger("arodonata.api.services.rulebase_refresh_service")


class RulebaseRefreshService:
    """Service for refreshing rulebase cache from Check Point API."""

    def __init__(self, client: ArodonataClient, cache: CacheRepository) -> None:
        """Initialize rulebase refresh service.

        Args:
            client: ArodonataClient instance for API calls.
            cache: Cache repository instance.
        """
        self._client = client
        self._cache = cache

        # Initialize extractors
        self._access_extractor = AccessRuleExtractor()
        self._nat_extractor = NATRuleExtractor()
        self._https_extractor = HTTPSRuleExtractor()
        self._threat_extractor = ThreatRuleExtractor()

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
            if item_type == "access-section" or "rulebase" in item:
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
                rule_dict = extractor.extract(item, context)

                # Build ID: mgmt:domain:layer:uid
                # For NAT, layer_name is usually "NAT"
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
            log().warning(f"Skipping non-dict layer object: {type(layer)} - {layer}")
            return None
        layer_name = layer.get("name")
        if not layer_name:
            log().warning("Skipping layer with no name")
            return None
        return layer_name

    async def _fetch_layer_rulebase(
        self,
        mgmt_name: str,
        domain: str,
        layer_name: str,
        command: str,
        payload: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Fetch rulebase for a specific layer.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
            layer_name: Layer name.
            command: API command to execute.
            payload: Request payload.

        Returns:
            Tuple of (success, rulebase_data).
        """
        try:
            rb_res = await self._client.api_call(
                mgmt_name=mgmt_name,
                domain=domain,
                command=command,
                payload=payload,
            )
            if rb_res.success and rb_res.data:
                return True, rb_res.data
            return False, None
        except Exception as api_err:
            log().warning(f"API call failed for layer {layer_name}: {api_err}")
            return False, None

    async def _save_referenced_objects(
        self,
        objects_list: list[dict[str, Any]],
        mgmt_name: str,
        domain: str,
        layer_name: str,
    ) -> None:
        """Save referenced objects from rulebase response to cache.

        Args:
            objects_list: List of object data from API.
            mgmt_name: Management server name.
            domain: Domain name.
            layer_name: Layer name for logging.
        """
        if not objects_list:
            return

        objs_to_save = []
        obj_service = self._client._object_service
        for obj_data in objects_list:
            cp_obj = obj_service._api_object_to_cpobject(obj_data, mgmt_name, domain)
            if cp_obj:
                objs_to_save.append(cp_obj)

        if objs_to_save:
            await self._cache.upsert_objects(objs_to_save)
            log().debug(f"Saved {len(objs_to_save)} referenced objects for {layer_name}")

    async def _process_layer_rules(
        self,
        mgmt_name: str,
        domain: str,
        layer_name: str,
        data: dict[str, Any],
        extractor: Any,
        model_class: type,
        context: ExtractionContext,
    ) -> int:
        """Extract and save rules for a layer.

        Args:
            mgmt_name: Management server name.
            domain: Domain name.
            layer_name: Layer name.
            data: Rulebase response data.
            extractor: Rule extractor instance.
            model_class: Rulebase model class.
            context: Extraction context.

        Returns:
            Number of rules processed.
        """
        # Populate objects map from response
        objects_list = data.get("objects", [])
        context.objects_map = {obj["uid"]: obj["name"] for obj in objects_list if "uid" in obj and "name" in obj}

        # Save referenced objects
        await self._save_referenced_objects(objects_list, mgmt_name, domain, layer_name)

        # Extract rules
        rules_data = data.get("rulebase", [])
        extracted_rules = self._extract_rules_recursive(
            rules_data=rules_data,
            extractor=extractor,
            context=context,
            model_class=model_class,
            mgmt_name=mgmt_name,
            domain=domain,
            layer_name=layer_name,
        )

        if not extracted_rules:
            return 0

        # Clear existing and save new
        await self._cache.delete_rulebase(model_class, mgmt_name, domain, layer_name)
        return await self._cache.upsert_rulebases(extracted_rules)

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
            mode: Refresh mode (only "force" currently implemented for rules).
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

    async def refresh_access_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh all access control rulebases for a domain."""
        try:
            # 1. Get all layers
            layers_res = await self._client.api_query(
                mgmt_name=mgmt_name,
                domain=domain,
                command="show-access-layers",
                details_level="standard",
            )

            if not layers_res.success:
                log().warning(f"Failed to get access layers for {mgmt_name}:{domain}: {layers_res.message}")
                return

            log().debug(f"Found {len(layers_res.objects)} access layers for {mgmt_name}:{domain}")

            # Pre-initialize extraction context to avoid repeated imports
            context = ExtractionContext(mgmt_name=mgmt_name, domain_name=domain)

            for layer in layers_res.objects:
                layer_name = self._validate_and_get_layer_name(layer)
                if not layer_name:
                    continue

                yield {"message": f"Fetching access rules for layer: {layer_name}"}

                # 2. Get rulebase for this layer
                success, data = await self._fetch_layer_rulebase(
                    mgmt_name=mgmt_name,
                    domain=domain,
                    layer_name=layer_name,
                    command="show-access-rulebase",
                    payload={"name": layer_name, "details-level": "full"},
                )

                if not success or not data:
                    continue

                # 3. Extract and save rules
                try:
                    processed = await self._process_layer_rules(
                        mgmt_name=mgmt_name,
                        domain=domain,
                        layer_name=layer_name,
                        data=data,
                        extractor=self._access_extractor,
                        model_class=RulebaseAccess,
                        context=context,
                    )

                    if processed:
                        log().debug(f"Saved {processed} access rules for {layer_name}")
                        yield {
                            "message": f"Saved {processed} access rules for {layer_name}",
                            "count": processed,
                        }
                    else:
                        log().debug(f"No rules found in layer {layer_name}")
                except (AttributeError, TypeError) as data_err:
                    log().warning(
                        f"Error accessing rulebase data for {layer_name}: {data_err}. Data type: {type(data)}"
                    )
                    continue

        except Exception as e:
            import traceback

            log().error(f"Error refreshing access rules for {mgmt_name}:{domain}: {e}\n{traceback.format_exc()}")
            yield {"message": f"Error: {e}", "status": "error"}

    async def refresh_nat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh NAT rulebase for a domain."""
        try:
            # NAT is simpler, usually just one rulebase per domain
            yield {"message": "Fetching NAT rulebase"}

            rb_res = await self._client.api_call(
                mgmt_name=mgmt_name,
                domain=domain,
                command="show-nat-rulebase",
                payload={"package": "Standard", "details-level": "full"},  # CheckPoint default package
            )

            # If "Standard" fails, try with policy-package? No, usually show-nat-rulebase without package
            # returns for current context.
            if not rb_res.success:
                rb_res = await self._client.api_call(
                    mgmt_name=mgmt_name,
                    domain=domain,
                    command="show-nat-rulebase",
                    payload={"details-level": "full"},
                )

            if not rb_res.success or not rb_res.data:
                return

            data = rb_res.data
            if not data:
                return

            # Populate objects map from response and SAVE to cache
            objects_list = data.get("objects", [])
            context = ExtractionContext(
                mgmt_name=mgmt_name,
                domain_name=domain,
                objects_map={obj["uid"]: obj["name"] for obj in objects_list if "uid" in obj and "name" in obj},
            )

            if objects_list:
                objs_to_save = []
                obj_service = self._client._object_service
                for obj_data in objects_list:
                    cp_obj = obj_service._api_object_to_cpobject(obj_data, mgmt_name, domain)
                    if cp_obj:
                        objs_to_save.append(cp_obj)
                if objs_to_save:
                    await self._cache.upsert_objects(objs_to_save)
                    log().debug(f"Saved {len(objs_to_save)} referenced objects for NAT")

            rules_data = data.get("rulebase", [])

            extracted_rules = self._extract_rules_recursive(
                rules_data=rules_data,
                extractor=self._nat_extractor,
                context=context,
                model_class=RulebaseNAT,
                mgmt_name=mgmt_name,
                domain=domain,
                layer_name="NAT",
            )

            if extracted_rules:
                await self._cache.delete_rulebase(RulebaseNAT, mgmt_name, domain, "NAT")
                processed = await self._cache.upsert_rulebases(extracted_rules)
                log().debug(f"Saved {processed} NAT rules for {mgmt_name}:{domain}")
                yield {
                    "message": f"Saved {processed} NAT rules",
                    "count": processed,
                }
            else:
                log().debug(f"No NAT rules found for {mgmt_name}:{domain}")

        except Exception as e:
            log().error(f"Error refreshing NAT rules for {mgmt_name}:{domain}: {e}")
            yield {"message": f"Error: {e}", "status": "error"}

    async def refresh_https_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh HTTPS inspection rulebases for a domain."""
        try:
            # Get HTTPS layers
            layers_res = await self._client.api_query(
                mgmt_name=mgmt_name,
                domain=domain,
                command="show-https-layers",
                details_level="standard",
            )

            if not layers_res.success:
                log().warning(f"Failed to get HTTPS layers for {mgmt_name}:{domain}: {layers_res.message}")
                return

            log().debug(f"Found {len(layers_res.objects)} HTTPS layers for {mgmt_name}:{domain}")

            # Pre-initialize extraction context to avoid repeated imports
            context = ExtractionContext(mgmt_name=mgmt_name, domain_name=domain)

            for layer in layers_res.objects:
                layer_name = self._validate_and_get_layer_name(layer)
                if not layer_name:
                    continue

                yield {"message": f"Fetching HTTPS rules for layer: {layer_name}"}

                # Get rulebase for this layer
                success, data = await self._fetch_layer_rulebase(
                    mgmt_name=mgmt_name,
                    domain=domain,
                    layer_name=layer_name,
                    command="show-https-rulebase",
                    payload={"name": layer_name, "details-level": "full", "use-object-dictionary": True},
                )

                if not success or not data:
                    continue

                # Extract and save rules
                try:
                    processed = await self._process_layer_rules(
                        mgmt_name=mgmt_name,
                        domain=domain,
                        layer_name=layer_name,
                        data=data,
                        extractor=self._https_extractor,
                        model_class=RulebaseHTTPS,
                        context=context,
                    )

                    if processed:
                        log().debug(f"Saved {processed} HTTPS rules for {layer_name}")
                        yield {
                            "message": f"Saved {processed} HTTPS rules for {layer_name}",
                            "count": processed,
                        }
                except (AttributeError, TypeError) as data_err:
                    log().warning(
                        f"Error accessing HTTPS rulebase data for {layer_name}: {data_err}. Data type: {type(data)}"
                    )
                    continue

        except Exception as e:
            log().error(f"Error refreshing HTTPS rules for {mgmt_name}:{domain}: {e}")
            yield {"message": f"Error: {e}", "status": "error"}

    async def refresh_threat_rulebases(self, mgmt_name: str, domain: str) -> AsyncGenerator[dict[str, Any]]:
        """Refresh threat prevention rulebases for a domain."""
        try:
            # Get Threat layers
            layers_res = await self._client.api_query(
                mgmt_name=mgmt_name,
                domain=domain,
                command="show-threat-layers",
                details_level="standard",
            )

            if not layers_res.success:
                log().warning(f"Failed to get Threat layers for {mgmt_name}:{domain}: {layers_res.message}")
                return

            log().debug(f"Found {len(layers_res.objects)} Threat layers for {mgmt_name}:{domain}")

            # Pre-initialize extraction context to avoid repeated imports
            context = ExtractionContext(mgmt_name=mgmt_name, domain_name=domain)

            for layer in layers_res.objects:
                layer_name = self._validate_and_get_layer_name(layer)
                if not layer_name:
                    continue

                yield {"message": f"Fetching Threat rules for layer: {layer_name}"}

                # Get rulebase for this layer
                success, data = await self._fetch_layer_rulebase(
                    mgmt_name=mgmt_name,
                    domain=domain,
                    layer_name=layer_name,
                    command="show-threat-rulebase",
                    payload={"name": layer_name, "details-level": "full", "use-object-dictionary": True},
                )

                if not success or not data:
                    continue

                # Extract and save rules
                try:
                    processed = await self._process_layer_rules(
                        mgmt_name=mgmt_name,
                        domain=domain,
                        layer_name=layer_name,
                        data=data,
                        extractor=self._threat_extractor,
                        model_class=RulebaseThreat,
                        context=context,
                    )

                    if processed:
                        log().debug(f"Saved {processed} Threat rules for {layer_name}")
                        yield {
                            "message": f"Saved {processed} Threat rules for {layer_name}",
                            "count": processed,
                        }
                except (AttributeError, TypeError) as data_err:
                    log().warning(
                        f"Error accessing Threat rulebase data for {layer_name}: {data_err}. Data type: {type(data)}"
                    )
                    continue

        except Exception as e:
            log().error(f"Error refreshing Threat rules for {mgmt_name}:{domain}: {e}")
            yield {"message": f"Error: {e}", "status": "error"}


__all__ = ["RulebaseRefreshService"]
