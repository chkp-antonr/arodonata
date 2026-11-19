"""Rulebase introspection, change reports, API reference, and repository script facades for `ArodonataClient`."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any

from arodonata.api_reference import DEFAULT_API_VERSION, ApiReferenceEngine, normalize_api_version
from arodonata.client._base import ClientBase
from arodonata.core.events import SyncProgressEvent
from arodonata.core.models.common import CacheMode
from arodonata.core.models.domains import RefreshOutcome
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseType,
    ThreatRuleEntry,
)
from arodonata.core.models.scripts import (
    EnsureRepositoryScriptResult,
    RepositoryScript,
    RepositoryScriptExecutionOutcome,
    RepositoryScriptStatus,
)
from arodonata.core.telemetry import traced
from arodonata.cpcrud import Plan
from arodonata.reports import (
    MAX_UID_LOOKUPS,
    ChangeReport,
    RenderedReportBundle,
    RenderOptions,
    ReportScope,
)
from arodonata.reports import build_change_report as _build_change_report
from arodonata.reports import build_change_report_from_plan as _build_change_report_from_plan
from arodonata.reports import collect_change_report as _collect_change_report
from arodonata.reports import render_change_report as _render_change_report
from arodonata.rulebase import (
    FilteredRulebaseResult,
    NumberedLayerRulebase,
    PackageRulebase,
    PolicyPackageInfo,
    RuleFormat,
    RuleLocations,
)


class ClientRulebaseReportsMixin(ClientBase):
    """Provides rulebase, change-report, API-reference, and repository-script facade methods."""

    # ------------------------------------------------------------------
    # Rulebase Refresh & Streaming
    # ------------------------------------------------------------------

    @traced
    async def refresh_rulebases(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize policy rulebase snapshots across target domains and return `RefreshOutcome`."""
        await self._ensure_initialized()
        return await self._rulebase_refresh.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_rulebases(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing policy rulebase snapshots."""
        await self._ensure_initialized()
        async for ev in self._rulebase_refresh.stream_refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_policy_packages(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize lightweight policy package catalogs (`item_type='packages'`) without downloading rulebases."""
        await self._ensure_initialized()
        return await self._rulebase_refresh.refresh_policy_packages(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    async def stream_refresh_policy_packages(
        self,
        *,
        mgmt_name: str | None = None,
        domains: Sequence[str] | str | None = None,
        include_global: bool = False,
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> AsyncIterator[SyncProgressEvent]:
        """Stream `SyncProgressEvent` items while synchronizing lightweight policy package catalogs."""
        await self._ensure_initialized()
        async for ev in self._rulebase_refresh.stream_refresh_policy_packages(
            mgmt_name=mgmt_name,
            domains=domains,
            include_global=include_global,
            mode=mode,
            cache_ttl=cache_ttl,
        ):
            yield ev

    @traced
    async def refresh_package_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        package: str,
        *,
        rulebase_type: RulebaseType = "access",
        mode: CacheMode = "smart",
        cache_ttl: float | None = None,
    ) -> RefreshOutcome:
        """Synchronize only the layers belonging to `(package, rulebase_type)` without pulling other packages or rulebase types."""
        await self._ensure_initialized()
        resolved_dom = (
            domain_name.strip()
            if domain_name is not None and domain_name.strip()
            else await self._rulebase_source.resolve_domain_for_target(
                mgmt_name,
                domain_name,
                package,
                kind="package",
                rulebase_type=rulebase_type,
                cache_mode=mode,
                cache_ttl=cache_ttl,
            )
        )
        return await self._rulebase_refresh.refresh_package_rulebase(
            mgmt_name,
            resolved_dom,
            package,
            rulebase_type=rulebase_type,
            mode=mode,
            cache_ttl=cache_ttl,
        )

    # ------------------------------------------------------------------
    # Rulebase Read & Introspection
    # ------------------------------------------------------------------

    @traced
    async def get_access_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        layer_uid: str | None = None,
        layer_name: str | None = None,
    ) -> list[AccessRuleEntry]:
        """Return cached access-control rules for `(mgmt_name, domain)`."""
        await self._ensure_initialized()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.access_rules
        if layer_uid is not None:
            rules = [r for r in rules if r.layer_uid == layer_uid]
        if layer_name is not None:
            rules = [r for r in rules if r.layer_name == layer_name]
        return rules

    @traced
    async def get_nat_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        package_uid: str | None = None,
        package_name: str | None = None,
    ) -> list[NatRuleEntry]:
        """Return cached NAT rules for `(mgmt_name, domain)`."""
        await self._ensure_initialized()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.nat_rules
        if package_uid is not None:
            rules = [r for r in rules if r.package_uid == package_uid]
        if package_name is not None:
            rules = [r for r in rules if r.package_name == package_name]
        return rules

    @traced
    async def get_https_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        layer_uid: str | None = None,
        layer_name: str | None = None,
    ) -> list[HttpsRuleEntry]:
        """Return cached HTTPS inspection rules for `(mgmt_name, domain)`."""
        await self._ensure_initialized()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.https_rules
        if layer_uid is not None:
            rules = [r for r in rules if r.layer_uid == layer_uid]
        if layer_name is not None:
            rules = [r for r in rules if r.layer_name == layer_name]
        return rules

    @traced
    async def get_threat_rules(
        self,
        mgmt_name: str,
        domain: str,
        *,
        layer_uid: str | None = None,
        layer_name: str | None = None,
    ) -> list[ThreatRuleEntry]:
        """Return cached Threat Prevention rules for `(mgmt_name, domain)`."""
        await self._ensure_initialized()
        snapshot = await self._cache.get_domain_rulebase(mgmt_name, domain)
        rules = snapshot.threat_rules
        if layer_uid is not None:
            rules = [r for r in rules if r.layer_uid == layer_uid]
        if layer_name is not None:
            rules = [r for r in rules if r.layer_name == layer_name]
        return rules

    @traced
    async def get_policy_packages(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> list[PolicyPackageInfo]:
        """Return cached `PolicyPackageInfo` entries for `(mgmt_name, domain_name)`."""
        await self._ensure_initialized()
        return await self._rulebase_source.get_policy_packages(
            mgmt_name,
            domain_name,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_package_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        package: str,
        *,
        rulebase_type: RulebaseType = "access",
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> PackageRulebase:
        """Return a SmartConsole-numbered `PackageRulebase` for `package` in `(mgmt_name, domain_name)`."""
        await self._ensure_initialized()
        return await self._rulebase_source.get_package_rulebase(
            mgmt_name,
            domain_name,
            package,
            rulebase_type=rulebase_type,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def get_layer_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None,
        layer: str,
        *,
        rulebase_type: RulebaseType | None = None,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> NumberedLayerRulebase:
        """Return a SmartConsole-numbered `NumberedLayerRulebase` for `layer` in `(mgmt_name, domain_name)`."""
        await self._ensure_initialized()
        return await self._rulebase_source.get_layer_rulebase(
            mgmt_name,
            domain_name,
            layer,
            rulebase_type=rulebase_type,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def locate_rules(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        rule_uids: Sequence[str] | None = None,
        layer_uids: Sequence[str] | None = None,
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> RuleLocations:
        """Locate SmartConsole rule numbers and layer prefixes across all packages and layers of a domain."""
        await self._ensure_initialized()
        return await self._rulebase_source.locate_rules(
            mgmt_name,
            domain_name,
            rule_uids=rule_uids,
            layer_uids=layer_uids,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    @traced
    async def filter_rulebase(
        self,
        mgmt_name: str,
        domain_name: str | None = None,
        *,
        package: str | None = None,
        layer: str | None = None,
        rulebase_type: RulebaseType = "access",
        filter_query: str = "",
        output_format: RuleFormat = "model_friendly",
        cache_mode: CacheMode = "cache",
        cache_ttl: float | None = None,
    ) -> FilteredRulebaseResult:
        """Evaluate `filter_query` locally against cached rulebase and cached objects/services."""
        await self._ensure_initialized()
        return await self._rulebase_source.filter_rulebase(
            mgmt_name,
            domain_name,
            package=package,
            layer=layer,
            rulebase_type=rulebase_type,
            filter_query=filter_query,
            output_format=output_format,
            cache_mode=cache_mode,
            cache_ttl=cache_ttl,
        )

    # ------------------------------------------------------------------
    # Change Reports
    # ------------------------------------------------------------------

    async def _warm_rulebase_for_report(self, mgmt_name: str, domain_name: str) -> Any:
        clean_dom = (domain_name or "").strip()
        if not clean_dom or clean_dom == "System Data":
            return None
        return await self.refresh_rulebases(
            mgmt_name=mgmt_name,
            domains=[clean_dom],
            mode="smart",
        )

    @traced
    async def collect_change_report(
        self,
        scopes: Sequence[ReportScope | dict[str, Any]],
        *,
        options: RenderOptions | None = None,
        max_uid_lookups: int = MAX_UID_LOOKUPS,
    ) -> ChangeReport:
        """Collect read-only auditable session change evidence (`ChangeReport`) across `scopes`."""
        await self._ensure_initialized()
        return await _collect_change_report(
            self._api,
            self._cache,
            scopes,
            options=options,
            max_uid_lookups=max_uid_lookups,
            now_fn=self._now,
            refresh_rulebase_fn=self._warm_rulebase_for_report,
        )

    @traced
    def build_change_report_from_plan(
        self,
        plan: Plan,
        *,
        title: str | None = None,
        header_fields: Mapping[str, str] | None = None,
        include_unchanged: bool = False,
    ) -> ChangeReport:
        """Synthesize an offline `ChangeReport` directly from a CPCRUD `Plan` for dry-run previews."""
        return _build_change_report_from_plan(
            plan,
            title=title,
            header_fields=header_fields,
            include_unchanged=include_unchanged,
        )

    @traced
    def render_change_report(
        self,
        report: ChangeReport,
        *,
        formats: Sequence[str] = ("html", "markdown", "json"),
        options: RenderOptions | None = None,
    ) -> RenderedReportBundle:
        """Render a `ChangeReport` offline into any requested subset of `'html'`, `'json'`, and `'markdown'`."""
        return _render_change_report(
            report,
            formats=formats,
            options=options,
        )

    @traced
    async def build_change_report(
        self,
        scopes: Sequence[ReportScope | dict[str, Any]],
        *,
        formats: Sequence[str] = ("html", "markdown", "json"),
        options: RenderOptions | None = None,
        max_uid_lookups: int = MAX_UID_LOOKUPS,
    ) -> RenderedReportBundle:
        """Collect and render a `ChangeReport` across `scopes` into `formats`."""
        await self._ensure_initialized()
        return await _build_change_report(
            self._api,
            self._cache,
            scopes,
            formats=formats,
            options=options,
            max_uid_lookups=max_uid_lookups,
            now_fn=self._now,
            refresh_rulebase_fn=self._warm_rulebase_for_report,
        )

    # ------------------------------------------------------------------
    # Offline API Reference & Payload Validation (`ApiReferenceEngine`)
    # ------------------------------------------------------------------

    async def ensure_api_reference(self) -> ApiReferenceEngine:
        """Return `self.api_reference`, loading the bundled gzipped index via `asyncio.to_thread` when needed (`R9`)."""
        if self._api_reference is None:
            self._api_reference = await ApiReferenceEngine.async_default()
        return self._api_reference

    def resolve_api_version(
        self,
        version: str | None = None,
        mgmt_name: str | None = None,
    ) -> str:
        """Resolve canonical Check Point API version (`v1.9`..`v2.2`) from explicit `version` or `mgmt_name` settings."""
        latest = (
            str(self._api_reference.meta.get("latest", DEFAULT_API_VERSION))
            if self._api_reference is not None
            else DEFAULT_API_VERSION
        )
        if version and str(version).strip():
            return normalize_api_version(version, default=latest)
        servers = self._settings.servers
        if mgmt_name and mgmt_name.strip() in servers:
            srv_ver = servers[mgmt_name.strip()].api_version
            if srv_ver:
                return normalize_api_version(srv_ver, default=latest)
        elif not mgmt_name and len(servers) == 1:
            sole_srv = next(iter(servers.values()))
            if sole_srv.api_version:
                return normalize_api_version(sole_srv.api_version, default=latest)
        if self._settings.api_version:
            return normalize_api_version(self._settings.api_version, default=latest)
        return latest

    def _resolve_api_version(
        self,
        version: str | None = None,
        mgmt_name: str | None = None,
    ) -> str:
        return self.resolve_api_version(version, mgmt_name=mgmt_name)

    def search_api_commands(
        self,
        query: str = "",
        *,
        category: str | None = None,
        crud_type: str | None = None,
        api_family: str | None = None,
        version: str | None = None,
        mgmt_name: str | None = None,
        limit: int = 15,
    ) -> list[dict[str, Any]]:
        """Step 1: Search Check Point API commands offline, inferring `version` from `mgmt_name` when omitted."""
        eff_version = self.resolve_api_version(version, mgmt_name=mgmt_name)
        return self.api_reference.search_commands(
            query,
            category=category,
            crud_type=crud_type,
            api_family=api_family,
            version=eff_version,
            limit=limit,
        )

    def describe_api_command(
        self,
        command: str | Sequence[str],
        *,
        version: str | None = None,
        mgmt_name: str | None = None,
        resolve_nested: bool = True,
        include_examples: bool = True,
    ) -> dict[str, Any] | None:
        """Step 2: Describe one or more Check Point API commands offline, inferring `version` from `mgmt_name`."""
        eff_version = self.resolve_api_version(version, mgmt_name=mgmt_name)
        return self.api_reference.describe_command(
            command,
            version=eff_version,
            resolve_nested=resolve_nested,
            include_examples=include_examples,
        )

    def validate_api_payload(
        self,
        command: str,
        payload: dict[str, Any] | None,
        *,
        version: str | None = None,
        mgmt_name: str | None = None,
    ) -> dict[str, Any]:
        """Step 3: Validate a candidate request payload offline against the command's schema for `version` / `mgmt_name`."""
        eff_version = self.resolve_api_version(version, mgmt_name=mgmt_name)
        return self.api_reference.validate_payload(
            command,
            payload,
            version=eff_version,
        )

    # ------------------------------------------------------------------
    # Universal Script Repository Management & Execution
    # ------------------------------------------------------------------

    @traced
    async def get_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        *,
        domain: str | None = None,
        details_level: str = "full",
    ) -> RepositoryScript:
        """Fetch a single Check Point Script Repository entry by name or UID (`show-repository-script`)."""
        await self._ensure_initialized()
        return await self._script_service.get_repository_script(
            mgmt_name,
            script_name_or_uid,
            domain=domain,
            details_level=details_level,
        )

    @traced
    async def list_repository_scripts(
        self,
        mgmt_name: str,
        *,
        domain: str | None = None,
        details_level: str = "full",
        limit: int = 300,
    ) -> list[RepositoryScript]:
        """List Check Point Script Repository entries in `domain` (`show-repository-scripts`)."""
        await self._ensure_initialized()
        return await self._script_service.list_repository_scripts(
            mgmt_name,
            domain=domain,
            details_level=details_level,
            limit=limit,
        )

    @traced
    async def check_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        *,
        domain: str | None = None,
        expected_body: str | None = None,
    ) -> RepositoryScriptStatus:
        """Inspect a repository script strictly read-only over `sid_cache` and compare against `expected_body`."""
        await self._ensure_initialized()
        return await self._script_service.check_repository_script(
            mgmt_name,
            script_name_or_uid,
            domain=domain,
            expected_body=expected_body,
        )

    @traced
    async def ensure_repository_script(
        self,
        mgmt_name: str,
        script_name: str,
        script_body: str,
        *,
        domain: str | None = None,
        comments: str | None = None,
        color: str | None = None,
        tags: Sequence[str] | None = None,
    ) -> EnsureRepositoryScriptResult:
        """Idempotently ensure `script_name` exists with `script_body`, avoiding writes when already matching."""
        await self._ensure_initialized()
        return await self._script_service.ensure_repository_script(
            mgmt_name,
            script_name,
            script_body,
            domain=domain,
            comments=comments,
            color=color,
            tags=tags,
        )

    @traced
    async def delete_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        *,
        domain: str | None = None,
    ) -> bool:
        """Delete a Check Point Script Repository entry from `domain` (`delete-repository-script`)."""
        await self._ensure_initialized()
        return await self._script_service.delete_repository_script(
            mgmt_name,
            script_name_or_uid,
            domain=domain,
        )

    @traced
    async def run_repository_script(
        self,
        mgmt_name: str,
        script_name_or_uid: str,
        targets: Sequence[str] | str,
        *,
        domain: str | None = None,
        args: Sequence[str] | str | None = None,
        comments: str | None = None,
        timeout: float | None = None,
        script_timeout: int | None = None,
    ) -> RepositoryScriptExecutionOutcome:
        """Execute any approved Check Point Script Repository entry via `run-script` (`script-type="repository"`)."""
        await self._ensure_initialized()
        return await self._script_service.run_repository_script(
            mgmt_name,
            script_name_or_uid,
            targets,
            domain=domain,
            args=args,
            comments=comments,
            timeout=timeout,
            script_timeout=script_timeout,
        )
