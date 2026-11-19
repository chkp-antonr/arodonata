"""Rulebase snapshot, package catalog, and layer replacement/hydration for `SqlCacheAdapter`."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from arodonata.adapters.storage.cache._base import _BATCH_ROWS, SqlCacheBase
from arodonata.adapters.storage.cache.rulebase_mappers import (
    _access_rule_to_row,
    _https_rule_to_row,
    _nat_rule_to_row,
    _package_layer_to_row,
    _record_to_access_rule,
    _record_to_https_rule,
    _record_to_nat_rule,
    _record_to_package_layer,
    _record_to_rulebase_layer,
    _record_to_rulebase_section,
    _record_to_threat_rule,
    _rulebase_layer_to_row,
    _rulebase_section_to_row,
    _threat_rule_to_row,
)
from arodonata.adapters.storage.tables import (
    AccessRuleRecord,
    HttpsRuleRecord,
    NatRuleRecord,
    RulebaseLayerRecord,
    RulebasePackageLayerRecord,
    RulebaseSectionRecord,
    ThreatRuleRecord,
    _ensure_utc,
)
from arodonata.core.models.common import utc_now
from arodonata.core.models.domains import DomainSyncState
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    ThreatRuleEntry,
)
from arodonata.core.telemetry import span_attrs, traced


class RulebaseCacheMixin(SqlCacheBase):
    """Implements `RulebaseCachePort` over SQL storage."""

    async def _insert_rulebase_collections(
        self,
        session: AsyncSession,
        mgmt: str,
        dom: str,
        *,
        package_layers: Sequence[RulebasePackageLayerEntry] = (),
        layers: Sequence[RulebaseLayerEntry] = (),
        sections: Sequence[RulebaseSectionEntry] = (),
        access_rules: Sequence[AccessRuleEntry] = (),
        nat_rules: Sequence[NatRuleEntry] = (),
        https_rules: Sequence[HttpsRuleEntry] = (),
        threat_rules: Sequence[ThreatRuleEntry] = (),
    ) -> tuple[int, int, int, int]:
        """Deduplicate and batch-insert rulebase collections, returning rule counts `(access, nat, https, threat)`."""
        if package_layers:
            dedup_pkg = list({pl.id: pl for pl in package_layers}.values())
            await self._insert_rows_batched(
                session,
                RulebasePackageLayerRecord,
                dedup_pkg,
                lambda pl: _package_layer_to_row(pl, mgmt, dom),
            )
        dedup_layers = list({layer.id: layer for layer in layers}.values())
        await self._insert_rows_batched(
            session,
            RulebaseLayerRecord,
            dedup_layers,
            lambda layer: _rulebase_layer_to_row(layer, mgmt, dom),
        )
        dedup_secs = list({sec.id: sec for sec in sections}.values())
        await self._insert_rows_batched(
            session,
            RulebaseSectionRecord,
            dedup_secs,
            lambda sec: _rulebase_section_to_row(sec, mgmt, dom),
        )
        dedup_access = list({r.id: r for r in access_rules}.values())
        await self._insert_rows_batched(
            session,
            AccessRuleRecord,
            dedup_access,
            lambda rule: _access_rule_to_row(rule, mgmt, dom),
        )
        dedup_nat = list({r.id: r for r in nat_rules}.values())
        await self._insert_rows_batched(
            session,
            NatRuleRecord,
            dedup_nat,
            lambda nat_rule: _nat_rule_to_row(nat_rule, mgmt, dom),
        )
        dedup_https = list({r.id: r for r in https_rules}.values())
        await self._insert_rows_batched(
            session,
            HttpsRuleRecord,
            dedup_https,
            lambda https_rule: _https_rule_to_row(https_rule, mgmt, dom),
        )
        dedup_threat = list({r.id: r for r in threat_rules}.values())
        await self._insert_rows_batched(
            session,
            ThreatRuleRecord,
            dedup_threat,
            lambda threat_rule: _threat_rule_to_row(threat_rule, mgmt, dom),
        )
        return len(dedup_access), len(dedup_nat), len(dedup_https), len(dedup_threat)

    @traced
    async def replace_domain_rulebase(
        self,
        snapshot: DomainRulebaseSnapshot,
        *,
        sync_state: DomainSyncState | None = None,
    ) -> None:
        """Atomically replace all `arodonata_rulebase_*` snapshot tables for `(snapshot.mgmt_name, snapshot.domain_name)`."""
        mgmt = snapshot.mgmt_name
        dom = snapshot.domain_name
        span_attrs(
            mgmt_name=mgmt,
            domain=dom,
            layers=len(snapshot.layers),
            access_rules=len(snapshot.access_rules),
            nat_rules=len(snapshot.nat_rules),
        )

        async with self._db.session() as session:
            for model_cls in (
                RulebasePackageLayerRecord,
                RulebaseLayerRecord,
                RulebaseSectionRecord,
                AccessRuleRecord,
                NatRuleRecord,
                HttpsRuleRecord,
                ThreatRuleRecord,
            ):
                await session.execute(
                    delete(model_cls).where(
                        model_cls.mgmt_name == mgmt,  # type: ignore[arg-type]
                        model_cls.domain_name == dom,  # type: ignore[arg-type]
                    )
                )

            await self._insert_rulebase_collections(
                session,
                mgmt,
                dom,
                package_layers=snapshot.package_layers,
                layers=snapshot.layers,
                sections=snapshot.sections,
                access_rules=snapshot.access_rules,
                nat_rules=snapshot.nat_rules,
                https_rules=snapshot.https_rules,
                threat_rules=snapshot.threat_rules,
            )

            if sync_state is not None:
                await self._upsert_sync_states_in_session(session, [sync_state])
            await session.commit()

    @traced
    async def replace_domain_package_catalog(
        self,
        mgmt_name: str,
        domain_name: str,
        package_layers: Sequence[RulebasePackageLayerEntry],
        *,
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace `arodonata_rulebase_package_layer` rows for `(mgmt_name, domain_name)` without touching layer, section, or rule tables."""
        dedup_pkg = list({pkg_layer.id: pkg_layer for pkg_layer in package_layers}.values())
        span_attrs(mgmt_name=mgmt_name, domain=domain_name, package_layers=len(dedup_pkg))
        async with self._db.session() as session:
            await session.execute(
                delete(RulebasePackageLayerRecord).where(
                    RulebasePackageLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                    RulebasePackageLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                )
            )
            await self._insert_rows_batched(
                session,
                RulebasePackageLayerRecord,
                dedup_pkg,
                lambda pkg_layer: _package_layer_to_row(pkg_layer, mgmt_name, domain_name),
            )
            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()
        return len(dedup_pkg)

    @traced
    async def upsert_domain_rulebase_layers(
        self,
        mgmt_name: str,
        domain_name: str,
        *,
        layers: Sequence[RulebaseLayerEntry] = (),
        sections: Sequence[RulebaseSectionEntry] = (),
        access_rules: Sequence[AccessRuleEntry] = (),
        nat_rules: Sequence[NatRuleEntry] = (),
        https_rules: Sequence[HttpsRuleEntry] = (),
        threat_rules: Sequence[ThreatRuleEntry] = (),
        package_layers: Sequence[RulebasePackageLayerEntry] = (),
        replaced_layer_uids: Sequence[str] = (),
        replaced_nat_package_uids: Sequence[str] = (),
        sync_states: Sequence[DomainSyncState] | None = None,
    ) -> int:
        """Atomically replace rulebase layers, sections, and rules strictly for `replaced_layer_uids` (and NAT packages) in `(mgmt_name, domain_name)`."""
        nat_from_layers = {
            u.removeprefix("nat:") for u in replaced_layer_uids if u.startswith("nat:") and u.removeprefix("nat:")
        }
        target_nat_pkg_uids = sorted(
            {u for u in replaced_nat_package_uids if u}
            | nat_from_layers
            | {nr.package_uid for nr in nat_rules if nr.package_uid}
        )
        nat_section_layer_uids = {f"nat:{u}" for u in target_nat_pkg_uids}
        target_layer_uids = sorted(
            {u for u in replaced_layer_uids if u}
            | {layer.uid for layer in layers if layer.uid}
            | {sec.layer_uid for sec in sections if sec.layer_uid}
            | nat_section_layer_uids
        )

        span_attrs(
            mgmt_name=mgmt_name,
            domain=domain_name,
            replaced_layers=len(target_layer_uids),
            replaced_nat_packages=len(target_nat_pkg_uids),
            access_rules=len(access_rules),
            nat_rules=len(nat_rules),
        )

        async with self._db.session() as session:
            if package_layers:
                pkg_rows = [_package_layer_to_row(pl, mgmt_name, domain_name) for pl in package_layers]
                await self._dialect_upsert(session, RulebasePackageLayerRecord, pkg_rows)

            for start in range(0, len(target_layer_uids), _BATCH_ROWS):
                chunk = target_layer_uids[start : start + _BATCH_ROWS]
                await session.execute(
                    delete(RulebaseLayerRecord).where(
                        RulebaseLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                        RulebaseLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        col(RulebaseLayerRecord.uid).in_(chunk),
                    )
                )
                for layer_scoped_cls in (
                    RulebaseSectionRecord,
                    AccessRuleRecord,
                    HttpsRuleRecord,
                    ThreatRuleRecord,
                ):
                    await session.execute(
                        delete(layer_scoped_cls).where(
                            layer_scoped_cls.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            layer_scoped_cls.domain_name == domain_name,  # type: ignore[arg-type]
                            col(layer_scoped_cls.layer_uid).in_(chunk),
                        )
                    )

            for start in range(0, len(target_nat_pkg_uids), _BATCH_ROWS):
                nat_chunk = target_nat_pkg_uids[start : start + _BATCH_ROWS]
                await session.execute(
                    delete(NatRuleRecord).where(
                        NatRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                        NatRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        col(NatRuleRecord.package_uid).in_(nat_chunk),
                    )
                )

            c_access, c_nat, c_https, c_threat = await self._insert_rulebase_collections(
                session,
                mgmt_name,
                domain_name,
                layers=layers,
                sections=sections,
                access_rules=access_rules,
                nat_rules=nat_rules,
                https_rules=https_rules,
                threat_rules=threat_rules,
            )

            if sync_states:
                await self._upsert_sync_states_in_session(session, sync_states)
            await session.commit()

        return c_access + c_nat + c_https + c_threat

    @traced
    async def get_domain_rulebase_packages(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainRulebaseSnapshot:
        """Load only `package_layers` and distinct NAT package stubs for `(mgmt_name, domain_name)` without loading rule tables."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        async with self._db.session() as session:
            pkg_rows = (
                (
                    await session.execute(
                        select(RulebasePackageLayerRecord)
                        .where(
                            RulebasePackageLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            RulebasePackageLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(
                            col(RulebasePackageLayerRecord.package_name),
                            col(RulebasePackageLayerRecord.position),
                        )
                    )
                )
                .scalars()
                .all()
            )
            nat_pkg_rows = (
                await session.execute(
                    select(
                        col(NatRuleRecord.package_uid),
                        col(NatRuleRecord.package_name),
                        func.max(col(NatRuleRecord.updated_at)),
                    )
                    .where(
                        col(NatRuleRecord.mgmt_name) == mgmt_name,
                        col(NatRuleRecord.domain_name) == domain_name,
                    )
                    .group_by(col(NatRuleRecord.package_uid), col(NatRuleRecord.package_name))
                )
            ).all()

        package_layers = [_record_to_package_layer(r) for r in pkg_rows]
        nat_pkg_uids_in_layers = {pl.package_uid for pl in package_layers if pl.rulebase_type == "nat"}
        nat_stubs = [
            NatRuleEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                package_uid=str(p_uid),
                package_name=str(p_name),
                uid=f"pkg-stub:{p_uid}",
                position=1,
                updated_at=_ensure_utc(max_ts) or utc_now(),
            )
            for p_uid, p_name, max_ts in nat_pkg_rows
            if p_uid and str(p_uid) not in nat_pkg_uids_in_layers
        ]
        return DomainRulebaseSnapshot(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            package_layers=package_layers,
            nat_rules=nat_stubs,
        )

    @traced
    async def get_domain_rulebase(
        self,
        mgmt_name: str,
        domain_name: str,
    ) -> DomainRulebaseSnapshot:
        """Load the cached `DomainRulebaseSnapshot` for `(mgmt_name, domain_name)`."""
        span_attrs(mgmt_name=mgmt_name, domain=domain_name)
        async with self._db.session() as session:
            pkg_rows = (
                (
                    await session.execute(
                        select(RulebasePackageLayerRecord)
                        .where(
                            RulebasePackageLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            RulebasePackageLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(
                            col(RulebasePackageLayerRecord.package_name),
                            col(RulebasePackageLayerRecord.position),
                        )
                    )
                )
                .scalars()
                .all()
            )
            layer_rows = (
                (
                    await session.execute(
                        select(RulebaseLayerRecord)
                        .where(
                            RulebaseLayerRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            RulebaseLayerRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(RulebaseLayerRecord.name))
                    )
                )
                .scalars()
                .all()
            )
            sec_rows = (
                (
                    await session.execute(
                        select(RulebaseSectionRecord)
                        .where(
                            RulebaseSectionRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            RulebaseSectionRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(
                            col(RulebaseSectionRecord.layer_uid),
                            col(RulebaseSectionRecord.position),
                        )
                    )
                )
                .scalars()
                .all()
            )
            access_rows = (
                (
                    await session.execute(
                        select(AccessRuleRecord)
                        .where(
                            AccessRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            AccessRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(AccessRuleRecord.layer_uid), col(AccessRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )
            nat_rows = (
                (
                    await session.execute(
                        select(NatRuleRecord)
                        .where(
                            NatRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            NatRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(NatRuleRecord.package_uid), col(NatRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )
            https_rows = (
                (
                    await session.execute(
                        select(HttpsRuleRecord)
                        .where(
                            HttpsRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            HttpsRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(HttpsRuleRecord.layer_uid), col(HttpsRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )
            threat_rows = (
                (
                    await session.execute(
                        select(ThreatRuleRecord)
                        .where(
                            ThreatRuleRecord.mgmt_name == mgmt_name,  # type: ignore[arg-type]
                            ThreatRuleRecord.domain_name == domain_name,  # type: ignore[arg-type]
                        )
                        .order_by(col(ThreatRuleRecord.layer_uid), col(ThreatRuleRecord.position))
                    )
                )
                .scalars()
                .all()
            )

        return DomainRulebaseSnapshot(
            mgmt_name=mgmt_name,
            domain_name=domain_name,
            package_layers=[_record_to_package_layer(r) for r in pkg_rows],
            layers=[_record_to_rulebase_layer(r) for r in layer_rows],
            sections=[_record_to_rulebase_section(r) for r in sec_rows],
            access_rules=[_record_to_access_rule(r) for r in access_rows],
            nat_rules=[_record_to_nat_rule(r) for r in nat_rows],
            https_rules=[_record_to_https_rule(r) for r in https_rows],
            threat_rules=[_record_to_threat_rule(r) for r in threat_rows],
        )
