"""Rulebase record <-> domain model and row-dict converters for `SqlCacheAdapter`."""

from __future__ import annotations

from typing import Any

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
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    HttpsRuleEntry,
    NatRuleEntry,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
    ThreatRuleEntry,
)


def _package_layer_to_row(pkg_layer: RulebasePackageLayerEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": pkg_layer.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "package_uid": pkg_layer.package_uid,
        "package_name": pkg_layer.package_name,
        "rulebase_type": pkg_layer.rulebase_type,
        "layer_uid": pkg_layer.layer_uid,
        "layer_name": pkg_layer.layer_name,
        "position": pkg_layer.position,
        "raw_data": dict(pkg_layer.raw_data),
        "updated_at": _ensure_utc(pkg_layer.updated_at) or utc_now(),
    }


def _record_to_package_layer(rec: RulebasePackageLayerRecord) -> RulebasePackageLayerEntry:
    return RulebasePackageLayerEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        package_uid=rec.package_uid,
        package_name=rec.package_name,
        rulebase_type=rec.rulebase_type,  # type: ignore[arg-type]
        layer_uid=rec.layer_uid,
        layer_name=rec.layer_name,
        position=rec.position,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _rulebase_layer_to_row(layer: RulebaseLayerEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": layer.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "uid": layer.uid,
        "name": layer.name,
        "rulebase_type": layer.rulebase_type,
        "parent_layer_uid": layer.parent_layer_uid,
        "parent_rule_uid": layer.parent_rule_uid,
        "is_global": layer.is_global,
        "shared": layer.shared,
        "implicit_cleanup_action": layer.implicit_cleanup_action,
        "raw_data": dict(layer.raw_data),
        "updated_at": _ensure_utc(layer.updated_at) or utc_now(),
    }


def _record_to_rulebase_layer(rec: RulebaseLayerRecord) -> RulebaseLayerEntry:
    return RulebaseLayerEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        uid=rec.uid,
        name=rec.name,
        rulebase_type=rec.rulebase_type,  # type: ignore[arg-type]
        parent_layer_uid=rec.parent_layer_uid,
        parent_rule_uid=rec.parent_rule_uid,
        is_global=rec.is_global,
        shared=rec.shared,
        implicit_cleanup_action=rec.implicit_cleanup_action,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _rulebase_section_to_row(sec: RulebaseSectionEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": sec.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": sec.layer_uid,
        "layer_name": sec.layer_name,
        "rulebase_type": sec.rulebase_type,
        "uid": sec.uid,
        "name": sec.name,
        "position": sec.position,
        "from_rule": sec.from_rule,
        "to_rule": sec.to_rule,
        "rule_uids": list(sec.rule_uids),
        "raw_data": dict(sec.raw_data),
        "updated_at": _ensure_utc(sec.updated_at) or utc_now(),
    }


def _record_to_rulebase_section(rec: RulebaseSectionRecord) -> RulebaseSectionEntry:
    return RulebaseSectionEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        layer_uid=rec.layer_uid,
        layer_name=rec.layer_name,
        rulebase_type=rec.rulebase_type,  # type: ignore[arg-type]
        uid=rec.uid,
        name=rec.name,
        position=rec.position,
        from_rule=rec.from_rule,
        to_rule=rec.to_rule,
        rule_uids=list(rec.rule_uids or []),
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _access_rule_to_row(rule: AccessRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": rule.layer_uid,
        "layer_name": rule.layer_name,
        "section_uid": rule.section_uid,
        "section_name": rule.section_name,
        "uid": rule.uid,
        "name": rule.name,
        "rule_type": rule.rule_type,
        "position": rule.position,
        "rule_number": rule.rule_number,
        "enabled": rule.enabled,
        "action": rule.action,
        "inline_layer_uid": rule.inline_layer_uid,
        "inline_layer_name": rule.inline_layer_name,
        "placeholder_domain_layer_uid": rule.placeholder_domain_layer_uid,
        "source": list(rule.source),
        "destination": list(rule.destination),
        "service": list(rule.service),
        "source_negate": rule.source_negate,
        "destination_negate": rule.destination_negate,
        "service_negate": rule.service_negate,
        "track": rule.track,
        "install_on": list(rule.install_on),
        "comments": rule.comments,
        "raw_data": dict(rule.raw_data),
        "updated_at": _ensure_utc(rule.updated_at) or utc_now(),
    }


def _record_to_access_rule(rec: AccessRuleRecord) -> AccessRuleEntry:
    return AccessRuleEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        layer_uid=rec.layer_uid,
        layer_name=rec.layer_name,
        section_uid=rec.section_uid,
        section_name=rec.section_name,
        uid=rec.uid,
        name=rec.name,
        rule_type=rec.rule_type,
        position=rec.position,
        rule_number=rec.rule_number,
        enabled=rec.enabled,
        action=rec.action,
        inline_layer_uid=rec.inline_layer_uid,
        inline_layer_name=rec.inline_layer_name,
        placeholder_domain_layer_uid=rec.placeholder_domain_layer_uid,
        source=list(rec.source or []),
        destination=list(rec.destination or []),
        service=list(rec.service or []),
        source_negate=rec.source_negate,
        destination_negate=rec.destination_negate,
        service_negate=rec.service_negate,
        track=rec.track,
        install_on=list(rec.install_on or []),
        comments=rec.comments,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _nat_rule_to_row(nat_rule: NatRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": nat_rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "package_uid": nat_rule.package_uid,
        "package_name": nat_rule.package_name,
        "section_uid": nat_rule.section_uid,
        "section_name": nat_rule.section_name,
        "uid": nat_rule.uid,
        "name": nat_rule.name,
        "rule_type": nat_rule.rule_type,
        "position": nat_rule.position,
        "rule_number": nat_rule.rule_number,
        "enabled": nat_rule.enabled,
        "method": nat_rule.method,
        "auto_generated": nat_rule.auto_generated,
        "original_source": nat_rule.original_source,
        "original_destination": nat_rule.original_destination,
        "original_service": nat_rule.original_service,
        "translated_source": nat_rule.translated_source,
        "translated_destination": nat_rule.translated_destination,
        "translated_service": nat_rule.translated_service,
        "install_on": list(nat_rule.install_on),
        "comments": nat_rule.comments,
        "raw_data": dict(nat_rule.raw_data),
        "updated_at": _ensure_utc(nat_rule.updated_at) or utc_now(),
    }


def _record_to_nat_rule(rec: NatRuleRecord) -> NatRuleEntry:
    return NatRuleEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        package_uid=rec.package_uid,
        package_name=rec.package_name,
        section_uid=rec.section_uid,
        section_name=rec.section_name,
        uid=rec.uid,
        name=rec.name,
        rule_type=rec.rule_type,
        position=rec.position,
        rule_number=rec.rule_number,
        enabled=rec.enabled,
        method=rec.method,
        auto_generated=rec.auto_generated,
        original_source=rec.original_source,
        original_destination=rec.original_destination,
        original_service=rec.original_service,
        translated_source=rec.translated_source,
        translated_destination=rec.translated_destination,
        translated_service=rec.translated_service,
        install_on=list(rec.install_on or []),
        comments=rec.comments,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _https_rule_to_row(https_rule: HttpsRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": https_rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": https_rule.layer_uid,
        "layer_name": https_rule.layer_name,
        "section_uid": https_rule.section_uid,
        "section_name": https_rule.section_name,
        "uid": https_rule.uid,
        "name": https_rule.name,
        "rule_type": https_rule.rule_type,
        "position": https_rule.position,
        "rule_number": https_rule.rule_number,
        "enabled": https_rule.enabled,
        "action": https_rule.action,
        "inline_layer_uid": https_rule.inline_layer_uid,
        "source": list(https_rule.source),
        "destination": list(https_rule.destination),
        "service": list(https_rule.service),
        "site_category": list(https_rule.site_category),
        "certificate": https_rule.certificate,
        "track": https_rule.track,
        "install_on": list(https_rule.install_on),
        "comments": https_rule.comments,
        "raw_data": dict(https_rule.raw_data),
        "updated_at": _ensure_utc(https_rule.updated_at) or utc_now(),
    }


def _record_to_https_rule(rec: HttpsRuleRecord) -> HttpsRuleEntry:
    return HttpsRuleEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        layer_uid=rec.layer_uid,
        layer_name=rec.layer_name,
        section_uid=rec.section_uid,
        section_name=rec.section_name,
        uid=rec.uid,
        name=rec.name,
        rule_type=rec.rule_type,
        position=rec.position,
        rule_number=rec.rule_number,
        enabled=rec.enabled,
        action=rec.action,
        inline_layer_uid=rec.inline_layer_uid,
        source=list(rec.source or []),
        destination=list(rec.destination or []),
        service=list(rec.service or []),
        site_category=list(rec.site_category or []),
        certificate=rec.certificate,
        track=rec.track,
        install_on=list(rec.install_on or []),
        comments=rec.comments,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )


def _threat_rule_to_row(threat_rule: ThreatRuleEntry, mgmt: str, dom: str) -> dict[str, Any]:
    return {
        "id": threat_rule.id,
        "mgmt_name": mgmt,
        "domain_name": dom,
        "layer_uid": threat_rule.layer_uid,
        "layer_name": threat_rule.layer_name,
        "section_uid": threat_rule.section_uid,
        "section_name": threat_rule.section_name,
        "uid": threat_rule.uid,
        "name": threat_rule.name,
        "rule_type": threat_rule.rule_type,
        "position": threat_rule.position,
        "rule_number": threat_rule.rule_number,
        "enabled": threat_rule.enabled,
        "action": threat_rule.action,
        "protected_scope": list(threat_rule.protected_scope),
        "source": list(threat_rule.source),
        "destination": list(threat_rule.destination),
        "service": list(threat_rule.service),
        "track": threat_rule.track,
        "install_on": list(threat_rule.install_on),
        "comments": threat_rule.comments,
        "raw_data": dict(threat_rule.raw_data),
        "updated_at": _ensure_utc(threat_rule.updated_at) or utc_now(),
    }


def _record_to_threat_rule(rec: ThreatRuleRecord) -> ThreatRuleEntry:
    return ThreatRuleEntry(
        id=rec.id,
        mgmt_name=rec.mgmt_name,
        domain_name=rec.domain_name,
        layer_uid=rec.layer_uid,
        layer_name=rec.layer_name,
        section_uid=rec.section_uid,
        section_name=rec.section_name,
        uid=rec.uid,
        name=rec.name,
        rule_type=rec.rule_type,
        position=rec.position,
        rule_number=rec.rule_number,
        enabled=rec.enabled,
        action=rec.action,
        protected_scope=list(rec.protected_scope or []),
        source=list(rec.source or []),
        destination=list(rec.destination or []),
        service=list(rec.service or []),
        track=rec.track,
        install_on=list(rec.install_on or []),
        comments=rec.comments,
        raw_data=dict(rec.raw_data or {}),
        updated_at=_ensure_utc(rec.updated_at) or utc_now(),
    )
