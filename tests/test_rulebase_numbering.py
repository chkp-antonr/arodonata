"""Unit tests for `arodonata.rulebase.numbering`, `CachedRulebaseSource`, and `arodonata.rulebase.filter`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter
from arodonata.core.errors import AmbiguousLayerName
from arodonata.core.models.domains import DomainInfo, DomainSyncState
from arodonata.core.models.objects import CPObject
from arodonata.core.models.rulebase import (
    AccessRuleEntry,
    DomainRulebaseSnapshot,
    RulebaseLayerEntry,
    RulebasePackageLayerEntry,
    RulebaseSectionEntry,
)
from arodonata.core.models.services import CPService
from arodonata.rulebase import CachedRulebaseSource


def _build_hierarchical_snapshot(mgmt_name: str = "mds1", domain_name: str = "Corp") -> DomainRulebaseSnapshot:
    """Build a domain rulebase snapshot with a Global layer containing a `place-holder`, a domain layer, and an inline layer."""
    return DomainRulebaseSnapshot(
        mgmt_name=mgmt_name,
        domain_name=domain_name,
        package_layers=[
            RulebasePackageLayerEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                package_uid="pkg-1",
                package_name="Corp_Policy",
                rulebase_type="access",
                layer_uid="layer-global",
                layer_name="Global Access",
                position=1,
            ),
            RulebasePackageLayerEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                package_uid="pkg-1",
                package_name="Corp_Policy",
                rulebase_type="access",
                layer_uid="layer-domain",
                layer_name="Corp Network",
                position=2,
            ),
        ],
        layers=[
            RulebaseLayerEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                uid="layer-global",
                name="Global Access",
                rulebase_type="access",
                is_global=True,
            ),
            RulebaseLayerEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                uid="layer-domain",
                name="Corp Network",
                rulebase_type="access",
                parent_layer_uid="layer-global",
                parent_rule_uid="r-global-ph",
            ),
            RulebaseLayerEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                uid="layer-inline",
                name="Web Inline",
                rulebase_type="access",
                parent_layer_uid="layer-domain",
                parent_rule_uid="r-dom-2",
            ),
        ],
        sections=[
            RulebaseSectionEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid="layer-domain",
                layer_name="Corp Network",
                rulebase_type="access",
                uid="sec-dom-main",
                name="Domain Main Rules",
                position=1,
                from_rule=1,
                to_rule=2,
                rule_uids=["r-dom-1", "r-dom-2"],
            ),
            RulebaseSectionEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid="layer-domain",
                layer_name="Corp Network",
                rulebase_type="access",
                uid="sec-dom-empty",
                name="Reserved Empty Section",
                position=2,
                rule_uids=[],
            ),
        ],
        access_rules=[
            AccessRuleEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid="layer-global",
                layer_name="Global Access",
                uid="r-global-1",
                name="Global Stealth",
                rule_type="access-rule",
                position=1,
                action="Drop",
            ),
            AccessRuleEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid="layer-global",
                layer_name="Global Access",
                uid="r-global-ph",
                name="Domain Placeholder",
                rule_type="place-holder",
                position=2,
                placeholder_domain_layer_uid="layer-domain",
            ),
            AccessRuleEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid="layer-domain",
                layer_name="Corp Network",
                section_uid="sec-dom-main",
                section_name="Domain Main Rules",
                uid="r-dom-1",
                name="Allow Internal DNS",
                rule_type="access-rule",
                position=1,
                source=["net-corp"],
                destination=["dns-srv"],
                service=["domain-udp"],
                action="Accept",
            ),
            AccessRuleEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid="layer-domain",
                layer_name="Corp Network",
                section_uid="sec-dom-main",
                section_name="Domain Main Rules",
                uid="r-dom-2",
                name="Web Tier Gate",
                rule_type="access-rule",
                position=2,
                inline_layer_uid="layer-inline",
                inline_layer_name="Web Inline",
                action="Apply Layer",
            ),
            AccessRuleEntry(
                mgmt_name=mgmt_name,
                domain_name=domain_name,
                layer_uid="layer-inline",
                layer_name="Web Inline",
                uid="r-inl-1",
                name="Allow App HTTPS",
                rule_type="access-rule",
                position=1,
                source=["grp-clients"],
                destination=["web-vip"],
                service=["https"],
                action="Accept",
            ),
        ],
    )


@pytest.mark.asyncio
async def test_package_and_layer_numbering_and_locate_rules() -> None:
    """`get_package_rulebase` expands Global placeholders (`2.1`, `2.2`) and inline layers (`2.2.1`), `get_layer_rulebase` numbers standalone layers (`1`, `2`, `2.1`), and `locate_rules` returns positions and prefixes."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)

    pub_time = datetime(2026, 10, 24, 5, 0, 0, tzinfo=UTC)
    await cache.upsert_domains([DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp")])
    await cache.replace_domain_rulebase(_build_hierarchical_snapshot("mds1", "Corp"))
    await cache.upsert_sync_state(
        DomainSyncState(
            mgmt_name="mds1",
            domain_name="Corp",
            scope="rulebase",
            item_type="*",
            last_published_at=pub_time,
            last_session_uid="sess-abc",
            synced_at=pub_time,
            status="ok",
            object_count=5,
        )
    )

    source = CachedRulebaseSource(cache=cache)

    # 1. Package view: top-level rules 1, 2; domain rules under placeholder 2.1, 2.2; inline rule 2.2.1
    pkg_rb = await source.get_package_rulebase("mds1", "Corp", "Corp_Policy", rulebase_type="access")
    numbers_by_uid = {r.uid: r.rule_number for r in pkg_rb.flat_rules}
    assert numbers_by_uid == {
        "r-global-1": "1",
        "r-global-ph": "2",
        "r-dom-1": "2.1",
        "r-dom-2": "2.2",
        "r-inl-1": "2.2.1",
    }

    # Check nested sections under placeholder rule #2
    ph_rule = pkg_rb.rules[1]
    assert ph_rule.uid == "r-global-ph"
    assert [s.range_label for s in ph_rule.nested_sections] == ["2.1-2.2", "No Rules"]

    # 2. Standalone layer view for "Corp Network": rules are 1, 2, and inline is 2.1
    layer_rb = await source.get_layer_rulebase("mds1", "Corp", "Corp Network")
    standalone_nums = {r.uid: r.rule_number for r in layer_rb.flat_rules}
    assert standalone_nums == {
        "r-dom-1": "1",
        "r-dom-2": "2",
        "r-inl-1": "2.1",
    }
    assert [s.range_label for s in layer_rb.sections] == ["1-2", "No Rules"]

    # 3. locate_rules across domain
    locs = await source.locate_rules(
        "mds1",
        "Corp",
        rule_uids=["r-global-1", "r-dom-1", "r-inl-1"],
        layer_uids=["layer-global", "layer-domain", "layer-inline"],
    )
    assert locs.snapshot_session_uid == "sess-abc"
    assert locs.snapshot_published_at == pub_time
    assert locs.sync_status == "ok"

    assert locs.rule_locations["r-global-1"][0].rule_number == "1"
    assert locs.rule_locations["r-dom-1"][0].rule_number == "2.1"
    assert locs.rule_locations["r-dom-1"][0].section_range == "2.1-2.2"
    assert locs.rule_locations["r-inl-1"][0].rule_number == "2.2.1"

    assert locs.layer_prefixes["layer-global"][0].prefix == ""
    assert locs.layer_prefixes["layer-domain"][0].prefix == "2."
    assert locs.layer_prefixes["layer-inline"][0].prefix == "2.2."

    await db.close()


@pytest.mark.asyncio
async def test_automatic_domain_resolution_and_ambiguous_layer_name_error() -> None:
    """When `domain_name` is `None` or `''`, `CachedRulebaseSource` resolves the unique matching domain or raises `AmbiguousLayerName` listing all `(domain, uid)` candidates."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)

    await cache.upsert_domains(
        [
            DomainInfo(mgmt_name="mds1", uid="d1", name="Corp"),
            DomainInfo(mgmt_name="mds1", uid="d2", name="Retail"),
        ]
    )
    await cache.replace_domain_rulebase(_build_hierarchical_snapshot("mds1", "Corp"))
    await cache.replace_domain_rulebase(
        DomainRulebaseSnapshot(
            mgmt_name="mds1",
            domain_name="Retail",
            layers=[
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Retail",
                    uid="layer-retail-only",
                    name="Retail Security",
                    rulebase_type="access",
                ),
                # Duplicate layer name "Corp Network" in Retail!
                RulebaseLayerEntry(
                    mgmt_name="mds1",
                    domain_name="Retail",
                    uid="layer-dup-retail",
                    name="Corp Network",
                    rulebase_type="access",
                ),
            ],
        )
    )

    source = CachedRulebaseSource(cache=cache)

    # Unique layer in Retail resolves automatically with domain_name=None
    retail_rb = await source.get_layer_rulebase("mds1", None, "Retail Security")
    assert retail_rb.domain_name == "Retail"
    assert retail_rb.layer_uid == "layer-retail-only"

    # Ambiguous layer name "Corp Network" present in both Corp and Retail raises AmbiguousLayerName
    with pytest.raises(AmbiguousLayerName) as exc_info:
        await source.get_layer_rulebase("mds1", "", "Corp Network")

    assert exc_info.value.layer_or_package == "Corp Network"
    assert set(exc_info.value.candidates) == {("Corp", "layer-domain"), ("Retail", "layer-dup-retail")}

    await db.close()


@pytest.mark.asyncio
async def test_local_rulebase_filtering_with_cached_objects_and_services() -> None:
    """`filter_rulebase` evaluates IP/CIDR, group membership, and service port filters locally against the cached snapshot and cached objects/services."""
    db = DatabaseManager()
    await db.initialize()
    cache = SqlCacheAdapter(db)

    await cache.upsert_domains([DomainInfo(mgmt_name="mds1", uid="d-corp", name="Corp")])
    await cache.replace_domain_rulebase(_build_hierarchical_snapshot("mds1", "Corp"))
    await cache.replace_domain_objects(
        "mds1",
        "Corp",
        [
            CPObject(
                uid="h-client-1",
                name="client-pc-1",
                type="host",
                mgmt_name="mds1",
                domain_name="Corp",
                ipv4_address="192.168.50.10",
            ),
            CPObject(
                uid="g-clients",
                name="grp-clients",
                type="group",
                mgmt_name="mds1",
                domain_name="Corp",
                members=["h-client-1"],
            ),
        ],
        types=["host", "group"],
    )
    await cache.replace_domain_services(
        "mds1",
        "Corp",
        [
            CPService(
                uid="svc-https",
                name="https",
                type="service-tcp",
                mgmt_name="mds1",
                domain_name="Corp",
                port="443",
                protocol="tcp",
            )
        ],
        types=["service-tcp"],
    )

    source = CachedRulebaseSource(cache=cache)

    # Filter by IP 192.168.50.10 (which is a member of grp-clients in rule 2.2.1!) and port 443
    res = await source.filter_rulebase(
        "mds1",
        "Corp",
        package="Corp_Policy",
        filter_query="src:192.168.50.10 svc:443",
        output_format="markdown",
    )
    assert res.matched_count == 1
    assert res.rules[0].rule_number == "2.2.1"
    assert "Allow App HTTPS" in res.rendered_text

    await db.close()
