"""Tests for arodonata.cache.models (SQLModel table definitions).

Covers the ServerList value object, the Domain.build() factory, Asset
creation/validation, composite-key fields, raw-data JSON handling, and the
existence of field defaults/indexes across the cache table models.
"""

from __future__ import annotations

from datetime import datetime

from arodonata.cache.models import Asset as AssetModel
from arodonata.cache.models import (
    CPObject,
    DistributedLock,
    Domain,
    LastPublishedSession,
    RulebaseAccess,
    RulebaseHTTPS,
    RulebaseNAT,
    RulebaseThreat,
    ServerList,
    SIDCache,
)

# --------------------------------------------------------------------------
# ServerList value object
# --------------------------------------------------------------------------


def test_server_list_from_csv_parses_and_strips_entries() -> None:
    """from_csv splits on commas and strips surrounding whitespace."""
    servers = ServerList.from_csv("server1, server2 ,server3")
    assert servers.servers == ["server1", "server2", "server3"]


def test_server_list_from_csv_empty_string_returns_empty_list() -> None:
    """An empty CSV string yields an empty ServerList."""
    servers = ServerList.from_csv("")
    assert servers.servers == []
    assert servers.to_csv() == ""


def test_server_list_from_csv_skips_blank_segments() -> None:
    """Blank segments between commas (e.g. trailing comma) are dropped."""
    servers = ServerList.from_csv("server1,,server2,")
    assert servers.servers == ["server1", "server2"]


def test_server_list_to_csv_round_trips() -> None:
    """to_csv reconstructs the comma-separated form."""
    servers = ServerList(["a", "b", "c"])
    assert servers.to_csv() == "a,b,c"


def test_server_list_bool_true_when_servers_present() -> None:
    """Truthiness reflects whether any servers are present."""
    assert bool(ServerList(["a"])) is True


def test_server_list_bool_false_when_empty() -> None:
    """An empty ServerList is falsy."""
    assert bool(ServerList([])) is False


def test_server_list_is_frozen() -> None:
    """ServerList is a frozen dataclass (immutable value object)."""
    servers = ServerList(["a"])
    try:
        servers.servers = ["b"]  # type: ignore[misc]
        raised = False
    except AttributeError:
        raised = True
    assert raised is True


# --------------------------------------------------------------------------
# SIDCache
# --------------------------------------------------------------------------


def test_sid_cache_creation_and_defaults() -> None:
    """SIDCache accepts required fields and defaults optional ones to None."""
    sid = SIDCache(
        mgmt_dmn_key="mgmt1:domain1",
        sid="abcdef1234567890",
        server_ip="10.0.0.1",
    )
    assert sid.mgmt_dmn_key == "mgmt1:domain1"
    assert sid.uid is None
    assert sid.last_keepalive is None
    assert sid.metadata_ is None
    assert isinstance(sid.created_at, datetime)


def test_sid_cache_repr_with_uid() -> None:
    """repr includes a truncated uid when present."""
    sid = SIDCache(
        mgmt_dmn_key="mgmt1:domain1",
        sid="abcdef1234567890",
        uid="uid-1234567890",
        server_ip="10.0.0.1",
    )
    text = repr(sid)
    assert "mgmt1:domain1" in text
    assert "uid=" in text


def test_sid_cache_repr_without_uid() -> None:
    """repr omits the uid segment entirely when uid is None."""
    sid = SIDCache(mgmt_dmn_key="mgmt1:domain1", sid="abcdef1234567890", server_ip="10.0.0.1")
    text = repr(sid)
    assert "uid=" not in text


def test_sid_cache_uid_field_is_indexed() -> None:
    """The uid column is indexed for lookups."""
    assert SIDCache.__table__.columns["uid"].index is True


# --------------------------------------------------------------------------
# Asset
# --------------------------------------------------------------------------


def test_asset_creation_with_composite_key() -> None:
    """Asset accepts a composite 'mgmt:domain:name' primary key and required fields."""
    asset = AssetModel(
        asset_id="mgmt1:domain1:gw-01",
        name="gw-01",
        asset_type="gateway",
        asset_uid="uid-123",
        mgmt_name="mgmt1",
    )
    assert asset.asset_id == "mgmt1:domain1:gw-01"
    assert asset.name == "gw-01"
    assert asset.asset_hardware == ""  # default
    assert asset.tags is None
    assert asset.raw_data is None


def test_asset_repr() -> None:
    """repr surfaces id, name, and type for debugging."""
    asset = AssetModel(
        asset_id="mgmt1:domain1:gw-01",
        name="gw-01",
        asset_type="gateway",
        asset_uid="uid-123",
        mgmt_name="mgmt1",
    )
    text = repr(asset)
    assert "gw-01" in text
    assert "gateway" in text
    assert "mgmt1:domain1:gw-01" in text


def test_asset_raw_data_and_tags_accept_json_values() -> None:
    """raw_data and tags fields accept arbitrary JSON-serializable structures."""
    asset = AssetModel(
        asset_id="mgmt1:domain1:gw-01",
        name="gw-01",
        asset_type="gateway",
        asset_uid="uid-123",
        mgmt_name="mgmt1",
        tags=[{"name": "prod", "color": "red"}],
        raw_data={"uid": "uid-123", "nested": {"a": 1}},
    )
    assert asset.tags == [{"name": "prod", "color": "red"}]
    assert asset.raw_data == {"uid": "uid-123", "nested": {"a": 1}}


def test_asset_primary_key_field() -> None:
    """asset_id is the SQLModel primary key column."""
    assert AssetModel.__table__.columns["asset_id"].primary_key is True


def test_asset_indexed_fields_exist() -> None:
    """Commonly queried Asset fields (name, type, mgmt_name, region) are indexed."""
    columns = AssetModel.__table__.columns
    for field_name in ("name", "asset_type", "mgmt_name", "region", "country_code"):
        assert columns[field_name].index is True, f"{field_name} should be indexed"


def test_asset_parent_asset_id_self_referential_foreign_key() -> None:
    """parent_asset_id is an indexed self-referencing foreign key to assets.asset_id."""
    column = AssetModel.__table__.columns["parent_asset_id"]
    assert column.index is True
    fk_targets = [fk.target_fullname for fk in column.foreign_keys]
    assert fk_targets == ["assets.asset_id"]


# --------------------------------------------------------------------------
# Domain.build() factory
# --------------------------------------------------------------------------


def test_domain_build_defaults_active_server_to_mgmt_name() -> None:
    """When active_server is omitted, it defaults to mgmt_name."""
    domain = Domain.build(
        mgmt_name="mgmt1",
        domain_name="dmn1",
        active_ip="192.168.1.10",
    )
    assert domain.active_server == "mgmt1"
    assert domain.mdm_dmn == "mgmt1:dmn1"
    assert domain.active_mds == "mgmt1"
    assert domain.domain_uid == ""
    assert domain.is_mdm is False
    assert domain.standby_mdss == ""


def test_domain_build_honors_explicit_active_server() -> None:
    """An explicitly provided active_server is not overridden."""
    domain = Domain.build(
        mgmt_name="mgmt1",
        domain_name="dmn1",
        active_ip="192.168.1.10",
        active_server="custom-server",
    )
    assert domain.active_server == "custom-server"


def test_domain_build_with_standby_servers_and_mdm_flag() -> None:
    """Standby server CSVs and is_mdm flag are passed through untouched."""
    domain = Domain.build(
        mgmt_name="mgmt1",
        domain_name="dmn1",
        domain_uid="uid-1",
        active_ip="192.168.1.10",
        standby_mdss="mds2,mds3",
        standby_ips="192.168.1.11,192.168.1.12",
        standby_servers="srv2,srv3",
        is_mdm=True,
    )
    assert domain.domain_uid == "uid-1"
    assert domain.standby_mdss == "mds2,mds3"
    assert domain.standby_ips == "192.168.1.11,192.168.1.12"
    assert domain.standby_servers == "srv2,srv3"
    assert domain.is_mdm is True


def test_domain_repr() -> None:
    """repr surfaces name, uid, and active_mds."""
    domain = Domain.build(mgmt_name="mgmt1", domain_name="dmn1", domain_uid="uid-1", active_ip="192.168.1.10")
    text = repr(domain)
    assert "dmn1" in text
    assert "uid-1" in text
    assert "mgmt1" in text


def test_domain_primary_key_is_mdm_dmn() -> None:
    """mdm_dmn is the composite primary key column."""
    assert Domain.__table__.primary_key.columns.keys() == ["mdm_dmn"]


# --------------------------------------------------------------------------
# DistributedLock
# --------------------------------------------------------------------------


def test_distributed_lock_creation_and_repr() -> None:
    """DistributedLock stores lock_key/owner/expiry and reprs them."""
    now = datetime(2026, 1, 1, 12, 0, 0)
    lock = DistributedLock(
        lock_key="asset_refresh:mgmt1",
        owner_id="host:123:main",
        acquired_at=now,
        expires_at=now,
    )
    assert lock.lock_key == "asset_refresh:mgmt1"
    assert lock.metadata_ is None
    text = repr(lock)
    assert "asset_refresh:mgmt1" in text
    assert "host:123:main" in text


def test_distributed_lock_primary_key() -> None:
    """lock_key is the primary key."""
    assert DistributedLock.__table__.columns["lock_key"].primary_key is True


# --------------------------------------------------------------------------
# CPObject
# --------------------------------------------------------------------------


def test_cpobject_creation_with_composite_key_and_defaults() -> None:
    """CPObject accepts a composite id and defaults optional fields sensibly."""
    obj = CPObject(
        id="mgmt1:domain1:uid-123",
        uid="uid-123",
        name="host1",
        type="host",
        mgmt_name="mgmt1",
    )
    assert obj.id == "mgmt1:domain1:uid-123"
    assert obj.domain_name == ""
    assert obj.ipv4_address == ""
    assert obj.nat_settings is None
    assert obj.interfaces is None
    assert obj.raw_data is None
    assert isinstance(obj.update_time, datetime)


def test_cpobject_repr() -> None:
    """repr surfaces id, name, and type."""
    obj = CPObject(
        id="mgmt1:domain1:uid-123",
        uid="uid-123",
        name="host1",
        type="host",
        mgmt_name="mgmt1",
    )
    text = repr(obj)
    assert "host1" in text
    assert "host" in text
    assert "mgmt1:domain1:uid-123" in text


def test_cpobject_nat_settings_and_interfaces_accept_json() -> None:
    """nat_settings (dict) and interfaces (list of dicts) accept JSON values."""
    obj = CPObject(
        id="mgmt1:domain1:uid-123",
        uid="uid-123",
        name="host1",
        type="host",
        mgmt_name="mgmt1",
        nat_settings={"auto-rule": True},
        interfaces=[{"name": "eth0", "ipv4-address": "10.0.0.1"}],
    )
    assert obj.nat_settings == {"auto-rule": True}
    assert obj.interfaces == [{"name": "eth0", "ipv4-address": "10.0.0.1"}]


def test_cpobject_indexed_fields_exist() -> None:
    """Frequently queried CPObject fields are indexed."""
    columns = CPObject.__table__.columns
    for field_name in ("uid", "name", "type", "mgmt_name", "domain_name", "ipv4_address"):
        assert columns[field_name].index is True, f"{field_name} should be indexed"


# --------------------------------------------------------------------------
# LastPublishedSession
# --------------------------------------------------------------------------


def test_last_published_session_defaults() -> None:
    """published_time defaults to the epoch when not supplied."""
    session = LastPublishedSession(id="mgmt1:domain1", mgmt_name="mgmt1", domain_name="domain1")
    assert session.published_time == datetime(1970, 1, 1)
    assert session.uid == ""
    assert isinstance(session.update_time, datetime)


def test_last_published_session_repr() -> None:
    """repr surfaces id and published_time."""
    session = LastPublishedSession(id="mgmt1:domain1", mgmt_name="mgmt1", domain_name="domain1")
    text = repr(session)
    assert "mgmt1:domain1" in text


# --------------------------------------------------------------------------
# Rulebase* models (access / NAT / HTTPS / threat)
# --------------------------------------------------------------------------


def test_rulebase_access_creation_and_repr() -> None:
    """RulebaseAccess accepts required fields, defaults action/track, and reprs."""
    rule = RulebaseAccess(
        id="mgmt1:domain1:Network:uid-1",
        uid="uid-1",
        rule_number=1,
        name="allow-web",
        enabled=True,
        layer_name="Network",
        mgmt_name="mgmt1",
    )
    assert rule.action == "accept"
    assert rule.track == ""
    assert rule.raw_data is None
    text = repr(rule)
    assert "allow-web" in text
    assert "Network" in text


def test_rulebase_nat_creation_and_repr() -> None:
    """RulebaseNAT accepts required fields and reprs name/layer."""
    rule = RulebaseNAT(
        id="mgmt1:domain1:NAT:uid-2",
        uid="uid-2",
        rule_number=1,
        name="nat-rule-1",
        enabled=True,
        layer_name="NAT",
        mgmt_name="mgmt1",
    )
    assert rule.original_source == ""
    assert rule.translated_service == ""
    text = repr(rule)
    assert "nat-rule-1" in text
    assert "NAT" in text


def test_rulebase_https_creation_and_repr() -> None:
    """RulebaseHTTPS accepts required fields and reprs name/layer."""
    rule = RulebaseHTTPS(
        id="mgmt1:domain1:HTTPS:uid-3",
        uid="uid-3",
        rule_number=1,
        name="https-rule-1",
        enabled=False,
        layer_name="HTTPS",
        mgmt_name="mgmt1",
    )
    assert rule.enabled is False
    assert rule.track == ""
    text = repr(rule)
    assert "https-rule-1" in text
    assert "HTTPS" in text


def test_rulebase_threat_creation_and_repr() -> None:
    """RulebaseThreat accepts required fields and reprs name/layer."""
    rule = RulebaseThreat(
        id="mgmt1:domain1:Threat:uid-4",
        uid="uid-4",
        rule_number=1,
        name="threat-rule-1",
        enabled=True,
        layer_name="Threat",
        mgmt_name="mgmt1",
    )
    assert rule.protections == ""
    text = repr(rule)
    assert "threat-rule-1" in text
    assert "Threat" in text


def test_rulebase_models_share_composite_id_primary_key() -> None:
    """All rulebase tables use a composite 'mgmt:domain:layer:uid' id primary key."""
    for model in (RulebaseAccess, RulebaseNAT, RulebaseHTTPS, RulebaseThreat):
        assert model.__table__.columns["id"].primary_key is True
