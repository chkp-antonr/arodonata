"""Unit tests for AssetTransformer."""

from __future__ import annotations

from unittest.mock import patch

from arodonata.api.asset_transformer import AssetTransformer
from arodonata.cache.models import Asset


def _gw_obj(**overrides):
    obj = {
        "uid": "gw-uid-1",
        "name": "gw1",
        "type": "simple-gateway",
    }
    obj.update(overrides)
    return obj


class TestTransformToAsset:
    def test_transforms_valid_object_to_asset(self):
        obj = _gw_obj()

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert isinstance(asset, Asset)
        assert asset.asset_id == "mgmt1:domainA:gw1"
        assert asset.name == "gw1"
        assert asset.asset_type == "simple-gateway"
        assert asset.asset_uid == "gw-uid-1"
        assert asset.domain_name == "domainA"
        assert asset.domain_uid == "duid-1"
        assert asset.mgmt_name == "mgmt1"
        assert asset.parent_asset_id == ""
        assert asset.raw_data == obj

    def test_returns_none_for_non_dict_object(self):
        assert (
            AssetTransformer.transform_to_asset(
                obj=["not", "a", "dict"], mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
            )
            is None
        )

    def test_returns_none_when_name_missing(self):
        obj = _gw_obj()
        del obj["name"]

        assert (
            AssetTransformer.transform_to_asset(obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1")
            is None
        )

    def test_returns_none_when_type_missing(self):
        obj = _gw_obj()
        del obj["type"]

        assert (
            AssetTransformer.transform_to_asset(obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1")
            is None
        )

    def test_returns_none_when_uid_missing(self):
        obj = _gw_obj()
        del obj["uid"]

        assert (
            AssetTransformer.transform_to_asset(obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1")
            is None
        )

    def test_returns_none_when_name_blank_after_strip(self):
        obj = _gw_obj(name="   ")

        assert (
            AssetTransformer.transform_to_asset(obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1")
            is None
        )

    def test_checkpoint_host_in_smc_user_domain_becomes_sms(self):
        obj = _gw_obj(type="checkpoint-host")

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="SMC User", domain_uid="duid-1"
        )

        assert asset is not None
        assert asset.asset_type == "sms"

    def test_checkpoint_host_outside_smc_user_domain_unchanged(self):
        obj = _gw_obj(type="checkpoint-host")

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset is not None
        assert asset.asset_type == "checkpoint-host"

    def test_hardware_extracted_from_nested_dict(self):
        obj = _gw_obj(hardware={"name": "Open server"})

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.asset_hardware == "Open server"

    def test_hardware_extracted_from_scalar_value(self):
        obj = _gw_obj(hardware="15600")

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.asset_hardware == "15600"

    def test_hardware_defaults_to_empty_string_when_absent(self):
        obj = _gw_obj()

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.asset_hardware == ""

    def test_comments_extracted_when_string(self):
        obj = _gw_obj(comments="  some notes  ")

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.comments == "some notes"

    def test_comments_defaults_to_empty_when_not_a_string(self):
        obj = _gw_obj(comments={"nested": "structure"})

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.comments == ""

    def test_tags_extracted_from_string_list(self):
        obj = _gw_obj(tags=["prod", "critical"])

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.tags == [{"name": "prod", "color": ""}, {"name": "critical", "color": ""}]

    def test_tags_extracted_from_dict_list(self):
        obj = _gw_obj(tags=[{"name": "prod", "color": "red"}, {"name": "no-color"}])

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.tags == [{"name": "prod", "color": "red"}, {"name": "no-color", "color": ""}]

    def test_tags_dict_without_name_is_skipped(self):
        obj = _gw_obj(tags=[{"color": "red"}])

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.tags == []

    def test_tags_default_to_empty_list_when_not_a_list(self):
        obj = _gw_obj(tags="not-a-list")

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
        )

        assert asset.tags == []

    def test_domain_uid_stripped(self):
        obj = _gw_obj()

        asset = AssetTransformer.transform_to_asset(
            obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="  duid-1  "
        )

        assert asset.domain_uid == "duid-1"

    def test_empty_domain_uid_becomes_empty_string(self):
        obj = _gw_obj()

        asset = AssetTransformer.transform_to_asset(obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="")

        assert asset.domain_uid == ""

    def test_value_error_during_creation_returns_none(self):
        obj = _gw_obj()

        with patch.object(AssetTransformer, "_create_asset_object", side_effect=ValueError("boom")):
            asset = AssetTransformer.transform_to_asset(
                obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
            )

        assert asset is None

    def test_unexpected_exception_during_creation_is_reraised(self):
        obj = _gw_obj()

        with patch.object(AssetTransformer, "_create_asset_object", side_effect=RuntimeError("unexpected")):
            try:
                AssetTransformer.transform_to_asset(
                    obj=obj, mgmt_name="mgmt1", domain_name="domainA", domain_uid="duid-1"
                )
                raised = False
            except RuntimeError:
                raised = True

        assert raised


class TestBuildClusterMemberMappings:
    def test_maps_member_names_to_cluster_name(self):
        objects_list = [
            {
                "type": "CpmiGatewayCluster",
                "name": "cluster1",
                "cluster-member-names": ["member1", "member2"],
            }
        ]

        mappings = AssetTransformer.build_cluster_member_mappings(objects_list)

        assert mappings == {"member1": "cluster1", "member2": "cluster1"}

    def test_ignores_non_cluster_objects(self):
        objects_list = [
            {"type": "simple-gateway", "name": "gw1"},
            {"type": "CpmiGatewayCluster", "name": "cluster1", "cluster-member-names": ["member1"]},
        ]

        mappings = AssetTransformer.build_cluster_member_mappings(objects_list)

        assert mappings == {"member1": "cluster1"}

    def test_ignores_non_dict_entries(self):
        objects_list = [
            "not-a-dict",
            {"type": "CpmiGatewayCluster", "name": "cluster1", "cluster-member-names": ["m1"]},
        ]

        mappings = AssetTransformer.build_cluster_member_mappings(objects_list)

        assert mappings == {"m1": "cluster1"}

    def test_cluster_without_name_is_skipped(self):
        objects_list = [{"type": "CpmiGatewayCluster", "name": "", "cluster-member-names": ["m1"]}]

        mappings = AssetTransformer.build_cluster_member_mappings(objects_list)

        assert mappings == {}

    def test_cluster_member_names_not_a_list_produces_no_mappings(self):
        objects_list = [{"type": "CpmiGatewayCluster", "name": "cluster1", "cluster-member-names": "member1"}]

        mappings = AssetTransformer.build_cluster_member_mappings(objects_list)

        assert mappings == {}

    def test_falsy_member_name_in_list_is_skipped(self):
        objects_list = [
            {"type": "CpmiGatewayCluster", "name": "cluster1", "cluster-member-names": ["member1", "", None]}
        ]

        mappings = AssetTransformer.build_cluster_member_mappings(objects_list)

        assert mappings == {"member1": "cluster1"}

    def test_empty_objects_list_returns_empty_mapping(self):
        assert AssetTransformer.build_cluster_member_mappings([]) == {}


class TestTransformToAssetWithClusterRelationships:
    def test_cluster_member_gets_parent_asset_id_from_mapping(self):
        obj = _gw_obj(name="member1")
        mappings = {"member1": "cluster1"}

        asset = AssetTransformer.transform_to_asset_with_cluster_relationships(
            obj=obj,
            mgmt_name="mgmt1",
            domain_name="domainA",
            domain_uid="duid-1",
            cluster_member_mappings=mappings,
        )

        assert asset is not None
        assert asset.parent_asset_id == "mgmt1:domainA:cluster1"

    def test_non_member_object_has_no_parent_from_mapping(self):
        obj = _gw_obj(name="standalone-gw")
        mappings = {"member1": "cluster1"}

        asset = AssetTransformer.transform_to_asset_with_cluster_relationships(
            obj=obj,
            mgmt_name="mgmt1",
            domain_name="domainA",
            domain_uid="duid-1",
            cluster_member_mappings=mappings,
        )

        assert asset is not None
        assert asset.parent_asset_id == ""

    def test_vs_netobj_type_never_gets_parent_asset_id_here(self):
        obj = _gw_obj(name="vs1", type="CpmiVsNetobj")
        # Even if (contrived) it's in the cluster mapping, VS objects are excluded.
        mappings = {"vs1": "cluster1"}

        asset = AssetTransformer.transform_to_asset_with_cluster_relationships(
            obj=obj,
            mgmt_name="mgmt1",
            domain_name="domainA",
            domain_uid="duid-1",
            cluster_member_mappings=mappings,
        )

        assert asset is not None
        assert asset.parent_asset_id == ""

    def test_vs_slot_obj_type_never_gets_parent_asset_id_here(self):
        obj = _gw_obj(name="slot1", type="vs_slot_obj")

        asset = AssetTransformer.transform_to_asset_with_cluster_relationships(
            obj=obj,
            mgmt_name="mgmt1",
            domain_name="domainA",
            domain_uid="duid-1",
            cluster_member_mappings={},
        )

        assert asset is not None
        assert asset.parent_asset_id == ""

    def test_falls_back_to_cluster_uid_field(self):
        obj = _gw_obj(name="gw1")
        obj["cluster-uid"] = "some-cluster-uid"

        asset = AssetTransformer.transform_to_asset_with_cluster_relationships(
            obj=obj,
            mgmt_name="mgmt1",
            domain_name="domainA",
            domain_uid="duid-1",
            cluster_member_mappings={},
        )

        assert asset is not None
        assert asset.parent_asset_id == "some-cluster-uid"

    def test_falls_back_to_parent_uid_field(self):
        obj = _gw_obj(name="gw1")
        obj["parent-uid"] = "some-parent-uid"

        asset = AssetTransformer.transform_to_asset_with_cluster_relationships(
            obj=obj,
            mgmt_name="mgmt1",
            domain_name="domainA",
            domain_uid="duid-1",
            cluster_member_mappings={},
        )

        assert asset is not None
        assert asset.parent_asset_id == "some-parent-uid"

    def test_returns_none_for_non_dict_object(self):
        assert (
            AssetTransformer.transform_to_asset_with_cluster_relationships(
                obj="not-a-dict",
                mgmt_name="mgmt1",
                domain_name="domainA",
                domain_uid="duid-1",
                cluster_member_mappings={},
            )
            is None
        )

    def test_returns_none_when_required_fields_missing(self):
        obj = {"name": "gw1"}  # missing type/uid

        assert (
            AssetTransformer.transform_to_asset_with_cluster_relationships(
                obj=obj,
                mgmt_name="mgmt1",
                domain_name="domainA",
                domain_uid="duid-1",
                cluster_member_mappings={},
            )
            is None
        )

    def test_value_error_during_creation_returns_none(self):
        obj = _gw_obj()

        with patch.object(AssetTransformer, "_create_asset_object", side_effect=KeyError("boom")):
            asset = AssetTransformer.transform_to_asset_with_cluster_relationships(
                obj=obj,
                mgmt_name="mgmt1",
                domain_name="domainA",
                domain_uid="duid-1",
                cluster_member_mappings={},
            )

        assert asset is None

    def test_unexpected_exception_during_creation_is_reraised(self):
        obj = _gw_obj()

        with patch.object(AssetTransformer, "_create_asset_object", side_effect=RuntimeError("unexpected")):
            try:
                AssetTransformer.transform_to_asset_with_cluster_relationships(
                    obj=obj,
                    mgmt_name="mgmt1",
                    domain_name="domainA",
                    domain_uid="duid-1",
                    cluster_member_mappings={},
                )
                raised = False
            except RuntimeError:
                raised = True

        assert raised
