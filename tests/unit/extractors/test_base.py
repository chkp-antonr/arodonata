"""Tests for extractors.base: ExtractionContext and BaseExtractor."""

from arodonata.extractors.base import BaseExtractor, ExtractionContext


def test_extraction_context_defaults_objects_map_to_none():
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="dmn1")

    assert context.mgmt_name == "mgmt1"
    assert context.domain_name == "dmn1"
    assert context.objects_map is None


def test_extraction_context_accepts_objects_map():
    objects_map = {"uid-1": "name-1"}
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="dmn1", objects_map=objects_map)

    assert context.objects_map == objects_map


def test_extraction_context_equality_is_value_based():
    a = ExtractionContext(mgmt_name="mgmt1", domain_name="dmn1")
    b = ExtractionContext(mgmt_name="mgmt1", domain_name="dmn1")

    assert a == b


def test_base_extractor_is_subclassable_marker_class():
    class DummyExtractor(BaseExtractor):
        def extract(self, raw_data, context):
            return {"uid": raw_data.get("uid")}

    instance = DummyExtractor()
    context = ExtractionContext(mgmt_name="mgmt1", domain_name="dmn1")

    assert isinstance(instance, BaseExtractor)
    assert instance.extract({"uid": "x"}, context) == {"uid": "x"}
