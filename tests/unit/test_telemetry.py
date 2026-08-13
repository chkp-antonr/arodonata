"""Tests for arodonata.telemetry (span attribute helper) and the api-only import path."""

from opentelemetry import trace

from arodonata.telemetry import span_attrs


def test_arlogi_v2_decorator_importable():
    from arlogi.otel.decorator import set_trace_modules, traced  # noqa: F401


def test_span_attrs_sets_prefixed_attributes(otel_spans):
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("demo"):
        span_attrs(mgmt_name="mgmt1", port=443, **{"lock.key": "login:mgmt1:"})
    span = otel_spans.get_finished_spans()[0]
    assert span.attributes["arodonata.mgmt_name"] == "mgmt1"
    assert span.attributes["arodonata.port"] == 443
    assert span.attributes["arodonata.lock.key"] == "login:mgmt1:"


def test_span_attrs_skips_none_values(otel_spans):
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("demo"):
        span_attrs(port=None, domain="system")
    span = otel_spans.get_finished_spans()[0]
    assert "arodonata.port" not in span.attributes
    assert span.attributes["arodonata.domain"] == "system"


def test_span_attrs_is_noop_without_provider():
    # NOTE: this runs in-process, where a real TracerProvider may already be
    # session-persistent from an earlier otel_spans-using test — so this does
    # not genuinely prove the no-provider case. The subprocess-based
    # test_traced_code_runs_correctly_with_no_provider_configured in
    # tests/unit/api/test_otel_client_surface.py is what genuinely covers
    # that guarantee. This test still validates correct (non-raising)
    # behavior under whatever provider state happens to exist.
    span_attrs(mgmt_name="mgmt1")  # must not raise
