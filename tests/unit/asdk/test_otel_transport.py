"""OTEL span tests for ApiTransport (the raw HTTP hop to CP mgmt servers)."""

from contextlib import asynccontextmanager
from unittest.mock import MagicMock

from arodonata.asdk.transport import ApiTransport


def _stub_client_factory(response):
    @asynccontextmanager
    async def _client(self, server_ip, port=None, sid=None):
        client = MagicMock()
        client.sid = sid
        client.api_call = MagicMock(return_value=response)
        yield client

    return _client


def _response(success=True, message="", code=""):
    r = MagicMock()
    r.success = success
    r.data = {}
    r.message = message
    r.status_code = code
    return r


async def test_api_call_records_span_with_command_attrs(otel_spans, monkeypatch):
    monkeypatch.setattr(ApiTransport, "_client", _stub_client_factory(_response()))
    transport = ApiTransport()
    result = await transport.api_call("10.0.0.1", "sid123", "show-hosts", timeout=5)
    assert result["success"] is True
    spans = otel_spans.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name.endswith("ApiTransport.api_call")
    assert spans[0].attributes["arodonata.command"] == "show-hosts"
    assert spans[0].attributes["arodonata.server_ip"] == "10.0.0.1"


async def test_api_call_failure_records_response_code(otel_spans, monkeypatch):
    monkeypatch.setattr(
        ApiTransport,
        "_client",
        _stub_client_factory(_response(success=False, message="generic error", code="err_x")),
    )
    transport = ApiTransport()
    result = await transport.api_call("10.0.0.1", "sid123", "add-host")
    assert result["success"] is False
    span = otel_spans.get_finished_spans()[0]
    assert span.attributes["arodonata.response_code"] == "err_x"


async def test_api_call_works_without_provider(monkeypatch):
    # NOTE: does not genuinely prove the no-provider case in-process (see
    # test_traced_code_runs_correctly_with_no_provider_configured in
    # tests/unit/api/test_otel_client_surface.py for the real subprocess
    # coverage). Still validates correct return values regardless.
    monkeypatch.setattr(ApiTransport, "_client", _stub_client_factory(_response()))
    transport = ApiTransport()
    result = await transport.api_call("10.0.0.1", "sid123", "show-hosts")
    assert result["success"] is True


async def test_gating_disables_transport_spans(otel_spans, monkeypatch):
    from arlogi.otel.decorator import set_trace_modules

    monkeypatch.setattr(ApiTransport, "_client", _stub_client_factory(_response()))
    transport = ApiTransport()
    set_trace_modules({"arodonata.asdk.transport": False})
    await transport.api_call("10.0.0.1", "sid123", "show-hosts")
    assert otel_spans.get_finished_spans() == ()
