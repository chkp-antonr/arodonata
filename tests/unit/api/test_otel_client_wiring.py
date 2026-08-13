"""ArodonataClient.__init__ must apply trace-module gating rules."""

from arodonata.config import ArodonataSettings
from tests.unit.api.client_test_helpers import make_client


def test_client_init_applies_trace_module_rules(monkeypatch):
    calls: list[dict | None] = []
    monkeypatch.setattr("arodonata.api.client.set_trace_modules", lambda rules: calls.append(rules))
    make_client(settings=ArodonataSettings(trace_modules="arodonata:on,arodonata.api.client:off"))
    assert calls == [{"arodonata": True, "arodonata.api.client": False}]


def test_client_init_does_not_touch_rules_when_unset(monkeypatch):
    """Without an explicit trace_modules config, the client must not call
    set_trace_modules at all — doing so would replace the process-global
    gating registry with {} and clobber a host application's own rules."""
    calls: list[dict | None] = []
    monkeypatch.setattr("arodonata.api.client.set_trace_modules", lambda rules: calls.append(rules))
    make_client(settings=ArodonataSettings())
    assert calls == []
