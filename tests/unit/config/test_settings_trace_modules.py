"""Tests for ARODONATA_TRACE_MODULES parsing (per-module span gating)."""

import pytest
from pydantic import ValidationError

from arodonata.config import ArodonataSettings


def test_default_is_empty_and_rules_empty():
    s = ArodonataSettings()
    assert s.trace_modules == ""
    assert s.trace_modules_rules == {}


def test_valid_rules_parse_to_dict():
    s = ArodonataSettings(trace_modules="arodonata:on, arodonata.api.client:off")
    assert s.trace_modules_rules == {"arodonata": True, "arodonata.api.client": False}


def test_env_var_alias(monkeypatch):
    monkeypatch.setenv("ARODONATA_TRACE_MODULES", "arodonata.asdk:off")
    s = ArodonataSettings()
    assert s.trace_modules_rules == {"arodonata.asdk": False}


@pytest.mark.parametrize("bad", ["arodonata", "arodonata:maybe", ":on", "arodonata:on,junk"])
def test_invalid_entries_raise(bad):
    with pytest.raises(ValidationError):
        ArodonataSettings(trace_modules=bad)
