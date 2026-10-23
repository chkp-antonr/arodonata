"""Unit tests for core exceptions, secret/SID redaction, and OpenTelemetry helpers."""

from __future__ import annotations

from typing import Any

import pytest
from opentelemetry import trace

from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    AmbiguousLayerName,
    ApiTimeoutError,
    ArodonataError,
    ConfigurationError,
    InvalidCredentialsError,
    is_sensitive_key,
    redact_secret,
    redact_sid,
    sanitize_mapping,
)
from arodonata.core.telemetry import (
    apply_trace_modules,
    parse_trace_modules,
    set_trace_modules,
    span_attrs,
    traced,
)


def test_redact_sid_masks_headers_json_and_known_sids() -> None:
    """Verify SID values in headers, JSON strings, and known_sids are masked."""
    raw = (
        'Request failed: X-chkp-sid: abcdef1234567890, payload={"sid": "tok_99887766", '
        '"password": "my_secret_password"}, raw_sid=custom_sid_token_42'
    )
    scrubbed = redact_sid(raw, known_sids=["custom_sid_token_42"])
    assert "abcdef1234567890" not in scrubbed
    assert "tok_99887766" not in scrubbed
    assert "my_secret_password" not in scrubbed
    assert "custom_sid_token_42" not in scrubbed
    assert REDACTED_PLACEHOLDER in scrubbed


def test_sanitize_mapping_redacts_nested_secrets() -> None:
    """Verify sanitize_mapping masks sensitive keys and nested SID strings."""
    payload: dict[str, Any] = {
        "mgmt_name": "mds1",
        "sid": "secret_sid_12345",
        "api_key": "secret_key_abc",
        "nested": {
            "password": "pw",
            "note": "session X-chkp-sid=9876543210abcdef failed",
        },
    }
    cleaned = sanitize_mapping(payload)
    assert cleaned["mgmt_name"] == "mds1"
    assert cleaned["sid"] == REDACTED_PLACEHOLDER
    assert cleaned["api_key"] == REDACTED_PLACEHOLDER
    assert cleaned["nested"]["password"] == REDACTED_PLACEHOLDER
    assert "9876543210abcdef" not in cleaned["nested"]["note"]


def test_exception_redacts_message_and_preserves_hierarchy() -> None:
    """Verify ArodonataError subclasses automatically scrub SIDs and preserve attributes."""
    err = ApiTimeoutError(
        'Read timed out for {"sid": "my_live_sid_value"}',
        phase="read",
        host="10.0.0.1",
        port=443,
        command="publish",
    )
    assert isinstance(err, TimeoutError)
    assert isinstance(err, ArodonataError)
    assert "my_live_sid_value" not in str(err)
    assert err.phase == "read"
    assert err.host == "10.0.0.1"
    assert err.port == 443
    assert err.command == "publish"

    amb = AmbiguousLayerName("Network", [("DomainA", "uid-1"), ("DomainB", "uid-2")])
    assert "DomainA" in str(amb)
    assert amb.layer_or_package == "Network"
    assert issubclass(InvalidCredentialsError, ArodonataError)
    assert redact_secret("secret") == REDACTED_PLACEHOLDER
    assert redact_secret(None) == ""
    assert is_sensitive_key("arodonata.sid")
    assert is_sensitive_key("client_api_key")


def test_parse_and_apply_trace_modules() -> None:
    """Verify trace_modules parsing and host rule preservation when trace_modules is empty."""
    import arlogi.otel.decorator as otel_dec

    set_trace_modules({"host.module": False})
    try:
        # Empty string must NOT overwrite existing process-global rules
        parsed_empty = apply_trace_modules("")
        assert parsed_empty == {}
        assert otel_dec._trace_modules == {"host.module": False}

        # Explicit rules parse and apply
        rules = apply_trace_modules("arodonata:on, arodonata.api.client:off")
        assert rules == {"arodonata": True, "arodonata.api.client": False}
        assert otel_dec._trace_modules == {"arodonata": True, "arodonata.api.client": False}

        with pytest.raises(ConfigurationError):
            parse_trace_modules("invalid_entry_without_colon")

        with pytest.raises(ConfigurationError):
            parse_trace_modules("arodonata:maybe")
    finally:
        set_trace_modules(None)


async def test_span_attrs_and_traced_recording(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify span_attrs namespaces non-None keys under arodonata.* and drops sensitive keys."""
    recorded: dict[str, Any] = {}

    class _FakeSpan:
        def is_recording(self) -> bool:
            return True

        def get_span_context(self) -> Any:
            return trace.INVALID_SPAN_CONTEXT

        def set_attribute(self, key: str, value: Any) -> None:
            recorded[key] = value

    monkeypatch.setattr(trace, "get_current_span", lambda *_args, **_kwargs: _FakeSpan())

    @traced
    async def sample_op() -> str:
        span_attrs(
            mgmt_name="mds1",
            domain="CMA1",
            empty_field=None,
            sid="never_record_me",
            api_key="never_record_key",
            count=3,
            tags=["host", "network"],
        )
        return "ok"

    res = await sample_op()
    assert res == "ok"
    assert recorded == {
        "arodonata.mgmt_name": "mds1",
        "arodonata.domain": "CMA1",
        "arodonata.count": 3,
        "arodonata.tags": ["host", "network"],
    }
    assert "arodonata.sid" not in recorded
    assert "arodonata.api_key" not in recorded
    assert "arodonata.empty_field" not in recorded
