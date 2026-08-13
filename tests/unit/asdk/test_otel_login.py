"""OTEL span tests for LoginCoordinator: span shape + credential safety."""

from unittest.mock import AsyncMock, MagicMock

from pydantic import SecretStr

from tests.unit.asdk.test_login_coordinator import _make_coordinator, _make_lock_manager

API_KEY = "SECRET-API-KEY-VALUE"
FULL_SID = "abcdef0123456789abcdef0123456789"


def _coordinator_for_real_login(*, api_key: str, login_sid: str):
    """Build a coordinator that drives login() through the real (unmocked)
    _perform_login -> _execute_login_request -> transport.login_with_apikey
    chain, so a credential leak into a span attribute would actually be caught.
    """
    cache = AsyncMock()
    cache.get_sid.return_value = None  # force a real login instead of a cache hit

    server_config = MagicMock(server_ip="10.0.0.1", api_key=SecretStr(api_key), port=None, is_mdm=False)
    registry = MagicMock()
    registry.get_server.return_value = server_config

    transport = AsyncMock()
    transport.login_with_apikey.return_value = {
        "success": True,
        "sid": login_sid,
        "data": {"uid": "uid-1"},
    }

    return _make_coordinator(cache=cache, registry=registry, transport=transport, lock_manager=_make_lock_manager())


async def test_login_records_span_with_mgmt_and_cache_attrs(otel_spans):
    coordinator = _coordinator_for_real_login(api_key=API_KEY, login_sid=FULL_SID)
    sid, _ip = await coordinator.login("mgmt1")
    assert sid == FULL_SID
    spans = {s.name: s for s in otel_spans.get_finished_spans()}
    login_span = next(s for n, s in spans.items() if n.endswith(".login"))
    assert login_span.attributes["arodonata.mgmt_name"] == "mgmt1"
    assert login_span.attributes["arodonata.domain"] == "system"


async def test_no_span_leaks_credentials_or_full_sid(otel_spans):
    coordinator = _coordinator_for_real_login(api_key=API_KEY, login_sid=FULL_SID)
    await coordinator.login("mgmt1")
    for span in otel_spans.get_finished_spans():
        blob = span.name + " " + " ".join(str(v) for v in span.attributes.values())
        assert API_KEY not in blob
        assert FULL_SID not in blob  # sid[:8] prefix would be fine; full SID never
