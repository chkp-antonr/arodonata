"""Unit tests for LoginCoordinator (auth mode, domain normalization, cache keying,
keepalive, logout, prefetch, login orchestration).

Retry/backoff and max-sessions cleanup paths live in
``test_login_coordinator_retry.py``.

Offline only: transport/APIClient seam is mocked, no network, no real sleeps.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from arodonata.asdk.login_coordinator import LoginCoordinator
from arodonata.asdk.server_registry import ServerConfig
from arodonata.core.exceptions import AuthenticationError, ThrottlingError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(*, auth_mode="api_key", username=None, password=None):
    settings = MagicMock()
    settings.login_max_retries = 3
    settings.login_retry_backoff = 1
    settings.session_expire_seconds = 3600
    settings.session_timeout = 600
    settings.auth_mode = auth_mode
    settings.username = username
    settings.password = password
    return settings


def _make_rate_limiter():
    rl = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=None)
    cm.__aexit__ = AsyncMock(return_value=False)
    rl.acquire = MagicMock(return_value=cm)
    return rl


def _make_lock_manager():
    lm = MagicMock()
    lm.DEFAULT_TTL_LOGIN = 90
    lm.initialize = AsyncMock()
    lm.close = AsyncMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=None)
    cm.__aexit__ = AsyncMock(return_value=False)
    lm.acquire = MagicMock(return_value=cm)
    return lm


def _make_coordinator(
    *,
    settings=None,
    registry=None,
    transport=None,
    cache=None,
    rate_limiter=None,
    lock_manager=None,
    session_cleaner=None,
):
    return LoginCoordinator(
        registry=registry or MagicMock(),
        transport=transport or AsyncMock(),
        rate_limiter=rate_limiter or _make_rate_limiter(),
        cache=cache or AsyncMock(),
        settings=settings or _make_settings(),
        lock_manager=lock_manager,
        session_cleaner=session_cleaner,
    )


def _sid_record(*, sid="sid-1", uid="uid-1", server_ip="10.0.0.1", created_at=None):
    rec = MagicMock()
    rec.sid = sid
    rec.uid = uid
    rec.server_ip = server_ip
    rec.created_at = created_at or datetime.now(UTC).replace(tzinfo=None)
    return rec


# ---------------------------------------------------------------------------
# Auth mode selection / _credential_username
# ---------------------------------------------------------------------------


def test_credential_username_none_in_apikey_mode():
    coord = _make_coordinator(settings=_make_settings(auth_mode="api_key", username="ignored"))
    assert coord._credential_username is None


def test_credential_username_returns_username_in_credential_mode():
    coord = _make_coordinator(settings=_make_settings(auth_mode="credential", username="svc-user"))
    assert coord._credential_username == "svc-user"


def test_init_records_auth_mode_and_password_secret():
    secret = SecretStr("pw")
    coord = _make_coordinator(settings=_make_settings(auth_mode="credential", username="u", password=secret))
    assert coord._auth_mode == "credential"
    assert coord._username == "u"
    assert coord._password_secret is secret


# ---------------------------------------------------------------------------
# _normalize_domain
# ---------------------------------------------------------------------------


def _coord_with_server(is_mdm):
    server = ServerConfig(name="mgmt1", server_ip="1.2.3.4", api_key=SecretStr("k"), is_mdm=is_mdm)
    registry = MagicMock()
    registry.get_server.return_value = server
    return _make_coordinator(registry=registry)


@pytest.mark.parametrize("is_mdm", [False, None])
def test_smc_user_normalized_when_not_mdm(is_mdm):
    coord = _coord_with_server(is_mdm)
    assert coord._normalize_domain("mgmt1", "SMC User") == ""


@pytest.mark.parametrize("alias", ["SMC User", "smc user", "SMC USER"])
def test_smc_user_case_insensitive(alias):
    coord = _coord_with_server(is_mdm=False)
    assert coord._normalize_domain("mgmt1", alias) == ""


def test_smc_user_not_normalized_on_mdm():
    coord = _coord_with_server(is_mdm=True)
    assert coord._normalize_domain("mgmt1", "SMC User") == "SMC User"


@pytest.mark.parametrize("is_mdm", [True, None])
def test_system_data_normalized_when_mdm_or_unknown(is_mdm):
    coord = _coord_with_server(is_mdm)
    assert coord._normalize_domain("mgmt1", "System Data") == ""


def test_system_data_not_normalized_on_smartcenter():
    coord = _coord_with_server(is_mdm=False)
    assert coord._normalize_domain("mgmt1", "System Data") == "System Data"


@pytest.mark.parametrize("is_mdm", [True, False, None])
@pytest.mark.parametrize("domain", ["General", "CPCodeOps", ""])
def test_regular_domains_pass_through(is_mdm, domain):
    coord = _coord_with_server(is_mdm)
    assert coord._normalize_domain("mgmt1", domain) == domain


def test_unknown_server_returns_domain_unchanged():
    registry = MagicMock()
    registry.get_server.return_value = None
    coord = _make_coordinator(registry=registry)
    assert coord._normalize_domain("unknown", "SMC User") == "SMC User"


def test_empty_domain_returns_empty_without_registry_lookup():
    registry = MagicMock()
    coord = _make_coordinator(registry=registry)
    assert coord._normalize_domain("mgmt1", "") == ""
    registry.get_server.assert_not_called()


# ---------------------------------------------------------------------------
# _split_key (cache key parse) and _get_lock_key
# ---------------------------------------------------------------------------


def test_split_key_mgmt_and_domain():
    assert LoginCoordinator._split_key("mgmt1:General") == ("mgmt1", "General", None)


def test_split_key_system_domain_empty():
    assert LoginCoordinator._split_key("mgmt1:") == ("mgmt1", "", None)


def test_split_key_with_username_credential_mode():
    assert LoginCoordinator._split_key("mgmt1:General:svc") == ("mgmt1", "General", "svc")


def test_split_key_username_with_empty_domain():
    assert LoginCoordinator._split_key("mgmt1::svc") == ("mgmt1", "", "svc")


def test_split_key_only_mgmt():
    assert LoginCoordinator._split_key("mgmt1") == ("mgmt1", "", None)


def test_get_lock_key_format_system_domain():
    coord = _coord_with_server(is_mdm=False)
    assert coord._get_lock_key("mgmt1", "SMC User") == "login:mgmt1:"


def test_get_lock_key_format_regular_domain():
    coord = _coord_with_server(is_mdm=False)
    assert coord._get_lock_key("mgmt1", "General") == "login:mgmt1:General"


# ---------------------------------------------------------------------------
# close / _get_lock_manager
# ---------------------------------------------------------------------------


async def test_close_closes_lock_manager_and_clears_locks():
    lm = _make_lock_manager()
    coord = _make_coordinator(lock_manager=lm)
    coord._in_process_locks["k"] = MagicMock()

    await coord.close()

    assert coord._closed is True
    lm.close.assert_awaited_once()
    assert coord._in_process_locks == {}


async def test_close_idempotent():
    lm = _make_lock_manager()
    coord = _make_coordinator(lock_manager=lm)
    await coord.close()
    await coord.close()
    lm.close.assert_awaited_once()


async def test_get_lock_manager_returns_existing():
    lm = _make_lock_manager()
    coord = _make_coordinator(lock_manager=lm)
    got = await coord._get_lock_manager()
    assert got is lm
    lm.initialize.assert_not_called()


async def test_get_lock_manager_global_none_raises(monkeypatch):
    coord = _make_coordinator(lock_manager=None)

    async def _none():
        return None

    import arodonata.cache as cache_mod

    monkeypatch.setattr(cache_mod, "_get_global_lock_manager", _none, raising=False)

    with pytest.raises(RuntimeError, match="Failed to initialize"):
        await coord._get_lock_manager()


async def test_get_lock_manager_initializes_global(monkeypatch):
    coord = _make_coordinator(lock_manager=None)
    lm = _make_lock_manager()

    async def _global():
        return lm

    import arodonata.cache as cache_mod

    monkeypatch.setattr(cache_mod, "_get_global_lock_manager", _global, raising=False)

    got = await coord._get_lock_manager()
    assert got is lm
    lm.initialize.assert_awaited_once()


# ---------------------------------------------------------------------------
# _execute_login_request (auth mode dispatch + session_timeout forwarding)
# ---------------------------------------------------------------------------


async def test_execute_login_request_apikey_mode_forwards_session_timeout():
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": True, "sid": "s"}
    coord = _make_coordinator(transport=transport)

    await coord._execute_login_request(
        "mgmt1",
        "General",
        "10.0.0.1",
        "api-key-1234",
        port=4434,
        session_name="n",
        session_description="d",
        session_timeout=900,
    )

    transport.login_with_apikey.assert_awaited_once_with(
        server_ip="10.0.0.1",
        api_key="api-key-1234",
        domain="General",
        port=4434,
        session_name="n",
        session_description="d",
        session_timeout=900,
    )
    transport.login_with_credentials.assert_not_called()


async def test_execute_login_request_empty_domain_passes_none():
    transport = AsyncMock()
    coord = _make_coordinator(transport=transport)
    await coord._execute_login_request("mgmt1", "", "10.0.0.1", "key")
    assert transport.login_with_apikey.await_args.kwargs["domain"] is None


async def test_execute_login_request_credential_mode_uses_credentials():
    transport = AsyncMock()
    secret = MagicMock()
    secret.get_secret_value.return_value = "pw"
    coord = _make_coordinator(
        settings=_make_settings(auth_mode="credential", username="svc", password=secret),
        transport=transport,
    )

    await coord._execute_login_request(
        "mgmt1",
        "General",
        "10.0.0.1",
        "ignored-key",
        session_timeout=120,
    )

    transport.login_with_credentials.assert_awaited_once_with(
        server_ip="10.0.0.1",
        username="svc",
        password="pw",
        domain="General",
        port=None,
        session_name=None,
        session_description=None,
        session_timeout=120,
    )
    transport.login_with_apikey.assert_not_called()


# ---------------------------------------------------------------------------
# _parse_login_response / _extract_uid_from_response
# ---------------------------------------------------------------------------


def test_parse_login_response_success_returns_sid_uid():
    coord = _make_coordinator()
    resp = {"success": True, "sid": "the-sid", "data": {"uid": "u-9"}}
    assert coord._parse_login_response(resp, "m", "d", "ip", "key") == ("the-sid", "u-9")


def test_parse_login_response_throttle_raises_throttling():
    coord = _make_coordinator()
    resp = {"success": False, "code": "err_too_many_requests", "message": "slow down"}
    with pytest.raises(ThrottlingError):
        coord._parse_login_response(resp, "m", "d", "ip", "key")


def test_parse_login_response_failure_raises_auth_error():
    coord = _make_coordinator()
    resp = {"success": False, "code": "generic_err", "message": "bad key", "data": {}}
    with pytest.raises(AuthenticationError, match="bad key"):
        coord._parse_login_response(resp, "m", "d", "ip", "key")


def test_parse_login_response_failure_default_message():
    coord = _make_coordinator()
    with pytest.raises(AuthenticationError, match="Unknown login error"):
        coord._parse_login_response({"success": False}, "m", "d", "ip", "")


def test_extract_uid_present():
    coord = _make_coordinator()
    assert coord._extract_uid_from_response({"data": {"uid": 42}}) == "42"


def test_extract_uid_absent():
    coord = _make_coordinator()
    assert coord._extract_uid_from_response({"data": {}}) is None
    assert coord._extract_uid_from_response({}) is None


# ---------------------------------------------------------------------------
# _raise_as_auth_error
# ---------------------------------------------------------------------------


def test_raise_as_auth_error_apikey_mode():
    coord = _make_coordinator()
    with pytest.raises(AuthenticationError, match="Login failed after 3 attempts"):
        coord._raise_as_auth_error(ValueError("boom"), "m", "d")


def test_raise_as_auth_error_credential_mode():
    coord = _make_coordinator(settings=_make_settings(auth_mode="credential", username="u"))
    with pytest.raises(AuthenticationError, match="Credential authentication failed"):
        coord._raise_as_auth_error(ValueError("boom"), "m", "d")


# ---------------------------------------------------------------------------
# _fire_keepalive
# ---------------------------------------------------------------------------


async def test_fire_keepalive_success_updates_cache():
    transport = AsyncMock()
    transport.keepalive.return_value = {"success": True}
    cache = AsyncMock()
    coord = _make_coordinator(transport=transport, cache=cache)

    await coord._fire_keepalive("mgmt1", "", "sid-x", "10.0.0.1", None)

    transport.keepalive.assert_awaited_once_with("10.0.0.1", "sid-x", None)
    cache.update_keepalive.assert_awaited_once_with("mgmt1", "", username=None)


async def test_fire_keepalive_credential_username_forwarded():
    transport = AsyncMock()
    cache = AsyncMock()
    coord = _make_coordinator(transport=transport, cache=cache)
    await coord._fire_keepalive("mgmt1", "General", "sid", "10.0.0.1", 4434, username="svc")
    cache.update_keepalive.assert_awaited_once_with("mgmt1", "General", username="svc")


async def test_fire_keepalive_failure_evicts_sid():
    transport = AsyncMock()
    transport.keepalive.side_effect = Exception("Session expired")
    cache = AsyncMock()
    coord = _make_coordinator(transport=transport, cache=cache)

    await coord._fire_keepalive("mgmt1", "", "dead", "10.0.0.1", None)

    cache.delete_sid.assert_awaited_once_with("mgmt1", "", username=None)
    cache.update_keepalive.assert_not_called()


async def test_fire_keepalive_eviction_failure_swallowed():
    transport = AsyncMock()
    transport.keepalive.side_effect = Exception("ka fail")
    cache = AsyncMock()
    cache.delete_sid.side_effect = Exception("delete fail")
    coord = _make_coordinator(transport=transport, cache=cache)

    # Must not raise
    await coord._fire_keepalive("mgmt1", "", "dead", "10.0.0.1", None)


# ---------------------------------------------------------------------------
# maintain_keepalives
# ---------------------------------------------------------------------------


async def test_maintain_keepalives_fires_for_all_stale():
    from arodonata.cache.models import SIDCache

    cache = AsyncMock()
    cache.list_stale_keepalives.return_value = [
        SIDCache(mgmt_dmn_key="mgmt1:", sid="a", server_ip="10.0.0.1"),
        SIDCache(mgmt_dmn_key="mgmt2:dmn1", sid="b", server_ip="10.0.0.2"),
    ]
    transport = AsyncMock()
    transport.keepalive.return_value = {"success": True}
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(port=None)

    coord = _make_coordinator(transport=transport, cache=cache, registry=registry)
    await coord.maintain_keepalives()

    assert transport.keepalive.await_count == 2


async def test_maintain_keepalives_excludes_key():
    from arodonata.cache.models import SIDCache

    cache = AsyncMock()
    cache.list_stale_keepalives.return_value = [
        SIDCache(mgmt_dmn_key="mgmt1:", sid="a", server_ip="10.0.0.1"),
        SIDCache(mgmt_dmn_key="mgmt2:", sid="b", server_ip="10.0.0.2"),
    ]
    transport = AsyncMock()
    transport.keepalive.return_value = {"success": True}
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(port=None)

    coord = _make_coordinator(transport=transport, cache=cache, registry=registry)
    await coord.maintain_keepalives(exclude_key="mgmt1:")

    assert transport.keepalive.await_count == 1
    assert transport.keepalive.await_args.args[1] == "b"


async def test_maintain_keepalives_parses_credential_key_for_username():
    from arodonata.cache.models import SIDCache

    cache = AsyncMock()
    cache.list_stale_keepalives.return_value = [
        SIDCache(mgmt_dmn_key="mgmt1:General:svc", sid="a", server_ip="10.0.0.1"),
    ]
    transport = AsyncMock()
    transport.keepalive.return_value = {"success": True}
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(port=4434)

    coord = _make_coordinator(transport=transport, cache=cache, registry=registry)
    await coord.maintain_keepalives()

    cache.update_keepalive.assert_awaited_once_with("mgmt1", "General", username="svc")


async def test_maintain_keepalives_list_error_returns_quietly():
    cache = AsyncMock()
    cache.list_stale_keepalives.side_effect = Exception("db down")
    coord = _make_coordinator(cache=cache)
    await coord.maintain_keepalives()  # must not raise


async def test_maintain_keepalives_no_stale_no_tasks():
    cache = AsyncMock()
    cache.list_stale_keepalives.return_value = []
    transport = AsyncMock()
    coord = _make_coordinator(cache=cache, transport=transport)
    await coord.maintain_keepalives()
    transport.keepalive.assert_not_called()


# ---------------------------------------------------------------------------
# logout / logout_all
# ---------------------------------------------------------------------------


async def test_logout_success_deletes_from_cache():
    cache = AsyncMock()
    cache.get_sid.return_value = _sid_record(sid="s", server_ip="10.0.0.1")
    transport = AsyncMock()
    transport.logout.return_value = {"success": True}
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(port=4434)

    coord = _make_coordinator(cache=cache, transport=transport, registry=registry)
    result = await coord.logout("mgmt1", "General")

    assert result is True
    transport.logout.assert_awaited_once_with("10.0.0.1", "s", port=4434)
    cache.delete_sid.assert_awaited_once_with("mgmt1", "General", username=None)


async def test_logout_no_cached_returns_true():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    transport = AsyncMock()
    coord = _make_coordinator(cache=cache, transport=transport)

    assert await coord.logout("mgmt1", "General") is True
    transport.logout.assert_not_called()


async def test_logout_transport_error_still_clears_cache():
    cache = AsyncMock()
    cache.get_sid.return_value = _sid_record(sid="s")
    transport = AsyncMock()
    transport.logout.side_effect = Exception("network")
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(port=None)

    coord = _make_coordinator(cache=cache, transport=transport, registry=registry)
    result = await coord.logout("mgmt1", "General")

    assert result is False
    cache.delete_sid.assert_awaited_once()


async def test_logout_credential_mode_scopes_by_username():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    coord = _make_coordinator(
        settings=_make_settings(auth_mode="credential", username="svc"),
        cache=cache,
    )
    await coord.logout("mgmt1", "General")
    cache.get_sid.assert_awaited_once_with("mgmt1", "General", username="svc")


async def test_logout_all_iterates_all_sessions():
    from arodonata.cache.models import SIDCache

    cache = AsyncMock()
    cache.list_all_sids.return_value = [
        SIDCache(mgmt_dmn_key="mgmt1:", sid="a", server_ip="10.0.0.1"),
        SIDCache(mgmt_dmn_key="mgmt2:General", sid="b", server_ip="10.0.0.2"),
    ]
    coord = _make_coordinator(cache=cache)
    coord.logout = AsyncMock(return_value=True)

    await coord.logout_all()

    assert coord.logout.await_count == 2
    coord.logout.assert_any_await("mgmt1", "")
    coord.logout.assert_any_await("mgmt2", "General")


# ---------------------------------------------------------------------------
# _extract_active_server_ip / _cache_domain_active_ip
# ---------------------------------------------------------------------------


def test_extract_active_server_ip_found():
    coord = _make_coordinator()
    obj = {
        "servers": [
            {"active": False, "ipv4-address": "10.0.0.1"},
            {"active": True, "ipv4-address": "10.0.0.9"},
        ]
    }
    assert coord._extract_active_server_ip(obj) == "10.0.0.9"


def test_extract_active_server_ip_no_active():
    coord = _make_coordinator()
    assert coord._extract_active_server_ip({"servers": [{"active": False, "ipv4-address": "x"}]}) == ""


def test_extract_active_server_ip_servers_not_list():
    coord = _make_coordinator()
    assert coord._extract_active_server_ip({"servers": "nope"}) == ""


async def test_cache_domain_active_ip_found_caches_and_returns():
    cache = AsyncMock()
    coord = _make_coordinator(cache=cache)
    domains = [
        {
            "name": "General",
            "uid": "uid-d",
            "servers": [{"active": True, "ipv4-address": "10.0.0.9"}],
        }
    ]

    ip = await coord._cache_domain_active_ip("mgmt1", "General", domains, "10.0.0.1", is_mdm=True)

    assert ip == "10.0.0.9"
    cache.upsert_domain.assert_awaited_once()


async def test_cache_domain_active_ip_not_found_returns_default_no_cache():
    cache = AsyncMock()
    coord = _make_coordinator(cache=cache)
    ip = await coord._cache_domain_active_ip("mgmt1", "Missing", [{"name": "Other"}], "10.0.0.1")
    assert ip == "10.0.0.1"
    cache.upsert_domain.assert_not_called()


# ---------------------------------------------------------------------------
# _prefetch_domain_server_ip
# ---------------------------------------------------------------------------


async def test_prefetch_uses_cached_active_ip():
    cache = AsyncMock()
    cache.get_domain.return_value = MagicMock(active_ip="10.0.0.5")
    coord = _make_coordinator(cache=cache)

    ip = await coord._prefetch_domain_server_ip("mgmt1", "General")
    assert ip == "10.0.0.5"


async def test_prefetch_unknown_server_raises():
    cache = AsyncMock()
    cache.get_domain.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = None
    coord = _make_coordinator(cache=cache, registry=registry)

    with pytest.raises(ValueError, match="Unknown management server"):
        await coord._prefetch_domain_server_ip("mgmt1", "General")


async def test_prefetch_fetches_from_api_and_caches():
    cache = AsyncMock()
    cache.get_domain.return_value = None
    registry = MagicMock()
    server_config = MagicMock(server_ip="10.0.0.1", port=4434, is_mdm=True)
    registry.get_server.return_value = server_config
    transport = AsyncMock()
    transport.api_call.return_value = {
        "success": True,
        "data": {
            "objects": [{"name": "General", "uid": "u", "servers": [{"active": True, "ipv4-address": "10.0.0.9"}]}]
        },
    }
    coord = _make_coordinator(cache=cache, registry=registry, transport=transport)
    coord.login = AsyncMock(return_value=("sys-sid", "10.0.0.1"))

    ip = await coord._prefetch_domain_server_ip("mgmt1", "General")

    assert ip == "10.0.0.9"
    coord.login.assert_awaited()


async def test_prefetch_api_failure_returns_primary_ip():
    cache = AsyncMock()
    cache.get_domain.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", port=None, is_mdm=False)
    transport = AsyncMock()
    transport.api_call.return_value = {"success": False, "message": "nope"}
    coord = _make_coordinator(cache=cache, registry=registry, transport=transport)
    coord.login = AsyncMock(return_value=("sys-sid", "10.0.0.1"))

    ip = await coord._prefetch_domain_server_ip("mgmt1", "General")
    assert ip == "10.0.0.1"


async def test_prefetch_no_data_returns_primary_ip():
    cache = AsyncMock()
    cache.get_domain.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", port=None, is_mdm=False)
    transport = AsyncMock()
    transport.api_call.return_value = {"success": True, "data": None}
    coord = _make_coordinator(cache=cache, registry=registry, transport=transport)
    coord.login = AsyncMock(return_value=("sys-sid", "10.0.0.1"))

    ip = await coord._prefetch_domain_server_ip("mgmt1", "General")
    assert ip == "10.0.0.1"


async def test_prefetch_retries_on_session_error_then_succeeds():
    cache = AsyncMock()
    cache.get_domain.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", port=None, is_mdm=False)
    transport = AsyncMock()
    transport.api_call.side_effect = [
        {"code": "generic_err_session_expired", "success": False},
        {
            "success": True,
            "data": [{"name": "General", "uid": "u", "servers": [{"active": True, "ipv4-address": "10.0.0.9"}]}],
        },
    ]
    coord = _make_coordinator(cache=cache, registry=registry, transport=transport)
    coord.login = AsyncMock(return_value=("sys-sid", "10.0.0.1"))

    ip = await coord._prefetch_domain_server_ip("mgmt1", "General")

    assert ip == "10.0.0.9"
    # Force relogin was triggered by the session error retry
    assert coord.login.await_count == 2


async def test_prefetch_data_dict_without_objects_key():
    cache = AsyncMock()
    cache.get_domain.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", port=None, is_mdm=False)
    transport = AsyncMock()
    transport.api_call.return_value = {"success": True, "data": {"total": 0}}
    coord = _make_coordinator(cache=cache, registry=registry, transport=transport)
    coord.login = AsyncMock(return_value=("sys-sid", "10.0.0.1"))

    ip = await coord._prefetch_domain_server_ip("mgmt1", "General")
    # domain not present in empty objects -> default primary
    assert ip == "10.0.0.1"


# ---------------------------------------------------------------------------
# _acquire_new_sid
# ---------------------------------------------------------------------------


async def test_acquire_new_sid_post_lock_cache_hit():
    cache = AsyncMock()
    cache.get_sid.return_value = _sid_record(sid="cached", server_ip="10.0.0.1")
    coord = _make_coordinator(cache=cache)
    coord._perform_login = AsyncMock()

    entry = datetime.now(UTC).replace(tzinfo=None)
    sid, ip = await coord._acquire_new_sid("mgmt1", "", False, entry, None, None, None)

    assert (sid, ip) == ("cached", "10.0.0.1")
    coord._perform_login.assert_not_called()


async def test_acquire_new_sid_force_but_newer_cache_returns_cached():
    entry = datetime.now(UTC).replace(tzinfo=None)
    newer = entry + timedelta(seconds=5)
    cache = AsyncMock()
    cache.get_sid.return_value = _sid_record(sid="cached", server_ip="10.0.0.1", created_at=newer)
    coord = _make_coordinator(cache=cache)
    coord._perform_login = AsyncMock()

    sid, ip = await coord._acquire_new_sid("mgmt1", "", True, entry, None, None, None)

    assert sid == "cached"
    coord._perform_login.assert_not_called()


async def test_acquire_new_sid_unknown_server_raises():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = None
    coord = _make_coordinator(cache=cache, registry=registry)

    entry = datetime.now(UTC).replace(tzinfo=None)
    with pytest.raises(ValueError, match="Unknown management server"):
        await coord._acquire_new_sid("mgmt1", "", False, entry, None, None, None)


async def test_acquire_new_sid_login_and_cache():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=4434)
    coord = _make_coordinator(cache=cache, registry=registry)
    coord._perform_login = AsyncMock(return_value=("new-sid", "uid-1"))

    entry = datetime.now(UTC).replace(tzinfo=None)
    sid, ip = await coord._acquire_new_sid("mgmt1", "", False, entry, None, None, None)

    assert (sid, ip) == ("new-sid", "10.0.0.1")
    cache.set_sid.assert_awaited_once_with("mgmt1", "", "new-sid", "10.0.0.1", "uid-1", username=None)


async def test_acquire_new_sid_uses_prefetched_server_ip():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(cache=cache, registry=registry)
    coord._perform_login = AsyncMock(return_value=("new-sid", None))

    entry = datetime.now(UTC).replace(tzinfo=None)
    sid, ip = await coord._acquire_new_sid("mgmt1", "General", False, entry, "10.0.0.99", None, None)

    assert ip == "10.0.0.99"


async def test_acquire_new_sid_cache_store_error_swallowed():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    cache.set_sid.side_effect = Exception("store fail")
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    coord = _make_coordinator(cache=cache, registry=registry)
    coord._perform_login = AsyncMock(return_value=("new-sid", "uid"))

    entry = datetime.now(UTC).replace(tzinfo=None)
    sid, ip = await coord._acquire_new_sid("mgmt1", "", False, entry, None, None, None)
    assert sid == "new-sid"  # returned despite cache error


# ---------------------------------------------------------------------------
# login (orchestration + locking)
# ---------------------------------------------------------------------------


async def test_login_pre_lock_cache_hit_returns_without_lock():
    cache = AsyncMock()
    cache.get_sid.return_value = _sid_record(sid="cached", server_ip="10.0.0.1")
    lm = _make_lock_manager()
    coord = _make_coordinator(cache=cache, lock_manager=lm)
    coord._acquire_new_sid = AsyncMock()

    sid, ip = await coord.login("mgmt1", "")

    assert (sid, ip) == ("cached", "10.0.0.1")
    lm.acquire.assert_not_called()
    coord._acquire_new_sid.assert_not_called()


async def test_login_cache_miss_acquires_lock_and_calls_acquire_new_sid():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    lm = _make_lock_manager()
    coord = _make_coordinator(cache=cache, lock_manager=lm)
    coord._acquire_new_sid = AsyncMock(return_value=("new-sid", "10.0.0.1"))

    sid, ip = await coord.login("mgmt1", "")

    assert (sid, ip) == ("new-sid", "10.0.0.1")
    lm.acquire.assert_called_once()
    coord._acquire_new_sid.assert_awaited_once()


async def test_login_cache_mode_refresh_forces_login():
    cache = AsyncMock()
    cache.get_sid.return_value = _sid_record(sid="cached", server_ip="10.0.0.1")
    lm = _make_lock_manager()
    coord = _make_coordinator(cache=cache, lock_manager=lm)
    coord._acquire_new_sid = AsyncMock(return_value=("fresh", "10.0.0.1"))

    sid, _ip = await coord.login("mgmt1", "", cache_mode="refresh")

    # refresh forces skip of pre-lock cache hit
    assert sid == "fresh"
    coord._acquire_new_sid.assert_awaited_once()
    # force flag propagated
    assert coord._acquire_new_sid.await_args.args[2] is True


async def test_login_domain_prefetches_server_ip():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    lm = _make_lock_manager()
    registry = MagicMock()
    registry.get_server.return_value = ServerConfig(
        name="mgmt1", server_ip="1.2.3.4", api_key=SecretStr("k"), is_mdm=True
    )
    coord = _make_coordinator(cache=cache, lock_manager=lm, registry=registry)
    coord._prefetch_domain_server_ip = AsyncMock(return_value="10.0.0.9")
    coord._acquire_new_sid = AsyncMock(return_value=("s", "10.0.0.9"))

    await coord.login("mgmt1", "General")

    coord._prefetch_domain_server_ip.assert_awaited_once_with("mgmt1", "General", force=False)
    # prefetched ip forwarded to _acquire_new_sid
    assert coord._acquire_new_sid.await_args.args[4] == "10.0.0.9"


async def test_login_credential_mode_scopes_cache_by_username():
    cache = AsyncMock()
    cache.get_sid.return_value = None
    lm = _make_lock_manager()
    coord = _make_coordinator(
        settings=_make_settings(auth_mode="credential", username="svc"),
        cache=cache,
        lock_manager=lm,
    )
    coord._acquire_new_sid = AsyncMock(return_value=("s", "10.0.0.1"))

    await coord.login("mgmt1", "")

    # pre-lock cache lookup scoped by username
    assert cache.get_sid.await_args.kwargs["username"] == "svc"


# ---------------------------------------------------------------------------
# create_dedicated_session
# ---------------------------------------------------------------------------


async def test_create_dedicated_session_success():
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=4434)
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {
        "success": True,
        "sid": "ded-sid",
        "data": {"uid": "u"},
    }
    coord = _make_coordinator(registry=registry, transport=transport)

    sid, ip = await coord.create_dedicated_session("mgmt1", "", session_name="job-1")

    assert (sid, ip) == ("ded-sid", "10.0.0.1")


async def test_create_dedicated_session_unknown_server_raises():
    registry = MagicMock()
    registry.get_server.return_value = None
    coord = _make_coordinator(registry=registry)

    with pytest.raises(ValueError, match="Unknown management server"):
        await coord.create_dedicated_session("mgmt1", "")


async def test_create_dedicated_session_login_failure_raises():
    """A persistent failure (every attempt denied) still raises after retries are
    exhausted -- retry/backoff timing is neutralized via patched asyncio.sleep,
    see test_login_coordinator_retry.py for the retry-then-succeed case."""
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {"success": False, "message": "denied"}
    coord = _make_coordinator(registry=registry, transport=transport)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(AuthenticationError, match="denied"):
            await coord.create_dedicated_session("mgmt1", "")


async def test_create_dedicated_session_resolves_domain_ip():
    registry = MagicMock()
    registry.get_server.return_value = MagicMock(server_ip="10.0.0.1", api_key=SecretStr("key"), port=None)
    transport = AsyncMock()
    transport.login_with_apikey.return_value = {
        "success": True,
        "sid": "ded-sid",
        "data": {},
    }
    coord = _make_coordinator(registry=registry, transport=transport)
    coord._prefetch_domain_server_ip = AsyncMock(return_value="10.0.0.9")

    sid, ip = await coord.create_dedicated_session("mgmt1", "General")

    assert ip == "10.0.0.9"
    coord._prefetch_domain_server_ip.assert_awaited_once_with("mgmt1", "General")
