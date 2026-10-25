"""Bucket 1 — Authentication modes against the live MDSM.

Covers:
1. API key auth (``auth_mode == "api_key"``) at system level and domain level.
2. Username/password auth (``auth_mode == "credential"``) for ``admin`` and ``Eng1``.
3. Dynamic per-call auth via ``client.auth_context(username=..., password=...)`` on a client
   created with no static credentials (``auth_mode == "dynamic"``).
4. Dynamic ``client.auth_context(api_key=...)`` on a credentialless client.
5. Hybrid override: ``apikey_client`` temporarily executing under ``Eng2`` via ``auth_context``
   inside ``create_dedicated_session``.
6. Invalid credentials fail fast with ``InvalidCredentialsError`` without waiting 70s for
   the login-throttle backoff.
"""

from __future__ import annotations

import os
import time

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from arodonata import (
    ArodonataClient,
    ArodonataSettings,
    InvalidCredentialsError,
    MissingConfigurationError,
)


async def test_api_key_auth_system_and_domain(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify API key authentication at both MDS system level and domain level."""
    assert apikey_client.settings.auth_mode == "api_key"

    sys_res = await apikey_client.api_call(mgmt_name, "show-session", {})
    assert sys_res.success, sys_res.error_message
    assert sys_res.data.get("domain", {}).get("name") == "System Data"

    dom_res = await apikey_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    assert dom_res.success, dom_res.error_message
    assert dom_res.data.get("domain", {}).get("name") == test_domain_a


async def test_credential_auth_admin_and_engineer(
    admin_client: ArodonataClient,
    eng1_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify static username/password authentication for admin and Eng1."""
    assert admin_client.settings.auth_mode == "credential"
    assert eng1_client.settings.auth_mode == "credential"

    r_admin = await admin_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    assert r_admin.success, r_admin.error_message
    assert r_admin.data.get("user-name") == "admin"

    r_eng1 = await eng1_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
    assert r_eng1.success, r_eng1.error_message
    assert r_eng1.data.get("user-name") == "eng1"


async def test_dynamic_auth_context_username_password(
    mgmt_name: str,
    mgmt_ip: str,
    test_domain_a: str,
    db_engine: AsyncEngine,
) -> None:
    """Client with no static credentials authenticates via ``client.auth_context(username, password)``."""
    eng2_pwd = os.environ["USER_Eng2"]
    cfg = ArodonataSettings(mgmt_names=[mgmt_name], mgmt_servers=[mgmt_ip])
    assert cfg.auth_mode == "dynamic"

    client = ArodonataClient(settings=cfg, engine=db_engine)
    await client.initialize(run_startup_cleanup=False)
    try:
        # Without auth_context, creating a dedicated session must fail with MissingConfigurationError
        with pytest.raises(MissingConfigurationError):
            await client.create_dedicated_session(mgmt_name, domain=test_domain_a)

        with client.auth_context(username="eng2", password=eng2_pwd):
            sid, server_ip = await client.create_dedicated_session(mgmt_name, domain=test_domain_a)
            try:
                res = await client.api_call(
                    mgmt_name,
                    "show-session",
                    {},
                    domain=test_domain_a,
                    sid=sid,
                    server_ip=server_ip,
                )
                assert res.success
                assert res.data.get("user-name") == "eng2"
            finally:
                await client.logout_sid(mgmt_name, sid, server_ip=server_ip)
    finally:
        await client.close(logout=False)


async def test_dynamic_auth_context_api_key(
    mgmt_name: str,
    mgmt_ip: str,
    api_key: str,
    test_domain_a: str,
    db_engine: AsyncEngine,
) -> None:
    """Credentialless client authenticates via ``client.auth_context(api_key=...)``."""
    cfg = ArodonataSettings(mgmt_names=[mgmt_name], mgmt_servers=[mgmt_ip])
    client = ArodonataClient(settings=cfg, engine=db_engine)
    await client.initialize(run_startup_cleanup=False)
    try:
        with client.auth_context(api_key=api_key):
            sid, server_ip = await client.create_dedicated_session(mgmt_name, domain=test_domain_a)
            try:
                res = await client.api_call(
                    mgmt_name,
                    "show-session",
                    {},
                    domain=test_domain_a,
                    sid=sid,
                    server_ip=server_ip,
                )
                assert res.success
                assert res.data.get("domain", {}).get("name") == test_domain_a
            finally:
                await client.logout_sid(mgmt_name, sid, server_ip=server_ip)
    finally:
        await client.close(logout=False)


async def test_hybrid_override_on_apikey_client(
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """``auth_context`` overrides static ``api_key`` for ``create_dedicated_session``."""
    eng3_pwd = os.environ["USER_Eng3"]
    with apikey_client.auth_context(username="eng3", password=eng3_pwd):
        sid, server_ip = await apikey_client.create_dedicated_session(mgmt_name, domain=test_domain_a)
        try:
            res = await apikey_client.api_call(
                mgmt_name,
                "show-session",
                {},
                domain=test_domain_a,
                sid=sid,
                server_ip=server_ip,
            )
            assert res.success
            assert res.data.get("user-name") == "eng3"
        finally:
            await apikey_client.logout_sid(mgmt_name, sid, server_ip=server_ip)


async def test_invalid_credentials_fail_fast(
    mgmt_name: str,
    mgmt_ip: str,
    test_domain_a: str,
    db_engine: AsyncEngine,
) -> None:
    """Wrong password must raise ``InvalidCredentialsError`` immediately (no 70s throttle wait)."""
    cfg = ArodonataSettings(
        mgmt_name=mgmt_name,
        mgmt_ip=mgmt_ip,
        username="eng4",
        password="definitely-wrong-password-000",
    )
    bad_client = ArodonataClient(settings=cfg, engine=db_engine)
    await bad_client.initialize(run_startup_cleanup=False)
    t0 = time.monotonic()
    try:
        with pytest.raises(InvalidCredentialsError):
            await bad_client.create_dedicated_session(mgmt_name, domain=test_domain_a)
        elapsed = time.monotonic() - t0
        assert elapsed < 30.0, f"Invalid credentials took {elapsed:.1f}s (should not retry)"
    finally:
        await bad_client.close(logout=False)
