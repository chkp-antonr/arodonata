"""Unit and ASGI tests for MCP security guards (`StaticTokenVerifier`, `auth_mode="host"`, and DNS rebinding `421`/`403`)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from arodonata import ArodonataClient
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_user_context, user_context
from arodonata.core.errors import REDACTED_PLACEHOLDER, ConfigurationError
from arodonata.core.models.common import ApiCallResult, ApiQueryResult
from arodonata.core.telemetry import set_trace_modules
from arodonata.mcp import (
    ArodonataMCPSettings,
    MCPBearerAuthMiddleware,
    MCPOriginHostGuardMiddleware,
    MCPToolQuotaManager,
    StaticTokenVerifier,
    create_asgi_app,
    create_mcp_server,
    host_matches_allowed,
    origin_matches_allowed,
)
from arodonata.mcp import errors as mcp_errors
from arodonata.mcp.errors import mcp_tool_guard


@pytest.mark.spec("SCN-MCP-001-2")
@pytest.mark.asyncio
async def test_static_token_verifier_maps_env_var_name_to_client_id_without_logging_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: Static bearer token authentication maps token variable name (`TEAM_A_TOKEN`) to `client_id`
    and never logs the token secret.
    """
    mcp_settings = ArodonataMCPSettings(
        auth_mode="static",
        token_vars="TEAM_A_TOKEN,TEAM_B_TOKEN",
    )
    env = {
        "TEAM_A_TOKEN": "super-secret-team-a-token-value-111",
        "TEAM_B_TOKEN": "super-secret-team-b-token-value-222",
    }
    verifier = StaticTokenVerifier.from_settings(mcp_settings, environ=env)

    logged_events: list[tuple[str, dict[str, Any]]] = []

    def fake_info(msg: str, **kwargs: Any) -> None:
        logged_events.append((msg, kwargs))

    monkeypatch.setattr("arodonata.mcp.security.logger.info", fake_info)

    token_a = await verifier.verify_token("super-secret-team-a-token-value-111")
    assert token_a is not None
    assert token_a.client_id == "TEAM_A_TOKEN"
    assert token_a.token == REDACTED_PLACEHOLDER

    token_b = await verifier.verify_token("super-secret-team-b-token-value-222")
    assert token_b is not None
    assert token_b.client_id == "TEAM_B_TOKEN"

    invalid = await verifier.verify_token("wrong-token")
    assert invalid is None

    # Verify logs contain `client_id` ("TEAM_A_TOKEN", "TEAM_B_TOKEN") and NEVER the secret token string
    assert len(logged_events) == 2
    assert logged_events[0][1]["client_id"] == "TEAM_A_TOKEN"
    assert logged_events[1][1]["client_id"] == "TEAM_B_TOKEN"
    serialized_logs = repr(logged_events) + repr(verifier)
    assert "super-secret-team-a-token-value-111" not in serialized_logs
    assert "super-secret-team-b-token-value-222" not in serialized_logs


@pytest.mark.spec("SCN-MCP-001-4")
def test_host_auth_mode_disables_internal_token_verifier() -> None:
    """Scenario: Host authentication mode in embedded ASGI applications disables internal token verifier."""
    srv = create_mcp_server(auth_mode="host")
    assert srv._arodonata_token_verifier is None
    assert srv.settings.auth is None

    asgi_app = create_asgi_app(mcp_server=srv, auth_mode="host")
    assert asgi_app.token_verifier is None
    assert asgi_app.mcp_settings.auth_mode == "host"


@pytest.mark.spec("SCN-MCP-001-5")
def test_dns_rebinding_host_421_and_origin_403_protection() -> None:
    """Scenario: Unlisted `Host` header is rejected with HTTP `421` and unlisted `Origin` with HTTP `403`."""

    async def echo_endpoint(_request: Any) -> JSONResponse:
        uctx = get_user_context()
        return JSONResponse({"ok": True, "client_id": uctx.client_id if uctx else None})

    base_starlette = Starlette(routes=[Route("/mcp", echo_endpoint, methods=["GET", "POST"])])
    verifier = StaticTokenVerifier([("TEAM_A_TOKEN", "tok-a-val")])
    authed_app = MCPBearerAuthMiddleware(base_starlette, verifier=verifier)
    guarded_app = MCPOriginHostGuardMiddleware(
        authed_app,
        allowed_hosts=["127.0.0.1:*", "localhost:*"],
        allowed_origins=["http://localhost:*"],
        enabled=True,
    )

    with TestClient(guarded_app) as test_client:
        # 1. Unlisted Host -> HTTP 421 Misdirected Request
        res_bad_host = test_client.post(
            "/mcp",
            headers={"Host": "evil.attacker.internal:8000", "Authorization": "Bearer tok-a-val"},
        )
        assert res_bad_host.status_code == 421

        # 2. Listed Host, unlisted Origin -> HTTP 403 Forbidden
        res_bad_origin = test_client.post(
            "/mcp",
            headers={
                "Host": "localhost:8000",
                "Origin": "https://evil.attacker.example",
                "Authorization": "Bearer tok-a-val",
            },
        )
        assert res_bad_origin.status_code == 403

        # 3. Listed Host & Origin, missing Bearer token -> HTTP 401 Unauthorized
        res_no_auth = test_client.post(
            "/mcp",
            headers={"Host": "localhost:8000", "Origin": "http://localhost:3000"},
        )
        assert res_no_auth.status_code == 401

        # 4. Listed Host & Origin + valid Bearer token -> HTTP 200 and UserContext.client_id bound
        res_ok = test_client.post(
            "/mcp",
            headers={
                "Host": "localhost:8000",
                "Origin": "http://localhost:3000",
                "Authorization": "Bearer tok-a-val",
            },
        )
        assert res_ok.status_code == 200
        assert res_ok.json() == {"ok": True, "client_id": "TEAM_A_TOKEN"}


@pytest.mark.spec("SCN-MCP-001-5")
def test_create_asgi_app_enforces_host_421_and_origin_403() -> None:
    """`create_asgi_app` rejects unlisted `Host` with `421` and unlisted `Origin` with `403`."""
    asgi_app = create_asgi_app(
        auth_mode="host",
        allowed_hosts=["127.0.0.1:*", "localhost:*"],
        allowed_origins=["http://localhost:*"],
    )
    with TestClient(asgi_app) as client:
        r_host = client.post("/mcp", headers={"Host": "rebinding.evil.com"})
        assert r_host.status_code == 421

        r_origin = client.post(
            "/mcp",
            headers={"Host": "localhost:8000", "Origin": "http://evil.com"},
        )
        assert r_origin.status_code == 403


@pytest.mark.spec("SCN-MCP-001-2", "SCN-MCP-001-3", "SCN-MCP-001-5")
@pytest.mark.asyncio
async def test_base64_padded_tokens_jwt_fail_closed_and_wildcard_port_validation() -> None:
    """Adversarial test for C3 and W26:
    - Base64 token with trailing '=' padding in `ARODONATA_MCP_TOKENS` is kept whole under `token_1`
      (never split into `client_id=<secret_prefix>, secret="="`).
    - `create_mcp_server` and `create_asgi_app` raise `ConfigurationError` when `auth_mode='jwt'` and `token_verifier=None`.
    - `host_matches_allowed` and `origin_matches_allowed` reject non-numeric or out-of-range port suffixes on `:*`.
    """
    b64_token = "c2VjcmV0dG9rZW4xMjM0NTY3ODkwMTIzNDU2Nzg5MDEy=="
    mcp_settings = ArodonataMCPSettings(
        auth_mode="static",
        tokens=[b64_token],
    )
    verifier = StaticTokenVerifier.from_settings(mcp_settings)
    assert verifier.client_ids == ["token_1"]
    assert "c2VjcmV0" not in repr(verifier)

    # Full base64 token authenticates; single '=' is rejected!
    assert await verifier.verify_token("=") is None
    matched = await verifier.verify_token(b64_token)
    assert matched is not None
    assert matched.client_id == "token_1"

    # Embedded JWT mode without token_verifier fails closed immediately
    with pytest.raises(ConfigurationError, match="auth_mode='jwt'"):
        create_mcp_server(auth_mode="jwt", token_verifier=None)

    with pytest.raises(ConfigurationError, match="auth_mode='jwt'"):
        create_asgi_app(auth_mode="jwt", token_verifier=None)

    # Wildcard port validation rejects malformed ports
    assert host_matches_allowed("localhost:8000", ["localhost:*"]) is True
    assert host_matches_allowed("localhost:abc", ["localhost:*"]) is False
    assert host_matches_allowed("localhost:0", ["localhost:*"]) is False
    assert host_matches_allowed("localhost:70000", ["localhost:*"]) is False
    assert host_matches_allowed("localhost:8000:evil", ["localhost:*"]) is False

    assert origin_matches_allowed("http://localhost:3000", ["http://localhost:*"]) is True
    assert origin_matches_allowed("http://localhost:notaport", ["http://localhost:*"]) is False
    assert origin_matches_allowed("http://localhost:99999", ["http://localhost:*"]) is False


class _DummyJwtVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        return AccessToken(token=REDACTED_PLACEHOLDER, client_id="jwt_user", scopes=["mcp"])


@pytest.mark.spec("SCN-MCP-001-6")
def test_create_mcp_server_and_asgi_app_enforce_fail_closed_security_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-MCP-001-6: Both `create_mcp_server` and `create_asgi_app` fail closed on wildcards and unsafe `auth_mode='none'`."""
    # 1. Wildcard allowed_hosts or allowed_origins with DNS rebinding protection enabled fails across auth modes
    for mode in ("host", "static", "none"):
        with pytest.raises(ConfigurationError, match="Wildcard"):
            create_mcp_server(auth_mode=mode, allowed_hosts=["*"])
        with pytest.raises(ConfigurationError, match="Wildcard"):
            create_asgi_app(auth_mode=mode, allowed_origins=["https://*"])
        with pytest.raises(ConfigurationError, match="Wildcard"):
            create_mcp_server(auth_mode=mode, allowed_hosts=["*.corp.example"])

    # 2. Unsafe auth_mode="none" combinations fail closed unless allow_insecure_unauthenticated=True
    for bad_kwargs in (
        {"host": "0.0.0.0"},
        {"host": "::"},
        {"host": "10.0.0.10"},
        {"allow_write_api": True},
        {"cpcrud": True},
        {"allowed_hosts": ["*"], "enable_dns_rebinding_protection": False},
        {"allowed_origins": ["http://*"], "enable_dns_rebinding_protection": False},
    ):
        with pytest.raises(ConfigurationError, match="auth_mode='none'"):
            create_mcp_server(auth_mode="none", **bad_kwargs)
        with pytest.raises(ConfigurationError, match="auth_mode='none'"):
            create_asgi_app(auth_mode="none", **bad_kwargs)

    # 3. Safe loopback read-only auth_mode="none" works without opt-in
    for lb_host in ("127.0.0.1", "localhost", "::1"):
        srv = create_mcp_server(auth_mode="none", host=lb_host)
        app = create_asgi_app(mcp_server=srv)
        assert app.mcp_settings.host == lb_host

    # 4. Explicit opt-in logs SECURITY WARNING and permits unsafe auth_mode="none"
    warnings: list[str] = []
    monkeypatch.setattr("arodonata.mcp.config.logger.warning", lambda msg, **_kw: warnings.append(str(msg)))
    opt_app = create_asgi_app(
        auth_mode="none",
        host="0.0.0.0",
        allow_write_api=True,
        allow_insecure_unauthenticated=True,
    )
    assert opt_app.mcp_settings.allow_write_api is True
    assert any("allow_insecure_unauthenticated" in w for w in warnings)


@pytest.mark.spec("SCN-MCP-001-7")
def test_ipv6_issuer_url_formatting_and_create_asgi_app_parity() -> None:
    """SCN-MCP-001-7: IPv6 hosts bracket cleanly in `AuthSettings.issuer_url` and `create_asgi_app(mcp_server=...)` prevents split-brain drift."""
    env = {"TEAM_A_TOKEN": "super-secret-ipv6-test-token-value-123456"}
    for host, expected_host_part in (("::1", "[::1]"), ("::", "[::]"), ("fe80::1", "[fe80::1]")):
        srv_static = create_mcp_server(auth_mode="static", host=host, port=8443, environ=env)
        assert srv_static.settings.auth is not None
        assert str(srv_static.settings.auth.issuer_url) == f"http://{expected_host_part}:8443/"

        srv_jwt = create_mcp_server(
            auth_mode="jwt",
            host=host,
            port=9000,
            token_verifier=_DummyJwtVerifier(),
        )
        assert srv_jwt.settings.auth is not None
        assert str(srv_jwt.settings.auth.issuer_url) == f"http://{expected_host_part}:9000/"

    # ASGI parity when injecting pre-built MCPServer
    srv_loopback_none = create_mcp_server(auth_mode="none", allow_write_api=False, cpcrud=False)

    # Rejects conflicting baked runtime overrides
    with pytest.raises(ConfigurationError, match="allow_write_api"):
        create_asgi_app(mcp_server=srv_loopback_none, allow_write_api=True)
    with pytest.raises(ConfigurationError, match="cpcrud"):
        create_asgi_app(mcp_server=srv_loopback_none, cpcrud=True)
    with pytest.raises(ConfigurationError, match="auth_mode"):
        create_asgi_app(mcp_server=srv_loopback_none, auth_mode="host")
    with pytest.raises(ConfigurationError, match="client"):
        create_asgi_app(
            client=ArodonataClient(ArodonataSettings(mgmt_name="m2", mgmt_ip="10.0.0.2", api_key="k")),
            mcp_server=srv_loopback_none,
        )
    with pytest.raises(ConfigurationError, match="settings"):
        create_asgi_app(
            settings=ArodonataSettings(mgmt_name="m2", mgmt_ip="10.0.0.2", api_key="k"), mcp_server=srv_loopback_none
        )
    with pytest.raises(ConfigurationError, match="token_verifier"):
        create_asgi_app(mcp_server=srv_loopback_none, token_verifier=_DummyJwtVerifier())
    with pytest.raises(ConfigurationError, match="quota_manager"):
        create_asgi_app(mcp_server=srv_loopback_none, quota_manager=MCPToolQuotaManager())
    with pytest.raises(ConfigurationError, match="mcp_settings.allow_write_api"):
        create_asgi_app(
            mcp_server=srv_loopback_none,
            mcp_settings=ArodonataMCPSettings(
                auth_mode="none", allow_write_api=True, allow_insecure_unauthenticated=True
            ),
        )

    # Enforces validate_security_policy() even when mcp_server is injected (e.g. overriding host to 0.0.0.0)
    with pytest.raises(ConfigurationError, match="auth_mode='none'"):
        create_asgi_app(mcp_server=srv_loopback_none, host="0.0.0.0")
    with pytest.raises(ConfigurationError, match="Wildcard"):
        create_asgi_app(mcp_server=srv_loopback_none, allowed_hosts=["*"])

    # Accepts identical baked values + compatible transport overrides
    app_ok = create_asgi_app(
        mcp_server=srv_loopback_none,
        auth_mode="none",
        allow_write_api=False,
        cpcrud=False,
        path="/custom-mcp",
    )
    assert app_ok.mcp_settings.path == "/custom-mcp"

    # External raw MCPServer without Arodonata metadata still validates security policy fail-closed
    raw_srv = MCPServer(name="external-raw")
    with pytest.raises(ConfigurationError, match="Wildcard"):
        create_asgi_app(mcp_server=raw_srv, auth_mode="host", allowed_hosts=["*"])


class _QuotaDummyApi:
    async def api_call(self, *_args: Any, **_kwargs: Any) -> ApiCallResult:
        return ApiCallResult(
            success=True,
            data={"objects": [{"uid": "dom-1", "name": "Corp", "type": "domain"}]},
        )

    async def api_query(self, *_args: Any, **_kwargs: Any) -> ApiQueryResult:
        return ApiQueryResult(success=True, objects=[], total=0)

    async def create_dedicated_session(self, *_args: Any, **_kwargs: Any) -> tuple[str, str]:
        return ("sid-q", "10.0.0.1")

    async def logout_sid(self, *_args: Any, **_kwargs: Any) -> bool:
        return True

    async def close(self, *, logout: bool | None = None) -> None:
        return None


@pytest.mark.spec("SCN-MCP-012-1")
@pytest.mark.asyncio
async def test_per_client_tool_quota_isolation_window_recovery_and_telemetry(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """SCN-MCP-012-1: Per-client sliding-window throttling isolates clients, separates live vs general quotas, recovers after window expiry, and leaks zero secrets."""
    clock = [100.0]

    def fake_monotonic() -> float:
        return clock[0]

    # 1. Unit tests on MCPToolQuotaManager directly
    qm = MCPToolQuotaManager(
        rate_limit_per_minute=3,
        live_rate_limit_per_minute=2,
        window_seconds=60.0,
        monotonic_fn=fake_monotonic,
    )
    # 2 live calls consume 2 live + 2 general slots
    assert qm.check_and_consume("TEAM_A", is_live=True).allowed is True
    assert qm.check_and_consume("TEAM_A", is_live=True).allowed is True
    # 3rd live call is rejected by live bucket WITHOUT consuming TEAM_A's remaining 3rd general slot
    live_rej = qm.check_and_consume("TEAM_A", is_live=True)
    assert live_rej.allowed is False
    assert live_rej.bucket == "live"
    assert live_rej.limit == 2
    assert live_rej.retry_after_seconds > 0
    # 3rd general (non-live) call still succeeds
    gen_last = qm.check_and_consume("TEAM_A", is_live=False)
    assert gen_last.allowed is True
    assert gen_last.remaining == 0
    # 4th general call is rejected
    gen_rej = qm.check_and_consume("TEAM_A", is_live=False)
    assert gen_rej.allowed is False
    assert gen_rej.bucket == "general"

    # TEAM_B and anonymous remain completely unaffected
    assert qm.check_and_consume("TEAM_B", is_live=True).allowed is True
    anon_dec = qm.check_and_consume(None, is_live=False)
    assert anon_dec.allowed is True
    assert anon_dec.client_id == "anonymous"

    # Advance monotonic clock past 60s window -> TEAM_A recovers cleanly
    clock[0] += 60.1
    assert qm.check_and_consume("TEAM_A", is_live=True).allowed is True

    # Disabled manager (0 limits) allows unrestricted calls without storing clients
    disabled_qm = MCPToolQuotaManager(rate_limit_per_minute=0, live_rate_limit_per_minute=0)
    assert disabled_qm.check_and_consume("TEAM_A", is_live=True).remaining == -1
    assert disabled_qm.check_and_consume("TEAM_A", is_live=True).allowed is True

    # 2. End-to-end integration through create_mcp_server + mcp_tool_guard + OTel + arlogi WARNING
    set_trace_modules(None)
    exporter = InMemorySpanExporter()
    proc = SimpleSpanProcessor(exporter)
    provider = trace.get_tracer_provider()
    if hasattr(provider, "add_span_processor"):
        provider.add_span_processor(proc)
    else:
        tp = TracerProvider()
        tp.add_span_processor(proc)
        trace.set_tracer_provider(tp)
    request.addfinalizer(proc.shutdown)
    exporter.clear()

    warn_logs: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(mcp_errors.logger, "warning", lambda msg, **kw: warn_logs.append((str(msg), dict(kw))))

    # Also test direct mcp_tool_guard with secret-like SID redaction if context were ever polluted
    @mcp_tool_guard(
        "dummy_guard_test",
        lambda: None,
        quota_manager=MCPToolQuotaManager(rate_limit_per_minute=1, monotonic_fn=fake_monotonic),
    )  # type: ignore[arg-type]
    async def _dummy_tool() -> CallToolResult:
        return CallToolResult(content=[TextContent(type="text", text='{"ok":true}')], is_error=False)

    e2e_clock = [500.0]
    mcp_cfg = ArodonataMCPSettings(
        auth_mode="host",
        tool_rate_limit_per_minute=2,
        live_tool_rate_limit_per_minute=1,
    )
    e2e_qm = MCPToolQuotaManager.from_settings(mcp_cfg, monotonic_fn=lambda: e2e_clock[0])

    async with ArodonataClient(
        ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="secret-api-key-never-logged"),
        api=_QuotaDummyApi(),
    ) as client:
        srv = create_mcp_server(client, mcp_settings=mcp_cfg, quota_manager=e2e_qm)
        tracer = trace.get_tracer("test.mcp.quota")

        with user_context(user_id="team-alpha", client_id="TEAM_ALPHA_TOKEN"):
            r1 = await srv.call_tool("list_domains", {"mgmt_name": "mds1", "cache_mode": "live"})
            assert r1.is_error is False
            with tracer.start_as_current_span("rate_limit_check"):
                r2 = await srv.call_tool("list_domains", {"mgmt_name": "mds1", "cache_mode": "live"})
            assert r2.is_error is True
            assert isinstance(r2.content[0], TextContent)
            err_json = json.loads(r2.content[0].text)
            assert err_json["error_code"] == "rate_limit_exceeded"
            assert err_json["bucket"] == "live"
            assert err_json["client_id"] == "TEAM_ALPHA_TOKEN"
            assert err_json["limit_per_minute"] == 1
            assert err_json["retry_after_seconds"] > 0

        # TEAM_BETA_TOKEN is isolated and still allowed
        with user_context(user_id="team-beta", client_id="TEAM_BETA_TOKEN"):
            r_beta = await srv.call_tool("list_domains", {"mgmt_name": "mds1", "cache_mode": "live"})
            assert r_beta.is_error is False

        # Unauthenticated call falls back to "anonymous"
        r_anon1 = await _dummy_tool()
        assert r_anon1.is_error is False
        r_anon2 = await _dummy_tool()
        assert r_anon2.is_error is True
        assert isinstance(r_anon2.content[0], TextContent)
        assert json.loads(r_anon2.content[0].text)["client_id"] == "anonymous"

        # Verify arlogi WARNING + OTel span attributes + zero secret/SID leakage
        assert any(
            msg == "MCP tool rate limit exceeded"
            and kw.get("client_id") == "TEAM_ALPHA_TOKEN"
            and kw.get("bucket") == "live"
            for msg, kw in warn_logs
        )
        finished_spans = exporter.get_finished_spans()
        rl_spans = [s for s in finished_spans if s.name == "rate_limit_check"]
        assert rl_spans
        attrs = dict(rl_spans[-1].attributes or {})
        assert attrs.get("arodonata.mcp_rate_limited") is True
        assert attrs.get("arodonata.mcp_client_id") == "TEAM_ALPHA_TOKEN"

        combined_audit = repr(warn_logs) + repr(attrs) + json.dumps(err_json)
        assert "secret-api-key-never-logged" not in combined_audit
        assert "sid-q" not in combined_audit

        # Verify bearer token / SID pattern passed in context never leaks into quota error payload, spans, or logs
        leaked_secret = "super-secret-bearer-token-xyz-987654"
        with user_context(user_id="leak-user", client_id=f"Authorization: Bearer {leaked_secret}"):
            with tracer.start_as_current_span("rate_limit_secret_check"):
                r_leak1 = await _dummy_tool()
                r_leak2 = await _dummy_tool()
            assert r_leak1.is_error is False
            assert r_leak2.is_error is True
            assert isinstance(r_leak2.content[0], TextContent)
            assert leaked_secret not in r_leak2.content[0].text
            assert leaked_secret not in repr(warn_logs)
