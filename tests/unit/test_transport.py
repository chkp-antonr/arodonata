"""Unit tests for `ApiTransport` and `VerifiedConnectionPool` (`src/arodonata/adapters/checkpoint/transport.py`)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import subprocess
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp import web

from arodonata.adapters.checkpoint.tls import TrustPolicy, compute_der_fingerprint
from arodonata.adapters.checkpoint.transport import (
    ApiTransport,
    FingerprintTCPConnector,
    PooledSocketEntry,
    RawHttpResponse,
    VerifiedConnectionPool,
    validate_command_name,
    verify_transport_peer_certificate,
)
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import (
    REDACTED_PLACEHOLDER,
    ApiTimeoutError,
    CertificateMismatchError,
    ConfigurationError,
    TransportError,
    UnknownServerCertificateError,
    ValidationError,
)


def _make_der(seed: str) -> tuple[bytes, str]:
    der = f"transport-der-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    formatted = ":".join(digest[i : i + 2] for i in range(0, 64, 2))
    return der, formatted


class FakeClock:
    def __init__(self, initial: float = 100.0) -> None:
        self.now = initial

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeSocketProtocol:
    def __init__(self) -> None:
        self.closed = False

    def is_connected(self) -> bool:
        return not self.closed

    def close(self) -> None:
        self.closed = True


class FakeSslObject:
    def __init__(self, der_bytes: bytes) -> None:
        self._der = der_bytes

    def getpeercert(self, binary_form: bool = False) -> bytes | dict[str, Any]:
        return self._der if binary_form else {}


class FakeAsyncioTransport:
    def __init__(self, der_bytes: bytes) -> None:
        self._ssl_obj = FakeSslObject(der_bytes)
        self.closed = False

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "ssl_object":
            return self._ssl_obj
        return default

    def close(self) -> None:
        self.closed = True


async def test_pre_request_tls_verification_blocks_before_sending_bytes(tmp_path: Path) -> None:
    """Scenario: Untrusted certificate refused in pinned mode before any HTTP request bytes are sent."""
    _der_good, fp_good = _make_der("good")
    der_bad, _fp_bad = _make_der("bad")

    sent_requests: list[dict[str, Any]] = []

    async def sender(**kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        sent_requests.append(kwargs)
        return RawHttpResponse(status=200, body=b'{"uid":"1"}'), None

    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp_good}",
    )
    transport = ApiTransport(
        settings=ArodonataSettings(tls_trust="pinned"),
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: der_bad,
        request_sender=sender,
    )

    with pytest.raises(CertificateMismatchError) as exc_info:
        await transport.execute("10.0.0.1", "login", {"api-key": "top-secret-key"})

    assert "No request was sent." in str(exc_info.value)
    assert len(sent_requests) == 0

    # Also test verify_transport_peer_certificate directly closing raw asyncio transport
    fake_transp = FakeAsyncioTransport(der_bad)
    with pytest.raises(UnknownServerCertificateError):
        verify_transport_peer_certificate(
            fake_transp,  # type: ignore[arg-type]
            host="10.0.0.99",
            port=443,
            trust_policy=policy,
        )
    assert fake_transp.closed is True


async def test_connect_and_read_timeouts_and_no_resend(tmp_path: Path) -> None:
    """Scenarios:
    - Socket connect or handshake timeout -> ApiTimeoutError(phase='connect')
    - Socket read timeout -> ApiTimeoutError(phase='read') warning command may still have run
    - ConnectionResetError or BrokenPipeError after transmission never resends
    """
    der, fp = _make_der("server-1")
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp}",
    )
    settings = ArodonataSettings(connect_timeout=5.0, api_timeout=20.0, login_timeout=20.0)

    # 1. Connect timeout
    async def slow_cert_getter(_h: str, _p: int) -> bytes:
        raise TimeoutError("TLS handshake timed out")

    transport_connect_timeout = ApiTransport(
        settings=settings,
        trust_policy=policy,
        peer_cert_getter=slow_cert_getter,
        request_sender=lambda **_kw: None,  # type: ignore[arg-type,return-value]
    )
    with pytest.raises(ApiTimeoutError) as conn_exc:
        await transport_connect_timeout.execute("10.0.0.1", "show-hosts")
    assert conn_exc.value.phase == "connect"
    assert conn_exc.value.request_sent is False
    assert conn_exc.value.host == "10.0.0.1"
    assert conn_exc.value.port == 443
    assert isinstance(conn_exc.value, TimeoutError)

    # 2. Read timeout (never resends)
    read_attempts = 0

    async def timeout_on_read(**kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        nonlocal read_attempts
        read_attempts += 1
        assert kwargs["read_timeout"] == 15.0  # explicit timeout=10.0 + 5.0
        raise TimeoutError("Socket read timeout")

    transport_read_timeout = ApiTransport(
        settings=settings,
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: der,
        request_sender=timeout_on_read,
    )
    with pytest.raises(ApiTimeoutError) as read_exc:
        await transport_read_timeout.execute("10.0.0.1", "add-host", {"name": "h1"}, timeout=10.0)
    assert read_exc.value.phase == "read"
    assert read_exc.value.request_sent is True
    assert read_exc.value.command == "add-host"
    assert "may still have run" in str(read_exc.value)
    assert read_attempts == 1

    # 3. ConnectionResetError and BrokenPipeError after write never resend and redact SID
    for err_cls in (ConnectionResetError, BrokenPipeError):
        attempts = 0

        async def reset_after_write(
            _err_cls: type[OSError] = err_cls,
            **_kwargs: Any,
        ) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
            nonlocal attempts
            attempts += 1
            raise _err_cls("Peer reset connection while reading response for sid=secret_sid_12345")

        transport_reset = ApiTransport(
            settings=settings,
            trust_policy=policy,
            peer_cert_getter=lambda _h, _p: der,
            request_sender=reset_after_write,
        )
        with pytest.raises(TransportError) as reset_exc:
            await transport_reset.execute("10.0.0.1", "add-host", {"name": "h1"}, sid="secret_sid_12345")
        assert attempts == 1
        assert reset_exc.value.phase == "post-send"
        assert reset_exc.value.request_sent is True
        assert "secret_sid_12345" not in str(reset_exc.value)
        assert REDACTED_PLACEHOLDER in str(reset_exc.value)


async def test_verified_connection_pool_show_reuse_and_mutation_bypass(tmp_path: Path) -> None:
    """Scenarios:
    - Consecutive show commands reuse verified keep-alive connection within 10s
    - Mutating commands and connections idle > 10s bypass reuse and open fresh connections
    """
    der, fp = _make_der("pool-cert")
    clock = FakeClock(1000.0)
    pool = VerifiedConnectionPool(max_idle_seconds=10.0, monotonic_fn=clock)
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp}",
    )

    handshakes = 0
    reused_flags: list[bool] = []

    def cert_getter(_h: str, _p: int) -> bytes:
        nonlocal handshakes
        handshakes += 1
        return der

    async def sender(**kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        reused = kwargs["reused_entry"]
        reused_flags.append(reused is not None)
        entry = reused or PooledSocketEntry(
            host=kwargs["host"],
            port=kwargs["port"],
            fingerprint=fp,
            protocol=FakeSocketProtocol(),
            last_used_at=clock(),
        )
        body = json.dumps({"objects": [], "total": 0}).encode("utf-8")
        return RawHttpResponse(status=200, body=body, reused_connection=reused is not None), entry

    transport = ApiTransport(
        settings=ArodonataSettings(),
        trust_policy=policy,
        connection_pool=pool,
        peer_cert_getter=cert_getter,
        request_sender=sender,
    )

    # Call 1: show-hosts -> fresh handshake, pooled on completion
    res1 = await transport.execute("10.0.0.1", "show-hosts", sid="sid_abc12345")
    assert res1.success is True
    assert handshakes == 1
    assert reused_flags[-1] is False
    assert pool.pooled_count("10.0.0.1", 443) == 1

    # Call 2: 5 seconds later (< 10s), show-networks -> reuses pooled connection without handshake!
    clock.advance(5.0)
    res2 = await transport.execute("10.0.0.1", "show-networks", sid="sid_abc12345")
    assert res2.success is True
    assert handshakes == 1  # No new TLS handshake!
    assert reused_flags[-1] is True
    assert pool.reuse_count == 1

    # Call 3: mutating command (add-host) -> bypasses pool and opens fresh connection
    clock.advance(1.0)
    res3 = await transport.execute("10.0.0.1", "add-host", {"name": "h1"}, sid="sid_abc12345")
    assert res3.success is True
    assert handshakes == 2
    assert reused_flags[-1] is False

    # Call 4: advance clock by 11 seconds (> 10s idle) -> pooled show connection expires and closes
    clock.advance(11.0)
    res4 = await transport.execute("10.0.0.1", "show-hosts", sid="sid_abc12345")
    assert res4.success is True
    assert handshakes == 3
    assert reused_flags[-1] is False

    await transport.close()
    assert pool.pooled_count() == 0


async def test_command_name_regex_validation_blocks_traversal_and_injections(tmp_path: Path) -> None:
    """Adversarial test for C1: ApiTransport.execute strictly enforces ^[a-z0-9]+(-[a-z0-9]+)*$."""
    der, fp = _make_der("cmd-val")
    sent_requests: list[dict[str, Any]] = []

    async def sender(**kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        sent_requests.append(kwargs)
        return RawHttpResponse(status=200, body=b"{}"), None

    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp}",
    )
    transport = ApiTransport(
        settings=ArodonataSettings(tls_trust="pinned"),
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: der,
        request_sender=sender,
    )

    assert validate_command_name("show-hosts") == "show-hosts"
    assert validate_command_name("web_api/show-access-rulebase") == "show-access-rulebase"
    assert validate_command_name("/web_api/login") == "login"

    malicious_commands = [
        "show-hosts/../publish",
        "show-x/%2e%2e/publish",
        "show-x/../../gaia_api/v1.7/run-script",
        "../../gaia_api/v1.7/run-script",
        "show-hosts?details-level=full",
        "show-hosts#frag",
        "SHOW-HOSTS",
        "show_hosts",
        "show-hosts ",
        "show--hosts",
        "-show-hosts",
        "show-hosts-",
        "show-hosts/sub",
        "show-hosts\\..\\publish",
        "",
    ]
    for bad_cmd in malicious_commands:
        with pytest.raises(ValidationError):
            await transport.execute("10.0.0.1", bad_cmd)

    assert len(sent_requests) == 0


async def test_request_sender_without_peer_cert_getter_rejected_and_proxy_rejected(tmp_path: Path) -> None:
    """Adversarial test for W2 and I12: unverified request_sender seam and proxy connections are rejected."""

    async def dummy_sender(**_kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        return RawHttpResponse(status=200, body=b"{}"), None

    with pytest.raises(ConfigurationError, match="peer_cert_getter"):
        ApiTransport(
            settings=ArodonataSettings(),
            request_sender=dummy_sender,
        )

    policy = TrustPolicy(
        mode="tofu",
        known_hosts_path=tmp_path / "known.json",
    )
    pool = VerifiedConnectionPool()
    connector = FingerprintTCPConnector(trust_policy=policy, connection_pool=pool)
    try:
        with pytest.raises(TransportError) as proxy_exc:
            await connector._create_proxy_connection(None, [], aiohttp.ClientTimeout())  # type: ignore[arg-type]
        assert proxy_exc.value.phase == "connect"
        assert proxy_exc.value.request_sent is False
    finally:
        await connector.close()


def _generate_self_signed_cert(tmp_dir: Path, cn: str = "127.0.0.1") -> tuple[Path, Path, bytes, str]:
    cert_pem = tmp_dir / f"{cn}.crt"
    key_pem = tmp_dir / f"{cn}.key"
    cert_der = tmp_dir / f"{cn}.der"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_pem),
            "-out",
            str(cert_pem),
            "-days",
            "1",
            "-subj",
            f"/CN={cn}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(cert_pem),
            "-outform",
            "DER",
            "-out",
            str(cert_der),
        ],
        check=True,
        capture_output=True,
    )
    der_bytes = cert_der.read_bytes()
    fp = compute_der_fingerprint(der_bytes)
    return cert_pem, key_pem, der_bytes, fp


async def test_real_loopback_tls_connector_pinning_pooling_and_redirects_blocked(tmp_path: Path) -> None:
    """Adversarial test for W1, W2, I10, I11:
    Exercises real FingerprintTCPConnector against a loopback TLS aiohttp.web server:
    - Verifies certificate fingerprint before sending HTTP request
    - Pools only show-* commands (mutating commands close socket and do not pool)
    - Rejects 301/302/307/308 redirects without following or leaking X-chkp-sid
    """
    cert_pem, key_pem, _der, server_fp = _generate_self_signed_cert(tmp_path, "server")
    _other_cert, _other_key, _other_der, other_fp = _generate_self_signed_cert(tmp_path, "other")

    received_commands: list[str] = []
    redirect_target_hits: list[dict[str, str]] = []

    async def handle_web_api(request: web.Request) -> web.StreamResponse:
        cmd = request.match_info["cmd"]
        received_commands.append(cmd)
        if cmd == "show-redirect":
            raise web.HTTPTemporaryRedirect(location=f"https://127.0.0.1:{request.url.port}/web_api/publish")
        if cmd == "show-disconnect":
            assert request.transport is not None
            request.transport.close()
            await asyncio.sleep(0.05)
            return web.json_response({})
        return web.json_response({"objects": [], "total": 0, "cmd": cmd})

    async def handle_evil_target(request: web.Request) -> web.StreamResponse:
        redirect_target_hits.append(dict(request.headers))
        return web.json_response({"stolen": True})

    app = web.Application()
    app.router.add_post("/web_api/{cmd}", handle_web_api)
    app.router.add_post("/evil", handle_evil_target)

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=str(cert_pem), keyfile=str(key_pem))

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_ctx)
    await site.start()
    try:
        assert site._server is not None
        port = site._server.sockets[0].getsockname()[1]

        # 1. Wrong pin in pinned mode -> CertificateMismatchError BEFORE any HTTP request reaches server
        bad_policy = TrustPolicy(
            mode="pinned",
            known_hosts_path=tmp_path / "bad_known.json",
            pinned_fingerprints=f"127.0.0.1:{port}={other_fp}",
        )
        bad_transport = ApiTransport(
            settings=ArodonataSettings(tls_trust="pinned"),
            trust_policy=bad_policy,
        )
        try:
            with pytest.raises(CertificateMismatchError):
                await bad_transport.execute("127.0.0.1", "show-hosts", port=port, sid="top_secret_sid")
            assert len(received_commands) == 0
        finally:
            await bad_transport.close()

        # 2. Correct pin -> show-* commands reuse connection; mutating command does not pool
        good_policy = TrustPolicy(
            mode="pinned",
            known_hosts_path=tmp_path / "good_known.json",
            pinned_fingerprints=f"127.0.0.1:{port}={server_fp}",
        )
        pool = VerifiedConnectionPool(max_idle_seconds=10.0)
        good_transport = ApiTransport(
            settings=ArodonataSettings(tls_trust="pinned"),
            trust_policy=good_policy,
            connection_pool=pool,
        )
        try:
            r1 = await good_transport.execute("127.0.0.1", "show-hosts", port=port, sid="sid_12345678")
            assert r1.success is True
            assert pool.pooled_count("127.0.0.1", port) == 1

            r2 = await good_transport.execute("127.0.0.1", "show-networks", port=port, sid="sid_12345678")
            assert r2.success is True
            assert pool.reuse_count == 1

            # Mutating command closes pooled connection and is not pooled after execution
            r3 = await good_transport.execute("127.0.0.1", "add-host", {"name": "h1"}, port=port, sid="sid_12345678")
            assert r3.success is True
            assert pool.pooled_count("127.0.0.1", port) == 0

            # 3. Redirect (307) -> rejected with TransportError, never follows redirect to /web_api/publish
            with pytest.raises(TransportError, match="redirect") as redir_exc:
                await good_transport.execute("127.0.0.1", "show-redirect", port=port, sid="sid_12345678")
            assert redir_exc.value.phase == "post-send"
            assert redir_exc.value.request_sent is True
            assert "publish" not in received_commands
            assert len(redirect_target_hits) == 0

            # 4. Server disconnect after request sent -> TransportError(phase="post-send", request_sent=True)
            with pytest.raises(TransportError) as disc_exc:
                await good_transport.execute("127.0.0.1", "show-disconnect", port=port, sid="sid_12345678")
            assert disc_exc.value.phase == "post-send"
            assert disc_exc.value.request_sent is True
        finally:
            await good_transport.close()
    finally:
        await runner.cleanup()
