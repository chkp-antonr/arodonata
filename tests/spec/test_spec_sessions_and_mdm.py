"""Specification acceptance tests for `sessions-and-mdm` (`SCN-SESS-*`)."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from arodonata import ArodonataClient
from arodonata.adapters.checkpoint import rate_limiter as rate_limiter_mod
from arodonata.adapters.checkpoint import sessions as sessions_mod
from arodonata.adapters.checkpoint.client import AMgmtClient
from arodonata.adapters.checkpoint.rate_limiter import RateLimiter
from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport, PooledSocketEntry, RawHttpResponse
from arodonata.adapters.storage import DatabaseManager, SqlLockAdapter
from arodonata.core.config import ArodonataSettings
from arodonata.core.context import get_user_context
from arodonata.core.errors import ApiTimeoutError, ValidationError
from arodonata.core.models.domains import DomainInfo, SIDCacheEntry


def _make_der(seed: str = "spec-sessions") -> tuple[bytes, str]:
    der = f"der-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    return der, ":".join(digest[i : i + 2] for i in range(0, 64, 2))


class _FakeTimeRig:
    def __init__(self) -> None:
        self.mono = 100.0
        self.wall = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.mono

    def now(self) -> datetime:
        return self.wall

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.mono += seconds
        self.wall += timedelta(seconds=seconds)
        await asyncio.sleep(0)


class _ScriptedServer:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.handlers: list[Any] = []
        self.login_counter = 0

    async def sender(
        self,
        *,
        host: str,
        port: int,
        command: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        connect_timeout: float,
        read_timeout: float,
        reused_entry: PooledSocketEntry | None,
    ) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        payload = json.loads(body.decode("utf-8")) if body else {}
        rec = {
            "host": host,
            "port": port,
            "command": command,
            "url": url,
            "sid": headers.get("X-chkp-sid"),
            "payload": payload,
        }
        self.calls.append(rec)
        if self.handlers:
            h = self.handlers.pop(0)
            out = h(rec) if callable(h) else h
            if isinstance(out, BaseException):
                raise out
            status, body_dict = out
            return RawHttpResponse(status=status, body=json.dumps(body_dict).encode("utf-8")), reused_entry
        if command == "login":
            self.login_counter += 1
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps(
                        {
                            "sid": f"sid_{self.login_counter}_secret",
                            "uid": f"sess-{self.login_counter}",
                        }
                    ).encode("utf-8"),
                ),
                reused_entry,
            )
        return RawHttpResponse(status=200, body=b'{"message":"OK"}'), reused_entry


def _build_amgmt(
    tmp_path: Path,
    server: _ScriptedServer,
    rig: _FakeTimeRig,
    *,
    settings: ArodonataSettings | None = None,
    known_hosts_ips: tuple[str, ...] = ("10.0.0.1",),
) -> AMgmtClient:
    der, fp = _make_der()
    cfg = settings or ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="static-secret-key",
        tls_trust="pinned",
        tls_fingerprints=",".join(f"{ip}:443={fp}" for ip in known_hosts_ips),
    )
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=",".join(f"{ip}:443={fp}" for ip in known_hosts_ips),
    )
    transport = ApiTransport(
        settings=cfg,
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: der,
        request_sender=server.sender,
    )
    return AMgmtClient(
        settings=cfg,
        engine=None,
        transport=transport,
        trust_policy=policy,
        monotonic_fn=rig.monotonic,
        now_fn=rig.now,
        sleep_fn=rig.sleep,
    )


@pytest.mark.spec("SCN-SESS-001-3")
async def test_global_domain_cold_cache_resolution_and_debug_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-SESS-001-3: Resolve `Global` domain via `show-global-domain` on cold cache and log DEBUG resolution."""
    server = _ScriptedServer()
    rig = _FakeTimeRig()
    debug_logs: list[str] = []

    def _capture_debug(msg: object, *args: object, **_kwargs: object) -> None:
        debug_logs.append(str(msg))

    monkeypatch.setattr(sessions_mod.logger, "debug", _capture_debug)

    # Handlers: system login -> show-domains (empty for Global) -> show-mdss -> show-global-domain -> Global login -> show-hosts
    def _route(rec: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        cmd = rec["command"]
        if cmd == "login":
            server.login_counter += 1
            return (200, {"sid": f"sid_{server.login_counter}_tok", "uid": f"suid-{server.login_counter}"})
        if cmd == "show-domains":
            return (
                200,
                {"objects": [{"name": "Corp", "uid": "d1", "servers": [{"ipv4-address": "10.0.0.1", "active": True}]}]},
            )
        if cmd == "show-mdss":
            return (200, {"objects": [{"name": "mds-node-1", "ipv4-address": "10.0.0.1"}]})
        if cmd == "show-global-domain":
            return (
                200,
                {
                    "name": "Global",
                    "uid": "uid-global",
                    "domain-type": "global domain",
                    "servers": [{"ipv4-address": "10.0.0.1", "active": True}],
                },
            )
        return (200, {"objects": []})

    server.handlers = [_route] * 6
    amgmt = _build_amgmt(tmp_path, server, rig)
    try:
        await amgmt.initialize()
        resolved = await amgmt._login_coordinator.refresh_domain_active_ip("mds1", "Global")
        assert resolved is not None
        assert resolved.name == "Global"
        assert resolved.is_global is True

        res = await amgmt.api_call("mds1", "show-hosts", domain="Global")
        assert res.success is True
        cmds = [c["command"] for c in server.calls]
        assert "show-global-domain" in cmds
        assert any("Resolved active server for domain 'mds1:Global'" in m for m in debug_logs)
    finally:
        await amgmt.close(logout=False)


@pytest.mark.spec("SCN-SESS-003-3")
async def test_write_session_task_cancellation_shields_discard_and_logout(tmp_path: Path) -> None:
    """SCN-SESS-003-3: `asyncio.CancelledError` inside `write_session` shields `discard` and `logout_sid`."""
    server = _ScriptedServer()
    rig = _FakeTimeRig()
    amgmt = _build_amgmt(tmp_path, server, rig)
    entered = asyncio.Event()
    never = asyncio.Event()

    async def _worker() -> None:
        async with amgmt.write_session("mds1", "Corp"):
            entered.set()
            await never.wait()

    try:
        task = asyncio.create_task(_worker())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        cmds = [c["command"] for c in server.calls]
        assert "login" in cmds
        assert "discard" in cmds
        assert "logout" in cmds
        assert cmds.index("discard") < cmds.index("logout")
        assert "publish" not in cmds
    finally:
        await amgmt.close(logout=False)


@pytest.mark.spec("SCN-SESS-006-1")
async def test_throttled_login_logs_warning_and_read_timeout_records_backoff_cooldown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-SESS-006-1: Throttled login logs WARNING with IP+principal+cooldown without exposing secrets."""
    server = _ScriptedServer()
    rig = _FakeTimeRig()
    warnings: list[str] = []
    gate_warnings: list[str] = []
    monkeypatch.setattr(sessions_mod.logger, "warning", lambda msg, *_a, **_kw: warnings.append(str(msg)))
    monkeypatch.setattr(rate_limiter_mod.logger, "warning", lambda msg, *_a, **_kw: gate_warnings.append(str(msg)))

    secret_api_key = "super-secret-api-key-never-log"
    secret_password = "super-secret-password-never-log"

    amgmt = _build_amgmt(
        tmp_path,
        server,
        rig,
        settings=ArodonataSettings(
            mgmt_name="mds1",
            mgmt_ip="10.0.0.1",
            api_key=secret_api_key,
            login_throttle_window=70.0,
            login_max_wait=600.0,
        ),
    )
    try:
        # 1. API-key login throttled before first login succeeds -> falls back to non-secret 'api_key', never exposes key
        server.handlers = [
            (429, {"code": "err_too_many_requests", "message": "Too many requests in a given amount of time"}),
            (200, {"sid": "sid_ok_1", "uid": "u-1", "user-name": "fpcr_ro"}),
        ]
        sid, _ip = await amgmt.create_dedicated_session("mds1", domain=None)
        assert sid == "sid_ok_1"
        assert rig.sleeps == [70.0]
        assert any("10.0.0.1" in w and "70s" in w and "user='api_key'" in w for w in warnings)
        assert any("10.0.0.1" in w and "user='api_key'" in w for w in gate_warnings)
        assert all(secret_api_key not in w for w in warnings + gate_warnings)

        # 2. Subsequent read-phase ApiTimeoutError and second throttle log resolved Check Point 'fpcr_ro'
        warnings.clear()
        gate_warnings.clear()
        rig.sleeps.clear()
        server.handlers = [
            ApiTimeoutError("read timed out", host="10.0.0.1", command="login", phase="read", request_sent=True),
            (429, {"code": "err_too_many_requests", "message": "Too many requests in a given amount of time"}),
            (200, {"sid": "sid_ok_2", "uid": "u-2", "user-name": "fpcr_ro"}),
        ]
        sid2, _ip2 = await amgmt.create_dedicated_session("mds1", domain=None)
        assert sid2 == "sid_ok_2"
        assert rig.sleeps == [2.0, 70.0]
        assert any("10.0.0.1" in w and "2.0s cooldown" in w and "user='fpcr_ro'" in w for w in warnings)
        assert any("10.0.0.1" in w and "70s" in w and "user='fpcr_ro'" in w for w in warnings)
        assert any("10.0.0.1" in w and "user='fpcr_ro'" in w for w in gate_warnings)
        assert all(secret_api_key not in w for w in warnings + gate_warnings)
    finally:
        await amgmt.close(logout=False)

    # 3. Credential auth throttling logs engineer username directly without exposing password
    warnings.clear()
    gate_warnings.clear()
    cred_server = _ScriptedServer()
    cred_rig = _FakeTimeRig()
    cred_amgmt = _build_amgmt(
        tmp_path,
        cred_server,
        cred_rig,
        settings=ArodonataSettings(
            mgmt_name="mds1",
            mgmt_ip="10.0.0.1",
            auth_mode="credential",
            username="AntonR",
            password=secret_password,
            login_throttle_window=70.0,
            login_max_wait=300.0,
        ),
    )
    try:
        cred_server.handlers = [
            (429, {"code": "err_too_many_requests", "message": "Too many requests in a given amount of time"}),
            (200, {"sid": "sid_ok_3", "uid": "u-3", "user-name": "AntonR"}),
        ]
        sid3, _ip3 = await cred_amgmt.create_dedicated_session("mds1", domain=None)
        assert sid3 == "sid_ok_3"
        assert any("10.0.0.1" in w and "70s" in w and "user='AntonR'" in w for w in warnings)
        assert any("10.0.0.1" in w and "user='AntonR'" in w for w in gate_warnings)
        assert all(secret_password not in w for w in warnings + gate_warnings)
    finally:
        await cred_amgmt.close(logout=False)


@pytest.mark.spec("SCN-SESS-007-1")
async def test_rate_limiter_suppresses_lock_release_error_without_leaking_local_slot() -> None:
    """SCN-SESS-007-1: Distributed DB lock release exception during slot exit is suppressed without leaking local slots."""
    db = DatabaseManager(engine=None)
    await db.initialize()
    real_lock = SqlLockAdapter(db)

    class _FailingReleaseLock:
        async def acquire(self, key: str, *, ttl_seconds: float, owner_id: str, wait_timeout: float = 0.0) -> bool:
            return await real_lock.acquire(key, ttl_seconds=ttl_seconds, owner_id=owner_id, wait_timeout=wait_timeout)

        async def release(self, key: str, *, owner_id: str) -> bool:
            await real_lock.release(key, owner_id=owner_id)
            raise RuntimeError("transient db error during unlock")

    limiter = RateLimiter(concurrent_limit=1, slot_timeout=1.0, lock_port=_FailingReleaseLock())  # type: ignore[arg-type]
    try:
        async with limiter.slot("10.0.0.1"):
            pass

        # Subsequent acquisition must succeed immediately without timeout or leaked local slot
        async with limiter.slot("10.0.0.1", timeout=0.2) as slot_idx:
            assert slot_idx == 0
    finally:
        await db.close()


@pytest.mark.spec("SCN-SESS-007-1")
async def test_login_coordinator_logout_sid_propagates_cancelled_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-SESS-007-1 (DA-019): LoginCoordinator.logout_sid propagates asyncio.CancelledError without swallowing it."""
    server = _ScriptedServer()
    rig = _FakeTimeRig()
    amgmt = _build_amgmt(tmp_path, server, rig)
    try:
        await amgmt.initialize()

        async def _cancel_execute(*_args: Any, **_kwargs: Any) -> Any:
            raise asyncio.CancelledError

        monkeypatch.setattr(amgmt._transport, "execute", _cancel_execute)
        with pytest.raises(asyncio.CancelledError):
            await amgmt._login_coordinator.logout_sid("mds1", "sid_to_cancel")
    finally:
        await amgmt.close(logout=False)


@pytest.mark.spec("SCN-SESS-008-1")
async def test_explicit_server_ip_rejected_before_connect_or_sid_across_keepalive_cache_hit_and_logout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-SESS-008-1 (FC-01): Untrusted explicit `server_ip` fails closed in keepalive, cached hit, and logout_sid."""
    server = _ScriptedServer()
    rig = _FakeTimeRig()
    amgmt = _build_amgmt(tmp_path, server, rig, known_hosts_ips=("10.0.0.1", "10.0.0.50"))
    try:
        await amgmt.initialize()
        await amgmt.cache.upsert_domains(
            [
                DomainInfo(
                    id="mds1:Corp",
                    mgmt_name="mds1",
                    name="Corp",
                    uid="dom-corp",
                    active_ip="10.0.0.50",
                    active_mds_ip="10.0.0.2",
                )
            ],
        )
        await amgmt.cache.upsert_sid(
            SIDCacheEntry(
                id="mds1:Corp:default",
                mgmt_name="mds1",
                domain_name="Corp",
                sid="sid_cached_secret",
                server_ip="10.0.0.50",
                last_used_at=rig.wall,
                expires_at=rig.wall + timedelta(seconds=300),
            )
        )
        server.calls.clear()

        # 1. Cache-hit get_readonly_session rejects untrusted explicit server_ip BEFORE returning SID
        with pytest.raises(ValidationError, match="Untrusted explicit server_ip"):
            await amgmt._login_coordinator.get_readonly_session("mds1", "Corp", server_ip="192.0.2.99")

        # 2. keepalive_sid rejects untrusted explicit server_ip BEFORE connecting or transmitting SID
        with pytest.raises(ValidationError, match="Untrusted explicit server_ip"):
            await amgmt._login_coordinator.keepalive_sid(
                "mds1", "Corp", sid="sid_cached_secret", server_ip="192.0.2.99"
            )

        # 3. logout_sid rejects untrusted explicit server_ip BEFORE evicting or transmitting SID
        with pytest.raises(ValidationError, match="Untrusted explicit server_ip"):
            await amgmt.logout_sid("mds1", "sid_cached_secret", server_ip="192.0.2.99")

        assert server.calls == []

        # 4. Valid CMA logout_sid bills RateLimiter slot against resolved `active_mds_ip` ("10.0.0.2")
        billed_mds_ips: list[str] = []
        orig_slot = amgmt._login_coordinator._rate_limiter.slot

        def _spy_slot(mds_ip: str, **kwargs: Any) -> Any:
            billed_mds_ips.append(mds_ip)
            return orig_slot(mds_ip, **kwargs)

        monkeypatch.setattr(amgmt._login_coordinator._rate_limiter, "slot", _spy_slot)
        ok = await amgmt.logout_sid("mds1", "sid_cached_secret", server_ip="10.0.0.50")
        assert ok is True
        assert billed_mds_ips == ["10.0.0.2"]
        assert len(server.calls) == 1
        assert server.calls[0]["host"] == "10.0.0.50"
        assert server.calls[0]["sid"] == "sid_cached_secret"
    finally:
        await amgmt.close(logout=False)


@pytest.mark.spec("SCN-SESS-008-1")
async def test_explicit_server_ip_dns_rebinding_subset_rejection_and_pinned_ip_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-SESS-008-1 (DA-001): Require resolved_ips.issubset(trusted_ips) and connect to pinned IP."""
    server = _ScriptedServer()
    rig = _FakeTimeRig()
    amgmt = _build_amgmt(tmp_path, server, rig, known_hosts_ips=("10.0.0.1", "10.0.0.50"))

    async def _fake_resolve(host: str) -> set[str]:
        if host == "rebind.attacker.test":
            return {"10.0.0.50", "169.254.169.254"}
        if host == "trusted-alias.internal":
            return {"10.0.0.50"}
        return set()

    monkeypatch.setattr(
        "arodonata.adapters.checkpoint.target_resolver._resolve_hostname_ips",
        _fake_resolve,
    )

    try:
        await amgmt.initialize()
        await amgmt.cache.upsert_domains(
            [
                DomainInfo(
                    id="mds1:Corp",
                    mgmt_name="mds1",
                    name="Corp",
                    uid="dom-corp",
                    active_ip="10.0.0.50",
                    active_mds_ip="10.0.0.1",
                )
            ]
        )

        # Dual-A-record mixing a trusted IP with 169.254.169.254 MUST fail closed with zero network I/O
        server.calls.clear()
        with pytest.raises(ValidationError, match="Untrusted explicit server_ip"):
            await amgmt.api_call("mds1", "show-hosts", domain="Corp", server_ip="rebind.attacker.test")
        assert server.calls == []

        # Trusted hostname resolving exclusively to trusted IPs pins to canonical IP before transport
        res = await amgmt.api_call("mds1", "show-hosts", domain="Corp", server_ip="trusted-alias.internal")
        assert res.success is True
        assert all(call["host"] == "10.0.0.50" for call in server.calls)
    finally:
        await amgmt.close(logout=False)


@pytest.mark.spec("SCN-SESS-010-1")
async def test_unresolvable_explicit_hostname_fails_closed_before_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    """SCN-SESS-010-1: A non-IP explicit hostname with zero DNS records is never forwarded unpinned."""
    from arodonata.adapters.checkpoint.target_resolver import validate_explicit_server_ip
    from arodonata.core.config import ServerEndpointConfig

    async def _no_dns(host: str) -> set[str]:
        return set()

    monkeypatch.setattr("arodonata.adapters.checkpoint.target_resolver._resolve_hostname_ips", _no_dns)

    async def _collect(mgmt_name: str, host: str) -> tuple[set[str], list[DomainInfo]]:
        # Even an exact textual match in the trusted set must not bypass IP pinning.
        return {"mgmt.example.com", "10.0.0.1"}, []

    async def _refresh(mgmt_name: str, domain: str) -> DomainInfo | None:
        return None

    with pytest.raises(ValidationError, match="Untrusted explicit server_ip"):
        await validate_explicit_server_ip(
            mgmt_name="mds1",
            domain=None,
            explicit_server_ip="mgmt.example.com",
            endpoint=ServerEndpointConfig(name="mds1", host="10.0.0.1"),
            collect_hosts_fn=_collect,
            refresh_domain_fn=_refresh,
        )


@pytest.mark.spec("SCN-SESS-009-1")
async def test_user_context_attributes_dedicated_session_and_restores_outer_scope(tmp_path: Path) -> None:
    """SCN-SESS-009-1: `UserContext` applies attribution to dedicated sessions and isolates concurrent tasks."""
    server = _ScriptedServer()
    rig = _FakeTimeRig()
    amgmt = _build_amgmt(tmp_path, server, rig)
    cfg = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1", api_key="k")
    client = ArodonataClient(cfg, api=amgmt)
    concurrent_seen: list[str | None] = []

    try:
        assert get_user_context() is None

        async def _sibling_task() -> None:
            ctx = get_user_context()
            concurrent_seen.append(ctx.username if ctx else None)

        with client.user_context(
            session_name="chg-42",
            session_description="firewall ticket #42",
            user_id="u-alice",
            username="alice",
        ):
            active_ctx = get_user_context()
            assert active_ctx is not None
            assert active_ctx.username == "alice"

            sibling = asyncio.create_task(_sibling_task())
            await sibling

            async with client.write_session("mds1", domain=None) as ws:
                assert ws.session_name == "chg-42"
                assert ws.user is not None
                assert ws.user.user_id == "u-alice"

        assert get_user_context() is None
        login_calls = [c for c in server.calls if c["command"] == "login"]
        assert len(login_calls) == 1
        assert login_calls[0]["payload"]["session-name"] == "chg-42"
        assert login_calls[0]["payload"]["session-description"] == "firewall ticket #42"
        assert concurrent_seen == ["alice"]  # copied task context sees binding; outer scope stayed None

        sibling_after = asyncio.create_task(_sibling_task())
        await sibling_after
        assert concurrent_seen[-1] is None
    finally:
        await client.close(logout=False)


@pytest.mark.spec("SCN-SESS-012-1")
@pytest.mark.asyncio
@pytest.mark.parametrize("tls_mode", ["pinned", "tofu"])
async def test_hostname_pinned_and_tofu_fingerprints_enforced_across_ip_pinning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_mode: str,
) -> None:
    """SCN-SESS-012-1: Hostname-pinned and TOFU-learned fingerprints are enforced when connecting via resolved IP."""
    from arodonata.adapters.checkpoint import target_resolver
    from arodonata.adapters.checkpoint.tls import compute_der_fingerprint
    from arodonata.core.errors import CertificateMismatchError

    rig = _FakeTimeRig()
    server = _ScriptedServer()
    expected_der = b"expected-mgmt-example-com-cert"
    rogue_der = b"rogue-mitm-cert-bytes"
    expected_fp = compute_der_fingerprint(expected_der)
    rogue_fp = compute_der_fingerprint(rogue_der)

    async def _fake_resolve(host: str) -> set[str]:
        if host == "mgmt.example.com":
            return {"10.0.0.50"}
        return set()

    monkeypatch.setattr(target_resolver, "_resolve_hostname_ips", _fake_resolve)

    known_hosts = tmp_path / "tls_known_hosts.json"
    if tls_mode == "pinned":
        policy = TrustPolicy(
            mode="pinned",
            known_hosts_path=known_hosts,
            pinned_fingerprints=f"mgmt.example.com:443={expected_fp},other.example.com:443={rogue_fp}",
        )
    else:
        policy = TrustPolicy(
            mode="tofu",
            known_hosts_path=known_hosts,
        )
        # Pre-learn mgmt.example.com:443 via TOFU; 10.0.0.50:443 is unseen.
        assert policy.verify_der("mgmt.example.com", 443, expected_der) == expected_fp

    presented_cert = {"der": expected_der}
    dialed_hosts: list[str] = []

    async def _recording_sender(**kwargs: Any) -> Any:
        dialed_hosts.append(kwargs["host"])
        return await server.sender(**kwargs)

    cfg = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.50",
        api_key="static-secret-key",
        tls_trust=tls_mode,  # type: ignore[arg-type]
    )
    transport = ApiTransport(
        settings=cfg,
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: presented_cert["der"],
        request_sender=_recording_sender,
    )
    client = AMgmtClient(
        settings=cfg,
        engine=None,
        transport=transport,
        trust_policy=policy,
        monotonic_fn=rig.monotonic,
        now_fn=rig.now,
        sleep_fn=rig.sleep,
    )
    await client.initialize()
    try:
        # 1. Matching cert on resolved canonical IP 10.0.0.50 succeeds and dials IP directly.
        res = await client.api_call("mds1", "show-domains", {}, sid="sid-1", server_ip="mgmt.example.com")
        assert res.success is True
        assert dialed_hosts and all(h == "10.0.0.50" for h in dialed_hosts)

        # 2. Mismatched cert (even if pinned under another host or unseen in TOFU) fails before HTTP write.
        client._transport.connection_pool.close_all()
        presented_cert["der"] = rogue_der
        calls_before = len(server.calls)

        with pytest.raises(CertificateMismatchError):
            await client.api_call("mds1", "show-domains", {}, sid="sid-1", server_ip="mgmt.example.com")
        assert len(server.calls) == calls_before

        with pytest.raises(CertificateMismatchError):
            await client._login_coordinator._perform_gated_login(
                "mds1",
                None,
                auth=await client._login_coordinator.resolve_credentials("mds1", None),
                explicit_server_ip="mgmt.example.com",
            )
        assert len(server.calls) == calls_before

        with pytest.raises(CertificateMismatchError):
            await client._login_coordinator.keepalive_sid("mds1", None, sid="sid-1", server_ip="mgmt.example.com")
        assert len(server.calls) == calls_before

        with pytest.raises(CertificateMismatchError):
            await client._login_coordinator.logout_sid("mds1", "sid-1", server_ip="mgmt.example.com")
        assert len(server.calls) == calls_before
    finally:
        await client.close(logout=False)
