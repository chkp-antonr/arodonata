"""Unit tests for `LoginCoordinator`, `SessionCleaner`, `WriteSession`, and `AMgmtClient`."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from arodonata import AMgmtClient, ArodonataSettings, AuthContext, UserContext, auth_context, get_write_session
from arodonata.adapters.checkpoint import (
    SYSTEM_DOMAIN_SENTINEL,
    ApiTransport,
    PooledSocketEntry,
    RawHttpResponse,
    TrustPolicy,
)
from arodonata.core.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    ServerIdentityError,
)
from arodonata.core.models.domains import DomainInfo
from arodonata.core.models.objects import CPObject
from arodonata.core.ports import ApiPort


def _make_der(seed: str = "sessions-cert") -> tuple[bytes, str]:
    der = f"der-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    formatted = ":".join(digest[i : i + 2] for i in range(0, 64, 2))
    return der, formatted


class FakeTimeRig:
    def __init__(self) -> None:
        self.mono = 1000.0
        self.wall = datetime(2026, 10, 23, 18, 0, 0, tzinfo=UTC)
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.mono

    def now(self) -> datetime:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += timedelta(seconds=seconds)

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)


class FakeCheckpointServer:
    """In-memory programmable Check Point Web API responder for transport testing."""

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
        parsed_body = json.loads(body.decode("utf-8")) if body else {}
        record = {
            "host": host,
            "port": port,
            "command": command,
            "url": url,
            "headers": dict(headers),
            "sid": headers.get("X-chkp-sid"),
            "payload": parsed_body,
            "connect_timeout": connect_timeout,
            "read_timeout": read_timeout,
        }
        self.calls.append(record)

        if self.handlers:
            handler = self.handlers.pop(0)
            if callable(handler):
                status, resp_dict = handler(record)
            else:
                status, resp_dict = handler
            return RawHttpResponse(status=status, body=json.dumps(resp_dict).encode("utf-8")), reused_entry

        if command == "login":
            self.login_counter += 1
            sid = f"sid_token_{self.login_counter}_secret"
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps({"sid": sid, "uid": f"sess-uid-{self.login_counter}"}).encode("utf-8"),
                ),
                reused_entry,
            )

        if command in ("logout", "keepalive", "discard"):
            return RawHttpResponse(status=200, body=b'{"message":"OK"}'), reused_entry

        if command == "publish":
            return RawHttpResponse(status=200, body=b'{"task-id":"pub-task-1"}'), reused_entry

        if command == "show-task":
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps(
                        {"tasks": [{"task-id": "pub-task-1", "status": "succeeded", "progress-percentage": 100}]}
                    ).encode("utf-8"),
                ),
                reused_entry,
            )

        return RawHttpResponse(status=200, body=b'{"objects":[],"total":0}'), reused_entry


def _build_client(
    tmp_path: Path,
    server: FakeCheckpointServer,
    rig: FakeTimeRig,
    *,
    settings: ArodonataSettings | None = None,
    auth_provider: Any = None,
) -> AMgmtClient:
    der, fp = _make_der()
    cfg = settings or ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="static-secret-key",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp}",
    )
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp}",
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
        auth_provider=auth_provider,
        monotonic_fn=rig.monotonic,
        now_fn=rig.now,
        sleep_fn=rig.sleep,
    )


async def test_sid_cache_reuse_transparent_relogin_and_keepalive_eviction(tmp_path: Path) -> None:
    """Scenarios:
    - Reuse of unexpired cached session
    - Transparent re-login on session expiration error
    - Immediate eviction when keepalive returns success=False
    - Default in-memory SQLite engine when engine=None
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    assert isinstance(client, ApiPort)
    assert client.owns_engine is True

    # 1. First read call performs login and caches SID in sid_cache
    res1 = await client.api_call("mds1", "show-hosts", domain="Corp")
    assert res1.success is True
    assert server.login_counter == 1
    cached = await client.cache.get_sid("mds1", "Corp")
    assert cached is not None
    assert cached.sid == "sid_token_1_secret"

    # 2. Second read call within session_expire_seconds (e.g. +100s < 540s) reuses cached SID without login
    rig.advance(100.0)
    res2 = await client.api_call("mds1", "show-networks", domain="Corp")
    assert res2.success is True
    assert server.login_counter == 1

    # 3. Server returns session expired on next call -> client evicts SID, re-logs in, and retries transparently!
    server.handlers.append((401, {"code": "generic_err_invalid_session_id", "message": "Invalid session id"}))
    server.handlers.append((200, {"sid": "sid_token_2_secret", "uid": "sess-uid-2"}))  # login response
    server.handlers.append(
        (200, {"objects": [{"uid": "h1", "name": "host-1"}], "total": 1})
    )  # retried show-hosts response

    res3 = await client.api_call("mds1", "show-hosts", domain="Corp")
    assert res3.success is True
    assert res3.data["total"] == 1
    cached_after_retry = await client.cache.get_sid("mds1", "Corp")
    assert cached_after_retry is not None
    assert cached_after_retry.sid == "sid_token_2_secret"

    # 4. Background keepalive returns success=False -> immediately evicts SID from sid_cache
    server.handlers.append((400, {"code": "err_session_expired", "message": "Session expired"}))
    keepalive_ok = await client.login_coordinator.keepalive_sid("mds1", "Corp")
    assert keepalive_ok is False
    assert await client.cache.get_sid("mds1", "Corp") is None

    await client.close()


async def test_dedicated_write_session_bypasses_sid_cache_and_updates_overlay(tmp_path: Path) -> None:
    """Scenarios:
    - Dedicated write sessions bypass global SID cache and call logout_sid when finished
    - WriteSession opens under administrator credentials, updates SessionOverlay via contextvars,
      auto-publishes on clean exit (invalidating domain), and discards on exception
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)

    # Seed baseline cached objects and services in SQLite cache
    existing_host = CPObject(
        uid="h-existing",
        name="web-01",
        type="host",
        mgmt_name="mds1",
        domain_name="Corp",
        ipv4_address="10.1.1.10",
    )
    to_delete_host = CPObject(
        uid="h-delete",
        name="legacy-01",
        type="host",
        mgmt_name="mds1",
        domain_name="Corp",
        ipv4_address="10.1.1.99",
    )
    await client.db.initialize()
    await client.cache.replace_domain_objects("mds1", "Corp", [existing_host, to_delete_host], types=["host"])

    admin_creds = AuthContext(username="alice", password="alice-secret-password")

    # Configure handlers for add-host, set-host, delete-host, and add-service-tcp inside WriteSession
    async with client.write_session("mds1", "Corp", auth=admin_creds) as ws:
        # Verify global sid_cache is untouched by write_session
        assert await client.cache.get_sid("mds1", "Corp") is None
        assert get_write_session("mds1", "Corp") is ws

        # Verify login used alice's admin credentials
        login_call = next(c for c in reversed(server.calls) if c["command"] == "login")
        assert login_call["payload"]["user"] == "alice"

        # 1. add-host
        server.handlers.append(
            (
                200,
                {
                    "uid": "h-new",
                    "name": "app-01",
                    "type": "host",
                    "ipv4-address": "10.1.1.20",
                },
            )
        )
        await client.api_call("mds1", "add-host", {"name": "app-01", "ipv4-address": "10.1.1.20"}, domain="Corp")

        # 2. set-host (update web-01 IP)
        server.handlers.append(
            (
                200,
                {
                    "uid": "h-existing",
                    "name": "web-01",
                    "type": "host",
                    "ipv4-address": "10.1.1.11",
                },
            )
        )
        await client.api_call("mds1", "set-host", {"name": "web-01", "ipv4-address": "10.1.1.11"}, domain="Corp")

        # 3. delete-host (delete legacy-01)
        server.handlers.append((200, {"message": "OK"}))
        await client.api_call("mds1", "delete-host", {"name": "legacy-01"}, domain="Corp")

        # 4. add-service-tcp
        server.handlers.append(
            (
                200,
                {
                    "uid": "svc-new",
                    "name": "tcp-8443",
                    "type": "service-tcp",
                    "port": "8443",
                },
            )
        )
        await client.api_call("mds1", "add-service-tcp", {"name": "tcp-8443", "port": "8443"}, domain="Corp")

        # Verify overlay reflects uncommitted creations, updates, and deletions without modifying DB!
        db_hosts = await client.cache.get_objects("mds1", "Corp", types=["host"])
        assert len(db_hosts) == 2  # DB still has original 2 rows

        merged_hosts = ws.overlay.apply_to_objects(db_hosts, types=["host"])
        by_name = {h.name: h for h in merged_hosts}
        assert set(by_name.keys()) == {"web-01", "app-01"}  # legacy-01 excluded, app-01 added
        assert by_name["web-01"].ipv4_address == "10.1.1.11"  # updated IP reflected

        merged_svcs = ws.overlay.apply_to_services([], types=["service-tcp"])
        assert len(merged_svcs) == 1
        assert merged_svcs[0].name == "tcp-8443"

    # After exiting write_session cleanly: publish + show-task + logout ran, and domain was invalidated
    assert ws.published is True
    assert ("mds1", "Corp") in client.invalidated_domains
    commands_run = [c["command"] for c in server.calls]
    assert "publish" in commands_run
    assert commands_run[-1] == "logout"

    # Now test exception inside write_session -> triggers discard and logout, not publish
    server.calls.clear()
    with pytest.raises(RuntimeError, match="aborting"):
        async with client.write_session("mds1", "Corp", auth=admin_creds) as ws_fail:
            server.handlers.append((200, {"uid": "h-temp", "name": "temp", "type": "host"}))
            await client.api_call("mds1", "add-host", {"name": "temp"}, domain="Corp")
            assert len(ws_fail.overlay.upserted_objects) == 1
            raise RuntimeError("aborting")

    assert ws_fail.discarded is True
    assert ws_fail.published is False
    assert len(ws_fail.overlay.upserted_objects) == 0
    fail_commands = [c["command"] for c in server.calls]
    assert "discard" in fail_commands
    assert "publish" not in fail_commands
    assert fail_commands[-1] == "logout"

    await client.close()


async def test_dynamic_authentication_and_fast_fail_on_invalid_credentials(tmp_path: Path) -> None:
    """Scenarios:
    - Cold startup in dynamic auth mode skips network cleanup without error
    - Dynamic authentication resolves credentials from AuthContext / AuthProvider
    - Credential rejection fails fast with InvalidCredentialsError (not retrying transient loops),
      evicts stale credentials, and notifies AuthProvider.on_auth_failed
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()

    failed_notifications: list[tuple[str, AuthContext, Exception]] = []

    class CustomAuthProvider:
        def __init__(self) -> None:
            self.calls = 0

        async def get_credentials(
            self,
            mgmt_name: str,
            domain: str | None = None,
            *,
            user: UserContext | None = None,
        ) -> AuthContext:
            self.calls += 1
            return AuthContext(username="dyn_admin", password="stale_password")

        async def on_auth_failed(self, mgmt_name: str, auth: AuthContext, exc: Exception) -> None:
            failed_notifications.append((mgmt_name, auth, exc))

    provider = CustomAuthProvider()
    dyn_settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1")
    assert dyn_settings.auth_mode == "dynamic"

    client = _build_client(tmp_path, server, rig, settings=dyn_settings, auth_provider=provider)

    # 1. Cold startup in dynamic mode skips network session cleanup cleanly
    async with client:
        assert len(server.calls) == 0

        # 2. AuthContext via contextvars works for API calls
        with auth_context(username="ctx_admin", password="valid_password"):
            res = await client.api_call("mds1", "show-hosts", domain="Corp")
            assert res.success is True
            assert server.login_counter == 1

        # 3. Now test InvalidCredentialsError via AuthProvider on another domain:
        # Check Point returns "Authentication to server failed" -> fails fast (1 attempt, 0 sleeps),
        # notifies AuthProvider.on_auth_failed, and evicts those credentials!
        server.calls.clear()
        rig.sleeps.clear()
        server.handlers.append(
            (400, {"code": "generic_err_login_failed", "message": "Authentication to server failed."})
        )

        with pytest.raises(InvalidCredentialsError) as exc_info:
            await client.api_call("mds1", "show-hosts", domain="DMZ")

        assert isinstance(exc_info.value, AuthenticationError)
        assert len(server.calls) == 1  # Fast fail: did NOT retry!
        assert rig.sleeps == []
        assert len(failed_notifications) == 1
        assert failed_notifications[0][0] == "mds1"
        assert failed_notifications[0][1].username == "dyn_admin"

        # Subsequent attempt with the same evicted identity fails immediately before hitting network
        with pytest.raises(InvalidCredentialsError, match="previously rejected and evicted"):
            await client.api_call("mds1", "show-hosts", domain="DMZ")
        assert len(server.calls) == 1


async def test_throttled_login_waits_70s_and_transient_revision_retries(tmp_path: Path) -> None:
    """Scenarios:
    - Throttled login waits out Check Point throttle window (default 70s) before retrying
    - Transient 'Database revision is in progress' retries with backoff instead of raising InvalidCredentialsError
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)

    # 1st attempt: throttled (HTTP 429 / too many login attempts) -> waits 70s
    # 2nd attempt: Database revision is in progress -> waits transient backoff (2s)
    # 3rd attempt: succeeds!
    server.handlers.append((429, {"code": "err_too_many_requests", "message": "Too many login attempts, throttled"}))
    server.handlers.append((400, {"code": "err_login_failed", "message": "Database revision is in progress"}))
    server.handlers.append((200, {"sid": "sid_recovered_123", "uid": "u-rec"}))
    server.handlers.append((200, {"objects": [], "total": 0}))

    res = await client.api_call("mds1", "show-hosts", domain="Corp")
    assert res.success is True
    assert 70.0 in rig.sleeps
    assert 2.0 in rig.sleeps
    await client.close()


async def test_startup_cleanup_seeds_system_domain_sid_when_cache_empty(tmp_path: Path) -> None:
    """Scenario: Startup cleanup seeds system domain SID when cache is empty."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    # Configure show-sessions response with 1 stale session to discard
    server.handlers.append((200, {"sid": "sid_seeded_system_1", "uid": "cleaner-uid"}))
    server.handlers.append(
        (
            200,
            {
                "objects": [
                    {
                        "uid": "stale-sess-1",
                        "application": "WEB_API",
                        "changes": 0,
                        "locks": 0,
                        "session-name": "arodonata-old",
                    }
                ]
            },
        )
    )
    server.handlers.append((200, {"message": "OK"}))  # discard stale-sess-1

    outcomes = await client.session_cleaner.run_startup_cleanup()
    assert outcomes == {"mds1": True}

    # The cleaner's session MUST be retained in sid_cache for System Data rather than logged out!
    seeded = await client.cache.get_sid("mds1", SYSTEM_DOMAIN_SENTINEL)
    assert seeded is not None
    assert seeded.sid == "sid_seeded_system_1"
    commands = [c["command"] for c in server.calls]
    assert commands == ["login", "show-sessions", "discard"]  # No logout!

    # Subsequent system-domain read call reuses the seeded SID without logging in again
    res = await client.api_call("mds1", "show-domains")
    assert res.success is True
    assert server.calls[-1]["sid"] == "sid_seeded_system_1"

    await client.close()


async def test_active_domain_server_failover_re_resolution(tmp_path: Path) -> None:
    """Scenario: Active domain server failover re-resolution."""
    der, fp = _make_der()
    server = FakeCheckpointServer()
    rig = FakeTimeRig()

    # Trust both 10.0.0.1 (MDS), 10.0.0.11 (old standby CMA), and 10.0.0.12 (new active CMA)
    cfg = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="static-secret-key",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp},10.0.0.11:443={fp},10.0.0.12:443={fp}",
    )
    client = _build_client(tmp_path, server, rig, settings=cfg)
    await client.db.initialize()

    # Seed stale domain record pointing to 10.0.0.11 as active_ip
    await client.cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="mds1",
                uid="dom-1",
                name="BranchDomain",
                active_ip="10.0.0.11",
                active_mds_ip="10.0.0.1",
                standby_ips=["10.0.0.12"],
            )
        ]
    )

    # 1. Login to 10.0.0.11 fails with domain failover error ("Domain is not active on this server")
    server.handlers.append((400, {"code": "err_domain_not_active", "message": "Domain is not active on this server"}))
    # 2. LoginCoordinator queries MDS system domain (10.0.0.1) via show-domains
    server.handlers.append((200, {"sid": "sid_sys_mds", "uid": "sys-1"}))
    server.handlers.append(
        (
            200,
            {
                "objects": [
                    {
                        "uid": "dom-1",
                        "name": "BranchDomain",
                        "servers": [
                            {"ipv4-address": "10.0.0.11", "active": False},
                            {
                                "ipv4-address": "10.0.0.12",
                                "active": True,
                                "multi-domain-server": {"ipv4-address": "10.0.0.2"},
                            },
                        ],
                    }
                ]
            },
        )
    )
    # 3. Retried login goes to new active_ip 10.0.0.12 and succeeds!
    server.handlers.append((200, {"sid": "sid_branch_new", "uid": "b-1"}))
    server.handlers.append((200, {"objects": [{"uid": "h-branch"}], "total": 1}))

    res = await client.api_call("mds1", "show-hosts", domain="BranchDomain")
    assert res.success is True
    assert res.data["total"] == 1

    # Verify domains table was updated with new active_ip and active_mds_ip
    updated_dom = await client.cache.get_domain("mds1", "BranchDomain")
    assert updated_dom is not None
    assert updated_dom.active_ip == "10.0.0.12"
    assert updated_dom.active_mds_ip == "10.0.0.2"

    await client.close()


async def test_identity_errors_are_never_retried_in_login_or_keepalive(tmp_path: Path) -> None:
    """Scenario: Identity errors are never retried in login, keepalive, or task-wait loops."""
    der_bad, _ = _make_der("untrusted-cert")
    _, fp_good = _make_der("trusted-cert")
    server = FakeCheckpointServer()

    cfg = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="static-secret-key",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp_good}",
    )
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp_good}",
    )
    cert_checks = 0

    def bad_cert_getter(_h: str, _p: int) -> bytes:
        nonlocal cert_checks
        cert_checks += 1
        return der_bad

    transport = ApiTransport(
        settings=cfg,
        trust_policy=policy,
        peer_cert_getter=bad_cert_getter,
        request_sender=server.sender,
    )
    client = AMgmtClient(settings=cfg, transport=transport, trust_policy=policy)

    with pytest.raises(ServerIdentityError):
        await client.api_call("mds1", "show-hosts")

    assert cert_checks == 1
    assert len(server.calls) == 0
    await client.close()
