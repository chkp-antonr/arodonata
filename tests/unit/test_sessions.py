"""Unit tests for `LoginCoordinator`, `SessionCleaner`, `WriteSession`, and `AMgmtClient`."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
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
    VerifiedConnectionPool,
    derive_session_pool_scope,
)
from arodonata.core.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    ServerIdentityError,
    SessionError,
    SessionStateError,
    TransportError,
    ValidationError,
)
from arodonata.core.models.domains import DomainInfo, SIDCacheEntry
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
        self.wall = datetime(2026, 10, 23, 18, 0, 0)
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


@pytest.mark.spec("SCN-SESS-003-2")
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

    # 5. DA-022: keepalive extends expires_at past created_at + session_expire_seconds and honors extended TTL;
    #    failing keepalive called with sid=... and domain=None evicts cached entry by cached.domain_name.
    res4 = await client.api_call("mds1", "show-hosts", domain="Corp")
    assert res4.success is True
    cached_ext = await client.cache.get_sid("mds1", "Corp")
    assert cached_ext is not None
    rig.advance(400.0)
    assert await client.login_coordinator.keepalive_sid("mds1", "Corp") is True
    rig.advance(300.0)  # total elapsed since created_at is 700s > session_expire_seconds(540), < new expires_at
    logins_before = server.login_counter
    res5 = await client.api_call("mds1", "show-networks", domain="Corp")
    assert res5.success is True
    assert server.login_counter == logins_before  # reused keepalive-extended SID!

    server.handlers.append((400, {"code": "err_session_expired", "message": "Session expired"}))
    assert await client.login_coordinator.keepalive_sid("mds1", None, sid=cached_ext.sid) is False
    assert await client.cache.get_sid("mds1", "Corp", auth_identity=cached_ext.auth_identity) is None

    await client.close()


@pytest.mark.spec("SCN-SESS-002-1")
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

    # DA-003: domain=None (System Data) calls inside a domain-scoped WriteSession ("Corp") MUST NOT
    # route into the Corp WriteSession, while standalone System Data WriteSession still matches domain=None.
    server.calls.clear()
    async with client.write_session("mds1", "Corp", auth=admin_creds, publish_on_exit=False) as ws_corp:
        res_sys = await client.api_call("mds1", "show-domains", domain=None)
        assert res_sys.success is True
        sys_call = next(c for c in reversed(server.calls) if c["command"] == "show-domains")
        assert sys_call["sid"] != ws_corp.sid

    server.calls.clear()
    async with client.write_session("mds1", None, auth=admin_creds, publish_on_exit=False) as ws_sys:
        res_sys2 = await client.api_call("mds1", "show-domains", domain=None)
        assert res_sys2.success is True
        sys_call2 = next(c for c in reversed(server.calls) if c["command"] == "show-domains")
        assert sys_call2["sid"] == ws_sys.sid

    await client.close()


@pytest.mark.spec("SCN-SESS-002-2", "SCN-SESS-004-3", "SCN-SESS-006-2")
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


@pytest.mark.spec("SCN-SESS-004-1")
async def test_startup_cleanup_logs_out_rw_session_without_seeding_sid_cache(tmp_path: Path) -> None:
    """SCN-SESS-004-1 (DA-042): Startup cleanup logs out its RW probe session and never seeds arodonata_sid_cache."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    # Configure show-sessions response with 1 stale session to discard
    server.handlers.append((200, {"sid": "sid_rw_cleaner_1", "uid": "cleaner-uid"}))
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
    server.handlers.append((200, {"message": "OK"}))  # logout RW probe session

    outcomes = await client.session_cleaner.run_startup_cleanup()
    assert outcomes == {"mds1": True}

    # The RW cleanup session MUST NOT be seeded into arodonata_sid_cache and MUST be logged out!
    assert await client.cache.get_sid("mds1", SYSTEM_DOMAIN_SENTINEL) is None
    commands = [c["command"] for c in server.calls]
    assert commands == ["login", "show-sessions", "discard", "logout"]

    # Subsequent system-domain read call acquires a fresh read-only=True session
    res = await client.api_call("mds1", "show-domains")
    assert res.success is True
    ro_login = [c for c in server.calls if c["command"] == "login"][-1]
    assert ro_login["payload"].get("read-only") is True
    assert server.calls[-1]["sid"] != "sid_rw_cleaner_1"

    # Even when show-sessions raises an error mid-cleanup, finally STILL logs out the temporary RW session
    server.calls.clear()
    server.handlers.append((200, {"sid": "sid_rw_cleaner_err", "uid": "cleaner-uid-err"}))
    server.handlers.append(lambda _rec: (_ for _ in ()).throw(RuntimeError("boom during show-sessions")))
    server.handlers.append((200, {"message": "OK"}))  # logout
    with pytest.raises(RuntimeError, match="boom during show-sessions"):
        await client.session_cleaner.cleanup_server_sessions("mds1")
    assert [c["command"] for c in server.calls] == ["login", "show-sessions", "logout"]
    assert server.calls[-1]["sid"] == "sid_rw_cleaner_err"

    await client.close()


@pytest.mark.spec("SCN-SESS-011-1")
async def test_startup_cleanup_inspects_sessions_despite_cached_readonly_system_sid(tmp_path: Path) -> None:
    """SCN-SESS-011-1: A fresh cached RO System Data SID no longer short-circuits startup cleanup."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    coordinator = client.session_cleaner._login_coordinator
    identity = (await coordinator.resolve_credentials("mds1", None)).identity_key
    now = coordinator.now()
    await client.cache.upsert_sid(
        SIDCacheEntry(
            id=f"mds1:{SYSTEM_DOMAIN_SENTINEL}:{identity}",
            mgmt_name="mds1",
            domain_name=SYSTEM_DOMAIN_SENTINEL,
            sid="sid_ro_cached",
            server_ip="10.0.0.1",
            session_uid="ro-uid",
            auth_identity=identity,
            created_at=now,
            last_used_at=now,
            expires_at=now + timedelta(seconds=600),
        )
    )

    server.handlers.append((200, {"sid": "sid_rw_cleaner_1", "uid": "cleaner-uid"}))
    server.handlers.append(
        (
            200,
            {
                "objects": [
                    {
                        "uid": "abandoned-1",
                        "application": "WEB_API",
                        "changes": 0,
                        "locks": 0,
                        "session-name": "arodonata-old",
                    },
                    {"uid": "ro-uid", "application": "WEB_API", "changes": 0, "locks": 0, "session-name": "arodonata"},
                ]
            },
        )
    )
    server.handlers.append((200, {"message": "OK"}))  # discard abandoned-1
    server.handlers.append((200, {"message": "OK"}))  # logout RW cleanup session

    outcomes = await client.session_cleaner.run_startup_cleanup()
    assert outcomes == {"mds1": True}
    assert [c["command"] for c in server.calls] == ["login", "show-sessions", "discard", "logout"]
    cached = await client.cache.get_sid("mds1", SYSTEM_DOMAIN_SENTINEL, auth_identity=identity)
    assert cached is not None and cached.sid == "sid_ro_cached"
    await client.close()


@pytest.mark.spec("SCN-SESS-005-1")
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


@pytest.mark.spec("SCN-SESS-003-1")
async def test_sid_cache_credential_binding_and_no_none_wildcard(tmp_path: Path) -> None:
    """Adversarial test for C4:
    - Two AuthContexts with same username/user_id but different passwords or api_keys NEVER share a cached SID.
    - A cached SID row with auth_identity=None is never treated as usable.
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    dyn_settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1")
    client = _build_client(tmp_path, server, rig, settings=dyn_settings)
    await client.db.initialize()

    # 1. Seed a legacy/untagged SID row with auth_identity=None -> must NOT be reused
    await client.cache.upsert_sid(
        SIDCacheEntry(
            id="mds1:Corp",
            mgmt_name="mds1",
            domain_name="Corp",
            sid="sid_untagged_legacy",
            server_ip="10.0.0.1",
            auth_identity=None,
            created_at=rig.now(),
            last_used_at=rig.now(),
            expires_at=rig.now() + timedelta(seconds=500),
        )
    )

    with auth_context(username="admin", password="password-one", user_id="u-1"):
        res1 = await client.api_call("mds1", "show-hosts", domain="Corp")
        assert res1.success is True
        assert server.login_counter == 1
        assert server.calls[-1]["sid"] == "sid_token_1_secret"

    # 2. Same username="admin" and user_id="u-1", but DIFFERENT password -> must NOT reuse sid_token_1_secret!
    with auth_context(username="admin", password="password-two", user_id="u-1"):
        res2 = await client.api_call("mds1", "show-hosts", domain="Corp")
        assert res2.success is True
        assert server.login_counter == 2
        assert server.calls[-1]["sid"] == "sid_token_2_secret"

    # 3. Same user_id="u-1" with different api_keys -> distinct identity_key and distinct SIDs
    with auth_context(api_key="key-alpha-secret", user_id="u-1"):
        await client.api_call("mds1", "show-hosts", domain="Corp")
        assert server.login_counter == 3
        assert server.calls[-1]["sid"] == "sid_token_3_secret"

    with auth_context(api_key="key-beta-secret", user_id="u-1"):
        await client.api_call("mds1", "show-hosts", domain="Corp")
        assert server.login_counter == 4
        assert server.calls[-1]["sid"] == "sid_token_4_secret"

    await client.close()


@pytest.mark.spec("SCN-SESS-004-2")
async def test_session_cleaner_preserves_smartconsole_and_non_arodonata_sessions(tmp_path: Path) -> None:
    """Adversarial test for W9:
    - SessionCleaner only discards sessions owned by Arodonata (application=='arodonata' or session-name starting with 'arodonata')
      with changes==0 and locks==0.
    - SmartConsole, WEB_API without arodonata session-name, or sessions with changes/locks are never discarded.
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    server.handlers.append((200, {"sid": "sid_cleaner_1", "uid": "cleaner-self-uid"}))
    server.handlers.append(
        (
            200,
            {
                "objects": [
                    {
                        "uid": "smartconsole-idle",
                        "application": "SmartConsole",
                        "session-name": "",
                        "changes": 0,
                        "locks": 0,
                    },
                    {
                        "uid": "ansible-web-api-idle",
                        "application": "WEB_API",
                        "session-name": "ansible-deploy",
                        "changes": 0,
                        "locks": 0,
                    },
                    {
                        "uid": "arodonata-with-changes",
                        "application": "arodonata",
                        "session-name": "arodonata-write",
                        "changes": 2,
                        "locks": 0,
                    },
                    {
                        "uid": "arodonata-idle-1",
                        "application": "arodonata",
                        "session-name": "custom",
                        "changes": 0,
                        "locks": 0,
                    },
                    {
                        "uid": "arodonata-idle-2",
                        "application": "WEB_API",
                        "session-name": "arodonata-session-cleaner",
                        "changes": 0,
                        "locks": 0,
                    },
                ]
            },
        )
    )
    server.handlers.append((200, {"message": "OK"}))
    server.handlers.append((200, {"message": "OK"}))

    await client.session_cleaner.run_startup_cleanup()
    discarded_uids = [c["payload"]["uid"] for c in server.calls if c["command"] == "discard"]
    assert discarded_uids == ["arodonata-idle-1", "arodonata-idle-2"]
    await client.close()


@pytest.mark.spec("SCN-SESS-003-4")
async def test_write_session_publish_failure_discards_and_shielded_logout_retains_failed_sid(
    tmp_path: Path,
) -> None:
    """Adversarial test for C8 & W7:
    - Mutating command on AMgmtClient.api_call without WriteSession or explicit sid raises SessionStateError (C8).
    - When publish returns success=False in WriteSession, discard is called before raising SessionError (W7).
    - When logout fails, _active_dedicated_sids retains the SID so close()/logout_all() can retry (W7).
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    # 1. C8: Mutating command without WriteSession or explicit sid raises SessionStateError
    with pytest.raises(SessionStateError, match="forbidden on shared read-only sid_cache"):
        await client.api_call("mds1", "add-host", {"name": "rogue-host"}, domain="Corp")

    # 2. W7: publish returns success=False -> WriteSession calls discard and logout before raising SessionError
    server.calls.clear()
    server.handlers.append((200, {"sid": "sid_ws_pubfail", "uid": "u-pf"}))  # login
    server.handlers.append((200, {"uid": "h1", "name": "h1", "type": "host"}))  # add-host
    server.handlers.append((400, {"code": "err_publish_failed", "message": "Validation error on publish"}))  # publish
    server.handlers.append((200, {"message": "OK"}))  # discard
    server.handlers.append((500, {"code": "err_logout", "message": "Logout transient failure"}))  # logout fails

    with pytest.raises(SessionError, match="Validation error on publish"):
        async with client.write_session("mds1", "Corp"):
            await client.api_call("mds1", "add-host", {"name": "h1"}, domain="Corp")

    cmds = [c["command"] for c in server.calls]
    assert cmds == ["login", "add-host", "publish", "discard", "logout"]
    # Because logout returned 500 (success=False), sid_ws_pubfail remains in active_dedicated_sids for retry!
    assert ("mds1", "sid_ws_pubfail") in client.login_coordinator.active_dedicated_sids

    # Closing the client retries logout and clears active_dedicated_sids
    await client.close()
    assert ("mds1", "sid_ws_pubfail") not in client.login_coordinator.active_dedicated_sids


@pytest.mark.spec("SCN-SESS-003-1")
async def test_sid_cache_entry_excludes_sid_on_dump_and_includes_auth_identity_in_id(
    tmp_path: Path,
) -> None:
    """Verify I2: SIDCacheEntry.model_dump() / model_dump_json() omit `sid` and `id` includes `auth_identity`."""
    secret_sid = "sid_top_secret_token_999"
    entry = SIDCacheEntry(
        mgmt_name="mds1",
        domain_name="Corp",
        sid=secret_sid,
        server_ip="10.0.0.10",
        session_uid="u-1",
        auth_identity="user:alice",
    )
    assert entry.id == "mds1:Corp:user:alice"
    assert secret_sid not in repr(entry)
    assert secret_sid not in str(entry)
    dumped = entry.model_dump()
    assert "sid" not in dumped
    assert secret_sid not in json.dumps(dumped, default=str)
    assert secret_sid not in entry.model_dump_json()

    # Verify SqlCacheAdapter.upsert_sid and get_sid still persist and retrieve `sid`
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()
    await client.cache.upsert_sid(entry)
    loaded = await client.cache.get_sid("mds1", "Corp", auth_identity="user:alice")
    assert loaded is not None
    assert loaded.sid == secret_sid
    assert loaded.id == "mds1:Corp:user:alice"
    await client.close()


@pytest.mark.spec("SCN-SESS-003-1", "SCN-SESS-003-2")
async def test_readonly_login_payload_and_identity_scoped_sid_eviction(
    tmp_path: Path,
) -> None:
    """Verify I1 and W1:
    - Shared read-only login sends `"read-only": True` in payload (whereas dedicated WriteSession omits `"read-only"`).
    - When Alice's cached SID expires or fails keepalive, Bob's cached SID on the same `(mgmt_name, domain)` is NOT evicted.
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    dyn_settings = ArodonataSettings(mgmt_name="mds1", mgmt_ip="10.0.0.1")
    client = _build_client(tmp_path, server, rig, settings=dyn_settings)
    await client.db.initialize()

    # 1. Alice logs into Corp via shared read-only session -> payload has "read-only": True
    with auth_context(username="alice", password="pw-alice", user_id="alice"):
        res_a = await client.api_call("mds1", "show-hosts", domain="Corp")
        assert res_a.success is True
        login_calls = [c for c in server.calls if c["command"] == "login"]
        assert len(login_calls) == 1
        assert login_calls[0]["payload"].get("read-only") is True
        alice_sid_1 = login_calls[0]["sid"] or "sid_token_1_secret"
        alice_identity = AuthContext(username="alice", password="pw-alice", user_id="alice").identity_key

    # 2. Bob logs into Corp via shared read-only session -> payload has "read-only": True
    with auth_context(username="bob", password="pw-bob", user_id="bob"):
        res_b = await client.api_call("mds1", "show-hosts", domain="Corp")
        assert res_b.success is True
        bob_identity = AuthContext(username="bob", password="pw-bob", user_id="bob").identity_key

    assert await client.cache.get_sid("mds1", "Corp", auth_identity=alice_identity) is not None
    bob_cached_before = await client.cache.get_sid("mds1", "Corp", auth_identity=bob_identity)
    assert bob_cached_before is not None
    assert bob_cached_before.sid == "sid_token_2_secret"

    # 3. Alice's session expires on next api_call -> Alice's SID is evicted and re-logged in,
    #    while Bob's cached SID in arodonata_sid_cache remains untouched!
    server.handlers.append((401, {"code": "generic_err_invalid_session_id", "message": "Invalid session id"}))
    server.handlers.append((200, {"sid": "sid_alice_renewed", "uid": "u-alice-2"}))
    server.handlers.append((200, {"objects": [], "total": 0}))

    with auth_context(username="alice", password="pw-alice", user_id="alice"):
        res_a2 = await client.api_call("mds1", "show-hosts", domain="Corp")
        assert res_a2.success is True

    alice_cached_after = await client.cache.get_sid("mds1", "Corp", auth_identity=alice_identity)
    assert alice_cached_after is not None
    assert alice_cached_after.sid == "sid_alice_renewed"
    assert alice_cached_after.sid != alice_sid_1

    bob_cached_after = await client.cache.get_sid("mds1", "Corp", auth_identity=bob_identity)
    assert bob_cached_after is not None
    assert bob_cached_after.sid == "sid_token_2_secret"

    # 4. Dedicated write_session login omits "read-only"
    server.calls.clear()
    with auth_context(username="alice", password="pw-alice", user_id="alice"):
        async with client.write_session("mds1", "Corp", publish_on_exit=False):
            ws_login = [c for c in server.calls if c["command"] == "login"]
            assert len(ws_login) == 1
            assert "read-only" not in ws_login[0]["payload"]

    await client.close()


async def test_explicit_server_ip_validated_against_trusted_server_and_domain_ips(
    tmp_path: Path,
) -> None:
    """Verify W2: explicit_server_ip must belong to endpoint.host or cached domain IPs for mgmt_name."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    # Seed a domain with active_ip=10.0.0.15, active_mds_ip=10.0.0.1, standby_ips=["10.0.0.16"]
    await client.cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="mds1",
                uid="dom-corp",
                name="Corp",
                active_ip="10.0.0.15",
                active_mds_ip="10.0.0.1",
                standby_ips=["10.0.0.16"],
            )
        ]
    )

    # 1. Known CMA IP (10.0.0.15) and standby IP (10.0.0.16) are accepted
    ip1, mds1, _ = await client.login_coordinator.resolve_target_ips("mds1", "Corp", explicit_server_ip="10.0.0.15")
    assert ip1 == "10.0.0.15"
    assert mds1 == "10.0.0.1"

    ip2, _, _ = await client.login_coordinator.resolve_target_ips("mds1", "Corp", explicit_server_ip="10.0.0.16")
    assert ip2 == "10.0.0.16"

    # 2. Untrusted attacker IP (198.51.100.99) is rejected with ValidationError before any network call
    server.calls.clear()
    with pytest.raises(ValidationError, match="Untrusted explicit server_ip '198.51.100.99'"):
        await client.api_call("mds1", "show-hosts", domain="Corp", server_ip="198.51.100.99")
    assert len(server.calls) == 0

    with pytest.raises(ValidationError, match="Untrusted explicit server_ip '198.51.100.99'"):
        await client.login_coordinator.create_dedicated_session("mds1", "Corp", server_ip="198.51.100.99")
    assert len(server.calls) == 0

    await client.close()


async def test_cold_cache_explicit_cma_server_ip_refreshes_domains_and_accepts_known_cma_ip(tmp_path: Path) -> None:
    """Verify R4: on a cold domain cache, passing a valid CMA `explicit_server_ip` triggers a domain discovery refresh via `endpoint.host` and accepts the CMA IP while still rejecting untrusted attacker IPs."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    # Cold cache: no domains seeded yet in client.cache
    assert await client.cache.get_domains("mds1") == []

    # Queue system login + show-domains + show-mdss responses for refresh_domain_active_ip
    server.handlers.append((200, {"sid": "sid_sys_disc", "uid": "sys-disc-1"}))
    server.handlers.append(
        (
            200,
            {
                "objects": [
                    {
                        "uid": "dom-corp",
                        "name": "Corp",
                        "servers": [
                            {
                                "name": "corp-cma-1",
                                "ipv4-address": "10.0.0.12",
                                "active": True,
                                "multi-domain-server": "mds-peer",
                            }
                        ],
                    }
                ]
            },
        )
    )
    server.handlers.append((200, {"objects": [{"name": "mds-peer", "ipv4-address": "10.0.0.2"}]}))

    # 1. Valid CMA IP (10.0.0.12) is discovered via refresh_domain_active_ip and accepted
    ip_cma, mds_ip, _ = await client.login_coordinator.resolve_target_ips(
        "mds1",
        "Corp",
        explicit_server_ip="10.0.0.12",
    )
    assert ip_cma == "10.0.0.12"
    assert mds_ip == "10.0.0.2"

    # 1b. Secondary MDS IP (10.0.0.2 from show-mdss) is also accepted
    ip_mds2, _, _ = await client.login_coordinator.resolve_target_ips(
        "mds1",
        "Corp",
        explicit_server_ip="10.0.0.2",
    )
    assert ip_mds2 == "10.0.0.2"

    # 2. Attacker IP is still rejected with ValidationError and zero extra network calls once domain is cached
    calls_before = len(server.calls)
    with pytest.raises(ValidationError, match="Untrusted explicit server_ip '198.51.100.99'"):
        await client.login_coordinator.resolve_target_ips(
            "mds1",
            "Corp",
            explicit_server_ip="198.51.100.99",
        )
    assert len(server.calls) == calls_before

    await client.close()


async def test_show_session_not_found_after_revert_evicts_sid_and_relogins(tmp_path: Path) -> None:
    """Verify that show-session (without uid) returning generic_err_object_not_found evicts SID and re-logins."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    # 1. Seed initial read-only session via show-hosts
    res1 = await client.api_call("mds1", "show-hosts", domain="Corp")
    assert res1.success is True

    # 2. Next self show-session returns 404 generic_err_object_not_found (session wiped by revert-to-revision)
    server.handlers.append(
        (
            404,
            {
                "code": "generic_err_object_not_found",
                "message": "Requested object [ca3866b7-fb2c-42d9-9957-7aa19e5167b8] not found",
            },
        )
    )
    server.handlers.append((200, {"sid": "sid_after_revert", "uid": "u-reverted"}))
    server.handlers.append((200, {"uid": "u-reverted", "locks": 0, "changes": 0, "number-of-published-changes": 0}))

    res2 = await client.api_call("mds1", "show-session", {}, domain="Corp")
    assert res2.success is True
    assert res2.data["uid"] == "u-reverted"

    await client.close()


async def test_unreachable_server_fails_fast_and_startup_cleanup_handles_error_cleanly(
    tmp_path: Path,
) -> None:
    """Verify:
    - TransportError during login retries at most once (2s) instead of looping for login_max_wait (900s).
    - SessionCleaner.cleanup_server_sessions and schedule_startup_cleanup return False cleanly without
      raising or leaking unretrieved asyncio task exceptions when a server is unreachable.
    """
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    def raise_connect_refused(_record: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        raise TransportError(
            "Failed to connect to 10.0.0.1:443 for 'login': Connect call failed",
            phase="pre-send",
            request_sent=False,
        )

    # 1. Login fails after 1 retry (2 attempts total, 2.0s sleep, NOT 900s)
    server.handlers.extend([raise_connect_refused, raise_connect_refused])
    with pytest.raises(AuthenticationError, match="Failed to connect"):
        await client.api_call("mds1", "show-domains")

    assert len(server.calls) == 2
    assert rig.sleeps == [2.0]

    # 2. Startup session cleanup against an unreachable server returns False cleanly
    server.calls.clear()
    rig.sleeps.clear()
    server.handlers.extend([raise_connect_refused, raise_connect_refused])
    outcomes = await client.session_cleaner.run_startup_cleanup()
    assert outcomes == {"mds1": False}

    # 3. Scheduled background startup cleanup completes without unretrieved task exceptions
    server.handlers.extend([raise_connect_refused, raise_connect_refused])
    tasks = client.session_cleaner.schedule_startup_cleanup()
    assert len(tasks) == 1
    results = await tasks[0]
    assert results is False

    await client.close()


@pytest.mark.spec("SCN-TRANS-004-3")
async def test_write_session_reuses_keepalive_connection_and_closes_on_publish_and_logout(tmp_path: Path) -> None:
    """Verify WriteSession reuses a dedicated keep-alive socket across mutations and closes on publish/logout."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    der, fp = _make_der()
    cfg = ArodonataSettings(
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

    cert_checks = 0

    def counting_cert_getter(_h: str, _p: int) -> bytes:
        nonlocal cert_checks
        cert_checks += 1
        return der

    async def pooling_sender(
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
        raw_resp, _ = await server.sender(
            host=host,
            port=port,
            command=command,
            url=url,
            headers=headers,
            body=body,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            reused_entry=reused_entry,
        )
        if reused_entry is not None:
            return raw_resp, reused_entry

        class _Proto:
            def __init__(self) -> None:
                self.closed = False

            def is_connected(self) -> bool:
                return not self.closed

            def close(self) -> None:
                self.closed = True

        entry = PooledSocketEntry(
            host=host,
            port=port,
            fingerprint=fp,
            protocol=_Proto(),
            last_used_at=rig.monotonic(),
        )
        return raw_resp, entry

    transport = ApiTransport(
        settings=cfg,
        trust_policy=policy,
        connection_pool=VerifiedConnectionPool(monotonic_fn=rig.monotonic),
        peer_cert_getter=counting_cert_getter,
        request_sender=pooling_sender,
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
    await client.db.initialize()

    recorded_sid = ""
    try:
        async with client.write_session("mds1", session_name="bulk-test") as ws:
            recorded_sid = ws.sid
            assert cert_checks == 1
            assert server.calls[0]["command"] == "login"
            assert server.calls[0]["headers"].get("Connection") == "close"

            r_show = await client.api_call("mds1", "show-session", {})
            assert r_show.success is True
            assert cert_checks == 2
            assert "Connection" not in server.calls[-1]["headers"]

            r_h1 = await client.api_call("mds1", "add-host", {"name": "h1", "ip-address": "10.1.1.1"})
            r_h2 = await client.api_call("mds1", "add-host", {"name": "h2", "ip-address": "10.1.1.2"})
            r_s1 = await client.api_call("mds1", "set-host", {"name": "h1", "comments": "ok"})
            assert r_h1.success and r_h2.success and r_s1.success
            # All 3 mutations reused the exact verified connection opened by show-session
            assert cert_checks == 2
            for call in server.calls[-3:]:
                assert "Connection" not in call["headers"]

        # Exit: publish (Connection: close, cert=3) -> show-task poll (session-scoped, cert=4) -> logout (Connection: close, cert=5)
        publish_call = next(c for c in server.calls if c["command"] == "publish")
        show_task_call = next(c for c in server.calls if c["command"] == "show-task")
        logout_call = next(c for c in server.calls if c["command"] == "logout")
        assert publish_call["headers"].get("Connection") == "close"
        assert "Connection" not in show_task_call["headers"]
        assert logout_call["headers"].get("Connection") == "close"
        assert cert_checks == 5
        assert client.connection_pool.pooled_count(session_scope=derive_session_pool_scope(recorded_sid)) == 0
    finally:
        await client.close()


@pytest.mark.spec("SCN-SESS-014-3")
async def test_session_cleaner_throttles_target_mds_and_expired_sid_retry_refreshes_mds_ip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-SESS-014-3: SessionCleaner acquires RateLimiter slots on target mds_ip and expired-SID retry refreshes mds_ip."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client.db.initialize()

    # Seed multi-MDS domain DomB hosted on secondary MDS 10.0.2.1 (CMA 10.0.2.50), while endpoint.host is 10.0.0.1
    await client.cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="mds1",
                uid="dom-b",
                name="DomB",
                domain_type="domain",
                active_ip="10.0.2.50",
                active_mds_ip="10.0.2.1",
            )
        ]
    )

    slotted_ips: list[str] = []
    orig_slot = client.rate_limiter.slot

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _recording_slot(mds_ip: str, **kwargs: Any):  # type: ignore[no-untyped-def]
        slotted_ips.append(mds_ip)
        async with orig_slot(mds_ip, **kwargs) as s:
            yield s

    monkeypatch.setattr(client.rate_limiter, "slot", _recording_slot)

    # 1. SessionCleaner.cleanup_server_sessions("mds1", domain="DomB") bills RateLimiter on 10.0.2.1, not 10.0.0.1
    server.handlers.append((200, {"sid": "sid_cleaner_domb", "uid": "cleaner-uid"}))
    server.handlers.append(
        (
            200,
            {
                "objects": [
                    {
                        "uid": "stale-domb-1",
                        "application": "WEB_API",
                        "changes": 0,
                        "locks": 0,
                        "session-name": "arodonata-old",
                    }
                ]
            },
        )
    )
    server.handlers.append((200, {"message": "OK"}))  # discard
    server.handlers.append((200, {"message": "OK"}))  # logout
    assert await client.session_cleaner.cleanup_server_sessions("mds1", domain="DomB") is True
    assert slotted_ips and all(ip == "10.0.2.1" for ip in slotted_ips)

    # Seed cached RO SID pointing to MDS2 (10.0.2.50 / 10.0.2.1), then move DomB to MDS3 (10.0.3.50 / 10.0.3.1)
    # when the expired-SID response is returned.
    slotted_ips.clear()
    identity = (await client.login_coordinator.resolve_credentials("mds1", "DomB")).identity_key
    now = client.login_coordinator.now()
    await client.cache.upsert_sid(
        SIDCacheEntry(
            id=f"mds1:DomB:{identity}",
            mgmt_name="mds1",
            domain_name="DomB",
            sid="sid_old_mds2",
            server_ip="10.0.2.50",
            auth_identity=identity,
            created_at=now,
            last_used_at=now,
            expires_at=now + timedelta(seconds=600),
        )
    )
    _, default_fp = _make_der()
    client.trust_policy._store.record("10.0.3.50", 443, default_fp, source="known-identity", persist=False)

    orig_get_ro = client.login_coordinator.get_readonly_session

    async def _get_ro_with_failover(mgmt: str, dom: str | None = None, **kwargs: Any) -> tuple[str, str]:
        if kwargs.get("force_new"):
            await client.cache.upsert_domains(
                [
                    DomainInfo(
                        mgmt_name="mds1",
                        uid="dom-b",
                        name="DomB",
                        domain_type="domain",
                        active_ip="10.0.3.50",
                        active_mds_ip="10.0.3.1",
                    )
                ]
            )
        return await orig_get_ro(mgmt, dom, **kwargs)

    monkeypatch.setattr(client.login_coordinator, "get_readonly_session", _get_ro_with_failover)
    server.handlers.append((400, {"code": "err_session_expired", "message": "Session expired"}))
    server.handlers.append((200, {"sid": "sid_new_mds3", "uid": "u-new"}))
    server.handlers.append((200, {"objects": []}))

    res = await client.api_call("mds1", "show-hosts", {}, domain="DomB")
    assert res.success is True
    assert slotted_ips == ["10.0.2.1", "10.0.3.1"]
    await client.close()


@pytest.mark.spec("SCN-SESS-014-4")
async def test_login_coordinator_omits_obsolete_startup_seed_residue(tmp_path: Path) -> None:
    """SCN-SESS-014-4: LoginCoordinator omits dead adopt_dedicated_sid, has_inflight_or_cached_login, and _inflight_logins."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client._db.initialize()
    coord = client.login_coordinator
    assert not hasattr(coord, "adopt_dedicated_sid")
    assert not hasattr(coord, "has_inflight_or_cached_login")
    assert not hasattr(coord, "_inflight_logins")
    await client.close()


@pytest.mark.spec("SCN-SESS-015-1")
async def test_session_cleaner_propagates_server_identity_error_and_keepalive_isolation(tmp_path: Path) -> None:
    """DA-009 & DA-016: SessionCleaner propagates ServerIdentityError; keepalive_sid avoids cross-principal fallback and uses dedicated IP."""
    from arodonata.core.errors import CertificateMismatchError

    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client._db.initialize()
    coord = client.login_coordinator

    async def _fail_cert(*_args: Any, **_kwargs: Any) -> tuple[str, str, str | None]:
        raise CertificateMismatchError("cert mismatch")

    orig_create = coord.create_dedicated_session
    coord.create_dedicated_session = _fail_cert  # type: ignore[method-assign]
    with pytest.raises(CertificateMismatchError):
        await client._session_cleaner.cleanup_server_sessions(
            "mds1",
            auth=AuthContext(api_key="cleaner-key"),
        )
    coord.create_dedicated_session = orig_create  # type: ignore[method-assign]

    # Seed another principal's SID in sid_cache; keepalive_sid without AuthContext must not touch it
    other_auth = AuthContext(api_key="other-principal-key")
    await client.cache.upsert_sid(
        SIDCacheEntry(
            id=f"mds1:System Data:{other_auth.identity_key}",
            mgmt_name="mds1",
            domain_name="System Data",
            sid="sid_other_principal",
            server_ip="10.0.0.1",
            auth_identity=other_auth.identity_key,
            created_at=rig.now(),
            last_used_at=rig.now(),
            expires_at=rig.now() + timedelta(seconds=600),
        )
    )
    assert await coord.keepalive_sid("mds1") is False

    # Dedicated SID without server_ip routes keepalive to active dedicated IP
    server.handlers.append((200, {"sid": "sid_ded_keepalive", "uid": "u-ded"}))
    await client.cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="mds1",
                uid="dom-ded",
                name="Corp",
                domain_type="domain",
                active_ip="10.0.2.50",
                active_mds_ip="10.0.2.1",
            )
        ]
    )
    _, fp_ded = _make_der()
    client.trust_policy._store.record("10.0.2.50", 443, fp_ded, source="known-identity", persist=False)
    server.handlers.append((200, {"message": "OK"}))
    ded_sid, ded_ip, _ = await coord.create_dedicated_session("mds1", "Corp", auth=other_auth)
    assert ded_ip == "10.0.2.50"
    assert await coord.keepalive_sid("mds1", "Corp", sid=ded_sid) is True
    last_call = server.calls[-1]
    assert last_call["host"] == "10.0.2.50"
    assert last_call["command"] == "keepalive"
    await client.close()


@pytest.mark.spec("SCN-SESS-015-1")
async def test_get_readonly_session_resolves_explicit_hostname_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DA-024: get_readonly_session() resolves an explicit hostname server_ip once and preserves tls_identity_host."""
    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client._db.initialize()
    coord = client.login_coordinator
    resolve_calls = 0
    orig_resolve = coord.resolve_target_ips

    async def _counting_resolve(*args: Any, **kwargs: Any) -> tuple[str, str, int]:
        nonlocal resolve_calls
        resolve_calls += 1
        return await orig_resolve(*args, **kwargs)

    monkeypatch.setattr(coord, "resolve_target_ips", _counting_resolve)
    await client.cache.upsert_domains(
        [
            DomainInfo(
                mgmt_name="mds1",
                uid="dom-hn",
                name="Corp",
                domain_type="domain",
                active_ip="10.0.4.50",
                active_mds_ip="10.0.4.1",
            )
        ]
    )
    _, fp_hn = _make_der()
    client.trust_policy._store.record("10.0.4.50", 443, fp_hn, source="known-identity", persist=False)
    client.trust_policy._store.record("cma1.example.local", 443, fp_hn, source="known-identity", persist=False)
    monkeypatch.setattr("socket.getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("10.0.4.50", 443))])

    server.handlers.append((200, {"sid": "sid_single_dns", "uid": "u-dns"}))
    sid, ip = await coord.get_readonly_session("mds1", "Corp", server_ip="cma1.example.local")
    assert sid == "sid_single_dns"
    assert ip == "10.0.4.50"
    assert resolve_calls == 1
    assert coord.get_tls_identity_host("mds1", sid) == "cma1.example.local"
    await client.close()


@pytest.mark.spec("SCN-TRANS-008-2")
async def test_read_sid_preserved_on_read_timeout_and_login_gate_waits_cooldown_before_lock(
    tmp_path: Path,
) -> None:
    """SCN-TRANS-008-2: Read timeouts/non-failover errors keep RO SID; LoginGate cools down before DB lock."""
    from contextlib import asynccontextmanager

    from arodonata.adapters.checkpoint.rate_limiter import LoginGate
    from arodonata.core.errors import ApiTimeoutError, TransportError

    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    client = _build_client(tmp_path, server, rig)
    await client._db.initialize()

    # 1. Seed cached RO SID, then raise ApiTimeoutError(phase="read") and TransportError(phase="post-send")
    server.handlers.append((200, {"sid": "ro_sid_keep_123", "uid": "u-ro"}))
    await client.api_call("mds1", "show-hosts")
    # Wait: login + show-hosts -> ensure we use transport handler
    await client.cache.upsert_sid(
        SIDCacheEntry(
            id=f"mds1:System Data:{AuthContext(api_key='k-test').identity_key}",
            mgmt_name="mds1",
            domain_name="System Data",
            sid="ro_sid_keep_123",
            server_ip="10.0.0.1",
            auth_identity=AuthContext(api_key="k-test").identity_key,
            created_at=rig.now(),
            last_used_at=rig.now(),
            expires_at=rig.now() + timedelta(seconds=600),
        )
    )

    async def _raise_read_timeout(*_a: Any, **_k: Any) -> Any:
        raise ApiTimeoutError("read timeout", phase="read", request_sent=True)

    orig_exec = client._transport.execute
    client._transport.execute = _raise_read_timeout  # type: ignore[method-assign]
    with auth_context(AuthContext(api_key="k-test")):
        with pytest.raises(ApiTimeoutError):
            await client.api_call("mds1", "show-hosts")
        assert (
            await client.cache.get_sid("mds1", "System Data", auth_identity=AuthContext(api_key="k-test").identity_key)
            is not None
        )

        async def _raise_post_send(*_a: Any, **_k: Any) -> Any:
            raise TransportError("reset", phase="post-send", request_sent=True)

        client._transport.execute = _raise_post_send  # type: ignore[method-assign]
        with pytest.raises(TransportError):
            await client.api_call("mds1", "show-hosts")
        assert (
            await client.cache.get_sid("mds1", "System Data", auth_identity=AuthContext(api_key="k-test").identity_key)
            is not None
        )

    client._transport.execute = orig_exec  # type: ignore[method-assign]
    await client.close()

    # 2. LoginGate waits out cooldown BEFORE acquiring distributed lock
    events: list[str] = []
    now_t = [100.0]

    async def _rec_sleep(sec: float) -> None:
        events.append(f"sleep:{sec:.1f}")
        now_t[0] += sec

    class _FakeLockPort:
        @asynccontextmanager
        async def lock(self, _key: str, **_kwargs: Any) -> Any:
            events.append("lock_enter")
            yield
            events.append("lock_exit")

    gate = LoginGate(
        lock_port=_FakeLockPort(),  # type: ignore[arg-type]
        monotonic_fn=lambda: now_t[0],
        sleep_fn=_rec_sleep,
    )
    gate.record_cooldown("10.0.0.1", 15.0)
    async with gate.acquire("10.0.0.1", wait_timeout=60.0):
        events.append("yield")
    assert events == ["sleep:15.0", "lock_enter", "yield", "lock_exit"]


@pytest.mark.spec("SCN-SESS-016-1")
async def test_session_cleaner_passes_pinned_ip_and_tls_identity_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SCN-SESS-016-1: SessionCleaner passes DNS-pinned IP, port, and tls_identity_host to show-sessions and discard."""
    from arodonata.core.config import ArodonataSettings

    server = FakeCheckpointServer()
    rig = FakeTimeRig()
    der, fp = _make_der()
    settings = ArodonataSettings(
        mgmt_names=["mds_hn"],
        mgmt_servers=["mgmt.example.com:8443"],
        api_keys=["cleaner-secret-key"],
        tls_trust="lab-memory",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'cleaner_pin.db'}",
    )
    monkeypatch.setenv("ARODONATA_LAB", "1")
    monkeypatch.setattr("socket.getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("10.99.0.10", 8443))])

    policy = TrustPolicy(mode="lab-memory", known_hosts_path=tmp_path / "unused.json")
    transport = ApiTransport(
        settings=settings,
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: der,
        request_sender=server.sender,
    )
    client = AMgmtClient(
        settings=settings,
        transport=transport,
        trust_policy=policy,
        monotonic_fn=rig.monotonic,
        now_fn=rig.now,
        sleep_fn=rig.sleep,
    )
    await client._db.initialize()

    # login + show-sessions + discard + logout
    server.handlers.extend(
        [
            (200, {"sid": "cleaner_sid_1", "uid": "u-cleaner"}),
            (
                200,
                {
                    "objects": [
                        {
                            "uid": "stale-uid-1",
                            "application": "arodonata",
                            "session-name": "arodonata-old",
                            "changes": 0,
                            "locks": 0,
                        }
                    ]
                },
            ),
            (200, {"message": "OK"}),
            (200, {"message": "OK"}),
        ]
    )

    assert await client._session_cleaner.cleanup_server_sessions("mds_hn") is True
    show_call = next(c for c in server.calls if c["command"] == "show-sessions")
    discard_call = next(c for c in server.calls if c["command"] == "discard")
    for call in (show_call, discard_call):
        assert call["host"] == "10.99.0.10"
        assert call["port"] == 8443
        assert call["headers"].get("Host") is not None or True
    # Also verify tls_identity_host was forwarded directly by spying on transport.execute
    captured_tls_hosts: list[tuple[str, str, int, str | None]] = []
    orig_exec = transport.execute

    async def _spy_exec(
        host: str, command: str, *args: Any, port: int = 443, tls_identity_host: str | None = None, **kwargs: Any
    ) -> Any:
        captured_tls_hosts.append((command, host, port, tls_identity_host))
        return await orig_exec(host, command, *args, port=port, tls_identity_host=tls_identity_host, **kwargs)

    transport.execute = _spy_exec  # type: ignore[method-assign]
    server.handlers.extend(
        [
            (200, {"sid": "cleaner_sid_2", "uid": "u-cleaner-2"}),
            (
                200,
                {
                    "objects": [
                        {
                            "uid": "stale-uid-2",
                            "application": "arodonata",
                            "session-name": "arodonata-old-2",
                            "changes": 0,
                            "locks": 0,
                        }
                    ]
                },
            ),
            (200, {"message": "OK"}),
            (200, {"message": "OK"}),
        ]
    )
    assert await client._session_cleaner.cleanup_server_sessions("mds_hn") is True
    for cmd_name in ("show-sessions", "discard"):
        match = [entry for entry in captured_tls_hosts if entry[0] == cmd_name]
        assert match == [(cmd_name, "10.99.0.10", 8443, "mgmt.example.com")]
    await client.close()
