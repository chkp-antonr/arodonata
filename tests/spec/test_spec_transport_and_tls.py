"""Specification acceptance tests for `transport-and-tls` (`SCN-TRANS-*`)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiohttp
import pytest

from arodonata.adapters.checkpoint.client import AMgmtClient
from arodonata.adapters.checkpoint.pager import TASK_QUERY_COMMANDS
from arodonata.adapters.checkpoint.tls import TrustPolicy, compute_der_fingerprint
from arodonata.adapters.checkpoint.transport import ApiTransport, PooledSocketEntry, RawHttpResponse
from arodonata.core.config import ArodonataSettings
from arodonata.core.errors import ServerIdentityError, TransportError
from arodonata.core.models.domains import DomainInfo


def _make_der(seed: str = "spec-trans") -> tuple[bytes, str]:
    der = f"der-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    return der, ":".join(digest[i : i + 2] for i in range(0, 64, 2))


@pytest.mark.spec("SCN-TRANS-002-4")
async def test_api_transport_execute_uses_trust_env_false_and_ignores_proxy_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-TRANS-002-4: `ApiTransport.execute()` initializes `ClientSession(trust_env=False)` ignoring proxy env vars."""
    from arodonata.testing.mock_server import CheckPointReplayHttpServer

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")

    observed_trust_env: list[bool] = []
    orig_client_session = aiohttp.ClientSession

    def _spy_session(*args: Any, **kwargs: Any) -> aiohttp.ClientSession:
        observed_trust_env.append(bool(kwargs.get("trust_env", True)))
        return orig_client_session(*args, **kwargs)

    monkeypatch.setattr(aiohttp, "ClientSession", _spy_session)

    async with CheckPointReplayHttpServer(host="127.0.0.1", port=0) as srv:
        settings = ArodonataSettings(mgmt_name="local", mgmt_ip="127.0.0.1", mgmt_port=srv.port, api_key="mock-api-key")
        policy = TrustPolicy(mode="tofu", known_hosts_path=tmp_path / "known_hosts.json")
        transport = ApiTransport(settings=settings, trust_policy=policy)
        try:
            login_res = await transport.execute("127.0.0.1", "login", {"api-key": "mock-api-key"}, port=srv.port)
            assert login_res.success is True
            res = await transport.execute(
                "127.0.0.1",
                "show-domains",
                {},
                port=srv.port,
                sid=str(login_res.data["sid"]),
            )
            assert res.success is True
            assert observed_trust_env == [False]
        finally:
            await transport.close()


@pytest.mark.spec("SCN-TRANS-002-5")
async def test_keepalive_and_sweep_propagate_server_identity_error_immediately(tmp_path: Path) -> None:
    """SCN-TRANS-002-5: `keepalive_sid` and `sweep_keepalives` propagate `ServerIdentityError` immediately."""
    der_1, fp_1 = _make_der("trusted")
    der_2, _fp_2 = _make_der("rogue")
    current_der = der_1
    send_calls = 0

    async def _sender(**kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        nonlocal send_calls
        send_calls += 1
        return RawHttpResponse(status=200, body=b'{"message":"OK"}'), kwargs.get("reused_entry")

    cfg = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="k",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp_1}",
    )
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=f"10.0.0.1:443={fp_1}",
    )
    transport = ApiTransport(
        settings=cfg,
        trust_policy=policy,
        peer_cert_getter=lambda _h, _p: current_der,
        request_sender=_sender,
    )
    now = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    client = AMgmtClient(settings=cfg, engine=None, transport=transport, trust_policy=policy, now_fn=lambda: now)
    try:
        await client.initialize()
        from arodonata.core.models.domains import SIDCacheEntry

        await client.cache.upsert_sid(
            SIDCacheEntry(
                id="mds1:Corp:default",
                mgmt_name="mds1",
                domain_name="Corp",
                sid="sid_1_secret",
                server_ip="10.0.0.1",
                last_used_at=now,
                expires_at=now + timedelta(seconds=300),
            )
        )
        # Switch peer certificate to mismatching rogue cert before keepalive runs
        current_der = der_2
        assert compute_der_fingerprint(der_2) != fp_1

        with pytest.raises(ServerIdentityError):
            await client._login_coordinator.keepalive_sid("mds1", "Corp", sid="sid_1_secret")
        assert send_calls == 0

        with pytest.raises(ServerIdentityError):
            await client._login_coordinator.sweep_keepalives("mds1")
        assert send_calls == 0
    finally:
        await client.close(logout=False)


@pytest.mark.spec("SCN-TRANS-006-3")
async def test_task_based_query_commands_through_api_query_and_fail_on_page_error(tmp_path: Path) -> None:
    """SCN-TRANS-006-3 (FC-08): `TASK_QUERY_COMMANDS` + `AMgmtClient.api_query('show-logs', ...)` through TaskWaiter."""
    assert "show-gateways-and-servers-task" in TASK_QUERY_COMMANDS
    assert "show-logs" in TASK_QUERY_COMMANDS
    assert "show-Gateways-and-servers-task" not in TASK_QUERY_COMMANDS

    der, fp = _make_der("pager-logs")
    calls: list[dict[str, Any]] = []
    mode = "ok"

    async def _sender(**kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        cmd = kwargs["command"]
        payload = json.loads(kwargs["body"].decode("utf-8")) if kwargs["body"] else {}
        calls.append({"cmd": cmd, "payload": payload})
        if cmd == "login":
            return RawHttpResponse(status=200, body=b'{"sid":"sid_log_1","uid":"u1"}'), kwargs.get("reused_entry")
        if cmd == "show-logs":
            offset = int(payload.get("offset", 0))
            return (
                RawHttpResponse(status=200, body=json.dumps({"task-id": f"task-p-{offset}"}).encode("utf-8")),
                kwargs.get("reused_entry"),
            )
        if cmd == "show-task":
            raw_tid = payload["task-id"]
            tid = raw_tid[0] if isinstance(raw_tid, list) else str(raw_tid)
            if tid == "task-p-0":
                detail = {"objects": [{"uid": "l1"}, {"uid": "l2"}], "from": 1, "to": 2, "total": 3}
            elif mode == "fail":
                return (
                    RawHttpResponse(
                        status=200,
                        body=json.dumps(
                            {
                                "tasks": [
                                    {
                                        "task-id": tid,
                                        "status": "failed",
                                        "progress-percentage": 100,
                                        "task-details": [{"fault-message": "page 2 failed"}],
                                    }
                                ]
                            }
                        ).encode("utf-8"),
                    ),
                    kwargs.get("reused_entry"),
                )
            elif mode == "stall":
                detail = {"objects": [], "from": 2, "to": 1, "total": 3}
            else:
                detail = {"objects": [{"uid": "l3"}], "from": 3, "to": 3, "total": 3}
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps(
                        {
                            "tasks": [
                                {
                                    "task-id": tid,
                                    "status": "succeeded",
                                    "progress-percentage": 100,
                                    "task-details": [detail],
                                }
                            ]
                        }
                    ).encode("utf-8"),
                ),
                kwargs.get("reused_entry"),
            )
        return RawHttpResponse(status=200, body=b"{}"), kwargs.get("reused_entry")

    cfg = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="k",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp}",
    )
    policy = TrustPolicy(
        mode="pinned", known_hosts_path=tmp_path / "known.json", pinned_fingerprints=f"10.0.0.1:443={fp}"
    )
    transport = ApiTransport(
        settings=cfg, trust_policy=policy, peer_cert_getter=lambda _h, _p: der, request_sender=_sender
    )
    client = AMgmtClient(settings=cfg, engine=None, transport=transport, trust_policy=policy)
    try:
        q_ok = await client.api_query("mds1", "show-logs", limit=2)
        assert q_ok.success is True
        assert [obj["uid"] for obj in q_ok.objects] == ["l1", "l2", "l3"]
        assert [c["cmd"] for c in calls].count("show-task") == 2

        # Whole query must fail if page 2 fails or stalls without advancing
        mode = "fail"
        q_fail = await client.api_query("mds1", "show-logs", limit=2)
        assert q_fail.success is False

        mode = "stall"
        q_stall = await client.api_query("mds1", "show-logs", limit=2)
        assert q_stall.success is False
    finally:
        await client.close(logout=False)


@pytest.mark.spec("SCN-TRANS-007-3")
async def test_cma_failover_loop_never_resends_after_post_send_transport_error(tmp_path: Path) -> None:
    """SCN-TRANS-007-3: `AMgmtClient.api_call` CMA failover never resends when `TransportError(request_sent=True)` occurs."""
    der, fp = _make_der("failover")
    hosts_hit: list[str] = []

    async def _sender(**kwargs: Any) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        cmd = kwargs["command"]
        hosts_hit.append(f"{kwargs['host']}:{cmd}")
        if cmd == "login":
            return RawHttpResponse(status=200, body=b'{"sid":"sid_fo_1","uid":"u1"}'), kwargs.get("reused_entry")
        if cmd == "show-domains":
            # Should NOT even be reached on post-send error, and if it were, standby is 10.0.0.11
            return (
                RawHttpResponse(
                    status=200,
                    body=json.dumps(
                        {
                            "objects": [
                                {
                                    "name": "Corp",
                                    "uid": "d1",
                                    "servers": [
                                        {"ipv4-address": "10.0.0.11", "active": True},
                                        {"ipv4-address": "10.0.0.10", "active": False},
                                    ],
                                }
                            ]
                        }
                    ).encode("utf-8"),
                ),
                kwargs.get("reused_entry"),
            )
        raise ConnectionResetError("connection reset after write")

    cfg = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="k",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp},10.0.0.10:443={fp},10.0.0.11:443={fp}",
    )
    policy = TrustPolicy(
        mode="pinned",
        known_hosts_path=tmp_path / "known.json",
        pinned_fingerprints=cfg.tls_fingerprints,
    )
    transport = ApiTransport(
        settings=cfg, trust_policy=policy, peer_cert_getter=lambda _h, _p: der, request_sender=_sender
    )
    client = AMgmtClient(settings=cfg, engine=None, transport=transport, trust_policy=policy)
    try:
        await client.initialize()
        await client.cache.upsert_domains(
            [
                DomainInfo(
                    id="mds1:Corp",
                    mgmt_name="mds1",
                    name="Corp",
                    uid="d1",
                    active_ip="10.0.0.10",
                    active_mds_ip="10.0.0.1",
                    standby_ips=["10.0.0.11"],
                )
            ],
        )

        with pytest.raises(TransportError) as exc_info:
            await client.api_call("mds1", "show-hosts", domain="Corp")
        assert exc_info.value.request_sent is True
        assert exc_info.value.phase == "post-send"
        # Neither transport nor CMA failover retried on 10.0.0.11 or re-queried show-domains
        assert hosts_hit == ["10.0.0.10:login", "10.0.0.10:show-hosts"]
    finally:
        await client.close(logout=False)
