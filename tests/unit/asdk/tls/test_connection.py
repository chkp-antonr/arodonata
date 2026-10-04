"""Verified connections against a real localhost TLS server (spec D2-D5, D17)."""

from __future__ import annotations

import builtins
import hashlib
import json
import logging
import socket
import time

import pytest

from arodonata.asdk.tls import TrustPolicy, TrustStore, probe_certificate, verified_api_client
from arodonata.config.tls import TrustMode
from arodonata.core.exceptions import ApiTimeoutError, CertificateMismatchError, ConfigurationError

SID = "SIDSENTINEL-0123456789abcdef"
SECRET = "SECRETSENTINEL-fedcba9876543210"


def client_for(server, policy, *, read_timeout=5.0, connect_timeout=2.0, sid=SID):
    return verified_api_client(
        "127.0.0.1", server.port, sid=sid, policy=policy, connect_timeout=connect_timeout, read_timeout=read_timeout
    )


def test_loopback_guard_refuses_other_hosts():
    with pytest.raises(AssertionError, match="tried to connect to 192.0.2.1"):
        socket.create_connection(("192.0.2.1", 443), timeout=0.1)


def test_probe_returns_the_presented_der(server_factory, certs):
    server = server_factory("a")
    assert probe_certificate("127.0.0.1", server.port, 2.0) == certs["a"][2]
    assert server.bytes_on(0) == 0  # the probe sends no application bytes


def test_tofu_first_call_persists_then_second_call_verifies(server_factory, tofu, certs, tmp_path):
    server = server_factory("a")
    assert client_for(server, tofu).api_call("show-hosts", {}).success
    stored = json.loads((tmp_path / "trust.json").read_text())["hosts"][f"127.0.0.1:{server.port}"]
    assert stored["sha256"] == hashlib.sha256(certs["a"][2]).hexdigest()
    before = (tmp_path / "trust.json").read_bytes()
    fresh = TrustPolicy(TrustMode.TOFU, TrustStore(tmp_path / "trust.json"), ())
    assert client_for(server, fresh).api_call("show-hosts", {}).success
    assert (tmp_path / "trust.json").read_bytes() == before


def test_mismatch_sends_zero_bytes(server_factory, tofu):
    first = server_factory("a")
    client_for(first, tofu).api_call("show-hosts", {})
    impostor = server_factory("b")
    tofu.store.record(f"127.0.0.1:{impostor.port}", tofu.store.load()[f"127.0.0.1:{first.port}"])  # A trusted there
    with pytest.raises(CertificateMismatchError):
        client_for(impostor, tofu).api_call("show-hosts", {})
    assert all(impostor.bytes_on(i) == 0 for i in range(4))


# Connection indexes: the first-contact probe is connection 0, so the first data connection is 1.


def test_resend_branch_cannot_reach_an_unverified_peer(server_factory, tofu):
    # 0: probe (A); 1: data (A), request dropped -> cpapi re-sends; 2: re-opened connection presents B
    server = server_factory("a", "a", "b", mode="drop_after_request")
    with pytest.raises(CertificateMismatchError):
        client_for(server, tofu).api_call("show-hosts", {})
    assert server.bytes_on(2) == 0
    assert [index for index, _ in server.request_lines] == [1]  # only the dropped request; nothing reached B


def test_connection_close_reopen_raises_instead_of_folding(server_factory, tofu):
    server = server_factory("a", "a", "b", mode="close")  # 0: probe (A); 1: data (A), then closed; 2: reopen (B)
    client = client_for(server, tofu)
    assert client.api_call("show-hosts", {}).success  # conn 1, cert A learned
    with pytest.raises(CertificateMismatchError):
        client.api_call("show-hosts", {})  # http.client auto-reopens conn 2 with cert B
    assert server.bytes_on(2) == 0


def test_connection_close_reopen_connect_timeout_is_not_resent(server_factory, tofu):
    # 0: probe; 1: data, answered with 'Connection: close'; 2: the auto-reopened connection never handshakes.
    # ApiTimeoutError is an OSError, so it lands in cpapi's re-send branch: the recorded failure must stop it.
    server = server_factory("a", modes=["close", "close", "never_handshake"])
    client = client_for(server, tofu, connect_timeout=1.0)
    assert client.api_call("show-hosts", {}).success
    started = time.monotonic()
    with pytest.raises(ApiTimeoutError) as info:
        client.api_call("show-hosts", {})
    assert info.value.phase == "connect" and info.value.command == "show-hosts"
    assert time.monotonic() - started < 5
    assert server.request_lines == [(1, "POST /web_api/show-hosts HTTP/1.1")]


@pytest.mark.parametrize("mode", ["headers_then_stall", "never_answer"])
def test_read_timeout_sends_publish_exactly_once(server_factory, tofu, mode):
    server = server_factory("a", mode=mode)
    started = time.monotonic()
    client = client_for(server, tofu, read_timeout=1.0)
    with pytest.raises(ApiTimeoutError) as info:
        client.api_call("publish", {})
    assert info.value.phase == "read" and info.value.command == "publish"
    assert client.conn.sock is None  # closed: a late reply can never answer a later request
    assert "may still have run on the server" in str(info.value)
    assert isinstance(info.value.__cause__, TimeoutError)
    assert time.monotonic() - started < 5
    assert [line for _, line in server.request_lines] == ["POST /web_api/publish HTTP/1.1"]


def test_read_timeout_after_cpapis_own_resend_is_an_api_timeout(server_factory, tofu):
    # 0: probe; 1: the request is dropped (RemoteDisconnected, not a timeout) -> cpapi re-sends on a new verified
    # connection inside its `except` block; 2: that re-sent request is never answered. The read timeout is raised
    # from inside cpapi's except block, so the re-send guard never sees it: api_call itself must translate it.
    server = server_factory("a", modes=["answer", "drop_after_request", "never_answer"])
    client = client_for(server, tofu, read_timeout=1.0)
    started = time.monotonic()
    with pytest.raises(ApiTimeoutError) as info:
        client.api_call("publish", {}, SID, False, -1)
    assert info.value.phase == "read" and info.value.command == "publish"
    assert info.value.host == "127.0.0.1" and info.value.port == server.port and info.value.timeout == 1.0
    assert "may still have run on the server" in str(info.value)
    assert isinstance(info.value.__cause__, TimeoutError)
    assert client.conn is None  # dropped: a late reply can never answer a later request
    assert time.monotonic() - started < 5
    for name, local_reprs in _tls_frame_locals(info.value):
        assert SID not in local_reprs, name
    # Known residual (out of scope, spec D5 / docs "Security residuals"): cpapi re-sends a request after a dropped
    # connection -- the peer is verified, but the command reached the server twice.
    assert server.request_lines == [(1, "POST /web_api/publish HTTP/1.1"), (2, "POST /web_api/publish HTTP/1.1")]


def test_connect_timeout_on_a_server_that_never_handshakes(server_factory, tofu):
    server = server_factory("a", mode="never_handshake")
    started = time.monotonic()
    with pytest.raises(ApiTimeoutError) as info:
        client_for(server, tofu, connect_timeout=1.0).api_call("show-hosts", {})
    assert info.value.phase == "connect" and time.monotonic() - started < 5
    assert "TLS probe of" in str(info.value)


def test_anchored_handshake_timeout_is_a_connect_timeout(server_factory, tofu):
    # 0: probe; 1: data; a second client anchors on the session PEM, and connection 2 never handshakes
    server = server_factory("a", modes=["answer", "answer", "never_handshake"])
    assert client_for(server, tofu).api_call("show-hosts", {}).success
    started = time.monotonic()
    with pytest.raises(ApiTimeoutError) as info:
        client_for(server, tofu, connect_timeout=1.0).api_call("show-hosts", {})
    assert info.value.phase == "connect" and time.monotonic() - started < 5
    assert [index for index, _ in server.request_lines] == [1]


def test_tcp_connect_timeout_is_a_connect_timeout(server_factory, tofu, monkeypatch):
    server = server_factory("a")
    assert client_for(server, tofu).api_call("show-hosts", {}).success  # the next client anchors without a probe

    def silent(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", silent)
    with pytest.raises(ApiTimeoutError) as info:
        client_for(server, tofu).api_call("show-hosts", {})
    assert info.value.phase == "connect" and "TCP connect" in str(info.value)


def test_verification_failure_with_a_failing_probe_is_still_an_identity_error(server_factory, tofu):
    # 0: probe (A); 1: data (A); 2: presents B (refused by the anchor); 3: the follow-up probe never handshakes
    server = server_factory("a", "a", "b", modes=["answer", "answer", "answer", "never_handshake"])
    assert client_for(server, tofu).api_call("show-hosts", {}).success
    with pytest.raises(CertificateMismatchError):
        client_for(server, tofu, connect_timeout=1.0).api_call("show-hosts", {})
    assert server.bytes_on(2) == 0


def test_operator_retrust_refuses_one_attempt_then_anchors_on_the_new_pem(
    server_factory, tofu, certs, tmp_path, caplog
):
    # 0: probe (A); 1: data (A), every answer closes the connection; then the certificate legitimately changes to B
    server = server_factory("a", "a", "b", mode="close")
    client = client_for(server, tofu)  # one long-lived client, like a lab script
    assert client.api_call("show-hosts", {}).success
    store = tmp_path / "trust.json"
    data = json.loads(store.read_text())
    data["hosts"][f"127.0.0.1:{server.port}"]["sha256"] = hashlib.sha256(certs["b"][2]).hexdigest()  # re-trust
    store.write_text(json.dumps(data))
    with caplog.at_level(logging.ERROR), pytest.raises(CertificateMismatchError, match="changed during the connection"):
        client.api_call("show-hosts", {})  # 2: auto-reopen anchored on A, refused; 3: probe sees B, accepted
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "changed during the connection" in errors[0]
    assert server.bytes_on(2) == 0
    # the cached connection anchored on A is dropped, so the retry re-runs anchor_pems instead of auto-reopening it
    # (http.client's CannotSendRequest after the failed send would mask this in the behaviour alone)
    assert client.conn is None
    assert client.api_call("show-hosts", {}).success  # 4: a new connection, anchored on B
    assert [index for index, _ in server.request_lines] == [1, 4]


def test_expired_pinned_certificate_is_accepted(server_factory, tofu):
    server = server_factory("expired")
    assert client_for(server, tofu).api_call("show-hosts", {}).success
    assert client_for(server, tofu).api_call("show-hosts", {}).success  # second call uses the anchored context


def test_cwd_fingerprints_txt_and_input_are_never_used(server_factory, tofu, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fingerprints.txt").write_text(json.dumps({"127.0.0.1": "00" * 20}))
    monkeypatch.setattr(builtins, "input", lambda *a: (_ for _ in ()).throw(AssertionError("input() called")))
    server = server_factory("a")
    assert client_for(server, tofu).api_call("show-hosts", {}).success
    assert json.loads((tmp_path / "fingerprints.txt").read_text()) == {"127.0.0.1": "00" * 20}


def test_identity_error_carries_no_sid(server_factory, tofu):
    first = server_factory("a")
    client_for(first, tofu).api_call("show-hosts", {})
    impostor = server_factory("b")
    tofu.store.record(f"127.0.0.1:{impostor.port}", tofu.store.load()[f"127.0.0.1:{first.port}"])
    with pytest.raises(CertificateMismatchError) as info:
        client_for(impostor, tofu).api_call("show-hosts", {})
    assert SID[:8] not in str(info.value)


def test_read_timeout_is_applied_to_a_cached_connection(server_factory, tofu):
    server = server_factory("a")
    client = client_for(server, tofu, read_timeout=7.0)
    assert client.api_call("show-hosts", {}).success
    client.read_timeout = 3.0  # the transport sets it per call (spec D16)
    assert client.api_call("show-hosts", {}).success
    assert client.conn.sock.gettimeout() == 3.0


def test_factory_reads_timeouts_and_policy_from_settings(monkeypatch, tmp_path):
    from arodonata.config import ArodonataSettings
    from arodonata.config.constants import READ_TIMEOUT_MARGIN

    monkeypatch.setenv("ARODONATA_CONNECT_TIMEOUT", "7")
    monkeypatch.setenv("ARODONATA_TLS_KNOWN_HOSTS_PATH", str(tmp_path / "k.json"))
    settings = ArodonataSettings()
    client = verified_api_client("127.0.0.1", 4434, settings=settings)
    assert client.connect_timeout == 7.0
    assert client.read_timeout == float(settings.default_read_timeout) > READ_TIMEOUT_MARGIN
    assert client.policy.mode is TrustMode.TOFU and client.policy.store.path == tmp_path / "k.json"
    assert client.get_port() == 4434 and client.check_fingerprint() is True


def test_a_failed_tcp_connect_never_leaves_a_plaintext_socket(certs, tofu, monkeypatch):
    # http.client's connect() sets self.sock before TCP_NODELAY, which may still raise: that socket must not stay
    import http.client

    from arodonata.asdk.tls import PinnedHTTPSConnection

    class Plain:
        closed = False

        def close(self):
            self.closed = True

    plain = Plain()

    def half_connected(self):
        self.sock = plain
        raise OSError(22, "setsockopt failed")

    monkeypatch.setattr(http.client.HTTPConnection, "connect", half_connected)
    conn = PinnedHTTPSConnection(
        verified_api_client("127.0.0.1", 1, policy=tofu, connect_timeout=1, read_timeout=1), [certs["a"][0].read_text()]
    )
    with pytest.raises(OSError, match="setsockopt"):
        conn.connect()
    assert conn.sock is None and plain.closed


def _tls_frame_locals(exc):
    """(function, repr of final locals) for every tls.py frame in the tracebacks of exc and its causes."""
    found, seen, pending = [], set(), [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        tb = current.__traceback__
        while tb is not None:
            if tb.tb_frame.f_code.co_filename.endswith("asdk/tls.py"):
                found.append((tb.tb_frame.f_code.co_name, repr(dict(tb.tb_frame.f_locals))))
            tb = tb.tb_next
        pending += [current.__cause__, current.__context__]
    return found


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(("show-hosts", {}, SID, False, -1), id="transport-shaped"),  # transport.py passes client.sid
        pytest.param(("login", {"user": "admin", "password": SECRET}), id="login-password"),
        pytest.param(("login", {"api-key": SECRET}), id="login-api-key"),
    ],
)
def test_identity_error_frames_in_tls_hold_no_sid_or_credentials(server_factory, tofu, call):
    first = server_factory("a")
    client_for(first, tofu).api_call("show-hosts", {})
    impostor = server_factory("b")
    tofu.store.record(f"127.0.0.1:{impostor.port}", tofu.store.load()[f"127.0.0.1:{first.port}"])
    with pytest.raises(CertificateMismatchError) as info:
        client_for(impostor, tofu).api_call(*call)
    frames = _tls_frame_locals(info.value)
    assert "api_call" in [name for name, _ in frames] and "connect" in [name for name, _ in frames]
    for name, local_reprs in frames:
        assert SID not in local_reprs and SECRET not in local_reprs, name


def test_read_timeout_frames_in_tls_hold_no_sid(server_factory, tofu):
    server = server_factory("a", mode="never_answer")
    with pytest.raises(ApiTimeoutError) as info:
        client_for(server, tofu, read_timeout=1.0).api_call("show-hosts", {}, SID, False, -1)
    frames = _tls_frame_locals(info.value)
    assert {"api_call", "create_https_connection"} <= {name for name, _ in frames}
    for name, local_reprs in frames:
        assert SID not in local_reprs, name


def test_single_conn_false_is_refused(tofu):
    from cpapi import APIClientArgs

    from arodonata.asdk.tls import VerifiedAPIClient

    with pytest.raises(ConfigurationError, match="re-send guard"):
        VerifiedAPIClient(
            APIClientArgs(server="127.0.0.1", single_conn=False), policy=tofu, connect_timeout=1, read_timeout=1
        )
