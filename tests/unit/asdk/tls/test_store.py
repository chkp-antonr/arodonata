"""TrustStore: format, atomic writes, locking, permissions, corruption (spec D11-D13)."""

from __future__ import annotations

import errno
import json
import multiprocessing
import os
import stat
import threading
from pathlib import Path

import pytest

from arodonata.asdk.tls import TrustEntry, TrustStore, host_key, reset_lab_memory
from arodonata.core.exceptions import TrustStoreError

A = "a1" * 32
B = "b2" * 32


def entry(sha: str = A, source: str = "tofu") -> TrustEntry:
    return TrustEntry(
        sha256=sha,
        pem="-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
        source=source,
        first_seen="2026-10-04T00:00:00+00:00",
    )


@pytest.mark.parametrize(
    ("host", "port", "key"),
    [
        ("192.168.5.140", 443, "192.168.5.140:443"),
        ("MGMT.Example.COM", 4434, "mgmt.example.com:4434"),
        ("::1", 443, "[::1]:443"),
        ("[2001:db8::0001]", 443, "[2001:db8::1]:443"),
    ],
)
def test_host_key_normalises(host, port, key):
    assert host_key(host, port) == key


def test_missing_file_loads_empty(tmp_path):
    assert TrustStore(tmp_path / "s" / "t.json").load() == {}


def test_record_creates_dir_0700_and_file_0600(tmp_path):
    store = TrustStore(tmp_path / "s" / "t.json")
    assert store.record("h:443", entry()) == entry()
    assert stat.S_IMODE(os.stat(store.path.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    doc = json.loads(store.path.read_text())
    assert doc["version"] == 1 and doc["hosts"]["h:443"]["sha256"] == A
    assert store.load()["h:443"] == entry()


def test_record_keeps_an_existing_entry(tmp_path):
    store = TrustStore(tmp_path / "t.json")
    store.record("h:443", entry(A))
    assert store.record("h:443", entry(B)).sha256 == A


def test_unknown_fields_are_preserved(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"version": 1, "note": "keep", "hosts": {"x:443": {"sha256": A, "comment": "mine"}}}))
    path.chmod(0o600)
    TrustStore(path).record("h:443", entry(B))
    doc = json.loads(path.read_text())
    assert doc["note"] == "keep" and doc["hosts"]["x:443"]["comment"] == "mine"


def test_hand_written_entry_without_pem_is_valid(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(
        json.dumps({"version": 1, "hosts": {"h:443": {"sha256": ":".join([A[i : i + 2] for i in range(0, 64, 2)])}}})
    )
    path.chmod(0o600)
    loaded = TrustStore(path).load()["h:443"]
    assert loaded.sha256 == A and loaded.pem is None and loaded.source == "manual"


@pytest.mark.parametrize(
    "content", ["{not json", json.dumps([1]), json.dumps({"hosts": {"h:443": {"sha256": "b2" * 20}}})]
)
def test_corrupt_file_raises_and_is_never_rewritten(tmp_path, content):
    path = tmp_path / "t.json"
    path.write_text(content)
    path.chmod(0o600)
    store = TrustStore(path)
    with pytest.raises(TrustStoreError, match=str(path)):
        store.load()
    with pytest.raises(TrustStoreError):
        store.record("h:443", entry())
    assert path.read_text() == content


def test_world_writable_file_is_refused(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"version": 1, "hosts": {}}))
    path.chmod(0o666)
    with pytest.raises(TrustStoreError, match="world-writable"):
        TrustStore(path).load()


def test_group_writable_file_warns(tmp_path, caplog):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"version": 1, "hosts": {}}))
    path.chmod(0o660)
    TrustStore(path).load()
    assert "group-writable" in caplog.text


def test_group_writable_warning_is_logged_once_per_store_path(tmp_path, caplog):
    # load() runs in every check() and anchor_pems(): one WARNING per store path per process, not one per connection
    reset_lab_memory()
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"version": 1, "hosts": {}}))
    path.chmod(0o660)
    TrustStore(path).load()
    TrustStore(path).load()

    def warnings() -> int:
        return len([r for r in caplog.records if "group-writable" in r.getMessage()])

    assert warnings() == 1
    reset_lab_memory()  # the test reset forgets it too
    TrustStore(path).load()
    assert warnings() == 2
    reset_lab_memory()


@pytest.mark.parametrize("call", ["record", "ensure_writable"])
def test_a_failing_flock_is_a_trust_store_error(tmp_path, monkeypatch, call):
    # ENOLCK / EOPNOTSUPP on some network or FUSE mounts: a configuration fact, never a raw OSError (which login
    # would classify as "unreachable", and which would kill the MCP preflight with a traceback)
    from arodonata.asdk import tls

    real_flock = tls.fcntl.flock
    calls: list[int] = []

    def failing_flock(fd: int, operation: int) -> None:
        calls.append(operation)
        if operation == tls.fcntl.LOCK_EX:
            raise OSError(errno.ENOLCK, os.strerror(errno.ENOLCK))
        real_flock(fd, operation)

    closed: list[int] = []
    real_close = os.close
    monkeypatch.setattr(tls.fcntl, "flock", failing_flock)
    monkeypatch.setattr(tls.os, "close", lambda fd: (closed.append(fd), real_close(fd))[1])
    store = TrustStore(tmp_path / "s" / "t.json")
    with pytest.raises(TrustStoreError) as info:
        if call == "record":
            store.record("h:443", entry())
        else:
            store.ensure_writable()
    text = str(info.value)
    assert str(store.lock_path) in text and os.strerror(errno.ENOLCK) in text
    assert "ARODONATA_TLS_KNOWN_HOSTS_PATH" in text  # the _NOT_WRITABLE_HINT
    assert isinstance(info.value.__cause__, OSError)
    assert calls == [tls.fcntl.LOCK_EX]  # never unlocked: the lock was not taken
    assert len(closed) == 1  # the lock file descriptor is closed
    assert not store.path.exists()


def test_unwritable_directory_raises_with_hint(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir(mode=0o555)
    try:
        with pytest.raises(TrustStoreError, match="ARODONATA_TLS_KNOWN_HOSTS_PATH"):
            TrustStore(ro / "t.json").ensure_writable()
    finally:
        ro.chmod(0o755)


def test_forty_threads_record_valid_json(tmp_path):
    store = TrustStore(tmp_path / "t.json")
    threads = [threading.Thread(target=store.record, args=(f"h{i}:443", entry())) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(json.loads(store.path.read_text())["hosts"]) == 40


def _record_in_child(path: str, key: str, sha: str, out: multiprocessing.Queue[str]) -> None:
    out.put(TrustStore(Path(path)).record(key, entry(sha)).sha256)


def test_two_processes_one_key_first_writer_wins(tmp_path):
    path = str(tmp_path / "t.json")
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    procs = [ctx.Process(target=_record_in_child, args=(path, "h:443", sha, out)) for sha in (A, B)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    results = {out.get(timeout=5), out.get(timeout=5)}
    assert len(results) == 1  # both see the same winner; the loser's caller turns that into a mismatch
    assert json.loads(Path(path).read_text())["hosts"]["h:443"]["sha256"] in (A, B)


def test_group_writable_warning_is_literal_and_points_at_the_reader(tmp_path, caplog):
    path = tmp_path / "[x]" / "t.json"  # a bracketed path segment would be eaten as Rich markup
    path.parent.mkdir()
    path.write_text(json.dumps({"version": 1, "hosts": {}}))
    path.chmod(0o660)
    TrustStore(path).load()
    (record,) = [r for r in caplog.records if "group-writable" in r.getMessage()]
    assert record.markup is False and record.funcName == "_read_raw"
