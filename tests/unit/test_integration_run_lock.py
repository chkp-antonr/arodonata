"""Lab-free tests for the integration-suite run lock.

The lock exists because every integration run shares one Check Point lab
server (same policies, same reverts) and one SQLite cache file that is
deleted on teardown. Two overlapping runs corrupt each other; the lock makes
the second one fail fast instead.
"""

from __future__ import annotations

import os

import pytest

from tests.integration.run_lock import IntegrationRunLock, IntegrationRunLocked


def test_second_acquire_fails_and_names_the_holder(tmp_path):
    """A held lock rejects a second acquirer with a message naming the holder PID."""
    path = tmp_path / "integration.lock"
    first = IntegrationRunLock(path).acquire()
    try:
        with pytest.raises(IntegrationRunLocked, match=str(os.getpid())):
            IntegrationRunLock(path).acquire()
    finally:
        first.release()


def test_release_allows_reacquire(tmp_path):
    """Once released, the same path can be locked again."""
    path = tmp_path / "integration.lock"
    IntegrationRunLock(path).acquire().release()

    second = IntegrationRunLock(path).acquire()
    second.release()


def test_lock_file_records_holder_pid(tmp_path):
    """The holder writes its PID so a blocked run can report who owns the lab."""
    path = tmp_path / "integration.lock"
    lock = IntegrationRunLock(path).acquire()
    try:
        assert f"pid={os.getpid()}" in path.read_text()
    finally:
        lock.release()


def test_context_manager_releases_on_exit(tmp_path):
    """Using the lock as a context manager releases it even if the body raises."""
    path = tmp_path / "integration.lock"
    with pytest.raises(RuntimeError, match="boom"):
        with IntegrationRunLock(path):
            raise RuntimeError("boom")

    IntegrationRunLock(path).acquire().release()
