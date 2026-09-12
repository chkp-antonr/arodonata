"""Exclusive run lock for the integration suite.

Every integration run shares one Check Point lab server — same domains, same
policy packages, same objects being published and reverted — and one SQLite
cache file (`DATABASE_URL`, deleted on teardown). Two runs overlapping do not
merely slow each other down; they mutate each other's fixtures: one run's
logout test removes the other's cached SID, one run's teardown unlinks the
database the other is still using, and one run's `revert-to-revision` makes
every login in the other fail with "Database revision is in progress".

The lock makes the second run fail fast with a message naming the holder.
It uses `fcntl.flock`, which the kernel releases when the holding process
exits for any reason — a killed or crashed run can never leave a stale lock.
(`flock` is also per open-file-description, so two handles in one process
conflict; that is what makes the contention path unit-testable in-process.)
"""

from __future__ import annotations

import fcntl
import os
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_LOCK_PATH = Path("_tmp/integration.lock")


class IntegrationRunLocked(RuntimeError):
    """Another integration run currently holds the lab."""


class IntegrationRunLock:
    """Exclusive, non-blocking file lock around one integration run.

    Usage::

        lock = IntegrationRunLock(path).acquire()  # raises IntegrationRunLocked
        ...
        lock.release()

    or as a context manager. Acquiring writes ``pid=`` / ``started=`` lines into
    the file so a blocked run can report who owns the lab.

    Keep a reference to the returned lock for as long as it must be held. The
    lock lives on the open file handle: if the object is garbage-collected the
    handle closes and the kernel releases the lock silently. A bare
    ``IntegrationRunLock(path).acquire()`` with the result discarded holds
    nothing.
    """

    def __init__(self, path: Path = DEFAULT_LOCK_PATH) -> None:
        self.path = Path(path)
        self._fh = None

    def acquire(self) -> IntegrationRunLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+")  # noqa: SIM115 — kept open for the lock's lifetime
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.seek(0)
            holder = fh.read().strip() or "unknown holder"
            fh.close()
            raise IntegrationRunLocked(
                f"Another integration run holds {self.path} ({holder.replace(os.linesep, ', ')}). "
                f"Integration tests share one lab server and one SQLite cache; "
                f"wait for that run to finish before starting another."
            ) from None

        fh.seek(0)
        fh.truncate()
        fh.write(f"pid={os.getpid()}{os.linesep}started={datetime.now(UTC).isoformat(timespec='seconds')}{os.linesep}")
        fh.flush()
        self._fh = fh
        return self

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> IntegrationRunLock:
        return self.acquire()

    def __exit__(self, *exc_info: object) -> None:
        self.release()
