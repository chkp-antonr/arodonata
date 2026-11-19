"""Single-run mutex for integration tests against the live Check Point lab.

Two concurrent ``pytest`` invocations against the same MDSM corrupt each other:
both snapshot "baseline", both mutate ``TEST_DOMAIN_A``/``B``, and the first one to
finish reverts the domain out from under the second. Even read-only buckets
collide on the per-admin login throttle when ``admin_client`` / ``eng*_client`` spin up.

Taken once at session start via ``flock(LOCK_EX | LOCK_NB)`` on
``_tmp/integration.lock``. Released automatically by the kernel when the pytest
process exits (including ``SIGKILL``).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore[assignment]


class IntegrationRunLocked(RuntimeError):
    """Another integration test run is already holding the lab lock."""


class IntegrationRunLock:
    """Non-blocking exclusive file lock scoped to one pytest session."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh: TextIO | None = None

    def acquire(self) -> None:
        """Acquire exclusive non-blocking flock or raise ``IntegrationRunLocked``."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # "a+" so we never truncate the holder's PID before knowing we own the lock.
        fh = self.path.open("a+", encoding="utf-8")
        if fcntl is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as err:
                fh.seek(0)
                holder = fh.read().strip() or "unknown holder"
                fh.close()
                raise IntegrationRunLocked(
                    f"Another integration run holds {self.path} ({holder}). "
                    f"Wait for it to finish before starting a second run."
                ) from err
        elif msvcrt is not None:
            try:
                fh.seek(1_000_000)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as err:
                fh.seek(0)
                holder = fh.read().strip() or "unknown holder"
                fh.close()
                raise IntegrationRunLocked(
                    f"Another integration run holds {self.path} ({holder}). "
                    f"Wait for it to finish before starting a second run."
                ) from err

        fh.seek(0)
        fh.truncate()
        started_at = datetime.now(UTC).isoformat()
        fh.write(f"pid={os.getpid()} started_at={started_at} argv={' '.join(os.sys.argv)}\n")
        fh.flush()
        self._fh = fh

    def release(self) -> None:
        """Release the flock and close the file descriptor."""
        if self._fh is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:
                try:
                    self._fh.seek(1_000_000)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        finally:
            self._fh.close()
            self._fh = None
