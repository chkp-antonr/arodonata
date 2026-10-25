"""Environment loader for integration tests and standalone lab scripts.

Precedence (highest wins):

    process environment (e.g. ``ARODONATA_LAB=home ./pytest.sh int-1``)
      > .env.lab.<ARODONATA_LAB>   (profile: non-secret server/domain/key-ref)
      > .env.secrets               (shared secrets: APIKEY, USER_*, *_API_KEY)
      > .env.test                  (defaults)

Profile files may reference secret variables pushed in by ``.env.secrets`` via
``${VAR}`` interpolation (handled natively by ``python-dotenv``), so a profile
can stay tracked in git without holding key material — e.g.::

    # .env.lab.home
    API_MGMT=192.168.5.140
    APIKEY=${CPMDSH5_API_KEY}

If ``ARODONATA_LAB`` is not set in the process environment, ``.env.test`` may set
a default profile name. An explicit ``ARODONATA_LAB=""`` disables profile loading
even if ``.env.test`` sets one.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]


class LabProfileMissing(RuntimeError):
    """Raised when ``ARODONATA_LAB=<name>`` points at a ``.env.lab.<name>`` that does not exist."""


def load_lab_env(repo_root: Path = REPO_ROOT) -> str | None:
    """Load ``.env.test`` -> ``.env.secrets`` -> ``.env.lab.<profile>`` into ``os.environ``.

    Returns the active profile name, or ``None`` if no profile is active.
    """
    caller_pinned = {k: v for k, v in os.environ.items() if k != "ARODONATA_LAB"}
    lab_in_env = "ARODONATA_LAB" in os.environ
    explicit_lab = os.environ.get("ARODONATA_LAB")

    load_dotenv(repo_root / ".env.test", override=False)
    load_dotenv(repo_root / ".env.secrets", override=True)

    lab = explicit_lab if lab_in_env else os.environ.get("ARODONATA_LAB")
    if lab:
        profile_file = repo_root / f".env.lab.{lab}"
        if not profile_file.exists():
            raise LabProfileMissing(f"ARODONATA_LAB={lab!r} set, but {profile_file} does not exist")
        load_dotenv(profile_file, override=True)

    # Restore anything the caller passed directly in the process environment.
    os.environ.update(caller_pinned)
    if lab:
        os.environ["ARODONATA_LAB"] = lab
    return lab or None


def allowed_test_domains() -> set[str] | None:
    """Domains the suite is allowed to touch on a shared MDS, or ``None`` if unrestricted.

    Reads comma-separated ``ARODONATA_TEST_DOMAINS``. ``Global`` is never in this
    set — tests that read ``Global`` opt in explicitly via ``include_global=True``.
    """
    raw = os.environ.get("ARODONATA_TEST_DOMAINS", "").strip()
    if not raw:
        return None
    return {d.strip() for d in raw.split(",") if d.strip()}


def is_test_domain(name: str) -> bool:
    """Return ``True`` if ``name`` is a non-Global domain this test run may touch."""
    if name == "Global":
        return False
    allowed = allowed_test_domains()
    return allowed is None or name in allowed
