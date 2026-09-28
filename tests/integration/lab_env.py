"""Load the environment for one lab: `.env.test`, `.env.secrets`, then an optional profile.

Every integration entry point (conftest, `restore_baseline.py`, the probe
scripts, `lab_build.py`) calls `load_lab_env` instead of loading dotenv files
itself, so they all agree on which lab they are talking to.

Choosing a lab: set `ARODONATA_LAB=<name>`, in the shell or in `.env.test`.
The loader then layers `.env.lab.<name>` on top. A profile holds non-secret
overrides only -- server address, test domain names -- and refers to secrets
with `${VAR}`, which is why it loads after `.env.secrets`:

    API_MGMT=10.0.0.140
    APIKEY=${HOME_LAB_API_KEY}
    TEST_DOMAIN_A=Domain4

With `ARODONATA_LAB` unset nothing changes: the suite targets whatever
`.env.test` names. A profile that is selected but missing is an error, never a
silent fall back to the default lab.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).parent.parent.parent
LAB_VAR = "ARODONATA_LAB"
# Comma-separated domains the suite's "every domain" fixtures (all_domains) walk.
# A lab MDS can carry domains that belong to someone else. The baseline
# snapshot/revert never depends on this: it covers only TEST_DOMAIN_A/B.
TEST_DOMAINS_VAR = "ARODONATA_TEST_DOMAINS"


class LabProfileMissing(RuntimeError):
    """`ARODONATA_LAB` names a profile whose `.env.lab.<name>` file does not exist."""


def load_lab_env(root: Path = PROJECT_ROOT) -> str | None:
    """Load the lab environment into `os.environ`; return the profile name, or None for the default lab.

    Files override values already in the environment, as the suite always has
    (`override=True`), so a stale shell export cannot point a run at the wrong
    server. Raises `LabProfileMissing` for a selected profile with no file.
    """
    for name in (".env.test", ".env.secrets"):
        path = root / name
        if path.exists():
            load_dotenv(path, override=True)

    profile = os.getenv(LAB_VAR) or None
    if profile is None:
        return None
    path = root / f".env.lab.{profile}"
    if not path.exists():
        raise LabProfileMissing(f"{LAB_VAR}={profile} but {path} does not exist")
    load_dotenv(path, override=True)
    return profile


def allowed_test_domains() -> frozenset[str] | None:
    """The domains named in `ARODONATA_TEST_DOMAINS`, or None (unset or blank) for every domain."""
    names = frozenset(n.strip() for n in os.getenv(TEST_DOMAINS_VAR, "").split(",") if n.strip())
    return names or None


def is_test_domain(name: str) -> bool:
    """Whether the suite may treat `name` as its own (always true when no list is set)."""
    allowed = allowed_test_domains()
    return allowed is None or name in allowed
