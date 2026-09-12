#!/usr/bin/env python3
"""Run the unit suite, then integration bucket 1 if the lab env exists.

Bucket 1 is the cheapest bucket (logins, sessions, rate limits, reads) and
mutates nothing on the server — the right smoke test to pair with the unit
suite. Run the other buckets explicitly: ./pytest.sh int-2 .. int-6.

Usage:
    uv run run_all_tests.py            # unit (+ int-1 when .env.test present)
    uv run run_all_tests.py --unit     # unit suite only
"""

import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], title: str) -> bool:
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")
    return subprocess.run(cmd, check=False).returncode == 0


def main() -> int:
    root = Path(__file__).parent
    ok = run(["uv", "run", "pytest"], "Unit suite (coverage)")

    unit_only = "--unit" in sys.argv[1:]
    has_env = (root / ".env.test").exists() and (root / ".env.secrets").exists()
    if not unit_only and has_env:
        ok &= run(["./pytest.sh", "int-1"], "Integration bucket 1 (FPCR lab)")
    elif not unit_only:
        print("\nSkipping integration: .env.test / .env.secrets not found")

    print("\n" + ("✅ all green" if ok else "❌ failures — see above"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
