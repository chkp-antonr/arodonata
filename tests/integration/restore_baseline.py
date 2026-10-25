"""Emergency CLI recovery tool: revert sandbox domains to the last saved baseline.

Use if a pytest run was killed with SIGKILL before session teardown could run::

    uv run python -m tests.integration.restore_baseline
    uv run python -m tests.integration.restore_baseline --force
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from arodonata import ArodonataClient, ArodonataSettings
from tests.integration.cp_revision import BaselineSnapshot, DomainBaseline, restore_to_baseline
from tests.integration.lab_env import REPO_ROOT, load_lab_env

DEFAULT_BASELINE_FILE = REPO_ROOT / "_tmp" / "cp_baseline.json"


async def _main(baseline_path: Path, *, force: bool) -> int:
    load_lab_env()

    if not baseline_path.exists():
        print(f"Baseline file not found: {baseline_path}", file=sys.stderr)
        return 1

    raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    snap = BaselineSnapshot(
        mgmt_name=raw["mgmt_name"],
        mgmt_ip=raw["mgmt_ip"],
        captured_at=raw["captured_at"],
        domains={d: DomainBaseline(**info) for d, info in raw["domains"].items()},
    )

    api_key = os.environ.get("APIKEY", "")
    if not api_key:
        print("APIKEY not set in .env.secrets / environment", file=sys.stderr)
        return 1

    cfg = ArodonataSettings(
        mgmt_names=[snap.mgmt_name],
        mgmt_servers=[snap.mgmt_ip],
        api_keys=[api_key],
    )
    client = ArodonataClient(settings=cfg)
    await client.initialize(run_startup_cleanup=False)
    try:
        outcomes = await restore_to_baseline(client, snap, force=force)
        for dom, reverted in outcomes.items():
            status = "REVERTED" if reverted else "already at baseline (no-op)"
            print(f"  {dom}: {status} -> {snap.domains[dom].session_uid}")
        return 0
    finally:
        await client.close(logout=True)


def main() -> None:
    """CLI entry point for restoring Check Point domains to saved baseline."""
    parser = argparse.ArgumentParser(description="Revert Check Point test domains to saved baseline.")
    parser.add_argument("--file", type=Path, default=DEFAULT_BASELINE_FILE, help="Path to cp_baseline.json")
    parser.add_argument("--force", action="store_true", help="Run revert-to-revision even if head matches")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_main(args.file, force=args.force)))


if __name__ == "__main__":
    main()
