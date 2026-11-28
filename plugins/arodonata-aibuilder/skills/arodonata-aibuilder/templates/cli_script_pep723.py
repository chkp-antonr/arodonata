#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "arodonata>=2.6.7",
#   "arlogi>=0.1.0",
# ]
# ///
"""Starter single-file PEP 723 CLI script for Check Point asset inventory and target classification."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence

import arlogi

from arodonata import ArodonataClient, ArodonataSettings, Asset


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect Check Point gateways/servers using native Asset role and platform classification.",
    )
    parser.add_argument("--mgmt-name", default=None, help="Configured management server name (ARODONATA_MGMT_NAME).")
    parser.add_argument("--domain", default=None, help="Target MDS domain name (omit for all cached domains or SMS).")
    parser.add_argument(
        "--role",
        dest="roles",
        action="append",
        default=None,
        help="Filter by AssetRole (repeatable, e.g. --role cluster --role gateway).",
    )
    parser.add_argument(
        "--platform",
        dest="platforms",
        action="append",
        default=None,
        help="Filter by AssetPlatform (repeatable, e.g. --platform gaia --platform maestro).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and preview planned target scope without executing remote mutations.",
    )
    parser.add_argument("--log-level", default="INFO", help="Logging level (INFO, DEBUG, WARNING).")
    parser.add_argument("--log-file", default="logs/arodonata_cli.jsonl", help="Structured JSONL audit log path.")
    return parser


def _summarize_assets(assets: Sequence[Asset]) -> dict[str, object]:
    policy_targets = [asset.name for asset in assets if asset.is_policy_target]
    execution_targets = [asset.name for asset in assets if asset.is_execution_target]
    return {
        "total": len(assets),
        "policy_target_count": len(policy_targets),
        "execution_target_count": len(execution_targets),
        "assets": [
            {
                "name": asset.name,
                "domain": asset.domain_name,
                "type": asset.type,
                "asset_role": asset.asset_role,
                "platform_family": asset.platform_family,
                "is_policy_target": asset.is_policy_target,
                "is_execution_target": asset.is_execution_target,
            }
            for asset in assets
        ],
    }


async def _run(args: argparse.Namespace) -> int:
    logger = arlogi.get_logger(__name__)
    settings = ArodonataSettings()
    mgmt_name = args.mgmt_name or settings.mgmt_name or (settings.mgmt_names[0] if settings.mgmt_names else None)

    if args.dry_run:
        logger.info(
            "dry-run preview complete; skipping live management connection",
            mgmt_name=mgmt_name,
            domain=args.domain,
            roles=args.roles,
            platforms=args.platforms,
        )
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "mgmt_name": mgmt_name,
                    "domain": args.domain,
                    "roles": args.roles,
                    "platforms": args.platforms,
                },
                indent=2,
            )
        )
        return 0

    async with ArodonataClient(settings=settings) as client:
        outcome = await client.refresh_assets(
            mgmt_name=mgmt_name,
            domains=args.domain,
            mode="smart",
        )
        if outcome.failed_domains:
            logger.error(
                "asset refresh failed for one or more domains",
                mgmt_name=mgmt_name,
                failed_domains=list(outcome.failed_domains),
            )
            return 2

        assets = await client.get_gateways(
            mgmt_name=mgmt_name,
            domain=args.domain,
            roles=args.roles,
            platforms=args.platforms,
            cache_mode="cache",
        )
        summary = _summarize_assets(assets)
        logger.info(
            "classified Check Point assets",
            mgmt_name=mgmt_name,
            domain=args.domain,
            total=summary["total"],
            policy_targets=summary["policy_target_count"],
            execution_targets=summary["execution_target_count"],
        )
        print(json.dumps(summary, indent=2))
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    arlogi.setup_logging(
        level=args.log_level,
        json_file_name=args.log_file,
        json_file_only=False,
    )
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
