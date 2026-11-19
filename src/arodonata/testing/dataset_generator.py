"""Deterministic enterprise raw dataset generator for Check Point MDSM API & CLI replay testing.

Generates `tests/fixtures/enterprise_raw_dataset/` with fixed seed (`20261108`) containing:
- 9 user MDSM domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`,
  `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`.
- 315 policy-enforcing gateways (341 total domain assets including cluster members and physical VSX chassis),
  with heterogeneous appliance, HA cluster, Virtual System, and cross-domain VSX distribution across every domain.
- 2,951 network objects and 210 service objects across domains, including 7-level nested object groups and address ranges.
- 1,050+ access and NAT rules across domain and Global policy packages with sections and inline layers.
- Raw CLI routing outputs (`ip -4 route show`, `clish -c "show route"`, `vsx stat -l`) covering
  `kernel`/`C`, `static`/`S`, `bgp`/`B`, `ospf`/`O`, `routed`/`R`, `I` IS-IS, ECMP, and cluster member drift.
- Base64-encoded `run-script` / `show-task` JSON payloads for `cprid` fallback verification.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

from ._dataset_common import (
    ALL_DOMAINS,
    DATASET_VERSION,
    DEFAULT_DATASET_DIR,
    DEFAULT_SEED,
    USER_DOMAINS,
    DatasetBuildContext,
)
from ._dataset_domains_dc import populate_dc_pod_domain, populate_dc_spine_domain
from ._dataset_domains_edge import (
    populate_branch_domain,
    populate_regional_domain,
    populate_wan_core_domain,
)
from ._dataset_domains_partner import populate_db_seg_domain, populate_partner_dmz_domain
from ._dataset_domains_transit import populate_perimeter_domain, populate_transit_domain
from ._dataset_global import populate_global_and_services, populate_mdsm_domains_and_sessions
from ._dataset_heterogeneous import populate_heterogeneous_mix
from ._dataset_policies import populate_bulk_objects, populate_policies_and_rulebases
from ._dataset_writer import write_dataset_and_manifest


def generate_enterprise_raw_dataset(
    output_dir: Path | str | None = None,
    *,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    """Generate the complete raw Check Point MDSM API and CLI dataset on disk and return its manifest."""
    root = Path(output_dir) if output_dir is not None else DEFAULT_DATASET_DIR
    rng = random.Random(seed)
    ctx = DatasetBuildContext()

    populate_mdsm_domains_and_sessions(ctx)
    populate_global_and_services(ctx)
    populate_branch_domain(ctx)
    populate_regional_domain(ctx)
    populate_wan_core_domain(ctx)
    populate_perimeter_domain(ctx)
    populate_transit_domain(ctx)
    populate_dc_spine_domain(ctx)
    populate_dc_pod_domain(ctx)
    populate_db_seg_domain(ctx)
    populate_partner_dmz_domain(ctx)
    populate_heterogeneous_mix(ctx)
    populate_bulk_objects(ctx, rng)
    total_access_rules, total_nat_rules = populate_policies_and_rulebases(ctx)

    return write_dataset_and_manifest(
        ctx,
        root,
        seed=seed,
        total_access_rules=total_access_rules,
        total_nat_rules=total_nat_rules,
    )


def ensure_enterprise_raw_dataset(
    output_dir: Path | str | None = None,
    *,
    seed: int = DEFAULT_SEED,
    force: bool = False,
) -> Path:
    """Ensure `tests/fixtures/enterprise_raw_dataset/` exists and matches `DATASET_VERSION` and `seed`."""
    root = Path(output_dir) if output_dir is not None else DEFAULT_DATASET_DIR
    manifest_path = root / "manifest.json"
    if not force and manifest_path.is_file():
        try:
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            if existing.get("version") == DATASET_VERSION and existing.get("seed") == seed:
                return root
        except Exception:
            pass
    generate_enterprise_raw_dataset(root, seed=seed)
    return root


__all__ = [
    "ALL_DOMAINS",
    "DATASET_VERSION",
    "DEFAULT_DATASET_DIR",
    "DEFAULT_SEED",
    "USER_DOMAINS",
    "ensure_enterprise_raw_dataset",
    "generate_enterprise_raw_dataset",
]
