"""Example 05 — Rulebase introspection, hierarchical SmartConsole numbering, and local filtering.

Run:
    uv run examples/05_rulebase_queries.py

Demonstrates:
1. `client.get_policy_packages(mgmt_name, domain)` — list cached policy packages and layers.
2. `client.get_package_rulebase(mgmt_name, domain, package)` — hierarchical SmartConsole rule
   numbers (`1`, `2.1`, `2.2.1`) across ordered Global/Domain layers and inline sub-layers.
3. `client.locate_rules(mgmt_name, domain, rule_uids=[...])` — reverse lookup from rule UID to
   SmartConsole rule numbers across packages.
4. `client.filter_rulebase(...)` — local rulebase query evaluation (`src:`, `dst:`, `svc:`,
   `action:`, free text, CIDR containment) rendered in `markdown` or `model_friendly` format.
"""

from __future__ import annotations

import asyncio
import os
import time

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402


async def main() -> None:
    """Inspect policy packages, numbered rulebases, rule locations, and local rule filtering."""
    settings = ArodonataSettings()
    t0 = time.perf_counter()

    async with ArodonataClient(settings=settings) as client:
        print("[Step 1/5] Resolving target domain (get_domains)...", flush=True)
        domains = await client.get_domains()
        if not domains:
            print("No domains discovered.")
            return

        dom = next((d for d in domains if d.name == os.getenv("EXAMPLE_DOMAIN")), domains[0])
        mgmt_name = dom.mgmt_name
        domain_name = dom.name

        print(f"[Step 2/5] Ensuring rulebase cache for {mgmt_name}:{domain_name} (refresh_rulebases)...", flush=True)
        await client.refresh_rulebases(mgmt_name=mgmt_name, domains=[domain_name], mode="smart")

        print(f"[Step 3/5] Listing policy packages in {domain_name} (get_policy_packages)...", flush=True)
        packages = await client.get_policy_packages(mgmt_name, domain_name, cache_mode="cache")
        if not packages:
            print(f"No policy packages cached in {domain_name}.")
            return

        pkg = packages[0]
        print(f"\nPolicy Package: {pkg.name} (uid={pkg.uid})")
        print(f"  Access layers: {[lay.layer_name for lay in pkg.access_layers]}")

        print(
            f"\n[Step 4/5] Computing hierarchical SmartConsole rule numbers for {pkg.name!r} (get_package_rulebase)...",
            flush=True,
        )
        pkg_rb = await client.get_package_rulebase(
            mgmt_name,
            domain_name,
            pkg.name,
            rulebase_type="access",
            cache_mode="cache",
        )
        for layer in pkg_rb.layers:
            print(f"\nLayer {layer.layer_name!r} (prefix={layer.prefix!r}, rules={len(layer.rules)}):")
            for nr in layer.rules[:5]:
                print(f"  #{nr.rule_number:<6} {nr.name or '(unnamed)':<28} action={nr.action} enabled={nr.enabled}")

        access_rules = await client.get_access_rules(mgmt_name, domain_name)
        if access_rules:
            sample = access_rules[0]
            locs = await client.locate_rules(
                mgmt_name,
                domain_name,
                rule_uids=[sample.uid],
                cache_mode="cache",
            )
            print(f"\nLocated rule UID {sample.uid}: {locs.rule_locations.get(sample.uid)}")

        print("\n[Step 5/5] Filtering rulebase locally (filter_rulebase)...", flush=True)
        filtered = await client.filter_rulebase(
            mgmt_name,
            domain_name,
            package=pkg.name,
            rulebase_type="access",
            filter_query=os.getenv("EXAMPLE_RULE_FILTER", "action:Accept"),
            output_format="markdown",
            cache_mode="cache",
        )
        print(f"\nFiltered rulebase ({filtered.matched_count}/{filtered.total_rules} matching rules):")
        print("\n".join(filtered.rendered_text.splitlines()[:15]))

    print(f"\nCompleted in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
