"""Empirically measure the MDS per-administrator login rate limit.

Check Point MDS enforces a per-admin login throttle ("Too many login requests
for the same user have been sent in a limited timeframe"). Each domain login
under the same APIKEY / username counts toward that user's quota on the MDS.

Usage:
    uv run python -m tests.integration.probe_login_throttle
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time

from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport
from arodonata.core.config import ArodonataSettings
from tests.integration.lab_env import load_lab_env


async def probe() -> None:
    """Run rapid login/logout cycles until throttled, then measure recovery time."""
    load_lab_env()

    mgmt = os.environ["API_MGMT"]
    apikey = os.environ["APIKEY"]
    dom_a = os.environ.get("TEST_DOMAIN_A", "Domain4")

    settings = ArodonataSettings()
    trust_policy = TrustPolicy(
        mode=settings.tls_trust,
        known_hosts_path=settings.tls_known_hosts_path,
        pinned_fingerprints=settings.tls_fingerprints,
    )
    transport = ApiTransport(settings=settings, trust_policy=trust_policy)
    try:
        print(f"Rapid login/logout against {mgmt} ({dom_a}) until throttled...")
        t0 = time.monotonic()
        count = 0
        while count < 30:
            res = await transport.execute(mgmt, "login", {"api-key": apikey, "domain": dom_a})
            dt = time.monotonic() - t0
            if not res.success:
                print(
                    f"  #{count + 1:2d} at +{dt:5.1f}s -> THROTTLED: "
                    f"status={res.status_code} code={res.error_code} msg={res.error_message}"
                )
                break
            count += 1
            sid = res.data["sid"]
            await transport.execute(mgmt, "logout", {}, sid=sid)
            print(f"  #{count:2d} at +{dt:5.1f}s -> ok")

        if count == 30:
            print("Never throttled in 30 logins!")
            return

        print("\nProbing recovery window (every 5s)...")
        t_throttled = time.monotonic()
        for step in range(1, 25):
            await asyncio.sleep(5)
            waited = time.monotonic() - t_throttled
            res = await transport.execute(mgmt, "login", {"api-key": apikey, "domain": dom_a})
            if res.success:
                await transport.execute(mgmt, "logout", {}, sid=res.data["sid"])
                print(f"  +{waited:5.1f}s (step {step}) -> RECOVERED")
                break
            print(f"  +{waited:5.1f}s (step {step}) -> still throttled ({res.error_message})")
    finally:
        await transport.close()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Measure Check Point MDS per-administrator login throttle window.")
    _ = parser.parse_args()
    asyncio.run(probe())


if __name__ == "__main__":
    main()
