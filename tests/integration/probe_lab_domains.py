"""Probe the live MDS lab to inspect domains, published sessions, and revert capability.

Usage:
    uv run python -m tests.integration.probe_lab_domains
    ARODONATA_LAB=home uv run python -m tests.integration.probe_lab_domains
"""

from __future__ import annotations

import argparse
import asyncio
import os
from typing import Any

from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport
from arodonata.core.config import ArodonataSettings
from tests.integration.lab_env import load_lab_env


async def _call(
    transport: ApiTransport,
    ip: str,
    cmd: str,
    payload: dict[str, Any] | None = None,
    sid: str | None = None,
) -> dict[str, Any]:
    res = await transport.execute(ip, cmd, payload or {}, sid=sid)
    data = dict(res.data)
    data["_status"] = res.status_code
    data["_success"] = res.success
    return data


async def probe() -> None:
    """Connect to the configured MDS and print domain, session, and revert readiness info."""
    lab = load_lab_env()

    mgmt = os.environ["API_MGMT"]
    apikey = os.environ["APIKEY"]
    dom_a = os.environ.get("TEST_DOMAIN_A", "Domain4")
    dom_b = os.environ.get("TEST_DOMAIN_B", "Domain5")
    print(f"=== Lab profile: {lab or '(default .env.test)'} | MDS: {mgmt}  sandbox: A={dom_a} B={dom_b} ===")

    settings = ArodonataSettings()
    trust_policy = TrustPolicy(
        mode=settings.tls_trust,
        known_hosts_path=settings.tls_known_hosts_path,
        pinned_fingerprints=settings.tls_fingerprints,
    )
    transport = ApiTransport(settings=settings, trust_policy=trust_policy)
    try:
        # 1. System-level login -> list domains
        sys_login = await _call(transport, mgmt, "login", {"api-key": apikey})
        assert sys_login.get("_success"), f"System login failed: {sys_login}"
        sys_sid = sys_login["sid"]
        try:
            doms = await _call(transport, mgmt, "show-domains", {"details-level": "full"}, sid=sys_sid)
            print(f"\nDomains ({doms.get('total')}):")
            domain_names: list[str] = []
            for d in doms.get("objects", []):
                servers = [
                    f"{s.get('name')}:{s.get('ipv4-address')}(active={s.get('active')})" for s in d.get("servers", [])
                ]
                print(f"  - {d['name']:20s} uid={d['uid']}  servers={servers}")
                domain_names.append(d["name"])

            admins = await _call(transport, mgmt, "show-administrators", {"details-level": "standard"}, sid=sys_sid)
            print(f"\nAdministrators ({admins.get('total')}):")
            for a in admins.get("objects", []):
                print(f"  - {a.get('name')}")
        finally:
            await _call(transport, mgmt, "logout", {}, sid=sys_sid)

        # 2. Inspect each domain: published sessions, open sessions, object counts
        for dom in domain_names:
            d_login = await _call(transport, mgmt, "login", {"api-key": apikey, "domain": dom})
            if not d_login.get("_success"):
                print(f"\n[{dom}] login failed: {d_login}")
                continue
            sid = d_login["sid"]
            try:
                pub = await _call(
                    transport,
                    mgmt,
                    "show-sessions",
                    {"view-published-sessions": True, "limit": 5, "details-level": "standard"},
                    sid=sid,
                )
                open_s = await _call(
                    transport,
                    mgmt,
                    "show-sessions",
                    {"view-published-sessions": False, "limit": 20, "details-level": "standard"},
                    sid=sid,
                )
                hosts = await _call(transport, mgmt, "show-hosts", {"limit": 1}, sid=sid)
                pkgs = await _call(transport, mgmt, "show-packages", {"limit": 10}, sid=sid)
                pkg_names = [p.get("name") for p in pkgs.get("objects", [])]
                pub_objs = pub.get("objects", [])
                head = pub_objs[0] if pub_objs else {}
                head_iso = (head.get("publish-time") or {}).get("iso-8601")
                print(
                    f"\n[{dom}] hosts={hosts.get('total')} packages={pkg_names} "
                    f"published_sessions={pub.get('total')} open_sessions={open_s.get('total')}\n"
                    f"  latest published: uid={head.get('uid')} name={head.get('name')!r} at={head_iso}"
                )
                for osess in open_s.get("objects", []):
                    if osess.get("changes") or osess.get("locks"):
                        print(
                            f"  OPEN dirty session: uid={osess.get('uid')} user={osess.get('user-name')} "
                            f"changes={osess.get('changes')} locks={osess.get('locks')}"
                        )
            finally:
                await _call(transport, mgmt, "logout", {}, sid=sid)

        # 3. Verify revert-to-revision syntax dry check on TEST_DOMAIN_A
        d_login = await _call(transport, mgmt, "login", {"api-key": apikey, "domain": dom_a})
        sid = d_login["sid"]
        try:
            probe_rev = await _call(
                transport,
                mgmt,
                "revert-to-revision",
                {"to-session": "00000000-0000-0000-0000-000000000000"},
                sid=sid,
            )
            print(
                f"\n[revert-to-revision probe on {dom_a}] status={probe_rev.get('_status')} "
                f"code={probe_rev.get('code')} message={probe_rev.get('message')}"
            )
        finally:
            await _call(transport, mgmt, "logout", {}, sid=sid)
    finally:
        await transport.close()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Probe live MDS domains, sessions, and revert readiness.")
    _ = parser.parse_args()
    asyncio.run(probe())


if __name__ == "__main__":
    main()
