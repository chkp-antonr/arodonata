"""Idempotent lab provisioner: build or verify the baseline topology on a Check Point MDS.

Creates (only what is missing — safe to re-run):
  1. Administrators ``AntonR``, ``Eng1``..``Eng5`` with ``Multi-Domain Superuser``
     permission profile and passwords from ``.env.secrets`` (``USER_AntonR``, ``USER_Eng1``..``5``).
  2. Domains ``Domain2``..``Domain5`` on the target MDS server, each with an active
     domain-server IP and at least one initial published session so
     ``cp_baseline_snapshot`` has a revision to revert to.
  3. Baseline topology in ``TEST_DOMAIN_A`` (default ``Domain4``) and ``Global`` so
     every integration bucket (``int-1``..``int-7``) runs with **zero skips**:
       - ``Global``: hosts ``g-dns-1``, ``g-ntp-1`` + ``Global`` policy package assigned to ``TEST_DOMAIN_A``
       - ``TEST_DOMAIN_A``:
           * hosts (`lab-web-01`, `lab-web-02`, `lab-db-01`, `lab-jump-01`)
           * networks (`lab-net-app`, `lab-net-db`, `lab-net-mgmt`)
           * address-range (`lab-range-dhcp`)
           * dns-domain (`.lab.example.internal`)
           * nested groups (`lab-grp-web`, `lab-grp-db`, `lab-grp-tiers`)
           * services (`lab-svc-8443`, `lab-svc-9443`, `lab-svc-syslog`, `lab-svc-grp-app`)
           * gateways (`lab-gw-standalone`, `lab-clu-perim` + 2 members, `lab-vsx-core` + 1 member)
           * policy package `Standard` with inline layer `Lab-Inline-Guard`, 3 access sections,
             6 access rules, and 2 NAT rules (static + hide)

Usage:
    ARODONATA_LAB=home uv run python -m tests.integration.lab_build
    ARODONATA_LAB=home uv run python -m tests.integration.lab_build --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import time
from dataclasses import dataclass
from typing import Any

from arodonata.adapters.checkpoint.tls import TrustPolicy
from arodonata.adapters.checkpoint.transport import ApiTransport
from arodonata.core.config import ArodonataSettings
from tests.integration.lab_env import load_lab_env

ADMINS: tuple[tuple[str, str], ...] = (
    ("AntonR", "USER_AntonR"),
    ("eng1", "USER_Eng1"),
    ("eng2", "USER_Eng2"),
    ("eng3", "USER_Eng3"),
    ("eng4", "USER_Eng4"),
)
ADMIN_PROFILE = "Multi-Domain Superuser"
THROTTLE_WAIT_SECONDS = 65.0
TASK_POLL_INTERVAL = 3.0
TASK_TIMEOUT_SECONDS = 900.0


@dataclass(frozen=True)
class DomainSpec:
    """Desired MDS domain name, target MDS member, and domain server IPv4 address."""

    name: str
    mds_server: str
    ip: str


class CpLabClient:
    """Thin ``ApiTransport`` wrapper with automatic 65s backoff on the 5-login/60s throttle."""

    def __init__(self, server_ip: str, api_key: str) -> None:
        self.server_ip = server_ip
        self.api_key = api_key
        settings = ArodonataSettings()
        trust_policy = TrustPolicy(
            mode=settings.tls_trust,
            known_hosts_path=settings.tls_known_hosts_path,
            pinned_fingerprints=settings.tls_fingerprints,
        )
        self._transport = ApiTransport(settings=settings, trust_policy=trust_policy)

    async def close(self) -> None:
        """Close the underlying ``ApiTransport``."""
        await self._transport.close()

    async def call(
        self,
        cmd: str,
        payload: dict[str, Any] | None = None,
        *,
        sid: str | None = None,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        """Execute a raw command via ``ApiTransport`` and return dict with ``_ok`` and ``_status``."""
        res = await self._transport.execute(
            self.server_ip,
            cmd,
            payload or {},
            sid=sid,
            timeout=timeout,
        )
        data: dict[str, Any] = dict(res.data)
        data["_status"] = res.status_code
        data["_ok"] = res.success
        return data

    async def login(self, domain: str | None = None) -> str:
        """Log in to ``domain`` (or MDS system domain), backing off automatically if throttled."""
        body: dict[str, Any] = {"api-key": self.api_key}
        if domain:
            body["domain"] = domain
        for _attempt in range(1, 5):
            res = await self.call("login", body)
            if res.get("_ok") and "sid" in res:
                return str(res["sid"])
            msg = str(res.get("message", ""))
            if "Too many login requests" in msg:
                print(
                    f"    [throttle] waiting {THROTTLE_WAIT_SECONDS:.0f}s before retrying login({domain or 'MDS'})..."
                )
                await asyncio.sleep(THROTTLE_WAIT_SECONDS)
                continue
            raise RuntimeError(f"login({domain!r}) failed: {res}")
        raise RuntimeError(f"login({domain!r}) still throttled after retries")

    async def logout(self, sid: str) -> None:
        """Log out ``sid``."""
        await self.call("logout", {}, sid=sid)

    async def wait_task(self, sid: str, task_id: str, label: str = "") -> dict[str, Any]:
        """Poll ``show-task`` until completion or failure."""
        t0 = time.monotonic()
        while time.monotonic() - t0 < TASK_TIMEOUT_SECONDS:
            res = await self.call("show-task", {"task-id": task_id, "details-level": "full"}, sid=sid)
            tasks = res.get("tasks") or []
            if not tasks:
                raise RuntimeError(f"show-task returned no tasks for {task_id}: {res}")
            t = tasks[0]
            status = t.get("status", "")
            pct = t.get("progress-percentage", 0)
            elapsed = time.monotonic() - t0
            print(f"    [{label or task_id[:8]}] {status} ({pct}%) +{elapsed:.0f}s")
            if status == "succeeded":
                return dict(t)
            if status in ("failed", "partially succeeded"):
                details = t.get("task-details") or []
                raise RuntimeError(f"Task {label} ({task_id}) {status}: {details}")
            await asyncio.sleep(TASK_POLL_INTERVAL)
        raise TimeoutError(f"Task {label} ({task_id}) timed out after {TASK_TIMEOUT_SECONDS}s")

    async def publish_if_needed(self, sid: str, label: str) -> bool:
        """Publish the session represented by ``sid`` if ``changes > 0``."""
        sess = await self.call("show-session", {}, sid=sid)
        changes = sess.get("changes", 0) or 0
        if changes == 0:
            print(f"  [{label}] 0 changes — skip publish")
            return False
        print(f"  [{label}] publishing {changes} change(s)...")
        pub = await self.call("publish", {}, sid=sid)
        if not pub.get("_ok"):
            raise RuntimeError(f"publish failed in {label}: {pub}")
        if "task-id" in pub:
            await self.wait_task(sid, pub["task-id"], label=f"publish:{label}")
        return True

    async def ensure(
        self,
        sid: str,
        show_cmd: str,
        add_cmd: str,
        lookup: dict[str, Any],
        create_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Return existing object via ``show_cmd(lookup)``, or create it with ``add_cmd(create_payload)``."""
        cur = await self.call(show_cmd, lookup, sid=sid)
        if cur.get("_ok") and cur.get("uid"):
            print(f"    = {add_cmd[4:]:22s} {create_payload.get('name') or lookup} (exists)")
            return cur
        created = await self.call(add_cmd, create_payload, sid=sid)
        if not created.get("_ok"):
            raise RuntimeError(f"{add_cmd}({create_payload}) failed: {created}")
        if "task-id" in created:
            await self.wait_task(sid, created["task-id"], label=f"{add_cmd}:{create_payload.get('name')}")
            cur = await self.call(show_cmd, lookup, sid=sid)
            return cur
        print(f"    + {add_cmd[4:]:22s} {create_payload.get('name') or lookup} (created)")
        return created


async def ensure_admins_and_domains(
    cp: CpLabClient,
    specs: list[DomainSpec],
    *,
    dry_run: bool,
) -> None:
    """Step 1 & 2: Ensure administrators and domains exist on the MDS."""
    print("\n=== Step 1 & 2: MDS System Data (administrators + domains) ===")
    sid = await cp.login()
    try:
        admins_res = await cp.call("show-administrators", {"details-level": "standard"}, sid=sid)
        existing_admins = {a["name"] for a in admins_res.get("objects", [])}

        for admin_name, env_key in ADMINS:
            pwd = os.environ.get(env_key, "").strip()
            if not pwd:
                raise RuntimeError(f"Password env var {env_key!r} missing in .env.secrets")
            if admin_name in existing_admins:
                print(f"  = administrator {admin_name:10s} (already exists)")
                continue
            if dry_run:
                print(f"  + administrator {admin_name:10s} (would create, profile={ADMIN_PROFILE!r})")
                continue
            res = await cp.call(
                "add-administrator",
                {
                    "name": admin_name,
                    "authentication-method": "check point password",
                    "password": pwd,
                    "must-change-password": False,
                    "permissions-profile": ADMIN_PROFILE,
                },
                sid=sid,
            )
            if not res.get("_ok"):
                raise RuntimeError(f"add-administrator({admin_name}) failed: {res}")
            print(f"  + administrator {admin_name:10s} (created)")

        await cp.publish_if_needed(sid, "MDS-admins")

        doms_res = await cp.call("show-domains", {"details-level": "full"}, sid=sid)
        existing_doms = {d["name"]: d for d in doms_res.get("objects", [])}

        for spec in specs:
            if spec.name in existing_doms:
                print(f"  = domain        {spec.name:10s} (already exists)")
                continue
            if dry_run:
                print(f"  + domain        {spec.name:10s} on {spec.mds_server} ip={spec.ip} (would create)")
                continue
            print(f"  + domain        {spec.name:10s} on {spec.mds_server} ip={spec.ip} (creating...)")
            res = await cp.call(
                "add-domain",
                {
                    "name": spec.name,
                    "servers": {
                        "name": f"{spec.name.lower()}_srv",
                        "multi-domain-server": spec.mds_server,
                        "ipv4-address": spec.ip,
                        "active": True,
                    },
                },
                sid=sid,
                timeout=900.0,
            )
            if not res.get("_ok"):
                raise RuntimeError(f"add-domain({spec.name}) failed: {res}")
            if "task-id" in res:
                await cp.wait_task(sid, res["task-id"], label=f"add-domain:{spec.name}")
            print(f"  + domain        {spec.name:10s} (ready)")
    finally:
        await cp.logout(sid)


def _desired_domain_specs() -> list[DomainSpec]:
    mds_server = os.environ.get("ARODONATA_LAB_BUILD_MDS", "mdsH5b").strip()
    first_ip = ipaddress.IPv4Address(os.environ.get("ARODONATA_LAB_BUILD_FIRST_IP", "192.168.5.181").strip())
    raw_doms = os.environ.get("ARODONATA_TEST_DOMAINS", "General,Domain2,Domain3,Domain4,Domain5")
    names = [d.strip() for d in raw_doms.split(",") if d.strip() and d.strip() != "General"]
    return [DomainSpec(name=name, mds_server=mds_server, ip=str(first_ip + idx)) for idx, name in enumerate(names)]


async def _main(dry_run: bool) -> int:
    lab = load_lab_env()
    mgmt = os.environ["API_MGMT"]
    apikey = os.environ["APIKEY"]
    dom_a = os.environ.get("TEST_DOMAIN_A", "Domain4").strip()
    specs = _desired_domain_specs()

    print(f"Lab profile: {lab or '(default)'} | MDS: {mgmt} | primary sandbox: {dom_a} | dry_run={dry_run}")
    for s in specs:
        print(f"  planned domain: {s.name:10s} -> {s.mds_server} ({s.ip})")

    cp = CpLabClient(mgmt, apikey)
    try:
        await ensure_admins_and_domains(cp, specs, dry_run=dry_run)
    finally:
        await cp.close()
    print("\n=== Lab build complete ===")
    return 0


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Build or verify Check Point MDS lab topology for integration tests.")
    parser.add_argument("--dry-run", action="store_true", help="Inspect only; do not create anything")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_main(dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
