#!/usr/bin/env python
"""Build the integration lab's domains, administrators and extra objects on an MDS.

Standalone tool, not a test -- pytest does not collect it. It reproduces what
the old shared lab contained apart from the FPCR seed data,
which FPCR's own `seed.py` creates afterwards (see the design note
docs/superpowers/specs/2026-09-28-home-lab-build-design.md):

    ARODONATA_LAB=home uv run tests/integration/lab_build.py            # plan only
    ARODONATA_LAB=home uv run tests/integration/lab_build.py --apply    # make the changes

Dry run by default: it logs in read-only, compares the wanted state below with
what the server reports, and prints the plan. `--apply` carries the plan out,
publishing as it goes. Anything that already exists is skipped, so it is safe
to run again after a partial failure.

Authenticates with the API key only (`APIKEY`; the home profile points it at
`HOME_LAB_API_KEY`). Engineer passwords come from `USER_Eng1..4` and are sent
only in the add-administrator call. No secret is printed.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # run as a script: make `tests.integration` importable
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from arodonata.asdk.tls import VerifiedAPIClient, verified_api_client
from tests.integration.probe_lab_domains import THROTTLE_CODE, _close, _error_detail, _step, lab_policy

READ_TIMEOUT = 180.0  # seconds per read; main() sets it from --timeout

# ---------------------------------------------------------------------------
# Wanted state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Domain:
    name: str
    server_ip: str
    mds: str  # name of the MDS member that hosts the domain's server

    @property
    def server_name(self) -> str:
        return f"{self.name}_Server"


@dataclass(frozen=True)
class Admin:
    name: str
    password_env: str  # env var holding the password; the value is never stored here


@dataclass(frozen=True)
class Obj:
    command: str  # add-<type>; the existence check is the matching show-<type>
    name: str
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def show_command(self) -> str:
        return "show-" + self.command.removeprefix("add-")


# Domain4 is TEST_DOMAIN_A and Domain5 is TEST_DOMAIN_B.
DOMAIN_NAMES: list[str] = ["General", "Domain2", "Domain3", "Domain4", "Domain5"]

# Where the domains' servers go is lab-specific and lives in the lab profile
# (.env.lab.<name>), not here: the MDS member and the first of consecutive IPs.
MDS_VAR = "ARODONATA_LAB_BUILD_MDS"
FIRST_IP_VAR = "ARODONATA_LAB_BUILD_FIRST_IP"


def wanted_domains(mds: str, first_ip: str) -> list[Domain]:
    """DOMAIN_NAMES on `mds`, at `first_ip` and the addresses after it."""
    base = ipaddress.IPv4Address(first_ip)
    return [Domain(name, str(base + i), mds) for i, name in enumerate(DOMAIN_NAMES)]


# admin, AntonR and auto exist on the MDS already. All are Multi-Domain Super
# Users on the old lab, and the tests log in to every domain as each of them.
ADMINS: list[Admin] = [Admin(f"eng{n}", f"USER_Eng{n}") for n in range(1, 5)]

# What the old lab held beyond Check Point's predefined objects and the FPCR
# seed (inventory of 2026-09-28).
EXTRAS: dict[str, list[Obj]] = {
    "General": [
        Obj("add-host", "crud-host-1", {"ip-address": "192.168.100.10"}),
        Obj("add-host", "crud-host-2", {"ip-address": "192.168.100.11"}),
        Obj("add-host", "localhost", {"ip-address": "127.0.0.1"}),
    ],
    "Domain4": [
        Obj("add-simple-gateway", "fakegwD4", {"ip-address": "192.168.101.10"}),
        Obj("add-network", "net_10.238.0.0.-19", {"subnet4": "10.238.0.0", "mask-length4": 19}),
    ],
    "Domain5": [
        Obj("add-simple-gateway", "fakegwD5", {"ip-address": "192.168.102.10"}),
    ],
}

# ---------------------------------------------------------------------------
# Planning (pure)
# ---------------------------------------------------------------------------


@dataclass
class Actual:
    """What the MDS reports: domain -> its servers' IPs, admin names, domain -> object names."""

    domains: dict[str, set[str]]
    admins: set[str]
    objects: dict[str, set[str]]
    # Domain -> its active server's IP. Domain logins go there directly: a login
    # through the MDS with a domain name fails for a domain the MDS has not
    # synchronised yet ("managementDomainNeverSynced"), which is every domain
    # this script has just created on the other member.
    active_ip: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Action:
    command: str  # an API command, or "note" for something to report and leave alone
    domain: str  # "" for the MDS level
    name: str
    payload: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        where = f"[{self.domain}] " if self.domain else "[MDS] "
        return f"{where}{self.command} {self.name}"


def plan(actual: Actual, domains: list[Domain]) -> list[Action]:
    """Actions still needed, in the order they must run: domains, then admins, then extras."""
    actions: list[Action] = []
    for d in domains:
        servers = actual.domains.get(d.name)
        if servers is None:
            actions.append(
                Action(
                    "add-domain",
                    "",
                    d.name,
                    {
                        "name": d.name,
                        "servers": {"name": d.server_name, "ip-address": d.server_ip, "multi-domain-server": d.mds},
                    },
                )
            )
        elif d.server_ip not in servers:
            actions.append(
                Action("note", "", f"{d.name} exists with servers {sorted(servers)}, not {d.server_ip}: left as is")
            )

    for a in ADMINS:
        if a.name not in actual.admins:
            actions.append(
                Action(
                    "add-administrator",
                    "",
                    a.name,
                    {
                        "name": a.name,
                        "authentication-method": "check point password",
                        "multi-domain-profile": "Multi-Domain Super User",
                        "must-change-password": False,
                    },
                )
            )

    for domain, objs in EXTRAS.items():
        have = actual.objects.get(domain, set())
        for obj in objs:
            if obj.name not in have:
                actions.append(Action(obj.command, domain, obj.name, {"name": obj.name, **obj.payload}))
    return actions


# ---------------------------------------------------------------------------
# Talking to the MDS
# ---------------------------------------------------------------------------


def login(
    server: str, api_key: str, *, domain: str | None, read_only: bool, throttle_wait: int = 70
) -> VerifiedAPIClient:
    """API-key login with a visible, throttle-tolerant wait. Exits the script on a real refusal."""
    for _ in range(4):
        client = verified_api_client(server, read_timeout=READ_TIMEOUT, policy=lab_policy())
        payload = {"session-name": "arodonata lab_build"} if not read_only else {}
        response, _s = _step(
            f"login {domain or 'MDS'}",
            client.login_with_api_key,
            api_key,
            domain=domain,
            read_only=read_only,
            payload=payload,
        )
        if response.success:
            return client
        code, detail = _error_detail(response)
        _close(client, logout=False)
        if code != THROTTLE_CODE:
            sys.exit(f"\nlogin to {domain or 'MDS'} refused: {detail}")
        print(f"throttled, waiting {throttle_wait}s", flush=True)
        time.sleep(throttle_wait)
    sys.exit(f"\nlogin to {domain or 'MDS'} still throttled")


def call(client: VerifiedAPIClient, command: str, payload: dict[str, Any], *, label: str | None = None) -> Any:
    """One API call with a heartbeat; exits the script on failure, printing the server's reason."""
    response, _s = _step(label or command, client.api_call, command, payload, client.sid)
    if not response.success:
        print()
        _close(client, logout=True)
        sys.exit(f"{command} failed: {_error_detail(response)[1]}")
    return response


def exists(client: VerifiedAPIClient, obj: Obj) -> bool:
    response = client.api_call(obj.show_command, {"name": obj.name}, client.sid)
    if response.success:
        return True
    code, detail = _error_detail(response)
    if code == "generic_err_object_not_found":
        return False
    sys.exit(f"{obj.show_command} {obj.name} failed: {detail}")


def read_actual(server: str, api_key: str, gap: int) -> Actual:
    print("Reading the current state (read-only):")
    mds = login(server, api_key, domain=None, read_only=True)
    try:
        domains = call(mds, "show-domains", {"details-level": "full", "limit": 200}).data.get("objects", [])
        admins = call(mds, "show-administrators", {"limit": 500}).data.get("objects", [])
    finally:
        _close(mds, logout=True)
    print("ok")
    actual = Actual(
        domains={d["name"]: {s.get("ipv4-address", "") for s in d.get("servers", [])} for d in domains},
        admins={a["name"] for a in admins},
        objects={},
        active_ip={
            d["name"]: next((s["ipv4-address"] for s in d.get("servers", []) if s.get("active")), "") for d in domains
        },
    )
    for domain, objs in EXTRAS.items():
        if domain not in actual.domains:
            continue  # nothing can exist in a domain that does not
        time.sleep(gap)  # logins count against the machine's per-minute allowance
        _step_print = f"  [{domain}] "
        print(_step_print, end="", flush=True)
        client = login(actual.active_ip.get(domain) or server, api_key, domain=domain, read_only=True)
        try:
            actual.objects[domain] = {obj.name for obj in objs if exists(client, obj)}
        finally:
            _close(client, logout=True)
        print(f"found {len(actual.objects[domain])}/{len(objs)}")
    return actual


def active_ips(server: str, api_key: str) -> dict[str, str]:
    """Domain -> active server IP, read fresh: domains created a moment ago are included."""
    mds = login(server, api_key, domain=None, read_only=True)
    try:
        domains = call(mds, "show-domains", {"details-level": "full", "limit": 200}).data.get("objects", [])
    finally:
        _close(mds, logout=True)
    print("ok")
    return {d["name"]: next((s["ipv4-address"] for s in d.get("servers", []) if s.get("active")), "") for d in domains}


def apply(server: str, api_key: str, actions: list[Action], gap: int) -> None:
    apply_mds_level(server, api_key, [a for a in actions if not a.domain and a.command != "note"])
    apply_domain_level(server, api_key, [a for a in actions if a.domain], gap)


def apply_mds_level(server: str, api_key: str, mds_level: list[Action]) -> None:
    if mds_level:
        print("MDS level:")
        mds = login(server, api_key, domain=None, read_only=False)
        print()
        try:
            for a in mds_level:
                payload = dict(a.payload)
                if a.command == "add-administrator":
                    env = next(ad.password_env for ad in ADMINS if ad.name == a.name)
                    password = os.getenv(env)
                    if not password:
                        sys.exit(f"\n{env} is not set: cannot create {a.name}")
                    payload["password"] = password
                print(f"  {a.describe()}: ", end="", flush=True)
                label = "running (a new domain takes minutes)" if a.command == "add-domain" else "running"
                call(mds, a.command, payload, label=label)
                print("done")
            print("  publish: ", end="", flush=True)
            call(mds, "publish", {})
            print("done")
        finally:
            _close(mds, logout=True)


def apply_domain_level(server: str, api_key: str, actions: list[Action], gap: int) -> None:
    by_domain: dict[str, list[Action]] = {}
    for a in actions:
        by_domain.setdefault(a.domain, []).append(a)
    if not by_domain:
        return
    print("Domain servers: ", end="", flush=True)
    ips = active_ips(server, api_key)
    for domain, items in by_domain.items():
        time.sleep(gap)
        ip = ips.get(domain)
        if not ip:
            sys.exit(f"{domain} has no active server in show-domains")
        print(f"[{domain} @ {ip}] ", end="", flush=True)
        client = login(ip, api_key, domain=domain, read_only=False)
        try:
            for a in items:
                call(client, a.command, a.payload, label=f"{a.command} {a.name}")
            call(client, "publish", {})
            print("published")
        finally:
            _close(client, logout=True)


def main() -> None:
    from tests.integration.lab_env import load_lab_env

    profile = load_lab_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=os.getenv("API_MGMT"), help="MDS management IP (default: $API_MGMT)")
    parser.add_argument("--apply", action="store_true", help="make the changes (default: print the plan only)")
    parser.add_argument("--timeout", type=int, default=180, help="socket timeout per request, seconds (default: 180)")
    parser.add_argument("--gap", type=int, default=20, help="seconds between domain logins (default: 20)")
    args = parser.parse_args()

    api_key = os.getenv("APIKEY")
    if not args.server or not api_key:
        sys.exit("Need --server (or $API_MGMT) and $APIKEY; select the lab with ARODONATA_LAB")
    mds, first_ip = os.getenv(MDS_VAR), os.getenv(FIRST_IP_VAR)
    if not mds or not first_ip:
        sys.exit(f"Need {MDS_VAR} and {FIRST_IP_VAR} in the lab profile: where the domains' servers go")
    domains = wanted_domains(mds, first_ip)
    global READ_TIMEOUT
    READ_TIMEOUT = float(args.timeout)  # bounds every read: a hung request would block forever
    print(f"Lab profile: {profile or 'default (.env.test)'}   server: {args.server}\n")

    actions = plan(read_actual(args.server, api_key, args.gap), domains)
    print("\nPlan:" if actions else "\nNothing to do: the lab is already built.")
    for a in actions:
        print(f"  {a.describe()}")
    if not actions or not args.apply:
        if actions:
            print("\nDry run. Re-run with --apply to make these changes.")
        return
    print()
    apply(args.server, api_key, [a for a in actions if a.command != "note"], args.gap)
    print("\nDone. Next: FPCR seed.py --publish (base + UAT) with TEST_DOMAIN_A=Domain4 TEST_DOMAIN_B=Domain5.")


if __name__ == "__main__":
    main()
