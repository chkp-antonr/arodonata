#!/usr/bin/env python
"""Measure Check Point's login rate limit: when it trips, and when it clears.

Standalone diagnostic, not a test -- pytest does not collect it. Run it to replace
guesses with numbers:

    uv run tests/integration/probe_login_throttle.py
    uv run tests/integration/probe_login_throttle.py --cycles 5 --no-logout

It deliberately talks to cpapi directly rather than through ArodonataClient. Our
own login path retries, backs off and waits out throttle windows, all of which
would hide exactly what this is trying to observe. Here one login is one login.

What it does:

1. Logs in to the system domain, reads `show-domains`, logs out. That first login
   is the one people forget to count: N domains means N+1 logins per cycle.
2. Repeats cycles of login (+ logout) to the system domain and every domain,
   recording per attempt: elapsed seconds, outcome, and the error code the server
   returned. Finishes the cycle even after a failure, so the run shows which
   domains are sick and which are healthy at the same moment.
3. Then probes a single login every `--recover-interval` seconds until one
   succeeds, and reports how long recovery actually took.

Step 3 is the number that matters most: LOGIN_THROTTLE_WINDOW_SECONDS (70 s) is
currently an educated guess at it.

`--no-logout` leaves sessions open, which is how the integration suite behaved
before 2026-09-14. Comparing a run with and without it says whether the limit is
about login *rate* or about accumulated open sessions -- a question this session
could not settle by inference.

Reads the same .env.test / .env.secrets as the integration suite. Never logs the
API key.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).parent.parent.parent
for _f in [_ROOT / ".env.test", _ROOT / ".env.secrets"]:
    if _f.exists():
        load_dotenv(_f, override=True)

from cpapi import APIClient, APIClientArgs  # noqa: E402 - after dotenv, like conftest

SYSTEM_DOMAIN = ""  # "" and "System Data" are the same thing to the API


@dataclass
class Attempt:
    """One login, as the server answered it."""

    at: float
    domain: str
    elapsed: float
    ok: bool
    detail: str = ""

    @property
    def label(self) -> str:
        return self.domain or "(system)"


@dataclass
class Probe:
    server: str
    api_key: str
    timeout: int
    logout: bool = True
    attempts: list[Attempt] = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)

    def login(self, domain: str) -> tuple[APIClient | None, Attempt]:
        """One raw login. Returns (client, attempt); client is None on failure."""
        client = APIClient(APIClientArgs(server=self.server, unsafe=True))
        t0 = time.monotonic()
        try:
            response = client.login_with_api_key(self.api_key, domain=domain or None)
        except Exception as exc:  # noqa: BLE001 - a socket timeout is a result, not a crash
            elapsed = time.monotonic() - t0
            return None, Attempt(t0 - self.started, domain, elapsed, False, f"{type(exc).__name__}: {exc}")

        elapsed = time.monotonic() - t0
        if response.success:
            return client, Attempt(t0 - self.started, domain, elapsed, True)

        # Keep code AND message: Check Point's max-sessions refusal is reportedly
        # hard to tell apart from a rejected password, and our own classifier
        # (CREDENTIAL_REJECTION_MESSAGE vs SessionCleaner.is_max_sessions_error)
        # depends on which strings actually come back. Collapsing them here would
        # destroy the evidence for that.
        data = response.data if isinstance(response.data, dict) else {}
        code = str(data.get("code") or "")
        message = str(data.get("message") or getattr(response, "error_message", "") or "")
        detail = " | ".join(part for part in (code, message) if part) or "unknown"
        return None, Attempt(t0 - self.started, domain, elapsed, False, detail)

    def logout_quietly(self, client: APIClient) -> None:
        try:
            client.api_call("logout", {}, client.sid)
        except Exception:  # noqa: BLE001 - best effort; a failed logout is not the measurement
            pass
        finally:
            try:
                client.close_connection()
            except Exception:  # noqa: BLE001
                pass

    def tcp_check(self, host: str, port: int = 443) -> str:
        """How long a bare TCP connect to the API port takes, right now.

        A login that hangs while this returns in milliseconds is a stalled
        application, not a congested network -- the distinction the timing alone
        cannot make. TCP rather than ICMP: ping is frequently filtered, and it is
        the API port we actually care about.
        """
        t0 = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=5):
                return f"tcp {port} ok in {time.monotonic() - t0:.2f}s"
        except Exception as exc:  # noqa: BLE001 - the failure is the datum
            return f"tcp {port} FAILED after {time.monotonic() - t0:.2f}s: {type(exc).__name__}"

    def ping_check(self, host: str, size: int = 1200) -> str:
        """Packet loss for large ICMP echoes, right now.

        Large on purpose. A path that carries small packets happily but drops
        large ones -- an MTU black hole, or congestion that only bites at size --
        produces exactly the symptom we are chasing: the TCP handshake completes
        (small packets), the login request goes out, and the larger response never
        arrives, so the read times out. A default 56-byte ping would come back
        clean and prove nothing.
        """
        cmd = ["ping", "-c", "3", "-s", str(size), "-t", "5", host]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
        except Exception as exc:  # noqa: BLE001 - ping missing or blocked is itself a result
            return f"ping -s {size} unavailable: {type(exc).__name__}"
        loss = next((ln.strip() for ln in out.splitlines() if "packet loss" in ln), "")
        rtt = next((ln.strip() for ln in out.splitlines() if "round-trip" in ln or "rtt" in ln), "")
        return f"ping -s {size}: {loss or 'no reply'}" + (f" | {rtt}" if rtt else "")

    def attempt(self, domain: str) -> Attempt:
        """Login, optionally log out, record and print the outcome."""
        client, record = self.login(domain)
        self.attempts.append(record)
        mark = "ok " if record.ok else "FAIL"
        print(f"  [{record.at:7.1f}s] {mark} {record.label:<14} {record.elapsed:6.1f}s {record.detail}")
        if not record.ok:
            print(f"           reachability: {self.tcp_check(self.server)}")
            print(f"           {self.ping_check(self.server)}")
        if client is not None:
            if self.logout:
                self.logout_quietly(client)
            else:
                try:
                    client.close_connection()  # leave the session open on the server
                except Exception:  # noqa: BLE001
                    pass
        return record


def discover_domains(probe: Probe) -> list[str]:
    """The system-domain login every cycle repeats, plus the domain list it exists to fetch."""
    print("Discovering domains (this is the +1 login every cycle pays):")
    client, record = probe.login(SYSTEM_DOMAIN)
    probe.attempts.append(record)
    if client is None:
        sys.exit(f"Cannot log in to the system domain: {record.detail}")
    print(f"  [{record.at:7.1f}s] ok  (system)       {record.elapsed:6.1f}s")

    try:
        response = client.api_call("show-domains", {"details-level": "standard", "limit": 200}, client.sid)
        objects = (response.data or {}).get("objects", []) if response.success else []
        domains = [o["name"] for o in objects if isinstance(o, dict) and o.get("name")]
    finally:
        probe.logout_quietly(client)

    print(f"  -> {len(domains)} domain(s): {', '.join(domains) or '(none - SMS?)'}")
    print(f"  -> each cycle performs {len(domains) + 1} logins\n")
    return domains


def saturate(probe: Probe, domains: list[str], cycles: int) -> list[str]:
    """Run every domain every cycle; return the domains that failed.

    Deliberately does NOT stop at the first failure. An earlier version did, and
    the result was useless: when Domain2 hung we never tried Domain3, Domain4,
    Domain5 or General, so the run could not tell "one sick domain server" from
    "every domain login is stalled" -- which is the question. Finishing the cycle
    costs a few more logins and answers it.
    """
    for cycle in range(1, cycles + 1):
        print(f"Cycle {cycle}/{cycles}:")
        failed: list[str] = []
        for domain in [SYSTEM_DOMAIN, *domains]:
            if not probe.attempt(domain).ok:
                failed.append(domain)
        if failed:
            healthy = [d or "(system)" for d in [SYSTEM_DOMAIN, *domains] if d not in failed]
            print(f"\n>>> Cycle {cycle}: FAILED {[d or '(system)' for d in failed]}  |  healthy {healthy}\n")
            return failed
        print(f"  (cycle {cycle}: all {len(domains) + 1} logins ok)\n")
    return []


def measure_recovery(probe: Probe, failed: list[str], domains: list[str], interval: int, limit: int) -> None:
    """Probe every failed domain until it recovers, with the system domain as a control.

    Per-domain, because they may not recover together -- and the control says
    whether the MDS itself is answering while a domain login is not.
    """
    print(f"Probing recovery every {interval}s (giving up after {limit}s):")
    pending = list(failed)
    t0 = time.monotonic()
    while pending and (time.monotonic() - t0) <= limit:
        time.sleep(interval)
        probe.attempt(SYSTEM_DOMAIN)  # control: is the MDS answering at all?
        for domain in list(pending):
            if probe.attempt(domain).ok:
                waited = time.monotonic() - t0
                print(f"\n>>> {domain} recovered ~{waited:.0f}s after the failing cycle\n")
                pending.remove(domain)
    if pending:
        print(f"\n>>> Still failing after {limit}s: {pending}\n")


def summarise(probe: Probe) -> None:
    ok = [a for a in probe.attempts if a.ok]
    bad = [a for a in probe.attempts if not a.ok]
    print("=" * 72)
    print(f"attempts: {len(probe.attempts)}   ok: {len(ok)}   failed: {len(bad)}")
    if ok:
        slow = sorted(ok, key=lambda a: -a.elapsed)[:5]
        print("slowest successful logins:")
        for a in slow:
            print(f"  {a.elapsed:6.1f}s  {a.label}")
    if bad:
        reasons: dict[str, int] = {}
        for a in bad:
            reasons[a.detail] = reasons.get(a.detail, 0) + 1
        print("failures by reason:")
        for reason, n in sorted(reasons.items(), key=lambda x: -x[1]):
            print(f"  {n:3d}x  {reason}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=os.getenv("API_MGMT"), help="MDS IP/host (default: $API_MGMT)")
    parser.add_argument("--api-key-env", default="APIKEY", help="env var holding the API key (default: APIKEY)")
    parser.add_argument("--cycles", type=int, default=10, help="login cycles over all domains (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="socket timeout per login in seconds (default: 30)")
    parser.add_argument("--recover-interval", type=int, default=10, help="recovery probe interval (default: 10)")
    parser.add_argument("--recover-max", type=int, default=240, help="give up on recovery after (default: 240)")
    parser.add_argument("--no-logout", action="store_true", help="leave sessions open (tests the leak hypothesis)")
    args = parser.parse_args()

    api_key = os.getenv(args.api_key_env)
    if not args.server or not api_key:
        sys.exit(f"Need --server (or $API_MGMT) and ${args.api_key_env}")

    # Bounds a hanging login: cpapi sets no timeout on its HTTPS connection, so
    # without this a stalled login blocks the probe indefinitely.
    socket.setdefaulttimeout(args.timeout)

    print(f"Server: {args.server}   socket timeout: {args.timeout}s   logout: {not args.no_logout}\n")
    probe = Probe(server=args.server, api_key=api_key, timeout=args.timeout, logout=not args.no_logout)

    domains = discover_domains(probe)
    failed = saturate(probe, domains, args.cycles)
    if failed:
        measure_recovery(probe, failed, domains, args.recover_interval, args.recover_max)
    else:
        print(f">>> No failure in {args.cycles} cycles -- the limit was not reached.\n")
    summarise(probe)


if __name__ == "__main__":
    main()
