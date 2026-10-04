#!/usr/bin/env python
"""Wake every lab domain and show how fast each one answers.

Standalone diagnostic, not a test -- pytest does not collect it. Run it by hand
before an integration run, especially after the lab has idled or been rebooted:

    uv run tests/integration/probe_lab_domains.py
    uv run tests/integration/probe_lab_domains.py --no-login     # machines only, no logins
    uv run tests/integration/probe_lab_domains.py --timeout 60 --gap 25

Why it logs in. `show-api-versions` sent without a session is answered by the
web API layer of whichever Multi-Domain Server machine owns the IP, not by the
domain: on 2026-09-28 every domain IP on one MDS member answered in the same 16.5 s
as the member itself, while one domain's logins were hanging for 120 s at a time. Only a
login reaches the domain's own management process, so that is what this does,
once per domain, followed by one `show-api-versions` inside the session.

What it does:

1. Logs in to the system domain, reads `show-mdss` and `show-domains`, logs out.
2. Sends `show-api-versions` without a session to every MDS machine and every
   domain server at once, and prints how long each took (the machine layer).
3. Unless --no-login: per domain, on the domain's active server, logs in, calls
   `show-api-versions`, logs out, and prints the time of each step. Logins on
   one machine are spaced by --gap seconds, because Check Point allows about
   three logins per minute per machine; a throttle refusal waits
   --throttle-wait seconds and retries, and that wait is reported separately so
   it is never mistaken for a slow domain.

Exits 1 if any domain failed to answer. Reads the same .env.test / .env.secrets
as the integration suite. Never prints the API key.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # run as a script: make `tests.integration` importable
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from arodonata.asdk.tls import VerifiedAPIClient, verified_api_client

READ_TIMEOUT = 120.0  # seconds per read; main() sets it from --timeout

THROTTLE_CODE = "err_too_many_requests"


@dataclass(frozen=True)
class Target:
    """One domain and where it lives right now."""

    domain: str
    ip: str  # the domain's active server; "" when show-domains lists none
    mds: str  # name of the MDS machine hosting that server; "?" if unknown
    mds_ip: str


@dataclass
class Result:
    target: Target
    ok: bool
    connect_s: float = 0.0  # TCP + TLS handshake + TLS identity check: the network and the machine's web layer
    login_s: float = 0.0  # the login request itself: the domain's own management process
    call_s: float = 0.0
    logout_s: float = 0.0
    throttle_wait_s: float = 0.0
    detail: str = ""


def targets_from(domains_data: dict[str, Any], mdss_data: dict[str, Any]) -> list[Target]:
    """Map `show-domains` (details-level full) and `show-mdss` to one Target per domain."""
    mds_ips = {
        m.get("name", ""): m.get("ipv4-address", "") for m in mdss_data.get("objects", []) if isinstance(m, dict)
    }
    targets = []
    for d in domains_data.get("objects", []):
        if not isinstance(d, dict) or not d.get("name"):
            continue
        active = next(
            (
                s
                for s in d.get("servers", [])
                if isinstance(s, dict) and s.get("active") is True and s.get("ipv4-address")
            ),
            None,
        )
        mds = (active or {}).get("multi-domain-server") or "?"
        targets.append(
            Target(domain=d["name"], ip=(active or {}).get("ipv4-address", ""), mds=mds, mds_ip=mds_ips.get(mds, ""))
        )
    return targets


def _load_env() -> None:
    """Same files, same order, same lab profile as the integration suite (lab_env.py)."""
    from tests.integration.lab_env import load_lab_env

    profile = load_lab_env()
    print(f"Lab profile: {profile or 'default (.env.test)'}")


def _error_detail(response: Any) -> tuple[str, str]:
    data = response.data if isinstance(response.data, dict) else {}
    code = str(data.get("code") or "")
    message = str(data.get("message") or getattr(response, "error_message", "") or "")
    return code, " | ".join(p for p in (code, message) if p) or "unknown"


def _close(client: VerifiedAPIClient, logout: bool) -> None:
    try:
        if logout and client.sid:
            client.api_call("logout", {}, client.sid)
    except Exception:  # noqa: BLE001 - best effort; a failed logout is not the measurement
        pass
    finally:
        try:
            client.close_connection()
        except Exception:  # noqa: BLE001
            pass


def _tcp(ip: str) -> str:
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=5):
            return f"tcp 443 ok in {time.monotonic() - t0:.2f}s"
    except Exception as exc:  # noqa: BLE001 - the failure is the datum
        return f"tcp 443 FAILED after {time.monotonic() - t0:.2f}s: {type(exc).__name__}"


def discover(server: str, api_key: str) -> list[Target]:
    print(f"Discovering domains via {server} (system-domain login):")
    client = verified_api_client(server, read_timeout=READ_TIMEOUT)
    t0 = time.monotonic()
    try:
        response = client.login_with_api_key(api_key)
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"  system login FAILED after {time.monotonic() - t0:.1f}s: {type(exc).__name__}: {exc}")
    if not response.success:
        sys.exit(f"  system login FAILED after {time.monotonic() - t0:.1f}s: {_error_detail(response)[1]}")
    print(f"  system login ok in {time.monotonic() - t0:.1f}s")
    try:
        domains = client.api_call("show-domains", {"details-level": "full", "limit": 200}, client.sid)
        mdss = client.api_call("show-mdss", {"details-level": "full", "limit": 50}, client.sid)
    finally:
        _close(client, logout=True)
    targets = targets_from(domains.data or {} if domains.success else {}, mdss.data or {} if mdss.success else {})
    print(f"  -> {len(targets)} domain(s)\n")
    return targets


def probe_machines(server: str, targets: list[Target]) -> None:
    """Session-less show-api-versions to every machine and domain server, in parallel."""
    hosts: dict[str, str] = {server: "management (API_MGMT)"}
    for t in targets:
        if t.mds_ip:
            hosts.setdefault(t.mds_ip, f"MDS {t.mds}")
    for t in targets:
        if t.ip:
            hosts.setdefault(t.ip, f"{t.domain} server (on {t.mds})")

    def one(ip: str) -> str:
        client = verified_api_client(ip, read_timeout=READ_TIMEOUT)
        t0 = time.monotonic()
        try:
            response = client.api_call("show-api-versions", {})
        except Exception as exc:  # noqa: BLE001
            return f"FAIL after {time.monotonic() - t0:5.1f}s: {type(exc).__name__}: {exc}"
        finally:
            _close(client, logout=False)
        elapsed = time.monotonic() - t0
        code, detail = _error_detail(response)
        # Refused for the missing session header = the API layer is up and answering.
        return f"up   {elapsed:5.1f}s" if response.success or code else f"FAIL {elapsed:5.1f}s: {detail}"

    print("Machine layer (show-api-versions without a session, in parallel):")
    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        verdicts = dict(zip(hosts, pool.map(one, hosts), strict=True))
    for ip, label in hosts.items():
        print(f"  {ip:15} {label:32} {verdicts[ip]}")
    print()


def _say(text: str) -> None:
    """Print without a newline, immediately: the line is finished by the step's outcome."""
    print(text, end="", flush=True)


@contextmanager
def _ticking(every: float = 10.0) -> Iterator[None]:
    """Print a dot every `every` seconds while a step runs, so a hang is visibly alive."""
    stop = threading.Event()

    def tick() -> None:
        while not stop.wait(every):
            _say(".")

    thread = threading.Thread(target=tick, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()


def _timed(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, float]:
    """Run `fn` with a heartbeat; return (result, seconds). Exceptions propagate."""
    t0 = time.monotonic()
    with _ticking():
        result = fn(*args, **kwargs)
    return result, time.monotonic() - t0


def _step(label: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, float]:
    """Announce `label`, run it with a heartbeat, print its duration; on failure print that and re-raise."""
    _say(f"{label} ...")
    t0 = time.monotonic()
    try:
        value, seconds = _timed(fn, *args, **kwargs)
    except Exception:
        _say(f" FAILED after {time.monotonic() - t0:.1f}s")
        raise
    _say(f" {seconds:.1f}s | ")
    return value, seconds


def wake_domain(target: Target, api_key: str, throttle_wait: int, throttle_retries: int) -> Result:
    """connect, login, show-api-versions, logout -- each announced as it starts and timed as it ends.

    Connect (TCP + TLS) is timed apart from the login request so a slow answer
    says where it is slow: a slow connect is the network or the machine; a fast
    connect followed by a slow login is the domain's management process.
    """
    result = Result(target, ok=False)
    if not target.ip:
        result.detail = "no active server in show-domains"
        print(f"FAIL: {result.detail}")
        return result

    for attempt in range(throttle_retries + 1):
        client = verified_api_client(target.ip, read_timeout=READ_TIMEOUT)
        login_started: float | None = None
        try:
            client.conn, result.connect_s = _step("connect+identity", client.create_https_connection)
            login_started = time.monotonic()
            response, result.login_s = _step(
                "login" if attempt == 0 else "retry login", client.login_with_api_key, api_key, domain=target.domain
            )
        except Exception as exc:  # noqa: BLE001 - a socket timeout is a result, not a crash
            if login_started is not None:  # the connect worked; the login is what failed
                result.login_s = time.monotonic() - login_started
            result.detail = f"{type(exc).__name__}: {exc} ({_tcp(target.ip)})"
            _close(client, logout=False)
            print(f"\n      {result.detail}")
            return result

        if not response.success:
            code, detail = _error_detail(response)
            _close(client, logout=False)
            if code == THROTTLE_CODE:
                _say(f"THROTTLED ({code}), waiting {throttle_wait}s ...")
                with _ticking():
                    time.sleep(throttle_wait)
                result.throttle_wait_s += throttle_wait
                _say(" | ")
                continue
            result.detail = f"login refused: {detail}"
            print(f"REFUSED: {detail}")
            return result

        try:
            call, result.call_s = _step("show-api-versions", client.api_call, "show-api-versions", {}, client.sid)
            result.ok = bool(call.success)
            result.detail = "" if call.success else f"show-api-versions: {_error_detail(call)[1]}"
            _, result.logout_s = _step("logout", client.api_call, "logout", {}, client.sid)
        except Exception as exc:  # noqa: BLE001
            result.detail = result.detail or f"{type(exc).__name__}: {exc}"
        finally:
            _close(client, logout=False)
        print("ok" if result.ok else f"FAILED: {result.detail}")
        return result

    result.detail = f"still throttled after {throttle_retries} retries"
    print(f"FAILED: {result.detail}")
    return result


def summary_table(results: list[Result]) -> str:
    """Final per-domain table: where each domain's time went."""
    head = f"  {'domain':12} {'server':15} {'mds':8} {'connect+id':>11} {'login':>8} {'call':>6} {'logout':>7} {'throttled':>9}  result"
    rows = [head, "  " + "-" * (len(head) - 2)]
    for r in results:
        t = r.target
        rows.append(
            f"  {t.domain:12} {t.ip or '-':15} {t.mds:8} {r.connect_s:10.1f}s {r.login_s:7.1f}s {r.call_s:5.1f}s "
            f"{r.logout_s:6.1f}s {r.throttle_wait_s:8.0f}s  {'ok' if r.ok else 'FAIL: ' + r.detail}"
        )
    return "\n".join(rows)


def wake_all(targets: list[Target], api_key: str, gap: int, throttle_wait: int, throttle_retries: int) -> list[Result]:
    print(f"Domains (login + show-api-versions + logout, {gap}s between logins on one machine):")
    started = time.monotonic()
    last_login_on: dict[str, float] = {}
    results = []
    for t in sorted(targets, key=lambda t: (t.mds, t.domain)):
        since = time.monotonic() - last_login_on.get(t.mds, -1e9)
        if since < gap:
            pause = gap - since
            print(f"  (pacing: {pause:.0f}s before the next login on {t.mds})", flush=True)
            time.sleep(pause)
        last_login_on[t.mds] = time.monotonic()
        _say(f"  [{time.monotonic() - started:6.1f}s] {t.domain:12} {t.ip or '-':15} {t.mds:8} ")
        results.append(wake_domain(t, api_key, throttle_wait, throttle_retries))
    return results


def main() -> None:
    _load_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=os.getenv("API_MGMT"), help="management IP (default: $API_MGMT)")
    parser.add_argument("--api-key-env", default="APIKEY", help="env var holding the API key (default: APIKEY)")
    parser.add_argument("--timeout", type=int, default=120, help="socket timeout per request, seconds (default: 120)")
    parser.add_argument("--gap", type=int, default=20, help="seconds between logins on one machine (default: 20)")
    parser.add_argument("--throttle-wait", type=int, default=70, help="wait after a throttle refusal (default: 70)")
    parser.add_argument("--throttle-retries", type=int, default=3, help="retries after throttling (default: 3)")
    parser.add_argument("--no-login", action="store_true", help="machine layer only: no per-domain logins")
    args = parser.parse_args()

    api_key = os.getenv(args.api_key_env)
    if not args.server or not api_key:
        sys.exit(f"Need --server (or $API_MGMT) and ${args.api_key_env}")

    # Bounds every read: without it a hung login blocks forever.
    global READ_TIMEOUT
    READ_TIMEOUT = float(args.timeout)
    print(f"Server: {args.server}   socket timeout: {args.timeout}s\n")

    targets = discover(args.server, api_key)
    probe_machines(args.server, targets)
    if args.no_login:
        return

    results = wake_all(targets, api_key, args.gap, args.throttle_wait, args.throttle_retries)
    failed = [r for r in results if not r.ok]
    print("\n" + "=" * 72)
    print(f"{len(results) - len(failed)}/{len(results)} domains answered\n")
    print(summary_table(results))
    print("  connect+id = TCP + TLS handshake + the certificate identity check (trust-store lookup, first-use probe).")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
