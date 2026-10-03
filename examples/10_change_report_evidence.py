"""Change report evidence for one policy change: pending (numbered live through the app's own SID), provisional, published.

Lab only, DOMAIN only. A setup session creates and publishes hosts, a group and access rules in two sections and an
inline layer. The change session — the one the evidence is about — then adds, modifies, moves, disables and deletes
rules and objects, so the report shows every status: NEW, changed cells with added/removed items, "(was N)" for a
moved rule, ✗ for a disabled one, DELETED, section rows, the details tables and a warning. The guard reverts the domain
to its last published session afterwards. Writes examples/_tmp/evidence-{1-pending,2-provisional,3-published}.html/.json.
HTML needs the report extra:

    uv sync --extra report
    ARODONATA_LAB=home uv run examples/10_change_report_evidence.py

Environment (as the integration suite): .env.test, .env.secrets, then .env.lab.<ARODONATA_LAB> (API_MGMT, APIKEY).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402
from arodonata.reports.changes import ChangeReportResult, OwnedSession, RenderOptions, SessionScope  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
for env_file in (".env.test", ".env.secrets"):
    if (ROOT / env_file).exists():
        load_dotenv(ROOT / env_file, override=True)
if os.environ.get("ARODONATA_LAB"):
    load_dotenv(ROOT / f".env.lab.{os.environ['ARODONATA_LAB']}", override=True)
logging.basicConfig(level=logging.WARNING)

DOMAIN = "Domain5"
LAB_DOMAINS = {"Domain4", "Domain5"}  # never run this against anything else
LAYER = "FPCR_UAT_Active Network"  # Domain5 baseline: Section_4 (rule, inline jump), Section_3, Section_2, ...
SECTION = "FPCR_UAT_Section_3"  # the setup rules go to the top of this section
MOVE_TO = "FPCR_UAT_Section_2"  # the change moves one of them to the top of this one
PREFIX = "pytest-example-cr-"
OUT = Path(__file__).parent / "_tmp"
OPTIONS = RenderOptions(
    title="Evidence: **RITM-EXAMPLE** — *Firewall change*",
    header_fields={"RITM": "RITM-EXAMPLE", "Requester": "jdoe"},
    generated_by="examples/10_change_report_evidence.py",
)

Call = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]


def n(name: str) -> str:
    return PREFIX + name


def write(result: ChangeReportResult, name: str) -> None:
    OUT.mkdir(exist_ok=True)
    if result.html:
        (OUT / f"{name}.html").write_bytes(result.html)
    if result.json:
        (OUT / f"{name}.json").write_bytes(result.json)
    for mgmt in result.report.servers:
        for domain in mgmt.domains:
            for session in domain.sessions:
                print(
                    f"{name}: {session.name} ({'published' if session.published else 'pending'}), numbering "
                    f"{session.numbering.source}{' provisional' if session.numbering.provisional else ''}, "
                    f"{len(session.rules)} rules, {len(session.objects)} objects"
                )
    for warning in result.report.warnings:
        print(f"  warning {warning.code}")
    print(f"  -> {OUT / name}.html")


@asynccontextmanager
async def dedicated(client: ArodonataClient, mgmt: str, name: str) -> AsyncIterator[tuple[Call, str, str, str]]:
    """A dedicated session in DOMAIN: (call, session uid, sid, server ip); logged out on exit."""
    sid, server_ip = await client.create_dedicated_session(mgmt, DOMAIN, session_name=name)
    try:

        async def call(command: str, payload: dict[str, Any]) -> dict[str, Any]:
            result = await client.api_call_with_sid(mgmt, sid, server_ip, command, payload=payload, domain=DOMAIN)
            if not result.success:
                raise RuntimeError(f"{command} failed: {result.code}")
            return result.data or {}

        yield call, (await call("show-session", {}))["uid"], sid, server_ip
    finally:
        await client.logout_sid(sid, server_ip, mgmt)


async def inline_layer(call: Call) -> str | None:
    layer = await call("show-access-rulebase", {"name": LAYER, "details-level": "standard", "limit": 500})
    return next(
        (
            str(r["inline-layer"])
            for item in layer.get("rulebase", [])
            for r in item.get("rulebase", [item])
            if r.get("inline-layer")
        ),
        None,
    )


async def setup(call: Call) -> str | None:
    """Published baseline the change works on; returns the inline layer uid (None if the layer has none)."""
    hosts = {"web-1": 11, "web-2": 12, "web-3": 13, "lb-1": 21, "lb-2": 22, "admin-1": 30, "old-1": 40}
    for host, octet in hosts.items():
        await call("add-host", {"name": n(host), "ip-address": f"198.51.100.{octet}"})
    await call("add-group", {"name": n("web"), "members": [n("web-1"), n("web-2")]})
    rule = {"layer": LAYER, "action": "Accept", "track": {"type": "Log"}}
    await call(
        "add-access-rule",
        {
            **rule,
            "position": {"top": SECTION},
            "name": n("allow-web"),
            "source": [n("lb-1"), n("lb-2")],
            "destination": n("web"),
            "service": "https",
        },
    )
    below = n("allow-web")
    for name, source, destination, service in (
        ("allow-admin", "admin-1", "web", "ssh"),
        ("allow-legacy", "old-1", "web-3", "http"),
        ("allow-monitor", "admin-1", "web-3", "echo-request"),
    ):
        await call(
            "add-access-rule",
            {
                **rule,
                "position": {"below": below},
                "name": n(name),
                "source": n(source),
                "destination": n(destination),
                "service": service,
            },
        )
        below = n(name)
    inline = await inline_layer(call)
    if inline:
        await call(
            "add-access-rule",
            {**rule, "layer": inline, "position": "top", "name": n("inline"), "source": n("web-1")},
        )
    await call("publish", {})
    return inline


async def change(call: Call, inline: str | None) -> None:
    """The change the evidence documents: every rule and object status once."""
    await call("add-host", {"name": n("lb-3"), "ip-address": "198.51.100.23"})  # added object
    await call("set-host", {"name": n("web-1"), "comments": "DMZ web front"})  # modified object
    # The API refuses add and remove in one field (generic_err_invalid_syntax): one call each.
    await call("set-group", {"name": n("web"), "members": {"add": n("web-3")}})  # members delta
    await call("set-group", {"name": n("web"), "members": {"remove": n("web-2")}})
    rule = {"layer": LAYER, "name": n("allow-web")}  # modified rule: an item added and one removed, track changed
    await call("set-access-rule", {**rule, "source": {"add": n("lb-3")}, "track": {"type": "None"}})
    await call("set-access-rule", {**rule, "source": {"remove": n("lb-2")}})
    await call(  # new rule between two existing ones
        "add-access-rule",
        {
            "layer": LAYER,
            "position": {"below": n("allow-web")},
            "name": n("allow-api"),
            "source": n("lb-3"),
            "destination": n("web"),
            "service": "https",
            "action": "Accept",
            "track": {"type": "Log"},
        },
    )
    await call("set-access-rule", {"layer": LAYER, "name": n("allow-admin"), "enabled": False})  # disabled
    await call(  # moved to another section: "(was N)"
        "set-access-rule", {"layer": LAYER, "name": n("allow-monitor"), "new-position": {"top": MOVE_TO}}
    )
    await call("delete-access-rule", {"layer": LAYER, "name": n("allow-legacy")})  # deleted rule
    await call("delete-host", {"name": n("old-1")})  # deleted object (only the deleted rule used it)
    if inline:
        await call("set-access-rule", {"layer": inline, "name": n("inline"), "action": "Drop"})  # inline layer number


async def main() -> None:
    if DOMAIN not in LAB_DOMAINS:
        raise SystemExit(f"{DOMAIN} is not a lab domain")
    ip = os.environ["API_MGMT"]
    settings = ArodonataSettings(mgmt_names=ip, mgmt_servers=ip, api_keys=os.environ["APIKEY"])
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with ArodonataClient(engine=engine, settings=settings) as client:
            mgmt = client.get_mgmt_names()[0]
            async with guarded_session(client, mgmt, domains=[DOMAIN]):
                async with dedicated(client, mgmt, n("setup")) as (call, _, _, _):
                    inline = await setup(call)
                async with dedicated(client, mgmt, n("change")) as (call, uid, sid, server_ip):
                    await change(call, inline)
                    owned = OwnedSession(sid=SecretStr(sid), server_ip=server_ip)
                    scope = SessionScope(domain=DOMAIN, session_uids=[uid], owned_session=owned)
                    write(await client.build_change_report([scope], ["html", "json"], OPTIONS), "evidence-1-pending")
                    # Without the owning SID the pending rules can only be numbered provisionally (with a warning).
                    scope = SessionScope(domain=DOMAIN, session_uids=[uid])
                    write(
                        await client.build_change_report([scope], ["html", "json"], OPTIONS), "evidence-2-provisional"
                    )
                    await call("publish", {})
                    # Correct within the smart TTL too: collect invalidates the domain first, and the snapshot is this
                    # session's own, so no forced re-locate and no warning.
                    write(await client.build_change_report([scope], ["html", "json"], OPTIONS), "evidence-3-published")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
