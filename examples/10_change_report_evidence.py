"""Change report evidence for one policy session: pending (numbered live through the app's own SID), then published.

Lab only. Creates hosts, a group and access rules (one in an inline layer) in DOMAIN inside a guarded session —
the guard reverts the domain to its last published session afterwards — and writes four files:
examples/_tmp/evidence-1-pending.html/.json and evidence-2-published.html/.json. HTML needs the report extra:

    uv sync --extra report
    ARODONATA_LAB=home uv run examples/10_change_report_evidence.py

Environment (as the integration suite): .env.test, .env.secrets, then .env.lab.<ARODONATA_LAB> (API_MGMT, APIKEY).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
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
LAYER = "FPCR_UAT_Active Network"
PREFIX = "pytest-example-cr-"
OUT = Path(__file__).parent / "_tmp"
OPTIONS = RenderOptions(
    title="Change evidence **RITM-EXAMPLE**",
    header_fields={"RITM": "RITM-EXAMPLE"},
    generated_by="examples/10_change_report_evidence.py",
)


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
                    f"{session.numbering.source}{' provisional' if session.numbering.provisional else ''}"
                )
    print(f"  -> {OUT / name}.html")


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
                sid, server_ip = await client.create_dedicated_session(mgmt, DOMAIN, session_name=PREFIX + "session")
                try:

                    async def call(command: str, payload: dict[str, Any]) -> dict[str, Any]:
                        result = await client.api_call_with_sid(mgmt, sid, server_ip, command, payload=payload)
                        if not result.success:
                            raise RuntimeError(f"{command} failed: {result.code}")
                        return result.data or {}

                    uid = (await call("show-session", {}))["uid"]
                    for n in (1, 2, 3):
                        await call("add-host", {"name": f"{PREFIX}web-{n}", "ip-address": f"198.51.100.{10 + n}"})
                    await call("add-group", {"name": PREFIX + "web", "members": [PREFIX + "web-1", PREFIX + "web-2"]})
                    rules = [PREFIX + "allow-web", PREFIX + "allow-admin"]
                    await call(
                        "add-access-rule",
                        {
                            "layer": LAYER,
                            "position": "top",
                            "name": rules[0],
                            "destination": PREFIX + "web",
                            "service": "https",
                            "action": "Accept",
                        },
                    )
                    await call(
                        "add-access-rule",
                        {
                            "layer": LAYER,
                            "position": {"below": rules[0]},
                            "name": rules[1],
                            "source": PREFIX + "web-3",
                            "action": "Accept",
                        },
                    )
                    layer = await call(
                        "show-access-rulebase", {"name": LAYER, "details-level": "standard", "limit": 500}
                    )
                    inline = next(
                        (
                            str(r["inline-layer"])
                            for item in layer.get("rulebase", [])
                            for r in item.get("rulebase", [item])
                            if r.get("inline-layer")
                        ),
                        None,
                    )
                    if inline:
                        await call(
                            "add-access-rule",
                            {
                                "layer": inline,
                                "position": "top",
                                "name": PREFIX + "inline",
                                "source": PREFIX + "web-1",
                                "action": "Accept",
                            },
                        )
                        rules.append(PREFIX + "inline")
                    owned = OwnedSession(sid=SecretStr(sid), server_ip=server_ip)
                    pending = await client.build_change_report(
                        [SessionScope(domain=DOMAIN, session_uids=[uid], owned_session=owned)],
                        ["html", "json"],
                        OPTIONS,
                    )
                    write(pending, "evidence-1-pending")
                    for name in rules:
                        await call(
                            "set-access-rule",
                            {"layer": inline if name.endswith("inline") else LAYER, "name": name, "enabled": False},
                        )
                    await call("publish", {})
                    # Correct within the smart TTL too: collect invalidates the domain first, and the snapshot is this
                    # session's own, so no forced re-locate and no warning.
                    published = await client.build_change_report(
                        [SessionScope(domain=DOMAIN, session_uids=[uid])], ["html", "json"], OPTIONS
                    )
                    write(published, "evidence-2-published")
                finally:
                    await client.logout_sid(sid, server_ip, mgmt)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
