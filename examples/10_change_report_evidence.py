"""Example 10 — Auditable change report evidence (`OwnedSession` pending vs published HTML/Markdown/JSON).

Run:
    ARODONATA_LAB=home uv run examples/10_change_report_evidence.py

Demonstrates:
1. Creating a baseline setup session and a change session in a lab domain (`Domain5` by default).
2. Collecting and rendering a `ChangeReport` while the session is still unpublished using
   `OwnedSession(sid=..., server_ip=...)` (`numbering_source == "owned_session"`).
3. Publishing the session and rendering the final auditable bundle (`html`, `markdown`, `json`)
   to `examples/_tmp/`.
4. Reverting the domain to its original baseline via `_session_guard.guarded_session`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(".env.test", override=True)
load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)
logging.basicConfig(level=logging.WARNING)

sys.path.insert(0, str(Path(__file__).parent))
from _session_guard import guarded_session  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402
from arodonata.reports import (  # noqa: E402
    OwnedSession,
    RenderedReportBundle,
    RenderOptions,
    SessionScope,
)

OUT_DIR = Path(__file__).parent / "_tmp"


def _write_bundle(bundle: RenderedReportBundle, prefix: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if bundle.html is not None:
        (OUT_DIR / f"{prefix}.html").write_bytes(bundle.html)
    if bundle.markdown is not None:
        (OUT_DIR / f"{prefix}.md").write_text(bundle.markdown, encoding="utf-8")
    if bundle.json_text is not None:
        (OUT_DIR / f"{prefix}.json").write_text(bundle.json_text, encoding="utf-8")

    for sess in bundle.report.sessions:
        print(
            f"{prefix}: session={sess.session_name!r} state={sess.state} "
            f"numbering_source={sess.numbering_source} "
            f"rules={len(sess.rule_changes)} objects={len(sess.object_changes)}"
        )
    print(f"  -> wrote {OUT_DIR / prefix}.{{html,md,json}}")


async def main() -> None:
    """Create a sample firewall change, generate pending and published evidence reports, and revert."""
    settings = ArodonataSettings()
    mgmt_name = settings.mgmt_names[0]
    domain = os.getenv("TEST_DOMAIN_B", "Domain5")
    tag = uuid.uuid4().hex[:6]
    options = RenderOptions(
        title="Evidence: **RITM-EXAMPLE** — *Firewall Policy Change*",
        header_fields={"RITM": "RITM-EXAMPLE", "Requester": "secops"},
    )

    print(f"[Step 1/5] Capturing baseline revision on {mgmt_name}:{domain}...", flush=True)
    async with ArodonataClient(settings=settings) as client, guarded_session(client, mgmt_name, domains=[domain]):
        print(f"[Step 2/5] Refreshing rulebase cache for {mgmt_name}:{domain}...", flush=True)
        await client.refresh_rulebases(mgmt_name=mgmt_name, domains=[domain], mode="force")
        packages = await client.get_policy_packages(mgmt_name, domain, cache_mode="cache")
        if not packages or not packages[0].access_layers:
            print(f"No policy package/access layer found in {domain}.")
            return
        layer_name = next(
            (lay.layer_name for lay in packages[0].access_layers if lay.layer_name != "Global"),
            packages[0].access_layers[0].layer_name,
        )

        print(
            f"[Step 3/5] Opening dedicated session on {mgmt_name}:{domain} and staging host + rule in {layer_name!r}...",
            flush=True,
        )
        sid, server_ip = await client.create_dedicated_session(
            mgmt_name,
            domain,
            session_name=f"ritm-example-{tag}",
            session_description="Change report evidence example",
        )
        try:
            s_info = await client.api_call(
                mgmt_name,
                "show-session",
                {},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )
            session_uid = str(s_info.data["uid"])

            host_name = f"cr-web-{tag}"
            rule_name = f"cr-allow-web-{tag}"
            await client.api_call(
                mgmt_name,
                "add-host",
                {"name": host_name, "ipv4-address": "198.51.100.245", "comments": "DMZ web server"},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )
            await client.api_call(
                mgmt_name,
                "add-access-rule",
                {
                    "layer": layer_name,
                    "position": "top",
                    "name": rule_name,
                    "source": "Any",
                    "destination": host_name,
                    "service": "https",
                    "action": "Accept",
                },
                domain=domain,
                sid=sid,
                server_ip=server_ip,
            )

            # 1. Pending session evidence numbered live via OwnedSession
            print("[Step 4/5] Building pending change report via OwnedSession...", flush=True)
            owned = OwnedSession(
                sid=sid,
                server_ip=server_ip,
                session_uid=session_uid,
                mgmt_name=mgmt_name,
                domain=domain,
            )
            pending_scope = SessionScope(
                mgmt_name=mgmt_name,
                domain=domain,
                session_uids=[session_uid],
                owned_sessions=owned,
            )
            pending_bundle = await client.build_change_report(
                [pending_scope],
                formats=("html", "markdown", "json"),
                options=options,
            )
            _write_bundle(pending_bundle, "evidence-1-pending")

            # 2. Publish the session and refresh rulebase cache
            print("[Step 5/5] Publishing session and building published change report...", flush=True)
            await client.api_call(
                mgmt_name,
                "publish",
                {},
                domain=domain,
                sid=sid,
                server_ip=server_ip,
                wait_for_task=True,
            )
        finally:
            await client.logout_sid(mgmt_name, sid, server_ip=server_ip)

        await client.refresh_rulebases(mgmt_name=mgmt_name, domains=[domain], mode="force")
        pub_scope = SessionScope(
            mgmt_name=mgmt_name,
            domain=domain,
            session_uids=[session_uid],
        )
        pub_bundle = await client.build_change_report(
            [pub_scope],
            formats=("html", "markdown", "json"),
            options=options,
        )
        _write_bundle(pub_bundle, "evidence-2-published")
        print(f"Reverting {mgmt_name}:{domain} to baseline revision...", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
