"""Standalone and embeddable Check Point Management HTTPS mock server (`mock_server.py`).

Allows downstream applications (MMP, FPCR, or custom scripts) to point `ArodonataClient` at
`localhost:443` (or any custom `host:port`) and interact with the full 10-domain, 276-gateway,
2,600-object, 1,000-rule enterprise dataset over real HTTPS without hardware appliances,
artificial rate limits, or login throttling delays.

CLI usage:
    python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import json
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from aiohttp import web

from arodonata.adapters.checkpoint.tls import compute_der_fingerprint
from arodonata.testing.dataset_generator import DEFAULT_DATASET_DIR, ensure_enterprise_raw_dataset
from arodonata.testing.replay_mock import FileReplayApiMock


def _generate_self_signed_cert(cert_dir: Path, host: str = "127.0.0.1") -> tuple[Path, Path, str]:
    """Generate a temporary self-signed RSA-2048 TLS certificate and return `(cert_path, key_path, sha256_fp)`."""
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    der_path = cert_dir / "server.der"

    san = (
        f"DNS:localhost,IP:127.0.0.1,IP:{host}"
        if host not in ("localhost", "127.0.0.1", "0.0.0.0")
        else "DNS:localhost,IP:127.0.0.1"
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "365",
            "-subj",
            "/CN=checkpoint-replay-mock.local",
            "-addext",
            f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(cert_path),
            "-outform",
            "DER",
            "-out",
            str(der_path),
        ],
        check=True,
        capture_output=True,
    )
    fp = compute_der_fingerprint(der_path.read_bytes())
    return cert_path, key_path, fp


def _rewrite_server_ips(data: dict[str, Any], target_host: str) -> dict[str, Any]:
    """Rewrite CMA and MDS `ipv4-address` fields in `show-domains` / `show-global-domain` / `show-mdss` to `target_host`."""
    rewritten = copy.deepcopy(data)

    def _patch_domain_dict(dom_obj: dict[str, Any]) -> None:
        servers = dom_obj.get("servers")
        if isinstance(servers, list):
            for srv in servers:
                if isinstance(srv, dict):
                    if "ipv4-address" in srv:
                        srv["original-ipv4-address"] = srv["ipv4-address"]
                        srv["ipv4-address"] = target_host
                    mds_sub = srv.get("multi-domain-server")
                    if isinstance(mds_sub, dict) and "ipv4-address" in mds_sub:
                        mds_sub["original-ipv4-address"] = mds_sub["ipv4-address"]
                        mds_sub["ipv4-address"] = target_host

    if isinstance(rewritten.get("objects"), list):
        for item in rewritten["objects"]:
            if isinstance(item, dict):
                if "ipv4-address" in item and item.get("type") == "mds":
                    item["original-ipv4-address"] = item["ipv4-address"]
                    item["ipv4-address"] = target_host
                _patch_domain_dict(item)
    else:
        _patch_domain_dict(rewritten)

    return rewritten


class CheckPointReplayHttpServer:
    """Embeddable `aiohttp.web` HTTPS server exposing Check Point `/web_api/<command>` backed by `FileReplayApiMock`."""

    def __init__(
        self,
        *,
        dataset_dir: Path | str = DEFAULT_DATASET_DIR,
        api_mock: FileReplayApiMock | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        advertise_host: str | None = None,
        rewrite_domain_ips: bool = True,
        cert_path: Path | str | None = None,
        key_path: Path | str | None = None,
    ) -> None:
        self._dataset_dir = ensure_enterprise_raw_dataset(dataset_dir)
        self._api_mock = api_mock or FileReplayApiMock(self._dataset_dir)
        self._host = host
        self._requested_port = port
        self._bound_port: int = port
        self._advertise_host = advertise_host
        self._rewrite_domain_ips = rewrite_domain_ips
        self._cert_path = Path(cert_path) if cert_path else None
        self._key_path = Path(key_path) if key_path else None
        self._temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self._fingerprint: str = ""
        self._sid_to_domain: dict[str, str] = {}

        self._app = web.Application()
        self._app.router.add_post("/web_api/{command}", self._handle_web_api)
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    @property
    def api_mock(self) -> FileReplayApiMock:
        """Underlying `FileReplayApiMock` instance."""
        return self._api_mock

    @property
    def host(self) -> str:
        """Bound host address."""
        return self._host

    @property
    def port(self) -> int:
        """Bound TCP port (resolved after `start()` when initialized with `port=0`)."""
        return self._bound_port

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint (`SHA256:...` or hex) of the server's TLS certificate."""
        return self._fingerprint

    @property
    def base_url(self) -> str:
        """HTTPS base URL (`https://<host>:<port>/web_api`)."""
        connect_host = "127.0.0.1" if self._host == "0.0.0.0" else self._host
        return f"https://{connect_host}:{self._bound_port}/web_api"

    async def _handle_web_api(self, request: web.Request) -> web.Response:
        command = request.match_info.get("command", "").strip()
        try:
            raw_text = await request.text()
            payload: dict[str, Any] = json.loads(raw_text) if raw_text.strip() else {}
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}

        sid = request.headers.get("X-chkp-sid", "").strip() or None
        explicit_domain = payload.get("domain")
        if command == "login":
            has_key = bool(str(payload.get("api-key") or "").strip())
            has_user_pass = bool(str(payload.get("user") or "").strip() and str(payload.get("password") or "").strip())
            if not (has_key or has_user_pass):
                return web.json_response(
                    {
                        "code": "generic_err_invalid_credentials",
                        "message": "Authentication credentials (api-key or user/password) are required",
                    },
                    status=401,
                )
            resolved_domain = str(explicit_domain) if explicit_domain else "System Data"
        else:
            if not sid or sid not in self._sid_to_domain:
                return web.json_response(
                    {
                        "code": "generic_err_wrong_session_id",
                        "message": "Session ID is missing or invalid",
                    },
                    status=401,
                )
            resolved_domain = self._sid_to_domain[sid]

        res = await self._api_mock.api_call(
            "mds",
            command,
            payload,
            domain=resolved_domain,
            sid=sid,
            wait_for_task=False,
        )

        if command == "login" and res.success and isinstance(res.data, dict):
            new_sid = str(res.data.get("sid") or "")
            if new_sid:
                self._sid_to_domain[new_sid] = self._api_mock._normalize_domain(resolved_domain)
        elif command == "logout" and sid:
            self._sid_to_domain.pop(sid, None)

        resp_data = res.data
        if (
            res.success
            and self._rewrite_domain_ips
            and command in ("show-domains", "show-domain", "show-global-domain", "show-mdss")
            and isinstance(resp_data, dict)
        ):
            adv_host = (
                self._advertise_host or request.url.host or ("127.0.0.1" if self._host == "0.0.0.0" else self._host)
            )
            resp_data = _rewrite_server_ips(resp_data, adv_host)

        return web.json_response(resp_data, status=res.status_code or (200 if res.success else 400))

    async def start(self) -> None:
        """Start the HTTPS server on `(self.host, self.port)`."""
        if self._cert_path is None or self._key_path is None:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="arodonata_mock_tls_")
            cert_p, key_p, fp = _generate_self_signed_cert(Path(self._temp_dir.name), host=self._host)
            self._cert_path = cert_p
            self._key_path = key_p
            self._fingerprint = fp
        else:
            der_bytes = ssl.PEM_cert_to_DER_cert(self._cert_path.read_text(encoding="utf-8"))
            self._fingerprint = compute_der_fingerprint(der_bytes)

        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=str(self._cert_path), keyfile=str(self._key_path))

        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host=self._host, port=self._requested_port, ssl_context=ssl_ctx)
        await self._site.start()

        # Extract actual bound port when requested_port == 0
        sockets = getattr(self._site._server, "sockets", None) if self._site._server is not None else None
        if sockets:
            sockname = sockets[0].getsockname()
            if isinstance(sockname, tuple) and len(sockname) >= 2:
                self._bound_port = int(sockname[1])

    async def stop(self) -> None:
        """Stop the HTTPS server and clean up any temporary TLS certificate directory."""
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None

    async def __aenter__(self) -> CheckPointReplayHttpServer:
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.stop()


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser for `python -m arodonata.testing.mock_server`."""
    parser = argparse.ArgumentParser(
        prog="python -m arodonata.testing.mock_server",
        description=(
            "Run the standalone Check Point Management HTTPS replay mock server "
            "serving the 10-domain enterprise raw dataset for MMP, FPCR, or integration testing."
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address for the HTTPS server (default: 127.0.0.1; use 0.0.0.0 for all interfaces).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="TCP port for the HTTPS server (default: 8443; use 443 with root privileges or port forwarding).",
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=DEFAULT_DATASET_DIR,
        help="Path to the enterprise raw dataset directory (auto-generated if missing).",
    )
    parser.add_argument(
        "--advertise-host",
        default=None,
        help="Optional IP/hostname written into show-domains server entries (defaults to request host).",
    )
    parser.add_argument(
        "--cert",
        type=Path,
        default=None,
        help="Optional path to a PEM TLS certificate file (auto-generated if omitted).",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=None,
        help="Optional path to a PEM TLS private key file (auto-generated if omitted).",
    )
    return parser


async def _run_cli_server(args: argparse.Namespace) -> None:
    server = CheckPointReplayHttpServer(
        dataset_dir=args.dataset_dir,
        host=args.host,
        port=args.port,
        advertise_host=args.advertise_host,
        cert_path=args.cert,
        key_path=args.key,
    )
    await server.start()
    manifest = server.api_mock.manifest
    counts = manifest.get("counts", {})
    print(f"Check Point Replay HTTPS Mock Server listening on {server.base_url}")
    print(f"TLS Certificate SHA-256 Fingerprint: {server.fingerprint}")
    print(
        f"Dataset loaded: {counts.get('total_domains', 0)} domains, "
        f"{counts.get('policy_enforcing_gateways', 0)} policy gateways ({counts.get('total_assets', 0)} total assets), "
        f"{counts.get('total_network_objects', 0)} network objects, {counts.get('total_access_rules', 0)} access rules."
    )
    print("Press Ctrl+C to stop.")
    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        await server.stop()


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m arodonata.testing.mock_server`."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run_cli_server(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
