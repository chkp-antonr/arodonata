"""Standalone and embeddable Check Point Management HTTPS mock server (`mock_server.py`).

Allows downstream applications (MMP, FPCR, or custom scripts) to point `ArodonataClient` at
`localhost:443` (or any custom `host:port`) and interact with the full 10-domain, 315-gateway,
2,950+-object, 1,050+-rule enterprise dataset over real HTTPS without hardware appliances,
artificial rate limits, or login throttling delays.

CLI usage:
    python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import copy
import datetime
import hmac
import ipaddress
import json
import secrets
import shutil
import ssl
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from aiohttp import web
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False

from arodonata.adapters.checkpoint.tls import compute_der_fingerprint
from arodonata.core.errors import ValidationError
from arodonata.core.telemetry import span_attrs, traced
from arodonata.testing.dataset_generator import DEFAULT_DATASET_DIR, ensure_enterprise_raw_dataset
from arodonata.testing.replay_mock import FileReplayApiMock, ReplayStateSnapshot


def _generate_self_signed_cert(cert_dir: Path, host: str = "127.0.0.1") -> tuple[Path, Path, str]:
    """Generate a temporary self-signed RSA-2048 TLS certificate and return `(cert_path, key_path, sha256_fp)`."""
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    der_path = cert_dir / "server.der"

    if shutil.which("openssl") is not None:
        san = (
            f"DNS:localhost,IP:127.0.0.1,IP:{host}"
            if host not in ("localhost", "127.0.0.1", "0.0.0.0")
            else "DNS:localhost,IP:127.0.0.1"
        )
        try:
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
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            pass

    if not _HAVE_CRYPTOGRAPHY:
        raise RuntimeError(
            "Neither 'openssl' CLI nor 'cryptography' library is available to generate self-signed TLS certificate."
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "checkpoint-replay-mock.local"),
        ]
    )
    san_names: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
    if host not in ("localhost", "127.0.0.1", "0.0.0.0"):
        try:
            san_names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san_names.append(x509.DNSName(host))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    der_path.write_bytes(der_bytes)
    fp = compute_der_fingerprint(der_bytes)
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
        enable_test_control: bool = False,
        test_control_token: str | None = None,
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
        self._enable_test_control = enable_test_control
        self._test_control_token: str = (
            test_control_token.strip()
            if isinstance(test_control_token, str) and test_control_token.strip()
            else secrets.token_urlsafe(24)
        )
        self._temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self._fingerprint: str = ""
        self._named_snapshots: dict[str, ReplayStateSnapshot] = {}

        self._app = web.Application()
        self._app.router.add_post("/web_api/{command}", self._handle_web_api)
        if self._enable_test_control:
            self._app.router.add_post("/__testing__/reset", self._handle_testing_reset)
            self._app.router.add_post("/__testing__/snapshot", self._handle_testing_snapshot)
            self._app.router.add_post("/__testing__/restore", self._handle_testing_restore)
            self._app.router.add_get("/__testing__/call-log", self._handle_testing_call_log)
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    @property
    def api_mock(self) -> FileReplayApiMock:
        """Underlying `FileReplayApiMock` instance."""
        return self._api_mock

    def snapshot_state(self) -> ReplayStateSnapshot:
        """Capture an in-memory snapshot of underlying emulator state."""
        return self._api_mock.snapshot_state()

    def restore_state(self, snapshot: ReplayStateSnapshot) -> None:
        """Restore underlying emulator state from `snapshot`."""
        self._api_mock.restore_state(snapshot)

    def reset(self) -> None:
        """Reset underlying emulator state back to dataset baseline."""
        self._api_mock.reset()

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

    @property
    def test_control_token(self) -> str:
        """Shared secret token accepted via `X-Arodonata-Test-Token` on `/__testing__/*` endpoints."""
        return self._test_control_token

    async def _read_json_dict(self, request: web.Request) -> dict[str, Any]:
        try:
            raw_text = await request.text()
            payload: Any = json.loads(raw_text) if raw_text.strip() else {}
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _authorize_testing_request(self, request: web.Request) -> web.Response | None:
        token = request.headers.get("X-Arodonata-Test-Token", "").strip()
        if token:
            if hmac.compare_digest(token, self._test_control_token):
                return None
            return web.json_response(
                {
                    "code": "generic_err_invalid_credentials",
                    "message": "Invalid X-Arodonata-Test-Token header",
                },
                status=401,
            )
        sid = request.headers.get("X-chkp-sid", "").strip()
        if sid:
            if self._api_mock.get_active_sid_binding(sid) is not None:
                return None
            return web.json_response(
                {
                    "code": "generic_err_invalid_session_id",
                    "message": "Session ID is invalid or expired",
                },
                status=401,
            )
        return web.json_response(
            {
                "code": "generic_err_missing_required_header",
                "message": "X-Arodonata-Test-Token or active X-chkp-sid header is required",
            },
            status=401,
        )

    async def _handle_testing_reset(self, request: web.Request) -> web.Response:
        auth_err = self._authorize_testing_request(request)
        if auth_err is not None:
            return auth_err
        self.reset()
        return web.json_response({"status": "ok"})

    async def _handle_testing_snapshot(self, request: web.Request) -> web.Response:
        auth_err = self._authorize_testing_request(request)
        if auth_err is not None:
            return auth_err
        payload = await self._read_json_dict(request)
        name = str(payload.get("name") or "default").strip() or "default"
        self._named_snapshots[name] = self.snapshot_state()
        return web.json_response({"status": "ok", "name": name})

    async def _handle_testing_restore(self, request: web.Request) -> web.Response:
        auth_err = self._authorize_testing_request(request)
        if auth_err is not None:
            return auth_err
        payload = await self._read_json_dict(request)
        name = str(payload.get("name") or "default").strip() or "default"
        snap = self._named_snapshots.get(name)
        if snap is None:
            return web.json_response(
                {"code": "generic_err_object_not_found", "message": f"Snapshot [{name}] not found"},
                status=404,
            )
        self.restore_state(snap)
        return web.json_response({"status": "ok", "name": name})

    async def _handle_testing_call_log(self, request: web.Request) -> web.Response:
        auth_err = self._authorize_testing_request(request)
        if auth_err is not None:
            return auth_err
        return web.json_response({"calls": self._api_mock.call_log})

    @traced
    async def _handle_web_api(self, request: web.Request) -> web.Response:
        command = request.match_info.get("command", "").strip()
        payload = await self._read_json_dict(request)
        sid = request.headers.get("X-chkp-sid", "").strip() or None
        explicit_domain = payload.get("domain")

        if command == "login":
            has_key = bool(str(payload.get("api-key") or "").strip())
            has_user_pass = bool(str(payload.get("user") or "").strip() and str(payload.get("password") or "").strip())
            if not (has_key or has_user_pass):
                span_attrs(command=command, status_code=401, error_code="generic_err_invalid_credentials")
                trace.get_current_span().set_status(Status(StatusCode.ERROR, "generic_err_invalid_credentials"))
                return web.json_response(
                    {
                        "code": "generic_err_invalid_credentials",
                        "message": "Authentication credentials (api-key or user/password) are required",
                    },
                    status=401,
                )
            resolved_domain = str(explicit_domain) if explicit_domain else "System Data"
            span_attrs(command=command, domain=resolved_domain, sid_ref="login")
        else:
            if not sid:
                span_attrs(command=command, status_code=401, error_code="generic_err_missing_required_header")
                trace.get_current_span().set_status(Status(StatusCode.ERROR, "generic_err_missing_required_header"))
                return web.json_response(
                    {
                        "code": "generic_err_missing_required_header",
                        "message": "X-chkp-sid header is missing",
                    },
                    status=401,
                )
            binding = self._api_mock.get_active_sid_binding(sid)
            if binding is None:
                span_attrs(command=command, status_code=401, error_code="generic_err_invalid_session_id")
                trace.get_current_span().set_status(Status(StatusCode.ERROR, "generic_err_invalid_session_id"))
                return web.json_response(
                    {
                        "code": "generic_err_invalid_session_id",
                        "message": "Session ID is invalid or expired",
                    },
                    status=401,
                )
            if binding.domain != "System Data":
                if explicit_domain is not None and str(explicit_domain).strip():
                    norm_explicit = self._api_mock._normalize_domain(str(explicit_domain))
                    if norm_explicit != binding.domain:
                        span_attrs(
                            command=command,
                            domain=binding.domain,
                            sid_ref=binding.sid_ref,
                            session_uid=binding.session_uid,
                            status_code=400,
                            error_code="err_validation_failed",
                        )
                        trace.get_current_span().set_status(Status(StatusCode.ERROR, "err_validation_failed"))
                        return web.json_response(
                            {
                                "code": "err_validation_failed",
                                "message": (
                                    f"Session bound to domain [{binding.domain}] cannot target domain [{norm_explicit}]"
                                ),
                            },
                            status=400,
                        )
                resolved_domain = binding.domain
            else:
                resolved_domain = str(explicit_domain) if explicit_domain else binding.domain
            span_attrs(
                command=command,
                domain=resolved_domain,
                sid_ref=binding.sid_ref,
                session_uid=binding.session_uid,
            )

        try:
            res = await self._api_mock.api_call(
                "mds",
                command,
                payload,
                domain=resolved_domain,
                sid=sid,
                wait_for_task=False,
            )
        except ValidationError as exc:
            span_attrs(status_code=400, success=False, error_code="err_validation_failed")
            trace.get_current_span().set_status(Status(StatusCode.ERROR, "err_validation_failed"))
            return web.json_response({"code": "err_validation_failed", "message": str(exc)}, status=400)

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

        span_attrs(status_code=res.status_code, success=res.success, error_code=res.error_code or "")
        if not res.success:
            trace.get_current_span().set_status(Status(StatusCode.ERROR, res.error_code or "api_error"))

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
    parser.add_argument(
        "--enable-test-control",
        action="store_true",
        default=False,
        help="Expose /__testing__/* state reset/snapshot/call-log endpoints for external integration tests.",
    )
    parser.add_argument(
        "--test-control-token",
        default=None,
        help="Optional shared secret token for X-Arodonata-Test-Token authentication on /__testing__/* endpoints.",
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
        enable_test_control=bool(args.enable_test_control),
        test_control_token=args.test_control_token,
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
