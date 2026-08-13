"""Client entry-point spans + the api-only import guarantee."""

import subprocess
import sys
from unittest.mock import AsyncMock

from tests.unit.api.client_test_helpers import make_client


async def test_api_call_emits_entry_span(otel_spans):
    mgmt = AsyncMock()
    mgmt.api_call.return_value = {"success": True, "data": {}, "message": "", "code": ""}
    client = make_client(mgmt=mgmt)

    await client.api_call("mgmt1", "show-hosts")

    names = [s.name for s in otel_spans.get_finished_spans()]
    assert any(n.endswith("ArodonataClient.api_call") for n in names)


def test_importing_arodonata_never_pulls_otel_sdk():
    """arodonata must run on opentelemetry-api alone (MMP owns the provider)."""
    code = (
        "import sys\n"
        "import arodonata\n"
        "import arodonata.api.client\n"
        "import arodonata.cpcrud.service\n"
        "sdk = [m for m in sys.modules if m.startswith('opentelemetry.sdk')]\n"
        "assert not sdk, f'arodonata imported the OTEL SDK: {sdk}'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_traced_code_runs_correctly_with_no_provider_configured():
    """The core 'standalone doesn't crash' guarantee — in a subprocess with no
    OTEL provider ever configured, a real @traced code path must still work.

    This is the ONLY genuinely provider-free test for this guarantee. The
    four "works_without_provider" tests elsewhere (test_telemetry.py,
    test_otel_transport.py, test_otel_lock_manager.py, test_otel_cpcrud.py)
    run in-process, where the `otel_spans` fixture makes the global
    TracerProvider session-persistent once any earlier test has used it —
    so they silently exercise the "with provider" path instead. A fresh
    subprocess never configures a provider at all.
    """
    code = (
        "import asyncio\n"
        "from arodonata.cache.database import DatabaseManager\n"
        "from arodonata.cache.lock_manager import DatabaseLockManager\n"
        "from sqlalchemy.ext.asyncio import create_async_engine\n"
        "\n"
        "async def main():\n"
        "    engine = create_async_engine('sqlite+aiosqlite:///:memory:')\n"
        "    manager = DatabaseLockManager(DatabaseManager(engine))\n"
        "    await manager.initialize()\n"
        "    ctx = await manager.acquire_lock('noprov-check', timeout=5, ttl=30)\n"
        "    await manager.release_lock('noprov-check', ctx.owner_id)\n"
        "    await engine.dispose()\n"
        "    print('OK')\n"
        "\n"
        "asyncio.run(main())\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
