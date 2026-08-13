"""Shared fixtures for real-server integration tests (FPCR lab).

Loads .env.test then .env.secrets from the repo root (symlinks into
.internal/). Missing variables skip the affected tests, so machines
without lab access still run the unit suite cleanly.

Tier markers (integration + tier_fast/tier_medium/tier_full) are applied
automatically from the directory path — tests never declare them.

Required environment variables:
    API_MGMT      - Management server IP
    DATABASE_URL  - SQLite path (e.g. sqlite+aiosqlite:///_tmp/test_cache.db)
    APIKEY        - API key for apikey_client
    USER_admin, USER_AntonR, USER_Eng1..USER_Eng4 - credential passwords
Optional:
    TEST_DOMAIN_A / TEST_DOMAIN_B - MDM sandbox domains for mutating tests
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from arodonata import ArodonataClient, ArodonataSettings

from .cp_revision import (
    restore_to_baseline,
    snapshot_baseline,
    write_baseline_file,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

_project_root = Path(__file__).parent.parent.parent
for _f in [_project_root / ".env.test", _project_root / ".env.secrets"]:
    if _f.exists():
        load_dotenv(_f, override=True)


def _require_env(name: str) -> str:
    """Get env var or skip the test if missing."""
    val = os.getenv(name)
    if not val:
        pytest.skip(f"Required env var '{name}' is not set — skipping integration test")
    return val


# ---------------------------------------------------------------------------
# Tier auto-markers from directory path
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        parts = Path(str(item.fspath)).parts
        if "integration" not in parts:
            continue
        item.add_marker(pytest.mark.integration)
        for tier in ("fast", "medium", "full"):
            if tier in parts:
                item.add_marker(getattr(pytest.mark, f"tier_{tier}"))

    # Sort integration tests by tier: fast -> medium -> full
    def _tier_sort_key(item: pytest.Item) -> int:
        parts = Path(str(item.fspath)).parts
        if "fast" in parts:
            return 0
        if "medium" in parts:
            return 1
        if "full" in parts:
            return 2
        return 3

    items.sort(key=_tier_sort_key)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
async def db_engine() -> AsyncEngine:
    """Session-scoped SQLite WAL engine; deletes the DB file on teardown."""
    db_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///_tmp/test_cache.db")

    db_path: Path | None = None
    if ":///" in db_url and ":memory:" not in db_url:
        db_path = Path(db_url.split("///", 1)[1])
        db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_async_engine(db_url, echo=False)

    @event.listens_for(engine.sync_engine, "connect")
    def _set_wal(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    try:
        yield engine
    finally:
        await engine.dispose()
        if db_path:
            for suffix in ["", "-wal", "-shm"]:
                p = db_path.parent / (db_path.name + suffix)
                p.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Clients — one fixture per lab identity
# ---------------------------------------------------------------------------


def _make_apikey_settings(mgmt_ip: str, api_key: str) -> ArodonataSettings:
    return ArodonataSettings(mgmt_names=mgmt_ip, mgmt_servers=mgmt_ip, api_keys=api_key)


def _disable_startup_cleanup(client: ArodonataClient) -> None:
    """Null the session cleaner so the background startup cleanup is a no-op.

    Concurrent startup cleanups from clients sharing one server IP hold
    rate-limiter slots during login and cause LockAcquisitionError. Tests
    that need cleanup restore it and call run_startup_cleanup() explicitly.
    """
    if client._login_coordinator:
        client._login_coordinator._session_cleaner = None


@pytest.fixture
async def apikey_client(db_engine: AsyncEngine):
    """(ArodonataClient, mgmt_name) authenticated with APIKEY."""
    mgmt_ip = _require_env("API_MGMT")
    api_key = _require_env("APIKEY")
    async with ArodonataClient(engine=db_engine, settings=_make_apikey_settings(mgmt_ip, api_key)) as client:
        _disable_startup_cleanup(client)
        yield client, mgmt_ip


def _credential_client_fixture(username: str, env_var: str, fixture_name: str):
    """Build a per-user credential client fixture."""

    @pytest.fixture(name=fixture_name)
    async def _fixture(db_engine: AsyncEngine):
        mgmt_ip = _require_env("API_MGMT")
        password = _require_env(env_var)
        async with ArodonataClient(engine=db_engine, username=username, password=password, mgmt_ip=mgmt_ip) as client:
            _disable_startup_cleanup(client)
            yield client, mgmt_ip

    return _fixture


# Server-side admin usernames are lowercase (eng1..eng4); the env var names
# keep the capitalization used in .env.secrets (USER_Eng1..). No eng5 user
# exists on the lab server.
admin_client = _credential_client_fixture("admin", "USER_admin", "admin_client")
antonr_client = _credential_client_fixture("AntonR", "USER_AntonR", "antonr_client")
eng1_client = _credential_client_fixture("eng1", "USER_Eng1", "eng1_client")
eng2_client = _credential_client_fixture("eng2", "USER_Eng2", "eng2_client")
eng3_client = _credential_client_fixture("eng3", "USER_Eng3", "eng3_client")
eng4_client = _credential_client_fixture("eng4", "USER_Eng4", "eng4_client")


@pytest.fixture
def test_domain_a() -> str:
    """Name of the sandbox domain for mutating medium/full-tier tests."""
    return _require_env("TEST_DOMAIN_A")


@pytest.fixture
def test_domain_b() -> str:
    """Second sandbox domain (full-tier multi-domain tests)."""
    return _require_env("TEST_DOMAIN_B")


# ---------------------------------------------------------------------------
# Domain discovery
# ---------------------------------------------------------------------------


def _extract_active_ip(domain_obj: dict) -> str:
    for server in domain_obj.get("servers", []):
        if isinstance(server, dict) and server.get("active") is True:
            ip = server.get("ipv4-address", "")
            if ip:
                return ip
    return ""


@pytest.fixture(scope="session")
async def all_domains(db_engine: AsyncEngine) -> list[dict]:
    """Session-scoped [{name, active_ip}] for all MDM domains; skips on SMS."""
    mgmt_ip = os.getenv("API_MGMT")
    api_key = os.getenv("APIKEY")
    if not mgmt_ip or not api_key:
        pytest.skip("API_MGMT or APIKEY not set — skipping domain-dependent test")

    async with ArodonataClient(engine=db_engine, settings=_make_apikey_settings(mgmt_ip, api_key)) as client:
        _disable_startup_cleanup(client)
        result = await client.api_call(mgmt_ip, "show-domains", details_level="full")

    if not result.success:
        pytest.skip(f"show-domains failed: {result.message}")

    objects = (result.data or {}).get("objects", [])
    domains = [
        {"name": d["name"], "active_ip": _extract_active_ip(d)}
        for d in objects
        if isinstance(d, dict) and d.get("name") and _extract_active_ip(d)
    ]
    if not domains:
        pytest.skip("Server has no domains with active IPs — MDM tests not applicable")
    return domains


# ---------------------------------------------------------------------------
# Revision snapshot safety net
# ---------------------------------------------------------------------------

_mutation_tracker = {"ran": False}


@pytest.fixture(autouse=True)
def _track_cp_mutations(request: pytest.FixtureRequest):
    """Record whether any cp_mutates-marked test actually executed."""
    if request.node.get_closest_marker("cp_mutates"):
        _mutation_tracker["ran"] = True
    yield


@pytest.fixture(scope="session", autouse=True)
async def cp_baseline_snapshot(db_engine: AsyncEngine):
    """Snapshot last published revisions before any test; revert after mutations.

    Writes _tmp/cp_baseline/baseline-<UTC>.json (never auto-deleted — it is
    the manual-recovery handle). A snapshot failure aborts the whole
    integration session: no safety net, no run. At teardown, if any
    cp_mutates test ran, every domain whose last published revision drifted
    from the baseline is reverted to it.
    """
    mgmt_ip = os.getenv("API_MGMT")
    api_key = os.getenv("APIKEY")
    if not mgmt_ip or not api_key:
        # No lab configured: individual tests skip via _require_env anyway.
        yield None
        return

    settings = _make_apikey_settings(mgmt_ip, api_key)
    async with ArodonataClient(engine=db_engine, settings=settings) as client:
        _disable_startup_cleanup(client)
        baseline = await snapshot_baseline(client, mgmt_ip)  # raises on failure

    path = write_baseline_file(baseline)
    log.warning("CP baseline snapshot written: %s", path)

    yield path

    if not _mutation_tracker["ran"]:
        return

    async with ArodonataClient(engine=db_engine, settings=settings) as client:
        _disable_startup_cleanup(client)
        try:
            reverted = await restore_to_baseline(client, mgmt_ip, baseline)
        except Exception:
            log.error(
                "BASELINE RESTORE FAILED — restore manually with:\n  uv run tests/integration/restore_baseline.py %s",
                path,
            )
            raise
    log.warning("Reverted domains to baseline: %s", reverted or "none (no drift)")
