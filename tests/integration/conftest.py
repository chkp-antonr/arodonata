"""Root fixtures and collection hooks for live Check Point MDSM integration tests.

Loaded ONLY when pytest collects under ``tests/integration/`` (unit tests under
``tests/unit/`` never import this module).

Safety model:
1. ``integration_run_lock`` (session, autouse) acquires ``_tmp/integration.lock`` via
   ``flock(LOCK_EX | LOCK_NB)`` before anything touches the lab or ``_tmp/test_cache.db``.
2. ``lab_ready`` (session, autouse) polls ``show-api-versions`` up to ``LAB_READY_TIMEOUT``
   (default 300s) so a freshly booted MDS VM finishes starting its Java API daemon.
3. ``db_engine`` creates a fresh SQLite database at ``DATABASE_URL`` (wiping any prior
   run's cache file) and disposes it at session end.
4. ``cp_baseline_snapshot`` (session, autouse) records the ``last_published_session`` UID
   for ``TEST_DOMAIN_A`` and ``TEST_DOMAIN_B`` BEFORE any test runs, writes it to
   ``_tmp/cp_baseline.json`` (so a ``SIGKILL``'d run can still be recovered via
   ``python -m tests.integration.restore_baseline``), and in its ``finally:`` block
   calls ``revert-to-revision`` on each domain whose head moved.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Generator
from datetime import UTC, datetime
from pathlib import Path

import arlogi
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.adapters.storage import DatabaseManager
from arodonata.core.telemetry import set_trace_modules
from tests.integration.cp_revision import (
    BaselineSnapshot,
    restore_to_baseline,
    snapshot_baseline,
    write_baseline_file,
)
from tests.integration.lab_env import REPO_ROOT, is_test_domain, load_lab_env
from tests.integration.lab_ready import LabNotReady, wait_until_ready
from tests.integration.run_lock import IntegrationRunLock, IntegrationRunLocked

# Load .env.test -> .env.secrets -> .env.lab.<ARODONATA_LAB>
ACTIVE_LAB = load_lab_env()

arlogi.setup_logging(
    level=os.environ.get("ARODONATA_LOG_LEVEL", "WARNING"),
)

BASELINE_DIR = REPO_ROOT / "_tmp" / "cp_baseline"
BASELINE_FILE = REPO_ROOT / "_tmp" / "cp_baseline.json"
LOCK_FILE = REPO_ROOT / "_tmp" / "integration.lock"
EXIT_LOCK_CONTENTION = 3
EXIT_LAB_NOT_READY = 4
EXIT_BASELINE_FAILURE = 5


# ---------------------------------------------------------------------------
# Auto-markers by directory (tests/integration/bN/... -> integration + bucket_N)
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Attach ``integration`` and ``bucket_N`` markers based on path under ``tests/integration/``."""
    bucket_order: dict[int, int] = {}
    for idx, item in enumerate(items):
        parts = Path(item.fspath).parts
        if "integration" not in parts:
            bucket_order[id(item)] = 0
            continue
        item.add_marker(pytest.mark.integration)
        p_idx = parts.index("integration")
        bucket_num = 99
        if p_idx + 1 < len(parts):
            sub = parts[p_idx + 1]
            if len(sub) == 2 and sub.startswith("b") and sub[1].isdigit():
                bucket_num = int(sub[1])
                item.add_marker(getattr(pytest.mark, f"bucket_{sub[1]}"))
        bucket_order[id(item)] = bucket_num * 10000 + idx
    items.sort(key=lambda it: bucket_order.get(id(it), 0))


# ---------------------------------------------------------------------------
# Environment / lab parameters (fail fast if .env.test / .env.secrets missing)
# ---------------------------------------------------------------------------


def _require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        pytest.skip(f"Integration env var {name!r} not set (check .env.test / .env.secrets)")
    return val


@pytest.fixture(scope="session", autouse=True)
def integration_tracing() -> Generator[None]:
    """Ensure ``@traced`` spans are active during integration runs."""
    set_trace_modules({"arodonata": True})
    yield


@pytest.fixture(scope="session", autouse=True)
def integration_run_lock() -> Generator[IntegrationRunLock]:
    """Refuse to start if another pytest process is already using the live lab (exit code 3)."""
    lock = IntegrationRunLock(LOCK_FILE)
    try:
        lock.acquire()
    except IntegrationRunLocked as exc:
        pytest.exit(str(exc), returncode=EXIT_LOCK_CONTENTION)
    try:
        yield lock
    finally:
        lock.release()


@pytest.fixture(scope="session")
def mgmt_ip() -> str:
    """Target management server IP address."""
    return _require_env("API_MGMT")


@pytest.fixture(scope="session")
def mgmt_name(mgmt_ip: str) -> str:
    """Logical management server name (convention: equals ``mgmt_ip`` in lab tests)."""
    return mgmt_ip


@pytest_asyncio.fixture(scope="session", loop_scope="session", autouse=True)
async def lab_ready(
    integration_run_lock: IntegrationRunLock,
    mgmt_ip: str,
) -> None:
    """Wait up to ``ARODONATA_TEST_READY_WAIT`` / ``LAB_READY_TIMEOUT`` (default 300s) for the MDS Web API (exit code 4)."""
    raw_timeout = os.environ.get("ARODONATA_TEST_READY_WAIT") or os.environ.get("LAB_READY_TIMEOUT", "300")
    timeout = float(raw_timeout)
    try:
        await wait_until_ready(mgmt_ip, timeout=timeout)
    except LabNotReady as exc:
        pytest.exit(str(exc), returncode=EXIT_LAB_NOT_READY)


@pytest.fixture(scope="session")
def api_key() -> str:
    """API key from ``APIKEY`` environment variable."""
    return _require_env("APIKEY")


@pytest.fixture(scope="session")
def test_domain_a() -> str:
    """Primary sandbox domain for mutating tests."""
    return os.environ.get("TEST_DOMAIN_A", "Domain4").strip()


@pytest.fixture(scope="session")
def test_domain_b() -> str:
    """Secondary sandbox domain for multi-domain tests."""
    return os.environ.get("TEST_DOMAIN_B", "Domain5").strip()


@pytest.fixture(scope="session")
def sandbox_domains(test_domain_a: str, test_domain_b: str) -> list[str]:
    """Ordered list of sandbox domains covered by ``cp_baseline_snapshot``."""
    return [test_domain_a, test_domain_b]


# ---------------------------------------------------------------------------
# Database engine (session-scoped, clean file in _tmp/)
# ---------------------------------------------------------------------------


def _sqlite_file_from_url(url: str) -> Path | None:
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if url.startswith(prefix):
            rel = url[len(prefix) :]
            if rel and rel != ":memory:":
                p = Path(rel)
                return p if p.is_absolute() else (REPO_ROOT / p)
    return None


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def db_engine() -> AsyncGenerator[AsyncEngine]:
    """Session-wide SQLite async engine with clean ``_tmp/test_cache.db`` initialization."""
    db_url = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///_tmp/test_cache.db")
    db_file = _sqlite_file_from_url(db_url)
    if db_file is not None:
        db_file.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ("", "-wal", "-shm"):
            f = Path(str(db_file) + suffix)
            if f.exists():
                f.unlink()

    engine = create_async_engine(db_url, echo=False)
    db_mgr = DatabaseManager(engine=engine)
    await db_mgr.initialize()

    try:
        yield engine
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Clients (startup session cleanup disabled — tests manage their own sessions)
# ---------------------------------------------------------------------------


async def _make_client(cfg: ArodonataSettings, engine: AsyncEngine) -> ArodonataClient:
    client = ArodonataClient(settings=cfg, engine=engine)
    await client.initialize(run_startup_cleanup=False)
    return client


@pytest_asyncio.fixture
async def apikey_client(
    mgmt_name: str,
    mgmt_ip: str,
    api_key: str,
    db_engine: AsyncEngine,
) -> AsyncGenerator[ArodonataClient]:
    """Function-scoped ``ArodonataClient`` authenticated via ``APIKEY`` (shares ``db_engine`` SID cache)."""
    cfg = ArodonataSettings(
        mgmt_names=[mgmt_name],
        mgmt_servers=[mgmt_ip],
        api_keys=[api_key],
    )
    client = await _make_client(cfg, db_engine)
    try:
        yield client
    finally:
        await client.close(logout=False)


async def _user_client(
    username: str,
    env_var: str,
    mgmt_name: str,
    mgmt_ip: str,
    db_engine: AsyncEngine,
) -> AsyncGenerator[ArodonataClient]:
    password = _require_env(env_var)
    cfg = ArodonataSettings(
        mgmt_name=mgmt_name,
        mgmt_ip=mgmt_ip,
        username=username,
        password=password,
    )
    client = await _make_client(cfg, db_engine)
    try:
        yield client
    finally:
        await client.close(logout=False)


@pytest_asyncio.fixture
async def admin_client(mgmt_name: str, mgmt_ip: str, db_engine: AsyncEngine) -> AsyncGenerator[ArodonataClient]:
    """Client for user ``admin``."""
    async for c in _user_client("admin", "USER_admin", mgmt_name, mgmt_ip, db_engine):
        yield c


@pytest_asyncio.fixture
async def antonr_client(mgmt_name: str, mgmt_ip: str, db_engine: AsyncEngine) -> AsyncGenerator[ArodonataClient]:
    """Client for user ``AntonR``."""
    async for c in _user_client("AntonR", "USER_AntonR", mgmt_name, mgmt_ip, db_engine):
        yield c


@pytest_asyncio.fixture
async def eng1_client(mgmt_name: str, mgmt_ip: str, db_engine: AsyncEngine) -> AsyncGenerator[ArodonataClient]:
    """Client for user ``eng1``."""
    async for c in _user_client("eng1", "USER_Eng1", mgmt_name, mgmt_ip, db_engine):
        yield c


@pytest_asyncio.fixture
async def eng2_client(mgmt_name: str, mgmt_ip: str, db_engine: AsyncEngine) -> AsyncGenerator[ArodonataClient]:
    """Client for user ``eng2``."""
    async for c in _user_client("eng2", "USER_Eng2", mgmt_name, mgmt_ip, db_engine):
        yield c


@pytest_asyncio.fixture
async def eng3_client(mgmt_name: str, mgmt_ip: str, db_engine: AsyncEngine) -> AsyncGenerator[ArodonataClient]:
    """Client for user ``eng3``."""
    async for c in _user_client("eng3", "USER_Eng3", mgmt_name, mgmt_ip, db_engine):
        yield c


@pytest_asyncio.fixture
async def eng4_client(mgmt_name: str, mgmt_ip: str, db_engine: AsyncEngine) -> AsyncGenerator[ArodonataClient]:
    """Client for user ``eng4``."""
    async for c in _user_client("eng4", "USER_Eng4", mgmt_name, mgmt_ip, db_engine):
        yield c


# ---------------------------------------------------------------------------
# Check Point revision safety net (session-scoped, autouse)
# ---------------------------------------------------------------------------

_mutation_tracker = {"ran": False}


@pytest.fixture(autouse=True)
def _track_cp_mutations(request: pytest.FixtureRequest) -> Generator[None]:
    """Record whether any ``cp_mutates``-marked test executed in this session."""
    if request.node.get_closest_marker("cp_mutates") is not None:
        _mutation_tracker["ran"] = True
    yield


@pytest_asyncio.fixture(scope="session", loop_scope="session", autouse=True)
async def cp_baseline_snapshot(
    db_engine: AsyncEngine,
    mgmt_name: str,
    mgmt_ip: str,
    api_key: str,
    sandbox_domains: list[str],
) -> AsyncGenerator[BaselineSnapshot]:
    """Snapshot ``TEST_DOMAIN_A`` / ``TEST_DOMAIN_B`` before the run; revert on teardown if ``cp_mutates`` ran."""
    rev_name = os.environ.get("CP_REVISION_NAME", "").strip() or None
    cfg = ArodonataSettings(
        mgmt_names=[mgmt_name],
        mgmt_servers=[mgmt_ip],
        api_keys=[api_key],
    )
    snap_client = await _make_client(cfg, db_engine)
    try:
        snap = await snapshot_baseline(
            snap_client,
            mgmt_name=mgmt_name,
            mgmt_ip=mgmt_ip,
            domains=sandbox_domains,
            revision_name=rev_name,
        )
    except Exception as exc:
        pytest.exit(f"Failed to capture Check Point baseline snapshot: {exc}", returncode=EXIT_BASELINE_FAILURE)
    finally:
        await snap_client.close(logout=False)

    utc_stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    timestamped_baseline_file = BASELINE_DIR / f"baseline-{utc_stamp}.json"
    write_baseline_file(snap, timestamped_baseline_file)
    write_baseline_file(snap, BASELINE_FILE)
    try:
        yield snap
    finally:
        if _mutation_tracker["ran"]:
            restore_client = await _make_client(cfg, db_engine)
            try:
                await restore_to_baseline(restore_client, snap)
            finally:
                await restore_client.close(logout=False)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def all_domains(
    db_engine: AsyncEngine,
    mgmt_name: str,
    mgmt_ip: str,
    api_key: str,
) -> list[str]:
    """Non-Global domains on the MDS that this test run is allowed to touch."""
    cfg = ArodonataSettings(
        mgmt_names=[mgmt_name],
        mgmt_servers=[mgmt_ip],
        api_keys=[api_key],
    )
    client = await _make_client(cfg, db_engine)
    try:
        doms = await client.get_domains(mgmt_name=mgmt_name, include_global=False, cache_mode="force")
    finally:
        await client.close(logout=False)
    names = sorted(d.name for d in doms if is_test_domain(d.name))
    assert names, f"No allowed non-Global domains discovered on {mgmt_name}"
    return names
