"""Wave 3 regression tests: SessionCleaner keyed auth_identity, single publish invalidation, re-exports, and @traced parity."""

from __future__ import annotations

import ast
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from arodonata import ArodonataClient, ArodonataSettings, AuthContext
from arodonata import client as client_pkg
from arodonata.adapters.checkpoint import AMgmtClient, connection_pool, connector, response_classifiers
from arodonata.adapters.checkpoint import session_cleaner as session_cleaner_mod
from arodonata.adapters.checkpoint import sessions as sessions_mod
from arodonata.adapters.checkpoint import target_resolver as target_resolver_mod
from arodonata.adapters.checkpoint import tls as tls_mod
from arodonata.adapters.checkpoint import transport as transport_mod
from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.checkpoint.transport import (
    ApiTransport,
    PooledSocketEntry,
    RawHttpResponse,
    VerifiedConnectionPool,
)
from arodonata.adapters.storage import DatabaseManager, SqlCacheAdapter, cache_adapter
from arodonata.adapters.storage import cache as cache_pkg
from arodonata.adapters.storage.cache import mappers as cache_mappers
from arodonata.client import _base as client_base
from arodonata.client import warmup as client_warmup
from arodonata.core.context import SYSTEM_DOMAIN_KEY
from arodonata.core.models.common import ApiCallResult, ApiQueryResult, utc_now
from arodonata.core.models.domains import SIDCacheEntry

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "arodonata"

_EXPECTED_CLIENT_TRACED_METHODS: frozenset[str] = frozenset(
    {
        "close",
        "api_call",
        "api_query",
        "refresh_objects",
        "refresh_services",
        "refresh_assets",
        "refresh_rulebases",
        "refresh_policy_packages",
        "refresh_package_rulebase",
        "refresh_topology",
        "get_domains",
        "get_gateways",
        "get_gateway_topology",
        "find_affected_gateways",
        "collect_gateway_routes",
        "check_route_collection_script",
        "ensure_route_collection_script",
        "get_topology_diagnostics",
        "reconcile_gateway_topology",
        "get_topology_annotations",
        "upsert_topology_annotations",
        "delete_topology_annotations",
        "export_topology_prefixes",
        "get_hosts",
        "get_networks",
        "get_address_ranges",
        "get_dns_domains",
        "get_groups",
        "get_objects",
        "get_services",
        "get_object_by_uid",
        "get_access_rules",
        "get_nat_rules",
        "get_https_rules",
        "get_threat_rules",
        "get_policy_packages",
        "get_package_rulebase",
        "get_layer_rulebase",
        "locate_rules",
        "filter_rulebase",
        "collect_change_report",
        "build_change_report_from_plan",
        "render_change_report",
        "build_change_report",
        "search_objects",
        "describe_objects",
        "query_objects",
        "get_cache_status",
        "add_object",
        "set_object",
        "delete_object",
        "find_object",
        "get_group_members",
        "publish_staged_session",
        "discard_staged_session",
        "get_repository_script",
        "list_repository_scripts",
        "check_repository_script",
        "ensure_repository_script",
        "delete_repository_script",
        "run_repository_script",
    }
)


def _make_der(seed: str = "wave3-cert") -> tuple[bytes, str]:
    der = f"der-{seed}".encode()
    digest = hashlib.sha256(der).hexdigest().upper()
    formatted = ":".join(digest[i : i + 2] for i in range(0, 64, 2))
    return der, formatted


@pytest.mark.spec("SCN-SESS-004-1", "SCN-SESS-003-2")
async def test_session_cleaner_multi_identity_seeding_and_keyed_sid_eviction(tmp_path: Path) -> None:
    """SCN-SESS-004-1 / SCN-SESS-003-2: SessionCleaner checks and evicts SID rows using auth_identity."""
    der, fp = _make_der("cleaner-id")
    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="static-unused",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp}",
    )

    calls: list[tuple[str, dict[str, Any]]] = []
    login_seq = 0
    show_sessions_objects: list[dict[str, Any]] = []

    async def fake_sender(
        *,
        host: str,
        port: int,
        command: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        connect_timeout: float,
        read_timeout: float,
        reused_entry: PooledSocketEntry | None,
    ) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        nonlocal login_seq
        payload = json.loads(body.decode("utf-8")) if body else {}
        calls.append((command, payload))
        if command == "login":
            login_seq += 1
            resp_data = {"sid": f"sid_clean_{login_seq}_tok", "uid": f"uid-clean-{login_seq}"}
        elif command == "show-sessions":
            resp_data = {"objects": list(show_sessions_objects)}
        else:
            resp_data = {"message": "OK"}
        entry = reused_entry or PooledSocketEntry(
            host=host,
            port=port,
            fingerprint=fp,
            protocol=object(),
            last_used_at=1.0,
        )
        return RawHttpResponse(status=200, body=json.dumps(resp_data).encode("utf-8")), entry

    transport = ApiTransport(
        settings=settings,
        trust_policy=tls_mod.TrustPolicy(
            mode="pinned",
            known_hosts_path=tmp_path / "kh.json",
            pinned_fingerprints=f"10.0.0.1:443={fp}",
        ),
        connection_pool=VerifiedConnectionPool(),
        peer_cert_getter=lambda _h, _p: der,
        request_sender=fake_sender,
    )

    amgmt = AMgmtClient(settings, transport=transport)
    await amgmt.initialize(run_startup_cleanup=False)
    try:
        auth_a = AuthContext(api_key="key-alpha-secret", user_id="admin-a")
        auth_b = AuthContext(api_key="key-beta-secret", user_id="admin-b")
        id_a = auth_a.identity_key
        id_b = auth_b.identity_key
        now = utc_now()

        # 1. Seed fresh SID for Identity A keyed by auth_identity
        await amgmt.cache.upsert_sid(
            SIDCacheEntry(
                id=f"mds1:{SYSTEM_DOMAIN_KEY}:{id_a}",
                mgmt_name="mds1",
                domain_name=SYSTEM_DOMAIN_KEY,
                sid="sid_a_live",
                server_ip="10.0.0.1",
                session_uid="uid-live-A",
                auth_identity=id_a,
                created_at=now,
                last_used_at=now,
                expires_at=now + timedelta(seconds=600),
            )
        )

        # Even if show-sessions reports uid-live-A with 0 changes, Identity B's startup cleanup
        # must NOT treat Identity A's SID as its own, must preserve uid-live-A, and must seed Identity B.
        show_sessions_objects[:] = [
            {
                "uid": "uid-live-A",
                "application": "arodonata",
                "session-name": "arodonata-session-cleaner",
                "changes": 0,
                "locks": 0,
            }
        ]
        ok_b = await amgmt.session_cleaner.cleanup_server_sessions("mds1", auth=auth_b, seed_system_sid=True)
        assert ok_b is True
        assert [c[1]["uid"] for c in calls if c[0] == "discard"] == []

        row_a = await amgmt.cache.get_sid("mds1", SYSTEM_DOMAIN_KEY, auth_identity=id_a)
        row_b = await amgmt.cache.get_sid("mds1", SYSTEM_DOMAIN_KEY, auth_identity=id_b)
        assert row_a is not None and row_a.sid == "sid_a_live"
        assert row_b is not None and row_b.sid == "sid_clean_1_tok"

        # 2. When an expired cached session for Identity A is discarded during non-seeding cleanup,
        # ONLY Identity A's SID row is evicted; Identity B's row stays intact.
        calls.clear()
        await amgmt.cache.upsert_sid(
            SIDCacheEntry(
                id=f"mds1:{SYSTEM_DOMAIN_KEY}:{id_a}",
                mgmt_name="mds1",
                domain_name=SYSTEM_DOMAIN_KEY,
                sid="sid_a_stale",
                server_ip="10.0.0.1",
                session_uid="uid-stale-A",
                auth_identity=id_a,
                created_at=now - timedelta(seconds=900),
                last_used_at=now - timedelta(seconds=900),
                expires_at=now - timedelta(seconds=10),
            )
        )
        show_sessions_objects[:] = [
            {
                "uid": "uid-stale-A",
                "application": "arodonata",
                "session-name": "arodonata-session-cleaner",
                "changes": 0,
                "locks": 0,
            }
        ]
        ok_clean_a = await amgmt.session_cleaner.cleanup_server_sessions("mds1", auth=auth_a, seed_system_sid=False)
        assert ok_clean_a is True
        assert [c[1]["uid"] for c in calls if c[0] == "discard"] == ["uid-stale-A"]
        assert await amgmt.cache.get_sid("mds1", SYSTEM_DOMAIN_KEY, auth_identity=id_a) is None
        row_b_after = await amgmt.cache.get_sid("mds1", SYSTEM_DOMAIN_KEY, auth_identity=id_b)
        assert row_b_after is not None and row_b_after.sid == "sid_clean_1_tok"
    finally:
        await amgmt.close()

    # 3. Verify strict keyed SidCachePort (returns None if auth_identity is None) hits fast path
    class _StrictKeyedSidCache:
        def __init__(self, row: SIDCacheEntry) -> None:
            self.row = row
            self.get_calls: list[str | None] = []

        async def get_domains(self, mgmt_name: str | None = None, *, include_global: bool = False) -> list[Any]:
            return []

        async def get_domain(self, mgmt_name: str, domain_name: str) -> Any:
            return None

        async def upsert_domains(self, domains: Any) -> None:
            return None

        async def get_sid(
            self,
            mgmt_name: str,
            domain_name: str,
            *,
            auth_identity: str | None = None,
        ) -> SIDCacheEntry | None:
            self.get_calls.append(auth_identity)
            if auth_identity is None:
                return None
            if (mgmt_name, domain_name, auth_identity) == (
                self.row.mgmt_name,
                self.row.domain_name,
                self.row.auth_identity,
            ):
                return self.row
            return None

        async def upsert_sid(self, entry: SIDCacheEntry) -> None:
            self.row = entry

        async def evict_sid(
            self,
            mgmt_name: str,
            domain_name: str,
            *,
            auth_identity: str | None = None,
        ) -> bool:
            return False

        async def list_sids(self, mgmt_name: str | None = None) -> list[SIDCacheEntry]:
            return [self.row]

    strict_auth = AuthContext(api_key="strict-key-only", user_id="strict-u")
    now2 = utc_now()
    strict_cache = _StrictKeyedSidCache(
        SIDCacheEntry(
            id=f"mds1:{SYSTEM_DOMAIN_KEY}:{strict_auth.identity_key}",
            mgmt_name="mds1",
            domain_name=SYSTEM_DOMAIN_KEY,
            sid="sid_strict_cached",
            server_ip="10.0.0.1",
            session_uid="uid-strict",
            auth_identity=strict_auth.identity_key,
            created_at=now2,
            last_used_at=now2,
            expires_at=now2 + timedelta(seconds=600),
        )
    )
    db_strict = DatabaseManager(engine=None)
    await db_strict.initialize()
    try:
        gate = LoginGate()
        limiter = RateLimiter()
        coord = sessions_mod.LoginCoordinator(
            settings=settings,
            transport=transport,
            cache=strict_cache,  # type: ignore[arg-type]
            login_gate=gate,
            rate_limiter=limiter,
        )
        cleaner = session_cleaner_mod.SessionCleaner(
            settings=settings,
            login_coordinator=coord,
            transport=transport,
            cache=strict_cache,
            rate_limiter=limiter,
        )
        calls.clear()
        assert await cleaner.cleanup_server_sessions("mds1", auth=strict_auth, seed_system_sid=True) is True
        assert strict_cache.get_calls == [strict_auth.identity_key]
        assert calls == []
    finally:
        await db_strict.close()


@pytest.mark.spec("SCN-CLIENT-003-2")
async def test_api_call_publish_invalidates_domain_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SCN-CLIENT-003-2: `api_call(..., 'publish')` calls `invalidate_domain` exactly once (no double call)."""
    der, fp = _make_der("single-inv")
    settings = ArodonataSettings(
        mgmt_name="mds1",
        mgmt_ip="10.0.0.1",
        api_key="secret-k",
        tls_trust="pinned",
        tls_fingerprints=f"10.0.0.1:443={fp}",
    )

    async def fake_sender(
        *,
        host: str,
        port: int,
        command: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        connect_timeout: float,
        read_timeout: float,
        reused_entry: PooledSocketEntry | None,
    ) -> tuple[RawHttpResponse, PooledSocketEntry | None]:
        resp = {"sid": "sid_pub_1", "uid": "u-1"} if command == "login" else {"message": "OK"}
        entry = reused_entry or PooledSocketEntry(
            host=host, port=port, fingerprint=fp, protocol=object(), last_used_at=1.0
        )
        return RawHttpResponse(status=200, body=json.dumps(resp).encode("utf-8")), entry

    transport = ApiTransport(
        settings=settings,
        trust_policy=tls_mod.TrustPolicy(
            mode="pinned",
            known_hosts_path=tmp_path / "pub_kh.json",
            pinned_fingerprints=f"10.0.0.1:443={fp}",
        ),
        connection_pool=VerifiedConnectionPool(),
        peer_cert_getter=lambda _h, _p: der,
        request_sender=fake_sender,
    )

    # 1. Default AMgmtClient path
    async with ArodonataClient(settings, transport=transport) as client:
        inv_calls: list[tuple[str, str | None]] = []
        sync_inv_calls: list[tuple[str, str | None]] = []
        orig_inv = client.invalidate_domain
        orig_sync_inv = client.sync_coordinator.invalidate_domain

        def _spy_inv(m: str, d: str | None = None) -> None:
            inv_calls.append((m, d))
            orig_inv(m, d)

        def _spy_sync_inv(m: str, d: str | None = None) -> None:
            sync_inv_calls.append((m, d))
            orig_sync_inv(m, d)

        monkeypatch.setattr(client, "invalidate_domain", _spy_inv)
        monkeypatch.setattr(client.sync_coordinator, "invalidate_domain", _spy_sync_inv)

        res = await client.api_call("mds1", "publish", domain="Corp", sid="explicit-sid")
        assert res.success is True
        assert inv_calls == [("mds1", "Corp")]
        assert sync_inv_calls == [("mds1", "Corp")]

    # 2. Custom ApiPort path
    class _CustomApi:
        async def api_call(self, *args: Any, **kwargs: Any) -> ApiCallResult:
            return ApiCallResult(success=True, status_code=200, data={"message": "OK"})

        async def api_query(self, *args: Any, **kwargs: Any) -> ApiQueryResult:
            return ApiQueryResult(success=True, objects=[], total=0)

        async def create_dedicated_session(self, *args: Any, **kwargs: Any) -> tuple[str, str]:
            return ("s1", "10.0.0.1")

        async def logout_sid(self, *args: Any, **kwargs: Any) -> bool:
            return True

        async def close(self, *, logout: bool | None = None) -> None:
            return None

    async with ArodonataClient(settings, api=_CustomApi()) as custom_client:
        custom_calls: list[tuple[str, str | None]] = []
        orig_custom_inv = custom_client.invalidate_domain

        def _spy_custom(m: str, d: str | None = None) -> None:
            custom_calls.append((m, d))
            orig_custom_inv(m, d)

        monkeypatch.setattr(custom_client, "invalidate_domain", _spy_custom)
        res2 = await custom_client.api_call("mds1", "publish", domain="Corp", sid="explicit-sid")
        assert res2.success is True
        assert custom_calls == [("mds1", "Corp")]


@pytest.mark.spec("SCN-CLIENT-017-1", "SCN-CLIENT-018-1", "SCN-CLIENT-018-2", "SCN-CLIENT-018-3")
def test_wave3_reexports_shared_loggers_traced_parity_and_dead_code_removal() -> None:
    """Verify Wave 3 backward-compatible re-exports, logger identities, 61 @traced parity, and dead code removal."""
    import arodonata

    # Re-export object identity
    assert arodonata.ArodonataClient is client_pkg.ArodonataClient
    assert cache_adapter.SqlCacheAdapter is cache_pkg.SqlCacheAdapter is SqlCacheAdapter
    assert sessions_mod.SessionCleaner is session_cleaner_mod.SessionCleaner
    assert sessions_mod.parse_domain_entry is response_classifiers.parse_domain_entry
    assert sessions_mod.is_session_expired_result is response_classifiers.is_session_expired_result
    assert sessions_mod.is_login_throttled_result is response_classifiers.is_login_throttled_result
    assert sessions_mod.is_transient_revision_lock_result is response_classifiers.is_transient_revision_lock_result
    assert sessions_mod.is_invalid_credentials_result is response_classifiers.is_invalid_credentials_result
    assert sessions_mod.is_max_sessions_exceeded_result is response_classifiers.is_max_sessions_exceeded_result
    assert sessions_mod.is_failover_or_unreachable_result is response_classifiers.is_failover_or_unreachable_result
    assert sessions_mod._canonicalize_host is target_resolver_mod._canonicalize_host
    assert sessions_mod._is_ip_literal is target_resolver_mod._is_ip_literal
    assert sessions_mod._resolve_hostname_ips is target_resolver_mod._resolve_hostname_ips
    assert transport_mod.VerifiedConnectionPool is connection_pool.VerifiedConnectionPool
    assert transport_mod.PooledSocketEntry is connection_pool.PooledSocketEntry
    assert transport_mod.derive_session_pool_scope is connection_pool.derive_session_pool_scope
    assert transport_mod.is_poolable_command is connection_pool.is_poolable_command
    assert transport_mod.is_readonly_poolable_command is connection_pool.is_readonly_poolable_command
    assert transport_mod.FingerprintTCPConnector is connector.FingerprintTCPConnector
    assert transport_mod.extract_peer_der_cert is connector.extract_peer_der_cert
    assert transport_mod.verify_transport_peer_certificate is connector.verify_transport_peer_certificate
    assert transport_mod._DEFAULT_CHECKPOINT_SSL_CONTEXT is connector._DEFAULT_CHECKPOINT_SSL_CONTEXT
    assert transport_mod._create_checkpoint_ssl_context is connector._create_checkpoint_ssl_context

    # Shared logger identity
    assert client_pkg.logger is client_base.logger is client_warmup.logger
    assert sessions_mod.logger is session_cleaner_mod.logger is target_resolver_mod.logger

    # @traced parity across ArodonataClient package modules (all 61 methods)
    discovered_traced: set[str] = set()
    for py_file in sorted((_SRC_ROOT / "client").glob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        decs = [ast.unparse(d) for d in item.decorator_list]
                        if "traced" in decs:
                            discovered_traced.add(item.name)
    assert discovered_traced == _EXPECTED_CLIENT_TRACED_METHODS
    for method_name in _EXPECTED_CLIENT_TRACED_METHODS:
        fn = getattr(ArodonataClient, method_name)
        assert hasattr(fn, "__wrapped__"), f"ArodonataClient.{method_name} missing @traced wrapper"

    # Dead code removal
    assert not hasattr(ArodonataSettings, "_CaptureExplicitAuthMode")
    for dead_helper in (
        "_cp_object_to_record",
        "_cp_service_to_record",
        "_asset_to_record",
        "_topology_entry_to_record",
        "_topology_annotation_to_record",
    ):
        assert not hasattr(cache_adapter, dead_helper)
        assert not hasattr(cache_mappers, dead_helper)
