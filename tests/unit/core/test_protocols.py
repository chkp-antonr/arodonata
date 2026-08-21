"""Unit tests for the core protocol definitions.

Exercises the runtime-checkable structural conformance of every
``Protocol`` in :mod:`arodonata.core.protocols`, the ``RefreshMode`` enum,
the plain data-holder classes, and the default (``...``) method bodies
so that a concrete subclass can call each inherited stub.
"""

from typing import get_type_hints

from arodonata.core.protocols import (
    IApiTransport,
    ICacheRepository,
    ILoginCoordinator,
    IRateLimiter,
    IServerRegistry,
    RawApiResponse,
    RefreshMode,
    ServerConfig,
    SIDRecord,
)

# ---------------------------------------------------------------------------
# RefreshMode
# ---------------------------------------------------------------------------


def test_refresh_mode_values():
    assert RefreshMode.SKIP == "skip"
    assert RefreshMode.CHECK == "check"
    assert RefreshMode.FORCE == "force"


def test_refresh_mode_is_str_enum():
    assert isinstance(RefreshMode.SKIP, str)
    assert RefreshMode("check") is RefreshMode.CHECK


def test_refresh_mode_membership():
    assert {m.value for m in RefreshMode} == {"skip", "check", "force", "incremental"}


def test_refresh_mode_incremental_member():
    from arodonata.core.protocols import RefreshMode

    assert RefreshMode.INCREMENTAL == "incremental"
    assert RefreshMode("incremental") is RefreshMode.INCREMENTAL
    assert {m.value for m in RefreshMode} == {"skip", "check", "force", "incremental"}


# ---------------------------------------------------------------------------
# RawApiResponse alias + data holders
# ---------------------------------------------------------------------------


def test_raw_api_response_is_dict_alias():
    payload: RawApiResponse = {"key": "value"}
    assert isinstance(payload, dict)


def test_server_config_is_instantiable_with_annotations():
    cfg = ServerConfig()
    cfg.name = "mgmt1"
    cfg.server_ip = "10.0.0.1"
    cfg.is_mdm = True
    cfg.version = "R81.20"
    assert cfg.name == "mgmt1"
    assert "name" in get_type_hints(ServerConfig)


def test_sid_record_is_instantiable_with_annotations():
    rec = SIDRecord()
    rec.sid = "abc"
    rec.server_ip = "10.0.0.1"
    assert rec.sid == "abc"
    assert "created_at" in get_type_hints(SIDRecord)


# ---------------------------------------------------------------------------
# runtime-checkable structural conformance
# ---------------------------------------------------------------------------


def test_cache_repository_structural_conformance():
    class Conforming:
        async def get_sid(self, *a, **k): ...
        async def set_sid(self, *a, **k): ...
        async def delete_sid(self, *a, **k): ...
        async def clear_sessions(self, *a, **k): ...
        async def get_assets(self, *a, **k): ...
        async def upsert_asset(self, *a, **k): ...
        async def upsert_assets(self, *a, **k): ...
        async def initialize(self): ...
        async def close(self): ...

    assert isinstance(Conforming(), ICacheRepository)


def test_cache_repository_rejects_non_conforming():
    class Missing:
        async def get_sid(self, *a, **k): ...

    assert not isinstance(Missing(), ICacheRepository)


def test_api_transport_structural_conformance():
    class Conforming:
        async def api_call(self, *a, **k): ...
        async def api_query(self, *a, **k): ...

    assert isinstance(Conforming(), IApiTransport)
    assert not isinstance(object(), IApiTransport)


def test_server_registry_structural_conformance():
    class Conforming:
        def get_server(self, name): ...
        def get_names(self): ...
        def update_metadata(self, name, **k): ...

    assert isinstance(Conforming(), IServerRegistry)
    assert not isinstance(object(), IServerRegistry)


def test_rate_limiter_structural_conformance():
    class Conforming:
        def acquire(self, server_ip): ...

    assert isinstance(Conforming(), IRateLimiter)
    assert not isinstance(object(), IRateLimiter)


def test_login_coordinator_structural_conformance():
    class Conforming:
        async def login(self, *a, **k): ...

    assert isinstance(Conforming(), ILoginCoordinator)
    assert not isinstance(object(), ILoginCoordinator)


# ---------------------------------------------------------------------------
# default (``...``) method bodies via concrete subclasses
# ---------------------------------------------------------------------------


async def test_cache_repository_default_method_bodies_return_none():
    class Concrete(ICacheRepository):
        pass

    repo = Concrete()
    assert await repo.get_sid("m", "d") is None
    assert await repo.set_sid("m", "d", "sid", "ip") is None
    assert await repo.delete_sid("m", "d") is None
    assert await repo.clear_sessions() is None
    assert await repo.get_assets() is None
    assert await repo.upsert_asset(object()) is None
    assert await repo.upsert_assets([]) is None
    assert await repo.initialize() is None
    assert await repo.close() is None


async def test_api_transport_default_method_bodies_return_none():
    class Concrete(IApiTransport):
        pass

    transport = Concrete()
    assert await transport.api_call("ip", "sid", "cmd") is None
    assert await transport.api_query("ip", "sid", "cmd") is None


def test_server_registry_default_method_bodies_return_none():
    class Concrete(IServerRegistry):
        pass

    reg = Concrete()
    assert reg.get_server("mgmt1") is None
    assert reg.get_names() is None
    assert reg.update_metadata("mgmt1", is_mdm=True, version="R81") is None


async def test_rate_limiter_default_context_manager_yields():
    class Concrete(IRateLimiter):
        pass

    entered = False
    async with Concrete().acquire("10.0.0.1"):
        entered = True
    assert entered is True


async def test_login_coordinator_default_method_body_returns_none():
    class Concrete(ILoginCoordinator):
        pass

    assert await Concrete().login("mgmt1", "domain") is None


def test_protocols_are_runtime_checkable():
    # runtime_checkable protocols expose _is_runtime_protocol.
    for proto in (
        ICacheRepository,
        IApiTransport,
        IServerRegistry,
        IRateLimiter,
        ILoginCoordinator,
    ):
        assert getattr(proto, "_is_runtime_protocol", False) is True


def test_module_all_exports() -> None:
    from arodonata.core import protocols

    expected: set[str] = {
        "ICacheRepository",
        "IApiTransport",
        "IServerRegistry",
        "IRateLimiter",
        "ILoginCoordinator",
        "RawApiResponse",
        "ServerConfig",
        "SIDRecord",
        "RefreshMode",
    }
    assert set(protocols.__all__) == expected
