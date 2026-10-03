from __future__ import annotations

from arodonata.models import Domain

from .fake_client import FakeArodonataClient
from .helpers import call_tool, make_server, payload


def _domain(name: str, mgmt: str = "mgmt1", mdm: bool = True) -> Domain:
    return Domain(
        uid=f"d-{name}",
        name=name,
        active_mds="mds1",
        active_ip="10.0.0.1",
        active_server="mds1",
        mgmt_name=mgmt,
        is_mdm=mdm,
    )


async def test_init_reports_servers_domains_and_cache_age():
    fake = FakeArodonataClient(["mgmt1", "mgmt2"])
    fake.responses["get_domains"] = [_domain("General"), _domain("Finance"), _domain("Solo", mgmt="mgmt2", mdm=False)]
    res = await call_tool(make_server(fake), "arodonata_init")
    assert res.is_error is False
    out = payload(res)
    servers = {s["mgmt_name"]: s for s in out["servers"]}
    assert servers["mgmt1"]["is_mds"] is True and servers["mgmt1"]["domains"] == ["General", "Finance"]
    assert servers["mgmt2"]["is_mds"] is False
    assert out["cache_age_seconds"] == 90
    assert "mgmt_name" in out["guidance"]
    assert fake.calls[0] == (
        "get_domains",
        # every configured server explicitly: get_domains without mgmt refreshes only the first server's list
        {"mgmt_names": ["mgmt1", "mgmt2"], "cache_mode": None, "cache_ttl": None, "include_global": False},
    )


async def test_init_single_server_guidance_says_mgmt_name_optional():
    fake = FakeArodonataClient(["only"])
    out = payload(await call_tool(make_server(fake), "arodonata_init"))
    assert "optional" in out["guidance"]


async def test_init_reports_a_running_background_warm_up_and_says_so_in_the_guidance():
    """Without this the model read cache_age_seconds=null as "empty, loads on first use" while the load was running."""
    from datetime import UTC, datetime, timedelta

    from arodonata.api.schemas import ObjectCacheWarmUp

    fake = FakeArodonataClient(["mgmt1", "mgmt2"])
    fake.responses["get_domains"] = [_domain("General")]
    fake.warm_ups["mgmt1"] = ObjectCacheWarmUp(state="running", started_at=datetime.now(UTC) - timedelta(seconds=30))
    out = payload(await call_tool(make_server(fake), "arodonata_init"))
    servers = {s["mgmt_name"]: s for s in out["servers"]}
    warm = servers["mgmt1"]["object_cache_warm_up"]
    assert warm["state"] == "running" and 29 <= warm["running_seconds"] <= 60
    assert "object_cache_warm_up" not in servers["mgmt2"]
    assert "being loaded in the background" in out["guidance"] and "mgmt1" in out["guidance"]


async def test_init_reports_a_finished_warm_up_with_its_counts():
    from datetime import UTC, datetime

    from arodonata.api.schemas import ObjectCacheWarmUp

    fake = FakeArodonataClient(["mgmt1"])
    now = datetime.now(UTC)
    fake.warm_ups["mgmt1"] = ObjectCacheWarmUp(
        state="finished", started_at=now, finished_at=now, refreshed_domains=11, failed_domains=1
    )
    out = payload(await call_tool(make_server(fake), "arodonata_init"))
    warm = out["servers"][0]["object_cache_warm_up"]
    assert warm == {"state": "finished", "refreshed_domains": 11, "failed_domains": 1}
    assert "being loaded in the background" not in out["guidance"]
