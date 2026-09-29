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
        {"mgmt_names": None, "cache_mode": None, "cache_ttl": None, "include_global": False},
    )


async def test_init_single_server_guidance_says_mgmt_name_optional():
    fake = FakeArodonataClient(["only"])
    out = payload(await call_tool(make_server(fake), "arodonata_init"))
    assert "optional" in out["guidance"]
