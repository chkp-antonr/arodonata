from __future__ import annotations

import inspect

from arodonata.api.client import ArodonataClient
from arodonata.api.services.rulebase_reader import RulebaseCaller, read_domain

PROTOCOL = {
    "api_call": {"mgmt_name", "domain", "command", "payload"},
    "api_query": {"mgmt_name", "domain", "command", "details_level", "container_key"},
}


def _accepts(cls: type, method: str) -> set[str]:
    params = inspect.signature(getattr(cls, method)).parameters
    return {n for n, p in params.items() if p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD)}


def test_client_and_sid_caller_satisfy_rulebase_caller():
    from arodonata.api.services.live_rulebase_source import SidCaller

    for cls in (ArodonataClient, SidCaller):  # mypy checks the real uses in src/ (read_domain(self._client, ...))
        for method, names in PROTOCOL.items():
            assert names <= _accepts(cls, method), f"{cls.__name__}.{method}"
    assert {n for n in dir(RulebaseCaller) if not n.startswith("_")} == set(PROTOCOL)


async def test_read_domain_with_packages_skips_listings_and_reads_only_their_layers():
    from tests.unit.rulebase.fakes import domain4_fake

    fake = domain4_fake()
    other = {
        "uid": "pkg-other",
        "name": "Other",
        "type": "package",
        "access": True,
        "nat-policy": True,
        "access-layers": [{"uid": "layer-of-other", "name": "Other Network", "domain": {"domain-type": "domain"}}],
    }
    fake.listings["show-packages"] = [*fake.listings["show-packages"], other]
    warnings: list[str] = []
    layouts, layers = await read_domain(fake, "m1", "Domain4", warnings, packages={"FPCR_UAT_Active"})
    assert [p.package_name for p in layouts] == ["FPCR_UAT_Active"] and warnings == []
    assert [c["command"] for c in fake.query_calls] == ["show-packages"]  # no show-*-layers listings
    read = {body.get("uid") or body.get("name") or body.get("package") for _, body in fake.calls}
    assert "layer-of-other" not in read and "Other" not in read
    full, _ = await read_domain(domain4_fake(), "m1", "Domain4", [])
    assert [(p.package_name, p.layers) for p in full] == [(p.package_name, p.layers) for p in layouts]
