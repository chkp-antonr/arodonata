from __future__ import annotations

from arodonata.cpcrud.models import Outcome, Plan, PlannedAction

from .fake_client import FakeArodonataClient
from .helpers import call_tool, make_server, payload, text, tool_names

TEMPLATE = {
    "management_servers": [
        {
            "name": "mgmt1",
            "domains": [{"name": "General", "objects": [{"type": "host", "name": "h1", "ip-address": "10.0.0.1"}]}],
        }
    ]
}


async def test_cpcrud_tools_absent_by_default_and_present_when_enabled():
    assert not {n for n in await tool_names(make_server(FakeArodonataClient())) if n.startswith("cpcrud_")}
    names = await tool_names(make_server(FakeArodonataClient(), cpcrud=True))
    assert {"cpcrud_validate", "cpcrud_plan", "cpcrud_apply", "cpcrud_inverse"} <= names


async def test_validate_returns_errors_list():
    fake = FakeArodonataClient()
    fake.cpcrud.validation_errors = ["objects[0]: 'ip-address' is invalid"]
    out = payload(await call_tool(make_server(fake, cpcrud=True), "cpcrud_validate", {"template": TEMPLATE}))
    assert out == {"valid": False, "errors": ["objects[0]: 'ip-address' is invalid"]}


async def test_plan_returns_plan_json_and_summary():
    fake = FakeArodonataClient()
    fake.cpcrud.plan_result = Plan(
        actions=[
            PlannedAction(
                id="a1",
                operation="add",
                type="host",
                mgmt_name="mgmt1",
                domain_name="General",
                outcome=Outcome.CREATE,
                resolved_name="h1",
            )
        ],
        template_hash="abc",
    )
    out = payload(
        await call_tool(make_server(fake, cpcrud=True), "cpcrud_plan", {"template": "management_servers: []"})
    )
    assert out["plan"]["template_hash"] == "abc" and out["summary"] == {"create": 1}
    assert out["actions"][0] == {
        "id": "a1",
        "operation": "add",
        "type": "host",
        "name": "h1",
        "outcome": "create",
        "mgmt_name": "mgmt1",
        "domain": "General",
    }


async def test_apply_defaults_to_dry_run_and_accepts_plan_json():
    fake = FakeArodonataClient()
    plan = Plan(template_hash="abc").model_dump(mode="json")
    out = payload(await call_tool(make_server(fake, cpcrud=True), "cpcrud_apply", {"plan": plan}))
    assert out["dry_run"] is True and out["report"]["summary"] == {"create": 1} and out["events"] == ["applying"]
    name, kw = fake.cpcrud.calls[0]
    assert name == "apply" and kw["dry_run"] is True and isinstance(kw["plan_or_template"], Plan)


async def test_apply_real_run_requires_explicit_flag_and_passes_options():
    fake = FakeArodonataClient()
    await call_tool(
        make_server(fake, cpcrud=True),
        "cpcrud_apply",
        {"template": TEMPLATE, "dry_run": False, "no_publish": True, "session_name": "mcp-change"},
    )
    kw = fake.cpcrud.calls[0][1]
    assert (
        kw["dry_run"] is False
        and kw["no_publish"] is True
        and kw["session_name"] == "mcp-change"
        and kw["plan_or_template"] == TEMPLATE
    )


async def test_apply_requires_plan_or_template():
    res = await call_tool(make_server(FakeArodonataClient(), cpcrud=True), "cpcrud_apply", {})
    assert res.is_error is True and "plan or template" in text(res)


async def test_inverse_round_trips_plan_json():
    fake = FakeArodonataClient()
    out = payload(
        await call_tool(
            make_server(fake, cpcrud=True),
            "cpcrud_inverse",
            {"plan": Plan(template_hash="abc").model_dump(mode="json")},
        )
    )
    assert out == {"template": {"management_servers": []}} and isinstance(fake.cpcrud.calls[0][1]["plan"], Plan)


async def test_validate_never_reads_a_server_side_file_path():
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake, cpcrud=True), "cpcrud_validate", {"template": __file__})
    assert res.is_error is True and "must be a YAML or JSON object" in text(res)
    assert fake.cpcrud.calls == []


async def test_plan_and_apply_reject_path_strings_without_calling_cpcrud():
    fake = FakeArodonataClient()
    server = make_server(fake, cpcrud=True)
    for tool in ("cpcrud_plan", "cpcrud_apply"):
        res = await call_tool(server, tool, {"template": __file__})
        assert res.is_error is True and "must be a YAML or JSON object" in text(res)
    assert fake.cpcrud.calls == []


async def test_invalid_yaml_string_is_a_tool_failure():
    fake = FakeArodonataClient()
    res = await call_tool(make_server(fake, cpcrud=True), "cpcrud_validate", {"template": "a: [unclosed"})
    assert res.is_error is True and "must be a YAML or JSON object" in text(res)
    assert fake.cpcrud.calls == []


async def test_yaml_string_template_reaches_cpcrud_as_dict():
    fake = FakeArodonataClient()
    server = make_server(fake, cpcrud=True)
    await call_tool(server, "cpcrud_validate", {"template": "management_servers: []"})
    await call_tool(server, "cpcrud_plan", {"template": "management_servers: []"})
    await call_tool(server, "cpcrud_apply", {"template": '{"management_servers": []}'})
    assert fake.cpcrud.calls[0] == ("validate", {"template": {"management_servers": []}})
    assert fake.cpcrud.calls[1] == ("plan", {"template": {"management_servers": []}})
    assert fake.cpcrud.calls[2][1]["plan_or_template"] == {"management_servers": []}


async def test_invalid_conflict_policy_names_valid_values():
    fake = FakeArodonataClient()
    server = make_server(fake, cpcrud=True)
    res = await call_tool(server, "cpcrud_plan", {"template": TEMPLATE, "on_name_conflict": "bogus"})
    assert res.is_error is True and "update, error" in text(res) and "internal" not in text(res)
    res = await call_tool(server, "cpcrud_plan", {"template": TEMPLATE, "on_ip_conflict": "bogus"})
    assert res.is_error is True and "reuse, create_new, error" in text(res)
    assert fake.cpcrud.calls == []
