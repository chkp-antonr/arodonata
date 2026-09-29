from __future__ import annotations

from mcp.client import Client

from .fake_client import FakeArodonataClient
from .helpers import make_server


async def test_prompts_registered_and_render_arguments():
    server = make_server(FakeArodonataClient())
    async with Client(server) as client:
        names = {p.name for p in (await client.list_prompts()).prompts}
        assert {
            "show_gateways_prompt",
            "show_policies_prompt",
            "show_rule_prompt",
            "topology_visualization_prompt",
            "source_to_destination_prompt",
        } <= names
        res = await client.get_prompt("source_to_destination_prompt", {"source": "10.1.2.7", "destination": "internet"})
        body = res.messages[0].content.text  # type: ignore[union-attr]
        assert "10.1.2.7" in body and "internet" in body and "show_access_rulebase" in body and "arodonata_init" in body
        rule = await client.get_prompt("show_rule_prompt", {"rule_ref": "rule 12"})
        assert "rule 12" in rule.messages[0].content.text  # type: ignore[union-attr]


async def test_every_prompt_publishes_a_sentence_description():
    server = make_server(FakeArodonataClient())
    async with Client(server) as client:
        prompts = (await client.list_prompts()).prompts
    assert prompts
    for prompt in prompts:
        description = prompt.description or ""
        assert description.endswith(".") and description != prompt.name.replace("_", " "), (prompt.name, description)
