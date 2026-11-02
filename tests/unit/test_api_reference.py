"""Unit tests for the bundled Check Point API Reference & Payload Validation Engine (`arodonata.api_reference`)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent

from arodonata import (
    ApiReferenceEngine,
    ArodonataClient,
    create_mcp_server,
    describe_api_command,
    get_api_reference,
    normalize_api_version,
    search_api_commands,
    validate_api_payload,
)


def test_default_bundled_index_lazy_singleton_and_meta() -> None:
    """Default bundled index loads lazily without network or DB and exposes expected metadata."""
    engine1 = get_api_reference()
    engine2 = ApiReferenceEngine.default()
    assert engine1 is engine2
    assert engine1.meta["latest"] == "v2.2"
    assert engine1.meta["versions"] == ["v1.9", "v2", "v2.1", "v2.2"]
    assert engine1.meta["commands_count"] > 1000
    assert engine1.meta["shared_objects_count"] > 500
    assert engine1.meta["enums_count"] > 300


def test_normalize_api_version() -> None:
    """Check Point version strings normalize across formats (1.9, v1.9.1, 2.0.1, v2.2)."""
    assert normalize_api_version(None) == "v2.2"
    assert normalize_api_version("") == "v2.2"
    assert normalize_api_version("1.9") == "v1.9"
    assert normalize_api_version("v1.9.1") == "v1.9"
    assert normalize_api_version("2") == "v2"
    assert normalize_api_version("2.0") == "v2"
    assert normalize_api_version("v2.0.1") == "v2"
    assert normalize_api_version("2.1") == "v2.1"
    assert normalize_api_version("2.2") == "v2.2"


def test_step_1_search_filters_by_version_crud_and_category() -> None:
    """Step 1 search filters commands by API version, CRUD type, and category."""
    # export-access-rulebase was added in v2.2
    v19_hits = search_api_commands("export-access-rulebase", version="v1.9")
    assert all(item["name"] != "export-access-rulebase" for item in v19_hits)

    v22_hits = search_api_commands("export-access-rulebase", version="v2.2")
    assert v22_hits
    assert v22_hits[0]["name"] == "export-access-rulebase"
    assert v22_hits[0]["added_in"] == "v2.2"
    assert "v2.2" in v22_hits[0]["supported_versions"]
    assert v22_hits[0]["short_description"]

    # Filter by crud_type and category
    host_adds = search_api_commands("host", crud_type="add", category="Network Objects", version="v2.2")
    assert any(item["name"] == "add-host" for item in host_adds)
    assert all(item["crud_type"] == "add" for item in host_adds)

    # Gaia family search
    gaia_hits = search_api_commands("interface", api_family="gaia")
    assert gaia_hits
    assert all(item["api_family"] == "gaia" for item in gaia_hits)


def test_step_2_describe_filters_fields_and_nested_objects_by_version() -> None:
    """Step 2 describe dynamically filters fields and nested objects by target version."""
    desc_v19 = describe_api_command("add-interface", version="v1.9")
    desc_v22 = describe_api_command("add-interface", version="v2.2")
    assert desc_v19 is not None
    assert desc_v22 is not None

    fields_v19 = {f["name"] for f in desc_v19["fields"]}
    fields_v22 = {f["name"] for f in desc_v22["fields"]}

    # v1.9-only fields on add-interface
    assert "gateway-owner" in fields_v19
    assert "anti-spoofing-enabled" in fields_v19
    assert "gateway-owner" not in fields_v22
    assert "anti-spoofing-enabled" not in fields_v22

    # v2+-only fields on add-interface
    assert "gateway-uid" in fields_v22
    assert "gateway-uid" not in fields_v19

    # Nested objects and enums are resolved
    assert "nested_objects" in desc_v22
    assert desc_v22["nested_objects"]
    assert "enums" in desc_v22
    assert "example" in desc_v22


def test_step_2_batch_describe_accepts_list_of_commands() -> None:
    """Batch describe accepts multiple command names and reports unknown or unsupported commands."""
    batch = describe_api_command(["add-host", "set-host", "export-access-rulebase", "no-such-cmd"], version="v1.9")
    assert batch is not None
    assert batch["target_version"] == "v1.9"
    assert "add-host" in batch["commands"]
    assert "set-host" in batch["commands"]
    assert "export-access-rulebase" not in batch["commands"]
    assert "export-access-rulebase" in batch["not_found"]
    assert "no-such-cmd" in batch["not_found"]


def test_step_3_validate_payload_catches_errors_and_accepts_valid_payloads() -> None:
    """Offline payload validation checks required fields, alternatives, enums, types, and version support."""
    # Valid add-host payload
    ok = validate_api_payload(
        "add-host", {"name": "web-01", "ip-address": "192.0.2.10", "color": "blue"}, version="v2.2"
    )
    assert ok["valid"] is True
    assert ok["error_count"] == 0
    assert ok["errors"] == []

    # Missing required fields + invalid enum color
    bad = validate_api_payload("add-host", {"color": "invalid-color"}, version="v2.2")
    assert bad["valid"] is False
    codes = {err["code"] for err in bad["errors"]}
    assert "missing_required_field" in codes
    assert "missing_alternative_group" in codes
    assert "invalid_enum_value" in codes

    # Conflicting alternatives (ip-address + ipv4-address together)
    conflict = validate_api_payload(
        "add-host",
        {"name": "web-01", "ip-address": "192.0.2.10", "ipv4-address": "192.0.2.10"},
        version="v2.2",
    )
    assert conflict["valid"] is False
    assert any(err["code"] == "conflicting_alternatives" for err in conflict["errors"])

    # Dual-stack ipv4-address + ipv6-address without ip-address is allowed
    dual_stack = validate_api_payload(
        "add-host",
        {"name": "web-01", "ipv4-address": "192.0.2.10", "ipv6-address": "2001:db8::10"},
        version="v2.2",
    )
    assert dual_stack["valid"] is True

    # Version-unsupported field (gateway-owner in v2.2 vs v1.9)
    ver_field = validate_api_payload(
        "add-interface",
        {"name": "eth0", "gateway-owner": "gw-01"},
        version="v2.2",
    )
    assert ver_field["valid"] is False
    assert any(
        err["code"] == "unsupported_field_version" and err["field"] == "gateway-owner" for err in ver_field["errors"]
    )

    # Version-unsupported command (export-access-rulebase in v1.9)
    ver_cmd = validate_api_payload("export-access-rulebase", {"name": "Network"}, version="v1.9")
    assert ver_cmd["valid"] is False
    assert ver_cmd["errors"][0]["code"] == "unsupported_command_version"

    # Unknown command returns suggestions
    unk_cmd = validate_api_payload("add-hst", {"name": "web-01"}, version="v2.2")
    assert unk_cmd["valid"] is False
    assert unk_cmd["errors"][0]["code"] == "unknown_command"

    # Invalid type (boolean field given int)
    bad_type = validate_api_payload(
        "add-host",
        {"name": "web-01", "ip-address": "192.0.2.10", "ignore-warnings": "not-a-bool"},
        version="v2.2",
    )
    assert bad_type["valid"] is False
    assert any(err["code"] == "invalid_type" and err["field"] == "ignore-warnings" for err in bad_type["errors"])


def test_from_path_loads_bundled_gzip() -> None:
    """ApiReferenceEngine.from_path loads a .json.gz file directly."""
    gz_path = (
        Path(__file__).resolve().parents[2] / "src" / "arodonata" / "api_reference" / "data" / "cp_api_index.json.gz"
    )
    custom = ApiReferenceEngine.from_path(gz_path)
    assert custom.meta["commands_count"] > 1000


def test_client_facade_infers_api_version_per_mgmt_name_and_fallbacks_to_latest() -> None:
    """ArodonataClient infers target API version from configured mgmt_name and falls back to v2.2."""
    client = ArodonataClient(
        mgmt_names=["corp-mds", "lab-mds"],
        mgmt_servers=["192.0.2.10", "192.0.2.20"],
        api_versions=["1.9", "2.1"],
    )
    assert client.api_reference is get_api_reference()

    # Inferred v1.9 from corp-mds
    desc_corp = client.describe_api_command("add-interface", mgmt_name="corp-mds")
    assert desc_corp is not None
    assert desc_corp["target_version"] == "v1.9"
    assert "gateway-owner" in {f["name"] for f in desc_corp["fields"]}

    # Inferred v2.1 from lab-mds
    desc_lab = client.describe_api_command("add-interface", mgmt_name="lab-mds")
    assert desc_lab is not None
    assert desc_lab["target_version"] == "v2.1"
    assert "gateway-uid" in {f["name"] for f in desc_lab["fields"]}

    # Fallback to v2.2 when mgmt_name is omitted on a multi-server client without global api_version
    desc_default = client.describe_api_command("add-interface")
    assert desc_default is not None
    assert desc_default["target_version"] == "v2.2"

    # Single-server client with api_version="1.9" infers v1.9 automatically even when mgmt_name=None
    single_client = ArodonataClient(
        mgmt_name="legacy-mgmt",
        mgmt_ip="192.0.2.30",
        api_version="1.9",
    )
    hits_single = single_client.search_api_commands("export-access-rulebase")
    assert all(h["name"] != "export-access-rulebase" for h in hits_single)

    val_single = single_client.validate_api_payload(
        "add-interface",
        {"name": "eth0", "gateway-owner": "gw-01"},
    )
    assert val_single["target_version"] == "v1.9"
    assert val_single["valid"] is True


def _parse_mcp_result(res: Any) -> dict[str, Any]:
    assert isinstance(res, CallToolResult)
    assert res.is_error is False
    assert res.content and isinstance(res.content[0], TextContent)
    parsed: dict[str, Any] = json.loads(res.content[0].text)
    return parsed


@pytest.mark.asyncio
async def test_mcp_api_reference_tool_search_describe_validate_and_version_inference() -> None:
    """MCP api_reference tool supports search, single/batch describe, validate, and mgmt_name version inference."""
    client = ArodonataClient(
        mgmt_names=["corp-mds", "modern-mds"],
        mgmt_servers=["192.0.2.10", "192.0.2.20"],
        api_versions=["1.9", "2.2"],
    )
    server = create_mcp_server(client, auth_mode="host")

    # 1. action="search"
    search_res = await server.call_tool(
        "api_reference",
        {"action": "search", "query": "host", "crud_type": "add", "limit": 5},
    )
    search_data = _parse_mcp_result(search_res)
    assert search_data["action"] == "search"
    assert search_data["target_version"] == "v2.2"
    assert any(c["name"] == "add-host" for c in search_data["commands"])

    # 2. action="describe" single command with version inference from mgmt_name="corp-mds" (v1.9)
    desc_v19_res = await server.call_tool(
        "api_reference",
        {"action": "describe", "command": "add-interface", "mgmt_name": "corp-mds"},
    )
    desc_v19 = _parse_mcp_result(desc_v19_res)
    assert desc_v19["action"] == "describe"
    assert desc_v19["target_version"] == "v1.9"
    assert "gateway-owner" in {f["name"] for f in desc_v19["fields"]}

    # 3. action="describe" batch command list
    batch_res = await server.call_tool(
        "api_reference",
        {"action": "describe", "command": ["add-host", "set-host"], "version": "v2.2"},
    )
    batch_data = _parse_mcp_result(batch_res)
    assert batch_data["action"] == "describe"
    assert "add-host" in batch_data["commands"]
    assert "set-host" in batch_data["commands"]

    # 4. action="validate" valid & invalid payloads
    val_ok_res = await server.call_tool(
        "api_reference",
        {
            "action": "validate",
            "command": "add-host",
            "payload": {"name": "web-01", "ip-address": "192.0.2.10"},
        },
    )
    val_ok = _parse_mcp_result(val_ok_res)
    assert val_ok["action"] == "validate"
    assert val_ok["valid"] is True
    assert val_ok["errors"] == []

    val_err_res = await server.call_tool(
        "api_reference",
        {
            "action": "validate",
            "command": "add-host",
            "payload": {"color": "invalid-color"},
        },
    )
    val_err = _parse_mcp_result(val_err_res)
    assert val_err["valid"] is False
    assert val_err["error_count"] >= 2

    # 5. Unknown command in describe returns ToolFailure (is_error=True) with suggestions
    missing_res = await server.call_tool(
        "api_reference",
        {"action": "describe", "command": "export-access-rulebase", "mgmt_name": "corp-mds"},
    )
    assert isinstance(missing_res, CallToolResult)
    assert missing_res.is_error is True

    # 6. Verify lookup_api_command prompt is registered
    prompts = await server.list_prompts()
    assert any(p.name == "lookup_api_command" for p in prompts)
