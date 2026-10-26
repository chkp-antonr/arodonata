"""MCP prompt templates for Check Point security policy exploration and auditing (`arodonata.mcp.prompts`)."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer


def register_mcp_prompts(server: MCPServer) -> None:
    """Register standard Check Point operational prompt templates on `server`."""

    @server.prompt(
        name="audit_access_rulebase",
        description="Guide an LLM agent through auditing a Check Point access rulebase using cached SmartConsole views.",
    )
    def audit_access_rulebase(
        mgmt_name: str = "default",
        domain: str = "",
        package: str = "Standard",
    ) -> str:
        dom_part = f" in domain '{domain}'" if domain else ""
        return (
            f"Audit the Check Point access rulebase for package '{package}' on server '{mgmt_name}'{dom_part}:\n"
            "1. Call `cache_control(action='status')` to check the freshness of the 'rulebase', 'objects', and 'services' scopes.\n"
            "2. Call `show_rulebase` with `rulebase_type='access'` and `format='model_friendly'` to inspect numbered rules.\n"
            "3. Highlight overly permissive rules (`Any -> Any [Any] => Accept`), disabled rules, and rules missing comments."
        )

    @server.prompt(
        name="investigate_ip_exposure",
        description="Investigate all network objects, groups, and access/NAT rules matching an IP address or subnet.",
    )
    def investigate_ip_exposure(
        ip_or_subnet: str,
        mgmt_name: str = "default",
        domain: str = "",
    ) -> str:
        dom_part = f" in domain '{domain}'" if domain else ""
        return (
            f"Investigate Check Point policy exposure for '{ip_or_subnet}' on server '{mgmt_name}'{dom_part}:\n"
            f"1. Call `search_objects(query='{ip_or_subnet}', include_global=True)` to find matching hosts, subnets, ranges, and parent groups.\n"
            f"2. Call `show_rulebase(rulebase_type='access', filter='{ip_or_subnet}', format='model_friendly')` to locate matching access rules.\n"
            f"3. Call `show_rulebase(rulebase_type='nat', filter='{ip_or_subnet}', format='model_friendly')` to locate matching NAT translations."
        )

    @server.prompt(
        name="summarize_recent_changes",
        description="Generate an auditable summary of published Check Point sessions and rule/object modifications.",
    )
    def summarize_recent_changes(
        mgmt_name: str = "default",
        domain: str = "",
        from_date: str = "",
    ) -> str:
        dom_part = f", domain='{domain}'" if domain else ""
        date_part = f", from_date='{from_date}'" if from_date else ""
        return (
            f"Summarize recent Check Point policy changes on server '{mgmt_name}'{dom_part}:\n"
            f"1. Call `change_report(mgmt_name='{mgmt_name}'{dom_part}{date_part}, format='markdown')`.\n"
            "2. Present each published session's administrator, publish timestamp, SmartConsole rule numbers, and field-level diffs."
        )


__all__ = [
    "register_mcp_prompts",
]
