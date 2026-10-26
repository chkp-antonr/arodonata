# CPCRUD Quickstart

`client.cpcrud` (`CPCRUDService`) is Arodonata's declarative Policy-as-Code engine. It takes a YAML or JSON template describing desired objects, services, groups, sections, and rules, computes an idempotent execution plan against cached + live state, applies changes in an isolated session per domain, and can generate a compensating rollback template (`inverse`).

## 1. Define a Declarative Template

```yaml
version: 1
mgmt_name: "mdsm-prod"
domain: "Domain4"
on_name_conflict: "update"
on_ip_conflict: "reuse"

objects:
  - type: "host"
    name: "web-srv-01"
    ipv4-address: "198.51.100.10"
    comments: "Managed by Arodonata CPCRUD"
    color: "dark green"

services:
  - type: "service-tcp"
    name: "tcp-8443"
    port: "8443"

groups:
  - type: "group"
    name: "grp-web-servers"
    members:
      - "web-srv-01"

rules:
  - type: "access-rule"
    layer: "Standard Network"
    position: "bottom"
    name: "allow-web-8443"
    source: ["Any"]
    destination: ["grp-web-servers"]
    service: ["tcp-8443"]
    rule_action: "Accept"
    track: "Log"
```

## 2. Validate, Plan, Apply, and Roll Back

```python
import asyncio
from pathlib import Path
from arodonata import ArodonataClient


async def main() -> None:
    template_text = Path("examples/crud_example.yaml").read_text(encoding="utf-8")

    async with ArodonataClient() as client:
        # Step 1: Offline JSON Schema validation (zero network or DB calls)
        errors = client.cpcrud.validate(template_text)
        if errors:
            raise ValueError(f"Invalid template: {errors}")

        # Step 2: Plan (captures DomainStamp and resolves diffs via HybridStateReader)
        plan = await client.cpcrud.plan(template_text)
        for action in plan.actions:
            print(f"[{action.outcome}] {action.object_type} {action.name} -> {action.command}")

        # Step 3: Apply (verifies DomainStamp hasn't drifted, executes in isolated WriteSession, publishes)
        report = await client.cpcrud.apply(plan)
        print(f"Applied: success={report.success}, published={report.published}")

        # Step 4: Generate a compensating rollback template from (plan, report)
        rollback_template = client.cpcrud.inverse(plan, report)
        rollback_plan = await client.cpcrud.plan(rollback_template)
        rollback_report = await client.cpcrud.apply(rollback_plan)
        print(f"Rolled back: success={rollback_report.success}")


if __name__ == "__main__":
    asyncio.run(main())
```

## 3. Staged Sessions (Human-in-the-Loop Approval)

When integrating into approval workflows (or MCP agent workflows), pass `no_publish=True, keep_session=True` to `apply()`. This leaves the Check Point session open and returns `StagedSessionInfo` (`session_uid`) in `report.staged_sessions`.

Later, once approved or rejected, finalize the session by its `session_uid`:

```python
# Approve and publish (adopts via take-over-session, publishes, logs out, and invalidates domain cache)
await client.publish_staged_session("mdsm-prod", "Domain4", session_uid=staged.session_uid)

# Or reject and discard cleanly
await client.discard_staged_session("mdsm-prod", "Domain4", session_uid=staged.session_uid)
```
