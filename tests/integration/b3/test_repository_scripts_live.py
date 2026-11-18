"""Bucket 3 — Live Check Point Script Repository lifecycle, execution, and baseline revert.

Gated under ``tests/integration/b3/`` (auto-marked ``integration`` and ``bucket_3``, so default
offline ``pytest`` runs deselect this module via ``-m "not integration"``).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from arodonata import (
    ArodonataClient,
    RepositoryScriptError,
    RepositoryScriptExecutionOutcome,
    RepositoryScriptNotFoundError,
    RepositoryScriptPermissionError,
)
from arodonata.core.models import normalize_script_body
from tests.integration.cp_revision import BaselineSnapshot, revert_domain_to

pytestmark = pytest.mark.cp_mutates


def _is_unsupported_repository_script_api(message: str | None) -> bool:
    """Return True if an API error indicates Check Point Management API < v1.9."""
    low = (message or "").lower()
    if "generic_err_command_not_found" in low or "command_not_found" in low or "not recognized" in low:
        return True
    return "command" in low and "not found" in low


def _pick_communicating_gateway(objects: list[dict[str, Any]]) -> str | None:
    """Return the first ``simple-gateway`` or ``CpmiHostCkp`` with communicating SIC."""
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        obj_type = str(obj.get("type") or "")
        if obj_type not in {"simple-gateway", "CpmiHostCkp"}:
            continue
        sic_state = str(obj.get("sic-state") or "").strip().lower()
        name = str(obj.get("name") or "").strip()
        if name and sic_state == "communicating":
            return name
    return None


async def test_repository_script_lifecycle_and_revert_to_baseline(
    antonr_client: ArodonataClient,
    apikey_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
    cp_baseline_snapshot: BaselineSnapshot,
) -> None:
    """Verify ``ensure/get/list/run/delete-repository-script`` and ``revert_domain_to`` cleanup."""
    tag = uuid.uuid4().hex[:6]
    script_name = f"it-b3-repo-script-{tag}"
    body_v1 = "#!/bin/bash\necho arodonata-v1\n"
    body_v2 = '#!/bin/bash\necho arodonata-v2 "$1"\n'

    # 1. Pre-check read-only status (skip gracefully on Management API < v1.9)
    try:
        initial = await apikey_client.check_repository_script(
            mgmt_name,
            script_name,
            domain=test_domain_a,
            expected_body=body_v1,
        )
    except RepositoryScriptError as exc:
        if _is_unsupported_repository_script_api(str(exc)):
            pytest.skip(f"Check Point Script Repository API not available on {mgmt_name}: {exc}")
        raise

    if not initial.exists and _is_unsupported_repository_script_api(initial.error):
        pytest.skip(f"Check Point Script Repository API not available on {mgmt_name}: {initial.error}")

    assert initial.exists is False
    assert initial.matches_expected is False

    base = cp_baseline_snapshot.domains[test_domain_a]
    try:
        # 2. Create repository script via ensure_repository_script
        created = await antonr_client.ensure_repository_script(
            mgmt_name,
            script_name,
            body_v1,
            domain=test_domain_a,
            comments="B3 repository-script test",
        )
        assert created.action == "created"
        assert created.published is True
        assert created.script.name == script_name

        # 3. Verify zero-write fast path across CRLF line-ending differences
        unchanged = await antonr_client.ensure_repository_script(
            mgmt_name,
            script_name,
            body_v1.replace("\n", "\r\n"),
            domain=test_domain_a,
        )
        assert unchanged.action == "unchanged"
        assert unchanged.published is False

        # 4. Update repository script body
        updated = await antonr_client.ensure_repository_script(
            mgmt_name,
            script_name,
            body_v2,
            domain=test_domain_a,
            comments="B3 repository-script updated",
        )
        assert updated.action == "updated"
        assert updated.published is True

        # 5. Fetch single script and list domain repository scripts
        fetched = await apikey_client.get_repository_script(
            mgmt_name,
            script_name,
            domain=test_domain_a,
        )
        assert fetched.name == script_name
        assert normalize_script_body(fetched.script_body) == normalize_script_body(body_v2)

        listed = await apikey_client.list_repository_scripts(
            mgmt_name,
            domain=test_domain_a,
        )
        assert any(item.name == script_name for item in listed)

        # 6. Optional live execution when a communicating gateway/host target exists
        gw_res = await apikey_client.api_call(
            mgmt_name,
            "show-gateways-and-servers",
            {"details-level": "standard", "limit": 50},
            domain=test_domain_a,
        )
        if gw_res.success and isinstance(gw_res.data, dict):
            target_gw = _pick_communicating_gateway(list(gw_res.data.get("objects") or []))
            if target_gw is not None:
                try:
                    outcome = await antonr_client.run_repository_script(
                        mgmt_name,
                        script_name,
                        [target_gw],
                        domain=test_domain_a,
                        args=["probe"],
                    )
                except RepositoryScriptPermissionError:
                    pass
                else:
                    assert isinstance(outcome, RepositoryScriptExecutionOutcome)
                    assert outcome.script_ref == script_name

        # 7. Delete repository script and verify absence
        deleted = await antonr_client.delete_repository_script(
            mgmt_name,
            script_name,
            domain=test_domain_a,
        )
        assert deleted is True

        with pytest.raises(RepositoryScriptNotFoundError):
            await apikey_client.get_repository_script(
                mgmt_name,
                script_name,
                domain=test_domain_a,
            )
    finally:
        reverted = await revert_domain_to(apikey_client, mgmt_name, base)
        assert reverted is True

    # 8. Confirm post-revert domain state has no leftover repository script
    post_revert = await apikey_client.check_repository_script(
        mgmt_name,
        script_name,
        domain=test_domain_a,
    )
    assert post_revert.exists is False
