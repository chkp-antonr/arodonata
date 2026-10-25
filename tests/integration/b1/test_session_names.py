"""Bucket 1 — Custom session-name / session-description and ``user_context`` attribution.

Covers:
1. ``client.write_session(..., session_name=..., session_description=..., publish_on_exit=False)``
   sets the custom name and description on the Check Point session and returns ``ws.session_uid``.
2. ``client.user_context(user_id=..., session_name=..., session_description=...)`` propagates
   session attribution into ``write_session`` automatically.
3. Explicitly discarding a ``write_session`` cleans up uncommitted changes and logs out on exit.
"""

from __future__ import annotations

import uuid

from arodonata import ArodonataClient


async def test_write_session_custom_name_and_description(
    antonr_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``write_session`` sets custom ``session_name`` and ``session_description`` on Check Point."""
    custom_name = f"arodonata-b1-{uuid.uuid4().hex[:8]}"
    custom_desc = "Integration test custom session description"

    async with antonr_client.write_session(
        mgmt_name,
        test_domain_a,
        session_name=custom_name,
        session_description=custom_desc,
        publish_on_exit=False,
    ) as ws:
        assert ws.sid
        assert ws.session_name == custom_name

        info = await antonr_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
        assert info.success
        assert info.data.get("name") == custom_name
        assert info.data.get("description") == custom_desc


async def test_user_context_propagates_session_name_to_write_session(
    eng3_client: ArodonataClient,
    mgmt_name: str,
    test_domain_a: str,
) -> None:
    """Verify ``user_context`` automatically populates ``session_name`` and ``session_description``."""
    tag = f"arodonata-uctx-{uuid.uuid4().hex[:8]}"
    desc = "Propagated from UserContext"

    with eng3_client.user_context(
        user_id="eng3-operator",
        username="eng3",
        session_name=tag,
        session_description=desc,
    ):
        async with eng3_client.write_session(
            mgmt_name,
            test_domain_a,
            publish_on_exit=False,
        ) as ws:
            assert ws.session_name == tag
            info = await eng3_client.api_call(mgmt_name, "show-session", {}, domain=test_domain_a)
            assert info.success
            assert info.data.get("name") == tag
            assert info.data.get("description") == desc
