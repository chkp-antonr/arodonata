"""Starter offline replay test verifying ArodonataClient asset/object retrieval via FileReplayApiMock."""

from __future__ import annotations

import arlogi
import pytest

from arodonata import (
    ArodonataClient,
    ArodonataSettings,
    classify_asset_platform,
    classify_asset_role,
)
from arodonata.testing import FileReplayApiMock


@pytest.mark.asyncio
async def test_offline_replay_inventory_and_classification() -> None:
    """Verify domain/gateway/host retrieval and native Asset classification offline against FileReplayApiMock."""
    logger = arlogi.get_logger(__name__)
    api_mock = FileReplayApiMock()
    settings = ArodonataSettings(
        mgmt_name="mds-replay",
        mgmt_ip="127.0.0.1",
        api_key="offline-replay-placeholder",
    )

    async with ArodonataClient(settings=settings, api=api_mock) as client:
        domains = await client.get_domains("mds-replay")
        domain_names = [domain.name for domain in domains]
        assert "Branch" in domain_names

        clusters = await client.get_gateways("mds-replay", "Branch", roles=["cluster"])
        members = await client.get_gateways("mds-replay", "Branch", roles=["cluster_member"])
        assert clusters
        assert members
        assert all(asset.is_policy_target and not asset.is_execution_target for asset in clusters)
        assert all(asset.is_execution_target and not asset.is_policy_target for asset in members)

        hosts = await client.get_hosts("mds-replay", "Branch")
        assert hosts

        assert classify_asset_role({"type": "CpmiVsxClusterNetobj"}) == "vsx_cluster"
        assert classify_asset_platform({"os-name": "Gaia Embedded", "hardware": "Quantum Spark"}) == "gaia_embedded"

        logger.info(
            "offline replay verification completed",
            domain="Branch",
            clusters=len(clusters),
            members=len(members),
            hosts=len(hosts),
        )

    api_mock.assert_no_global_mutations()
