"""Simple script to understand Check Point session management.

This script demonstrates:
1. Get current last published session (baseline)
2. Create a test host
3. Publish changes
4. Verify last published changed
5. Revert to saved baseline
6. Verify last published returned to original

Run: uv run examples/07_session_basics.py

Environment variables (examples/.env.lib):
    DATABASE_URL=sqlite+aiosqlite:///./_tmp/arodonata.db
    MGMT_NAMES=mgmt1
    MGMT_SERVERS=10.0.0.1
    API_KEY_VARS=MY_API_KEY_VAR
    ARODONATA_LOG_LEVEL=WARNING
"""

import asyncio
import os
import sys
from typing import Any

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings

# Configuration from environment variables
DOMAIN = "General"  # Default domain, can override if needed
MGMT_NAME: str = os.getenv("MGMT_NAMES", "").split(",")[0] if os.getenv("MGMT_NAMES") else ""

if not MGMT_NAME:
    print("ERROR: MGMT_NAMES not set in environment variables")
    print("Please set MGMT_NAMES in your .env.lib file")
    sys.exit(1)

TEST_HOST_NAME = "session-test-host"
TEST_HOST_IP = "192.168.250.250"


def _extract_time(time_field: Any) -> str:
    """Extract readable time from Check Point time field.

    Check Point returns time as a dict: {'posix': 123, 'iso-8601': '2026-07-22T20:29+0300'}
    """
    if not time_field:
        return "unknown"
    if isinstance(time_field, dict):
        iso_time = time_field.get("iso-8601", "")
        if iso_time:
            return iso_time
        return str(time_field)
    if isinstance(time_field, str):
        return time_field
    return str(time_field)


async def print_session_info(session_data: dict, title: str) -> None:
    """Print session information in a readable format."""
    print(f"\n{'=' * 60}")
    print(f"{title}")
    print(f"{'=' * 60}")

    if session_data:
        uid = session_data.get("uid", "unknown")
        name = session_data.get("name", "unknown")
        user_name = session_data.get("user-name", "unknown")
        changes = session_data.get("changes", 0)
        creation_time = _extract_time(session_data.get("creation-time"))
        publish_time = _extract_time(session_data.get("publish-time"))
        last_login = _extract_time(session_data.get("last-login-time"))
        state = session_data.get("state", "unknown")

        print(f"  UID:           {uid}")
        print(f"  Name:          {name}")
        print(f"  User:          {user_name}")
        print(f"  State:         {state}")
        print(f"  Changes:       {changes}")
        print(f"  Creation Time: {creation_time}")
        print(f"  Publish Time:  {publish_time}")
        if last_login != "unknown":
            print(f"  Last Login:    {last_login}")
    else:
        print("  ⚠ No session data available")


async def main() -> None:
    """Main session learning workflow."""
    print(f"Using database: {os.getenv('DATABASE_URL', 'sqlite+aiosqlite:///:memory:')}")
    print(f"Management server: {MGMT_NAME} (from MGMT_NAMES env var)")
    print(f"Domain: {DOMAIN}")

    # Load settings from environment
    settings = ArodonataSettings()

    # Create engine and client
    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=settings)

    try:
        async with client:
            # ============================================================
            # STEP 1: Get current last published session (BASELINE)
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 1: Get BASELINE (current last published session)")
            print(f"{'=' * 60}")

            baseline_result = await client.api_call(
                MGMT_NAME,
                "show-last-published-session",
                DOMAIN,
                payload={},
            )

            if baseline_result.success and baseline_result.data:
                baseline_session = baseline_result.data
                baseline_uid = baseline_session.get("uid", "")
                baseline_name = baseline_session.get("name", "unknown")

                await print_session_info(baseline_session, "CURRENT BASELINE (before any changes)")

                # Save baseline UID for later revert
                print(f"\n  ✓ Saved baseline UID: {baseline_uid[:16]}...")

            else:
                print(f"  ✗ Failed to get baseline: {baseline_result.message}")
                return

            # ============================================================
            # STEP 2: Create a test host
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 2: Create test host")
            print(f"{'=' * 60}")

            print(f"\n  Creating host: {TEST_HOST_NAME}")
            print(f"  IP Address: {TEST_HOST_IP}")

            create_result = await client.api_call(
                MGMT_NAME,
                "add-host",
                DOMAIN,
                payload={
                    "name": TEST_HOST_NAME,
                    "ip-address": TEST_HOST_IP,
                    "comments": "Test host for session learning",
                },
            )

            if create_result.success:
                print("  ✓ Host created successfully")
            else:
                print(f"  ✗ Failed to create host: {create_result.message}")
                return

            # ============================================================
            # STEP 3: Publish changes
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 3: Publish changes")
            print(f"{'=' * 60}")

            publish_result = await client.api_call(
                MGMT_NAME,
                "publish",
                DOMAIN,
                payload={},
                wait_for_task=True,
                timeout=300,  # 5 minutes timeout for publish
            )

            if publish_result.success:
                print("  ✓ Changes published successfully")
            else:
                print(f"  ✗ Failed to publish: {publish_result.message}")
                return

            # ============================================================
            # STEP 4: Verify last published CHANGED
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 4: Verify last published session changed")
            print(f"{'=' * 60}")

            await asyncio.sleep(2)  # Brief pause for propagation

            new_published_result = await client.api_call(
                MGMT_NAME,
                "show-last-published-session",
                DOMAIN,
                payload={},
            )

            if new_published_result.success and new_published_result.data:
                new_session = new_published_result.data
                new_uid = new_session.get("uid", "")

                await print_session_info(new_session, "NEW LAST PUBLISHED (after changes)")

                # Compare with baseline
                if new_uid != baseline_uid:
                    print("\n  ✓ Last published session CHANGED")
                    print(f"    Baseline UID: {baseline_uid[:16]}...")
                    print(f"    New UID:      {new_uid[:16]}...")
                else:
                    print("\n  ⚠ Last published session did NOT change (unexpected!)")
            else:
                print("  ✗ Failed to get new last published session")

            # ============================================================
            # STEP 5: REVERT to baseline
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 5: REVERT to baseline")
            print(f"{'=' * 60}")
            print(f"\n  Reverting to baseline: {baseline_name}")
            print("  This may take a couple of minutes...")

            # First discard any open sessions
            print("\n  Discarding open sessions...")
            discard_result = await client.api_call(
                MGMT_NAME,
                "discard",
                DOMAIN,
                payload={},
            )
            if discard_result.success:
                print("    ✓ Discarded open sessions")
            else:
                print(f"    Note: Discard returned: {discard_result.message[:100]}")

            # Now revert to baseline
            print("\n  Reverting to baseline session...")
            revert_result = await client.api_call(
                MGMT_NAME,
                "revert-to-revision",
                DOMAIN,
                payload={"to-session": baseline_uid},
                wait_for_task=True,
                timeout=300,  # 5 minutes timeout for revert
            )

            if revert_result.success:
                print("  ✓ Successfully reverted to baseline")
            else:
                print(f"  ✗ Failed to revert: {revert_result.message}")
                print("  ⚠ You may need to revert manually via SmartConsole")
                return

            # ============================================================
            # STEP 6: Verify last published RETURNED to baseline
            # ============================================================
            print(f"\n{'=' * 60}")
            print("STEP 6: Verify last published returned to baseline")
            print(f"{'=' * 60}")

            await asyncio.sleep(2)  # Brief pause for propagation

            final_published_result = await client.api_call(
                MGMT_NAME,
                "show-last-published-session",
                DOMAIN,
                payload={},
            )

            if final_published_result.success and final_published_result.data:
                final_session = final_published_result.data
                final_uid = final_session.get("uid", "")
                final_name = final_session.get("name", "unknown")

                await print_session_info(final_session, "FINAL LAST PUBLISHED (after revert)")

                # Verify we returned to baseline
                if final_uid == baseline_uid:
                    print("\n  ✅ SUCCESS: Last published returned to BASELINE!")
                    print(f"    Original UID: {baseline_uid[:16]}...")
                    print(f"    Current UID:  {final_uid[:16]}...")
                    print(f"    Session names match: {baseline_name == final_name}")
                else:
                    print("\n  ⚠ UNEXPECTED: Last published did NOT return to baseline")
                    print(f"    Expected UID: {baseline_uid[:16]}...")
                    print(f"    Got UID:      {final_uid[:16]}...")
            else:
                print("  ✗ Failed to get final last published session")

    finally:
        await engine.dispose()

    print(f"\n{'=' * 60}")
    print("SESSION LEARNING COMPLETED!")
    print(f"{'=' * 60}")
    print("\nYou now understand:")
    print("  1. How to get last published session (baseline)")
    print("  2. How to create objects")
    print("  3. How to publish changes")
    print("  4. How last published changes after publish")
    print("  5. How to revert to a specific session")
    print("  6. How to verify the revert worked")
    print("\nKey concepts:")
    print("  • last-published-session = current state")
    print("  • revert-to-revision needs logged-in session")
    print("  • revert takes time (can be several minutes)")
    print("  • revert returns to EXACT state - no cleanup needed!")
    print("  • Always verify operations completed successfully")


if __name__ == "__main__":
    asyncio.run(main())
