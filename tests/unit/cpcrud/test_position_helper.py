"""Position resolution: section-relative and cleanup-aware bottom (spec §9)."""

from unittest.mock import AsyncMock

import pytest

from arodonata.cpcrud.models import RuleMatch, SectionInfo
from arodonata.cpcrud.position_helper import resolve_nat_position, resolve_position


@pytest.mark.asyncio
async def test_plain_integer_position_passes_through():
    reader = AsyncMock()
    result = await resolve_position(reader, 3, "layer-u1", "access", mgmt="m", domain="d")
    assert result == {"position": 3}
    reader.get_section.assert_not_awaited()
    reader.get_last_rule.assert_not_awaited()


@pytest.mark.asyncio
async def test_plain_top_position_passes_through():
    reader = AsyncMock()
    result = await resolve_position(reader, "top", "layer-u1", "access", mgmt="m", domain="d")
    assert result == {"position": "top"}


@pytest.mark.asyncio
async def test_plain_bottom_with_no_cleanup_rule_passes_through():
    reader = AsyncMock()
    reader.get_last_rule.return_value = RuleMatch(
        uid="r1",
        name="normal-rule",
        rule_number=5,
        raw={"source": ["u1"], "destination": ["any"], "service": ["any"]},
    )
    result = await resolve_position(reader, "bottom", "layer-u1", "access", mgmt="m", domain="d")
    assert result == {"position": "bottom"}


@pytest.mark.asyncio
async def test_bottom_with_cleanup_rule_present_lands_one_above():
    reader = AsyncMock()
    reader.get_last_rule.return_value = RuleMatch(
        uid="r1",
        name="Cleanup Rule",
        rule_number=7,
        raw={
            "source": [{"name": "Any"}],
            "destination": [{"name": "Any"}],
            "service": [{"name": "Any"}],
            "action": "drop",
        },
    )
    result = await resolve_position(reader, "bottom", "layer-u1", "access", mgmt="m", domain="d")
    # Anchored on the cleanup rule, not its number: several rules added in one apply keep their order and section.
    assert result == {"position": {"above": "r1"}}


@pytest.mark.asyncio
async def test_cleanup_detection_ignores_action_accept_cleanup_counts_too():
    """Cleanup rules are Any/Any/Any regardless of action -- an Accept-based cleanup rule still counts."""
    reader = AsyncMock()
    reader.get_last_rule.return_value = RuleMatch(
        uid="r1",
        name="Accept Cleanup",
        rule_number=3,
        raw={
            "source": [{"name": "Any"}],
            "destination": [{"name": "Any"}],
            "service": [{"name": "Any"}],
            "action": "accept",
        },
    )
    result = await resolve_position(reader, "bottom", "layer-u1", "access", mgmt="m", domain="d")
    assert result == {"position": {"above": "r1"}}


@pytest.mark.asyncio
async def test_bottom_no_existing_rules_at_all_passes_through():
    reader = AsyncMock()
    reader.get_last_rule.return_value = None
    result = await resolve_position(reader, "bottom", "layer-u1", "access", mgmt="m", domain="d")
    assert result == {"position": "bottom"}


_CLEANUP = RuleMatch(
    uid="r-c",
    name="Cleanup rule",
    rule_number=6,
    raw={"source": [{"name": "Any"}], "destination": [{"name": "Any"}], "service": [{"name": "Any"}], "action": "Drop"},
)


@pytest.mark.asyncio
async def test_section_bottom_above_the_sections_cleanup_rule():
    """Backlog #40: `{"bottom": <section>}` would put the rule after the section's drop rule (home lab, discarded
    write: rule 8 after Cleanup rule 7); the cleanup rule's number puts it above, inside the section."""
    reader = AsyncMock()
    reader.get_section.return_value = SectionInfo(uid="s-c", name="Cleanup", layer_uid="layer-u1")
    reader.get_last_rule_in_section.return_value = _CLEANUP
    result = await resolve_position(reader, {"bottom": "Cleanup"}, "layer-u1", "access", mgmt="m", domain="d")
    reader.get_last_rule_in_section.assert_awaited_once_with("layer-u1", "s-c", "access", mgmt="m", domain="d")
    reader.get_last_rule.assert_not_awaited()  # show-*-rulebase refuses a section uid (home lab)
    assert result == {"position": {"above": "r-c"}}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "last",
    [
        None,
        RuleMatch(
            uid="r1", name="web", rule_number=3, raw={"source": ["u1"], "destination": ["any"], "service": ["any"]}
        ),
    ],
)
async def test_section_bottom_without_a_cleanup_rule_goes_to_the_sections_bottom(last):
    reader = AsyncMock()
    reader.get_section.return_value = SectionInfo(uid="s1", name="Web Section", layer_uid="layer-u1")
    reader.get_last_rule_in_section.return_value = last
    result = await resolve_position(reader, {"bottom": "Web Section"}, "layer-u1", "access", mgmt="m", domain="d")
    reader.get_section.assert_awaited_once_with("Web Section", "layer-u1", "access", mgmt="m", domain="d")
    assert result == {"position": {"bottom": "s1"}}


@pytest.mark.asyncio
async def test_section_relative_top_does_not_check_cleanup():
    reader = AsyncMock()
    reader.get_section.return_value = SectionInfo(uid="s1", name="Web Section", layer_uid="layer-u1")
    result = await resolve_position(reader, {"top": "Web Section"}, "layer-u1", "access", mgmt="m", domain="d")
    reader.get_last_rule.assert_not_awaited()
    assert result == {"position": {"top": "s1"}}


@pytest.mark.asyncio
async def test_section_not_found_raises_plan_time_error():
    from arodonata.core.exceptions import ConfigurationError

    reader = AsyncMock()
    reader.get_section.return_value = None
    with pytest.raises(ConfigurationError, match="Web Section"):
        await resolve_position(reader, {"bottom": "Web Section"}, "layer-u1", "access", mgmt="m", domain="d")


@pytest.mark.asyncio
async def test_above_below_rule_reference_passes_through_as_name():
    reader = AsyncMock()
    result = await resolve_position(reader, {"above": "some-rule"}, "layer-u1", "access", mgmt="m", domain="d")
    assert result == {"position": {"above": "some-rule"}}


# ---------------------------------------------------------------------------
# resolve_nat_position -- NAT counterpart: package-scoped, no layer/section concept,
# no cleanup-aware bottom (no implicit NAT cleanup rule), synchronous (no reader needed).
# ---------------------------------------------------------------------------


def test_nat_position_integer_passes_through():
    assert resolve_nat_position(3) == {"position": 3}


def test_nat_position_top_passes_through():
    assert resolve_nat_position("top") == {"position": "top"}


def test_nat_position_bottom_passes_through_no_cleanup_check():
    """Unlike access-rule's bottom, NAT's bottom is never cleanup-aware -- plain pass-through."""
    assert resolve_nat_position("bottom") == {"position": "bottom"}


def test_nat_position_above_rule_reference_passes_through_as_name():
    assert resolve_nat_position({"above": "some-nat-rule"}) == {"position": {"above": "some-nat-rule"}}


def test_nat_position_below_rule_reference_passes_through_as_name():
    assert resolve_nat_position({"below": "some-nat-rule"}) == {"position": {"below": "some-nat-rule"}}


def test_nat_position_section_relative_top_raises_hard_error():
    """NAT section resolution isn't implemented -- a section-relative position must fail loudly,
    not silently guess or misresolve."""
    from arodonata.core.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError, match="NAT_Section_1"):
        resolve_nat_position({"top": "NAT_Section_1"})


def test_nat_position_section_relative_bottom_raises_hard_error():
    from arodonata.core.exceptions import ConfigurationError

    with pytest.raises(ConfigurationError, match="not supported"):
        resolve_nat_position({"bottom": "NAT_Section_1"})
