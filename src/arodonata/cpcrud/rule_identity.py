"""Traffic-based rule identity: a rule's identity is its traffic, never its name."""

from __future__ import annotations

from arodonata.cpcrud.models import RuleMatch


def traffic_tuple(
    source_uids: list[str],
    dest_uids: list[str],
    service_uids: list[str],
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Order-independent identity for access/threat-prevention/https rules."""
    return (frozenset(source_uids), frozenset(dest_uids), frozenset(service_uids))


def nat_tuple(
    orig_src: str,
    orig_dst: str,
    orig_svc: str,
    xlate_src: str,
    xlate_dst: str,
    xlate_svc: str,
) -> tuple[str, str, str, str, str, str]:
    """Positional (NOT set-like) 6-tuple identity for nat-rule.

    Unlike traffic_tuple, position matters: original and translated sides are
    never interchangeable, so this is a plain tuple, not built from frozensets.
    """
    return (orig_src, orig_dst, orig_svc, xlate_src, xlate_dst, xlate_svc)


def pick_tie_break(candidates: list[RuleMatch], declared_name: str | None) -> RuleMatch:
    """When multiple rules share a traffic tuple: prefer the declared name, else topmost."""
    if declared_name:
        for c in candidates:
            if c.name == declared_name:
                return c
    return min(candidates, key=lambda c: c.rule_number)
