"""Traffic-based rule identity (FPCR/MMP semantics, redesigned per spec §6)."""

from arodonata.cpcrud.models import RuleMatch
from arodonata.cpcrud.rule_identity import nat_tuple, pick_tie_break, traffic_tuple


def test_traffic_tuple_order_independent():
    t1 = traffic_tuple(["u1", "u2"], ["u3"], ["u4"])
    t2 = traffic_tuple(["u2", "u1"], ["u3"], ["u4"])
    assert t1 == t2


def test_traffic_tuple_distinguishes_different_sets():
    t1 = traffic_tuple(["u1"], ["u3"], ["u4"])
    t2 = traffic_tuple(["u1", "u2"], ["u3"], ["u4"])
    assert t1 != t2


def test_traffic_tuple_shape():
    t = traffic_tuple(["u1"], ["u2"], ["u3"])
    assert t == (frozenset({"u1"}), frozenset({"u2"}), frozenset({"u3"}))


def test_nat_tuple_is_positional_not_setlike():
    t1 = nat_tuple("s1", "d1", "svc1", "s2", "d2", "svc2")
    t2 = nat_tuple("d1", "s1", "svc1", "s2", "d2", "svc2")  # swapped orig src/dst
    assert t1 != t2  # NAT tuple is positional -- unlike traffic_tuple, order matters


def test_nat_tuple_any_literal_preserved():
    t = nat_tuple("Any", "d1", "svc1", "s2", "d2", "svc2")
    assert t[0] == "Any"


def test_pick_tie_break_prefers_declared_name_match():
    candidates = [
        RuleMatch(uid="u1", name="rule-a", rule_number=5, raw={}),
        RuleMatch(uid="u2", name="rule-b", rule_number=2, raw={}),
    ]
    winner = pick_tie_break(candidates, declared_name="rule-b")
    assert winner.uid == "u2"


def test_pick_tie_break_falls_back_to_lowest_rule_number():
    candidates = [
        RuleMatch(uid="u1", name="rule-a", rule_number=5, raw={}),
        RuleMatch(uid="u2", name="rule-b", rule_number=2, raw={}),
    ]
    winner = pick_tie_break(candidates, declared_name=None)
    assert winner.uid == "u2"


def test_pick_tie_break_no_name_declared_still_uses_lowest_number():
    candidates = [
        RuleMatch(uid="u1", name="rule-a", rule_number=9, raw={}),
        RuleMatch(uid="u2", name="rule-b", rule_number=1, raw={}),
        RuleMatch(uid="u3", name="rule-c", rule_number=4, raw={}),
    ]
    winner = pick_tie_break(candidates, declared_name="no-such-name")
    assert winner.uid == "u2"


def test_pick_tie_break_single_candidate():
    candidates = [RuleMatch(uid="u1", name="only", rule_number=1, raw={})]
    assert pick_tie_break(candidates, declared_name=None).uid == "u1"
