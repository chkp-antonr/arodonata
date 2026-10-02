from __future__ import annotations

from arodonata.reports.changes.build import build_session
from arodonata.reports.changes.names import NameBudget, resolve_names
from tests.unit.reports.entries import entry, group, host, modified, session_meta
from tests.unit.reports.fakes import FakeReportClient


def _built(members_after):
    e = entry(
        session_meta("s1"),
        added=[host("h2", "host-two")],
        modified=[modified(group("g1", "grp", ["h1"]), group("g1", "grp", ["h1", *members_after]))],
    )
    return [(build_session(e), e)]


def _added_names(sessions):
    g = next(o for o in sessions[0].objects if o.uid == "g1")
    return [r.name for c in g.changes for r in c.added]


async def test_group_member_names_resolved_or_uid_fallback():
    fake = FakeReportClient()
    fake.object_names = {"h3": "host-three"}
    sessions, warning = await resolve_names(fake, "m1", "Domain4", _built(["h2", "h3", "h4"]), NameBudget(), 4)
    assert _added_names(sessions) == ["host-two", "host-three", "h4"]
    looked_up = sorted(c[1]["uid"] for c in fake.calls if c[0] == "show-object")
    assert looked_up == ["h3", "h4"]  # h2 came from the session's own entries
    assert all(c[1]["details_level"] == "standard" and c[1]["domain"] == "Domain4" for c in fake.calls)
    assert warning is not None and warning.code == "names_unresolved" and warning.message.startswith("1 ")


async def test_name_lookup_failure_warns_names_unresolved():
    fake = FakeReportClient()
    fake.object_names = {"h3": "host-three"}
    fake.object_failures = {"h3"}
    sessions, warning = await resolve_names(fake, "m1", "Domain4", _built(["h3"]), NameBudget(), 4)
    assert _added_names(sessions) == ["h3"]
    assert warning is not None and (warning.mgmt, warning.domain, warning.message[:2]) == ("m1", "Domain4", "1 ")


async def test_name_lookup_capped():
    fake = FakeReportClient()
    fake.object_names = {"a": "A", "b": "B", "c": "C"}
    budget = NameBudget(remaining=1)
    sessions, warning = await resolve_names(fake, "m1", "Domain4", _built(["a", "b", "c"]), budget, 4)
    assert len([c for c in fake.calls if c[0] == "show-object"]) == 1 and budget.remaining == 0
    assert warning is not None and warning.message.startswith("2 ")
    assert sorted(_added_names(sessions)) == sorted(["A", "b", "c"])
