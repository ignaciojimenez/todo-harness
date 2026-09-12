"""Triage rules, tested against a fake tracker — no network.

The cases are drawn from PER-53, which was captured by voice into the Linear
mobile app and arrived carrying a stock `Improvement` label, an `agent/fleet`
label that would have let a future reconciler close it, and a 180-word body.
"""

from __future__ import annotations

from harness.models import Issue, IssueQuery, Update
from harness.sources.triage import TriageSource

CONTRACT = frozenset({"agent/fleet", "agent/sec", "needs/decision",
                      "needs/laptop", "kind/broken", "kind/new"})
PROJECTS = ["infrastructure-automation", "dotfiles", "touchid-agent", "No repo"]


class FakeTracker:
    name = "fake"

    def __init__(self, issues: list[Issue], projects: list[str] | None = None) -> None:
        self._issues = issues
        self._projects = projects if projects is not None else PROJECTS
        self.applied: list = []

    def list_issues(self, query: IssueQuery) -> list[Issue]:
        out = self._issues
        if query.without_project is True:
            out = [i for i in out if i.project is None]
        if query.open_only:
            out = [i for i in out if not i.closed]
        return out

    def list_projects(self) -> list[str]:
        return self._projects

    def apply(self, action) -> None:
        self.applied.append(action)


def source(**kw) -> TriageSource:
    kw.setdefault("allowed_labels", CONTRACT)
    return TriageSource(**kw)


def test_infers_project_when_exactly_one_is_named():
    t = FakeTracker([Issue(id="1", title="Reduce agent-lxc noise",
                           body="This is about infrastructure-automation.")])
    (action,) = source().plan(t)
    assert isinstance(action, Update)
    assert action.project == "infrastructure-automation"


def test_leaves_project_alone_when_two_are_named():
    """A wrong project is worse than none — none is a queryable state."""
    t = FakeTracker([Issue(id="1", title="move dotfiles bits",
                           body="touches touchid-agent too")])
    assert list(source().plan(t)) == []
    assert len(source_report(t).ambiguous_project) == 1


def test_leaves_project_alone_when_none_is_named():
    t = FakeTracker([Issue(id="1", title="buy a new label printer")])
    assert list(source().plan(t)) == []


def test_strips_labels_outside_the_contract():
    """`Improvement` is a Linear default nobody adopted."""
    t = FakeTracker([Issue(id="1", title="x", labels=frozenset({"Improvement"}))])
    (action,) = source().plan(t)
    assert action.remove_labels == frozenset({"Improvement"})


def test_keeps_contract_labels():
    t = FakeTracker([Issue(id="1", title="x", labels=frozenset({"needs/decision"}))])
    assert list(source().plan(t)) == []


def test_substring_does_not_count_as_a_project_match():
    """"dotfiles-adjacent" must not map onto the dotfiles project."""
    t = FakeTracker([Issue(id="1", title="something dotfiles-adjacent")])
    assert list(source().plan(t)) == []


def test_long_body_is_reported_never_rewritten():
    """The words are the author's. Report, do not truncate."""
    body = "\n".join(f"line {i}" for i in range(20))
    t = FakeTracker([Issue(id="1", title="x", body=body)])
    s = source()
    actions = list(s.plan(t))
    assert actions == []
    assert len(s.report.long_body) == 1


def test_triaged_issues_are_not_touched():
    t = FakeTracker([Issue(id="1", title="x", project="dotfiles",
                           labels=frozenset({"Improvement"}))])
    assert list(source().plan(t)) == []


def test_the_per53_case_end_to_end():
    """Both fixes in one action, as the real issue would have needed."""
    t = FakeTracker([
        Issue(id="1",
              title="Reduce agent-lxc investigation noise",
              body="agent-lxc lives in infrastructure-automation",
              labels=frozenset({"agent/fleet", "Improvement"})),
    ])
    (action,) = source().plan(t)
    assert action.project == "infrastructure-automation"
    assert action.remove_labels == frozenset({"Improvement"})
    assert "agent/fleet" not in action.remove_labels, (
        "agent/fleet is a contract label; stripping it is an ownership decision "
        "a normaliser must not make on its own"
    )


def source_report(t: FakeTracker):
    s = source()
    s.plan(t)
    return s.report
