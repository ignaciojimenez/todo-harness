"""SecuritySource and OsvSource share the `agent/sec` label — the same
ownership tag covering the same problem from two angles. Each still calls
`reconcile()` against only its own findings, so a marker the other source
created is invisible to it and reads as "no longer reported".

Not hypothetical: in production, three CodeQL-gap issues opened by
SecuritySource were marked absent by OsvSource on the very next sweep, purely
because they were not among OSV's own findings — six actions where three were
real, tripping the `--max-actions` circuit breaker and failing the run.
"""

from __future__ import annotations

from harness.models import Issue, IssueQuery, MarkAbsent
from harness.sources.osv import OsvSource
from harness.sources.security import SecuritySource

GH_KEY = "https://github.com/o/r/security/code-scanning#language:go"
OSV_KEY = "https://osv.dev/list?q=pkg&ecosystem=Go#o/r"


class FakeTracker:
    def __init__(self, issues: list[Issue]) -> None:
        self._issues = issues
        self.applied: list = []

    def list_issues(self, query: IssueQuery) -> list[Issue]:
        out = self._issues
        if query.label:
            out = [i for i in out if query.label in i.labels]
        if query.open_only:
            out = [i for i in out if not i.closed]
        return out

    def apply(self, action) -> None:
        self.applied.append(action)


def test_osv_does_not_mark_a_security_issue_absent(monkeypatch):
    """The exact production failure: a github.com marker seen by OsvSource
    must not be judged gone just because OSV never produced it."""
    issue = Issue(id="1", title="CodeQL go analysis is failing in r",
                  labels=frozenset({"agent/sec"}), key=GH_KEY)
    src = OsvSource(owner="o", token="t")
    monkeypatch.setattr(src, "findings", lambda: [])
    assert list(src.plan(FakeTracker([issue]))) == []


def test_security_does_not_mark_an_osv_issue_absent(monkeypatch):
    """The same bug, the other direction."""
    issue = Issue(id="1", title="lodash 4.17.20 in r — 1 advisory",
                  labels=frozenset({"agent/sec"}), key=OSV_KEY)
    src = SecuritySource(owner="o", token="t")
    monkeypatch.setattr(src, "findings", lambda: [])
    assert list(src.plan(FakeTracker([issue]))) == []


def test_security_still_closes_its_own_stale_issue(monkeypatch):
    """The fix narrows absence-detection to markers a source could have
    produced — it must not also block a source from noticing its own finding
    is really gone."""
    issue = Issue(id="1", title="x", labels=frozenset({"agent/sec"}), key=GH_KEY)
    src = SecuritySource(owner="o", token="t")
    monkeypatch.setattr(src, "findings", lambda: [])
    (action,) = src.plan(FakeTracker([issue]))
    assert isinstance(action, MarkAbsent)


def test_osv_still_closes_its_own_stale_issue(monkeypatch):
    issue = Issue(id="1", title="x", labels=frozenset({"agent/sec"}), key=OSV_KEY)
    src = OsvSource(owner="o", token="t")
    monkeypatch.setattr(src, "findings", lambda: [])
    (action,) = src.plan(FakeTracker([issue]))
    assert isinstance(action, MarkAbsent)
