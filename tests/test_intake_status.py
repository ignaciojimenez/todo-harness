"""A finding lands in the queue, not in Backlog by default.

Every issue the harness opened took Linear's team default, Backlog, which the
queue rules call shelved and unread. PER-138, a Go stdlib advisory on
touchid-agent, sat there unseen from 2026-10-21 to 2026-11-05.

The rule (docs/decisions.md, 2026-11-06): Todo when the exposure is a real path
or it pages; Backlog only where the source cannot rule out build-time, which
for OSV means a manifest the exposure map marks local. And once an issue
exists, its status is the human's.

Linear is faked in memory, down to the one behaviour this is about: an
`issueCreate` with no `stateId` lands in the team default. The states are PER's
as listed on 2026-11-06, so a test that passes here passes against the real
type layout, not one invented to agree with the code.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from harness.models import Finding, Issue, IssueQuery, Lane, Open, Status, Update
from harness.runners.cli import describe
from harness.sources.osv import Dep, OsvSource
from harness.sources.security import SecuritySource, intake
from harness.trackers.linear import LinearError, LinearTracker

FIXTURES = Path(__file__).parent / "fixtures"
UNDICI = json.loads((FIXTURES / "dependabot-alerts-undici-2026-11-04.json").read_text())

PER_STATES = [
    {"id": "s-review", "type": "started", "name": "In Review"},
    {"id": "s-backlog", "type": "backlog", "name": "Backlog"},
    {"id": "s-canceled", "type": "canceled", "name": "Canceled"},
    {"id": "s-todo", "type": "unstarted", "name": "Todo"},
    {"id": "s-done", "type": "completed", "name": "Done"},
    {"id": "s-duplicate", "type": "duplicate", "name": "Duplicate"},
    {"id": "s-progress", "type": "started", "name": "In Progress"},
]
"""PER's workflow states as `list_issue_statuses` returned them, ids replaced."""

NAMES = {s["id"]: s["name"] for s in PER_STATES}


class FakeLinear:
    """Just enough of Linear's GraphQL to hold issue states."""

    def __init__(self, states=PER_STATES, default="s-backlog"):
        self.states = states
        self.default = default
        self.issues: dict[str, dict] = {}
        self.updates: list[dict] = []

    def __call__(self, query: str, variables: dict | None = None) -> dict:
        v = variables or {}
        if "teams(" in query:
            return {"teams": {"nodes": [
                {"id": "team", "states": {"nodes": self.states}}
            ]}}
        if "issueLabels" in query:
            return {"issueLabels": {"nodes": [
                {"id": "l-sec", "name": "sec", "parent": {"name": "agent"}}
            ]}}
        if "issueCreate" in query:
            i = v["input"]
            iid = f"issue-{len(self.issues) + 1}"
            # Linear's own behaviour: no stateId means the team default.
            self.issues[iid] = {**i, "stateId": i.get("stateId", self.default)}
            return {"issueCreate": {"success": True,
                                    "issue": {"id": iid, "identifier": iid}}}
        if "issueUpdate" in query:
            self.updates.append(v["input"])
            self.issues[v["id"]].update(v["input"])
            return {"issueUpdate": {"success": True}}
        if "attachmentCreate" in query:
            return {"attachmentCreate": {"success": True}}
        if "labels { nodes { name } }" in query:
            return {"issue": {"labels": {"nodes": [{"name": "sec"}]}}}
        raise AssertionError(f"unexpected query: {query}")

    def status(self, iid: str) -> str:
        return NAMES[self.issues[iid]["stateId"]]


def _tracker(monkeypatch, linear: FakeLinear) -> LinearTracker:
    t = LinearTracker(team_key="PER", api_key="k")
    monkeypatch.setattr(t, "_gql", linear)
    return t


class _Empty:
    def list_issues(self, query: IssueQuery) -> list[Issue]:
        return []


def _security(monkeypatch, alerts: list[dict]) -> SecuritySource:
    src = SecuritySource(owner="ignaciojimenez", token="t")
    monkeypatch.setattr(src, "repos", lambda: ["pastebin-worker"])
    src.default_branches = {"pastebin-worker": "main"}
    monkeypatch.setattr(
        src, "_get",
        lambda path, required=False: alerts if "/dependabot/alerts" in path else [],
    )
    return src


def _osv(monkeypatch, dep: Dep) -> OsvSource:
    src = OsvSource(owner="ignaciojimenez", token="t")
    monkeypatch.setattr(src, "deps", lambda: [dep])
    monkeypatch.setattr(src, "already_alerted", lambda: set())
    monkeypatch.setattr(src, "_osv_batch", lambda deps: [[{"id": "GO-1"}]])
    monkeypatch.setattr(src, "_details", lambda vulns: vulns)
    return src


def _runtime(alerts: list[dict]) -> list[dict]:
    """The captured undici group with its scope flipped to runtime: the same
    alerts, now in the shipped artefact of an internet-facing worker."""
    out = copy.deepcopy(alerts)
    for a in out:
        a["dependency"]["scope"] = "runtime"
    return out


def _open_one(monkeypatch, src) -> tuple[FakeLinear, str]:
    (action,) = src.plan(_Empty())
    assert isinstance(action, Open)
    linear = FakeLinear()
    _tracker(monkeypatch, linear).apply(action)
    (iid,) = linear.issues
    return linear, iid


# ── acceptance ───────────────────────────────────────────────────────────────


def test_a_public_finding_opens_in_todo(monkeypatch):
    linear, iid = _open_one(monkeypatch, _security(monkeypatch, _runtime(UNDICI)))
    assert "exposure **public**" in linear.issues[iid]["description"]
    assert linear.status(iid) == "Todo"


def test_a_local_finding_opens_in_backlog(monkeypatch):
    dep = Dep("ignaciojimenez/pastebin-worker", "Go", "stdlib", "1.26.0",
              manifest="scripts/go.mod")
    linear, iid = _open_one(monkeypatch, _osv(monkeypatch, dep))
    assert "exposure **local**" in linear.issues[iid]["description"]
    assert linear.status(iid) == "Backlog"


def test_an_update_leaves_a_status_the_human_set(monkeypatch):
    """Opened in Todo, moved to In Progress by hand, then everything an Update
    can carry drifts at once. The issue stays In Progress.

    Labels are left out: `_merged_label_ids` reads a grouped label back as its
    bare name and cannot resolve it, a separate defect this fake surfaced."""
    linear, iid = _open_one(monkeypatch, _security(monkeypatch, _runtime(UNDICI)))
    linear.issues[iid]["stateId"] = "s-progress"
    t = _tracker(monkeypatch, linear)
    t._project_ids = {"pastebin-worker": "p-1"}
    t.apply(Update(
        issue_id=iid, why="drift", project="pastebin-worker", priority=1,
        title="t", body="b",
    ))
    assert linear.updates, "the update must actually have been sent"
    assert linear.status(iid) == "In Progress"
    assert all("stateId" not in u for u in linear.updates)


# ── the check would fire ─────────────────────────────────────────────────────


def test_the_fake_lands_a_create_without_a_state_in_backlog(monkeypatch):
    """What the tests above would see if `_create` stopped setting a state:
    the old behaviour, and the reason PER-138 went unread."""
    linear = FakeLinear()
    linear("mutation { issueCreate }", {"input": {"title": "t"}})
    assert linear.status("issue-1") == "Backlog"


def test_an_update_that_did_set_a_state_would_be_caught(monkeypatch):
    linear, iid = _open_one(monkeypatch, _security(monkeypatch, _runtime(UNDICI)))
    linear.issues[iid]["stateId"] = "s-progress"
    linear("mutation { issueUpdate }", {"id": iid, "input": {"stateId": "s-todo"}})
    assert linear.status(iid) != "In Progress"


def test_a_team_without_a_todo_state_refuses_rather_than_defaulting(monkeypatch):
    linear = FakeLinear(states=[s for s in PER_STATES if s["type"] != "unstarted"])
    t = _tracker(monkeypatch, linear)
    finding = Finding(key="https://example.invalid/x", title="t")
    with pytest.raises(LinearError, match="no unstarted state"):
        t.apply(Open(finding, why="new"))
    assert linear.issues == {}


# ── the rule ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("exposure", ["public", "supplychain", "unknown"])
def test_a_real_path_is_todo(exposure):
    assert intake(Lane.PLAN, exposure) is Status.TODO


def test_local_is_backlog():
    assert intake(Lane.PLAN, "local") is Status.BACKLOG


def test_a_page_is_todo_whatever_the_exposure():
    assert intake(Lane.PAGE, "local") is Status.TODO


def test_an_exploited_build_time_alert_pages_into_todo(monkeypatch):
    """Build-time GitHub alerts stay silent, unless exploited: then they page,
    and a page never lands somewhere nobody reads."""
    alerts = copy.deepcopy(UNDICI)
    alerts[2]["security_advisory"]["epss"] = {"percentage": 0.5, "percentile": 0.95}
    (action,) = _security(monkeypatch, alerts).plan(_Empty())
    assert action.finding.lane is Lane.PAGE
    assert action.finding.status is Status.TODO


def test_build_time_github_alerts_still_open_nothing(monkeypatch):
    """The second decision, unchanged: GitHub can see scope, so build-time
    stays silent rather than going to Backlog."""
    assert list(_security(monkeypatch, UNDICI).plan(_Empty())) == []


def test_a_finding_defaults_to_todo():
    """A source that says nothing about status gets the queue, never the
    tracker's default."""
    assert Finding(key="https://example.invalid/x", title="t").status is Status.TODO


def test_a_plan_says_where_each_issue_starts():
    """The live plan is how a human checks this before it applies."""
    f = Finding(key="https://example.invalid/x", title="t", status=Status.BACKLOG)
    assert describe(Open(f, why="new")).endswith("(new; starts in backlog)")
