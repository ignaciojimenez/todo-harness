"""The properties that only matter once nobody is watching.

These are not correctness tests — the reconciler's tests cover that. These are
operability tests: what happens when the harness is wrong, or dead.
"""

from __future__ import annotations

import json

import pytest

from harness.models import Heartbeat, Issue, IssueQuery
from harness.notifiers import HealthchecksNotifier, NullNotifier
from harness.runners.cli import main
from harness.stores import JsonStore


class FakeTracker:
    name = "fake"

    def __init__(self, issues):
        self._issues = issues
        self.applied = []

    def list_issues(self, query: IssueQuery):
        out = self._issues
        if query.without_project is True:
            out = [i for i in out if i.project is None]
        return [i for i in out if not i.closed] if query.open_only else out

    def list_projects(self):
        return ["infrastructure-automation", "dotfiles"]

    def apply(self, action):
        self.applied.append(action)


def noisy(n: int):
    """n issues that each need exactly one fix."""
    return [
        Issue(id=f"i{k}", ref=f"PER-{k}", title="about dotfiles",
              labels=frozenset({"Improvement"}))
        for k in range(n)
    ]


# ── circuit breaker ──────────────────────────────────────────────────────────


def test_apply_refuses_an_oversized_plan(tmp_path, capsys):
    t = FakeTracker(noisy(30))
    rc = main(
        ["apply", "--max-actions", "10", "--state", str(tmp_path / "s.json")],
        tracker=t,
    )
    assert rc == 2
    assert t.applied == [], "breaker must refuse, not partially apply"
    assert "refusing to apply 30 actions" in capsys.readouterr().err


def test_breaker_trip_is_recorded_as_an_error_not_a_quiet_run(tmp_path):
    """A run that declined to act must not look like a healthy empty one."""
    state = tmp_path / "s.json"
    main(["apply", "--max-actions", "5", "--state", str(state)],
         tracker=FakeTracker(noisy(9)))
    run = json.loads(state.read_text())["runs"][-1]
    assert run["errors"] == 1
    assert "refusing" in run["note"]


def test_plan_is_never_blocked_by_the_breaker(tmp_path, capsys):
    """Planning writes nothing, so a big plan is information, not a hazard."""
    rc = main(["plan", "--max-actions", "1", "--state", str(tmp_path / "s.json")],
              tracker=FakeTracker(noisy(20)))
    assert rc == 0
    assert capsys.readouterr().out.count("UPDATE") == 20


def test_plan_applies_nothing(tmp_path):
    t = FakeTracker(noisy(3))
    main(["plan", "--state", str(tmp_path / "s.json")], tracker=t)
    assert t.applied == []


# ── run log ──────────────────────────────────────────────────────────────────


def test_applied_actions_are_recorded_with_their_reason(tmp_path):
    state = tmp_path / "s.json"
    main(["apply", "--state", str(state)], tracker=FakeTracker(noisy(2)))
    run = json.loads(state.read_text())["runs"][-1]
    assert run["applied"] == 2
    assert {a["do"] for a in run["actions"]} == {"Update"}
    assert all(a["why"] for a in run["actions"]), "an action without a why is unaccountable"


def test_run_log_is_capped(tmp_path):
    store = JsonStore(tmp_path / "s.json")
    for i in range(120):
        store.record_run({"n": i}, keep=50)
    assert len(store.runs) == 50
    assert store.runs[-1]["n"] == 119


# ── dead-man's switch ────────────────────────────────────────────────────────


def test_healthchecks_pings_start_then_success():
    seen: list[str] = []
    n = HealthchecksNotifier("https://hc.example/uuid", inner=NullNotifier(),
                             transport=seen.append)
    n.start()
    n.heartbeat(Heartbeat(source="x", swept=0, opened=0, updated=0, closed=0))
    assert seen == ["https://hc.example/uuid/start", "https://hc.example/uuid"]


def test_healthchecks_reports_failure_when_the_run_had_errors():
    seen: list[str] = []
    n = HealthchecksNotifier("https://hc.example/uuid", inner=NullNotifier(),
                             transport=seen.append)
    n.heartbeat(Heartbeat(source="x", swept=0, opened=0, updated=0, closed=0, errors=1))
    assert seen == ["https://hc.example/uuid/fail"]


def test_a_broken_ping_never_takes_the_run_down(capsys):
    """Monitoring being unreachable must not become a work outage.

    The missing ping is itself the alert, so carrying on loses nothing.
    """
    def boom(url: str) -> None:
        raise OSError("dns is having a day")

    n = HealthchecksNotifier("https://hc.example/uuid", inner=NullNotifier(),
                             transport=boom)
    n.heartbeat(Heartbeat(source="x", swept=0, opened=0, updated=0, closed=0))
    assert "heartbeat ping failed" in capsys.readouterr().err


def test_an_exception_mid_run_still_reports_failure(tmp_path):
    """The path that matters most: a crash must not look like silence."""
    seen: list[str] = []

    class Exploding(FakeTracker):
        def list_projects(self):
            raise RuntimeError("linear is down")

    notifier = HealthchecksNotifier(
        "https://hc.example/u", inner=NullNotifier(), transport=seen.append
    )
    with pytest.raises(RuntimeError):
        main(
            ["apply", "--state", str(tmp_path / "s.json")],
            tracker=Exploding([]),
            notifier=notifier,
        )

    assert seen == ["https://hc.example/u/start", "https://hc.example/u/fail"]


# ── source selection ─────────────────────────────────────────────────────────


def test_unknown_source_fails_loudly(tmp_path):
    with pytest.raises(SystemExit, match="unknown source"):
        main(["plan", "--sources", "nope", "--state", str(tmp_path / "s.json")],
             tracker=FakeTracker([]))
