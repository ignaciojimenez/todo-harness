"""An exploited advisory pages, whichever alert in its group it is.

GitHub lists alerts newest first, and the sweep judged each group by the first
one. So the newest advisory decided the lane for every older one, and an
exploited advisory stayed silent unless it happened to be the newest. Every
alert's own score lost out too: the sweep logs printed all five of undici's
alerts as "EPSS 8%ile", when their percentiles run from 4 to 28.

The fixture is pastebin-worker's real undici group, in the order GitHub returned
it on 2026-11-04. Nothing live is near the paging threshold, so the exploited
score is planted here, in a copy, and never in the file.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from harness.models import Finding, Issue, Lane, Open, Update
from harness.notifiers import NullNotifier
from harness.reconcile import Policy, reconcile
from harness.runners import cli
from harness.runners.cli import describe, main
from harness.sources.security import Alert, SecuritySource, decide, marker_url, route

FIXTURES = Path(__file__).parent / "fixtures"
UNDICI = json.loads((FIXTURES / "dependabot-alerts-undici-2026-11-04.json").read_text())
"""Newest first, as captured: #126, #125, #124, #123, #120."""

NAME = "pastebin-worker"
EXPLOITED = 0.95
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


def _sweep(monkeypatch, alerts: list[dict]) -> SecuritySource:
    src = SecuritySource(owner="ignaciojimenez", token="t")
    monkeypatch.setattr(src, "repos", lambda: [NAME])
    src.default_branches = {NAME: "main"}
    monkeypatch.setattr(
        src, "_get",
        lambda path, required=False: alerts if "/dependabot/alerts" in path else [],
    )
    return src


def _planted(position: int, percentile: float | None = EXPLOITED) -> list[dict]:
    alerts = copy.deepcopy(UNDICI)
    epss = None if percentile is None else {"percentage": 0.5, "percentile": percentile}
    alerts[position]["security_advisory"]["epss"] = epss
    return alerts


def alert(**kw) -> Alert:
    kw.setdefault("kind", "dependabot")
    kw.setdefault("repo", f"ignaciojimenez/{NAME}")
    kw.setdefault("number", 1)
    kw.setdefault("title", "t")
    kw.setdefault("severity", "high")
    kw.setdefault("path", "pnpm-lock.yaml")
    kw.setdefault("package", "undici")
    kw.setdefault("scope", "development")
    kw.setdefault("epss", 0.10)
    return Alert(**kw)


# ── the fixture says what the module docstring says ──────────────────────────


def test_the_capture_is_newest_first_with_scores_that_differ(monkeypatch):
    alerts = _sweep(monkeypatch, UNDICI).alerts()
    assert [a.number for a in alerts] == [126, 125, 124, 123, 120]
    assert len({a.epss for a in alerts}) == 5
    assert {a.scope for a in alerts} == {"development"}


# ── the lane belongs to the group, not to its newest alert ───────────────────


@pytest.mark.parametrize("position", range(len(UNDICI)))
def test_an_exploited_advisory_pages_wherever_it_sits(monkeypatch, position):
    (finding,) = _sweep(monkeypatch, _planted(position)).findings()
    assert finding.lane is Lane.PAGE
    assert finding.priority == 1


def test_the_page_names_the_advisory_that_caused_it(monkeypatch):
    planted = _planted(4)
    summary = planted[4]["security_advisory"]["summary"][:40]
    (finding,) = _sweep(monkeypatch, planted).findings()
    assert summary in finding.title
    assert "EPSS 95%ile" in finding.body


def test_page_is_recorded_for_the_sweep(monkeypatch):
    src = _sweep(monkeypatch, _planted(4))
    (finding,) = src.findings()
    assert src.paged == [finding]
    assert src.silent == [], "a paged group is not also reported as swallowed"


@pytest.mark.parametrize("position", range(1, len(UNDICI)))
def test_an_unscored_advisory_is_not_read_as_a_quiet_one(monkeypatch, position):
    """Route's own rule, applied to every alert: a missing score is not a low
    one. It already held when the unscored alert was the newest, which a new
    advisory usually is."""
    (finding,) = _sweep(monkeypatch, _planted(position, percentile=None)).findings()
    assert finding.lane is Lane.PLAN
    assert "no EPSS score yet" in finding.body


def test_the_most_exploited_alert_decides_among_equals():
    calm, hot = alert(number=1, epss=0.91), alert(number=2, epss=0.99)
    head, lane, why = decide([calm, hot])
    assert (head.number, lane) == (2, Lane.PAGE)
    assert "99%ile" in why


# ── what must not change ─────────────────────────────────────────────────────


def test_build_time_alerts_stay_silent(monkeypatch):
    """The captured group, untouched. Whether these should be silent at all is a
    separate call, and this must not make it by accident."""
    (finding,) = _sweep(monkeypatch, UNDICI).findings()
    assert finding.lane is Lane.SILENT


def test_each_silent_alert_prints_its_own_reason(monkeypatch):
    """Every one printed the newest alert's EPSS, which made the log wrong."""
    src = _sweep(monkeypatch, UNDICI)
    src.findings()
    assert {a.number: why.split("EPSS ")[1].split(")")[0] for a, why in src.silent} == {
        126: "8%ile", 125: "25%ile", 124: "8%ile", 123: "4%ile", 120: "28%ile",
    }


def test_one_alert_routes_as_it_always_did():
    a = alert(scope="runtime")
    assert decide([a]) == (a, *route(a))


def test_the_order_of_a_group_changes_nothing():
    alerts = [alert(number=1), alert(number=2, epss=EXPLOITED), alert(number=3, epss=None)]
    assert decide(alerts)[0].number == decide(alerts[::-1])[0].number == 2


# ── identity: PER-141 and PER-143 were one group ─────────────────────────────


def test_a_groups_marker_ignores_the_casing_of_its_alerts():
    """GitHub names the same package both ways: 34 `Pillow` and 20 `pillow` in
    the site repo. The marker followed whichever came first, so one group got a
    second identity on 2026-10-24: PER-143 opened, and PER-141 closed."""
    assert marker_url(alert(package="Pillow")) == marker_url(alert(package="pillow"))


def test_the_marker_survives_the_deciding_alert_changing():
    """Which alert decides moves with EPSS, day to day. Identity must not."""
    calm = alert(number=1, package="Pillow", epss=0.10)
    hot = alert(number=2, package="pillow", epss=EXPLOITED)
    assert marker_url(decide([calm])[0]) == marker_url(decide([calm, hot])[0])


def test_a_lowercase_marker_is_unchanged():
    """Every open issue's marker is lowercase today, so none of them re-keys."""
    assert marker_url(alert(package="vite")).endswith("package%3Avite")


# ── two manifests share one marker ───────────────────────────────────────────


def _finding(lane: Lane, title: str) -> Finding:
    return Finding(
        key=marker_url(alert()), title=title, lane=lane,
        labels=frozenset({"agent/sec"}), priority=1 if lane is Lane.PAGE else 2,
    )


POLICY = Policy(managed_label="agent/sec")


@pytest.mark.parametrize("flip", [False, True])
def test_a_page_is_not_lost_to_another_manifests_plan(flip):
    """The marker has no manifest in it, and live toml and vitest each have two
    groups on one marker. Whichever came last won, so a PLAN could erase a PAGE."""
    both = [_finding(Lane.PAGE, "page"), _finding(Lane.PLAN, "plan")]
    (action,) = reconcile(both[::-1] if flip else both, [], POLICY, NOW).actions
    assert isinstance(action, Open)
    assert action.finding.lane is Lane.PAGE


# ── a page reaches someone when the issue already exists ─────────────────────


def _open(priority: int = 2) -> Issue:
    return Issue(
        id="i1", ref="PER-140", title="t", labels=frozenset({"agent/sec"}),
        key=marker_url(alert()), priority=priority,
    )


def test_a_finding_escalating_to_page_carries_the_page():
    """EPSS moves on alerts that already have an issue. That is the common way
    to become exploited, and it raised a priority and woke nobody."""
    finding = _finding(Lane.PAGE, "now exploited")
    (update,) = reconcile([finding], [_open()], POLICY, NOW).actions
    assert isinstance(update, Update)
    assert update.priority == 1
    assert update.page == finding


def test_the_priority_is_the_record_that_the_page_went_out():
    """No second store: the next sweep sees priority 1 and stays quiet."""
    finding = _finding(Lane.PAGE, "now exploited")
    assert reconcile([finding], [_open(priority=1)], POLICY, NOW).actions == ()


def test_a_plan_finding_drifting_in_priority_does_not_page():
    (update,) = reconcile([_finding(Lane.PLAN, "p")], [_open(priority=3)], POLICY, NOW).actions
    assert update.priority == 2
    assert update.page is None


def test_label_drift_on_a_page_finding_does_not_page_again():
    labelled = Finding(
        key=marker_url(alert()), title="t", lane=Lane.PAGE, priority=1,
        labels=frozenset({"agent/sec", "kind/risk"}),
    )
    (update,) = reconcile([labelled], [_open(priority=1)], POLICY, NOW).actions
    assert update.add_labels == {"kind/risk"}
    assert update.page is None


class Escalating:
    def __init__(self) -> None:
        self.finding = _finding(Lane.PAGE, "now exploited")

    def plan(self, tracker):
        return reconcile([self.finding], tracker.issues, POLICY, NOW).actions


class Tracker:
    name = "fake"

    def __init__(self, *issues: Issue) -> None:
        self.issues = list(issues)
        self.applied: list = []

    def list_issues(self, query):
        return []

    def list_projects(self):
        return []

    def apply(self, action) -> None:
        self.applied.append(action)


def test_applying_an_escalation_pages_after_the_write(monkeypatch):
    monkeypatch.setitem(cli.SOURCES, "up", lambda a: Escalating())
    n = NullNotifier()
    t = Tracker(_open())
    assert main(["apply", "--sources", "up"], tracker=t, notifier=n) == 0
    assert len(t.applied) == 1
    assert [p.title for p in n.pages] == ["now exploited"]


def test_planning_an_escalation_says_so_and_never_pages(monkeypatch, capsys):
    monkeypatch.setitem(cli.SOURCES, "up", lambda a: Escalating())
    n = NullNotifier()
    main(["plan", "--sources", "up"], tracker=Tracker(_open()), notifier=n)
    assert n.pages == []
    assert "priority=1 page" in capsys.readouterr().out


def test_an_escalation_page_that_fails_fails_the_run(monkeypatch, capsys):
    monkeypatch.setitem(cli.SOURCES, "up", lambda a: Escalating())

    class Broken(NullNotifier):
        def page(self, finding):
            raise RuntimeError("page not delivered: HTTP 404")

    n = Broken()
    main(["apply", "--sources", "up"], tracker=Tracker(_open()), notifier=n)
    assert n.beats[-1].failed
    assert "PAGE NOT SENT" in capsys.readouterr().out


def test_an_ordinary_update_describes_no_page():
    assert "page" not in describe(Update(issue_id="i", why="w", priority=2))
