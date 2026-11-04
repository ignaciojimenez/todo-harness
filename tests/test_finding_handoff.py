"""PER-169: a finding that moves is not a finding that is gone.

PER-89/99/100/102 were opened by OSV for four build-time npm packages in the
site repo. When Dependabot raised its own alert for each, OSV stopped reporting
the package (it covers only what GitHub does not) and GitHub routed the alert
silent. Neither source emitted the finding any more, so each issue was closed
as "no longer true" with the vulnerable version still in the lockfile.

Everything here is real down to the network: the alerts and OSV answers are the
ones captured on 2026-11-04, through the real parser, router and reconciler.

⚠️ The capture came after the site's fix landed (21:14 UTC, alerts `fixed` at
21:30), so only #90 was still open. `BEFORE_FIX` rewinds the others by their
own `fixed_at`, which is the one edit made to what GitHub returned, and it is
made here rather than in the fixture.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from harness.models import Close, Issue, IssueQuery, Lane, MarkAbsent, MarkPresent, Open
from harness.runners.cli import _plan_notes
from harness.sources.osv import Dep, OsvSource, marker_url
from harness.sources.security import SecuritySource, route

FIXTURES = Path(__file__).parent / "fixtures"
OWNER = "ignaciojimenez"
NAME = "ignaciojimenezpi.github.io"
SITE = f"{OWNER}/{NAME}"
LABEL = "agent/sec"

ALERTS = json.loads((FIXTURES / "dependabot-alerts-site-2026-11-04.json").read_text())
STILL_OPEN = [a for a in ALERTS if a["state"] == "open"]
BEFORE_FIX = [a for a in ALERTS if a["number"] in {44, 45, 46, 90}]
"""The four the sweep logs print as silent from 2026-10-30 until the fix landed.
#42 and #43 are captured but left out: GitHub stamps them fixed at the same
moment, yet no sweep log from those weeks lists them, and that is unexplained."""

VULNERABLE = {
    "brace-expansion": "2.1.4",
    "shell-quote": "1.10.0",
    "source-map-js": "1.2.1",
    "postcss-selector-parser": "6.1.4",
}
"""The pre-fix lockfile, read at the parent of the site's 329e7bc."""

UPGRADED = {
    "shell-quote": "1.12.0",
    "source-map-js": "1.2.2",
    "postcss-selector-parser": "6.1.5",
}
"""The fixed versions OSV was asked about. brace-expansion left the lockfile
altogether, which is a different way for a finding to really end."""

ISSUES = {
    "brace-expansion": "PER-89",
    "postcss-selector-parser": "PER-99",
    "source-map-js": "PER-100",
    "shell-quote": "PER-102",
}


def _osv_answer(name: str, version: str) -> list[dict]:
    path = FIXTURES / f"osv-query-npm-{name}-{version}.json"
    return json.loads(path.read_text()).get("vulns", [])


def _key(name: str) -> str:
    return marker_url(Dep(SITE, "npm", name, "any"))


def _serve_alerts(monkeypatch, gh: SecuritySource, alerts: list[dict]) -> None:
    """GitHub, as far as the sweep can see: this repo, these open alerts."""
    monkeypatch.setattr(gh, "repos", lambda: [NAME])
    gh.default_branches = {NAME: "main"}

    def get(path, required=False):
        return alerts if "/dependabot/alerts" in path else []

    monkeypatch.setattr(gh, "_get", get)


def _osv(monkeypatch, versions: dict[str, str], alerts: list[dict]) -> OsvSource:
    src = OsvSource(owner=OWNER, token="t")
    _serve_alerts(monkeypatch, src._gh, alerts)
    monkeypatch.setattr(
        src, "deps", lambda: [Dep(SITE, "npm", n, v) for n, v in versions.items()]
    )
    # The captured answers are `/v1/query` records, already whole.
    monkeypatch.setattr(
        src, "_osv_batch", lambda deps: [_osv_answer(d.name, d.version) for d in deps]
    )
    monkeypatch.setattr(src, "_details", lambda vulns: vulns)
    return src


def _security(monkeypatch, alerts: list[dict]) -> SecuritySource:
    src = SecuritySource(owner=OWNER, token="t")
    _serve_alerts(monkeypatch, src, alerts)
    return src


class Tracker:
    def __init__(self, *issues: Issue) -> None:
        self.issues = list(issues)

    def list_issues(self, query: IssueQuery) -> list[Issue]:
        return [
            i for i in self.issues
            if (not query.label or query.label in i.labels)
            and (not query.open_only or not i.closed)
        ]


def _issue(key: str, ref: str = "PER-1", **kw) -> Issue:
    return Issue(id=f"id-{ref}", ref=ref, title="t", labels=frozenset({LABEL}), key=key, **kw)


def _hours_ago(h: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=h)


PACKAGES = sorted(VULNERABLE)


# ── the fixtures say what the issue says ─────────────────────────────────────


@pytest.mark.parametrize("name", PACKAGES)
def test_osv_really_reports_the_vulnerable_version(name):
    """The capture proves the premise, not just that the file parses."""
    assert _osv_answer(name, VULNERABLE[name]), f"OSV reports nothing for {name}"


@pytest.mark.parametrize("name", sorted(UPGRADED))
def test_osv_really_reports_nothing_for_the_upgrade(name):
    assert _osv_answer(name, UPGRADED[name]) == []


def test_the_alerts_route_silent_as_build_time(monkeypatch):
    """Read through the real parser: scope, EPSS and manifest as the router
    sees them. If any of these stopped parsing, every test below would pass
    for the wrong reason."""
    alerts = _security(monkeypatch, BEFORE_FIX).alerts()
    assert {a.package for a in alerts} == set(VULNERABLE)
    for a in alerts:
        assert (a.scope, a.path) == ("development", "package-lock.json")
        assert a.epss is not None and a.epss < 0.90
        assert route(a)[0] is Lane.SILENT


# ── the reproduction: PER-89, PER-99, PER-100, PER-102 ───────────────────────


@pytest.mark.parametrize("name", PACKAGES)
def test_osv_alone_reports_the_package(monkeypatch, name):
    """The sweep before the hand-off: GitHub silent, OSV opens the issue."""
    src = _osv(monkeypatch, {name: VULNERABLE[name]}, alerts=[])
    (action,) = src.plan(Tracker())
    assert isinstance(action, Open)
    assert action.finding.key == _key(name)


@pytest.mark.parametrize("name", PACKAGES)
def test_handoff_to_a_silent_alert_does_not_start_the_clock(monkeypatch, name):
    """The next sweep: Dependabot now reports the same package, and routes it
    silent. Nothing about the vulnerability changed."""
    src = _osv(monkeypatch, {name: VULNERABLE[name]}, BEFORE_FIX)
    assert list(src.plan(Tracker(_issue(_key(name), ISSUES[name])))) == []


@pytest.mark.parametrize("name", PACKAGES)
def test_handoff_does_not_close_the_issue_as_no_longer_true(monkeypatch, name):
    """The production failure, exactly: `absent for 30h, no longer true`, with
    the vulnerable version still pinned."""
    src = _osv(monkeypatch, {name: VULNERABLE[name]}, BEFORE_FIX)
    issue = _issue(_key(name), ISSUES[name], absent_since=_hours_ago(30))
    actions = list(src.plan(Tracker(issue)))
    assert not [a for a in actions if isinstance(a, Close)], actions
    assert [type(a) for a in actions] == [MarkPresent]


def test_the_only_alert_still_open_at_capture_holds_its_issue(monkeypatch):
    """#90 unrewound: the state GitHub actually returned on 2026-11-04."""
    assert [a["number"] for a in STILL_OPEN] == [90]
    src = _osv(monkeypatch, {"postcss-selector-parser": "6.1.4"}, STILL_OPEN)
    issue = _issue(_key("postcss-selector-parser"), "PER-99")
    assert list(src.plan(Tracker(issue))) == []


def test_a_withdrawn_alert_hands_the_finding_back(monkeypatch):
    """PER-145's path. GitHub withdrew #48 on 2026-10-26 and raised #90 four
    days later. In between OSV reports the package again, under the same
    marker, so the issue never moves. With PER-99 closed by then, the gap opened
    PER-145, and #90 closed that one too."""
    src = _osv(monkeypatch, {"postcss-selector-parser": "6.1.4"}, alerts=[])
    issue = _issue(_key("postcss-selector-parser"), "PER-99", priority=2)
    assert list(src.plan(Tracker(issue))) == []


def test_a_handoff_to_an_alert_with_its_own_issue_still_holds(monkeypatch):
    """A runtime alert gets a GitHub issue of its own, so one upgrade shows two
    issues until it lands. Both close themselves then. Closing the OSV one
    here would be the same false claim with a better excuse."""
    runtime = json.loads(json.dumps(STILL_OPEN))
    runtime[0]["dependency"]["scope"] = "runtime"
    src = _osv(monkeypatch, {"postcss-selector-parser": "6.1.4"}, runtime)
    assert list(src.plan(Tracker(_issue(_key("postcss-selector-parser"))))) == []
    (opened,) = _security(monkeypatch, runtime).plan(Tracker())
    assert isinstance(opened, Open) and "github.com" in opened.finding.key


# ── lanes: the same failure with no second source involved ───────────────────


def _unscored(alerts: list[dict]) -> list[dict]:
    out = json.loads(json.dumps(alerts))
    for a in out:
        a["security_advisory"]["epss"] = None
    return out


def test_an_alert_scored_into_silent_keeps_its_issue(monkeypatch):
    """A CVE too new for EPSS routes to PLAN and opens an issue. Once scored,
    a build-time one routes silent. Its issue was read as absent, and closed,
    with the alert still open on GitHub."""
    (opened,) = _security(monkeypatch, _unscored(STILL_OPEN)).plan(Tracker())
    assert isinstance(opened, Open)

    scored = _security(monkeypatch, STILL_OPEN)
    assert list(scored.plan(Tracker(_issue(opened.finding.key)))) == []


def test_a_silent_alert_clears_an_absence_mark(monkeypatch):
    (opened,) = _security(monkeypatch, _unscored(STILL_OPEN)).plan(Tracker())
    issue = _issue(opened.finding.key, absent_since=_hours_ago(30))
    actions = list(_security(monkeypatch, STILL_OPEN).plan(Tracker(issue)))
    assert [type(a) for a in actions] == [MarkPresent]


def test_a_local_manifest_finding_keeps_its_issue(monkeypatch):
    """OSV's own silent lane. An exposure edit moves a finding, it does not fix
    it, so the issue must not read that as absence."""
    src = _osv(monkeypatch, {"shell-quote": "1.10.0"}, alerts=[])
    monkeypatch.setattr("harness.sources.osv.exposure_of", lambda repo, path: "local")
    assert list(src.plan(Tracker(_issue(_key("shell-quote"))))) == []
    assert src.silent, "the silent note still prints"


# ── the policy is not changed here ───────────────────────────────────────────


def test_build_time_alerts_still_open_nothing(monkeypatch):
    """Whether these should be silent is a separate call. This fix must not
    make it by accident."""
    sec = _security(monkeypatch, BEFORE_FIX)
    assert list(sec.plan(Tracker())) == []
    assert {a.number for a, _ in sec.silent} == {a["number"] for a in BEFORE_FIX}

    osv = _osv(monkeypatch, VULNERABLE, BEFORE_FIX)
    assert list(osv.plan(Tracker())) == []
    assert osv.covered == len(VULNERABLE)


# ── closing still works ──────────────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(UPGRADED))
def test_an_upgrade_past_the_fix_starts_the_clock(monkeypatch, name):
    src = _osv(monkeypatch, {name: UPGRADED[name]}, alerts=[])
    (action,) = src.plan(Tracker(_issue(_key(name))))
    assert isinstance(action, MarkAbsent)


@pytest.mark.parametrize("name", sorted(UPGRADED))
def test_an_upgrade_past_the_fix_closes_after_the_window(monkeypatch, name):
    src = _osv(monkeypatch, {name: UPGRADED[name]}, alerts=[])
    issue = _issue(_key(name), absent_since=_hours_ago(30))
    (action,) = src.plan(Tracker(issue))
    assert isinstance(action, Close)


def test_a_package_gone_from_the_lockfile_closes_too(monkeypatch):
    """What really happened to brace-expansion: the upgrade dropped it."""
    src = _osv(monkeypatch, UPGRADED, alerts=[])
    issue = _issue(_key("brace-expansion"), absent_since=_hours_ago(30))
    (action,) = src.plan(Tracker(issue))
    assert isinstance(action, Close)


def test_nothing_closes_inside_the_window(monkeypatch):
    src = _osv(monkeypatch, {"shell-quote": "1.12.0"}, alerts=[])
    issue = _issue(_key("shell-quote"), absent_since=_hours_ago(23))
    assert list(src.plan(Tracker(issue))) == []


def test_the_alert_closing_after_the_upgrade_releases_the_issue(monkeypatch):
    """GitHub lags the lockfile. The hold lasts while the alert is open, and
    ends by itself once GitHub catches up."""
    held = _osv(monkeypatch, {"postcss-selector-parser": "6.1.5"}, STILL_OPEN)
    issue = _issue(_key("postcss-selector-parser"))
    assert list(held.plan(Tracker(issue))) == []

    released = _osv(monkeypatch, {"postcss-selector-parser": "6.1.5"}, alerts=[])
    (action,) = released.plan(Tracker(issue))
    assert isinstance(action, MarkAbsent)


# ── a close says why, and only what it knows ─────────────────────────────────


def test_an_osv_close_names_both_sources_it_asked(monkeypatch):
    src = _osv(monkeypatch, {"shell-quote": "1.12.0"}, alerts=[])
    issue = _issue(_key("shell-quote"), absent_since=_hours_ago(30))
    (action,) = src.plan(Tracker(issue))
    assert "no longer true" not in action.why
    assert "OSV" in action.why and "GitHub" in action.why
    assert "30h" in action.why


def test_a_github_close_says_what_github_stopped_showing(monkeypatch):
    src = _security(monkeypatch, alerts=[])
    key = f"https://github.com/{SITE}/security/dependabot?q=is%3Aopen+package%3Ax"
    (action,) = src.plan(Tracker(_issue(key, absent_since=_hours_ago(30))))
    assert isinstance(action, Close)
    assert "no longer true" not in action.why
    assert "GitHub" in action.why


# ── reporting the issues the bug already closed ──────────────────────────────


@pytest.mark.parametrize("name", PACKAGES)
def test_a_wrongly_closed_issue_is_reported(monkeypatch, name):
    """Before the site's fix, this is all four. Nothing reopens it: a silent
    finding opens nothing, so a human decides."""
    src = _osv(monkeypatch, {name: VULNERABLE[name]}, BEFORE_FIX)
    closed = _issue(_key(name), ISSUES[name], closed=True, absent_since=_hours_ago(500))
    assert list(src.plan(Tracker(closed))) == []
    assert src.report.closed_while_true == (ISSUES[name],)
    assert any(ISSUES[name] in n for n in _plan_notes(src.report))


def test_only_postcss_is_reported_once_the_fix_landed(monkeypatch):
    """The live state on 2026-11-04: three of the four really are fixed now."""
    closed = [
        _issue(_key(n), ref, closed=True, absent_since=_hours_ago(500))
        for n, ref in ISSUES.items()
    ]
    src = _osv(monkeypatch, {**UPGRADED, "postcss-selector-parser": "6.1.4"}, STILL_OPEN)
    assert list(src.plan(Tracker(*closed))) == []
    assert src.report.closed_while_true == ("PER-99",)


def test_github_reports_its_own_wrongly_closed_issues_too(monkeypatch):
    """The same report from the other source, which reads its own markers."""
    (opened,) = _security(monkeypatch, _unscored(STILL_OPEN)).plan(Tracker())
    closed = _issue(opened.finding.key, "PER-7", closed=True, absent_since=_hours_ago(500))
    src = _security(monkeypatch, STILL_OPEN)
    assert list(src.plan(Tracker(closed))) == []
    assert src.report.closed_while_true == ("PER-7",)


def test_a_human_close_is_not_second_guessed(monkeypatch):
    """A person closing an issue leaves no absence mark. They may have meant it."""
    src = _osv(monkeypatch, {"shell-quote": "1.10.0"}, BEFORE_FIX)
    closed = _issue(_key("shell-quote"), "PER-102", closed=True)
    assert list(src.plan(Tracker(closed))) == []
    assert src.report.closed_while_true == ()


def test_an_open_issue_for_the_same_finding_settles_it(monkeypatch):
    src = _osv(monkeypatch, {"shell-quote": "1.10.0"}, BEFORE_FIX)
    key = _key("shell-quote")
    closed = _issue(key, "PER-102", closed=True, absent_since=_hours_ago(500))
    assert list(src.plan(Tracker(closed, _issue(key, "PER-200")))) == []
    assert src.report.closed_while_true == ()


def test_a_finding_that_can_reopen_itself_is_not_also_reported(monkeypatch):
    """No alert, so OSV reports it in the PLAN lane and proposes a new issue.
    That is already the visible answer."""
    src = _osv(monkeypatch, {"shell-quote": "1.10.0"}, alerts=[])
    closed = _issue(_key("shell-quote"), "PER-102", closed=True, absent_since=_hours_ago(500))
    (action,) = src.plan(Tracker(closed))
    assert isinstance(action, Open)
    assert src.report.closed_while_true == ()
