"""The properties that only matter once nobody is watching.

These are not correctness tests — the reconciler's tests cover that. These are
operability tests: what happens when the harness is wrong, or dead.
"""

from __future__ import annotations

import pytest

from harness.models import Heartbeat, Issue, IssueQuery
from harness.notifiers import HealthchecksNotifier, NullNotifier
from harness.runners.cli import main


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


def test_apply_refuses_an_oversized_plan(capsys):
    t = FakeTracker(noisy(30))
    rc = main(
        ["apply", "--max-actions", "10"],
        tracker=t,
    )
    assert rc == 2
    assert t.applied == [], "breaker must refuse, not partially apply"
    assert "refusing to apply 30 actions" in capsys.readouterr().err




def test_plan_is_never_blocked_by_the_breaker(capsys):
    """Planning writes nothing, so a big plan is information, not a hazard."""
    rc = main(["plan", "--max-actions", "1"],
              tracker=FakeTracker(noisy(20)))
    assert rc == 0
    assert capsys.readouterr().out.count("UPDATE") == 20


def test_plan_applies_nothing():
    t = FakeTracker(noisy(3))
    main(["plan"], tracker=t)
    assert t.applied == []


# ── run log ──────────────────────────────────────────────────────────────────






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


def test_an_exception_mid_run_still_reports_failure():
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
            ["apply"],
            tracker=Exploding([]),
            notifier=notifier,
        )

    assert seen == ["https://hc.example/u/start", "https://hc.example/u/fail"]


# ── source selection ─────────────────────────────────────────────────────────


def test_unknown_source_fails_loudly():
    with pytest.raises(SystemExit, match="unknown source"):
        main(["plan", "--sources", "nope"],
             tracker=FakeTracker([]))


def test_a_failed_ping_never_leaks_the_url(capsys):
    """The ping URL is a credential: holding it lets you suppress the alert.

    Job logs on a public repo are public, and urllib errors quote the URL they
    failed on — so the notifier must redact it rather than rely on the CI
    platform's secret masking.
    """
    url = "https://hc.example/super-secret-uuid"

    def boom(u: str) -> None:
        raise OSError(f"failed to open {u}")

    HealthchecksNotifier(url, inner=NullNotifier(), transport=boom).heartbeat(
        Heartbeat(source="x", swept=0, opened=0, updated=0, closed=0)
    )
    err = capsys.readouterr().err
    assert "super-secret-uuid" not in err
    assert "<ping-url>" in err






# ── pages ────────────────────────────────────────────────────────────────────


class OneFinding:
    """A source that proposes opening exactly one issue."""

    def __init__(self, lane):
        from harness.models import Finding, Lane, Open

        self.actions = [Open(Finding(
            key="https://github.com/o/r/security/secret-scanning/1",
            title="Exposed token in r", lane=Lane(lane)), why="newly true")]

    def plan(self, tracker):
        return self.actions


def _with_source(monkeypatch, lane):
    from harness.runners import cli

    monkeypatch.setitem(cli.SOURCES, "one", lambda a: OneFinding(lane))


def test_a_page_finding_pages_once_it_is_opened(monkeypatch):
    """The PAGE lane existed and nothing ever called `page()`: a leaked secret
    became an Urgent issue that woke nobody."""
    _with_source(monkeypatch, "page")
    n = NullNotifier()
    t = FakeTracker([])
    assert main(["apply", "--sources", "one"], tracker=t, notifier=n) == 0
    assert len(t.applied) == 1
    assert [p.title for p in n.pages] == ["Exposed token in r"]


def test_planning_never_pages(monkeypatch):
    _with_source(monkeypatch, "page")
    n = NullNotifier()
    main(["plan", "--sources", "one"], tracker=FakeTracker([]), notifier=n)
    assert n.pages == []


def test_a_plan_finding_does_not_page(monkeypatch):
    _with_source(monkeypatch, "plan")
    n = NullNotifier()
    main(["apply", "--sources", "one"], tracker=FakeTracker([]), notifier=n)
    assert n.pages == []


def test_a_page_that_fails_to_send_fails_the_run(monkeypatch, capsys):
    """A page that silently did not arrive is the failure this lane exists to
    prevent. It must reach the heartbeat as an error, so /fail fires."""
    _with_source(monkeypatch, "page")

    class Broken(NullNotifier):
        def page(self, finding):
            raise RuntimeError("page not delivered: HTTP 404")

    n = Broken()
    main(["apply", "--sources", "one"], tracker=FakeTracker([]), notifier=n)
    assert n.beats and n.beats[-1].errors == 1
    assert "PAGE NOT SENT" in capsys.readouterr().out


def test_slack_page_posts_the_title_and_the_evidence():
    import json

    from harness.models import Finding, Lane
    from harness.notifiers import SlackNotifier

    sent = []
    s = SlackNotifier("https://hooks.slack.com/services/T/B/x",
                      post=lambda url, body: sent.append((url, json.loads(body))))
    s.page(Finding(key="https://github.com/o/r/security", title="Leak",
                   lane=Lane.PAGE))
    (url, body), = sent
    assert url.endswith("/T/B/x")
    assert "Leak" in body["text"] and "https://github.com/o/r/security" in body["text"]


def test_a_failed_slack_page_raises_and_never_leaks_the_webhook():
    """The webhook is a credential — anyone holding it can post as the alert."""
    import urllib.error

    import pytest

    from harness.models import Finding
    from harness.notifiers import SlackNotifier

    hook = "https://hooks.slack.com/services/T/B/secret"

    def boom(url, body):
        raise urllib.error.URLError(f"cannot reach {url}")

    with pytest.raises(RuntimeError) as e:
        SlackNotifier(hook, post=boom).page(Finding(key="https://x.test/a", title="t"))
    assert "secret" not in str(e.value) and "<webhook-url>" in str(e.value)


def test_test_page_refuses_without_a_webhook(monkeypatch, capsys):
    monkeypatch.delenv("HARNESS_SLACK_WEBHOOK", raising=False)
    assert main(["test-page"], notifier=NullNotifier()) == 1
    assert "no HARNESS_SLACK_WEBHOOK" in capsys.readouterr().err


def test_test_page_sends_exactly_one_page(monkeypatch):
    monkeypatch.setenv("HARNESS_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    n = NullNotifier()
    assert main(["test-page"], notifier=n) == 0
    assert len(n.pages) == 1 and n.beats == [], "a test page is not a sweep"


def test_a_bare_webhook_path_is_accepted():
    """infrastructure-automation stores webhooks as the path after
    /services/ and prefixes the host itself. The harness's secret was set the
    same way, and the first real test page failed with "unknown url type"."""
    from harness.models import Finding
    from harness.notifiers import SlackNotifier

    sent = []
    SlackNotifier("T000/B000/xyz", post=lambda url, body: sent.append(url)).page(
        Finding(key="https://x.test/a", title="t"))
    assert sent == ["https://hooks.slack.com/services/T000/B000/xyz"]
