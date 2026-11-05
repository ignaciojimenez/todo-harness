"""A connection that drops is a scan gap, not a crash.

`_get` caught `URLError` and `TimeoutError`, but `urlopen` only wraps errors from
sending the request. One raised while reading the response comes through raw, so
GitHub hanging up (`RemoteDisconnected`, 2026-11-04) took the whole run down. An
exception reaches `/fail`, and the dead-man's switch is meant to stay quiet for
what the next sweep heals by itself (docs/decisions.md, 2026-09-21).

🔴 The risk in fixing this is the other direction: a sweep that swallows a failure
and looks clean closes real issues. So every test here also holds the old rule,
that partial data may add and must never subtract.
"""

from __future__ import annotations

import http.client
import http.server
import ssl
import threading
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from harness.models import Issue, IssueQuery, MarkAbsent
from harness.notifiers import NullNotifier
from harness.runners.cli import main
from harness.sources.osv import Dep, OsvSource, marker_url
from harness.sources.security import GitHubError, SecuritySource

ALERTS = "repos/x/y/dependabot/alerts?state=open&per_page=100"
GH_KEY = "https://github.com/x/y/security/dependabot?q=is%3Aopen+package%3Apkg"


class _Body:
    """A response that fails, or answers nonsense, only once it is read."""

    headers: dict = {}

    def __init__(self, read):
        self.read = read

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _raises(error):
    def read():
        raise error

    return read


class Tracker:
    name = "fake"

    def __init__(self, *issues):
        self.issues = list(issues)

    def list_issues(self, query: IssueQuery):
        return self.issues

    def list_projects(self):
        return []

    def apply(self, action):
        raise AssertionError(f"a plan must not write: {action}")


def _issue(key, **kw):
    return Issue(id="i1", ref="PER-1", title="t", labels=frozenset({"agent/sec"}), key=key, **kw)


# ── the real thing: a server that hangs up ───────────────────────────────────


class _HangsUp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.close_connection = True  # answers nothing at all

    def log_message(self, *args):
        pass


@pytest.fixture
def hangs_up(monkeypatch):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HangsUp)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        "harness.sources.security.API", f"http://127.0.0.1:{server.server_port}"
    )
    yield
    server.shutdown()
    server.server_close()


def test_a_real_hang_up_is_the_exception_it_was_in_production(hangs_up):
    """Against a real socket, so this is not a mock agreeing with a mock."""
    src = SecuritySource(owner="x", token="t")
    assert src._get(ALERTS) == []
    assert src.failures == [f"{ALERTS} → RemoteDisconnected"]


# ── everything that can go wrong after the request was sent ──────────────────


@pytest.mark.parametrize(
    "read",
    [
        _raises(http.client.RemoteDisconnected("closed")),
        _raises(ConnectionResetError(104, "reset")),
        _raises(http.client.IncompleteRead(b"[")),
        _raises(ssl.SSLError("bad record")),
        _raises(TimeoutError("slow")),
        lambda: b"<html>502 from a proxy</html>",
    ],
    ids=["hang-up", "reset", "short-read", "tls", "timeout", "not-json"],
)
def test_a_failed_read_is_recorded_not_raised(monkeypatch, read):
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=0: _Body(read))
    src = SecuritySource(owner="x", token="t")
    assert src._get(ALERTS) == []
    assert len(src.failures) == 1


def test_the_token_never_reaches_a_failure_message(monkeypatch):
    def boom(req, timeout=0):
        raise http.client.RemoteDisconnected(req.headers["Authorization"])

    monkeypatch.setattr("urllib.request.urlopen", boom)
    src = SecuritySource(owner="x", token="s3cret")
    src._get(ALERTS)
    assert "s3cret" not in src.failures[0]


def test_a_rejected_token_still_fails_the_run(monkeypatch):
    """401 is not transient. Catching more must not catch this."""

    def refused(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "nope", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", refused)
    with pytest.raises(GitHubError, match="token rejected"):
        SecuritySource(owner="x", token="t")._get(ALERTS)


# ── partial data may add, and must never subtract ────────────────────────────


def _github_drops(monkeypatch):
    def boom(req, timeout=0):
        raise http.client.RemoteDisconnected("closed")

    monkeypatch.setattr("urllib.request.urlopen", boom)


def test_a_dropped_connection_marks_nothing_absent(monkeypatch):
    _github_drops(monkeypatch)
    src = SecuritySource(owner="x", token="t")
    assert list(src.plan(Tracker(_issue(GH_KEY)))) == []
    assert src.report.absence_suppressed == 1


def test_a_dropped_connection_closes_nothing(monkeypatch):
    _github_drops(monkeypatch)
    src = SecuritySource(owner="x", token="t")
    gone = datetime.now(timezone.utc) - timedelta(days=9)
    assert list(src.plan(Tracker(_issue(GH_KEY, absent_since=gone)))) == []


def test_a_connection_dropping_on_a_later_page_keeps_what_it_read(monkeypatch):
    first = [{"number": 1}]

    class Page(_Body):
        headers = {"Link": '<https://api.github.com/next>; rel="next"'}

    pages = [Page(lambda: b'[{"number": 1}]')]

    def urlopen(req, timeout=0):
        if pages:
            return pages.pop()
        raise http.client.RemoteDisconnected("closed")

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    src = SecuritySource(owner="x", token="t")
    assert src._get(ALERTS) == first
    assert src.failures == [f"{ALERTS} → RemoteDisconnected"]


# ── the run ──────────────────────────────────────────────────────────────────


def test_the_run_reports_the_gap_and_does_not_fail(monkeypatch):
    """The dispatch that crashed on 2026-11-04, end to end."""
    _github_drops(monkeypatch)
    monkeypatch.setenv("HARNESS_GH_TOKEN", "t")
    n = NullNotifier()
    rc = main(["plan", "--sources", "security", "--owner", "x"],
              tracker=Tracker(_issue(GH_KEY)), notifier=n)
    assert rc == 0
    assert n.beats[-1].errors >= 1
    assert n.beats[-1].failed is False


# ── OSV's batch had no handling at all ───────────────────────────────────────


def _osv(monkeypatch, n_deps: int) -> OsvSource:
    src = OsvSource(owner="x", token="t")
    deps = [Dep("x/y", "npm", f"pkg{i}", "1.0.0") for i in range(n_deps)]
    monkeypatch.setattr(src, "deps", lambda: deps)
    monkeypatch.setattr(src, "already_alerted", lambda: set())
    return src


@pytest.mark.parametrize(
    "error",
    [
        http.client.RemoteDisconnected("closed"),
        urllib.error.HTTPError("https://api.osv.dev", 503, "down", {}, None),
        urllib.error.URLError("no route"),
    ],
    ids=["hang-up", "http-503", "no-route"],
)
def test_osv_going_away_marks_the_sweep_incomplete(monkeypatch, error):
    def boom(req, timeout=0):
        raise error

    monkeypatch.setattr("urllib.request.urlopen", boom)
    src = _osv(monkeypatch, 1)
    issue = _issue(marker_url(Dep("x/y", "npm", "pkg0", "1.0.0")))
    assert list(src.plan(Tracker(issue))) == []
    assert src.report.absence_suppressed == 1
    assert "querybatch" in src.failures[0]


def test_one_failed_osv_chunk_keeps_the_answers_lined_up(monkeypatch):
    """Answers pair with deps by position. A failed first chunk must not shift
    the second chunk's advisories onto the wrong packages."""
    calls = []

    class Batch(_Body):
        def __init__(self):
            super().__init__(
                lambda: b'{"results": [{"vulns": [{"id": "GHSA-x"}]}]}'
            )

    def urlopen(req, timeout=0):
        calls.append(req)
        if len(calls) == 1:
            raise http.client.RemoteDisconnected("closed")
        return Batch()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    src = _osv(monkeypatch, 101)
    answers = src._osv_batch(src.deps())
    assert len(answers) == 101
    assert answers[:100] == [[]] * 100
    assert answers[100] == [{"id": "GHSA-x"}]
    assert len(src.failures) == 1


def test_a_healthy_batch_is_read_as_before(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=0: _Body(lambda: b'{"results": [{"vulns": [{"id": "A"}]}, {}]}'),
    )
    src = _osv(monkeypatch, 2)
    assert src._osv_batch(src.deps()) == [[{"id": "A"}], []]
    assert src.failures == []


def test_marks_absent_when_the_sweep_really_was_complete(monkeypatch):
    """The guard above would pass against a source that never subtracts."""
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda req, timeout=0: _Body(lambda: b'{"results": [{}]}'),
    )
    src = _osv(monkeypatch, 1)
    issue = _issue(marker_url(Dep("x/y", "npm", "pkg0", "1.0.0")))
    (action,) = src.plan(Tracker(issue))
    assert isinstance(action, MarkAbsent)
