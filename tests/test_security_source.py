"""Routing and grouping, tested against the real cases that shaped them.

Every case here is drawn from an alert that actually existed in Ignacio's repos
on 2026-09-13, or from a defect the prototype's backtest caught. No network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from harness.models import Lane
from harness.sources.security import (
    Alert,
    exposure_of,
    group_key,
    marker_url,
    route,
)


def dep(**kw) -> Alert:
    kw.setdefault("kind", "dependabot")
    kw.setdefault("repo", "ignaciojimenez/pastebin-worker")
    kw.setdefault("number", 1)
    kw.setdefault("title", "something bad")
    kw.setdefault("severity", "medium")
    kw.setdefault("path", "package.json")
    kw.setdefault("package", "vitest")
    return Alert(**kw)


# ── exposure: both path-prefixed entries were wrong at first ─────────────────


def test_pastebin_scripts_are_local_not_public():
    """5 real alerts about a laptop CLI nearly became 2 tickets."""
    assert exposure_of("pastebin-worker", "scripts/pb") == "local"
    assert exposure_of("pastebin-worker", "worker/index.ts") == "public"


def test_photography_utils_is_supplychain_not_local():
    """It looks like a helper; the album workflows run it in CI with repo write."""
    assert exposure_of("ignaciojimenezpi.github.io", "photography/utils/requirements.txt") \
        == "supplychain"
    assert exposure_of("ignaciojimenezpi.github.io", "package.json") == "public"


def test_an_unmapped_repo_is_unknown_not_local():
    """It used to default to local, which routed a runtime vulnerability in any
    new repo to silent — the map's gap read as a verdict."""
    assert exposure_of("some/new-repo", "go.mod") == "unknown"


def test_an_unmapped_repo_asks_to_be_classified_but_never_pages():
    lane, why = route(dep(repo="ignaciojimenez/new-repo", scope="runtime", epss=0.2))
    assert lane is Lane.PLAN and "exposure map" in why
    dev_lane, _ = route(dep(repo="ignaciojimenez/new-repo", scope="development", epss=0.2))
    assert dev_lane is Lane.SILENT, "build-time only stays silent wherever it is"


def test_the_tap_and_the_provisioner_are_supply_chain():
    """Both ship code onto machines: the formula that installs touchid-agent,
    and the images hosts boot from."""
    assert exposure_of("homebrew-tap", "Formula/touchid-agent.rb") == "supplychain"
    assert exposure_of("rpi-provisioner", "anything") == "supplychain"


# ── routing ──────────────────────────────────────────────────────────────────


def test_a_leaked_secret_always_pages():
    lane, _ = route(Alert(kind="secret", repo="r", number=1, title="AWS key",
                          severity="critical", path=None))
    assert lane is Lane.PAGE


def test_dev_scope_is_silent():
    """The real vitest alerts: dev-only, not in the shipped Worker."""
    lane, why = route(dep(scope="development", epss=0.305))
    assert lane is Lane.SILENT
    assert "not in the shipped artefact" in why


def test_actively_exploited_pages_even_when_dev_scope():
    """EPSS outranks scope: if it is being exploited, the excuse stops mattering."""
    lane, why = route(dep(scope="development", epss=0.97))
    assert lane is Lane.PAGE
    assert "exploited" in why


def test_missing_epss_is_not_treated_as_a_low_score():
    """`or 0.0` once made an unscored CVE read as "nobody is exploiting this"."""
    lane, why = route(dep(scope="runtime", epss=None, path="package.json"))
    assert lane is Lane.PLAN
    assert "too new to judge" in why


def test_missing_epss_on_a_local_manifest_stays_silent():
    lane, _ = route(dep(repo="ignaciojimenez/pastebin-worker", path="scripts/x",
                        scope="runtime", epss=None))
    assert lane is Lane.SILENT


def test_high_severity_sast_in_exposed_code_is_planned():
    lane, _ = route(Alert(kind="code", repo="ignaciojimenez/pastebin-worker",
                          number=1, title="py/clear-text-logging",
                          severity="high", path="worker/index.ts"))
    assert lane is Lane.PLAN


def test_high_severity_sast_in_local_code_is_silent():
    """The five scripts/pb findings: real pattern, unreachable from the service."""
    lane, _ = route(Alert(kind="code", repo="ignaciojimenez/pastebin-worker",
                          number=1, title="py/clear-text-logging",
                          severity="high", path="scripts/pb"))
    assert lane is Lane.SILENT


# ── grouping: one action, one ticket ─────────────────────────────────────────


def test_three_advisories_on_one_package_are_one_piece_of_work():
    a = dep(number=1, title="CVE one")
    b = dep(number=2, title="CVE two")
    c = dep(number=3, title="CVE three")
    assert len({group_key(x) for x in (a, b, c)}) == 1


def test_package_names_are_case_insensitive():
    """"Pillow" and "pillow" once counted as two packages, for one bump."""
    assert group_key(dep(package="Pillow")) == group_key(dep(package="pillow"))


def test_the_same_package_in_two_manifests_is_two_jobs():
    """Their exposure genuinely differs, which is why manifest is in the key."""
    site = "ignaciojimenez/ignaciojimenezpi.github.io"
    a = dep(repo=site, package="pillow", path="requirements.txt")
    b = dep(repo=site, package="pillow", path="photography/utils/requirements.txt")
    assert group_key(a) != group_key(b)


def test_the_same_package_in_two_repos_is_two_jobs():
    a = dep(repo="ignaciojimenez/a", package="pillow")
    b = dep(repo="ignaciojimenez/b", package="pillow")
    assert group_key(a) != group_key(b)


# ── markers ──────────────────────────────────────────────────────────────────


def test_marker_is_a_filtered_list_not_a_single_alert():
    """It must stay valid as individual alerts in the group are fixed."""
    url = marker_url(dep(package="pillow"))
    assert url.startswith("https://github.com/ignaciojimenez/pastebin-worker/security")
    assert "pillow" in url
    assert "/1" not in url.rsplit("?", 1)[0], "must not point at one alert number"


def test_marker_is_stable_across_alerts_in_a_group():
    assert marker_url(dep(number=1)) == marker_url(dep(number=2))


def test_marker_is_a_usable_key():
    """The key validator requires an absolute http(s) URL."""
    from harness.models import Finding

    Finding(key=marker_url(dep()), title="x")  # must not raise


def test_exposure_accepts_both_repo_forms():
    """The map is keyed by bare name; alerts carry owner/name.

    The first version of the port matched neither and classified everything
    local, which would have made the whole sweep silently find nothing.
    """
    assert exposure_of("pastebin-worker", "worker/x") == "public"
    assert exposure_of("ignaciojimenez/pastebin-worker", "worker/x") == "public"


# ── pagination: the prototype paged, the port did not ────────────────────────


class _Page:
    """Just enough of an HTTP response for `_get`."""

    def __init__(self, body, link=None):
        import json

        self._raw = json.dumps(body).encode()
        self.headers = {"Link": link} if link else {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._raw


def _serve(monkeypatch, pages: dict):
    """Serve `pages` by URL; anything unlisted is a 500."""
    import urllib.error

    seen = []

    def fake(req, timeout=0):
        seen.append(req.full_url)
        if req.full_url not in pages:
            raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)
        body, link = pages[req.full_url]
        return _Page(body, link)

    monkeypatch.setattr("urllib.request.urlopen", fake)
    return seen


API = "https://api.github.com"
ALERTS = f"{API}/repos/x/y/dependabot/alerts?state=open&per_page=100"
NEXT = f"{API}/repositories/1/dependabot/alerts?state=open&per_page=100&after=abc"


def test_alerts_past_the_first_page_are_seen(monkeypatch):
    """Alert 101 once went unread: the port fetched one page where the
    prototype had paginated. Unread is worse than unreported — the reconciler
    would have closed its issue as fixed."""
    from harness.sources.security import SecuritySource

    _serve(monkeypatch, {
        ALERTS: ([{"number": n} for n in range(100)], f'<{NEXT}>; rel="next"'),
        NEXT: ([{"number": 100}], None),
    })
    src = SecuritySource(owner="x", token="t")
    got = src._get("repos/x/y/dependabot/alerts?state=open&per_page=100")
    assert [a["number"] for a in got] == list(range(101))
    assert not src.failures


def test_repos_are_listed_once_across_pages(monkeypatch):
    """`repos()` used to page by itself; on top of a paging `_get` that would
    sweep every repo twice."""
    from harness.sources.security import SecuritySource

    first = f"{API}/users/x/repos?per_page=100"
    second = f"{API}/user/1/repos?per_page=100&page=2"
    seen = _serve(monkeypatch, {
        first: ([{"name": f"r{n}"} for n in range(100)], f'<{second}>; rel="next"'),
        second: ([{"name": "r100"}], None),
    })
    got = SecuritySource(owner="x", token="t").repos()
    assert got == [f"r{n}" for n in range(101)]
    assert seen == [first, second]


def test_a_failed_later_page_marks_the_sweep_incomplete(monkeypatch):
    """Page one alone is a partial answer, and a partial answer read as whole
    concludes absence for everything on the missing page."""
    from harness.sources.security import SecuritySource

    _serve(monkeypatch, {ALERTS: ([{"number": 1}], f'<{NEXT}>; rel="next"')})
    src = SecuritySource(owner="x", token="t")
    src._get("repos/x/y/dependabot/alerts?state=open&per_page=100")
    assert src.failures and "500" in src.failures[0]


def test_the_token_is_never_sent_off_github(monkeypatch):
    """The next URL comes from a response header. Following it blindly would
    hand the bearer token to whatever host it names."""
    from harness.sources.security import SecuritySource

    seen = _serve(monkeypatch, {
        ALERTS: ([{"number": 1}], '<https://evil.example/steal>; rel="next"'),
    })
    src = SecuritySource(owner="x", token="t")
    src._get("repos/x/y/dependabot/alerts?state=open&per_page=100")
    assert seen == [ALERTS]
    assert src.failures and "evil.example" in src.failures[0]


# ── coverage: a scanner that is off looks exactly like a clean repo ──────────


def _refuse(monkeypatch, code: int, message: str):
    import io
    import json
    import urllib.error

    def fake(req, timeout=0):
        body = io.BytesIO(json.dumps({"message": message}).encode())
        raise urllib.error.HTTPError(req.full_url, code, "no", {}, body)

    monkeypatch.setattr("urllib.request.urlopen", fake)


SECRETS = "repos/ignaciojimenez/dotfiles/secret-scanning/alerts?state=open&per_page=100"


def test_disabled_secret_scanning_becomes_an_issue(monkeypatch):
    """The exact 404 GitHub returned for dotfiles on 2026-09-18."""
    from harness.sources.security import SecuritySource, _gap_finding

    _refuse(monkeypatch, 404, "Secret scanning is disabled on this repository.")
    src = SecuritySource(owner="ignaciojimenez", token="t")
    assert src._get(SECRETS, required=True) == []
    assert src.gaps == [SECRETS] and not src.failures

    f = _gap_finding(SECRETS, "agent/sec")
    assert f.title == "Secret scanning is off in dotfiles"
    assert f.lane is Lane.PLAN
    assert f.key == ("https://github.com/ignaciojimenez/dotfiles/settings/"
                     "security_analysis#secret-scanning")


def test_a_refusal_that_is_not_disabled_marks_the_sweep_incomplete(monkeypatch):
    """A token without the permission gets a 403 too. That is not a gap in the
    repo, and it is not a clean repo either — the run must not look healthy."""
    from harness.sources.security import SecuritySource

    _refuse(monkeypatch, 403, "Resource not accessible by personal access token")
    src = SecuritySource(owner="ignaciojimenez", token="t")
    src._get(SECRETS, required=True)
    assert not src.gaps
    assert src.failures and "not accessible" in src.failures[0]


def test_optional_scanners_stay_quiet_when_off(monkeypatch):
    """Code scanning is set up on few repos; its 404 is not a finding."""
    from harness.sources.security import SecuritySource

    _refuse(monkeypatch, 404, "no analysis found")
    src = SecuritySource(owner="ignaciojimenez", token="t")
    src._get("repos/ignaciojimenez/dotfiles/code-scanning/alerts")
    assert not src.gaps and not src.failures


# ── blindness: seeing nothing must never read as a clean estate ─────────────


def test_an_owner_with_no_visible_repos_marks_the_sweep_incomplete(monkeypatch):
    """A mistyped owner, or a token that lists nothing, returns an empty list
    with HTTP 200. Read as complete, that is a clean estate: every open
    `agent/sec` issue would be marked absent, and closed a day later."""
    from harness.sources.security import SecuritySource

    _serve(monkeypatch, {f"{API}/users/x/repos?per_page=100": ([], None)})
    src = SecuritySource(owner="x", token="t")
    assert src.repos() == []
    assert src.failures and "no repositories" in src.failures[0]


def test_seen_counts_the_repos_swept(monkeypatch):
    """The heartbeat's number. It said 0 for a sweep across fifteen repos,
    which is the same thing it would say for a sweep that saw none."""
    from harness.sources.security import SecuritySource

    _serve(monkeypatch, {
        f"{API}/users/x/repos?per_page=100": ([{"name": "a"}, {"name": "b"}], None),
    })
    src = SecuritySource(owner="x", token="t")
    src.alerts()
    assert src.seen == 2 and src.unit == "repos"


# ── analyses: a language CodeQL silently dropped looks exactly like clean ────

# Real payloads, captured 2026-10-11 with
# `gh api repos/ignaciojimenez/<repo>/code-scanning/analyses --paginate` and
# `gh api repos/ignaciojimenez/<repo>/code-scanning/default-setup`.
FIXTURES = Path(__file__).parent / "fixtures"
TOUCHID = "ignaciojimenez/touchid-agent"
DOTFILES = "ignaciojimenez/dotfiles"
CAPTURED = datetime(2026, 10, 11, 19, 0, tzinfo=timezone.utc)
BEFORE_PRS = datetime(2026, 10, 11, 18, 0, tzinfo=timezone.utc)
"""touchid-agent's PRs #48 and #49 first scanned swift and c-cpp at 18:29.
Sliced here, the history is the state PER-81/82 were opened against."""
CODEQL = {"name": "CodeQL"}


def _analyses(repo: str, before: datetime | None = None) -> list[dict]:
    name = repo.split("/")[1]
    rows = json.loads((FIXTURES / f"codeql-analyses-{name}.json").read_text())
    if before is not None:
        rows = [a for a in rows if datetime.fromisoformat(a["created_at"]) < before]
    return rows


def _gaps(repo, analyses, branch, now):
    from harness.sources.security import _coverage

    return {g.category: g for g in _coverage(repo, analyses, branch, now)}


def test_the_touchid_agent_first_run_flags_go_swift_and_c():
    """Go, Swift and C failed and were silently dropped; Ruby and Actions ran
    clean and must not be flagged. Judged as the sweep saw it that evening."""
    first_run = _analyses(TOUCHID, before=datetime(2026, 9, 18, 17, 53, tzinfo=timezone.utc))
    gaps = _gaps(TOUCHID, first_run, "main", datetime(2026, 9, 18, 18, 0, tzinfo=timezone.utc))
    assert set(gaps) == {"/language:go", "/language:swift", "/language:c-cpp"}
    assert not any(g.stale for g in gaps.values())
    assert "unsuccessful execution" in gaps["/language:go"].error


def test_dropped_languages_are_not_scanned_since_the_day_they_failed():
    """Bug 1. Before the PRs, swift and c-cpp last ran on `main` on 2026-09-18,
    failed, and the new workflow never produced them again. "Latest ever"
    called them failing for three weeks, with a close condition — a clean
    rerun — that the config could never deliver."""
    gaps = _gaps(TOUCHID, _analyses(TOUCHID, before=BEFORE_PRS), "main", BEFORE_PRS)
    for lang in ("swift", "c-cpp"):
        g = gaps[f"/language:{lang}"]
        assert g.stale and f"{g.last:%Y-%m-%d}" == "2026-09-18"
    # Ruby ran clean once and was dropped in the same switch: still uncovered.
    assert gaps["/language:ruby"].stale
    # Still produced, latest clean: covered.
    assert "/language:go" not in gaps and "/language:actions" not in gaps


def test_clean_pull_request_runs_are_not_coverage():
    """Bug 2. Every clean swift and c-cpp analysis in the history is on
    `refs/pull/48/merge` or `refs/pull/49/merge`; `main` still does not scan
    swift. Counting them would close PER-81/82 on a proposal."""
    rows = _analyses(TOUCHID)
    clean = {a["ref"] for a in rows
             if a["category"] in {"/language:swift", "/language:c-cpp"} and not a["error"]}
    assert clean == {"refs/pull/48/merge", "refs/pull/49/merge"}  # the premise

    gaps = _gaps(TOUCHID, rows, "main", CAPTURED)
    for lang in ("swift", "c-cpp"):
        g = gaps[f"/language:{lang}"]
        assert g.stale and f"{g.last:%Y-%m-%d}" == "2026-09-18"


def test_failed_pull_request_runs_open_nothing():
    """The other direction: PRs #45 and #46 failed go and actions on
    2026-10-03 while `main` stayed clean. A PR ref never opens anything."""
    rows = _analyses(TOUCHID)
    assert any(a["error"] and a["ref"].startswith("refs/pull/") for a in rows)
    gaps = _gaps(TOUCHID, rows, "main", CAPTURED)
    assert "/language:go" not in gaps and "/language:actions" not in gaps


def test_a_planted_failure_of_a_produced_language_is_still_failing():
    """The fix must not turn real failures into staleness or silence. dotfiles
    runs actions on `master` constantly; make the newest one fail."""
    rows = _analyses(DOTFILES) + [{
        "tool": CODEQL, "ref": "refs/heads/master", "category": "/language:actions",
        "error": "unsuccessful execution, exit code: 32",
        "created_at": "2026-10-11T18:30:00Z",
    }]
    g = _gaps(DOTFILES, rows, "master", CAPTURED)["/language:actions"]
    assert not g.stale and "exit code: 32" in g.error


def test_the_default_branch_is_whatever_the_repo_says():
    """dotfiles' default branch is `master`. Hardcoding `main` would find no
    analyses at all, which reads as "code scanning off" — quiet, and wrong."""
    rows = _analyses(DOTFILES)
    assert _gaps(DOTFILES, rows, "main", CAPTURED) == {}
    assert set(_gaps(DOTFILES, rows, "master", CAPTURED)) == {"/language:ruby"}


def test_staleness_agrees_with_default_setup_where_that_is_the_config():
    """A cross-check against GitHub's own answer. dotfiles uses default setup,
    whose `languages` is the configured set; the history-derived rule must
    call exactly the rest stale. (touchid-agent uses a workflow, so its
    default-setup `languages` is not its config and proves nothing.)"""
    setup = json.loads((FIXTURES / "codeql-default-setup-dotfiles.json").read_text())
    assert setup["state"] == "configured"
    rows = _analyses(DOTFILES)
    produced = {a["category"] for a in rows}
    stale = {c for c, g in _gaps(DOTFILES, rows, "master", CAPTURED).items() if g.stale}
    assert stale == produced - {f"/language:{lang}" for lang in setup["languages"]}


def test_a_run_still_uploading_does_not_read_as_dropping_languages():
    """A sweep can land mid-run: actions uploaded, go not yet. Without the
    settle window, go — clean, and about to be re-analysed — would flip to
    stale and open an issue that closes a day later."""
    rows = _analyses(TOUCHID) + [{
        "tool": CODEQL, "ref": "refs/heads/main", "category": "/language:actions", "error": "",
        "created_at": "2026-10-20T12:00:00Z",
    }]
    mid_run = datetime(2026, 10, 20, 12, 5, tzinfo=timezone.utc)
    assert "/language:go" not in _gaps(TOUCHID, rows, "main", mid_run)
    # …but a run that had a day to finish and still did not produce go has
    # dropped it.
    later = datetime(2026, 10, 21, 13, 0, tzinfo=timezone.utc)
    assert _gaps(TOUCHID, rows, "main", later)["/language:go"].stale


def test_a_dormant_repo_is_not_stale():
    """Measured against the repo's own runs, not the clock: nobody pushing for
    a year leaves every category as covered as its last run."""
    rows = _analyses(DOTFILES)
    years_later = datetime(2027, 10, 11, tzinfo=timezone.utc)
    assert set(_gaps(DOTFILES, rows, "master", years_later)) == {"/language:ruby"}


def test_other_sarif_tools_are_not_codeql_languages():
    """cobra's OSSAR workflow uploaded to the same endpoint until 2024. A stale
    category from another tool is not a CodeQL language, and calling it one
    would put a false title on a real issue."""
    rows = _analyses(DOTFILES) + [{
        "tool": {"name": "OSSAR"}, "ref": "refs/heads/master",
        "category": ".github/workflows/ossar-analysis.yml:OSSAR-Scan",
        "error": "", "created_at": "2026-09-01T10:00:00Z",
    }]
    assert set(_gaps(DOTFILES, rows, "master", CAPTURED)) == {"/language:ruby"}


def test_a_later_clean_rerun_clears_the_gap():
    """Only the *latest* analysis per category counts — the real Go rerun at
    17:57:09 must stop the finding without touching Swift or C."""
    rows = _analyses(TOUCHID, before=datetime(2026, 9, 18, 17, 58, tzinfo=timezone.utc))
    gaps = _gaps(TOUCHID, rows, "main", datetime(2026, 9, 18, 18, 0, tzinfo=timezone.utc))
    assert "/language:go" not in gaps
    assert {"/language:swift", "/language:c-cpp"} <= set(gaps)


def test_latest_is_by_timestamp_not_list_order():
    """A failed rerun and its fix can land in either order within one page."""
    out_of_order = [
        {"tool": CODEQL, "ref": "refs/heads/main", "category": "/language:go",
         "error": "unsuccessful execution", "created_at": "2026-09-18T18:00:00Z"},
        {"tool": CODEQL, "ref": "refs/heads/main", "category": "/language:go", "error": "",
         "created_at": "2026-09-18T17:00:00Z"},
    ]
    g = _gaps(TOUCHID, out_of_order, "main", CAPTURED)["/language:go"]
    assert g.error == "unsuccessful execution"


def test_no_analyses_is_not_a_gap():
    """Code scanning off entirely (a 404) is optional and must stay quiet —
    same rule as the alerts endpoint."""
    assert _gaps(TOUCHID, [], "main", CAPTURED) == {}


def test_stale_and_failing_findings_say_different_things():
    by_cat = _gaps(TOUCHID, _analyses(TOUCHID), "main", CAPTURED)
    from harness.sources.security import _analysis_gap_finding

    stale = _analysis_gap_finding(by_cat["/language:swift"], "agent/sec")
    assert stale.lane is Lane.PLAN
    assert stale.title == "CodeQL swift not scanned in touchid-agent since 2026-09-18"
    assert "`main`" in stale.body and "confirm_delete" in stale.body

    rows = _analyses(DOTFILES) + [{
        "tool": CODEQL, "ref": "refs/heads/master", "category": "/language:actions",
        "error": "boom", "created_at": "2026-10-11T18:30:00Z",
    }]
    failing = _analysis_gap_finding(
        _gaps(DOTFILES, rows, "master", CAPTURED)["/language:actions"], "agent/sec")
    assert failing.title == "CodeQL actions analysis is failing in dotfiles"
    assert "`boom`" in failing.body and "`master`" in failing.body


def test_the_key_survives_failing_becoming_stale():
    """PER-81 was opened as failing and is now stale. One condition, one key —
    and the very URL already attached to PER-81, so the fix re-matches the
    existing issue instead of opening a duplicate."""
    from harness.sources.security import _analysis_gap_finding

    then = _gaps(TOUCHID, _analyses(TOUCHID, before=datetime(2026, 9, 18, 17, 53, tzinfo=timezone.utc)),
                 "main", datetime(2026, 9, 18, 18, 0, tzinfo=timezone.utc))["/language:swift"]
    now = _gaps(TOUCHID, _analyses(TOUCHID), "main", CAPTURED)["/language:swift"]
    assert not then.stale and now.stale
    a, b = (_analysis_gap_finding(g, "agent/sec") for g in (then, now))
    assert a.key == b.key == (
        "https://github.com/ignaciojimenez/touchid-agent/security/code-scanning#language:swift"
    )


ANALYSES = "repos/ignaciojimenez/touchid-agent/code-scanning/analyses?per_page=100"
REPOS = f"{API}/users/ignaciojimenez/repos?per_page=100"


def test_the_sweep_judges_each_repo_on_its_listed_default_branch(monkeypatch):
    """End to end: `alerts()` takes the branch from the repo listing and
    records stale and failing gaps the same way a disabled scanner is."""
    from harness.sources.security import SecuritySource

    _serve(monkeypatch, {
        REPOS: ([{"name": "touchid-agent", "default_branch": "main"}], None),
        f"{API}/{ANALYSES}": (_analyses(TOUCHID), None),
    })
    src = SecuritySource(owner="ignaciojimenez", token="t")
    src.alerts()
    gaps = {(g.repo, g.category, g.stale) for g in src.analysis_gaps}
    assert gaps == {
        (TOUCHID, "/language:swift", True),
        (TOUCHID, "/language:c-cpp", True),
        (TOUCHID, "/language:ruby", True),
    }


def test_a_repo_without_a_default_branch_is_unscanned_not_clean(monkeypatch):
    from harness.sources.security import SecuritySource

    _serve(monkeypatch, {
        REPOS: ([{"name": "touchid-agent"}], None),
        f"{API}/{ANALYSES}": (_analyses(TOUCHID), None),
    })
    src = SecuritySource(owner="ignaciojimenez", token="t")
    src.alerts()
    assert not src.analysis_gaps
    assert any("no default branch" in f for f in src.failures)
