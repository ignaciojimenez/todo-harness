"""Routing and grouping, tested against the real cases that shaped them.

Every case here is drawn from an alert that actually existed in Ignacio's repos
on 2026-09-13, or from a defect the prototype's backtest caught. No network.
"""

from __future__ import annotations

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
