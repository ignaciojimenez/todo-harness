"""purl parsing and marker identity — the parts that decide what gets scanned.

Every skipped purl is a dependency nobody checked, so the parser is where a
silent coverage hole would live.
"""

from __future__ import annotations

from harness.sources.osv import Dep, marker_url, parse_purl


def test_parses_a_go_purl():
    assert parse_purl("pkg:golang/golang.org/x/crypto@v0.55.0") == (
        "Go", "golang.org/x/crypto", "0.55.0",
    )


def test_strips_the_go_v_prefix():
    """OSV wants 0.55.0; Go writes v0.55.0. The mismatch returns a confident
    empty answer rather than an error, which is the dangerous kind."""
    assert parse_purl("pkg:golang/x@v1.2.3")[2] == "1.2.3"


def test_parses_npm_and_pypi():
    assert parse_purl("pkg:npm/lodash@4.17.20")[:2] == ("npm", "lodash")
    assert parse_purl("pkg:pypi/pillow@9.0.0")[:2] == ("PyPI", "pillow")


def test_a_version_range_is_not_a_version():
    """GitHub lists Actions as `7.*.*`. Asking OSV about a range returns
    nothing, which would read as "this is fine"."""
    assert parse_purl("pkg:githubactions/actions/checkout@7.%2A.%2A") is None


def test_unknown_ecosystem_is_skipped_not_guessed():
    """A wrong ecosystem name returns an empty result, not an error."""
    assert parse_purl("pkg:conda/numpy@1.0") is None


def test_malformed_purls_are_rejected():
    assert parse_purl("golang.org/x/crypto") is None
    assert parse_purl("pkg:golang/no-version") is None


def test_marker_is_repo_scoped():
    """The same vulnerable package in two repos is two separate upgrades."""
    a = Dep("ignaciojimenez/touchid-agent", "Go", "golang.org/x/crypto", "0.55.0")
    b = Dep("ignaciojimenez/other", "Go", "golang.org/x/crypto", "0.55.0")
    assert marker_url(a) != marker_url(b)
    assert marker_url(a).endswith("#ignaciojimenez/touchid-agent")


def test_marker_is_stable_for_the_same_package_and_repo():
    a = Dep("r/x", "Go", "pkg", "1.0.0")
    b = Dep("r/x", "Go", "pkg", "1.0.1")  # version moves, identity does not
    assert marker_url(a) == marker_url(b)


def test_marker_is_a_valid_finding_key():
    from harness.models import Finding

    Finding(key=marker_url(Dep("r/x", "Go", "p", "1")), title="x")


def test_a_transient_repo_failure_does_not_take_down_the_sweep(monkeypatch):
    """One repo's HTTP 500 must not mean nothing gets scanned — but it must not
    look clean either."""
    import urllib.error

    from harness.sources.security import SecuritySource

    src = SecuritySource(owner="x", token="t")

    def boom(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert src._get("repos/x/y/dependabot/alerts") == []
    assert src.failures and "500" in src.failures[0]


def test_a_rejected_token_fails_the_run_instead(monkeypatch):
    """401 is not transient, and carrying on would report a false all-clear."""
    import urllib.error

    import pytest

    from harness.sources.security import GitHubError, SecuritySource

    src = SecuritySource(owner="x", token="t")

    def unauthorised(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "nope", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", unauthorised)
    with pytest.raises(GitHubError, match="token rejected"):
        src._get("repos/x/y/dependabot/alerts")


def test_a_suppressed_advisory_does_not_produce_a_finding():
    """An advisory that is unfixable AND inapplicable would pin its issue open
    for ever, because it never stops being reported."""
    from harness.sources.osv import suppression_for

    assert suppression_for("ignaciojimenez/touchid-agent", "GO-2026-5932")
    assert suppression_for("ignaciojimenez/touchid-agent", "GO-2026-6354") is None


def test_suppression_is_scoped_to_one_repo():
    """The same advisory may genuinely apply elsewhere."""
    from harness.sources.osv import suppression_for

    assert suppression_for("ignaciojimenez/other-repo", "GO-2026-5932") is None


def test_every_suppression_states_a_reason():
    """The mechanism most likely to rot into a way of hiding things."""
    from harness.sources.osv import SUPPRESSED

    for (repo, vid), why in SUPPRESSED.items():
        assert len(why) > 40, f"{repo}/{vid} needs a real reason, not a shrug"
        assert "verified" in why.lower(), f"{repo}/{vid} should say when it was checked"
