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


def test_unknown_repo_defaults_to_local():
    """Silent by default. A repo nobody classified must not page anyone."""
    assert exposure_of("some/new-repo", "go.mod") == "local"


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
