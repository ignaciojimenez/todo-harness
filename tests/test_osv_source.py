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


def test_seen_counts_the_packages_checked(monkeypatch):
    """A token that loses dependency-graph access shrinks this number long
    before anything else notices. It must reach the heartbeat."""
    from harness.sources.osv import OsvSource

    src = OsvSource(owner="x", token="t")
    monkeypatch.setattr(src._gh, "repos", lambda: ["r"])
    monkeypatch.setattr(src._gh, "_get", lambda path, required=False: [])
    monkeypatch.setattr(src, "_raw_sbom", lambda repo: {"sbom": {"packages": [
        {"externalRefs": [{"referenceLocator": "pkg:pypi/requests@2.32.0"}]},
        {"externalRefs": [{"referenceLocator": "pkg:npm/vitest@1.0.0"}]},
    ]}})
    assert len(src.deps()) == 2
    assert src.seen == 2 and src.unit == "packages"


# ── runtimes (PER-63) ────────────────────────────────────────────────────────

import base64
import io
import json
from pathlib import Path

import pytest

from harness.sources.osv import OsvSource, _body, _ours, go_runtime

FIXTURES = Path(__file__).parent / "fixtures"
STDLIB_1_26_0 = json.loads((FIXTURES / "osv-query-stdlib-go1.26.0.json").read_text())
"""OSV's real answer for Go stdlib 1.26.0, captured 2026-10-11: 46 advisories."""


def test_toolchain_wins_over_go_and_loses_its_prefix():
    """OSV returned 162 advisories for `go1.26.0` against 46 for `1.26.0`. A
    wrong version string is a confident wrong answer, not an error."""
    assert go_runtime("go 1.25.0\ntoolchain go1.26.8\n") == ("1.26.8", "")


def test_go_directive_is_used_when_there_is_no_toolchain():
    assert go_runtime("module x\n\ngo 1.26.8 // pinned\n") == ("1.26.8", "")


@pytest.mark.parametrize("go_mod", ["go 1.26\n", "go 1.22rc1\n", "toolchain go1.27\n"])
def test_a_version_that_is_not_a_release_is_not_queried(go_mod):
    """`go 1.26` is a language version; setup-go resolves it to the latest
    patch, so there is no single release to ask about."""
    version, why = go_runtime(go_mod)
    assert version is None and why.startswith("runtime not checked:")


def test_a_go_mod_without_directives_is_reported():
    assert go_runtime("module x\n")[0] is None


def _source(monkeypatch, files: dict[str, str], name: str = "touchid-agent") -> OsvSource:
    """An OsvSource whose repo has exactly `files` on its default branch."""
    src = OsvSource(owner="ignaciojimenez", token="t")
    monkeypatch.setattr(src._gh, "repos", lambda: [name])
    src._gh.default_branches = {name: "main"}
    monkeypatch.setattr(src._gh, "_get", lambda path, required=False: [])
    monkeypatch.setattr(src, "already_alerted", lambda: set())
    shas = {f"sha-{i}": text for i, text in enumerate(files.values())}

    def raw_get(path, repo, what):
        if "/dependency-graph/sbom" in path:
            return {}
        if "/git/trees/main" in path:
            return {"tree": [
                {"path": p, "type": "blob", "sha": f"sha-{i}"}
                for i, p in enumerate(files)
            ]}
        sha = path.rsplit("/", 1)[-1]
        return {"content": base64.b64encode(shas[sha].encode()).decode()}

    monkeypatch.setattr(src, "_raw_get", raw_get)
    return src


def _serve_osv_records(monkeypatch, records: list[dict]) -> None:
    by_id = {v["id"]: v for v in records}

    def urlopen(req, timeout=0):
        url = req if isinstance(req, str) else req.full_url
        return io.BytesIO(json.dumps(by_id[url.rsplit("/", 1)[-1]]).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)


def test_acceptance_go_1_26_0_yields_one_stdlib_finding_with_osvs_real_count(monkeypatch):
    """PER-63, forced: the case the sweep missed. The query path is real down
    to OSV; OSV's answers are the captured ones."""
    go_mod = (FIXTURES / "runtime-go1.26.0.mod").read_text()
    src = _source(monkeypatch, {"go.mod": go_mod})
    queried = []

    def batch(deps):
        queried.extend(deps)
        # querybatch's real shape: id and modified only.
        return [[{"id": v["id"], "modified": v["modified"]}
                 for v in STDLIB_1_26_0["vulns"]]]

    monkeypatch.setattr(src, "_osv_batch", batch)
    _serve_osv_records(monkeypatch, STDLIB_1_26_0["vulns"])

    [finding] = src.findings()

    assert [(d.ecosystem, d.name, d.version, d.manifest) for d in queried] == [
        ("Go", "stdlib", "1.26.0", "go.mod")
    ]
    assert len(STDLIB_1_26_0["vulns"]) == 46
    assert finding.title.startswith("Go stdlib 1.26.0 in touchid-agent (go.mod) — 46 advisories")
    assert finding.key.endswith("#ignaciojimenez/touchid-agent/go.mod")
    assert _ours(finding.key)
    assert "exposure **supplychain**" in finding.body
    assert "… and 40 more" in finding.body
    # Details were fetched, not rendered from querybatch's id-only stubs.
    assert finding.body.count(" · fixed in 1.") == 6
    assert "no fix available" not in finding.body
    assert "could not be fetched" not in finding.body
    assert not src.failures


def test_fix_versions_are_this_packages_not_the_advisorys():
    """GO-2026-6603 covers net/http and golang.org/x/net. Its x/net fix (0.60.0)
    is not a Go release, and printing it on a stdlib issue says "upgrade to a
    version that does not exist"."""
    [record] = [v for v in STDLIB_1_26_0["vulns"] if v["id"] == "GO-2026-6603"]
    assert {a["package"]["name"] for a in record["affected"]} >= {"stdlib", "golang.org/x/net"}
    dep = Dep("r/x", "Go", "stdlib", "1.26.0", manifest="go.mod")
    line = _body(dep, [record], "public").splitlines()[4]
    assert "fixed in 1.26.9, 1.27.2" in line
    assert "0.60.0" not in line


def test_an_advisory_whose_details_failed_is_not_called_unfixable():
    """The stub querybatch returns has no `affected`. Rendering it as "no fix
    available" is what every OSV issue said before details were fetched."""
    dep = Dep("r/x", "npm", "braces", "3.0.3")
    body = _body(dep, [{"id": "GHSA-x", "modified": "2026-10-01T00:00:00Z"}], "public")
    assert "no fix available" not in body
    assert "could not be fetched" in body


def test_a_failed_detail_fetch_marks_the_sweep_incomplete(monkeypatch):
    src = OsvSource(owner="x", token="t")

    def down(req, timeout=0):
        raise TimeoutError

    monkeypatch.setattr("urllib.request.urlopen", down)
    [stub] = src._details([{"id": "GO-1", "modified": "m"}])
    assert stub == {"id": "GO-1", "modified": "m"}
    assert src.failures == ["osv GO-1 → TimeoutError"]


def test_python_and_node_are_reported_not_queried(monkeypatch):
    """A floor such as `requires-python = ">=3.11"` is not the interpreter that
    runs, and a guessed version returns a confident answer about the wrong one."""
    src = _source(monkeypatch, {
        "pyproject.toml": '[project]\nrequires-python = ">=3.11"\n',
        "web/package.json": '{"engines": {"node": ">=22"}}',
        ".nvmrc": "22.11.0\n",
    }, name="todo-harness")
    assert src.runtimes("ignaciojimenez/todo-harness", "todo-harness") == []
    assert len(src.skipped) == 3
    assert all("runtime not checked:" in s for s in src.skipped)
    assert any("web/package.json" in s for s in src.skipped)


def test_two_modules_in_one_repo_are_two_findings(monkeypatch):
    """One issue per (repo, manifest, runtime): two go.mod files are two bumps."""
    src = _source(monkeypatch, {"go.mod": "go 1.26.0\n", "tools/go.mod": "go 1.26.0\n"})
    deps = src.runtimes("ignaciojimenez/touchid-agent", "touchid-agent")
    assert len({marker_url(d) for d in deps}) == 2


def test_a_runtime_in_a_local_manifest_goes_silent(monkeypatch):
    """pastebin-worker's scripts/ is a laptop CLI; the exposure map is
    manifest-level, so its runtime routes the same way its packages do."""
    src = _source(monkeypatch, {"scripts/go.mod": "go 1.26.0\n"}, name="pastebin-worker")
    monkeypatch.setattr(src, "_osv_batch", lambda deps: [[{"id": "GO-1"}]])
    monkeypatch.setattr(src, "_details", lambda vulns: vulns)
    assert src.findings() == []
    [(dep, why)] = src.silent
    assert dep.manifest == "scripts/go.mod" and "local" in why


def test_an_unreadable_tree_marks_the_sweep_incomplete(monkeypatch):
    src = OsvSource(owner="x", token="t")
    src._gh.default_branches = {"r": "main"}

    def refused(req, timeout=0):
        import urllib.error
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", refused)
    assert src.runtimes("x/r", "r") == []
    assert src.failures == ["x/r tree → HTTP 500"]


def test_a_truncated_tree_marks_the_sweep_incomplete(monkeypatch):
    src = OsvSource(owner="x", token="t")
    src._gh.default_branches = {"r": "main"}
    monkeypatch.setattr(src, "_raw_get", lambda *a: {"tree": [], "truncated": True})
    src.runtimes("x/r", "r")
    assert src.failures and "truncated" in src.failures[0]
