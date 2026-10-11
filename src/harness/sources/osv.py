"""OSV, as the gap-filler behind GitHub's dependency alerts.

Exists because GitHub's silence turned out not to mean "clean". Verified
2026-09-14: `touchid-agent` pinned `golang.org/x/crypto v0.55.0`, had Dependabot
alerts enabled, imports `golang.org/x/crypto/ssh` in `agent.go` and `main.go` —
and GitHub reported zero, while OSV returned two DoS advisories against exactly
that package, both fixed in 0.56.0.

**It reports only what Dependabot did not.** Running both sources unfiltered
would open two issues for one upgrade, which is the failure the grouping rules
exist to prevent. So this asks GitHub what it already knows about, and covers
the rest. A side effect worth watching: the number of findings here *is* a
measure of how much to trust GitHub's coverage.

Two things OSV does not give, which changes the routing:

* **no dev/runtime scope** — the SBOM does not carry it either, so a build-only
  dependency cannot be suppressed the way the GitHub source suppresses it;
* **no EPSS** — so there is no evidence of active exploitation.

Without exploitation evidence, nothing here pages. A page that cannot say
"someone is doing this right now" teaches its reader to ignore pages, and the
one alert that mattered then arrives into a habit of dismissal.

**Runtimes are not in the SBOM.** GitHub lists third-party packages only, so
the Go stdlib a binary links went unasked: verified 2026-09-15, OSV reported 33
advisories against go1.26.0's stdlib that the sweep never surfaced. Each repo's
`go.mod` is read for the toolchain it declares and queried as `stdlib`. Python
and Node are reported as unchecked instead — see `UNCHECKED_RUNTIMES`.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from ..models import Action, Finding, IssueQuery, Lane
from ..ports import Tracker
from ..reconcile import Policy, reconcile
from .security import SecuritySource, exposure_of

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

ECOSYSTEM = {
    "golang": "Go",
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
    "githubactions": "GitHub Actions",
}
"""purl type → OSV ecosystem. Unknown types are skipped and reported rather
than guessed at: a wrong ecosystem returns a confident empty answer."""


SUPPRESSED: dict[tuple[str, str], str] = {
    ("touchid-agent", "GO-2026-5932"): (
        "golang.org/x/crypto/openpgp is unmaintained and has no fix, and this "
        "repo imports only crypto/ssh and crypto/ssh/agent — verified "
        "2026-09-15. Without this the issue can never close, because an "
        "advisory with no fix never stops being reported."
    ),
}
"""Advisories that do not apply, with the reason they do not.

OSV has no notion of dismissal — unlike GitHub, where dismissing an alert
removes it from the state the sweep reads. Without an equivalent, an advisory
that is unfixable *and* inapplicable pins its issue open for ever, and a queue
you cannot close things in is one you stop believing.

🔴 Two rules, because this is the mechanism most likely to rot into a way of
hiding things: every entry states **why** it does not apply, and every
suppression is **printed on the run that applies it**. A suppression nobody can
see is indistinguishable from a vulnerability nobody noticed.
"""


def suppression_for(repo: str, vuln_id: str) -> str | None:
    return SUPPRESSED.get((repo.rsplit("/", 1)[-1], vuln_id))


@dataclass(frozen=True, slots=True)
class Dep:
    repo: str
    ecosystem: str
    name: str
    version: str
    manifest: str = ""
    """The file that declared it. Set for runtimes, which come from a manifest
    rather than the SBOM; part of the identity, because the exposure map is
    manifest-level."""


SKIP_SELF = "the repository itself, not a dependency"
SKIP_UNPINNED = "NO VERSION — constraint is a range, so nothing can judge it"
SKIP_RANGE = "version is a range, not a version"
SKIP_ECOSYSTEM = "ecosystem not mapped; guessing one returns a confident empty answer"


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """`pkg:golang/golang.org/x/crypto@v0.55.0` → (Go, golang.org/x/crypto, 0.55.0)."""
    return _parse(purl)[0]


def _parse(purl: str) -> tuple[tuple[str, str, str] | None, str]:
    """Parsed dependency, or None plus the reason it was skipped.

    The reason matters: a skipped purl is a dependency nobody scanned, and the
    three reasons are not equally benign. A self-reference is noise; an unpinned
    constraint is a real coverage hole.
    """
    if not purl.startswith("pkg:"):
        return None, "not a purl"
    body = purl[4:]
    kind = body.partition("/")[0].lower()
    if kind == "github":
        return None, SKIP_SELF
    if "@" not in body:
        return None, SKIP_UNPINNED
    path, version = body.rsplit("@", 1)
    version = urllib.parse.unquote(version).lstrip("v")
    if "*" in version or not version:
        return None, SKIP_RANGE
    kind, _, name = path.partition("/")
    eco = ECOSYSTEM.get(kind.lower())
    if not eco or not name:
        return None, SKIP_ECOSYSTEM
    return (eco, urllib.parse.unquote(name), version), ""


UNCHECKED_RUNTIMES: dict[str, str] = {
    "pyproject.toml": "requires-python is a constraint, not the interpreter that runs",
    "package.json": "engines.node is a constraint, not the Node that runs",
    ".python-version": "OSV has no CPython package; its advisories carry git ranges only",
    ".nvmrc": "OSV has no Node package; its advisories carry git ranges only",
    ".node-version": "OSV has no Node package; its advisories carry git ranges only",
}
"""Manifests that imply a runtime this source does not query, and why.

Checked 2026-10-11. OSV has no first-party package for CPython or Node: the
PSF's records (`PSF-*`) carry only GIT ranges on python/cpython, Node's come
from NVD with git ranges, and `cpython` under PyPI returns a confident zero.
Bitnami's `python` and `node` packages do answer by version, but they are a
repackager's view, not upstream's. The deciding fact is the version, though:
no repo here pins one. `requires-python = ">=3.11"` is a floor, and CI asks
setup-python for "3.12" and setup-node for "22", which float to the latest
patch on every run. Querying the floor would report advisories against a
version that never runs, and a guess at the patch would be silent when wrong.
"""

_GO_DIRECTIVE = re.compile(r"^\s*(go|toolchain)\s+(\S+)", re.MULTILINE)
_GO_RELEASE = re.compile(r"\d+\.\d+\.\d+")


def go_runtime(go_mod: str) -> tuple[str | None, str]:
    """The Go release a `go.mod` builds with, or None and why not.

    `toolchain` wins over `go`, as it does for setup-go's `go-version-file`.
    Both are minimums for a local build; a CI build pinned by
    `go-version-file` uses exactly this one.

    🔴 Verified 2026-10-11, each a confident wrong answer from OSV rather than
    an error: `go1.26.0` returns 162 advisories against the 46 for `1.26.0`, so
    the toolchain's `go` prefix must go; and `go 1.26` is a language version,
    not a release, which setup-go resolves to whatever patch is latest.
    """
    found = {k: v.split("//")[0].strip() for k, v in _GO_DIRECTIVE.findall(go_mod)}
    if "toolchain" in found:
        directive, raw = "toolchain", found["toolchain"].removeprefix("go")
    elif "go" in found:
        directive, raw = "go", found["go"]
    else:
        return None, "runtime not checked: no go or toolchain directive"
    if not _GO_RELEASE.fullmatch(raw):
        return None, (
            f"runtime not checked: {directive} {found[directive]} is not a "
            "release (a language version or pre-release resolves to an "
            "unknown toolchain)"
        )
    return raw, ""


@dataclass
class OsvSource:
    owner: str
    token: str | None = None
    managed_label: str = "agent/sec"
    allowed_labels: frozenset[str] = frozenset()
    close_after_hours: int = 24
    name: str = "osv"
    unit: str = "packages"

    seen: int = 0
    """Packages checked against OSV. A token losing dependency-graph access
    shrinks this long before anything else notices."""

    silent: list = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    """Dependencies that went unscanned, with the reason. Reported rather than
    dropped: an unpinned constraint is a coverage hole no scanner can close, and
    it looks identical to "nothing wrong here" if nobody says so."""

    @property
    def failures(self) -> list[str]:
        return self._gh.failures

    suppressions: list[str] = field(default_factory=list)
    """Applied suppressions, printed every run. See SUPPRESSED."""

    fallbacks: list[str] = field(default_factory=list)
    """Repos whose SBOM only worked unauthenticated. Harmless for public repos,
    but it means the token is not granting what it was meant to."""

    covered: int = 0
    """How many packages Dependabot already flags. Context for the gap count."""

    def __post_init__(self) -> None:
        self._gh = SecuritySource(owner=self.owner, token=self.token)
        self._records: dict[str, dict] = {}

    # ── fetching ─────────────────────────────────────────────────────────────

    def deps(self) -> list[Dep]:
        out: list[Dep] = []
        for name in self._gh.repos():
            repo = f"{self.owner}/{name}"
            sbom = self._gh._get(f"repos/{repo}/dependency-graph/sbom")
            packages = sbom if isinstance(sbom, list) else []
            if not packages:
                raw = self._raw_sbom(repo)
                packages = ((raw.get("sbom") or {}).get("packages") or [])
            for p in packages:
                for ref in p.get("externalRefs") or []:
                    loc = ref.get("referenceLocator", "")
                    parsed, why = _parse(loc)
                    if parsed is None:
                        # Self-references are noise; everything else is a
                        # dependency that went unscanned and should be said so.
                        if loc.startswith("pkg:") and why != SKIP_SELF:
                            self.skipped.append(f"{repo}  {loc.split('@')[0]}  — {why}")
                        continue
                    eco, pkg, ver = parsed
                    out.append(Dep(repo, eco, pkg, ver))
            out.extend(self.runtimes(repo, name))
        self.seen = len(out)
        return out

    def runtimes(self, repo: str, name: str) -> list[Dep]:
        """The language runtimes a repo declares, read from its default branch.

        Go only; see `UNCHECKED_RUNTIMES` for why Python and Node are reported
        rather than queried. A manifest that cannot be read marks the sweep
        incomplete: a runtime nobody checked looks exactly like a clean one.
        """
        branch = self._gh.default_branches.get(name)
        if not branch:
            self._gh.failures.append(
                f"repos/{repo} → no default branch in the listing; runtimes unread"
            )
            return []
        tree = self._raw_get(
            f"repos/{repo}/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1",
            repo, "tree",
        )
        if tree.get("truncated"):
            self._gh.failures.append(f"{repo} tree → truncated; manifests may be missing")
        out: list[Dep] = []
        for entry in tree.get("tree") or []:
            path = entry.get("path", "")
            base = path.rsplit("/", 1)[-1]
            if entry.get("type") != "blob":
                continue
            if base in UNCHECKED_RUNTIMES:
                self.skipped.append(
                    f"{repo}  {path}  — runtime not checked: {UNCHECKED_RUNTIMES[base]}"
                )
            elif base == "go.mod":
                blob = self._raw_get(f"repos/{repo}/git/blobs/{entry['sha']}", repo, path)
                if not blob:
                    continue  # failure already recorded
                version, why = go_runtime(base64.b64decode(blob.get("content", "")).decode())
                if version:
                    out.append(Dep(repo, "Go", "stdlib", version, manifest=path))
                else:
                    self.skipped.append(f"{repo}  {path}  — {why}")
        return out

    def _raw_sbom(self, repo: str) -> dict:
        return self._raw_get(f"repos/{repo}/dependency-graph/sbom", repo, "sbom")

    def _raw_get(self, path: str, repo: str, what: str) -> dict:
        """GET one object, falling back to no auth when the token is refused.

        🔴 **An under-scoped token is worse than no token here.** These
        endpoints serve public repositories unauthenticated, but a PAT lacking
        repository read gets 403 — so presenting credentials turned a working
        call into a failure, and the empty SBOM read as "no dependencies".
        Verified 2026-09-15: no auth → HTTP 200, seven packages.
        """
        url = f"https://api.github.com/{path}"
        accept = {"Accept": "application/vnd.github+json"}

        for headers, labelled in (
            ({**accept, "Authorization": f"Bearer {self._gh.token}"}, "with token"),
            (accept, "unauthenticated"),
        ):
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(url, headers=headers), timeout=30
                ) as r:
                    if labelled == "unauthenticated" and repo not in self.fallbacks:
                        self.fallbacks.append(repo)
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code in {401, 403}:
                    continue  # try again without credentials
                self._gh.failures.append(f"{repo} {what} → HTTP {e.code}")
                return {}
            except Exception as e:  # noqa: BLE001
                self._gh.failures.append(f"{repo} {what} → {type(e).__name__}")
                return {}

        # Both attempts refused. NOT "this repo has no dependencies" — recording
        # it is what stops the sweep concluding a fixed CVE from an empty SBOM.
        self._gh.failures.append(f"{repo} {what} → refused with and without auth")
        return {}

    def already_alerted(self) -> set[tuple[str, str]]:
        """(repo, package) pairs GitHub already reports, so we do not double up."""
        seen = set()
        for a in self._gh.alerts():
            if a.kind == "dependabot" and a.package:
                seen.add((a.repo, a.package.casefold()))
        return seen

    def _osv_batch(self, deps: list[Dep]) -> list[list[dict]]:
        out: list[list[dict]] = []
        for i in range(0, len(deps), 100):
            chunk = deps[i : i + 100]
            payload = json.dumps({
                "queries": [
                    {"package": {"name": d.name, "ecosystem": d.ecosystem},
                     "version": d.version}
                    for d in chunk
                ]
            }).encode()
            req = urllib.request.Request(
                OSV_BATCH, data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=60) as r:
                results = json.loads(r.read()).get("results", [])
            out.extend(x.get("vulns") or [] for x in results)
        return out

    def _details(self, vulns: list[dict]) -> list[dict]:
        """Full advisory records for the stubs `querybatch` returns.

        🔴 `querybatch` answers with `id` and `modified` only — verified
        2026-10-11. Rendering those stubs printed every advisory as having no
        summary and **no fix available**, on every OSV issue opened before this
        fetch existed. A record that cannot be fetched stays a stub, and the
        body says its details are missing rather than that there is no fix.
        """
        out = []
        for v in vulns:
            vid = v.get("id", "")
            if vid not in self._records:
                try:
                    url = OSV_VULN + urllib.parse.quote(vid, safe="")
                    with urllib.request.urlopen(url, timeout=30) as r:
                        self._records[vid] = json.loads(r.read())
                except Exception as e:  # noqa: BLE001
                    self._gh.failures.append(f"osv {vid} → {type(e).__name__}")
                    self._records[vid] = v
            out.append(self._records[vid])
        return out

    # ── planning ─────────────────────────────────────────────────────────────

    def findings(self) -> list[Finding]:
        deps = self.deps()
        covered = self.already_alerted()
        gaps = [d for d in deps if (d.repo, d.name.casefold()) not in covered]
        self.covered = len(deps) - len(gaps)

        self.silent = []
        out: list[Finding] = []
        grouped: dict[tuple, list] = defaultdict(list)
        self.suppressions = []
        for dep, vulns in zip(gaps, self._osv_batch(gaps)):
            kept = []
            for v in vulns:
                why = suppression_for(dep.repo, v.get("id", ""))
                if why:
                    self.suppressions.append(
                        f"{dep.repo}  {v['id']}  suppressed — "
                        f"{' '.join(why.split())[:140]}"
                    )
                else:
                    kept.append(v)
            if kept:
                grouped[(dep.repo, dep.manifest, dep.name.casefold())].append((dep, kept))

        for (repo, manifest, _), members in grouped.items():
            dep = members[0][0]
            vulns = members[0][1]
            exposure = exposure_of(repo, manifest or None)
            if exposure == "local":
                self.silent.append((dep, "dependency of a local-only manifest"))
                continue
            out.append(Finding(
                key=marker_url(dep),
                title=f"{_what(dep)} in {repo.split('/')[-1]}"
                      f"{f' ({manifest})' if manifest else ''} — "
                      f"{len(vulns)} advisor{'y' if len(vulns) == 1 else 'ies'} "
                      "OSV reports and GitHub does not"[:120],
                body=_body(dep, self._details(vulns), exposure),
                lane=Lane.PLAN,
                labels=frozenset({self.managed_label}),
                priority=2,
            ))
        return out

    def plan(self, tracker: Tracker) -> Iterable[Action]:
        from datetime import datetime, timedelta, timezone

        managed = [
            i for i in tracker.list_issues(
                IssueQuery(open_only=True, label=self.managed_label)
            )
            if _ours(i.key)
        ]
        result = reconcile(
            self.findings(),
            managed,
            Policy(
                managed_label=self.managed_label,
                close_after=timedelta(hours=self.close_after_hours),
                allowed_labels=self.allowed_labels,
            ),
            datetime.now(timezone.utc),
            complete=not self.failures,
        )
        self.report = result
        return result.actions


def _ours(key: str | None) -> bool:
    """Mirror of `SecuritySource._ours` — see there for why this exists.

    `agent/sec` is shared with `SecuritySource`; a GitHub-alert marker seen
    here is not one of this source's findings and must not be judged absent.
    """
    return key is None or urllib.parse.urlsplit(key).hostname == "osv.dev"


def marker_url(d: Dep) -> str:
    """Identity, and a page showing the advisories.

    The fragment carries the repo because OSV's listing is not repo-scoped, and
    the same vulnerable package in two repos is two separate upgrades. A
    runtime adds its manifest: two modules in one repo are two toolchain bumps. A
    fragment is ignored by the server, so the link still lands somewhere useful.
    """
    q = urllib.parse.urlencode({"q": d.name, "ecosystem": d.ecosystem})
    return f"https://osv.dev/list?{q}#{d.repo}{f'/{d.manifest}' if d.manifest else ''}"


def _what(d: Dep) -> str:
    """`golang.org/x/crypto 0.55.0`, or `Go stdlib 1.26.0` for a runtime."""
    name = f"{d.ecosystem} {d.name}" if d.manifest else d.name
    return f"{name} {d.version}"


def _body(d: Dep, vulns: list[dict], exposure: str) -> str:
    if d.manifest:
        head = [
            f"**{d.repo}** · `{d.manifest}` declares {d.ecosystem} **{d.version}** "
            f"· exposure **{exposure}**.",
            "",
            "🔴 **GitHub cannot report this.** Its SBOM lists third-party "
            "packages only, so the toolchain's standard library is in no "
            "Dependabot alert. Raise the `toolchain` line (or `go`, if there is "
            "none) to a fixed release: a CI build pinned by `go-version-file` "
            "then builds with it.",
        ]
    else:
        head = [
            f"**{d.repo}** · `{d.name}` **{d.version}** ({d.ecosystem}) · "
            f"exposure **{exposure}**.",
            "",
            "🔴 **GitHub reports nothing for this package.** Dependabot alerts "
            "being enabled is not evidence of coverage; treat its silence on "
            "this ecosystem as unproven.",
        ]
    lines = [*head, ""]
    for v in vulns[:6]:
        if "affected" not in v:
            lines.append(f"- **{v['id']}** — details could not be fetched; see osv.dev")
            continue
        # An advisory can cover several packages: one against net/http also
        # lists golang.org/x/net, whose fixes are not this package's fixes.
        mine = [
            a for a in v["affected"]
            if (a.get("package") or {}).get("name", "").casefold() == d.name.casefold()
            and (a.get("package") or {}).get("ecosystem") == d.ecosystem
        ] or v["affected"]
        affected_pkgs = sorted({
            i.get("path", "")
            for a in mine
            for i in (a.get("ecosystem_specific", {}) or {}).get("imports", [])
            if i.get("path")
        })
        fixed = sorted({
            e["fixed"]
            for a in mine
            for r in a.get("ranges", [])
            for e in r.get("events", [])
            if "fixed" in e
        })
        aliases = ", ".join(v.get("aliases", [])[:3])
        lines.append(
            f"- **{v['id']}**{f' ({aliases})' if aliases else ''} — "
            f"{(v.get('summary') or '').strip()[:100]}"
            f"{f' · fixed in {', '.join(fixed)}' if fixed else ' · **no fix available**'}"
        )
        if affected_pkgs:
            lines.append(f"  - affects only: `{'`, `'.join(affected_pkgs[:4])}`")
    if len(vulns) > 6:
        lines.append(f"- … and {len(vulns) - 6} more at the link.")
    lines += [
        "",
        "🔴 **An advisory is against the module; applicability depends on the "
        "*package* you import.** Where the affected packages are listed above, "
        "check them against your imports before sizing this — a vulnerability "
        "in a package you never call is not your vulnerability. For Go, "
        "`govulncheck` answers this properly by tracing reachability.",
    ]
    return "\n".join(lines)
