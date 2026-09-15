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
"""

from __future__ import annotations

import json
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


@dataclass
class OsvSource:
    owner: str
    token: str | None = None
    managed_label: str = "agent/sec"
    allowed_labels: frozenset[str] = frozenset()
    close_after_hours: int = 24
    name: str = "osv"

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
        return out

    def _raw_sbom(self, repo: str) -> dict:
        """Fetch the SBOM, falling back to no auth when the token is refused.

        🔴 **An under-scoped token is worse than no token here.** This endpoint
        serves public repositories unauthenticated, but a PAT lacking repository
        read gets 403 — so presenting credentials turned a working call into a
        failure, and the empty result read as "no dependencies". Verified
        2026-09-15: no auth → HTTP 200, seven packages.
        """
        url = f"https://api.github.com/repos/{repo}/dependency-graph/sbom"
        accept = {"Accept": "application/vnd.github+json"}

        for headers, labelled in (
            ({**accept, "Authorization": f"Bearer {self._gh.token}"}, "with token"),
            (accept, "unauthenticated"),
        ):
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(url, headers=headers), timeout=30
                ) as r:
                    if labelled == "unauthenticated":
                        self.fallbacks.append(repo)
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                if e.code in {401, 403}:
                    continue  # try again without credentials
                self._gh.failures.append(f"{repo} sbom → HTTP {e.code}")
                return {}
            except Exception as e:  # noqa: BLE001
                self._gh.failures.append(f"{repo} sbom → {type(e).__name__}")
                return {}

        # Both attempts refused. NOT "this repo has no dependencies" — recording
        # it is what stops the sweep concluding a fixed CVE from an empty SBOM.
        self._gh.failures.append(f"{repo} sbom → refused with and without auth")
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
                grouped[(dep.repo, dep.name.casefold())].append((dep, kept))

        for (repo, _), members in grouped.items():
            dep = members[0][0]
            vulns = members[0][1]
            exposure = exposure_of(repo, None)
            if exposure == "local":
                self.silent.append((dep, "dependency of a local-only repo"))
                continue
            out.append(Finding(
                key=marker_url(dep),
                title=f"{dep.name} {dep.version} in {repo.split('/')[-1]} — "
                      f"{len(vulns)} advisor{'y' if len(vulns) == 1 else 'ies'} "
                      "OSV reports and GitHub does not"[:120],
                body=_body(dep, vulns, exposure),
                lane=Lane.PLAN,
                labels=frozenset({self.managed_label}),
                priority=2,
            ))
        return out

    def plan(self, tracker: Tracker) -> Iterable[Action]:
        from datetime import datetime, timedelta, timezone

        managed = tracker.list_issues(
            IssueQuery(open_only=True, label=self.managed_label)
        )
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


def marker_url(d: Dep) -> str:
    """Identity, and a page showing the advisories.

    The fragment carries the repo because OSV's listing is not repo-scoped, and
    the same vulnerable package in two repos is two separate upgrades. A
    fragment is ignored by the server, so the link still lands somewhere useful.
    """
    q = urllib.parse.urlencode({"q": d.name, "ecosystem": d.ecosystem})
    return f"https://osv.dev/list?{q}#{d.repo}"


def _body(d: Dep, vulns: list[dict], exposure: str) -> str:
    lines = [
        f"**{d.repo}** · `{d.name}` **{d.version}** ({d.ecosystem}) · "
        f"exposure **{exposure}**.",
        "",
        "🔴 **GitHub reports nothing for this package.** Dependabot alerts being "
        "enabled is not evidence of coverage; treat its silence on this "
        "ecosystem as unproven.",
        "",
    ]
    for v in vulns[:6]:
        affected_pkgs = sorted({
            i.get("path", "")
            for a in v.get("affected", [])
            for i in (a.get("ecosystem_specific", {}) or {}).get("imports", [])
            if i.get("path")
        })
        fixed = sorted({
            e["fixed"]
            for a in v.get("affected", [])
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
    lines += [
        "",
        "🔴 **An advisory is against the module; applicability depends on the "
        "*package* you import.** Where the affected packages are listed above, "
        "check them against your imports before sizing this — a vulnerability "
        "in a package you never call is not your vulnerability. For Go, "
        "`govulncheck` answers this properly by tracing reachability.",
    ]
    return "\n".join(lines)
