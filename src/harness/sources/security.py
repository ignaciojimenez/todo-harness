"""GitHub security alerts, as a finding source.

Ported from a prototype that ran in shadow mode for weeks. The routing below is
the part that took three real defects to get right — read the notes before
changing any threshold.

The question it asks is **"what is vulnerable right now"**, never "what advisory
was published". An advisory is an event and cannot retract; a Dependabot email
once arrived 19 hours after the fix had shipped. Asking GitHub for open alerts
on every sweep means a fixed vulnerability simply stops being reported, and the
issue closes on its own.

⚠️ GitHub is not a complete picture. Verified 2026-09-14: `touchid-agent` had
Dependabot alerts enabled and `golang.org/x/crypto v0.55.0` in `go.mod`, with
two DoS advisories against the `ssh` package it imports — and GitHub reported
zero. Treat silence here as unproven coverage, which is why an OSV source is
planned alongside rather than instead.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from ..models import Action, Finding, IssueQuery, Lane
from ..ports import Tracker
from ..reconcile import Policy, reconcile

API = "https://api.github.com"

EXPOSURE: dict[str, list[tuple[str, str]]] = {
    "pastebin-worker": [
        # scripts/ is a laptop CLI for managing an instance; worker/ is the
        # deployed service. Repo-level exposure would call the CLI public and
        # raise its findings to `plan`, which is how five alerts about a local
        # admin script nearly became two tickets.
        ("scripts", "local"),
        ("", "public"),
    ],
    "ignaciojimenezpi.github.io": [
        # NOT local, despite looking like a helper: the album workflows
        # pip-install these requirements and run the code in CI with
        # `contents: write` on a public repo, and Pillow's attack surface is the
        # image files it parses.
        ("photography/utils", "supplychain"),
        ("", "public"),
    ],
    "recordsdelmundo-site-static": [("", "public")],
    "touchid-agent": [("", "supplychain")],  # brew tap → other people's laptops
    "homebrew-tap": [("", "supplychain")],  # the formula that installs it
    "rpi-provisioner": [("", "supplychain")],  # writes the images hosts boot from
    "infrastructure-automation": [("", "supplychain")],  # controls the fleet
    "todo-harness": [("", "supplychain")],  # holds tracker write credentials
}
"""Where code actually runs, keyed by manifest prefix, first match wins.

The one piece of config a human owns — it cannot be derived from any API, and
repo visibility is not a proxy for it. **Both entries above with a path prefix
were wrong at first**, in opposite directions, which is the argument for
checking rather than assuming when adding a repo.
"""

EPSS_PAGE_PERCENTILE = 0.90
"""Above this, "someone is actively exploiting this" outweighs a dev-only scope."""


def exposure_of(repo: str, path: str | None) -> str:
    """Exposure for a manifest. Accepts `name` or `owner/name`.

    A repo missing from the map is `unknown`, never `local`. Defaulting to local
    routed a runtime vulnerability in any new repo to silent: the map's gap read
    as a verdict, and the fix for a missing classification is to ask for one.

    🔴 Normalising is not cosmetic. The map is keyed by bare name while alerts
    carry `owner/name`, so the first version of this matched nothing and
    classified every finding `local` — a sweep that silently found nothing and
    looked exactly like a clean estate.
    """
    name = repo.rsplit("/", 1)[-1]
    if name not in EXPOSURE:
        return "unknown"
    for prefix, exp in EXPOSURE[name]:
        if (path or "").startswith(prefix):
            return exp
    return "local"


@dataclass(frozen=True, slots=True)
class Alert:
    """One GitHub alert, flattened to what routing needs."""

    kind: str
    repo: str
    number: int
    title: str
    severity: str | None
    path: str | None
    package: str | None = None
    scope: str | None = None
    epss: float | None = None

    @property
    def exposure(self) -> str:
        return exposure_of(self.repo, self.path)


def route(a: Alert) -> tuple[Lane, str]:
    """Which lane an alert belongs in, and why. The `why` reaches the issue."""
    if a.kind == "secret":
        return Lane.PAGE, "a live credential is exposed"

    if a.kind == "dependabot":
        if a.epss is None:
            # Absence of a score is not evidence of a low one — a CVE too new to
            # be scored read as "nobody is exploiting this" and was routed
            # silent. Caught on a package that had no score.
            if a.exposure != "local":
                return Lane.PLAN, "no EPSS score yet; too new to judge as quiet"
            return Lane.SILENT, "unscored, and only a local manifest"
        if a.epss >= EPSS_PAGE_PERCENTILE:
            return Lane.PAGE, f"EPSS {a.epss:.0%}ile — actively exploited in the wild"
        if a.scope == "development":
            return Lane.SILENT, (
                f"build-time only (EPSS {a.epss:.0%}ile); not in the shipped artefact"
            )
        if a.exposure == "public":
            return Lane.PLAN, "runtime dependency of an internet-facing service"
        if a.exposure == "supplychain":
            return Lane.PLAN, "runtime dependency of something distributed to machines"
        if a.exposure == "unknown":
            return Lane.PLAN, "repo is not in the exposure map — classify it in EXPOSURE"
        return Lane.SILENT, f"runtime dependency of a {a.exposure}-only manifest"

    if a.kind == "code":
        if a.severity in {"critical", "high"} and a.exposure != "local":
            return Lane.PLAN, f"SAST finding in {a.exposure} code"
        return Lane.SILENT, "SAST finding in code that is not exposed"

    return Lane.PLAN, "unclassified — defaulting to human review"


def group_key(a: Alert) -> tuple:
    """What counts as *one piece of work*.

    Deliberately not the alert. One Pillow upgrade can fix three advisories, and
    three tickets for one action would make this a findings list rather than a
    queue. Manifest is part of the key because the exposure map is
    manifest-level: the same package in a published site and in a CI-only helper
    are genuinely different jobs.
    """
    if a.kind == "dependabot":
        return (a.repo, a.path or "", (a.package or "").casefold())
    if a.kind == "code":
        return (a.repo, a.path or "", a.title)
    return (a.repo, a.number)


def marker_url(a: Alert) -> str:
    """A real, clickable URL that identifies the group — and is its identity.

    Points at the filtered alert list rather than one alert, so it stays valid
    as individual alerts in the group are fixed or dismissed.
    """
    base = f"https://github.com/{a.repo}/security"
    if a.kind == "dependabot":
        q = urllib.parse.quote_plus(f"is:open package:{a.package}")
        return f"{base}/dependabot?q={q}"
    if a.kind == "code":
        q = urllib.parse.quote_plus(f"is:open rule:{a.title}")
        return f"{base}/code-scanning?query={q}"
    return f"{base}/secret-scanning/{a.number}"


class GitHubError(RuntimeError):
    pass


@dataclass
class SecuritySource:
    owner: str
    token: str | None = None
    managed_label: str = "agent/sec"
    allowed_labels: frozenset[str] = frozenset()
    close_after_hours: int = 24
    name: str = "security"
    unit: str = "repos"

    seen: int = 0
    """Repos swept. Zero is never a clean estate — see `repos()`."""

    failures: list[str] = field(default_factory=list)
    """Endpoints that failed transiently. A sweep across many repos must not be
    taken down by one of them — but a repo that silently went unscanned is
    indistinguishable from a clean one, so these are reported and they mark the
    run as degraded rather than healthy."""

    gaps: list[str] = field(default_factory=list)
    """Repos where GitHub says a scanner is **disabled**. Each becomes a finding:
    a repo nobody scans looks exactly like a clean one, and a new repo starts
    unscanned unless someone remembers. Re-enabling it closes the issue."""

    analysis_gaps: list[tuple[str, str, str]] = field(default_factory=list)
    """(repo, category, error) for each CodeQL language whose *latest* analysis
    errored. Default setup drops a failed language and still reports the run a
    success — touchid-agent's first run left Go, Swift and C unscanned with
    only Ruby and Actions actually covered. Same shape as `gaps`: a 404 here
    means code scanning is off entirely, which is optional and stays quiet."""

    silent: list[tuple[Alert, str]] = field(default_factory=list)
    """Routed away. Never an issue; printed so what was swallowed is arguable."""

    paged: list[Finding] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.token = self.token or os.environ.get("HARNESS_GH_TOKEN")
        if not self.token:
            raise GitHubError(
                "no GitHub token: set HARNESS_GH_TOKEN. Read-only on security "
                "alerts across the repos you want swept; it never needs write."
            )

    # ── fetching ─────────────────────────────────────────────────────────────

    def _get(self, path: str, required: bool = False) -> list[dict]:
        """GET a collection — every page of it — returning [] where a feature
        is simply off.

        404 and 403 mean "not enabled here", not "broken" — most repos have
        code scanning or secret scanning switched off, and a sweep that treated
        that as an error would never finish.

        🔴 Pages are followed by the `Link` header, which is the only scheme the
        alert endpoints support (they page by cursor, not `page=`). The port
        once read page one and stopped: alert 101 went unread, and the
        reconciler would have closed its issue as fixed. A page that fails
        after the first marks the sweep incomplete rather than returning a
        partial list as if it were whole.

        `required` is for scanners every repo should have. There, "not enabled"
        is not a shrug: GitHub's 404 says *"Secret scanning is disabled on this
        repository."* (captured 2026-09-18), which is recorded as a gap. Any
        other refusal — a token missing a permission, say — cannot be told apart
        from a clean repo, so it marks the sweep incomplete instead.
        """
        url = f"{API}/{path.lstrip('/')}"
        out: list[dict] = []
        first = True
        while url:
            if not url.startswith(f"{API}/"):
                # The next URL is taken from a response header, and the request
                # carries the token. Never send it anywhere but the API.
                self.failures.append(f"{path} → refused off-API next page {url}")
                return out
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = json.loads(r.read())
                    url = _next_page(r.headers.get("Link"))
            except urllib.error.HTTPError as e:
                if e.code in {403, 404} and first and required:
                    msg = _message(e)
                    if "disabled" in msg.lower():
                        self.gaps.append(path)
                    else:
                        self.failures.append(f"{path} → HTTP {e.code}: {msg}")
                    return []
                if e.code in {403, 404} and first:
                    return []  # feature simply not enabled on this repo
                if e.code in {401}:
                    # Not transient, and everything after it would be a false
                    # clean bill of health. Fail the run.
                    raise GitHubError(f"GET {path} → HTTP 401: token rejected") from e
                self.failures.append(f"{path} → HTTP {e.code}")
                return out
            except (urllib.error.URLError, TimeoutError) as e:
                self.failures.append(f"{path} → {type(e).__name__}")
                return out
            if not isinstance(data, list):
                return out
            out.extend(data)
            first = False
        return out

    def repos(self) -> list[str]:
        """🔴 An empty list with HTTP 200 is not an empty estate. A mistyped
        owner or a token that lists nothing returns exactly that, and read as a
        complete sweep it marks every open issue absent — closed a day later,
        on no evidence at all. So it marks the sweep incomplete instead."""
        before = len(self.failures)
        names = [
            r["name"]
            for r in self._get(f"users/{self.owner}/repos?per_page=100")
            if not r.get("archived")
        ]
        if not names and len(self.failures) == before:
            self.failures.append(
                f"users/{self.owner}/repos → no repositories to sweep; a wrong "
                "owner or a blind token looks exactly like an empty estate"
            )
        return names

    def alerts(self) -> list[Alert]:
        found: list[Alert] = []
        names = self.repos()
        self.seen = len(names)
        for name in names:
            repo = f"{self.owner}/{name}"
            for a in self._get(f"repos/{repo}/dependabot/alerts?state=open&per_page=100",
                               required=True):
                adv = a.get("security_advisory") or {}
                dep = a.get("dependency") or {}
                found.append(Alert(
                    kind="dependabot", repo=repo, number=a.get("number", 0),
                    title=(adv.get("summary") or "")[:90],
                    severity=adv.get("severity"),
                    path=dep.get("manifest_path"),
                    package=((a.get("security_vulnerability") or {})
                             .get("package") or {}).get("name"),
                    scope=dep.get("scope"),
                    epss=(adv.get("epss") or {}).get("percentile"),
                ))
            for a in self._get(f"repos/{repo}/code-scanning/alerts?state=open&per_page=100"):
                rule = a.get("rule") or {}
                loc = ((a.get("most_recent_instance") or {}).get("location") or {})
                found.append(Alert(
                    kind="code", repo=repo, number=a.get("number", 0),
                    title=rule.get("id") or "",
                    severity=rule.get("security_severity_level") or rule.get("severity"),
                    path=loc.get("path"),
                ))
            analyses = self._get(f"repos/{repo}/code-scanning/analyses?per_page=100")
            for category, error in _analysis_errors(analyses):
                self.analysis_gaps.append((repo, category, error))
            for a in self._get(f"repos/{repo}/secret-scanning/alerts?state=open&per_page=100",
                               required=True):
                found.append(Alert(
                    kind="secret", repo=repo, number=a.get("number", 0),
                    title=a.get("secret_type_display_name") or "secret",
                    severity="critical", path=None,
                ))
        return found

    # ── planning ─────────────────────────────────────────────────────────────

    def findings(self) -> list[Finding]:
        grouped: dict[tuple, list[Alert]] = defaultdict(list)
        for a in self.alerts():
            grouped[group_key(a)].append(a)

        self.silent, self.paged = [], []
        out: list[Finding] = []
        for members in grouped.values():
            head = members[0]
            lane, why = route(head)
            if lane is Lane.SILENT:
                self.silent.extend((m, why) for m in members)
                continue
            f = Finding(
                key=marker_url(head),
                title=_title(head, len(members)),
                body=_body(head, members, why),
                lane=lane,
                labels=frozenset({self.managed_label}),
                priority=1 if lane is Lane.PAGE else 2,
            )
            out.append(f)
            if lane is Lane.PAGE:
                self.paged.append(f)
        out.extend(_gap_finding(p, self.managed_label) for p in self.gaps)
        out.extend(
            _analysis_gap_finding(repo, category, error, self.managed_label)
            for repo, category, error in self.analysis_gaps
        )
        return out

    def plan(self, tracker: Tracker) -> Iterable[Action]:
        from datetime import datetime, timedelta, timezone

        managed = [
            i for i in tracker.list_issues(
                IssueQuery(open_only=True, label=self.managed_label)
            )
            if _ours(i.key)
        ]
        policy = Policy(
            managed_label=self.managed_label,
            close_after=timedelta(hours=self.close_after_hours),
            allowed_labels=self.allowed_labels,
        )
        findings = self.findings()
        result = reconcile(
            findings, managed, policy, datetime.now(timezone.utc),
            complete=not self.failures,
        )
        self.report = result
        return result.actions


def _ours(key: str | None) -> bool:
    """Whether a marker could be this source's own.

    `agent/sec` is shared with `OsvSource` — the same label covering the same
    problem from two angles. Without this, an issue OSV opened is invisible to
    this source's findings and reads as "no longer reported", marking it
    absent on the very next sweep it shares the label with. An issue with no
    marker at all is left in either way, so the "adopted by hand" detection in
    `reconcile()` still sees it.
    """
    return key is None or urllib.parse.urlsplit(key).hostname == "github.com"


def _message(e: urllib.error.HTTPError) -> str:
    """GitHub's own words for a refusal — the only thing that tells "disabled"
    from "you may not look"."""
    try:
        return str(json.loads(e.read() or b"{}").get("message") or "")
    except (ValueError, AttributeError, OSError):
        return ""


def _gap_finding(path: str, label: str) -> Finding:
    """A scanner switched off, as a piece of work. Closes itself once it is on."""
    _, owner, name, endpoint = path.split("?")[0].split("/")[:4]
    scanner = endpoint.replace("-", " ")
    fix = (
        f"`gh api -X PATCH repos/{owner}/{name}` with "
        '`security_and_analysis.secret_scanning` and '
        '`secret_scanning_push_protection` set to `enabled`'
        if endpoint == "secret-scanning"
        else f"`gh api -X PUT repos/{owner}/{name}/vulnerability-alerts`"
    )
    return Finding(
        key=f"https://github.com/{owner}/{name}/settings/security_analysis#{endpoint}",
        title=f"{scanner.capitalize()} is off in {name}",
        body="\n".join([
            f"GitHub reports {scanner} **disabled** on **{owner}/{name}**, so the "
            "sweep cannot see what it would have found there — which looks "
            "exactly like a clean repo.",
            "",
            f"Enable it (free on public repos): {fix}. This issue closes on the "
            "next sweep.",
        ]),
        lane=Lane.PLAN,
        labels=frozenset({label}),
        priority=2,
    )


def _analysis_errors(analyses: list[dict]) -> list[tuple[str, str]]:
    """(category, error) for each category whose *most recent* analysis errored.

    Latest is by `created_at`, not by list position — a failed run and its
    fixed rerun can land in either order within one page, and picking the
    wrong one is the whole bug this exists to catch.
    """
    latest: dict[str, dict] = {}
    for a in analyses:
        category = a.get("category")
        if not category:
            continue
        current = latest.get(category)
        if current is None or a.get("created_at", "") > current.get("created_at", ""):
            latest[category] = a
    return [(category, a["error"]) for category, a in latest.items() if a.get("error")]


def _analysis_gap_finding(repo: str, category: str, error: str, label: str) -> Finding:
    """A CodeQL language whose latest run errored, as a piece of work. Default
    setup drops the language and reports the run a success, so this looks
    exactly like a clean language until someone checks. Closes itself once a
    clean analysis for this category lands.

    The key carries only repo and category — never the analysis id or a
    timestamp — so every failed rerun of the same language maps to the same
    issue instead of opening a new one each time.
    """
    lang = category.strip("/").split(":", 1)[-1]
    name = repo.rsplit("/", 1)[-1]
    return Finding(
        key=f"https://github.com/{repo}/security/code-scanning"
            f"#{urllib.parse.quote(category.strip('/'), safe=':')}",
        title=f"CodeQL {lang} analysis is failing in {name}",
        body="\n".join([
            f"GitHub's latest code-scanning analysis for **{category}** on "
            f"**{repo}** errored, so the sweep cannot see what CodeQL would "
            "have found there — which looks exactly like a clean language.",
            "",
            f"GitHub's error: `{error}`",
            "",
            "This issue closes on the next sweep once a clean analysis for "
            "this category lands.",
        ]),
        lane=Lane.PLAN,
        labels=frozenset({label}),
        priority=2,
    )


def _next_page(link: str | None) -> str | None:
    """The `rel="next"` URL from a GitHub `Link` header, if there is one."""
    for part in (link or "").split(","):
        url, _, rel = part.partition(";")
        if rel.strip() == 'rel="next"':
            return url.strip().strip("<>")
    return None


def _title(a: Alert, n: int) -> str:
    if a.kind == "dependabot":
        extra = f" ({n} advisories)" if n > 1 else ""
        return f"{a.package} in {a.repo.split('/')[-1]}{extra} — {a.title}"[:120]
    if a.kind == "code":
        extra = f" ({n} instances)" if n > 1 else ""
        return f"{a.title} in {a.path}{extra}"[:120]
    return f"Exposed {a.title} in {a.repo.split('/')[-1]}"


def _body(a: Alert, members: list[Alert], why: str) -> str:
    where = a.path or "repository"
    lines = [
        f"**{a.repo}** · `{where}` · exposure **{a.exposure}** · severity "
        f"{a.severity or 'unknown'}.",
        "",
        f"Routed here because: {why}.",
    ]
    if len(members) > 1:
        nums = ", ".join(f"#{m.number}" for m in members[:8])
        lines += ["", f"Covers {len(members)} alerts ({nums}) — one fix closes them all."]
    lines += [
        "",
        "🔴 Fix it at the source. Dismissing the alert also clears this issue, "
        "because the sweep reads GitHub's state rather than keeping its own.",
    ]
    return "\n".join(lines)
