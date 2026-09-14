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

    🔴 Normalising is not cosmetic. The map is keyed by bare name while alerts
    carry `owner/name`, so the first version of this matched nothing and
    classified every finding `local` — a sweep that silently found nothing and
    looked exactly like a clean estate.
    """
    name = repo.rsplit("/", 1)[-1]
    for prefix, exp in EXPOSURE.get(name, []):
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

    def _get(self, path: str) -> list[dict]:
        """GET a collection, returning [] where a feature is simply off.

        404 and 403 mean "not enabled here", not "broken" — most repos have
        code scanning or secret scanning switched off, and a sweep that treated
        that as an error would never finish.
        """
        req = urllib.request.Request(
            f"{API}/{path.lstrip('/')}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in {403, 404}:
                return []
            raise GitHubError(f"GET {path} → HTTP {e.code}") from e
        return data if isinstance(data, list) else []

    def repos(self) -> list[str]:
        out = []
        page = 1
        while True:
            batch = self._get(f"users/{self.owner}/repos?per_page=100&page={page}")
            if not batch:
                return out
            out.extend(r["name"] for r in batch if not r.get("archived"))
            if len(batch) < 100:
                return out
            page += 1

    def alerts(self) -> list[Alert]:
        found: list[Alert] = []
        for name in self.repos():
            repo = f"{self.owner}/{name}"
            for a in self._get(f"repos/{repo}/dependabot/alerts?state=open&per_page=100"):
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
            for a in self._get(f"repos/{repo}/secret-scanning/alerts?state=open&per_page=100"):
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
        return out

    def plan(self, tracker: Tracker) -> Iterable[Action]:
        from datetime import datetime, timedelta, timezone

        managed = tracker.list_issues(
            IssueQuery(open_only=True, label=self.managed_label)
        )
        policy = Policy(
            managed_label=self.managed_label,
            close_after=timedelta(hours=self.close_after_hours),
            allowed_labels=self.allowed_labels,
        )
        result = reconcile(
            self.findings(), managed, policy, datetime.now(timezone.utc)
        )
        self.report = result
        return result.actions


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
