"""Normalise untriaged intake.

A *rule* source, not a finding source: it inspects the tracker and proposes
corrections, so it opens and closes nothing and needs no store.

It exists because capture surfaces don't know the contract. An issue dictated
into a phone arrives shaped by whatever the capturing client thought a good
issue looks like — headings, stock labels, a label that happens to mean
"a machine may close this". Teaching every client the rules is a losing game;
normalising afterwards works no matter what captured it.

Deliberately narrow. It fixes only what is unambiguous:

* strips labels outside the contract;
* sets the project when exactly one known project is named in the text.

Everything else it reports and leaves alone. A normaliser that guesses is one
people switch off — and a wrong project is worse than no project, because no
project is a queryable state and a wrong one is invisible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from ..models import Action, Issue, IssueQuery, Update
from ..ports import Tracker


@dataclass(frozen=True, slots=True)
class TriageReport:
    """What the sweep could not fix. Printed, never written to the tracker."""

    seen: int = 0
    ambiguous_project: tuple[Issue, ...] = ()
    no_project_match: tuple[Issue, ...] = ()
    long_body: tuple[Issue, ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.ambiguous_project or self.no_project_match or self.long_body)


@dataclass
class TriageSource:
    allowed_labels: frozenset[str]
    """The tracker's label contract. Anything else on intake is stripped."""

    max_body_lines: int = 6
    """Descriptions longer than this are reported, never truncated — the text is
    the author's, and silently rewriting someone's words is not normalisation."""

    name: str = "triage"
    needs_store: bool = False
    """Everything is derived from the tracker each run, so an empty store is
    harmless here — unlike a finding source."""

    report: TriageReport = field(default_factory=TriageReport)

    def plan(self, tracker: Tracker) -> Iterable[Action]:
        untriaged = tracker.list_issues(
            IssueQuery(open_only=True, without_project=True)
        )
        projects = tracker.list_projects()

        actions: list[Action] = []
        ambiguous: list[Issue] = []
        unmatched: list[Issue] = []
        verbose: list[Issue] = []

        for issue in untriaged:
            reasons: list[str] = []
            project = None

            matches = _projects_named(issue, projects)
            if len(matches) == 1:
                project = matches[0]
                reasons.append(f"names {project}")
            elif len(matches) > 1:
                ambiguous.append(issue)
            else:
                unmatched.append(issue)

            strip = issue.labels - self.allowed_labels
            if strip:
                reasons.append("labels outside the contract: " + ", ".join(sorted(strip)))

            if _line_count(issue.body) > self.max_body_lines:
                verbose.append(issue)

            if project or strip:
                actions.append(
                    Update(
                        issue_id=issue.id,
                        why="; ".join(reasons),
                        project=project,
                        remove_labels=frozenset(strip),
                    )
                )

        self.report = TriageReport(
            seen=len(untriaged),
            ambiguous_project=tuple(ambiguous),
            no_project_match=tuple(unmatched),
            long_body=tuple(verbose),
        )
        return actions


def _projects_named(issue: Issue, projects: Iterable[str]) -> list[str]:
    """Projects whose name appears in the issue text.

    Matching is whole-token and case-insensitive. A substring match would map
    anything mentioning "dotfiles" in passing onto that project, and the cost of
    a wrong project is higher than the cost of leaving it untriaged.
    """
    haystack = f"{issue.title}\n{issue.body}".lower()
    found = []
    for p in projects:
        if not p:
            continue
        if re.search(rf"(?<![\w-]){re.escape(p.lower())}(?![\w-])", haystack):
            found.append(p)
    return found


def _line_count(body: str) -> int:
    return len([ln for ln in (body or "").splitlines() if ln.strip()])
