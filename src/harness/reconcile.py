"""The stateful core, kept pure.

`reconcile()` takes what a source found, what the tracker holds, and what the
store remembers, and returns the actions that would make them agree. It performs
no IO, so it is fully testable without a network, and `--plan` is simply "print
the return value instead of applying it".

The rules it encodes, and why each exists:

* **Absence closes, but slowly.** A finding that stops being emitted is no
  longer true, which is the whole reason sources are state-shaped. But one
  clear sweep is not evidence — a flapping fault would open and close an issue
  forever — so a close needs `close_after_clear_sweeps` consecutive clear
  sweeps.
* **Reappearance resets.** Any sighting zeroes the streak. Otherwise a finding
  that blinks out near the threshold closes on its next absence regardless of
  how long it has been back.
* **We only touch what we own.** An issue whose managed label a human removed
  is theirs now. The harness stops proposing anything for it and forgets its
  key — that is the "adopt" gesture, and it must work without anyone telling
  the harness it happened.
* **Silent findings are not issues.** A queue is for actions. Findings routed
  `SILENT` are recorded by the source for audit and never reach the tracker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .models import Action, Close, Finding, Issue, Lane, Open, Update


@dataclass(frozen=True, slots=True)
class Policy:
    managed_label: str
    """Carried by every issue this source opens. Its removal is the adopt gesture."""

    close_after_clear_sweeps: int = 3
    """Consecutive absences before closing. Never 1."""

    allowed_labels: frozenset[str] = frozenset()
    """Labels the tracker's contract permits. Anything else on a managed issue
    is stripped. Empty means "do not police labels"."""

    def __post_init__(self) -> None:
        if self.close_after_clear_sweeps < 2:
            raise ValueError(
                "close_after_clear_sweeps must be >= 2: closing on a single "
                "clear sweep lets a flapping fault churn the queue"
            )


class StreakReader:
    """The slice of `Store` that `reconcile` needs, so tests can pass a dict."""

    def __init__(self, issue_ids: dict[str, str], streaks: dict[str, int]) -> None:
        self.issue_ids = issue_ids
        self.streaks = streaks

    def issue_id_for(self, key: str) -> str | None:
        return self.issue_ids.get(key)

    def clear_streak(self, key: str) -> int:
        return self.streaks.get(key, 0)


@dataclass(frozen=True, slots=True)
class Plan:
    actions: tuple[Action, ...]
    seen_keys: frozenset[str]
    """Keys present this sweep — the runner resets their streaks after applying."""

    absent_keys: frozenset[str]
    """Managed keys not seen — the runner bumps their streaks after applying."""

    dropped_keys: frozenset[str]
    """Keys the harness no longer owns (label removed). Forget them."""


def reconcile(
    findings: Iterable[Finding],
    managed: Sequence[Issue],
    store: StreakReader,
    policy: Policy,
) -> Plan:
    """Return the actions that reconcile `findings` against `managed`."""
    actionable = [f for f in findings if f.lane is not Lane.SILENT]
    by_key = {f.key: f for f in actionable}

    by_id = {i.id: i for i in managed}
    owned_ids = {i.id for i in managed if policy.managed_label in i.labels}

    actions: list[Action] = []
    dropped: set[str] = set()

    # Keys whose issue we no longer own: a human adopted it. Stop touching it.
    for key in list(store.issue_ids):
        issue_id = store.issue_id_for(key)
        if issue_id and issue_id in by_id and issue_id not in owned_ids:
            dropped.add(key)

    for key, finding in by_key.items():
        if key in dropped:
            continue
        issue_id = store.issue_id_for(key)
        issue = by_id.get(issue_id) if issue_id else None

        if issue is None or issue.closed:
            actions.append(Open(finding, why="newly true, no open issue"))
            continue

        if (diff := _drift(issue, finding, policy)) is not None:
            actions.append(diff)

    # Absent: owned issues whose finding was not emitted this sweep.
    absent: set[str] = set()
    for key in list(store.issue_ids):
        if key in by_key or key in dropped:
            continue
        issue_id = store.issue_id_for(key)
        if not issue_id or issue_id not in owned_ids:
            continue
        issue = by_id[issue_id]
        if issue.closed:
            continue
        absent.add(key)
        streak = store.clear_streak(key) + 1
        if streak >= policy.close_after_clear_sweeps:
            actions.append(
                Close(issue_id, why=f"absent for {streak} consecutive sweeps")
            )

    return Plan(
        actions=tuple(actions),
        seen_keys=frozenset(by_key) - dropped,
        absent_keys=frozenset(absent),
        dropped_keys=frozenset(dropped),
    )


def _drift(issue: Issue, finding: Finding, policy: Policy) -> Update | None:
    """What has changed about a finding that is still true."""
    reasons: list[str] = []
    title = body = project = None
    priority = None

    if issue.title != finding.title:
        title = finding.title
        reasons.append("title")
    if finding.body and issue.body != finding.body:
        body = finding.body
        reasons.append("body")
    if finding.project and issue.project != finding.project:
        project = finding.project
        reasons.append("project")
    if finding.priority is not None and issue.priority != finding.priority:
        priority = finding.priority
        reasons.append("priority")

    want = finding.labels | {policy.managed_label}
    add = want - issue.labels
    # Strip only labels outside the tracker's contract. A contract label a human
    # added deliberately (`needs:choco`) is left alone — this normalises, it does
    # not tidy. With no contract configured it touches nothing.
    remove = issue.labels - policy.allowed_labels if policy.allowed_labels else frozenset()
    if add:
        reasons.append("labels+")
    if remove:
        reasons.append("labels-")

    if not reasons:
        return None
    return Update(
        issue_id=issue.id,
        why="drift: " + ", ".join(reasons),
        title=title,
        body=body,
        project=project,
        priority=priority,
        add_labels=frozenset(add),
        remove_labels=frozenset(remove),
    )
