"""The stateful core, kept pure — and with nowhere of its own to keep state.

`reconcile()` takes what a source found, what the tracker holds, and the current
time, and returns the actions that would make them agree. No IO, no clock of its
own, no store. It is fully testable without a network, and `--plan` is simply
"print the return value instead of applying it".

**There is deliberately no second registry.** An earlier version kept a
key→issue map and absence counters in a local file, which meant the truth about
an issue lived in two places and the copy that mattered could not travel. Both
now live on the issue itself: identity as a tracker-side marker carrying the
finding's URL, and absence as a timestamp beside it. Export the tracker and the
harness's memory comes with it.

The rules, and why each exists:

* **Absence closes, but only after a while.** A finding that stops being emitted
  is no longer true, which is why sources must be state-shaped. But a fault that
  flaps would open and close an issue forever, so a close needs the finding to
  have been gone for `close_after` — measured in *time*, not sweeps, so an
  irregular schedule cannot shorten it.
* **Reappearance clears the mark.** Any sighting resets absence, or a finding
  blinking out near the threshold would close on its next absence regardless of
  how long it had been back.
* **We only touch what we own.** An issue whose managed label a human removed is
  theirs. The harness proposes nothing for it — that is the "adopt" gesture, and
  it must work without anyone telling the harness it happened.
* **Silent findings are not issues.** A queue is for actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Sequence

from .models import (
    Action,
    Close,
    Finding,
    Issue,
    Lane,
    MarkAbsent,
    MarkPresent,
    Open,
    Update,
)


@dataclass(frozen=True, slots=True)
class Policy:
    managed_label: str
    """Carried by every issue this source opens. Its removal is the adopt gesture."""

    close_after: timedelta = timedelta(hours=24)
    """How long a finding must be gone before its issue closes. Never zero."""

    allowed_labels: frozenset[str] = frozenset()
    """Labels the tracker's contract permits. Anything else on a managed issue is
    stripped. Empty means "do not police labels"."""

    def __post_init__(self) -> None:
        if self.close_after <= timedelta(0):
            raise ValueError(
                "close_after must be positive: closing the moment a finding "
                "first goes missing lets a flapping fault churn the queue"
            )


@dataclass(frozen=True, slots=True)
class Plan:
    actions: tuple[Action, ...]
    adopted: tuple[str, ...] = ()
    """Issues a human has taken. Reported, never acted on."""


def reconcile(
    findings: Iterable[Finding],
    managed: Sequence[Issue],
    policy: Policy,
    now: datetime,
) -> Plan:
    """Return the actions that reconcile `findings` against `managed`.

    `managed` is every open issue carrying the policy's label, each already
    carrying the key and absence mark the tracker read back for it.
    """
    actionable = {f.key: f for f in findings if f.lane is not Lane.SILENT}

    ours = [i for i in managed if policy.managed_label in i.labels]
    adopted = [i.ref or i.id for i in managed if policy.managed_label not in i.labels]
    by_key = {i.key: i for i in ours if i.key}

    actions: list[Action] = []

    for key, finding in actionable.items():
        issue = by_key.get(key)
        if issue is None or issue.closed:
            actions.append(Open(finding, why="newly true, no open issue"))
            continue
        if issue.absent_since is not None:
            actions.append(
                MarkPresent(issue.id, why="seen again; absence mark cleared")
            )
        if (diff := _drift(issue, finding, policy)) is not None:
            actions.append(diff)

    for key, issue in by_key.items():
        if key in actionable or issue.closed:
            continue
        if issue.absent_since is None:
            actions.append(MarkAbsent(issue.id, since=now, why="no longer reported"))
            continue
        gone = now - issue.absent_since
        if gone >= policy.close_after:
            actions.append(
                Close(issue.id, why=f"absent for {_human(gone)}, no longer true")
            )

    return Plan(actions=tuple(actions), adopted=tuple(adopted))


def _human(d: timedelta) -> str:
    h = d.total_seconds() / 3600
    return f"{h:.0f}h" if h < 48 else f"{h / 24:.0f}d"


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
    # added deliberately (`needs/decision`) is left alone — this normalises, it
    # does not tidy. With no contract configured it touches nothing.
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
