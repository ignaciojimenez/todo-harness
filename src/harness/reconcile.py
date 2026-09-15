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
    absence_suppressed: int = 0
    """Issues that would have been marked absent or closed, but were not because
    the sweep was incomplete. Reported, so a degraded run says what it withheld
    rather than looking like a quiet one."""

    adopted: tuple[str, ...] = ()
    """Issues a human has taken. Reported, never acted on."""

    unmarked: tuple[str, ...] = ()
    """Issues carrying the managed label but no marker — so the harness cannot
    tell which finding they are. Almost always a human adding an `agent/*` label
    by hand. Reported rather than skipped: silently ignoring an issue that claims
    to be ours is how a queue quietly stops meaning anything."""


def reconcile(
    findings: Iterable[Finding],
    managed: Sequence[Issue],
    policy: Policy,
    now: datetime,
    complete: bool = True,
) -> Plan:
    """Return the actions that reconcile `findings` against `managed`.

    `managed` is every open issue carrying the policy's label, each already
    carrying the key and absence mark the tracker read back for it.

    🔴 **`complete=False` means the source could not see everything, and then
    absence proves nothing.** Partial data may add; it must never subtract. This
    is not hypothetical: a scheduled run whose token lacked dependency-graph
    access fetched an empty SBOM, concluded a real CVE had been fixed, and
    marked its issue absent — twenty-four hours from closing a live
    vulnerability. A source that cannot see is indistinguishable from an estate
    that is clean, and only the source knows which it was.
    """
    actionable = {f.key: f for f in findings if f.lane is not Lane.SILENT}

    ours = [i for i in managed if policy.managed_label in i.labels]
    adopted = [i.ref or i.id for i in managed if policy.managed_label not in i.labels]
    by_key = {i.key: i for i in ours if i.key}
    unmarked = [i.ref or i.id for i in ours if not i.key]

    actions: list[Action] = []
    suppressed = 0

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
        if not complete:
            suppressed += 1
            continue
        if issue.absent_since is None:
            actions.append(MarkAbsent(issue.id, since=now, why="no longer reported"))
            continue
        gone = now - issue.absent_since
        if gone >= policy.close_after:
            actions.append(
                Close(issue.id, why=f"absent for {_human(gone)}, no longer true")
            )

    return Plan(
        actions=tuple(actions),
        adopted=tuple(adopted),
        unmarked=tuple(unmarked),
        absence_suppressed=suppressed,
    )


def _human(d: timedelta) -> str:
    h = d.total_seconds() / 3600
    return f"{h:.0f}h" if h < 48 else f"{h / 24:.0f}d"


def _drift(issue: Issue, finding: Finding, policy: Policy) -> Update | None:
    """What has changed about a finding that is still true.

    🔴 **Title and body are written once, at creation, and never corrected.**
    They belong to whoever is working the issue after that. An issue adopted by
    attaching a marker to it — which is how a human hands existing work to the
    harness — would otherwise have its write-up replaced by a generated template
    on the next sweep, every sweep. Losing someone's analysis to a scheduled job
    is a far worse failure than a title that has gone slightly stale, and the
    marker points at the live source anyway.

    What is corrected is what the contract owns: labels, project, priority.
    """
    reasons: list[str] = []
    project = None
    priority = None

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
        project=project,
        priority=priority,
        add_labels=frozenset(add),
        remove_labels=frozenset(remove),
    )
