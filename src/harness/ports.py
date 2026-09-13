"""The four ports.

Everything swappable in this system is one of these. They are `Protocol`s, so
an implementation just has to match the shape — no base class, no registration,
no import from this package at all if you would rather not.

    Source   what to do        (triage rules, a security sweep, a fleet sweep)
    Tracker  where issues live (Linear, GitHub Issues, a JSON file)
    Notifier where heartbeats and pages go (Slack, stdout, healthchecks.io)

**There is no Store.** An earlier design kept identity and absence counters in a
local file; that meant two registries disagreeing about the same issue, and the
copy that mattered could not travel. A tracker records the finding marker and
the absence timestamp alongside the issue, so exporting the tracker exports the
harness's memory too.
"""

from __future__ import annotations

from typing import Iterable, Protocol, runtime_checkable

from .models import Action, Finding, Heartbeat, Issue, IssueQuery


@runtime_checkable
class Tracker(Protocol):
    """An issue tracker. The only thing allowed to perform writes."""

    name: str

    def list_issues(self, query: IssueQuery) -> list[Issue]:
        """Issues matching `query`.

        Filtering by label is what makes the "adopt" gesture work: a human
        removes the label and the issue silently leaves the harness's reach,
        without anything needing to be told.
        """
        ...

    def list_projects(self) -> list[str]:
        """Project names, or `[]` where the tracker has no such concept."""
        ...

    def apply(self, action: Action) -> None: ...


@runtime_checkable
class Source(Protocol):
    """Produces the actions it believes should happen. Must not perform writes.

    Two shapes are normal and both fit here:

    * a *rule* source inspects tracker state and proposes corrections
      (the triage normaliser);
    * a *finding* source sweeps the outside world and hands its findings to
      `reconcile.reconcile()`, which turns them into actions using the store.

    Either way the result is a plan, and a plan can be reviewed before it runs.
    """

    name: str

    def plan(self, tracker: Tracker) -> Iterable[Action]: ...


@runtime_checkable
class Notifier(Protocol):
    """Where a run reports itself.

    `page` and `heartbeat` are separate on purpose. Pages wake someone; the
    tracker never does. Merging them is how a queue turns into an alert system
    nobody can ignore, and then ignores.
    """

    def heartbeat(self, hb: Heartbeat) -> None: ...
    def page(self, finding: Finding) -> None: ...
