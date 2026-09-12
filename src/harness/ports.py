"""The four ports.

Everything swappable in this system is one of these. They are `Protocol`s, so
an implementation just has to match the shape — no base class, no registration,
no import from this package at all if you would rather not.

    Source   what to do        (triage rules, a security sweep, a fleet sweep)
    Tracker  where issues live (Linear, GitHub Issues, a JSON file)
    Store    what was true last time (KV, SQLite, a file)
    Notifier where heartbeats and pages go (Slack, stdout, healthchecks.io)

The tracker deliberately holds no state beyond the issues themselves. Counters
and the key→id map live in the Store, on whatever box runs the sweep, so
swapping trackers stays cheap and the tracker never becomes the system.
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
class Store(Protocol):
    """Small durable state. Never the tracker, never a database if a file will do.

    Two jobs only: remember which tracker issue a finding key maps to, and count
    how many consecutive sweeps a finding has been absent. The second is what
    stops a flapping fault from churning the queue.
    """

    def issue_id_for(self, key: str) -> str | None: ...
    def remember(self, key: str, issue_id: str) -> None: ...
    def forget(self, key: str) -> None: ...

    def clear_streak(self, key: str) -> int:
        """Consecutive sweeps this key has been absent."""
        ...

    def bump_clear_streak(self, key: str) -> int: ...
    def reset_clear_streak(self, key: str) -> None: ...

    def record_run(self, entry: dict, keep: int = 50) -> None:
        """Durable record of what a run did and why. See `JsonStore.record_run`."""
        ...


@runtime_checkable
class Notifier(Protocol):
    """Where a run reports itself.

    `page` and `heartbeat` are separate on purpose. Pages wake someone; the
    tracker never does. Merging them is how a queue turns into an alert system
    nobody can ignore, and then ignores.
    """

    def heartbeat(self, hb: Heartbeat) -> None: ...
    def page(self, finding: Finding) -> None: ...
