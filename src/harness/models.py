"""Core data types.

Everything here is frozen and free of IO. The reconciler turns these into
`Action`s; a runner decides whether to print them or apply them. That split is
what makes `--plan` a property of the design rather than a feature bolted on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
from enum import Enum
from typing import Mapping


class Lane(str, Enum):
    """Where a finding's attention should go.

    Deliberately not a severity. Severity describes the finding; a lane
    describes what a human is expected to do about it, which is the only thing
    a tracker can act on.
    """

    PAGE = "page"  # wake someone: an issue, plus one page on the sweep that opens it
    PLAN = "plan"  # a tracker issue: real work, but nobody is woken
    SILENT = "silent"  # recorded for audit, never becomes an issue


@dataclass(frozen=True, slots=True)
class Finding:
    """Something a source asserts is true *right now*.

    A source emits the complete set of findings on every sweep. Absence is
    meaningful: a finding that stops being emitted is the signal to close its
    issue. This is why sources must be state-shaped rather than event-shaped —
    an event stream cannot express "no longer true".
    """

    key: str
    """Stable identity across sweeps, and **an absolute http(s) URL**.

    It is recorded on the tracker side as the finding's marker, which is what
    lets the harness keep no registry of its own. Making it a real URL rather
    than an invented string is the difference between a marker a human can click
    through to the evidence — a Dependabot alert, a CI run — and an opaque token
    that only the harness understands.

    Must not embed anything that changes while the finding persists: no
    timestamps, counts or severities, or the same condition reads as new.

    Only findings a *source opens* need one. Issues a human captures carry no
    marker and never will — the harness does not manage them, so it has nothing
    to identify.

    Where no natural URL exists, prefer one that still helps whoever opens the
    issue: the runbook for the check, the doc that explains it. Fall back to a
    reserved `.invalid` host only when there is genuinely nothing to point at.
    """

    def __post_init__(self) -> None:
        u = urlparse(self.key)
        if u.scheme not in {"http", "https"} or not u.netloc:
            raise ValueError(
                f"finding key must be an absolute http(s) URL, got {self.key!r}. "
                "The key is recorded as the marker on the tracker side, and most "
                "trackers reject other schemes — so this fails here, where the "
                "source can be fixed, rather than at write time."
            )

    title: str
    body: str = ""
    lane: Lane = Lane.PLAN
    labels: frozenset[str] = frozenset()
    project: str | None = None
    priority: int | None = None
    extra: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IssueQuery:
    """A tracker-agnostic question about issues.

    Deliberately tiny. Every field here has an obvious meaning in Linear, GitHub
    Issues and Jira; anything that would only make sense in one of them belongs
    in that adapter, not in the port.
    """

    open_only: bool = True
    label: str | None = None
    without_project: bool | None = None
    """None means "do not filter". True is the untriaged-intake question."""


@dataclass(frozen=True, slots=True)
class Issue:
    """A tracker issue as it currently exists."""

    id: str
    """The tracker's own handle — whatever mutations need. Opaque."""

    title: str
    body: str = ""
    labels: frozenset[str] = frozenset()
    project: str | None = None
    priority: int | None = None
    closed: bool = False

    key: str | None = None
    """The finding marker the tracker holds for this issue, if any."""

    absent_since: datetime | None = None
    """When its finding was last observed to have stopped being true. `None`
    means currently reported. This replaces a locally-held counter, so the
    tracker carries the whole truth about the issue."""

    ref: str = ""
    """Human-facing identifier (PER-53). Display only; never a key."""

    url: str = ""


# ── Actions ──────────────────────────────────────────────────────────────────
# A source's entire output. Data, never a side effect, so the same plan can be
# printed, diffed, reviewed, or applied.


@dataclass(frozen=True, slots=True)
class Open:
    finding: Finding
    why: str


@dataclass(frozen=True, slots=True)
class Update:
    issue_id: str
    why: str
    title: str | None = None
    body: str | None = None
    project: str | None = None
    priority: int | None = None
    add_labels: frozenset[str] = frozenset()
    remove_labels: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class MarkAbsent:
    """Record that a finding stopped being reported, starting the clock.

    Separate from `Close` on purpose: the gap between them is what stops a
    flapping fault churning the queue, and making it an explicit action means it
    shows up in a plan rather than happening invisibly.
    """

    issue_id: str
    since: datetime
    why: str


@dataclass(frozen=True, slots=True)
class MarkPresent:
    """Clear an absence mark because the finding is true again."""

    issue_id: str
    why: str


@dataclass(frozen=True, slots=True)
class Close:
    issue_id: str
    why: str


@dataclass(frozen=True, slots=True)
class Comment:
    issue_id: str
    body: str
    why: str


Action = Open | Update | Close | Comment | MarkAbsent | MarkPresent


@dataclass(frozen=True, slots=True)
class Heartbeat:
    """Emitted every run, including — especially — when nothing happened.

    A sweep that says nothing when it finds nothing is indistinguishable from a
    sweep that has been dead for a fortnight. This type exists so that silence
    is never the success signal.
    """

    source: str
    swept: int
    opened: int
    updated: int
    closed: int
    errors: int = 0

    def line(self) -> str:
        s = (
            f"{self.source}: swept {self.swept} · opened {self.opened} "
            f"· updated {self.updated} · closed {self.closed}"
        )
        return s + f" · errors {self.errors}" if self.errors else s
