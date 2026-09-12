"""Where a run reports itself.

`page` and `heartbeat` stay separate. Pages wake someone; heartbeats prove the
sweep is alive. Merging them is how a tracker becomes an alerting system that
nobody can ignore, and therefore ignores.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from .models import Finding, Heartbeat


@dataclass
class StdoutNotifier:
    """Default. On a scheduled runner, stdout is the job log — which is a
    perfectly good heartbeat sink as long as something watches the job."""

    stream = sys.stdout

    def heartbeat(self, hb: Heartbeat) -> None:
        print(hb.line(), file=self.stream)

    def page(self, finding: Finding) -> None:
        print(f"PAGE {finding.key}: {finding.title}", file=self.stream)


@dataclass
class NullNotifier:
    """For tests. Never the default: a harness whose heartbeat can be silently
    switched off has no way to distinguish healthy from dead."""

    beats: list[Heartbeat] | None = None
    pages: list[Finding] | None = None

    def __post_init__(self) -> None:
        self.beats = [] if self.beats is None else self.beats
        self.pages = [] if self.pages is None else self.pages

    def heartbeat(self, hb: Heartbeat) -> None:
        assert self.beats is not None
        self.beats.append(hb)

    def page(self, finding: Finding) -> None:
        assert self.pages is not None
        self.pages.append(finding)
