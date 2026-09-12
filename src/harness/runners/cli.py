"""Command-line runner.

`plan` and `apply` differ by one branch and nothing else — both compute the
identical plan from the identical code path. That is the payoff from keeping
`reconcile()` pure: there is no separate dry-run implementation that can drift
from the real one and reassure you about behaviour it does not have.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from ..models import Action, Close, Comment, Heartbeat, Open, Update
from ..notifiers import StdoutNotifier
from ..sources.triage import TriageSource
from ..trackers.linear import LinearTracker

DEFAULT_CONTRACT = "agent/fleet,agent/sec,needs:choco"


def describe(a: Action) -> str:
    match a:
        case Open():
            return f"OPEN   {a.finding.key}  {a.finding.title}   ({a.why})"
        case Update():
            bits = []
            if a.project:
                bits.append(f"project={a.project}")
            if a.priority is not None:
                bits.append(f"priority={a.priority}")
            if a.add_labels:
                bits.append("+" + ",".join(sorted(a.add_labels)))
            if a.remove_labels:
                bits.append("-" + ",".join(sorted(a.remove_labels)))
            if a.title:
                bits.append("title")
            if a.body:
                bits.append("body")
            return f"UPDATE {a.issue_id}  {' '.join(bits)}   ({a.why})"
        case Close():
            return f"CLOSE  {a.issue_id}   ({a.why})"
        case Comment():
            return f"NOTE   {a.issue_id}   ({a.why})"
    raise AssertionError(f"unhandled action {type(a).__name__}")


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="harness")
    p.add_argument("mode", choices=["plan", "apply"])
    p.add_argument("--team", default=os.environ.get("HARNESS_TEAM", "PER"))
    p.add_argument(
        "--contract",
        default=os.environ.get("HARNESS_CONTRACT", DEFAULT_CONTRACT),
        help="comma-separated labels the tracker permits",
    )
    p.add_argument("--max-body-lines", type=int, default=6)
    args = p.parse_args(argv)

    contract = frozenset(x.strip() for x in args.contract.split(",") if x.strip())
    tracker = LinearTracker(team_key=args.team)
    source = TriageSource(allowed_labels=contract, max_body_lines=args.max_body_lines)
    notifier = StdoutNotifier()

    actions = list(source.plan(tracker))
    rep = source.report

    for a in actions:
        print(("      " if args.mode == "plan" else "APPLY ") + describe(a))

    applied = 0
    if args.mode == "apply":
        for a in actions:
            tracker.apply(a)
            applied += 1

    # Everything the sweep saw but would not touch. This is the half worth
    # reading: a normaliser is judged by what it declines to guess at.
    if not rep.empty:
        print("\nleft alone, needs a human:")
        for i in rep.ambiguous_project:
            print(f"  {i.ref or i.id}  several projects named — will not guess")
        for i in rep.no_project_match:
            print(f"  {i.ref or i.id}  no project named in the text")
        for i in rep.long_body:
            print(f"  {i.ref or i.id}  body longer than {args.max_body_lines} lines")

    notifier.heartbeat(
        Heartbeat(
            source=source.name,
            swept=rep.seen,
            opened=0,
            updated=applied,
            closed=0,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
