"""Command-line runner.

`plan` and `apply` differ by one branch and nothing else — both compute the
identical plan from the identical code path. That is the payoff from keeping
`reconcile()` pure: there is no separate dry-run implementation that can drift
from the real one and reassure you about behaviour it does not have.

Two safety properties live here rather than in the core, because they are
properties of *running unattended* rather than of reconciling:

* a **circuit breaker** — an oversized plan is refused, not applied;
* a **dead-man's switch** — every exit path reports, and the failure paths
  report failure, so silence can only mean the runner itself is gone.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from typing import Callable, Sequence

from ..models import (
    Action,
    Close,
    Comment,
    Heartbeat,
    MarkAbsent,
    MarkPresent,
    Open,
    Update,
)
from ..notifiers import HealthchecksNotifier, StdoutNotifier
from ..ports import Source, Tracker
from ..sources.osv import OsvSource
from ..sources.security import SecuritySource
from ..sources.triage import TriageSource
from ..trackers.linear import LinearTracker

DEFAULT_CONTRACT = ",".join(
    [
        "agent/fleet", "agent/sec",                      # who may close it
        "needs/decision", "needs/hands", "needs/laptop",  # what blocks it now
        "kind/broken", "kind/risk", "kind/debt", "kind/new", "kind/improvement",
    ]
)
"""The tracker's label contract. Anything on an untriaged issue that is not in
here gets stripped, so this list going stale is actively destructive — it would
remove labels a human deliberately applied."""

SOURCES: dict[str, Callable[[argparse.Namespace], Source]] = {
    "triage": lambda a: TriageSource(
        allowed_labels=frozenset(
            x.strip() for x in a.contract.split(",") if x.strip()
        ),
        max_body_lines=a.max_body_lines,
    ),
    "security": lambda a: SecuritySource(
        owner=a.owner,
        allowed_labels=frozenset(
            x.strip() for x in a.contract.split(",") if x.strip()
        ),
        close_after_hours=a.close_after_hours,
    ),
    "osv": lambda a: OsvSource(
        owner=a.owner,
        allowed_labels=frozenset(
            x.strip() for x in a.contract.split(",") if x.strip()
        ),
        close_after_hours=a.close_after_hours,
    ),
}
"""Registry. A deployment enables the sources that suit where it runs: triage
is pure HTTP and belongs in CI, while a fleet sweep needs LAN access and must
run on the box. Same binary, different `--sources`."""


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
        case MarkAbsent():
            return f"ABSENT {a.issue_id}  since {a.since:%Y-%m-%d %H:%M}   ({a.why})"
        case MarkPresent():
            return f"BACK   {a.issue_id}   ({a.why})"
    raise AssertionError(f"unhandled action {type(a).__name__}")


def _target(a: Action) -> str:
    return a.finding.key if isinstance(a, Open) else a.issue_id


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="harness")
    p.add_argument("mode", choices=["plan", "apply"])
    p.add_argument("--team", default=os.environ.get("HARNESS_TEAM", "PER"))
    p.add_argument(
        "--sources",
        default=os.environ.get("HARNESS_SOURCES", "triage"),
        help=f"comma-separated; available: {', '.join(sorted(SOURCES))}",
    )
    p.add_argument("--contract", default=os.environ.get("HARNESS_CONTRACT", DEFAULT_CONTRACT))
    p.add_argument("--max-body-lines", type=int, default=6)
    p.add_argument("--owner", default=os.environ.get("HARNESS_OWNER", "ignaciojimenez"))
    p.add_argument(
        "--close-after-hours",
        type=int,
        default=int(os.environ.get("HARNESS_CLOSE_AFTER_HOURS", "24")),
        help="how long a finding must be gone before its issue closes",
    )
    p.add_argument(
        "--max-actions",
        type=int,
        default=int(os.environ.get("HARNESS_MAX_ACTIONS", "25")),
        help=(
            "refuse to apply a plan larger than this. A source with a bad "
            "config can propose a great deal very quickly; bounding the blast "
            "radius costs one comparison."
        ),
    )
    p.add_argument(
        "--ping-url",
        default=os.environ.get("HARNESS_PING_URL"),
        help="healthchecks.io-style dead-man's switch. Absence of a ping is the alert.",
    )
    return p


def main(
    argv: Sequence[str] | None = None,
    tracker: Tracker | None = None,
    notifier=None,
) -> int:
    args = build_parser().parse_args(argv)

    if notifier is None:
        notifier = (
            HealthchecksNotifier(args.ping_url) if args.ping_url else StdoutNotifier()
        )
    start = getattr(notifier, "start", None)
    if callable(start):
        start()

    try:
        names = [s.strip() for s in args.sources.split(",") if s.strip()]
        unknown = [n for n in names if n not in SOURCES]
        if unknown:
            raise SystemExit(
                f"unknown source(s): {', '.join(unknown)}. "
                f"available: {', '.join(sorted(SOURCES))}"
            )

        tracker = tracker or LinearTracker(team_key=args.team)

        actions: list[Action] = []
        swept = 0
        degraded = 0
        notes: list[str] = []
        for name in names:
            source = SOURCES[name](args)
            actions.extend(source.plan(tracker))
            rep = getattr(source, "report", None)
            if rep is not None:
                swept += getattr(rep, "seen", 0)
                notes.extend(_notes(rep, args))
                notes.extend(_plan_notes(rep))
            for f in getattr(source, "failures", ()):
                degraded += 1
                notes.append(f"UNSCANNED  {f}")
            for sup in getattr(source, "suppressions", ()):
                notes.append(sup)
            for purl in getattr(source, "skipped", ()):
                notes.append(f"UNSCANNED  {purl}")
            for alert, why in getattr(source, "silent", ()):
                notes.append(f"{alert.repo} #{alert.number}  silent — {why}")

        for a in actions:
            print(("      " if args.mode == "plan" else "APPLY ") + describe(a))

        # Circuit breaker. Refuse rather than apply, and report failure: a run
        # that declines to act must not look like a healthy quiet one.
        if args.mode == "apply" and len(actions) > args.max_actions:
            msg = (
                f"refusing to apply {len(actions)} actions "
                f"(--max-actions {args.max_actions}). Re-run with `plan` and "
                "check the source before raising the limit."
            )
            print(msg, file=sys.stderr)
            _report(notifier, args, swept, applied=0, errors=1, note=msg)
            return 2

        applied = 0
        if args.mode == "apply":
            for a in actions:
                tracker.apply(a)
                applied += 1

        if notes:
            print("\nleft alone, needs a human:")
            for n in notes:
                print("  " + n)

        # A run that could not reach part of the estate is not a healthy run,
        # even when everything it did reach was clean.
        _report(notifier, args, swept, applied, errors=degraded,
                actions=actions if args.mode == "apply" else None)
        return 0
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - the run must report before dying
        fail = getattr(notifier, "fail", None)
        if callable(fail):
            fail(f"{type(e).__name__}: {e}")
        else:
            print(f"run failed: {type(e).__name__}: {e}", file=sys.stderr)
        raise


def _plan_notes(plan) -> list[str]:
    """Things a reconciling source saw but would not act on."""
    out = []
    n = getattr(plan, "absence_suppressed", 0)
    if n:
        out.append(
            f"{n} issue(s) NOT marked absent — the sweep was incomplete, so "
            "absence proves nothing this run"
        )
    for ref in getattr(plan, "adopted", ()):
        out.append(f"{ref}  adopted by a human — the harness has stopped touching it")
    for ref in getattr(plan, "unmarked", ()):
        out.append(f"{ref}  carries an agent label but no marker — which finding is it?")
    return out


def _notes(rep, args) -> list[str]:
    out = []
    for i in getattr(rep, "ambiguous_project", ()):
        out.append(f"{i.ref or i.id}  several projects named — will not guess")
    for i in getattr(rep, "no_project_match", ()):
        out.append(f"{i.ref or i.id}  no project named in the text")
    for i in getattr(rep, "long_body", ()):
        out.append(f"{i.ref or i.id}  body longer than {args.max_body_lines} lines")
    return out


def _report(notifier, args, swept, applied, errors, note=None, actions=None):
    hb = Heartbeat(
        source=args.sources,
        swept=swept,
        opened=sum(isinstance(a, Open) for a in (actions or ())),
        updated=applied,
        closed=sum(isinstance(a, Close) for a in (actions or ())),
        errors=errors,
    )
    notifier.heartbeat(hb)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
