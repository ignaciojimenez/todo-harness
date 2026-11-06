"""A label update keeps the grouped labels an issue already has.

Linear replaces an issue's whole label set, so `_merged_label_ids` reads the
current set back and edits it. It read names only, and Linear names a grouped
label without its group: `sec`, not `agent/sec`. The lookup is keyed by path,
so any label update on an issue carrying a grouped label raised "label 'sec'
does not exist" and took the run down. Every contract label is grouped, so that
is every triage strip on a labelled issue and every `labels+` on a sec issue.

Latent, not observed: no failed sweep through 2026-11-06 shows it. Surfaced by
the fake Linear written for the intake-status tests.
"""

from __future__ import annotations

import pytest

from harness.models import Finding, Open, Update
from harness.trackers.linear import LinearError, LinearTracker
from linear_fake import FakeLinear


def _with_labels(monkeypatch, *labels: str) -> tuple[FakeLinear, LinearTracker, str]:
    linear = FakeLinear()
    t = LinearTracker(team_key="PER", api_key="k")
    monkeypatch.setattr(t, "_gql", linear)
    t.apply(Open(
        Finding(key="https://example.invalid/x", title="t", labels=frozenset(labels)),
        why="new",
    ))
    (iid,) = linear.issues
    return linear, t, iid


def test_a_strip_keeps_the_grouped_labels(monkeypatch):
    """Triage's shape: an untriaged issue with contract labels and one outside it."""
    linear, t, iid = _with_labels(monkeypatch, "kind/risk", "needs/laptop", "bug")
    t.apply(Update(issue_id=iid, why="drift", remove_labels=frozenset({"bug"})))
    assert linear.labels(iid) == {"kind/risk", "needs/laptop"}


def test_an_add_keeps_the_grouped_labels(monkeypatch):
    """Reconcile's shape: a sec issue gaining a label."""
    linear, t, iid = _with_labels(monkeypatch, "agent/sec")
    t.apply(Update(issue_id=iid, why="drift", add_labels=frozenset({"kind/risk"})))
    assert linear.labels(iid) == {"agent/sec", "kind/risk"}


def test_a_grouped_label_can_be_removed_by_its_path(monkeypatch):
    linear, t, iid = _with_labels(monkeypatch, "agent/sec", "needs/laptop")
    t.apply(Update(issue_id=iid, why="drift", remove_labels=frozenset({"needs/laptop"})))
    assert linear.labels(iid) == {"agent/sec"}


def test_adding_a_label_outside_the_catalogue_still_refuses(monkeypatch):
    """The fix reads current labels by id; it must not loosen the rule that the
    harness never invents a label."""
    linear, t, iid = _with_labels(monkeypatch, "agent/sec")
    with pytest.raises(LinearError, match="does not exist"):
        t.apply(Update(issue_id=iid, why="drift", add_labels=frozenset({"kind/nope"})))
    assert linear.labels(iid) == {"agent/sec"}
