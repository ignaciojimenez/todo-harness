"""Every rule in `reconcile` gets a test that fails if the rule is removed.

A test that only checks the happy path would pass against a reconciler that
does nothing at all — which is the same failure as an alert that never fires.
So each case here forces the condition it cares about.
"""

from __future__ import annotations

import pytest

from harness.models import Close, Finding, Issue, Lane, Open, Update
from harness.reconcile import Policy, StreakReader, reconcile

MANAGED = "agent/fleet"
CONTRACT = frozenset({"agent/fleet", "agent/sec", "needs/decision", "needs/laptop"})


def policy(**kw) -> Policy:
    kw.setdefault("managed_label", MANAGED)
    kw.setdefault("allowed_labels", CONTRACT)
    return Policy(**kw)


def store(ids=None, streaks=None) -> StreakReader:
    return StreakReader(dict(ids or {}), dict(streaks or {}))


def finding(key="disk:cobra", **kw) -> Finding:
    kw.setdefault("title", "cobra root filesystem at 91%")
    return Finding(key=key, **kw)


def managed_issue(id="PER-1", labels=frozenset({MANAGED}), **kw) -> Issue:
    kw.setdefault("title", "cobra root filesystem at 91%")
    return Issue(id=id, labels=labels, **kw)


# ── opening ──────────────────────────────────────────────────────────────────


def test_new_finding_opens_an_issue():
    plan = reconcile([finding()], [], store(), policy())
    assert [type(a) for a in plan.actions] == [Open]


def test_known_finding_with_matching_issue_does_nothing():
    """Idempotence. Running the sweep twice must not open a second issue."""
    plan = reconcile(
        [finding()],
        [managed_issue()],
        store(ids={"disk:cobra": "PER-1"}),
        policy(),
    )
    assert plan.actions == ()


def test_closed_issue_for_a_still_true_finding_reopens():
    """The condition is true again; a closed issue is not a record of that."""
    plan = reconcile(
        [finding()],
        [managed_issue(closed=True)],
        store(ids={"disk:cobra": "PER-1"}),
        policy(),
    )
    assert [type(a) for a in plan.actions] == [Open]


# ── closing, slowly ──────────────────────────────────────────────────────────


def test_one_clear_sweep_does_not_close():
    """The rule that stops a flapping fault churning the queue."""
    plan = reconcile(
        [],
        [managed_issue()],
        store(ids={"disk:cobra": "PER-1"}, streaks={"disk:cobra": 0}),
        policy(close_after_clear_sweeps=3),
    )
    assert plan.actions == ()
    assert plan.absent_keys == frozenset({"disk:cobra"})


def test_closes_on_the_nth_consecutive_clear_sweep():
    plan = reconcile(
        [],
        [managed_issue()],
        store(ids={"disk:cobra": "PER-1"}, streaks={"disk:cobra": 2}),
        policy(close_after_clear_sweeps=3),
    )
    assert [type(a) for a in plan.actions] == [Close]
    assert "3 consecutive" in plan.actions[0].why


def test_reappearance_clears_the_streak():
    """A finding that blinks back must not close on its next single absence."""
    plan = reconcile(
        [finding()],
        [managed_issue()],
        store(ids={"disk:cobra": "PER-1"}, streaks={"disk:cobra": 2}),
        policy(close_after_clear_sweeps=3),
    )
    assert not any(isinstance(a, Close) for a in plan.actions)
    assert plan.seen_keys == frozenset({"disk:cobra"})
    assert plan.absent_keys == frozenset()


def test_policy_refuses_to_close_on_a_single_sweep():
    with pytest.raises(ValueError, match="flapping"):
        Policy(managed_label=MANAGED, close_after_clear_sweeps=1)


# ── ownership: the adopt gesture ─────────────────────────────────────────────


def test_removing_the_managed_label_stops_all_action():
    """A human took it. The harness must go quiet without being told."""
    adopted = managed_issue(labels=frozenset())
    plan = reconcile(
        [finding()],
        [adopted],
        store(ids={"disk:cobra": "PER-1"}),
        policy(),
    )
    assert plan.actions == ()
    assert plan.dropped_keys == frozenset({"disk:cobra"})


def test_adopted_issue_is_never_closed_even_when_the_finding_clears():
    adopted = managed_issue(labels=frozenset())
    plan = reconcile(
        [],
        [adopted],
        store(ids={"disk:cobra": "PER-1"}, streaks={"disk:cobra": 99}),
        policy(close_after_clear_sweeps=3),
    )
    assert plan.actions == ()


# ── lanes ────────────────────────────────────────────────────────────────────


def test_silent_findings_never_reach_the_tracker():
    """A queue is for actions, not findings."""
    plan = reconcile([finding(lane=Lane.SILENT)], [], store(), policy())
    assert plan.actions == ()


def test_page_findings_still_get_an_issue():
    """Paging is the notifier's job; it does not exempt the work from tracking."""
    plan = reconcile([finding(lane=Lane.PAGE)], [], store(), policy())
    assert [type(a) for a in plan.actions] == [Open]


# ── drift ────────────────────────────────────────────────────────────────────


def test_label_outside_the_contract_is_stripped():
    """`Improvement` is a tracker default nobody adopted. PER-53 arrived with it."""
    issue = managed_issue(labels=frozenset({MANAGED, "Improvement"}))
    plan = reconcile(
        [finding()], [issue], store(ids={"disk:cobra": "PER-1"}), policy()
    )
    assert [type(a) for a in plan.actions] == [Update]
    assert plan.actions[0].remove_labels == frozenset({"Improvement"})


def test_a_contract_label_a_human_added_is_left_alone():
    """`needs/decision` is a deliberate human signal, not drift."""
    issue = managed_issue(labels=frozenset({MANAGED, "needs/decision"}))
    plan = reconcile(
        [finding()], [issue], store(ids={"disk:cobra": "PER-1"}), policy()
    )
    assert plan.actions == ()


def test_no_contract_configured_means_no_label_policing():
    issue = managed_issue(labels=frozenset({MANAGED, "whatever"}))
    plan = reconcile(
        [finding()],
        [issue],
        store(ids={"disk:cobra": "PER-1"}),
        policy(allowed_labels=frozenset()),
    )
    assert plan.actions == ()


def test_changed_title_is_an_update_not_a_new_issue():
    issue = managed_issue(title="cobra root filesystem at 80%")
    plan = reconcile(
        [finding()], [issue], store(ids={"disk:cobra": "PER-1"}), policy()
    )
    assert [type(a) for a in plan.actions] == [Update]
    assert plan.actions[0].title == "cobra root filesystem at 91%"
