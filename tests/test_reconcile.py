"""Every rule in `reconcile` gets a test that fails if the rule is removed.

A test that only checks the happy path would pass against a reconciler that
does nothing at all — which is the same failure as an alert that never fires.
So each case here forces the condition it cares about.

Note there is no store to set up. Identity and absence live on the issue, so a
test case is just "these findings, these issues, this clock".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from harness.models import Close, Finding, Issue, Lane, MarkAbsent, MarkPresent, Open, Update
from harness.reconcile import Policy, reconcile

MANAGED = "agent/fleet"
CONTRACT = frozenset({"agent/fleet", "agent/sec", "needs/decision", "needs/laptop"})
KEY = "https://github.com/ignaciojimenez/x/security/dependabot/7"
NOW = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)


def policy(**kw) -> Policy:
    kw.setdefault("managed_label", MANAGED)
    kw.setdefault("allowed_labels", CONTRACT)
    return Policy(**kw)


def finding(**kw) -> Finding:
    kw.setdefault("key", KEY)
    kw.setdefault("title", "cobra root filesystem at 91%")
    return Finding(**kw)


def issue(id="i1", labels=frozenset({MANAGED}), **kw) -> Issue:
    kw.setdefault("key", KEY)
    kw.setdefault("title", "cobra root filesystem at 91%")
    return Issue(id=id, labels=labels, **kw)


def kinds(plan):
    return [type(a) for a in plan.actions]


# ── opening ──────────────────────────────────────────────────────────────────


def test_new_finding_opens_an_issue():
    assert kinds(reconcile([finding()], [], policy(), NOW)) == [Open]


def test_known_finding_with_matching_issue_does_nothing():
    """Idempotence. Running the sweep twice must not open a second issue."""
    assert reconcile([finding()], [issue()], policy(), NOW).actions == ()


def test_identity_comes_from_the_issue_not_a_local_map():
    """An issue whose marker does not match is a different finding, not this one.

    So the new finding gets its own issue, and the unmatched one is treated as
    having gone absent — which is exactly right, and is the behaviour a local
    key map would have had to be kept in sync to reproduce.
    """
    other = issue(key="https://github.com/ignaciojimenez/x/security/dependabot/99")
    plan = reconcile([finding()], [other], policy(), NOW)
    assert sorted(t.__name__ for t in kinds(plan)) == ["MarkAbsent", "Open"]


def test_closed_issue_for_a_still_true_finding_reopens():
    """The condition is true again; a closed issue is not a record of that."""
    assert kinds(reconcile([finding()], [issue(closed=True)], policy(), NOW)) == [Open]


# ── closing, slowly, and on a clock ──────────────────────────────────────────


def test_first_absence_marks_but_does_not_close():
    """The rule that stops a flapping fault churning the queue."""
    plan = reconcile([], [issue()], policy(close_after=timedelta(hours=24)), NOW)
    assert kinds(plan) == [MarkAbsent]
    assert plan.actions[0].since == NOW


def test_still_absent_but_not_long_enough_does_nothing():
    gone = issue(absent_since=NOW - timedelta(hours=5))
    assert reconcile([], [gone], policy(close_after=timedelta(hours=24)), NOW).actions == ()


def test_closes_once_it_has_been_absent_long_enough():
    gone = issue(absent_since=NOW - timedelta(hours=30))
    plan = reconcile([], [gone], policy(close_after=timedelta(hours=24)), NOW)
    assert kinds(plan) == [Close]
    assert "30h" in plan.actions[0].why


def test_reappearance_clears_the_absence_mark():
    """A finding that blinks back must not close on its next single absence."""
    gone = issue(absent_since=NOW - timedelta(hours=23))
    plan = reconcile([finding()], [gone], policy(), NOW)
    assert kinds(plan) == [MarkPresent]


def test_an_irregular_schedule_cannot_shorten_the_wait():
    """Time-based, not sweep-count-based. Ten sweeps in an hour still close nothing.

    GitHub delays scheduled runs under load, so sweeps are not evenly spaced;
    counting them would make the close threshold depend on the weather.
    """
    gone = issue(absent_since=NOW - timedelta(hours=1))
    for _ in range(10):
        plan = reconcile([], [gone], policy(close_after=timedelta(hours=24)), NOW)
        assert plan.actions == ()


def test_policy_refuses_a_zero_wait():
    with pytest.raises(ValueError, match="flapping"):
        Policy(managed_label=MANAGED, close_after=timedelta(0))


# ── ownership: the adopt gesture ─────────────────────────────────────────────


def test_removing_the_managed_label_stops_all_action():
    """A human took it. The harness must go quiet without being told."""
    adopted = issue(labels=frozenset(), ref="PER-9")
    plan = reconcile([finding()], [adopted], policy(), NOW)
    assert kinds(plan) == [Open], "the finding is real, so it still needs an issue"
    assert plan.adopted == ("PER-9",)


def test_adopted_issue_is_never_closed_even_when_long_absent():
    adopted = issue(labels=frozenset(), absent_since=NOW - timedelta(days=99))
    plan = reconcile([], [adopted], policy(), NOW)
    assert plan.actions == ()


# ── lanes ────────────────────────────────────────────────────────────────────


def test_silent_findings_never_reach_the_tracker():
    """A queue is for actions, not findings."""
    assert reconcile([finding(lane=Lane.SILENT)], [], policy(), NOW).actions == ()


def test_page_findings_still_get_an_issue():
    """Paging is the notifier's job; it does not exempt the work from tracking."""
    assert kinds(reconcile([finding(lane=Lane.PAGE)], [], policy(), NOW)) == [Open]


# ── drift ────────────────────────────────────────────────────────────────────


def test_label_outside_the_contract_is_stripped():
    i = issue(labels=frozenset({MANAGED, "Improvement"}))
    plan = reconcile([finding()], [i], policy(), NOW)
    assert kinds(plan) == [Update]
    assert plan.actions[0].remove_labels == frozenset({"Improvement"})


def test_a_contract_label_a_human_added_is_left_alone():
    """`needs/decision` is a deliberate human signal, not drift."""
    i = issue(labels=frozenset({MANAGED, "needs/decision"}))
    assert reconcile([finding()], [i], policy(), NOW).actions == ()


def test_no_contract_configured_means_no_label_policing():
    i = issue(labels=frozenset({MANAGED, "whatever"}))
    plan = reconcile([finding()], [i], policy(allowed_labels=frozenset()), NOW)
    assert plan.actions == ()


def test_a_human_edited_body_is_never_overwritten():
    """PER-55 was hand-written, then adopted by attaching a marker to it.

    Without this rule the sweep would replace that analysis with a generated
    template every six hours, for ever.
    """
    i = issue(title="a much better title someone wrote",
              body="analysis a human did, with the import trace")
    plan = reconcile([finding(body="generated template")], [i], policy(), NOW)
    assert plan.actions == ()


def test_labels_are_still_corrected_on_an_adopted_issue():
    """The contract is the harness's to enforce; the prose is not."""
    i = issue(title="whatever", labels=frozenset({MANAGED, "Improvement"}))
    plan = reconcile([finding()], [i], policy(), NOW)
    assert kinds(plan) == [Update]
    assert plan.actions[0].remove_labels == frozenset({"Improvement"})
    assert plan.actions[0].title is None and plan.actions[0].body is None


# ── keys ─────────────────────────────────────────────────────────────────────


def test_a_key_that_is_not_a_url_fails_at_the_source():
    """Fail where the source can be fixed, not at write time."""
    with pytest.raises(ValueError, match="absolute http"):
        Finding(key="dependabot:pastebin-worker:pillow", title="x")


def test_a_synthesised_url_is_fine_for_findings_with_no_natural_link():
    f = Finding(key="https://harness.invalid/fleet/disk/cobra", title="disk full")
    assert kinds(reconcile([f], [], policy(), NOW)) == [Open]


def test_an_issue_claiming_our_label_without_a_marker_is_reported_not_skipped():
    """A human adding agent/fleet by hand. The harness cannot know what it is,
    but silently ignoring it is how a queue stops meaning anything."""
    mystery = Issue(id="i9", ref="PER-77", labels=frozenset({MANAGED}), title="?")
    plan = reconcile([], [mystery], policy(), NOW)
    assert plan.actions == ()
    assert plan.unmarked == ("PER-77",)
