"""Linear's GraphQL, in memory: just enough to hold issue states and labels.

Faithful on the two points the tests depend on, both of which have bitten:

* an `issueCreate` with no `stateId` lands in the team default, Backlog;
* a grouped label reads back as its bare name plus its parent (`sec` under
  `agent`), never as the `agent/sec` path the harness speaks in. Seen in the
  Linear MCP's listing of PER issues on 2026-11-06, and documented on
  `_label_path`.

The states are PER's as `list_issue_statuses` returned them on 2026-11-06, ids
replaced, so a test that passes here passes against the real type layout.
"""

from __future__ import annotations

PER_STATES = [
    {"id": "s-review", "type": "started", "name": "In Review"},
    {"id": "s-backlog", "type": "backlog", "name": "Backlog"},
    {"id": "s-canceled", "type": "canceled", "name": "Canceled"},
    {"id": "s-todo", "type": "unstarted", "name": "Todo"},
    {"id": "s-done", "type": "completed", "name": "Done"},
    {"id": "s-duplicate", "type": "duplicate", "name": "Duplicate"},
    {"id": "s-progress", "type": "started", "name": "In Progress"},
]

LABELS = [
    {"id": "l-agent-sec", "name": "sec", "parent": {"name": "agent"}},
    {"id": "l-kind-risk", "name": "risk", "parent": {"name": "kind"}},
    {"id": "l-needs-laptop", "name": "laptop", "parent": {"name": "needs"}},
    {"id": "l-bug", "name": "bug", "parent": None},
]
"""Three groups from the contract, and one ungrouped label outside it."""


class FakeLinear:
    def __init__(self, states=PER_STATES, default="s-backlog"):
        self.states = states
        self.default = default
        self.issues: dict[str, dict] = {}
        self.updates: list[dict] = []
        self._names = {s["id"]: s["name"] for s in states}
        self._labels = {n["id"]: n for n in LABELS}

    def __call__(self, query: str, variables: dict | None = None) -> dict:
        v = variables or {}
        if "teams(" in query:
            return {"teams": {"nodes": [
                {"id": "team", "states": {"nodes": self.states}}
            ]}}
        if "issueLabels" in query:
            return {"issueLabels": {"nodes": LABELS}}
        if "issueCreate" in query:
            i = v["input"]
            iid = f"issue-{len(self.issues) + 1}"
            # Linear's own behaviour: no stateId means the team default.
            self.issues[iid] = {
                **i, "stateId": i.get("stateId", self.default),
                "labelIds": i.get("labelIds", []),
            }
            return {"issueCreate": {"success": True,
                                    "issue": {"id": iid, "identifier": iid}}}
        if "issueUpdate" in query:
            self.updates.append(v["input"])
            self.issues[v["id"]].update(v["input"])
            return {"issueUpdate": {"success": True}}
        if "attachmentCreate" in query:
            return {"attachmentCreate": {"success": True}}
        if "issue(id: $id)" in query and "labels" in query:
            nodes = [self._labels[i] for i in self.issues[v["id"]]["labelIds"]]
            return {"issue": {"labels": {"nodes": nodes}}}
        raise AssertionError(f"unexpected query: {query}")

    def status(self, iid: str) -> str:
        return self._names[self.issues[iid]["stateId"]]

    def labels(self, iid: str) -> set[str]:
        """The issue's labels as a human reads them in the UI."""
        out = set()
        for i in self.issues[iid]["labelIds"]:
            n = self._labels[i]
            out.add(f"{n['parent']['name']}/{n['name']}" if n["parent"] else n["name"])
        return out
