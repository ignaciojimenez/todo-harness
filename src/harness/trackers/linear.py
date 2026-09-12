"""Linear, over its GraphQL API. Standard library only.

Linear-specific knowledge is confined to this file — the filter language, the
uuid/identifier split, the fact that closing means moving to a state of type
`completed`. Nothing above this layer knows any of it.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..models import Action, Close, Comment, Issue, IssueQuery, Open, Update

ENDPOINT = "https://api.linear.app/graphql"

_ISSUE_FIELDS = """
  id identifier title description url priority
  state { type }
  project { name }
  labels { nodes { name parent { name } } }
"""


class LinearError(RuntimeError):
    pass


@dataclass
class LinearTracker:
    team_key: str
    api_key: str | None = None
    endpoint: str = ENDPOINT
    name: str = "linear"

    def __post_init__(self) -> None:
        self.api_key = self.api_key or os.environ.get("LINEAR_API_KEY")
        if not self.api_key:
            raise LinearError(
                "no Linear API key: pass api_key or set LINEAR_API_KEY. "
                "Scope it to Read+Write on one team; it never needs Admin."
            )
        self._label_ids: dict[str, str] | None = None
        self._project_ids: dict[str, str] | None = None
        self._team_id: str | None = None
        self._done_state: str | None = None

    # ── transport ────────────────────────────────────────────────────────────

    def _gql(self, query: str, variables: dict | None = None) -> dict:
        payload = json.dumps({"query": query, "variables": variables or {}}).encode()
        req = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={
                "Authorization": self.api_key or "",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:  # pragma: no cover - network
            raise LinearError(f"HTTP {e.code}: {e.read()[:400]!r}") from e
        if body.get("errors"):
            raise LinearError(json.dumps(body["errors"])[:600])
        return body["data"]

    # ── reads ────────────────────────────────────────────────────────────────

    def _filter(self, q: IssueQuery) -> dict:
        f: dict = {"team": {"key": {"eq": self.team_key}}}
        if q.open_only:
            f["state"] = {"type": {"nin": ["completed", "canceled"]}}
        if q.label:
            # A grouped label is matched on its child name plus its parent, since
            # Linear does not store the composed path.
            if "/" in q.label:
                parent, child = q.label.split("/", 1)
                f["labels"] = {
                    "some": {"name": {"eq": child}, "parent": {"name": {"eq": parent}}}
                }
            else:
                f["labels"] = {"some": {"name": {"eq": q.label}}}
        if q.without_project is True:
            f["project"] = {"null": True}
        elif q.without_project is False:
            f["project"] = {"null": False}
        return f

    def list_issues(self, query: IssueQuery) -> list[Issue]:
        out: list[Issue] = []
        after = None
        while True:
            data = self._gql(
                """
                query($filter: IssueFilter, $after: String) {
                  issues(filter: $filter, first: 100, after: $after) {
                    nodes { %s }
                    pageInfo { hasNextPage endCursor }
                  }
                }
                """
                % _ISSUE_FIELDS,
                {"filter": self._filter(query), "after": after},
            )["issues"]
            out.extend(_to_issue(n) for n in data["nodes"])
            if not data["pageInfo"]["hasNextPage"]:
                return out
            after = data["pageInfo"]["endCursor"]

    def list_projects(self) -> list[str]:
        if self._project_ids is None:
            self._load_projects()
        return sorted(self._project_ids or {})

    # ── lazily resolved ids ──────────────────────────────────────────────────

    def _load_projects(self) -> None:
        nodes = self._gql("{ projects(first: 250) { nodes { id name } } }")["projects"][
            "nodes"
        ]
        self._project_ids = {n["name"]: n["id"] for n in nodes}

    def _load_labels(self) -> None:
        nodes = self._gql(
            "{ issueLabels(first: 250) { nodes { id name parent { name } } } }"
        )["issueLabels"]["nodes"]
        # Keyed by composed path, so callers name labels the same way they read
        # them back. Group nodes themselves are not applicable to issues.
        self._label_ids = {_label_path(n): n["id"] for n in nodes}

    def _load_team(self) -> None:
        nodes = self._gql(
            """
            query($key: String!) {
              teams(filter: { key: { eq: $key } }, first: 1) {
                nodes { id states { nodes { id type } } }
              }
            }
            """,
            {"key": self.team_key},
        )["teams"]["nodes"]
        if not nodes:
            raise LinearError(f"no team with key {self.team_key!r}")
        self._team_id = nodes[0]["id"]
        done = [s for s in nodes[0]["states"]["nodes"] if s["type"] == "completed"]
        if not done:
            raise LinearError(f"team {self.team_key!r} has no completed state")
        self._done_state = done[0]["id"]

    def _label_id(self, name: str) -> str:
        if self._label_ids is None:
            self._load_labels()
        assert self._label_ids is not None
        if name not in self._label_ids:
            raise LinearError(
                f"label {name!r} does not exist. Create it deliberately — the "
                "harness will not invent labels outside the contract."
            )
        return self._label_ids[name]

    def _project_id(self, name: str) -> str:
        if self._project_ids is None:
            self._load_projects()
        assert self._project_ids is not None
        if name not in self._project_ids:
            raise LinearError(f"project {name!r} does not exist")
        return self._project_ids[name]

    # ── writes ───────────────────────────────────────────────────────────────

    def apply(self, action: Action) -> None:
        match action:
            case Open():
                self._create(action)
            case Update():
                self._update(action)
            case Close():
                if self._done_state is None:
                    self._load_team()
                self._mutate(action.issue_id, {"stateId": self._done_state})
            case Comment():
                self._gql(
                    """
                    mutation($id: String!, $body: String!) {
                      commentCreate(input: { issueId: $id, body: $body }) { success }
                    }
                    """,
                    {"id": action.issue_id, "body": action.body},
                )
            case _:  # pragma: no cover - exhaustive
                raise LinearError(f"unsupported action {type(action).__name__}")

    def _create(self, action: Open) -> None:
        if self._team_id is None:
            self._load_team()
        f = action.finding
        payload: dict = {
            "teamId": self._team_id,
            "title": f.title,
            "description": f.body,
        }
        if f.labels:
            payload["labelIds"] = [self._label_id(n) for n in sorted(f.labels)]
        if f.project:
            payload["projectId"] = self._project_id(f.project)
        if f.priority is not None:
            payload["priority"] = f.priority
        self._gql(
            """
            mutation($input: IssueCreateInput!) {
              issueCreate(input: $input) { success issue { identifier } }
            }
            """,
            {"input": payload},
        )

    def _update(self, action: Update) -> None:
        payload: dict = {}
        if action.title is not None:
            payload["title"] = action.title
        if action.body is not None:
            payload["description"] = action.body
        if action.project is not None:
            payload["projectId"] = self._project_id(action.project)
        if action.priority is not None:
            payload["priority"] = action.priority
        if action.add_labels or action.remove_labels:
            payload["labelIds"] = self._merged_label_ids(action)
        if payload:
            self._mutate(action.issue_id, payload)

    def _merged_label_ids(self, action: Update) -> list[str]:
        """Linear replaces the whole label set, so compute it from current state."""
        current = self._gql(
            "query($id: String!) { issue(id: $id) { labels { nodes { name } } } }",
            {"id": action.issue_id},
        )["issue"]["labels"]["nodes"]
        names = {n["name"] for n in current}
        names |= set(action.add_labels)
        names -= set(action.remove_labels)
        return [self._label_id(n) for n in sorted(names)]

    def _mutate(self, issue_id: str, payload: dict) -> None:
        self._gql(
            """
            mutation($id: String!, $input: IssueUpdateInput!) {
              issueUpdate(id: $id, input: $input) { success }
            }
            """,
            {"id": issue_id, "input": payload},
        )


def _label_path(node: dict) -> str:
    """Render a grouped label as `group/child`.

    Linear stores a grouped label's name without its group, so a bare child name
    like `decision` or `new` is ambiguous across groups and useless as a contract
    string. Composing the path keeps `agent/fleet` meaning what it always meant,
    and makes `needs/laptop` unambiguous.
    """
    parent = (node.get("parent") or {}).get("name")
    return f"{parent}/{node['name']}" if parent else node["name"]


def _to_issue(n: dict) -> Issue:
    return Issue(
        id=n["id"],
        ref=n.get("identifier", ""),
        title=n.get("title") or "",
        body=n.get("description") or "",
        labels=frozenset(_label_path(x) for x in (n.get("labels") or {}).get("nodes", [])),
        project=((n.get("project") or {}) or {}).get("name"),
        priority=n.get("priority"),
        closed=(n.get("state") or {}).get("type") in {"completed", "canceled"},
        url=n.get("url") or "",
    )
