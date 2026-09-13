# todo-harness

Keeps a task tracker agreeing with what is actually true, on a schedule.

Most tooling around trackers is event-shaped: something happens, an issue is
created. Events cannot retract, so the tracker slowly fills with work that is
no longer real and stops being trustworthy. This is the other shape — sources
declare what is true *now*, and the harness opens, updates and closes to match.

## How it fits together

```
Source ──findings──▶ reconcile() ──actions──▶ Tracker
                                                 │
                            Notifier ◀───────────┘
                            (heartbeat, pages)
```

Three ports, all `Protocol`s — implement the shape, inherit nothing:

| Port | Swap it to | Ships with |
|---|---|---|
| `Source` | a different sweep | triage normaliser |
| `Tracker` | GitHub Issues, Jira, a file | Linear |
| `Notifier` | Slack, healthchecks.io | stdout |

**The harness keeps no state of its own.** A finding's identity is its URL,
recorded against the issue in the tracker — so the tracker's own deduplication
does the work a local key map used to, and exporting your issues exports the
harness's memory with them. Absence is a timestamp stored beside it.

`reconcile()` is pure — no IO — so `--plan` is not a feature, it is just
printing the return value. Run it against production and nothing happens.

## Rules it enforces, and why

- **Absence closes, but only after a while.** A finding that stops being
  emitted is no longer true; a finding that flaps would otherwise churn the
  queue forever. Closing needs it to have been gone for `close_after` —
  measured in *time*, so an irregular schedule cannot shorten the wait.
- **Removing the managed label stops everything.** That is the *adopt* gesture:
  a human takes an issue and the harness goes quiet without being told.
- **A heartbeat every run, including empty ones.** A sweep that only speaks when
  it finds something is indistinguishable from one that died a fortnight ago.
- **Silent findings never become issues.** A queue is for actions.

## Use

```bash
pip install .
export LINEAR_API_KEY=...          # scope it Read+Write on one team, never Admin
harness plan                       # show what would change
harness apply                      # do it
```

For development, run from the source tree rather than installing editable —
`pytest` picks up `src/` from `pyproject.toml`, and the CLI runs as:

```bash
PYTHONPATH=src python -m harness.runners.cli plan
```

## Docs

[`docs/decisions.md`](docs/decisions.md) — one-line record of the design calls.

MIT.
