"""Durable state, kept as small and as boring as possible.

A JSON file is the right default: the whole point of keeping this out of the
tracker is that it should be cheap to inspect, cheap to reset, and cheap to
throw away when you change trackers. Swap in KV or SQLite by matching `Store`.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


class JsonStore:
    """key→issue-id map plus clear-sweep counters, in one file.

    Writes are atomic (temp file + replace) because a sweep killed mid-write
    would otherwise lose the key→id map, and a lost map means the next sweep
    opens duplicates of everything it already opened.
    """

    def __init__(self, path: str | Path = "state.json") -> None:
        self.path = Path(path)
        self.was_created = not self.path.exists()
        """True when no prior state was found. A finding source starting from a
        blank map will re-open everything it has ever opened, so the runner
        refuses rather than letting that happen quietly."""

        self._data: dict[str, dict] = {"issue_ids": {}, "streaks": {}}
        if self.path.exists():
            self._data.update(json.loads(self.path.read_text() or "{}"))
        self._data.setdefault("issue_ids", {})
        self._data.setdefault("streaks", {})
        self._data.setdefault("runs", [])

    # reads
    @property
    def issue_ids(self) -> dict[str, str]:
        return self._data["issue_ids"]

    def issue_id_for(self, key: str) -> str | None:
        return self._data["issue_ids"].get(key)

    def clear_streak(self, key: str) -> int:
        return self._data["streaks"].get(key, 0)

    # writes
    def remember(self, key: str, issue_id: str) -> None:
        self._data["issue_ids"][key] = issue_id
        self.flush()

    def forget(self, key: str) -> None:
        self._data["issue_ids"].pop(key, None)
        self._data["streaks"].pop(key, None)
        self.flush()

    def bump_clear_streak(self, key: str) -> int:
        n = self.clear_streak(key) + 1
        self._data["streaks"][key] = n
        self.flush()
        return n

    def reset_clear_streak(self, key: str) -> None:
        if self._data["streaks"].pop(key, None) is not None:
            self.flush()

    def record_run(self, entry: dict, keep: int = 50) -> None:
        """Append a run record, newest last, capped.

        Every action carries a `why`. Without this it is printed to a job log
        that expires, and three weeks later nothing can say which sweep closed
        an issue or on what evidence. An unaccountable reconciler is one people
        stop trusting the moment it does something surprising.
        """
        runs = self._data["runs"]
        runs.append(entry)
        del runs[:-keep]
        self.flush()

    @property
    def runs(self) -> list[dict]:
        return self._data["runs"]

    def flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
