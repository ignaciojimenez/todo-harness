"""Where a run reports itself.

`page` and `heartbeat` stay separate. Pages wake someone; heartbeats prove the
sweep is alive. Merging them is how a tracker becomes an alerting system that
nobody can ignore, and therefore ignores.

The important type here is `HealthchecksNotifier`, and the reason is worth
stating plainly: **a heartbeat you have to go and look at is not a heartbeat.**
Printing "swept 0" to a job log proves nothing if the job stopped running a
fortnight ago — the log simply stops, and nothing anywhere notices. Only an
external dead-man's switch, which alerts on the *absence* of a ping, can tell
"healthy and quiet" from "dead".
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .models import Finding, Heartbeat

Transport = Callable[[str], None]
"""Fetch a URL for its side effect. Injectable so tests need no network."""


def _http_get(url: str) -> None:  # pragma: no cover - network
    with urllib.request.urlopen(url, timeout=10):
        pass


class _Inner(Protocol):
    def heartbeat(self, hb: Heartbeat) -> None: ...
    def page(self, finding: Finding) -> None: ...


@dataclass
class StdoutNotifier:
    """On a scheduled runner stdout is the job log. Necessary, never sufficient —
    see `HealthchecksNotifier`."""

    def heartbeat(self, hb: Heartbeat) -> None:
        print(hb.line(), file=sys.stdout)

    def page(self, finding: Finding) -> None:
        print(f"PAGE {finding.key}: {finding.title}", file=sys.stdout)


@dataclass
class HealthchecksNotifier:
    """Dead-man's switch. Wraps another notifier and pings on every outcome.

    Three signals, because "did not run" and "ran and failed" need different
    responses: `/start` when the run begins, a bare ping on success, `/fail`
    when it did not. Silence then means the runner itself is gone, which is the
    one failure a self-report can never cover.

    A failed ping is reported loudly but never raises: the sweep's job is to
    reconcile, and taking the run down because monitoring is unreachable would
    turn a monitoring outage into a work outage. The missing ping is itself the
    alert, so nothing is lost by carrying on.
    """

    ping_url: str
    inner: _Inner = field(default_factory=StdoutNotifier)
    transport: Transport = _http_get

    def start(self) -> None:
        self._ping("/start")

    def heartbeat(self, hb: Heartbeat) -> None:
        self.inner.heartbeat(hb)
        self._ping("/fail" if hb.errors else "")

    def page(self, finding: Finding) -> None:
        self.inner.page(finding)

    def fail(self, reason: str) -> None:
        print(f"run failed: {reason}", file=sys.stderr)
        self._ping("/fail")

    def _ping(self, suffix: str) -> None:
        try:
            self.transport(self.ping_url.rstrip("/") + suffix)
        except (urllib.error.URLError, OSError) as e:
            # Loud, but not fatal — see the class docstring. The URL is redacted
            # because it is a credential: anyone holding it can send a fake ping
            # and suppress the alert. Job logs on a public repo are public, and
            # urllib errors often quote the URL they failed on.
            detail = str(e).replace(self.ping_url, "<ping-url>")
            print(f"heartbeat ping failed ({detail}) — the missing ping is the alert",
                  file=sys.stderr)


Poster = Callable[[str, bytes], None]
"""POST a JSON body to a URL. Injectable so tests need no network."""


def _http_post(url: str, body: bytes) -> None:  # pragma: no cover - network
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10):
        pass


@dataclass
class SlackNotifier:
    """Pages go to a Slack incoming webhook; heartbeats stay in the job log.

    A page is sent once, when its issue is opened — the runner guarantees that,
    not this class. Re-paging every sweep for a finding already in the tracker
    is how a pager becomes background noise.

    Unlike a heartbeat ping, a failed page **raises**. The runner counts it as
    an error, so the run reports `/fail` and the dead-man's switch alerts
    instead: a page that silently did not arrive is the one failure this whole
    lane exists to prevent.
    """

    webhook_url: str
    post: Poster = _http_post

    def heartbeat(self, hb: Heartbeat) -> None:
        print(hb.line(), file=sys.stdout)

    def page(self, finding: Finding) -> None:
        print(f"PAGE {finding.key}: {finding.title}", file=sys.stdout)
        text = f":rotating_light: *{finding.title}*\n{finding.key}"
        body = json.dumps({"text": text}).encode()
        try:
            self.post(self.webhook_url, body)
        except (urllib.error.URLError, OSError, ValueError) as e:
            # The webhook URL is a credential — anyone holding it can post to
            # the channel — and urllib errors quote the URL they failed on.
            detail = str(e).replace(self.webhook_url, "<webhook-url>")
            raise RuntimeError(f"page not delivered: {detail}") from None


@dataclass
class NullNotifier:
    """For tests. Never a default: a harness whose heartbeat can be silently
    switched off has no way to distinguish healthy from dead."""

    beats: list[Heartbeat] = field(default_factory=list)
    pages: list[Finding] = field(default_factory=list)

    def heartbeat(self, hb: Heartbeat) -> None:
        self.beats.append(hb)

    def page(self, finding: Finding) -> None:
        self.pages.append(finding)
