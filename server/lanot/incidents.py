"""Incident lifecycle: turns the current findings into opened / reopened /
updated / resolved events, persisted in the incidents table."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .db import Database, Incident
from .rules import Finding

__all__ = ["Incident", "IncidentEvent", "IncidentManager", "REOPEN_WINDOW_S"]

REOPEN_WINDOW_S = 900.0
STARTUP_GRACE_S = 180.0


@dataclass
class IncidentEvent:
    kind: Literal["opened", "reopened", "updated", "resolved"]
    incident: Incident
    initial: bool = False


class IncidentManager:
    def __init__(self, db: Database, clock: Callable[[], float], started_at: float | None = None):
        """`started_at`: server start; nothing is resolved during the startup
        grace because probes, agents and temperature windows are still empty
        (None disables the grace)."""
        self.db = db
        self.clock = clock
        self.started_at = started_at
        # Problems already present at the very first start are flagged initial;
        # after a restart with open incidents they simply continue.
        self._first = not db.open_incidents()

    def apply(self, findings: list[Finding], muted: frozenset | set = frozenset()) -> list[IncidentEvent]:
        """`muted` (rule, key) pairs are frozen: their open incidents are not
        resolved (muted findings should already be absent from `findings`)."""
        now = self.clock()
        initial, self._first = self._first, False
        events: list[IncidentEvent] = []
        wanted = {(f.rule, f.key): f for f in findings}
        open_ = {(i.rule, i.key): i for i in self.db.open_incidents()}

        in_grace = self.started_at is not None and now - self.started_at < STARTUP_GRACE_S
        for k, inc in open_.items():
            if k not in wanted and k not in muted and not in_grace:
                inc.resolved_at = now
                events.append(IncidentEvent("resolved", self.db.save_incident(inc)))

        for k, f in wanted.items():
            inc = open_.get(k)
            if inc is not None:
                # only an escalation is worth a push; going back to medium is saved quietly
                escalated = inc.severity == "medium" and f.severity == "high"
                inc.last_seen_at, inc.severity, inc.title, inc.detail = now, f.severity, f.title, f.detail
                self.db.save_incident(inc)
                if escalated:
                    events.append(IncidentEvent("updated", inc))
                continue
            prev = self.db.last_resolved(*k)
            if prev is not None and now - prev.resolved_at <= REOPEN_WINDOW_S:
                prev.resolved_at = None
                prev.flap_count += 1
                prev.last_seen_at, prev.severity, prev.title, prev.detail = now, f.severity, f.title, f.detail
                events.append(IncidentEvent("reopened", self.db.save_incident(prev)))
            else:
                new = Incident(f.rule, f.key, f.severity, f.title, f.detail, opened_at=now, last_seen_at=now)
                events.append(IncidentEvent("opened", self.db.save_incident(new), initial=initial))
        return events
