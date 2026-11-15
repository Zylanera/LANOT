"""Push notifications via ntfy: rate limiting, coalescing, daily summary."""

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .config import Settings
from .db import Database, Incident
from .incidents import IncidentEvent

log = logging.getLogger(__name__)

DASHBOARD_URL = "http://localhost:8080"
RUNNING_TEXT = "Investigating …"
NTFY_TIMEOUT_S = 5.0  # a hung ntfy must not stall the rules tick
BATTERY_STEPS = (20, 10)  # extra pushes while a host runs on battery, once each per incident

Post = Callable[[dict], Awaitable[None]]


def make_ntfy_post(client, settings: Settings) -> Post:
    """Real `post` callable: JSON publish to the ntfy base URL, short timeout.
    Raises on network errors and non-2xx so the notifier keeps the push queued."""

    async def post(payload: dict) -> None:
        resp = await client.post(settings.ntfy_url, json=payload, timeout=NTFY_TIMEOUT_S)
        resp.raise_for_status()

    return post


def _diag_data(inc: Incident | None) -> dict | None:
    if inc is None or not inc.diagnosis_json:
        return None
    try:
        data = json.loads(inc.diagnosis_json)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _summary_or_none(inc: Incident | None) -> str | None:
    data = _diag_data(inc)
    if data and str(data.get("summary") or "").strip():
        return str(data["summary"]).strip()
    return None


def _summary(inc: Incident) -> str:
    return _summary_or_none(inc) or RUNNING_TEXT


def _is_followup(inc: Incident | None) -> bool:
    data = _diag_data(inc)
    return bool(data) and data.get("followup") is True


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _times_down(n: int) -> str:
    return "down once" if n == 1 else f"down {n} times"


def _priority(inc: Incident) -> int:
    return 5 if inc.severity == "high" else 4


class Notifier:
    """Rules for one incident:
    - the opening push goes out at once ("Investigating …" or the summary);
    - the FIRST diagnosis goes out at once as well, under the plain title. It is
      the only update push that skips the 10-min limit;
    - later state changes and follow-up diagnoses wait for the limit;
    - an undelivered diagnosis is never dropped: whatever push goes out next for
      the incident carries it (a resolve push included);
    - battery escalations (20%, 10%) of a power outage bypass the limit.
    flush / on_diagnosis / on_battery are serialised by one lock."""

    def __init__(self, post: Post, clock: Callable[[], float], min_interval: float = 600.0,
                 db: Database | None = None, topic: str = "lanot", dashboard_url: str = DASHBOARD_URL,
                 name_of: Callable[[str], str] = str):
        """`db` persists `last_push_at` so the rate limit survives a restart.
        Pending (coalesced) pushes live in memory only."""
        self.post, self.clock, self.min_interval = post, clock, min_interval
        self.db, self.topic, self.dashboard_url = db, topic, dashboard_url.rstrip("/")
        self.name_of = name_of  # host id -> display name
        self._pending: dict[int, IncidentEvent] = {}  # newest state event per incident
        self._diag: dict[int, Incident] = {}  # diagnoses not yet on the phone
        self._diag_done: set[int] = set()  # incidents whose first diagnosis was delivered
        self._delivered: dict[int, str] = {}  # last summary that reached the phone
        self._initial: dict[int, Incident] = {}  # waiting for the start-up summary push
        self._initial_ids: set[int] = set()
        self._last_push: dict[int, float] = {}
        self._battery: dict[int, set[int]] = {}  # battery steps already covered per incident
        self._lock = asyncio.Lock()

    # -- input ---------------------------------------------------------------
    def on_event(self, ev: IncidentEvent) -> None:
        inc = ev.incident
        if ev.initial:
            self._initial[inc.id] = inc
            self._initial_ids.add(inc.id)
        else:
            self._pending[inc.id] = ev  # newest state wins; a waiting diagnosis stays in _diag

    async def on_diagnosis(self, inc: Incident) -> None:
        async with self._lock:
            if _summary_or_none(inc) == self._delivered.get(inc.id):
                return  # the phone already shows exactly this
            self._diag[inc.id] = inc
            if inc.id in self._initial:
                self._initial[inc.id] = inc
                return  # the start-up summary push is not out yet
            await self._try_send(inc.id)

    async def on_battery(self, inc: Incident, pct: float | None) -> None:
        """Called every rules tick for an open power_lost incident."""
        if pct is None:
            return
        async with self._lock:
            crossed = {s for s in BATTERY_STEPS if pct <= s}
            done = self._battery.get(inc.id)
            if done is None:  # first sight: the opening push already shows this level
                self._battery[inc.id] = crossed
                return
            new = crossed - done
            if not new:
                return
            step = min(new)
            name = self.name_of(inc.key)
            payload = {
                "topic": self.topic, "title": f"{name}: battery down to {step}%",
                "message": f"Battery at {pct:.0f}%. Mains power is still out. "
                           f"If this goes on, {name} shuts down soon and monitoring stops with it.",
                "priority": 5, "tags": ["battery"], "click": self._click(inc),
            }
            if await self._deliver(payload):
                done |= crossed  # 25 -> 9 in one step: only the 10% push

    async def flush(self) -> None:
        async with self._lock:
            if self._initial:
                await self._send_initial()
            for id_ in list(dict.fromkeys([*self._pending, *self._diag])):
                if id_ not in self._initial:
                    await self._try_send(id_)

    # -- internals -----------------------------------------------------------
    def _limited(self, inc: Incident) -> bool:
        last = self._last_push_at(inc)
        return last is not None and self.clock() - last < self.min_interval

    async def _try_send(self, id_: int) -> None:
        ev, d = self._pending.get(id_), self._diag.get(id_)
        if ev is None and d is None:
            return
        base = ev.incident if ev is not None else d
        first = (d is not None and id_ not in self._diag_done and id_ not in self._initial_ids
                 and not _is_followup(d))
        if ev is None:
            if self._limited(d) and not first:
                return
            payload, summary = self._diagnosis_payload(d)
        elif ev.kind == "resolved":
            if self._limited(base):
                return  # the waiting diagnosis rides along with the resolve push
            payload, summary = self._payload(ev, d)
        else:
            if self._limited(base) and not first:
                return
            payload, summary = self._payload(ev, d)
        if not await self._deliver(payload):
            return
        self._mark_pushed(base)
        if self._pending.get(id_) is ev:
            self._pending.pop(id_, None)
        if d is not None and self._diag.get(id_) is d:
            self._diag.pop(id_, None)
        if summary:
            self._diag_done.add(id_)
            self._delivered[id_] = summary

    def _last_push_at(self, inc: Incident) -> float | None:
        vals = [v for v in (self._last_push.get(inc.id), inc.last_push_at) if v is not None]
        return max(vals) if vals else None

    def _mark_pushed(self, inc: Incident) -> None:
        now = self.clock()
        self._last_push[inc.id] = now
        inc.last_push_at = now
        if self.db is not None:
            fresh = self.db.get_incident(inc.id)  # avoid overwriting newer fields
            if fresh is not None:
                fresh.last_push_at = now
                self.db.save_incident(fresh)

    async def _deliver(self, payload: dict) -> bool:
        try:
            await self.post(payload)
            return True
        except Exception as exc:
            log.warning("ntfy push failed, will retry: %s", exc)
            return False

    def _click(self, inc: Incident) -> str:
        return f"{self.dashboard_url}/incident/{inc.id}"

    def _base(self, inc: Incident, title: str, message: str, tag: str) -> dict:
        return {"topic": self.topic, "title": title, "message": message,
                "priority": _priority(inc), "tags": [tag], "click": self._click(inc)}

    def _diagnosis_payload(self, d: Incident) -> tuple[dict, str | None]:
        """A diagnosis on its own. "Follow-up:" only for a follow-up investigation
        or a diagnosis that arrives after the resolve push."""
        summary = _summary_or_none(d)
        title = d.title
        if d.resolved_at is not None or _is_followup(d):
            title = "Follow-up: " + title
        tag = "rotating_light" if d.severity == "high" else "warning"
        return self._base(d, title, summary or RUNNING_TEXT, tag), summary

    def _payload(self, ev: IncidentEvent, d: Incident | None = None) -> tuple[dict, str | None]:
        inc = ev.incident
        if ev.kind == "resolved":
            minutes = max(1, round(((inc.resolved_at or self.clock()) - inc.opened_at) / 60))
            # first open to final resolve, up-periods between flaps included
            message = f"Lasted {minutes} min ({_times_down(inc.flap_count + 1)})"
            summary = _summary_or_none(d)
            if summary:
                message += "\n" + summary
            return self._base(inc, "Resolved: " + inc.title, message, "white_check_mark"), summary
        summary = _summary_or_none(d) or _summary_or_none(inc)
        title = inc.title
        if ev.kind == "updated" and inc.resolved_at is not None:
            title = "Follow-up: " + title
        if d is not None and _is_followup(d):
            title = "Follow-up: " + title
        if inc.rule == "power_lost":
            message = (inc.detail or f"{self.name_of(inc.key)} is running on battery.") + (
                ("\n" + summary) if summary else "")
        else:
            message = summary or RUNNING_TEXT
        if ev.kind == "reopened":
            message += f" ({_times_down(inc.flap_count + 1)})"
        tag = "rotating_light" if inc.severity == "high" else "warning"
        return self._base(inc, title, message, tag), summary

    async def _send_initial(self) -> None:
        incs = list(self._initial.values())
        n = len(incs)
        payload = {
            "topic": self.topic,
            "title": f"Found at startup: {_plural(n, 'problem', 'problems')}",
            "message": "\n".join(i.title for i in incs),
            "priority": 5 if any(i.severity == "high" for i in incs) else 4,
            "tags": ["rotating_light" if any(i.severity == "high" for i in incs) else "warning"],
            "click": self.dashboard_url,
        }
        if await self._deliver(payload):
            self._initial.clear()
            for i in incs:
                self._mark_pushed(i)


# -- daily summary -------------------------------------------------------------
def daily_summary(db: Database, since: float, until: float, tz: str = "UTC") -> dict:
    opened = [i for i in db.list_incidents(limit=100_000) if since <= i.opened_at < until]
    outages = [i for i in opened if i.rule == "internet_down"]
    outage_min = round(sum(min(i.resolved_at or until, until) - i.opened_at for i in outages) / 60)
    mutes = db.mutes_active(until)
    open_all = db.open_incidents()
    still_open = sum(1 for i in open_all if (i.rule, i.key) not in mutes)
    muted_open = len(open_all) - still_open

    n = len(opened)
    lines = ["No incidents."] if n == 0 else [f"{_plural(n, 'new incident', 'new incidents')}."]
    if outages:
        lines.append(f"Internet: {_plural(len(outages), 'outage', 'outages')}, {outage_min} min in total.")
    lines.append(f"{_plural(still_open, 'problem', 'problems')} still open." if still_open else "No open problems.")
    if muted_open:
        lines.append(f"{muted_open} muted.")
    day = datetime.fromtimestamp(until, ZoneInfo(tz))
    return {"title": f"Daily summary {day:%Y-%m-%d}", "message": "\n".join(lines)}


def schedule_daily(clock: Callable[[], float], tz: str = "UTC", hour: int = 8) -> float:
    """Timestamp of the next `hour`:00 local time strictly after now."""
    zone = ZoneInfo(tz)
    now = datetime.fromtimestamp(clock(), zone)
    day = now.date()
    while True:
        cand = datetime(day.year, day.month, day.day, hour, tzinfo=zone)
        if cand.timestamp() > now.timestamp():
            return cand.timestamp()
        day += timedelta(days=1)


async def daily_summary_loop(db: Database, post: Post, clock: Callable[[], float], sleep,
                             tz: str = "UTC", hour: int = 8, topic: str = "lanot",
                             dashboard_url: str = DASHBOARD_URL) -> None:
    last_day = None
    while True:
        nxt = schedule_daily(clock, tz, hour)
        while clock() < nxt:  # sleep may wake slightly early
            await sleep(nxt - clock())
        day = datetime.fromtimestamp(nxt, ZoneInfo(tz)).date()
        if day == last_day:
            continue
        last_day = day
        try:
            s = daily_summary(db, nxt - 86400, nxt, tz)
            payload = {"topic": topic, "title": s["title"], "message": s["message"], "priority": 3,
                       "tags": ["bar_chart"], "click": dashboard_url}
            await post(payload)
        except Exception as exc:
            log.warning("daily summary failed: %s", exc)
