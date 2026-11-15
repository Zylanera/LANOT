"""Server entry point: builds the FastAPI app and runs the background loops.

    uvicorn lanot.main:app --host 0.0.0.0 --port 8080

Loops (each wrapped so an exception is logged and the loop continues; one
loop's death never takes the others down):
  pinger 10 s, FritzBox 30 s, rules 10 s, notifier flush 10 s,
  gateway discovery and housekeeping hourly, daily summary, healthcheck.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import api
from .config import Settings
from .db import Database, Incident
from .fritz import FritzPoller
from .housekeeping import ALIVE_MAX_AGE_S, alarm_path_alive, healthcheck_loop, run_once
from .incidents import IncidentManager
from .investigator.facts import Deps
from .investigator.runner import Investigator
from .notify import Notifier, daily_summary_loop, make_ntfy_post
from .pinger import Target, default_targets, discover_gateway, run_pinger
from .rules import PROBE_FAILS, build_view, evaluate
from .web import routes

log = logging.getLogger(__name__)

PROCESS_START = time.time()

RULE_INTERVAL_S = 10.0
FLUSH_INTERVAL_S = 10.0
FRITZ_INTERVAL_S = 30.0
FRITZ_TIMEOUT_S = 20.0
GATEWAY_INTERVAL_S = 3600.0
HOUSEKEEPING_INTERVAL_S = 3600.0
RESTART_DELAY_S = 10.0
FOLLOWUP_AFTER_S = 1800.0  # an incident open this long may get a follow-up investigation ...
FOLLOWUP_GAP_S = 1800.0  # ... at most one per this many seconds
FRITZ_LOG_LOOKBACK_S = 900.0
ERR_SLOW = "FritzBox did not answer in time"
# open incidents of these rules make the FritzBox poller also fetch the event log
FRITZ_LOG_RULES = {"internet_down", "dns_broken", "device_down", "router_unqueryable"}
_FRITZ_FIELDS = ("link_up", "wan_connected", "external_ip", "uptime_s", "downstream_kbps", "upstream_kbps")


async def every(name: str, interval: float, job: Callable[[], Awaitable], *, sleep=asyncio.sleep) -> None:
    """Run `job` now and then every `interval` s; exceptions are logged, never fatal."""
    while True:
        started = time.monotonic()
        try:
            await job()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("loop %s failed, continuing", name)
        await sleep(max(0.0, interval - (time.monotonic() - started)))


async def supervise(name: str, factory: Callable[[], Awaitable], *, restart_delay: float = RESTART_DELAY_S) -> None:
    """Keep a long-running coroutine alive: restart it after a crash.
    A normal return (e.g. healthcheck without URL) ends supervision."""
    while True:
        try:
            await factory()
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("task %s crashed, restarting in %.0f s", name, restart_delay)
        await asyncio.sleep(restart_delay)


@dataclass
class _Snapshot:
    """What the last (or running) diagnosis of an incident was based on."""
    at: float
    flap_count: int
    affected: frozenset


def failing_targets(view) -> frozenset:
    return frozenset(t for t, p in view.probes.items() if len(p) >= PROBE_FAILS and not any(p[-PROBE_FAILS:]))


class Runtime:
    """All background behaviour. `notifier` needs on_event(ev) and async
    flush(); `investigator` needs async investigate(incident)."""

    def __init__(self, settings: Settings, db: Database, *, notifier, investigator, fritz=None,
                 clock: Callable[[], float] = time.time, started_at: float | None = None,
                 gateway_finder: Callable[[], str | None] | None = None):
        self.settings, self.db = settings, db
        self.notifier, self.investigator, self.fritz = notifier, investigator, fritz
        self.clock = clock
        self.started_at = started_at if started_at is not None else clock()
        self.cfg = settings.config
        self.gateway_finder = gateway_finder or (lambda: discover_gateway(target=self.cfg.internet.trace_target))
        self.gateway: str | None = None
        self.manager = IncidentManager(db, clock, started_at=self.started_at)
        self._sem = asyncio.Semaphore(1)  # at most one investigation at a time; others queue
        self._tasks: set[asyncio.Task] = set()
        self._busy: set[int] = set()  # incident ids queued or under investigation
        self._snaps: dict[int, _Snapshot] = {}
        self._fritz_running = False
        self._fritz_log_since: float | None = None
        self.last_tick_ok: float | None = None  # end of the last rules tick that ran through

    # -- targets ---------------------------------------------------------------
    def important_services(self) -> list[Target]:
        out = []
        for s in self.db.get_setting("important_services", []) or []:
            try:
                if s["kind"] not in ("icmp", "tcp", "http"):
                    continue
                out.append(Target(str(s["name"]), s["kind"], str(s["address"]),
                                  int(s["port"]) if s.get("port") else None))
            except (KeyError, TypeError, ValueError):
                log.warning("ignoring malformed important service %r", s)
        return out

    def targets(self) -> list[Target]:
        return default_targets(self.cfg, extra=self.important_services(), gateway=self.gateway)

    # -- rule loop -----------------------------------------------------------------
    async def tick(self) -> list:
        now = self.clock()
        targets = await asyncio.to_thread(self.targets)
        view = await asyncio.to_thread(build_view, self.db, self.settings, now,
                                       started_at=self.started_at, targets=targets)
        findings = evaluate(view, now)
        events = await asyncio.to_thread(self.manager.apply, findings, muted=view.mutes)
        for ev in events:
            try:
                self.notifier.on_event(ev)
            except Exception:
                log.exception("notifier rejected event for incident %s", ev.incident.id)
        failing = failing_targets(view)
        for ev in events:
            inc = ev.incident
            if ev.kind == "opened" or (ev.kind == "reopened" and not inc.diagnosis_json):
                if inc.id not in self._busy:
                    self._launch(inc, now, failing, followup=False)
        await self._followups(now, failing)
        if events:  # push now, not at the next periodic flush (coalescing stays in the notifier)
            try:
                await self.notifier.flush()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("notifier flush after rule tick failed")
        await self._battery(view)
        self.last_tick_ok = self.clock()
        return events

    async def _battery(self, view) -> None:
        """Battery escalation pushes (20%, 10%) while a battery host runs on battery."""
        on_battery = getattr(self.notifier, "on_battery", None)
        if on_battery is None:
            return
        on_batt = {h for h in self.cfg.battery_hosts if (ps := view.power.get(h)) is not None and not ps.ac_online}
        if not on_batt:
            return
        for inc in await asyncio.to_thread(self.db.open_incidents):
            if inc.rule == "power_lost" and inc.key in on_batt:
                ps = view.power[inc.key]
                try:
                    await on_battery(inc, ps.battery_pct)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("battery push failed")

    def _affected(self, inc: Incident, failing: frozenset) -> frozenset:
        """The incident's own failing targets: its key (device or service name),
        or the internet path for internet_down. Other targets flapping must not
        trigger a follow-up."""
        if inc.rule == "internet_down":
            own = self.cfg.internet.target_names | {"gateway", "router"}
        else:
            own = frozenset({inc.key})
        return failing & own

    async def _followups(self, now: float, failing: frozenset) -> None:
        open_incs = await asyncio.to_thread(self.db.open_incidents)
        open_ids = {i.id for i in open_incs}
        for stale in [k for k in self._snaps if k not in open_ids and k not in self._busy]:
            del self._snaps[stale]
        for inc in open_incs:
            if inc.id in self._busy:
                continue
            affected = self._affected(inc, failing)
            snap = self._snaps.get(inc.id)
            if snap is None:
                if inc.diagnosis_json:  # e.g. after a restart: take today's picture as the baseline
                    self._snaps[inc.id] = _Snapshot(now, inc.flap_count, affected)
                else:  # never diagnosed (restart during an investigation)
                    self._launch(inc, now, failing, followup=False)
                continue
            if (now - inc.opened_at >= FOLLOWUP_AFTER_S and now - snap.at >= FOLLOWUP_GAP_S
                    and (inc.flap_count != snap.flap_count or affected != snap.affected)):
                self._launch(inc, now, failing, followup=True)

    def _launch(self, inc: Incident, now: float, failing: frozenset, *, followup: bool) -> None:
        self._busy.add(inc.id)
        self._snaps[inc.id] = _Snapshot(now, inc.flap_count, self._affected(inc, failing))
        task = asyncio.create_task(self._investigate(inc.id, followup))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _investigate(self, inc_id: int, followup: bool) -> None:
        try:
            async with self._sem:
                inc = await asyncio.to_thread(self.db.get_incident, inc_id)
                if inc is None:
                    return
                if followup and inc.resolved_at is not None:
                    return  # over already: no follow-up needed
                if not followup and inc.diagnosis_json:
                    return
                log.info("investigating incident %s%s", inc_id, " (follow-up)" if followup else "")
                await self.investigator.investigate(inc, followup=followup)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("investigation of incident %s failed", inc_id)
        finally:
            self._busy.discard(inc_id)

    async def drain(self) -> None:
        """Wait for all queued investigations (tests, shutdown)."""
        while self._tasks:
            batch = list(self._tasks)
            await asyncio.gather(*batch, return_exceptions=True)
            # awaiting already finished tasks need not yield, so the done callbacks
            # that empty _tasks may not have run yet: drop finished ones here
            self._tasks.difference_update(t for t in batch if t.done())

    # -- FritzBox ------------------------------------------------------------------
    async def _fritz_call(self, fn, *args):
        """fn in a thread, at most FRITZ_TIMEOUT_S; None on timeout or error.
        A timed-out thread keeps running; no new call starts until it ends."""
        if self._fritz_running:
            return None
        started = False

        def run():
            nonlocal started
            started = True
            try:
                return fn(*args)
            finally:
                self._fritz_running = False

        self._fritz_running = True
        try:
            return await asyncio.wait_for(asyncio.to_thread(run), FRITZ_TIMEOUT_S)
        except Exception as exc:  # TimeoutError included
            log.warning("FritzBox call %s failed: %s", getattr(fn, "__name__", fn), type(exc).__name__)
            return None
        finally:
            if not started:  # cancelled before the thread picked it up: nothing will reset the flag
                self._fritz_running = False

    async def fritz_tick(self) -> None:
        if self.fritz is None:
            return
        now = self.clock()
        data = await self._fritz_call(self.fritz.poll)
        if not isinstance(data, dict):
            data = {"ok": False, "error": ERR_SLOW, **{k: None for k in _FRITZ_FIELDS}}
        open_incs = await asyncio.to_thread(self.db.open_incidents)
        if any(i.rule in FRITZ_LOG_RULES for i in open_incs):
            since = self._fritz_log_since or now - FRITZ_LOG_LOOKBACK_S
            lines = await self._fritz_call(self.fritz.event_log, since)
            if lines is not None:
                self._fritz_log_since = now
                if lines:
                    data["event_log"] = list(lines)
        else:
            self._fritz_log_since = None
        await asyncio.to_thread(self.db.insert_fritz, now, data)

    # -- other periodic jobs ----------------------------------------------------------
    async def gateway_tick(self) -> None:
        gw = await asyncio.to_thread(self.gateway_finder)
        if gw:  # keep the last known gateway while discovery fails (e.g. during an outage)
            if gw != self.gateway:
                log.info("provider gateway: %s", gw)
            self.gateway = gw

    async def housekeeping_tick(self) -> None:
        purged, trimmed = await asyncio.to_thread(run_once, self.db, self.settings, self.clock())
        if purged or trimmed:
            log.info("housekeeping: %d rows past retention, %d rows for size", purged, trimmed)

    def alarm_path_alive(self) -> tuple[bool, str]:
        if self.last_tick_ok is None and self.clock() - self.started_at < ALIVE_MAX_AGE_S:
            return True, ""  # just started: first tick and probes are on their way
        return alarm_path_alive(self.db, self.last_tick_ok, self.clock())

    def start(self, http, post) -> list[asyncio.Task]:
        s = self.settings
        jobs = {
            "pinger": supervise("pinger", lambda: run_pinger(self.db, self.targets)),
            "fritz": every("fritz", FRITZ_INTERVAL_S, self.fritz_tick),
            "gateway": every("gateway", GATEWAY_INTERVAL_S, self.gateway_tick),
            "rules": every("rules", RULE_INTERVAL_S, self.tick),
            "flush": every("flush", FLUSH_INTERVAL_S, self.notifier.flush),
            "housekeeping": every("housekeeping", HOUSEKEEPING_INTERVAL_S, self.housekeeping_tick),
            "daily": supervise("daily", lambda: daily_summary_loop(
                self.db, post, self.clock, asyncio.sleep, tz=s.tz, hour=self.cfg.daily_summary_hour,
                topic=s.ntfy_topic, dashboard_url=self.cfg.dashboard_url)),
            "healthcheck": supervise("healthcheck", lambda: healthcheck_loop(
                s.healthcheck_url, http, alive=self.alarm_path_alive)),
        }
        if self.fritz is None:
            jobs.pop("fritz").close()  # no TR-064 polling: drop the coroutine unstarted
        return [asyncio.create_task(coro, name=f"lanot-{name}") for name, coro in jobs.items()]

    async def stop(self, tasks: list[asyncio.Task]) -> None:
        pending = [*tasks, *self._tasks]
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


def quiet_http_loggers() -> None:
    """httpx logs every request URL at INFO, the secret healthcheck URL included."""
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def build_runtime(settings: Settings, db: Database, http) -> tuple[Runtime, Callable]:
    cfg = settings.config
    post = make_ntfy_post(http, settings)
    notifier = Notifier(post, time.time, db=db, topic=settings.ntfy_topic, dashboard_url=cfg.dashboard_url,
                        name_of=cfg.name_of)
    fritz = None
    if cfg.router.polls_tr064:
        fritz = FritzPoller(cfg.router.host, settings.fritz_user, settings.fritz_password, tz=cfg.timezone)
    investigator = Investigator(Deps(db=db, config=cfg, fritz=fritz), settings, time.time, notifier=notifier)
    rt = Runtime(settings, db, notifier=notifier, investigator=investigator, fritz=fritz,
                 started_at=PROCESS_START)
    return rt, post


def create_app(settings: Settings | None = None, *, start_background: bool = True) -> FastAPI:
    """With start_background=False the database opens at once and no loops run
    (tests). Otherwise the database opens at startup, so importing the module
    never touches the disk."""
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.db is None:
            Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
            app.state.db = await asyncio.to_thread(Database, settings.db_path)
        if not start_background:
            yield
            return
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        quiet_http_loggers()
        cfg = settings.config  # fail early on a broken config file
        missing = [h for h in cfg.agent_hosts if h not in settings.agent_tokens]
        if missing:
            log.warning("no AGENT_TOKENS entry for agent host(s) %s: their data will be refused", ", ".join(missing))
        async with httpx.AsyncClient() as http:
            rt, post = build_runtime(settings, app.state.db, http)
            app.state.runtime = rt
            tasks = rt.start(http, post)
            try:
                yield
            finally:
                await rt.stop(tasks)

    app = FastAPI(title="LANOT", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.db = None if start_background else Database(settings.db_path)
    app.include_router(api.router)
    app.include_router(routes.router)
    app.mount("/static", StaticFiles(directory=str(Path(routes.__file__).parent / "static")), name="static")
    return app


app = create_app()
