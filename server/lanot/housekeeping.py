"""Retention, size cap and the external healthcheck ping."""

import asyncio
import logging
from collections.abc import Callable

from .config import Settings
from .db import Database

log = logging.getLogger(__name__)


def run_once(db: Database, settings: Settings, now: float) -> tuple[int, int]:
    """Purge data past retention, then enforce the size cap.
    Returns (rows purged, rows deleted for size)."""
    purged = db.purge_older_than(now - settings.retention_days * 86400)
    trimmed = db.enforce_size(settings.db_max_bytes)
    return purged, trimmed


ALIVE_MAX_AGE_S = 60.0


def alarm_path_alive(db: Database, last_tick_ok: float | None, now: float,
                     max_age: float = ALIVE_MAX_AGE_S) -> tuple[bool, str]:
    """The dead man's switch may only say "alive" when the alarm path works:
    the last rules tick finished recently and the pinger still writes probes."""
    if last_tick_ok is None or now - last_tick_ok >= max_age:
        age = "never" if last_tick_ok is None else f"{now - last_tick_ok:.0f} s ago"
        return False, f"last successful rules tick {age}"
    newest = db.newest_probe_ts()
    if newest is None or now - newest >= max_age:
        age = "none" if newest is None else f"{now - newest:.0f} s old"
        return False, f"newest probe row {age}"
    return True, ""


async def healthcheck_loop(url: str | None, client, interval: float = 60, sleep=asyncio.sleep,
                           alive: Callable[[], tuple[bool, str]] | None = None) -> None:
    """Dead man's switch: every `interval` s GET `url` when `alive()` says the
    alarm path works, otherwise GET `url`/fail (healthchecks.io style) so the alert
    comes at once. No-op if `url` is unset. The URL itself is never logged."""
    if not url:
        return
    while True:
        try:
            ok, why = alive() if alive is not None else (True, "")
        except Exception as exc:
            ok, why = False, f"liveness check failed: {type(exc).__name__}"
        target = url if ok else url.rstrip("/") + "/fail"
        if not ok:
            log.warning("healthcheck: reporting FAIL, %s", why)
        try:
            await client.get(target, timeout=10.0)
        except Exception as exc:
            log.warning("healthcheck ping failed: %s", type(exc).__name__)
        await sleep(interval)
