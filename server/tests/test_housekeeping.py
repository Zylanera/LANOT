import asyncio

import httpx
import pytest

from lanot.config import Settings
from lanot.housekeeping import healthcheck_loop, run_once
from conftest import sample_metrics
from lanot_common.protocol import MetricsReport

DAY = 86400.0


def test_housekeeping_30_days(db):
    now = 100 * DAY
    for age, host in ((31, "old"), (29, "new")):
        db.insert_metrics(MetricsReport(**sample_metrics(host)), now - age * DAY)
    db.insert_probe("t", now - 40 * DAY, True, 1.0)
    db.insert_probe("t", now - 1 * DAY, True, 1.0)
    run_once(db, Settings(db_path=":x:"), now)
    assert db.latest_metrics("old") is None and db.latest_metrics("new") is not None
    assert len(db.probes("t", 0)) == 1


def test_housekeeping_enforces_size(db):
    calls = []
    db.enforce_size = lambda m: calls.append(m) or 0
    run_once(db, Settings(db_path=":x:", db_max_bytes=123), 1000.0)
    assert calls == [123]


def test_housekeeping_keeps_incidents(db):
    from lanot.db import Incident
    i = db.save_incident(Incident("r", "k", "medium", "t", "", 0.0, 0.0, 1.0))
    run_once(db, Settings(db_path=":x:"), 100 * DAY)
    assert db.get_incident(i.id) is not None


class FakeClient:
    def __init__(self, fail=False):
        self.urls, self.fail = [], fail

    async def get(self, url, **kw):
        self.urls.append(url)
        if self.fail:
            raise httpx.ConnectError("x")
        return httpx.Response(200)


async def test_healthcheck_noop_without_url():
    c = FakeClient()
    await asyncio.wait_for(healthcheck_loop(None, c), 1)
    assert c.urls == []


async def test_healthcheck_pings_each_interval_and_survives_errors():
    for fail in (False, True):
        c = FakeClient(fail=fail)
        slept = []

        async def sleep(s):
            slept.append(s)
            if len(slept) == 3:
                raise asyncio.CancelledError

        with pytest.raises(asyncio.CancelledError):
            await healthcheck_loop("http://hc/x", c, interval=60, sleep=sleep)
        assert c.urls == ["http://hc/x"] * 3 and slept == [60, 60, 60]


# -- dead man's switch depends on the alarm path ---------------------------------
from lanot.housekeeping import alarm_path_alive  # noqa: E402


async def _one_ping(alive, caplog=None):
    c = FakeClient()

    async def sleep(s):
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await healthcheck_loop("http://hc/x", c, alive=alive, sleep=sleep)
    return c.urls


async def test_healthcheck_ok_pings():
    assert await _one_ping(lambda: (True, "")) == ["http://hc/x"]


async def test_healthcheck_stale_tick_pings_fail(db, caplog):
    db.insert_probe("t", 1000.0, True, 1.0)
    alive = lambda: alarm_path_alive(db, last_tick_ok=900.0, now=1010.0)
    assert await _one_ping(alive) == ["http://hc/x/fail"]
    assert "rules tick" in caplog.text


async def test_healthcheck_stale_probes_pings_fail(db, caplog):
    db.insert_probe("t", 900.0, True, 1.0)
    alive = lambda: alarm_path_alive(db, last_tick_ok=1005.0, now=1010.0)
    assert await _one_ping(alive) == ["http://hc/x/fail"]
    assert "probe" in caplog.text


def test_alarm_path_alive_all_fresh(db):
    db.insert_probe("t", 1000.0, True, 1.0)
    assert alarm_path_alive(db, last_tick_ok=1001.0, now=1010.0) == (True, "")
    assert alarm_path_alive(db, last_tick_ok=None, now=1010.0)[0] is False


def test_httpx_request_logging_silenced():
    # httpx logs every request URL at INFO; the healthcheck URL is a secret
    import logging
    from lanot.main import quiet_http_loggers
    quiet_http_loggers()
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
