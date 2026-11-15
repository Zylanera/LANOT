import asyncio
import json
from datetime import datetime
from zoneinfo import ZoneInfo

import httpx
import pytest

from conftest import make_settings
from lanot.db import Incident
from lanot.incidents import IncidentEvent
from lanot.notify import Notifier, daily_summary, daily_summary_loop, make_ntfy_post, schedule_daily

TZ_NAME = "America/New_York"
TZ = ZoneInfo(TZ_NAME)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def inc(i, severity="medium", **kw):
    base = dict(rule="r", key=f"k{i}", severity=severity, title=f"Problem {i}", detail="d",
                opened_at=1000.0, last_seen_at=1000.0, id=i)
    base.update(kw)
    return Incident(**base)


def opened(i, initial=False, **kw):
    return IncidentEvent("opened", inc(i, **kw), initial=initial)


def reopened(i, **kw):
    return IncidentEvent("reopened", inc(i, flap_count=1, **kw))


def resolved(i, resolved_at=1060.0, **kw):
    return IncidentEvent("resolved", inc(i, resolved_at=resolved_at, **kw))


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def sent():
    return []


@pytest.fixture
def ok_post(sent):
    async def post(payload):
        sent.append(payload)
    return post


@pytest.fixture
def n(ok_post, clock):
    return Notifier(ok_post, clock, name_of={"monitor": "Monitor"}.get)


async def test_first_push_immediate_format(n, sent):
    n.on_event(opened(1, severity="high"))
    await n.flush()
    assert len(sent) == 1
    p = sent[0]
    assert p == {
        "topic": "lanot", "title": "Problem 1", "message": "Investigating …", "priority": 5,
        "tags": ["rotating_light"], "click": "http://localhost:8080/incident/1",
    }
    await n.flush()
    assert len(sent) == 1


async def test_medium_priority_and_tag(n, sent):
    n.on_event(opened(1))
    await n.flush()
    assert sent[0]["priority"] == 4 and sent[0]["tags"] == ["warning"]


async def test_diagnosis_summary_in_message(n, sent):
    n.on_event(opened(1, diagnosis_json=json.dumps({"summary": "Router restarted."})))
    await n.flush()
    assert sent[0]["message"] == "Router restarted."


async def test_coalesce_within_10_min(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(60)
    n.on_event(resolved(1))
    n.on_event(reopened(1))
    await n.flush()
    assert len(sent) == 1
    clock.advance(541)
    await n.flush()
    assert len(sent) == 2 and "down 2 times" in sent[1]["message"]


async def test_resolved_message(n, sent, clock):
    n.on_event(opened(1, severity="high"))
    await n.flush()
    clock.advance(700)
    n.on_event(resolved(1, resolved_at=1000.0 + 7 * 60 + 20, flap_count=2, severity="high"))
    await n.flush()
    p = sent[1]
    assert p["title"] == "Resolved: Problem 1"
    assert p["message"] == "Lasted 7 min (down 3 times)"
    assert p["tags"] == ["white_check_mark"] and p["priority"] == 5


async def test_resolved_duration_minimum_one_minute(n, sent, clock):
    n.on_event(resolved(1, resolved_at=1010.0))
    await n.flush()
    assert sent[0]["message"].startswith("Lasted 1 min")


async def test_initial_merged(n, sent):
    for i in range(3):
        n.on_event(opened(i + 1, initial=True))
    await n.flush()
    assert len(sent) == 1 and sent[0]["title"] == "Found at startup: 3 problems"
    assert "Problem 2" in sent[0]["message"]


async def test_initial_pushes_count_for_rate_limit(n, sent, clock):
    n.on_event(opened(1, initial=True))
    await n.flush()
    clock.advance(30)
    n.on_event(IncidentEvent("updated", inc(1, severity="high")))
    await n.flush()
    assert len(sent) == 1
    clock.advance(571)
    await n.flush()
    assert len(sent) == 2


async def test_failed_post_retried(clock):
    sent, fail = [], [True]

    async def post(payload):
        if fail[0]:
            raise httpx.ConnectError("down")
        sent.append(payload)

    n = Notifier(post, clock)
    n.on_event(opened(1))
    await n.flush()
    assert sent == []
    clock.advance(10)
    await n.flush()
    assert sent == []
    fail[0] = False
    clock.advance(10)
    await n.flush()
    assert len(sent) == 1
    await n.flush()
    assert len(sent) == 1


async def test_failed_first_push_not_counted_as_pushed(db, clock):
    sent, fail = [], [True]

    async def post(payload):
        if fail[0]:
            raise httpx.ConnectError("down")
        sent.append(payload)

    i = db.save_incident(inc(None, id=None, opened_at=1000.0))
    n = Notifier(post, clock, db=db)
    n.on_event(IncidentEvent("opened", i))
    await n.flush()
    assert db.get_incident(i.id).last_push_at is None
    fail[0] = False
    clock.advance(10)
    await n.flush()
    assert len(sent) == 1 and db.get_incident(i.id).last_push_at == 1010.0


async def test_last_push_persisted_across_restart(db, ok_post, sent, clock):
    i = db.save_incident(inc(None, id=None))
    n1 = Notifier(ok_post, clock, db=db)
    n1.on_event(IncidentEvent("opened", i))
    await n1.flush()
    assert db.get_incident(i.id).last_push_at == 1000.0

    clock.advance(100)
    n2 = Notifier(ok_post, clock, db=db)  # restart
    n2.on_event(IncidentEvent("updated", db.get_incident(i.id)))
    await n2.flush()
    assert len(sent) == 1
    clock.advance(500)
    await n2.flush()
    assert len(sent) == 2


async def test_diagnosis_followup_after_60s_sent_immediately(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(61)
    await n.on_diagnosis(inc(1, diagnosis_json=json.dumps({"summary": "Loose cable."})))
    assert len(sent) == 2 and sent[1]["message"] == "Loose cable."


async def test_diagnosis_within_60s_is_first_and_goes_out_now(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(30)
    await n.on_diagnosis(inc(1, diagnosis_json=json.dumps({"summary": "Loose cable."})))
    await n.flush()
    assert len(sent) == 2 and sent[1]["message"] == "Loose cable." and sent[1]["title"] == "Problem 1"


async def test_diagnosis_before_opening_push_delivered_merges(clock):
    sent, fail = [], [True]

    async def post(payload):
        if fail[0]:
            raise httpx.ConnectError("down")
        sent.append(payload)

    n = Notifier(post, clock)
    n.on_event(opened(1))
    await n.flush()
    await n.on_diagnosis(inc(1, diagnosis_json=json.dumps({"summary": "Cause X."})))
    fail[0] = False
    await n.flush()
    assert len(sent) == 1 and sent[0]["message"] == "Cause X."


async def test_make_ntfy_post_uses_base_url_and_json():
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        post = make_ntfy_post(c, make_settings())
        await post({"topic": "lanot", "title": "t"})
    assert str(seen[0].url) == "http://127.0.0.1:8081" and seen[0].method == "POST"
    assert json.loads(seen[0].content) == {"topic": "lanot", "title": "t"}


async def test_make_ntfy_post_raises_on_error():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as c:
        with pytest.raises(httpx.HTTPStatusError):
            await make_ntfy_post(c, make_settings())({"topic": "x"})


# -- daily summary --------------------------------------------------------
def ts(y, m, d, h=0, mi=0):
    return datetime(y, m, d, h, mi, tzinfo=TZ).timestamp()


def test_daily_summary_counts_outages(db):
    since, until = ts(2026, 11, 13, 8), ts(2026, 11, 14, 8)
    db.save_incident(Incident("internet_down", "internet", "high", "Internet down", "",
                              ts(2026, 11, 13, 10), ts(2026, 11, 13, 10, 20), ts(2026, 11, 13, 10, 20)))
    db.save_incident(Incident("internet_down", "internet", "high", "Internet down", "",
                              ts(2026, 11, 13, 15), ts(2026, 11, 13, 15, 10), ts(2026, 11, 13, 15, 10)))
    db.save_incident(Incident("disk_full", "nas:/", "medium", "Disk full", "",
                              ts(2026, 11, 13, 12), ts(2026, 11, 14, 7), None))
    db.save_incident(Incident("disk_full", "old", "medium", "old", "", ts(2026, 11, 10), ts(2026, 11, 10), ts(2026, 11, 10, 1)))
    s = daily_summary(db, since, until, TZ_NAME)
    assert s["title"] == "Daily summary 2026-11-14"
    assert "3 new incidents" in s["message"]
    assert "Internet: 2 outages, 30 min in total" in s["message"]
    assert "1 problem still open" in s["message"]


def test_daily_summary_quiet_day(db):
    s = daily_summary(db, ts(2026, 11, 13, 8), ts(2026, 11, 14, 8), TZ_NAME)
    assert "No incidents" in s["message"] and "Internet" not in s["message"]


def test_daily_summary_outage_still_running_counts_until_end(db):
    db.save_incident(Incident("internet_down", "internet", "high", "x", "", ts(2026, 11, 14, 7), ts(2026, 11, 14, 7, 30), None))
    s = daily_summary(db, ts(2026, 11, 13, 8), ts(2026, 11, 14, 8), TZ_NAME)
    assert "60 min in total" in s["message"]


def test_schedule_daily_next_08_local():
    clock = Clock(ts(2026, 11, 14, 7, 59))
    assert schedule_daily(clock, TZ_NAME) == ts(2026, 11, 14, 8)
    clock = Clock(ts(2026, 11, 14, 8))
    assert schedule_daily(clock, TZ_NAME) == ts(2026, 11, 15, 8)
    clock = Clock(ts(2026, 11, 14, 20))
    assert schedule_daily(clock, TZ_NAME) == ts(2026, 11, 15, 8)


def test_schedule_daily_across_dst():
    # US clocks go back on 2026-11-01: 25 h between 08:00 on Oct 31 and Nov 1
    clock = Clock(ts(2026, 10, 31, 9))
    assert schedule_daily(clock, TZ_NAME) == ts(2026, 11, 1, 8)
    assert ts(2026, 11, 1, 8) - ts(2026, 10, 31, 8) == 25 * 3600
    # 07:00 in New York is 12:00 UTC, so the next 06:00 UTC is on the following day
    utc6 = datetime(2026, 11, 15, 6, tzinfo=ZoneInfo("UTC")).timestamp()
    assert schedule_daily(Clock(ts(2026, 11, 14, 7)), "UTC", hour=6) == utc6


async def test_daily_summary_loop_sends_and_sleeps(db, ok_post, sent):
    clock = Clock(ts(2026, 11, 14, 7))
    slept = []

    async def sleep(s):
        slept.append(s)
        clock.advance(s)
        if len(slept) == 2:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await daily_summary_loop(db, ok_post, clock, sleep, tz=TZ_NAME, dashboard_url="http://192.0.2.24:8080")
    assert slept[0] == 3600 and len(sent) == 1
    assert sent[0]["topic"] == "lanot" and sent[0]["title"] == "Daily summary 2026-11-14" and sent[0]["priority"] == 3
    assert sent[0]["click"] == "http://192.0.2.24:8080"
    assert slept[1] == 24 * 3600


async def test_daily_summary_loop_survives_post_failure(db):
    clock = Clock(ts(2026, 11, 14, 7))
    calls = []

    async def post(p):
        calls.append(p)
        raise httpx.ConnectError("down")

    n = [0]

    async def sleep(s):
        n[0] += 1
        clock.advance(s)
        if n[0] == 3:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await daily_summary_loop(db, post, clock, sleep, tz=TZ_NAME)
    assert len(calls) == 2


async def test_daily_summary_loop_early_wake_sends_once(db, ok_post, sent):
    clock = Clock(ts(2026, 11, 14, 7))
    slept = []

    async def sleep(s):
        slept.append(s)
        clock.advance(s - 0.005 if len(slept) == 1 else s)
        if len(slept) == 3:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await daily_summary_loop(db, ok_post, clock, sleep, tz=TZ_NAME)
    assert len(sent) == 1 and slept[1] == pytest.approx(0.005, abs=1e-3) and slept[2] == 24 * 3600


async def test_daily_summary_loop_survives_db_error(db, ok_post, sent, monkeypatch):
    clock = Clock(ts(2026, 11, 14, 7))
    calls = [0]
    import lanot.notify as notify
    real = notify.daily_summary

    def flaky(*a, **k):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("db locked")
        return real(*a, **k)

    monkeypatch.setattr(notify, "daily_summary", flaky)
    n = [0]

    async def sleep(s):
        n[0] += 1
        clock.advance(s)
        if n[0] == 3:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await daily_summary_loop(db, ok_post, clock, sleep, tz=TZ_NAME)
    assert calls[0] == 2 and len(sent) == 1


async def test_late_diagnosis_after_resolve_is_followup(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(100)
    n.on_event(resolved(1))
    clock.advance(600)
    await n.flush()
    clock.advance(61)
    await n.on_diagnosis(inc(1, resolved_at=1060.0, diagnosis_json=json.dumps({"summary": "Cable."})))
    assert sent[-1]["title"] == "Follow-up: Problem 1" and sent[-1]["message"] == "Cable."


async def test_followup_diagnosis_push_title():
    sent = []

    async def post(p):
        sent.append(p)

    n = Notifier(post, Clock(5000.0))
    i = inc(1, diagnosis_json=json.dumps({"summary": "New picture", "followup": True}), last_push_at=1000.0)
    await n.on_diagnosis(i)
    assert sent[0]["title"] == "Follow-up: Problem 1" and sent[0]["message"] == "New picture"


# -- diagnosis delivery, battery, flush lock -----------------
def diag(i, summary="Loose cable.", **kw):
    return inc(i, diagnosis_json=json.dumps({"summary": summary}), **kw)


async def test_first_diagnosis_20s_after_open_pushed_immediately(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(20)
    await n.on_diagnosis(diag(1))
    assert len(sent) == 2
    assert sent[1]["title"] == "Problem 1" and sent[1]["message"] == "Loose cable."


async def test_followup_diagnosis_still_rate_limited(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(20)
    await n.on_diagnosis(diag(1))
    clock.advance(60)
    follow = inc(1, diagnosis_json=json.dumps({"summary": "New picture", "followup": True}))
    await n.on_diagnosis(follow)
    assert len(sent) == 2
    clock.advance(600)
    await n.flush()
    assert len(sent) == 3 and sent[2]["title"] == "Follow-up: Problem 1" and sent[2]["message"] == "New picture"


async def test_resolve_before_diagnosis_delivered_carries_summary(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(20)
    n.on_event(resolved(1, resolved_at=1020.0))
    await n.flush()  # resolved held by the 10-min limit
    clock.advance(5)
    await n.on_diagnosis(diag(1, resolved_at=1020.0))
    clock.advance(600)
    await n.flush()
    assert len(sent) == 2
    assert sent[1]["title"].startswith("Resolved: ") and "Loose cable." in sent[1]["message"]
    await n.flush()
    assert len(sent) == 2


async def test_newer_event_never_drops_waiting_diagnosis(n, sent, clock):
    n.on_event(opened(1))
    await n.flush()
    clock.advance(20)
    await n.on_diagnosis(diag(1))
    clock.advance(30)
    follow = inc(1, diagnosis_json=json.dumps({"summary": "New picture", "followup": True}))
    await n.on_diagnosis(follow)  # waits for the limit
    n.on_event(resolved(1, resolved_at=1100.0))
    n.on_event(reopened(1))
    clock.advance(600)
    await n.flush()
    assert len(sent) == 3 and "New picture" in sent[2]["message"]


async def test_concurrent_flushes_no_duplicate(clock):
    sent = []

    async def slow_post(p):
        await asyncio.sleep(0.01)
        sent.append(p)

    n = Notifier(slow_post, clock)
    n.on_event(opened(1))
    await asyncio.gather(n.flush(), n.flush(), n.flush())
    assert len(sent) == 1
    await asyncio.gather(n.flush(), n.on_diagnosis(diag(1)), n.on_diagnosis(diag(1)), n.flush())
    assert [p["message"] for p in sent] == ["Investigating …", "Loose cable."]
    clock.advance(700)
    await n.flush()
    assert len(sent) == 2  # the same diagnosis twice is not pushed again


async def test_ntfy_post_uses_short_timeout():
    seen = {}

    class C:
        async def post(self, url, json=None, timeout=None):
            seen["timeout"] = timeout

            class R:
                def raise_for_status(self):
                    pass
            return R()

    await make_ntfy_post(C(), make_settings())({"topic": "x"})
    assert seen["timeout"] == 5.0


def power(i, pct, **kw):
    return inc(i, rule="power_lost", key="monitor", severity="high",
               title=f"Monitor: mains power lost (battery {pct}%)",
               detail=f"Battery at {pct}%. Monitor is running on battery.", **kw)


async def test_power_lost_push_has_battery(n, sent):
    n.on_event(IncidentEvent("opened", power(1, 93)))
    await n.flush()
    assert sent[0]["title"] == "Monitor: mains power lost (battery 93%)"
    assert "93%" in sent[0]["message"]


async def test_battery_thresholds_pushed_once_each(n, sent, clock):
    n.on_event(IncidentEvent("opened", power(1, 93)))
    await n.flush()
    await n.on_battery(power(1, 93), 93.0)
    clock.advance(30)
    await n.on_battery(power(1, 20), 20.0)  # escalation bypasses the 10-min limit
    await n.on_battery(power(1, 19), 19.0)
    assert len(sent) == 2 and sent[1]["title"] == "Monitor: battery down to 20%"
    clock.advance(30)
    await n.on_battery(power(1, 10), 10.0)
    await n.on_battery(power(1, 9), 9.0)
    assert len(sent) == 3 and sent[2]["title"] == "Monitor: battery down to 10%"
    assert sent[2]["priority"] == 5


async def test_battery_already_low_at_open_not_repeated(n, sent):
    n.on_event(IncidentEvent("opened", power(1, 15)))
    await n.on_battery(power(1, 15), 15.0)
    await n.flush()
    assert len(sent) == 1
    await n.on_battery(power(1, 14), 14.0)
    assert len(sent) == 1
