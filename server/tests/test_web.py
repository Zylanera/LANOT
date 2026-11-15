import asyncio
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from lanot_common.protocol import LogBatch, LogLine, MetricsReport, StateReport

from conftest import sample_metrics, sample_state
from dataclasses import replace

from conftest import CFG, make_settings
from lanot.db import Incident
from lanot.main import Runtime, create_app, every
from lanot.pinger import Target
from lanot.web.routes import attribute

HOSTS = {"docker-host": "t1", "nas": "t2", "monitor": "t3"}


@pytest.fixture
def settings(tmp_path):
    return make_settings(db_path=str(tmp_path / "web.db"), agent_tokens=HOSTS,
                         allowed_hosts="testserver,192.0.2.24:8080")


@pytest.fixture
def app(settings):
    return create_app(settings, start_background=False)


@pytest.fixture
def db(app):
    return app.state.db


@pytest.fixture
def client(app):
    return TestClient(app)


def seed_incident(db, severity="medium", rule="disk_full", key="nas:/mnt/tank", title="NAS: disk /mnt/tank 93% full",
                  resolved=False, diagnosis=None, opened_at=None, flap_count=0):
    now = time.time()
    opened_at = opened_at if opened_at is not None else now - 600
    inc = Incident(rule, key, severity, title, "d", opened_at=opened_at, last_seen_at=now,
                   resolved_at=now - 60 if resolved else None, flap_count=flap_count,
                   diagnosis_json=json.dumps(diagnosis) if diagnosis else None)
    return db.save_incident(inc)


DIAG = {
    "summary": "The disk is almost full.",
    "what_happened": "Pool tank reached 93%.",
    "cause": "Lots of new recordings.",
    "confidence": "likely",
    "suggestions": ["Check whether old recordings can be deleted"],
    "evidence": ["df: 93%"],
    "model": "claude",
    "tool_calls": 2,
    "duration_s": 12.0,
    "facts": {"traceroute": "1 192.168.178.1"},
}


# -- overview ----------------------------------------------------------------
def test_overview_bad_when_open_high_incident(client, db):
    seed_incident(db, severity="high")
    assert client.get("/api/v1/ui/overview").json()["status"] == "bad"


def test_overview_warn_for_medium_and_ok_when_empty(client, db):
    body = client.get("/api/v1/ui/overview").json()
    assert body["status"] == "ok"
    assert {"status", "tiles", "incidents", "updated"} <= set(body)
    names = [t["name"] for t in body["tiles"]]
    assert names[:2] == ["Internet", "Docker host"] and "FritzBox" in names
    seed_incident(db, severity="medium")
    body = client.get("/api/v1/ui/overview").json()
    assert body["status"] == "warn"
    nas = next(t for t in body["tiles"] if t["id"] == "nas")
    assert nas["status"] == "warn" and "93%" in nas["text"]
    assert body["incidents"][0]["title"].startswith("NAS")


def test_resolved_incident_does_not_turn_status_red(client, db):
    seed_incident(db, severity="high", resolved=True)
    assert client.get("/api/v1/ui/overview").json()["status"] == "ok"


def test_host_tile_shows_live_metrics(client, db):
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), time.time())
    tile = next(t for t in client.get("/api/v1/ui/overview").json()["tiles"] if t["id"] == "docker-host")
    assert tile["status"] == "ok" and tile["text"] == "running"  # numbers only on the detail page


def test_start_page_lang_and_no_third_party(client):
    html = client.get("/").text
    assert "All good" in html
    assert 'lang="en"' in html and "fonts.googleapis" not in html  # no third-party requests


def test_overview_renders_chain_with_five_stations(client):
    html = client.get("/").text
    for name in ("LAN", "FritzBox", "Line", "Provider", "Internet"):
        assert f'<span class="st-name">{name}</span>' in html
    chain = client.get("/api/v1/ui/overview").json()["chain"]
    assert [s["name"] for s in chain["stations"]] == ["LAN", "FritzBox", "Line", "Provider", "Internet"]


def test_chain_breaks_at_attributed_station(client, db):
    now = time.time()
    seed_incident(db, severity="high", rule="internet_down", key="internet", title="Internet down",
                  opened_at=now - 120)
    db.insert_fritz(now - 30, {"ok": True, "error": None, "link_up": True, "wan_connected": False})
    stations = client.get("/api/v1/ui/overview").json()["chain"]["stations"]
    by = {s["id"]: s for s in stations}
    assert by["provider"]["status"] == "bad" and by["provider"]["broken"]
    assert by["internet"]["status"] == "unknown" and by["line"]["status"] == "ok"
    html = client.get("/").text
    assert 'class="seg broken"' in html and "✕" in html
    assert "1 problem: Internet down" in html


def test_start_page_shows_word_not_only_colour(client, db):
    seed_incident(db, severity="high")
    html = client.get("/").text
    assert "1 problem" in html
    # markers carry a hidden word; the colour is never the only signal
    assert '<span class="sr-only">Problem: </span>' in html
    assert '<span class="sr-only">unknown: </span>' in html


@pytest.mark.parametrize("path", ["/", "/incidents", "/internet", "/device/docker-host", "/logs", "/settings"])
def test_pages_200_on_empty_db(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_unknown_device_and_incident_404(client):
    assert client.get("/device/nope").status_code == 404
    assert client.get("/incident/999").status_code == 404


# -- incidents -----------------------------------------------------------------
def test_incident_page_shows_confidence(client, db):
    inc = seed_incident(db, diagnosis=DIAG)
    html = client.get(f"/incident/{inc.id}").text
    for s in ("What happened", "Probable cause", "Confidence", "likely",
              "What you could check", "Check whether old recordings can be deleted", "<details", "evidence",
              "df: 93%"):
        assert s in html


def test_incident_without_diagnosis_says_running(client, db):
    inc = seed_incident(db)
    assert "Investigating" in client.get(f"/incident/{inc.id}").text


def test_incident_list(client, db):
    seed_incident(db, title="First incident")
    seed_incident(db, title="Second incident", resolved=True, key="x")
    html = client.get("/incidents").text
    assert "First incident" in html and "Second incident" in html and "resolved after" in html


# -- internet ----------------------------------------------------------------
def test_attribution():
    assert attribute({"link_up": False}) == "line" and attribute({"link_up": True, "wan_connected": False}) == "provider"


def test_attribution_router_lan_and_default():
    assert attribute({}, False) == "router"
    assert attribute({}, False, lan_ok=True) == "router"
    assert attribute({}, False, lan_ok=False) == "lan"
    assert attribute({"link_up": True, "wan_connected": True}, True) == "provider"
    assert attribute({}, None) == "provider"


def test_internet_page_lists_outage_with_attribution(client, db):
    now = time.time()
    seed_incident(db, severity="high", rule="internet_down", key="internet", title="Internet down",
                  resolved=True, opened_at=now - 400)
    db.insert_fritz(now - 300, {"ok": True, "error": None, "link_up": False, "wan_connected": False})
    html = client.get("/internet").text
    assert 'class="who">Line<' in html and "Internet history" in html
    assert html.count('class="daybar') == 30


# -- settings ----------------------------------------------------------------
def test_mute_roundtrip(client, db):
    r = client.post("/settings/mute", data={"rule": "device_down", "key": "printer", "duration": "1d"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert ("device_down", "printer") in db.mutes_active(time.time() + 3600)
    assert ("device_down", "printer") not in db.mutes_active(time.time() + 2 * 86400)
    html = client.get("/settings").text
    assert "printer" in html.lower() and "unmute" in html.lower()
    r = client.post("/settings/mute/clear", data={"rule": "device_down", "key": "printer"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert db.mutes_active(time.time()) == set()


def test_mute_rejects_invalid_input(client, db):
    for data in ({"rule": "nonsense", "key": "docker-host", "duration": "1h"},
                 {"rule": "device_down", "key": "docker-host", "duration": "99y"},
                 {"rule": "device_down", "key": "<b>", "duration": "1h"}):
        r = client.post("/settings/mute", data=data, follow_redirects=False)
        assert r.status_code == 303 and "error=" in r.headers["location"]
    assert db.mutes_active(time.time()) == set()


def test_mute_from_incident_page_returns_there(client, db):
    inc = seed_incident(db)
    r = client.post("/settings/mute", data={"rule": inc.rule, "key": inc.key, "duration": "1h",
                                                  "back": f"/incident/{inc.id}"}, follow_redirects=False)
    assert r.headers["location"].startswith(f"/incident/{inc.id}")
    r = client.post("/settings/mute", data={"rule": inc.rule, "key": inc.key, "duration": "1h",
                                                  "back": "https://evil.example/"}, follow_redirects=False)
    assert r.headers["location"].startswith("/settings")


def test_important_service_add_validate_delete(client, db):
    ok = {"name": "gitea", "kind": "tcp", "address": "192.0.2.31", "port": "3000"}
    assert client.post("/settings/services", data=ok, follow_redirects=False).status_code == 303
    assert db.get_setting("important_services") == [
        {"name": "gitea", "kind": "tcp", "address": "192.0.2.31", "port": 3000}]
    for bad in ({**ok, "name": "x2", "port": "70000"}, {**ok, "name": "x3", "kind": "ftp"},
                {**ok, "name": "docker-host"}, {**ok, "name": "x4", "address": "a b;rm"}, {**ok, "name": "gitea"},
                {**ok, "name": "x5", "kind": "tcp", "port": ""}):
        r = client.post("/settings/services", data=bad, follow_redirects=False)
        assert "error=" in r.headers["location"], bad
    assert len(db.get_setting("important_services")) == 1
    assert "gitea" in client.get("/settings").text
    client.post("/settings/services/delete", data={"name": "gitea"})
    assert db.get_setting("important_services") == []


def test_thresholds_validated(client, db):
    good = {"disk_warn": "85", "disk_high": "95", "temp_cpu": "85", "temp_disk": "50"}
    client.post("/settings/thresholds", data=good)
    assert db.get_setting("thresholds") == {"disk_warn": 85.0, "disk_high": 95.0, "temp_cpu": 85.0, "temp_disk": 50.0}
    r = client.post("/settings/thresholds", data={**good, "disk_warn": "97"}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    r = client.post("/settings/thresholds", data={**good, "temp_cpu": "abc"}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    assert db.get_setting("thresholds")["disk_warn"] == 85.0


def test_important_containers(client, db):
    db.insert_state(StateReport(**sample_state("docker-host")), time.time())
    assert "docker-host/web" in client.get("/settings").text
    client.post("/settings/containers", data={"c": ["docker-host/web", "nas/db"]})
    assert db.get_setting("important_containers") == ["docker-host/web", "nas/db"]
    r = client.post("/settings/containers", data={"c": ["bad entry"]}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    assert db.get_setting("important_containers") == ["docker-host/web", "nas/db"]


def test_cross_origin_post_rejected(client, db):
    r = client.post("/settings/mute", data={"rule": "device_down", "key": "docker-host", "duration": "1h"},
                    headers={"Origin": "http://evil.example"}, follow_redirects=False)
    assert r.status_code == 403
    assert db.mutes_active(time.time()) == set()


# -- XSS ------------------------------------------------------------------------
def test_log_line_is_escaped(client, db):
    now = time.time()
    db.insert_logs(LogBatch(host="docker-host", lines=[LogLine(ts=now, source="syslog", severity=3,
                                                        message="<script>alert(1)</script>")]), now)
    for path in ("/logs?q=alert", "/device/docker-host"):
        html = client.get(path).text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html, path
        assert "<script>alert(1)" not in html, path


def test_diagnosis_is_escaped(client, db):
    inc = seed_incident(db, diagnosis={**DIAG, "cause": "<img src=x onerror=alert(1)>"})
    html = client.get(f"/incident/{inc.id}").text
    assert "<img src=x" not in html and "&lt;img src=x" in html


def test_log_search_filters(client, db):
    now = time.time()
    db.insert_logs(LogBatch(host="docker-host", lines=[LogLine(ts=now, source="s", severity=6, message="hello world")]), now)
    db.insert_logs(LogBatch(host="nas", lines=[LogLine(ts=now, source="s", severity=3, message="hello error")]), now)
    html = client.get("/logs?q=hello&host=nas").text
    assert "hello error" in html and "hello world" not in html
    html = client.get("/logs?q=hello&severity=error").text
    assert "hello error" in html and "hello world" not in html


# -- device ---------------------------------------------------------------------
def test_device_series_api(client, db):
    now = time.time()
    for i in range(3):
        db.insert_metrics(MetricsReport(**sample_metrics("docker-host", ts=now - 300 * i)), now - 300 * i)
    body = client.get("/api/v1/ui/series/docker-host?range=24h").json()
    assert len(body["ts"]) == 3 and body["cpu"][0] == 12.5
    assert body["mem"][0] == 25.0 and body["temps"]["CPU"][0] == 55.0 and body["disks"]["/"][0] == 40.0
    assert client.get("/api/v1/ui/series/nope").status_code == 404


def test_device_page_lists_containers(client, db):
    db.insert_state(StateReport(**sample_state("docker-host")), time.time())
    html = client.get("/device/docker-host").text
    assert "web" in html and "Container" in html and "uplot.min.js" in html


# -- wiring -----------------------------------------------------------------------
class FakeNotifier:
    def __init__(self):
        self.events = []
        self.flushes = 0

    def on_event(self, ev):
        self.events.append(ev)

    async def flush(self):
        self.flushes += 1


class FakeInvestigator:
    def __init__(self, db=None, delay=0.0):
        self.calls = []
        self.followups = []
        self.db, self.delay = db, delay
        self.running = 0
        self.max_running = 0

    async def investigate(self, inc, *, followup=False):
        self.calls.append(inc.id)
        self.followups.append(followup)
        self.running += 1
        self.max_running = max(self.max_running, self.running)
        await asyncio.sleep(self.delay)
        if self.db is not None:
            self.db.set_diagnosis(inc.id, json.dumps({"summary": "x"}))
        self.running -= 1


def fail_probes(db, target, now, n=3):
    for i in range(n):
        db.insert_probe(target, now - 10 * (n - i), False, None)


def only_agent(cfg, host_id):
    """The config with an agent on `host_id` only (no agent_silent noise from the others)."""
    return replace(cfg, hosts=tuple(replace(h, agent=h.id == host_id) for h in cfg.hosts))


def make_runtime(settings, db, inv=None, clock=time.time):
    one_agent = settings.model_copy(update={"agent_tokens": {"docker-host": "t"}})
    one_agent.with_config(only_agent(settings.config, "docker-host"))
    return Runtime(one_agent, db, notifier=FakeNotifier(), investigator=inv or FakeInvestigator(db),
                   clock=clock, started_at=clock() - 3600)


async def test_rule_tick_device_down_one_event_one_investigation(settings, db):
    rt = make_runtime(settings, db)
    fail_probes(db, "docker-host", time.time())
    await rt.tick()
    await rt.drain()
    assert [e.kind for e in rt.notifier.events] == ["opened"]
    assert rt.notifier.events[0].incident.rule == "device_down"
    assert len(rt.investigator.calls) == 1
    await rt.tick()  # still down: no new event, no new investigation
    await rt.drain()
    assert len(rt.notifier.events) == 1 and len(rt.investigator.calls) == 1


async def test_tick_pushes_new_incident_within_same_tick(settings, db):
    from lanot.notify import Notifier
    posts = []

    async def post(payload):
        posts.append(payload)

    rt = make_runtime(settings, db)
    rt.notifier = Notifier(post, time.time, db=db)
    fail_probes(db, "docker-host", time.time())
    await rt.tick()  # no separate flush call, no interval wait
    await rt.drain()
    assert len(posts) == 1


async def test_investigations_run_one_at_a_time(settings, db):
    inv = FakeInvestigator(db, delay=0.05)
    rt = make_runtime(settings, db, inv)
    now = time.time()
    fail_probes(db, "docker-host", now)
    fail_probes(db, "nas", now)
    await rt.tick()
    await rt.drain()
    assert len(inv.calls) == 2 and inv.max_running == 1


async def test_reopened_without_diagnosis_is_investigated(settings, db):
    inv = FakeInvestigator()  # never stores a diagnosis
    rt = make_runtime(settings, db, inv)
    inc = seed_incident(db, rule="device_down", key="docker-host", severity="high", resolved=True)
    fail_probes(db, "docker-host", time.time())
    await rt.tick()
    await rt.drain()
    assert [e.kind for e in rt.notifier.events] == ["reopened"] and inv.calls == [inc.id]


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


async def test_followup_after_30_min_when_flaps_change(settings, db):
    clock = Clock()
    inv = FakeInvestigator(db)
    rt = make_runtime(settings, db, inv, clock=clock)
    db.set_setting("thresholds", {"disk_warn": 30.0})
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), clock())  # 40% full > 30
    await rt.tick()
    await rt.drain()
    assert len(inv.calls) == 1
    inc = db.open_incidents()[0]
    clock.t += 1900
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), clock())
    await rt.tick()
    await rt.drain()
    assert len(inv.calls) == 1  # nothing changed: no follow-up
    inc = db.get_incident(inc.id)
    inc.flap_count = 2
    db.save_incident(inc)
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), clock())
    await rt.tick()
    await rt.drain()
    assert len(inv.calls) == 2 and inv.followups == [False, True]  # changed after 30 min: one follow-up
    inc = db.get_incident(inc.id)
    inc.flap_count = 3
    db.save_incident(inc)
    clock.t += 60
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), clock())
    await rt.tick()
    await rt.drain()
    assert len(inv.calls) == 2  # at most one per 30 min


async def test_targets_include_services_and_gateway(settings, db):
    rt = make_runtime(settings, db)
    db.set_setting("important_services", [{"name": "gitea", "kind": "tcp", "address": "192.0.2.31", "port": 3000}])
    rt.gateway = "10.0.0.1"
    names = {t.name: t for t in rt.targets()}
    assert names["gitea"] == Target("gitea", "tcp", "192.0.2.31", 3000)
    assert names["gateway"].address == "10.0.0.1"


async def test_fritz_tick_stores_poll(settings, db):
    class Poller:
        def poll(self):
            return {"ok": True, "error": None, "link_up": True}

        def event_log(self, since):
            return ["14.11.26 10:00:00 DSL online"]

    rt = make_runtime(settings, db)
    rt.fritz = Poller()
    await rt.fritz_tick()
    assert db.latest_fritz()["link_up"] is True
    seed_incident(db, rule="internet_down", key="internet", severity="high")
    await rt.fritz_tick()
    assert db.latest_fritz()["event_log"] == ["14.11.26 10:00:00 DSL online"]


async def test_fritz_tick_times_out(settings, db, monkeypatch):
    import lanot.main as main

    monkeypatch.setattr(main, "FRITZ_TIMEOUT_S", 0.05)

    class Slow:
        def poll(self):
            time.sleep(0.3)
            return {"ok": True}

    rt = make_runtime(settings, db)
    rt.fritz = Slow()
    await rt.fritz_tick()
    assert db.latest_fritz()["ok"] is False


async def test_every_survives_exceptions():
    calls = []

    async def job():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")

    task = asyncio.create_task(every("test", 0.01, job))
    await asyncio.sleep(0.1)
    task.cancel()
    assert len(calls) >= 2


def test_module_app_importable():
    import lanot.main as main

    assert isinstance(main.app, FastAPI)


# -- layout ----------------------------------------------------------------------
def test_hamburger_menu_present(client):
    html = client.get("/").text
    assert '<details class="menu" id="menu">' in html
    assert 'aria-controls="menu-panel" aria-expanded="false"' in html and ">Menu<" in html
    assert html.count('href="/settings"') == 2  # inline nav + menu panel


def test_overview_is_minimal(client, db):
    db.set_setting("important_services", [{"name": "gitea", "kind": "tcp", "address": "192.0.2.31", "port": 3000}])
    html = client.get("/").text
    assert ">Services<" not in html
    assert all(t["id"] != "services" for t in client.get("/api/v1/ui/overview").json()["tiles"])
    assert "No open incidents." in html


def test_service_incident_counts_toward_its_host(client, db):
    db.set_setting("important_services", [{"name": "gitea", "kind": "tcp", "address": "192.0.2.31", "port": 3000}])
    seed_incident(db, rule="service_down", key="gitea", title="Service gitea unreachable")
    tile = next(t for t in client.get("/api/v1/ui/overview").json()["tiles"] if t["id"] == "docker-host")
    assert tile["status"] == "warn" and "gitea" in tile["text"]


def test_overview_lists_open_and_three_recent_resolved(client, db):
    now = time.time()
    seed_incident(db, title="Open")
    for n in range(5):
        seed_incident(db, title=f"Resolved {n}", key=f"k{n}", resolved=True, opened_at=now - 3600 - n)
    seed_incident(db, title="Old", key="old", resolved=True, opened_at=now - 10 * 86400)
    inc = db.list_incidents(limit=1)[0]
    body = client.get("/api/v1/ui/overview").json()["incidents"]
    assert [i["open"] for i in body] == [True, False, False, False]
    assert "Old" not in [i["title"] for i in body]
    assert "Recently resolved" in client.get("/").text


def test_incident_without_diagnosis_shows_one_line(client, db):
    inc = seed_incident(db, resolved=True)
    html = client.get(f"/incident/{inc.id}").text
    assert html.count("no AI diagnosis") == 1
    assert "What happened" not in html and "Probable cause" not in html


def test_incident_header_is_compact(client, db):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    # fixed within today (config time zone) so the test does not depend on the time of day
    today_start = datetime.now(ZoneInfo(CFG.timezone)).replace(hour=0, minute=0, second=1, microsecond=0)
    inc = seed_incident(db, diagnosis=DIAG, resolved=True, flap_count=1, opened_at=today_start.timestamp())
    html = client.get(f"/incident/{inc.id}").text
    assert "Started today" in html and "resolved" in html and "happened 2 times" in html
    assert ">Kind<" not in html and ">Severity<" not in html


def test_number_formatting(client, db):
    from lanot.web.routes import fmt_bytes, fmt_num, fmt_time, temp_labels
    from zoneinfo import ZoneInfo

    assert fmt_num(3.04, 1) == "3.0" and fmt_num(12.6) == "13"
    assert fmt_bytes(14.9e12) == "14.9\u00a0TB"
    tz = ZoneInfo(CFG.timezone)
    now = time.time()
    assert fmt_time(now, tz, now).startswith("today ")
    assert fmt_time(now - 86400, tz, now).startswith("yesterday ")
    assert fmt_time(1_700_000_000, ZoneInfo("UTC"), 1_800_000_000) == "Nov 14, 2023 22:13"
    labels = temp_labels(["coretemp/Package id 0", "coretemp/Core 1", "drivetemp.hwmon3/temp1", "nvme/Composite"])
    assert labels["coretemp/Package id 0"] == ("CPU", "cpu")
    assert labels["coretemp/Core 1"] == ("CPU core 1", "cpu")
    assert labels["drivetemp.hwmon3/temp1"] == ("Disk 1", "disk")
    assert labels["nvme/Composite"] == ("NVMe", "disk")
    db.insert_probe("docker-host", now, True, 2.54)
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), now)
    html = client.get("/device/docker-host").text
    assert "reachable, 2.5 ms" in html
    assert "CPU temperature" in html


# -- follow-ups, mutes, limits -----------------------------------------------------------------
async def test_followup_ignores_other_targets_flapping(settings, db):
    clock = Clock()
    inv = FakeInvestigator(db)
    rt = make_runtime(settings, db, inv, clock=clock)
    fail_probes(db, "printer", clock())
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), clock())  # docker-host's agent is alive
    await rt.tick()
    await rt.drain()
    printer = db.open_incidents()[0]
    assert inv.calls == [printer.id]
    for _ in range(3):  # another device flaps over the next 1.5 h
        clock.t += 1900
        fail_probes(db, "printer", clock())
        fail_probes(db, "docker-host", clock())
        db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), clock())
        await rt.tick()
        await rt.drain()
        for i in range(3):
            db.insert_probe("docker-host", clock() + 1 + i, True, 1.0)
        clock.t += 5
        await rt.tick()
        await rt.drain()
    assert inv.calls.count(printer.id) == 1  # no follow-up for printer: its own target never changed
    assert True not in [f for c, f in zip(inv.calls, inv.followups) if c == printer.id]


def test_affected_targets_are_the_incidents_own(settings, db):
    R = make_runtime(settings, db)
    failing = frozenset({"docker-host", "cloudflare", "google", "router"})
    mk = lambda rule, key: Incident(rule, key, "high", "t", None, 0, 0)
    assert R._affected(mk("device_down", "printer"), failing) == frozenset()
    assert R._affected(mk("device_down", "docker-host"), failing) == {"docker-host"}
    assert R._affected(mk("internet_down", "internet"), failing) == {"cloudflare", "google", "router"}
    assert R._affected(mk("disk_full", "docker-host:/"), failing) == frozenset()


def test_incident_page_labels_followup(client, db):
    inc = seed_incident(db, diagnosis={**DIAG, "followup": True})
    assert ">Follow-up<" in client.get(f"/incident/{inc.id}").text
    inc2 = seed_incident(db, diagnosis=DIAG, key="other")
    assert ">Follow-up<" not in client.get(f"/incident/{inc2.id}").text


def test_mute_key_with_space(client, db):
    inc = seed_incident(db, rule="temp_high", key="nas:coretemp/Package id 0", title="NAS: hot")
    r = client.post("/settings/mute", data={"rule": inc.rule, "key": inc.key, "duration": "1h",
                                                  "back": f"/incident/{inc.id}"}, follow_redirects=False)
    assert "error=" not in r.headers["location"]
    assert ("temp_high", "nas:coretemp/Package id 0") in db.mutes_active(time.time())


def test_mute_requires_known_pair(client, db):
    r = client.post("/settings/mute", data={"rule": "device_down", "key": "made-up", "duration": "1h"},
                    follow_redirects=False)
    assert "error=mute" in r.headers["location"] and db.mutes_active(time.time()) == set()
    r = client.post("/settings/mute", data={"rule": "device_down", "key": "a\x00b", "duration": "1h"},
                    follow_redirects=False)
    assert "error=mute" in r.headers["location"]


def test_important_services_capped_at_30(client, db):
    db.set_setting("important_services", [{"name": f"s{i}", "kind": "tcp", "address": "192.0.2.31", "port": 1000 + i}
                                          for i in range(30)])
    r = client.post("/settings/services", data={"name": "new", "kind": "tcp", "address": "192.0.2.31",
                                                    "port": "9999"}, follow_redirects=False)
    assert "error=service_full" in r.headers["location"]
    assert len(db.get_setting("important_services")) == 30
    assert "which is the maximum" in client.get("/settings?error=service_full").text


async def test_fritz_flag_reset_when_call_never_starts(settings, db, monkeypatch):
    import lanot.main as main

    async def never_runs(fn, *args):
        await asyncio.sleep(10)

    monkeypatch.setattr(main, "FRITZ_TIMEOUT_S", 0.05)
    monkeypatch.setattr(main.asyncio, "to_thread", never_runs)
    rt = make_runtime(settings, db)
    assert await rt._fritz_call(lambda: {"ok": True}) is None
    assert rt._fritz_running is False  # the next poll can start


def test_device_errors_limited_to_7_days(client, db):
    now = time.time()
    db.insert_logs(LogBatch(host="docker-host", lines=[LogLine(ts=now - 8 * 86400, source="s", severity=3,
                                                        message="ancient error")]), now - 8 * 86400)
    assert "ancient error" not in client.get("/device/docker-host").text


def test_never_seen_agent_host_tile_is_unknown(client, db):
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), time.time())
    tiles = {t["id"]: t for t in client.get("/api/v1/ui/overview").json()["tiles"]}
    assert tiles["nas"]["status"] == "unknown" and tiles["nas"]["word"] == "unknown"
    assert tiles["nas"]["text"] == "No data from the agent yet"
    assert tiles["docker-host"]["status"] == "ok"
    assert tiles["printer"]["text"] != "No data from the agent yet"


async def test_tick_pushes_battery_steps_during_power_outage(settings, db):
    from lanot.notify import Notifier
    from lanot_common.protocol import MetricsReport as MR
    posts = []

    async def post(payload):
        posts.append(payload)

    clock = Clock()
    one = settings.model_copy(update={"agent_tokens": {"monitor": "t"}}).with_config(
        only_agent(settings.config, "monitor"))
    rt = Runtime(one, db, notifier=Notifier(post, clock, db=db, name_of=CFG.name_of), investigator=FakeInvestigator(db),
                 clock=clock, started_at=clock() - 3600)

    def battery(pct):
        m = sample_metrics("monitor", clock())
        m["power"] = {"ac_online": False, "battery_pct": pct}
        db.insert_metrics(MR(**m), clock())

    rt.manager._first = False  # not the very first start (no start-up summary push)
    battery(93.0)
    await rt.tick()
    await rt.drain()
    assert posts[0]["title"] == "Monitor: mains power lost (battery 93%)"
    clock.t += 60
    battery(19.0)
    await rt.tick()
    await rt.drain()
    assert [p["title"] for p in posts if "battery down to" in p["title"]] == ["Monitor: battery down to 20%"]
    clock.t += 60
    battery(18.0)
    await rt.tick()
    await rt.drain()
    assert len([p for p in posts if "battery down to" in p["title"]]) == 1


async def test_runtime_alarm_path_alive_tracks_tick(settings, db):
    clock = Clock()
    rt = make_runtime(settings, db, clock=clock)
    assert rt.alarm_path_alive()[0] is False  # started an hour ago, never ticked
    db.insert_probe("docker-host", clock(), True, 1.0)
    await rt.tick()
    await rt.drain()
    assert rt.alarm_path_alive() == (True, "")
    clock.t += 61
    ok, why = rt.alarm_path_alive()
    assert not ok and "rules tick" in why


# -- muted incidents and the Host allowlist -----------------------------------------
def test_muted_open_incident_does_not_colour_overview(client, db):
    inc = seed_incident(db, severity="high")
    db.set_mute(inc.rule, inc.key, time.time() + 3600)
    body = client.get("/api/v1/ui/overview").json()
    assert body["status"] == "ok" and body["headline"] == "All good."
    nas = next(t for t in body["tiles"] if t["id"] == "nas")
    assert "93%" not in nas["text"] and nas["status"] != "bad"
    item = next(i for i in body["incidents"] if i["id"] == inc.id)
    assert item["status"] == "muted" and item["word"] == "muted" and item["muted"] is True
    html = client.get("/").text
    assert 'class="mute-tag' in html and ">muted<" in html


def test_muted_incident_marked_on_list_and_device_page(client, db):
    inc = seed_incident(db, severity="high")
    db.set_mute(inc.rule, inc.key, time.time() + 3600)
    assert ">muted<" in client.get("/incidents").text
    assert ">muted<" in client.get("/device/nas").text


def test_daily_summary_skips_muted_open(db):
    from lanot.notify import daily_summary
    inc = seed_incident(db, severity="high")
    db.set_mute(inc.rule, inc.key, time.time() + 3600)
    s = daily_summary(db, time.time() - 86400, time.time())
    assert "No open problems" in s["message"] and "1 muted" in s["message"]


def test_post_with_foreign_host_refused(client, db):
    data = {"rule": "device_down", "key": "printer", "duration": "1h"}
    r = client.post("/settings/mute", data=data, headers={"host": "evil.example:8080"},
                    follow_redirects=False)
    assert r.status_code == 403 and db.mutes_active(time.time()) == set()
    r = client.post("/settings/mute", data=data, headers={"host": "192.0.2.24:8080"},
                    follow_redirects=False)
    assert r.status_code == 303


def test_allowed_hosts_default_and_configurable():
    s = make_settings()
    assert s.form_hosts() == ["192.0.2.24:8080", "localhost:8080", "127.0.0.1:8080"]
    assert make_settings(allowed_hosts="a:1, b:2").form_hosts() == ["a:1", "b:2"]


@pytest.mark.parametrize("path", ["/", "/incidents", "/internet", "/devices", "/logs", "/settings"])
def test_pages_with_empty_config(tmp_path, path):
    from lanot.config import LanotConfig, Router
    cfg = LanotConfig(router=Router(type="generic", display_name="Router", tr064=False))
    s = make_settings(cfg, db_path=str(tmp_path / "empty.db"), allowed_hosts="testserver")
    c = TestClient(create_app(s, start_background=False))
    r = c.get(path)
    assert r.status_code == 200
    if path == "/":
        assert '<span class="st-name">Router</span>' in r.text
