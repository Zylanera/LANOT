import pytest

from lanot.db import Incident
from lanot.incidents import IncidentManager
from lanot.rules import Finding

F_INET = Finding("internet_down", "internet", "high", "Internet down", "d")
F_DISK = Finding("disk_full", "nas:/", "medium", "NAS: disk / 91% full", "d")


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def mgr(db, clock):
    return IncidentManager(db, clock)


def test_new_finding_opens_with_id(mgr, db):
    ev = mgr.apply([F_INET])
    assert [e.kind for e in ev] == ["opened"] and ev[0].incident.id is not None
    got = db.get_incident(ev[0].incident.id)
    assert got.title == "Internet down" and got.resolved_at is None and got.opened_at == 1000.0


def test_existing_open_no_event_but_last_seen_updated(mgr, db, clock):
    mgr.apply([F_INET])
    clock.advance(30)
    assert mgr.apply([F_INET]) == []
    assert db.open_incidents()[0].last_seen_at == 1030.0


def test_severity_change_emits_updated(mgr, clock):
    mgr.apply([F_DISK])
    clock.advance(10)
    ev = mgr.apply([Finding("disk_full", "nas:/", "high", "t2", "d")])
    assert [e.kind for e in ev] == ["updated"] and ev[0].incident.severity == "high"


def test_gone_finding_resolves(mgr, clock):
    mgr.apply([F_INET])
    clock.advance(60)
    ev = mgr.apply([])
    assert [e.kind for e in ev] == ["resolved"] and ev[0].incident.resolved_at == 1060.0
    assert mgr.apply([]) == []


def test_flap_reopens_same_incident(mgr, clock):
    first = mgr.apply([F_INET])[0].incident
    clock.advance(60)
    mgr.apply([])
    clock.advance(120)
    ev = mgr.apply([F_INET])
    assert ev[0].kind == "reopened" and ev[0].incident.flap_count == 1
    assert ev[0].incident.id == first.id and ev[0].incident.resolved_at is None
    assert ev[0].incident.opened_at == 1000.0


def test_after_15_min_new_incident(mgr, clock, db):
    first = mgr.apply([F_INET])[0].incident
    clock.advance(10)
    mgr.apply([])
    clock.advance(901)
    ev = mgr.apply([F_INET])
    assert ev[0].kind == "opened" and ev[0].incident.id != first.id


def test_exactly_900_s_still_reopens(mgr, clock):
    mgr.apply([F_INET])
    mgr.apply([])
    clock.advance(900)
    assert mgr.apply([F_INET])[0].kind == "reopened"


def test_initial_flag_only_first_apply_on_empty_db(mgr, clock):
    ev = mgr.apply([F_INET])
    assert ev[0].initial is True
    clock.advance(10)
    assert mgr.apply([F_INET, F_DISK])[0].initial is False


def test_restart_no_duplicate(db, clock):
    IncidentManager(db, clock).apply([F_INET])
    clock.advance(600)
    m2 = IncidentManager(db, clock)
    assert m2.apply([F_INET]) == []
    assert len(db.open_incidents()) == 1 and len(db.list_incidents()) == 1
    ev = m2.apply([F_INET, F_DISK])
    assert ev[0].kind == "opened" and ev[0].initial is False  # DB was not empty at start


def test_restart_resolves_stale_open_incident(db, clock):
    IncidentManager(db, clock).apply([F_INET])
    ev = IncidentManager(db, clock).apply([])
    assert [e.kind for e in ev] == ["resolved"]


def test_db_incident_accessors_and_mutes(db):
    a = db.save_incident(Incident("r", "k", "medium", "t", None, 1.0, 1.0))
    b = db.save_incident(Incident("r", "k2", "high", "t", "d", 2.0, 2.0, resolved_at=3.0))
    assert [i.id for i in db.list_incidents()] == [b.id, a.id]
    assert [i.id for i in db.list_incidents(limit=1, offset=1)] == [a.id]
    assert db.last_resolved("r", "k2").id == b.id and db.last_resolved("r", "k") is None
    assert db.get_incident(999) is None
    db.set_mute("r", "k", 100.0)
    db.set_mute("r", "k", 200.0)  # upsert
    assert db.mutes_active(150.0) == {("r", "k")} and db.mutes_active(200.0) == set()
    db.clear_mute("r", "k")
    assert db.mutes_active(0.0) == set()


def test_fritz_accessors(db):
    assert db.latest_fritz() is None
    db.insert_fritz(1.0, {"ok": True})
    db.insert_fritz(2.0, {"ok": False, "error": "e"})
    assert db.latest_fritz() == {"ok": False, "error": "e", "ts": 2.0}
    assert [f["ts"] for f in db.recent_fritz(5)] == [1.0, 2.0]


def test_no_resolve_during_startup_grace(db, clock):
    f_silent = Finding("agent_silent", "docker-host", "medium", "t", "d")
    f_down = Finding("device_down", "nas", "high", "t", "d")
    IncidentManager(db, clock).apply([f_silent, f_down])
    clock.advance(3600)  # the server restarts
    m = IncidentManager(db, clock, started_at=clock())
    clock.advance(60)
    assert m.apply([]) == [] and len(db.open_incidents()) == 2
    clock.advance(121)  # 181 s after start
    assert sorted(e.kind for e in m.apply([])) == ["resolved", "resolved"]
    assert db.open_incidents() == []


def test_opening_allowed_during_grace(db, clock):
    m = IncidentManager(db, clock, started_at=clock())
    assert m.apply([F_INET])[0].kind == "opened"


def test_muted_incident_neither_resolved_nor_duplicated(mgr, db, clock):
    mgr.apply([F_INET])
    clock.advance(60)
    assert mgr.apply([], muted={("internet_down", "internet")}) == []
    assert len(db.open_incidents()) == 1
    clock.advance(60)
    assert [e.kind for e in mgr.apply([])] == ["resolved"]


def test_deescalation_is_quiet(mgr, db, clock):
    mgr.apply([Finding("disk_full", "nas:/", "high", "t", "d")])
    clock.advance(10)
    assert mgr.apply([F_DISK]) == []  # high -> medium: no push-worthy event
    assert db.open_incidents()[0].severity == "medium"
    clock.advance(10)
    ev = mgr.apply([Finding("disk_full", "nas:/", "high", "t", "d")])
    assert [e.kind for e in ev] == ["updated"]
