import sqlite3
import threading

import pytest
from conftest import sample_metrics, sample_state
from lanot_common.protocol import LogBatch, LogLine, MetricsReport, StateReport


def line(ts, msg="m", sev=6, src="docker"):
    return LogLine(ts=ts, source=src, severity=sev, message=msg)


def test_wal_enabled(db, tmp_path):
    assert sqlite3.connect(str(tmp_path / "t.db")).execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_metrics_roundtrip_and_receive_time(db):
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host", ts=100)), received=5000)
    assert db.last_received("docker-host") == 5000
    assert db.last_received("other") is None
    m = db.latest_metrics("docker-host")
    assert m.ts == 100 and m.filesystems[0].mount == "/" and m.power.ac_online
    assert db.latest_metrics("other") is None


def test_latest_is_most_recent_received(db):
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host", ts=100)), received=10)
    db.insert_metrics(MetricsReport(**{**sample_metrics("docker-host", ts=50), "cpu_pct": 99.0}), received=20)
    assert db.latest_metrics("docker-host").cpu_pct == 99.0


def test_state_roundtrip(db):
    db.insert_state(StateReport(**sample_state("docker-host")), received=7)
    assert db.latest_state("docker-host").containers[0].name == "web"
    assert db.last_received("docker-host") == 7
    assert db.latest_state("x") is None


def test_metrics_series(db):
    for i in range(3):
        d = {**sample_metrics("docker-host", ts=100 + i), "cpu_pct": float(i), "temps": {"cpu": 50.0 + i}}
        db.insert_metrics(MetricsReport(**d), received=1000 + i)
    assert db.metrics_series("docker-host", "cpu_pct", since=1001) == [(1001, 1.0), (1002, 2.0)]
    assert db.metrics_series("docker-host", "temps.cpu", since=0)[0] == (1000, 50.0)
    with pytest.raises(ValueError):
        db.metrics_series("docker-host", "cpu_pct; drop table logs", since=0)


def test_log_search_fts(db):
    db.insert_logs(LogBatch(host="nas", lines=[LogLine(ts=1, source="kernel", severity=3, message="ata3: I/O error")]), 1)
    assert db.search_logs("I/O")[0]["host"] == "nas"
    assert db.search_logs("nomatch") == []


def test_log_search_filters(db):
    db.insert_logs(LogBatch(host="a", lines=[line(10, "disk fail", 3), line(20, "disk ok", 6)]), 1)
    db.insert_logs(LogBatch(host="b", lines=[line(30, "disk fail", 3)]), 1)
    assert len(db.search_logs("disk")) == 3
    assert len(db.search_logs("disk", host="a")) == 2
    assert len(db.search_logs("disk", max_severity=3)) == 2
    assert [r["ts"] for r in db.search_logs("disk", since=15, until=25)] == [20]
    assert len(db.search_logs(None, host="b")) == 1
    assert len(db.search_logs(None, limit=2)) == 2
    assert db.search_logs(None)[0]["ts"] == 30  # newest first
    assert db.search_logs('"') == []  # hostile FTS syntax is neutralised


def test_insert_logs_returns_count(db):
    assert db.insert_logs(LogBatch(host="a", lines=[line(1), line(2)]), 1) == 2
    assert db.insert_logs(LogBatch(host="a", lines=[]), 1) == 0


def test_probes(db):
    db.insert_probe("1.1.1.1", 10, True, 12.5)
    db.insert_probe("1.1.1.1", 20, False, None)
    db.insert_probe("other", 20, True, 1.0)
    assert db.probes("1.1.1.1", since=15) == [(20, False, None)]
    assert db.probes("1.1.1.1", since=0) == [(10, True, 12.5), (20, False, None)]


def test_fritz_insert(db):
    db.insert_fritz(10, {"uptime": 5})


def test_purge(db):
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), received=10)
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), received=100)
    db.insert_state(StateReport(**sample_state("docker-host")), received=10)
    db.insert_logs(LogBatch(host="a", lines=[line(1, "old")]), 10)
    db.insert_logs(LogBatch(host="a", lines=[line(1, "new")]), 100)
    db.insert_probe("t", 10, True, 1.0)
    db.insert_probe("t", 100, True, 1.0)
    db.insert_fritz(10, {})
    db.insert_fritz(100, {})
    assert db.purge_older_than(50) == 5
    assert db.last_received("docker-host") == 100
    assert db.latest_state("docker-host") is None
    assert [r["message"] for r in db.search_logs(None)] == ["new"]  # FTS index stays in sync
    assert db.search_logs("old") == []
    assert db.probes("t", 0) == [(100, True, 1.0)]


def test_enforce_size_drops_oldest_logs_first(db):
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), received=1)
    for i in range(10):
        db.insert_logs(LogBatch(host="a", lines=[line(i, f"batch{i} " + "x" * 2000) for _ in range(100)]), i)
    full = db.size_bytes()
    target = full // 2
    deleted = db.enforce_size(target)
    assert deleted > 0
    assert db.size_bytes() <= target
    remaining = db.search_logs(None, limit=2000)
    assert remaining, "should not wipe all logs"
    assert min(r["ts"] for r in remaining) > 0  # oldest gone
    assert max(r["ts"] for r in remaining) == 9  # newest kept
    assert db.latest_metrics("docker-host") is not None  # metrics untouched while logs remain
    assert db.enforce_size(10**12) == 0


def test_enforce_size_falls_back_to_other_tables(db):
    for i in range(300):
        db.insert_metrics(MetricsReport(**sample_metrics("docker-host")), received=i)
    assert db.enforce_size(1) > 0


def test_threads_have_own_connections(db):
    errors = []

    def work(n):
        try:
            for i in range(50):
                db.insert_logs(LogBatch(host=f"h{n}", lines=[line(i)]), i)
                db.search_logs(None)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    assert len(db.search_logs(None, limit=1000)) == 200


def test_incident_settings_mute_tables_exist(db):
    con = sqlite3.connect(db.path)
    cols = {r[1] for r in con.execute("PRAGMA table_info(incidents)")}
    assert cols == {"id", "rule", "key", "severity", "title", "detail", "opened_at", "last_seen_at",
                    "resolved_at", "flap_count", "last_push_at", "diagnosis_json"}
    assert {r[1] for r in con.execute("PRAGMA table_info(settings)")} == {"key", "value_json"}
    assert {r[1] for r in con.execute("PRAGMA table_info(mutes)")} == {"rule", "key", "until"}


def test_last_received_ignores_logs(db):
    db.insert_logs(LogBatch(host="a", lines=[line(1)]), 500)
    assert db.last_received("a") is None
    db.insert_metrics(MetricsReport(**sample_metrics("a")), received=100)
    assert db.last_received("a") == 100  # newer logs do not count


def test_enforce_size_orders_by_received_not_agent_ts(db):
    pad = "x" * 2000
    # "fast" host clock is far in the future; its logs were received first
    db.insert_logs(LogBatch(host="fast", lines=[line(10**12, "fast " + pad) for _ in range(300)]), 1)
    db.insert_logs(LogBatch(host="ok", lines=[line(5, "ok " + pad) for _ in range(300)]), 2)
    db.enforce_size(db.size_bytes() * 6 // 10)
    hosts = {r["host"] for r in db.search_logs(None, limit=1000)}
    assert hosts == {"ok"}

