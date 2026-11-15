import time

from conftest import TOK, auth, sample_metrics, sample_state
from lanot_common.protocol import MetricsReport


def test_health_needs_no_auth(client):
    assert client.get("/api/v1/health").json() == {"ok": True}


def test_bad_token_401(client):
    r = client.post("/api/v1/metrics", json=sample_metrics("docker-host"), headers=auth("wrong"))
    assert r.status_code == 401


def test_missing_token_401(client):
    assert client.post("/api/v1/metrics", json=sample_metrics("docker-host")).status_code == 401


def test_unknown_host_401(client):
    r = client.post("/api/v1/metrics", json=sample_metrics("nope"), headers=auth("tok-docker-host"))
    assert r.status_code == 401


def test_token_for_other_host_401(client):
    r = client.post("/api/v1/metrics", json=sample_metrics("nas"), headers=auth(TOK["docker-host"]))
    assert r.status_code == 401


def test_metrics_stored_with_receive_time(client, db):
    m = sample_metrics("docker-host", ts=time.time() - 600)  # agent clock 10 min behind
    assert client.post("/api/v1/metrics", json=m, headers=auth(TOK["docker-host"])).status_code == 200
    assert abs(db.last_received("docker-host") - time.time()) < 2
    assert isinstance(db.latest_metrics("docker-host"), MetricsReport)


def test_state_stored(client, db):
    r = client.post("/api/v1/state", json=sample_state("monitor"), headers=auth(TOK["monitor"]))
    assert r.status_code == 200
    assert db.latest_state("monitor").pools[0].name == "tank"


def test_invalid_body_422(client):
    r = client.post("/api/v1/metrics", json={"host": "docker-host"}, headers=auth(TOK["docker-host"]))
    assert r.status_code == 422


def test_logs_stored(client, db):
    batch = {"host": "docker-host", "lines": [{"ts": 1, "source": "docker", "severity": 4, "message": "hello"}]}
    r = client.post("/api/v1/logs", json=batch, headers=auth(TOK["docker-host"]))
    assert r.status_code == 200 and r.json()["stored"] == 1
    assert db.search_logs("hello")[0]["host"] == "docker-host"


def test_log_flood_ingest(client):
    batch = {"host": "docker-host", "lines": [{"ts": 1, "source": "docker", "severity": 6, "message": "x"} for _ in range(10000)]}
    t = time.time()
    r = client.post("/api/v1/logs", json=batch, headers=auth(TOK["docker-host"]))
    assert r.status_code == 200 and time.time() - t < 3
