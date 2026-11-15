import json

import httpx
import pytest
from lanot_agent.buffer import DiskBuffer
from lanot_agent.sender import Sender
from lanot_common.protocol import LogBatch, LogLine, MetricsReport


def metrics(host="h", ts=1.0) -> MetricsReport:
    return MetricsReport(
        host=host, ts=ts, cpu_pct=1, load1=0.1, mem_used=1, mem_total=2,
        net_rx_bps=0, net_tx_bps=0, temps={}, filesystems=[], uptime_s=5,
    )


def make(tmp_path, handler):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    buf = DiskBuffer(tmp_path)
    return Sender("http://lanot:8080/", "tok", buf, client), buf


def test_send_posts_with_bearer(tmp_path):
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"ok": True})

    s, buf = make(tmp_path, handler)
    s.send("metrics", metrics())
    assert str(seen[0].url) == "http://lanot:8080/api/v1/metrics"
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert json.loads(seen[0].content)["host"] == "h"
    assert buf.peek() is None


def test_sender_buffers_when_down(tmp_path):
    def handler(req):
        raise httpx.ConnectError("down")

    s, buf = make(tmp_path, handler)
    s.send("metrics", metrics())
    assert buf.peek() is not None


def test_sender_buffers_on_5xx(tmp_path):
    s, buf = make(tmp_path, lambda req: httpx.Response(503))
    s.send("metrics", metrics())
    assert buf.peek() is not None


@pytest.mark.parametrize("code", [400, 413, 422])
def test_sender_drops_rejected_payload(tmp_path, code):
    s, buf = make(tmp_path, lambda req: httpx.Response(code))
    s.send("metrics", metrics())
    assert buf.peek() is None  # retrying can never succeed


@pytest.mark.parametrize("code", [401, 403, 404, 408, 429, 500, 503])
def test_sender_keeps_payload_for_retryable_status(tmp_path, code):
    s, buf = make(tmp_path, lambda req: httpx.Response(code))
    s.send("metrics", metrics())
    assert buf.peek() is not None


def test_drain_keeps_item_on_401_then_delivers_after_fix(tmp_path):
    status = {"v": 401}
    s, buf = make(tmp_path, lambda req: httpx.Response(status["v"]))
    s.send("metrics", metrics())
    assert s.drain() == 0 and buf.peek() is not None
    status["v"] = 200
    assert s.drain() == 1 and buf.peek() is None


def test_live_send_queues_behind_backlog(tmp_path):
    arrived = []

    def handler(req):
        arrived.append(json.loads(req.content)["ts"])
        return httpx.Response(200)

    s, buf = make(tmp_path, handler)
    buf.push("metrics", metrics(ts=1.0).model_dump_json().encode())
    buf.push("metrics", metrics(ts=2.0).model_dump_json().encode())
    s.send("metrics", metrics(ts=3.0))
    assert arrived == []  # live data must not overtake the backlog
    assert s.drain() == 3
    assert arrived == [1.0, 2.0, 3.0]


def test_drain_in_order(tmp_path):
    up = {"v": False}
    arrived = []

    def handler(req):
        if not up["v"]:
            raise httpx.ConnectError("down")
        arrived.append((req.url.path, json.loads(req.content)))
        return httpx.Response(200, json={"ok": True})

    s, buf = make(tmp_path, handler)
    s.send("metrics", metrics(ts=1.0))
    s.send("logs", LogBatch(host="h", lines=[LogLine(ts=2.0, source="x", severity=6, message="m")]))
    s.send("metrics", metrics(ts=3.0))
    up["v"] = True
    assert s.drain() == 3
    assert [p for p, _ in arrived] == ["/api/v1/metrics", "/api/v1/logs", "/api/v1/metrics"]
    assert arrived[0][1]["ts"] == 1.0 and arrived[2][1]["ts"] == 3.0
    assert buf.peek() is None


def test_drain_stops_on_first_failure(tmp_path):
    calls = []

    def handler(req):
        calls.append(1)
        raise httpx.ConnectError("down")

    s, buf = make(tmp_path, handler)
    for i in range(3):
        buf.push("metrics", metrics(ts=float(i)).model_dump_json().encode())
    assert s.drain() == 0
    assert len(calls) == 1
    assert buf.peek() is not None


def test_drain_respects_max_items(tmp_path):
    s, buf = make(tmp_path, lambda req: httpx.Response(200))
    for i in range(5):
        buf.push("metrics", metrics(ts=float(i)).model_dump_json().encode())
    assert s.drain(max_items=2) == 2
