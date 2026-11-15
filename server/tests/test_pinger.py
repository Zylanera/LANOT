import asyncio
import socket
import threading

import dns.message
import dns.rrset
import pytest

from lanot import pinger
from conftest import CFG
from lanot.pinger import Target, default_targets, discover_gateway, probe, run_pinger


async def test_probe_unreachable():
    ok, rtt = await probe(Target(name="x", kind="tcp", address="127.0.0.1", port=1))
    assert not ok and rtt is None


async def test_probe_tcp_open():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        ok, rtt = await probe(Target(name="x", kind="tcp", address="127.0.0.1", port=srv.getsockname()[1]))
        assert ok and rtt is not None and rtt >= 0
    finally:
        srv.close()


@pytest.fixture
def fake_dns():
    """UDP DNS server answering every A query with 1.2.3.4, recording that it was asked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    seen = []
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except OSError:
                continue
            q = dns.message.from_wire(data)
            seen.append(str(q.question[0].name))
            r = dns.message.make_response(q)
            r.answer.append(dns.rrset.from_text(q.question[0].name, 60, "IN", "A", "1.2.3.4"))
            sock.sendto(r.to_wire(), addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield sock.getsockname()[1], seen
    stop.set()
    t.join()
    sock.close()


async def test_dns_probe_uses_given_server(fake_dns):
    port, seen = fake_dns
    t = Target(name="dns-x", kind="dns", address="127.0.0.1", port=port)
    ok, rtt = await probe(t)
    assert ok and rtt is not None
    assert seen == ["example.com."]
    await probe(Target(name="dns-y", kind="dns", address="127.0.0.1", port=port, query="lan.example"))
    assert seen[-1] == "lan.example."


async def test_dns_probe_fails_when_no_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    ok, rtt = await probe(Target(name="d", kind="dns", address="127.0.0.1", port=port), timeout=0.5)
    assert not ok and rtt is None


async def test_http_probe_unreachable():
    ok, rtt = await probe(Target(name="h", kind="http", address="127.0.0.1", port=1))
    assert not ok and rtt is None


async def test_icmp_probe_uses_icmplib(monkeypatch):
    class R:
        is_alive = True
        avg_rtt = 3.5

    calls = []

    async def fake_ping(addr, count, timeout, privileged):
        calls.append(privileged)
        return R()

    monkeypatch.setattr(pinger, "async_ping", fake_ping)
    assert await probe(Target(name="i", kind="icmp", address="1.1.1.1")) == (True, 3.5)
    assert calls == [False]


async def test_icmp_falls_back_to_privileged(monkeypatch):
    from icmplib import SocketPermissionError

    class R:
        is_alive = False
        avg_rtt = 0.0

    calls = []

    async def fake_ping(addr, count, timeout, privileged):
        calls.append(privileged)
        if not privileged:
            raise SocketPermissionError(False)
        return R()

    monkeypatch.setattr(pinger, "async_ping", fake_ping)
    assert await probe(Target(name="i", kind="icmp", address="1.1.1.1")) == (False, None)
    assert calls == [False, True]


async def test_probe_never_raises(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(pinger, "async_ping", boom)
    assert await probe(Target(name="i", kind="icmp", address="1.1.1.1")) == (False, None)


TRACE = """traceroute to 1.1.1.1 (1.1.1.1), 2 hops max, 60 byte packets
 1  192.168.178.1  0.5 ms  0.4 ms  0.4 ms
 2  10.20.30.1  8.1 ms  8.0 ms  7.9 ms
"""


def test_discover_gateway_hop2():
    assert discover_gateway(run=lambda: TRACE) == "10.20.30.1"


@pytest.mark.parametrize(
    "out", ["", " 1  192.168.178.1  1 ms\n 2  * * *\n", "garbage", " 1  192.168.178.1  1 ms\n"]
)
def test_discover_gateway_none(out):
    assert discover_gateway(run=lambda: out) is None


def test_discover_gateway_run_raises():
    def boom():
        raise FileNotFoundError("traceroute")

    assert discover_gateway(run=boom) is None


def test_default_targets():
    names = [t.name for t in default_targets(CFG)]
    assert names == [
        "router", "cloudflare", "google", "dns-router", "dns-external", "docker-host", "nas", "printer", "monitor",
    ]
    by = {t.name: t for t in default_targets(CFG)}
    assert by["router"].address == "192.168.178.1" and by["router"].kind == "icmp"
    assert by["dns-router"].kind == "dns" and by["dns-router"].address == "192.168.178.1"
    assert by["dns-external"].address == "1.1.1.1" and by["dns-external"].query == "example.com"
    assert by["docker-host"].address == "192.0.2.31" and by["nas"].address == "192.0.2.30"
    assert by["printer"].address == "192.0.2.32" and by["monitor"].address == "192.0.2.24"


def test_default_targets_without_router_dns():
    from lanot.config import parse_config
    cfg = parse_config({"internet": {"check_router_dns": False}})
    assert "dns-router" not in [t.name for t in default_targets(cfg)]


def test_default_targets_gateway_and_extra():
    extra = [Target(name="svc-web", kind="http", address="192.0.2.31", port=8080, important=False)]
    ts = default_targets(CFG, extra, gateway="10.20.30.1")
    assert ts[1].name == "gateway" and ts[1].address == "10.20.30.1"
    assert ts[-1] is extra[0]
    assert "gateway" not in [t.name for t in default_targets(CFG)]


async def test_run_pinger_inserts_and_survives_target_exception(db, monkeypatch):
    async def fake_probe(t, timeout=2.0):
        if t.name == "bad":
            raise RuntimeError("boom")
        return True, 1.5

    monkeypatch.setattr(pinger, "probe", fake_probe)
    targets = [Target(name="a", kind="icmp", address="x"), Target(name="bad", kind="icmp", address="y")]
    task = asyncio.create_task(run_pinger(db, lambda: targets, interval=0.05))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(db.probes("a", 0)) >= 2
    bad = db.probes("bad", 0)
    assert bad and all(ok is False and rtt is None for _, ok, rtt in bad)
