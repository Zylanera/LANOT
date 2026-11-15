"""Reachability probes (icmp / dns / tcp / http) and the loop that stores them."""

import asyncio
import logging
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import dns.asyncresolver
import httpx
from icmplib import SocketPermissionError, async_ping

log = logging.getLogger(__name__)

DNS_QUERY_NAME = "example.com"
_HOP_RE = re.compile(r"^\s*2\s+(\d{1,3}(?:\.\d{1,3}){3})\b")


@dataclass
class Target:
    name: str
    kind: Literal["icmp", "dns", "tcp", "http"]
    address: str
    port: int | None = None
    important: bool = True
    query: str | None = None  # dns only: the name to resolve


def default_targets(cfg, extra: list[Target] | None = None, gateway: str | None = None) -> list[Target]:
    """The router, the discovered provider gateway (omitted if None), the
    internet ping targets, the DNS checks and every configured host, then the
    service targets supplied by the caller (dashboard settings)."""
    targets = [Target("router", "icmp", cfg.router.host)]
    if gateway:
        targets.append(Target("gateway", "icmp", gateway))
    targets += [Target(t.name, "icmp", t.address) for t in cfg.internet.ping_targets]
    if cfg.internet.check_router_dns:
        targets.append(Target("dns-router", "dns", cfg.router.host, query=cfg.internet.dns_query))
    targets.append(Target("dns-external", "dns", cfg.internet.dns_server, query=cfg.internet.dns_query))
    targets += [Target(h.id, "icmp", h.address) for h in cfg.hosts]
    return targets + list(extra or [])


def _traceroute(target: str = "1.1.1.1") -> str:
    return subprocess.run(
        ["traceroute", "-n", "-m", "2", target], capture_output=True, text=True, timeout=30
    ).stdout


def discover_gateway(run: Callable[[], str] | None = None, target: str = "1.1.1.1") -> str | None:
    """Hop 2 of a traceroute to an internet address (the ISP side of the
    router), or None. Assumes the router is hop 1, which holds for a single
    router between LAN and provider."""
    try:
        out = run() if run is not None else _traceroute(target)
    except Exception:
        return None
    for line in out.splitlines():
        m = _HOP_RE.match(line)
        if m:
            return m.group(1)
    return None


async def _icmp(t: Target, timeout: float) -> tuple[bool, float | None]:
    try:
        r = await async_ping(t.address, count=1, timeout=timeout, privileged=False)
    except SocketPermissionError:
        r = await async_ping(t.address, count=1, timeout=timeout, privileged=True)
    return (True, r.avg_rtt) if r.is_alive else (False, None)


async def _dns(t: Target, timeout: float) -> tuple[bool, float | None]:
    res = dns.asyncresolver.Resolver(configure=False)
    res.nameservers = [t.address]
    res.port = t.port or 53
    res.lifetime = timeout
    start = time.perf_counter()
    await res.resolve(t.query or DNS_QUERY_NAME, "A")
    return True, (time.perf_counter() - start) * 1000


async def _tcp(t: Target, timeout: float) -> tuple[bool, float | None]:
    start = time.perf_counter()
    _, writer = await asyncio.wait_for(asyncio.open_connection(t.address, t.port), timeout)
    rtt = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True, rtt


async def _http(t: Target, timeout: float) -> tuple[bool, float | None]:
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.get(f"http://{t.address}:{t.port or 80}/")
    # any answer below 500 means the service is up
    if r.status_code >= 500:
        return False, None
    return True, (time.perf_counter() - start) * 1000


_PROBES = {"icmp": _icmp, "dns": _dns, "tcp": _tcp, "http": _http}


async def probe(t: Target, timeout: float = 2.0) -> tuple[bool, float | None]:
    """Never raises: any failure is (False, None)."""
    try:
        return await asyncio.wait_for(_PROBES[t.kind](t, timeout), timeout + 1)
    except Exception:
        return False, None


async def run_pinger(db, targets_provider: Callable[[], list[Target]], interval: float = 10) -> None:
    while True:
        started = time.monotonic()
        try:
            targets = list(targets_provider())
            results = await asyncio.gather(*(probe(t) for t in targets), return_exceptions=True)
            ts = time.time()
            for t, res in zip(targets, results):
                ok, rtt = (False, None) if isinstance(res, BaseException) else res
                try:
                    await asyncio.to_thread(db.insert_probe, t.name, ts, ok, rtt)
                except Exception:
                    log.exception("could not store probe for %s", t.name)
        except Exception:
            log.exception("pinger round failed")
        await asyncio.sleep(max(0.0, interval - (time.monotonic() - started)))
