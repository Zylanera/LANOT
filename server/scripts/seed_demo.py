"""Fill a throw-away database with fake data and (optionally) serve the dashboard.

    python server/scripts/seed_demo.py --db /tmp/lanot-demo.db --serve --port 8090

Uses lanot.example.toml for the network layout. Scenarios: "ok" (nothing
open), "problem" (a full disk on the NAS and a sick container on the Docker
host; default) and "internet" (additionally an ongoing outage at the
provider). With --serve a fake agent keeps probes and metrics fresh every
10 s; no real pinger, FritzBox poller, notifier or investigator runs. Never
point --db at a real LANOT database: the file is deleted first.
"""

import argparse
import json
import math
import os
import random
import threading
import time
from pathlib import Path

from lanot_common.protocol import LogBatch, LogLine, MetricsReport, StateReport

from lanot.config import Settings, load_config
from lanot.db import Database, Incident

EXAMPLE = Path(__file__).resolve().parents[2] / "lanot.example.toml"
HOSTS = ("nas", "docker-host", "monitor")
TOKENS = {h: f"demo-{h}" for h in HOSTS}
GB = 10**9

FS = {
    "docker-host": [("/mnt/user", 12_000, 0.61), ("/mnt/cache", 500, 0.42)],
    "nas": [("/mnt/tank", 16_000, 0.93), ("/mnt/backup", 8_000, 0.55)],
    "monitor": [("/", 1_000, 0.38)],
}
CONTAINERS = {
    "docker-host": [("jellyfin", "running", None), ("nextcloud", "running", "healthy"),
                    ("gitea", "exited", None), ("pihole", "running", "unhealthy")],
    "nas": [("syncthing", "running", "healthy")],
    "monitor": [("lanot-server", "running", None), ("ntfy", "running", None), ("lanot-agent", "running", None)],
}
PROBE_TARGETS = ("router", "gateway", "cloudflare", "google", "dns-router", "dns-external",
                 "nas", "docker-host", "monitor", "printer")
OUTAGE_DETAIL = "None of the internet probe targets (1.1.1.1, 8.8.8.8) answered for at least 3 checks."


def metrics(host: str, ts: float, rnd: random.Random) -> MetricsReport:
    wave = math.sin(ts / 3600)
    temps = {"cpu": 48 + 8 * wave + rnd.uniform(-2, 2)}
    if host != "monitor":
        temps["drivetemp-sda"] = 36 + 3 * wave
    return MetricsReport(
        host=host, ts=ts, cpu_pct=max(1.0, 18 + 12 * wave + rnd.uniform(-6, 6)), load1=0.8,
        mem_used=int((0.45 + 0.1 * wave) * 32 * GB), mem_total=32 * GB,
        net_rx_bps=2e6, net_tx_bps=5e5, temps=temps,
        filesystems=[{"mount": m, "total": t * GB, "used": int(t * GB * pct)} for m, t, pct in FS[host]],
        uptime_s=int(ts - (time.time() - 12 * 86400)),
        power={"ac_online": True, "battery_pct": 100.0} if host == "monitor" else None,
    )


def state(host: str, ts: float) -> StateReport:
    return StateReport(
        host=host, ts=ts,
        containers=[{"name": n, "status": s, "health": h, "restarts": 3 if h == "unhealthy" else 0}
                    for n, s, h in CONTAINERS[host]],
        pools=[{"name": "tank", "health": "ONLINE", "cap_pct": 93.0, "errors": "No known data errors"}]
        if host == "nas" else [],
        disks=[{"dev": "sda", "model": "EXAMPLE-HDD-12TB", "smart_passed": True, "attrs": {"Reallocated_Sector_Ct": 0}}]
        if host != "monitor" else [],
        array="STARTED" if host == "docker-host" else None,
    )


def fresh_probes(db: Database, now: float, internet_down: bool) -> None:
    for t in PROBE_TARGETS:
        ok = not (internet_down and t in ("gateway", "cloudflare", "google", "dns-external"))
        db.insert_probe(t, now, ok, 3.0 if ok else None)


def fresh_fritz(db: Database, now: float, internet_down: bool) -> None:
    db.insert_fritz(now, {"ok": True, "error": None, "link_up": True, "wan_connected": not internet_down,
                          "external_ip": None if internet_down else "203.0.113.17", "uptime_s": 86400,
                          "downstream_kbps": 500_000, "upstream_kbps": 100_000})


DIAG = {
    "summary": "Pool tank on the NAS is 93% full; it has grown by about 40 GB a day for a week.",
    "what_happened": "Storage pool tank on the NAS crossed the 90% warning threshold and is now at 93%. "
                     "Usage grows steadily; the pool reports no errors.",
    "cause": "The nightly backup of the Docker host creates new snapshots every day and old ones are not pruned.",
    "confidence": "likely",
    "suggestions": ["Look at the snapshot list in the TrueNAS UI and count the old snapshots.",
                    "Check whether a retention period is set for the backup task.",
                    "<script>alert('xss')</script> (this text must show up harmless)"],
    "evidence": ["df: /mnt/tank 93% (14.9 of 16 TB)", "zfs list -t snapshot: 214 snapshots",
                 "growth over 7 days: +280 GB"],
    "model": "claude-sonnet-5-5", "tool_calls": 6, "duration_s": 48.3,
    "facts": {"incident": {"rule": "disk_full", "key": "nas:/mnt/tank"},
              "metrics": {"filesystems": [{"mount": "/mnt/tank", "pct": 93.1}]},
              "traceroute": " 1  192.168.178.1  0.4 ms\n 2  198.51.100.1  8.1 ms"},
}


def seed(path: str, scenario: str) -> Settings:
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            os.remove(path + suffix)
    db = Database(path)
    rnd = random.Random(42)
    now = time.time()

    # 7 days of metrics, every 5 min (the last hour every 30 s)
    for host in HOSTS:
        ts = now - 7 * 86400
        while ts < now:
            db.insert_metrics(metrics(host, ts, rnd), ts)
            ts += 300 if ts < now - 3600 else 30
        db.insert_state(state(host, now - 60), now - 60)

    # logs, including errors and one hostile line
    lines = {
        "docker-host": [(6, "docker", "container jellyfin: health check ok"),
                        (3, "docker", "pihole: health check failed: timeout after 10s"),
                        (4, "kernel", "eth0: link speed changed to 1000 Mbit/s"),
                        (3, "syslog", "<script>alert(1)</script> fake log line from a container")],
        "nas": [(6, "zfs", "scrub of tank finished without errors"),
                (4, "zfs", "pool tank capacity 93%")],
        "monitor": [(6, "systemd", "Started docker.service"), (5, "upower", "AC adapter online")],
    }
    for host, ls in lines.items():
        db.insert_logs(LogBatch(host=host, lines=[LogLine(ts=now - 120 * i, source=src, severity=sev, message=m)
                                                  for i, (sev, src, m) in enumerate(ls)]), now)

    # internet outage history: one of each attribution
    outages = [  # (days ago, minutes, kind)
        (2, 6, "line"), (5, 14, "provider"), (9, 3, "router"), (13, 2, "lan"), (13.2, 25, "provider"),
        (21, 9, "line"), (27, 4, "provider"),
    ]
    for days, minutes, kind in outages:
        start = now - days * 86400
        end = start + minutes * 60
        db.save_incident(Incident("internet_down", "internet", "high", "Internet down", OUTAGE_DETAIL,
                                  opened_at=start, last_seen_at=end, resolved_at=end,
                                  flap_count=1 if minutes > 10 else 0))
        t = start
        while t < end:
            if kind == "line":
                db.insert_fritz(t, {"ok": True, "error": None, "link_up": False, "wan_connected": False})
            elif kind == "provider":
                db.insert_fritz(t, {"ok": True, "error": None, "link_up": True, "wan_connected": False})
            else:
                db.insert_fritz(t, {"ok": False, "error": "FritzBox unreachable"})
                db.insert_probe("router", t, False, None)
                db.insert_probe("docker-host", t, kind == "router", 1.0 if kind == "router" else None)
            t += 30

    if scenario in ("problem", "internet"):
        disk = db.save_incident(Incident("disk_full", "nas:/mnt/tank", "medium", "NAS: disk /mnt/tank 93% full",
                                         f"{int(14.9e12)} of {int(16e12)} bytes used.",
                                         opened_at=now - 3 * 3600, last_seen_at=now))
        db.set_diagnosis(disk.id, json.dumps(DIAG))
        db.save_incident(Incident("container_bad", "docker-host/pihole", "medium",
                                  "Docker host: container pihole reports errors (unhealthy)",
                                  "Status running, health unhealthy.",
                                  opened_at=now - 25 * 60, last_seen_at=now, flap_count=2))
        db.set_setting("important_containers", ["docker-host/pihole", "docker-host/jellyfin", "nas/syncthing"])
    if scenario == "internet":
        db.save_incident(Incident("internet_down", "internet", "high", "Internet down", OUTAGE_DETAIL,
                                  opened_at=now - 4 * 60, last_seen_at=now))
    # an old resolved incident with a "none" diagnosis
    old = db.save_incident(Incident("device_down", "printer", "high", "Printer unreachable",
                                    "192.0.2.32 does not answer ping (3 checks in a row).",
                                    opened_at=now - 4 * 86400, last_seen_at=now - 4 * 86400 + 900,
                                    resolved_at=now - 4 * 86400 + 900))
    db.set_diagnosis(old.id, json.dumps({"summary": "No AI assessment available. See the dashboard for the facts.",
                                         "what_happened": "", "cause": "", "confidence": "unclear",
                                         "suggestions": [], "evidence": [], "model": "none", "tool_calls": 0,
                                         "duration_s": 1.2, "facts": {"probes": {"printer": [[now, False, None]]}}}))
    db.set_setting("important_services", [{"name": "nextcloud", "kind": "http", "address": "192.0.2.31",
                                           "port": 8443}])
    db.set_mute("service_down", "gitea", now + 7 * 86400)
    fresh_probes(db, now, scenario == "internet")
    fresh_fritz(db, now, scenario == "internet")
    return Settings(db_path=path, agent_tokens=TOKENS, allowed_hosts="127.0.0.1:8090,localhost:8090").with_config(
        load_config(EXAMPLE))


def fake_agent(db: Database, scenario: str, stop: threading.Event) -> None:
    rnd = random.Random(7)
    while not stop.wait(10):
        now = time.time()
        fresh_probes(db, now, scenario == "internet")
        fresh_fritz(db, now, scenario == "internet")
        for host in HOSTS:
            db.insert_metrics(metrics(host, now, rnd), now)
            db.insert_state(state(host, now), now)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="/tmp/lanot-demo.db")
    ap.add_argument("--scenario", choices=("ok", "problem", "internet"), default="problem")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args()
    if os.path.abspath(args.db).startswith("/data/"):
        raise SystemExit("refusing to overwrite a database under /data")
    settings = seed(args.db, args.scenario)
    print(f"demo database ready: {args.db} ({args.scenario})")
    if not args.serve:
        return
    import uvicorn

    from lanot.main import create_app

    app = create_app(settings, start_background=False)
    stop = threading.Event()
    threading.Thread(target=fake_agent, args=(app.state.db, args.scenario, stop), daemon=True).start()
    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    finally:
        stop.set()


if __name__ == "__main__":
    main()
