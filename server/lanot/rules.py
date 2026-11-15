"""Fixed alarm rules. Pure: `evaluate(view, now)` turns a snapshot of the
system into findings. Nothing here is AI-driven or touches the database
(except `build_view`, which only reads)."""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Literal

from lanot_common.protocol import MetricsReport, PowerState, StateReport

from .config import LanotConfig
from .fritz import ERR_NO_USER
from .pinger import Target, default_targets

PROBE_FAILS = 3
PROBE_WINDOW_S = 120.0  # only probes this recent count (a stopped pinger must not alarm forever)
SILENT_AFTER_S = 120.0
STARTUP_GRACE_S = 180.0
TEMP_WINDOW_S = 300.0
TEMP_SAMPLE_GAP_S = 60.0  # the window must be covered by samples at most this far apart at its start
LOG_WINDOW_S = 60.0  # a matching line received this recently opens a log_error
LOG_HOLD_S = 600.0  # ...and keeps it open until no matching line for this long
SEGFAULT_WINDOW_S = 600.0  # equals LOG_HOLD_S
SEGFAULT_MIN = 3
ERROR_SEVERITY_MAX = 3
ERROR_LINE_LIMIT = 5000
# Unraid syslog carries no PRI, so its kernel lines arrive as severity 6. Lines
# containing one of these words are matched against LOG_PATTERNS whatever their
# severity (SQL LIKE prefilter, case-insensitive). Keep in sync with LOG_PATTERNS.
LOG_KEYWORDS = ("i/o error", "zfs", "smart", "failing_now", "out of memory", "oom-kill", "kernel panic", "oops",
                "bug: unable to handle", "ext4-fs error", "xfs", "btrfs", "segfault", "squashfs error")
# known false positives: NVIDIA driver (NVRM) asserts and Ubuntu's "whoopsie" crash reporter
_NOISE_RE = re.compile(r"NVRM:|whoopsie", re.I)
# sudo/audit lines echo whole command lines ("grep 'I/O error'", our own checks): never a fault
_AUDIT_RE = re.compile(r"^\s*sudo(\[\d+\])?:|\bCOMMAND=|@cee:\{\"sudo\"")
DISK_HYSTERESIS_PCT = 1.0  # an open disk_full only de-escalates / ends 1% below its threshold
PRIVATE_SUFFIXES = (".lan", ".local", ".home", ".internal")

DEFAULT_THRESHOLDS = {
    "disk_warn": 90.0,
    "disk_high": 95.0,
    "temp_cpu": 90.0,
    "temp_disk": 55.0,
}

Severity = Literal["medium", "high"]

CONTAINER_STATES = {
    "exited": "stopped",
    "unhealthy": "reports errors (unhealthy)",
    "restarting": "keeps restarting",
    "dead": "crashed",
}
POOL_HEALTH = {"DEGRADED": "degraded (DEGRADED)", "FAULTED": "failed (FAULTED)"}

# (name, regex, severity, label)
LOG_PATTERNS: list[tuple[str, re.Pattern, Severity, str]] = [
    (n, re.compile(rx, re.I), sev, label)
    for n, rx, sev, label in [
        ("io_error", r"i/o error", "high", "I/O errors in the log"),
        ("zfs", r"zfs.*(fault|degraded|checksum)", "high", "ZFS errors in the log"),
        ("smart", r"smart.*(fail|prefail)", "high", "SMART errors in the log"),
        ("oom", r"out of memory|oom-kill", "medium", "out of memory (OOM) in the log"),
        ("kernel_panic", r"kernel panic|\boops\b", "high", "kernel panic in the log"),
        ("fs_error", r"ext4-fs error|xfs.*corrupt|btrfs.*error", "high", "file system errors in the log"),
        ("segfault", r"segfault", "medium", "crashes (segfaults) in the log"),
        ("squashfs", r"squashfs error", "high", "system file corrupt (SQUASHFS error)"),
    ]
]
# For lines above ERROR_SEVERITY_MAX (no PRI or info/debug): only unmistakable fault lines.
# smartd's routine "SMART Prefailure Attribute ... changed" lines must not count.
LOG_PATTERNS_STRICT: dict[str, re.Pattern] = {n: re.compile(rx, re.I) for n, rx in {
    "io_error": r"\bi/o error\b",
    "zfs": r"\bzfs\b.*\b(fault(ed|s)?|degraded|checksum)\b",
    "smart": r"^(?!.*prefail)(?=.*\bsmart\b).*(\bFAILED\b|FAILING_NOW|\bsmart\b.*\b(error|fail(ed|ure))\b)",
    "oom": r"out of memory: killed process|oom-kill|invoked oom-killer",
    "kernel_panic": r"\boops\b|kernel panic|BUG: unable to handle",
    "fs_error": r"\bext4-fs error\b|\bxfs\b.*\bcorrupt|\bbtrfs\b.*\berror\b",
    "segfault": r"\bsegfault\b",
    "squashfs": r"\bsquashfs error\b",
}.items()}


@dataclass(frozen=True)
class Finding:
    rule: str
    key: str
    severity: Severity
    title: str
    detail: str


@dataclass
class SystemView:
    started_at: float
    config: LanotConfig = field(default_factory=LanotConfig)
    targets: list[Target] | None = None  # None: default_targets(config)
    hosts: list[str] = field(default_factory=list)  # hosts that run an agent
    probes: dict[str, list[bool]] = field(default_factory=dict)  # oldest -> newest, recent only
    metrics: dict[str, MetricsReport] = field(default_factory=dict)
    state: dict[str, StateReport] = field(default_factory=dict)
    prev_state: dict[str, StateReport] = field(default_factory=dict)  # the report before `state`
    last_received: dict[str, float | None] = field(default_factory=dict)
    power: dict[str, PowerState] = field(default_factory=dict)
    errors: dict[str, list[tuple]] = field(default_factory=dict)  # (received, message[, severity]), last 10 min
    temps: dict[str, list[tuple[float, dict[str, float]]]] = field(default_factory=dict)
    fritz: list[dict] = field(default_factory=list)  # oldest -> newest
    mutes: set[tuple[str, str]] = field(default_factory=set)
    thresholds: dict[str, float] = field(default_factory=dict)
    important_containers: set[str] = field(default_factory=set)  # "host/name"
    open_incidents: set[tuple[str, str]] = field(default_factory=set)  # (rule, key) currently open
    open_severity: dict[tuple[str, str], str] = field(default_factory=dict)  # severity of those


def _failed(view: SystemView, target: str) -> bool:
    p = view.probes.get(target, [])
    return len(p) >= PROBE_FAILS and not any(p[-PROBE_FAILS:])


def _ok(view: SystemView, target: str) -> bool:
    p = view.probes.get(target)
    return bool(p) and p[-1]


def _is_external(address: str) -> bool:
    try:
        return not ipaddress.ip_address(address).is_private
    except ValueError:
        return "." in address and not address.lower().endswith(PRIVATE_SUFFIXES)


def evaluate(view: SystemView, now: float) -> list[Finding]:
    cfg = view.config
    name_of = cfg.name_of
    th = {**DEFAULT_THRESHOLDS, **view.thresholds}
    targets = view.targets if view.targets is not None else default_targets(cfg)
    inet = cfg.internet.ping_targets
    out: list[Finding] = []

    internet = all(_failed(view, t.name) for t in inet)
    internet_ok = any(_ok(view, t.name) for t in inet)
    if internet:
        out.append(Finding("internet_down", "internet", "high", "Internet down",
                           f"None of the internet probe targets ({', '.join(t.address for t in inet)}) "
                           "answered for at least 3 checks."))

    down_hosts = set()
    for t in targets:
        if t.kind == "icmp" and t.name not in cfg.internet.target_names and _failed(view, t.name):
            down_hosts.add(t.name)
            out.append(Finding("device_down", t.name, "high", f"{name_of(t.name)} unreachable",
                               f"{t.address} does not answer ping (3 checks in a row)."))
        elif t.kind in ("tcp", "http") and t.important and _failed(view, t.name):
            if internet and _is_external(t.address):
                continue
            out.append(Finding("service_down", t.name, "medium", f"Service {name_of(t.name)} unreachable",
                               f"{t.kind} {t.address}{':' + str(t.port) if t.port else ''} does not answer."))

    router = cfg.router.display_name
    router_dns = cfg.internet.check_router_dns
    if _failed(view, "dns-external") and (not router_dns or _failed(view, "dns-router")) and internet_ok:
        out.append(Finding("dns_broken", "dns", "medium", "DNS not working",
                           ("Neither DNS server (router and external) answers" if router_dns
                            else "The external DNS server does not answer") + ", but the internet itself does."))
    elif router_dns and _failed(view, "dns-router") and _ok(view, "dns-external") and internet_ok:
        out.append(Finding("dns_broken", "router", "medium",
                           f"{router} DNS not answering: devices on the LAN cannot resolve names",
                           f"The DNS server of {router} has not answered for at least 3 checks. An external "
                           "DNS server and the internet work."))

    out += _agent_silent(view, now, down_hosts)
    out += _logs(view, now)
    out += _metrics(view, now, th)
    out += _state(view)

    for host in cfg.battery_hosts:
        ps = view.power.get(host)
        if ps is None or ps.ac_online:
            continue
        name = name_of(host)
        if ps.battery_pct is not None:
            title = f"{name}: mains power lost (battery {ps.battery_pct:.0f}%)"
            batt = f"Battery at {ps.battery_pct:.0f}%."
        else:
            title, batt = f"{name}: mains power lost", "Battery level unknown."
        out.append(Finding("power_lost", host, "high", title,
                           batt + f" {name} is running on battery: power cut or charger unplugged. "
                           "Monitoring continues as long as the battery lasts."))

    recent = view.fritz[-3:]
    if len(recent) == 3 and all(not f.get("ok") for f in recent) and recent[-1].get("error") != ERR_NO_USER:
        out.append(Finding("router_unqueryable", "router", "medium", f"{router} cannot be queried",
                           f"The last 3 queries failed: {recent[-1].get('error')}"))

    return [f for f in out if (f.rule, f.key) not in view.mutes]


def _agent_silent(view: SystemView, now: float, down_hosts: set[str]) -> list[Finding]:
    if now - view.started_at < STARTUP_GRACE_S:
        return []
    out = []
    for host in view.hosts:
        if host in down_hosts:  # device_down already explains it
            continue
        last = view.last_received.get(host) or view.started_at
        if now - last > SILENT_AFTER_S:
            out.append(Finding("agent_silent", host, "medium", f"{view.config.name_of(host)} not reporting",
                               f"No metrics or state data for {int(now - last)} s."))
    return out


def _logs(view: SystemView, now: float) -> list[Finding]:
    out = []
    for host, lines in view.errors.items():
        # (received, message[, severity]); without a severity the line counts as severe
        lines = sorted(((t[0], t[1], t[2] if len(t) > 2 else 0) for t in lines
                        if t[0] >= now - LOG_HOLD_S and not _AUDIT_RE.search(t[1]) and not _NOISE_RE.search(t[1])),
                       key=lambda x: x[0])
        for name, rx, sev, label in LOG_PATTERNS:
            key = f"{host}:{name}"
            strict = LOG_PATTERNS_STRICT[name]
            hits = [(ts, m) for ts, m, lsev in lines
                    if (rx if lsev <= ERROR_SEVERITY_MAX else strict).search(m)]
            if name == "segfault":
                fresh = [h for h in hits if h[0] >= now - SEGFAULT_WINDOW_S]
                fire = len(fresh) >= SEGFAULT_MIN
            else:
                fire = any(ts >= now - LOG_WINDOW_S for ts, _ in hits)
            # an already open incident is held while any hit is in the hold window
            if not (fire or (hits and ("log_error", key) in view.open_incidents)):
                continue
            if name == "squashfs" and host in view.config.unraid_hosts:
                # on Unraid, SQUASHFS means bzroot/bzfirmware/bzmodules on the USB stick
                label = "Unraid " + label
            out.append(Finding("log_error", key, sev, f"{view.config.name_of(host)}: {label}",
                               f"{len(hits)} matching lines, latest: {hits[-1][1][:200]}"))
    return out


def _is_disk_sensor(sensor: str) -> bool:
    return sensor.lower().startswith(("drivetemp", "nvme"))


def _metrics(view: SystemView, now: float, th: dict) -> list[Finding]:
    out = []
    name_of = view.config.name_of
    for host, m in view.metrics.items():
        for fs in m.filesystems:
            pct = fs.pct
            key = f"{host}:{fs.mount}"
            was = view.open_severity.get(("disk_full", key))
            if ("disk_full", key) not in view.open_incidents:
                was = None
            high_at = th["disk_high"] - (DISK_HYSTERESIS_PCT if was == "high" else 0)
            warn_at = th["disk_warn"] - (DISK_HYSTERESIS_PCT if was else 0)
            if pct >= warn_at:
                out.append(Finding("disk_full", key,
                                   "high" if pct >= high_at else "medium",
                                   f"{name_of(host)}: disk {fs.mount} {pct:.0f}% full",
                                   f"{fs.used} of {fs.total} bytes used."))
    for host, hist in view.temps.items():
        window = [(ts, t) for ts, t in hist if ts >= now - TEMP_WINDOW_S]
        if len(window) < 2 or window[0][0] > now - TEMP_WINDOW_S + TEMP_SAMPLE_GAP_S:
            continue
        for sensor in window[-1][1]:
            limit = th["temp_disk"] if _is_disk_sensor(sensor) else th["temp_cpu"]
            vals = [t[sensor] for _, t in window if sensor in t]
            if len(vals) == len(window) and min(vals) >= limit:
                out.append(Finding("temp_high", f"{host}:{sensor}", "high" if vals[-1] >= limit + 10 else "medium",
                                   f"{name_of(host)}: {sensor} at {vals[-1]:.0f} °C for 5 minutes",
                                   f"Limit {limit:.0f} °C, lowest value in the window {min(vals):.0f} °C."))
    return out


def _state(view: SystemView) -> list[Finding]:
    out = []
    name_of = view.config.name_of
    for host, s in view.state.items():
        name = name_of(host)
        for f, ok in sorted((s.boot_files or {}).items()):
            if not ok:
                out.append(Finding("boot_corrupt", f"{host}:{f}", "high",
                                   f"{name}: {f} corrupt, do not reboot",
                                   f"The Unraid boot file {f} on the USB stick does not match its checksum. "
                                   "Containers keep running, but Docker may crash. Replace the file from the "
                                   "matching Unraid release, then restart Docker or the server."))
        prev = view.prev_state.get(host)
        # two reports in a row (5 min apart): a containerd restart must not alarm
        if s.docker_healthy is False and prev is not None and prev.docker_healthy is False:
            out.append(Finding("containerd_down", host, "high",
                               f"{name}: containerd is down, container health checks are not running",
                               "Docker answers, but the containerd process is not running. Running containers "
                               "keep working; health checks, restarts and docker exec do not."))
        for p in s.pools:
            if p.health != "ONLINE":
                out.append(Finding("pool_bad", f"{host}:{p.name}", "high",
                                   f"{name}: pool {p.name} {POOL_HEALTH.get(p.health, 'state ' + p.health)}",
                                   f"State {p.health}, errors: {p.errors}"))
        for d in s.disks:
            if not d.smart_passed:
                out.append(Finding("smart_bad", f"{host}:{d.dev}", "high",
                                   f"{name}: SMART check of {d.dev} failed", d.model))
        for c in s.containers:
            if f"{host}/{c.name}" not in view.important_containers:
                continue
            if c.health == "unhealthy":
                what = CONTAINER_STATES["unhealthy"]
            elif c.status in ("exited", "dead", "restarting"):
                what = CONTAINER_STATES[c.status]
            else:
                continue
            out.append(Finding("container_bad", f"{host}/{c.name}", "medium",
                               f"{name}: container {c.name} {what}", f"Status {c.status}, health {c.health}."))
    return out


def build_view(db, settings, now: float, *, started_at: float, targets: list[Target] | None = None) -> SystemView:
    """Read everything the rules need. `settings` gives the network layout
    (agent hosts); thresholds and important containers come from the settings table."""
    cfg = settings.config
    hosts = cfg.agent_hosts
    since = now - PROBE_WINDOW_S
    tlist = targets if targets is not None else default_targets(cfg)
    probes = {t.name: [ok for _, ok, _ in db.probes(t.name, since)][-PROBE_FAILS:] for t in tlist}
    metrics, state, prev_state, last, power, errors, temps = {}, {}, {}, {}, {}, {}, {}
    for h in hosts:
        last[h] = db.last_received(h)
        if (m := db.latest_metrics(h)) is not None:
            metrics[h] = m
            if m.power is not None:
                power[h] = m.power
        if (s := db.latest_state(h)) is not None:
            state[h] = s
            if (p := db.previous_state(h)) is not None:
                prev_state[h] = p
        errors[h] = db.rule_logs(h, now - LOG_HOLD_S, ERROR_SEVERITY_MAX, LOG_KEYWORDS, ERROR_LINE_LIMIT)
        temps[h] = db.temps_since(h, now - TEMP_WINDOW_S - TEMP_SAMPLE_GAP_S)
    open_incs = db.open_incidents()
    return SystemView(
        started_at=started_at, config=cfg, targets=tlist, hosts=hosts, probes=probes, metrics=metrics, state=state,
        prev_state=prev_state, last_received=last, power=power, errors=errors, temps=temps,
        fritz=db.recent_fritz(PROBE_FAILS) if cfg.router.polls_tr064 else [],
        mutes=db.mutes_active(now),
        open_incidents={(i.rule, i.key) for i in open_incs},
        open_severity={(i.rule, i.key): i.severity for i in open_incs},
        thresholds=db.get_setting("thresholds", {}) or {},
        important_containers=set(db.get_setting("important_containers", []) or []),
    )
