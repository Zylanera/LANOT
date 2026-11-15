"""Dashboard pages and the JSON the page script polls.

Untrusted text (log lines, diagnoses, container names) is only ever rendered
through Jinja2 autoescaping; nothing here marks it safe. Forms are plain HTML
POSTs that redirect (303).
"""

import ipaddress
import json
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

import jinja2
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..config import RESERVED_IDS
from ..db import Database, Incident
from ..fritz import ERR_NO_USER
from ..pinger import default_targets
from ..rules import DEFAULT_THRESHOLDS

BASE = Path(__file__).parent
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(BASE / "templates")),
    autoescape=True,  # every template, regardless of extension
    trim_blocks=True,
    lstrip_blocks=True,
)
templates = Jinja2Templates(env=_env)

router = APIRouter()

# -- vocabulary ------------------------------------------------------------------
STATUS_WORD = {"ok": "OK", "warn": "Warning", "bad": "Problem", "unknown": "unknown", "muted": "muted"}
CHAIN_IDS = ("lan", "router", "line", "provider", "internet")
FRESH_S = 300.0
PROBE_RECENT_S = 120.0
OUTAGE_DAYS = 30
RECENT_RESOLVED_S = 7 * 86400
RECENT_RESOLVED_MAX = 3
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

RULE_LABELS = {
    "internet_down": "Internet down",
    "device_down": "Device unreachable",
    "service_down": "Service unreachable",
    "dns_broken": "DNS broken",
    "agent_silent": "Device not reporting",
    "log_error": "Error in the log",
    "disk_full": "Disk full",
    "temp_high": "Temperature too high",
    "pool_bad": "Storage pool unhealthy",
    "smart_bad": "Disk reports a SMART failure",
    "container_bad": "Container not running",
    "power_lost": "Power outage",
    "boot_corrupt": "Boot file corrupt",
    "containerd_down": "containerd down",
    "router_unqueryable": "Router cannot be queried",
}

MUTE_DURATIONS = {
    "1h": (3600, "1 hour"),
    "8h": (8 * 3600, "8 hours"),
    "1d": (86400, "1 day"),
    "7d": (7 * 86400, "7 days"),
    "30d": (30 * 86400, "30 days"),
    "forever": (10 * 365 * 86400, "until I turn it back on"),
}

LOG_RANGES = {"1h": (3600, "last hour"), "24h": (86400, "last 24 hours"),
              "7d": (7 * 86400, "last 7 days"), "30d": (30 * 86400, "last 30 days")}
LOG_SEVERITIES = {"all": (None, "all"), "warning": (4, "warnings and errors"), "error": (3, "errors only")}
SEVERITY_WORD = {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning", 5: "notice", 6: "info",
                 7: "debug"}
SERIES_RANGES = {"24h": (86400, 120.0), "7d": (7 * 86400, 900.0)}

THRESHOLD_FIELDS = {
    # key: (label, unit, min, max)
    "disk_warn": ("Disk: warning from", "%", 50.0, 100.0),
    "disk_high": ("Disk: problem from", "%", 50.0, 100.0),
    "temp_cpu": ("CPU temperature: warning from", "°C", 40.0, 110.0),
    "temp_disk": ("Disk temperature: warning from", "°C", 30.0, 80.0),
}

MAX_SERVICES = 30

ERRORS = {
    "service_name": "The name may only contain lowercase letters, digits, - and _ (max. 40 characters).",
    "service_taken": "This name is already in use (or reserved for a device).",
    "service_full": f"There are already {MAX_SERVICES} important services, which is the maximum. "
                    "Remove another service first.",
    "service_kind": "Please choose \"Port (TCP)\" or \"Web page (HTTP)\" as the kind.",
    "service_address": "The address is not valid. Use an IP address or a host name.",
    "service_port": "The port must be a number from 1 to 65535 (required for \"Port (TCP)\").",
    "thresholds": "The thresholds are not valid. Enter numbers within the allowed range; "
                  "\"problem from\" must be above \"warning from\".",
    "containers": "A container entry is not valid.",
    "mute": "Muting failed: unknown target or invalid duration.",
}
SAVED = {"1": "Saved.", "muted": "Muted.", "unmuted": "Turned back on."}

_SERVICE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
                          r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")
_CONTAINER_RE = re.compile(r"^([a-z0-9_-]{1,40})/([A-Za-z0-9][A-Za-z0-9_.-]{0,127})$")
_BACK_RE = re.compile(r"^/incident/\d{1,12}$")


# -- formatting ----------------------------------------------------------------------
def _tz(request: Request) -> ZoneInfo:
    return ZoneInfo(request.app.state.settings.tz)


def _cfg(request: Request):
    return request.app.state.settings.config


def fmt_time(ts: float | None, tz: ZoneInfo, now: float | None = None) -> str:
    """"today 23:13", "yesterday 20:38", "Nov 9 23:38"; the year only if it is not the current one."""
    if ts is None:
        return ""
    t = datetime.fromtimestamp(ts, tz)
    today = datetime.fromtimestamp(time.time() if now is None else now, tz).date()
    if t.date() == today:
        return t.strftime("today %H:%M")
    if t.date() == today - timedelta(days=1):
        return t.strftime("yesterday %H:%M")
    day = f"{MONTHS[t.month - 1]} {t.day}"
    if t.year != today.year:
        day += f", {t.year}"
    return f"{day} {t:%H:%M}"


def fmt_num(v: float | None, digits: int = 0) -> str:
    if v is None:
        return ""
    return f"{v:.{digits}f}"


def temp_labels(keys) -> dict[str, tuple[str, str]]:
    """hwmon key -> (human name, kind) with kind "cpu", "disk" or "other".
    Keys look like "coretemp/Package id 0", "drivetemp.hwmon3/temp1", "nvme/Composite"
    (or simply "cpu" / "drivetemp-sda")."""
    out: dict[str, tuple[str, str]] = {}
    disk_n = nvme_n = 0
    for k in sorted(keys):
        chip, _, lab = k.partition("/")
        base = chip.split(".")[0].lower()
        head, _, suffix = base.partition("-")
        if head in ("cpu", "coretemp", "k10temp", "zenpower", "cpu_thermal"):
            core = lab.lower().startswith("core")
            out[k] = (f"CPU core {lab[4:].strip()}" if core else "CPU", "cpu")
        elif head == "drivetemp":
            disk_n += 1
            out[k] = (f"Disk {suffix or disk_n}", "disk")
        elif head == "nvme":
            nvme_n += 1
            out[k] = ("NVMe", "disk")
        elif head == "acpitz":
            out[k] = ("Mainboard", "other")
        else:
            out[k] = (k, "other")
    if nvme_n > 1:
        n = 0
        for k, (name, kind) in out.items():
            if name == "NVMe":
                n += 1
                out[k] = (f"NVMe {n}", kind)
    seen: dict[str, int] = {}
    for k, (name, kind) in list(out.items()):
        seen[name] = seen.get(name, 0) + 1
        if seen[name] > 1:
            out[k] = (f"{name} ({seen[name]})", kind)
    return out


def fmt_duration(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 60:
        return "under 1 min"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        h, m = divmod(s // 60, 60)
        return f"{h} h {m} min" if m else f"{h} h"
    d, h = divmod(s // 3600, 24)
    return f"{d} {'day' if d == 1 else 'days'}" + (f" {h} h" if h else "")


def fmt_bytes(n: float) -> str:
    """Decimal units: 7.3 TB / 210 GB."""
    for unit, size in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6)):
        if n >= size:
            v = n / size
            text = f"{v:.1f}" if v < 100 else f"{v:.0f}"
            return text + " " + unit
    return f"{int(n)} B"


def sev_status(severity: str) -> str:
    return "bad" if severity == "high" else "warn"


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def times_word(n: int) -> str:
    return "once" if n == 1 else f"{n} times"


def diagnosis_of(inc: Incident) -> dict | None:
    if not inc.diagnosis_json:
        return None
    try:
        d = json.loads(inc.diagnosis_json)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def incident_view(inc: Incident, now: float, tz: ZoneInfo, muted: frozenset | set = frozenset()) -> dict:
    """`muted`: active (rule, key) mutes; a muted open incident gets the grey "muted" state."""
    diag = diagnosis_of(inc)
    open_ = inc.resolved_at is None
    is_muted = open_ and (inc.rule, inc.key) in muted
    end = now if open_ else inc.resolved_at
    summary = str(diag.get("summary") or "").strip() if diag else ""
    conf = diag.get("confidence") if diag else None
    when = fmt_time(inc.opened_at, tz, now)
    duration = fmt_duration(end - inc.opened_at)
    times = inc.flap_count + 1
    # one muted line under the title, for lists
    line = f"{when}, ongoing for {duration}" if open_ else f"{when}, resolved after {duration}"
    # compact header of the detail page
    head = f"Started {when}"
    if not open_:
        same_day = (datetime.fromtimestamp(inc.opened_at, tz).date()
                    == datetime.fromtimestamp(inc.resolved_at, tz).date())
        resolved = (datetime.fromtimestamp(inc.resolved_at, tz).strftime("%H:%M") if same_day
                    else fmt_time(inc.resolved_at, tz, now))
        head += f", resolved {resolved} ({duration})"
    else:
        head += f", ongoing for {duration}"
    if times > 1:
        head += f", happened {times_word(times)}"
    return {
        "confidence": conf if conf in ("certain", "likely", "unclear") else ("unclear" if diag else None),
        "id": inc.id, "rule": inc.rule, "key": inc.key, "title": inc.title, "detail": inc.detail or "",
        "severity": inc.severity, "rule_label": RULE_LABELS.get(inc.rule, inc.rule),
        "status": ("muted" if is_muted else sev_status(inc.severity)) if open_ else "ok", "muted": is_muted,
        "open": open_, "when": when, "line": line, "head": head, "resolved_at": inc.resolved_at,
        "duration": duration, "times": times, "summary": summary, "diag": diag,
    }


def _strip_host(title: str, name: str) -> str:
    prefix = f"{name}: "
    return title[len(prefix):] if title.startswith(prefix) else title


# -- outage attribution ---------------------------------------------------------------
def attribute(fritz: dict, router_probe_ok: bool | None = None, *, lan_ok: bool | None = None) -> str:
    """Where an internet outage came from: "line" (DSL/cable not in sync),
    "provider" (router online, internet behind it not), "router" (the router
    did not answer) or "lan" (the router and the other LAN devices were
    unreachable from the server, i.e. its own network path). `lan_ok`: did
    other LAN devices answer while the router did not (None = unknown)."""
    fritz = fritz or {}
    if fritz.get("link_up") is False:
        return "line"
    if fritz.get("link_up") is True and fritz.get("wan_connected") is False:
        return "provider"
    if router_probe_ok is False:
        return "lan" if lan_ok is False else "router"
    return "provider"


def cause_names(cfg) -> dict[str, str]:
    return {"lan": "LAN", "router": cfg.router.display_name, "line": "Line", "provider": "Provider"}


def attribution_text(cfg) -> dict[str, str]:
    r = cfg.router.display_name
    return {
        "line": f"{r} had no connection on the line. Usually a problem at the provider or with the cable.",
        "provider": f"{r} was connected to the line, but the internet behind it did not work. "
                    "That is almost always the provider.",
        "router": f"{r} itself did not answer, for example because it restarted.",
        "lan": f"The LAN was disrupted: neither {r} nor the other devices were reachable. "
               "Check the cables and the switch near the LANOT server.",
    }


def model_label(model: str | None) -> str:
    m = (model or "").lower()
    if not m or m == "none":
        return "no AI"
    return "Anthropic API" if "claude" in m else "local model"


def outage_attribution(db: Database, cfg, lo: float, hi: float) -> str:
    polls = db.fritz_between(lo, hi)
    agg: dict = {}
    if any(p.get("link_up") is False for p in polls):
        agg = {"link_up": False}
    elif any(p.get("link_up") is True and p.get("wan_connected") is False for p in polls):
        agg = {"link_up": True, "wan_connected": False}
    box = db.probes_between("router", lo, hi)
    box_ok = None if not box else all(ok for _, ok in box)
    lan_ok = None
    if box_ok is False:
        down_at = [ts for ts, ok in box if not ok]
        lan = [ok for h in cfg.lan_hosts for ts, ok in db.probes_between(h, min(down_at), max(down_at))]
        lan_ok = any(lan) if lan else None
    return attribute(agg, box_ok, lan_ok=lan_ok)


# -- overview ----------------------------------------------------------------------
def known_hosts(settings) -> list[str]:
    ids = settings.config.host_ids
    return ids + [h for h in settings.agent_tokens if h not in ids]


def service_hosts(db: Database, cfg) -> dict[str, str]:
    """Important service name -> the device that hosts it (by its address), if known."""
    by_addr = {h.address: h.id for h in cfg.hosts}
    ids = set(cfg.host_ids)
    out = {}
    for svc in db.get_setting("important_services", []) or []:
        addr = str(svc.get("address", ""))
        host = addr if addr in ids else by_addr.get(addr)
        if host:
            out[str(svc.get("name"))] = host
    return out


def tile_of(inc: Incident, hosts: list[str], cfg, services: dict[str, str] | None = None) -> str | None:
    internet_keys = cfg.internet.target_names | {"gateway"}
    if inc.rule in ("internet_down", "dns_broken") or (inc.rule == "device_down" and inc.key in internet_keys):
        return "internet"
    if inc.key == "router":
        return "router"
    if inc.rule == "service_down":
        host = (services or {}).get(inc.key)
        return host if host in hosts else None
    head = inc.key.replace("/", ":").split(":", 1)[0]
    return head if head in hosts else None


def _last_probe(db: Database, target: str, now: float) -> tuple[float, bool, float | None] | None:
    p = db.probes(target, now - PROBE_RECENT_S)
    return p[-1] if p else None


def _tile(id_: str, name: str, href: str, incs: list[Incident], ok_status: str, ok_text: str) -> dict:
    if incs:
        incs = sorted(incs, key=lambda i: (i.severity != "high", i.opened_at))
        status = sev_status(incs[0].severity)
        text = _strip_host(incs[0].title, name)
        if len(incs) > 1:
            text += f" (+{len(incs) - 1} more)"
    else:
        status, text = ok_status, ok_text
    return {"id": id_, "name": name, "href": href, "status": status, "word": STATUS_WORD[status], "text": text}


def _host_ok_text(db: Database, settings, host: str, now: float) -> tuple[str, str]:
    last = db.last_received(host)
    m = db.latest_metrics(host) if last is not None and now - last <= FRESH_S else None
    if m is not None:
        return "ok", "running"
    p = _last_probe(db, host, now)
    h = settings.config.host(host)
    agent = (h.agent if h else False) or host in settings.agent_tokens
    if agent and last is None:
        return "unknown", "No data from the agent yet"
    if p is not None and p[1]:
        return "ok", "running" + (", but no recent data from the agent" if agent and last else "")
    if p is not None:
        return "unknown", "Not answering right now"
    if agent:
        return "unknown", f"No data from {settings.config.name_of(host)} yet. Is the agent running?"
    return "unknown", "No measurements yet"


def _probe_state(db: Database, targets, now: float) -> bool | None:
    """True if any target answered recently, False if all measured ones failed, None if no data."""
    last = [p for t in targets if (p := _last_probe(db, t, now)) is not None]
    if not last:
        return None
    return any(p[1] for p in last)


def build_chain(db: Database, cfg, now: float, open_incs: list[Incident]) -> dict:
    """LAN -> router -> line -> provider -> internet. The first broken station
    is "bad"; everything after it is unknown (nothing can be seen past the break)."""
    st: dict[str, tuple[str, str]] = {}
    inet = [t.name for t in cfg.internet.ping_targets]
    outage = next((i for i in open_incs if i.rule == "internet_down"), None)
    fz = db.latest_fritz() if cfg.router.polls_tr064 else None
    fz = fz if fz and now - fz["ts"] <= FRESH_S else None
    lan = _probe_state(db, cfg.lan_hosts, now)
    box = _probe_state(db, ("router",), now)
    net = _probe_state(db, inet, now)
    link = fz.get("link_up") if fz and fz.get("ok") else None
    wan = fz.get("wan_connected") if fz and fz.get("ok") else None

    st["lan"] = {True: ("ok", "devices reachable"), False: ("bad", "devices unreachable"),
                 None: ("unknown", "unknown")}[lan]
    if any(i.rule == "device_down" and i.key == "router" for i in open_incs) or box is False:
        st["router"] = ("bad", "not answering")
    else:
        st["router"] = ("ok", "reachable") if box else ("unknown", "unknown")
    if link is False:
        st["line"] = ("bad", "no connection")
    elif link is True:
        st["line"] = ("ok", "connected")
    else:
        st["line"] = ("ok", "connected") if net else ("unknown", "unknown")
    if wan is False:
        st["provider"] = ("bad", "no connection")
    else:
        st["provider"] = ("ok", "connected") if (wan or net) else ("unknown", "unknown")
    if outage is not None or net is False:
        st["internet"] = ("bad", "unreachable")
    elif any(i.rule == "dns_broken" for i in open_incs):
        st["internet"] = ("warn", "name resolution (DNS) disrupted")
    else:
        st["internet"] = ("ok", "reachable") if net else ("unknown", "unknown")

    if outage is not None:
        broken = outage_attribution(db, cfg, outage.opened_at - 60, now)
        if st[broken][0] != "bad":
            st[broken] = ("bad", {"lan": "disrupted", "router": "not answering",
                                  "line": "no connection", "provider": "no internet behind it"}[broken])
    else:
        broken = next((k for k in CHAIN_IDS if st[k][0] == "bad"), None)
    speed = ""
    if fz and fz.get("ok") and fz.get("downstream_kbps"):
        speed = f"{fz['downstream_kbps'] // 1000}/{(fz.get('upstream_kbps') or 0) // 1000} Mbit/s"
    names = {"lan": "LAN", "router": cfg.router.display_name, "line": "Line", "provider": "Provider",
             "internet": "Internet"}
    stations, after = [], False
    for k in CHAIN_IDS:
        status, text = st[k]
        if after:
            status, text = "unknown", "unknown"
        # minimal: a visible text only where something is wrong (plus the line speed)
        if status in ("ok", "unknown"):
            text = speed if (k == "line" and status == "ok") else ""
        stations.append({"id": k, "name": names[k], "status": status, "word": STATUS_WORD[status], "text": text,
                         "broken": k == broken})
        after = after or k == broken
    return {"stations": stations, "broken": broken}


def _hero(open_incs: list[Incident], now: float) -> str:
    if not open_incs:
        return "All good."
    worst = sorted(open_incs, key=lambda i: (i.severity != "high", i.opened_at))[0]
    head, sep, rest = worst.title.partition(": ")
    what = f"on {head}: {rest}" if sep else f": {worst.title}"
    since = fmt_duration(now - worst.opened_at)
    n = len(open_incs)
    if n == 1:
        return f"1 problem {what}, for {since}.".replace("problem :", "problem:")
    return f"{n} problems. Most urgent {what}, for {since}.".replace("urgent :", "urgent:")


def build_overview(db: Database, settings, now: float, tz: ZoneInfo) -> dict:
    cfg = settings.config
    hosts = known_hosts(settings)
    all_open = db.open_incidents()
    mutes = db.mutes_active(now)
    # muted incidents stay listed (grey "muted") but colour nothing
    open_incs = [i for i in all_open if (i.rule, i.key) not in mutes]
    svc_hosts = service_hosts(db, cfg)
    by_tile: dict[str, list[Incident]] = {}
    for inc in open_incs:
        by_tile.setdefault(tile_of(inc, hosts, cfg, svc_hosts) or "other", []).append(inc)

    tiles = []
    if _probe_state(db, [t.name for t in cfg.internet.ping_targets], now) is None:
        st, txt = "unknown", "No measurements yet"
    else:
        prev = db.last_resolved("internet_down", "internet")
        st = "ok"
        txt = (f"Up, no outage for {fmt_duration(now - prev.resolved_at)}" if prev
               else "Up, no outages known")
    tiles.append(_tile("internet", "Internet", "/internet", by_tile.get("internet", []), st, txt))
    for h in hosts:
        st, txt = _host_ok_text(db, settings, h, now)
        tiles.append(_tile(h, cfg.name_of(h), f"/device/{h}", by_tile.get(h, []), st, txt))
    fz = db.latest_fritz() if cfg.router.polls_tr064 else None
    p = _last_probe(db, "router", now)
    if fz and fz.get("ok") and now - fz["ts"] <= FRESH_S:
        st, txt = "ok", "Up"
        if fz.get("downstream_kbps"):
            txt += f", line {fz['downstream_kbps'] // 1000}/{(fz.get('upstream_kbps') or 0) // 1000} Mbit/s"
    elif p is not None and p[1]:
        st = "ok"
        txt = "Reachable" + (" (no credentials for details)" if fz and fz.get("error") == ERR_NO_USER else "")
    else:
        st, txt = "unknown", "No measurements yet"
    tiles.append(_tile("router", cfg.router.display_name, "/internet", by_tile.get("router", []), st, txt))
    if by_tile.get("other"):
        tiles.append(_tile("other", "Other", "/incidents", by_tile["other"], "ok", ""))

    if any(i.severity == "high" for i in open_incs):
        status = "bad"
    elif open_incs:
        status = "warn"
    else:
        status = "ok"
    # open incidents, then at most 3 resolved in the last 7 days
    recent = [i for i in db.list_incidents(limit=20)
              if i.resolved_at is not None and i.resolved_at >= now - RECENT_RESOLVED_S][:RECENT_RESOLVED_MAX]
    incidents = []
    for inc in sorted(all_open, key=lambda i: -i.opened_at) + recent:
        v = incident_view(inc, now, tz, mutes)
        incidents.append({k: v[k] for k in ("id", "title", "status", "open", "when", "line", "duration", "times",
                                            "confidence", "muted")}
                         | {"word": STATUS_WORD[v["status"]], "summary": v["summary"] if v["open"] else ""})
    return {"status": status, "word": STATUS_WORD[status], "headline": _hero(open_incs, now), "tiles": tiles,
            "chain": build_chain(db, cfg, now, open_incs), "incidents": incidents, "updated": now}


# -- helpers for handlers -------------------------------------------------------------
def _page(request: Request, name: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    base = {"nav": ctx.pop("nav", ""), "STATUS_WORD": STATUS_WORD}
    return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status_code)


def _not_found(request: Request, what: str) -> HTMLResponse:
    return _page(request, "base.html", {"title": "Not found", "missing": what}, status_code=404)


def _check_origin(request: Request) -> None:
    """Refuse cross-site form posts (the dashboard has no login). The Host
    header must be one of ours too: a rebound DNS name would pass the Origin
    check because Origin and Host then agree."""
    host = (request.headers.get("host") or "").lower()
    if host not in request.app.state.settings.form_hosts():
        raise HTTPException(status_code=403, detail="request for a foreign host name refused")
    origin = request.headers.get("origin")
    if origin is not None and urlparse(origin).netloc != request.headers.get("host"):
        raise HTTPException(status_code=403, detail="cross-site request refused")


async def _form(request: Request) -> dict[str, list[str]]:
    _check_origin(request)
    body = await request.body()
    if len(body) > 64 * 1024:
        raise HTTPException(status_code=413)
    return parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)


def _one(form: dict, key: str) -> str:
    return (form.get(key) or [""])[0].strip()


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


# -- pages ------------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def overview_page(request: Request):
    db, settings = request.app.state.db, request.app.state.settings
    ov = build_overview(db, settings, time.time(), _tz(request))
    return _page(request, "overview.html", {"nav": "overview", "title": "Overview", "ov": ov})


@router.get("/api/v1/ui/overview")
def overview_api(request: Request) -> dict:
    return build_overview(request.app.state.db, request.app.state.settings, time.time(), _tz(request))


@router.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request):
    db, settings = request.app.state.db, request.app.state.settings
    ov = build_overview(db, settings, time.time(), _tz(request))
    return _page(request, "devices.html", {"nav": "devices", "title": "Devices", "ov": ov})


@router.get("/incidents", response_class=HTMLResponse)
def incidents_page(request: Request, page: int = 1):
    db, tz, now = request.app.state.db, _tz(request), time.time()
    per = 50
    page = max(1, min(page, 10_000))
    total = db.count_incidents()
    mutes = db.mutes_active(now)
    items = [incident_view(i, now, tz, mutes) for i in db.list_incidents(limit=per, offset=(page - 1) * per)]
    return _page(request, "incidents.html", {"nav": "incidents", "title": "Incidents", "items": items,
                                             "page": page, "more": page * per < total})


@router.get("/incident/{inc_id}", response_class=HTMLResponse)
def incident_page(request: Request, inc_id: int, ok: str | None = None, error: str | None = None):
    db, tz, now = request.app.state.db, _tz(request), time.time()
    inc = db.get_incident(inc_id)
    if inc is None:
        return _not_found(request, "This incident does not exist (any more).")
    v = incident_view(inc, now, tz, db.mutes_active(now))
    diag = v["diag"]
    facts = json.dumps(diag.get("facts"), ensure_ascii=False, indent=1) if diag and diag.get("facts") else ""
    muted = (inc.rule, inc.key) in db.mutes_active(now)
    return _page(request, "incident.html", {
        "nav": "incidents", "title": inc.title, "inc": v, "facts": facts, "muted": muted,
        "durations": MUTE_DURATIONS, "saved": SAVED.get(ok or ""), "error": ERRORS.get(error or ""),
        "back": f"/incident/{inc.id}", "model": model_label(diag.get("model")) if diag else "",
    })


@router.get("/internet", response_class=HTMLResponse)
def internet_page(request: Request):
    db, tz, now = request.app.state.db, _tz(request), time.time()
    cfg = _cfg(request)
    since = now - OUTAGE_DAYS * 86400
    names, texts = cause_names(cfg), attribution_text(cfg)
    outages = []
    incs = db.incidents_since("internet_down", since)
    for inc in incs:
        end = inc.resolved_at or now
        who = outage_attribution(db, cfg, inc.opened_at - 60, end)
        outages.append({**incident_view(inc, now, tz), "who": names[who], "who_text": texts[who]})
    # daily bars, local days, today last
    today = datetime.fromtimestamp(now, tz).date()
    days = []
    for back in range(OUTAGE_DAYS - 1, -1, -1):
        d = today - timedelta(days=back)
        lo = datetime(d.year, d.month, d.day, tzinfo=tz).timestamp()
        hi = (datetime(d.year, d.month, d.day, tzinfo=tz) + timedelta(days=1)).timestamp()
        secs = sum(max(0.0, min(i.resolved_at or now, hi) - max(i.opened_at, lo)) for i in incs)
        n = sum(1 for i in incs if i.opened_at < hi and (i.resolved_at or now) > lo)
        days.append({"label": f"{d.month}/{d.day}", "secs": secs, "count": n,
                     "text": "no outages" if n == 0 else f"{plural(n, 'outage', 'outages')}, {fmt_duration(secs)}"})
    peak = max((d["secs"] for d in days), default=0) or 1
    for d in days:
        d["pct"] = 0 if d["secs"] == 0 else max(4, round(d["secs"] * 100 / peak))
    open_now = any(i.resolved_at is None for i in incs)
    fz = db.latest_fritz() if cfg.router.polls_tr064 else None
    return _page(request, "internet.html", {
        "nav": "internet", "title": "Internet history", "outages": outages, "days": days, "open_now": open_now,
        "fritz": fz if fz and fz.get("ok") else None, "total": len(incs),
        "total_time": fmt_duration(sum((i.resolved_at or now) - i.opened_at for i in incs)),
    })


@router.get("/device/{host}", response_class=HTMLResponse)
def device_page(request: Request, host: str, period: str = Query("24h", alias="range")):
    db, settings, tz, now = request.app.state.db, request.app.state.settings, _tz(request), time.time()
    cfg = settings.config
    if host not in known_hosts(settings):
        return _not_found(request, "LANOT does not know this device.")
    rng = period if period in SERIES_RANGES else "24h"
    last = db.last_received(host)
    m = db.latest_metrics(host)
    s = db.latest_state(host)
    probe = _last_probe(db, host, now)
    errors = [{**r, "when": fmt_time(r["ts"], tz, now), "sev": SEVERITY_WORD.get(r["severity"], str(r["severity"]))}
              for r in db.search_logs(None, host=host, since=now - 7 * 86400, max_severity=3, limit=20)]
    hosts = known_hosts(settings)
    svc_hosts = service_hosts(db, cfg)
    mutes = db.mutes_active(now)
    incs = [incident_view(i, now, tz, mutes) for i in db.open_incidents()
            if tile_of(i, hosts, cfg, svc_hosts) == host]
    important = set(db.get_setting("important_containers", []) or [])
    containers = []
    if s is not None:
        for c in sorted(s.containers, key=lambda c: c.name.lower()):
            if c.health == "unhealthy":
                st, word = "bad", "unhealthy"
            elif c.status == "running":
                st, word = "ok", "running"
            elif c.status == "restarting":
                st, word = "warn", "restarting"
            elif c.status in ("exited", "dead"):
                st, word = "unknown", "stopped"
            else:
                st, word = "unknown", c.status
            containers.append({"name": c.name, "status": st, "word": word, "restarts": c.restarts,
                               "important": f"{host}/{c.name}" in important})
    fs = [{"mount": f.mount, "pct": f.pct, "used": fmt_bytes(f.used), "total": fmt_bytes(f.total),
           "status": "bad" if f.pct >= 95 else "warn" if f.pct >= 90 else "ok"} for f in (m.filesystems if m else [])]
    fresh = last is not None and now - last <= FRESH_S
    # compact summary: one status line plus a few figures
    if probe is None:
        reach = "no measurement"
    elif probe[1]:
        reach = "reachable" + (f", {fmt_num(probe[2], 0 if probe[2] >= 10 else 1)} ms" if probe[2] else "")
    else:
        reach = "unreachable"
    loud = [i for i in incs if not i["muted"]]
    if loud:
        status = loud[0]["status"]
    elif fresh or (probe and probe[1]):
        status = "ok"
    else:
        status = "unknown"
    agent = host in settings.agent_tokens or bool((h := cfg.host(host)) and h.agent)
    figures: list[tuple[str, str]] = []
    if m is not None:
        figures.append(("CPU", f"{fmt_num(m.cpu_pct)}%"))
        if m.mem_total:
            figures.append(("Memory", f"{fmt_num(m.mem_used * 100 / m.mem_total)}%"))
        labels = temp_labels(m.temps)
        cpu_t = [v for k, v in m.temps.items() if labels[k][1] == "cpu"]
        if cpu_t:
            figures.append(("CPU temperature", f"{fmt_num(max(cpu_t))} °C"))
        disk_t = [(v, labels[k][0]) for k, v in m.temps.items() if labels[k][1] == "disk"]
        if disk_t:
            v, name = max(disk_t)
            figures.append((f"Temperature {name}", f"{fmt_num(v)} °C"))
        days = m.uptime_s // 86400
        figures.append(("Up for", (f"{days} {'day' if days == 1 else 'days'}" if days
                                   else fmt_duration(m.uptime_s))))
        if m.power is not None and not m.power.ac_online:
            batt = f", {fmt_num(m.power.battery_pct)}%" if m.power.battery_pct is not None else ""
            figures.append(("Power", "battery" + batt))
    if not fresh and agent:
        figures.append(("Last data", fmt_time(last, tz, now) if last else "none yet"))
    open_c = any(c["status"] in ("bad", "warn") for c in containers)
    open_p = bool(s and any(p.health != "ONLINE" for p in s.pools))
    open_d = bool(s and any(not d.smart_passed for d in s.disks))
    return _page(request, "device.html", {
        "nav": "devices", "title": cfg.name_of(host), "host": host, "name": cfg.name_of(host), "s": s,
        "status": status, "reach": reach, "figures": figures,
        "errors": errors, "incs": incs, "containers": containers, "fs": fs,
        "open_containers": open_c, "open_pools": open_p, "open_disks": open_d,
        "range": rng, "agent": agent,
    })


@router.get("/api/v1/ui/series/{host}")
def series_api(request: Request, host: str, period: str = Query("24h", alias="range")) -> dict:
    db, settings = request.app.state.db, request.app.state.settings
    if host not in known_hosts(settings):
        raise HTTPException(status_code=404, detail="unknown device")
    span, step = SERIES_RANGES.get(period, SERIES_RANGES["24h"])
    rows = db.metrics_sampled(host, time.time() - span, step)
    ts, cpu, mem = [], [], []
    temps: dict[str, list] = {}
    disks: dict[str, list] = {}
    for i, (received, d) in enumerate(rows):
        ts.append(round(received))
        cpu.append(d.get("cpu_pct"))
        total = d.get("mem_total") or 0
        mem.append(round(d.get("mem_used", 0) * 100 / total, 1) if total else None)
        names = temp_labels(d.get("temps") or {})
        for key, val in (d.get("temps") or {}).items():
            temps.setdefault(names[key][0], [None] * i).append(val)
        for f in d.get("filesystems") or []:
            pct = round(f["used"] * 100 / f["total"], 1) if f.get("total") else 0.0
            disks.setdefault(f["mount"], [None] * i).append(pct)
        for series in (*temps.values(), *disks.values()):
            if len(series) < i + 1:
                series.append(None)
    return {"ts": ts, "cpu": cpu, "mem": mem, "temps": temps, "disks": disks}


@router.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, q: str = "", host: str = "", period: str = Query("24h", alias="range"),
              severity: str = "all"):
    db, settings, tz, now = request.app.state.db, request.app.state.settings, _tz(request), time.time()
    cfg = settings.config
    hosts = known_hosts(settings)
    q = q[:200]
    host = host if host in hosts else ""
    rng = period if period in LOG_RANGES else "24h"
    severity = severity if severity in LOG_SEVERITIES else "all"
    rows = db.search_logs(q or None, host=host or None, since=now - LOG_RANGES[rng][0],
                          max_severity=LOG_SEVERITIES[severity][0], limit=200)
    lines = [{**r, "when": fmt_time(r["ts"], tz, now), "name": cfg.name_of(r["host"]),
              "sev": SEVERITY_WORD.get(r["severity"], str(r["severity"])),
              "status": "bad" if r["severity"] <= 3 else "warn" if r["severity"] == 4 else "unknown"}
             for r in rows]
    return _page(request, "logs.html", {
        "nav": "logs", "title": "Log search", "q": q, "host": host, "range": rng, "severity": severity,
        "hosts": [(h, cfg.name_of(h)) for h in hosts], "ranges": LOG_RANGES, "severities": LOG_SEVERITIES,
        "lines": lines,
    })


# -- settings ---------------------------------------------------------------------------
def _reserved_names(cfg) -> set[str]:
    return {t.name for t in default_targets(cfg, gateway="0.0.0.0")} | set(RESERVED_IDS)


def _mute_options(db: Database, cfg) -> list[tuple[str, str]]:
    opts: dict[tuple[str, str], str] = {("internet_down", "internet"): "Internet down"}
    for t in default_targets(cfg):
        if t.kind == "icmp" and t.name not in cfg.internet.target_names:
            opts[("device_down", t.name)] = f"{cfg.name_of(t.name)} unreachable"
    for svc in db.get_setting("important_services", []) or []:
        opts[("service_down", svc["name"])] = f"Service {svc['name']} unreachable"
    for c in db.get_setting("important_containers", []) or []:
        opts[("container_bad", c)] = f"Container {c} not running"
    for inc in db.list_incidents(limit=300):
        opts.setdefault((inc.rule, inc.key), inc.title)
    return [(f"{r}|{k}", label) for (r, k), label in sorted(opts.items(), key=lambda x: x[1].lower())]


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, ok: str | None = None, error: str | None = None):
    db, settings, tz, now = request.app.state.db, request.app.state.settings, _tz(request), time.time()
    cfg = settings.config
    services = db.get_setting("important_services", []) or []
    important = list(db.get_setting("important_containers", []) or [])
    known: list[str] = []
    for h in known_hosts(settings):
        s = db.latest_state(h)
        if s is not None:
            known += [f"{h}/{c.name}" for c in s.containers]
    containers = sorted(set(known) | set(important), key=str.lower)
    thresholds = {**DEFAULT_THRESHOLDS, **(db.get_setting("thresholds", {}) or {})}
    titles = {(i.rule, i.key): i.title for i in reversed(db.list_incidents(limit=300))}
    mutes = []
    for mu in db.list_mutes(now):
        label = (titles.get((mu["rule"], mu["key"]))
                 or f"{RULE_LABELS.get(mu['rule'], mu['rule'])}: {cfg.name_of(mu['key'])}")
        forever = mu["until"] - now > 5 * 365 * 86400
        mutes.append({**mu, "label": label, "until_text": "until further notice" if forever
                      else "until " + fmt_time(mu["until"], tz, now)})
    return _page(request, "settings.html", {
        "nav": "settings", "title": "Settings", "services": services, "containers": containers,
        "important": set(important), "thresholds": thresholds, "fields": THRESHOLD_FIELDS, "mutes": mutes,
        "mute_options": _mute_options(db, cfg), "durations": MUTE_DURATIONS,
        "saved": SAVED.get(ok or ""), "error": ERRORS.get(error or ""),
    })


def _validate_service(form: dict, existing: list[dict], cfg) -> tuple[dict | None, str | None]:
    name = _one(form, "name").lower()
    kind = _one(form, "kind")
    address = _one(form, "address")
    port_raw = _one(form, "port")
    if len(existing) >= MAX_SERVICES:
        return None, "service_full"
    if not _SERVICE_NAME_RE.match(name):
        return None, "service_name"
    if name in _reserved_names(cfg) or any(s.get("name") == name for s in existing):
        return None, "service_taken"
    if kind not in ("tcp", "http"):
        return None, "service_kind"
    try:
        ipaddress.ip_address(address)
    except ValueError:
        if not _HOSTNAME_RE.match(address):
            return None, "service_address"
    port = None
    if port_raw:
        if not port_raw.isdigit() or not 1 <= int(port_raw) <= 65535:
            return None, "service_port"
        port = int(port_raw)
    elif kind == "tcp":
        return None, "service_port"
    return {"name": name, "kind": kind, "address": address, "port": port}, None


@router.post("/settings/services")
async def add_service(request: Request):
    form = await _form(request)
    db, cfg = request.app.state.db, _cfg(request)

    def apply():
        existing = db.get_setting("important_services", []) or []
        svc, err = _validate_service(form, existing, cfg)
        if err:
            return err
        db.set_setting("important_services", [*existing, svc])
        return None

    err = await run_in_threadpool(apply)
    return _redirect(f"/settings?error={err}#services" if err else "/settings?ok=1#services")


@router.post("/settings/services/delete")
async def delete_service(request: Request):
    form = await _form(request)
    db = request.app.state.db
    name = _one(form, "name")

    def apply():
        existing = db.get_setting("important_services", []) or []
        db.set_setting("important_services", [s for s in existing if s.get("name") != name])

    await run_in_threadpool(apply)
    return _redirect("/settings?ok=1#services")


@router.post("/settings/containers")
async def set_containers(request: Request):
    form = await _form(request)
    db, settings = request.app.state.db, request.app.state.settings
    hosts = set(known_hosts(settings))
    wanted: list[str] = []
    for raw in form.get("c", []):
        m = _CONTAINER_RE.match(raw.strip())
        if not m or m.group(1) not in hosts:
            return _redirect("/settings?error=containers#containers")
        if raw.strip() not in wanted:
            wanted.append(raw.strip())
    await run_in_threadpool(db.set_setting, "important_containers", wanted)
    return _redirect("/settings?ok=1#containers")


@router.post("/settings/thresholds")
async def set_thresholds(request: Request):
    form = await _form(request)
    db = request.app.state.db
    values = {}
    for key, (_, _, lo, hi) in THRESHOLD_FIELDS.items():
        try:
            v = float(_one(form, key))
        except ValueError:
            return _redirect("/settings?error=thresholds#thresholds")
        if not lo <= v <= hi:  # also rejects nan
            return _redirect("/settings?error=thresholds#thresholds")
        values[key] = v
    if values["disk_warn"] >= values["disk_high"]:
        return _redirect("/settings?error=thresholds#thresholds")
    await run_in_threadpool(db.set_setting, "thresholds", values)
    return _redirect("/settings?ok=1#thresholds")


def _mute_target(form: dict) -> tuple[str, str]:
    target = _one(form, "target")
    if target:
        rule, _, key = target.partition("|")
        return rule, key
    return _one(form, "rule"), _one(form, "key")


@router.post("/settings/mute")
async def mute(request: Request):
    form = await _form(request)
    db, cfg = request.app.state.db, _cfg(request)
    rule, key = _mute_target(form)
    back = _one(form, "back")
    target = back if _BACK_RE.match(back) else "/settings"
    duration = _one(form, "duration")
    if (rule not in RULE_LABELS or not 1 <= len(key) <= 200 or not key.isprintable()
            or duration not in MUTE_DURATIONS):
        return _redirect(f"{target}?error=mute#mute")

    def apply() -> bool:
        # only something the server knows: an existing incident or an offered option
        known = db.has_incident(rule, key) or f"{rule}|{key}" in {v for v, _ in _mute_options(db, cfg)}
        if known:
            db.set_mute(rule, key, time.time() + MUTE_DURATIONS[duration][0])
        return known

    if not await run_in_threadpool(apply):
        return _redirect(f"{target}?error=mute#mute")
    return _redirect(f"{target}?ok=muted#mute")


@router.post("/settings/mute/clear")
async def unmute(request: Request):
    form = await _form(request)
    db = request.app.state.db
    rule, key = _mute_target(form)
    back = _one(form, "back")
    target = back if _BACK_RE.match(back) else "/settings"
    await run_in_threadpool(db.clear_mute, rule, key)
    return _redirect(f"{target}?ok=unmuted#mute")
