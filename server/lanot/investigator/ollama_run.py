"""Local fallback: one Ollama /api/chat call with a JSON-schema format, no tools."""

import datetime as dt
import json
import logging
import time
from collections.abc import Awaitable, Callable

import httpx

from .facts import DIAGNOSIS_SCHEMA, Diagnosis, diagnosis_from, host_of_key

log = logging.getLogger(__name__)

OLLAMA_TIMEOUT_S = 120.0

OLLAMA_SYSTEM = (
    "You are the investigator of LANOT, a monitoring system for a small local network. You get a fact "
    "bundle about an incident and explain the probable cause in plain English that a non-expert can follow. "
    "Answer in English only. Rely only on the facts given. If the facts are not enough, say so. "
    "Do not invent anything and do not mention anything that is not in the facts. You changed nothing and "
    "you only suggest checks, never changes. Keep facts apart from assumptions and set confidence honestly "
    "(likely or unclear). Answer only with JSON following this schema: " + json.dumps(DIAGNOSIS_SCHEMA)
)

LOCAL_NOTE = "(Assessment by the local model, made without internet access. Please verify.)"

NUM_CTX = 8192  # Ollama's default of 4096 tokens cut the full JSON bundle; the prompt below is compact
PROMPT_LOG_LINES = 40
PROMPT_LOG_SEVERITY = 4
PROMPT_LINE_CHARS = 300
PROMPT_FRITZ_EVENTS = 10
PROMPT_TRACE_LINES = 15

INSTRUCTION = (
    "Task: explain the incident above for a non-expert. Answer in English only. "
    "Answer only from the facts above. If the facts are not enough, say so. Do not invent anything. "
    "Suggest only checks, no changes. confidence is likely or unclear. "
    "Answer only with one JSON object following this schema:\n"
)


def _clip(text, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _utc(ts) -> str:
    if not isinstance(ts, (int, float)):
        return str(ts)
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _probe_lines(probes: dict) -> list[str]:
    out = []
    for target, rows in sorted(probes.items()):
        oks = [bool(r[1]) for r in rows if isinstance(r, (list, tuple)) and len(r) >= 2]
        if oks:
            out.append(f"- {target}: {sum(oks)}/{len(oks)} ok" + ("" if oks[-1] else ", last one failed"))
    return out


def _fritz_line(f: dict) -> str:
    if not f:
        return "no data"
    if not f.get("ok"):
        return f"cannot be queried ({_clip(f.get('error') or 'unknown', 120)})"

    def yn(v):
        return "?" if v is None else ("yes" if v else "no")
    speed = ""
    if f.get("downstream_kbps"):
        speed = f", line {f['downstream_kbps'] // 1000}/{(f.get('upstream_kbps') or 0) // 1000} Mbit/s"
    return (f"line in sync {yn(f.get('link_up'))}, internet connected {yn(f.get('wan_connected'))}, "
            f"external IP {'present' if f.get('external_ip') else 'none'}{speed}")


def _metric_line(metrics: dict) -> str:
    series = (metrics or {}).get("series") or {}

    def vals(name):
        return [v for _, v in series.get(name, []) if isinstance(v, (int, float))]
    parts = []
    if cpu := vals("cpu_pct"):
        parts.append(f"CPU max {max(cpu):.0f}%")
    if load := vals("load1"):
        parts.append(f"load max {max(load):.1f}")
    used, total = vals("mem_used"), vals("mem_total")
    if used and total and total[-1]:
        parts.append(f"memory {used[-1] * 100 / total[-1]:.0f}%")
    if temp := vals("temps.cpu"):
        parts.append(f"CPU temperature max {max(temp):.0f} °C")
    if up := vals("uptime_s"):
        parts.append(f"uptime {up[-1] / 3600:.1f} h")
    if ac := vals("power.ac_online"):
        parts.append("mains power " + ("on" if ac[-1] else "off"))
    if batt := vals("power.battery_pct"):
        parts.append(f"battery min {min(batt):.0f}%")
    if not parts:
        return "none"
    return f"{metrics.get('host', '?')}: " + ", ".join(parts)


def build_user_prompt(bundle, cfg=None) -> str:
    """Compact prompt for a small local model: summaries instead of the raw
    JSON bundle (that one is stored and shown in the dashboard). The task and
    the schema come last, right before the answer."""
    inc = bundle.incident or {}
    host = host_of_key(inc.get("key"), cfg)
    lines = [
        f"Incident: {inc.get('title', '?')}",
        f"Rule: {inc.get('rule', '?')}",
        f"Host/key: {inc.get('key', '?')}",
        f"Severity: {inc.get('severity', '?')}",
        f"Started: {_utc(inc.get('opened_at'))}",
        f"Status: {'resolved ' + _utc(inc.get('resolved_at')) if inc.get('resolved_at') else 'open'}"
        + (f", down {inc['flap_count'] + 1} times" if inc.get("flap_count") else ""),
    ]
    if inc.get("detail"):
        lines.append(f"Detail: {_clip(inc['detail'], 300)}")
    lines += ["", "Reachability (pings and checks, 10 min before and after the start):",
              *(_probe_lines(bundle.probes or {}) or ["- no measurements"])]
    if bundle.fritz:
        lines += ["", f"FritzBox: {_fritz_line(bundle.fritz)}"]
    events = list(bundle.fritz_log or [])[-PROMPT_FRITZ_EVENTS:]
    if events:
        lines += ["FritzBox events (newest last):", *(f"- {_clip(e, 200)}" for e in events)]
    lines += ["", f"Metrics: {_metric_line(bundle.metrics or {})}"]
    trace = [l for l in str(bundle.traceroute or "").splitlines() if l.strip()][:PROMPT_TRACE_LINES]
    if trace:
        lines += ["", "Traceroute:", *(_clip(l, 120) for l in trace)]
    if host:
        rows = [r for r in (bundle.logs or []) if r.get("host") == host
                and isinstance(r.get("severity"), int) and r["severity"] <= PROMPT_LOG_SEVERITY]
        rows = rows[-PROMPT_LOG_LINES:]
        lines += ["", f"Log lines of {host} (severity <= {PROMPT_LOG_SEVERITY}, at most {PROMPT_LOG_LINES}, "
                  "newest last):"]
        lines += [f"- {_utc(r.get('ts'))[11:19]} [{r.get('severity')}] {r.get('source', '')}: "
                  f"{_clip(r.get('message', ''), PROMPT_LINE_CHARS)}" for r in rows] or ["- none"]
    else:
        lines += ["", "Log lines: none (the incident does not concern a single host)"]
    lines += ["", INSTRUCTION + json.dumps(DIAGNOSIS_SCHEMA)]
    return "\n".join(lines)


Post = Callable[[str, dict], Awaitable[dict]]


async def _httpx_post(url: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_S) as c:
        r = await c.post(url, json=payload)
        r.raise_for_status()
        return r.json()


async def run_ollama(bundle, settings, *, post: Post | None = None) -> Diagnosis:
    started = time.monotonic()
    payload = {
        "model": settings.ollama_model,
        "messages": [
            {"role": "system", "content": OLLAMA_SYSTEM},
            {"role": "user", "content": build_user_prompt(bundle, settings.config)},
        ],
        "format": DIAGNOSIS_SCHEMA,
        "stream": False,
        "options": {"num_ctx": NUM_CTX},
    }
    data = await (post or _httpx_post)(settings.ollama_url.rstrip("/") + "/api/chat", payload)
    used = data.get("prompt_eval_count") if isinstance(data, dict) else None
    if isinstance(used, int) and used >= NUM_CTX - 16:
        log.warning("Ollama prompt probably truncated: prompt_eval_count=%d, num_ctx=%d", used, NUM_CTX)
    content = json.loads(data["message"]["content"])
    d = diagnosis_from(content, settings.ollama_model, 0, time.monotonic() - started)
    if d.confidence == "certain":  # a local model without tools never gets to claim certainty
        d.confidence = "likely"
    d.what_happened = (d.what_happened + " " + LOCAL_NOTE).strip()
    return d
