"""Fixed fact gathering (no AI) and the shared result types.

The fact bundle is always stored with the diagnosis, even when no model is
reachable. Every part is collected defensively: one failing source must not
lose the others.
"""

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ..db import Database, Incident
from ..pinger import default_targets, probe as default_probe
from .tools import TRACEROUTE_TIMEOUT_S, redact_obj

log = logging.getLogger(__name__)

WINDOW_S = 600  # logs/probes/metrics ±10 min around opened_at
MAX_LOG_LINES = 300
MAX_HOST_LOG_LINES = 100  # extra lines of the incident's own host
MAX_LOG_SEVERITY = 4
MAX_LOG_MESSAGE = 500
MAX_PROBES_PER_TARGET = 60
METRIC_FIELDS = ("cpu_pct", "load1", "mem_used", "mem_total", "net_rx_bps", "net_tx_bps", "temps.cpu",
                 "uptime_s", "power.ac_online", "power.battery_pct")

CONFIDENCE = ("certain", "likely", "unclear")
Confidence = Literal["certain", "likely", "unclear"]
Run = Callable[[list[str], float], Awaitable[tuple[int, str, str]]]


async def run_process(argv: list[str], timeout: float) -> tuple[int, str, str]:
    """Run argv (no shell); raises TimeoutError after `timeout` s (process killed)."""
    proc = await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except BaseException:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        raise
    return proc.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


@dataclass
class Deps:
    db: Database
    config: Any = None  # LanotConfig; None = empty layout
    fritz: Any = None  # FritzPoller or None
    probe: Callable = default_probe
    run: Run = run_process
    anthropic: Any = None  # AsyncAnthropic-like client; None = built from settings
    ollama_post: Callable | None = None  # async (url, payload) -> response json; None = httpx


@dataclass
class Diagnosis:
    summary: str
    what_happened: str
    cause: str
    confidence: Confidence
    suggestions: list[str]
    evidence: list[str]
    model: str
    tool_calls: int
    duration_s: float


# The part of Diagnosis a model fills in (final_diagnosis tool / Ollama format).
DIAGNOSIS_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "1-2 sentences for the push notification"},
        "what_happened": {"type": "string", "description": "What happened (facts)"},
        "cause": {"type": "string", "description": "Probable cause"},
        "confidence": {"type": "string", "enum": list(CONFIDENCE)},
        "suggestions": {"type": "array", "items": {"type": "string"},
                        "description": "What the user could check (checks only, no changes)"},
        "evidence": {"type": "array", "items": {"type": "string"},
                     "description": "Concrete evidence (log lines, metrics, test results)"},
    },
    "required": ["summary", "what_happened", "cause", "confidence", "suggestions", "evidence"],
    "additionalProperties": False,
}


def diagnosis_from(data: dict, model: str, tool_calls: int, duration_s: float) -> Diagnosis:
    """Build a Diagnosis from model output; tolerates sloppy types, needs a summary."""
    if not isinstance(data, dict):
        raise ValueError("diagnosis is not an object")
    summary = str(data.get("summary") or "").strip()
    if not summary:
        raise ValueError("diagnosis without summary")
    conf = data.get("confidence")
    if conf not in CONFIDENCE:
        conf = "unclear"

    def strs(v) -> list[str]:
        if isinstance(v, str):
            return [v]
        return [str(x) for x in v] if isinstance(v, list) else []

    return Diagnosis(summary=summary, what_happened=str(data.get("what_happened") or ""),
                     cause=str(data.get("cause") or ""), confidence=conf,
                     suggestions=strs(data.get("suggestions")), evidence=strs(data.get("evidence")),
                     model=model, tool_calls=tool_calls, duration_s=round(duration_s, 2))


@dataclass
class FactBundle:
    incident: dict
    probes: dict[str, list] = field(default_factory=dict)
    fritz: dict = field(default_factory=dict)
    fritz_log: list[str] = field(default_factory=list)
    logs: list[dict] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    traceroute: str = ""

    def to_dict(self) -> dict:
        """Redacted copy, safe to send out and to store."""
        return redact_obj(asdict(self))

    def to_text(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=1)


def host_of_key(key: str, cfg) -> str | None:
    """`nas`, `nas:/mnt` and `nas/web` all belong to host nas (if it is configured)."""
    head = str(key or "").replace("/", ":").split(":", 1)[0]
    return head if cfg is not None and cfg.host(head) is not None else None


def incident_host(inc: Incident, cfg) -> str | None:
    return host_of_key(inc.key, cfg)


async def _safe(what: str, coro, default):
    try:
        return await coro
    except Exception as e:
        log.warning("fact %s failed: %s", what, type(e).__name__)
        return default


async def _probes(db: Database, cfg, lo: float, hi: float) -> dict[str, list]:
    out = {}
    names = [t.name for t in default_targets(cfg)] if cfg is not None else []
    if "gateway" not in names:
        names.append("gateway")  # discovered at runtime, not part of the static list
    for name in names:
        rows = await asyncio.to_thread(db.probes, name, lo)
        rows = [[ts, ok, rtt] for ts, ok, rtt in rows if ts <= hi][-MAX_PROBES_PER_TARGET:]
        if rows:
            out[name] = rows
    return out


async def _metrics(db: Database, host: str | None, lo: float, hi: float) -> dict:
    if not host:
        return {}
    out = {}
    for f in METRIC_FIELDS:
        series = await asyncio.to_thread(db.metrics_series, host, f, lo)
        series = [[ts, v] for ts, v in series if ts <= hi]
        if series:
            out[f] = series
    return {"host": host, "series": out} if out else {}


async def _traceroute(run: Run, target: str) -> str:
    try:
        rc, out, err = await run(["traceroute", "-n", "-w", "2", "-m", "15", target], TRACEROUTE_TIMEOUT_S)
    except Exception as e:
        return f"traceroute failed: {type(e).__name__}"
    return (out + err).strip() or "traceroute gave no output"


async def collect_facts(incident: Incident, deps: Deps) -> FactBundle:
    db = deps.db
    lo, hi = incident.opened_at - WINDOW_S, incident.opened_at + WINDOW_S
    inc = {k: v for k, v in asdict(incident).items() if k != "diagnosis_json"}
    fritz = deps.fritz

    async def fritz_state():
        if fritz is not None:
            return await asyncio.to_thread(fritz.poll)
        return await asyncio.to_thread(db.latest_fritz) or {}

    async def fritz_events():
        return await asyncio.to_thread(fritz.event_log, lo) if fritz is not None else []

    cfg = deps.config
    host = incident_host(incident, cfg)
    trace_target = cfg.internet.trace_target if cfg is not None else "1.1.1.1"

    async def logs():
        rows = await asyncio.to_thread(db.search_logs, None, since=lo, until=hi,
                                       max_severity=MAX_LOG_SEVERITY, limit=MAX_LOG_LINES)
        if host:  # other hosts' chatter must not crowd out the incident host's own lines
            own = await asyncio.to_thread(db.search_logs, None, host=host, since=lo, until=hi,
                                          max_severity=MAX_LOG_SEVERITY, limit=MAX_HOST_LOG_LINES)
            seen = {r["id"] for r in rows}
            rows = sorted(rows + [r for r in own if r["id"] not in seen], key=lambda r: (-r["ts"], -r["id"]))
        return list(reversed(rows))  # oldest first

    probes, fstate, fevents, log_rows, metrics, trace = await asyncio.gather(
        _safe("probes", _probes(db, cfg, lo, hi), {}),
        _safe("fritz", fritz_state(), {}),
        _safe("fritz_log", fritz_events(), []),
        _safe("logs", logs(), []),
        _safe("metrics", _metrics(db, host, lo, hi), {}),
        _traceroute(deps.run, trace_target),
    )
    b = FactBundle(incident=inc, probes=probes, fritz=fstate, fritz_log=fevents, logs=log_rows,
                   metrics=metrics, traceroute=trace)
    d = b.to_dict()  # redacted from here on; clip after redaction so no secret is cut in half
    for row in d["logs"]:
        if isinstance(row.get("message"), str) and len(row["message"]) > MAX_LOG_MESSAGE:
            row["message"] = row["message"][: MAX_LOG_MESSAGE - 1] + "…"
    return FactBundle(**d)
