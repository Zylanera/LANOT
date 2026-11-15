"""Read-only tools of the investigator and secret redaction.

Every tool returns text that is redacted and truncated before it can reach
the model. host_cmd goes over SSH with a key the hosts force onto `lanot-ro`
(the real allowlist); the character check here is only defense in depth.
"""

import asyncio
import json
import logging
import re
from collections.abc import Callable
from typing import Any

from ..pinger import Target

log = logging.getLogger(__name__)

MAX_OUTPUT = 8000
SSH_TIMEOUT_S = 30
TRACEROUTE_TIMEOUT_S = 60
REDACTED = "[REDACTED]"

# A secret-looking key name. `pass`/`pwd` only count as a whole key segment
# (DB_PASS, mysql-pass, DB_PWD), so `passed`, `bypass` or `compass` stay.
# Bare `auth` is no key: "auth: Failed for user root" is an ordinary log line.
#
# Linear time: a lookahead decides whether the [\w-] run holds a keyword, then
# the run is consumed possessively (`++`, Python >= 3.11), so a failed match
# never re-splits the run. Matches start only at the start of a run.
_KEYWORDS = r"(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|credential|authorization)"
_SEGMENT_KEYWORDS = r"(?:[\w-]*?[_-])?(?:pass|pwd)(?![^\W_])"
_KEY_NAME = rf"(?=[\w-]*?{_KEYWORDS}|{_SEGMENT_KEYWORDS})[\w-]++"
_VALUE = r"""(?P<val>"(?:[^"\\]|\\.)*+"|'(?:[^'\\]|\\.)*+'|\S++)"""
_KV_RE = re.compile(
    rf"""(?i)(?<![\w-])(?P<key>["']?{_KEY_NAME}["']?\s*[=:]\s*){_VALUE}""")
_CLI_RE = re.compile(
    rf"""(?i)(?<![\w-])(?P<key>--(?:[\w-]*?-)?(?:password|passwd|token|secret|api-key)[= ]\s*){_VALUE}""")
_SECRET_KEY = re.compile(rf"(?i)^{_KEY_NAME}$")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")
_AUTHZ_RE = re.compile(r"(?i)(authorization:\s*)[^\s\"']+(?:\s+[^\s\"']+)?")
MAX_LINE = 4000
_CUT_MARK = "…[cut]"

_REDACT_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----"),
    re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"),
    re.compile(r"AKI[A][0-9A-Z]{16}"),  # AWS access key id ([A] keeps naive scanners off this line)
    re.compile(r"sk-ant-[\w-]+"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]


def _value_sub(m: re.Match) -> str:
    key, val = m.group("key"), m.group("val")
    if val.startswith(REDACTED):  # already handled (e.g. "Authorization: [REDACTED]")
        return m.group(0)
    # the shell's working directory variable is a path, not a password
    if key.strip("\"' =:").upper() == "PWD" and val.strip("\"'").startswith("/"):
        return m.group(0)
    if val[:1] in "\"'" and len(val) >= 2 and val[-1] == val[0]:
        return f"{key}{val[0]}{REDACTED}{val[0]}"
    return key + REDACTED
_CMD_OK = re.compile(r"^[A-Za-z0-9._:/@=+,\- ]+$")
_TARGET_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]*$")
_PROBE_KIND = {"ping": "icmp", "dns": "dns", "tcp": "tcp", "http": "http"}


def redact(text: str) -> str:
    """Replace anything that looks like a credential with [REDACTED]; for
    key/value forms the key stays readable and only the value goes. Lines
    longer than MAX_LINE are cut first (marked), which also bounds regex cost."""
    if len(text) > MAX_LINE:
        text = "\n".join(line if len(line) <= MAX_LINE else line[: MAX_LINE - len(_CUT_MARK)] + _CUT_MARK
                         for line in text.split("\n"))
    for pat in _REDACT_PATTERNS:
        text = pat.sub(REDACTED, text)
    text = _BEARER_RE.sub("Bearer " + REDACTED, text)
    text = _AUTHZ_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _CLI_RE.sub(_value_sub, text)
    return _KV_RE.sub(_value_sub, text)


def redact_obj(obj: Any) -> Any:
    """Redact all strings in a JSON-like structure (keeps it valid JSON);
    values under secret-looking keys are dropped entirely."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: (REDACTED if isinstance(k, str) and _SECRET_KEY.search(k) and v not in (None, "")
                    else redact_obj(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj


def _clip(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    marker = "\n… [cut]"
    return text[: limit - len(marker)] + marker


def _int(value, default: int, lo: int, hi: int) -> int:
    try:
        v = int(value) if value is not None else default
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def tool_defs(cfg) -> list[dict]:
    """Tool definitions for the model. Host names come from the config; host_cmd
    is only offered when at least one host allows investigator access."""
    agents = cfg.agent_hosts
    ssh_hosts = list(cfg.investigator_hosts)
    host_prop = {"type": "string", "enum": agents} if agents else {"type": "string"}
    defs = [
        {
            "name": "query_logs",
            "description": "Full-text search over the stored system logs of all hosts. "
                           "Returns the newest matching lines (max. 100).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "search terms, empty = all lines"},
                    "host": host_prop,
                    "minutes_back": {"type": "integer", "description": "time span in minutes (default 60, max. 1440)"},
                    "max_severity": {"type": "integer",
                                     "description": "syslog severity 0-7, only lines <= this value"},
                },
                "required": ["query"],
            },
        },
        {
            "name": "query_metrics",
            "description": "Metrics of a host as a time series, e.g. cpu_pct, load1, mem_used, net_rx_bps, "
                           "temps.cpu, uptime_s, power.battery_pct.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": host_prop,
                    "field": {"type": "string"},
                    "minutes_back": {"type": "integer"},
                },
                "required": ["host", "field", "minutes_back"],
            },
        },
        {
            "name": "net_test",
            "description": "Network test from the LANOT server. ping/tcp/http check reachability, dns asks the "
                           f"name server `target` for {cfg.internet.dns_query}, traceroute shows the path.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["ping", "dns", "tcp", "http", "traceroute"]},
                    "target": {"type": "string", "description": "IP address or host name"},
                    "port": {"type": "integer"},
                },
                "required": ["kind", "target"],
            },
        },
    ]
    if cfg.router.polls_tr064:
        defs += [
            {
                "name": "fritz_status",
                "description": "Current FritzBox status (line, internet connection, external IP, uptime).",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "fritz_log",
                "description": "FritzBox event log of the last 24 hours.",
                "input_schema": {"type": "object", "properties": {}},
            },
        ]
    if ssh_hosts:
        defs.append({
            "name": "host_cmd",
            "description": "Runs a READ-ONLY command over SSH on a host. Only a fixed list is allowed "
                           "(e.g. journalctl, dmesg, docker ps/inspect/logs, zpool status, smartctl -a, "
                           "df, free, ip, ss, systemctl status). No pipes, redirections or special characters.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "enum": ssh_hosts},
                    "command": {"type": "string"},
                },
                "required": ["host", "command"],
            },
        })
    return defs


class Toolbox:
    """The investigator's tools. `deps` needs db, fritz (or None), probe and run."""

    def __init__(self, deps, settings, clock: Callable[[], float]):
        self.deps, self.settings, self.clock = deps, settings, clock
        self.definitions = tool_defs(settings.config)
        self.hosts = settings.config.investigator_hosts  # host -> (user, address)

    async def call(self, name: str, args: dict) -> str:
        """Dispatch a tool call; never raises, always redacted and truncated."""
        fn = getattr(self, name, None) if name in {t["name"] for t in self.definitions} else None
        if fn is None:
            return f"unknown tool: {name}"
        try:
            out = await fn(**(args or {}))
        except TypeError as e:
            out = f"Error: invalid parameters ({e})"
        except Exception as e:
            log.warning("tool %s failed: %s", name, type(e).__name__)
            out = f"Error: {type(e).__name__}"
        return _clip(redact(str(out)))

    async def query_logs(self, query: str = "", host: str | None = None, minutes_back: int | None = None,
                         max_severity: int | None = None) -> str:
        minutes = _int(minutes_back, 60, 1, 1440)
        sev = _int(max_severity, 7, 0, 7) if max_severity is not None else None
        rows = await asyncio.to_thread(
            self.deps.db.search_logs, query or None, host=host, since=self.clock() - minutes * 60,
            max_severity=sev, limit=100)
        if not rows:
            return "no matching log lines"
        lines = [f"{r['ts']:.0f} {r['host']} {r['source']} sev={r['severity']} {r['message']}"
                 for r in reversed(rows)]
        return _clip(redact("\n".join(lines)))

    async def query_metrics(self, host: str, field: str, minutes_back: int) -> str:
        minutes = _int(minutes_back, 60, 1, 1440)
        try:
            series = await asyncio.to_thread(self.deps.db.metrics_series, host, field,
                                             self.clock() - minutes * 60)
        except ValueError as e:
            return f"Error: {e}"
        if not series:
            return "no metrics"
        series = series[-200:]
        return _clip(redact(json.dumps([[round(ts), v] for ts, v in series])))

    async def net_test(self, kind: str, target: str, port: int | None = None) -> str:
        if not isinstance(target, str) or not _TARGET_OK.match(target) or len(target) > 253:
            return f"invalid target: {target!r}"
        if kind == "traceroute":
            try:
                _, out, err = await self.deps.run(
                    ["traceroute", "-n", "-w", "2", "-m", "15", target], TRACEROUTE_TIMEOUT_S)
            except TimeoutError:
                return "traceroute: timed out"
            except Exception as e:
                return f"traceroute failed: {type(e).__name__}"
            return _clip(redact((out + err).strip() or "no output"))
        if kind not in _PROBE_KIND:
            return f"invalid test kind: {kind!r}"
        if kind == "tcp" and port is None:
            return "port missing for tcp test"
        p = _int(port, 0, 1, 65535) if port is not None else None
        query = self.settings.config.internet.dns_query if kind == "dns" else None
        ok, rtt = await self.deps.probe(Target(target, _PROBE_KIND[kind], target, p, query=query))
        where = f"{target}:{p}" if p else target
        if ok:
            return f"{kind} {where}: reachable" + (f", {rtt:.1f} ms" if rtt is not None else "")
        return f"{kind} {where}: unreachable"

    async def fritz_status(self) -> str:
        fritz = self.deps.fritz
        data = await asyncio.to_thread(fritz.poll) if fritz else await asyncio.to_thread(self.deps.db.latest_fritz)
        return json.dumps(redact_obj(data or {"error": "no FritzBox data"}), ensure_ascii=False)

    async def fritz_log(self) -> str:
        fritz = self.deps.fritz
        if not fritz:
            return "FritzBox polling is not configured"
        lines = await asyncio.to_thread(fritz.event_log, self.clock() - 86400)
        return _clip(redact("\n".join(lines[-100:]) or "no entries"))

    async def host_cmd(self, host: str, command: str) -> str:
        if host not in self.hosts:
            return f"unknown host: {host!r} (allowed: {', '.join(self.hosts) or 'none'})"
        if not isinstance(command, str) or not command.strip() or not _CMD_OK.match(command):
            return "command denied: forbidden characters (no pipes, redirections or special characters)"
        user, address = self.hosts[host]
        argv = ["ssh", "-i", self.settings.investigator_key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.settings.known_hosts_file}",
                f"{user}@{address}", "--", command]
        try:
            rc, out, err = await self.deps.run(argv, SSH_TIMEOUT_S)
        except TimeoutError:
            return f"timed out after {SSH_TIMEOUT_S} s"
        except Exception as e:
            return f"SSH failed: {type(e).__name__}"
        # Refusals are keyed on the stderr prefix: the tools themselves also exit 2.
        if err.startswith("denied:"):
            reason = (err[len("denied:"):].strip().splitlines() or [""])[0]
            return _clip(redact(f"command denied: {reason}".strip()))
        text = out
        if err.strip():
            text += ("\n" if text and not text.endswith("\n") else "") + "[stderr]\n" + err
        if rc not in (0, None):
            text += f"\n[exit {rc}]"
        return _clip(redact(text.strip() or "no output"))
