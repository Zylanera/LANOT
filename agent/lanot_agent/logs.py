"""Log sources: tailed files (syslog), the systemd journal and docker events."""

import json
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Iterator

import httpx
from lanot_common.protocol import LogLine

log = logging.getLogger(__name__)

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_TS_RE = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) ")
_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
# Unraid syslog has no PRI: kernel faults are recognised by their words (display only;
# the server's log rules match their patterns whatever the severity)
_ERR_RE = re.compile(r"error|fail|fatal|panic|i/o error|\boom\b|oom[-_]kill|out of memory|\boops\b|corrupt"
                     r"|degraded|\bfault(ed|s)?\b", re.IGNORECASE)
_WARN_RE = re.compile(r"warn", re.IGNORECASE)

MAX_READ_BYTES = 1024 * 1024  # read chunk size
JOURNAL_TIMEOUT = 60  # wall-clock seconds for one journalctl run
MAX_LINES = 2000  # max lines returned by one read_new(); the rest is picked up next call


def guess_severity(text: str) -> int:
    if _ERR_RE.search(text):
        return 3
    if _WARN_RE.search(text):
        return 4
    return 6


def _syslog_ts(m: re.Match, now: float) -> float:
    year = time.localtime(now).tm_year
    fields = (_MONTHS.get(m.group(1), 1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
    ts = time.mktime((year, *fields, 0, 0, -1))
    if ts > now + 86400:  # "Dec 31" read in January belongs to last year
        ts = time.mktime((year - 1, *fields, 0, 0, -1))
    return ts


def parse_syslog(line: str, source: str = "syslog", now: float | None = None) -> LogLine:
    """RFC3164: optional `<PRI>`, `Mmm dd hh:mm:ss host tag: msg`. Severity is
    PRI & 7 when present, otherwise guessed from keywords."""
    now = time.time() if now is None else now
    severity: int | None = None
    pri = _PRI_RE.match(line)
    if pri:
        severity = int(pri.group(1)) & 7
        line = line[pri.end():]
    ts = now
    m = _TS_RE.match(line)
    if m:
        try:
            ts = _syslog_ts(m, now)
        except (ValueError, OverflowError):
            pass
    if severity is None:
        severity = guess_severity(line)
    return LogLine(ts=ts, source=source, severity=severity, message=line)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


class FileTailer:
    """Follows a text file across restarts (state file), rotation and truncation.

    `read_new()` never persists its position: the caller calls `commit()` once
    the lines are safely delivered or buffered. Until then every `read_new()`
    starts again from the last committed position.
    """

    def __init__(self, path: Path, state_file: Path) -> None:
        self.path = Path(path)
        self.state_file = Path(state_file)
        self.source = self.path.name
        self._committed: tuple[int | None, int] = (None, 0)
        self._pending: tuple[int | None, int] | None = None
        try:
            st = json.loads(self.state_file.read_text())
            self._committed = (int(st["inode"]), int(st["offset"]))
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def commit(self) -> None:
        if self._pending is None:
            return
        self._committed, self._pending = self._pending, None
        try:
            _write_json(self.state_file, {"inode": self._committed[0], "offset": self._committed[1]})
        except OSError:
            log.warning("cannot save tail state %s", self.state_file, exc_info=True)

    def _read_from(self, path: Path, offset: int, limit: int) -> tuple[list[LogLine], int]:
        """Up to `limit` complete lines after offset; returns them and the new offset."""
        out: list[LogLine] = []
        with path.open("rb") as fh:
            while len(out) < limit:
                fh.seek(offset)
                data = fh.read(MAX_READ_BYTES)
                end = data.rfind(b"\n")
                if end < 0:
                    break
                consumed = 0
                for raw in data[: end + 1].split(b"\n")[:-1]:
                    if len(out) >= limit:
                        break
                    consumed += len(raw) + 1
                    text = raw.decode("utf-8", errors="replace").rstrip("\r")
                    if text:
                        out.append(parse_syslog(text, self.source))
                offset += consumed
        return out, offset

    def _find_rotated(self, inode: int) -> Path | None:
        for p in self.path.parent.glob(self.path.name + "*"):
            try:
                if p != self.path and p.stat().st_ino == inode:
                    return p
            except OSError:
                continue
        return None

    def read_new(self, limit: int = MAX_LINES) -> list[LogLine]:
        inode, offset = self._committed
        lines: list[LogLine] = []
        try:
            st = self.path.stat()
        except OSError:
            self._pending = None
            return lines
        if inode is not None and st.st_ino != inode:
            # rotated: finish the old file (now renamed) before the new one
            old = self._find_rotated(inode)
            if old is not None:
                try:
                    lines, offset = self._read_from(old, offset, limit)
                except OSError:
                    lines = []
                if len(lines) >= limit:
                    self._pending = (inode, offset)  # old file may have more; continue next call
                    return lines
            inode, offset = st.st_ino, 0
        elif st.st_size < offset:
            offset = 0  # truncated in place
        inode = st.st_ino
        try:
            got, offset = self._read_from(self.path, offset, limit - len(lines))
        except OSError:
            got = []
        self._pending = (inode, offset)
        return lines + got


Runner = Callable[[list[str]], Iterator[str]]


def _journalctl(argv: list[str]) -> Iterator[str]:
    """Stream journalctl's stdout lines; the process is killed if the consumer stops early."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    watchdog = threading.Timer(JOURNAL_TIMEOUT, proc.kill)  # hung journalctl: kill ends the stream
    watchdog.daemon = True
    watchdog.start()
    try:
        assert proc.stdout is not None
        yield from proc.stdout
    finally:
        watchdog.cancel()
        proc.kill()
        proc.wait()


class JournalFollower:
    """Reads new journal entries of a (host) journal directory since the last
    committed cursor, oldest first, at most `limit` per call. No `-n` is used
    with a cursor: `-n` would select the newest entries and skip the rest."""

    def __init__(self, directory: str, cursor_file: Path, runner: Runner | None = None) -> None:
        self.directory = directory
        self.cursor_file = Path(cursor_file)
        self.run = runner or _journalctl
        self._pending: str | None = None
        try:
            self.cursor: str | None = self.cursor_file.read_text().strip() or None
        except OSError:
            self.cursor = None

    def commit(self) -> None:
        if not self._pending or self._pending == self.cursor:
            return
        self.cursor, self._pending = self._pending, None
        try:
            self.cursor_file.parent.mkdir(parents=True, exist_ok=True)
            self.cursor_file.write_text(self.cursor)
        except OSError:
            log.warning("cannot save journal cursor", exc_info=True)

    def read_new(self, limit: int = MAX_LINES) -> list[LogLine]:
        argv = ["journalctl", "-D", self.directory, "-o", "json", "--no-pager"]
        if self.cursor:
            argv += ["--after-cursor", self.cursor]
        else:
            argv += ["-n", "200"]  # first start: recent history only
        lines: list[LogLine] = []
        cursor = self.cursor
        try:
            it = self.run(argv)
            try:
                for raw in it:
                    try:
                        e = json.loads(raw)
                        msg = e.get("MESSAGE", "")
                        if isinstance(msg, list):  # binary messages come as byte arrays
                            msg = bytes(msg).decode("utf-8", errors="replace")
                        ident = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or ""
                        sev = int(e.get("PRIORITY", 6))
                        ts = int(e["__REALTIME_TIMESTAMP"]) / 1e6
                        lines.append(
                            LogLine(ts=ts, source="journal", severity=min(max(sev, 0), 7),
                                    message=f"{ident}: {msg}" if ident else str(msg))
                        )
                        cursor = e.get("__CURSOR", cursor)
                    except (ValueError, KeyError, TypeError):
                        continue
                    if len(lines) >= limit:
                        break
            finally:
                close = getattr(it, "close", None)
                if close:
                    close()
        except Exception:
            log.warning("journalctl failed", exc_info=True)
            if not lines:
                self._pending = None
                return []
        self._pending = cursor
        return lines


_EVENT_FILTERS = json.dumps({"type": ["container"], "event": ["die", "oom", "health_status", "restart"]})


class DockerEvents:
    """Polls the docker events API for a finite window (`since`..`until`), so it
    never blocks; events already seen are skipped via their nanosecond time."""

    def __init__(self, socket: str, client: httpx.Client | None = None, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self.client = client or httpx.Client(
            transport=httpx.HTTPTransport(uds=socket), base_url="http://docker", timeout=10
        )
        self.last_nano = int(clock() * 1e9)
        self._pending = self.last_nano

    def commit(self) -> None:
        self.last_nano = self._pending

    @staticmethod
    def _to_line(e: dict) -> LogLine:
        attrs = (e.get("Actor") or {}).get("Attributes") or {}
        name = attrs.get("name", "?")
        action = e.get("Action", "")
        severity = 6
        if action == "die":
            code = str(attrs.get("exitCode", "0"))
            msg = f"container {name} died (exit {code})"
            severity = 3 if code != "0" else 6
        elif action == "oom":
            msg, severity = f"container {name} was OOM-killed", 3
        elif action.startswith("health_status"):
            status = action.partition(":")[2].strip() or "?"
            msg = f"container {name} health: {status}"
            severity = 3 if status == "unhealthy" else 6
        else:
            msg = f"container {name} {action}"
        return LogLine(ts=float(e.get("time", time.time())), source="docker-events", severity=severity, message=msg)

    def read_new(self) -> list[LogLine]:
        self._pending = self.last_nano  # a failed read must never commit a stale position
        now = self.clock()
        try:
            resp = self.client.get(
                "/events",
                params={"since": int(self.last_nano // 10**9), "until": int(now), "filters": _EVENT_FILTERS},
            )
            resp.raise_for_status()
        except httpx.HTTPError:
            log.warning("docker events unavailable", exc_info=True)
            return []
        lines: list[LogLine] = []
        newest = self.last_nano
        for raw in resp.text.splitlines():
            try:
                e = json.loads(raw)
                nano = int(e.get("timeNano") or int(e["time"]) * 10**9)
                if nano <= self.last_nano:
                    continue
                lines.append(self._to_line(e))
                newest = max(newest, nano)
            except (ValueError, KeyError, TypeError):
                continue
        self._pending = newest
        return lines
