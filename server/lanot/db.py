"""SQLite storage for the LANOT server.

WAL mode, one connection per thread (reads run concurrently), all writes
serialized through a single lock. Agent-supplied tables store both the agent's
timestamp (`ts`) and the server receive time (`received`); liveness and
retention use `received` so a skewed agent clock cannot fake freshness.
"""

import json
import re
import sqlite3
import threading
from dataclasses import asdict, dataclass

from lanot_common.protocol import LogBatch, MetricsReport, StateReport

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY, host TEXT NOT NULL, ts REAL NOT NULL,
    received REAL NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS metrics_host_received ON metrics(host, received);
CREATE INDEX IF NOT EXISTS metrics_received ON metrics(received);

CREATE TABLE IF NOT EXISTS state (
    id INTEGER PRIMARY KEY, host TEXT NOT NULL, ts REAL NOT NULL,
    received REAL NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS state_host_received ON state(host, received);
CREATE INDEX IF NOT EXISTS state_received ON state(received);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY, host TEXT NOT NULL, ts REAL NOT NULL,
    received REAL NOT NULL, source TEXT NOT NULL, severity INTEGER NOT NULL,
    message TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS logs_received ON logs(received);
CREATE INDEX IF NOT EXISTS logs_host_ts ON logs(host, ts);
CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
    message, content='logs', content_rowid='id');
CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
END;
CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
    INSERT INTO logs_fts(logs_fts, rowid, message) VALUES ('delete', old.id, old.message);
END;

CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY, target TEXT NOT NULL, ts REAL NOT NULL,
    ok INTEGER NOT NULL, rtt_ms REAL);
CREATE INDEX IF NOT EXISTS probes_target_ts ON probes(target, ts);

CREATE TABLE IF NOT EXISTS fritz (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS fritz_ts ON fritz(ts);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, key TEXT NOT NULL,
    severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT,
    opened_at REAL NOT NULL, last_seen_at REAL NOT NULL, resolved_at REAL,
    flap_count INTEGER NOT NULL DEFAULT 0, last_push_at REAL, diagnosis_json TEXT);
CREATE INDEX IF NOT EXISTS incidents_rule_key ON incidents(rule, key);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS mutes (
    rule TEXT NOT NULL, key TEXT NOT NULL, until REAL NOT NULL,
    PRIMARY KEY (rule, key));
"""

@dataclass
class Incident:
    rule: str
    key: str
    severity: str
    title: str
    detail: str | None
    opened_at: float
    last_seen_at: float
    resolved_at: float | None = None
    flap_count: int = 0
    last_push_at: float | None = None
    diagnosis_json: str | None = None
    id: int | None = None


_INC_COLS = (
    "rule", "key", "severity", "title", "detail", "opened_at", "last_seen_at",
    "resolved_at", "flap_count", "last_push_at", "diagnosis_json",
)

_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_PURGE_BY_RECEIVED = ("metrics", "state", "logs")
_DELETE_CHUNK = 5000
_SIZE_CHUNK = 200


class Database:
    def __init__(self, path: str):
        self.path = path
        self._local = threading.local()
        self._write_lock = threading.Lock()
        with self._write_lock:
            con = self._conn()
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        con = getattr(self._local, "con", None)
        if con is None:
            con = sqlite3.connect(self.path, isolation_level=None, timeout=30)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA synchronous=NORMAL")
            con.execute("PRAGMA busy_timeout=30000")
            self._local.con = con
        return con

    # -- writes ----------------------------------------------------------
    def _write(self, sql: str, params=()) -> int:
        with self._write_lock:
            return self._conn().execute(sql, params).rowcount

    def insert_metrics(self, r: MetricsReport, received: float) -> None:
        self._write(
            "INSERT INTO metrics(host, ts, received, data) VALUES (?,?,?,?)",
            (r.host, r.ts, received, r.model_dump_json()),
        )

    def insert_state(self, r: StateReport, received: float) -> None:
        self._write(
            "INSERT INTO state(host, ts, received, data) VALUES (?,?,?,?)",
            (r.host, r.ts, received, r.model_dump_json()),
        )

    def insert_logs(self, b: LogBatch, received: float) -> int:
        rows = [(b.host, l.ts, received, l.source, l.severity, l.message) for l in b.lines]
        if not rows:
            return 0
        with self._write_lock:
            con = self._conn()
            con.execute("BEGIN")
            try:
                con.executemany(
                    "INSERT INTO logs(host, ts, received, source, severity, message) VALUES (?,?,?,?,?,?)",
                    rows,
                )
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
        return len(rows)

    def insert_probe(self, target: str, ts: float, ok: bool, rtt_ms: float | None) -> None:
        self._write(
            "INSERT INTO probes(target, ts, ok, rtt_ms) VALUES (?,?,?,?)", (target, ts, int(ok), rtt_ms)
        )

    def insert_fritz(self, ts: float, data: dict) -> None:
        self._write("INSERT INTO fritz(ts, data) VALUES (?,?)", (ts, json.dumps(data)))

    def save_incident(self, inc: Incident) -> Incident:
        """Insert (id is None) or update; returns the incident with its id."""
        d = asdict(inc)
        vals = [d[c] for c in _INC_COLS]
        with self._write_lock:
            con = self._conn()
            if inc.id is None:
                cur = con.execute(
                    f"INSERT INTO incidents({', '.join(_INC_COLS)}) VALUES ({','.join('?' * len(_INC_COLS))})",
                    vals,
                )
                inc.id = cur.lastrowid
            else:
                con.execute(
                    f"UPDATE incidents SET {', '.join(c + '=?' for c in _INC_COLS)} WHERE id=?",
                    vals + [inc.id],
                )
        return inc

    def set_diagnosis(self, id: int, diagnosis_json: str) -> None:
        """Only touches diagnosis_json, so a concurrent incident update is not lost."""
        self._write("UPDATE incidents SET diagnosis_json=? WHERE id=?", (diagnosis_json, id))

    def take_quota(self, key: str, limit: int) -> bool:
        """Atomically count one use in an integer setting (missing = 0).
        False, and nothing counted, once `limit` uses are recorded."""
        with self._write_lock:
            con = self._conn()
            row = con.execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
            used = json.loads(row[0]) if row else 0
            if used >= limit:
                return False
            con.execute(
                "INSERT INTO settings(key, value_json) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                (key, json.dumps(used + 1)),
            )
        return True

    def set_mute(self, rule: str, key: str, until: float) -> None:
        self._write(
            "INSERT INTO mutes(rule, key, until) VALUES (?,?,?) "
            "ON CONFLICT(rule, key) DO UPDATE SET until=excluded.until",
            (rule, key, until),
        )

    def clear_mute(self, rule: str, key: str) -> None:
        self._write("DELETE FROM mutes WHERE rule=? AND key=?", (rule, key))

    def set_setting(self, key: str, value) -> None:
        self._write(
            "INSERT INTO settings(key, value_json) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
            (key, json.dumps(value)),
        )

    # -- reads -----------------------------------------------------------
    def last_received(self, host: str) -> float | None:
        """Latest receive time of metrics or state. Logs are deliberately
        excluded: a log flood must not mask a dead metrics collector."""
        row = self._conn().execute(
            """SELECT max(r) FROM (
                 SELECT max(received) AS r FROM metrics WHERE host=?
                 UNION ALL SELECT max(received) FROM state WHERE host=?)""",
            (host, host),
        ).fetchone()
        return row[0]

    def _latest(self, table: str, host: str, offset: int = 0) -> str | None:
        row = self._conn().execute(
            f"SELECT data FROM {table} WHERE host=? ORDER BY received DESC, id DESC LIMIT 1 OFFSET ?",
            (host, offset),
        ).fetchone()
        return row[0] if row else None

    def latest_metrics(self, host: str) -> MetricsReport | None:
        data = self._latest("metrics", host)
        return MetricsReport.model_validate_json(data) if data else None

    def latest_state(self, host: str) -> StateReport | None:
        data = self._latest("state", host)
        return StateReport.model_validate_json(data) if data else None

    def previous_state(self, host: str) -> StateReport | None:
        """The state report received just before the latest one."""
        data = self._latest("state", host, offset=1)
        return StateReport.model_validate_json(data) if data else None

    def metrics_series(self, host: str, field: str, since: float) -> list[tuple[float, float]]:
        """(receive time, value) pairs; `field` is a MetricsReport path such as
        `cpu_pct` or `temps.cpu`."""
        if not _FIELD_RE.match(field):
            raise ValueError(f"invalid metric field: {field!r}")
        rows = self._conn().execute(
            "SELECT received, json_extract(data, ?) FROM metrics "
            "WHERE host=? AND received>=? ORDER BY received",
            ("$." + ".".join(f'"{p}"' for p in field.split(".")), host, since),
        ).fetchall()
        return [(r[0], r[1]) for r in rows if r[1] is not None]

    def search_logs(
        self,
        query: str | None,
        host: str | None = None,
        since: float | None = None,
        until: float | None = None,
        max_severity: int | None = None,
        limit: int = 200,
    ) -> list[dict]:
        where, params = [], []
        join = ""
        terms = [t.replace('"', "") for t in (query or "").split()]
        terms = [t for t in terms if t]
        if (query or "").strip() and not terms:
            return []
        if terms:
            join = "JOIN logs_fts ON logs_fts.rowid = logs.id"
            where.append("logs_fts MATCH ?")
            params.append(" ".join(f'"{t}"' for t in terms))
        for cond, val in (
            ("logs.host = ?", host),
            ("logs.ts >= ?", since),
            ("logs.ts <= ?", until),
            ("logs.severity <= ?", max_severity),
        ):
            if val is not None:
                where.append(cond)
                params.append(val)
        sql = (
            "SELECT logs.id, logs.host, logs.ts, logs.received, logs.source, logs.severity, logs.message "
            f"FROM logs {join} {'WHERE ' + ' AND '.join(where) if where else ''} "
            "ORDER BY logs.ts DESC, logs.id DESC LIMIT ?"
        )
        params.append(limit)
        return [dict(r) for r in self._conn().execute(sql, params)]

    def error_logs(self, host: str, since_received: float, max_severity: int, limit: int) -> list[tuple[float, str]]:
        """(receive time, message) of severe lines, oldest first, newest `limit`
        kept. Uses receive time: a host with a skewed clock must still alarm."""
        rows = self._conn().execute(
            "SELECT received, message FROM logs WHERE host=? AND received>=? AND severity<=? "
            "ORDER BY received DESC, id DESC LIMIT ?",
            (host, since_received, max_severity, limit),
        ).fetchall()
        return [(r[0], r[1]) for r in reversed(rows)]

    def rule_logs(self, host: str, since_received: float, max_severity: int, keywords, limit: int
                  ) -> list[tuple[float, str, int]]:
        """Lines for the log rules, oldest first: the newest `limit` severe lines
        plus the newest `limit` lines containing one of `keywords` (any severity,
        case-insensitive LIKE). Both by receive time; a line in both counts once."""
        like = " OR ".join("message LIKE ? ESCAPE '\\'" for _ in keywords) or "0"
        pats = ["%" + k.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%" for k in keywords]
        rows = self._conn().execute(
            "SELECT id, received, message, severity FROM ("
            " SELECT id, received, message, severity FROM logs WHERE host=? AND received>=? AND severity<=?"
            " ORDER BY received DESC, id DESC LIMIT ?)"
            " UNION "
            "SELECT id, received, message, severity FROM ("
            f" SELECT id, received, message, severity FROM logs WHERE host=? AND received>=? AND ({like})"
            " ORDER BY received DESC, id DESC LIMIT ?)"
            " ORDER BY received, id",
            (host, since_received, max_severity, limit, host, since_received, *pats, limit),
        ).fetchall()
        return [(r[1], r[2], r[3]) for r in rows]

    def newest_probe_ts(self) -> float | None:
        return self._conn().execute("SELECT max(ts) FROM probes").fetchone()[0]

    def probes(self, target: str, since: float) -> list[tuple[float, bool, float | None]]:
        rows = self._conn().execute(
            "SELECT ts, ok, rtt_ms FROM probes WHERE target=? AND ts>=? ORDER BY ts", (target, since)
        )
        return [(r["ts"], bool(r["ok"]), r["rtt_ms"]) for r in rows]

    @staticmethod
    def _incident(row) -> Incident:
        return Incident(**{k: row[k] for k in (*_INC_COLS, "id")})

    def get_incident(self, id: int) -> Incident | None:
        row = self._conn().execute("SELECT * FROM incidents WHERE id=?", (id,)).fetchone()
        return self._incident(row) if row else None

    def open_incidents(self) -> list[Incident]:
        rows = self._conn().execute("SELECT * FROM incidents WHERE resolved_at IS NULL ORDER BY id")
        return [self._incident(r) for r in rows]

    def last_resolved(self, rule: str, key: str) -> Incident | None:
        row = self._conn().execute(
            "SELECT * FROM incidents WHERE rule=? AND key=? AND resolved_at IS NOT NULL "
            "ORDER BY resolved_at DESC, id DESC LIMIT 1",
            (rule, key),
        ).fetchone()
        return self._incident(row) if row else None

    def list_incidents(self, limit: int = 50, offset: int = 0) -> list[Incident]:
        rows = self._conn().execute(
            "SELECT * FROM incidents ORDER BY opened_at DESC, id DESC LIMIT ? OFFSET ?", (limit, offset)
        )
        return [self._incident(r) for r in rows]

    def mutes_active(self, now: float) -> set[tuple[str, str]]:
        rows = self._conn().execute("SELECT rule, key FROM mutes WHERE until > ?", (now,))
        return {(r["rule"], r["key"]) for r in rows}

    def get_setting(self, key: str, default=None):
        row = self._conn().execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def recent_fritz(self, limit: int) -> list[dict]:
        """Newest `limit` polls, oldest first; each dict carries its `ts`."""
        rows = self._conn().execute("SELECT ts, data FROM fritz ORDER BY ts DESC, id DESC LIMIT ?", (limit,))
        return [{**json.loads(r["data"]), "ts": r["ts"]} for r in reversed(rows.fetchall())]

    def latest_fritz(self) -> dict | None:
        rows = self.recent_fritz(1)
        return rows[0] if rows else None

    def temps_since(self, host: str, since: float) -> list[tuple[float, dict[str, float]]]:
        rows = self._conn().execute(
            "SELECT received, json_extract(data, '$.temps') FROM metrics "
            "WHERE host=? AND received>=? ORDER BY received",
            (host, since),
        )
        return [(r[0], json.loads(r[1] or "{}")) for r in rows]

    # -- dashboard reads ---------------------------------------------------
    def probes_between(self, target: str, lo: float, hi: float) -> list[tuple[float, bool]]:
        rows = self._conn().execute(
            "SELECT ts, ok FROM probes WHERE target=? AND ts>=? AND ts<=? ORDER BY ts", (target, lo, hi)
        )
        return [(r[0], bool(r[1])) for r in rows]

    def fritz_between(self, lo: float, hi: float) -> list[dict]:
        rows = self._conn().execute("SELECT ts, data FROM fritz WHERE ts>=? AND ts<=? ORDER BY ts", (lo, hi))
        return [{**json.loads(r["data"]), "ts": r["ts"]} for r in rows]

    def metrics_sampled(self, host: str, since: float, step: float) -> list[tuple[float, dict]]:
        """At most one report per `step` seconds (the newest in each bucket), oldest first."""
        rows = self._conn().execute(
            "SELECT received, data FROM metrics WHERE id IN ("
            " SELECT max(id) FROM metrics WHERE host=? AND received>=? GROUP BY CAST(received / ? AS INTEGER))"
            " ORDER BY received",
            (host, since, step),
        )
        return [(r[0], json.loads(r[1])) for r in rows]

    def list_mutes(self, now: float) -> list[dict]:
        rows = self._conn().execute("SELECT rule, key, until FROM mutes WHERE until > ? ORDER BY until", (now,))
        return [dict(r) for r in rows]

    def incidents_since(self, rule: str, since: float) -> list[Incident]:
        """Incidents of `rule` still open or resolved after `since`, newest first."""
        rows = self._conn().execute(
            "SELECT * FROM incidents WHERE rule=? AND (resolved_at IS NULL OR resolved_at>=?) "
            "ORDER BY opened_at DESC, id DESC",
            (rule, since),
        )
        return [self._incident(r) for r in rows]

    def has_incident(self, rule: str, key: str) -> bool:
        return self._conn().execute(
            "SELECT 1 FROM incidents WHERE rule=? AND key=? LIMIT 1", (rule, key)).fetchone() is not None

    def count_incidents(self) -> int:
        return self._conn().execute("SELECT count(*) FROM incidents").fetchone()[0]

    # -- retention -------------------------------------------------------
    def purge_older_than(self, ts: float) -> int:
        total = 0
        for table in _PURGE_BY_RECEIVED:
            total += self._delete_chunked(table, "received < ?", (ts,))
        total += self._delete_chunked("probes", "ts < ?", (ts,))
        total += self._delete_chunked("fritz", "ts < ?", (ts,))
        return total

    def _delete_chunked(self, table: str, cond: str, params: tuple, chunk: int = _DELETE_CHUNK) -> int:
        # Lock is taken per chunk so ingest writes can interleave.
        total = 0
        while True:
            with self._write_lock:
                n = self._conn().execute(
                    f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {cond} LIMIT {chunk})",
                    params,
                ).rowcount
            total += n
            if n < chunk:
                return total

    def size_bytes(self) -> int:
        """Bytes of live (non-free) pages in the database."""
        return self._used(self._conn())

    def enforce_size(self, max_bytes: int) -> int:
        """Delete oldest rows until live data fits in max_bytes: logs first,
        then metrics, state, probes, fritz. "Oldest" is by receive time (agent
        clocks can lie); probes/fritz are written by the server so ts is fine.
        The write lock is held per chunk only. Returns rows deleted."""
        deleted = 0
        for table, order in (
            ("logs", "received"),
            ("metrics", "received"),
            ("state", "received"),
            ("probes", "ts"),
            ("fritz", "ts"),
        ):
            while True:
                with self._write_lock:
                    con = self._conn()
                    if self._used(con) <= max_bytes:
                        return deleted
                    n = con.execute(
                        f"DELETE FROM {table} WHERE id IN "
                        f"(SELECT id FROM {table} ORDER BY {order}, id LIMIT {_SIZE_CHUNK})"
                    ).rowcount
                deleted += n
                if n == 0:
                    break
        return deleted

    @staticmethod
    def _used(con) -> int:
        page_size = con.execute("PRAGMA page_size").fetchone()[0]
        pages = con.execute("PRAGMA page_count").fetchone()[0]
        free = con.execute("PRAGMA freelist_count").fetchone()[0]
        return (pages - free) * page_size
