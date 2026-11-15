import json
import os
import time

import httpx
from lanot_agent.logs import DockerEvents, FileTailer, JournalFollower, parse_syslog


def test_severity_guess():
    assert parse_syslog("Nov 14 19:02:01 nas kernel: ata3: I/O error").severity == 3
    assert parse_syslog("Nov 14 19:02:01 h app: disk Warning 80%").severity == 4
    assert parse_syslog("Nov 14 19:02:01 h app: all good").severity == 6


def test_syslog_pri_wins_over_keywords():
    line = parse_syslog("<11>Nov 14 19:02:01 h app: all good")
    assert line.severity == 3
    assert "<11>" not in line.message


def test_syslog_timestamp_parsed():
    line = parse_syslog("Nov 14 19:02:01 h app: x", now=time.mktime((2026, 11, 14, 20, 0, 0, 0, 0, -1)))
    assert time.localtime(line.ts)[:6] == (2026, 11, 14, 19, 2, 1)


def read_commit(t, **kw):
    lines = t.read_new(**kw)
    t.commit()
    return [l.message for l in lines]


def test_tail_reads_only_new_lines(tmp_path):
    f = tmp_path / "syslog"
    f.write_text("Nov 14 19:00:00 h a: one\n")
    t = FileTailer(f, tmp_path / "st.json")
    assert read_commit(t) == ["Nov 14 19:00:00 h a: one"]
    assert read_commit(t) == []
    with f.open("a") as fh:
        fh.write("Nov 14 19:00:01 h a: two\n")
    assert [m.endswith("two") for m in read_commit(t)] == [True]


def test_tail_keeps_partial_line_for_later(tmp_path):
    f = tmp_path / "syslog"
    f.write_text("complete\npart")
    t = FileTailer(f, tmp_path / "st.json")
    assert read_commit(t) == ["complete"]
    with f.open("a") as fh:
        fh.write("ial\n")
    assert read_commit(t) == ["partial"]


def test_tail_handles_rotation(tmp_path):
    f = tmp_path / "syslog"
    f.write_text("a1\n")
    t = FileTailer(f, tmp_path / "st.json")
    assert read_commit(t) == ["a1"]
    with f.open("a") as fh:
        fh.write("a2\n")  # written but not yet read when the rotation happens
    os.rename(f, tmp_path / "syslog.1")
    f.write_text("b1\nb2\n")
    assert read_commit(t) == ["a2", "b1", "b2"]
    assert read_commit(t) == []


def test_tail_handles_truncation(tmp_path):
    f = tmp_path / "syslog"
    f.write_text("a1\na2\n")
    t = FileTailer(f, tmp_path / "st.json")
    read_commit(t)
    f.write_text("b1\n")  # same inode, shorter
    assert read_commit(t) == ["b1"]


def test_tail_resumes_after_restart(tmp_path):
    f = tmp_path / "syslog"
    st = tmp_path / "st.json"
    f.write_text("a1\n")
    read_commit(FileTailer(f, st))
    with f.open("a") as fh:
        fh.write("a2\n")
    assert read_commit(FileTailer(f, st)) == ["a2"]


def test_tail_missing_file_is_empty(tmp_path):
    assert FileTailer(tmp_path / "nope", tmp_path / "st.json").read_new() == []


def test_tail_without_commit_rereads_same_lines(tmp_path):
    f = tmp_path / "syslog"
    st = tmp_path / "st.json"
    f.write_text("a1\na2\n")
    t = FileTailer(f, st)
    assert [l.message for l in t.read_new()] == ["a1", "a2"]
    assert [l.message for l in t.read_new()] == ["a1", "a2"]  # nothing committed
    assert [l.message for l in FileTailer(f, st).read_new()] == ["a1", "a2"]  # nor persisted
    t.commit()
    assert t.read_new() == []


def test_tail_caps_lines_per_call_across_rotation(tmp_path):
    f = tmp_path / "syslog"
    f.write_text("")
    t = FileTailer(f, tmp_path / "st.json")
    read_commit(t)
    f.write_text("".join(f"old{i}\n" for i in range(5)))  # unread backlog ...
    os.rename(f, tmp_path / "syslog.1")  # ... that gets rotated away
    f.write_text("".join(f"new{i}\n" for i in range(4)))
    got = []
    calls = 0
    while True:
        chunk = read_commit(t, limit=2)
        if not chunk:
            break
        assert len(chunk) <= 2
        got += chunk
        calls += 1
    assert got == [f"old{i}" for i in range(5)] + [f"new{i}" for i in range(4)]
    assert calls == 5


def test_tail_cap_without_rotation(tmp_path):
    f = tmp_path / "syslog"
    f.write_text("".join(f"l{i}\n" for i in range(7)))
    t = FileTailer(f, tmp_path / "st.json")
    assert [read_commit(t, limit=3) for _ in range(3)] == [["l0", "l1", "l2"], ["l3", "l4", "l5"], ["l6"]]


def journal_entry(cursor, prio, msg, ident="sshd", ts_us=1700000000000000):
    return json.dumps(
        {"__CURSOR": cursor, "PRIORITY": str(prio), "MESSAGE": msg,
         "SYSLOG_IDENTIFIER": ident, "__REALTIME_TIMESTAMP": str(ts_us)}
    )


def test_journal_follower_uses_cursor(tmp_path):
    calls = []
    outputs = [
        [journal_entry("c1", 3, "boom"), journal_entry("c2", 6, "fine")],
        [],
    ]

    def runner(argv):
        calls.append(argv)
        return iter(outputs.pop(0))

    j = JournalFollower("/host/var/log/journal", tmp_path / "cur", runner=runner)
    lines = j.read_new()
    assert [(l.severity, l.source) for l in lines] == [(3, "journal"), (6, "journal")]
    assert lines[0].ts == 1700000000.0 and "boom" in lines[0].message
    assert "--after-cursor" not in calls[0]
    assert calls[0][:3] == ["journalctl", "-D", "/host/var/log/journal"]
    j.commit()
    assert j.read_new() == []
    assert calls[1][calls[1].index("--after-cursor") + 1] == "c2"
    assert "-n" not in calls[1]  # -n would pick the newest entries and skip older ones
    # restart keeps the cursor
    j2 = JournalFollower("/host/var/log/journal", tmp_path / "cur", runner=lambda a: calls.append(a) or iter([]))
    j2.read_new()
    assert calls[2][calls[2].index("--after-cursor") + 1] == "c2"


def test_journal_follower_without_commit_does_not_advance(tmp_path):
    calls = []

    def runner(argv):
        calls.append(argv)
        return iter([journal_entry("c1", 6, "x")])

    j = JournalFollower("/d", tmp_path / "cur", runner=runner)
    j.read_new()
    j.read_new()
    assert "--after-cursor" not in calls[1]
    assert not (tmp_path / "cur").exists()


def test_journal_follower_caps_and_delivers_whole_backlog(tmp_path):
    entries = [journal_entry(f"c{i}", 6, f"m{i}") for i in range(7)]

    def runner(argv):
        start = 0
        if "--after-cursor" in argv:
            start = int(argv[argv.index("--after-cursor") + 1][1:]) + 1
        return iter(entries[start:])  # like journalctl: oldest first, everything after cursor

    j = JournalFollower("/d", tmp_path / "cur", runner=runner)
    got = []
    while True:
        chunk = j.read_new(limit=3)
        j.commit()
        if not chunk:
            break
        assert len(chunk) <= 3
        got += [l.message for l in chunk]
    assert got == [f"sshd: m{i}" for i in range(7)]


def test_journal_follower_tolerates_garbage_and_failure(tmp_path):
    j = JournalFollower("/d", tmp_path / "cur", runner=lambda a: iter(["not json", journal_entry("c", 4, "w")]))
    assert [l.severity for l in j.read_new()] == [4]

    def boom(argv):
        raise OSError("no journalctl")

    assert JournalFollower("/d", tmp_path / "cur2", runner=boom).read_new() == []


def docker_client(events):
    body = "\n".join(json.dumps(e) for e in events) + "\n"
    return httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, text=body)),
        base_url="http://docker",
    )


def ev(action, name="jellyfin", t=1001, **attrs):
    return {"Type": "container", "Action": action, "time": t, "timeNano": t * 10**9,
            "Actor": {"Attributes": {"name": name, **attrs}}}


def test_docker_events_unhealthy_is_error():
    c = docker_client([ev("health_status: unhealthy")])
    lines = DockerEvents("/x.sock", client=c, clock=lambda: 1000.0).read_new()
    assert len(lines) == 1
    assert lines[0].severity == 3
    assert lines[0].source == "docker-events"
    assert "jellyfin" in lines[0].message


def test_docker_events_severities():
    c = docker_client([
        ev("die", t=1001, exitCode="1"),
        ev("die", t=1002, exitCode="0"),
        ev("oom", t=1003),
        ev("restart", t=1004),
        ev("health_status: healthy", t=1005),
    ])
    lines = DockerEvents("/x.sock", client=c, clock=lambda: 1000.0).read_new()
    assert [l.severity for l in lines] == [3, 6, 3, 6, 6]


def test_docker_events_not_repeated_and_failure_empty():
    c = docker_client([ev("oom")])
    d = DockerEvents("/x.sock", client=c, clock=lambda: 1000.0)
    assert len(d.read_new()) == 1
    assert len(d.read_new()) == 1  # not committed: would be lost if delivery failed
    d.commit()
    assert d.read_new() == []  # same event returned again by the overlapping window

    def down(req):
        raise httpx.ConnectError("no sock")

    bad = httpx.Client(transport=httpx.MockTransport(down), base_url="http://docker")
    assert DockerEvents("/x", client=bad).read_new() == []


def test_docker_events_failed_read_does_not_commit_stale_position():
    state = {"up": True}
    body = json.dumps(ev("oom")) + chr(10)

    def handler(req):
        if not state["up"]:
            raise httpx.ConnectError("sock down")
        return httpx.Response(200, text=body)

    c = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    d = DockerEvents("/x.sock", client=c, clock=lambda: 1000.0)
    assert len(d.read_new()) == 1  # cycle 1: delivery fails afterwards, so no commit
    state["up"] = False
    assert d.read_new() == []  # cycle 2: socket down
    d.commit()  # send_logs commits after every read, even an empty one
    state["up"] = True
    assert len(d.read_new()) == 1  # the event from cycle 1 must still be delivered


def test_journalctl_stream_is_killed_after_deadline(monkeypatch):
    import sys
    from lanot_agent import logs

    monkeypatch.setattr(logs, "JOURNAL_TIMEOUT", 0.3)
    t0 = time.monotonic()
    got = list(logs._journalctl([sys.executable, "-c", "import time; print('x', flush=True); time.sleep(30)"]))
    assert got == ["x" + chr(10)]
    assert time.monotonic() - t0 < 10


def test_guess_severity_flags_kernel_faults_without_pri():
    from lanot_agent.logs import guess_severity
    for text in ("kernel: Out of memory: Killed process 4242 (java)", "Oops: 0000 [#1] SMP",
                 "XFS (md1p1): Metadata corruption detected", "pool tank is DEGRADED",
                 "zio: checksum fault on vdev", "ata3: I/O error, dev sdb", "oom-kill:constraint=CONSTRAINT_NONE"):
        assert guess_severity(text) == 3, text
    assert guess_severity("usb 1-1: new high-speed USB device") == 6
    assert guess_severity("Set default route via 10.0.0.1") == 6  # no "fault" inside "default"
    assert guess_severity("bedroom zoom") == 6
