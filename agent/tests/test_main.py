import json
import subprocess

import httpx
import pytest
from lanot_agent import main as agent_main
from lanot_agent.config import AgentConfig


def cfg_for(tmp_path, root, **kw):
    return AgentConfig(
        host_name="h1", server_url="http://o", agent_token="t",
        host_root=str(root), buffer_dir=str(tmp_path / "buf"),
        docker_sock=str(tmp_path / "no.sock"), **kw,
    )


def test_tick_schedules_and_batches(tmp_path, fake_root):
    posts = []

    def handler(req):
        posts.append((req.url.path, json.loads(req.content)))
        return httpx.Response(200, json={"ok": True})

    log = tmp_path / "syslog"
    log.write_text("".join(f"line {i}\n" for i in range(2500)))
    cfg = cfg_for(tmp_path, fake_root, log_files=[str(log)])
    agent = agent_main.build(cfg, httpx.Client(transport=httpx.MockTransport(handler)))
    agent.state.docker = lambda: []
    agent.tick(0.0)
    paths = [p for p, _ in posts]
    assert paths.count("/api/v1/metrics") == 1 and paths.count("/api/v1/state") == 1
    batches = [b for p, b in posts if p == "/api/v1/logs"]
    assert [len(b["lines"]) for b in batches] == [2000, 500]
    assert posts[0][1]["host"] == "h1"
    assert "power" in posts[0][1] and posts[0][1]["power"] is None  # ENABLE_POWER off
    posts.clear()
    agent.tick(5.0)
    assert posts == []  # nothing due yet
    agent.tick(10.0)
    assert [p for p, _ in posts] == []  # logs due but no new lines
    agent.tick(30.0)
    assert [p for p, _ in posts] == ["/api/v1/metrics"]


def test_tick_survives_failing_source(tmp_path, fake_root):
    class Boom:
        def read_new(self):
            raise RuntimeError("x")

    agent = agent_main.build(cfg_for(tmp_path, fake_root), httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))))
    agent.log_sources = [Boom()]
    agent.tick(0.0)  # must not raise


def test_host_run_returns_stdout_on_nonzero_exit(monkeypatch):
    seen = {}

    def fake(argv, **kw):
        seen["argv"], seen["kw"] = argv, kw
        return subprocess.CompletedProcess(argv, 2, stdout="standby-json", stderr="")

    monkeypatch.setattr(agent_main.subprocess, "run", fake)
    assert agent_main.host_run(["smartctl", "-a", "/dev/sda"]) == "standby-json"
    assert seen["argv"][:8] == ["nsenter", "-t", "1", "-m", "-u", "-n", "-i", "--"]
    assert seen["argv"][8:] == ["smartctl", "-a", "/dev/sda"]
    assert seen["kw"]["timeout"] == 60 and "check" not in seen["kw"]


def test_host_run_raises_on_missing_binary_or_timeout(monkeypatch):
    def missing(argv, **kw):
        raise FileNotFoundError("nsenter")

    monkeypatch.setattr(agent_main.subprocess, "run", missing)
    with pytest.raises(FileNotFoundError):
        agent_main.host_run(["x"])

    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 60)

    monkeypatch.setattr(agent_main.subprocess, "run", slow)
    with pytest.raises(subprocess.TimeoutExpired):
        agent_main.host_run(["x"])


def test_failed_delivery_does_not_commit_log_position(tmp_path, fake_root, monkeypatch):
    posts = []
    up = {"v": False}

    def handler(req):
        if not up["v"]:
            raise httpx.ConnectError("down")
        posts.append((req.url.path, json.loads(req.content)))
        return httpx.Response(200)

    log = tmp_path / "syslog"
    log.write_text("one\ntwo\n")
    agent = agent_main.build(cfg_for(tmp_path, fake_root, log_files=[str(log)]), httpx.Client(transport=httpx.MockTransport(handler)))
    agent.state.docker = lambda: []

    def disk_full(kind, payload):
        raise OSError("disk full")

    real_push = agent.sender.buffer.push
    monkeypatch.setattr(agent.sender.buffer, "push", disk_full)
    agent.tick(0.0)  # server down and buffer full: sending raises, position must stay put
    monkeypatch.setattr(agent.sender.buffer, "push", real_push)
    up["v"] = True
    agent.tick(10.0)
    sent = [m["message"] for p, b in posts if p == "/api/v1/logs" for m in b["lines"]]
    assert sent == ["one", "two"]
    # and a restarted agent does not resend them
    posts.clear()
    agent2 = agent_main.build(cfg_for(tmp_path, fake_root, log_files=[str(log)]), httpx.Client(transport=httpx.MockTransport(handler)))
    agent2.tick(0.0)
    assert [p for p, _ in posts if p == "/api/v1/logs"] == []


def test_buffered_delivery_commits_position(tmp_path, fake_root):
    def handler(req):
        raise httpx.ConnectError("down")

    log = tmp_path / "syslog"
    log.write_text("one\n")
    cfg = cfg_for(tmp_path, fake_root, log_files=[str(log)])
    agent = agent_main.build(cfg, httpx.Client(transport=httpx.MockTransport(handler)))
    agent.state.docker = lambda: []
    agent.tick(0.0)  # undeliverable but safely buffered -> committed
    assert agent.log_sources[0].read_new() == []
    assert agent.sender.buffer.peek() is not None


def test_docker_source_down_after_failed_delivery_loses_nothing(tmp_path, fake_root, monkeypatch):
    from lanot_agent.logs import DockerEvents

    up = {"sock": True, "server": False}
    ev = {"Type": "container", "Action": "oom", "time": 1001, "timeNano": 1001 * 10**9,
          "Actor": {"Attributes": {"name": "c1"}}}
    docker = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, text=json.dumps(ev) + chr(10)) if up["sock"] else (_ for _ in ()).throw(httpx.ConnectError("x"))
        ),
        base_url="http://docker",
    )
    posts = []

    def handler(req):
        if not up["server"]:
            raise httpx.ConnectError("down")
        posts.append(json.loads(req.content))
        return httpx.Response(200)

    agent = agent_main.build(cfg_for(tmp_path, fake_root), httpx.Client(transport=httpx.MockTransport(handler)))
    agent.log_sources = [DockerEvents("/x", client=docker, clock=lambda: 1000.0)]
    real_push = agent.sender.buffer.push
    monkeypatch.setattr(agent.sender.buffer, "push", lambda k, p: (_ for _ in ()).throw(OSError("full")))
    agent.send_logs()  # read ok, delivery raises -> no commit
    up["sock"] = False
    agent.send_logs()  # socket down: empty read, commit must not advance
    monkeypatch.setattr(agent.sender.buffer, "push", real_push)
    up["sock"], up["server"] = True, True
    agent.send_logs()
    assert [l["message"] for b in posts for l in b["lines"]] == ["container c1 was OOM-killed"]
