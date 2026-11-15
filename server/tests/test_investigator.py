"""Investigator: facts, tools, Claude loop, Ollama fallback, daily cap.
No real network, Claude, Ollama or SSH: everything is injected."""

import asyncio
import json
import types

import anthropic
import pytest

try:  # anthropic 2.x ships its own httpx fork
    import httpx2 as _httpx
except ImportError:  # pragma: no cover
    import httpx as _httpx

from conftest import CFG, make_settings
from lanot.db import Incident
from lanot.investigator import anthropic_run
from lanot.investigator.facts import Deps, Diagnosis, collect_facts
from lanot.investigator.ollama_run import run_ollama
from lanot.investigator.runner import CAP_SUMMARY, NONE_SUMMARY, Investigator
from lanot.investigator.tools import Toolbox, redact
from lanot_common.protocol import LogBatch

NOW = 1_800_000_000.0  # 2027-01-15, a fixed epoch for the fake clock


# -- fakes -----------------------------------------------------------------
def block(**kw):
    return types.SimpleNamespace(**kw)


def response(*content, stop_reason="tool_use"):
    return types.SimpleNamespace(content=list(content), stop_reason=stop_reason)


FINAL_INPUT = {
    "summary": "Docker host was gone briefly, cause a short power cut.",
    "what_happened": "Docker host did not answer for 3 minutes.",
    "cause": "Probably a short power cut.",
    "confidence": "likely",
    "suggestions": ["Check the UPS"],
    "evidence": ["Ping 12:00-12:03 failed"],
}


def final_response():
    return response(block(type="tool_use", id="fin", name="final_diagnosis", input=dict(FINAL_INPUT)))


def tool_response(i=0):
    return response(block(type="tool_use", id=f"t{i}", name="query_logs", input={"query": "error"}))


class FakeMessages:
    def __init__(self, script):
        self.script = script  # callable(kwargs, n) -> response, may raise
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.script(kwargs, len(self.calls))


class FakeClaude:
    def __init__(self, script):
        self.messages = FakeMessages(script)


def is_final_request(kwargs) -> bool:
    last = kwargs["messages"][-1]
    content = last["content"]
    if isinstance(content, str):
        return anthropic_run.FINAL_PROMPT in content
    return any(isinstance(b, dict) and b.get("type") == "text" and b.get("text") == anthropic_run.FINAL_PROMPT
               for b in content)


class FakeOllama:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    async def __call__(self, url, payload):
        self.calls.append((url, payload))
        if self.fail:
            raise ConnectionError("no ollama")
        content = dict(FINAL_INPUT, summary="Ollama says: power cut.")
        return {"message": {"role": "assistant", "content": json.dumps(content)}}


class FakeRun:
    def __init__(self, rc=0, out="", err="", exc=None):
        self.rc, self.out, self.err, self.exc = rc, out, err, exc
        self.calls = []

    async def __call__(self, argv, timeout):
        self.calls.append((argv, timeout))
        if self.exc:
            raise self.exc
        return self.rc, self.out, self.err


class FakeFritz:
    def poll(self):
        return {"ok": True, "error": None, "link_up": True, "wan_connected": False}

    def event_log(self, since):
        return ["14.11.26 12:00:00 Internet connection lost", "password=test-pass-1"]


class FakeNotifier:
    def __init__(self):
        self.seen = []

    async def on_diagnosis(self, inc):
        self.seen.append(inc)


async def fake_probe(target, timeout=2.0):
    return True, 1.5


def conn_error():
    return anthropic.APIConnectionError(request=_httpx.Request("POST", "https://api.anthropic.com/v1/messages"))


@pytest.fixture
def settings():
    return make_settings(anthropic_api_key="test-api-key")  # pragma: allowlist secret


def make_deps(db, claude=None, ollama=None, run=None):
    return Deps(db=db, config=CFG, fritz=FakeFritz(), probe=fake_probe, run=run or FakeRun(out="1 192.168.178.1"),
                anthropic=claude, ollama_post=ollama or FakeOllama())


def open_incident(db, rule="device_down", key="docker-host"):
    return db.save_incident(Incident(rule, key, "high", "Docker host unreachable", None, NOW - 60, NOW - 60))


def clock():
    return NOW


# -- end-to-end chain ------------------------------------------------------
async def test_claude_path_used_when_online(db, settings):
    claude = FakeClaude(lambda kw, n: final_response())
    inv = Investigator(make_deps(db, claude=claude), settings, clock)
    inc = open_incident(db)
    d = await inv.investigate(inc)
    assert d.model.startswith("claude")
    assert d.summary == FINAL_INPUT["summary"]
    assert d.confidence == "likely"
    stored = json.loads(db.get_incident(inc.id).diagnosis_json)
    assert stored["summary"] == FINAL_INPUT["summary"]
    assert stored["model"] == settings.anthropic_model
    assert "facts" in stored and stored["facts"]["incident"]["rule"] == "device_down"
    kw = claude.messages.calls[0]
    assert kw["max_tokens"] == 4096
    assert kw["system"] == anthropic_run.system_prompt(CFG)
    assert "Docker host (id docker-host, unraid, 192.0.2.31)" in kw["system"]
    assert {t["name"] for t in kw["tools"]} >= {
        "query_logs", "query_metrics", "net_test", "fritz_status", "fritz_log", "host_cmd", "final_diagnosis"}


async def test_fallback_to_ollama_on_connection_error(db, settings):
    def script(kw, n):
        raise conn_error()

    ollama = FakeOllama()
    inv = Investigator(make_deps(db, claude=FakeClaude(script), ollama=ollama), settings, clock)
    inc = open_incident(db)
    d = await inv.investigate(inc)
    assert d.model == "qwen2.5:7b"
    assert db.get_incident(inc.id).diagnosis_json
    assert json.loads(db.get_incident(inc.id).diagnosis_json)["summary"] == "Ollama says: power cut."
    assert len(ollama.calls) == 1


async def test_internet_down_skips_claude(db, settings):
    claude = FakeClaude(lambda kw, n: final_response())
    inv = Investigator(make_deps(db, claude=claude), settings, clock)
    open_incident(db, rule="internet_down", key="internet")
    inc = open_incident(db)
    d = await inv.investigate(inc)
    assert claude.messages.calls == []
    assert d.model == "qwen2.5:7b"


async def test_no_api_key_skips_claude(db):
    s = make_settings(anthropic_api_key=None)
    claude = FakeClaude(lambda kw, n: final_response())
    d = await Investigator(make_deps(db, claude=claude), s, clock).investigate(open_incident(db))
    assert claude.messages.calls == []
    assert d.model == "qwen2.5:7b"


async def test_both_fail_gives_none(db, settings):
    def script(kw, n):
        raise conn_error()

    notifier = FakeNotifier()
    inv = Investigator(make_deps(db, claude=FakeClaude(script), ollama=FakeOllama(fail=True)),
                       settings, clock, notifier=notifier)
    inc = open_incident(db)
    d = await inv.investigate(inc)
    assert d.model == "none" and d.confidence == "unclear" and d.summary == NONE_SUMMARY
    stored = json.loads(db.get_incident(inc.id).diagnosis_json)
    assert stored["summary"] == NONE_SUMMARY and stored["facts"]["traceroute"]
    assert [i.id for i in notifier.seen] == [inc.id]
    assert notifier.seen[0].diagnosis_json  # notifier sees the stored diagnosis


async def test_tool_limit_enforced(db, settings):
    def script(kw, n):
        return final_response() if is_final_request(kw) else tool_response(n)

    claude = FakeClaude(script)
    inv = Investigator(make_deps(db, claude=claude), settings, clock)
    d = await inv.investigate(open_incident(db))
    assert d.tool_calls == 15
    assert d.model.startswith("claude")
    assert is_final_request(claude.messages.calls[-1])
    assert len(claude.messages.calls) == 16


async def test_parallel_tool_calls_beyond_limit_not_executed(db, settings):
    # 4 tool calls per turn: 16 requested by turn 4, only 15 may run
    def script(kw, n):
        if is_final_request(kw):
            return final_response()
        return response(*[block(type="tool_use", id=f"t{n}-{i}", name="fritz_status", input={})
                          for i in range(4)])

    claude = FakeClaude(script)
    tools = Toolbox(make_deps(db), settings, clock)
    executed = []
    real_call = tools.call

    async def counting(name, args):
        executed.append(name)
        return await real_call(name, args)

    tools.call = counting
    d = await anthropic_run.run_anthropic(object(), tools, settings, client=claude, bundle_text="FACTS")
    assert d.tool_calls == 15 and len(executed) == 15
    # every tool_use got a tool_result, the skipped one flagged as error
    results = claude.messages.calls[-1]["messages"][-1]["content"]
    tr = [b for b in results if b.get("type") == "tool_result"]
    assert len(tr) == 4 and tr[-1]["is_error"] is True


async def test_time_limit_forces_final(db, settings):
    t = {"now": 0.0}

    def mono():
        return t["now"]

    def script(kw, n):
        t["now"] += 50.0  # each API round trip "takes" 50 s
        return final_response() if is_final_request(kw) else tool_response(n)

    claude = FakeClaude(script)
    tools = Toolbox(make_deps(db), settings, clock)
    d = await anthropic_run.run_anthropic(object(), tools, settings, client=claude, bundle_text="F", monotonic=mono)
    assert d.model.startswith("claude")
    assert d.tool_calls < 15
    assert is_final_request(claude.messages.calls[-1])
    assert t["now"] <= anthropic_run.MAX_SECONDS + 50.0


async def test_hanging_api_call_is_cut_off(db, settings, monkeypatch):
    monkeypatch.setattr(anthropic_run, "MAX_SECONDS", 0.3)
    monkeypatch.setattr(anthropic_run, "FINAL_RESERVE_S", 0.1)

    class Hanging:
        def __init__(self):
            self.calls = []
            self.messages = self

        async def create(self, **kw):
            self.calls.append(kw)
            if is_final_request(kw):
                return final_response()
            await asyncio.sleep(10)

    claude = Hanging()
    tools = Toolbox(make_deps(db), settings, clock)
    d = await anthropic_run.run_anthropic(object(), tools, settings, client=claude, bundle_text="F")
    assert d.summary == FINAL_INPUT["summary"] and is_final_request(claude.calls[-1])


async def test_no_final_diagnosis_falls_back(db, settings):
    def script(kw, n):
        return response(block(type="text", text="I do not know."), stop_reason="end_turn")

    inv = Investigator(make_deps(db, claude=FakeClaude(script)), settings, clock)
    d = await inv.investigate(open_incident(db))
    assert d.model == "qwen2.5:7b"


async def test_daily_cap(db, settings):
    claude = FakeClaude(lambda kw, n: final_response())
    inv = Investigator(make_deps(db, claude=claude), settings, clock)
    models = []
    for _ in range(21):
        models.append((await inv.investigate(open_incident(db))).model)
    assert all(m.startswith("claude") for m in models[:20])
    assert models[20] == "none"
    assert len(claude.messages.calls) == 20
    last = db.list_incidents(limit=1)[0]
    stored = json.loads(last.diagnosis_json)
    assert stored["summary"] == CAP_SUMMARY and stored["facts"]["incident"]
    assert db.get_setting("investigations_2027-01-15") == 20


async def test_daily_cap_uses_local_date(db, settings):
    # 2027-01-16 03:00 UTC is still 2027-01-15 in New York (the test config's time zone)
    late = 1_800_068_400.0
    claude = FakeClaude(lambda kw, n: final_response())
    inv = Investigator(make_deps(db, claude=claude), settings, lambda: late)
    await inv.investigate(open_incident(db))
    assert db.get_setting("investigations_2027-01-15") == 1


# -- facts -----------------------------------------------------------------
def _logs(db, items):
    db.insert_logs(LogBatch.model_validate({"host": "docker-host", "lines": [
        {"ts": ts, "source": "kernel", "severity": sev, "message": msg} for ts, sev, msg in items]}), NOW)


async def test_collect_facts_window_and_severity(db):
    inc = open_incident(db)
    _logs(db, [
        (inc.opened_at - 300, 3, "disk error"),
        (inc.opened_at + 300, 4, "warn token=abc123"),
        (inc.opened_at - 900, 3, "too old"),
        (inc.opened_at + 900, 3, "too new"),
        (inc.opened_at, 6, "info only"),
    ])
    db.insert_probe("docker-host", inc.opened_at - 30, False, None)
    db.insert_probe("docker-host", inc.opened_at - 3600, True, 1.0)
    f = await collect_facts(inc, make_deps(db))
    msgs = sorted(l["message"] for l in f.logs)
    assert msgs == ["disk error", "warn token=[REDACTED]"]
    assert f.probes["docker-host"] == [[inc.opened_at - 30, False, None]]
    assert f.fritz["wan_connected"] is False
    assert "[REDACTED]" in f.fritz_log[1] and "test-pass-1" not in json.dumps(f.to_dict())
    assert f.traceroute == "1 192.168.178.1"
    assert f.incident["rule"] == "device_down" and "diagnosis_json" not in f.incident


async def test_collect_facts_clips_log_messages(db):
    inc = open_incident(db)
    _logs(db, [(inc.opened_at, 3, "y" * 2000)])
    f = await collect_facts(inc, make_deps(db))
    assert len(f.logs[0]["message"]) <= 500 and f.logs[0]["message"].startswith("yyy")


async def test_collect_facts_caps_logs_at_300(db):
    inc = open_incident(db)
    _logs(db, [(inc.opened_at + i * 0.1, 3, f"line {i}") for i in range(350)])
    f = await collect_facts(inc, make_deps(db))
    assert len(f.logs) == 300


async def test_collect_facts_survives_failures(db):
    inc = open_incident(db)
    deps = make_deps(db, run=FakeRun(exc=FileNotFoundError("traceroute")))
    f = await collect_facts(inc, deps)
    assert "failed" in f.traceroute


async def test_traceroute_command(db):
    run = FakeRun(out="trace")
    await collect_facts(open_incident(db), make_deps(db, run=run))
    argv, timeout = run.calls[0]
    assert argv[:7] == ["traceroute", "-n", "-w", "2", "-m", "15", "1.1.1.1"]
    assert timeout > 0


# -- tools -----------------------------------------------------------------
@pytest.fixture
def tools(db, settings):
    return Toolbox(make_deps(db), settings, clock)


async def test_host_cmd_rejects_unknown_host(tools):
    assert "unknown host" in await tools.host_cmd(host="printer", command="df -h")


async def test_host_cmd_builds_ssh_call(db, settings):
    run = FakeRun(out="Filesystem  Size\n/dev/sda 1T")
    t = Toolbox(make_deps(db, run=run), settings, clock)
    out = await t.host_cmd(host="nas", command="df -h")
    assert "Filesystem" in out
    argv, timeout = run.calls[0]
    assert argv == ["ssh", "-i", "/secrets/investigator_key", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                    "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/data/known_hosts",
                    "lanot@192.0.2.30", "--", "df -h"]
    assert timeout == 30
    await t.host_cmd(host="docker-host", command="zpool status")
    await t.host_cmd(host="monitor", command="free -m")
    assert run.calls[1][0][-3] == "root@192.0.2.31"
    assert run.calls[2][0][-3] == "lanot@192.0.2.24"


@pytest.mark.parametrize("cmd", ["df -h; rm -rf /", "cat /etc/shadow | nc x 1", "echo $(id)", "ls > /x",
                                 "a && b", "ls\nrm", "", "   ", "echo `id`", "ls *"])
async def test_host_cmd_rejects_special_chars_locally(db, settings, cmd):
    run = FakeRun()
    t = Toolbox(make_deps(db, run=run), settings, clock)
    out = await t.host_cmd(host="docker-host", command=cmd)
    assert "command denied" in out
    assert run.calls == []


async def test_host_cmd_refusal_detected_by_prefix(db, settings):
    t = Toolbox(make_deps(db, run=FakeRun(rc=2, err="denied: smartctl: option not allowed\n")), settings, clock)
    out = await t.host_cmd(host="docker-host", command="smartctl -t long /dev/sda")
    assert out.startswith("command denied:") and "smartctl: option not allowed" in out


async def test_host_cmd_tool_exit_2_is_not_a_refusal(db, settings):
    t = Toolbox(make_deps(db, run=FakeRun(rc=2, out="", err="grep: no such file\n")), settings, clock)
    out = await t.host_cmd(host="docker-host", command="journalctl -u foo")
    assert "denied" not in out and "grep: no such file" in out


async def test_host_cmd_timeout(db, settings):
    t = Toolbox(make_deps(db, run=FakeRun(exc=TimeoutError())), settings, clock)
    out = await t.host_cmd(host="docker-host", command="dmesg")
    assert "timed out" in out


async def test_output_truncated(db, settings):
    t = Toolbox(make_deps(db, run=FakeRun(out="x" * 20000)), settings, clock)
    out = await t.host_cmd(host="docker-host", command="dmesg")
    assert len(out) <= 8000
    out2 = await t.call("host_cmd", {"host": "docker-host", "command": "dmesg"})
    assert len(out2) <= 8000


async def test_host_cmd_output_redacted(db, settings):
    t = Toolbox(make_deps(db, run=FakeRun(out="PASSWORD=supersecret\nok")), settings, clock)
    out = await t.host_cmd(host="docker-host", command="docker inspect web")
    assert "supersecret" not in out and "[REDACTED]" in out and "ok" in out


async def test_call_dispatch_redacts_every_tool(db, settings):
    _logs(db, [(NOW - 30, 3, "login failed api_key=abcdef")])
    t = Toolbox(make_deps(db), settings, clock)
    out = await t.call("query_logs", {"query": "login"})
    assert "abcdef" not in out and "[REDACTED]" in out
    assert "test-pass-1" not in await t.call("fritz_log", {})
    assert "unknown tool" in await t.call("rm_rf", {})
    assert "Error" in await t.call("query_metrics", {"host": "docker-host"})  # missing args


async def test_query_metrics(db, settings):
    from lanot_common.protocol import MetricsReport
    from conftest import sample_metrics
    db.insert_metrics(MetricsReport.model_validate(sample_metrics("docker-host")), NOW - 120)
    t = Toolbox(make_deps(db), settings, clock)
    out = await t.call("query_metrics", {"host": "docker-host", "field": "cpu_pct", "minutes_back": 10})
    assert "12.5" in out
    assert "Error" in await t.call("query_metrics", {"host": "docker-host", "field": "x;drop", "minutes_back": 10})


async def test_net_test_kinds(db, settings):
    seen = []

    async def probe(target, timeout=2.0):
        seen.append(target)
        return target.kind != "tcp", 3.0

    run = FakeRun(out="1 192.168.178.1  0.5 ms")
    deps = Deps(db=db, config=CFG, fritz=FakeFritz(), probe=probe, run=run, anthropic=None, ollama_post=FakeOllama())
    t = Toolbox(deps, settings, clock)
    assert "reachable" in await t.net_test(kind="ping", target="1.1.1.1")
    assert seen[-1].kind == "icmp" and seen[-1].address == "1.1.1.1"
    await t.net_test(kind="dns", target="192.168.178.1")
    assert seen[-1].kind == "dns" and seen[-1].query == "example.com"
    assert "unreachable" in await t.net_test(kind="tcp", target="192.0.2.31", port=22)
    assert seen[-1].port == 22
    await t.net_test(kind="http", target="192.0.2.24", port=8080)
    assert seen[-1].kind == "http"
    out = await t.net_test(kind="traceroute", target="8.8.8.8")
    assert "0.5 ms" in out
    assert run.calls[-1][0] == ["traceroute", "-n", "-w", "2", "-m", "15", "8.8.8.8"]
    assert "invalid" in await t.net_test(kind="traceroute", target="-f evil")
    assert "invalid" in await t.net_test(kind="smtp", target="1.1.1.1")
    assert "port" in await t.net_test(kind="tcp", target="1.1.1.1")


async def test_fritz_status(tools):
    out = await tools.call("fritz_status", {})
    assert "wan_connected" in out


# -- ollama ----------------------------------------------------------------
async def test_run_ollama_payload(db, settings):
    inc = open_incident(db)
    deps = make_deps(db)
    bundle = await collect_facts(inc, deps)
    d = await run_ollama(bundle, settings, post=deps.ollama_post)
    url, payload = deps.ollama_post.calls[0]
    assert url == settings.ollama_url.rstrip("/") + "/api/chat"
    assert payload["model"] == "qwen2.5:7b" and payload["stream"] is False
    assert payload["format"]["properties"]["confidence"]["enum"] == ["certain", "likely", "unclear"]
    assert "test-pass-1" not in json.dumps(payload)
    assert d.model == "qwen2.5:7b" and d.tool_calls == 0 and d.summary == "Ollama says: power cut."


def _ollama_post(**over):
    async def post(url, payload):
        post.calls.append(payload)
        return {"message": {"content": json.dumps(dict(FINAL_INPUT, **over))}}
    post.calls = []
    return post


async def test_ollama_confidence_certain_capped(db, settings):
    bundle = await collect_facts(open_incident(db), make_deps(db))
    d = await run_ollama(bundle, settings, post=_ollama_post(confidence="certain"))
    assert d.confidence == "likely"
    assert "local model" in d.what_happened and "Please verify" in d.what_happened
    d = await run_ollama(bundle, settings, post=_ollama_post(confidence="unclear"))
    assert d.confidence == "unclear"


async def test_ollama_answer_passed_through(db, settings):
    bundle = await collect_facts(open_incident(db), make_deps(db))
    d = await run_ollama(bundle, settings, post=_ollama_post())
    assert d.summary == FINAL_INPUT["summary"]


async def test_ollama_prompt_starts_with_incident_title(db, settings):
    inc = open_incident(db)
    bundle = await collect_facts(inc, make_deps(db))
    post = _ollama_post()
    await run_ollama(bundle, settings, post=post)
    system, user = (m["content"] for m in post.calls[0]["messages"])
    assert "Answer in English only" in system and "Answer in English only" in user
    assert "If the facts are not enough, say so" in user
    assert user.startswith("Incident: " + inc.title)
    assert inc.rule in user.split("Log lines")[0] and inc.key in user.split("Log lines")[0]


async def test_run_ollama_bad_json_raises(db, settings):
    async def post(url, payload):
        return {"message": {"content": "not json"}}

    with pytest.raises(Exception):
        await run_ollama(await collect_facts(open_incident(db), make_deps(db)), settings, post=post)


def test_diagnosis_fields():
    d = Diagnosis("s", "w", "c", "unclear", [], [], "none", 0, 0.0)
    assert d.summary == "s" and d.model == "none"


# -- redaction -------------------------------------------------------------
# Fake credentials in the shapes the redactor knows. They are glued together at
# run time so that secret scanners do not mistake this file for a leak.
FAKE_PEM = ("-----BEGIN " + "OPENSSH PRI" + "VATE KEY-----\nAAAAB3Nza\nmore\n"
            "-----END " + "OPENSSH PRI" + "VATE KEY-----")
FAKE_JWT = ".".join(["eyJ" + "hbGciOiJub25lIn0", "eyJ" + "zdWIiOiJ0ZXN0In0", "test-signature"])
FAKE_AWS_ID = "AK" + "IA" + "TESTTESTTESTTEST"
FAKE_ANTHROPIC_KEY = "sk-" + "ant-" + "test-0000"
FAKE_OPENAI_KEY = "sk-" + "test" + "0" * 24


@pytest.mark.parametrize("text,secret", [
    ("password=hunter2", "hunter2"),
    ("PASSWD: example", "example"),
    ("pwd=abc", "abc"),
    ("client_secret = s3cr3t", "s3cr3t"),
    ("token:xyz789", "xyz789"),
    ("api_key=k1", "k1"),
    ("API-KEY: k2", "k2"),
    ("apikey=k3", "k3"),
    ('{"password": "hunter2"}', "hunter2"),  # pragma: allowlist secret
    ("{'db_password': 'hunter2'}", "hunter2"),  # pragma: allowlist secret
    ('password: "hunter two"', "two"),  # pragma: allowlist secret
    ("password='hunter two'", "two"),  # pragma: allowlist secret
    ("SECRET_KEY=abc123", "abc123"),
    ("DB_PASS=xyz", "xyz"),
    ("DB_PWD=x9", "x9"),
    ("mysql-pass: q1w2", "q1w2"),
    ("passphrase=foo1", "foo1"),
    ("aws_credentials=c0ffee", "c0ffee"),
    ("APIKEY=k4", "k4"),
    ("--password hunter2", "hunter2"),
    ("--password=hunter3", "hunter3"),
    ("--token abc999", "abc999"),
    ("--secret=s9", "s9"),
    ("--api-key k5", "k5"),
    ("--db-password hunter4", "hunter4"),
    ('--password "two words"', "words"),
    ('{"Authorization": "Bearer abc123"}', "abc123"),
    ("Authorization: Bearer abc.def", "abc.def"),
    ("authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    (FAKE_PEM, "AAAAB3Nza"),
    (f"jwt {FAKE_JWT}", FAKE_JWT.split(".")[1]),
    (f"aws {FAKE_AWS_ID} here", FAKE_AWS_ID),
    (f"key {FAKE_ANTHROPIC_KEY} end", FAKE_ANTHROPIC_KEY),
    (f"openai {FAKE_OPENAI_KEY}", FAKE_OPENAI_KEY),
])
def test_redact(text, secret):
    out = redact(text)
    assert secret not in out and "[REDACTED]" in out


def test_redact_keeps_key_readable():
    assert redact('{"password": "hunter2", "user": "alice"}') == '{"password": "[REDACTED]", "user": "alice"}'  # pragma: allowlist secret
    assert redact("DB_PASS=xyz rest") == "DB_PASS=[REDACTED] rest"
    assert redact('password: "hunter two" end') == 'password: "[REDACTED]" end'  # pragma: allowlist secret
    assert redact("--password hunter2 -u root") == "--password [REDACTED] -u root"
    assert redact("Authorization: Bearer abc") == "Authorization: [REDACTED]"


@pytest.mark.parametrize("text", [
    "auth: Failed for user root",
    "pam_unix(sshd:auth): authentication failure; user=root",
    "PWD=/root",
    "check passed: disk ok",
    "bypass=1 compass: north",
    "3 passed, 0 failed",
])
def test_redact_keeps_non_secrets(text):
    assert redact(text) == text


@pytest.mark.parametrize("text", [
    "token" * 20000,
    "pass_" * 20000,
    "-" * 100000,
    "--" + "a-" * 50000,
    '"password": "' + "a" * 100000,  # pragma: allowlist secret
    "x " * 50000,
])
def test_redact_is_fast_on_hostile_lines(text):
    import time
    t0 = time.perf_counter()
    redact(text)
    assert time.perf_counter() - t0 < 1.0


def test_kv_regex_itself_is_not_quadratic():
    import time
    from lanot.investigator import tools as tmod
    t0 = time.perf_counter()
    tmod._KV_RE.sub(tmod._value_sub, "token" * 20000)
    tmod._CLI_RE.sub(tmod._value_sub, "--" + "a-" * 50000)
    assert time.perf_counter() - t0 < 1.0


def test_redact_cuts_long_lines():
    out = redact("a" * 5000 + " password=late\nshort")
    first, _, rest = out.partition("\n")
    assert len(first) <= 4000 and first.endswith("…[cut]") and "late" not in out
    assert rest == "short"


@pytest.mark.parametrize("text,leak", [
    (r'{"password": "a\"b"}', "b"),  # pragma: allowlist secret
    (r"{'secret': 'x\'y'}", "y"),  # pragma: allowlist secret
    (r'token="ab\\"', "ab"),
])
def test_redact_escaped_quotes(text, leak):
    out = redact(text)
    assert leak not in out.replace("REDACTED", "")
    assert out.count('"') % 2 == 0 and out.count("'") % 2 == 0


def test_redact_escaped_quote_exact():
    assert redact(r'{"password": "a\"b", "user": "x"}') == '{"password": "[REDACTED]", "user": "x"}'  # pragma: allowlist secret


@pytest.mark.parametrize("text,expected", [
    ("Bearer abc.def-ghi_jkl~+/==", "Bearer [REDACTED]"),
    ("got bearer eyx123 from proxy", "got Bearer [REDACTED] from proxy"),
    ('curl -H "Authorization: Bearer abc" https://x', 'curl -H "Authorization: [REDACTED]" https://x'),
    ("Authorization: Bearer abc", "Authorization: [REDACTED]"),
])
def test_redact_bearer(text, expected):
    assert redact(text) == expected


def test_redact_keeps_harmless_text():
    text = "disk /dev/sda temperature 45 C, pool tank ONLINE"
    assert redact(text) == text
    assert redact("") == ""


def test_bundle_redacts_secret_keys(db):
    from lanot.investigator.facts import FactBundle
    b = FactBundle(incident={"title": "x"}, probes={}, fritz={"password": "pw123", "ok": True}, fritz_log=[],  # pragma: allowlist secret
                   logs=[], metrics={}, traceroute="")
    assert "pw123" not in b.to_text() and "pw123" not in json.dumps(b.to_dict())
    b2 = FactBundle(incident={}, fritz={"DB_PASS": "x1", "auth": "ok"})
    assert b2.to_dict()["fritz"] == {"DB_PASS": "[REDACTED]", "auth": "ok"}
    assert b.to_dict()["fritz"]["ok"] is True


# -- follow-up investigations --------------------------------------------------------
async def test_followup_never_replaces_ai_diagnosis_with_fallback(db, settings):
    def script(kw, n):
        raise conn_error()

    notifier = FakeNotifier()
    inv = Investigator(make_deps(db, claude=FakeClaude(script), ollama=FakeOllama(fail=True)),
                       settings, clock, notifier=notifier)
    inc = open_incident(db)
    good = json.dumps({"summary": "Good diagnosis", "model": "claude-sonnet-5-5", "confidence": "certain"})
    db.set_diagnosis(inc.id, good)
    d = await inv.investigate(db.get_incident(inc.id), followup=True)
    assert d.model == "none"
    assert db.get_incident(inc.id).diagnosis_json == good  # kept
    assert notifier.seen == []  # no useless push


async def test_followup_is_marked(db, settings):
    claude = FakeClaude(lambda kw, n: final_response())
    inv = Investigator(make_deps(db, claude=claude), settings, clock)
    inc = open_incident(db)
    db.set_diagnosis(inc.id, json.dumps({"summary": "old", "model": "claude-sonnet-5-5"}))
    await inv.investigate(db.get_incident(inc.id), followup=True)
    stored = json.loads(db.get_incident(inc.id).diagnosis_json)
    assert stored["followup"] is True and stored["summary"] == FINAL_INPUT["summary"]


async def test_first_investigation_is_not_a_followup(db, settings):
    claude = FakeClaude(lambda kw, n: final_response())
    inc = open_incident(db)
    await Investigator(make_deps(db, claude=claude), settings, clock).investigate(inc)
    assert "followup" not in json.loads(db.get_incident(inc.id).diagnosis_json)


# -- compact Ollama prompt ----------------------------------------
from lanot.investigator.facts import FactBundle as _FB  # noqa: E402
from lanot.investigator.ollama_run import NUM_CTX, build_user_prompt  # noqa: E402


def _big_bundle():
    logs = []
    for i in range(300):
        for host in ("docker-host", "nas", "monitor"):
            logs.append({"id": len(logs), "host": host, "ts": 1000.0 + i, "received": 1000.0 + i, "source": "kernel",
                         "severity": 3 if i % 2 else 6, "message": f"{host}-line {i} " + "x" * 480})
    probes = {t: [[1000.0 + 10 * i, i % 7 != 0, 1.5] for i in range(60)]
              for t in ("gateway", "router", "cloudflare", "google", "docker-host", "nas", "monitor", "dns-router")}
    metrics = {"host": "docker-host", "series": {
        "cpu_pct": [[1000.0 + i, 10.0 + i % 50] for i in range(120)],
        "mem_used": [[1000.0 + i, 4e9] for i in range(120)], "mem_total": [[1000.0 + i, 8e9] for i in range(120)],
        "temps.cpu": [[1000.0 + i, 55.0] for i in range(120)], "load1": [[1000.0 + i, 0.7] for i in range(120)]}}
    return _FB(incident={"id": 7, "rule": "device_down", "key": "docker-host", "title": "Docker host unreachable",
                         "severity": "high", "opened_at": 1300.0, "detail": "192.0.2.31 does not answer"},
               probes=probes, fritz={"ok": True, "link_up": True, "wan_connected": True, "external_ip": "1.2.3.4",
                                     "downstream_kbps": 500000, "upstream_kbps": 100000, "ts": 1300.0},
               fritz_log=[f"14:0{i} event {i}" for i in range(50)], logs=logs, metrics=metrics,
               traceroute="\n".join(f" {i}  10.0.0.{i}  1.0 ms" for i in range(1, 16)))


def test_ollama_prompt_compact_for_large_bundle():
    user = build_user_prompt(_big_bundle(), CFG)
    assert len(user) / 3.5 < 6000


def test_ollama_prompt_only_incident_host_logs_max_40():
    user = build_user_prompt(_big_bundle(), CFG)
    assert "docker-host-line" in user and "nas-line" not in user and "monitor-line" not in user
    assert user.count("docker-host-line") <= 40
    line = next(l for l in user.splitlines() if "docker-host-line" in l)
    assert len(line) <= 330
    assert "docker-host-line 299" in user  # newest kept


def test_ollama_prompt_summarises_probes_and_ends_with_instruction():
    user = build_user_prompt(_big_bundle(), CFG)
    assert "cloudflare: 51/60 ok" in user
    assert user.rstrip().endswith("}")  # JSON schema last
    tail = user[-2500:]
    assert "Answer in English only" in tail and "only from the facts" in tail and '"summary"' in tail
    assert "FritzBox: line in sync yes, internet connected yes" in user


async def test_ollama_sets_num_ctx_and_warns_on_truncation(caplog):
    seen = []

    async def post(url, payload):
        seen.append(payload)
        return {"message": {"content": json.dumps(FINAL_INPUT)}, "prompt_eval_count": NUM_CTX}

    await run_ollama(_big_bundle(), make_settings(), post=post)
    assert seen[0]["options"]["num_ctx"] == 8192 == NUM_CTX
    assert "truncat" in caplog.text.lower()


def test_tool_defs_follow_the_config():
    from lanot.config import LanotConfig, Router
    from lanot.investigator.tools import tool_defs
    names = {t["name"] for t in tool_defs(CFG)}
    assert {"host_cmd", "fritz_status", "fritz_log"} <= names
    ssh = next(t for t in tool_defs(CFG) if t["name"] == "host_cmd")
    assert ssh["input_schema"]["properties"]["host"]["enum"] == ["docker-host", "nas", "monitor"]
    bare = {t["name"] for t in tool_defs(LanotConfig(router=Router(type="generic")))}
    assert bare == {"query_logs", "query_metrics", "net_test"}
