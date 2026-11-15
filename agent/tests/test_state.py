import json

import httpx
from agent_support import fixture
from lanot_common.protocol import Container, Pool

from lanot_agent.config import AgentConfig
from lanot_agent.state import (
    StateCollector,
    array_from_var_ini,
    containers_from,
    disk_from_smartctl_json,
    docker_containers,
    pools_from,
)


def test_zpool_parse():
    pools = pools_from(fixture("zpool_list.txt"), fixture("zpool_status.txt"))
    assert [p.name for p in pools] == ["boot-pool", "tank", "backup"]
    assert pools[1] == Pool(name="tank", health="ONLINE", cap_pct=93.0, errors="No known data errors")


def test_zpool_errors_from_status():
    status = "  pool: tank\n state: DEGRADED\nerrors: 2 data errors, use '-v' for a list\n"
    lst = "tank\t100\t90\t10\t-\t-\t1\t90\t1.00\tDEGRADED\t-\n"
    assert pools_from(lst, status) == [
        Pool(name="tank", health="DEGRADED", cap_pct=90.0, errors="2 data errors, use '-v' for a list")
    ]


def test_zpool_no_pools():
    assert pools_from("", "no pools available\n") == []


def test_smart_parse():
    d = disk_from_smartctl_json(fixture("smart_sda.json"))
    assert d.smart_passed and d.attrs["Reallocated_Sector_Ct"] == 0
    assert d.dev == "/dev/sdd" and d.model == "EXAMPLE-HDD-12TB"


def test_smart_failed():
    raw = json.dumps(
        {
            "device": {"name": "/dev/sdx"},
            "model_name": "M",
            "smart_status": {"passed": False},
            "ata_smart_attributes": {"table": [{"name": "Reallocated_Sector_Ct", "raw": {"value": 8}}]},
        }
    )
    d = disk_from_smartctl_json(raw)
    assert not d.smart_passed and d.attrs == {"Reallocated_Sector_Ct": 8}


def test_unraid_array():
    assert array_from_var_ini(fixture("var.ini")) == "STARTED"
    assert array_from_var_ini('mdState="STOPPED"\n') == "STOPPED"


def test_unraid_array_none():
    assert array_from_var_ini("") is None


def test_unhealthy_container():
    got = containers_from(fixture("containers.json"))
    assert got[0] == Container(name="jellyfin", status="running", health="unhealthy", restarts=0)
    assert got[-1].status == "created" and got[-1].health is None


def test_container_restarts_from_inspect():
    insp = json.loads(fixture("inspect_container.json"))
    insp["RestartCount"] = 4
    got = containers_from(fixture("containers.json"), inspect=lambda name: insp if name == "jellyfin" else None)
    assert got[0].restarts == 4 and got[0].health == "unhealthy"


def test_docker_containers_over_http():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/containers/json":
            assert req.url.params["all"] == "1"
            return httpx.Response(200, text=fixture("containers.json"))
        if req.url.path == "/containers/jellyfin/json":
            return httpx.Response(200, text=fixture("inspect_container.json"))
        return httpx.Response(404, json={"message": "no such container"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://docker")
    got = docker_containers(client)
    assert got[0] == Container(name="jellyfin", status="running", health="unhealthy", restarts=0)
    assert len(got) == 6


def _cfg(**kw):
    env = {"HOST_NAME": "nas", "LANOT_URL": "http://o", "AGENT_TOKEN": "t", **kw}
    return AgentConfig.from_env(env)


def test_config_defaults_and_flags():
    c = _cfg()
    assert c.host_root == "/host" and c.buffer_dir == "/buffer"
    assert c.log_files == [] and c.journal_dir == ""
    assert not c.enable_zfs and not c.enable_smart
    c = _cfg(ENABLE_ZFS="true", ENABLE_SMART="1", LOG_FILES="/a, /b", ENABLE_UNRAID="no")
    assert c.enable_zfs and c.enable_smart and not c.enable_unraid
    assert c.log_files == ["/a", "/b"]


def test_state_collector_all_sources(tmp_path):
    (tmp_path / "var/local/emhttp").mkdir(parents=True)
    (tmp_path / "var/local/emhttp/var.ini").write_text(fixture("var.ini"))
    def run(argv):
        cmd = " ".join(argv)
        if cmd.startswith("zpool list"):
            return fixture("zpool_list.txt")
        if cmd.startswith("zpool status"):
            return fixture("zpool_status.txt")
        if cmd.startswith("smartctl --scan"):
            return "/dev/sdd -d sat # /dev/sdd [SAT], ATA device\n"
        if cmd.startswith("smartctl -n standby -j -a /dev/sdd"):
            return fixture("smart_sda.json")
        raise AssertionError(cmd)

    cfg = _cfg(ENABLE_ZFS="1", ENABLE_SMART="1", ENABLE_UNRAID="1", HOST_ROOT=str(tmp_path))
    s = StateCollector(cfg, run, docker=lambda: [Container(name="x", status="running", health=None, restarts=0)]).collect("nas")
    assert s.host == "nas" and s.array == "STARTED"
    assert [p.name for p in s.pools] == ["boot-pool", "tank", "backup"]
    assert s.disks[0].dev == "/dev/sdd" and s.containers[0].name == "x"


def test_state_collector_isolates_failures():
    def run(argv):
        raise RuntimeError("boom")

    cfg = _cfg(ENABLE_ZFS="1", ENABLE_SMART="1", ENABLE_UNRAID="1")
    s = StateCollector(cfg, run, docker=lambda: (_ for _ in ()).throw(OSError("no sock"))).collect("h")
    assert s.pools == [] and s.disks == [] and s.containers == [] and s.array is None


STANDBY_OUT = json.dumps(
    {
        "smartctl": {
            "messages": [{"string": "Device is in STANDBY mode, exit(2)", "severity": "information"}],
            "exit_status": 2,
        }
    }
)


def test_standby_disk_is_skipped_without_waking_it():
    calls = []

    def run(argv):
        calls.append(argv)
        if argv[:2] == ["smartctl", "--scan"]:
            return "/dev/sdb -d sat # x\n/dev/sdd -d sat # y\n"
        if argv[-1] == "/dev/sdb":
            return STANDBY_OUT
        return fixture("smart_sda.json")

    cfg = _cfg(ENABLE_SMART="1")
    s = StateCollector(cfg, run, docker=lambda: []).collect("h")
    assert [d.dev for d in s.disks] == ["/dev/sdd"]
    smart_calls = [c for c in calls if c[:2] != ["smartctl", "--scan"]]
    assert smart_calls and all(c[:3] == ["smartctl", "-n", "standby"] for c in smart_calls)


# --- boot files (Unraid) and containerd ---------------------------------------

import hashlib as _hashlib

from lanot_agent.state import BOOT_FILES, BootCheck, boot_files_from


def _boot(root, name, data: bytes, good=True, fmt="{h}  /boot/{n}\n"):
    (root / "boot").mkdir(parents=True, exist_ok=True)
    (root / "boot" / name).write_bytes(data)
    h = _hashlib.sha256(data if good else data + b"x").hexdigest()
    (root / "boot" / f"{name}.sha256").write_text(fmt.format(h=h, n=name))


def test_boot_files_ok_and_corrupt(tmp_path):
    _boot(tmp_path, "bzfirmware", b"a" * (3 * 1024 * 1024 + 7), good=False)
    _boot(tmp_path, "bzmodules", b"m" * 10, fmt="{h}\n")
    _boot(tmp_path, "bzroot", b"r", fmt="{h}")
    _boot(tmp_path, "bzimage", b"i", fmt="{h}  bzimage\r\n")
    assert BOOT_FILES == ("bzfirmware", "bzmodules", "bzroot", "bzimage", "bzroot-gui")
    assert boot_files_from(tmp_path) == {"bzfirmware": False, "bzmodules": True, "bzroot": True, "bzimage": True}


def test_boot_files_uppercase_hash_ok(tmp_path):
    (tmp_path / "boot").mkdir()
    (tmp_path / "boot/bzroot").write_bytes(b"r")
    (tmp_path / "boot/bzroot.sha256").write_text(_hashlib.sha256(b"r").hexdigest().upper())
    assert boot_files_from(tmp_path) == {"bzroot": True}


def test_boot_files_missing_are_skipped_and_garbage_is_bad(tmp_path):
    assert boot_files_from(tmp_path) == {}
    (tmp_path / "boot").mkdir()
    (tmp_path / "boot/bzroot").write_bytes(b"r")  # no .sha256 -> not checked
    (tmp_path / "boot/bzimage").write_bytes(b"i")
    (tmp_path / "boot/bzimage.sha256").write_text("not a hash\n")
    (tmp_path / "boot/bzmodules.sha256").write_text("ab" * 32)  # file itself missing
    assert boot_files_from(tmp_path) == {"bzimage": False, "bzmodules": False}


def test_boot_files_never_written(tmp_path):
    _boot(tmp_path, "bzroot", b"r")
    before = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in (tmp_path / "boot").iterdir()}
    boot_files_from(tmp_path)
    after = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in (tmp_path / "boot").iterdir()}
    assert before == after


def test_boot_check_hourly(tmp_path):
    _boot(tmp_path, "bzroot", b"r")
    now = [1000.0]
    calls = []
    def check(root):
        calls.append(root)
        return {"bzroot": True}
    bc = BootCheck(tmp_path, clock=lambda: now[0], check=check, threaded=False)
    assert bc.result() == {"bzroot": True} and len(calls) == 1
    now[0] += 3599
    assert bc.result() == {"bzroot": True} and len(calls) == 1  # cached
    now[0] += 2
    bc.result()
    assert len(calls) == 2


def test_boot_check_threaded_reports_none_until_done(tmp_path):
    import threading
    gate = threading.Event()
    def check(root):
        gate.wait(5)
        return {"bzroot": False}
    bc = BootCheck(tmp_path, clock=lambda: 0.0, check=check)
    assert bc.result() is None  # running in the background
    gate.set()
    bc.join(5)
    assert bc.result() == {"bzroot": False}


def test_boot_check_failure_gives_none(tmp_path):
    def check(root):
        raise OSError("usb gone")
    bc = BootCheck(tmp_path, clock=lambda: 0.0, check=check, threaded=False)
    assert bc.result() is None


def _proc(root, *names):
    for i, n in enumerate(names, start=1):
        (root / "proc" / str(i)).mkdir(parents=True)
        (root / "proc" / str(i) / "comm").write_text(n + "\n")
    (root / "proc" / "self").mkdir(parents=True, exist_ok=True)  # non-numeric entries ignored


def _norun(argv):
    raise AssertionError(argv)


def _ctr():
    return [Container(name="x", status="running", health=None, restarts=0)]


def test_docker_healthy_true_false(tmp_path):
    _proc(tmp_path / "a", "systemd", "dockerd", "containerd", "containerd-shim")
    _proc(tmp_path / "b", "systemd", "dockerd", "containerd-shim")  # shim alone does not count
    for sub, want in (("a", True), ("b", False)):
        cfg = _cfg(HOST_ROOT=str(tmp_path / sub))
        assert StateCollector(cfg, _norun, docker=_ctr).collect("h").docker_healthy is want


def test_docker_healthy_unknown_when_docker_or_proc_fails(tmp_path):
    _proc(tmp_path, "containerd")
    boom = lambda: (_ for _ in ()).throw(OSError("no sock"))
    assert StateCollector(_cfg(HOST_ROOT=str(tmp_path)), _norun, docker=boom).collect("h").docker_healthy is None
    # no /proc at all, or an empty one: unknown, never "down"
    assert StateCollector(_cfg(HOST_ROOT=str(tmp_path / "x")), _norun, docker=_ctr).collect("h").docker_healthy is None
    (tmp_path / "y" / "proc").mkdir(parents=True)
    assert StateCollector(_cfg(HOST_ROOT=str(tmp_path / "y")), _norun, docker=_ctr).collect("h").docker_healthy is None


def test_boot_files_only_with_unraid(tmp_path):
    _boot(tmp_path, "bzroot", b"r")
    cfg = _cfg(HOST_ROOT=str(tmp_path))
    assert StateCollector(cfg, _norun, docker=_ctr).collect("h").boot_files is None
    cfg = _cfg(HOST_ROOT=str(tmp_path), ENABLE_UNRAID="1")
    sc = StateCollector(cfg, _norun, docker=_ctr, boot=BootCheck(tmp_path, clock=lambda: 0.0, threaded=False))
    assert sc.collect("h").boot_files == {"bzroot": True}


def test_boot_files_eio_marks_file_bad(tmp_path, monkeypatch):
    import errno
    import pathlib
    import lanot_agent.state as st
    _boot(tmp_path, "bzroot", b"r")
    _boot(tmp_path, "bzimage", b"i")
    _boot(tmp_path, "bzmodules", b"m")

    real_open = open
    def bad_open(path, *a, **kw):
        if str(path).endswith("/boot/bzroot"):
            raise OSError(errno.EIO, "Input/output error")
        return real_open(path, *a, **kw)
    monkeypatch.setattr("builtins.open", bad_open)

    real_read_text = pathlib.Path.read_text
    def bad_read_text(self, *a, **kw):
        if self.name == "bzimage.sha256":
            raise OSError(errno.EIO, "Input/output error")
        return real_read_text(self, *a, **kw)
    monkeypatch.setattr(pathlib.Path, "read_text", bad_read_text)

    assert st.boot_files_from(tmp_path) == {"bzmodules": True, "bzroot": False, "bzimage": False}


def test_boot_files_include_bzroot_gui(tmp_path):
    _boot(tmp_path, "bzroot-gui", b"g", good=False)
    assert boot_files_from(tmp_path) == {"bzroot-gui": False}


def test_boot_files_drop_page_cache(tmp_path, monkeypatch):
    import lanot_agent.state as st
    calls = []
    monkeypatch.setattr(st.os, "posix_fadvise", lambda fd, off, ln, adv: calls.append((off, ln, adv)), raising=False)
    monkeypatch.setattr(st.os, "POSIX_FADV_DONTNEED", 4, raising=False)
    _boot(tmp_path, "bzroot", b"r")
    _boot(tmp_path, "bzimage", b"i")
    assert boot_files_from(tmp_path) == {"bzroot": True, "bzimage": True}
    assert calls == [(0, 0, 4), (0, 0, 4)]
