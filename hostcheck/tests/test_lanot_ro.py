"""Tests for the lanot-ro forced-command allowlist (security boundary)."""
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = str(Path(__file__).resolve().parent.parent / "lanot-ro")


def run(cmd, dryrun=True):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "SSH_ORIGINAL_COMMAND": cmd}
    if dryrun:
        env["LANOT_RO_DRYRUN"] = "1"
    return subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True)


def argv_of(cmd):
    r = run(cmd)
    assert r.returncode == 0, r.stderr
    return r.stdout.splitlines()


OK = [
    "zpool status tank", "smartctl -a /dev/sda", "journalctl -u docker -n 200",
    "docker logs --tail 100 jellyfin", "ping -c 3 1.1.1.1",
    "journalctl -k -b -p 3 --since 2026-01-01 --until today -n 50",
    "dmesg", "dmesg -T --level=err,warn", "docker ps", "docker ps -a",
    "docker inspect jellyfin", "docker logs --since 10m jellyfin",
    "docker stats --no-stream", "zpool status", "zpool status -v tank",
    "zpool list", "zfs list", "smartctl -H /dev/nvme0n1", "smartctl -i /dev/nvme0",
    "smartctl -j -a /dev/sdaa", "df -h", "free -m", "uptime", "ip addr", "ip route",
    "ip link", "ss -tulpn", "systemctl --failed --no-pager",
    "systemctl status docker.service --no-pager", "getent hosts example.com",
    "traceroute -n -m 10 1.1.1.1", "tail -n 100 /var/log/syslog",
    "tail -n 5 /var/log/docker.log", "tail -n 5 /var/log/messages",
    "cat /proc/mdstat", "cat /var/local/emhttp/disks.ini", "sensors", "lsblk",
]

DENY = [
    "zpool scrub tank", "smartctl -t long /dev/sda", "journalctl --vacuum-size=1M",
    "docker rm jellyfin", "docker exec jellyfin sh", "journalctl; rm -rf /",
    "ping -c 3 1.1.1.1 && reboot", "cat /etc/shadow", "tail -n 10 /etc/shadow",
    "echo `id`", "ls $(id)", "smartctl -a /dev/sda > /etc/passwd",
    "systemctl stop docker", "zpool status tank -o x", "",
    "zpool status tank *", "docker logs --tail 10 --details jellyfin",
    "ping -c 3 -f 1.1.1.1", "journalctl -u ../../etc", "cat /var/log/../../etc/shadow",
    "tail -n 10 /var/log/syslog /etc/shadow",
    "df -h a b c d e f g h i j k l",  # 13 tokens
    "df -h\nreboot", "ping -c 99 1.1.1.1", "smartctl -a /dev/sda1",
    "traceroute -n -m 50 1.1.1.1",
    # extras
    "   ", "ping -c 3 -f", "ping -c 3 -1.1.1.1", "docker logs -f", "docker logs --tail 10 -f",
    "docker logs --tail 99999 x", "journalctl -n 99999", "journalctl -n 0",
    "journalctl -u -f", "journalctl --since -x", "journalctl -u docker -u ssh",
    "journalctl -p 9", "dmesg --level=bogus", "dmesg --level=", "dmesg -c", "dmesg -C",
    "docker inspect -f", "docker ps -a -a", "docker stats", "docker cp a b",
    "systemctl status -l --no-pager", "systemctl status docker", "systemctl --failed",
    "systemctl restart docker --no-pager", "zpool status -x", "zpool destroy tank",
    "zfs destroy tank", "zfs list -t snapshot", "smartctl -a /dev/sda -s on",
    "smartctl -a /dev/../etc/passwd", "smartctl -a sda", "smartctl --scan",
    "smartctl -a /dev/sda /dev/sdb", "tail -n 10 /var/log/syslog.1",
    "tail -f /var/log/syslog", "tail -n 0 /var/log/syslog", "tail -n 99999 /var/log/syslog",
    "cat /proc/mdstat /etc/shadow", "cat", "ip addr add 1.2.3.4 dev lo", "ip route del x",
    "ss -K", "sensors -s", "lsblk -f", "free", "df", "uptime -s", "reboot", "sh", "bash -c id",
    "getent passwd root", "getent hosts -x", "traceroute 1.1.1.1", "traceroute -n -m 0 1.1.1.1",
    "ping 1.1.1.1", "ping -c 0 1.1.1.1", "ping -c 3 1.1.1.1 2.2.2.2",
    "df -h|id", "df -h'", 'df -h"', "df -h\\", "df -h~", "df -h$HOME", "df -h#",
    "df\t-h\treboot;", "docker\u00a0ps", "df -h\r",
    "journalctl --since=today", "journalctl --output=export", "journalctl -o export",
    "docker logs --tail=5 x", "journalctl --vacuum-time=1s",
    "docker inspect --format={{.Config.Env}} x",
    "x" * 129, "docker inspect " + "a" * 129, "df -h " + "-" * 600,
]


@pytest.mark.parametrize("cmd", OK)
def test_allowed(cmd):
    r = run(cmd)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split()[:2] == cmd.split()[:2]


@pytest.mark.parametrize("cmd", DENY)
def test_denied(cmd):
    r = run(cmd)
    assert r.returncode == 2
    assert "denied" in r.stderr
    assert r.stdout == ""


def test_missing_env_denied():
    r = subprocess.run(["bash", SCRIPT], env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    assert r.returncode == 2 and "denied" in r.stderr


def test_journal_gets_no_pager():
    assert run("journalctl -n 5").stdout.strip().endswith("--no-pager")
    assert "--no-pager" in run("journalctl -u docker").stdout.split()


def test_journal_default_n():
    out = run("journalctl -u docker").stdout.split()
    assert out[out.index("-n") + 1] == "500"


def test_smartctl_standby():
    out = run("smartctl -a /dev/sda").stdout.split()
    assert "-n" in out and out[out.index("-n") + 1] == "standby"
    out = run("smartctl -j -a /dev/nvme0n1").stdout.split()
    assert out[out.index("-n") + 1] == "standby"


def test_docker_logs_default_tail():
    out = run("docker logs jellyfin").stdout.split()
    assert out[out.index("--tail") + 1] == "200"
    assert out[-1] == "jellyfin"


def test_docker_logs_tail_cap():
    assert run("docker logs --tail 5000 x").returncode == 0
    assert run("docker logs --tail 5001 x").returncode == 2


def test_ping_forces_timeout():
    out = run("ping -c 3 1.1.1.1").stdout.split()
    assert out[out.index("-W") + 1] == "2"


def test_traceroute_forces_timeout():
    out = run("traceroute -n -m 5 1.1.1.1").stdout.split()
    assert out[out.index("-w") + 1] == "2"


def test_flags_any_order_once():
    assert run("journalctl -n 5 -u docker -b").returncode == 0
    assert run("journalctl -b -b").returncode == 2


def test_syntax_check():
    r = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_hostile_env_not_used():
    r = subprocess.run(["/bin/bash", SCRIPT],
                       env={"PATH": "/tmp/evil", "SSH_ORIGINAL_COMMAND": "uptime",
                            "LANOT_RO_DRYRUN": "1", "BASH_ENV": "/tmp/x", "IFS": "t"},
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "uptime"


def test_inspect_fixed_template_no_secrets():
    a = argv_of("docker inspect jellyfin")
    assert a[:4] == ["docker", "inspect", "--type", "container"]
    assert a[4] == "--format" and a[-1] == "jellyfin"
    for bad in ("Env", "Cmd", "Args", "Labels"):
        assert not any(bad in x for x in a)


def test_dryrun_one_element_per_line():
    a = argv_of("docker inspect jellyfin")
    assert any(" " in x for x in a)  # template stays one element
    assert argv_of("ping -c 2 1.1.1.1") == ["ping", "-c", "2", "-W", "2", "1.1.1.1"]


def test_exec_uses_clean_env():
    src = open(SCRIPT).read()
    assert 'exec env -i PATH="$PATH" LC_ALL=C "${argv[@]}"' in src


# ---- argv mode: command passed as the single argument (sudo drops SSH_ORIGINAL_COMMAND) ----

def run_argv(args, env_cmd=None, dryrun=True):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if env_cmd is not None:
        env["SSH_ORIGINAL_COMMAND"] = env_cmd
    if dryrun:
        env["LANOT_RO_DRYRUN"] = "1"
    return subprocess.run(["bash", SCRIPT, *args], env=env, capture_output=True, text=True)


@pytest.mark.parametrize("cmd", OK)
def test_argv_allowed(cmd):
    r = run_argv([cmd])
    assert r.returncode == 0, r.stderr
    assert r.stdout == run(cmd).stdout


@pytest.mark.parametrize("cmd", DENY)
def test_argv_denied(cmd):
    r = run_argv([cmd])
    assert r.returncode == 2
    assert "denied" in r.stderr
    assert r.stdout == ""


def test_argv_with_empty_env_var():
    # sshd sets SSH_ORIGINAL_COMMAND="" never, but sudo may leave it empty/unset.
    r = run_argv(["uptime"], env_cmd="")
    assert r.returncode == 0 and r.stdout.strip() == "uptime"


def test_argv_no_args_no_env_denied():
    r = run_argv([])
    assert r.returncode == 2 and "denied" in r.stderr


def test_argv_empty_arg_denied():
    # Interactive login without a command: forced command passes "" as $1.
    r = run_argv([""])
    assert r.returncode == 2 and "denied" in r.stderr and r.stdout == ""


@pytest.mark.parametrize("args", [["uptime", "uptime"], ["df", "-h"], ["uptime", ""], ["", ""]])
def test_argv_two_args_denied(args):
    r = run_argv(args)
    assert r.returncode == 2 and "denied" in r.stderr and r.stdout == ""


@pytest.mark.parametrize("arg", ["uptime", "reboot", ""])
def test_argv_and_env_both_set_denied(arg):
    r = run_argv([arg], env_cmd="uptime")
    assert r.returncode == 2 and "denied" in r.stderr and r.stdout == ""


def test_argv_mode_not_executed_without_dryrun_on_deny():
    r = run_argv(["id; reboot"], dryrun=False)
    assert r.returncode == 2 and "denied" in r.stderr and r.stdout == ""
