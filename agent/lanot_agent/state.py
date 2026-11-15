"""Slow-changing host state: containers, ZFS pools, SMART disks, Unraid array.

Host commands go through the injected `run(argv) -> str` (nsenter in prod).
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Callable

import httpx
from lanot_common.protocol import Container, Disk, Pool, StateReport

from .config import AgentConfig

log = logging.getLogger(__name__)

Run = Callable[[list[str]], str]

_HEALTH_RE = re.compile(r"\((healthy|unhealthy|health: starting)\)")


# --- docker -----------------------------------------------------------------


def containers_from(listing: str, inspect: Callable[[str], dict | None] | None = None) -> list[Container]:
    """Parse `GET /containers/json?all=1`. Health comes from the Status text
    unless `inspect(name)` returns a container inspect document, which then
    also provides RestartCount and State.Health.Status."""
    out: list[Container] = []
    for c in json.loads(listing):
        name = c["Names"][0].lstrip("/")
        m = _HEALTH_RE.search(c.get("Status", ""))
        health = {"health: starting": "starting"}.get(m.group(1), m.group(1)) if m else None
        restarts = 0
        info = inspect(name) if inspect else None
        if info:
            restarts = int(info.get("RestartCount", 0))
            health = (info.get("State", {}).get("Health") or {}).get("Status", health)
        out.append(Container(name=name, status=c["State"], health=health, restarts=restarts))
    return out


def docker_containers(client: httpx.Client) -> list[Container]:
    resp = client.get("/containers/json", params={"all": "1"})
    resp.raise_for_status()

    def inspect(name: str) -> dict | None:
        r = client.get(f"/containers/{name}/json")
        return r.json() if r.status_code == 200 else None

    return containers_from(resp.text, inspect)


def _default_docker(sock: str) -> list[Container]:
    with httpx.Client(transport=httpx.HTTPTransport(uds=sock), base_url="http://docker", timeout=10) as c:
        return docker_containers(c)


# --- zfs --------------------------------------------------------------------


def pools_from(list_out: str, status_out: str) -> list[Pool]:
    """`zpool list -Hp` columns: name size alloc free ckpoint expandsz frag cap dedup health altroot."""
    errors: dict[str, str] = {}
    cur = None
    for line in status_out.splitlines():
        s = line.strip()
        if s.startswith("pool:"):
            cur = s.split(":", 1)[1].strip()
        elif s.startswith("errors:") and cur:
            errors[cur] = s.split(":", 1)[1].strip()
    pools = []
    for line in list_out.splitlines():
        f = line.split("\t")
        if len(f) < 10:
            continue
        pools.append(Pool(name=f[0], health=f[9], cap_pct=float(f[7]), errors=errors.get(f[0], "unknown")))
    return pools


# --- smart ------------------------------------------------------------------


def disk_from_smartctl_json(raw: str) -> Disk | None:
    """Returns None when smartctl reported no SMART status (e.g. USB flash)."""
    d = json.loads(raw)
    status = d.get("smart_status")
    if not status or "passed" not in status:
        return None
    attrs: dict[str, int] = {}
    for a in d.get("ata_smart_attributes", {}).get("table", []):
        attrs[a["name"]] = int(a["raw"]["value"])
    for k, v in d.get("nvme_smart_health_information_log", {}).items():
        if isinstance(v, int) and not isinstance(v, bool):
            attrs[k] = v
    return Disk(
        dev=d["device"]["name"],
        model=d.get("model_name", "unknown"),
        smart_passed=bool(status["passed"]),
        attrs=attrs,
    )


def _smart_disks(run: Run) -> list[Disk]:
    disks = []
    for line in run(["smartctl", "--scan"]).splitlines():
        dev = line.split("#")[0].split()
        if not dev:
            continue
        try:
            out = run(["smartctl", "-n", "standby", "-j", "-a", dev[0]])
            if "STANDBY" in out:  # spun down: never wake it, retry next cycle
                continue
            disk = disk_from_smartctl_json(out)
        except Exception:
            log.warning("smartctl failed for %s", dev[0], exc_info=True)
            continue
        if disk:
            disks.append(disk)
    return disks


# --- unraid -----------------------------------------------------------------


def array_from_var_ini(text: str) -> str | None:
    """Unraid array state: `mdState` in /var/local/emhttp/var.ini (STARTED, STOPPED, ...)."""
    m = re.search(r'^mdState="([^"]*)"', text, re.MULTILINE)
    return m.group(1) if m else None


# --- unraid boot files -------------------------------------------------------

BOOT_FILES = ("bzfirmware", "bzmodules", "bzroot", "bzimage", "bzroot-gui")
BOOT_CHECK_EVERY = 3600.0
_CHUNK = 1024 * 1024
_SHA_RE = re.compile(r"^([0-9a-fA-F]{64})(?![0-9a-zA-Z])")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:  # read-only, chunked: the files are up to ~700 MB
        while chunk := f.read(_CHUNK):
            h.update(chunk)
        try:  # drop what we read from the page cache, the host needs it more
            os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        except (AttributeError, OSError):
            pass
    return h.hexdigest()


def boot_files_from(root: Path) -> dict[str, bool]:
    """For each Unraid boot file with a `<file>.sha256` next to it on the USB
    stick (`<root>/boot`), whether the file matches. Files without a .sha256
    are skipped; a missing file, an unparsable .sha256 or any read error
    (e.g. EIO from a dying stick) counts as bad."""
    out: dict[str, bool] = {}
    boot = Path(root) / "boot"
    for name in BOOT_FILES:
        sha_file = boot / f"{name}.sha256"
        try:
            if not sha_file.is_file():
                continue
            m = _SHA_RE.match(sha_file.read_text(errors="replace").strip())
            out[name] = bool(m) and _sha256(boot / name) == m.group(1).lower()
        except OSError:
            out[name] = False
    return out


def _low_priority() -> None:
    """Best effort: lowest CPU and idle I/O priority for the calling thread."""
    try:
        os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 19)
    except Exception:
        pass
    try:
        import ctypes
        import platform

        if platform.machine() != "x86_64":  # the syscall number below is x86_64-only
            return
        IOPRIO_WHO_PROCESS, IOPRIO_CLASS_IDLE, SYS_ioprio_set = 1, 3, 251  # x86_64
        ctypes.CDLL(None, use_errno=True).syscall(
            SYS_ioprio_set, IOPRIO_WHO_PROCESS, threading.get_native_id(), IOPRIO_CLASS_IDLE << 13
        )
    except Exception:
        pass


class BootCheck:
    """Runs `check(root)` at most every BOOT_CHECK_EVERY seconds, by default in a
    low-priority background thread. `result()` never blocks: it returns the
    last finished result (None before the first one, or after a failure)."""

    def __init__(self, root: Path, clock: Callable[[], float] = time.monotonic,
                 check: Callable[[Path], dict[str, bool]] = boot_files_from,
                 every: float = BOOT_CHECK_EVERY, threaded: bool = True) -> None:
        self.root, self.clock, self.check, self.every, self.threaded = Path(root), clock, check, every, threaded
        self._next: float | None = None
        self._result: dict[str, bool] | None = None
        self._thread: threading.Thread | None = None

    def _work(self) -> None:
        if self.threaded:
            _low_priority()
        try:
            self._result = self.check(self.root)
        except Exception:
            log.warning("boot file check failed", exc_info=True)
            self._result = None

    def result(self) -> dict[str, bool] | None:
        now = self.clock()
        busy = self._thread is not None and self._thread.is_alive()
        if not busy and (self._next is None or now >= self._next):
            self._next = now + self.every
            if self.threaded:
                self._thread = threading.Thread(target=self._work, name="boot-check", daemon=True)
                self._thread.start()
            else:
                self._work()
        return self._result

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)


# --- containerd -------------------------------------------------------------


def containerd_running(proc: Path) -> bool:
    """Whether a process named exactly `containerd` runs (like `pgrep -x
    containerd`), read from the host's /proc (pid: host). Raises when /proc
    itself is unreadable, so the caller reports "unknown" instead of "down"."""
    pids = [p for p in Path(proc).iterdir() if p.name.isdigit()]
    if not pids:
        raise OSError(f"no processes under {proc}")
    for p in pids:
        try:
            if (p / "comm").read_text().strip() == "containerd":
                return True
        except OSError:  # process exited meanwhile
            continue
    return False


# --- collector --------------------------------------------------------------


class StateCollector:
    def __init__(
        self,
        cfg: AgentConfig,
        run: Run,
        docker: Callable[[], list[Container]] | None = None,
        boot: BootCheck | None = None,
    ) -> None:
        self.cfg = cfg
        self.run = run
        self.docker = docker or (lambda: _default_docker(cfg.docker_sock))
        self.boot = boot or (BootCheck(Path(cfg.host_root)) if cfg.enable_unraid else None)

    def _safe(self, what: str, fn, default):
        try:
            return fn()
        except Exception:
            log.warning("state collector %s failed", what, exc_info=True)
            return default

    def collect(self, host: str) -> StateReport:
        cfg = self.cfg
        docker_ok = True
        try:
            containers = self.docker()
        except Exception:
            log.warning("state collector docker failed", exc_info=True)
            containers, docker_ok = [], False
        # Only a verdict when the Docker API answered: False = containerd is gone.
        docker_healthy = self._safe("containerd", lambda: containerd_running(Path(cfg.host_root) / "proc"), None) if docker_ok else None
        pools = (
            self._safe(
                "zfs",
                lambda: pools_from(self.run(["zpool", "list", "-Hp"]), self.run(["zpool", "status"])),
                [],
            )
            if cfg.enable_zfs
            else []
        )
        disks = self._safe("smart", lambda: _smart_disks(self.run), []) if cfg.enable_smart else []
        array = (
            self._safe(
                "unraid",
                lambda: array_from_var_ini(
                    (Path(cfg.host_root) / "var/local/emhttp/var.ini").read_text()
                ),
                None,
            )
            if cfg.enable_unraid
            else None
        )
        boot_files = self._safe("boot files", self.boot.result, None) if (cfg.enable_unraid and self.boot) else None
        return StateReport(host=host, ts=time.time(), containers=containers, pools=pools, disks=disks, array=array,
                           boot_files=boot_files, docker_healthy=docker_healthy)
