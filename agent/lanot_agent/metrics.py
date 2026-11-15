"""Host metrics read straight from /proc and /sys under a root directory."""

import os
import time
from pathlib import Path

from lanot_common.protocol import FsUsage, MetricsReport

from .power import read_power

REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "ntfs", "ntfs3", "fuseblk", "exfat"}


def _read(p: Path) -> str:
    try:
        return p.read_text()
    except OSError:
        return ""


def _cpu_times(root: Path) -> tuple[int, int] | None:
    for line in _read(root / "proc/stat").splitlines():
        if line.startswith("cpu "):
            v = [int(x) for x in line.split()[1:]]
            idle = v[3] + (v[4] if len(v) > 4 else 0)  # idle + iowait
            return sum(v[:8]), idle
    return None


def _net_bytes(root: Path) -> tuple[int, int]:
    rx = tx = 0
    # PID 1 (pid: host) gives the host netns; the container must also run with
    # network_mode: host so /sys/class/net matches.
    for line in _read(root / "proc/1/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        iface = name.strip()
        if not rest or not (root / "sys/class/net" / iface / "device").exists():
            continue  # only physical NICs: skips lo, docker0, br-*, veth*, tailscale
        f = rest.split()
        rx += int(f[0])
        tx += int(f[8])
    return rx, tx


def _meminfo(root: Path) -> tuple[int, int]:
    d: dict[str, int] = {}
    for line in _read(root / "proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        parts = v.split()
        if parts:
            d[k] = int(parts[0]) * 1024
    total = d.get("MemTotal", 0)
    return total, total - d.get("MemAvailable", d.get("MemFree", 0))


def _temps(root: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    base = root / "sys/class/hwmon"
    if not base.is_dir():
        return out
    hws = sorted(base.iterdir())
    names = {hw: _read(hw / "name").strip() or hw.name for hw in hws}
    for hw in hws:
        chip = names[hw]
        if list(names.values()).count(chip) > 1:  # e.g. several drivetemp chips
            chip = f"{chip}.{hw.name}"
        for t in sorted(hw.glob("temp*_input")):
            try:
                val = int(t.read_text().strip()) / 1000
            except (OSError, ValueError):
                continue
            label = _read(hw / t.name.replace("_input", "_label")).strip() or t.name.removesuffix("_input")
            out[f"{chip}/{label}"] = val
    return out


def _filesystems(root: Path) -> list[FsUsage]:
    out: list[FsUsage] = []
    seen: set[str] = set()
    for line in _read(root / "proc/1/mounts").splitlines():
        f = line.split()
        if len(f) < 3 or f[2] not in REAL_FS or f[1] in seen:
            continue
        mount = f[1]
        try:
            st = os.statvfs(root / mount.lstrip("/"))
        except OSError:
            continue
        seen.add(mount)
        total = st.f_blocks * st.f_frsize
        out.append(FsUsage(mount=mount, total=total, used=total - st.f_bfree * st.f_frsize))
    return out


class MetricsCollector:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._cpu: tuple[int, int] | None = None
        self._net: tuple[int, int, float] | None = None

    def _cpu_pct(self) -> float:
        cur = _cpu_times(self.root)
        prev, self._cpu = self._cpu, cur
        if cur is None or prev is None:
            return 0.0
        total, idle = cur[0] - prev[0], cur[1] - prev[1]
        if total <= 0:
            return 0.0
        return round((total - idle) * 100 / total, 1)

    def _net_bps(self) -> tuple[float, float]:
        rx, tx = _net_bytes(self.root)
        now = time.monotonic()
        prev, self._net = self._net, (rx, tx, now)
        if prev is None or now <= prev[2]:
            return 0.0, 0.0
        dt = now - prev[2]
        return max(rx - prev[0], 0) / dt, max(tx - prev[1], 0) / dt

    def collect(self, host: str) -> MetricsReport:
        mem_total, mem_used = _meminfo(self.root)
        load = _read(self.root / "proc/loadavg").split()
        up = _read(self.root / "proc/uptime").split()
        rx_bps, tx_bps = self._net_bps()
        return MetricsReport(
            host=host,
            ts=time.time(),
            cpu_pct=self._cpu_pct(),
            load1=float(load[0]) if load else 0.0,
            mem_used=mem_used,
            mem_total=mem_total,
            net_rx_bps=rx_bps,
            net_tx_bps=tx_bps,
            temps=_temps(self.root),
            filesystems=_filesystems(self.root),
            uptime_s=int(float(up[0])) if up else 0,
            power=read_power(self.root),
        )
