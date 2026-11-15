import os
from pathlib import Path

from agent_support import set_net, set_proc_stat, write
from lanot_common.protocol import PowerState

from lanot_agent.metrics import MetricsCollector
from lanot_agent.power import read_power


def test_cpu_pct_from_two_samples(fake_root):
    c = MetricsCollector(fake_root)
    first = c.collect("h")
    assert first.cpu_pct == 0.0
    set_proc_stat(fake_root, busy=150, idle=950)  # +50 busy, +50 idle
    assert c.collect("h").cpu_pct == 50.0


def test_filesystems_skip_tmpfs(fake_root):
    got = [f.mount for f in MetricsCollector(fake_root).collect("h").filesystems]
    assert got == ["/", "/mnt/tank"]


def test_filesystem_sizes_from_statvfs(fake_root):
    fs = MetricsCollector(fake_root).collect("h").filesystems[1]
    st = os.statvfs(fake_root / "mnt/tank")
    assert fs.total == st.f_blocks * st.f_frsize
    assert fs.used == (st.f_blocks - st.f_bfree) * st.f_frsize


def test_unreadable_mount_is_skipped(fake_root):
    with (fake_root / "proc/1/mounts").open("a") as f:
        f.write("/dev/sdz1 /mnt/gone ext4 rw 0 0\n")
    got = [f.mount for f in MetricsCollector(fake_root).collect("h").filesystems]
    assert "/mnt/gone" not in got


def test_memory_load_uptime_temps(fake_root):
    m = MetricsCollector(fake_root).collect("h")
    assert m.host == "h"
    assert m.mem_total == 16000000 * 1024
    assert m.mem_used == (16000000 - 4000000) * 1024
    assert m.load1 == 0.5
    assert m.uptime_s == 100000
    assert m.temps == {"coretemp/Package id 0": 52.0, "nvme/temp1": 38.5}


def test_net_bps_from_two_samples(fake_root, monkeypatch):
    t = iter([100.0, 110.0])
    monkeypatch.setattr("lanot_agent.metrics.time.monotonic", lambda: next(t))
    c = MetricsCollector(fake_root)
    assert c.collect("h").net_rx_bps == 0.0
    set_net(fake_root, rx=1000 + 5000, tx=500 + 2000)
    m = c.collect("h")
    assert m.net_rx_bps == 500.0  # loopback ignored
    assert m.net_tx_bps == 200.0


def test_power_attached_to_report(fake_root):
    assert MetricsCollector(fake_root).collect("h").power == PowerState(ac_online=False, battery_pct=57.0)


def test_power_on_battery(fake_root):
    assert read_power(fake_root) == PowerState(ac_online=False, battery_pct=57.0)


def test_power_on_ac(fake_root):
    write(fake_root, "sys/class/power_supply/ADP1/online", "1\n")
    assert read_power(fake_root) == PowerState(ac_online=True, battery_pct=57.0)


def test_power_none_without_supply(empty_root):
    assert read_power(empty_root) is None


def test_missing_proc_does_not_crash(empty_root):
    m = MetricsCollector(empty_root).collect("h")
    assert m.cpu_pct == 0.0 and m.filesystems == [] and m.temps == {}


def test_net_ignores_virtual_interfaces(fake_root, monkeypatch):
    # set_net writes docker0 and veth1a2b with large counters too
    t = iter([0.0, 1.0])
    monkeypatch.setattr("lanot_agent.metrics.time.monotonic", lambda: next(t))
    c = MetricsCollector(fake_root)
    c.collect("h")
    set_net(fake_root, rx=1000 + 100, tx=500 + 50)
    m = c.collect("h")
    assert (m.net_rx_bps, m.net_tx_bps) == (100.0, 50.0)


def test_hwmon_duplicate_names_get_unique_keys(fake_root):
    for i, val in ((2, "31000"), (3, "33000")):
        write(fake_root, f"sys/class/hwmon/hwmon{i}/name", "drivetemp\n")
        write(fake_root, f"sys/class/hwmon/hwmon{i}/temp1_input", f"{val}\n")
    t = MetricsCollector(fake_root).collect("h").temps
    assert t["drivetemp.hwmon2/temp1"] == 31.0
    assert t["drivetemp.hwmon3/temp1"] == 33.0
    assert t["coretemp/Package id 0"] == 52.0


def test_power_none_when_battery_without_mains(fake_root):
    import shutil

    shutil.rmtree(fake_root / "sys/class/power_supply/ADP1")
    assert read_power(fake_root) is None
