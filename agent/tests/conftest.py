from pathlib import Path

import pytest
from agent_support import set_net, set_proc_stat, write

@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    r = tmp_path
    set_proc_stat(r, busy=100, idle=900)
    set_net(r, rx=1000, tx=500)
    write(r, "proc/loadavg", "0.50 0.40 0.30 1/200 1000\n")
    write(r, "proc/uptime", "100000.00 150000.00\n")
    write(
        r,
        "proc/meminfo",
        "MemTotal:       16000000 kB\nMemFree:         2000000 kB\n"
        "MemAvailable:    4000000 kB\nBuffers:             432 kB\n",
    )
    write(
        r,
        "proc/1/mounts",
        "rootfs / rootfs rw 0 0\n"
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "tmpfs /run tmpfs rw,nosuid 0 0\n"
        "proc /proc proc rw 0 0\n"
        "overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n"
        "tank /mnt/tank zfs rw,xattr 0 0\n",
    )
    (r / "mnt/tank").mkdir(parents=True)
    for nic, phys in (("eth0", True), ("lo", False), ("docker0", False), ("veth1a2b", False)):
        (r / "sys/class/net" / nic).mkdir(parents=True)
        if phys:
            (r / "sys/class/net" / nic / "device").mkdir()
    write(r, "sys/class/hwmon/hwmon0/name", "coretemp\n")
    write(r, "sys/class/hwmon/hwmon0/temp1_input", "52000\n")
    write(r, "sys/class/hwmon/hwmon0/temp1_label", "Package id 0\n")
    write(r, "sys/class/hwmon/hwmon1/name", "nvme\n")
    write(r, "sys/class/hwmon/hwmon1/temp1_input", "38500\n")
    write(r, "sys/class/power_supply/ADP1/type", "Mains\n")
    write(r, "sys/class/power_supply/ADP1/online", "0\n")
    write(r, "sys/class/power_supply/BAT1/type", "Battery\n")
    write(r, "sys/class/power_supply/BAT1/capacity", "57\n")
    return r


@pytest.fixture
def empty_root(tmp_path: Path) -> Path:
    return tmp_path
