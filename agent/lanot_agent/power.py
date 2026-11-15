"""AC / battery state from /sys/class/power_supply (laptops only)."""

from pathlib import Path

from lanot_common.protocol import PowerState


def _read(p: Path) -> str | None:
    try:
        return p.read_text().strip()
    except OSError:
        return None


def read_power(root: Path) -> PowerState | None:
    base = root / "sys/class/power_supply"
    if not base.is_dir():
        return None
    ac_online: bool | None = None
    battery_pct: float | None = None
    for supply in sorted(base.iterdir()):
        kind = _read(supply / "type")
        if kind == "Mains":
            online = _read(supply / "online")
            if online is not None:
                ac_online = ac_online or online == "1"
        elif kind == "Battery":
            cap = _read(supply / "capacity")
            if cap is not None and battery_pct is None:
                try:
                    battery_pct = float(cap)
                except ValueError:
                    pass
    if ac_online is None:  # no Mains node: AC state unknown
        return None
    return PowerState(ac_online=bool(ac_online), battery_pct=battery_pct)
