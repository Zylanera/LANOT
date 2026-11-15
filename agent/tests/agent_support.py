from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def set_proc_stat(root: Path, busy: int, idle: int) -> None:
    """Aggregate cpu line; busy goes to user, idle to idle (jiffies)."""
    write(root, "proc/stat", f"cpu  {busy} 0 0 {idle} 0 0 0 0 0 0\ncpu0 {busy} 0 0 {idle} 0 0 0 0 0 0\n")


def set_net(root: Path, rx: int, tx: int) -> None:
    write(
        root,
        "proc/1/net/dev",  # host netns via PID 1 (pid: host)
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 999999 10 0 0 0 0 0 0 999999 10 0 0 0 0 0 0\n"
        f"  eth0: {rx} 10 0 0 0 0 0 0 {tx} 10 0 0 0 0 0 0\n"
        # virtual interfaces whose counters move too: must not be counted
        f"docker0: {rx * 100} 10 0 0 0 0 0 0 {tx * 100} 10 0 0 0 0 0 0\n"
        f"veth1a2b: {rx * 50} 10 0 0 0 0 0 0 {tx * 50} 10 0 0 0 0 0 0\n",
    )
