"""Disk-backed FIFO for payloads that could not be delivered.

One file per item, named `<seq>.<kind>`; the zero-padded sequence number gives
FIFO order and survives restarts. Writes are atomic (tmp file + rename).
"""

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


class DiskBuffer:
    def __init__(self, dir: Path, max_bytes: int = 50 * 1024**2) -> None:
        self.dir = Path(dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        names = self._names()
        self._seq = int(names[-1].split(".", 1)[0]) + 1 if names else 0

    def _names(self) -> list[str]:
        return sorted(n for n in os.listdir(self.dir) if n.split(".", 1)[0].isdigit() and "." in n and not n.endswith(".tmp"))

    def push(self, kind: str, payload: bytes) -> None:
        name = f"{self._seq:020d}.{kind}"
        self._seq += 1
        tmp = self.dir / (name + ".tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, self.dir / name)
        self._enforce_cap()

    def peek(self) -> tuple[str, str, bytes] | None:
        for name in self._names():
            try:
                data = (self.dir / name).read_bytes()
            except FileNotFoundError:
                continue
            return name, name.split(".", 1)[1], data
        return None

    def ack(self, id: str) -> None:
        try:
            (self.dir / id).unlink()
        except FileNotFoundError:
            pass

    def size_bytes(self) -> int:
        total = 0
        for name in self._names():
            try:
                total += (self.dir / name).stat().st_size
            except FileNotFoundError:
                pass
        return total

    def _enforce_cap(self) -> None:
        while self.size_bytes() > self.max_bytes:
            names = self._names()
            if not names:
                return
            log.warning("buffer over cap, dropping oldest item %s", names[0])
            self.ack(names[0])
