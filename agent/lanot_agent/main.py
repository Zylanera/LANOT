"""Agent entry point: collect on a schedule and ship to the LANOT server."""

import hashlib
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Callable

import httpx
from lanot_common.protocol import LogBatch

from .buffer import DiskBuffer
from .config import AgentConfig
from .logs import DockerEvents, FileTailer, JournalFollower
from .metrics import MetricsCollector
from .sender import Sender
from .state import StateCollector

log = logging.getLogger("lanot_agent")

METRICS_EVERY = 30
STATE_EVERY = 300
LOGS_EVERY = 10
DRAIN_EVERY = 10
MAX_BATCH_LINES = 2000
MAX_ROUNDS_PER_TICK = 10  # backlog catch-up per log cycle
HOST_CMD_TIMEOUT = 60

NSENTER = ["nsenter", "-t", "1", "-m", "-u", "-n", "-i", "--"]


def host_run(argv: list[str]) -> str:
    """Run a command in the host's namespaces and return its stdout, even on a
    nonzero exit (smartctl uses bit-flag exit codes; standby is 2). Raises only
    when the binary is missing or the command times out."""
    return subprocess.run(
        NSENTER + argv, capture_output=True, text=True, errors="replace", timeout=HOST_CMD_TIMEOUT
    ).stdout


class Agent:
    def __init__(
        self,
        cfg: AgentConfig,
        sender: Sender,
        metrics: MetricsCollector,
        state: StateCollector,
        log_sources: list,
    ) -> None:
        self.cfg = cfg
        self.sender = sender
        self.metrics = metrics
        self.state = state
        self.log_sources = log_sources
        self._next = {"metrics": 0.0, "state": 0.0, "logs": 0.0, "drain": 0.0}

    def _due(self, name: str, now: float, every: float) -> bool:
        if now < self._next[name]:
            return False
        self._next[name] = now + every
        return True

    def send_metrics(self) -> None:
        report = self.metrics.collect(self.cfg.host_name)
        if not self.cfg.enable_power:
            report.power = None
        self.sender.send("metrics", report)

    def send_state(self) -> None:
        self.sender.send("state", self.state.collect(self.cfg.host_name))

    def send_logs(self) -> None:
        """Read each source, send/buffer its lines, and only then commit the
        source's position. If sending raises, nothing is committed and the same
        lines are read again next cycle."""
        for src in self.log_sources:
            try:
                for _ in range(MAX_ROUNDS_PER_TICK):
                    lines = src.read_new()
                    for i in range(0, len(lines), MAX_BATCH_LINES):
                        self.sender.send("logs", LogBatch(host=self.cfg.host_name, lines=lines[i : i + MAX_BATCH_LINES]))
                    src.commit()
                    if len(lines) < MAX_BATCH_LINES:
                        break
            except Exception:
                log.warning("log source %r failed", src, exc_info=True)

    def tick(self, now: float) -> None:
        """Run whatever is due. Failures are logged, never raised."""
        jobs: list[tuple[str, float, Callable[[], object]]] = [
            ("metrics", METRICS_EVERY, self.send_metrics),
            ("state", STATE_EVERY, self.send_state),
            ("logs", LOGS_EVERY, self.send_logs),
            ("drain", DRAIN_EVERY, self.sender.drain),
        ]
        for name, every, fn in jobs:
            if self._due(name, now, every):
                try:
                    fn()
                except Exception:
                    log.exception("%s job failed", name)


def build(cfg: AgentConfig, client: httpx.Client | None = None) -> Agent:
    buf_dir = Path(cfg.buffer_dir)
    buffer = DiskBuffer(buf_dir / "queue")
    client = client or httpx.Client(timeout=15)
    sender = Sender(cfg.server_url, cfg.agent_token, buffer, client)
    sources: list = []
    for path in cfg.log_files:
        key = hashlib.sha1(path.encode()).hexdigest()[:12]
        sources.append(FileTailer(Path(path), buf_dir / f"tail-{key}.json"))
    if cfg.journal_dir:
        sources.append(JournalFollower(cfg.journal_dir, buf_dir / "journal.cursor"))
    if os.path.exists(cfg.docker_sock):
        sources.append(DockerEvents(cfg.docker_sock))
    return Agent(cfg, sender, MetricsCollector(Path(cfg.host_root)), StateCollector(cfg, host_run), sources)


def run(cfg: AgentConfig) -> None:
    agent = build(cfg)
    log.info("agent for %s -> %s started", cfg.host_name, cfg.server_url)
    while True:
        agent.tick(time.monotonic())
        time.sleep(1)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    run(AgentConfig.from_env())


if __name__ == "__main__":
    main()
