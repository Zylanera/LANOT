"""Wire models shared by the LANOT server and the agent containers.

All timestamps (`ts`) are unix time in seconds as floats.
"""

from pydantic import BaseModel, Field, field_validator

MAX_LOG_MESSAGE_LEN = 4000


class FsUsage(BaseModel):
    mount: str
    total: int
    used: int

    @property
    def pct(self) -> float:
        if self.total == 0:
            return 0.0
        return self.used * 100 / self.total


class PowerState(BaseModel):
    ac_online: bool
    battery_pct: float | None


class MetricsReport(BaseModel):
    host: str
    ts: float
    cpu_pct: float
    load1: float
    mem_used: int
    mem_total: int
    net_rx_bps: float
    net_tx_bps: float
    temps: dict[str, float]
    filesystems: list[FsUsage]
    uptime_s: int
    power: PowerState | None = None


class Container(BaseModel):
    name: str
    status: str
    health: str | None
    restarts: int


class Pool(BaseModel):
    name: str
    health: str
    cap_pct: float
    errors: str


class Disk(BaseModel):
    dev: str
    model: str
    smart_passed: bool
    attrs: dict[str, int]


class StateReport(BaseModel):
    host: str
    ts: float
    containers: list[Container]
    pools: list[Pool]
    disks: list[Disk]
    array: str | None = None
    # Unraid boot files on the USB stick: name -> checksum matches its .sha256
    # (None: not checked, e.g. not Unraid or first check still running)
    boot_files: dict[str, bool] | None = None
    # Docker API answers and containerd runs (None: could not tell)
    docker_healthy: bool | None = None


class LogLine(BaseModel):
    ts: float
    source: str
    severity: int = Field(ge=0, le=7)
    message: str

    @field_validator("message")
    @classmethod
    def _truncate_message(cls, value: str) -> str:
        return value[:MAX_LOG_MESSAGE_LEN]


class LogBatch(BaseModel):
    host: str
    lines: list[LogLine]
