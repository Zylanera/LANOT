"""Agent configuration read from environment variables."""

from dataclasses import dataclass, field
from typing import Mapping

_TRUE = {"1", "true", "yes", "on"}


def _bool(env: Mapping[str, str], key: str) -> bool:
    return env.get(key, "").strip().lower() in _TRUE


def _list(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


@dataclass(frozen=True)
class AgentConfig:
    host_name: str
    server_url: str
    agent_token: str
    host_root: str = "/host"
    buffer_dir: str = "/buffer"
    log_files: list[str] = field(default_factory=list)
    journal_dir: str = ""
    docker_sock: str = "/var/run/docker.sock"
    enable_zfs: bool = False
    enable_smart: bool = False
    enable_unraid: bool = False
    enable_power: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AgentConfig":
        if env is None:
            import os

            env = os.environ
        return cls(
            host_name=env["HOST_NAME"],
            server_url=env["LANOT_URL"],
            agent_token=env["AGENT_TOKEN"],
            host_root=env.get("HOST_ROOT", "/host"),
            buffer_dir=env.get("BUFFER_DIR", "/buffer"),
            log_files=_list(env.get("LOG_FILES", "")),
            journal_dir=env.get("JOURNAL_DIR", ""),
            docker_sock=env.get("DOCKER_SOCK", "/var/run/docker.sock"),
            enable_zfs=_bool(env, "ENABLE_ZFS"),
            enable_smart=_bool(env, "ENABLE_SMART"),
            enable_unraid=_bool(env, "ENABLE_UNRAID"),
            enable_power=_bool(env, "ENABLE_POWER"),
        )
