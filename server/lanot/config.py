"""Server configuration.

Two sources:
- the environment (secrets and runtime knobs): `Settings`, read by pydantic-settings;
- a TOML file describing the network (hosts, router, internet probes):
  `LanotConfig`, loaded from LANOT_CONFIG (default /config/lanot.toml).

See lanot.example.toml for every key of the file.
"""

import ipaddress
import logging
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import PrivateAttr, field_validator
from pydantic_settings import BaseSettings, NoDecode

log = logging.getLogger(__name__)

ROLES = ("unraid", "truenas", "linux", "ping-only")
ROUTER_TYPES = ("fritzbox", "generic")
# Target and tile names the server uses itself; host ids must not collide with them.
RESERVED_IDS = frozenset({"router", "gateway", "internet", "dns", "dns-router", "dns-external", "other"})
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
                          r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class ConfigError(ValueError):
    """The config file is missing a key, has a wrong type or an invalid value."""


@dataclass(frozen=True)
class Host:
    id: str
    display_name: str
    address: str
    role: str = "linux"
    agent: bool = True
    investigator: bool = False
    investigator_user: str = "lanot"
    has_battery: bool = False


@dataclass(frozen=True)
class Router:
    type: str = "fritzbox"
    host: str = "192.168.178.1"
    display_name: str = "FritzBox"
    tr064: bool = True  # poll line state and event log over TR-064 (FritzBox only)

    @property
    def polls_tr064(self) -> bool:
        return self.type == "fritzbox" and self.tr064


@dataclass(frozen=True)
class PingTarget:
    name: str
    address: str


@dataclass(frozen=True)
class Internet:
    ping_targets: tuple[PingTarget, ...] = (PingTarget("cloudflare", "1.1.1.1"), PingTarget("google", "8.8.8.8"))
    dns_server: str = "1.1.1.1"
    dns_query: str = "example.com"
    check_router_dns: bool = True

    @property
    def target_names(self) -> frozenset[str]:
        return frozenset(t.name for t in self.ping_targets)

    @property
    def trace_target(self) -> str:
        return self.ping_targets[0].address


@dataclass(frozen=True)
class LanotConfig:
    timezone: str = "UTC"
    dashboard_url: str = "http://localhost:8080"
    monitor_host: str | None = None  # id of the host LANOT itself runs on
    daily_summary_hour: int = 8
    allowed_hosts: tuple[str, ...] = ()  # Host headers accepted for form posts; empty = derived
    router: Router = field(default_factory=Router)
    internet: Internet = field(default_factory=Internet)
    hosts: tuple[Host, ...] = ()

    # -- lookups -----------------------------------------------------------------
    def host(self, host_id: str) -> Host | None:
        return next((h for h in self.hosts if h.id == host_id), None)

    @property
    def host_ids(self) -> list[str]:
        return [h.id for h in self.hosts]

    @property
    def agent_hosts(self) -> list[str]:
        return [h.id for h in self.hosts if h.agent]

    @property
    def investigator_hosts(self) -> dict[str, tuple[str, str]]:
        """host id -> (ssh user, address) for hosts the investigator may query."""
        return {h.id: (h.investigator_user, h.address) for h in self.hosts if h.investigator}

    @property
    def unraid_hosts(self) -> frozenset[str]:
        return frozenset(h.id for h in self.hosts if h.role == "unraid")

    @property
    def battery_hosts(self) -> list[str]:
        return [h.id for h in self.hosts if h.has_battery]

    @property
    def lan_hosts(self) -> list[str]:
        """Hosts whose pings tell whether the LAN works. The monitor pinging
        itself proves nothing, so it is left out."""
        return [h.id for h in self.hosts if h.id != self.monitor_host]

    def name_of(self, key: str) -> str:
        if key == "router":
            return self.router.display_name
        h = self.host(key)
        return h.display_name if h else key

    def form_hosts(self) -> list[str]:
        if self.allowed_hosts:
            return list(self.allowed_hosts)
        out = []
        netloc = urlparse(self.dashboard_url).netloc.lower()
        if netloc:
            out.append(netloc)
        for h in ("localhost:8080", "127.0.0.1:8080"):
            if h not in out:
                out.append(h)
        return out


# -- parsing --------------------------------------------------------------------------
def _get(table: dict, key: str, kind: type | tuple, default: Any, where: str) -> Any:
    if key not in table:
        return default
    value = table[key]
    if kind is int and isinstance(value, bool):
        raise ConfigError(f"{where}.{key} must be an integer")
    if not isinstance(value, kind):
        name = kind.__name__ if isinstance(kind, type) else " or ".join(k.__name__ for k in kind)
        raise ConfigError(f"{where}.{key} must be of type {name}")
    return value


def _address(value: str, where: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if _HOSTNAME_RE.match(value):
            return value
    raise ConfigError(f"{where}: {value!r} is neither an IP address nor a host name")


def _unknown_keys(table: dict, allowed: set[str], where: str) -> None:
    extra = sorted(set(table) - allowed)
    if extra:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(extra)}")


def parse_config(data: dict) -> LanotConfig:
    _unknown_keys(data, {"general", "router", "internet", "hosts"}, "config")
    general = _get(data, "general", dict, {}, "config")
    _unknown_keys(general, {"timezone", "dashboard_url", "monitor_host", "daily_summary_hour", "allowed_hosts"},
                  "general")
    tz = _get(general, "timezone", str, "UTC", "general")
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"general.timezone: unknown time zone {tz!r}") from exc
    url = _get(general, "dashboard_url", str, "http://localhost:8080", "general")
    if urlparse(url).scheme not in ("http", "https") or not urlparse(url).netloc:
        raise ConfigError("general.dashboard_url must be an http(s) URL")
    hour = _get(general, "daily_summary_hour", int, 8, "general")
    if not 0 <= hour <= 23:
        raise ConfigError("general.daily_summary_hour must be between 0 and 23")
    allowed = _get(general, "allowed_hosts", list, [], "general")
    if not all(isinstance(a, str) and a for a in allowed):
        raise ConfigError("general.allowed_hosts must be a list of host:port strings")

    r = _get(data, "router", dict, {}, "config")
    _unknown_keys(r, {"type", "host", "display_name", "tr064"}, "router")
    rtype = _get(r, "type", str, "fritzbox", "router")
    if rtype not in ROUTER_TYPES:
        raise ConfigError(f"router.type must be one of {', '.join(ROUTER_TYPES)}")
    router = Router(
        type=rtype,
        host=_address(_get(r, "host", str, "192.168.178.1", "router"), "router.host"),
        display_name=_get(r, "display_name", str, "FritzBox" if rtype == "fritzbox" else "Router", "router"),
        tr064=_get(r, "tr064", bool, True, "router"),
    )

    i = _get(data, "internet", dict, {}, "config")
    _unknown_keys(i, {"ping_targets", "dns_server", "dns_query", "check_router_dns"}, "internet")
    targets = []
    raw_targets = _get(i, "ping_targets", list, None, "internet")
    if raw_targets is None:
        raw_targets = [{"name": p.name, "address": p.address} for p in Internet().ping_targets]
    for n, t in enumerate(raw_targets):
        where = f"internet.ping_targets[{n}]"
        if not isinstance(t, dict):
            raise ConfigError(f"{where} must be a table with name and address")
        _unknown_keys(t, {"name", "address"}, where)
        name = _get(t, "name", str, "", where)
        if not ID_RE.match(name) or name in RESERVED_IDS:
            raise ConfigError(f"{where}.name {name!r} is not allowed")
        targets.append(PingTarget(name, _address(_get(t, "address", str, "", where), where + ".address")))
    if not targets:
        raise ConfigError("internet.ping_targets must not be empty")
    internet = Internet(
        ping_targets=tuple(targets),
        dns_server=_address(_get(i, "dns_server", str, "1.1.1.1", "internet"), "internet.dns_server"),
        dns_query=_address(_get(i, "dns_query", str, "example.com", "internet"), "internet.dns_query"),
        check_router_dns=_get(i, "check_router_dns", bool, True, "internet"),
    )

    hosts = []
    taken = set(RESERVED_IDS) | {t.name for t in targets}
    for n, h in enumerate(_get(data, "hosts", list, [], "config")):
        where = f"hosts[{n}]"
        if not isinstance(h, dict):
            raise ConfigError(f"{where} must be a table")
        _unknown_keys(h, {"id", "display_name", "address", "role", "agent", "investigator", "investigator_user",
                          "has_battery"}, where)
        hid = _get(h, "id", str, "", where)
        if not ID_RE.match(hid):
            raise ConfigError(f"{where}.id {hid!r}: use lowercase letters, digits, - and _ (max. 40)")
        if hid in taken:
            raise ConfigError(f"{where}.id {hid!r} is reserved or used twice")
        taken.add(hid)
        role = _get(h, "role", str, "linux", where)
        if role not in ROLES:
            raise ConfigError(f"{where}.role must be one of {', '.join(ROLES)}")
        agent = _get(h, "agent", bool, role != "ping-only", where)
        investigator = _get(h, "investigator", bool, False, where)
        if role == "ping-only" and (agent or investigator):
            raise ConfigError(f"{where}: a ping-only host has no agent and no investigator access")
        user = _get(h, "investigator_user", str, "root" if role == "unraid" else "lanot", where)
        if not _USER_RE.match(user):
            raise ConfigError(f"{where}.investigator_user {user!r} is not a valid user name")
        hosts.append(Host(
            id=hid,
            display_name=_get(h, "display_name", str, hid, where),
            address=_address(_get(h, "address", str, "", where), where + ".address"),
            role=role, agent=agent, investigator=investigator, investigator_user=user,
            has_battery=_get(h, "has_battery", bool, False, where),
        ))

    monitor = _get(general, "monitor_host", str, None, "general")
    if monitor is not None and monitor not in {h.id for h in hosts}:
        raise ConfigError(f"general.monitor_host {monitor!r} is not one of the [[hosts]] ids")
    return LanotConfig(timezone=tz, dashboard_url=url.rstrip("/"), monitor_host=monitor, daily_summary_hour=hour,
                       allowed_hosts=tuple(a.lower() for a in allowed), router=router, internet=internet,
                       hosts=tuple(hosts))


def load_config(path: str | Path) -> LanotConfig:
    with open(path, "rb") as f:
        try:
            data = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
    return parse_config(data)


# -- environment ----------------------------------------------------------------------
class Settings(BaseSettings):
    db_path: str = "/data/lanot.db"
    lanot_config: str = "/config/lanot.toml"
    # AGENT_TOKENS="nas:<token>,docker-host:<token>"
    agent_tokens: Annotated[dict[str, str], NoDecode] = {}
    # Optional: the investigator works without a model (facts only), with Ollama, or with the Anthropic API.
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-5-5"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:7b"
    # SSH key of the investigator; the hosts force it onto lanot-ro
    investigator_key: str = "/secrets/investigator_key"
    known_hosts_file: str = "/data/known_hosts"
    fritz_user: str | None = None
    fritz_password: str | None = None
    ntfy_url: str = "http://127.0.0.1:8081"
    ntfy_topic: str = "lanot"
    healthcheck_url: str | None = None
    db_max_bytes: int = 20 * 1024**3
    retention_days: int = 30
    # Host headers accepted for form posts (DNS-rebinding guard); ALLOWED_HOSTS="a:8080,b:8080".
    # Unset: [general] allowed_hosts, or the host of dashboard_url plus localhost.
    allowed_hosts: Annotated[list[str] | None, NoDecode] = None

    _config: LanotConfig | None = PrivateAttr(default=None)

    @field_validator("anthropic_api_key", "fritz_password", "healthcheck_url", mode="before")
    @classmethod
    def _placeholder_is_unset(cls, value):
        if isinstance(value, str) and (not value.strip() or value.strip().startswith("CHANGE_ME")):
            return None
        return value

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def _parse_hosts(cls, value):
        if isinstance(value, str):
            return [h.strip().lower() for h in value.split(",") if h.strip()]
        return value

    @field_validator("agent_tokens", mode="before")
    @classmethod
    def _parse_tokens(cls, value):
        if isinstance(value, str):
            pairs = {}
            for item in value.split(","):
                if not item.strip():
                    continue
                host, sep, token = item.partition(":")
                if not sep or not host.strip() or not token.strip():
                    raise ValueError("AGENT_TOKENS entries must look like host:token")
                pairs[host.strip()] = token.strip()
            return pairs
        return value

    @property
    def config(self) -> LanotConfig:
        """The network layout. Loaded on first use; a missing file gives an
        empty layout (no hosts) and a warning, a broken file raises ConfigError."""
        if self._config is None:
            path = Path(self.lanot_config)
            if path.is_file():
                self._config = load_config(path)
            else:
                log.warning("config file %s not found, running without hosts", path)
                self._config = LanotConfig()
        return self._config

    def with_config(self, cfg: LanotConfig) -> "Settings":
        self._config = cfg
        return self

    @property
    def tz(self) -> str:
        return self.config.timezone

    def form_hosts(self) -> list[str]:
        return self.allowed_hosts if self.allowed_hosts else self.config.form_hosts()
