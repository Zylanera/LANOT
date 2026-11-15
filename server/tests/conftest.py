import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from lanot import api
from lanot.config import Host, LanotConfig, Router, Settings

TOK = {"nas": "tok-nas", "docker-host": "tok-docker-host", "monitor": "tok-monitor"}

# Neutral example network used by all server tests (addresses from 192.0.2.0/24, TEST-NET-1).
CFG = LanotConfig(
    timezone="America/New_York",
    dashboard_url="http://192.0.2.24:8080",
    monitor_host="monitor",
    router=Router(type="fritzbox", host="192.168.178.1", display_name="FritzBox"),
    hosts=(
        Host("docker-host", "Docker host", "192.0.2.31", role="unraid", investigator=True,
             investigator_user="root"),
        Host("nas", "NAS", "192.0.2.30", role="truenas", investigator=True),
        Host("printer", "Printer", "192.0.2.32", role="ping-only", agent=False),
        Host("monitor", "Monitor", "192.0.2.24", role="linux", investigator=True, has_battery=True),
    ),
)


def make_settings(cfg: LanotConfig = CFG, **kw) -> Settings:
    kw.setdefault("db_path", ":unused:")
    kw.setdefault("lanot_config", "/nonexistent/lanot.toml")
    return Settings(**kw).with_config(cfg)


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def sample_metrics(host: str, ts: float = 1000.0) -> dict:
    return {
        "host": host,
        "ts": ts,
        "cpu_pct": 12.5,
        "load1": 0.4,
        "mem_used": 4_000,
        "mem_total": 16_000,
        "net_rx_bps": 100.0,
        "net_tx_bps": 50.0,
        "temps": {"cpu": 55.0},
        "filesystems": [{"mount": "/", "total": 100, "used": 40}],
        "uptime_s": 3600,
        "power": {"ac_online": True, "battery_pct": 100.0},
    }


def sample_state(host: str, ts: float = 1000.0) -> dict:
    return {
        "host": host,
        "ts": ts,
        "containers": [{"name": "web", "status": "running", "health": None, "restarts": 0}],
        "pools": [{"name": "tank", "health": "ONLINE", "cap_pct": 40.0, "errors": "none"}],
        "disks": [{"dev": "sda", "model": "X", "smart_passed": True, "attrs": {"Reallocated": 0}}],
        "array": None,
    }


@pytest.fixture
def db(tmp_path):
    from lanot.db import Database
    return Database(str(tmp_path / "t.db"))


@pytest.fixture
def client(db):
    app = FastAPI()
    app.include_router(api.router)
    app.state.db = db
    app.state.settings = make_settings(agent_tokens=TOK)
    return TestClient(app)
