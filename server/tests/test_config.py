from pathlib import Path

import pytest

from lanot.config import ConfigError, LanotConfig, Settings, load_config, parse_config

REPO = Path(__file__).resolve().parents[2]


def test_agent_tokens_parsed_from_env(monkeypatch):
    monkeypatch.setenv("AGENT_TOKENS", "nas:a,docker-host:b, monitor:c")
    s = Settings()
    assert s.agent_tokens == {"nas": "a", "docker-host": "b", "monitor": "c"}


def test_defaults(monkeypatch):
    monkeypatch.delenv("AGENT_TOKENS", raising=False)
    s = Settings()
    assert s.db_path == "/data/lanot.db"
    assert s.lanot_config == "/config/lanot.toml"
    assert s.anthropic_model == "claude-sonnet-5-5"
    assert s.ntfy_topic == "lanot"
    assert s.db_max_bytes == 20 * 1024**3
    assert s.retention_days == 30
    assert s.agent_tokens == {}


def test_placeholder_and_empty_secrets_are_unset(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "CHANGE_ME")
    monkeypatch.setenv("FRITZ_PASSWORD", "")
    monkeypatch.setenv("HEALTHCHECK_URL", "  ")
    s = Settings()
    assert s.anthropic_api_key is None
    assert s.fritz_password is None
    assert s.healthcheck_url is None


def test_real_secrets_are_kept(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-api-key")
    monkeypatch.setenv("HEALTHCHECK_URL", "https://healthchecks.example/ping/test")
    s = Settings()
    assert s.anthropic_api_key == "test-api-key"  # pragma: allowlist secret
    assert s.healthcheck_url == "https://healthchecks.example/ping/test"


def test_missing_config_file_gives_empty_layout(tmp_path):
    s = Settings(lanot_config=str(tmp_path / "nope.toml"))
    assert s.config == LanotConfig() and s.config.hosts == () and s.tz == "UTC"


def test_example_config_loads():
    cfg = load_config(REPO / "lanot.example.toml")
    assert cfg.host_ids == ["nas", "docker-host", "monitor", "printer"]
    assert cfg.agent_hosts == ["nas", "docker-host", "monitor"]
    assert cfg.investigator_hosts == {"nas": ("lanot", "192.0.2.30"), "docker-host": ("root", "192.0.2.31"),
                                      "monitor": ("lanot", "192.0.2.24")}
    assert cfg.unraid_hosts == {"docker-host"} and cfg.battery_hosts == ["monitor"]
    assert cfg.lan_hosts == ["nas", "docker-host", "printer"]  # the monitor host itself is left out
    assert cfg.router.polls_tr064 and cfg.router.host == "192.168.178.1"
    assert [t.address for t in cfg.internet.ping_targets] == ["1.1.1.1", "8.8.8.8"]
    assert cfg.name_of("docker-host") == "Docker host" and cfg.name_of("router") == "FritzBox"
    assert cfg.name_of("unknown") == "unknown"


def test_config_file_used_by_settings(tmp_path):
    p = tmp_path / "lanot.toml"
    p.write_text('[general]\ntimezone = "Asia/Tokyo"\ndashboard_url = "http://10.0.0.5:8080"\n'
                 '[[hosts]]\nid = "box"\naddress = "10.0.0.7"\n')
    s = Settings(lanot_config=str(p))
    assert s.tz == "Asia/Tokyo" and s.config.host_ids == ["box"]
    assert s.config.host("box").display_name == "box" and s.config.host("box").agent is True
    assert s.form_hosts() == ["10.0.0.5:8080", "localhost:8080", "127.0.0.1:8080"]


def test_allowed_hosts_precedence():
    cfg = parse_config({"general": {"dashboard_url": "http://10.0.0.5:8080", "allowed_hosts": ["A:1"]}})
    assert cfg.form_hosts() == ["a:1"]
    s = Settings(allowed_hosts="b:2, c:3").with_config(cfg)
    assert s.form_hosts() == ["b:2", "c:3"]


def test_defaults_for_roles():
    cfg = parse_config({"hosts": [{"id": "u", "address": "10.0.0.2", "role": "unraid", "investigator": True},
                                  {"id": "p", "address": "10.0.0.3", "role": "ping-only"}]})
    assert cfg.investigator_hosts == {"u": ("root", "10.0.0.2")}
    assert cfg.agent_hosts == ["u"]
    assert parse_config({}).router.display_name == "FritzBox"
    assert parse_config({"router": {"type": "generic"}}).router.display_name == "Router"
    assert not parse_config({"router": {"type": "generic"}}).router.polls_tr064


@pytest.mark.parametrize("data", [
    {"general": {"timezone": "Mars/Base"}},
    {"general": {"dashboard_url": "ftp://x"}},
    {"general": {"daily_summary_hour": 24}},
    {"general": {"monitor_host": "ghost"}},
    {"general": {"nope": 1}},
    {"router": {"type": "cisco"}},
    {"router": {"host": "a b"}},
    {"internet": {"ping_targets": []}},
    {"internet": {"ping_targets": [{"name": "router", "address": "1.1.1.1"}]}},
    {"hosts": [{"id": "Bad Id", "address": "10.0.0.1"}]},
    {"hosts": [{"id": "router", "address": "10.0.0.1"}]},
    {"hosts": [{"id": "a", "address": "10.0.0.1"}, {"id": "a", "address": "10.0.0.2"}]},
    {"hosts": [{"id": "a", "address": "10.0.0.1", "role": "windows"}]},
    {"hosts": [{"id": "a", "address": "10.0.0.1", "role": "ping-only", "investigator": True}]},
    {"hosts": [{"id": "a", "address": "10.0.0.1", "investigator_user": "root; rm"}]},
    {"hosts": [{"id": "a", "address": "10.0.0.1", "agent": "yes"}]},
    {"hosts": [{"id": "a"}]},
])
def test_invalid_config_rejected(data):
    with pytest.raises(ConfigError):
        parse_config(data)


def test_broken_toml_rejected(tmp_path):
    p = tmp_path / "bad.toml"
    p.write_text("[general\n")
    with pytest.raises(ConfigError):
        load_config(p)
