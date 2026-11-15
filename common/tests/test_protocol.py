import pytest
from pydantic import ValidationError

from lanot_common.protocol import FsUsage, LogLine, MetricsReport


def test_fs_pct():
    assert FsUsage(mount="/", total=1000, used=930).pct == 93.0


def test_logline_truncates():
    assert len(LogLine(ts=1, source="syslog", severity=3, message="x" * 5000).message) == 4000


def test_severity_range():
    with pytest.raises(ValidationError):
        LogLine(ts=1, source="s", severity=9, message="m")


def test_roundtrip():
    r = MetricsReport(host="nas", ts=1.0, cpu_pct=1, load1=0.1, mem_used=1, mem_total=2,
                      net_rx_bps=0, net_tx_bps=0, temps={}, filesystems=[], uptime_s=5)
    assert MetricsReport.model_validate_json(r.model_dump_json()) == r


def test_state_optional_fields_default_none():
    from lanot_common.protocol import StateReport
    s = StateReport(host="nas", ts=1.0, containers=[], pools=[], disks=[])
    assert s.boot_files is None and s.docker_healthy is None
    # payload without the optional fields still validates
    old = '{"host":"nas","ts":1.0,"containers":[],"pools":[],"disks":[],"array":null}'
    assert StateReport.model_validate_json(old).boot_files is None


def test_state_optional_fields_roundtrip():
    from lanot_common.protocol import StateReport
    s = StateReport(host="nas", ts=1.0, containers=[], pools=[], disks=[],
                    boot_files={"bzfirmware": False, "bzroot": True}, docker_healthy=True)
    assert StateReport.model_validate_json(s.model_dump_json()) == s
