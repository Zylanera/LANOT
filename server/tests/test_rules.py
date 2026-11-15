import json

from lanot.rules import Finding, SystemView, build_view, evaluate
from lanot.pinger import Target
from dataclasses import replace

from conftest import CFG, make_settings
from lanot_common.protocol import Container, Disk, FsUsage, MetricsReport, Pool, PowerState, StateReport

NOW = 100_000.0
T, F = True, False


def view(**kw) -> SystemView:
    kw.setdefault("started_at", NOW - 3600)
    kw.setdefault("config", CFG)
    if "last_received" in kw:
        kw.setdefault("hosts", list(kw["last_received"]))
    return SystemView(**kw)


def rules(findings):
    return [f.rule for f in findings]


def metrics(host="nas", fs=(), **kw):
    return MetricsReport(
        host=host, ts=NOW, cpu_pct=1, load1=0, mem_used=1, mem_total=2, net_rx_bps=0, net_tx_bps=0,
        temps={}, filesystems=[FsUsage(mount=m, total=100, used=u) for m, u in fs], uptime_s=1, **kw)


def state(host="docker-host", containers=(), pools=(), disks=(), **kw):
    return StateReport(host=host, ts=NOW, containers=list(containers), pools=list(pools), disks=list(disks), **kw)


def test_device_down_after_3_failures():
    fs = evaluate(view(probes={"nas": [F, F, F]}), NOW)
    assert rules(fs) == ["device_down"]
    assert fs[0].key == "nas" and fs[0].title == "NAS unreachable"


def test_two_failures_no_alarm():
    assert evaluate(view(probes={"nas": [T, F, F]}), NOW) == []
    assert evaluate(view(probes={"nas": [F, F]}), NOW) == []


def test_old_failures_before_recovery_no_alarm():
    assert evaluate(view(probes={"nas": [F, F, F, T]}), NOW) == []


def test_internet_down_needs_both():
    assert evaluate(view(probes={"cloudflare": [F, F, F], "google": [T, T, T]}), NOW) == []
    fs = evaluate(view(probes={"cloudflare": [F, F, F], "google": [F, F, F]}), NOW)
    assert rules(fs) == ["internet_down"] and fs[0].key == "internet"
    assert fs[0].title == "Internet down"


def test_router_down_does_not_suppress_internet_down():
    v = view(probes={"cloudflare": [F] * 3, "google": [F] * 3, "router": [F] * 3})
    assert sorted(rules(evaluate(v, NOW))) == ["device_down", "internet_down"]


def test_internet_down_suppresses_external_service_but_not_local():
    targets = [Target("ext", "http", "example.com", 443), Target("nas", "tcp", "192.0.2.31", 445)]
    p = {"cloudflare": [F] * 3, "google": [F] * 3, "ext": [F] * 3, "nas": [F] * 3}
    fs = evaluate(view(targets=targets, probes=p), NOW)
    assert [(f.rule, f.key) for f in fs] == [("internet_down", "internet"), ("service_down", "nas")]


def test_service_down_only_when_important():
    targets = [Target("a", "tcp", "192.0.2.31", 1, important=False), Target("b", "http", "192.0.2.31", 2)]
    fs = evaluate(view(targets=targets, probes={"a": [F] * 3, "b": [F] * 3}), NOW)
    assert [(f.rule, f.key) for f in fs] == [("service_down", "b")]


def test_dns_broken_needs_both_dns_and_cloudflare_ok():
    p = {"dns-router": [F] * 3, "dns-external": [F] * 3, "cloudflare": [T] * 3}
    assert rules(evaluate(view(probes=p), NOW)) == ["dns_broken"]
    p["dns-external"] = [T] * 3
    assert [f.key for f in evaluate(view(probes=p), NOW)] == ["router"]  # router-only case
    p.update({"dns-external": [F] * 3, "cloudflare": [F] * 3})
    assert "dns_broken" not in rules(evaluate(view(probes=p), NOW))


def sev(pct):
    fs = evaluate(view(metrics={"nas": metrics(fs=[("/mnt/tank", pct)])}), NOW)
    return fs[0].severity if fs else None


def test_disk_thresholds():
    assert sev(93) == "medium" and sev(96) == "high" and sev(89) is None
    assert sev(90) == "medium" and sev(95) == "high"


def test_disk_title_and_key():
    f = evaluate(view(metrics={"nas": metrics(fs=[("/mnt/tank", 93)])}), NOW)[0]
    assert f.key == "nas:/mnt/tank" and f.title == "NAS: disk /mnt/tank 93% full"


def temp_hist(values, span=300, step=10, sensor="coretemp/Package id 0"):
    n = span // step
    return {"docker-host": [(NOW - span + i * step, {sensor: v}) for i, v in enumerate(values(n + 1))]}


def test_temp_needs_5_min():
    assert rules(evaluate(view(temps=temp_hist(lambda n: [95] * n)), NOW)) == ["temp_high"]
    assert evaluate(view(temps=temp_hist(lambda n: [95] * n, span=120)), NOW) == []  # only 2 min
    assert evaluate(view(temps=temp_hist(lambda n: [95] * (n - 1) + [80])), NOW) == []  # dipped
    assert evaluate(view(temps=temp_hist(lambda n: [85] * n)), NOW) == []  # below CPU limit


def test_temp_disk_uses_lower_threshold():
    h = temp_hist(lambda n: [57] * n, sensor="drivetemp/temp1")
    f = evaluate(view(temps=h), NOW)
    assert rules(f) == ["temp_high"] and f[0].key == "docker-host:drivetemp/temp1"


def test_thresholds_configurable():
    h = temp_hist(lambda n: [85] * n)
    assert rules(evaluate(view(temps=h, thresholds={"temp_cpu": 80}), NOW)) == ["temp_high"]
    m = {"nas": metrics(fs=[("/", 80)])}
    assert rules(evaluate(view(metrics=m, thresholds={"disk_warn": 75}), NOW)) == ["disk_full"]


def test_muted_rule_ignored():
    v = view(probes={"nas": [F] * 3}, mutes={("device_down", "nas")})
    assert evaluate(v, NOW) == []
    v = view(probes={"nas": [F] * 3}, mutes={("device_down", "printer")})
    assert rules(evaluate(v, NOW)) == ["device_down"]


def test_agent_silent_grace():
    assert evaluate(view(last_received={"docker-host": NOW - 600}, started_at=NOW - 60), NOW) == []
    fs = evaluate(view(last_received={"docker-host": NOW - 600}, started_at=NOW - 3600), NOW)
    assert rules(fs) == ["agent_silent"] and fs[0].key == "docker-host"


def test_agent_silent_threshold_and_never_received():
    assert evaluate(view(last_received={"docker-host": NOW - 100}), NOW) == []
    assert rules(evaluate(view(last_received={"docker-host": None}), NOW)) == ["agent_silent"]
    assert evaluate(view(last_received={"docker-host": None}, started_at=NOW - 150), NOW) == []


def test_agent_silent_not_duplicated_for_dead_device():
    v = view(last_received={"docker-host": NOW - 600}, probes={"docker-host": [F] * 3})
    assert rules(evaluate(v, NOW)) == ["device_down"]


def test_power_lost():
    v = view(power={"monitor": PowerState(ac_online=False, battery_pct=80)})
    fs = evaluate(v, NOW)
    assert rules(fs) == ["power_lost"] and fs[0].key == "monitor"
    assert evaluate(view(power={"monitor": PowerState(ac_online=True, battery_pct=80)}), NOW) == []


def test_pool_and_smart():
    s = state(pools=[Pool(name="tank", health="DEGRADED", cap_pct=1, errors="x")],
              disks=[Disk(dev="sda", model="M", smart_passed=False, attrs={}),
                     Disk(dev="sdb", model="M", smart_passed=True, attrs={})])
    fs = evaluate(view(state={"docker-host": s}), NOW)
    assert [(f.rule, f.key) for f in fs] == [("pool_bad", "docker-host:tank"), ("smart_bad", "docker-host:sda")]


def test_container_bad_only_when_important_one_per_container():
    cs = [Container(name="jellyfin", status="running", health="unhealthy", restarts=0),
          Container(name="other", status="exited", health=None, restarts=0),
          Container(name="fine", status="running", health=None, restarts=0)]
    v = view(state={"docker-host": state(containers=cs)})
    assert evaluate(v, NOW) == []  # nothing configured -> nothing fires
    v.important_containers = {"docker-host/jellyfin"}
    fs = evaluate(v, NOW)
    assert [(f.rule, f.key, f.title) for f in fs] == [
        ("container_bad", "docker-host/jellyfin", "Docker host: container jellyfin reports errors (unhealthy)")]
    v.important_containers = {"docker-host/jellyfin", "docker-host/other", "docker-host/fine"}
    assert [f.key for f in evaluate(v, NOW)] == ["docker-host/jellyfin", "docker-host/other"]


def test_router_unqueryable_needs_3_failed_polls():
    bad = {"ok": False, "error": "timeout"}
    assert rules(evaluate(view(fritz=[bad] * 3), NOW)) == ["router_unqueryable"]
    assert evaluate(view(fritz=[bad, bad]), NOW) == []
    assert evaluate(view(fritz=[bad, {"ok": True}, bad]), NOW) == []


def test_log_flood_one_incident():
    v = view(errors={"docker-host": [(NOW - 1, "ata3: I/O error")] * 10000})
    fs = [f for f in evaluate(v, NOW) if f.rule == "log_error"]
    assert len(fs) == 1 and fs[0].key == "docker-host:io_error"


def test_log_error_held_open_until_10_min_without_match():
    def f(age, open_=True):
        v = view(errors={"docker-host": [(NOW - age, "ata3: I/O error")]},
                 open_incidents={("log_error", "docker-host:io_error")} if open_ else set())
        return [x.key for x in evaluate(v, NOW)]
    assert f(30) == ["docker-host:io_error"]
    assert f(120, open_=False) == []  # too old to open
    assert f(120) == ["docker-host:io_error"]  # but held while open
    assert f(590) == ["docker-host:io_error"]
    assert f(601) == []


def test_log_detail_shows_newest_line():
    v = view(errors={"docker-host": [(NOW - 1, "I/O error NEW"), (NOW - 5, "I/O error OLD")]})
    assert "NEW" in evaluate(v, NOW)[0].detail


def test_log_error_fires_for_host_with_skewed_clock(db):
    from lanot_common.protocol import LogBatch, LogLine
    db.insert_logs(LogBatch(host="docker-host", lines=[LogLine(ts=NOW - 600, source="k", severity=3,
                                                         message="ata3: I/O error")]), NOW - 2)
    s = make_settings(replace(CFG, hosts=CFG.hosts[:1]))
    v = build_view(db, s, NOW, started_at=NOW - 1000)
    assert [f.key for f in evaluate(v, NOW) if f.rule == "log_error"] == ["docker-host:io_error"]


def test_log_patterns_and_windows():
    def one(msg, age=1):
        return [f.key for f in evaluate(view(errors={"docker-host": [(NOW - age, msg)]}), NOW)]
    assert one("ZFS: pool DEGRADED") == ["docker-host:zfs"]
    assert one("Out of memory: Killed process 1") == ["docker-host:oom"]
    assert one("Kernel panic - not syncing") == ["docker-host:kernel_panic"]
    assert one("EXT4-fs error (device sda1)") == ["docker-host:fs_error"]
    assert one("nothing special") == []
    assert one("I/O error", age=90) == []  # older than 60 s


def test_segfault_needs_3_in_10_min():
    seg = lambda n, age: [(NOW - age + i, "app[1]: segfault at 0") for i in range(n)]
    assert evaluate(view(errors={"docker-host": seg(2, 300)}), NOW) == []
    assert [f.key for f in evaluate(view(errors={"docker-host": seg(3, 300)}), NOW)] == ["docker-host:segfault"]
    assert evaluate(view(errors={"docker-host": seg(3, 700)}), NOW) == []


def test_build_view_reads_db(db):
    from conftest import sample_metrics, sample_state
    db.insert_metrics(MetricsReport(**sample_metrics("docker-host", NOW - 5)), NOW - 5)
    db.insert_state(StateReport(**sample_state("docker-host", NOW - 5)), NOW - 5)
    for i in range(3):
        db.insert_probe("nas", NOW - 30 + i * 10, False, None)
    db.insert_probe("nas", NOW - 3600, True, 1.0)  # outside window
    db.insert_fritz(NOW - 10, {"ok": False, "error": "x"})
    db.set_mute("device_down", "printer", NOW + 60)
    db.set_setting("thresholds", {"disk_warn": 50})
    db.set_setting("important_containers", ["docker-host/web"])
    s = make_settings(replace(CFG, hosts=CFG.hosts[:2]))
    v = build_view(db, s, NOW, started_at=NOW - 1000)
    assert v.hosts == ["docker-host", "nas"] and v.probes["nas"] == [F, F, F]
    assert v.last_received == {"docker-host": NOW - 5, "nas": None}
    assert "docker-host" in v.metrics and "docker-host" in v.state and v.power["docker-host"].ac_online
    assert v.mutes == {("device_down", "printer")} and v.thresholds == {"disk_warn": 50}
    assert v.important_containers == {"docker-host/web"} and len(v.fritz) == 1
    assert rules(evaluate(v, NOW)) == ["device_down"]


def test_squashfs_log_pattern():
    v = view(errors={"docker-host": [(NOW - 1, "SQUASHFS error: xz decompression failed, data probably corrupt")]})
    fs = [f for f in evaluate(v, NOW) if f.rule == "log_error"]
    assert [(f.key, f.severity, f.title) for f in fs] == [
        ("docker-host:squashfs", "high", "Docker host: Unraid system file corrupt (SQUASHFS error)")]


def test_squashfs_title_host_neutral_elsewhere():
    v = view(errors={"monitor": [(NOW - 1, "SQUASHFS error: Unable to read page, block 1234")]})
    fs = [f for f in evaluate(v, NOW) if f.rule == "log_error"]
    assert [(f.key, f.title) for f in fs] == [("monitor:squashfs", "Monitor: system file corrupt (SQUASHFS error)")]
    assert "Unraid" not in fs[0].title


def test_boot_corrupt():
    s = state(boot_files={"bzfirmware": False, "bzroot": True, "bzmodules": False})
    fs = evaluate(view(state={"docker-host": s}), NOW)
    assert [(f.rule, f.key, f.severity) for f in fs] == [
        ("boot_corrupt", "docker-host:bzfirmware", "high"), ("boot_corrupt", "docker-host:bzmodules", "high")]
    assert fs[0].title == "Docker host: bzfirmware corrupt, do not reboot"
    assert fs[0].detail.startswith("The Unraid boot file bzfirmware on the USB stick does not match its checksum.")
    assert "Replace the file from the matching Unraid release" in fs[0].detail


def test_boot_ok_or_unknown_no_alarm():
    for bf in (None, {}, {"bzfirmware": True, "bzroot": True}):
        assert evaluate(view(state={"docker-host": state(boot_files=bf)}), NOW) == []


def test_containerd_down():
    fs = evaluate(view(state={"nas": state(host="nas", docker_healthy=False)},
                       prev_state={"nas": state(host="nas", docker_healthy=False)}), NOW)
    assert [(f.rule, f.key, f.severity, f.title) for f in fs] == [
        ("containerd_down", "nas", "high", "NAS: containerd is down, container health checks are not running")]


def test_containerd_not_evaluated_when_unknown_or_healthy():
    for dh in (None, True):
        assert evaluate(view(state={"docker-host": state(docker_healthy=dh)}), NOW) == []


def test_all_rules_have_mute_labels():
    from lanot.web.routes import RULE_LABELS
    assert "boot_corrupt" in RULE_LABELS and "containerd_down" in RULE_LABELS


def test_containerd_down_needs_two_consecutive_samples():
    bad = state(host="nas", docker_healthy=False)
    for prev in (None, state(host="nas", docker_healthy=True), state(host="nas", docker_healthy=None)):
        ps = {} if prev is None else {"nas": prev}
        assert evaluate(view(state={"nas": bad}, prev_state=ps), NOW) == []  # one bad sample: a restart
    # recovered now, bad before: nothing
    assert evaluate(view(state={"nas": state(host="nas", docker_healthy=True)}, prev_state={"nas": bad}), NOW) == []


def test_build_view_reads_previous_state(db):
    from conftest import sample_state
    db.insert_state(StateReport(**{**sample_state("docker-host", NOW - 305), "docker_healthy": False}), NOW - 305)
    db.insert_state(StateReport(**{**sample_state("docker-host", NOW - 5), "docker_healthy": False}), NOW - 5)
    s = make_settings(replace(CFG, hosts=CFG.hosts[:1]))
    v = build_view(db, s, NOW, started_at=NOW - 1000)
    assert v.prev_state["docker-host"].ts == NOW - 305 and v.state["docker-host"].ts == NOW - 5
    assert ("containerd_down", "docker-host") in [(f.rule, f.key) for f in evaluate(v, NOW)]


# -- log rules on syslog without PRI, DNS, titles ----------------------------------------------------------
def _log_view(db, msg, severity=6, age=2, host="docker-host"):
    from lanot_common.protocol import LogBatch, LogLine
    db.insert_logs(LogBatch(host=host, lines=[LogLine(ts=NOW - age, source="syslog", severity=severity,
                                                       message=msg)]), NOW - age)
    s = make_settings()
    return build_view(db, s, NOW, started_at=NOW - 1000)


def test_unraid_oom_without_pri_is_seen(db):
    v = _log_view(db, "kernel: Out of memory: Killed process 4242 (java)")
    assert [f.key for f in evaluate(v, NOW) if f.rule == "log_error"] == ["docker-host:oom"]


def test_unraid_xfs_corruption_without_pri_is_seen(db):
    v = _log_view(db, "kernel: XFS (md1p1): Metadata corruption detected at xfs_buf_ioend")
    assert [f.key for f in evaluate(v, NOW) if f.rule == "log_error"] == ["docker-host:fs_error"]


def test_severity6_line_without_pattern_is_ignored(db):
    v = _log_view(db, "kernel: usb 1-1: new high-speed USB device")
    assert [f for f in evaluate(v, NOW) if f.rule == "log_error"] == []


def test_dns_router_only_failure():
    p = {"dns-router": [F] * 3, "dns-external": [T] * 3, "cloudflare": [T] * 3}
    fs = evaluate(view(probes=p), NOW)
    assert [(f.rule, f.key, f.severity) for f in fs] == [("dns_broken", "router", "medium")]
    assert fs[0].title == "FritzBox DNS not answering: devices on the LAN cannot resolve names"
    p["cloudflare"] = [F] * 3
    assert "dns_broken" not in rules(evaluate(view(probes=p), NOW))


def test_dns_both_fail_keeps_key_dns():
    p = {"dns-router": [F] * 3, "dns-external": [F] * 3, "cloudflare": [T] * 3}
    assert [(f.rule, f.key) for f in evaluate(view(probes=p), NOW)] == [("dns_broken", "dns")]


def test_power_lost_title_shows_battery():
    fs = evaluate(view(power={"monitor": PowerState(ac_online=False, battery_pct=93.4)}), NOW)
    assert fs[0].title == "Monitor: mains power lost (battery 93%)"
    assert "93%" in fs[0].detail
    fs = evaluate(view(power={"monitor": PowerState(ac_online=False, battery_pct=None)}), NOW)
    assert fs[0].title == "Monitor: mains power lost"


def test_container_state_words():
    cs = [Container(name="a", status="exited", health=None, restarts=0),
          Container(name="b", status="running", health="unhealthy", restarts=0),
          Container(name="c", status="restarting", health=None, restarts=5),
          Container(name="d", status="dead", health=None, restarts=0)]
    v = view(state={"docker-host": state(containers=cs)}, important_containers={"docker-host/a", "docker-host/b", "docker-host/c", "docker-host/d"})
    assert [f.title for f in evaluate(v, NOW)] == [
        "Docker host: container a stopped", "Docker host: container b reports errors (unhealthy)",
        "Docker host: container c keeps restarting", "Docker host: container d crashed"]


def test_pool_health_words():
    ps = [Pool(name="p1", health="DEGRADED", cap_pct=1, errors="x"),
          Pool(name="p2", health="FAULTED", cap_pct=1, errors="x"),
          Pool(name="p3", health="UNAVAIL", cap_pct=1, errors="x")]
    assert [f.title for f in evaluate(view(state={"nas": state(host="nas", pools=ps)}), NOW)] == [
        "NAS: pool p1 degraded (DEGRADED)", "NAS: pool p2 failed (FAULTED)",
        "NAS: pool p3 state UNAVAIL"]


def test_disk_full_hysteresis():
    def sev(pct, open_sev=None):
        m = metrics()
        m.filesystems = [FsUsage(mount="/mnt", total=1000, used=round(pct * 10))]
        v = view(metrics={"nas": m})
        if open_sev:
            v.open_incidents = {("disk_full", "nas:/mnt")}
            v.open_severity = {("disk_full", "nas:/mnt"): open_sev}
        return [f.severity for f in evaluate(v, NOW)]
    assert sev(94.5) == ["medium"]
    assert sev(94.5, "high") == ["high"]  # within 1% below 95: stays high
    assert sev(93.9, "high") == ["medium"]
    assert sev(89.5) == []
    assert sev(89.5, "medium") == ["medium"]  # within 1% below 90: stays open
    assert sev(88.9, "medium") == []


def test_sudo_audit_lines_never_match(db):
    # sudo logs the full command line; a command mentioning "Out of memory" is no OOM
    msg = 'sudo: @cee:{"sudo":{"accept":{"command":"docker exec x python -c g(\'Out of memory\')"}}}'
    v = _log_view(db, msg, severity=7)
    assert [f for f in evaluate(v, NOW) if f.rule == "log_error"] == []
    v = view(errors={"docker-host": [(NOW - 1, "sudo:  admin : TTY=pts/0 ; COMMAND=/usr/bin/grep 'I/O error' x")]})
    assert evaluate(v, NOW) == []


# -- the any-severity path needs strict patterns ----------------------
def _log_keys(db, msg, severity, host="docker-host"):
    return [f.key for f in evaluate(_log_view(db, msg, severity=severity, host=host), NOW) if f.rule == "log_error"]


def test_whoopsie_is_no_kernel_oops(db):
    assert _log_keys(db, "systemd: whoopsie.path: Deactivated successfully.", 6, host="docker-host") == []


def test_smartd_prefailure_attribute_change_is_info(db):
    msg = ("smartd[1234]: Device: /dev/sda [SAT], SMART Prefailure Attribute: 1 Raw_Read_Error_Rate "
           "changed from 64 to 65")
    assert _log_keys(db, msg, 6, host="nas") == []


def test_nvidia_nvrm_out_of_memory_is_no_oom(db):
    msg = "kernel: NVRM: GPU0 nvAssertOkFailedNoLog: Check failed: Out of memory [NV_ERR_NO_MEMORY]"
    assert _log_keys(db, msg, 4, host="docker-host") == []


def test_sev6_oom_kill_still_found(db):
    assert _log_keys(db, "Out of memory: Killed process 1234 (x)", 6) == ["docker-host:oom"]


def test_sev6_xfs_corruption_still_found(db):
    assert _log_keys(db, "XFS (md1): Metadata corruption detected", 6) == ["docker-host:fs_error"]


def test_strict_patterns_positive_at_low_priority(db):
    assert _log_keys(db, "kernel: Oops: 0000 [#1] SMP PTI", 6) == ["docker-host:kernel_panic"]
    assert _log_keys(db, "smartd[1]: Device: /dev/sdb, FAILED SMART self-check. BACK UP DATA NOW!", 6) == [
        "docker-host:smart", "docker-host:kernel_panic"]  # the Oops line above is still in the window


def test_power_only_watched_on_battery_hosts():
    off = PowerState(ac_online=False, battery_pct=50)
    assert evaluate(view(power={"nas": off}), NOW) == []  # nas has no has_battery in the config
    assert rules(evaluate(view(power={"monitor": off}), NOW)) == ["power_lost"]


def test_internet_down_needs_every_configured_target():
    from lanot.config import parse_config
    cfg = parse_config({"internet": {"ping_targets": [
        {"name": "a", "address": "192.0.2.101"}, {"name": "b", "address": "192.0.2.102"},
        {"name": "c", "address": "192.0.2.103"}]}})
    p = {"a": [F] * 3, "b": [F] * 3, "c": [T] * 3}
    assert evaluate(view(config=cfg, probes=p), NOW) == []
    p["c"] = [F] * 3
    fs = evaluate(view(config=cfg, probes=p), NOW)
    assert rules(fs) == ["internet_down"] and "192.0.2.103" in fs[0].detail
