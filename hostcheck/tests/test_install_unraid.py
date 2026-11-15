"""Tests for deploy/hostcheck/install-unraid.sh against a temp BOOT dir."""
import os
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy/hostcheck/install-unraid.sh"
RO = REPO / "hostcheck/lanot-ro"
# an unrelated key the admin already uses; must survive every run untouched
ADMIN_KEY = "ssh-ed25519 AAAAexampleadminkey admin@laptop"
MARK = "lanot-investigator"


def pubkey(tmp: Path) -> Path:
    p = tmp / "investigator_key.pub"
    p.write_text("ssh-ed25519 AAAAexampleinvestigatorkey someone@example\n")
    return p


def run(boot: Path, *args, key: Path | None = None):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "BOOT": str(boot)}
    if key is not None:
        env["PUBKEY"] = str(key)
    return subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True)


def ak(boot: Path) -> Path:
    return boot / "config/ssh/root/authorized_keys"


def seed(boot: Path, content: str) -> None:
    ak(boot).parent.mkdir(parents=True)
    ak(boot).write_text(content)


def test_install_idempotent(tmp_path):
    boot = tmp_path / "boot"
    seed(boot, ADMIN_KEY + "\n")
    key = pubkey(tmp_path)
    for _ in range(3):
        r = run(boot, str(RO), key=key)
        assert r.returncode == 0, r.stderr
    lines = ak(boot).read_text().splitlines()
    assert lines[0] == ADMIN_KEY
    assert len(lines) == 2
    assert lines[1].startswith(f'command="/bin/bash {boot}/config/lanot/lanot-ro",no-pty,')
    assert " ssh-ed25519 AAAAexampleinvestigatorkey " in lines[1] and lines[1].endswith(MARK)
    assert "someone@example" not in lines[1]  # the key's own comment is replaced by the marker
    assert (boot / "config/lanot/lanot-ro").read_bytes() == RO.read_bytes()
    assert stat.S_IMODE((boot / "config/lanot").stat().st_mode) == 0o700
    # backup holds the original, taken once
    assert (Path(str(ak(boot)) + ".bak-lanot")).read_text() == ADMIN_KEY + "\n"


def test_install_needs_a_public_key(tmp_path):
    boot = tmp_path / "boot"
    seed(boot, ADMIN_KEY + "\n")
    assert run(boot, str(RO)).returncode != 0
    bad = tmp_path / "bad.pub"
    bad.write_text("not a key\n")
    assert run(boot, str(RO), key=bad).returncode != 0
    assert MARK not in ak(boot).read_text()


def test_missing_trailing_newline(tmp_path):
    boot = tmp_path / "boot"
    seed(boot, ADMIN_KEY)  # no newline at the end
    assert run(boot, str(RO), key=pubkey(tmp_path)).returncode == 0
    text = ak(boot).read_text()
    lines = text.splitlines()
    assert lines[0] == ADMIN_KEY and lines[1].endswith(MARK) and text.endswith("\n")


def test_backup_not_overwritten(tmp_path):
    boot = tmp_path / "boot"
    seed(boot, ADMIN_KEY + "\n")
    bak = Path(str(ak(boot)) + ".bak-lanot")
    bak.write_text("older backup\n")
    assert run(boot, str(RO), key=pubkey(tmp_path)).returncode == 0
    assert bak.read_text() == "older backup\n"


def test_remove(tmp_path):
    boot = tmp_path / "boot"
    seed(boot, ADMIN_KEY)
    assert run(boot, str(RO), key=pubkey(tmp_path)).returncode == 0
    r = run(boot, "--remove")
    assert r.returncode == 0, r.stderr
    assert ak(boot).read_text().splitlines() == [ADMIN_KEY]
    assert stat.S_IMODE(ak(boot).stat().st_mode) == 0o600
    r = run(boot, "--remove")  # again: no-op
    assert r.returncode == 0 and "not present" in r.stdout
    assert ak(boot).read_text().splitlines() == [ADMIN_KEY]


def test_remove_only_line(tmp_path):
    boot = tmp_path / "boot"
    ak(boot).parent.mkdir(parents=True)
    assert run(boot, str(RO), key=pubkey(tmp_path)).returncode == 0  # creates the file with just our line
    assert run(boot, "--remove").returncode == 0
    assert ak(boot).read_text() == ""


def test_missing_script_fails(tmp_path):
    boot = tmp_path / "boot"
    seed(boot, ADMIN_KEY + "\n")
    r = run(boot, str(tmp_path / "nope"), key=pubkey(tmp_path))
    assert r.returncode != 0
    assert MARK not in ak(boot).read_text()
