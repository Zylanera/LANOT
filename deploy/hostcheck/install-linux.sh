#!/bin/bash
# Install the investigator's read-only SSH access on a systemd Linux host (Ubuntu, Debian). Idempotent.
#   sudo PUBKEY=/path/investigator_key.pub bash deploy/hostcheck/install-linux.sh [path/to/lanot-ro]
# What it does:
# - system user "$LANOT_USER" (default lanot; no password, shell /bin/bash)
# - $DEST (default /usr/local/sbin/lanot-ro, root 0755) + a sudoers entry for exactly that script
# - authorized_keys: the investigator key, forced onto lanot-ro. sudo drops
#   SSH_ORIGINAL_COMMAND (env_reset), so the command is passed as the single argument.
# Remove again: sudo userdel -r lanot && sudo rm /etc/sudoers.d/91-lanot-ro /usr/local/sbin/lanot-ro
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

SRC="${1:-$(dirname "$0")/../../hostcheck/lanot-ro}"
LANOT_USER="${LANOT_USER:-lanot}"
DEST="${DEST:-/usr/local/sbin/lanot-ro}"
SUDOERS="${SUDOERS:-/etc/sudoers.d/91-lanot-ro}"
HOME_DIR="${HOME_DIR:-/var/lib/$LANOT_USER}"

[[ -f "$SRC" ]] || { echo "lanot-ro not found: $SRC" >&2; exit 1; }
[[ -n "${PUBKEY:-}" && -f "$PUBKEY" ]] || { echo "set PUBKEY to the investigator's public key file" >&2; exit 1; }
read -r ktype kdata _ <"$PUBKEY" || true
[[ "$ktype" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa)$ && "$kdata" =~ ^[A-Za-z0-9+/=]+$ ]] \
  || { echo "$PUBKEY does not look like an OpenSSH public key" >&2; exit 1; }
bash -n "$SRC"
KEYLINE="command=\"sudo -n $DEST \\\"\$SSH_ORIGINAL_COMMAND\\\"\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $ktype $kdata lanot-investigator"

# 1. user
if ! id "$LANOT_USER" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$HOME_DIR" --create-home --shell /bin/bash "$LANOT_USER"
fi
usermod --shell /bin/bash --home "$HOME_DIR" "$LANOT_USER"
passwd -l "$LANOT_USER" >/dev/null            # no password login, ever
install -d -o "$LANOT_USER" -g "$LANOT_USER" -m 0700 "$HOME_DIR"

# 2. script (root-owned, not writable by the user)
install -o root -g root -m 0755 "$SRC" "$DEST"

# 3. sudoers: validate a temp file first, then move into place
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '%s ALL=(root) NOPASSWD: %s\n' "$LANOT_USER" "$DEST" >"$tmp"
chmod 0440 "$tmp"
if ! visudo -c -f "$tmp" >/dev/null 2>&1; then
  echo "sudoers syntax check failed" >&2; exit 1
fi
install -o root -g root -m 0440 "$tmp" "$SUDOERS"

# 4. authorized_keys (exactly this one line)
install -d -o "$LANOT_USER" -g "$LANOT_USER" -m 0700 "$HOME_DIR/.ssh"
printf '%s\n' "$KEYLINE" >"$tmp"
install -o "$LANOT_USER" -g "$LANOT_USER" -m 0600 "$tmp" "$HOME_DIR/.ssh/authorized_keys"

# 5. sshd must not exclude the user (report only, never edit sshd_config)
if sshd -T 2>/dev/null | grep -qiE '^(allowusers|allowgroups|denyusers|denygroups) '; then
  echo "WARNING: sshd has AllowUsers/AllowGroups/Deny* rules that may lock out $LANOT_USER:" >&2
  sshd -T | grep -iE '^(allowusers|allowgroups|denyusers|denygroups) ' >&2
fi

echo "ok: user $LANOT_USER, $DEST, $SUDOERS, authorized_keys"
