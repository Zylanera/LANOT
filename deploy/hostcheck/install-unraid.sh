#!/bin/bash
# Install (or remove) the investigator's read-only SSH access on Unraid. Idempotent. Run as root on Unraid.
#   PUBKEY=/path/investigator_key.pub bash install-unraid.sh [path/to/lanot-ro]   install / update
#   bash install-unraid.sh --remove                                             remove the key line again
#
# Unraid 7: /root/.ssh is a symlink to /boot/config/ssh/root (on the USB stick), so
# editing /boot/config/ssh/root/authorized_keys takes effect immediately AND survives
# a reboot. It is the same file as the GUI field (Users -> root -> SSH authorized keys).
# root runs the forced command directly (no sudo), so SSH_ORIGINAL_COMMAND arrives.
# /boot is FAT (no exec bit), hence "/bin/bash <script>" in the key line.
#
# Variables:
#   PUBKEY   public key file of the investigator (required for install)
#   BOOT     Unraid flash mount, default /boot (tests point it at a temp dir)
#   LANOT_DIR  where lanot-ro is stored, default $BOOT/config/lanot
set -euo pipefail

BOOT="${BOOT:-/boot}"
DIR="${LANOT_DIR:-$BOOT/config/lanot}"
AK="$BOOT/config/ssh/root/authorized_keys"
MARK='lanot-investigator'

backup() {
  # only the first run backs up: a later backup would already contain our line
  if [[ -f "$AK" && ! -e "$AK.bak-lanot" ]]; then
    cp -p "$AK" "$AK.bak-lanot"
  fi
}

if [[ "${1:-}" == "--remove" ]]; then
  [[ -f "$AK" ]] || { echo "nothing to remove: $AK missing"; exit 0; }
  if grep -qF "$MARK" "$AK"; then
    backup
    tmp=$(mktemp "$AK.XXXXXX")
    grep -vF "$MARK" "$AK" >"$tmp" || true   # grep exits 1 when no line is left
    chmod 600 "$tmp"
    mv "$tmp" "$AK"
    echo "removed investigator key from $AK"
  else
    echo "investigator key not present in $AK"
  fi
  exit 0
fi

SRC="${1:-$(dirname "$0")/../../hostcheck/lanot-ro}"
[[ -f "$SRC" ]] || { echo "lanot-ro not found: $SRC" >&2; exit 1; }
[[ -n "${PUBKEY:-}" && -f "$PUBKEY" ]] || { echo "set PUBKEY to the investigator's public key file" >&2; exit 1; }
read -r ktype kdata _ <"$PUBKEY" || true
[[ "$ktype" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa)$ && "$kdata" =~ ^[A-Za-z0-9+/=]+$ ]] \
  || { echo "$PUBKEY does not look like an OpenSSH public key" >&2; exit 1; }
bash -n "$SRC"

# the key line points at the stored copy; the comment is our marker for --remove
LINE="command=\"/bin/bash $DIR/lanot-ro\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $ktype $kdata $MARK"

mkdir -p "$DIR"
chmod 0700 "$DIR"
cp "$SRC" "$DIR/lanot-ro.new"
chmod 0600 "$DIR/lanot-ro.new"
mv "$DIR/lanot-ro.new" "$DIR/lanot-ro"

mkdir -p "$(dirname "$AK")"
chmod 0700 "$(dirname "$AK")"
touch "$AK"
chmod 0600 "$AK"
if ! grep -qF "$MARK" "$AK"; then
  backup
  # a last line without newline would be glued to ours
  if [[ -s "$AK" && -n "$(tail -c1 "$AK")" ]]; then
    printf '\n' >>"$AK"
  fi
  printf '%s\n' "$LINE" >>"$AK"
  echo "added investigator key to $AK"
else
  echo "investigator key already present in $AK (use --remove first to replace it)"
fi
echo "ok: $DIR/lanot-ro"
