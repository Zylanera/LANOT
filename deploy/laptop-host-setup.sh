#!/usr/bin/env bash
# Optional preparation for a LAPTOP that runs LANOT as the always-on monitor host.
# Not needed on a desktop or server. Idempotent; run with sudo.
#
# It changes system settings, so read it first:
#   1. closing the lid no longer suspends (logind drop-in, logind reloaded with HUP)
#   2. sleep, suspend and hibernate targets are masked
#   3. if the battery supports it, the charge limit is set to CHARGE_LIMIT percent
#      (default 80) and a small systemd unit re-applies it at boot
#
# Undo: rm /etc/systemd/logind.conf.d/lanot.conf && systemctl kill -s HUP systemd-logind
#       systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target
#       systemctl disable --now lanot-charge-limit.service && rm /etc/systemd/system/lanot-charge-limit.service
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
CHARGE_LIMIT="${CHARGE_LIMIT:-80}"

# 1) the lid switch must not suspend
mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/lanot.conf <<'CONF'
[Login]
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
CONF
systemctl kill -s HUP systemd-logind

# 2) no sleep states
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

# 3) battery charge limit, where the firmware offers one
bat=""
for f in /sys/class/power_supply/BAT*/charge_control_end_threshold; do
  [ -e "$f" ] && bat="$f" && break
done
if [ -n "$bat" ]; then
  echo "$CHARGE_LIMIT" > "$bat"
  cat > /etc/systemd/system/lanot-charge-limit.service <<UNIT
[Unit]
Description=Battery charge limit $CHARGE_LIMIT percent

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo $CHARGE_LIMIT > $bat'

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable lanot-charge-limit.service
  echo "charge limit $CHARGE_LIMIT % set ($bat)"
else
  echo "this battery has no charge limit setting, skipped"
fi
