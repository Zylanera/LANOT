#!/bin/bash
# Create or update the LANOT agent as a TrueNAS SCALE custom app. Run as root (sudo) on TrueNAS.
#
# Variables (with examples):
#   LANOT_DIR=/mnt/tank/.lanot           a directory on a data pool, holds agent.env and the buffer (required)
#   HOST_NAME=nas                        id of this host in lanot.toml (required)
#   LANOT_URL=http://192.0.2.24:8080     the LANOT server (required)
#   TZ=UTC
#
# Before the first run:
#   zfs create -o exec=on -o setuid=off -o atime=off tank/.lanot     (pool name is yours)
#   install -d -m 0700 "$LANOT_DIR/buffer"
#   printf 'AGENT_TOKEN=%s\n' '<token>' > "$LANOT_DIR/agent.env"; chmod 600 "$LANOT_DIR/agent.env"
#   docker load < lanot-agent.tar
set -euo pipefail

: "${LANOT_DIR:?set LANOT_DIR, e.g. /mnt/tank/.lanot}"
: "${HOST_NAME:?set HOST_NAME to the id of this host in lanot.toml}"
: "${LANOT_URL:?set LANOT_URL, e.g. http://192.0.2.24:8080}"
TZ="${TZ:-UTC}"
APP=lanot-agent

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -s "$LANOT_DIR/agent.env" ]] || { echo "missing $LANOT_DIR/agent.env" >&2; exit 1; }
for v in "$LANOT_DIR" "$HOST_NAME" "$LANOT_URL" "$TZ"; do
  [[ "$v" =~ ^[A-Za-z0-9._:/+-]+$ ]] || { echo "unexpected characters in: $v" >&2; exit 1; }
done

compose=$(sed -e "s#__LANOT_DIR__#$LANOT_DIR#g" -e "s#__HOST_NAME__#$HOST_NAME#g" \
              -e "s#__LANOT_URL__#$LANOT_URL#g" -e "s#__TZ__#$TZ#g" "$(dirname "$0")/agent-app.yaml")
payload=$(python3 -c 'import json, sys; print(json.dumps({"app_name": sys.argv[1], "custom_app": True,
    "custom_compose_config_string": sys.stdin.read()}))' "$APP" <<<"$compose")

if midclt call app.query "[[\"name\", \"=\", \"$APP\"]]" | grep -q "\"$APP\""; then
  # The app exists: redeploy picks up a newly loaded image. To change the settings
  # above, delete the app in the TrueNAS UI (Apps) and run this script again.
  midclt call -j app.redeploy "$APP" >/dev/null
  echo "redeployed $APP"
else
  midclt call -j app.create "$payload" >/dev/null
  echo "created $APP"
fi
