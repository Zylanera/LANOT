#!/bin/bash
# Install or update the LANOT agent with plain `docker run` (Unraid, or any Linux host
# without compose). Run as root on the host. The image must already be loaded:
#   docker save lanot-agent:dev | ssh root@HOST docker load
#
# Variables (with examples):
#   HOST_NAME=docker-host                id of this host in lanot.toml (required)
#   LANOT_URL=http://192.0.2.24:8080     the LANOT server (required)
#   ENV_FILE=/boot/config/lanot/agent.env  file with AGENT_TOKEN=..., mode 600 (required)
#   BUFFER=/mnt/user/appdata/lanot-agent   writable queue directory
#   LOG_FILES=/host/var/log/syslog,/host/var/log/docker.log   plain log files to tail
#   JOURNAL_DIR=/host/var/log/journal    systemd journal instead (leave LOG_FILES empty)
#   ENABLE_UNRAID=1 ENABLE_SMART=1 ENABLE_ZFS=1 ENABLE_POWER=0
#   TZ=UTC                               must match the host, the syslog has local times
#
# On Unraid the container lives in docker.img and dockerd starts it again after a
# reboot or an array stop/start. That needs `--restart always`: Unraid stops
# containers with `docker stop`, and `unless-stopped` would leave it stopped.
set -euo pipefail

NAME="${NAME:-lanot-agent}"
IMAGE="${IMAGE:-lanot-agent:dev}"
: "${HOST_NAME:?set HOST_NAME to the id of this host in lanot.toml}"
: "${LANOT_URL:?set LANOT_URL, e.g. http://192.0.2.24:8080}"
: "${ENV_FILE:?set ENV_FILE to a file containing AGENT_TOKEN=...}"
BUFFER="${BUFFER:-/var/lib/lanot-agent}"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -s "$ENV_FILE" ]] || { echo "missing $ENV_FILE" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null || { echo "image $IMAGE not loaded" >&2; exit 1; }
mkdir -p "$BUFFER"

if docker container inspect "$NAME" >/dev/null 2>&1; then
  docker rm -f "$NAME" >/dev/null
fi

docker run -d --name "$NAME" --restart always \
  --privileged --pid host --network host --read-only --tmpfs /tmp \
  -v /:/host:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$BUFFER":/buffer \
  --log-opt max-size=10m --log-opt max-file=3 \
  --env-file "$ENV_FILE" \
  -e HOST_NAME="$HOST_NAME" \
  -e LANOT_URL="$LANOT_URL" \
  -e TZ="${TZ:-UTC}" \
  -e LOG_FILES="${LOG_FILES:-}" \
  -e JOURNAL_DIR="${JOURNAL_DIR:-}" \
  -e ENABLE_UNRAID="${ENABLE_UNRAID:-0}" \
  -e ENABLE_SMART="${ENABLE_SMART:-1}" \
  -e ENABLE_ZFS="${ENABLE_ZFS:-0}" \
  -e ENABLE_POWER="${ENABLE_POWER:-0}" \
  "$IMAGE"

docker ps --filter "name=^${NAME}$" --format '{{.Names}} {{.Status}}'
