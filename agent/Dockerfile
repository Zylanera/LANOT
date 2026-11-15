# LANOT agent image. Build from the repo root:
#   docker build -f agent/Dockerfile -t lanot-agent:dev .
#
# Runtime requirements (set in the compose file, not baked into the image):
#   privileged: true        nsenter into the host's namespaces, SMART access
#   pid: host               nsenter -t 1 targets the host's PID 1
#   network_mode: host      /proc/1/net/dev must describe the host NICs
#   read_only: true         the image works with a read-only root filesystem;
#                           only the buffer volume (and tmpfs /tmp) is writable
#   volumes:
#     - <host buffer dir>:/buffer             writable: queue, tail state, cursors
#     - /:/host:ro                            host /proc, /sys, mounts, logs
#     - /var/run/docker.sock:/var/run/docker.sock:ro
#   env: HOST_NAME, LANOT_URL, AGENT_TOKEN (+ optional LOG_FILES, JOURNAL_DIR,
#        ENABLE_ZFS/SMART/UNRAID/POWER, HOST_ROOT, BUFFER_DIR, DOCKER_SOCK)
# Runs as root: nsenter and device access need it.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends smartmontools util-linux systemd \
    && rm -rf /var/lib/apt/lists/*

COPY common /src/common
COPY agent /src/agent
RUN pip install --no-cache-dir /src/common /src/agent \
    && rm -rf /src

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BUFFER_DIR=/buffer
VOLUME /buffer

CMD ["python", "-m", "lanot_agent.main"]
