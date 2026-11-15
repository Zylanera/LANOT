# LANOT server image (API, rules, pinger, FritzBox poller, investigator, dashboard).
# Build from the repo root:
#   docker build -f server/Dockerfile -t lanot-server:dev .
#
# Runtime (set in the compose file, not baked in):
#   volumes:  <data dir>:/data (SQLite database, known_hosts)
#             lanot.toml at /config/lanot.toml (ro)
#             investigator SSH key at /secrets/investigator_key (ro, optional)
#   env:      AGENT_TOKENS, ANTHROPIC_API_KEY, FRITZ_USER, FRITZ_PASSWORD, NTFY_URL, NTFY_TOPIC,
#             HEALTHCHECK_URL, OLLAMA_URL ... (see lanot/config.py and deploy/.env.example)
#   ports:    8080 (dashboard + agent API, LAN only)
#   cap_add:  NET_RAW (ICMP pings; icmplib falls back to privileged sockets)
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client traceroute iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY common /src/common
COPY server /src/server
RUN pip install --no-cache-dir /src/common /src/server \
    && rm -rf /src

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/lanot.db \
    LANOT_CONFIG=/config/lanot.toml
VOLUME /data
EXPOSE 8080

CMD ["uvicorn", "lanot.main:app", "--host", "0.0.0.0", "--port", "8080"]
