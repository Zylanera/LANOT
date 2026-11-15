# Architecture

This page explains how the parts of LANOT fit together and why they are built
the way they are. For installation see the README, for the threat model see
SECURITY.md.

## Overview

```
  NAS (agent)        Docker host (agent)        Monitor host
  -----------        -------------------        ------------------------------------
  metrics, state  --HTTP POST-->                 server: API, SQLite, pinger,
  logs            --HTTP POST-->                         rules, notifier, investigator,
                                                         dashboard (port 8080)
        ^                ^                       agent (the monitor host itself)
        |                |                       ntfy (push, port 8081)
        +--- SSH, read-only (lanot-ro) ---------  Ollama (optional, host service)

  Router  <-- ping, DNS, TR-064 (FritzBox) ----  server
  healthchecks.io style URL  <-- every minute -- server
  Anthropic API  <-- only during an investigation, optional -- server
```

Everything runs in Docker. The server and the monitor host's agent come from
`deploy/compose.yml`; other hosts run the agent with `docker run` (Unraid,
Linux) or as a custom app (TrueNAS).

## Packages

| Directory | Python package | What it is |
|---|---|---|
| `common/` | `lanot_common` | Pydantic models for the agent to server protocol |
| `agent/` | `lanot_agent` | Collectors, disk buffer, sender |
| `server/` | `lanot` | FastAPI app, background loops, dashboard |
| `hostcheck/` | (bash) | `lanot-ro`, the forced-command allowlist |

## Agent

One process, one loop, ticking once a second (`lanot_agent/main.py`):

| Job | Interval | Source |
|---|---|---|
| metrics | 30 s | `/host/proc`, `/host/sys` (CPU, memory, load, physical NICs only, hwmon temperatures, real file systems, uptime, AC and battery) |
| state | 5 min | Docker API (containers, health, restarts), `zpool` and `smartctl` via `nsenter` into the host, Unraid `var.ini`, Unraid boot file checksums (hourly, in a low-priority thread), whether `containerd` runs |
| logs | 10 s | tailed files (rotation and truncation aware) or `journalctl -D` with a cursor, plus Docker events |
| drain | 10 s | resend whatever is in the buffer |

Delivery is at-least-once. A log source only commits its position after the
lines were sent or written to the disk buffer, so a crash or an unreachable
server never loses lines. The buffer is a directory of files, one per payload,
FIFO by sequence number, capped at 50 MB (oldest dropped first). Payloads the
server rejects as invalid (400, 413, 422) are dropped; everything else is
retried.

`smartctl` always runs with `-n standby`: a sleeping disk is skipped, never
woken up.

## Server

`lanot/main.py` builds the app and starts these loops. Each one is wrapped so an
exception is logged and the loop goes on.

| Loop | Interval | Module |
|---|---|---|
| pinger | 10 s | `pinger.py`: ICMP via icmplib, DNS via dnspython, TCP connect, HTTP GET |
| FritzBox | 30 s | `fritz.py`: TR-064 line and WAN state; the event log while related incidents are open |
| rules | 10 s | `rules.py` and `incidents.py` |
| notifier flush | 10 s | `notify.py` |
| gateway discovery | 1 h | hop 2 of a traceroute to the first internet target |
| housekeeping | 1 h | `housekeeping.py`: retention and size cap |
| daily summary | daily | `notify.py` |
| healthcheck | 60 s | `housekeeping.py` |

### Storage

One SQLite file in WAL mode (`db.py`). One connection per thread, all writes
serialized through one lock, logs indexed with FTS5 for the log search. Agent
tables store both the agent's timestamp and the server's receive time; liveness,
log rules and retention use the receive time, so a host with a wrong clock can
neither fake freshness nor dodge alarms. Metrics, state, logs, probes and
FritzBox polls are deleted after 30 days, or earlier when the file grows past
the size cap (logs go first). Incidents and diagnoses are kept.

### Rules and incidents

`rules.evaluate()` is a pure function of a snapshot (`SystemView`) and the time.
It returns findings: `(rule, key, severity, title, detail)`. The incident
manager turns findings into incidents:

- a new finding opens an incident;
- the same `(rule, key)` coming back within 15 minutes reopens the old incident
  and counts a flap instead of opening a new one;
- a finding that is gone resolves the incident (not during the first 3 minutes
  after a server start, while the probe windows are still empty);
- a muted `(rule, key)` neither fires nor resolves.

Thresholds (disk, temperatures), important services and important containers
are stored in the database and edited in the dashboard. The network layout comes
from `lanot.toml` and is fixed for the life of the process.

Some rules deliberately wait: three failed probes in a row (about 30 s),
temperatures above the limit for 5 minutes, containerd missing in two state
reports in a row, three segfaults in 10 minutes. Disk alarms have a 1%
hysteresis so a disk hovering at 90% does not flap.

### Notifications

`notify.Notifier` sends JSON to ntfy. Per incident: the opening push goes out at
once, the first diagnosis right after it, later changes at most every 10
minutes, and the all-clear carries the total duration and how often it went
down. Problems found at the very first start are summed up in one push. Battery
hosts get extra pushes at 20% and 10%. The rate limit survives restarts
(`last_push_at` is stored).

### Investigator

`investigator/runner.py` runs once per new incident, one at a time, and again
for incidents that stay open longer than 30 minutes when their picture changes
(more flaps or other failing targets), at most every 30 minutes.

1. `facts.py` collects a fixed bundle without any model: the incident, probes
   10 minutes before and after the start, the FritzBox state and event log,
   severe log lines of the incident's host and of all hosts, metrics, a
   traceroute. The bundle is redacted (`tools.redact`) and stored with the
   diagnosis in every case.
2. With an API key and no open internet outage, `anthropic_run.py` runs a manual
   tool-use loop against the Anthropic Messages API. The tools are in
   `tools.py`; the model must finish with a `final_diagnosis` call that follows
   a JSON schema (summary, what happened, cause, confidence, suggestions,
   evidence).
3. Otherwise, or if that fails, `ollama_run.py` sends a compact text version of
   the bundle to Ollama with the same schema as the response format. No tools.
   A local model's confidence is capped at "likely".
4. If both fail, the incident gets a "no AI assessment" note and the facts.

The daily cap (20) and the per-run limits (15 tool calls, 3 minutes) are
enforced in code.

### Dashboard

`web/routes.py` renders Jinja2 templates; `web/static/app.js` polls
`/api/v1/ui/overview` every 5 seconds on the start page and draws the history
charts with the bundled uPlot. No external requests, no build step. Colours are
never the only signal: every status also has a shape and a word.

The "path to the internet" strip on the start page (LAN, router, line,
provider, internet) and the outage attribution on the internet page come from
`attribute()`: the FritzBox line state if available, otherwise whether the
router and the other LAN hosts answered pings during the outage.

## Protocol

Agents POST JSON to `/api/v1/metrics`, `/api/v1/state` and `/api/v1/logs` with
`Authorization: Bearer <token>`. The models are in
`common/lanot_common/protocol.py`. Unknown hosts and wrong tokens get 401.
`/api/v1/health` needs no token and is used by the container health check.

## Configuration loading

`lanot/config.py` reads the environment with pydantic-settings and the TOML
file with the standard library's `tomllib`, so the config file adds no
dependency. The file is validated strictly: unknown keys, duplicate or reserved
host ids, invalid addresses and unknown time zones stop the server at start
with a message that names the key.

## Tests

Each package has its own test suite; none of them needs Docker, network access,
SSH or a model. The server tests use an in-memory example network (hosts `nas`,
`docker-host`, `monitor`, `printer` in 192.0.2.0/24). The hostcheck tests run
`lanot-ro` in dry-run mode against a long list of allowed and refused commands,
and the Unraid installer against a temporary directory.
