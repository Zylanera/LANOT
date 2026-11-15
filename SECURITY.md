# Security

## Reporting a vulnerability

Please open a GitHub security advisory on this repository (Security tab,
"Report a vulnerability"). Do not open a public issue for it. Include what you
found, how to reproduce it and which version or commit you tested. I will
answer in the advisory.

## What LANOT is supposed to protect

LANOT runs inside a home or small office LAN and is trusted with a lot: it reads
logs, metrics and container state of every host, and it can SSH into them. The
design goal is that it can look at everything and change nothing, and that its
own secrets do not leak into logs, the dashboard or the AI provider.

## Trust boundaries

### Dashboard and agent API (port 8080)

- There is no login and no TLS. The dashboard is meant to be reachable from the
  LAN only. If you expose it, put a reverse proxy with authentication and TLS in
  front of it.
- Form posts (mute, settings) are checked against an allowlist of `Host`
  headers (DNS rebinding) and must not carry a foreign `Origin` (cross-site
  requests). Everything else on the dashboard is read-only.
- Every untrusted string (log lines, container names, AI output) is rendered
  through Jinja2 autoescaping, and the page script only uses `textContent`.
  The page loads nothing from third-party hosts.
- Agents authenticate with one bearer token per host (`AGENT_TOKENS`), compared
  in constant time. A token is only valid for its own host id. Agent timestamps
  are not trusted for liveness or retention; the server uses its own receive
  time.

### Agents (privileged)

The agent is **not** sandboxed, and cannot be with what it does:

- `privileged: true`, `pid: host` and `network_mode: host` (SMART needs device
  access, `nsenter -t 1` runs `zpool` and `smartctl` in the host namespaces,
  `/proc/1/net/dev` must be the host's).
- `/` of the host is mounted read-only at `/host`.
- `/var/run/docker.sock` is mounted. A read-only bind mount does not make the
  Docker API read-only: anything that can talk to that socket controls Docker,
  and with it the host. The agent code only issues `GET` requests
  (`/containers/json`, `/containers/<name>/json`, `/events`).
- The container file system is read-only; the only writable places are its
  buffer directory and a tmpfs `/tmp`.

Treat the agent image like any other root-level software on the host: build it
yourself from this repository and keep the host's Docker socket away from
anything else you do not trust.

### Investigator

- It is started by the fixed rules, never by itself, and it only explains.
- Its tools: search the stored logs and metrics, network tests from the server
  (ping, DNS, TCP, HTTP, traceroute; targets are validated), the FritzBox status
  and event log, and `host_cmd`.
- `host_cmd` runs over SSH with a dedicated key. On every host that key is
  pinned in `authorized_keys` with `command=` to `hostcheck/lanot-ro` plus
  `no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`. lanot-ro is
  the real boundary, not the server code:
  - only a fixed set of read-only command forms is accepted (journalctl, dmesg,
    docker ps/inspect/logs/stats, zpool status/list, zfs list, smartctl -a/-H/-i,
    df, free, uptime, sensors, lsblk, ip, ss, systemctl status/--failed, ping,
    traceroute, getent hosts, tail and cat of a few fixed files);
  - the input is split on plain spaces with globbing off, every token is
    checked against a small character set, there is no `eval`, no `sh -c`, and
    the final command runs with `exec env -i` and a fixed `PATH`;
  - options with side effects are refused (`smartctl -t`, `zpool scrub`,
    `journalctl --vacuum-*`, `docker exec`, `systemctl restart` and so on),
    `smartctl` always gets `-n standby` so it does not spin up sleeping disks,
    and `docker inspect` uses a fixed template that leaves out `Env`, `Cmd`,
    `Args` and labels;
  - anything else ends with `denied: ...` and exit code 2.
- On Unraid the key logs in as root (Unraid has no real user management); on
  Linux and TrueNAS it logs in as a locked user `lanot` whose only sudo right is
  running lanot-ro.
- The server also refuses shell metacharacters before it even connects. That is
  defense in depth only.
- Limits per run: 15 tool calls, 3 minutes; at most 20 investigations a day.

What lanot-ro does **not** protect against: the read-only commands still show a
lot (process names, open ports, mounts, container logs). Anyone who holds the
private investigator key can read the same. Keep it on the monitor host, mode
600, and remove the key line from the hosts if you stop using LANOT.

### Data sent to the Anthropic API

When `ANTHROPIC_API_KEY` is set, the fact bundle and the tool results of an
investigation are sent to the Anthropic API. Before that, everything passes a
redaction step that replaces values of password, secret, token and API key
fields, bearer and basic authorization headers, PEM private keys, JWTs and a few
well-known key formats with `[REDACTED]`. Redaction is pattern based. It
catches the common forms, not every possible secret, so assume that log lines
reach the provider. Leave the key unset to keep everything local (Ollama, or no
model at all).

### Secrets on disk

- `.env` (server) and `agent.env` (each agent) hold the tokens, the FritzBox
  password, the API key and the healthcheck URL. Mode 600, never in the
  repository; only `*.example` files with `CHANGE_ME` placeholders are
  committed.
- The FritzBox password and the healthcheck URL are never logged; FritzBox
  errors are reported by exception type only, because their messages can carry
  credentials. HTTP client request logging is turned down for the same reason.
- `lanot.toml` holds no secrets.

## Known gaps

- No authentication or TLS on port 8080 (see above).
- ntfy runs without access control by default. Anyone on the LAN can read the
  topic, and pushes contain incident titles. Configure ntfy auth if that
  matters to you.
- The agent API accepts any payload size up to the server's request limits.
  A compromised agent token can fill the database up to `DB_MAX_BYTES`.
- `StrictHostKeyChecking=accept-new` is used for the investigator's SSH
  connections: the first connection to a host trusts its key. Pre-fill
  `data/known_hosts` if you want to pin keys up front.
