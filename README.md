# LANOT

LANOT (LAN Observation Tool) watches a small network around the clock: a few
servers, a router, the internet uplink. When something breaks it sends a push
notification to your phone, and an investigator collects the facts and writes a
short, plain-language explanation of the likely cause. Fixing it is up to you.
LANOT never changes anything on your machines.

It targets Unraid, TrueNAS SCALE and plain Linux hosts, and has extra support for
FritzBox routers. Should work on current Unraid, TrueNAS SCALE and Debian/Ubuntu-based Linux.

## What it does

- **Probes** every 10 seconds: the router, the provider's first hop, two
  internet addresses, DNS (router and external), every configured host, and any
  TCP or HTTP service you mark as important in the dashboard.
- **Agents** on each server send metrics every 30 seconds (CPU, memory, load,
  network, temperatures, file systems, uptime, battery), state every 5 minutes
  (containers, ZFS pools, SMART, Unraid array and boot files) and logs every
  10 seconds (syslog files or the systemd journal, plus Docker events). When the
  server is unreachable they queue on disk (50 MB cap) and catch up later.
- **Rules** decide what is an incident. They are fixed code, not AI: device
  down after 3 failed pings, internet down when all internet targets fail, DNS
  broken, disk over 90/95%, temperature too high for 5 minutes, pool degraded,
  SMART failed, important container unhealthy, agent silent, power lost on a
  battery host, known-bad log lines (I/O errors, OOM, kernel panic, file system
  errors and so on).
- **Notifications** go through a bundled [ntfy](https://ntfy.sh) server. Flapping
  is folded into one incident (at most one extra push per 10 minutes), you get an
  all-clear when it is over, and a daily summary in the morning.
- **The investigator** runs once per new incident. It always gathers a fixed
  fact bundle (probes, router state and event log, logs and metrics around the
  start, a traceroute). With an Anthropic API key it then asks a Claude model,
  which may use read-only tools: search logs and metrics, run network tests from
  the server, and run whitelisted commands on the hosts over SSH. Without the
  internet (or without a key) it falls back to a local Ollama model that only
  sees the facts. The diagnosis always carries a confidence level and the raw
  evidence.
- **The dashboard** shows an overview, incidents, the internet history with a
  guess where each outage came from (LAN, router, line, provider), per-device
  history charts, log search and settings (mute, important services and
  containers, thresholds). Plain HTML and a little JavaScript, no build step,
  usable on a phone.
- **A dead man's switch**: the server pings a healthchecks.io style URL every
  minute, and calls its `/fail` endpoint when its own alarm path is stuck.

## Requirements

- One always-on Linux machine with Docker and Docker Compose for the server
  (the "monitor host"). The server itself is light. The Ollama fallback needs a
  machine that can run a 7B model (for example a GPU with 6 GB or more).
- Python 3.12 or later if you want to run the tests.
- Optional: a FritzBox with a separate user for TR-064 queries, an Anthropic API
  key, an Ollama install on the monitor host, a healthchecks.io account.

## Install

1. Build the images on the monitor host:

   ```
   git clone <this repository> lanot && cd lanot
   deploy/build-images.sh
   ```

2. Create the data directory (the compose file defaults to `/srv/lanot`, set
   `LANOT_DIR` to use another one):

   ```
   sudo mkdir -p /srv/lanot/{data,secrets,ntfy,agent-buffer}
   cp lanot.example.toml /srv/lanot/lanot.toml          # then edit it
   cp deploy/.env.example /srv/lanot/.env && chmod 600 /srv/lanot/.env
   cp deploy/agent.env.example /srv/lanot/agent.env && chmod 600 /srv/lanot/agent.env
   cp deploy/compose.yml /srv/lanot/compose.yml
   ```

   Generate one token per agent host (`openssl rand -hex 32`) and put them into
   `AGENT_TOKENS` in `.env`. The monitor host's own token also goes into
   `agent.env`.

3. Start it:

   ```
   cd /srv/lanot && AGENT_HOST_NAME=monitor docker compose up -d
   ```

   The dashboard is on port 8080, ntfy on port 8081. Subscribe to the topic
   (`lanot` by default) in the ntfy app on your phone.

4. Install an agent on every other server. Load the image there
   (`docker save lanot-agent:dev | ssh root@HOST docker load`), then:
   - Unraid or plain Linux: `deploy/install-agent.sh` (see the variables at the
     top of the script).
   - TrueNAS SCALE: `deploy/truenas/install-agent.sh`.

5. Optional, the investigator's SSH access. Create a key pair for it on the
   monitor host:

   ```
   ssh-keygen -t ed25519 -N "" -C lanot-investigator -f /srv/lanot/secrets/investigator_key
   ```

   Then install `hostcheck/lanot-ro` and the public key on each host you mark
   with `investigator = true`:
   - Unraid: `deploy/hostcheck/install-unraid.sh`
   - Ubuntu or Debian: `deploy/hostcheck/install-linux.sh`
   - TrueNAS: `deploy/hostcheck/truenas.md`

   The private key never leaves the monitor host. Skip this step and the
   investigator simply has no `host_cmd` tool.

6. Optional, if the monitor host is a laptop: `deploy/laptop-host-setup.sh`
   stops it from suspending when the lid is closed and sets a battery charge
   limit. Read the script first, it changes system settings.

## Configuration

Two places:

- `lanot.toml` describes the network. Every key is explained in
  [`lanot.example.toml`](lanot.example.toml). The server validates the file at
  start and refuses to run with a broken one. Restart after changes.
- `.env` holds the secrets and a few runtime knobs. See
  [`deploy/.env.example`](deploy/.env.example).

### lanot.toml

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[general]` | `timezone` | `"UTC"` | Time zone for the dashboard, the daily summary and the FritzBox log |
| | `dashboard_url` | `"http://localhost:8080"` | Link target in pushes; its host is accepted for form posts |
| | `monitor_host` | none | id of the host LANOT runs on; its own pings are not used to judge the LAN |
| | `daily_summary_hour` | `8` | Local hour of the daily summary |
| | `allowed_hosts` | derived | Host headers accepted for form posts |
| `[router]` | `type` | `"fritzbox"` | `"fritzbox"` or `"generic"` |
| | `host` | `"192.168.178.1"` | Router address (pinged, DNS checked) |
| | `display_name` | `"FritzBox"` / `"Router"` | Shown in the dashboard |
| | `tr064` | `true` | Poll a FritzBox over TR-064 (needs `FRITZ_USER`/`FRITZ_PASSWORD`) |
| `[internet]` | `ping_targets` | 1.1.1.1, 8.8.8.8 | List of `{ name, address }`; internet is down when all fail |
| | `dns_server` | `"1.1.1.1"` | External DNS server to check |
| | `dns_query` | `"example.com"` | Name to resolve |
| | `check_router_dns` | `true` | Also check the router's DNS |
| `[[hosts]]` | `id` | required | Lowercase id; the agent's `HOST_NAME` |
| | `display_name` | the id | Shown in the dashboard and pushes |
| | `address` | required | IP or host name |
| | `role` | `"linux"` | `unraid`, `truenas`, `linux` or `ping-only` |
| | `agent` | `true` (`false` for ping-only) | Runs an agent |
| | `investigator` | `false` | The investigator may run read-only commands over SSH |
| | `investigator_user` | `root` on Unraid, else `lanot` | SSH user for that |
| | `has_battery` | `false` | Alarm and battery pushes when it runs on battery |

### Environment (server)

| Variable | Default | Meaning |
|---|---|---|
| `LANOT_CONFIG` | `/config/lanot.toml` | Path of the config file |
| `DB_PATH` | `/data/lanot.db` | SQLite database |
| `AGENT_TOKENS` | empty | `host:token,host:token` |
| `ANTHROPIC_API_KEY` | unset | Enables the online investigator |
| `ANTHROPIC_MODEL` | `claude-sonnet-5-5` | Model id |
| `OLLAMA_URL`, `OLLAMA_MODEL` | `http://127.0.0.1:11434`, `qwen2.5:7b` | Local fallback |
| `INVESTIGATOR_KEY` | `/secrets/investigator_key` | SSH key for `host_cmd` |
| `FRITZ_USER`, `FRITZ_PASSWORD` | unset | TR-064 login |
| `NTFY_URL`, `NTFY_TOPIC` | `http://127.0.0.1:8081`, `lanot` | Push server and topic |
| `HEALTHCHECK_URL` | unset | Dead man's switch |
| `RETENTION_DAYS`, `DB_MAX_BYTES` | `30`, 20 GiB | Metrics and logs older than this, or beyond the size cap, are deleted. Incidents are kept. |
| `ALLOWED_HOSTS` | unset | Overrides `allowed_hosts` from the config |

### Environment (agent)

`HOST_NAME`, `LANOT_URL` and `AGENT_TOKEN` are required. Optional:
`LOG_FILES` (comma separated), `JOURNAL_DIR`, `ENABLE_ZFS`, `ENABLE_SMART`,
`ENABLE_UNRAID`, `ENABLE_POWER`, `HOST_ROOT` (default `/host`), `BUFFER_DIR`
(default `/buffer`), `DOCKER_SOCK`.

## Security model, in short

The dashboard has no login and is meant for the LAN only. The agents are
privileged containers. The investigator can only run a fixed list of read-only
commands, enforced on each host by a forced-command SSH key. Details, and what
is not covered, in [SECURITY.md](SECURITY.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Known limitations

- No authentication on the dashboard or a TLS listener. Put it behind a reverse
  proxy with auth if anything but your LAN can reach port 8080.
- The router side assumes one router between the LAN and the provider. The
  provider gateway is "hop 2 of a traceroute", and the line state needs a
  FritzBox. Other routers get ping and DNS checks only.
- Pushes only reach your phone while it can reach the ntfy server, usually only
  at home. During a power cut the router is off too, so the healthchecks mail is
  the only thing that gets out.
- Log rules are tuned on Unraid, TrueNAS and Ubuntu logs. Expect to mute a
  false alarm or two at first.
- The investigator's answers are model output. They are labelled as such, but
  read them as a hint, not as a verdict.
- One SQLite file, one server. No high availability.

## Development

```
python3 -m venv .venv && . .venv/bin/activate
pip install -e common -e "agent[test]" -e "server[test]"
pytest common/tests -q
pytest agent/tests -q
pytest server/tests -q
pytest hostcheck/tests -q
```

`server/scripts/seed_demo.py --serve` fills a throw-away database with fake
data and serves the dashboard on port 8090, without any real probes.

## License

MIT, see [LICENSE](LICENSE). Bundled third-party code is listed in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
