# Investigator access on TrueNAS SCALE

TrueNAS keeps users, sudo rules and SSH keys in its own database, so this is done
in the web UI (or with `midclt`) instead of a script. Written for TrueNAS SCALE 25.x.

Throughout this page `LANOT_DIR` is a directory on one of your data pools, for
example `/mnt/tank/.lanot` on a dataset created with
`zfs create -o exec=on -o setuid=off -o atime=off tank/.lanot`.
The same directory also holds the agent's token and buffer (see
`deploy/truenas/install-agent.sh`).

## 1. The check script

Copy `hostcheck/lanot-ro` to `$LANOT_DIR/lanot-ro`, owned by root and not
writable by anyone else:

```
sudo install -o root -g root -m 0755 lanot-ro "$LANOT_DIR/lanot-ro"
sudo chown root:root "$LANOT_DIR" && sudo chmod 0755 "$LANOT_DIR"
```

The directory itself must not be writable by the investigator user either,
otherwise it could swap the script.

## 2. The user

Credentials, Users, Add:

- Username `lanot`, its own group, password disabled, SSH password login off, SMB off,
  no roles.
- Shell `/usr/bin/bash`. Home directory `$LANOT_DIR/home/lanot` (TrueNAS wants a
  writable home on a data pool before it accepts an SSH key).
- "Allowed sudo commands with no password": only `$LANOT_DIR/lanot-ro`.
- SSH public key, as one line, with your investigator key and the path filled in:

```
command="sudo -n /mnt/tank/.lanot/lanot-ro \"$SSH_ORIGINAL_COMMAND\"",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA...yourkey... lanot-investigator
```

sudo clears `SSH_ORIGINAL_COMMAND` (env_reset), so the command is handed over as
the single argument. lanot-ro checks it the same way and refuses everything
outside its list with `denied: ...` and exit code 2.

In `lanot.toml`, set `investigator = true` and `investigator_user = "lanot"` for
this host.

## Updating the script

```
scp hostcheck/lanot-ro admin@NAS:/tmp/lanot-ro.new
ssh admin@NAS 'sudo install -o root -g root -m 0755 /tmp/lanot-ro.new "$LANOT_DIR/lanot-ro" && rm /tmp/lanot-ro.new'
```

## Removing it

- Only the investigator: Credentials, Users, `lanot`, Edit, clear the SSH key, Save.
  Or delete the user, but keep the home directory if the agent still uses `LANOT_DIR`.
- Agent and investigator: Apps, `lanot-agent`, Delete; delete the user; then
  remove the dataset (`zfs destroy -r tank/.lanot`, with your pool name).
