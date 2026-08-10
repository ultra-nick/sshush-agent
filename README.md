# sshush-agent

The server-side agent for [SSHush](https://sshush.app), an iOS app for monitoring Linux servers.

This repository is public so you can read every line that runs on your server before you install
it. That is the point of it being here.

## What it does

The agent does four things, and nothing else:

1. **Heartbeat.** Every `interval_s` it POSTs its identity (`agent_id` plus a secret) to
   `endpoint`, then ignores every response and every error - no retry, no backoff, no reaction
   to any status code. The backend infers presence from beats arriving and absence from beats
   stopping.
2. **Metrics.** It samples local metrics from `/proc` and `/sys`: CPU, memory, swap, disk, load,
   network interface state, and temperature.
3. **Rules.** It evaluates threshold rules against those samples, on the server. A rule breaches
   only after the value has stayed past its threshold for the rule's full duration, and clears on
   a single sample back the other side - slow to alarm, fast to reassure.
4. **Breach reports.** When a rule changes state, it POSTs that one transition to
   `breach_endpoint`.

It also relays one value it does not otherwise use: the phone's push-notification token, when
the app writes one to `/var/lib/sshush/device_token` (see below). The agent holds the secret, so
it is what tells the backend where alerts should go.

Metrics are read and rules are evaluated entirely on the server; only a crossed threshold is ever
sent, never the underlying numbers. Beyond those outbound POSTs the agent **never listens on any
port, executes a remote command, or fetches anything** - its whole network footprint is the two
endpoints you can read in `/etc/sshush/config.json`. An agent with no rules configured simply
beats; metrics sampling and breach reporting switch on only when rules are present.

### Configuration is split across three files

Credentials need root; settings do not. That split is the whole point: on a server where `sudo`
needs a password, root exists only during the interactive install, so editing rules afterwards
must not need it.

**1. The identity**, `/etc/sshush/config.json` (`root:sshush`, mode `0640`) - read ONCE at
startup, never watched or reloaded:

```json
{
  "agent_id":        "<uuid>",
  "secret":          "<base64url, 32 bytes>",
  "endpoint":        "https://example.com/v1/beat",
  "breach_endpoint": "https://example.com/v1/breach"
}
```

**2. The settings**, `/var/lib/sshush/rules.json` (owned by the installing user, mode `0644`) -
re-read whenever it changes, within about 10 seconds:

```json
{
  "interval_s":          60,
  "unreachable_after_s": 180,
  "rules": [
    {
      "rule_id":    "<uuid>",
      "metric":     "disk",
      "threshold":  90,
      "duration_s": 300,
      "label":      "/"
    }
  ]
}
```

`rules` may be empty or omitted, in which case the agent only beats. Valid metrics are `cpu`,
`mem`, `swap`, `disk`, `load`, `temp`, and `interfaceDown`; `disk` takes a mount point as its
`label` and `interfaceDown` an interface name. `interfaceDown` is a state rule and ignores
`threshold`. `interval_s` (20-86400) is the beat cadence. `unreachable_after_s` (60-3600) is how
long of silence the backend should treat as this server being down; the agent does not act on
it, it only reports it on every beat. A settings file whose `interval_s` is too slow to survive
one lost beat within `unreachable_after_s` is applied but logs a warning.

**3. The push token**, `/var/lib/sshush/device_token` (same owner) - plain text, re-read on
change. A 64-character hex token is relayed to the backend; an empty file means "clear it"; no
file at all means nothing to say. It lives apart from the rules so that writing a token can
never rewrite your rules, and vice versa.

Both endpoints must be `https://`. The agent refuses to start with a plain-http endpoint unless
`--insecure` is passed explicitly, because the secret would cross the network unencrypted - that
is a choice a test environment can make on purpose, not a default anyone can ship by accident.

For its first beat interval a freshly started agent beats every 10 seconds rather than every
`interval_s`, so a new install is confirmed in seconds instead of a minute. It settles to the
configured interval after that. The cadence is the only thing that changes: responses are still
ignored entirely.

Still worth reviewing first: how the agent is installed, what privileges it runs with, and how
it is removed.

## Requirements

- Linux with systemd (Debian, Ubuntu, RHEL/Alma/Rocky, Raspberry Pi OS)
- root, to install
- Go 1.22 or newer, to build

Containerised environments (Docker, LXC) are not supported.

## Build

The binary is static and has no dependencies outside the Go standard library.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o packaging/sshush-agent ./cmd/sshush-agent
```

For a Raspberry Pi or another 64-bit ARM machine, use `GOARCH=arm64`.

The output goes into `packaging/` because `install.sh` expects the binary to sit beside it.
Nothing is ever downloaded at install time.

## Install

From the `packaging/` directory, with the binary built as above:

```sh
sudo ./install.sh
```

The installer is idempotent. Re-running it over an existing install stops the services,
overwrites every managed file, and starts them again.

### What it puts on your system

| Path | Owner | Mode |
|---|---|---|
| `/usr/local/bin/sshush-agent` | `root:root` | `0755` |
| `/usr/local/bin/sshush-uninstall` | `root:root` | `0700` |
| `/etc/systemd/system/sshush-agent.service` | `root:root` | `0644` |
| `/etc/systemd/system/sshush-uninstall.path` | `root:root` | `0644` |
| `/etc/systemd/system/sshush-uninstall.service` | `root:root` | `0644` |
| `/etc/sshush/` | `root:sshush` | `0750` |
| `/etc/sshush/config.json` (when shipped) | `root:sshush` | `0640` |
| `/var/lib/sshush/` | `<installing user>:sshush` | `0770` |
| `/var/lib/sshush/rules.json` | `<installing user>:sshush` | `0644` |
| `/var/lib/sshush/device_token`* | `<installing user>:sshush` | `0644` |

\*`device_token` is not written by the installer - it appears only if and when the app relays a
push token (same owner and mode). The installer creates `rules.json` (empty) and, when a
`config.json` is shipped alongside, installs that.

It also creates a system user `sshush` with a `nologin` shell and no home directory.

The state directory is owned by the user who ran the install, with the agent's group, so that
user can edit rules afterwards WITHOUT root - that is the whole reason the configuration is
split. If that matters to you, note what it means: anyone who can act as that user can change
what this agent alerts on, and can hand it a push token. The credentials in `/etc/sshush` stay
root-only either way.

Nothing else on your system is touched. There is no package manager integration, no cron entry,
and no modification of any existing file.

## How it runs

The agent runs as the unprivileged `sshush` user, never as root, under these systemd
restrictions:

```
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/sshush
```

`ProtectSystem=strict` makes the entire filesystem read-only to the agent. `/var/lib/sshush` is
the single exception and the only location it can write to. `/etc/sshush` is written at install
time and is read-only to the agent by design.

`Restart=on-failure` is deliberate: a clean exit leaves the service stopped rather than looping.

## Uninstall

Either of these removes it completely:

```sh
sudo /usr/local/bin/sshush-uninstall
```

or, from the app, which asks the agent to remove itself.

Both routes run the same script. It is idempotent, so if it is interrupted, running it again
finishes the job.

### How self-removal works, and why it is safe

The agent is unprivileged, but uninstalling requires root. That gap is bridged by a systemd path
unit rather than by giving the agent any privilege:

`sshush-uninstall.path` watches for a file at `/var/lib/sshush/uninstall`. When that file
appears, systemd runs `sshush-uninstall` as root.

The file's **contents are never read**. Nothing in the uninstall script is derived from it, from
the environment, or from any argument. Every path the script touches is a hardcoded absolute
literal. The marker carries exactly one bit of meaning: *the `sshush` user asked*.

The consequence is the property that matters. An attacker who completely compromises the agent
gains the ability to uninstall it, and nothing else. They cannot redirect the root-level deletion
somewhere else, because there is no input to redirect. They cannot replace `/var/lib/sshush` with
a symlink either, since `/var/lib` is owned by root, and symlinks planted inside it are not
followed during removal.

If you are reading this code to decide whether to trust it, that is the design decision to check.

## Licence

Copyright 2026 Nick Webster.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

The licence covers this source code. It does not grant any right to use the SSHush name or
branding (Apache 2.0 section 6).
