# sshush-agent

The server-side agent for [SSHush](https://sshush.app), an iOS app for monitoring Linux servers.

This repository is public so you can read every line that runs on your server before you install
it. That is the point of it being here.

## Status: early

**The agent does not do anything yet.** This repository currently contains the install and
removal layer only. The binary is a stub: it logs a line to the journal every 60 seconds and
exits cleanly on `SIGTERM`.

It does **not** yet collect metrics, read configuration, open a network connection, or talk to
any server. Those come later, and this section will change when they do.

What is here is the part worth reviewing first: how the agent is installed, what privileges it
runs with, and how it is removed.

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
| `/var/lib/sshush/` | `sshush:sshush` | `0750` |

It also creates a system user `sshush` with a `nologin` shell and no home directory.

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
