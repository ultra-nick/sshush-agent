# CLAUDE.md - sshush-agent

Authoritative reference for any Claude session working on this repo. Read it
fully before changing anything.

## THIS REPO IS PUBLIC

`github.com/ultra-nick/sshush-agent`, Apache 2.0. Its purpose is that
strangers read every line before running it as root on their servers. That
shapes three hard rules:

1. **Never commit a secret or a config.json.** `.gitignore` blocks
   `config.json` because install.sh's convention (config shipped next to the
   installer) puts it exactly where `git add -A` finds it. A secret in a
   public git history is unrecoverable.
2. **Never commit private infrastructure details** - test-machine addresses,
   droplet IPs, credentials, anything about the development environment.
   Those live in the (local-only) sshush-api repo's CLAUDE.md and in session
   memory, not here.
3. **Pushes must use the noreply author email**
   (`264198737+ultra-nick@users.noreply.github.com`). GitHub rejects pushes
   carrying the real address (GH007) - work with that protection, never
   disable it.

## Overview

The server-side agent for SSHush. Go, **stdlib only** - no external
dependencies, ever; auditability is the product. Module
`github.com/ultra-nick/sshush-agent`, single binary from
`cmd/sshush-agent`, static with `CGO_ENABLED=0`, targets linux amd64/arm64.

What it does (all it does): reads `/etc/sshush/config.json` once at startup;
POSTs a heartbeat (`agent_id` + secret) to `endpoint` every `interval_s`;
samples local metrics; evaluates alert rules locally; POSTs rule transitions
to `breach_endpoint`. It never listens on any port, never executes remote
commands, never fetches anything.

```
cmd/sshush-agent/main.go   config load/validate, tick loop, beat sender
internal/metrics/          /proc + /sys samplers, pure fixture-tested parsers
internal/rules/            duration state machine, transition events
internal/report/           seq generation, FIFO retry queue, breach sender
packaging/                 install.sh, sshush-uninstall, systemd units
```

## Key intentional decisions

These look wrong but are correct. Do not change them without understanding
the full context (most have a comment at the code site too).

1. **The agent ignores every beat response and every beat error.** No retry,
   no backoff, no reaction to status codes. The next beat is always one
   interval away. This is the single most important rule; the backend infers
   everything from beats arriving or stopping.
2. **Breach reports ARE retried** (unlike beats) - each subsequent tick, with
   the ORIGINAL request bytes. The seq is frozen at build time; the
   backend's replay guard makes retries idempotent only if it never changes.
3. **The breach queue is strict FIFO and flush stops at the first retryable
   failure.** Seqs increase with age; delivering a newer request past a
   stuck older one gets the older swallowed as stale on arrival. There is a
   test that fails if this is "optimised".
4. **seq is derived from unix seconds, not persisted.** Restarts happen on
   every rule edit; a persisted counter lost to file damage would reset and
   have every later breach silently swallowed forever. Same-second builds
   increment; a backward clock step falls back to last+1.
5. **Rules start UNREPORTED, and each rule's first settled determination is
   emitted once.** Restart is a reconciliation point in both directions; the
   backend's state-change guard dedups it. Without this, raising a threshold
   over a breached value and restarting leaves the backend claiming breach
   forever.
6. **An unreadable metric is NO INFORMATION** - never a breach, never a
   clear, and it neither advances nor resets a duration timer.
7. **Breach needs the full duration above threshold; clear needs one sample
   below.** Slow to alarm, fast to reassure. Deliberately asymmetric.
8. **interval_s has a floor of 30** so the 10s request timeout is always
   well under the interval - overlapping beats are impossible by
   construction, with no bookkeeping.
9. **The first tick fires immediately at startup.** A restarted agent
   announces itself now; "heartbeat resumed" is only as prompt as the first
   beat after restart.
10. **Plain-http endpoints are refused unless `--insecure` is passed.**
    Shipping the secret unencrypted is an explicit per-host choice, never a
    default. The systemd unit does not carry the flag; test hosts add a
    drop-in.
11. **install.sh uses install(1), never mv or cp -a.** On SELinux-enforcing
    hosts mv preserves the payload's `admin_home_t` label into
    /usr/local/bin and systemd fails exec (203/EXEC) while `ls -l` looks
    perfect. Verified both ways on Rocky 9. Diagnose with
    `ausearch -m avc -ts recent </dev/null` (always redirect stdin - it
    blocks otherwise), not the journal.
12. **Restart=on-failure with clean exit 0 on SIGTERM/SIGINT** - a stopped
    agent stays stopped.
13. **The uninstall marker's contents are never read.** Every path in
    sshush-uninstall is a hardcoded absolute literal; the marker carries one
    bit ("the sshush user asked"), so a fully compromised agent can do
    nothing worse than uninstall itself. Self-deletion is the last line,
    with `|| :` so the script's exit code stays 0.
14. **No StateDirectory= in the unit** - install.sh creates /var/lib/sshush
    and the uninstaller removes it; StateDirectory complicates both.
15. **`useradd`'s group behaviour is not trusted**: install.sh runs an
    explicit `groupadd --system` (USERGROUPS_ENAB differs across distros)
    and the uninstaller a matching `groupdel`.
16. **install.sh clears a stale uninstall marker before enabling the path
    unit** - without this, an interrupted uninstall's leftover marker tears
    down the new install seconds after it completes. Reproduced for real.
17. **Never log the secret, on any path** - config parse errors name fields
    but not values; transport errors cannot contain the request body.
18. **cpu busy includes irq/softirq/steal** (matches top/htop on cloud VMs;
    guest excluded - already folded into user). **mem uses MemAvailable**,
    not MemFree. **load is per-core.** **disk matches df's formula.**

## On-server contract

```
/usr/local/bin/sshush-agent          root:root  0755
/usr/local/bin/sshush-uninstall      root:root  0700
/etc/systemd/system/sshush-*.{service,path}  root:root 0644
/etc/sshush/                         root:sshush 0750  (read-only to agent)
/etc/sshush/config.json              root:sshush 0640
/var/lib/sshush/                     sshush:sshush 0750 (ONLY writable path)
system user sshush, nologin, no home
```

Config is read once, never reloaded or watched; the app rewrites it and
restarts the service over SSH. Rule edits therefore restart the agent - the
design leans into that (decisions 4, 5, 9).

## Verify after any change

```bash
gofmt -l . && go vet ./... && go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/sshush-agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/sshush-agent
/bin/dash -n packaging/install.sh && /bin/dash -n packaging/sshush-uninstall
```

Shell scripts are POSIX sh, no bashisms; validate with dash, and test both
scripts' non-root refusal paths if touched. Packaging changes deserve a pass
on a real systemd host (Debian-family AND RHEL-family with SELinux
enforcing) before release - stubs do not catch label or unit behaviour.
