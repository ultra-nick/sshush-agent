#!/bin/sh
#
# SSHush agent installer.
#
# POSIX sh only, no bashisms. Targets systemd distributions: Debian, Ubuntu,
# RHEL/Alma/Rocky, Raspberry Pi OS.
#
# Idempotent: re-running over an existing install stops the services, overwrites
# every managed file in place, and starts them again. Nothing is ever
# downloaded - the sshush-agent binary and the three unit files must sit in the
# same directory as this script.

set -eu

AGENT_USER=sshush
AGENT_GROUP=sshush

BIN_DIR=/usr/local/bin
UNIT_DIR=/etc/systemd/system
CONF_DIR=/etc/sshush
STATE_DIR=/var/lib/sshush

UNINSTALL_MARKER="$STATE_DIR/uninstall"

fail() {
	echo "install.sh: $*" >&2
	exit 1
}

say() {
	echo "install.sh: $*"
}

# ---------------------------------------------------------------- preflight

if [ "$(id -u)" -ne 0 ]; then
	cat >&2 <<'EOF'
install.sh: this installer must run as root.

Re-run it with whichever of these your system provides:

  sudo ./install.sh
  doas ./install.sh
  su -c ./install.sh

It will not escalate its own privileges.
EOF
	exit 1
fi

command -v systemctl >/dev/null 2>&1 ||
	fail "systemctl not found. This installer supports systemd distributions only."
command -v useradd >/dev/null 2>&1 ||
	fail "useradd not found. Install the shadow-utils (or passwd) package and try again."
command -v groupadd >/dev/null 2>&1 ||
	fail "groupadd not found. Install the shadow-utils (or passwd) package and try again."

# A system account must not be able to log in. Debian-family ships nologin in
# /usr/sbin, RHEL-family in /sbin.
NOLOGIN=
for candidate in /usr/sbin/nologin /sbin/nologin; do
	if [ -x "$candidate" ]; then
		NOLOGIN="$candidate"
		break
	fi
done
[ -n "$NOLOGIN" ] ||
	fail "no nologin binary at /usr/sbin/nologin or /sbin/nologin. Cannot create a login-disabled system user."

# Everything this installer places comes from its own directory. Resolving $0
# rather than trusting the caller's cwd means ./install.sh and /path/to/install.sh
# behave identically.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) ||
	fail "cannot resolve the directory containing install.sh."

for required in \
	sshush-agent \
	sshush-uninstall \
	sshush-agent.service \
	sshush-uninstall.path \
	sshush-uninstall.service; do
	[ -f "$SCRIPT_DIR/$required" ] ||
		fail "$required not found in $SCRIPT_DIR. Unpack the full release next to install.sh; nothing is downloaded."
done

# ---------------------------------------------------------------- user/group

# Create the group explicitly rather than relying on useradd to derive one.
# Whether `useradd --system` also creates a matching group depends on
# USERGROUPS_ENAB in /etc/login.defs, which differs across the target distros,
# and both the unit's Group= and the directory ownership below require it to exist.
if getent group "$AGENT_GROUP" >/dev/null 2>&1; then
	say "group $AGENT_GROUP already exists"
else
	groupadd --system "$AGENT_GROUP"
	say "created system group $AGENT_GROUP"
fi

if id -u "$AGENT_USER" >/dev/null 2>&1; then
	say "user $AGENT_USER already exists"
else
	useradd --system --gid "$AGENT_GROUP" --no-create-home --shell "$NOLOGIN" "$AGENT_USER"
	say "created system user $AGENT_USER (shell $NOLOGIN, no home directory)"
fi

# ---------------------------------------------------------------- stop first

# Idempotency: a running agent holds its binary open, and a live uninstall
# watcher could fire mid-install. Both are stopped before anything is written.
# Absent units are not an error here.
systemctl stop sshush-uninstall.path >/dev/null 2>&1 || :
systemctl stop sshush-agent.service >/dev/null 2>&1 || :

# ---------------------------------------------------------------- install

# install(1), never mv or cp -a. On SELinux-enforcing hosts (RHEL family) the
# unpacked payload under /root carries the admin_home_t label; mv is a rename,
# so the label survives into /usr/local/bin and systemd then refuses to exec
# the binary (status=203/EXEC) while ls -l shows a perfect layout. install
# creates a new file, so the target directory's type transition applies
# (bin_t / systemd_unit_file_t) and no restorecon is needed. Verified both
# ways on Rocky 9 with SELinux enforcing; diagnose any recurrence with
# `ausearch -m avc -ts recent < /dev/null`, not the journal.
install -o root -g root -m 0755 "$SCRIPT_DIR/sshush-agent" "$BIN_DIR/sshush-agent"
install -o root -g root -m 0700 "$SCRIPT_DIR/sshush-uninstall" "$BIN_DIR/sshush-uninstall"

install -o root -g root -m 0644 "$SCRIPT_DIR/sshush-agent.service" "$UNIT_DIR/sshush-agent.service"
install -o root -g root -m 0644 "$SCRIPT_DIR/sshush-uninstall.path" "$UNIT_DIR/sshush-uninstall.path"
install -o root -g root -m 0644 "$SCRIPT_DIR/sshush-uninstall.service" "$UNIT_DIR/sshush-uninstall.service"

# The user rules editing must belong to. sudo sets SUDO_USER to the invoking
# name; a direct root login leaves it unset, and the fallback gives root, which
# is correct. This is the one moment root exists in every case (including the
# password-sudo terminal handoff), so the settings file's ownership is fixed
# here, at install time, to a user who can then edit it forever without root.
OWNER="${SUDO_USER:-$(id -un)}"

# install -d resets mode and ownership on a directory that already exists, so a
# re-run repairs drift rather than leaving a previous cycle's permissions.
# Config is root-owned and group-readable: readable by the agent, never writable.
install -d -o root -g "$AGENT_GROUP" -m 0750 "$CONF_DIR"

# The state directory must let the OWNER create a temp file and rename it over
# rules.json (an unprivileged rules edit), while the agent - running as the
# sshush group - keeps write access for its own state (the uninstall marker).
# So: owner OWNER, group sshush, mode 0770. Owner and group both get rwx;
# nobody else has any access. install -d re-applies this on every re-run, which
# is how re-enrolment after an SSH username change moves ownership to the new
# user without disturbing file contents.
install -d -o "$OWNER" -g "$AGENT_GROUP" -m 0770 "$STATE_DIR"

# The settings file: interval_s and rules[]. Owned by OWNER (write) with group
# sshush (the agent reads it), mode 0644. Created with an empty rule set only
# when absent - a re-run re-applies ownership and mode but never touches the
# contents, so a rules edit made since install survives re-enrolment.
if [ ! -f "$STATE_DIR/rules.json" ]; then
	printf '{"interval_s":60,"rules":[]}\n' > "$STATE_DIR/rules.json"
	say "created an empty $STATE_DIR/rules.json (no rules yet)"
fi
chown "$OWNER":"$AGENT_GROUP" "$STATE_DIR/rules.json"
chmod 0644 "$STATE_DIR/rules.json"

# The agent's identity file. Enrolment will write this eventually; until then
# a config.json shipped next to install.sh is placed here. Root-owned and
# group-readable: the agent reads it, only root can change it. It holds the
# beat secret, so it is never world-readable.
CONFIG_PLACED=no
if [ -f "$SCRIPT_DIR/config.json" ]; then
	install -o root -g "$AGENT_GROUP" -m 0640 "$SCRIPT_DIR/config.json" "$CONF_DIR/config.json"
	CONFIG_PLACED=yes
elif [ ! -f "$CONF_DIR/config.json" ]; then
	say "WARNING: no config.json shipped and none present at $CONF_DIR/config.json."
	say "         The agent exits without an identity, and systemd will retry every 10s"
	say "         until the file exists. Place it and run: systemctl restart sshush-agent"
fi

# A marker left behind by an interrupted uninstall would fire
# sshush-uninstall.path the instant it is enabled below, tearing down the
# install that just completed. Clear it before the watcher goes live.
if [ -e "$UNINSTALL_MARKER" ]; then
	rm -f "$UNINSTALL_MARKER"
	say "cleared a stale uninstall marker at $UNINSTALL_MARKER"
fi

# ---------------------------------------------------------------- activate

systemctl daemon-reload
systemctl enable --now sshush-agent.service
systemctl enable --now sshush-uninstall.path

# ---------------------------------------------------------------- summary

# printf padding rather than hand-spaced heredoc columns: the paths above are
# variables, so literal alignment drifts as soon as one of them changes length.
row() {
	printf '  %-44s %-15s %s\n' "$1" "$2" "$3"
}

printf '\nSSHush agent installed.\n\n'
row "$BIN_DIR/sshush-agent" "root:root" "0755"
row "$BIN_DIR/sshush-uninstall" "root:root" "0700"
row "$UNIT_DIR/sshush-agent.service" "root:root" "0644"
row "$UNIT_DIR/sshush-uninstall.path" "root:root" "0644"
row "$UNIT_DIR/sshush-uninstall.service" "root:root" "0644"
row "$CONF_DIR/" "root:$AGENT_GROUP" "0750  identity dir, root-only"
if [ "$CONFIG_PLACED" = yes ]; then
	row "$CONF_DIR/config.json" "root:$AGENT_GROUP" "0640  agent identity (secret)"
fi
row "$STATE_DIR/" "$OWNER:$AGENT_GROUP" "0770  agent state + user-writable"
row "$STATE_DIR/rules.json" "$OWNER:$AGENT_GROUP" "0644  settings, editable by $OWNER"
row "system user $AGENT_USER" "$NOLOGIN" "no home directory"

cat <<EOF

Enabled and running: sshush-agent.service, sshush-uninstall.path

  Status:  systemctl status sshush-agent
  Logs:    journalctl -u sshush-agent -f
  Remove:  $BIN_DIR/sshush-uninstall

EOF
